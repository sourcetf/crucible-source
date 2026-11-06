//! PHP 引擎：优先 php-fpm（绝对路径 conf + UDS），失败回退 php-cgi + PHP_FCGI_CHILDREN。
//! 禁止把 CLI `php` 当 FastCGI（自动 remap 到 php-cgi）。

use super::fastcgi::{self, FcgiAddr, FcgiRequest};
use super::sandbox;
use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

static PHP_RUNTIME: Lazy<Mutex<HashMap<String, PhpRuntime>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 每个 key（port-app_idx）一把「冷启动中」锁：并发首次请求只允许一个真正 spawn。
///
/// 没有它时 N 个并发首请求会各自走完 ensure 流程 —— 每个都 `remove_file(sock)` + spawn
/// 一个 php-fpm/php-cgi，**只有最后一个被登记进 PHP_RUNTIME**，前面几个变成没人管、也不再
/// 被复用的孤儿（且共用同一个 sock 路径，后 spawn 的会把先 spawn 的 socket 覆盖掉）。
/// 实测（OpenBSD，本仓库）：16 个并发首请求 `/php/` → 9 个 php-fpm master 同时存活
/// （每个还带 16 个 pool worker ≈ 144 个多余进程），进程表被瞬间堆满。
/// `native_http::ensure_sidecar` / `sidecar_engine::ensure_sidecar_simple` 早有同款 per-key 锁。
/// key 的集合由配置决定（port-app_idx），数量有界，无需淘汰。
static SPAWN_LOCKS: Lazy<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn spawn_lock(key: &str) -> Arc<tokio::sync::Mutex<()>> {
    SPAWN_LOCKS
        .lock()
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

#[cfg(not(unix))]
static TCP_PORT_SEQ: std::sync::atomic::AtomicU16 =
    std::sync::atomic::AtomicU16::new(9100);

struct PhpRuntime {
    addr: FcgiAddr,
    /// Keep child alive for process lifetime.
    #[allow(dead_code)]
    child: Option<Child>,
    #[allow(dead_code)]
    kind: PhpKind,
    /// 该池被 chroot 到哪个目录（`sandbox.chroot = "docroot"` 时）。请求期据此把
    /// `SCRIPT_FILENAME`/`DOCUMENT_ROOT` 换成**chroot 内**的路径 —— 否则 FPM 在
    /// jail 里看到的是 `/crucible/www-apps/php/index.php` 这种宿主绝对路径，
    /// 会解析成 `<docroot>/crucible/...` 而 404。
    chroot: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug)]
enum PhpKind {
    Fpm,
    Cgi,
}

/// h1/h2/h3 共用的执行结果：脚本不存在 → 404；否则上游响应。
enum PhpOutcome {
    NotFound,
    Upstream(fastcgi::FcgiResponse),
}

/// Handle a PHP / FastCGI app request (h1)。
pub async fn handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
) -> Result<Response<BoxBody>> {
    // 所有需要的东西必须在 `into_body()` 之前取（extensions/headers 会随 req 一起被消耗）。
    let is_head = req.method() == http::Method::HEAD;
    let method = req.method().as_str().to_string();
    let uri_path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let request_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri_path.clone());
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let req_headers = headers_with_host(req.headers().clone(), req.uri());
    let extra_params: HashMap<String, String> = req
        .extensions()
        .get::<crate::server::apps::deps::DepsEnv>()
        .map(|d| (*d.vars).clone())
        .unwrap_or_default()
        .into_iter()
        .collect();
    // 任务 6（OOM 防护）+ slowloris：上限 32MiB，帧间空闲 60s ⇒ 413/408/400。
    let body = match crate::server::apps::collect_app_body(
        req.into_body(),
        crate::server::h1::APP_BODY_CAP,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return Ok(e.into_response()),
    };

    match php_exchange(
        lc,
        app,
        app_idx,
        method,
        &uri_path,
        request_uri,
        query,
        content_type,
        req_headers,
        extra_params,
        body,
        peer,
    )
    .await?
    {
        PhpOutcome::NotFound => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full("php: script not found"))
            .unwrap()),
        PhpOutcome::Upstream(resp) => {
            // 上游响应头必须净化后再透传：否则 `Content-Length`/`Transfer-Encoding`
            // 与重建后的 body 不符会造成响应走私（详见 fastcgi::sanitize_response_headers）。
            let headers =
                fastcgi::sanitize_response_headers(resp.headers, resp.body.len(), is_head);
            let mut builder = Response::builder().status(resp.status);
            for (k, v) in headers.iter() {
                builder = builder.header(k, v);
            }
            Ok(builder.body(full(resp.body)).unwrap())
        }
    }
}

/// h2/h3 字节入口：与 [`handle`] 同一核心，只是 body 已在协议层收齐为 `Bytes`。
pub async fn handle_bytes(
    req: &Request<bytes::Bytes>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    deps_env: &crate::server::apps::deps::DepsEnv,
) -> Result<Response<bytes::Bytes>> {
    let is_head = req.method() == http::Method::HEAD;
    let method = req.method().as_str().to_string();
    let uri_path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let request_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri_path.clone());
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let req_headers = headers_with_host(req.headers().clone(), req.uri());
    // simple 路径的 `.env`（deps）不是请求 extension 而是实参（h1 走 extension）——
    // 不接上的话 /php/ 在 h2/h3 上拿不到 .env（h1 能拿到），又是一处版本间不一致。
    let extra_params: HashMap<String, String> = (*deps_env.vars).clone().into_iter().collect();
    let body = req.body().clone();

    match php_exchange(
        lc,
        app,
        app_idx,
        method,
        &uri_path,
        request_uri,
        query,
        content_type,
        req_headers,
        extra_params,
        body,
        peer,
    )
    .await?
    {
        PhpOutcome::NotFound => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(bytes::Bytes::from_static(b"php: script not found"))
            .unwrap()),
        PhpOutcome::Upstream(resp) => {
            // 上游响应头净化（同 handle）：防 Content-Length/TE 与 body 不符的响应走私。
            let headers =
                fastcgi::sanitize_response_headers(resp.headers, resp.body.len(), is_head);
            let mut builder = Response::builder().status(resp.status);
            for (k, v) in headers.iter() {
                builder = builder.header(k, v);
            }
            Ok(builder.body(resp.body).unwrap())
        }
    }
}

/// FastCGI 执行核心（h1/h2/h3 共用）。
#[allow(clippy::too_many_arguments)]
async fn php_exchange(
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    app_idx: usize,
    method: String,
    uri_path: &str,
    request_uri: String,
    query: String,
    content_type: String,
    req_headers: http::HeaderMap,
    extra_params: HashMap<String, String>,
    body: bytes::Bytes,
    peer: SocketAddr,
) -> Result<PhpOutcome> {
    let key = runtime_key(lc.port, app_idx);
    ensure_runtime(&key, lc, app, app_idx).await?;

    let (addr, pool_chroot) = {
        let map = PHP_RUNTIME.lock();
        let rt = map
            .get(&key)
            .context("php runtime missing after ensure")?;
        (rt.addr.clone(), rt.chroot.clone())
    };

    let docroot = resolve_docroot(lc, app);
    // percent-decode：文件解析与 SCRIPT_NAME/PATH_INFO 都用解码后的路径
    // （CGI：PATH_INFO "is not URL-encoded"）。REQUEST_URI 保持原始编码形态。
    let uri_path = crate::server::apps::app_ffi::decode_path(uri_path);
    let (script, path_info) = resolve_script(&docroot, app, &uri_path)?;
    if !script.is_file() {
        // **不要把路径发回客户端**：`script.display()` 是 `/crucible/www-apps/php/...` 这种
        // **服务器绝对路径**（docroot 泄露），而请求者只是任意能命中该路由的客户端。
        // 与其它引擎口径一致：细节进本地日志，客户端拿一句固定文本。
        // 而这条日志本身是**客户端可驱动**的（反复请求不存在的 .php 即可）⇒ 走节流，
        // 否则就是一个按请求速率计费的写入口（本机磁盘长期紧张）。
        crate::server::log_throttle::warn_every(
            "php-script-not-found",
            std::time::Duration::from_secs(60),
            &format!("php: script not found: {}", script.display()),
        );
        return Ok(PhpOutcome::NotFound);
    }

    let docroot_abs = canonicalize_display(&docroot);
    let script_abs = canonicalize_display(&script);
    let script_name = script_name_for(&docroot, app, &uri_path, &script, &path_info);

    // 池被 chroot（`sandbox.chroot = "docroot"`）时，FPM 的**文件系统视图**以 docroot
    // 为根：必须把 SCRIPT_FILENAME 换成 chroot 内的路径，否则它按宿主绝对路径去找
    // 文件（`<docroot>/crucible/www-apps/php/x.php`）而 404。DOCUMENT_ROOT 相应为 `/`。
    // 相对关系由构造保证（chroot == 本应用 docroot），这里做前缀剥离。
    let (document_root, script_filename) = match &pool_chroot {
        Some(root) => {
            let root_s = canonicalize_display(root);
            let rel = script_abs
                .strip_prefix(root_s.trim_end_matches('/'))
                .map(|r| format!("/{}", r.trim_start_matches('/')))
                .unwrap_or_else(|| script_abs.clone());
            ("/".to_string(), rel)
        }
        None => (docroot_abs.clone(), script_abs.clone()),
    };

    let fcgi = FcgiRequest {
        method,
        script_filename,
        document_root,
        request_uri,
        query_string: query,
        content_type,
        remote_addr: peer.ip().to_string(),
        remote_port: peer.port(),
        script_name,
        path_info,
        headers: req_headers,
        server_name: lc
            .server_name
            .clone()
            .unwrap_or_else(|| "crucible".into()),
        server_port: lc.port,
        https: lc.ssl.is_some(),
        body,
        extra_params,
    };

    let resp = fastcgi::exchange(&addr, &fcgi)
        .await
        .with_context(|| format!("fastcgi to {:?}", addr))?;

    Ok(PhpOutcome::Upstream(resp))
}

/// External FastCGI upstream (`engine = "fastcgi"`)，要求 `socket=`。
pub async fn handle_external(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    let is_head = req.method() == http::Method::HEAD;
    let method = req.method().as_str().to_string();
    let uri_path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let request_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri_path.clone());
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // 同 php-fpm 路径：HTTP_* 需要请求头，必须在 into_body 之前克隆。
    let req_headers = headers_with_host(req.headers().clone(), req.uri());
    // `.env`（deps）注入：`engine = "php"` 从 extensions 取，`engine = "fastcgi"` 此前
    // 恒空 —— 同一份 .env 在 php 引擎下能到 PHP、在 fastcgi 引擎下拿不到（行为分叉）。
    let extra_params: HashMap<String, String> = req
        .extensions()
        .get::<crate::server::apps::deps::DepsEnv>()
        .map(|d| (*d.vars).clone())
        .unwrap_or_default()
        .into_iter()
        .collect();
    // 任务 6（OOM 防护）+ slowloris：上限 32MiB，帧间空闲 60s ⇒ 413/408/400
    // （与 h1 的 proxy/static 收口同口径；旧实现只有 Limited，慢 body 无限挂起）。
    let body = match crate::server::apps::collect_app_body(
        req.into_body(),
        crate::server::h1::APP_BODY_CAP,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return Ok(e.into_response()),
    };

    match external_exchange(
        lc,
        app,
        peer,
        method,
        &uri_path,
        request_uri,
        query,
        content_type,
        req_headers,
        extra_params,
        body,
    )
    .await?
    {
        PhpOutcome::NotFound => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full("php: script not found"))
            .unwrap()),
        PhpOutcome::Upstream(resp) => {
            // 上游响应头净化（同 handle_external）。
            let headers =
                fastcgi::sanitize_response_headers(resp.headers, resp.body.len(), is_head);
            let mut builder = Response::builder().status(resp.status);
            for (k, v) in headers.iter() {
                builder = builder.header(k, v);
            }
            Ok(builder.body(full(resp.body)).unwrap())
        }
    }
}

/// h2/h3 字节入口（`engine = "fastcgi"`，外部 socket）：与 [`handle_external`] 同一核心。
pub async fn handle_external_bytes(
    req: &Request<bytes::Bytes>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    deps_env: &crate::server::apps::deps::DepsEnv,
) -> Result<Response<bytes::Bytes>> {
    let is_head = req.method() == http::Method::HEAD;
    let method = req.method().as_str().to_string();
    let uri_path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let request_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri_path.clone());
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let req_headers = headers_with_host(req.headers().clone(), req.uri());
    // 与 h1 `handle_external` 同一份 .env 注入（simple 路径是实参而非 extension）。
    let extra_params: HashMap<String, String> = (*deps_env.vars).clone().into_iter().collect();
    let body = req.body().clone();

    match external_exchange(
        lc,
        app,
        peer,
        method,
        &uri_path,
        request_uri,
        query,
        content_type,
        req_headers,
        extra_params,
        body,
    )
    .await?
    {
        PhpOutcome::NotFound => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(bytes::Bytes::from_static(b"php: script not found"))
            .unwrap()),
        PhpOutcome::Upstream(resp) => {
            // 上游响应头净化（同 handle_external）。
            let headers =
                fastcgi::sanitize_response_headers(resp.headers, resp.body.len(), is_head);
            let mut builder = Response::builder().status(resp.status);
            for (k, v) in headers.iter() {
                builder = builder.header(k, v);
            }
            Ok(builder.body(resp.body).unwrap())
        }
    }
}

/// 外部 FastCGI socket 的执行核心（h1/h2/h3 共用）。
#[allow(clippy::too_many_arguments)]
async fn external_exchange(
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    method: String,
    uri_path: &str,
    request_uri: String,
    query: String,
    content_type: String,
    req_headers: http::HeaderMap,
    extra_params: HashMap<String, String>,
    body: bytes::Bytes,
) -> Result<PhpOutcome> {
    let sock = app
        .socket
        .as_deref()
        .context("fastcgi engine requires socket= (unix:/path or host:port)")?;
    let addr = FcgiAddr::parse(sock)?;
    let docroot = resolve_docroot(lc, app);
    // percent-decode：文件解析与 SCRIPT_NAME/PATH_INFO 都用解码后的路径
    // （CGI：PATH_INFO "is not URL-encoded"）。REQUEST_URI 保持原始编码形态。
    let uri_path = crate::server::apps::app_ffi::decode_path(uri_path);
    let (script, path_info) = resolve_script(&docroot, app, &uri_path)?;
    if !script.is_file() {
        return Ok(PhpOutcome::NotFound);
    }

    let script_abs = canonicalize_display(&script);
    let script_name = script_name_for(&docroot, app, &uri_path, &script, &path_info);

    let fcgi = FcgiRequest {
        method,
        script_filename: script_abs,
        document_root: canonicalize_display(&docroot),
        request_uri,
        query_string: query,
        content_type,
        remote_addr: peer.ip().to_string(),
        remote_port: peer.port(),
        script_name,
        path_info,
        headers: req_headers,
        server_name: lc
            .server_name
            .clone()
            .unwrap_or_else(|| "crucible".into()),
        server_port: lc.port,
        https: lc.ssl.is_some(),
        body,
        extra_params,
    };
    let resp = fastcgi::exchange(&addr, &fcgi).await?;
    Ok(PhpOutcome::Upstream(resp))
}

pub fn reconcile(lc: &ListenerConfig, apps: &[(usize, &AppRouteConfig)]) {
    for (idx, app) in apps {
        if !app.enabled {
            continue;
        }
        if !matches!(
            app.engine.to_ascii_lowercase().as_str(),
            "php"
        ) {
            continue;
        }
        let key = runtime_key(lc.port, *idx);
        // 异步 ensure 会在首次请求触发；这里做轻量 health 探测。
        if let Some(rt) = PHP_RUNTIME.lock().get(&key) {
            let addr = rt.addr.clone();
            tokio::spawn(async move {
                if !fastcgi::probe(&addr).await {
                    log::warn!("php runtime {key} sock unhealthy: {:?}", addr);
                }
            });
        }
    }
}

async fn ensure_runtime(
    key: &str,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    app_idx: usize,
) -> Result<()> {
    // 快路径（不拿锁）：已在表里且探活通过 → 直接返回。
    {
        let cached_addr = PHP_RUNTIME.lock().get(key).map(|rt| rt.addr.clone());
        if let Some(addr) = cached_addr {
            if fastcgi::probe(&addr).await {
                return Ok(());
            }
        }
    }

    // 冷启动/重启串行化：并发首请求只允许一个真正 spawn（见 SPAWN_LOCKS 的说明）。
    let lock = spawn_lock(key);
    let _guard = lock.lock().await;

    // 拿锁后重查：等锁期间别人可能已经起好（或已重启好）。
    {
        let cached_addr = PHP_RUNTIME.lock().get(key).map(|rt| rt.addr.clone());
        if let Some(addr) = cached_addr {
            if fastcgi::probe(&addr).await {
                return Ok(());
            }
        }
    }

    // 到这里确定需要（重新）起：先摘除并杀掉旧的死 runtime（若有）。
    // `Child` 被 drop 不会终止进程（child_registry 的文档明写），此前只做 `remove` ⇒ 每
    // 重启一次就泄漏一个 php-fpm/php-cgi，而且它的 pid 永久留在 REGISTRY 里。
    if let Some(mut rt) = PHP_RUNTIME.lock().remove(key) {
        log::warn!("php sock dead, restarting {key}");
        if let Some(mut c) = rt.child.take() {
            crate::server::apps::child_registry::kill_child(&mut c);
        }
    }

    let state_dir = state_dir_for_key(key);

    // Prefer configured socket, else UDS under state/php.
    if let Some(sock) = &app.socket {
        let addr = FcgiAddr::parse(sock)?;
        if fastcgi::probe(&addr).await {
            PHP_RUNTIME.lock().insert(
                key.to_string(),
                PhpRuntime {
                    addr,
                    child: None,
                    kind: PhpKind::Fpm,
                    chroot: None,
                },
            );
            return Ok(());
        }
    }

    // Try php-fpm first.
    match start_fpm(key, lc, app, app_idx, &state_dir).await {
        Ok(rt) => {
            PHP_RUNTIME.lock().insert(key.to_string(), rt);
            return Ok(());
        }
        Err(e) => log::warn!("php-fpm start failed ({e:#}); falling back to php-cgi"),
    }

    let rt = start_cgi(key, lc, app, &state_dir).await?;
    PHP_RUNTIME.lock().insert(key.to_string(), rt);
    Ok(())
}

#[cfg(unix)]
async fn start_fpm(
    key: &str,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    _app_idx: usize,
    state_dir: &Path,
) -> Result<PhpRuntime> {
    let fpm_bin = resolve_php_bin(app, true)?;
    let sock_path = state_dir.join(format!("{key}.sock"));
    let conf_path = state_dir.join(format!("{key}.conf"));
    let pid_path = state_dir.join(format!("{key}.pid"));
    let err_path = state_dir.join(format!("{key}-error.log"));
    // 上一代遗留的 fpm master（正常关机漏杀 / webserver 被 SIGKILL）：它仍持有本
    // sock 路径上的旧监听 inode。直接 `remove_file + spawn` 会让它继续活着 ——
    // 同形态进程 = 2，且旧 master/worker 永远不会被 kill_all 回收（deploy3 §4.3）。
    // 判据：pidfile 里的 pid 或命令行含本 conf 绝对路径 + 程序名 php-fpm/php-cgi；
    // 只动**不是本进程直系子进程**的（自己的子进程由 PHP_RUNTIME 管理/回收）。
    kill_stale_php(&[conf_path.as_path()], Some(pid_path.as_path()), &sock_path);
    let _ = fs::remove_file(&sock_path);

    // 全部绝对路径；禁止 prefix=/（部分 fpm 报 unknown entry）
    let listen = format!("{}", abs_path(&sock_path).display());
    // user/group/listen.owner/listen.group 只在 **root** 下有意义：非 root 的 fpm
    // 会明确忽略它们（NOTICE: 'user' directive is ignored when FPM is not running
    // as root），但**仍会 getgrnam/getpwnam 解析**。Debian/Ubuntu 只有用户 nobody、
    // 没有名为 nobody 的**组**（组是 nogroup）⇒
    //   ERROR: [pool x] cannot get gid for group 'nobody'
    //   ERROR: FPM initialization failed
    // ⇒ php-fpm 起不来、/php/ 恒 502（本机 2026-10-23 真机复现）。
    // 非 root 时直接省略这四行：FPM 行为等价（本来就不 chown），且不再解析不存在的组。
    // 还有第三种情况：**我们要把整个 fpm 降权到非特权用户**（sandbox 沙箱）。那时
    // master 一上来就不是 root，`user`/`group` 会被忽略，而 `listen.owner/group`
    // 会真正去 `chown()` 到 nobody —— 非 root 做不到，FPM 报错退出。所以只要本次
    // 会降权（或本来就不是 root），就一律省略这四行。
    let will_drop = {
        let cfg = app.sandbox_effective(&lc.global_sandbox);
        matches!(
            crate::server::apps::sandbox::resolve_ids(cfg.user.as_deref(), cfg.group.as_deref()),
            Ok(Some(_))
        ) && cfg.enabled
    };
    let (pool_owner, listen_owner) = if unsafe { libc::geteuid() } == 0 && !will_drop {
        (
            "user = nobody\ngroup = nobody\n",
            "listen.owner = nobody\nlisten.group = nobody\n",
        )
    } else {
        ("", "")
    };
    let docroot = resolve_docroot(lc, app);
    let tmp_dir = prepare_app_tmp(key)?;
    let cfg = app.sandbox_effective(&lc.global_sandbox);
    // `chroot = "docroot"`：把 worker 关进 docroot（FPM 原生 `chroot` 指令，**worker**
    // 生效；master 读 conf/pid/log 在 chroot 之前，不受影响）。需要配合请求期的
    // SCRIPT_FILENAME 改写（见 `PhpRuntime::chroot`）。
    // 沙箱关闭时连 chroot 一起忽略（`enabled = false` = 完全不做隔离）。
    let chroot: Option<PathBuf> = if !cfg.enabled {
        None
    } else {
        match cfg.chroot.as_deref().map(str::trim) {
            Some("docroot") | Some("app") => Some(docroot.clone()),
            Some("") | None | Some("none") | Some("off") => None,
            Some(other) => Some(PathBuf::from(other)),
        }
    };
    // **PHP 上「chroot」与「降权」互斥**（真机实测的硬约束，不是取舍口味）：
    // php-fpm 的池级 `chroot` 由 **master** 执行，而 master 必须先以 root 身份
    // `chroot(2)` 才能把 worker 关进去 —— fpm 自己就会打印
    //   `'chroot' directive is ignored when FPM is not running as root`
    // 并**静默放弃** chroot。而我们的沙箱正是把整个 fpm 降权到非特权用户。
    // 两条路只能选一条：
    //   * 要降权（推荐，威胁模型是"引擎必被攻破"）⇒ 不要配 `chroot`；
    //   * 要 FPM 原生 chroot ⇒ 必须让 master 保持 root（等于放弃第一道防线）。
    // 这里**明确报错**而不是静默忽略 —— "以为开了其实没开"正是本项目一直在猎杀的形态。
    if chroot.is_some() && will_drop {
        bail!(
            "php app `{key}`: [sandbox] chroot 与降权（user 非 none）不能同时用 ——              php-fpm 的池级 chroot 需要 master 以 root 运行，降权后它会被 fpm **静默忽略**。请二选一：去掉 chroot（保留降权，推荐），或把 [sandbox] user 设为 none/root（放弃降权）。"
        );
    }
    let chroot_line = chroot
        .as_ref()
        .map(|d| format!("chroot = {}\nchdir = /\n", d.display()))
        .unwrap_or_default();
    // **chroot 下的 tmp 必须是 chroot 内的路径**：宿主侧实际位置是 `<docroot>/tmp`
    //（要建出来并 chown 给引擎用户，否则 worker 写不了），而 conf/`-d` 里写 `/tmp`。
    let host_tmp: PathBuf = match &chroot {
        Some(d) => {
            let t = d.join("tmp");
            fs::create_dir_all(&t).with_context(|| format!("mkdir jail tmp {}", t.display()))?;
            t
        }
        None => tmp_dir.clone(),
    };
    let conf = format!(
        r#"[global]
error_log = {err}
daemonize = no
pid = {pid}

[{pool}]
{pool_owner}listen = {listen}
{listen_owner}listen.mode = 0660
listen.backlog = 4096
pm = static
pm.max_children = {workers}
{chroot_line}chdir = {tmp}
catch_workers_output = yes
; 每应用独立的临时目录（`state/php/tmp/<key>`）：会话/上传临时文件彼此不可见，
; 也让 unveil 不必揭示整个 /tmp。chroot 打开时这里的路径要按 chroot 内的视角给。
php_admin_value[sys_temp_dir] = {tmp}
php_admin_value[upload_tmp_dir] = {tmp}
php_admin_value[session.save_path] = {tmp}
; 只允许 .php 被当作 PHP 解析：路由的 extensions 含 ""（目录/无扩展名兜底），
; 若不过滤，docroot 里任意无扩展名文件（deps/bin/index 等）会被当 PHP 脚本执行/回显
; 源码，绕过静态层「应用 docroot 私密文件 → 404」的策略。
security.limit_extensions = .php
; PHP 的 max_execution_time 只计 CPU 时间（sleep/等 IO 不计）。没有这条时，客户端
; 已 60s 超时（FCGI_TIMEOUT）后 sleep/阻塞的脚本仍永久占住一个 worker；pm=static 下
; N 个慢请求即可让 PHP 全站排队到超时。设成略大于 FCGI_TIMEOUT 让 fpm 自行回收。
request_terminate_timeout = 65s
pm.max_requests = 10000
"#,
        err = abs_path(&err_path).display(),
        pid = abs_path(&pid_path).display(),
        pool = key.replace(['/', '\\', ':'], "_"),
        listen = listen,
        pool_owner = pool_owner,
        listen_owner = listen_owner,
        tmp = if chroot.is_some() { "/tmp".to_string() } else { host_tmp.display().to_string() },
        chroot_line = chroot_line,
        workers = app.workers.max(1),
    );
    fs::write(&conf_path, conf).context("write php-fpm conf")?;

    let mut cmd = Command::new(&fpm_bin);
    // 干净环境：php-fpm 是长驻进程，spawn 时刻可能落在别的应用的请求期 `.env` 窗口内。
    // fpm 池默认 clear_env=yes（worker 环境会被清），但 master 自己会永久留下别人的密钥。
    // 统一用「启动期基底」spawn（与 cgi_script / sidecar 同一判据）。
    crate::server::apps::env_lock::apply_clean_env(&mut cmd, &[]);
    // `opcache.lockfile_path` 必须在**命令行**给：它在 master 启动期就被读取，
    // 池里的 `php_admin_value[...]` 来不及生效（真机实测：加了池级指令仍报
    // `Unable to create opcache lock file in /tmp`）。默认值是 `/tmp`，而我们的
    // unveil **故意不揭示 `/tmp`**（那是跨应用串味的入口）⇒ 指向每应用自建 tmp。
    cmd.arg("-y")
        .arg(abs_path(&conf_path))
        .arg("-d")
        .arg(format!(
            "opcache.lockfile_path={}",
            if chroot.is_some() { "/tmp".to_string() } else { host_tmp.display().to_string() }
        ))
        .arg("-F") // foreground; we manage as child
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // **进程级沙箱**（OpenBSD unveil/pledge；其它平台 no-op）。放在 spawn 前：
    // 钩子会在 fork 之后、exec 之前于子进程里施加（见 apps::sandbox 的文件头）。
    // chroot 交给 FPM 的池级 `chroot =`（只关 worker）；**不能**在 pre_exec 里 chroot
    // —— 那会连 master 一起关进去，master 就读不到 conf/pid/log/sock（都在 docroot 外）。
    let mut spec_cfg = cfg.clone();
    spec_cfg.chroot = None;
    // **必须走 apply_for_app**（而不是 build_spec + apply）：降权（uid/gid）与
    // 「把本应用的状态/临时目录交给目标用户」都在它里面 —— 只调 build_spec 的
    // 话 fpm 会以 root 起来，等于这一整层防护对 PHP 失效（本文件此前就是这样）。
    sandbox::apply_for_app(
        &mut cmd,
        "php",
        &spec_cfg,
        Some(&docroot),
        Some(&state_dir),
        Some(&host_tmp),
        Some(Path::new(&fpm_bin)),
    )?;
    let mut child = crate::server::apps::child_registry::spawn_tracked(
        &mut cmd,
        &format!("php-fpm {key}"),
    )
    .with_context(|| format!("spawn {fpm_bin}"))?;

    let addr = FcgiAddr::Unix(abs_path(&sock_path));
    // 就绪超时/失败必须**收拾掉刚拉起的子进程**：只 `?` 的话 child 被 drop 但不终止
    // （child_registry 注释明写 Drop 不会杀进程），于是每次「sock 未就绪」都会留下一个
    // 活着却永远不被复用的 php-fpm（反复失败即可把进程堆起来）。与 native_http 同一修法。
    if let Err(e) = wait_ready(&addr, Duration::from_secs(5)).await {
        crate::server::apps::child_registry::kill_child(&mut child);
        return Err(e);
    }
    Ok(PhpRuntime {
        addr,
        child: Some(child),
        kind: PhpKind::Fpm,
        chroot,
    })
}

#[cfg(not(unix))]
async fn start_fpm(
    key: &str,
    _lc: &ListenerConfig,
    app: &AppRouteConfig,
    _app_idx: usize,
    state_dir: &Path,
) -> Result<PhpRuntime> {
    // 非 Unix：无法 UDS fpm，直接走 cgi TCP 回退。
    start_cgi(key, _lc, app, state_dir).await
}

async fn start_cgi(
    key: &str,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    state_dir: &Path,
) -> Result<PhpRuntime> {
    let cgi_bin = resolve_php_bin(app, false)?;
    let docroot = resolve_docroot(lc, app);
    let tmp_dir = prepare_app_tmp(key)?;
    let cfg = app.sandbox_effective(&lc.global_sandbox);
    let workers = app.workers.max(1).to_string();

    #[cfg(unix)]
    {
        let sock_path = state_dir.join(format!("{key}-cgi.sock"));
        // 同 start_fpm：先回收上一代仍监听本 sock 的 php-cgi（命令行带 `-b <sock>`）。
        kill_stale_php(&[sock_path.as_path()], None, &sock_path);
        let _ = fs::remove_file(&sock_path);
        let abs_sock = abs_path(&sock_path);
        let mut cmd = Command::new(&cgi_bin);
        // 干净环境（同 fpm 路径）：php-cgi 的 worker 直接继承 spawn 时的 environ，
        // 默认继承会把别的应用的请求期 `.env` 永久带上。
        crate::server::apps::env_lock::apply_clean_env(&mut cmd, &[]);
        cmd.arg("-b")
            .arg(format!("{}", abs_sock.display()))
            // 临时目录也指到每应用独立目录（与 fpm 池的 php_admin_value 同口径）。
            .arg("-d")
            .arg(format!("sys_temp_dir={}", tmp_dir.display()))
            .arg("-d")
            .arg(format!("upload_tmp_dir={}", tmp_dir.display()))
            .arg("-d")
            .arg(format!("session.save_path={}", tmp_dir.display()))
            .arg("-d")
            .arg(format!("opcache.lockfile_path={}", tmp_dir.display()))
            .env("PHP_FCGI_CHILDREN", &workers)
            .env("PHP_FCGI_MAX_REQUESTS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        sandbox::apply_for_app(
            &mut cmd,
            "php",
            &cfg,
            Some(&docroot),
            Some(&state_dir),
            Some(&tmp_dir),
            Some(Path::new(&cgi_bin)),
        )?;
        let mut child = crate::server::apps::child_registry::spawn_tracked(
            &mut cmd,
            &format!("php-cgi {key}"),
        )
        .with_context(|| format!("spawn {cgi_bin}"))?;
        let addr = FcgiAddr::Unix(abs_sock);
        if let Err(e) = wait_ready(&addr, Duration::from_secs(5)).await {
            crate::server::apps::child_registry::kill_child(&mut child);
            return Err(e);
        }
        // php-cgi 的 `-b <sock>` 用 bind() 建 socket，权限 = 0777 & ~umask。umask 宽松
        // （0/002）或服务以 root 运行时，本地任意用户可直连该 FastCGI socket —— 而 FastCGI
        // 协议无鉴权，socket 权限是**唯一**防线：攻击者能执行 SCRIPT_FILENAME 指向的任意
        // PHP 文件（本机提权）。fpm 路径用 `listen.mode = 0660` + owner nobody 兜住了，
        // 这里显式收到 0600（与「只给 webserver 自己用」的口径一致）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600));
        }
        Ok(PhpRuntime {
            addr,
            child: Some(child),
            kind: PhpKind::Cgi,
            chroot: None,
        })
    }

    #[cfg(not(unix))]
    {
        use std::sync::atomic::Ordering;
        let port = TCP_PORT_SEQ.fetch_add(1, Ordering::Relaxed);
        let bind = format!("0.0.0.0:{port}");
        let mut cmd = Command::new(&cgi_bin);
        // 干净环境（同 unix 路径）。
        crate::server::apps::env_lock::apply_clean_env(&mut cmd, &[]);
        cmd.arg("-b")
            .arg(&bind)
            .env("PHP_FCGI_CHILDREN", &workers)
            .env("PHP_FCGI_MAX_REQUESTS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = crate::server::apps::child_registry::spawn_tracked(
            &mut cmd,
            &format!("php-cgi {key}"),
        )
        .with_context(|| format!("spawn {cgi_bin}"))?;
        let addr = FcgiAddr::Tcp(bind);
        if let Err(e) = wait_ready(&addr, Duration::from_secs(5)).await {
            crate::server::apps::child_registry::kill_child(&mut child);
            return Err(e);
        }
        Ok(PhpRuntime {
            addr,
            child: Some(child),
            kind: PhpKind::Cgi,
            chroot: None,
        })
    }
}

async fn wait_ready(addr: &FcgiAddr, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if fastcgi::probe(addr).await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("php FastCGI not ready: {:?}", addr)
}

/// 回收上一代 webserver 遗留的 fpm/cgi master（见 [`start_fpm`] 调用点）。
///
/// `needles` = 会出现在目标进程命令行里的绝对路径（fpm 的 `-y <conf>`、cgi 的
/// `-b <sock>`）；`pid_path` = 本 runtime 的 pidfile（fpm 自己写的）。只杀同时满足：
///   * 存活、pid>1、**不是本进程的直系子进程**（自己的子进程归 PHP_RUNTIME 管）；
///   * 命令行可读，程序名是 php-fpm/php-cgi，且含上述绝对路径之一。
///     这样 deploy 环境里别人起的同名 php-fpm（conf 在别的目录）不会被误杀。
#[cfg(unix)]
fn kill_stale_php(needles: &[&Path], pid_path: Option<&Path>, sock_path: &Path) {
    use crate::server::apps::child_registry;
    use std::os::unix::net::UnixStream;

    let mut pids: Vec<i32> = Vec::new();
    if let Some(pp) = pid_path {
        if let Ok(text) = fs::read_to_string(pp) {
            if let Ok(pid) = text.trim().parse::<i32>() {
                pids.push(pid);
            }
        }
    }
    // socket 还活着 ⇒ 一定有个 master 在监听；按命令行里的绝对路径找它
    // （pidfile 可能缺失/陈旧，不能只依赖它）。
    if UnixStream::connect(sock_path).is_ok() {
        for needle in needles {
            let s = abs_path(needle).display().to_string();
            for pid in child_registry::pids_with_cmdline(&s) {
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }
    }
    let needles_s: Vec<String> = needles
        .iter()
        .map(|p| abs_path(p).display().to_string())
        .collect();
    for pid in pids {
        if pid <= 1 || child_registry::is_direct_child(pid) {
            continue;
        }
        let Some(cmd) = child_registry::cmdline(pid) else {
            continue;
        };
        let prog = cmd.split_whitespace().next().unwrap_or("").trim_end_matches(':');
        let base = prog.rsplit('/').next().unwrap_or("");
        let is_php = base.starts_with("php-fpm") || base.starts_with("php-cgi");
        if !is_php || !needles_s.iter().any(|n| cmd.contains(n.as_str())) {
            continue;
        }
        log::warn!("php: 回收上一代遗留的 fpm/cgi pid={pid}（{cmd}）");
        let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
        for _ in 0..40 {
            if unsafe { libc::kill(pid, 0) } != 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        if unsafe { libc::kill(pid, 0) } == 0 {
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

fn resolve_php_bin(app: &AppRouteConfig, want_fpm: bool) -> Result<String> {
    if let Some(bin) = &app.php_bin {
        return Ok(remap_cli_php(bin, want_fpm));
    }
    // ① **先按目录扫版本，取最高的那个**。
    //
    //    为什么放在显式候选表之前：候选表里无版本的 `php-fpm` 排在 `php-fpm-8.5`
    //    前面，机器上只要存在一个指向旧版本的无版本链接，就会**静默选中旧版本**。
    //    PHP 的安全修复是按版本发的（例如 2026-10 的 CVE-2026-109618/109619「请求
    //    内存 UAF → 可 RCE」只存在于有修复的版本之外），静默降级选旧版是典型的
    //    「以为升过级」事故。
    if let Some(p) = scan_highest_versioned(want_fpm) {
        return Ok(p);
    }
    if want_fpm {
        for cand in [
            "php-fpm",
            "php-fpm85",
            "php-fpm84",
            "php-fpm-8.5",
            "php-fpm-8.4",
            "php-fpm-8.3",
            "php-fpm-8.2",
            "php-fpm83",
            "php-fpm82",
            "php-fpm81",
            "/usr/local/sbin/php-fpm",
            "/usr/local/sbin/php-fpm85",
            "/usr/local/sbin/php-fpm84",
            "/usr/local/sbin/php-fpm-8.5",
            "/usr/local/sbin/php-fpm-8.4",
            "/usr/local/sbin/php-fpm-8.3",
            "/usr/local/sbin/php-fpm-8.2",
            "/usr/local/sbin/php-fpm83",
            "/usr/local/sbin/php-fpm82",
        ] {
            if which_ok(cand) {
                return Ok(cand.to_string());
            }
        }
        bail!("php-fpm not found in PATH");
    }
    for cand in [
        "php-cgi",
        "php-cgi85",
        "php-cgi84",
        "php-cgi-8.5",
        "php-cgi-8.4",
        "php-cgi-8.3",
        "php-cgi-8.2",
        "php-cgi83",
        "php-cgi82",
        "/usr/local/bin/php-cgi",
        "/usr/local/bin/php-cgi83",
        "/usr/local/bin/php-cgi-8.4",
        "/usr/local/bin/php-cgi-8.3",
    ] {
        if which_ok(cand) {
            return Ok(cand.to_string());
        }
    }
    // 禁止把 php CLI 当 FastCGI；若仅有 php，尝试 remap 名
    if which_ok("php") {
        let remapped = remap_cli_php("php", want_fpm);
        if remapped != "php" && which_ok(&remapped) {
            return Ok(remapped);
        }
    }
    bail!("php-cgi not found in PATH");
}

/// 扫目录找**版本最高**的 `php-fpm-<major>.<minor>` / `php-cgi-<major>.<minor>`
/// （也认 `php-fpm85` 这种无点写法），返回绝对路径。
///
/// 只扫 `/usr/local/sbin`（OpenBSD 的 fpm 在这里）、`/usr/local/bin`、`/usr/sbin`、
/// `/usr/bin` 与 `PATH`。**版本优先于 PATH 顺序** —— 目的就是不让旧版本因为排在
/// 前面而被静默选中。
fn scan_highest_versioned(want_fpm: bool) -> Option<String> {
    let prog = if want_fpm { "php-fpm" } else { "php-cgi" };
    let mut dirs: Vec<PathBuf> = vec![
        PathBuf::from("/usr/local/sbin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/sbin"),
        PathBuf::from("/usr/bin"),
    ];
    if let Ok(path) = std::env::var("PATH") {
        for d in path.split(':').filter(|s| !s.is_empty()) {
            dirs.push(PathBuf::from(d));
        }
    }
    let mut best: Option<((u32, u32), String)> = None;
    for d in dirs {
        let rd = match fs::read_dir(&d) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let name = match e.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            let rest = match name.strip_prefix(prog) {
                Some(r) => r,
                // `php-fpm` 本身（无版本）走候选表，交给 PATH 语义。
                None => continue,
            };
            let ver = match parse_php_version(rest) {
                Some(v) => v,
                None => continue,
            };
            let path = e.path();
            if !path.is_file() {
                continue;
            }
            if best.as_ref().map(|(bv, _)| ver > *bv).unwrap_or(true) {
                best = Some((ver, path.display().to_string()));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// 解析 `-8.5` / `8.5` / `85` / `8.5.12` 这类版本片段为 `(major, minor)`；
/// 解析不出来返回 `None`（说明不是 PHP 版本化二进制，例如 `php-fpm-wrapper`）。
fn parse_php_version(s: &str) -> Option<(u32, u32)> {
    let s = s.trim_start_matches(['.', '-', '_']);
    if s.is_empty() {
        return None;
    }
    if let Some((maj, rest)) = s.split_once('.') {
        let maj: u32 = maj.parse().ok()?;
        let min: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let min: u32 = min.parse().ok()?;
        return Some((maj, min));
    }
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    // 后面必须跟着 `-pN` 之外的东西不允许（`php-fpm-8.5p1` 也可接受，digits 已截断）
    match digits.len() {
        0 => None,
        1 => Some((digits.parse().ok()?, 0)),
        2 => Some((digits[0..1].parse().ok()?, digits[1..2].parse().ok()?)),
        3 => Some((digits[0..1].parse().ok()?, digits[1..3].parse().ok()?)),
        _ => Some((digits[0..1].parse().ok()?, digits[1..3].parse().ok()?)),
    }
}

/// 把 CLI `php` 名字映射到同目录的 `php-fpm` / `php-cgi` 候选（§7.4：禁止把 CLI php
/// 当 FastCGI）。
///
/// 旧实现只认 basename == `php` 或 `starts_with("php.")`，且命中时返回**裸**
/// `"php-cgi"`。两个问题：
///   1. `php_bin = "php8.3"` / `"php83"` / `"php-cli"` 原样传入 —— fpm 用 `-y conf -F`
///      起 CLI php（立即失败），cgi 回退又用同一 CLI 二进制 `-b sock`（也失败）⇒ 每个
///      请求 5s+5s 双 spawn 双失败（进程泄漏叠加成按请求计费的 DoS）。
///   2. 命中时丢掉原目录（PATH 里多个 PHP 版本会换到另一个构建）。
///
/// 现在：识别 `php`/`php8.3`/`php83`/`php-cli` 等 CLI 名（**排除** `php-fpm`/`php-cgi`
/// 本身），返回**同目录**下的 `php-fpm`（want_fpm）或 `php-cgi` 名字。
fn remap_cli_php(bin: &str, want_fpm: bool) -> String {
    let path = Path::new(bin);
    let base = path.file_name().and_then(|s| s.to_str()).unwrap_or(bin);
    let lower = base.to_ascii_lowercase();
    let is_cli = if lower == "php" || lower == "php-cli" || lower == "phpcli" {
        true
    } else if let Some(rest) = lower.strip_prefix("php") {
        // `php<版本>`：php8.3 / php83 / php-8.3 / php_8；排除 php-fpm* / php-cgi*。
        !rest.is_empty()
            && !rest.starts_with("-fpm")
            && !rest.starts_with("fpm")
            && !rest.starts_with("-cgi")
            && !rest.starts_with("cgi")
            && rest
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_')
    } else {
        false
    };
    if !is_cli {
        return bin.to_string();
    }
    let target = if want_fpm { "php-fpm" } else { "php-cgi" };
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            dir.join(target).to_string_lossy().into_owned()
        }
        _ => target.to_string(),
    }
}

fn which_ok(bin: &str) -> bool {
    if bin.starts_with('/') {
        return Path::new(bin).is_file();
    }
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn resolve_docroot(lc: &ListenerConfig, app: &AppRouteConfig) -> PathBuf {
    let p = app.docroot.clone().unwrap_or_else(|| lc.root.clone());
    check_docroot_perm(&p);
    p
}

/// php-fpm 以 nobody 运行；docroot 若被 www 用户可写则可被 webshell 提升利用，
/// 这里在返回前对其做一次权限体检（仅日志，不阻断——远端 root 目录/\ /root 可能 0700）。
fn check_docroot_perm(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(p) {
        let mode = md.permissions().mode();
        if md.is_dir() && (mode & 0o022) != 0 {
            log::warn!(
                "php: docroot {:?} is group/world-writable (mode {:o}); php-fpm (nobody) may be able to write",
                p, mode & 0o7777
            );
        }
    }
}

fn resolve_script(
    docroot: &Path,
    app: &AppRouteConfig,
    uri_path: &str,
) -> Result<(PathBuf, String)> {
    let mut path = uri_path.to_string();
    // Strip app path prefix if configured (e.g. /php/index.php → index.php under docroot)
    // 必须匹配整段或 "/" 边界，避免 /phpfoo 命中 /php 前缀（与 mod.rs 一致）.
    // **并归一化尾斜杠**：配置写 `paths = ["/php/"]`（Admin 只校验「以 / 开头」，合法）时
    // 旧代码拿 `/php//` 去比前缀 ⇒ 前缀永远剥不掉 ⇒ 脚本路径变成 docroot/php/x.php → 404。
    // mod.rs / app_ffi::rel_script_path / cgi_script / native_http / tsx 都已归一化，只有
    // 这里漏了 —— 于是同一个 app 在 php 引擎下「配尾斜杠就 404」，其余引擎正常。
    for p in &app.paths {
        let p = p.trim_end_matches('/');
        if !p.is_empty() && (path == p || path.starts_with(&format!("{p}/"))) {
            path = path[p.len()..].to_string();
            if !path.starts_with('/') {
                path = format!("/{path}");
            }
            break;
        }
    }
    if path.ends_with('/') || path == "/" || path.is_empty() {
        let index = app.index.as_deref().unwrap_or("index.php");
        path = format!("/{index}");
    }
    // 从最长候选开始逐级回退（nginx fastcgi_split_path_info 语义）：
    //   /php/app.php/foo/bar → 脚本 <docroot>/app.php，PATH_INFO=/foo/bar
    // 此前把整段路径当文件名 ⇒ 这类 URI 一律 404，而 pretty-URL 框架默认这么请求。
    // `script_under_docroot` 自带穿越校验，回退不会放宽安全性。
    let mut end = path.len();
    loop {
        if let Ok(p) = fastcgi::script_under_docroot(docroot, &path[..end]) {
            if p.is_file() {
                return Ok((p, path[end..].to_string()));
            }
        }
        match path[..end].rfind('/') {
            Some(0) | None => break,
            Some(pos) => end = pos,
        }
    }
    // 都找不到：返回整段路径（调用方负责 404 + 节流日志）。
    let script = fastcgi::script_under_docroot(docroot, &path)?;
    Ok((script, String::new()))
}

/// `SCRIPT_NAME` 的 CGI 语义实现：**实际执行的脚本**在 URL 空间里的路径。
///
/// 为什么不能只拿 `SCRIPT_NAME = 请求 URI - PATH_INFO`：
///   * 目录索引请求 `/php/`（`app.index = index.php`）会执行 `docroot/index.php`，
///     但「URI 去掉 PATH_INFO」仍是 `/php/` —— nginx/Apache 都报 `/php/index.php`；
///   * 编码字符（`%20`/中文）解码后与实际文件名对应，URI 前缀则可能是编码形态。
///     以「docroot 相对脚本路径 + 命中的应用前缀」构造，才与 CGI/1.1 §4.1.13 一致。
///     docroot 与脚本不在同一词法前缀下（符号链接等）时退回旧的 URI 推导。
fn script_name_for(
    docroot: &Path,
    app: &AppRouteConfig,
    uri_path: &str,
    script: &Path,
    path_info: &str,
) -> String {
    let prefix = matched_app_prefix(app, uri_path);
    if let Ok(rel) = script.strip_prefix(docroot) {
        let rel = rel.to_string_lossy();
        if !rel.is_empty() {
            let rel = rel.replace('\\', "/");
            let rel = rel.trim_start_matches('/');
            return format!("{prefix}/{rel}");
        }
    }
    script_name_from_uri(uri_path, path_info)
}

/// 命中的应用前缀（`paths` 里最长匹配、尾斜杠已归一化）；catch-all 时为空串。
fn matched_app_prefix<'a>(app: &'a AppRouteConfig, path: &str) -> &'a str {
    let mut best: Option<&str> = None;
    for p in &app.paths {
        let p = p.trim_end_matches('/');
        if p.is_empty() {
            continue;
        }
        if (path == p || path.starts_with(&format!("{p}/")))
            && best.is_none_or(|b| p.len() > b.len()) {
                best = Some(p);
            }
    }
    best.unwrap_or("")
}

/// `SCRIPT_NAME` = 请求 URI 去掉 PATH_INFO 之后的部分（path_info 为空时就是整个 URI）。
fn script_name_from_uri(uri_path: &str, path_info: &str) -> String {
    if !path_info.is_empty() && uri_path.ends_with(path_info) {
        uri_path[..uri_path.len() - path_info.len()].to_string()
    } else {
        uri_path.to_string()
    }
}

/// 请求头补齐 `Host`：HTTP/2、HTTP/3 的权威信息在 `:authority` 伪头（hyper 映射到
/// `uri.authority()`），**没有**字面 `Host` 头。而 CGI/FastCGI 语义里 `HTTP_HOST` 就是
/// 请求的 Host —— 缺了它，PHP 应用（`$_SERVER['HTTP_HOST']`、按域名路由、生成绝对 URL）
/// 在 h2/h3 上与 h1 行为不一致（实测 h1 有 `HTTP_HOST`、h2c 无）。缺 `Host` 时用 URI
/// authority 补一条，使三种协议的 `HTTP_HOST` 一致。
fn headers_with_host(mut h: http::HeaderMap, uri: &http::Uri) -> http::HeaderMap {
    if !h.contains_key(http::header::HOST) {
        if let Some(a) = uri.authority() {
            if let Ok(v) = http::HeaderValue::from_str(a.as_str()) {
                h.insert(http::header::HOST, v);
            }
        }
    }
    h
}

fn runtime_key(port: u16, app_idx: usize) -> String {
    format!("{port}-{app_idx}")
}

fn abs_state_php() -> PathBuf {
    let p = PathBuf::from("state/php");
    abs_path(&p)
}

/// **每应用一个状态子目录**：`state/php/<key>/`。
///
/// 为什么不能共用 `state/php/`：降权后 spawn 前要把「本应用的状态目录」`chown` 给引擎
/// 用户（否则它写不了 socket/pid/log）。若所有 PHP 应用共用同一个目录，一次 chown
/// 就把**别的 PHP 应用**的 socket/error.log 也交给了本应用的用户 —— 应用之间可互读。
/// 每 key 一个目录后，chown 的作用域天然就是本应用。
fn state_dir_for_key(key: &str) -> PathBuf {
    let dir = abs_state_php().join(key);
    let _ = fs::create_dir_all(&dir);
    // 0700：即使哪天又退化成共用用户，同用户之外的进程也读不到。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    dir
}

/// 每个应用独立的临时目录（会话/上传临时文件）：`state/php/tmp/<key>`。
///
/// 为什么要独立：unveil 只揭示这个目录就够 PHP 用（否则得把整个 `/tmp` 交出去，
/// 那里有别的进程/别的应用的临时文件）；同时 PHP 的 `sys_temp_dir` /
/// `session.save_path` / `upload_tmp_dir` 都指向它，应用之间互相看不到会话。
fn prepare_app_tmp(key: &str) -> Result<PathBuf> {
    // 状态目录已经是每 key 一个，tmp 直接挂在它下面即可（再套一层 <key> 是冗余）。
    let dir = state_dir_for_key(key).join("tmp");
    fs::create_dir_all(&dir).with_context(|| format!("mkdir app tmp {}", dir.display()))?;
    Ok(dir)
}

fn abs_path(p: &Path) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(p)
}

fn canonicalize_display(p: &Path) -> String {
    fs::canonicalize(p)
        .unwrap_or_else(|_| abs_path(p))
        .display()
        .to_string()
}

#[cfg(test)]
mod cgi_names_tests {
    use super::script_name_from_uri;
    #[test]
    fn script_name_follows_cgi_semantics() {
        assert_eq!(
            script_name_from_uri("/php/index.php", ""),
            "/php/index.php"
        );
        assert_eq!(
            script_name_from_uri("/php/index.php/foo/bar", "/foo/bar"),
            "/php/index.php"
        );
        // path_info 为空（目录索引）→ SCRIPT_NAME 取整个 URI
        assert_eq!(script_name_from_uri("/php/", ""), "/php/");
    }
}

#[cfg(test)]
mod spawn_lock_tests {
    use super::spawn_lock;
    use std::sync::Arc;

    /// 冷启动串行化的关键不变量：**同一个 key 必须始终拿到同一把锁**（否则并发首请求
    /// 各拿一把锁，等于没锁 —— 就是「16 并发首请求拉起 9 个 php-fpm」那个缺陷），
    /// 不同 key 必须是不同的锁（不同应用的冷启动互不阻塞）。
    #[test]
    fn spawn_lock_is_per_key() {
        let a = spawn_lock("22095-0");
        let b = spawn_lock("22095-0");
        let c = spawn_lock("22095-1");
        assert!(Arc::ptr_eq(&a, &b), "同一 key 必须拿到同一把锁");
        assert!(!Arc::ptr_eq(&a, &c), "不同 key 必须是不同的锁");
    }
}

#[cfg(test)]
mod resolve_script_tests {
    use super::resolve_script;
    use crate::config::AppRouteConfig;
    use std::path::PathBuf;

    fn app(paths: &[&str]) -> AppRouteConfig {
        AppRouteConfig {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            enabled: true,
            engine: "php".into(),
            socket: None,
            extensions: vec!["php".into(), "".into()],
            index: Some("index.php".into()),
            php_bin: None,
            workers: 1,
            source_dir: None,
            out_dir: None,
            entry: vec![],
            watch: false,
            docroot: None,
            lib: None,
            deps_dir: None,
            init_timeout_secs: None,
            libc: None,
            sandbox: None,
        }
    }

    /// `paths = ["/php/"]`（尾斜杠）与 `["/php"]` 必须等价：前缀都要剥掉。
    /// 旧代码拿字面量 `/php/` 去比 `/php/index.php` ⇒ 剥不掉 ⇒ 找 docroot/php/index.php
    /// ⇒ 404（同一 app 只在 php 引擎上因尾斜杠配置失效，其余引擎走 rel_script_path 正常）。
    #[test]
    fn trailing_slash_prefix_is_stripped() {
        let dir = std::env::temp_dir().join("crucible_php_resolve_slash");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.php"), b"<?php echo 1;").unwrap();

        for paths in [vec!["/php/"], vec!["/php"]] {
            let a = app(&paths);
            let (script, pi) = resolve_script(&dir, &a, "/php/index.php").unwrap();
            assert_eq!(script, dir.join("index.php"), "paths={paths:?}");
            assert_eq!(pi, "");
            // 目录请求回落 index.php
            let (s2, _) = resolve_script(&dir, &a, "/php/").unwrap();
            assert_eq!(s2, dir.join("index.php"), "paths={paths:?}");
        }

        // PATH_INFO 回退（pretty URL）：脚本存在，其余段作为 PATH_INFO
        let a = app(&["/php/"]);
        let (s3, pi3) = resolve_script(&dir, &a, "/php/index.php/foo/bar").unwrap();
        assert_eq!(s3, dir.join("index.php"));
        assert_eq!(pi3, "/foo/bar");

        // 非前缀不误伤（/phplint 不属于 /php）
        let (s4, _) = resolve_script(&dir, &a, "/phplint/x.php").unwrap();
        assert_eq!(s4, PathBuf::from(dir.join("phplint/x.php")));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod script_name_tests {
    use super::*;

    fn app(paths: &[&str], index: &str) -> AppRouteConfig {
        AppRouteConfig {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            enabled: true,
            engine: "php".into(),
            socket: None,
            extensions: vec!["php".into()],
            index: Some(index.into()),
            php_bin: None,
            workers: 1,
            source_dir: None,
            out_dir: None,
            entry: vec![],
            watch: false,
            docroot: None,
            lib: None,
            deps_dir: None,
            init_timeout_secs: None,
            libc: None,
            sandbox: None,
        }
    }

    /// 目录索引必须报**实际脚本**的 URI 路径（nginx/Apache 语义），PATH_INFO 情形下
    /// 仍是脚本路径（不含尾部 PATH_INFO）。旧实现按「URI - PATH_INFO」推导，`/php/`
    /// 会报 `/php/`（真机）。
    #[test]
    fn script_name_uses_resolved_script() {
        let root = std::env::temp_dir().join(format!(
            "crucible-php-name-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.php"), b"<?php echo 1;").unwrap();
        let a = app(&["/php"], "index.php");
        // 目录索引
        assert_eq!(
            script_name_for(&root, &a, "/php/", &root.join("index.php"), ""),
            "/php/index.php"
        );
        // 直接请求 + PATH_INFO
        assert_eq!(
            script_name_for(&root, &a, "/php/index.php", &root.join("index.php"), ""),
            "/php/index.php"
        );
        assert_eq!(
            script_name_for(
                &root,
                &a,
                "/php/index.php/foo/bar",
                &root.join("index.php"),
                "/foo/bar"
            ),
            "/php/index.php"
        );
        // 子目录脚本
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/app.php"), b"<?php").unwrap();
        assert_eq!(
            script_name_for(&root, &a, "/php/sub/app.php", &root.join("sub/app.php"), ""),
            "/php/sub/app.php"
        );
        // 尾斜杠写法同样成立
        let a2 = app(&["/php/"], "index.php");
        assert_eq!(
            script_name_for(&root, &a2, "/php/", &root.join("index.php"), ""),
            "/php/index.php"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
