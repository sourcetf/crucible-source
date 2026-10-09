//! PHP 引擎：优先 php-fpm（绝对路径 conf + UDS），失败回退 php-cgi + PHP_FCGI_CHILDREN。
//! 禁止把 CLI `php` 当 FastCGI（自动 remap 到 php-cgi）。

use super::fastcgi::{self, FcgiAddr, FcgiRequest};
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
    // 任务 6（OOM 防护）：引擎请求体上限 32MiB，超限直接 413（不再无界缓冲）。
    let body = match http_body_util::Limited::new(
        req.into_body(),
        crate::server::h1::APP_BODY_CAP,
    )
    .collect()
    .await
    {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Ok(Response::builder()
                .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                .body(full("request body too large"))
                .unwrap())
        }
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

    let addr = {
        let map = PHP_RUNTIME.lock();
        map.get(&key)
            .map(|r| r.addr.clone())
            .context("php runtime missing after ensure")?
    };

    let docroot = resolve_docroot(lc, app);
    let uri_path = uri_path.to_string();
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
    let script_name = script_name_from_uri(&uri_path, &path_info);

    let fcgi = FcgiRequest {
        method,
        script_filename: script_abs,
        document_root: docroot_abs,
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
    // 任务 6（OOM 防护）：同上，32MiB 上限。
    let body = match http_body_util::Limited::new(
        req.into_body(),
        crate::server::h1::APP_BODY_CAP,
    )
    .collect()
    .await
    {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Ok(Response::builder()
                .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                .body(full("request body too large"))
                .unwrap())
        }
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
    let uri_path = uri_path.to_string();
    let (script, path_info) = resolve_script(&docroot, app, &uri_path)?;
    if !script.is_file() {
        return Ok(PhpOutcome::NotFound);
    }

    let script_abs = canonicalize_display(&script);
    let script_name = script_name_from_uri(&uri_path, &path_info);

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

    let state_dir = abs_state_php();
    fs::create_dir_all(&state_dir).context("mkdir state/php")?;

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

    let rt = start_cgi(key, app, &state_dir).await?;
    PHP_RUNTIME.lock().insert(key.to_string(), rt);
    Ok(())
}

#[cfg(unix)]
async fn start_fpm(
    key: &str,
    _lc: &ListenerConfig,
    app: &AppRouteConfig,
    _app_idx: usize,
    state_dir: &Path,
) -> Result<PhpRuntime> {
    let fpm_bin = resolve_php_bin(app, true)?;
    let sock_path = state_dir.join(format!("{key}.sock"));
    let conf_path = state_dir.join(format!("{key}.conf"));
    let pid_path = state_dir.join(format!("{key}.pid"));
    let err_path = state_dir.join(format!("{key}-error.log"));
    let _ = fs::remove_file(&sock_path);

    // 全部绝对路径；禁止 prefix=/（部分 fpm 报 unknown entry）
    let listen = format!("{}", abs_path(&sock_path).display());
    let conf = format!(
        r#"[global]
error_log = {err}
daemonize = no
pid = {pid}

[{pool}]
user = nobody
group = nobody
listen = {listen}
listen.owner = nobody
listen.group = nobody
listen.mode = 0660
listen.backlog = 4096
pm = static
pm.max_children = {workers}
chdir = /tmp
catch_workers_output = yes
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
        workers = app.workers.max(1),
    );
    fs::write(&conf_path, conf).context("write php-fpm conf")?;

    let mut cmd = Command::new(&fpm_bin);
    // 干净环境：php-fpm 是长驻进程，spawn 时刻可能落在别的应用的请求期 `.env` 窗口内。
    // fpm 池默认 clear_env=yes（worker 环境会被清），但 master 自己会永久留下别人的密钥。
    // 统一用「启动期基底」spawn（与 cgi_script / sidecar 同一判据）。
    crate::server::apps::env_lock::apply_clean_env(&mut cmd, &[]);
    cmd.arg("-y")
        .arg(abs_path(&conf_path))
        .arg("-F") // foreground; we manage as child
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    start_cgi(key, app, state_dir).await
}

async fn start_cgi(key: &str, app: &AppRouteConfig, state_dir: &Path) -> Result<PhpRuntime> {
    let cgi_bin = resolve_php_bin(app, false)?;
    let workers = app.workers.max(1).to_string();

    #[cfg(unix)]
    {
        let sock_path = state_dir.join(format!("{key}-cgi.sock"));
        let _ = fs::remove_file(&sock_path);
        let abs_sock = abs_path(&sock_path);
        let mut cmd = Command::new(&cgi_bin);
        // 干净环境（同 fpm 路径）：php-cgi 的 worker 直接继承 spawn 时的 environ，
        // 默认继承会把别的应用的请求期 `.env` 永久带上。
        crate::server::apps::env_lock::apply_clean_env(&mut cmd, &[]);
        cmd.arg("-b")
            .arg(format!("{}", abs_sock.display()))
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
        return Ok(PhpRuntime {
            addr,
            child: Some(child),
            kind: PhpKind::Cgi,
        });
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

fn resolve_php_bin(app: &AppRouteConfig, want_fpm: bool) -> Result<String> {
    if let Some(bin) = &app.php_bin {
        return Ok(remap_cli_php(bin, want_fpm));
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
