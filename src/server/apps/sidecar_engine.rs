//! Shared FFI / Unix sidecar dispatch for optional app engines.

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::deps::DepsEnv;
use crate::server::apps::{app_ffi, native_http};
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;

/// h2/h3 字节路径的 sidecar 墙钟上限：整段（发送 + 收集响应体）共用一个 deadline。
/// sidecar 接受连接后不回包（应用卡死/死锁）时，请求任务与 UDS fd 不能永久挂着 ——
/// 此前这条路径完全裸奔（proxy/fastcgi/CGI 都有各自超时）。
const SIDECAR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub async fn handle_with_fallback(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    engine: &str,
    stub_body: &str,
) -> Result<Response<BoxBody>> {
    if native_http::lib_available(app, engine) {
        return app_ffi::execute(req, lc, app, peer).await;
    }
    // **顺序**：显式配置且**活着**的 `socket` 优先于自动探测的 `deps/bin/index`。
    //
    // 为什么：`sidecar_available` 只判「`deps/bin/index` **这个文件存在**」，并不验证它跑得起来；
    // 而 `uds_socket_available` 会真的去 connect（`sock_alive`）。JSP 就是典型：
    // `www-apps/jsp/init.sh` 会生成 `deps/bin/index` 包装脚本，但 `target/jsp-sidecar.jar`
    // 可能压根没构建 ⇒ 走 sidecar 分支必然失败，**永远到不了**配置里那条 `socket = "..."`，
    // 于是 `/jsp/`、`/do/` 恒 502，而且日志还说「sidecar sock not ready」**误导**排查
    // （实测：同一台机上该 socket 直接 `nc -U` 是通的）。
    //
    // 为什么这是**无回归**的改动：`uds_socket_available` 要求 socket **活着** —— 配了但没起
    // 的 socket 会照旧往下落到 sidecar 分支（与今天完全一致）。只有「显式配了、而且真的能连」
    // 的时候才会抢在自动探测之前 —— 那本来就是运维写在配置里的意图。
    if native_http::uds_socket_available(app) {
        return native_http::try_handle_uds(req, app, peer).await;
    }
    if native_http::sidecar_available(app, lc) {
        return native_http::try_handle(req, lc, app, peer, app_idx).await;
    }
    // No FFI .so and no sidecar/UDS — do not pretend success.
    let _ = stub_body;
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(format!(
            "502 Bad Gateway: engine `{engine}` unavailable (no libapp_{engine}.so, sidecar, or socket)\n"
        )))
        .unwrap())
}

/// [`handle_with_fallback`] 的**字节版**（h2/h3 simple 路径）：请求体已在协议层收齐为
/// `Bytes`，与 h1 走同一条 fallback 链（FFI .so → 显式且存活的 UDS → `deps/bin/index`
/// 持久 sidecar → 502），只是传输层按 `Bytes` 收发。
///
/// 为什么不直接复用 `handle_with_fallback`：它的入参是 `Request<Incoming>`，而
/// `hyper::body::Incoming` 没有公开构造函数（hyper 1.9 `pub(crate) fn new_channel`），
/// 字节路径无法把已收齐的 body 包回 `Incoming`。
pub async fn handle_with_fallback_simple(
    req: &Request<Bytes>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    engine: &str,
    deps: &DepsEnv,
) -> Result<Response<Bytes>> {
    if native_http::lib_available(app, engine) {
        let outcome = app_ffi::execute_simple(req, lc, app, peer, deps).await?;
        return Ok(app_ffi::simple_response_from_outcome(outcome));
    }
    // 与 h1 同序：显式配置的 socket（活着才算）优先，其次自动探测的 sidecar。
    #[cfg(unix)]
    {
        if native_http::uds_socket_available(app) {
            let sock = native_http::uds_socket_path(app).context("apps[].socket missing")?;
            // 显式 socket 的 sidecar（JSP/do）：**剥掉路由前缀**再转发 —— Jetty 的
            // WebAppContext 是 `/`，原样发 `/jsp/index.jsp` 会让它去 docroot/jsp/ 找文件，
            // 恒 404（与 h1 侧 native_http::try_handle_uds 同一判据）。
            let target = crate::server::apps::app_ffi::rel_script_path(app, req.uri().path());
            return proxy_uds_simple(req, &sock, peer, Some(target)).await;
        }
        if native_http::sidecar_available(app, lc) {
            let sock = ensure_sidecar_simple(lc, app, app_idx).await?;
            // 与 h1 侧同语义：自动 sidecar 同样剥掉路由前缀（sidecar 挂在 /ruby、/go
            // 这类前缀下，内部只认应用相对路径）。
            let target = crate::server::apps::app_ffi::rel_script_path(app, req.uri().path());
            return proxy_uds_simple(req, &sock, peer, Some(target)).await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (req, lc, app, peer, app_idx, deps);
    }
    // 「无后端可用」是**引擎不可用**（配置/构建问题），与 h1 `handle_with_fallback` 同口径：
    // 返回一个固定的 502 **响应**（而不是 Err）—— Err 会被 `simple_engine_error` 换成通用
    // 文本「502 Bad Gateway (engine error)」，于是同一个 URL 的 502 错误体在 h1 与 h2/h3
    // 上不同（跨协议不一致）。这里给出与 h1 逐字相同的 502 文本。
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Bytes::from(format!(
            "502 Bad Gateway: engine `{engine}` unavailable (no libapp_{engine}.so, sidecar, or socket)\n"
        )))
        .unwrap())
}

/// 客户端转发头：只能由本代理重写，透传等于让客户端伪造来源。
fn is_client_forward_header(lower: &str) -> bool {
    matches!(
        lower,
        "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" | "x-real-ip"
    )
}

/// hop-by-hop 头（RFC 9110 §7.6.1）：只为当前这条连接服务，不能带进响应/请求的另一端。
fn is_hop_by_hop(lower: &str) -> bool {
    matches!(
        lower,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// 上游响应 → 下游响应（字节版）：过滤 hop-by-hop（含 `Connection` 点名的头）与
/// 和真实 body 长度不符的 `Content-Length`（否则 h1 keep-alive 上是响应走私，
/// h2/h3 上对端判 CL 不符直接 RST 流）。与 proxy.rs 对同一天花板同一口径。
fn upstream_response(rparts: http::response::Parts, body: Bytes) -> Result<Response<Bytes>> {
    let conn_tokens: Vec<String> = rparts
        .headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let mut builder = Response::builder().status(rparts.status);
    for (k, v) in rparts.headers.iter() {
        let lower = k.as_str().to_ascii_lowercase();
        if is_hop_by_hop(&lower) || conn_tokens.iter().any(|t| t == &lower) {
            continue;
        }
        if lower == "content-length" {
            let declared = v.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok());
            if declared != Some(body.len() as u64) {
                continue;
            }
        }
        builder = builder.header(k, v);
    }
    builder
        .body(body)
        .context("build native sidecar response (simple)")
}

#[cfg(unix)]
pub(crate) async fn proxy_uds_simple(
    req: &Request<Bytes>,
    sock: &std::path::Path,
    peer: SocketAddr,
    path_override: Option<String>,
) -> Result<Response<Bytes>> {
    use hyper::client::conn::http1;
    use http_body_util::BodyExt as _;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect {}", sock.display()))?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .context("h1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("native_http simple conn: {e}");
        }
    });

    // h2/h3 的 URI 带 scheme+authority（:authority），而 UDS sidecar 是 origin server：
    // 目标一律改写为 origin-form（path?query），否则请求行会写成 absolute-form，sidecar
    // 可能解析失败/路由错。h2 也不保证有 Host 头 ⇒ authority 存在而 Host 缺失时补上。
    let target = match path_override {
        Some(p) => match req.uri().query() {
            Some(q) => format!("{p}?{q}"),
            None => p,
        },
        None => req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string()),
    };
    let mut builder = Request::builder().method(req.method().clone()).uri(target);
    let mut has_host = false;
    for (k, v) in req.headers() {
        let lower = k.as_str().to_ascii_lowercase();
        if lower == "host" {
            has_host = true;
        }
        if is_client_forward_header(&lower) || is_hop_by_hop(&lower) {
            continue;
        }
        builder = builder.header(k, v);
    }
    if !has_host {
        if let Some(auth) = req.uri().authority() {
            builder = builder.header(http::header::HOST, auth.as_str());
        }
    }
    builder = builder.header("x-forwarded-for", peer.ip().to_string());
    let upstream = builder
        .body(http_body_util::Full::new(req.body().clone()))
        .context("build upstream req")?;

    // 整段一个 deadline：发送、响应头、响应体收集都算在内。
    //
    // 超时必须同时**终止受管的 sidecar 进程**（与 native_http 同一判据）：挂死的进程仍占着
    // 监听 socket，`sock_alive` 恒真 ⇒ 该 sidecar 永远留在缓存里，之后每个请求都要等满
    // 30s 才 502，永不自愈。杀掉后下一个请求重新拉起。显式 `apps[].socket`（运维自己起的
    // Jetty）不在受管表里，不会被误杀。
    let (rparts, rbytes) = tokio::time::timeout(SIDECAR_TIMEOUT, async {
        let resp = sender
            .send_request(upstream)
            .await
            .context("sidecar request")?;
        let (rparts, rbody) = resp.into_parts();
        let rbytes = http_body_util::Limited::new(rbody, crate::server::h1::UPSTREAM_BODY_CAP)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("collect upstream body: {e}"))?
            .to_bytes();
        Ok::<_, anyhow::Error>((rparts, rbytes))
    })
    .await
    .map_err(|_| {
        kill_managed_sidecar_simple_by_sock(sock);
        anyhow::anyhow!("sidecar timeout after {SIDECAR_TIMEOUT:?}")
    })??;
    upstream_response(rparts, rbytes)
}

/// 代理超时后杀掉**受管**（`SIDECARS_SIMPLE` 表里登记的）sidecar 进程（见调用点说明）。
#[cfg(unix)]
fn kill_managed_sidecar_simple_by_sock(sock: &std::path::Path) -> bool {
    let key = {
        let map = SIDECARS_SIMPLE.lock();
        map.iter().find(|(_, s)| s.sock == sock).map(|(k, _)| k.clone())
    };
    let Some(key) = key else {
        return false;
    };
    if let Some(mut dead) = SIDECARS_SIMPLE.lock().remove(&key) {
        log::warn!(
            "sidecar(simple): {} 代理超时（客户端已 502）→ 终止受管进程，后续请求将重启",
            dead.sock.display()
        );
        crate::server::apps::child_registry::kill_child(&mut dead.child);
        return true;
    }
    false
}

#[cfg(unix)]
fn sock_alive(sock: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(sock).is_ok()
}

#[cfg(unix)]
struct SimpleSidecar {
    sock: std::path::PathBuf,
    child: std::process::Child,
}

/// h2/h3 字节路径的 sidecar 注册表（键与 native_http 相同：port-app_idx-engine）。
///
/// 与 native_http 的注册表并存：两边用**同一个 sock 路径**（`state/native/{key}/app.sock`），
/// 且 spawn 前先 `sock_alive` 探测，所以一条协议先起的 sidecar 会被另一条复用；
/// 只有「两条协议首次请求同时到达」的窄窗口可能各 spawn 一个（后启动的赢下 socket）。
/// 彻底消除重复需要 native_http 暴露字节入口（跨组项，见工单总结）。
#[cfg(unix)]
static SIDECARS_SIMPLE: once_cell::sync::Lazy<
    parking_lot::Mutex<std::collections::HashMap<String, SimpleSidecar>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

#[cfg(unix)]
static SIMPLE_SPAWN_LOCKS: once_cell::sync::Lazy<
    parking_lot::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

/// 确保 `deps/bin/index` 持久 sidecar 已启动，返回其 UDS 路径。
/// 与 native_http::ensure_sidecar 同一套约定（env、state 目录、5s 就绪等待、
/// 失败 kill 子进程），保证 h1/h2/h3 起出来的是同一种进程。
#[cfg(unix)]
async fn ensure_sidecar_simple(
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    app_idx: usize,
) -> Result<std::path::PathBuf> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let key = format!("{}-{}-{}", lc.port, app_idx, app.engine);
    let state = abs_path(&std::path::PathBuf::from(format!("state/native/{key}")));
    std::fs::create_dir_all(&state).context("mkdir native state")?;
    let sock = abs_canon(&state.join("app.sock"));

    // 别的协议（h1）或本注册表之外的实例已经把这个 socket 起好了：直接复用，
    // 绝不能 remove_file 抢走它。
    if sock_alive(&sock) {
        return Ok(sock);
    }
    {
        let map = SIDECARS_SIMPLE.lock();
        if let Some(s) = map.get(&key) {
            if sock_alive(&s.sock) {
                return Ok(s.sock.clone());
            }
        }
    }

    let lock = SIMPLE_SPAWN_LOCKS
        .lock()
        .entry(key.clone())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;
    // 等锁期间可能已被别人建好（或已由另一协议拉起）。
    if sock_alive(&sock) {
        return Ok(sock);
    }
    {
        let map = SIDECARS_SIMPLE.lock();
        if let Some(s) = map.get(&key) {
            if sock_alive(&s.sock) {
                return Ok(s.sock.clone());
            }
        }
    }
    // 死条目：杀进程再摘除（只删表会留下孤儿）。
    if let Some(mut dead) = SIDECARS_SIMPLE.lock().remove(&key) {
        crate::server::apps::child_registry::kill_child(&mut dead.child);
    }

    let deps_bin = native_http::sidecar_binary(app, lc)
        .context("native sidecar binary missing: deps/bin/index (no CGI fallback)")?;
    let docroot = abs_canon(&app.docroot.clone().unwrap_or_else(|| lc.root.clone()));
    let _ = std::fs::remove_file(&sock);
    let log_path = state.join("sidecar.log");
    let log_file = std::fs::File::create(&log_path).context("sidecar.log")?;

    let mut cmd = Command::new(&deps_bin);
    // 干净环境（与 h1 `native_http::ensure_sidecar` 同一判据）：sidecar 是长驻进程，spawn
    // 时刻可能落在别的应用的请求期 `.env` 窗口内 —— 默认继承 environ 会把别人的密钥永久
    // 烤进 sidecar 环境。启动期基底 + 空请求 `.env`。
    crate::server::apps::env_lock::apply_clean_env(&mut cmd, &[]);
    cmd.current_dir(&docroot)
        .env("WEBSERVER_LISTEN_UNIX", sock.display().to_string())
        // 与 h1 `native_http::ensure_sidecar` 同一套 env：sidecar（ruby 等）据此
        // 兜底剥离路由前缀。此前 h2/h3 这条 spawn 路径漏了它，同一 sidecar 由 h1 起
        // 与由 h2 起拿到的环境不同（版本间不一致）。
        .env("WEBSERVER_APP_PREFIXES", app.paths.join(","))
        .env("WEBSERVER_WORKERS", app.workers.max(1).to_string())
        .env("DOCUMENT_ROOT", docroot.display().to_string())
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log_file));
    let mut child = crate::server::apps::child_registry::spawn_tracked(
        &mut cmd,
        &format!("native sidecar {key} (simple)"),
    )
    .with_context(|| format!("spawn sidecar {}", deps_bin.display()))?;

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if sock_alive(&sock) {
            SIDECARS_SIMPLE.lock().insert(
                key,
                SimpleSidecar {
                    sock: sock.clone(),
                    child,
                },
            );
            return Ok(sock);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    // 超时必须收拾刚拉起的子进程（Child 被 drop 不会终止进程）。
    crate::server::apps::child_registry::kill_child(&mut child);
    bail!(
        "native sidecar sock not ready: {} (see {}; spawned child killed)",
        sock.display(),
        log_path.display()
    )
}

#[cfg(unix)]
fn abs_path(p: &std::path::Path) -> std::path::PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(p)
    }
}

#[cfg(unix)]
fn abs_canon(p: &std::path::Path) -> std::path::PathBuf {
    let a = abs_path(p);
    std::fs::canonicalize(&a).unwrap_or(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 上游响应必须过滤 hop-by-hop/Connection 点名的头，并丢弃与实际 body 不符的
    /// Content-Length；其余头（Set-Cookie 等）原样保留。
    #[test]
    fn upstream_response_filters_hop_by_hop_and_bad_cl() {
        let (parts, _) = Response::builder()
            .status(200)
            .header("transfer-encoding", "chunked")
            .header("connection", "keep-alive, x-internal")
            .header("keep-alive", "timeout=5")
            .header("x-internal", "secret")
            .header("content-length", "999")
            .header("set-cookie", "a=1")
            .body(())
            .unwrap()
            .into_parts();
        let r = upstream_response(parts, Bytes::from_static(b"hello")).unwrap();
        assert!(r.headers().get("transfer-encoding").is_none());
        assert!(r.headers().get("connection").is_none());
        assert!(r.headers().get("keep-alive").is_none());
        assert!(r.headers().get("x-internal").is_none(), "Connection 点名的头必须过滤");
        assert!(r.headers().get("content-length").is_none());
        assert_eq!(r.headers().get("set-cookie").unwrap(), "a=1");

        // CL 恰等于真实长度时保留（HEAD 场景仍能给出实体长度）。
        let (parts, _) = Response::builder()
            .status(200)
            .header("content-length", "5")
            .body(())
            .unwrap()
            .into_parts();
        let r = upstream_response(parts, Bytes::from_static(b"hello")).unwrap();
        assert_eq!(r.headers().get("content-length").unwrap(), "5");
    }

    #[test]
    fn hop_by_hop_list_is_complete() {
        for h in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(is_hop_by_hop(h), "{h} 应为 hop-by-hop");
        }
        assert!(!is_hop_by_hop("content-type"));
        assert!(is_client_forward_header("x-forwarded-for"));
        assert!(!is_client_forward_header("x-custom"));
    }
}
