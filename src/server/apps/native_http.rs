//! C/Go/Rust 无 .so 时的持久 Unix HTTP sidecar（Hyper 代理 + 简易连接池）。
//! 禁止 CGI fallback —— spawn 失败直接返回错误。

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

static SIDECARS: Lazy<Mutex<HashMap<String, Sidecar>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 每个 key 一把「创建中」锁：并发首次请求只允许一个真正 spawn。
///
/// 没有它时，N 个并发的首次请求会各自走完 entire ensure 流程：每个都
/// `remove_file(sock)` + spawn + 等到自己的 sock 就绪 —— 最后只有最后一个被登记进
/// SIDECARS，前面几个进程直接变成没人管、也不再被复用的孤儿（且共用同一个 sock 路径，
/// 后 spawn 的会把先 spawn 的 socket 覆盖掉）。
/// key 的集合由配置决定（port-app_idx-engine），数量有界，无需淘汰。
#[cfg(unix)]
static SPAWN_LOCKS: Lazy<Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(unix)]
fn spawn_lock(key: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    SPAWN_LOCKS
        .lock()
        .entry(key.to_string())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

struct Sidecar {
    sock: PathBuf,
    #[allow(dead_code)]
    child: Child,
}

/// Try FFI-less native sidecar for c/go/rust when `.so` is missing.
pub async fn try_handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
) -> Result<Response<BoxBody>> {
    #[cfg(not(unix))]
    {
        let _ = (req, lc, app, peer, app_idx);
        bail!("native_http sidecar requires Unix (OpenBSD/Linux)");
    }

    #[cfg(unix)]
    {
        let key = format!("{}-{}-{}", lc.port, app_idx, app.engine);
        ensure_sidecar(&key, lc, app).await?;
        let sock = {
            let map = SIDECARS.lock();
            map.get(&key)
                .map(|s| s.sock.clone())
                .context("sidecar missing")?
        };
        // 两条分支必须同语义：显式 socket 与自动探测的 `deps/bin/index` 都剥掉应用
        // 路由前缀（sidecar 挂在 `/jsp`、`/go` 这类前缀下，内部只认应用相对路径）。
        // 样例应用（c/go/rust）不回读请求路径做路由，剥前缀同样安全。
        let target = uds_target_uri(app, req.uri());
        proxy_unix(req, &sock, peer, Some(target)).await
    }
}

#[cfg(unix)]
async fn ensure_sidecar(key: &str, lc: &ListenerConfig, app: &AppRouteConfig) -> Result<()> {
    {
        let map = SIDECARS.lock();
        if let Some(s) = map.get(key) {
            if sock_alive(&s.sock) {
                return Ok(());
            }
        }
    }
    // 快路径未命中：串行化创建（拿锁后必须重查 SIDECARS —— 等锁期间可能已经有人建好了）。
    // 这是并发首请求只 spawn 一个进程的关键。
    let lock = spawn_lock(key);
    let _guard = lock.lock().await;
    {
        let map = SIDECARS.lock();
        if let Some(s) = map.get(key) {
            if sock_alive(&s.sock) {
                return Ok(());
            }
        }
    }
    // Remove dead entry（顺带收掉它的子进程：只从表里删掉等于把它变成没人管的孤儿，
    // sock 死了不代表进程已经退出）。
    if let Some(mut dead) = SIDECARS.lock().remove(key) {
        crate::server::apps::child_registry::kill_child(&mut dead.child);
    }

    let docroot = app
        .docroot
        .clone()
        .unwrap_or_else(|| lc.root.clone());
    let docroot = abs_canon(&docroot);
    let deps_bin = app
        .deps_dir
        .clone()
        .unwrap_or_else(|| docroot.join("deps"))
        .join("bin")
        .join("index");
    if !deps_bin.is_file() {
        bail!(
            "native sidecar binary missing: {} (no CGI fallback)",
            deps_bin.display()
        );
    }

    let state = abs_path(&PathBuf::from(format!("state/native/{key}")));
    fs::create_dir_all(&state).context("mkdir native state")?;
    let sock = abs_canon(&state.join("app.sock"));
    let _ = fs::remove_file(&sock);
    let log_path = state.join("sidecar.log");
    let log_file = fs::File::create(&log_path).context("sidecar.log")?;

    let mut cmd = Command::new(&deps_bin);
    cmd.current_dir(&docroot)
        .env("WEBSERVER_LISTEN_UNIX", sock.display().to_string())
        // 路由前缀：sidecar 自行决定是否剥离（JSP/Jetty 据此把 /jsp/x.jsp 映射到 docroot/x.jsp）。
        .env("WEBSERVER_APP_PREFIXES", app.paths.join(","))
        .env("WEBSERVER_WORKERS", app.workers.max(1).to_string())
        .env("DOCUMENT_ROOT", docroot.display().to_string())
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log_file));
    let mut child = crate::server::apps::child_registry::spawn_tracked(
        &mut cmd,
        &format!("native sidecar {key}"),
    )
    .with_context(|| format!("spawn sidecar {}", deps_bin.display()))?;

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if sock_alive(&sock) {
            SIDECARS.lock().insert(
                key.to_string(),
                Sidecar {
                    sock: sock.clone(),
                    child,
                },
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    // 超时失败路径必须**收拾掉刚拉起的子进程**：只 `bail!` 的话 child 被 drop 但不
    // 终止（child_registry 的注释也点明了 Drop 不会杀进程），于是每次「sock 未就绪」
    // 都会留下一个活着却永远不被复用的 sidecar —— 反复请求就能把进程数堆起来。
    // kill_child = SIGTERM → 短暂等待 → SIGKILL → wait 回收 → 注销注册表。
    crate::server::apps::child_registry::kill_child(&mut child);
    bail!(
        "native sidecar sock not ready: {} (see {}; spawned child killed)",
        sock.display(),
        log_path.display()
    );
}

#[cfg(unix)]
fn sock_alive(sock: &Path) -> bool {
    use std::os::unix::net::UnixStream;
    UnixStream::connect(sock).is_ok()
}

#[cfg(unix)]
/// P2-5：每 sidecar 常驻 h1 连接池——避免每请求新建 UDS 连接 + 握手；
/// 坏连接在 send 失败路径回收重连。键 = sock 路径。
static UDS_POOL: Lazy<
    Mutex<HashMap<PathBuf, Vec<hyper::client::conn::http1::SendRequest<Full<Bytes>>>>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));
#[cfg(unix)]
const UDS_POOL_CAP: usize = 16;

#[cfg(unix)]
async fn checkout_unix(sock: &Path) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    if let Some(sender) = UDS_POOL.lock().get_mut(sock).and_then(Vec::pop) {
        if sender.is_ready() {
            return Ok(sender);
        }
        // 池里取出的连接已坏：丢弃走新建。
    }
    let stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect {}", sock.display()))?;
    let (sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .context("h1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("native_http conn: {e}");
        }
    });
    Ok(sender)
}

#[cfg(unix)]
fn checkin_unix(sock: &Path, sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>) {
    if sender.is_ready() {
        let mut map = UDS_POOL.lock();
        let v = map.entry(sock.to_path_buf()).or_default();
        if v.len() < UDS_POOL_CAP {
            v.push(sender);
        }
    }
}

#[cfg(unix)]
/// 显式 `apps[].socket`（UDS sidecar）的目标路径：**剥掉应用路由前缀**。
///
/// 为什么必须剥：sidecar 是「挂在某个路径前缀下的应用」（JSP 挂在 `/jsp`、ActionBridge
/// 挂在 `/do`），Jetty 侧的 WebAppContext 是 `/`，它期望的是**应用内相对路径**。
/// 原样转发 `/jsp/index.jsp` 会让 Jetty 去 `<docroot>/jsp/index.jsp` 找文件 —— 不存在，
/// 于是恒 404（实测：`curl /jsp/` 拿到的是 Jetty 自己的 404 页，`/do/` 同样）。
/// 目录请求回落到 `index`（`/jsp/` → `/index.jsp`），与 FFI/cgi_script 同一套判据。
///
/// 只对**显式配置的 socket** 生效；自动探测的 `deps/bin/index` sidecar（c/go/rust 的
/// 无 .so 回退）保持原路径语义不变（那些样例应用自己打印 `r.URL.Path`）。
fn uds_target_uri(app: &AppRouteConfig, uri: &http::Uri) -> http::Uri {
    let rel = crate::server::apps::app_ffi::rel_script_path(app, uri.path());
    let s = match uri.query() {
        Some(q) => format!("{rel}?{q}"),
        None => rel,
    };
    s.parse::<http::Uri>().unwrap_or_else(|_| uri.clone())
}

async fn proxy_unix(
    req: Request<Incoming>,
    sock: &Path,
    peer: SocketAddr,
    target: Option<http::Uri>,
) -> Result<Response<BoxBody>> {
    use hyper::client::conn::http1;

    let (parts, body) = req.into_parts();
    // 任务 6（OOM 防护）：sidecar 请求体上限 32MiB；Limited 错误已装箱 → map_err。
    let collected = http_body_util::Limited::new(body, crate::server::h1::APP_BODY_CAP)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("collect body: {e}"))?;
    let bytes = collected.to_bytes();
    let peer_ip = peer.ip().to_string();

    let target = target.unwrap_or_else(|| parts.uri.clone());
    let build = || -> Result<http::Request<Full<Bytes>>> {
        let mut builder = Request::builder()
            .method(parts.method.clone())
            .uri(target.clone());
        for (k, v) in parts.headers.iter() {
            // **丢弃客户端自带的转发头**，否则客户端可以把任意 IP 放在最左边，
            // 后端拿它做日志/ACL 就是伪造点（proxy.rs 的 WS 路径早就是「跳过再写」，
            // 这里此前是「追加语义」，把客户端值原样传下去了）。
            if matches!(
                k.as_str(),
                "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" | "x-real-ip"
            ) {
                continue;
            }
            builder = builder.header(k, v);
        }
        // 只写真实 peer（sidecar 是本地应用后端，它要的就是「谁连到了 webserver」）。
        builder = builder.header("x-forwarded-for", peer_ip.clone());
        builder.body(Full::new(bytes.clone()))
            .context("build upstream req")
    };

    // P2-5：池化 checkout；坏连接重建后重试一次。
    // 池化 checkout；**只**在发送前检查连接可用性，不对已发出的请求重试。
    //
    // hyper 在「请求已写入、上游随即关闭」时同样返回 Err——旧代码对任何 Err 都
    // 无条件重建连接再发一次，非幂等请求（POST 等）会在上游被执行两次。
    // 真需要上游重试应由调用方按方法幂等性显式决定，传输层不该擅自复制请求。
    let mut sender = checkout_unix(sock).await?;
    if !sender.is_ready() {
        sender = checkout_unix(sock).await?;
    }
    let resp = sender.send_request(build()?).await.context("sidecar request")?;
    let (rparts, rbody) = resp.into_parts();
    // 任务 6（OOM 防护）：sidecar 响应体上限 64MiB。
    let rbytes = http_body_util::Limited::new(rbody, crate::server::h1::UPSTREAM_BODY_CAP)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("collect upstream body: {e}"))?
        .to_bytes();
    checkin_unix(sock, sender);
    let mut out = Response::builder().status(rparts.status);
    for (k, v) in rparts.headers.iter() {
        out = out.header(k, v);
    }
    Ok(out.body(full(rbytes)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(full("native_http response build error"))
            .unwrap()
    }))
}

fn abs_path(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

fn abs_canon(p: &Path) -> PathBuf {
    let a = abs_path(p);
    fs::canonicalize(&a).unwrap_or(a)
}

/// Whether a default/configured `.so` exists for in-process FFI.
pub fn lib_available(app: &AppRouteConfig, engine: &str) -> bool {
    if let Some(p) = &app.lib {
        return p.is_file();
    }
    project_path(&format!("target/app-engines/libapp_{engine}.so")).is_file()
}

/// Sidecar binary from init.sh (`deps/bin/index`) for c/go/rust when FFI .so is unavailable.
pub fn sidecar_available(app: &AppRouteConfig, lc: &ListenerConfig) -> bool {
    sidecar_binary(app, lc).is_some()
}

pub fn sidecar_binary(app: &AppRouteConfig, lc: &ListenerConfig) -> Option<PathBuf> {
    let docroot = app
        .docroot
        .clone()
        .unwrap_or_else(|| lc.root.clone());
    let deps_bin = app
        .deps_dir
        .clone()
        .unwrap_or_else(|| docroot.join("deps"))
        .join("bin")
        .join("index");
    let p = abs_path(&deps_bin);
    p.is_file().then_some(p)
}

/// Configured Unix domain socket for HTTP sidecar (e.g. JSP Jetty/Python shim).
pub fn uds_socket_available(app: &AppRouteConfig) -> bool {
    uds_socket_path(app).is_some_and(|p| {
        #[cfg(unix)]
        {
            sock_alive(&p)
        }
        #[cfg(not(unix))]
        {
            let _ = p;
            false
        }
    })
}

pub fn uds_socket_path(app: &AppRouteConfig) -> Option<PathBuf> {
    let raw = app.socket.as_ref()?;
    let p = raw.strip_prefix("unix:").unwrap_or(raw.as_str());
    let path = abs_path(Path::new(p));
    path.exists().then_some(path)
}

/// Proxy one request to a pre-started UDS HTTP sidecar (`apps[].socket`).
pub async fn try_handle_uds(
    req: Request<Incoming>,
    app: &AppRouteConfig,
    peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    #[cfg(not(unix))]
    {
        let _ = (req, app, peer);
        bail!("UDS sidecar requires Unix (OpenBSD/Linux)");
    }
    #[cfg(unix)]
    {
        let sock = uds_socket_path(app).context("apps[].socket missing")?;
        let target = uds_target_uri(app, req.uri());
        proxy_unix(req, &sock, peer, Some(target)).await
    }
}

fn project_path(rel: &str) -> PathBuf {
    abs_path(Path::new(rel))
}
