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
        proxy_unix(req, &sock, peer).await
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
    // Remove dead entry
    SIDECARS.lock().remove(key);

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
        .env("WEBSERVER_WORKERS", app.workers.max(1).to_string())
        .env("DOCUMENT_ROOT", docroot.display().to_string())
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log_file));
    let child = crate::server::apps::child_registry::spawn_tracked(
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
    bail!(
        "native sidecar sock not ready: {} (see {})",
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
async fn proxy_unix(
    req: Request<Incoming>,
    sock: &Path,
    peer: SocketAddr,
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

    let build = || -> Result<http::Request<Full<Bytes>>> {
        let mut builder = Request::builder()
            .method(parts.method.clone())
            .uri(parts.uri.clone());
        for (k, v) in parts.headers.iter() {
            builder = builder.header(k, v);
        }
        // P2-5：X-Forwarded-For 注入（追加语义；sidecar 是本地应用后端）。
        let xff = match parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(existing) => format!("{existing}, {peer_ip}"),
            None => peer_ip.clone(),
        };
        builder = builder.header("x-forwarded-for", xff);
        builder.body(Full::new(bytes.clone()))
            .context("build upstream req")
    };

    // P2-5：池化 checkout；坏连接重建后重试一次。
    let mut sender = checkout_unix(sock).await?;
    let resp = match sender.send_request(build()?).await {
        Ok(r) => r,
        Err(_) => {
            sender = checkout_unix(sock).await?;
            sender
                .send_request(build()?)
                .await
                .context("sidecar request")?
        }
    };
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
        proxy_unix(req, &sock, peer).await
    }
}

fn project_path(rel: &str) -> PathBuf {
    abs_path(Path::new(rel))
}
