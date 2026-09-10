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
use std::time::Duration;

static PHP_RUNTIME: Lazy<Mutex<HashMap<String, PhpRuntime>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

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

/// Handle a PHP / FastCGI app request.
pub async fn handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
) -> Result<Response<BoxBody>> {
    let key = runtime_key(lc.port, app_idx);
    ensure_runtime(&key, lc, app, app_idx).await?;

    let addr = {
        let map = PHP_RUNTIME.lock();
        map.get(&key)
            .map(|r| r.addr.clone())
            .context("php runtime missing after ensure")?
    };

    let docroot = resolve_docroot(lc, app);
    let uri_path = req.uri().path().to_string();
    let script = resolve_script(&docroot, app, &uri_path)?;
    if !script.is_file() {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full(format!("php script not found: {}", script.display())))
            .unwrap());
    }

    let method = req.method().as_str().to_string();
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

    let docroot_abs = canonicalize_display(&docroot);
    let script_abs = canonicalize_display(&script);

    let fcgi = FcgiRequest {
        method,
        script_filename: script_abs,
        document_root: docroot_abs,
        request_uri,
        query_string: query,
        content_type,
        remote_addr: peer.ip().to_string(),
        server_name: lc
            .server_name
            .clone()
            .unwrap_or_else(|| "crucible".into()),
        server_port: lc.port,
        https: lc.ssl.is_some(),
        body,
        extra_params: HashMap::new(),
    };

    let resp = fastcgi::exchange(&addr, &fcgi)
        .await
        .with_context(|| format!("fastcgi to {:?}", addr))?;

    let mut builder = Response::builder().status(resp.status);
    for (k, v) in resp.headers.iter() {
        builder = builder.header(k, v);
    }
    Ok(builder.body(full(resp.body)).unwrap())
}

/// External FastCGI upstream (`engine = "fastcgi"`)，要求 `socket=`。
pub async fn handle_external(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    let sock = app
        .socket
        .as_deref()
        .context("fastcgi engine requires socket= (unix:/path or host:port)")?;
    let addr = FcgiAddr::parse(sock)?;
    let docroot = resolve_docroot(lc, app);
    let uri_path = req.uri().path().to_string();
    let script = resolve_script(&docroot, app, &uri_path)?;
    let method = req.method().as_str().to_string();
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

    let fcgi = FcgiRequest {
        method,
        script_filename: canonicalize_display(&script),
        document_root: canonicalize_display(&docroot),
        request_uri,
        query_string: query,
        content_type,
        remote_addr: peer.ip().to_string(),
        server_name: lc
            .server_name
            .clone()
            .unwrap_or_else(|| "crucible".into()),
        server_port: lc.port,
        https: lc.ssl.is_some(),
        body,
        extra_params: HashMap::new(),
    };
    let resp = fastcgi::exchange(&addr, &fcgi).await?;
    let mut builder = Response::builder().status(resp.status);
    for (k, v) in resp.headers.iter() {
        builder = builder.header(k, v);
    }
    Ok(builder.body(full(resp.body)).unwrap())
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
    let cached_addr = {
        let map = PHP_RUNTIME.lock();
        map.get(key).map(|rt| rt.addr.clone())
    };
    if let Some(addr) = cached_addr {
        if fastcgi::probe(&addr).await {
            return Ok(());
        }
        log::warn!("php sock dead, restarting {key}");
        PHP_RUNTIME.lock().remove(key);
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
"#,
        err = abs_path(&err_path).display(),
        pid = abs_path(&pid_path).display(),
        pool = key.replace(['/', '\\', ':'], "_"),
        listen = listen,
        workers = app.workers.max(1),
    );
    fs::write(&conf_path, conf).context("write php-fpm conf")?;

    let mut cmd = Command::new(&fpm_bin);
    cmd.arg("-y")
        .arg(abs_path(&conf_path))
        .arg("-F") // foreground; we manage as child
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = crate::server::apps::child_registry::spawn_tracked(
        &mut cmd,
        &format!("php-fpm {key}"),
    )
    .with_context(|| format!("spawn {fpm_bin}"))?;

    let addr = FcgiAddr::Unix(abs_path(&sock_path));
    wait_ready(&addr, Duration::from_secs(5)).await?;
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
        cmd.arg("-b")
            .arg(format!("{}", abs_sock.display()))
            .env("PHP_FCGI_CHILDREN", &workers)
            .env("PHP_FCGI_MAX_REQUESTS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = crate::server::apps::child_registry::spawn_tracked(
            &mut cmd,
            &format!("php-cgi {key}"),
        )
        .with_context(|| format!("spawn {cgi_bin}"))?;
        let addr = FcgiAddr::Unix(abs_sock);
        wait_ready(&addr, Duration::from_secs(5)).await?;
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
        cmd.arg("-b")
            .arg(&bind)
            .env("PHP_FCGI_CHILDREN", &workers)
            .env("PHP_FCGI_MAX_REQUESTS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = crate::server::apps::child_registry::spawn_tracked(
            &mut cmd,
            &format!("php-cgi {key}"),
        )
        .with_context(|| format!("spawn {cgi_bin}"))?;
        let addr = FcgiAddr::Tcp(bind);
        wait_ready(&addr, Duration::from_secs(5)).await?;
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
        let b = remap_cli_php(bin);
        return Ok(b);
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
        let remapped = remap_cli_php("php");
        if remapped != "php" && which_ok(&remapped) {
            return Ok(remapped);
        }
    }
    bail!("php-cgi not found in PATH");
}

fn remap_cli_php(bin: &str) -> String {
    let base = Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(bin);
    if base == "php" || base.starts_with("php.") {
        return "php-cgi".into();
    }
    bin.to_string()
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

fn resolve_script(docroot: &Path, app: &AppRouteConfig, uri_path: &str) -> Result<PathBuf> {
    let mut path = uri_path.to_string();
    // Strip app path prefix if configured (e.g. /php/index.php → index.php under docroot)
    // 必须匹配整段或 "/" 边界，避免 /phpfoo 命中 /php 前缀（与 mod.rs 一致）.
    for p in &app.paths {
        if !p.is_empty() && (path == *p || path.starts_with(&format!("{p}/"))) {
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
    let script = fastcgi::script_under_docroot(docroot, &path)?;
    Ok(script)
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
