//! Application engine dispatch: try_handle / match_app / dispatch.

pub mod app_ffi;
pub mod asp;
pub mod aspnet;
/// 引擎失败的统一响应：**不回显** `{e:#}`。
///
/// `{e:#}` 是完整 anyhow 链，里面是 docroot 绝对路径、socket 路径、被 spawn 的二进制
/// 路径、库/后端错误文本 —— 而拿到它的人只是任意一个能命中该路由的客户端。项目里
/// `proxy::try_proxy` 早就按这个口径处理（并写明了原因），本文件这十几处是漏网的。
/// 细节只进本地日志（本项目明确要求「日志不要脱敏」，日志就是排障入口）。
fn engine_error(engine: &str, e: &anyhow::Error) -> Response<BoxBody> {
    log::warn!("{engine} engine error: {e:#}");
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(full("502 Bad Gateway (engine error)"))
        .unwrap()
}

pub mod cgi_script;
pub mod child_registry;
pub mod deps;
pub mod env_lock;
pub mod fastcgi;
#[cfg(all(feature = "go_shm_ipc", unix))]
pub mod go_shm;
pub mod jsp;
pub mod lua;
pub mod native_http;
pub mod php;
pub mod script_ffi;
pub mod sidecar_engine;
pub mod tsx;

use crate::config::{AppRouteConfig, FileOpenMode, ListenerConfig};
use crate::server::h1::{full, BoxBody};
use crate::server::live_config::LiveConfig;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

pub async fn try_handle(
    req: Request<Incoming>,
    live: &Arc<LiveConfig>,
    lc: &ListenerConfig,
    peer: SocketAddr,
) -> Option<Response<BoxBody>> {
    let path = req.uri().path().to_string();
    let ext = Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();

    // file_open preview/download skips engines (§16.2 path-level).
    match lc.file_open_mode(&path) {
        FileOpenMode::Preview | FileOpenMode::Download => return None,
        FileOpenMode::Execute | FileOpenMode::Auto => {}
    }

    let (app_idx, app) = match_app_indexed(lc, &path, &ext)?;
    // Clone app config for async moves; keep indices for php/native keys.
    let app = app.clone();
    // P1-1：deps 的 .env 变量随请求 extensions 下发（引擎侧按需读取），避免改所有引擎签名。
    let deps_env = match deps::try_cached(lc, &app).await {
        Ok(e) => e,
        Err(e) => {
            log::warn!("deps ensure failed: {e:#}");
            deps::DepsEnv::default()
        }
    };
    let mut req = req;
    req.extensions_mut().insert(deps_env);
    Some(dispatch(req, live, lc, &app, app_idx, peer).await)
}

/// Path/ext only — does not consume the request body.
pub fn would_handle(lc: &ListenerConfig, path: &str) -> bool {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if let FileOpenMode::Preview | FileOpenMode::Download = lc.file_open_mode(path) {
        return false;
    }
    match_app(lc, path, ext).is_some()
}

/// H2/H3 路径：请求体已在协议层收齐（Request<Bytes>），P1-9 连同 P1-1 的 .env 变量
/// 一起交给引擎；deps 冷路径 ensure 失败不阻塞响应（记日志后用空环境继续）。
pub async fn try_handle_simple(
    req: &Request<Bytes>,
    lc: &ListenerConfig,
    peer: SocketAddr,
) -> Option<Response<Bytes>> {
    let path = req.uri().path();
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    // file_open preview/download 优先于引擎（§3.2，与 try_handle 一致）。
    if let FileOpenMode::Preview | FileOpenMode::Download = lc.file_open_mode(path) {
        return None;
    }
    let app = match_app(lc, path, ext)?;
    let deps_env = match deps::try_cached(lc, app).await {
        Ok(e) => e,
        Err(e) => {
            log::warn!("deps ensure failed (simple path): {e:#}");
            deps::DepsEnv::default()
        }
    };
    // 引擎执行失败**不能**变成 None。原先是 `execute_simple(...).await.ok()?`：
    // 路由已经匹配上（match_app 成功）、引擎却报错时，返回 None 会被 h2/h3 当成
    // 「没有 app 命中」，于是一路落到 proxy/static —— `.php` 文件被当静态文件
    // 原样回给客户端，**源码泄露**（h2/h3 上默认配置即可复现；同一 URL 在 h1 上
    // 是由 php-fpm 正常执行的）。这里改成与 h1 的 dispatch 一致：回 502。
    let outcome = match app_ffi::execute_simple(req, lc, app, peer, &deps_env).await {
        Ok(o) => o,
        // 与 h1 的 dispatch 同一口径：`{e:#}` 只进**本地日志**，回给客户端的是固定文本
        // —— 它是完整 anyhow 链，里面是 docroot/socket/被 spawn 的二进制绝对路径，而拿到它的
        // 人只是任意一个能命中该路由的客户端（这是上一轮 15 处回显的漏网处）。
        // 这里不能用 `engine_error()`：simple 路径的响应体是 `Bytes`（不是 `BoxBody`）。
        Err(e) => {
            log::warn!("app engine {} failed (simple path): {e:#}", app.engine);
            return Some(
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Bytes::from_static(b"502 Bad Gateway (engine error)"))
                    .unwrap(),
            );
        }
    };
    Some(app_ffi::simple_response_from_outcome(outcome))
}

pub fn match_app<'a>(
    lc: &'a ListenerConfig,
    path: &str,
    ext: &str,
) -> Option<&'a AppRouteConfig> {
    match_app_indexed(lc, path, ext).map(|(_, a)| a)
}

/// 路径里是否有**隐藏段**（某一段以 `.` 开头）；`/.well-known/`（ACME）是唯一例外。
///
/// 为什么引擎侧也要判：`extensions` 为空的应用（如 `/c`、`/go`）声明「本前缀下全是我的」，
/// 而 Rust 的 `Path::extension()` 对 `.env` 返回 **None**（前导点算文件主干）⇒ `ext` 是空串，
/// 于是连 `extensions = ["rs", ""]` 的 `/rust` 也把 `.env` 认成自己的。实测：生产口上
/// `GET /rust/.env`、`GET /c/.env` 都是 **200**（access log 的 handler 是 `app`，即引擎直接
/// 把文件吐了出来）—— 而 `.env` 正是 `deps.rs` 读进引擎进程环境的 `KEY=VAL`。
/// 引擎是「执行脚本」的层，不是「把 docroot 里所有文件都端出去」的层。
fn has_hidden_segment(path: &str) -> bool {
    path.split('/').any(|seg| {
        !seg.is_empty()
            && seg != "."
            && seg.starts_with('.')
            && !seg.eq_ignore_ascii_case(".well-known")
    })
}

fn match_app_indexed<'a>(
    lc: &'a ListenerConfig,
    path: &str,
    ext: &str,
) -> Option<(usize, &'a AppRouteConfig)> {
    if has_hidden_segment(path) {
        return None;
    }
    lc.apps.iter().enumerate().find(|(_, a)| {
        if !a.enabled {
            return false;
        }
        let path_ok = if a.paths.is_empty() {
            true
        } else {
            // 前缀必须落在 '/' 边界上，避免 /phplint 命中 /php。
            // 同时**归一化尾斜杠**：配置里写 `/php/` 时 `format!("{p}/")` 会变成 `/php//`，
            // 前缀永远匹配不上 ⇒ 该 app 静默不生效（排查起来毫无线索）。
            a.paths.iter().any(|p| {
                let p = p.trim_end_matches('/');
                let p = if p.is_empty() { "/" } else { p };
                p == "/" || path == p || path.starts_with(&format!("{p}/"))
            })
        };
        if !path_ok {
            return false;
        }
        if a.extensions.is_empty() {
            true
        } else {
            a.extensions.iter().any(|e| e == ext || e == "*")
        }
    })
}

/// 路径是否落在**某个应用路由的前缀**下（不看 `enabled`、不看 `extensions`）。
///
/// 用途：静态层的「应用 docroot 内私密文件」策略（见 `static_files::app_private_path`）——
/// 需要判断「这是应用的地盘」，而不是「应用会处理这个文件」。
pub fn under_app_prefix(lc: &ListenerConfig, path: &str) -> bool {
    lc.apps.iter().any(|a| {
        if a.paths.is_empty() {
            // paths 为空 = 该路由对所有路径生效（与 match_app 的语义一致）
            return true;
        }
        a.paths
            .iter()
            .any(|p| p == "/" || path == p || path.starts_with(&format!("{p}/")))
    })
}

/// 「这个路径**本该**由某个应用引擎处理」——与 [`would_handle`] 的区别是**不看 `enabled`**。
///
/// 为什么需要它：引擎被临时 `enabled = false`（排障、灰度、误配）时，`would_handle` 返回
/// false，静态层于是高高兴兴把 `GET /php/index.php` 当普通文件吐出去 —— **PHP 源码**
/// （里面的数据库口令、密钥）就这样被下载走；`/rust/main.rs` 同理。引擎开关是**服务**
/// 的开关，不该变成「源码公开」的开关。静态层用这个判据拒服务，改由 404 回。
pub fn route_owns_path(lc: &ListenerConfig, path: &str) -> bool {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if has_hidden_segment(path) {
        return false;
    }
    lc.apps.iter().any(|a| {
        let path_ok = if a.paths.is_empty() {
            true
        } else {
            a.paths
                .iter()
                .any(|p| p == "/" || path == p || path.starts_with(&format!("{p}/")))
        };
        if !path_ok {
            return false;
        }
        if a.extensions.is_empty() {
            true
        } else {
            a.extensions.iter().any(|e| e == ext || e == "*")
        }
    })
}

async fn dispatch(
    req: Request<Incoming>,
    _live: &Arc<LiveConfig>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    app_idx: usize,
    peer: SocketAddr,
) -> Response<BoxBody> {
    let engine = app.engine.to_ascii_lowercase();
    match engine.as_str() {
        "php" => match php::handle(req, lc, app, peer, app_idx).await {
            Ok(r) => r,
            Err(e) => engine_error("php", &e),
        },
        "fastcgi" => match php::handle_external(req, lc, app, peer).await {
            Ok(r) => r,
            Err(e) => engine_error("fastcgi", &e),
        },
        "c" | "rust" => {
            if native_http::lib_available(app, &engine) {
                match app_ffi::execute(req, lc, app, peer).await {
                    Ok(resp) => resp,
                    Err(e) => engine_error("app ffi", &e),
                }
            } else if native_http::sidecar_available(app, lc) {
                match native_http::try_handle(req, lc, app, peer, app_idx).await {
                    Ok(resp) => resp,
                    // 同 `engine_error`：sidecar 的错误链里有 socket 路径与后端文本，
                    // 只进本地日志，不回显给客户端。
                    Err(e) => engine_error("native sidecar", &e),
                }
            } else {
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(format!(
                        "engine `{engine}`: no libapp_{engine}.so; run make engines"
                    )))
                    .unwrap()
            }
        }
        "go" => {
            // Spec §7.3: prefer in-process FFI libapp_go.so when present (Linux).
            // OpenBSD: c-shared unsupported; missing .so is OK if go_shm_ipc + go-shm-server.
            if native_http::lib_available(app, "go") {
                match app_ffi::execute(req, lc, app, peer).await {
                    Ok(resp) => resp,
                    Err(e) => engine_error("app ffi", &e),
                }
            } else {
                #[cfg(all(feature = "go_shm_ipc", unix))]
                {
                    if go_shm::available() {
                        match go_shm::execute(req, lc, app, app_idx, peer).await {
                            Ok(resp) => return resp,
                            Err(e) => {
                                return engine_error("go shm", &e);
                            }
                        }
                    }
                }
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(format!(
                        "engine go: no libapp_go.so (FFI) or go-shm-server (openbsd fallback)"
                    )))
                    .unwrap()
            }
        }
        "lua" => match lua::handle(req, lc, app, peer, app_idx).await {
            Ok(r) => r,
            Err(e) => engine_error("lua", &e),
        },
        // "do" is an Apache/Tomcat-style alias for JSP dispatch.
        "jsp" | "do" => match jsp::handle(req, lc, app, peer, app_idx).await {
            Ok(r) => r,
            Err(e) => engine_error("jsp", &e),
        },
        "asp" => {
            if native_http::lib_available(app, "asp") {
                match app_ffi::execute(req, lc, app, peer).await {
                    Ok(resp) => resp,
                    Err(e) => engine_error("asp ffi", &e),
                }
            } else {
                match asp::handle(req, lc, app, peer, app_idx).await {
                    Ok(r) => r,
                    Err(e) => engine_error("asp", &e),
                }
            }
        },
        "aspnet" | "aspx" => match aspnet::handle(req, lc, app, peer, app_idx).await {
            Ok(r) => r,
            Err(e) => engine_error("aspnet", &e),
        },
        "tsx" => match tsx::handle(req, lc, app, peer, app_idx).await {
            Ok(r) => r,
            Err(e) => engine_error("tsx", &e),
        },
        "python" | "ruby" | "perl" => {
            if native_http::lib_available(app, &engine) {
                match app_ffi::execute(req, lc, app, peer).await {
                    Ok(resp) => resp,
                    Err(e) => engine_error(&format!("{engine} ffi"), &e),
                }
            } else {
                match script_ffi::handle(req, lc, app, peer, app_idx).await {
                    Ok(r) => r,
                    Err(e) => engine_error("script_ffi", &e),
                }
            }
        },
        "cgi" | "wsgi" | "asgi" | "psgi" | "rack" | "uwsgi" => {
            match app_ffi::execute(req, lc, app, peer).await {
                Ok(resp) => resp,
                Err(e) => engine_error("app engine", &e),
            }
        }
        "cgi_script" => match cgi_script::handle(req, lc, app, peer).await {
            Ok(r) => r,
            Err(e) => engine_error("cgi_script", &e),
        },
        other => Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .body(full(format!("engine `{other}` not implemented")))
            .unwrap(),
    }
}

pub fn reconcile_apps_runtime(live: &LiveConfig) {
    let cfg = live.snapshot();
    for l in &cfg.listeners {
        let apps: Vec<(usize, &AppRouteConfig)> = l.apps.iter().enumerate().collect();
        php::reconcile(l, &apps);
        for (idx, a) in &apps {
            if !a.enabled {
                continue;
            }
            let eng = a.engine.to_ascii_lowercase();
            // Normalize "do" → jsp for availability checks.
            let eng = if eng == "do" { "jsp".into() } else { eng };
            match eng.as_str() {
                "php" => {} // already reconciled above
                "jsp" => {
                    if a.socket.is_some() && !native_http::uds_socket_available(a) {
                        log::warn!(
                            "reconcile jsp listener={} app_idx={idx}: socket configured but not ready",
                            l.port
                        );
                    }
                }
                "c" | "rust" | "go" | "lua" | "asp" | "aspnet" | "tsx"
                | "python" | "ruby" | "perl" | "cgi" | "wsgi" | "asgi" | "psgi"
                | "rack" | "uwsgi" => {
                    let ok = native_http::lib_available(a, &eng)
                        || native_http::sidecar_available(a, l)
                        || native_http::uds_socket_available(a);
                    if !ok {
                        log::debug!(
                            "reconcile engine={eng} port={} idx={idx}: lib/sidecar not yet available",
                            l.port
                        );
                    }
                }
                other => log::debug!("reconcile unknown engine={other} port={}", l.port),
            }
            log::debug!("reconcile app engine={} lib={:?}", a.engine, a.lib);
        }
    }

    // §7.3 热卸载：配置不再引用的引擎 → shutdown + dlclose（无在途请求时）。
    let mut active: Vec<(String, String)> = Vec::new();
    for l in &cfg.listeners {
        for a in &l.apps {
            if !a.enabled {
                continue;
            }
            let mut eng = a.engine.to_ascii_lowercase();
            if eng == "do" {
                eng = "jsp".into();
            }
            if let Ok(p) = app_ffi::resolve_lib(a, &eng) {
                active.push((eng, p.to_string_lossy().into_owned()));
            }
        }
    }
    app_ffi::reconcile_unload(&active);
}

#[cfg(test)]
mod script_rel_tests {
    use crate::server::admin_files::{script_rel, would_execute_on_get};
    use crate::config::{AppRouteConfig, FileOpenMode, FileOpenTable, ListenerConfig};
    use std::path::{Path, PathBuf};

    fn listener_with_rust_app() -> ListenerConfig {
        ListenerConfig {
            address: "0.0.0.0".into(),
            address_v6: None,
            port: 19095,
            root: PathBuf::from("www-apps"),
            autoindex: crate::config::AutoindexConfig::default(),
            http_versions: vec!["h1".into()],
            server_name: None,
            ssl: None,
            file_open: FileOpenTable::default(),
            apps: vec![AppRouteConfig {
                paths: vec!["/rust".into()],
                enabled: true,
                engine: "rust".into(),
                socket: None,
                extensions: vec!["rs".into(), "".into()],
                index: None,
                php_bin: None,
                workers: 4,
                source_dir: None,
                out_dir: None,
                entry: vec![],
                watch: false,
                docroot: Some(PathBuf::from("www-apps/rust")),
                lib: Some(PathBuf::from("target/app-engines/libapp_rust.so")),
                deps_dir: None,
                init_timeout_secs: None,
                libc: None,
            }],
            basic_auth: None,
            proxy_rules: vec![],
            page_rules: vec![],
            status_path: None,
            port_reuse: false,
            rate_limit: None,
            l4_forward: None,
            quic_ecn: false,
            qmux: false,
            connect_udp: false,
        }
    }

    /// P0 机制回归：**分发判据与落盘判据看到的是两个不同的路径**。
    ///
    /// 分发拿**原始** URL 路径问 `would_handle`（字面前缀匹配，不做点段折叠），而落盘用
    /// `safe_join`/`web_path_of` 归一化后的路径。于是 `/./rust/x.rs` 这种写法：
    /// **分发**判「不归引擎」（`/./rust/...` 不以 `/rust/` 开头）→ 交给上传器；
    /// 而**落盘**归一化成 `/rust/x.rs` → 正好写进引擎 docroot，随后 `GET /rust/x.rs` 由
    /// 引擎执行 ⇒ 一条请求换一个 webshell。上传端点现在用 `would_execute_on_get`
    /// （归一化后的判据）兜住 —— 这个测试把这个「两个判据不一致」的事实钉住，
    /// 免得以后有人把闸门挪回原始路径比较。
    #[test]
    fn dot_folded_path_bypasses_dispatch_but_not_the_normalized_gate() {
        let lc = listener_with_rust_app();
        // 前缀被折叠/加重斜杠：分发判据（原始路径）认不出来
        for raw in ["/./rust/x.rs", "//rust/x.rs"] {
            assert!(
                !super::would_handle(&lc, raw),
                "分发判据（原始路径）对 {raw} 应为 false —— 这正是缺口所在"
            );
        }
        // 尾段被折叠（`/rust/./x.rs`）**不构成缺口**：前缀 `/rust/` 仍然字面匹配，
        // 引擎自己会拿到它并用归一化后的 script_rel 解析到同一个文件。
        assert!(super::would_handle(&lc, "/rust/./x.rs"));

        // 归一化后的判据（上传闸门用它）必须把上面两类**都**认成「引擎的地盘」
        assert!(would_execute_on_get(&lc, "./rust/x.rs"));
        assert!(would_execute_on_get(&lc, "rust/./x.rs"));
        assert!(would_execute_on_get(&lc, "//rust/x.rs"));

        // 正常路径两边一致
        assert!(super::would_handle(&lc, "/rust/x.rs"));
        assert!(would_execute_on_get(&lc, "rust/x.rs"));
    }

    /// 隐藏文件不归引擎：`/rust/.env`（`extensions=["rs",""]`）与 `/c/.env`（无 extensions）
    /// 都必须落到静态层（再由静态层的隐藏路径策略回 404），绝不能由引擎直接吐出内容。
    /// 实测基线：两者在生产口上都是 200，handler 是 `app`。
    #[test]
    fn hidden_paths_are_not_owned_by_engines() {
        let mut lc = listener_with_rust_app();
        assert!(super::would_handle(&lc, "/rust/index.rs"));
        assert!(!super::would_handle(&lc, "/rust/.env"), "{:?}", lc.apps);
        assert!(!super::route_owns_path(&lc, "/rust/.env"));
        // 无 extensions 的 catch-all 应用同样不得吞下隐藏路径
        lc.apps[0].extensions.clear();
        assert!(super::would_handle(&lc, "/rust/anything.txt"));
        assert!(!super::would_handle(&lc, "/rust/.env"));
        // .well-known 是例外（ACME 需要它可服务）
        assert!(!super::has_hidden_segment("/.well-known/acme-challenge/tok"));
        assert!(super::has_hidden_segment("/rust/.env"));
        assert!(super::has_hidden_segment("/rust/.git/config"));
        assert!(!super::has_hidden_segment("/rust/normal.txt"));
    }

    #[test]
    fn would_handle_rust_paths() {
        let lc = listener_with_rust_app();
        assert!(super::would_handle(&lc, "/rust/index.rs"));
        assert!(super::would_handle(&lc, "/rust/foo.rs"));
        assert!(!super::would_handle(&lc, "/static/hello.txt"));
    }

    #[test]
    fn would_execute_and_would_handle_agree() {
        let lc = listener_with_rust_app();
        assert!(would_execute_on_get(&lc, "rust/index.rs"));
        assert!(super::would_handle(&lc, "/rust/index.rs"));
        assert!(!would_execute_on_get(&lc, "static/x.txt"));
        assert!(!super::would_handle(&lc, "/static/x.txt"));
    }

    #[test]
    fn would_handle_respects_file_open_preview() {
        let mut lc = listener_with_rust_app();
        lc.file_open
            .insert("/rust/index.rs", FileOpenMode::Preview);
        assert!(!super::would_handle(&lc, "/rust/index.rs"));
        assert!(!would_execute_on_get(&lc, "rust/index.rs"));
    }

    #[test]
    fn script_rel_stays_under_docroot() {
        let root = std::env::temp_dir().join("crucible_apps_script_rel");
        let _ = std::fs::create_dir_all(root.join("subdir"));
        let p = script_rel(&root, "subdir/page.jsp").expect("ok");
        assert!(p.starts_with(&root));
        assert!(script_rel(&root, "../escape.jsp").is_err());
        assert!(script_rel(&root, "subdir/../../etc/passwd").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn script_rel_rejects_absolute_escape() {
        // Absolute-looking rels must still be joined safely or rejected.
        let root = Path::new("www-apps");
        let r = script_rel(root, "/etc/passwd");
        // Either err or result still under root after normalization.
        if let Ok(p) = r {
            let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            assert!(
                p.starts_with(&canon_root) || p.starts_with(root),
                "escaped docroot: {p:?}"
            );
        }
    }
}
