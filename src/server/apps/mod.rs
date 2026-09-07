//! Application engine dispatch: try_handle / match_app / dispatch.

pub mod app_ffi;
pub mod asp;
pub mod aspnet;
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
    let deps_env = match deps::try_cached(live, &app).await {
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
    live: &Arc<LiveConfig>,
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
    let deps_env = match deps::try_cached(live, app).await {
        Ok(e) => e,
        Err(e) => {
            log::warn!("deps ensure failed (simple path): {e:#}");
            deps::DepsEnv::default()
        }
    };
    let outcome = app_ffi::execute_simple(req, lc, app, peer, &deps_env)
        .await
        .ok()?;
    Some(app_ffi::simple_response_from_outcome(outcome))
}

pub fn match_app<'a>(
    lc: &'a ListenerConfig,
    path: &str,
    ext: &str,
) -> Option<&'a AppRouteConfig> {
    match_app_indexed(lc, path, ext).map(|(_, a)| a)
}

fn match_app_indexed<'a>(
    lc: &'a ListenerConfig,
    path: &str,
    ext: &str,
) -> Option<(usize, &'a AppRouteConfig)> {
    lc.apps.iter().enumerate().find(|(_, a)| {
        if !a.enabled {
            return false;
        }
        let path_ok = if a.paths.is_empty() {
            true
        } else {
            // 前缀必须落在 '/' 边界上，避免 /phplint 命中 /php。
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
            Err(e) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("php error: {e:#}")))
                .unwrap(),
        },
        "fastcgi" => match php::handle_external(req, lc, app, peer).await {
            Ok(r) => r,
            Err(e) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("fastcgi error: {e:#}")))
                .unwrap(),
        },
        "c" | "rust" => {
            if native_http::lib_available(app, &engine) {
                match app_ffi::execute(req, lc, app, peer).await {
                    Ok(resp) => resp,
                    Err(e) => Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full(format!("app ffi error: {e:#}")))
                        .unwrap(),
                }
            } else if native_http::sidecar_available(app, lc) {
                match native_http::try_handle(req, lc, app, peer, app_idx).await {
                    Ok(resp) => resp,
                    Err(e) => Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full(format!(
                            "native sidecar error (no CGI fallback): {e:#}"
                        )))
                        .unwrap(),
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
                    Err(e) => Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full(format!("app ffi error: {e:#}")))
                        .unwrap(),
                }
            } else {
                #[cfg(all(feature = "go_shm_ipc", unix))]
                {
                    if go_shm::available() {
                        match go_shm::execute(req, lc, app, app_idx, peer).await {
                            Ok(resp) => return resp,
                            Err(e) => {
                                return Response::builder()
                                    .status(StatusCode::BAD_GATEWAY)
                                    .body(full(format!("go shm error: {e:#}")))
                                    .unwrap();
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
            Err(e) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("lua error: {e:#}")))
                .unwrap(),
        },
        // "do" is an Apache/Tomcat-style alias for JSP dispatch.
        "jsp" | "do" => match jsp::handle(req, lc, app, peer, app_idx).await {
            Ok(r) => r,
            Err(e) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("jsp error: {e:#}")))
                .unwrap(),
        },
        "asp" => {
            if native_http::lib_available(app, "asp") {
                match app_ffi::execute(req, lc, app, peer).await {
                    Ok(resp) => resp,
                    Err(e) => Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full(format!("asp ffi error: {e:#}")))
                        .unwrap(),
                }
            } else {
                match asp::handle(req, lc, app, peer, app_idx).await {
                    Ok(r) => r,
                    Err(e) => Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full(format!("asp error: {e:#}")))
                        .unwrap(),
                }
            }
        },
        "aspnet" | "aspx" => match aspnet::handle(req, lc, app, peer, app_idx).await {
            Ok(r) => r,
            Err(e) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("aspnet error: {e:#}")))
                .unwrap(),
        },
        "tsx" => match tsx::handle(req, lc, app, peer, app_idx).await {
            Ok(r) => r,
            Err(e) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("tsx error: {e:#}")))
                .unwrap(),
        },
        "python" | "ruby" | "perl" => {
            if native_http::lib_available(app, &engine) {
                match app_ffi::execute(req, lc, app, peer).await {
                    Ok(resp) => resp,
                    Err(e) => Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full(format!("{engine} ffi error: {e:#}")))
                        .unwrap(),
                }
            } else {
                match script_ffi::handle(req, lc, app, peer, app_idx).await {
                    Ok(r) => r,
                    Err(e) => Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full(format!("script_ffi error: {e:#}")))
                        .unwrap(),
                }
            }
        },
        "cgi" | "wsgi" | "asgi" | "psgi" | "rack" | "uwsgi" => {
            match app_ffi::execute(req, lc, app, peer).await {
                Ok(resp) => resp,
                Err(e) => Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(format!("app engine error: {e:#}")))
                    .unwrap(),
            }
        }
        "cgi_script" => match cgi_script::handle(req, lc, app, peer).await {
            Ok(r) => r,
            Err(e) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("cgi_script error: {e:#}")))
                .unwrap(),
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
            address: "127.0.0.1".into(),
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
        }
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
