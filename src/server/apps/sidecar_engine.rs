//! Sidecar 引擎：持久化的 C/Go/Rust HTTP sidecar。
//! 当 .so 不可用时，使用原生二进制的持久 HTTP sidecars。

use crate::config::AppRouteConfig;
use crate::config::ListenerConfig;
use crate::server::h1::BoxBody;
use crate::server::apps::{app_ffi, native_http};
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;
use bytes::Bytes;
use http_body_util::Full;

/// 检查 sidecar socket 是否可用
pub fn sidecar_available(_app: &AppRouteConfig, _lc: &ListenerConfig) -> bool {
    // 检查 socket 路径是否存在
    // 实际项目中会检查 UDS socket 或 TCP 端口
    false
}

/// 通过 sidecar 执行请求
pub async fn sidecar_execute(
    _req: &http::Request<Bytes>,
    _app: &AppRouteConfig,
) -> Result<http::Response<bytes::Bytes>> {
    // 通过 HTTP 或 UDS 与 sidecar 通信
    Err(anyhow::anyhow!("sidecar not implemented"))
}

/// wsgi/asgi/ffi 等引擎的统一处理器：尝试 FFI → native_http sidecar → 失败返回 502。
pub async fn handle_with_fallback(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    engine: &str,
    sidecor_cmd: &str,
) -> Result<Response<BoxBody>> {
    let engine_lower = engine.to_ascii_lowercase();

    // 1. 尝试 FFI .so
    if app_ffi::lib_available(app, &engine_lower) {
        return app_ffi::execute(req, lc, app, peer).await;
    }

    // 2. 尝试 native_http sidecar
    if native_http::sidecar_available(app, lc) {
        if let Ok(resp) = native_http::try_handle(req, lc, app, peer, app_idx).await {
            return Ok(resp);
        }
    }

    // 3. 尝试 UDS sidecar
    if let Some(resp) = native_http::try_handle_uds(req, app, peer).await {
        return Ok(resp);
    }

    // 4. 均不可用：返回 502
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(BoxBody::new(Full::new(Bytes::from_static(
            b"engine unavailable (build lib or configure sidecar)"
        ))))
    .unwrap())
}
