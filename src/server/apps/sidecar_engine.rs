//! Shared FFI / Unix sidecar dispatch for optional app engines.

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::{app_ffi, native_http};
use crate::server::h1::{full, BoxBody};
use anyhow::Result;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;

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
    if native_http::sidecar_available(app, lc) {
        return native_http::try_handle(req, lc, app, peer, app_idx).await;
    }
    if native_http::uds_socket_available(app) {
        return native_http::try_handle_uds(req, app, peer).await;
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
