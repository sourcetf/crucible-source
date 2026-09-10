//! Legacy CGI spawn engine (explicit `cgi_script` route only).
//!
//! **C/Go/Rust must not call [`execute_binary`] on success paths** — see §7.3 / §19.

use crate::config::AppRouteConfig;
use crate::config::ListenerConfig;
use crate::server::h1::BoxBody;
use anyhow::Result;
use http::Request;
use hyper::body::Incoming;

/// 通过 CGI sidecars 执行请求
pub async fn handle(
    _req: Request<Incoming>,
    _lc: &ListenerConfig,
    _app: &AppRouteConfig,
    _peer: std::net::SocketAddr,
) -> Result<http::Response<BoxBody>> {
    // CGI spawn 已禁用；改用 FFI .so 或 HTTP sidecar
    Err(anyhow::anyhow!("CGI spawn disabled per spec §7.2"))
}