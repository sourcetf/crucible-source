//! CGI 脚本执行器（C/Go/Rust 最终禁止走这条）。
//! 仅作为遗留的 HTTP sidecar fallback。

use crate::config::AppRouteConfig;
use crate::config::ListenerConfig;
use anyhow::Result;
use http::Request;

/// 通过 CGI sidecars 执行请求
pub async fn handle(
    _req: Request<http::body::Incoming>,
    _lc: &ListenerConfig,
    _app: &AppRouteConfig,
    _peer: std::net::SocketAddr,
) -> Result<http::Response<crate::server::h1::BoxBody>> {
    // CGI spawn 已禁用；改用 FFI .so 或 HTTP sidecar
    Err(anyhow::anyhow!("CGI spawn disabled per spec §7.2"))
}
