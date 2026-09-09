//! TypeScript / TSX one-click compile + watch deploy engine — FFI / sidecar / stub.

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::sidecar_engine;
use crate::server::h1::BoxBody;
use anyhow::Result;
use http::{Request, Response};
use hyper::body::Incoming;
use std::net::SocketAddr;

pub async fn handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
) -> Result<Response<BoxBody>> {
    sidecar_engine::handle_with_fallback(req, lc, app, peer, app_idx, "tsx", "tsx").await
}
