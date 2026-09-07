//! Python / Ruby / Perl static-embed script FFI engine.

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
    let name = app.engine.to_ascii_lowercase();
    let stub = match name.as_str() {
        "python" | "py" => "python",
        "ruby" | "rb" => "ruby",
        "perl" | "pl" => "perl",
        other => other,
    };
    sidecar_engine::handle_with_fallback(req, lc, app, peer, app_idx, &name, stub).await
}
