//! HTTP/1.1 静态文件服务 - 优化版（专为静态文件设计，减少 alloc）。

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;
use std::sync::Arc;

/// 针对静态文件的 H1 服务入口（优化版）。
pub async fn serve_static(
    req: Request<Incoming>,
    live: Arc<LiveConfig>,
    lc: &ListenerConfig,
    peer: SocketAddr,
) -> Result<Response<Bytes>> {
    let path = req.uri().path();
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    // 静态文件路径
    let file_path = lc.root.join(&path[1..]);
    if file_path.exists() {
        let mime = mime_guess::from_path(&file_path).first_or_octet_stream();
        let body = std::fs::read(&file_path).unwrap_or_default();
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, mime.essence_str())
            .body(Bytes::from(body))
            .unwrap())
    } else {
        let not_found = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Bytes::from_static(b"not found"))
            .unwrap();
        Ok(not_found)
    }
}
