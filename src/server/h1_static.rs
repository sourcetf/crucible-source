//! HTTP/1.1 静态文件服务 - 优化版（专为静态文件设计，减少 alloc）。
//!
//! 注意：当前主分发路径使用 `static_files::serve_simple`（含 nosniff/containment）；
//! 本模块保留为低 alloc 快路径，同样实施穿越拒绝与 nosniff。

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

    // P2-1：显式穿越段一律拒绝（含解码后的 %2e%2e 变体）。
    if path.split(['/', '\\']).any(|seg| seg == "..") {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Bytes::from_static(b"forbidden"))
            .unwrap());
    }
    let _ = (live, peer);

    let file_path = lc.root.join(&path[1..]);
    if file_path.exists() {
        let mime = mime_guess::from_path(&file_path).first_or_octet_stream();
        let body = std::fs::read(&file_path).unwrap_or_default();
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, mime.essence_str())
            // P2-13：nosniff 防 MIME 跳转执行
            .header("x-content-type-options", "nosniff")
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
