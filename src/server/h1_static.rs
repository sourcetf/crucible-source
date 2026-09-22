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

    // P2-1：去掉前导 '/' 后若仍为绝对路径（Windows 盘符 / `\\` 前缀），
    // `Path::join` 会丢弃 root 直接指向该绝对路径——任意文件读取。
    // 同时拒绝 NUL 字节（截断文件名校验）。
    let rel = path.trim_start_matches('/');
    if rel.is_empty() || rel.contains('\0') {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Bytes::from_static(b"forbidden"))
            .unwrap());
    }
    let rel_path = std::path::Path::new(rel);
    if rel_path.is_absolute() {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Bytes::from_static(b"forbidden"))
            .unwrap());
    }
    let file_path = lc.root.join(rel_path);
    // containment：join 后必须仍在 root 之下（canonicalize 解析 symlink 后复核）。
    let canon_root = lc.root.canonicalize().unwrap_or_else(|_| lc.root.clone());
    let canon = file_path.canonicalize().unwrap_or_else(|_| file_path.clone());
    if !canon.starts_with(&canon_root) {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Bytes::from_static(b"forbidden"))
            .unwrap());
    }
    if canon.exists() {
        let mime = mime_guess::from_path(&canon).first_or_octet_stream();
        let body = std::fs::read(&canon).unwrap_or_default();
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
