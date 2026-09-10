//! Go shared memory IPC（OpenBSD 上的 go-shm-server fallback）。
//! 仅在 `go_shm_ipc` feature + unix 平台编译为完整实现；
//! 在其它平台，available() 永为 false，execute 返回 501。

use crate::config::{AppRouteConfig, ListenerConfig};
use anyhow::Result;
use http::Request;
use hyper::body::Incoming;
use http_body_util::BodyExt;
use crate::server::h1::BoxBody;
use http_body_util::Full;
use http::Response;
use std::net::SocketAddr;

#[cfg(all(feature = "go_shm_ipc", unix))]
pub fn available() -> bool {
    // 检查 go-shm-server 是否运行
    // TODO: 实现 socket 检查
    false
}

#[cfg(all(feature = "go_shm_ipc", unix))]
pub async fn execute(
    req: Request<Incoming>,
    _lc: &ListenerConfig,
    _app: &AppRouteConfig,
    _app_idx: usize,
    _peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    let body = req.body().collect().await.map(|c| c.to_bytes())?;
    Err(anyhow::anyhow!("go shm IPC not configured"))
}

#[cfg(not(all(feature = "go_shm_ipc", unix)))]
pub fn available() -> bool {
    false
}

#[cfg(not(all(feature = "go_shm_ipc", unix)))]
pub async fn execute(
    req: Request<Incoming>,
    _lc: &ListenerConfig,
    _app: &AppRouteConfig,
    _app_idx: usize,
    _peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    Err(anyhow::anyhow!("go shm IPC requires go_shm_ipc feature and unix"))
}