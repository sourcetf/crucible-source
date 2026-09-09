//! Go shared memory IPC（OpenBSD 上的 go-shm-server fallback）。
//! 仅在 `go_shm_ipc` feature + unix 平台编译。

#[cfg(not(all(feature = "go_shm_ipc", unix)))]
compile_error!("go_shm module requires go_shm_ipc feature and unix platform");

use crate::config::{AppRouteConfig, ListenerConfig};
use anyhow::Result;
use http::Request;
use bytes::Bytes;
use http::Response;
use crate::server::h1::BoxBody;
use std::net::SocketAddr;

pub fn available() -> bool {
    // 检查 go-shm-server 是否运行
    false
}

pub async fn execute(
    _req: Request<Bytes>,
    _lc: &ListenerConfig,
    _app: &AppRouteConfig,
    _app_idx: usize,
    _peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    Err(anyhow::anyhow!("go shm IPC not configured"))
}
