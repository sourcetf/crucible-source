//! Sidecar 引擎：持久化的 C/Go/Rust HTTP sidecar。
//! 当 .so 不可用时，使用原生二进制的持久 HTTP sidecars。

use crate::config::AppRouteConfig;
use crate::config::ListenerConfig;
use anyhow::Result;
use std::path::PathBuf;

/// 检查 sidecar socket 是否可用
pub fn sidecar_available(_app: &AppRouteConfig, _lc: &ListenerConfig) -> bool {
    // 检查 socket 路径是否存在
    // 实际项目中会检查 UDS socket 或 TCP 端口
    false
}

/// 通过 sidecar 执行请求
pub async fn sidecar_execute(
    _req: &http::Request<bytes::Bytes>,
    _app: &AppRouteConfig,
) -> Result<http::Response<bytes::Bytes>> {
    // 通过 HTTP 或 UDS 与 sidecar 通信
    Err(anyhow::anyhow!("sidecar not implemented"))
}
