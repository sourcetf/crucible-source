//! HTTP/3 (QUIC) via quinn + h3-quinn.
//!
//! 注意：当前版本 h3 0.0.7 与 h3-quinn 0.0.10 不完全兼容。
//! 为避免编译错误，此功能已暂时禁用。
//! 建议在 h3-quinn 0.0.11+ 与 h3 0.0.8+ 发布后恢复使用。

#[cfg(feature = "h3_enabled")]
pub async fn serve(
    _bind: std::net::SocketAddr,
    _lc: crate::config::ListenerConfig,
    _live: std::sync::Arc<crate::server::live_config::LiveConfig>,
) -> anyhow::Result<()> {
    anyhow::bail!("h3 HTTP/3 support not available - version mismatch between h3 and h3-quinn")
}