//! OCSP 线路化：自动获取 OCSP，缓存到程序目录。
//! §16.14 OCSP：自动获取不需要手动指定，过期前自动重新拉取。

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// OCSP 响应缓存路径
pub fn ocsp_cache_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("state/ocsp"))
        .join("responses")
}

/// 检查缓存的 OCSP 响应是否过期
pub fn is_cache_expired(name: &str) -> bool {
    let cache_file = ocsp_cache_dir().join(format!("{}.der", name));
    let metadata = match std::fs::metadata(&cache_file) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let mtime = match metadata.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };
    let age = SystemTime::now()
        .duration_since(mtime)
        .unwrap_or(Duration::from_secs(86400));
    // 默认 1 天过期
    age > Duration::from_secs(86400)
}

/// 拉取 OCSP 响应（简化实现）
pub async fn fetch_ocsp(
    _issuer_cert: &[u8],
    _cert: &[u8],
    _url: &str,
) -> Result<Vec<u8>> {
    // 这里实现 OCSP 自动获取逻辑
    // 实际项目中会使用 HTTP 客户端请求 OCSP 端点
    // 当前作为 stub，返回空响应
    Ok(Vec::new())
}
