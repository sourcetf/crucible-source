//! Tor Hidden Service (v3) 辅助工具。
//! 功能已被 tor_rs.rs 和 onion_ca.rs 取代。
//! 本文件保留兼容性导出。

use anyhow::Result;
use std::path::PathBuf;

/// Tor HS 配置
#[derive(Debug, Clone)]
pub struct TorHsConfig {
    pub enabled: bool,
    pub hostname: Option<String>,
    pub private_key_path: Option<PathBuf>,
    pub ports: Vec<u16>,
}

impl Default for TorHsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hostname: None,
            private_key_path: None,
            ports: Vec::new(),
        }
    }
}

/// 生成隐藏服务秘钥
pub fn generate_hs_key(_hostname: &str) -> Result<String> {
    // 简化实现：返回 base32 编码的伪随机密钥
    Ok(format!(
        "v3{}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        fastrand::u64()
    ))
}

/// 解析 .onion 主机名
pub fn parse_onion(hostname: &str) -> Option<String> {
    if hostname.ends_with(".onion") && hostname.len() == 62 {
        Some(hostname.to_string())
    } else {
        None
    }
}
