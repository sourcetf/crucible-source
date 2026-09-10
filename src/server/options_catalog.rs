//! 选项目录：暴露可用的配置选项和功能。
//! Admin UI 使用此模块获取功能列表。

use serde::{Deserialize, Serialize};

/// TLS 版本选项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsVersionOption {
    pub code: String,
    pub name: String,
    pub available: bool,
}

/// 获取可用的 TLS 版本列表
pub fn tls_versions() -> Vec<TlsVersionOption> {
    vec![
        TlsVersionOption { code: "SSLv2".to_string(), name: "SSLv2".to_string(), available: cfg!(feature = "tls_tomcrypt") },
        TlsVersionOption { code: "SSLv3".to_string(), name: "SSLv3".to_string(), available: cfg!(feature = "tls_nss") },
        TlsVersionOption { code: "TLSv1.0".to_string(), name: "TLS 1.0".to_string(), available: cfg!(feature = "tls_nss") },
        TlsVersionOption { code: "TLSv1.1".to_string(), name: "TLS 1.1".to_string(), available: cfg!(feature = "tls_nss") },
        TlsVersionOption { code: "TLSv1.2".to_string(), name: "TLS 1.2".to_string(), available: true },
        TlsVersionOption { code: "TLSv1.3".to_string(), name: "TLS 1.3".to_string(), available: true },
    ]
}

/// 获取可用的应用引擎
pub fn app_engines() -> Vec<String> {
    vec![
        "php".to_string(), "fastcgi".to_string(), "jsp".to_string(), "asp".to_string(), "aspnet".to_string(), "tsx".to_string(), "do".to_string(),
        "python".to_string(), "ruby".to_string(), "perl".to_string(), "lua".to_string(), "wsgi".to_string(), "asgi".to_string(), "psgi".to_string(), "rack".to_string(),
        "cgi".to_string(), "uwsgi".to_string(), "c".to_string(), "go".to_string(), "rust".to_string(),
    ]
}

/// 获取可用的 DNSKEY 模式
pub fn dnssec_algorithms() -> Vec<&'static str> {
    vec![
        "RSASHA256",
        "RSASHA512",
        "ECDSAP256SHA256",
        "ECDSAP384SHA384",
        "ED25519",
    ]
}

/// 获取可用的 DNSKEY 角色
pub fn dnssec_roles() -> Vec<&'static str> {
    vec!["ksk", "zsk", "csk"]
}

/// 返回功能目录的 JSON 格式（Admin API 使用）
pub fn catalog_json() -> String {
    let catalog = serde_json::json!({
        "tls_versions": tls_versions(),
        "app_engines": app_engines(),
        "dnssec_algorithms": dnssec_algorithms(),
        "dnssec_roles": dnssec_roles(),
    });
    catalog.to_string()
}