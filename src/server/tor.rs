//! Tor 端点选择（unix socket / TCP SOCKS5 / .onion v3 判定）.
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorProxyMode { UnixSocket(PathBuf), Tcp(SocketAddr), Auto }

impl Default for TorProxyMode { fn default() -> Self { Self::Auto } }

pub fn is_onion_v3(host: &str) -> bool {
    host.ends_with(".onion") && host.len() == 62
}

pub fn resolve_proxy_mode(env: Option<&str>) -> TorProxyMode {
    if let Some(v) = env {
        if v.starts_with('/') { return TorProxyMode::UnixSocket(PathBuf::from(v)); }
        if let Ok(addr) = v.parse() { return TorProxyMode::Tcp(addr); }
    }
    if let Ok(s) = std::env::var("TOR_SOCKS") { return resolve_proxy_mode(Some(&s)); }
    let default = PathBuf::from("/var/run/tor/socks");
    if default.exists() { TorProxyMode::UnixSocket(default) } else { TorProxyMode::Tcp(SocketAddr::from(([127,0,0,1], 9050))) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn t() { assert!(is_onion_v3("w6sxlmzmz2mgzkg5r5fcvycu3lx2i5mkc4z3ycpuj5l22ewpplr2q70.onion")); }
    #[test] fn t2() { assert!(!is_onion_v3("example.com")); }
}
