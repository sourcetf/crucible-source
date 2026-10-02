//! port_reuse TLS 路由 — peek ClientHello → parse_sni → 目标 ssl listener 直通.
//! 实际在 accept 热路径调用 peek_sni()；TCP forward 由 proxy_to_ssl_listener() 完成.
use std::net::SocketAddr;
use std::path::Path;

pub fn peek_sni(buf: &[u8]) -> Option<String> {
    if let Some(s) = crate::server::tls::client_hello::parse_sni(buf) { return Some(s); }
    None
}

// 带守卫的双向 TCP 转发**已移到 `l4::forward_guarded`**（本文件里曾有一份等价实现，
// 但没有任何调用者 —— listener.rs 反而内联了一遍不带守卫的，于是两个超时守卫形同虚设）。
// 这里只保留 SNI 解析与路由表。
//
// 教训：同一段逻辑有第二份实现时，先改的那份会被当成「已修」，实际生效的却是另一份。

pub struct SniRouter { routes: parking_lot::RwLock<std::collections::HashMap<String, usize>> }
impl Default for SniRouter { fn default() -> Self { Self { routes: Default::default() } } }
impl SniRouter {
    pub fn new() -> std::sync::Arc<Self> { std::sync::Arc::new(Self::default()) }
    pub fn register(&self, sni: &str, idx: usize) { self.routes.write().insert(sni.to_lowercase(), idx); }
    pub fn lookup(&self, sni: &str) -> Option<usize> { self.routes.read().get(&sni.to_lowercase()).copied() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn r() {
        let r = SniRouter::new();
        r.register("v.example.com", 1);
        assert_eq!(r.lookup("V.Example.com"), Some(1));
        assert!(r.lookup("other").is_none());
    }
}
