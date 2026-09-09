//! port_reuse TLS 路由 — peek ClientHello → parse_sni → 目标 ssl listener 直通.
//! 实际在 accept 热路径调用 peek_sni()；TCP forward 由 proxy_to_ssl_listener() 完成.
use std::net::SocketAddr;
use std::path::Path;

pub fn peek_sni(buf: &[u8]) -> Option<String> {
    if let Some(s) = crate::server::tls::client_hello::parse_sni(buf) { return Some(s); }
    None
}

pub async fn proxy_to_ssl_listener(plain: tokio::net::TcpStream, target: SocketAddr) -> std::io::Result<()> {
    let mut upstream = tokio::net::TcpStream::connect(target).await?;
    let (mut pr, mut pw) = plain.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    let _ = tokio::try_join!(
        tokio::io::copy(&mut pr, &mut uw),
        tokio::io::copy(&mut ur, &mut pw),
    );
    Ok(())
}

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
