//! port_reuse TLS 路由 — peek ClientHello → parse_sni → 目标 ssl listener 直通.
//! 实际在 accept 热路径调用 peek_sni()；TCP forward 由 proxy_to_ssl_listener() 完成.
use std::net::SocketAddr;
use std::path::Path;

pub fn peek_sni(buf: &[u8]) -> Option<String> {
    if let Some(s) = crate::server::tls::client_hello::parse_sni(buf) { return Some(s); }
    None
}

/// 连接目标的上限时间：目标不响应时立刻放弃，而不是把 accept 资源一直挂住。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// 两个方向共享的**空闲**超时：搬完一段数据就重新计时。
///
/// 为什么要它：h1/h2/h3 都有空闲超时，这条「peek SNI → TCP 直通」路径此前**一个超时都没有** ——
/// 客户端连上什么都不发、或与一个不回包的目标互等，就能无限占用连接/FD/内存
///（等于绕过 listener 上的所有超时）。
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub async fn proxy_to_ssl_listener(plain: tokio::net::TcpStream, target: SocketAddr) -> std::io::Result<()> {
    let mut upstream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("port_reuse: connect {target} 超时（{CONNECT_TIMEOUT:?}）"),
            ))
        }
    };
    let (mut pr, mut pw) = plain.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    // 每个方向各一个「带空闲超时的 copy」：超时即结束该方向，try_join 随即收尾。
    let c2u = copy_idle(&mut pr, &mut uw);
    let u2c = copy_idle(&mut ur, &mut pw);
    let _ = tokio::try_join!(c2u, u2c);
    Ok(())
}

/// `tokio::io::copy` + 每段数据之间的空闲超时（单段搬完就重置计时）。
async fn copy_idle<R, W>(r: &mut R, w: &mut W) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(IDLE_TIMEOUT, r.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(total), // EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(total), // 空闲超时：正常收尾（对端可在其它方向继续）
        };
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
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
