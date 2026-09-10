//! Tor 出站客户端（早期规格 A）：反代上游经 Tor 的统一入口。
//!
//! 连接优先级（最终态）：
//! 1) 配置了 `tor_socks`：unix:/path 或绝对路径 → SOCKS5 over UDS；
//!    TCP 仅允许 loopback（127.0.0.1/::1/localhost），否则拒绝；
//! 2) 未配置：优先 in-process arti（state/tor-client/arti，feature=tor_arti 时编译）；
//!    失败/未启用 → 依次尝试默认 UDS：state/tor-client/socks.sock、
//!    /run/tor/socks、/var/run/tor/socks、/run/tor/socks.sock；
//! 3) 全部失败 → 系统 127.0.0.1:9050（TCP，loopback）。
//!
//! 要点：SOCKS5 CONNECT 传主机名，不做本地 DNS（.onion 必须）。
//! 依赖（可选）：arti-client（rustls + static-sqlite，避开与 BoringSSL 的
//! OpenSSL 冲突）+ tokio-socks；早期拉起系统 tor SocksPort:19050 的方案已废弃。
//! HS 实例 SocksPort 0 不复用（见 tor_hs.rs）。

use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SOCKS5 代理连接（IPv4 / IPv6 目标，ATYP 按 RFC 1928 选择）。
pub async fn connect_via_socks5(
    proxy_addr: SocketAddr,
    target: SocketAddr,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // SOCKS5 握手
    // 发送：版本 + 认证方法列表 (NO AUTH)
    let handshake = [0x05, 0x01, 0x00];
    stream.write_all(&handshake).await?;

/// SOCKS5 握手（纯手写，无依赖；CONNECT 传主机名）。
async fn socks5_connect<S>(
    mut stream: S,
    target: &TorTarget,
    proxy_auth_user: Option<&str>,
) -> Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // greeting：需要用户名隔离时提供用户名/密码方法
    if let Some(u) = proxy_auth_user {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 5 {
        bail!("socks5: bad version {:#x}", resp[0]);
    }
    if resp[1] == 2 {
        let user = proxy_auth_user.unwrap_or("").as_bytes();
        let mut auth = vec![0x01, user.len() as u8];
        auth.extend_from_slice(user);
        auth.push(0); // 空密码
        stream.write_all(&auth).await?;
        let mut aresp = [0u8; 2];
        stream.read_exact(&mut aresp).await?;
        if aresp[1] != 0 {
            bail!("socks5: auth rejected");
        }
    } else if resp[1] != 0 {
        bail!("socks5: no-auth rejected ({:#x})", resp[1]);
    }

    // 发送 CONNECT 请求
    // VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    // ATYP: 0x01=IPv4(4B) 0x03=域名(1B长度+N) 0x04=IPv6(16B)
    let mut req = vec![0x05u8, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await?;

    // 读取并完整消费 CONNECT 应答：VER REP RSV ATYP + BND.ADDR + BND.PORT
    // 不消费 BND.ADDR/PORT 会把残余字节留在流上，破坏后续隧道数据。
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        anyhow::bail!("Socks5 reply bad version: {}", head[0]);
    }
    if head[1] != 0x00 {
        anyhow::bail!("Socks5 connect failed: code {}", head[1]);
    }
    match head[3] {
        0x01 => {
            let mut bnd = [0u8; 4 + 2];
            stream.read_exact(&mut bnd).await?;
        }
        0x04 => {
            let mut bnd = [0u8; 16 + 2];
            stream.read_exact(&mut bnd).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut bnd = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut bnd).await?;
        }
        other => anyhow::bail!("Socks5 reply bad ATYP: {other}"),
    }
    Ok(stream)
}

/// `connect_via_socks5` 的域名目标变体（Tor 解析 .onion 用 ATYP=0x03）。
pub async fn connect_via_socks5_domain(
    proxy_addr: SocketAddr,
    host: &str,
    port: u16,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    let handshake = [0x05, 0x01, 0x00];
    stream.write_all(&handshake).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        anyhow::bail!("Socks5 handshake failed");
    }

    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        anyhow::bail!("Socks5 domain too long: {} bytes", host_bytes.len());
    }
    let mut req = Vec::with_capacity(5 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        anyhow::bail!("Socks5 reply bad version: {}", head[0]);
    }
    if head[1] != 0x00 {
        anyhow::bail!("Socks5 connect failed: code {}", head[1]);
    }
    match head[3] {
        0x01 => {
            let mut bnd = [0u8; 4 + 2];
            stream.read_exact(&mut bnd).await?;
        }
        0x04 => {
            let mut bnd = [0u8; 16 + 2];
            stream.read_exact(&mut bnd).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut bnd = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut bnd).await?;
        }
        other => anyhow::bail!("Socks5 reply bad ATYP: {other}"),
    }

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// 最小 SOCKS5 假服务器：握手后回显 CONNECT 请求帧供断言。
    async fn fake_socks5_echo(
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<Vec<u8>>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let h = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hs = [0u8; 3];
            s.read_exact(&mut hs).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut frame = Vec::new();
            // Read VER/CMD/RSV/ATYP then variable addr+port.
            let mut head = [0u8; 4];
            s.read_exact(&mut head).await.unwrap();
            frame.extend_from_slice(&head);
            let atyp = head[3];
            match atyp {
                0x01 => {
                    let mut b = [0u8; 4 + 2];
                    s.read_exact(&mut b).await.unwrap();
                    frame.extend_from_slice(&b);
                }
                0x04 => {
                    let mut b = [0u8; 16 + 2];
                    s.read_exact(&mut b).await.unwrap();
                    frame.extend_from_slice(&b);
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    s.read_exact(&mut l).await.unwrap();
                    frame.extend_from_slice(&l);
                    let mut b = vec![0u8; l[0] as usize + 2];
                    s.read_exact(&mut b).await.unwrap();
                    frame.extend_from_slice(&b);
                }
                _ => {}
            }
            // 回成功应答（IPv4 bound 0.0.0.0:0）
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            frame
        });
        Ok((addr, h))
    }

    #[tokio::test]
    async fn socks5_ipv4_atyp_is_01_no_length_prefix() {
        let (proxy, h) = fake_socks5_echo().await.unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let _ = connect_via_socks5(proxy, target).await.unwrap();
        let frame = h.await.unwrap();
        assert_eq!(frame[0], 0x05);
        assert_eq!(frame[1], 0x01); // CMD=CONNECT
        assert_eq!(frame[3], 0x01); // ATYP=IPv4
        assert_eq!(&frame[4..8], &[93, 184, 216, 34]);
        assert_eq!(&frame[8..10], &443u16.to_be_bytes());
        assert_eq!(frame.len(), 10);
    }

    #[tokio::test]
    async fn socks5_ipv6_atyp_is_04() {
        let (proxy, h) = fake_socks5_echo().await.unwrap();
        let target: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let _ = connect_via_socks5(proxy, target).await.unwrap();
        let frame = h.await.unwrap();
        assert_eq!(frame[3], 0x04); // ATYP=IPv6
        assert_eq!(frame.len(), 4 + 16 + 2);
        assert_eq!(&frame[4..6], &[0x20, 0x01]);
        assert_eq!(&frame[18..20], &8080u16.to_be_bytes());
    }

    #[tokio::test]
    async fn socks5_domain_atyp_is_03_with_len() {
        let (proxy, h) = fake_socks5_echo().await.unwrap();
        let _ = connect_via_socks5_domain(proxy, "example.com", 80)
            .await
            .unwrap();
        let frame = h.await.unwrap();
        assert_eq!(frame[3], 0x03);
        assert_eq!(frame[4], 11); // len("example.com")
        assert_eq!(&frame[5..16], b"example.com");
        assert_eq!(&frame[16..18], &80u16.to_be_bytes());
    }
}
