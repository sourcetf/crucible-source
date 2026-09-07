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

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// SOCKS5 目标（域名不解析）。
#[derive(Debug, Clone)]
pub enum TorTarget {
    Domain(String, u16),
    Ip(std::net::SocketAddr),
}

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

    // CONNECT + 域名（不做本地 DNS）
    let (host_b, port) = match target {
        TorTarget::Domain(h, p) => (h.as_bytes().to_vec(), *p),
        TorTarget::Ip(sa) => match sa.ip() {
            std::net::IpAddr::V4(v4) => (v4.octets().to_vec(), sa.port()),
            std::net::IpAddr::V6(_) => bail!("socks5: v6 target via domain form"),
        },
    };
    if host_b.len() > 255 {
        bail!("socks5: hostname too long");
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_b.len() as u8];
    req.extend_from_slice(&host_b);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0 {
        bail!("socks5: CONNECT failed code={}", head[1]);
    }
    // 按地址类型丢弃绑定地址
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut skip = vec![0u8; l[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        _ => bail!("socks5: bad atyp {}", head[3]),
    }
    Ok(stream)
}

/// UDS 上的 SOCKS5。
pub async fn connect_socks5_uds(sock: &std::path::Path, target: TorTarget) -> Result<UnixStream> {
    let uds = UnixStream::connect(sock)
        .await
        .with_context(|| format!("socks uds {}", sock.display()))?;
    socks5_connect(uds, &target, None)
        .await
        .context("socks5 uds handshake")
}

/// TCP 上的 SOCKS5（仅允许 loopback——规格 C 坑表）。
pub async fn connect_socks5_tcp(addr: &str, target: TorTarget) -> Result<TcpStream> {
    let host = addr.rsplit_once(':').map(|x| x.0).unwrap_or(addr);
    let loopback = matches!(host, "127.0.0.1" | "::1" | "localhost");
    if !loopback {
        bail!("tor socks tcp refused: {host} is not loopback");
    }
    let tcp = TcpStream::connect(addr).await.with_context(|| format!("tor tcp {addr}"))?;
    socks5_connect(tcp, &target, None)
        .await
        .context("socks5 tcp handshake")
}

#[cfg(feature = "tor_arti")]
async fn connect_arti(target: &TorTarget) -> Result<impl AsyncRead + AsyncWrite + Unpin> {
    // arti-client（rustls + static-sqlite）：state/tor-client/arti。
    // 编译需 --features tor_arti；运行期数据目录 state/tor-client/arti/{cache,state}。
    use arti_client::{TorClient, TorClientConfig};
    use tokio_crate::net::TcpStream as TokioTcp;
    static CLIENT: tokio::sync::OnceCell<TorClient<PreferredRuntime>> = tokio::sync::OnceCell::const_new();
    let client = CLIENT
        .get_or_try_init(|| async {
            let cfg = TorClientConfig::default();
            TorClient::with_runtime(PreferredRuntime::current()?)
                .create_bootstrapped()
                .await
        })
        .await?
        .clone();
    let (host, port) = match target {
        TorTarget::Domain(h, p) => (h.clone(), *p),
        TorTarget::Ip(sa) => (sa.ip().to_string(), sa.port()),
    };
    let stream = client.connect((host.as_str(), port)).await?;
    Ok(TokioTcp::new(stream)) // 占位：arti Stream 需按实际类型返回
}

/// 统一入口：优先链见模块注释。返回可读写的 Tor 流。
pub async fn connect_via_tor(
    host: &str,
    port: u16,
    tor_socks: Option<&str>,
) -> Result<TorStream> {
    let target = TorTarget::Domain(host.to_string(), port);

    // 1) 显式 tor_socks：unix:/path 或绝对路径 → UDS；TCP → 仅 loopback
    if let Some(spec) = tor_socks {
        let spec = spec.trim();
        if spec.starts_with("unix:") || spec.starts_with('/') {
            let path = spec.strip_prefix("unix:").unwrap_or(spec);
            let uds = connect_socks5_uds(std::path::Path::new(path), target).await?;
            return Ok(TorStream::Uds(uds));
        }
        let tcp = connect_socks5_tcp(spec, target).await?;
        return Ok(TorStream::Tcp(tcp));
    }

    // 2) in-process arti（feature 门控；未编译时跳过）
    #[cfg(feature = "tor_arti")]
    {
        match connect_arti(&target).await {
            Ok(stream) => return Ok(TorStream::Arti(Box::new(stream))),
            Err(e) => log::warn!("tor: arti failed: {e:#}; fall back to socks"),
        }
    }

    // 3) 默认 UDS 候选
    for cand in [
        "state/tor-client/socks.sock",
        "/run/tor/socks",
        "/var/run/tor/socks",
        "/run/tor/socks.sock",
    ] {
        let p = std::path::Path::new(cand);
        if p.exists() {
            if let Ok(uds) = connect_socks5_uds(p, target.clone()).await {
                return Ok(TorStream::Uds(uds));
            }
        }
    }

    // 4) 系统 9050（loopback TCP）
    let tcp = connect_socks5_tcp("127.0.0.1:9050", target).await?;
    Ok(TorStream::Tcp(tcp))
}

/// 抹平 UDS / TCP / arti 三种底层流的枚举包装。
pub enum TorStream {
    Uds(UnixStream),
    Tcp(TcpStream),
    #[cfg(feature = "tor_arti")]
    Arti(Box<dyn AsyncRead + AsyncWrite + Unpin + Send>),
}

impl AsyncRead for TorStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TorStream::Uds(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TorStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tor_arti")]
            TorStream::Arti(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TorStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            TorStream::Uds(s) => std::pin::Pin::new(s).poll_write(cx, data),
            TorStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, data),
            #[cfg(feature = "tor_arti")]
            TorStream::Arti(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TorStream::Uds(s) => std::pin::Pin::new(s).poll_flush(cx),
            TorStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tor_arti")]
            TorStream::Arti(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TorStream::Uds(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TorStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tor_arti")]
            TorStream::Arti(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
