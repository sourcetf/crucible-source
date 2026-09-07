//! Bidirectional TCP ↔ relay bridge for legacy TLS handshakes (NSS / TomCrypt).

use std::io::{Read, Write};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Spawn background threads copying bytes both ways between `tcp` and `relay`.
pub fn spawn_bidirectional_bridge(tcp: std::net::TcpStream, mut relay: UnixStream) -> anyhow::Result<()> {
    let mut tcp_to_relay = tcp
        .try_clone()
        .map_err(|e| anyhow::anyhow!("tcp try_clone: {e}"))?;
    let mut relay_to_tcp = relay
        .try_clone()
        .map_err(|e| anyhow::anyhow!("relay try_clone: {e}"))?;
    let mut tcp_from_relay = tcp
        .try_clone()
        .map_err(|e| anyhow::anyhow!("tcp try_clone: {e}"))?;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut relay_to_tcp, &mut tcp_to_relay);
    });
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut tcp_from_relay, &mut relay);
    });
    Ok(())
}

/// Write peek to relay peer, bridge tcp ↔ relay, return relay fd for C shim.
/// Use for NSS (reads only from the fd — needs ClientHello reinjected on the wire).
pub async fn relay_with_peek(stream: TcpStream, peek: Vec<u8>) -> anyhow::Result<RawFd> {
    let (mut relay_tx, relay_rx) =
        UnixStream::pair().map_err(|e| anyhow::anyhow!("socketpair: {e}"))?;
    relay_tx
        .write_all(&peek)
        .map_err(|e| anyhow::anyhow!("relay peek write: {e}"))?;
    let std_stream = stream.into_std().map_err(|e| anyhow::anyhow!("into_std: {e}"))?;
    spawn_bidirectional_bridge(std_stream, relay_tx)?;
    Ok(relay_rx.into_raw_fd())
}

/// Bridge tcp ↔ relay **without** writing peek (TomCrypt owns peek via `peek_io`).
/// Writing peek here AND into peek_io double-feeds ClientHello as a fake CMK and can abort.
pub async fn relay_bridge_only(stream: TcpStream) -> anyhow::Result<RawFd> {
    let (relay_tx, relay_rx) =
        UnixStream::pair().map_err(|e| anyhow::anyhow!("socketpair: {e}"))?;
    let std_stream = stream.into_std().map_err(|e| anyhow::anyhow!("into_std: {e}"))?;
    spawn_bidirectional_bridge(std_stream, relay_tx)?;
    Ok(relay_rx.into_raw_fd())
}

/// 桥接阻塞 legacy Read/Write（NSS PR_Read / TomCrypt read）到 async。
///
/// 健壮性修复（任务 6）：旧实现把阻塞 read/write 直接放进 poll_read/poll_write 的
/// `block_in_place`——worker_threads=2 时两个慢 legacy 客户端就能占死全部 executor
/// 线程。新实现为每条连接开一对专用阻塞线程，经 tokio mpsc 与 async 侧交换：
/// - 读侧 bounded(8)：`Receiver::poll_recv` 正确注册 waker，天然背压；
/// - 写侧 unbounded：legacy 响应体在本服务侧已 ≤16MiB（read_file_capped），
///   无无界内存面；Sender 无 poll_ready（tokio 1.53），unbounded 避免假 Pending 死锁。
/// 调用方需把连接拆成读写两个 half（NSS/TomCrypt 的同一描述符并发读写由
/// NSPR/shim 内部锁保护，TLS 全双工语义）。
pub struct LegacySyncIo {
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    chunk: Option<Vec<u8>>,
    off: usize,
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

const LEGACY_READ_BUF: usize = 16 * 1024;

impl LegacySyncIo {
    fn new<R: Read + Send + 'static, W: Write + Send + 'static>(
        mut reader: R,
        mut writer: W,
    ) -> Self {
        let (r_tx, r_rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(8);
        let (w_tx, mut w_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // 读线程：阻塞 read → 通道（Ok(空 Vec) 表示 EOF）。
        let _ = std::thread::Builder::new()
            .name("cruc-legacy-rd".into())
            .spawn(move || {
                let mut buf = vec![0u8; LEGACY_READ_BUF];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => {
                            let _ = r_tx.blocking_send(Ok(Vec::new()));
                            break;
                        }
                        Ok(n) => {
                            if r_tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                                break; // async 侧已 drop
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            let _ = r_tx.blocking_send(Err(e));
                            break;
                        }
                    }
                }
            });

        // 写线程：通道 → 阻塞 write_all；通道关闭（async 侧 drop）后 flush 收尾。
        let _ = std::thread::Builder::new()
            .name("cruc-legacy-wr".into())
            .spawn(move || {
                while let Some(data) = w_rx.blocking_recv() {
                    if writer.write_all(&data).is_err() {
                        break;
                    }
                }
                let _ = writer.flush();
            });

        Self {
            rx: r_rx,
            chunk: None,
            off: 0,
            tx: w_tx,
        }
    }
}

impl AsyncRead for LegacySyncIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 先消费上次取回但未读完的残余。
        if self.chunk.is_none() {
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        // 读线程显式 EOF
                        return Poll::Ready(Ok(()));
                    }
                    self.chunk = Some(data);
                    self.off = 0;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())), // 读线程退出 → EOF
            }
        }
        // 借用拆分：chunk 借用域内只读，游标更新放在域外（E0502）。
        let n = {
            let chunk = self.chunk.as_ref().expect("chunk set above");
            let take = (chunk.len() - self.off).min(buf.remaining());
            buf.put_slice(&chunk[self.off..self.off + take]);
            take
        };
        self.off += n;
        if self
            .chunk
            .as_ref()
            .is_some_and(|c| self.off >= c.len())
        {
            self.chunk = None;
            self.off = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for LegacySyncIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.tx.send(data.to_vec()) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "legacy writer thread gone",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 写线程按序 write_all，无需额外 flush。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // legacy 栈不支持 close_notify：drop 时由线程收尾（flush 后退出）。
        Poll::Ready(Ok(()))
    }
}

/// 把同一阻塞连接拆成「读 half + 写 half」交给桥的两个线程；
/// 底层描述符的并发读写线程安全由 C 栈保证（见各 Half 文档）。
pub fn sync_io_bridge<R, W>(reader: R, writer: W) -> LegacySyncIo
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    LegacySyncIo::new(reader, writer)
}
