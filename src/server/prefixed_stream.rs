//! 前缀流包装器：为 HTTP/2 与 HTTP/1.1 提供统一的流接口。
//! 主要用于 h2::serve_with_prefix 中的流包装。

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// 包装已读取前缀的 TCP 流
pub struct PrefixedStream<R, W> {
    reader: R,
    writer: W,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> PrefixedStream<R, W> {
    pub fn new(reader: R, writer: W, prefix: Vec<u8>) -> Self {
        Self {
            reader,
            writer,
            prefix,
            prefix_pos: 0,
        }
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead
    for PrefixedStream<R, W>
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // 先返回前缀
        if self.prefix_pos < self.prefix.len() {
            let available = self.prefix.len() - self.prefix_pos;
            let to_copy = buf.len().min(available);
            buf[..to_copy].copy_from_slice(
                &self.prefix[self.prefix_pos..self.prefix_pos + to_copy],
            );
            self.prefix_pos += to_copy;
            return Poll::Ready(Ok(to_copy));
        }
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}
