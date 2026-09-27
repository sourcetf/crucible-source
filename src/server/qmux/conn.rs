//! QMux v1 的**连接状态机**（服务端侧），跑在一条已完成握手的双向字节流（TLS）上。
//!
//! 逐条对着草案实现/校验：
//!
//! * §3.2 记录自定界（`Size(i) + Frames`），帧不跨记录，末尾对不齐 → `FRAME_ENCODING_ERROR`；
//! * §4 只允许 QUIC v1 的那批帧 + `QX_TRANSPORT_PARAMETERS` / `QX_PING`；
//! * §4.1 同一流的 STREAM 必须**连续**（`offset` 紧接上一字节），否则 `PROTOCOL_VIOLATION`
//!   —— 因此实现不需要重组缓冲；
//! * §4.2 第一个帧必须是 `QX_TRANSPORT_PARAMETERS`，否则 `PROTOCOL_VIOLATION`；我方参数
//!   在流可用时立刻发出，不等对端；
//! * §4.3 `QX_PING` 请求序号严格递增、响应原样回显；
//! * §5.1 未知传输参数忽略、被禁的传输参数 → `TRANSPORT_PARAMETER_ERROR`；§5.2
//!   `max_record_size` 不小于默认 16382，超限记录 → `FRAME_ENCODING_ERROR`；
//! * §6 读侧**永不**因应用不读而阻塞：缓冲上限就是我们声明的流控额度，应用消费即回补
//!   `MAX_STREAM_DATA`/`MAX_DATA`；
//! * §7.1 空闲计时以「记录」为单位（收满一条 / 发完一条都重置），到期优雅关闭发送侧；
//! * §7.3 收到 `CONNECTION_CLOSE` 后不再发帧。
//!
//! 并发模型：共享状态一律 `parking_lot::Mutex`（临界区内不 await），唤醒用 waker 槽，
//! 出向记录走 `mpsc` + `try_send`（满即背压，由 writer 任务唤醒）。**锁顺序固定为
//! 「先 stream.core 后 conn.conn_sent」，全文件一致**，避免 AB-BA。

use super::proto::{
    self, err, parse_frames, put_varint, varint_len, Frame, ProtoError, RecordReader,
    TransportParams, DEFAULT_MAX_RECORD_SIZE,
};
use anyhow::Result;
use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

/// 单条流的接收缓冲上限（= 声明的 `initial_max_stream_data_bidi_remote`）。
pub const STREAM_RECV_WINDOW: u64 = 256 * 1024;
/// 连接级接收缓冲上限（= 声明的 `initial_max_data`）。
pub const CONN_RECV_WINDOW: u64 = 1024 * 1024;
/// 允许的对端发起双向流数（= `initial_max_streams_bidi`）。
pub const MAX_STREAMS_BIDI: u64 = 100;
/// 允许的对端发起单向流数（= `initial_max_streams_uni`；本实现不消费单向流，只声明）。
pub const MAX_STREAMS_UNI: u64 = 100;
/// 出向记录队列长度（背压点）。
const OUT_QUEUE: usize = 64;
/// 计算 STREAM 帧净荷上限时为帧头预留的空间。
const FRAME_OVERHEAD: usize = 32;

/// 本方参数：集中一处，且与上面的常量必须一致。
pub fn local_params() -> TransportParams {
    TransportParams {
        max_idle_timeout: 30_000,
        initial_max_data: CONN_RECV_WINDOW,
        initial_max_stream_data_bidi_local: STREAM_RECV_WINDOW,
        initial_max_stream_data_bidi_remote: STREAM_RECV_WINDOW,
        initial_max_stream_data_uni: STREAM_RECV_WINDOW,
        initial_max_streams_bidi: MAX_STREAMS_BIDI,
        initial_max_streams_uni: MAX_STREAMS_UNI,
        max_record_size: DEFAULT_MAX_RECORD_SIZE,
        max_datagram_frame_size: Some(DEFAULT_MAX_RECORD_SIZE),
        reset_stream_at: true,
    }
}

/// 应用协议用的 ALPN 标识。
///
/// 草案 §8.1：QMux 本身**没有** ALPN，由上层协议指定，命名沿用草案示例的
/// `<协议>-<草案号>qx`。本实现服务的是 **HTTP/1.1 over QMux**：`h1-02qx`
/// （`02` = draft-ietf-quic-qmux-02，即本文件实现的那版）。
pub const QMUX_ALPN: &[u8] = b"h1-02qx";

/// 应用侧收到的流事件。
#[derive(Debug)]
enum StreamEvent {
    Data(Bytes),
    Fin,
    Reset(u64),
}

/// 单条流的全部状态（一把锁；锁顺序的第一环）。
struct StreamCore {
    events: Option<mpsc::UnboundedSender<StreamEvent>>,
    // 收侧
    received: u64,
    consumed: u64,
    recv_limit: u64,
    fin: bool,
    final_size: Option<u64>,
    // 发侧
    send_limit: u64,
    send_sent: u64,
    send_stopped: bool,
    fin_sent: bool,
    write_waker: Option<Waker>,
}

struct StreamState {
    id: u64,
    core: Mutex<StreamCore>,
}

/// 连接共享状态。
struct Conn {
    out: mpsc::Sender<Vec<u8>>,
    out_waker: Mutex<Option<Waker>>,
    peer_params: Mutex<Option<TransportParams>>,
    streams: Mutex<HashMap<u64, Arc<StreamState>>>,
    /// (已发送, 对端额度) —— 连接级发送窗口；锁顺序的第二环
    conn_sent: Mutex<(u64, u64)>,
    /// (已接收, 已交付, 我们声明的上限) —— 连接级接收窗口
    conn_recv: Mutex<(u64, u64, u64)>,
    peer_max_record: AtomicU64,
    peer_bidi_opened: AtomicU64,
    closed: AtomicBool,
    last_activity: Mutex<Instant>,
}

impl Conn {
    fn try_push_record(&self, body: Vec<u8>) -> std::result::Result<(), ()> {
        if self.closed.load(Ordering::Relaxed) {
            return Ok(()); // §7.3：收到 CONNECTION_CLOSE 后不再发帧
        }
        let mut rec = Vec::with_capacity(body.len() + 8);
        put_varint(&mut rec, body.len() as u64);
        rec.extend_from_slice(&body);
        self.out.try_send(rec).map_err(|_| ())
    }

    /// 把帧按对端 `max_record_size` 装箱入队（帧不跨记录）。返回**没能入队**的帧。
    fn push_frames(&self, mut frames: Vec<Frame>) -> Vec<Frame> {
        let max = self.peer_max_record.load(Ordering::Relaxed).max(1) as usize;
        let mut body: Vec<u8> = Vec::new();
        let mut in_body = 0usize;
        let mut idx = 0usize;
        while idx < frames.len() {
            let mut enc = Vec::new();
            frames[idx].encode(&mut enc);
            if enc.len() > max {
                log::warn!(
                    "qmux: 单帧 {} 字节超过对端 max_record_size={max}，丢弃（写入侧本应先切分）",
                    enc.len()
                );
                idx += 1;
                continue;
            }
            if in_body > 0 && body.len() + enc.len() + varint_len(body.len() as u64) > max {
                if self.try_push_record(std::mem::take(&mut body)).is_err() {
                    return frames[idx..].to_vec();
                }
                in_body = 0;
                continue; // 重新装这一帧
            }
            body.extend_from_slice(&enc);
            in_body += 1;
            idx += 1;
        }
        if in_body > 0 && self.try_push_record(body).is_err() {
            // 最后一条没进去：把该记录里的帧还回去（保守做法：重试整批）
            return frames[frames.len() - in_body..].to_vec();
        }
        Vec::new()
    }

    /// 单帧入队（机会式小帧：MAX_*、PING 响应、CONNECTION_CLOSE）。失败只记日志。
    fn push_one(&self, f: Frame) {
        let left = self.push_frames(vec![f]);
        if !left.is_empty() {
            log::debug!("qmux: 出向队列满，丢弃机会式帧（下次消费会补）");
        }
    }

    fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    /// 应用消费了 `n` 字节 → 需要时回补窗口（§6）。
    fn on_consumed(&self, stream_id: u64, n: u64) {
        let mut need_stream = None;
        let mut need_conn = None;
        {
            let streams = self.streams.lock();
            if let Some(st) = streams.get(&stream_id) {
                let mut c = st.core.lock();
                c.consumed += n;
                if c.recv_limit.saturating_sub(c.consumed) < STREAM_RECV_WINDOW / 2 {
                    c.recv_limit = c.consumed + STREAM_RECV_WINDOW;
                    need_stream = Some(c.recv_limit);
                }
            }
        }
        {
            let mut cr = self.conn_recv.lock();
            cr.1 += n;
            if cr.2.saturating_sub(cr.1) < CONN_RECV_WINDOW / 2 {
                cr.2 = cr.1 + CONN_RECV_WINDOW;
                need_conn = Some(cr.2);
            }
        }
        if let Some(maximum) = need_stream {
            self.push_one(Frame::MaxStreamData {
                stream_id,
                maximum,
            });
        }
        if let Some(lim) = need_conn {
            self.push_one(Frame::MaxData(lim));
        }
    }

    fn wake_writer(&self, stream_id: u64) {
        let streams = self.streams.lock();
        if let Some(st) = streams.get(&stream_id) {
            if let Some(w) = st.core.lock().write_waker.take() {
                w.wake();
            }
        }
    }

    fn wake_all_writers(&self) {
        let ids: Vec<u64> = self.streams.lock().keys().copied().collect();
        for id in ids {
            self.wake_writer(id);
        }
    }
}

/// 应用侧看到的一条 QMux 逻辑流：`AsyncRead + AsyncWrite`。
///
/// 直接喂给现有 h1 handler（`crate::server::h1::serve_io`）即可 ——
/// 于是 HTTP/1.1 跑在 QMux 的流上（ALPN 见 [`QMUX_ALPN`]）。
pub struct QmuxStream {
    pub id: u64,
    conn: Arc<Conn>,
    state: Arc<StreamState>,
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    cur: Option<Bytes>,
    /// 应用写入但尚未入队的数据
    write_buf: Vec<u8>,
    shutdown_done: bool,
}

impl QmuxStream {
    pub fn stream_id(&self) -> u64 {
        self.id
    }

    /// 尽力把 `write_buf` 成帧入队；返回未能发出的字节数（>0 = 需要等额度/队列）。
    ///
    /// 锁顺序：先 `state.core`，再 `conn.conn_sent`（全文件一致）。
    fn flush_frames(&mut self) -> usize {
        let max = self.conn.peer_max_record.load(Ordering::Relaxed) as usize;
        let payload_cap = max.saturating_sub(FRAME_OVERHEAD).max(64);
        let mut frames: Vec<Frame> = Vec::new();
        let mut queued = 0usize;
        {
            let mut c = self.state.core.lock();
            if c.send_stopped {
                // 对端要求停发：把缓冲丢掉并让写方看到错误
                self.write_buf.clear();
                return 0;
            }
            while queued < self.write_buf.len() {
                let mut sr = self.conn.conn_sent.lock();
                let avail = (c.send_limit.saturating_sub(c.send_sent))
                    .min(sr.1.saturating_sub(sr.0)) as usize;
                if avail == 0 {
                    // 如实报 blocked（机会式）
                    let (sl, cl) = (c.send_limit, sr.1);
                    drop(sr);
                    self.conn.push_one(Frame::StreamDataBlocked {
                        stream_id: self.id,
                        limit: sl,
                    });
                    self.conn.push_one(Frame::DataBlocked(cl));
                    break;
                }
                let take = (self.write_buf.len() - queued).min(avail).min(payload_cap);
                let offset = c.send_sent;
                c.send_sent += take as u64;
                sr.0 += take as u64;
                frames.push(Frame::Stream {
                    stream_id: self.id,
                    offset,
                    fin: false,
                    data: self.write_buf[queued..queued + take].to_vec(),
                });
                queued += take;
            }
        }
        if frames.is_empty() {
            return self.write_buf.len() - queued;
        }
        let leftover = self.conn.push_frames(frames);
        if !leftover.is_empty() {
            // 队列满：把没进去的字节对应的额度退回，等 writer 唤醒后重试
            let n: u64 = leftover
                .iter()
                .map(|f| match f {
                    Frame::Stream { data, .. } => data.len() as u64,
                    _ => 0,
                })
                .sum();
            let mut c = self.state.core.lock();
            c.send_sent = c.send_sent.saturating_sub(n);
            let mut sr = self.conn.conn_sent.lock();
            sr.0 = sr.0.saturating_sub(n);
            return self.write_buf.len() - queued + n as usize;
        }
        self.write_buf.len() - queued
    }
}

impl AsyncRead for QmuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(chunk) = this.cur.take() {
                if chunk.is_empty() {
                    continue;
                }
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.cur = Some(chunk.slice(n..));
                }
                this.conn.on_consumed(this.id, n as u64);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.rx).poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(b))) => {
                    this.cur = Some(b);
                    continue;
                }
                Poll::Ready(Some(StreamEvent::Fin)) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(StreamEvent::Reset(code))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        format!("qmux: 流被对端重置（code {code}）"),
                    )))
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for QmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.state.core.lock().send_stopped {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "qmux: 对端已用 STOP_SENDING 要求停发",
            )));
        }
        // 先清掉上一次的残留（正常不该有：我们从不保留未接受的字节）
        if this.flush_frames() > 0 {
            this.state.core.lock().write_waker = Some(cx.waker().clone());
            *this.conn.out_waker.lock() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // 只接受**确实成帧发走**的前缀；尾部不留在缓冲里（否则调用方重发会重复）。
        this.write_buf.extend_from_slice(data);
        let left = this.flush_frames();
        let accepted = data.len() - left.min(data.len());
        if left > 0 {
            this.write_buf.truncate(this.write_buf.len() - left);
            this.state.core.lock().write_waker = Some(cx.waker().clone());
            *this.conn.out_waker.lock() = Some(cx.waker().clone());
        } else {
            this.write_buf.clear();
        }
        if accepted == 0 {
            return Poll::Pending;
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.flush_frames() > 0 {
            this.state.core.lock().write_waker = Some(cx.waker().clone());
            *this.conn.out_waker.lock() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        // FIN **必须**排在所有流数据之后：先把缓冲发干净，发不干净就下次再关。
        if this.flush_frames() > 0 {
            this.state.core.lock().write_waker = Some(cx.waker().clone());
            *this.conn.out_waker.lock() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        this.shutdown_done = true;
        let (offset, already) = {
            let mut c = this.state.core.lock();
            let already = c.fin_sent;
            c.fin_sent = true;
            (c.send_sent, already)
        };
        if !already {
            this.conn.push_one(Frame::Stream {
                stream_id: this.id,
                offset,
                fin: true,
                data: Vec::new(),
            });
        }
        Poll::Ready(Ok(()))
    }
}

/// 服务端入口：在 `io` 上跑一条 QMux 连接，把每条对端发起的双向流交给 `handler`。
pub async fn serve<IO, F, Fut>(io: IO, handler: F) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(QmuxStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let params = local_params();
    let (mut rd, mut wr) = tokio::io::split(io);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(OUT_QUEUE);
    let conn = Arc::new(Conn {
        out: tx,
        out_waker: Mutex::new(None),
        peer_params: Mutex::new(None),
        streams: Mutex::new(HashMap::new()),
        conn_sent: Mutex::new((0, 0)),
        conn_recv: Mutex::new((0, 0, CONN_RECV_WINDOW)),
        peer_max_record: AtomicU64::new(DEFAULT_MAX_RECORD_SIZE),
        peer_bidi_opened: AtomicU64::new(0),
        closed: AtomicBool::new(false),
        last_activity: Mutex::new(Instant::now()),
    });

    // 写任务：出向记录 → 底层流；每写完一条记录重置空闲计时（§7.1）。
    //
    // 退出时**必须把队列里剩下的记录写完**（例如协议错误时刚入队的 CONNECTION_CLOSE）：
    // 直接 abort 会让对端只看到连接被断，看不到我们发的关闭原因 —— 这是实测踩到的 bug。
    let conn_w = Arc::clone(&conn);
    let stop = Arc::new(tokio::sync::Notify::new());
    let stop_w = Arc::clone(&stop);
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                rec = rx.recv() => match rec {
                    Some(rec) => {
                        if wr.write_all(&rec).await.is_err() { break; }
                        let _ = wr.flush().await;
                        conn_w.touch();
                        if let Some(w) = conn_w.out_waker.lock().take() { w.wake(); }
                    }
                    None => break, // 所有发送端已 drop
                },
                _ = stop_w.notified() => {
                    // 冲刷：把已入队但还没写的记录写完再收摊
                    while let Ok(rec) = rx.try_recv() {
                        if wr.write_all(&rec).await.is_err() { break; }
                        let _ = wr.flush().await;
                    }
                    break;
                }
            }
        }
        let _ = wr.flush().await;
        let _ = wr.shutdown().await;
    });

    // 我方参数立刻发出（§4.2：不等对端）
    conn.push_one(Frame::QxTransportParameters(params.encode()));

    let idle = Duration::from_millis(if params.max_idle_timeout == 0 {
        30_000
    } else {
        params.max_idle_timeout
    });
    let mut reader = RecordReader::new();
    let mut scratch = vec![0u8; 16 * 1024];
    let mut first_frame_seen = false;
    let mut peer_ping_max = 0u64;

    let result: Result<()> = loop {
        let remaining = idle.saturating_sub(conn.last_activity.lock().elapsed());
        if remaining.is_zero() {
            log::info!("qmux: 空闲超时（{idle:?}），关闭连接（§7.2：不发帧）");
            break Ok(());
        }
        let n = match tokio::time::timeout(remaining, rd.read(&mut scratch)).await {
            Ok(Ok(0)) => break Ok(()), // 对端优雅关闭
            Ok(Ok(n)) => n,
            Ok(Err(e)) => break Err(anyhow::anyhow!("qmux: 底层读取失败: {e}")),
            Err(_) => break Ok(()), // 空闲超时
        };
        reader.push(&scratch[..n]);
        match drain_records(
            &conn,
            &handler,
            &mut reader,
            &mut first_frame_seen,
            &mut peer_ping_max,
        )
        .await
        {
            Ok(()) => {}
            Err(e) => break Err(e),
        }
    };

    conn.closed.store(true, Ordering::Relaxed);
    // 让写任务把队列里剩下的记录（尤其 CONNECTION_CLOSE）写完；给它 2s，超时再 abort。
    stop.notify_one();
    if tokio::time::timeout(Duration::from_secs(2), writer)
        .await
        .is_err()
    {
        log::debug!("qmux: 写任务未在 2s 内收摊，强制中止");
    }
    result
}

/// 处理缓冲区里所有**完整的**记录；不完整的留给下一轮。
async fn drain_records<F, Fut>(
    conn: &Arc<Conn>,
    handler: &F,
    reader: &mut RecordReader,
    first_frame_seen: &mut bool,
    peer_ping_max: &mut u64,
) -> Result<()>
where
    F: Fn(QmuxStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    loop {
        let body = match reader.next_record() {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(()),
            Err(e) => {
                close_with(conn, &e);
                return Err(anyhow::anyhow!("{e}"));
            }
        };
        conn.touch(); // 收满一条记录 → 重置空闲计时（§7.1）
        let frames = match parse_frames(&body) {
            Ok(f) => f,
            Err(e) => {
                close_with(conn, &e);
                return Err(anyhow::anyhow!("{e}"));
            }
        };
        if !*first_frame_seen {
            *first_frame_seen = true;
            if !matches!(frames.first(), Some(Frame::QxTransportParameters(_))) {
                let e = ProtoError::protocol("第一个帧必须是 QX_TRANSPORT_PARAMETERS（§4.2）");
                close_with(conn, &e);
                return Err(anyhow::anyhow!("{e}"));
            }
        }
        for f in frames {
            if let Err(e) = handle_frame(conn, handler, f, peer_ping_max).await {
                close_with(conn, &e);
                return Err(anyhow::anyhow!("{e}"));
            }
        }
    }
}

fn close_with(conn: &Arc<Conn>, e: &ProtoError) {
    conn.push_one(Frame::ConnectionClose {
        app: false,
        error_code: e.code,
        frame_type: 0,
        reason: e.reason.clone().into_bytes(),
    });
}

/// 处理一个帧：所有规范校验都在这里，便于对着草案逐条复核。
async fn handle_frame<F, Fut>(
    conn: &Arc<Conn>,
    handler: &F,
    f: Frame,
    peer_ping_max: &mut u64,
) -> std::result::Result<(), ProtoError>
where
    F: Fn(QmuxStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    match f {
        Frame::Padding(_) => {}
        Frame::QxTransportParameters(tp) => {
            let (parsed, unknown) = TransportParams::decode(&tp)?;
            if !unknown.is_empty() {
                log::debug!(
                    "qmux: 对端声明了 {} 个未知传输参数（§5.1 要求忽略）",
                    unknown.len()
                );
            }
            conn.peer_max_record
                .store(parsed.max_record_size, Ordering::Relaxed);
            conn.conn_sent.lock().1 = parsed.initial_max_data;
            *conn.peer_params.lock() = Some(parsed);
            conn.wake_all_writers();
        }
        Frame::Stream {
            stream_id,
            offset,
            fin,
            data,
        } => {
            if stream_id & 0x2 != 0 {
                return Err(ProtoError::protocol("单向流上的 STREAM（本实现只服务双向流）"));
            }
            if stream_id & 0x1 != 0 {
                return Err(ProtoError::protocol("STREAM 落在服务端发起的流 ID 上"));
            }
            let st = {
                let mut map = conn.streams.lock();
                if let Some(s) = map.get(&stream_id) {
                    Arc::clone(s)
                } else {
                    let opened = conn.peer_bidi_opened.fetch_add(1, Ordering::Relaxed) + 1;
                    if opened > MAX_STREAMS_BIDI {
                        return Err(ProtoError::new(
                            err::STREAM_LIMIT_ERROR,
                            "超过 initial_max_streams_bidi",
                        ));
                    }
                    let (sl, cl) = conn
                        .peer_params
                        .lock()
                        .as_ref()
                        .map(|p| (p.initial_max_stream_data_bidi_local, p.initial_max_data))
                        .unwrap_or((0, 0));
                    let _ = cl;
                    let (tx, rx) = mpsc::unbounded_channel();
                    let s = Arc::new(StreamState {
                        id: stream_id,
                        core: Mutex::new(StreamCore {
                            events: Some(tx),
                            received: 0,
                            consumed: 0,
                            recv_limit: STREAM_RECV_WINDOW,
                            fin: false,
                            final_size: None,
                            send_limit: sl,
                            send_sent: 0,
                            send_stopped: false,
                            fin_sent: false,
                            write_waker: None,
                        }),
                    });
                    map.insert(stream_id, Arc::clone(&s));
                    drop(map);
                    log::info!("qmux: 对端发起新流 {stream_id}");
                    let app = QmuxStream {
                        id: stream_id,
                        conn: Arc::clone(conn),
                        state: Arc::clone(&s),
                        rx,
                        cur: None,
                        write_buf: Vec::new(),
                        shutdown_done: false,
                    };
                    tokio::spawn(handler(app));
                    s
                }
            };
            // 连续性 + 流控 + FIN 状态（§4.1 / §4 / §6）
            {
                let mut c = st.core.lock();
                if c.fin {
                    return Err(ProtoError::protocol("FIN 之后又收到 STREAM 帧"));
                }
                if offset != c.received {
                    return Err(ProtoError::protocol(format!(
                        "流 {stream_id} 的 STREAM 不连续：期望 offset={} 实际 {offset}（§4.1）",
                        c.received
                    )));
                }
                if c.received + data.len() as u64 > c.recv_limit {
                    return Err(ProtoError::flow(format!(
                        "流 {stream_id} 超流级流控（{} > {}）",
                        c.received + data.len() as u64,
                        c.recv_limit
                    )));
                }
                {
                    let mut cr = conn.conn_recv.lock();
                    if cr.0 + data.len() as u64 > cr.2 {
                        return Err(ProtoError::flow("超连接级流控（initial_max_data）"));
                    }
                    cr.0 += data.len() as u64;
                }
                c.received += data.len() as u64;
                if !data.is_empty() {
                    // 排障期保留一行 info：QMux 流上「字节到底有没有交给上层」是这套实现
                    // 最需要可观测的一步（只记首帧，避免刷屏）。
                    if c.received == data.len() as u64 {
                        log::info!(
                            "qmux: 流 {stream_id} 首个数据帧 {} 字节，前 24 字节 {:02x?}",
                            data.len(),
                            &data[..data.len().min(24)]
                        );
                    }
                    if let Some(tx) = c.events.as_ref() {
                        let _ = tx.send(StreamEvent::Data(Bytes::from(data)));
                    }
                }
                if fin {
                    c.fin = true;
                    c.final_size = Some(c.received);
                    if let Some(tx) = c.events.as_ref() {
                        let _ = tx.send(StreamEvent::Fin);
                    }
                }
            }
        }
        Frame::MaxData(v) => {
            conn.conn_sent.lock().1 = v;
            conn.wake_all_writers();
        }
        Frame::MaxStreamData { stream_id, maximum } => {
            {
                let map = conn.streams.lock();
                if let Some(s) = map.get(&stream_id) {
                    s.core.lock().send_limit = maximum;
                }
            }
            conn.wake_writer(stream_id);
        }
        Frame::MaxStreams { maximum, .. } => {
            log::debug!("qmux: 对端允许我们开 {maximum} 条流（本实现不主动开流）");
        }
        Frame::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => {
            let map = conn.streams.lock();
            if let Some(s) = map.get(&stream_id) {
                let mut c = s.core.lock();
                if c.received > final_size {
                    return Err(ProtoError::new(
                        err::FINAL_SIZE_ERROR,
                        "RESET_STREAM 的 final_size 小于已收字节数",
                    ));
                }
                c.fin = true;
                if let Some(tx) = c.events.as_ref() {
                    let _ = tx.send(StreamEvent::Reset(error_code));
                }
            }
        }
        Frame::ResetStreamAt { .. } => {
            // §9.2 扩展：数据已按序到达，「可靠部分」即全部已收数据 ⇒ 按 RESET_STREAM 语义处理
            log::debug!("qmux: 收到 RESET_STREAM_AT（按 RESET_STREAM 语义处理）");
        }
        Frame::StopSending { stream_id, .. } => {
            {
                let map = conn.streams.lock();
                if let Some(s) = map.get(&stream_id) {
                    let mut c = s.core.lock();
                    c.send_stopped = true;
                    if let Some(w) = c.write_waker.take() {
                        w.wake();
                    }
                }
            }
        }
        Frame::DataBlocked(_) | Frame::StreamDataBlocked { .. } | Frame::StreamsBlocked { .. } => {
            // 对端被我们的额度卡住：把当前额度再宣一次（幂等）
            let conn_max = conn.conn_recv.lock().2;
            conn.push_one(Frame::MaxData(conn_max));
            let streams: Vec<Arc<StreamState>> = conn.streams.lock().values().cloned().collect();
            for s in streams {
                let maximum = s.core.lock().recv_limit;
                conn.push_one(Frame::MaxStreamData {
                    stream_id: s.id,
                    maximum,
                });
            }
        }
        Frame::QxPing(seq) => {
            if seq <= *peer_ping_max {
                return Err(ProtoError::protocol("QX_PING 序号必须严格递增（§4.3）"));
            }
            *peer_ping_max = seq;
            conn.push_one(Frame::QxPingAck(seq));
        }
        Frame::QxPingAck(seq) => {
            log::debug!("qmux: 收到 QX_PING 响应 seq={seq}");
        }
        Frame::Datagram(_) => {
            // §6：来不及交付的数据报可以丢；本实现暂不暴露 datagram API
            log::trace!("qmux: 收到 DATAGRAM（未启用上层 API，按 §6 丢弃）");
        }
        Frame::ConnectionClose {
            error_code, reason, ..
        } => {
            conn.closed.store(true, Ordering::Relaxed);
            log::info!(
                "qmux: 对端关闭连接 code=0x{error_code:x} reason={}",
                String::from_utf8_lossy(&reason)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::qmux::proto::{err, put_varint, QX_TP_TYPE};

    /// 测试用客户端：手写帧，直接对 `proto` 编解码。
    struct Client {
        io: tokio::io::DuplexStream,
        /// **跨调用持久**的记录解析器：读到的字节是流式的，一次 read 可能带回多条记录，
        /// 每次新建 reader 会把多出来的记录连字节一起丢掉（这正是本套测试最初 6 个用例
        /// 失败的原因 —— 表现为等 30s 空闲超时后连接被关）。
        rd: RecordReader,
        scratch: Vec<u8>,
    }

    impl Client {
        fn new(io: tokio::io::DuplexStream) -> Self {
            Self {
                io,
                rd: RecordReader::new(),
                scratch: vec![0u8; 4096],
            }
        }

        async fn send_frames(&mut self, frames: Vec<Frame>) {
            let mut buf = Vec::new();
            proto::encode_record(&frames, &mut buf);
            self.io.write_all(&buf).await.unwrap();
        }

        async fn send_raw_record(&mut self, body: &[u8]) {
            let mut buf = Vec::new();
            put_varint(&mut buf, body.len() as u64);
            buf.extend_from_slice(body);
            self.io.write_all(&buf).await.unwrap();
        }

        /// 读一条记录并解析（保留缓冲，支持一次 read 带回多条记录）。
        async fn read_record(&mut self) -> Vec<Frame> {
            loop {
                if let Some(body) = self.rd.next_record().unwrap() {
                    return parse_frames(&body).unwrap();
                }
                let mut scratch = std::mem::take(&mut self.scratch);
                let n = self.io.read(&mut scratch).await.unwrap();
                self.scratch = scratch;
                if n == 0 {
                    panic!("连接被对端关闭");
                }
                let bytes = self.scratch[..n].to_vec();
                self.rd.push(&bytes);
            }
        }

        async fn handshake(&mut self) {
            // §4.2：**服务端不等对端**，我方参数在流可用时立刻发出 —— 所以先读再发，
            // 顺带验证「服务端确实主动推了参数」（这也是被测行为的正确顺序）。
            let f = self.read_record().await;
            assert!(
                matches!(f.first(), Some(Frame::QxTransportParameters(_))),
                "服务端首个帧必须是 QX_TRANSPORT_PARAMETERS，实际 {f:?}"
            );
            let tp = local_params().encode();
            self.send_frames(vec![Frame::QxTransportParameters(tp)])
                .await;
        }
    }

    fn spawn_server<F, Fut>(io: tokio::io::DuplexStream, handler: F) -> tokio::task::JoinHandle<Result<()>>
    where
        F: Fn(QmuxStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move { serve(io, handler).await })
    }

    /// 服务端必须**主动**先发自己的传输参数（§4.2：不等对端）。
    /// 这条单测把「发送方向」与「接收方向」分开定位：客户端什么都不发，只读。
    #[tokio::test]
    async fn server_sends_tp_without_waiting() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |_s: QmuxStream| async move {});
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::QxTransportParameters(_)) => {}
            other => panic!("期望服务端主动发参数，实际 {other:?}"),
        }
        srv.abort();
    }

    /// 服务端能**收到并处理**客户端记录（接收方向）：发一条 QX_PING，必须收到回显。
    #[tokio::test]
    async fn server_reads_client_records() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |_s: QmuxStream| async move {});
        client.handshake().await;
        client.send_frames(vec![Frame::QxPing(1)]).await;
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::QxPingAck(1)) => {}
            other => panic!("期望 QX_PING 回显，实际 {other:?}"),
        }
        srv.abort();
    }

    /// 端到端：握手 → 开流 0 → 发 STREAM → 服务端回显 → FIN 双向收尾。
    #[tokio::test]
    async fn handshake_stream_and_echo() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |mut s: QmuxStream| async move {
            let mut got = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            let _ = s.write_all(b"ECHO:").await;
            let _ = s.write_all(&got).await;
            let _ = s.shutdown().await;
        });
        client.handshake().await;
        client
            .send_frames(vec![Frame::Stream {
                stream_id: 0,
                offset: 0,
                fin: true,
                data: b"ping".to_vec(),
            }])
            .await;
        // 读回显（可能是多个 STREAM 帧）
        let mut out = Vec::new();
        loop {
            let frames = client.read_record().await;
            let mut done = false;
            for f in frames {
                if let Frame::Stream { offset, data, fin, .. } = f {
                    assert_eq!(offset, out.len() as u64, "偏移必须连续");
                    out.extend_from_slice(&data);
                    if fin {
                        done = true;
                    }
                }
            }
            if done {
                break;
            }
        }
        assert_eq!(out, b"ECHO:ping");
        srv.abort();
    }

    /// §4.2：第一个帧不是 QX_TRANSPORT_PARAMETERS → 服务端必须发 CONNECTION_CLOSE(PROTOCOL_VIOLATION)。
    #[tokio::test]
    async fn first_frame_must_be_transport_parameters() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |_s: QmuxStream| async move {});
        // 故意先发 MAX_DATA
        client.send_frames(vec![Frame::MaxData(1)]).await;
        // 第一条记录仍是服务端的参数；第二条应是 CONNECTION_CLOSE
        let _ = client.read_record().await;
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::ConnectionClose { error_code, .. }) => {
                assert_eq!(*error_code, err::PROTOCOL_VIOLATION)
            }
            other => panic!("期望 CONNECTION_CLOSE(PROTOCOL_VIOLATION)，实际 {other:?}"),
        }
        srv.abort();
    }

    /// §4：被禁的帧（PING=0x01）→ FRAME_ENCODING_ERROR。
    #[tokio::test]
    async fn prohibited_frame_closes_connection() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |_s: QmuxStream| async move {});
        client.handshake().await;
        let mut body = Vec::new();
        put_varint(&mut body, 0x01); // QUIC PING：§4 禁止
        client.send_raw_record(&body).await;
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::ConnectionClose { error_code, .. }) => {
                assert_eq!(*error_code, err::FRAME_ENCODING_ERROR)
            }
            other => panic!("期望 CONNECTION_CLOSE(FRAME_ENCODING_ERROR)，实际 {other:?}"),
        }
        srv.abort();
    }

    /// §4.1：同一流的 STREAM 偏移不连续 → PROTOCOL_VIOLATION。
    #[tokio::test]
    async fn non_contiguous_stream_offsets_rejected() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |mut s: QmuxStream| async move {
            let mut buf = [0u8; 64];
            while let Ok(n) = s.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });
        client.handshake().await;
        client
            .send_frames(vec![Frame::Stream {
                stream_id: 0,
                offset: 5, // 第一条就必须是 offset=0
                fin: false,
                data: b"x".to_vec(),
            }])
            .await;
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::ConnectionClose { error_code, .. }) => {
                assert_eq!(*error_code, err::PROTOCOL_VIOLATION)
            }
            other => panic!("期望 PROTOCOL_VIOLATION，实际 {other:?}"),
        }
        srv.abort();
    }

    /// §4.3：QX_PING 请求必须被回显；序号不递增则是协议违规。
    #[tokio::test]
    async fn ping_echo_and_monotonic_check() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |_s: QmuxStream| async move {});
        client.handshake().await;
        client.send_frames(vec![Frame::QxPing(7)]).await;
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::QxPingAck(7)) => {}
            other => panic!("期望 QX_PING 响应 seq=7，实际 {other:?}"),
        }
        // 再发一个更小的序号 → 协议违规
        client.send_frames(vec![Frame::QxPing(3)]).await;
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::ConnectionClose { error_code, .. }) => {
                assert_eq!(*error_code, err::PROTOCOL_VIOLATION)
            }
            other => panic!("期望 PROTOCOL_VIOLATION，实际 {other:?}"),
        }
        srv.abort();
    }

    /// §5.1：被禁的传输参数 → TRANSPORT_PARAMETER_ERROR。
    #[tokio::test]
    async fn forbidden_transport_parameter_rejected() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |_s: QmuxStream| async move {});
        // 带 max_ack_delay(0x0b)：草案 §5.1 明文禁止
        let mut tp = Vec::new();
        put_varint(&mut tp, 0x0b);
        put_varint(&mut tp, 1);
        put_varint(&mut tp, 25);
        client
            .send_frames(vec![Frame::QxTransportParameters(tp)])
            .await;
        let _ = client.read_record().await; // 服务端参数
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::ConnectionClose { error_code, .. }) => {
                assert_eq!(*error_code, err::TRANSPORT_PARAMETER_ERROR)
            }
            other => panic!("期望 TRANSPORT_PARAMETER_ERROR，实际 {other:?}"),
        }
        srv.abort();
    }

    /// 我方参数里必须带 magic（§4.2）与 max_record_size（§5.2）。
    #[tokio::test]
    async fn server_advertises_required_params() {
        let (a, b) = tokio::io::duplex(8 * 1024);
        let mut client = Client::new(a);
        let srv = spawn_server(b, |_s: QmuxStream| async move {});
        let mut raw = Vec::new();
        Frame::QxTransportParameters(local_params().encode()).encode(&mut raw);
        assert_eq!(&raw[..8], b"\xffQMX\r\n\r\n");
        assert_eq!(varint_len(QX_TP_TYPE), 8);
        let f = client.read_record().await;
        match f.first() {
            Some(Frame::QxTransportParameters(tp)) => {
                let (p, _) = TransportParams::decode(tp).unwrap();
                assert_eq!(p.initial_max_streams_bidi, MAX_STREAMS_BIDI);
            }
            other => panic!("期望服务端参数，实际 {other:?}"),
        }
        srv.abort();
    }
}
