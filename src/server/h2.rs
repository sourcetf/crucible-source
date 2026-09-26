//! HTTP/2 handler wired through the local `h2` wrapper (BATCH_CAP + send buffer).
//!
//! Fair-gate knobs:
//! - `max_send_buffer_size` → h2 `Builder` (on-wire)
//! - `BATCH_CAP` + coalesce → [`CoalescingIo`] wrapping the socket write path via
//!   [`BatchWriter`] (small writes buffered until cap / flush)

use crate::config::ListenerConfig;
use crate::server::h1::{BoxBody, REQUEST_BODY_CAP};
use crate::server::live_config::LiveConfig;
use crate::server::prefixed_stream::PrefixedStream;
use anyhow::Result;
use bytes::Bytes;
use futures_util::StreamExt;
use h2::{
    framed_write::BatchWriter, server::Builder as H2Builder, BATCH_CAP, COALESCE_WRITES_DEFAULT,
};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use std::io::{self, Write};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Fair-gate knobs retained from overnight tuning.
/// Override at runtime with `CRUCIBLE_BATCH_CAP` (sweep_batch_cap.sh).
pub fn h2_batch_cap() -> usize {
    std::env::var("CRUCIBLE_BATCH_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0 && *n <= 256)
        .unwrap_or(BATCH_CAP)
}

pub const H2_BATCH_CAP: usize = BATCH_CAP;
/// 全局同时在飞 h2 流上限（含排队等配额的阶段）。见 [`H2_INFLIGHT_WAIT`] 与
/// [`serve_io`] 里的说明：配额**只能**在 spawn 出来的任务里获取。
pub const H2_MAX_INFLIGHT: usize = 256;
/// 拿不到在飞配额时的最长等待：超时回 503 而不是无限排队。等待期间连接仍在被驱动
/// （accept 循环不阻塞），所以是「快速失败」而不是「整条连接停摆」。
pub const H2_INFLIGHT_WAIT: Duration = Duration::from_secs(5);
/// 请求体读取的**空闲**超时：两次 `data()` 之间超过该时长即判定为慢速攻击
/// （与 nginx 的 client_body_timeout 同语义），回 408 并结束该流。
/// 注意这是「读不到新字节」的上限，不是整个请求体的总时长上限；分片/断点续传的
/// 停顿发生在两次请求**之间**，不受影响。
pub const H2_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
static H2_INFLIGHT: once_cell::sync::Lazy<Arc<tokio::sync::Semaphore>> =
    once_cell::sync::Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(H2_MAX_INFLIGHT)));
pub const H2_MAX_SEND_BUFFER: usize = 128 * 1024;
pub const H2_COALESCE_WRITES: bool = COALESCE_WRITES_DEFAULT;
/// Soft concurrent-stream hint applied when Builder supports it.
pub const H2_MAX_CONCURRENT_STREAMS: u32 = 256;
pub const H2_INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;

/// 单个请求的头部列表总字节上限（HPACK 解出来之后的量）：无界头列表是内存/CPU 放大面
/// （一个连接反复发巨大头部即可），64KiB 对正常请求足够宽裕，超限 h2 会以
/// ENHANCE_YOUR_CALM/压缩错误终止该流而不是吃掉内存。
pub const H2_MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;

pub async fn serve(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    serve_io(stream, live, lc, peer).await
}

/// Re-inject bytes already read (HTTP/2 connection preface) before handshake.
pub async fn serve_with_prefix(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    prefix: &[u8],
) -> Result<()> {
    let io = PrefixedStream::new(stream, prefix.to_vec());
    serve_io(io, live, lc, peer).await
}

#[cfg(feature = "tls")]
pub async fn serve_tls<IO>(
    stream: IO,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_io(stream, live, lc, peer).await
}

async fn serve_io<IO>(
    stream: IO,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Materialize BatchWriter knobs so they are never silently discarded: they
    // configure CoalescingIo which wraps the socket before handshake.
    let live_cap = h2_batch_cap();
    let batch = BatchWriter::new(())
        .with_cap(live_cap)
        .with_coalesce(H2_COALESCE_WRITES);
    let coalesce = batch.coalesce_enabled();
    let cap = batch.cap();
    log::info!(
        "h2 knobs peer={peer} BATCH_CAP={cap} coalesce={coalesce} max_send_buffer={H2_MAX_SEND_BUFFER} \
         max_concurrent_streams={H2_MAX_CONCURRENT_STREAMS} initial_window={H2_INITIAL_WINDOW_SIZE}"
    );

    let io = CoalescingIo::new(stream, coalesce, cap);

    let mut builder = H2Builder::new();
    builder.max_send_buffer_size(H2_MAX_SEND_BUFFER);
    // Apply every Builder option the crates.io h2 API exposes for these knobs.
    builder.initial_window_size(H2_INITIAL_WINDOW_SIZE);
    builder.initial_connection_window_size(H2_INITIAL_WINDOW_SIZE);
    builder.max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
    builder.max_header_list_size(H2_MAX_HEADER_LIST_SIZE);
    // Note: h2 0.4 Builder has no enable_push / coalesce setter — coalesce is
    // applied via CoalescingIo + BatchWriter above; logged so knobs are visible.

    let mut conn = builder.handshake(io).await?;
    while let Some(result) = conn.accept().await {
        let (request, mut respond) = result?;
        let live = Arc::clone(&live);
        let lc = lc.clone();
        let sem = H2_INFLIGHT.clone();
        tokio::spawn(async move {
            // P0（DoS）：配额**绝不能**在 accept 循环里 await —— await 期间 `conn` 不被
            // poll，连接驱动停摆（回应写不出、WINDOW_UPDATE 发不出、其他流全部卡住），
            // 一条恶意连接持满 256 个慢速流即可让**所有** h2 连接失去响应。
            // 改成任务内获取 + 限时等待：拿不到配额就快速回 503，连接继续被驱动，
            // 正常突发（短暂排队）仍按原语义处理。
            let _permit = match tokio::time::timeout(
                H2_INFLIGHT_WAIT,
                sem.acquire_owned(),
            )
            .await
            {
                Ok(Ok(p)) => p,
                _ => {
                    let t0 = std::time::Instant::now();
                    let mut b = Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header(http::header::RETRY_AFTER, "1");
                    b = b.header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
                    crate::server::access_log::log_response(
                        &live,
                        peer,
                        "h2",
                        request.method().as_str(),
                        request.uri().path(),
                        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                        None,
                        t0.elapsed(),
                        "busy",
                    );
                    // 不读 body 直接回包：流关闭时 h2 会自动归还连接级窗口
                    // （recv.rs release_closed_capacity），不会占住连接窗口。
                    if let Ok(mut send) = respond.send_response(b.body(()).unwrap(), false) {
                        let _ = send.send_data(Bytes::from_static(b"server busy"), true);
                    }
                    return;
                }
            };
            let (parts, body) = request.into_parts();
            // 与 h1 同序的 admin 前置门（见 basic_auth::admin_gate）：**先判鉴权/CSRF、
            // 再收 body**。否则不带凭据的并发 POST 每个都能占住 REQUEST_BODY_CAP（8MiB）
            // 的缓冲，等于不用通过鉴权就能放大内存。
            {
                let snap = live.snapshot();
                if parts.uri.path().starts_with(&snap.admin.path) {
                    let t0 = std::time::Instant::now();
                    use crate::server::basic_auth::{admin_gate, retry_after_secs, AdminGate};
                    // (状态码, Retry-After, 文案)；None = 已过鉴权门，交给 admin::handle
                    // 判定顺序与 h1/h3 的「ACL → CSRF → 鉴权门」一致：ACL 是**无状态**的
                    // 纯判定，提前到收 body 之前做不会影响限流计数，因此这里先补判一次；
                    // 限流是有状态的（消耗令牌），仍留在 handle_h2 里只算一次。
                    let reject: Option<(StatusCode, Option<u64>, &'static str)> =
                        if !crate::server::access::is_allowed(&snap.ip_access, peer) {
                            let (st, msg) = crate::server::access::deny_response();
                            Some((st, None, msg))
                        } else if !snap.admin.listener_allowed(lc.port) {
                            // P2-21：非允许端口上的 admin 路径必须回 **404** 而不是 401 ——
                            // 401 会让浏览器弹出 Basic 口令框，等于诱导口令在未授权/明文口上
                            // 线传输。h1 的这条检查位于 admin 分支之前，这里提前到收 body
                            // 之前补上，保证三协议同语义（判定无状态，不影响限流计数）。
                            Some((StatusCode::NOT_FOUND, None, "not found"))
                        } else if crate::server::access::cross_site_blocked(&parts.headers) {
                            let (st, msg) = crate::server::access::cross_site_response();
                            Some((st, None, msg))
                        } else {
                            match admin_gate(&parts.headers, &snap.admin, peer.ip()) {
                                AdminGate::Proceed => None,
                                AdminGate::Unauthorized => Some((
                                    StatusCode::UNAUTHORIZED,
                                    None,
                                    "unauthorized",
                                )),
                                AdminGate::Throttled(d) => Some((
                                    StatusCode::TOO_MANY_REQUESTS,
                                    Some(retry_after_secs(d)),
                                    "too many failed authentication attempts",
                                )),
                            }
                        };
                    if let Some((status, retry, msg)) = reject {
                        // 安全拒绝也要落访问日志（h1 的同类分支在 handle_request 完成侧统一记，
                        // 这里提前 return 会绕过下面那段日志 —— 否则爆破/扫描命中的这条路径
                        // 在 access log 里完全不可见）。
                        crate::server::access_log::log_response(
                            &live,
                            peer,
                            "h2",
                            parts.method.as_str(),
                            parts.uri.path(),
                            status.as_u16(),
                            None,
                            t0.elapsed(),
                            "acl",
                        );
                        let mut b = Response::builder().status(status);
                        if status == StatusCode::UNAUTHORIZED {
                            b = b.header(
                                http::header::WWW_AUTHENTICATE,
                                format!("Basic realm=\"{}\"", snap.admin.realm),
                            );
                        }
                        if let Some(secs) = retry {
                            b = b.header(http::header::RETRY_AFTER, secs.to_string());
                        }
                        // 不收 body 直接回包：未读的 DATA 留在该流接收缓冲里，任务结束、
                        // 流被释放时 h2 会归还**连接级**窗口并清空缓冲
                        // （recv.rs::release_closed_capacity：「Normal drop without
                        // reading: buf=in_flight -> full release」），所以不会占住连接窗口。
                        // 该流的流级窗口不再归还——但那条流已经从我们这边结束了。
                        match respond.send_response(b.body(()).unwrap(), false) {
                            Ok(mut send) => {
                                let _ = send.send_data(Bytes::from_static(msg.as_bytes()), true);
                            }
                            Err(e) => log::debug!("h2 admin pre-gate send peer={peer}: {e}"),
                        }
                        return;
                    }
                }
            }
            // P1-9/P1-4：请求体的取舍。
            //
            // 只有**上传**分支需要流式 body（大文件直接写盘，不受 8MiB 单请求上限约束）；
            // 其余分支（admin/apps/proxy/DoH/static）都要 `Bytes` 形态，统一走 [`collect_bytes`]。
            // 这里只是**预判像不像上传**，各分支还会按需自行收齐 —— 因此 page_rules 改写路径、
            // 或 app/proxy 抢走 URL 时，最坏只是少一次流式机会，不会出现语义分叉。
            //
            // P0（真 bug，实测 >1MiB 必卡死）已修：归还接收窗口的责任在**调用方**
            // （h2 0.4 契约），流式路径由 [`H2RecvBody`] 逐帧归还，收齐路径由它内部同样归还。
            let method = parts.method.as_str().to_string();
            let pre_path = parts.uri.path().to_string();
            let is_upload_like = matches!(
                parts.method,
                http::Method::PUT | http::Method::PATCH | http::Method::POST
            ) && !crate::server::apps::would_handle(&lc, &pre_path)
                && !would_proxy(&lc, &pre_path)
                && crate::server::upload_api::enabled_for(&lc, &pre_path);
            let req: Request<H2Body> = if is_upload_like {
                // 注意：这里必须用**泛型**的 `combinators::BoxBody::new`（错误类型擦除成
                // Box<dyn Error>），不能用 h1 的 `BoxBody` 别名（那个的 Error 是 Infallible）。
                Request::from_parts(
                    parts,
                    http_body_util::combinators::BoxBody::new(H2RecvBody::new(body)),
                )
            } else {
                let boxed = Request::from_parts(
                    parts,
                    http_body_util::combinators::BoxBody::new(H2RecvBody::new(body)),
                );
                match collect_bytes(boxed, REQUEST_BODY_CAP).await {
                    Ok(r) => {
                        let (p, b) = r.into_parts();
                        Request::from_parts(p, bytes_body(b))
                    }
                    Err(resp) => {
                        // 与旧行为一致：超限 413 / 空闲超时 408 / 读错 400，直接回包。
                        let (rp, data) = resp.into_parts();
                        if let Ok(mut send) =
                            respond.send_response(Response::from_parts(rp, ()), false)
                        {
                            if !data.is_empty() {
                                let _ = send.send_data(data, true);
                            }
                        }
                        return;
                    }
                }
            };
            let t0 = std::time::Instant::now();
            // HSTS 判定要在 handle_h2 之前取：lc 会被 move 进去。
            let is_https = lc.ssl.is_some();
            let mut response = handle_h2(req, live.clone(), lc, peer).await;
            // 访问日志用的路径：与旧实现一致，记**改写前**的请求路径（改写发生在
            // handle_h2 内部的副本上，这里拿不到也不需要）。
            let path = pre_path;
            // HTTPS 响应统一补 HSTS。此前只有 h1.rs 做了这件事，h2/h3 完全没有——
            // 而 h2/h3 才是主用协议，等于「开了 TLS 却不发 HSTS」。
            // entry().or_insert 不覆盖分支已显式设置的值，与 h1 语义一致。
            if is_https {
                response
                    .headers_mut()
                    .entry(http::header::STRICT_TRANSPORT_SECURITY)
                    .or_insert_with(|| {
                        http::HeaderValue::from_static(crate::server::h1::hsts_header())
                    });
            }
            let (mut parts, data) = response.into_parts();
            // 大文件（static 层 FileSource 标记）：用 DATA 帧分块从磁盘读，避免整读进内存。
            let file_src = parts
                .extensions
                .remove::<crate::server::static_files::FileSource>();
            let engine = parts
                .extensions
                .get::<crate::server::access_log::EngineTag>()
                .map(|t| t.0)
                .unwrap_or("http");
            // P1-11：完成侧全字段访问日志；h2 侧拿得到精确响应字节数。
            crate::server::access_log::log_response(
                &live,
                peer,
                "h2",
                &method,
                &path,
                parts.status.as_u16(),
                // 流式响应（FileSource）日志记真实长度，而不是空 body 的 0
                Some(file_src.as_ref().map(|s| s.len).unwrap_or(data.len() as u64)),
                t0.elapsed(),
                engine,
            );
            let end = file_src.is_none() && data.is_empty();
            if let Ok(mut send) = respond.send_response(Response::from_parts(parts, ()), end) {
                if let Some(src) = file_src {
                    // 大文件：按 64KiB 分块读盘、逐帧发送。`send_data` 自带 h2 流控背压
                    //（窗口满时 Pending），所以读盘被发送速率拉住，文件不会进内存。
                    // 循环体里不用 `?`（外层是 spawn 的 `async move` 块，返回 ()）。
                    use tokio::io::{AsyncReadExt, AsyncSeekExt};
                    match tokio::fs::File::open(&src.path).await {
                        Ok(mut f) => {
                            let mut left = src.len;
                            if src.start > 0
                                && f.seek(std::io::SeekFrom::Start(src.start)).await.is_err()
                            {
                                log::warn!("h2 stream_file seek {} peer={peer}", src.path.display());
                                left = 0;
                            }
                            let mut buf =
                                vec![0u8; crate::server::static_files::STREAM_CHUNK];
                            while left > 0 {
                                let want = left.min(buf.len() as u64) as usize;
                                match f.read(&mut buf[..want]).await {
                                    Ok(0) => {
                                        log::warn!("h2 stream_file 提前 EOF peer={peer}");
                                        break;
                                    }
                                    Ok(n) => {
                                        left -= n as u64;
                                        if let Err(e) =
                                            send.send_data(Bytes::copy_from_slice(&buf[..n]), false)
                                        {
                                            log::debug!("h2 stream_file send_data peer={peer}: {e}");
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("h2 stream_file read peer={peer}: {e}");
                                        break;
                                    }
                                }
                            }
                            if let Err(e) = send.send_data(Bytes::new(), true) {
                                log::debug!("h2 stream_file end peer={peer}: {e}");
                            }
                        }
                        Err(e) => log::warn!(
                            "h2 stream_file open {} peer={peer}: {e}",
                            src.path.display()
                        ),
                    }
                } else if !data.is_empty() {
                    let _ = send.send_data(data, true);
                }
            }
        });
    }
    Ok(())
}

/// admin::handle 返回 `Response<BoxBody>`（h1 体类型）；h2 分支收齐为 `Response<Bytes>`。
async fn collect_to_bytes(resp: Response<BoxBody>) -> Response<Bytes> {
    let (parts, body) = resp.into_parts();
    let data = BodyExt::collect(body)
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    Response::from_parts(parts, data)
}

/// h2 请求体的「装箱」类型：既能装已收齐的 `Bytes`，也能装**流式**的 h2 `RecvStream`。
/// 错误类型擦除成 `Box<dyn Error + Send + Sync>`，两种形态才能共用同一个请求类型
/// （否则每个分发分支都要泛型化，改动面大得多）。
pub type H2Body =
    http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// 把已收齐的 `Bytes` 装成 [`H2Body`]。
fn bytes_body(b: Bytes) -> H2Body {
    Full::new(b)
        .map_err(|e: std::convert::Infallible| -> Box<dyn std::error::Error + Send + Sync> {
            match e {}
        })
        .boxed()
}

/// 统一的纯文本响应（h2 的响应体类型是 `Bytes`）。
fn plain(status: StatusCode, msg: &str) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Bytes::from(msg.to_string()))
        .unwrap()
}

/// 收齐请求体（≤ `cap`）→ `Request<Bytes>`；超限/**空闲超时**/读错的响应直接返回。
///
/// 只有上传分支**不**走这里（那里的 body 要流式写盘，见 [`H2RecvBody`]）；
/// 其余分支（admin/apps/proxy/DoH）的引擎与接口本来就是 `Bytes` 形态。
async fn collect_bytes(
    req: Request<H2Body>,
    cap: usize,
) -> Result<Request<Bytes>, Response<Bytes>> {
    let (parts, mut body) = req.into_parts();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let frame = match tokio::time::timeout(H2_BODY_IDLE_TIMEOUT, body.frame()).await {
            Ok(Some(Ok(f))) => f,
            Ok(Some(Err(e))) => {
                log::debug!("h2 body read: {e}");
                return Err(plain(StatusCode::BAD_REQUEST, "request body read failed"));
            }
            Ok(None) => break,
            Err(_) => {
                return Err(plain(
                    StatusCode::REQUEST_TIMEOUT,
                    "request body read timeout",
                ))
            }
        };
        let Some(data) = frame.data_ref() else { continue };
        if buf.len() + data.len() > cap {
            return Err(plain(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large for this protocol (single-request limit 8MiB); \
use chunked uploads (Content-Range) or HTTP/1.1 for larger bodies",
            ));
        }
        buf.extend_from_slice(data);
    }
    Ok(Request::from_parts(parts, Bytes::from(buf)))
}

/// h2 请求体的**流式**适配：直接驱动 `RecvStream`，每帧归还接收窗口，带空闲超时。
///
/// 为什么必须显式归还窗口：h2 0.4 不在 `Bytes` 被丢弃时自动归还，契约写明由调用方
/// `flow_control().release_capacity(n)`（见 recv.rs）；少了它 ⇒ 收满初始窗口（1MiB）
/// 后窗口停在 0，对端发不出、我们等不到，**双向互等**（已实测挂死）。
/// 归还推迟到**下一次** poll：消费方拿到帧就立刻处理，推迟一轮不影响吞吐，
/// 却避免了「还没交付就先归还」的语义问题。
struct H2RecvBody {
    inner: h2::RecvStream,
    pending_release: usize,
    idle: std::pin::Pin<Box<tokio::time::Sleep>>,
    timed_out: bool,
}

impl H2RecvBody {
    fn new(inner: h2::RecvStream) -> Self {
        Self {
            inner,
            pending_release: 0,
            idle: Box::pin(tokio::time::sleep(H2_BODY_IDLE_TIMEOUT)),
            timed_out: false,
        }
    }
}

impl hyper::body::Body for H2RecvBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.pending_release > 0 {
            let n = std::mem::take(&mut this.pending_release);
            if this.inner.flow_control().release_capacity(n).is_err() {
                return Poll::Ready(None);
            }
        }
        if this.idle.as_mut().poll(cx).is_ready() {
            this.timed_out = true;
            return Poll::Ready(Some(Err("h2 request body idle timeout".into())));
        }
        match this.inner.poll_data(cx) {
            Poll::Ready(Some(Ok(b))) => {
                this.idle
                    .as_mut()
                    .reset(tokio::time::Instant::now() + H2_BODY_IDLE_TIMEOUT);
                this.pending_release = b.len();
                Poll::Ready(Some(Ok(hyper::body::Frame::data(b))))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        // 长度由请求头给出（Content-Length）；这里不谎报，让下游按帧读。
        hyper::body::SizeHint::new()
    }
}

/// AsyncWrite wrapper that coalesces small writes using the same semantics as
/// [`BatchWriter`] (buffer until `cap` frames, or flush immediately when coalesce=false).
struct CoalescingIo<IO> {
    inner: IO,
    coalesce: bool,
    cap: usize,
    pending_frames: usize,
    buf: Vec<u8>,
}

impl<IO> CoalescingIo<IO> {
    fn new(inner: IO, coalesce: bool, cap: usize) -> Self {
        Self {
            inner,
            coalesce,
            cap: cap.max(1),
            pending_frames: 0,
            buf: Vec::with_capacity(16 * 1024),
        }
    }

    fn should_flush_after_push(&self) -> bool {
        !self.coalesce || self.pending_frames >= self.cap || self.buf.len() >= 16 * 1024
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for CoalescingIo<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for CoalescingIo<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if !self.coalesce {
            return Pin::new(&mut self.inner).poll_write(cx, data);
        }
        // Buffer this frame; flush when batch is full (BatchWriter semantics).
        // AsyncWrite 契约：返回 Pending/Err 表示本次 data 未被消费，调用方会原样重试——
        // 必须把刚缓冲的这帧撤回，否则重试后同一帧会在线上出现两份。
        let pre_len = self.buf.len();
        let pre_frames = self.pending_frames;
        self.buf.extend_from_slice(data);
        self.pending_frames = self.pending_frames.saturating_add(1);
        if self.should_flush_after_push() {
            let pending = std::mem::take(&mut self.buf);
            self.pending_frames = 0;
            match Pin::new(&mut self.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) => {
                    if n < pending.len() {
                        // Re-queue remainder + count as one pending frame.
                        self.buf.extend_from_slice(&pending[n..]);
                        self.pending_frames = 1;
                    }
                    Poll::Ready(Ok(data.len()))
                }
                Poll::Ready(Err(e)) => {
                    self.buf = pending;
                    self.buf.truncate(pre_len);
                    self.pending_frames = pre_frames;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => {
                    self.buf = pending;
                    self.buf.truncate(pre_len);
                    self.pending_frames = pre_frames;
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(data.len()))
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // P2-3：部分写后不能直接返回 Pending——内层刚返回 Ready 时未必注册了 waker，
        // 直接 Pending 会写悬挂。余量留在缓冲里立即重试推进；只有内层自身 Pending
        //（waker 已注册）才向调用方返回 Pending。
        while self.coalesce && !self.buf.is_empty() {
            let pending = std::mem::take(&mut self.buf);
            self.pending_frames = 0;
            match Pin::new(&mut self.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n < pending.len() => {
                    self.buf.extend_from_slice(&pending[n..]);
                    self.pending_frames = 1;
                    continue;
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => {
                    self.buf = pending;
                    self.pending_frames = 1;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.buf = pending;
                    self.pending_frames = 1;
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Sync Write shim so unit tests / docs can drive BatchWriter against the same knobs.
#[allow(dead_code)]
fn batch_write_demo(frames: &[&[u8]], coalesce: bool, cap: usize) -> io::Result<Vec<u8>> {
    let mut w = BatchWriter::new(Vec::new())
        .with_coalesce(coalesce)
        .with_cap(cap);
    for f in frames {
        w.write_frame(f)?;
    }
    w.flush_batch()?;
    w.into_inner()
}

async fn handle_h2(
    req: Request<H2Body>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Response<Bytes> {
    use crate::server::static_files;

    let mut req = req;
    let path = req.uri().path().to_string();
    crate::server::telemetry::record_request();

    let snap = live.snapshot();
    // DoH 分流已下移到 ACL/限速之后（见下方），此处不再提前返回。
    if !crate::server::access::is_allowed(&snap.ip_access, peer) {
        return tag(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Bytes::from_static(b"forbidden by ip_access"))
                .unwrap(),
            "acl",
        );
    }

    if let Some(rl) = &lc.rate_limit {
        if rl.enabled {
            let ok = if rl.per_path {
                crate::server::rate_limit::allow_path(
                    peer.ip(),
                    &path,
                    rl.rate_per_sec,
                    rl.burst,
                )
            } else {
                crate::server::rate_limit::allow(peer.ip(), rl.rate_per_sec, rl.burst)
            };
            if !ok {
                return tag(
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .body(Bytes::from_static(b"rate limit exceeded"))
                        .unwrap(),
                    "acl",
                );
            }
        }
    }

    // /__metrics 必须排在 ip_access + 限流**之后**（此前是 handle_h2 的第一个分支，
    // 于是用 IP 白名单当边界的部署把它暴露给任何人）。与 h1 完全一致：排在 basic_auth
    // **之前**（listener 口令与「谁能抓指标」是两件事），指标的门在 telemetry 内部按
    // [admin].metrics_public 判定（默认要求管理员凭据）。
    if let Some(resp) =
        crate::server::telemetry::maybe_handle_simple(&req, &snap.telemetry, &snap.admin, peer.ip())
    {
        return tag(resp, "telemetry");
    }

    // DoH 挪到这里（ACL/限速之后、basic auth 之前）：
    // 原先排在 is_allowed 之前，等于绕过监听器 IP 白名单与限速白拿一个递归解析器；
    // 而排在 basic auth 之前是因为 DoH 客户端无法交互式提供 Basic 凭据。
    {
        let dns_eff = crate::server::dns::effective(&snap);
        if dns_eff.enabled && dns_eff.doh.enabled {
            // 只有「确实是 DoH 请求」才收 body —— 否则会给普通上传白白套上 8MiB 上限。
            // 判定条件与 doh_prepared 的前几个早退分支保持一致（path + host）。
            let host = req.headers().get(http::header::HOST).cloned();
            if crate::server::dns::dot_doh::is_doh_request(&dns_eff, req.uri().path(), host.as_ref())
            {
                let collected = match collect_bytes(req, REQUEST_BODY_CAP).await {
                    Ok(r) => r,
                    Err(resp) => return tag(resp, "dns-doh"),
                };
                let (parts, body) = collected.into_parts();
                let (method, uri, headers) = (
                    parts.method.clone(),
                    parts.uri.clone(),
                    parts.headers.clone(),
                );
                let body_for_rest = body.clone();
                if let Some(resp) = crate::server::dns::dot_doh::doh_prepared(
                    &dns_eff,
                    &method,
                    &uri,
                    &headers,
                    body,
                    peer,
                )
                .await
                {
                    return tag(collect_to_bytes(resp).await, "dns-doh");
                }
                req = Request::from_parts(parts, bytes_body(body_for_rest));
            }
        }
    }

    // P0-1：listener 级 Basic Auth（§16.1 分发顺序）——此前 h2 完全缺失该检查，
    // 配置了 basic_auth 的站点在 ALPN=h2 / prior-knowledge 下对任何人敞开。
    // 与 h1 同一实现（check_listener_headers_at）：带来源 IP 的失败退避，
    // 退避期回 429 而不是再跑一次 argon2。
    if let Some(ba) = &lc.basic_auth {
        match crate::server::basic_auth::check_listener_headers_at(req.headers(), ba, peer.ip()) {
            crate::server::basic_auth::BasicCheck::Ok => {}
            crate::server::basic_auth::BasicCheck::Unauthorized => {
                return tag(
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(
                            http::header::WWW_AUTHENTICATE,
                            format!("Basic realm=\"{}\"", ba.realm),
                        )
                        .body(Bytes::from_static(b"unauthorized"))
                        .unwrap(),
                    "acl",
                )
            }
            crate::server::basic_auth::BasicCheck::Throttled(d) => {
                return tag(
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header(
                            http::header::RETRY_AFTER,
                            crate::server::basic_auth::retry_after_secs(d).to_string(),
                        )
                        .body(Bytes::from_static(b"too many failed authentication attempts"))
                        .unwrap(),
                    "acl",
                )
            }
        }
    }

    // P2-21（任务 4）：admin 暴露面——[admin].listeners_allow 非空时仅列出的端口可达。
    if path.starts_with(&snap.admin.path) && !snap.admin.listener_allowed(lc.port) {
        return tag(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Bytes::from_static(b"not found"))
                .unwrap(),
            "acl",
        );
    }

    // P2-8（§16.18）：status_path 接线（与 h1 一致；尊重 ip_access/限速/basic_auth）。
    if lc.status_path.as_deref() == Some(path.as_str()) {
        return tag(
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Bytes::from(include_str!("status_page.html")))
                .unwrap(),
            "status",
        );
    }

    // admin：P1-4——走与 h1 完全一致的 admin::handle（UI + 全部 API + CSRF/Basic 鉴权）。
    // 旧实现对 /__admin/api/* 只回 UI shell，新二进制一旦链接 12 个 tab 的 API 在 h2 全失效。
    if path.starts_with(&snap.admin.path) {
        // admin::handle 是 h1 体类型（Bytes）的接口：先收齐（≤8MiB）。
        let req = match collect_bytes(req, REQUEST_BODY_CAP).await {
            Ok(r) => r,
            Err(resp) => return tag(resp, "admin"),
        };
        let resp = crate::server::admin::handle(req.map(Full::new), live).await;
        // 兜底记账（与 h1 同语义）：鉴权与失败退避已在 admin_gate 里完成，这里只在
        // 「过了门却仍回 401」（两次校验之间配置被热重载）时补记一次。
        crate::server::basic_auth::note_admin_result(peer.ip(), resp.status());
        let mut resp = collect_to_bytes(resp).await;
        resp.extensions_mut()
            .insert(crate::server::access_log::EngineTag("admin"));
        return resp;
    }

    // page_rules: block/redirect(apply_simple) + rewrite(路径改写) + cache/header(响应头)
    if let Some((status, location)) = crate::server::page_rules::apply_simple(&lc, &path) {
        if status == StatusCode::FORBIDDEN {
            return tag(
                Response::builder()
                    .status(status)
                    .body(Bytes::from_static(b"blocked by page rule"))
                    .unwrap(),
                "rule",
            );
        }
        return tag(
            Response::builder()
                .status(status)
                .header(http::header::LOCATION, location)
                .body(Bytes::new())
                .unwrap(),
            "rule",
        );
    }
    if let Some(np) = crate::server::page_rules::rewrite_path(&lc, &path) {
        let pq = match req.uri().query() {
            Some(q) => format!("{np}?{q}"),
            None => np,
        };
        if let Ok(u) = pq.parse() {
            *req.uri_mut() = u;
        }
    }
    // 改写后必须以新路径做后续判定与分发（同 h1 的修正：此前 pre/post 路径混用，
    // 会导致 would_handle/would_proxy 与真正 handler 看到的路径不一致）。
    let path = req.uri().path().to_string();
    // P1-5：h1 的 pass_upstream（page rule pass 动作）在 h2 同样生效。
    if let Some((murl, upstream)) = crate::server::page_rules::pass_upstream(&lc, &path) {
        // proxy_page_rule 需要 h1 体类型（Bytes）：先收齐（≤8MiB）。
        let req = match collect_bytes(req, REQUEST_BODY_CAP).await {
            Ok(r) => r,
            Err(resp) => return tag(resp, "proxy"),
        };
        let resp = crate::server::proxy::proxy_page_rule(
            req.map(Full::new),
            &murl,
            &upstream,
            peer.ip(),
            lc.ssl.is_some(),
        )
        .await;
        return tag(collect_to_bytes(resp).await, "proxy");
    }
    let resp_mods = crate::server::page_rules::response_headers(&lc, &path);
    let mut resp = h2_tail(req, live, lc, peer, path).await;
    for (name, value) in resp_mods {
        if let (Ok(nn), Ok(vv)) = (
            name.parse::<http::header::HeaderName>(),
            http::header::HeaderValue::from_str(&value),
        ) {
            resp.headers_mut().insert(nn, vv);
        }
    }
    resp
}

async fn h2_tail(
    req: Request<H2Body>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    path: String,
) -> Response<Bytes> {
    // 分发顺序必须与 h1 一致（规格 §4：apps 优先于 proxy），上传排在 apps/proxy **之后**、
    // 静态**之前**（与 h1 相同）。这里的 `upload_like` 只是「apps/proxy 都不会接管这条 URL」
    // 的等价判定（`would_handle`/`would_proxy` 与两个执行分支用的是同一组谓词），
    // 用来决定**要不要把 body 保持流式**——顺序本身仍由下面各分支的先后保证。
    let upload_like = matches!(
        *req.method(),
        http::Method::PUT | http::Method::PATCH | http::Method::POST
    ) && !crate::server::apps::would_handle(&lc, &path)
        && !would_proxy(&lc, &path)
        && crate::server::upload_api::enabled_for(&lc, &path);
    if upload_like {
        // 流式上传：body 不进内存，逐帧落盘（上限 2GiB，见 upload_resume::MAX_UPLOAD_BYTES）。
        return tag(
            crate::server::upload_api::handle_stream(req, &lc, peer).await,
            "upload",
        );
    }
    // 其余分支都要 Bytes 形态（引擎 FFI、代理上游、静态层都按 Bytes 传参）。
    let req = match collect_bytes(req, REQUEST_BODY_CAP).await {
        Ok(r) => r,
        Err(resp) => return tag(resp, "static"),
    };
    if let Some(resp) = crate::server::apps::try_handle_simple(&req, &live, &lc, peer).await {
        return tag(resp, "app");
    }
    if would_proxy(&lc, &path) {
        if let Some((_matched, resp)) =
            crate::server::proxy::try_proxy(&lc, req.map(Full::new), peer.ip()).await
        {
            return tag(collect_to_bytes(resp).await, "proxy");
        }
        return tag(
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Bytes::from_static(b"proxy rule matched but produced no response"))
                .unwrap(),
            "proxy",
        );
    }
    // §44 上传：仅当该路径开了 autoindex + enable_upload 时接管写方法。
    // 走到这里说明 body 已被收齐（上面 apps/proxy 需要 Bytes），用 `handle_bytes` 适配。
    if matches!(
        *req.method(),
        http::Method::PUT | http::Method::PATCH | http::Method::POST
    ) && crate::server::upload_api::enabled_for(&lc, &path)
    {
        return tag(
            crate::server::upload_api::handle_bytes(req, &lc, peer).await,
            "upload",
        );
    }
    match crate::server::static_files::serve_simple(&req, &lc).await {
        Ok(r) => tag(r, "static"),
        Err(_) => tag(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Bytes::from_static(b"not found"))
                .unwrap(),
            "static",
        ),
    }
}

fn would_proxy(lc: &ListenerConfig, path: &str) -> bool {
    lc.proxy_rules.iter().any(|r| path.starts_with(&r.path))
}

fn tag(mut resp: Response<Bytes>, engine: &'static str) -> Response<Bytes> {
    resp.extensions_mut()
        .insert(crate::server::access_log::EngineTag(engine));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_writer_knobs_apply() {
        let out = batch_write_demo(&[b"a", b"b", b"c"], true, 3).unwrap();
        assert_eq!(out, b"abc");
    }

    /// P0-1 回归：h2 dispatch 顺序必须含 listener 级 basic_auth。
    #[test]
    fn h2_dispatch_order_has_basic_auth() {
        let src = include_str!("h2.rs");
        let handle_pos = src.find("async fn handle_h2").expect("handle_h2");
        let tail = &src[handle_pos..];
        let ba = tail.find("check_listener_headers").expect("basic_auth check");
        let admin = tail.find("admin::handle").expect("admin call");
        let ip = tail.find("is_allowed").expect("ip_access");
        assert!(ip < ba && ba < admin, "order must be ip_access → basic_auth → admin");
    }

    /// P0 回归：请求体适配器必须显式归还 h2 接收窗口（release_capacity）。
    /// h2 0.4 不会在 Bytes 丢弃时归还（契约要求调用方显式归还）；少这一步
    /// → body > 初始窗口（1MiB）时对端发不出、我们等不到，双向卡死。
    #[test]
    fn h2_body_loop_releases_recv_capacity() {
        let src = include_str!("h2.rs");
        let pos = src
            .find("impl hyper::body::Body for H2RecvBody")
            .expect("H2RecvBody impl");
        let tail = &src[pos..];
        let rel = tail.find("release_capacity").expect("release_capacity missing");
        let poll = tail.find("poll_data").expect("poll_data missing");
        assert!(
            rel < poll,
            "release_capacity 必须在 H2RecvBody 里、poll_data 之前（先归还上一帧再取下一帧）"
        );
    }

    /// 上传走流式、其余分支走收齐：两条路径都必须存在，且上传不再先收齐。
    #[test]
    fn h2_upload_uses_streaming_body() {
        let src = include_str!("h2.rs");
        let pos = src.find("async fn h2_tail").expect("h2_tail");
        let tail = &src[pos..];
        let stream = tail.find("handle_stream").expect("handle_stream call");
        let collect = tail.find("collect_bytes").expect("collect_bytes call");
        assert!(
            stream < collect,
            "上传分支必须在收齐之前用流式 body（否则又是 8MiB 上限）"
        );
    }

    /// P0 回归：在飞配额不得在 accept 循环里 await（await 期间 conn 不被 poll，
    /// 连接驱动停摆 → 一条恶意连接即可让所有 h2 连接失去响应）。
    #[test]
    fn h2_inflight_permit_not_awaited_in_accept_loop() {
        let src = include_str!("h2.rs");
        let loop_pos = src
            .find("while let Some(result) = conn.accept().await")
            .expect("accept loop");
        let tail = &src[loop_pos..];
        let spawn_pos = tail.find("tokio::spawn").expect("spawn");
        assert!(
            !tail[..spawn_pos].contains("acquire"),
            "permit acquisition must happen inside the spawned task, not in the accept loop"
        );
    }
}
