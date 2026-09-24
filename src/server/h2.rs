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
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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
/// Cap concurrent in-flight H2 stream tasks（与 H2_MAX_CONCURRENT_STREAMS 对齐；
/// 注意 BATCH_CAP 是写合并的帧批量，两者语义不同，勿混用调参）。
static H2_INFLIGHT: once_cell::sync::Lazy<tokio::sync::Semaphore> =
    once_cell::sync::Lazy::new(|| tokio::sync::Semaphore::new(256));
pub const H2_MAX_SEND_BUFFER: usize = 128 * 1024;
pub const H2_COALESCE_WRITES: bool = COALESCE_WRITES_DEFAULT;
/// Soft concurrent-stream hint applied when Builder supports it.
pub const H2_MAX_CONCURRENT_STREAMS: u32 = 256;
pub const H2_INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;

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
    // Note: h2 0.4 Builder has no enable_push / coalesce setter — coalesce is
    // applied via CoalescingIo + BatchWriter above; logged so knobs are visible.

    let mut conn = builder.handshake(io).await?;
    while let Some(result) = conn.accept().await {
        let (request, mut respond) = result?;
        let live = Arc::clone(&live);
        let lc = lc.clone();
        let permit = match H2_INFLIGHT.acquire().await {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    tokio::spawn(async move {
                        let _permit = permit;
            let (parts, mut body) = request.into_parts();
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
                        // 不收 body 直接回包：未读的请求体由 h2 丢弃并释放流控额度
                        //（与上面 413 分支同一做法），连接不受影响。
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
            // P1-9/P1-4：收齐请求体（上限 8MiB）——POST/PUT 才能把 body 交给引擎/admin；
            // 且不排空 H2 请求体会卡住流量控制窗口。超限直接 413。
            let mut buf: Vec<u8> = Vec::new();
            let mut overflow = false;
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(c) => {
                        if buf.len() + c.len() > REQUEST_BODY_CAP {
                            overflow = true;
                            break;
                        }
                        buf.extend_from_slice(&c);
                    }
                    Err(_) => break,
                }
            }
            if overflow {
                let resp = Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(())
                    .unwrap();
                if let Ok(mut send) = respond.send_response(resp, true) {
                    let _ = send.send_data(Bytes::from_static(b"request body too large"), true);
                }
                return;
            }
            let method = parts.method.as_str().to_string();
            let fake = Request::from_parts(parts, Bytes::from(buf));
            let path = fake.uri().path().to_string();
            let t0 = std::time::Instant::now();
            // HSTS 判定要在 handle_h2 之前取：lc 会被 move 进去。
            let is_https = lc.ssl.is_some();
            let mut response = handle_h2(fake, live.clone(), lc, peer).await;
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
            let (parts, data) = response.into_parts();
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
                Some(data.len() as u64),
                t0.elapsed(),
                engine,
            );
            let end = data.is_empty();
            if let Ok(mut send) = respond.send_response(Response::from_parts(parts, ()), end) {
                if !data.is_empty() {
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
    req: Request<Bytes>,
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
            let (method, uri, headers) =
                (req.method().clone(), req.uri().clone(), req.headers().clone());
            if let Some(resp) = crate::server::dns::dot_doh::doh_prepared(
                &dns_eff,
                &method,
                &uri,
                &headers,
                req.body().clone(),
                peer,
            )
            .await
            {
                return tag(collect_to_bytes(resp).await, "dns-doh");
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
    req: Request<Bytes>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    path: String,
) -> Response<Bytes> {
    // 分发顺序必须与 h1 一致（规格 §4：apps 优先于 proxy）。
    // 此前这里是 proxy 在前、apps 在后，还写着「补齐 h1 分发顺序」——恰好相反：
    // 同一条 URL 在 h1 上交给应用引擎、在 h2/h3 上被反代走，行为随协议而变。
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
}
