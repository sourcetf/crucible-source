//! HTTP/1.1 request handler (hyper 1.x).

use crate::config::ListenerConfig;
use crate::server::apps;
use crate::server::live_config::LiveConfig;
use crate::server::prefixed_stream::PrefixedStream;
use crate::server::static_files;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;


/// HSTS header value (RFC 6797) — applied to all HTTPS responses.
pub fn hsts_header() -> &'static str {
    "max-age=31536000; includeSubDomains; preload"
}

/// Host 头是否「像个主机名」——用于 port_reuse 明文口构造 301 Location。
///
/// 只需挡住明显不像主机名的输入（含空格、斜杠、`@`、`?`、`#`、控制字符），
/// 避免把客户端可控的 Host 原样拼进 Location 造成开放重定向。
/// 允许字母/数字/`.`/`-`/`_`，以及 IPv6 字面量的 `[` `]` `:`。
fn is_plausible_hostname(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let bracketed = h.starts_with('[') && h.ends_with(']');
    h.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'-' | b'_')
            || (bracketed && matches!(b, b'[' | b']' | b':'))
    })
}

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

/// admin 请求体缓冲上限：admin::handle 侧本就全量缓冲 body（写文件/读 TOML），
/// 入口统一收齐并设上限，防 DoS；32MiB 足够 config 文本/证书/常规管理上传。
pub const ADMIN_BODY_CAP: usize = 32 * 1024 * 1024;
/// h2/h3 引擎/admin 请求体缓冲上限（P1-9）：不排空 body 会卡住 H2/H3 流量控制。
pub const REQUEST_BODY_CAP: usize = 8 * 1024 * 1024;
/// 应用引擎（php/FFI 等）请求体缓冲上限（任务 6 OOM 防护）：覆盖常见上传配置。
pub const APP_BODY_CAP: usize = 32 * 1024 * 1024;
/// 反代上游请求/响应缓冲上限（任务 6 OOM 防护）。
pub const UPSTREAM_BODY_CAP: usize = 64 * 1024 * 1024;

pub async fn serve(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    serve_io(TokioIo::new(stream), live, lc, peer).await
}

/// 请求头读取超时：客户端连上后「挤牙膏」式发头部会把连接长期占住任务与 socket
/// （slowloris）。hyper 的 header_read_timeout 只覆盖「读完整请求头」这段，
/// 之后的请求体读取与 keep-alive 长连接不受影响（不改 keep-alive 语义）。
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// 单个请求的头部条数上限：几十万行头部是廉价的内存/CPU 放大面。
const MAX_HEADERS: usize = 100;

pub async fn serve_with_prefix(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    prefix: &[u8],
) -> Result<()> {
    serve_peek(stream, live, lc, peer, prefix.to_vec()).await
}

async fn serve_peek(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    prefix: Vec<u8>,
) -> Result<()> {
    let io = PrefixedStream::new(stream, prefix);
    serve_io(TokioIo::new(io), live, lc, peer).await
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
    serve_io(TokioIo::new(stream), live, lc, peer).await
}

async fn serve_io<IO>(
    io: TokioIo<IO>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req: Request<Incoming>| {
        let live = Arc::clone(&live);
        let lc = lc.clone();
        async move { Ok::<_, std::convert::Infallible>(handle_request(req, live, lc, peer).await) }
    });
    hyper::server::conn::http1::Builder::new()
        // 设了 header_read_timeout 就**必须**给 Timer：否则 hyper 在每个连接上
        // panic（common/time.rs: "timeout set, but no timer set"）—— 实测那样会让
        // 整个 h1 监听口失效（accept 任务被杀，9095/9081 全停）。
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_headers(MAX_HEADERS)
        .serve_connection(io, svc)
        .await?;
    Ok(())
}

pub async fn handle_request(
    req: Request<Incoming>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Response<BoxBody> {
    // P1-11：访问日志在响应完成侧统一记录全字段（时间/method/status/bytes/duration/engine），
    // 请求入口拿不到 status/bytes/duration；engine 标签由各 dispatch 分支经 extensions 注入。
    let t0 = std::time::Instant::now();
    let method = req.method().as_str().to_string();
    let path0 = req.uri().path().to_string();
    let is_https = lc.ssl.is_some();
    let mut resp = handle_request_inner(req, Arc::clone(&live), lc, peer).await;
    // 大文件（static 层的 FileSource 标记）在这里换成真正的流式 body：这是所有
    // 分支（acl/admin/apps/proxy/static/upload…）回包的**唯一**收口点。
    // 用 extensions 传来源而不是改 body 类型，是为了不动其它 ~30 处 `Response<BoxBody>`
    // 构造点；代价只是每个协议要在自己的发送路径上认这个标记。
    if let Some(src) = resp
        .extensions_mut()
        .remove::<crate::server::static_files::FileSource>()
    {
        *resp.body_mut() = stream_file(src);
    }
    // P1-7：所有 HTTPS 响应统一补 HSTS。此前只在 dispatch_tail 之后加，telemetry/
    // geoip/DoH/acl 拒绝/限速/basic_auth/admin/status/rule/proxy 等提前返回分支全部漏掉。
    // entry().or_insert 不覆盖分支已显式设置的值。
    if is_https {
        resp.headers_mut()
            .entry(http::header::STRICT_TRANSPORT_SECURITY)
            .or_insert_with(|| http::HeaderValue::from_static(hsts_header()));
    }
    let engine = resp
        .extensions()
        .get::<crate::server::access_log::EngineTag>()
        .map(|t| t.0)
        .unwrap_or("http");
    crate::server::access_log::log_response(
        &live,
        peer,
        "h1",
        &method,
        &path0,
        resp.status().as_u16(),
        None,
        t0.elapsed(),
        engine,
    );
    resp
}

async fn handle_request_inner(
    req: Request<Incoming>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Response<BoxBody> {
    let path = req.uri().path().to_string();
    crate::server::telemetry::record_request();

    let snap = live.snapshot();
    if let Some(resp) = crate::server::admin_geoip::try_handle_public(&req, &live).await {
        return tag(resp, "geoip");
    }

    // 请求路径：IP access → rate limit → metrics → DoH → basic auth → page_rules → admin → apps → proxy → static
    //
    // DoH 必须排在 ACL/限速**之后**：此前它排在前面，等于任何能连上 TLS 口的人
    // 都绕过监听器 IP 白名单与限速，白拿一个公共递归解析器（DoS/滥用放大器）。
    // 同时它排在 basic_auth 之前——DoH 客户端（浏览器/系统解析器）无法交互式
    // 提供 Basic 凭据，要求它会直接让 DoH 不可用。
    if !crate::server::access::is_allowed(&snap.ip_access, peer) {
        let (st, msg) = crate::server::access::deny_response();
        return tag(
            Response::builder().status(st).body(full(msg)).unwrap(),
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
                let (st, msg) = crate::server::rate_limit::deny_response();
                return tag(
                    Response::builder().status(st).body(full(msg)).unwrap(),
                    "acl",
                );
            }
        }
    }

    // /__metrics 必须排在 ip_access + 限流**之后**：此前它是本函数的第一个分支，
    // 于是「用 IP 白名单当边界」的部署把指标（请求总数、活跃 H3 流）暴露给任何人。
    // 位置与 DoH 对齐——排在 basic_auth **之前**：listener 口令与「谁能抓指标」是两件事，
    // 指标的门在 telemetry 内部按 [admin].metrics_public 判定（默认要求管理员凭据）。
    if let Some(resp) =
        crate::server::telemetry::maybe_handle(&req, &snap.telemetry, &snap.admin, peer.ip())
    {
        return tag(resp, "telemetry");
    }

    // DoH（RFC8484，需求 9）：按 Host/路径分流；未命中（非 DoH 域名）原样放行，
    // 保证同一 443 上正常 HTTPS 站点不受影响。
    let req = match crate::server::dns::dot_doh::h1_try_handle(req, &snap, peer).await {
        Ok(r) => return tag(r, "dns-doh"),
        Err(req) => req,
    };

    // P2-21（任务 4）：admin 暴露面——[admin].listeners_allow 非空时仅列出的端口可达
    // （防止 Basic 凭据在明文 listener 上线传输；空 = 兼容旧行为全端口可达）。
    //
    // 位置必须与 h1/h2/h3 保持一致：**早于 listener 级 basic_auth**（h2/h3 的收 body
    // 前置门里就是「ACL → listeners_allow → CSRF → admin 门」这个顺序）。此前 h1 把它
    // 放在 listener basic_auth 之后，于是「端口不在白名单 + 该口又配了 listener 口令」
    // 时会先回 401 —— 浏览器立刻弹出 Basic 口令框，等于把一个本该完全不可见的口
    // 变成凭据输入面；h2/h3 在同一场景回的是 404。白名单的语义是「这个口根本没有
    // 管理面」，所以 404 必须先生效。
    if path.starts_with(&snap.admin.path) && !snap.admin.listener_allowed(lc.port) {
        return tag(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("not found"))
                .unwrap(),
            "acl",
        );
    }

    if let Some(ba) = &lc.basic_auth {
        match crate::server::basic_auth::check_listener(&req, ba, peer.ip()) {
            crate::server::basic_auth::BasicCheck::Ok => {}
            crate::server::basic_auth::BasicCheck::Unauthorized => {
                return tag(
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(
                            http::header::WWW_AUTHENTICATE,
                            format!("Basic realm=\"{}\"", ba.realm),
                        )
                        .body(full("unauthorized"))
                        .unwrap(),
                    "acl",
                )
            }
            // 失败退避（见 basic_auth 文末）：回 429 + Retry-After，且这一档**不跑**
            // 口令哈希——否则并发错口令依旧每次烧一次 argon2，退避只是个摆设。
            crate::server::basic_auth::BasicCheck::Throttled(d) => {
                return tag(
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header(
                            http::header::RETRY_AFTER,
                            crate::server::basic_auth::retry_after_secs(d).to_string(),
                        )
                        .body(full("too many failed authentication attempts"))
                        .unwrap(),
                    "acl",
                )
            }
        }
    }

    // P2-8（§16.18）：status_path 接线——此前只解析配置无服务逻辑（status_page.html 孤儿）。
    // 放在 ip_access/rate_limit/basic_auth 之后：状态页尊重访问控制。
    if lc.status_path.as_deref() == Some(path.as_str()) {
        return tag(
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(full(include_str!("status_page.html")))
                .unwrap(),
            "status",
        );
    }

    // 早期规格 5：端口复用口（port_reuse 且非 TLS listener）上的明文 HTTP 请求
    // 统一返回 HSTS 头 + 301 到 https://{host}/，防不支持 HSTS 的客户端钉死明文。
    if lc.port_reuse && lc.ssl.is_none() {
        let raw_host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        // 不做开放重定向：Host 是客户端可控的，直接拼进 Location 就等于
        // 把 https://evil.example 回给用户（钓鱼/凭据窃取面）。
        // 优先用本 listener 配置的 server_name；否则仅在 Host 看起来是合法主机名时
        // 才采用，否则退化成纯相对路径跳转。
        let host = match lc.server_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(sn) => Some(sn.to_string()),
            None => {
                if is_plausible_hostname(&raw_host) {
                    Some(raw_host)
                } else {
                    None
                }
            }
        };
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let target = match host {
            Some(h) => format!("https://{h}{pq}"),
            None => pq,
        };
        let mut resp = Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(http::header::LOCATION, target)
            .header(
                http::header::STRICT_TRANSPORT_SECURITY,
                "max-age=31536000; includeSubDomains; preload",
            )
            .body(full("moved to https"))
            .unwrap();
        resp.extensions_mut()
            .insert(crate::server::access_log::EngineTag("hsts"));
        return resp;
    }

    // admin：在 ip_access / rate limit / basic auth 之后、页面规则改写之前
    if path.starts_with(&snap.admin.path) {
        // CSRF 补强（详见 access::cross_site_blocked）：admin.rs 的检查缺 `Origin` 时
        // 整段跳过、且 GET 从不带 `Origin`，这里用浏览器自写的 Sec-Fetch-Site 拒跨站。
        // 与 h2/h3 同序：先判跨站（403），再判鉴权（401/429）。
        if crate::server::access::cross_site_blocked(req.headers()) {
            let (st, msg) = crate::server::access::cross_site_response();
            return tag(Response::builder().status(st).body(full(msg)).unwrap(), "acl");
        }
        // 鉴权门必须放在**收 body 之前**：admin::handle 的第一步才是鉴权，而这里
        // 一旦先收满 body（上限 32MiB），一个不带凭据的并发 POST 就能让每个连接各占
        // 32MiB —— 不用通过鉴权（或随便带个垃圾凭据）就能放大内存占用。
        // 门内做的就是完整鉴权（含失败退避），因此未经校验的请求一个字节 body 都不收；
        // admin::handle 里那次同凭据的校验会命中 basic_auth 的成功备忘（见该处说明），
        // 所以合法管理请求**只跑一次** argon2id，换来的是「任意垃圾凭据也能占住
        // 32MiB/请求」这条放大路径被彻底掐掉。
        match crate::server::basic_auth::admin_gate(req.headers(), &snap.admin, peer.ip()) {
            crate::server::basic_auth::AdminGate::Proceed => {}
            crate::server::basic_auth::AdminGate::Unauthorized => {
                return tag(
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(
                            http::header::WWW_AUTHENTICATE,
                            format!("Basic realm=\"{}\"", snap.admin.realm),
                        )
                        .body(full("unauthorized"))
                        .unwrap(),
                    "acl",
                )
            }
            crate::server::basic_auth::AdminGate::Throttled(d) => {
                return tag(
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header(
                            http::header::RETRY_AFTER,
                            crate::server::basic_auth::retry_after_secs(d).to_string(),
                        )
                        .body(full("too many failed authentication attempts"))
                        .unwrap(),
                    "acl",
                )
            }
        }
        // P1-4：admin::handle 统一吃 Request<Full<Bytes>>——admin 侧本就全量缓冲 body，
        // 入口收齐（32MiB 上限）后 h2/h3 才能复用同一处理函数（API 不再只回 UI shell）。
        let (parts, body) = req.into_parts();
        let bytes = match Limited::new(body, ADMIN_BODY_CAP).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return tag(
                    Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(full("admin request body too large"))
                        .unwrap(),
                    "acl",
                )
            }
        };
        let mut resp = crate::server::admin::handle(
            Request::from_parts(parts, Full::new(bytes)),
            live,
        )
        .await;
        // 兜底记账：失败计数/退避已在 admin_gate 完成，这里只在「过了门却仍回 401」
        // （两次校验之间配置被热重载）时补记一次，不重复清零。
        crate::server::basic_auth::note_admin_result(peer.ip(), resp.status());
        resp.extensions_mut()
            .insert(crate::server::access_log::EngineTag("admin"));
        return resp;
    }

    let mut req = req;
    if let Some(np) = crate::server::page_rules::rewrite_path(&lc, &path) {
        let pq = match req.uri().query() {
            Some(q) => format!("{np}?{q}"),
            None => np,
        };
        if let Ok(u) = pq.parse() {
            *req.uri_mut() = u;
        }
    }
    // 改写之后必须以**新路径**做后续判定与分发。
    // 此前把改写前的 path 传进 dispatch_tail，于是 `would_handle`/`would_proxy` 判断
    // 的是一个路径、真正干活的 handler（apps::try_handle 内部自己重算 req.uri()）
    // 用的是另一个：改写命中时会错发 502「app dispatch returned empty」，
    // 或者把本该交给引擎的请求当静态文件发出去。
    let path = req.uri().path().to_string();
    if let Some(resp) = crate::server::page_rules::apply(&lc, &req) {
        return tag(resp, "rule");
    }
    if let Some((murl, upstream)) = crate::server::page_rules::pass_upstream(&lc, &path) {
        // 反代本就全量缓冲 body：这里收齐后转 Full 交反代（语义不变，见 proxy.rs）。
        let (parts, body) = req.into_parts();
        // 上限与 proxy.rs 一致（UPSTREAM_BODY_CAP）：无界 collect 会被超大 body 撑爆内存，
        // 使 proxy.rs 内部的上限形同虚设。
        let bytes = match Limited::new(body, UPSTREAM_BODY_CAP).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return tag(
                    Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(full("request body too large"))
                        .unwrap(),
                    "proxy",
                )
            }
        };
        let resp = crate::server::proxy::proxy_page_rule(
            Request::from_parts(parts, Full::new(bytes)),
            &murl,
            &upstream,
            peer.ip(),
            lc.ssl.is_some(),
        )
        .await;
        return tag(resp, "proxy");
    }
    let resp_mods = crate::server::page_rules::response_headers(&lc, &path);
    let mut resp = dispatch_tail(req, live, lc.clone(), peer, path).await;
    crate::server::headers_mod::apply_response(resp.headers_mut(), &resp_mods);
    // HTTPS responses get HSTS header (P1-7)
    if lc.ssl.is_some() {
        resp.headers_mut().insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            http::HeaderValue::from_static(hsts_header()),
        );
    }
    resp
}

/// dispatch 分支打"响应由谁产出"标签，供访问日志 engine 字段使用。
fn tag(resp: Response<BoxBody>, engine: &'static str) -> Response<BoxBody> {
    let mut resp = resp;
    resp.extensions_mut()
        .insert(crate::server::access_log::EngineTag(engine));
    resp
}

async fn dispatch_tail(
    req: Request<Incoming>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    path: String,
) -> Response<BoxBody> {
    if apps::would_handle(&lc, &path) {
        let resp = apps::try_handle(req, &live, &lc, peer)
            .await
            .unwrap_or_else(|| {
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full("app dispatch returned empty"))
                    .unwrap()
            });
        return tag(resp, "app");
    }

    if would_proxy(&lc, &path) {
        // 反代本就全量缓冲 body：收齐后转 Full 交反代（行为不变）。
        // 上限与 proxy.rs 一致（UPSTREAM_BODY_CAP）：无界 collect 会被超大 body 撑爆内存。
        let (parts, body) = req.into_parts();
        let bytes = match Limited::new(body, UPSTREAM_BODY_CAP).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return tag(
                    Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(full("request body too large"))
                        .unwrap(),
                    "proxy",
                )
            }
        };
        let req = Request::from_parts(parts, Full::new(bytes));
        if let Some((_matched, resp)) = crate::server::proxy::try_proxy(&lc, req, peer.ip()).await {
            return tag(resp, "proxy");
        }
        return tag(
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full("proxy rule matched but produced no response"))
                .unwrap(),
            "proxy",
        );
    }

    // §44 上传：仅当该路径开了 autoindex + enable_upload 时接管写方法。
    // 放在这里 = ACL / 限速 / basic_auth 都已完成，上传与静态下载享受同一套防护。
    if matches!(
        *req.method(),
        http::Method::PUT | http::Method::PATCH | http::Method::POST
    ) && crate::server::upload_api::enabled_for(&lc, &path)
    {
        return tag(
            crate::server::upload_api::handle(req, &lc, peer).await,
            "upload",
        );
    }
    match static_files::serve(&req, &lc).await {
        Ok(r) => tag(r, "static"),
        Err(_) => tag(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("not found"))
                .unwrap(),
            "static",
        ),
    }
}

fn would_proxy(lc: &ListenerConfig, path: &str) -> bool {
    lc.proxy_rules.iter().any(|r| path.starts_with(&r.path))
}

pub fn full(s: impl Into<Bytes>) -> BoxBody {
    Full::new(s.into()).boxed()
}

pub fn empty() -> BoxBody {
    Full::new(Bytes::new()).boxed()
}

/// 大文件流式 body（>16MiB 的静态响应）：按 64KiB 分块从磁盘读，经 mpsc 交给 hyper。
///
/// 为什么用 mpsc：`tokio::fs::File::read` 的 future 借用 `&mut File`，直接塞进
/// `poll_frame` 会变成自引用结构；让后台任务读、body 只 poll 通道最省事，
/// 顺带得到背压（通道容量 2 帧 ⇒ 读盘不会跑到发送前面去）。
///
/// 错误处理：`BoxBody` 的 error 类型是 `Infallible`，而响应头此刻**已经发出**，
/// 读失败只能结束流 + 记日志（Content-Length 与实际不符时 hyper 会关闭连接，
/// 客户端据此判定传输失败 —— 唯一诚实的处理，不能改状态码了）。
pub fn stream_file(src: crate::server::static_files::FileSource) -> BoxBody {
    use crate::server::static_files::STREAM_CHUNK;
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(2);
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut f = match tokio::fs::File::open(&src.path).await {
            Ok(f) => f,
            Err(e) => {
                log::warn!("stream_file open {}: {e}", src.path.display());
                return;
            }
        };
        if src.start > 0 {
            if let Err(e) = f.seek(std::io::SeekFrom::Start(src.start)).await {
                log::warn!("stream_file seek {}: {e}", src.path.display());
                return;
            }
        }
        let mut left = src.len;
        let mut buf = vec![0u8; STREAM_CHUNK];
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            match f.read(&mut buf[..want]).await {
                Ok(0) => {
                    // 文件在传输中被截断：如实记日志并结束（不要死循环）
                    log::warn!("stream_file 提前 EOF（文件被截断？）{}", src.path.display());
                    break;
                }
                Ok(n) => {
                    left -= n as u64;
                    if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        return; // 接收端（body）已丢弃：客户端断开
                    }
                }
                Err(e) => {
                    log::warn!("stream_file read {}: {e}", src.path.display());
                    return;
                }
            }
        }
    });
    BoxBody::new(FileStreamBody {
        rx: parking_lot::Mutex::new(rx),
        len: src.len,
    })
}

/// [`stream_file`] 的 body 适配：把通道里的块当 DATA 帧发出去。
///
/// 接收端放在 `parking_lot::Mutex` 里是必须的：`tokio::sync::mpsc::Receiver` 是
/// `Send` 但**不是** `Sync`，而本 crate 的 [`BoxBody`] 别名是
/// `BoxBody<Bytes, Infallible>`（=`Send + Sync` 的 trait object）。
/// 锁只在 `poll_frame` 里短暂持有，且临界区内不 await，不会引入阻塞。
struct FileStreamBody {
    rx: parking_lot::Mutex<tokio::sync::mpsc::Receiver<Bytes>>,
    len: u64,
}

impl hyper::body::Body for FileStreamBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.rx.lock().poll_recv(cx) {
            std::task::Poll::Ready(Some(b)) => {
                std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b))))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// 精确长度：hyper 需要它来确认与 Content-Length 一致（否则可能改用 chunked）。
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.len)
    }
}
