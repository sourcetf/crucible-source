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
    let resp = handle_request_inner(req, Arc::clone(&live), lc, peer).await;
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
    if let Some(resp) = crate::server::telemetry::maybe_handle(&req, &snap.telemetry) {
        return tag(resp, "telemetry");
    }
    if let Some(resp) = crate::server::admin_geoip::try_handle_public(&req, &live).await {
        return tag(resp, "geoip");
    }

    // DoH（RFC8484，需求 9）：按 Host/路径分流；未命中（非 DoH 域名）原样放行，
    // 保证同一 443 上正常 HTTPS 站点不受影响。
    let req = match crate::server::dns::dot_doh::h1_try_handle(req, &snap, peer).await {
        Ok(r) => return tag(r, "dns-doh"),
        Err(req) => req,
    };

    // 请求路径：IP access → rate limit → basic auth → page_rules → admin → apps → proxy → static
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

    if let Some(ba) = &lc.basic_auth {
        if !crate::server::basic_auth::check_listener(&req, ba) {
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
            );
        }
    }

    // P2-21（任务 4）：admin 暴露面——[admin].listeners_allow 非空时仅列出的端口可达
    // （防止 Basic 凭据在明文 listener 上线传输；空 = 兼容旧行为全端口可达）。
    if path.starts_with(&snap.admin.path) && !snap.admin.listener_allowed(lc.port) {
        return tag(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("not found"))
                .unwrap(),
            "acl",
        );
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
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();
        let target = if host.is_empty() {
            "/".to_string()
        } else {
            format!("https://{host}{}", req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default())
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
    if let Some(resp) = crate::server::page_rules::apply(&lc, &req) {
        return tag(resp, "rule");
    }
    if let Some((murl, upstream)) = crate::server::page_rules::pass_upstream(&lc, &path) {
        // 反代本就全量缓冲 body：这里收齐后转 Full 交反代（语义不变，见 proxy.rs）。
        let (parts, body) = req.into_parts();
        let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
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
    let mut resp = dispatch_tail(req, live, lc, peer, path).await;
    crate::server::headers_mod::apply_response(resp.headers_mut(), &resp_mods);
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
        let (parts, body) = req.into_parts();
        let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
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
