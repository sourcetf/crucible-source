//! Optional Prometheus-style metrics endpoint.

use crate::config::{AdminConfig, TelemetryConfig};
use crate::server::basic_auth::{admin_gate, retry_after_secs, AdminGate};
use crate::server::h1::{full, BoxBody};
use bytes::Bytes;
use http::{header, Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static H3_STREAMS_ACTIVE: AtomicU64 = AtomicU64::new(0);

pub fn record_request() {
    REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn set_h3_streams(n: u64) {
    H3_STREAMS_ACTIVE.store(n, Ordering::Relaxed);
}

pub fn metrics_body() -> String {
    format!(
        "# HELP crucible_requests_total Total HTTP requests served\n\
         # TYPE crucible_requests_total counter\n\
         crucible_requests_total {}\n\
         # HELP crucible_h3_streams_active Active HTTP/3 streams\n\
         # TYPE crucible_h3_streams_active gauge\n\
         crucible_h3_streams_active {}\n",
        REQUESTS_TOTAL.load(Ordering::Relaxed),
        H3_STREAMS_ACTIVE.load(Ordering::Relaxed),
    )
}

/// `/__metrics` 的访问判定（三协议共用一个判定，各自拼自己的体类型）。
enum MetricsAccess {
    /// 放行：`metrics_public = true`，或已通过管理员鉴权门。
    Serve,
    /// 拒绝：(状态码, Retry-After 秒数, 文案)。
    Reject(StatusCode, Option<u64>, &'static str),
}

/// 任务 3：`/__metrics` 默认**不再匿名可读**。
///
/// 为什么必须加：指标（请求总数、活跃 H3 流）是内部信息，此前任何能连上端口的人
/// 都能读到；未配 `ip_access` 时等于全公开，用了 IP 白名单当边界的部署也会把它漏出去。
/// 这里复用 admin 那套门（[`crate::server::basic_auth::admin_gate`]）：同一份口令校验、
/// 同一张失败退避表 —— 既不额外开一条绕过退避的 argon2 爆破口，也不会出现
/// 「面板要口令、指标不要」这种半开状态。
/// 需要公开抓取（抓取端无法带凭据，改用 ip_access 白名单兜底）时在 `[admin]` 里设
/// `metrics_public = true`；此时仍排在 ip_access + 限流之后。
///
/// 401 与 admin 一致带 `WWW-Authenticate`（否则客户端不知道要发凭据）；退避期回 429
/// 而不是 401 —— 与 admin 路径同一语义（401 会被反复重试，反而放大请求量）。
fn metrics_access<T>(req: &Request<T>, admin: &AdminConfig, ip: IpAddr) -> MetricsAccess {
    // 开关在 `[admin]` 上（metrics_public）—— 与它复用的 admin 口令校验同属一处配置。
    if admin.metrics_public {
        return MetricsAccess::Serve;
    }
    match admin_gate(req.headers(), admin, ip) {
        AdminGate::Proceed => MetricsAccess::Serve,
        AdminGate::Unauthorized => {
            MetricsAccess::Reject(StatusCode::UNAUTHORIZED, None, "unauthorized")
        }
        AdminGate::Throttled(d) => MetricsAccess::Reject(
            StatusCode::TOO_MANY_REQUESTS,
            Some(retry_after_secs(d)),
            "too many failed authentication attempts",
        ),
    }
}

/// 拼拒绝响应（状态码/头部与 admin 路径一致；文案体由调用方给）。
fn reject_parts(status: StatusCode, retry: Option<u64>, realm: &str) -> http::response::Builder {
    let mut b = Response::builder().status(status);
    if status == StatusCode::UNAUTHORIZED {
        b = b.header(header::WWW_AUTHENTICATE, format!("Basic realm=\"{realm}\""));
    }
    if let Some(secs) = retry {
        b = b.header(header::RETRY_AFTER, secs.to_string());
    }
    b
}

pub fn maybe_handle(
    req: &Request<Incoming>,
    cfg: &TelemetryConfig,
    admin: &AdminConfig,
    ip: IpAddr,
) -> Option<Response<BoxBody>> {
    if !cfg.enabled {
        return None;
    }
    // 先判路径再判方法——否则 telemetry.enabled 时全站任何 POST 都被这里 405 吞掉
    if req.uri().path() != cfg.path {
        return None;
    }
    if req.method() != http::Method::GET {
        return Some(
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(full("method not allowed"))
                .unwrap(),
        );
    }
    match metrics_access(req, admin, ip) {
        MetricsAccess::Serve => Some(metrics_response()),
        MetricsAccess::Reject(status, retry, msg) => Some(
            reject_parts(status, retry, &admin.realm)
                .body(full(msg))
                .unwrap(),
        ),
    }
}

/// H2/H3 path uses bodyless requests.
///
/// 与 h1 的 [`maybe_handle`] 同语义：方法不是 GET 时回 **405**（而不是 None 落到
/// 静态文件/404）—— 否则同一条 `POST /__metrics` 在 h1 上是 405、在 h2/h3 上是 404，
/// 行为随协议而变。
pub fn maybe_handle_simple<T>(
    req: &Request<T>,
    cfg: &TelemetryConfig,
    admin: &AdminConfig,
    ip: IpAddr,
) -> Option<Response<Bytes>> {
    if !cfg.enabled || req.uri().path() != cfg.path {
        return None;
    }
    if req.method() != http::Method::GET {
        return Some(
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Bytes::from_static(b"method not allowed"))
                .unwrap(),
        );
    }
    match metrics_access(req, admin, ip) {
        MetricsAccess::Serve => {
            let body = metrics_body();
            Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )
                    .body(Bytes::from(body))
                    .unwrap(),
            )
        }
        MetricsAccess::Reject(status, retry, msg) => Some(
            reject_parts(status, retry, &admin.realm)
                .body(Bytes::from_static(msg.as_bytes()))
                .unwrap(),
        ),
    }
}

fn metrics_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(full(metrics_body()))
        .unwrap()
}
