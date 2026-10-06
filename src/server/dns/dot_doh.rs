//! DoT（RFC7858）与 DoH（RFC8484）服务器端。
//!
//! - DoT：独立 TCP 监听（TLS 后按 2 字节长度前缀收发 DNS wire 报文），转发到本机 named（UDP）
//! - DoH：`h1_try_handle` + h2/h3 `doh_prepared`（路径/Host 白名单分离，需求 9）
//!   443 SNI 复用的纯 DNS-wire 探测仍属可选增强，不阻塞 HTTP DoH。
//! - 443 端口复用不冲突：DoH 走 /dns-query 路径 + Host 白名单；正常 HTTPS 站点不受影响

use crate::config::Config;
use crate::server::h1::{full, BoxBody};
use anyhow::Result;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use http_body_util::BodyExt;
use std::sync::Arc;

/// DoH 请求体上限（DNS wire over UDP 最大 65535）：h1 侧有界收集，防 chunked 无上限 OOM。
const DOH_WIRE_CAP: usize = 65535;

/// DoT TLS 握手指**截止时间**。`tokio_boring::accept` 自身没有任何超时：一个匿名对端
/// 建立 TCP 后不完成握手（甚至只发一半 ClientHello）就能把这条连接的任务、fd 与并发
/// permit 永久挂住 —— 默认 max_conns=128，几个来源 IP 挂满即 DoT 永久拒绝服务。
/// 与 Web TLS 路径 `tls/boring_path.rs` 的 HANDSHAKE_TIMEOUT 同类问题，取值同量级。
const DOT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// DoT 帧读取（长度前缀与帧体各自）的空闲超时：完成握手后发 `len=65535` 再挂住的对端
/// 同样只能占用这段时间（旧实现只给长度前缀加了超时，帧体是裸 `read_exact`，永远等）。
const DOT_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// DoT accept 出错（EMFILE/ENFILE 等）的退避：tokio accept 返回 Err 后立即重试是**紧循环**，
/// 单端口就能烧满一个 worker。与 `server::mod` 的主 accept 循环同一修法。
const DOT_ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);
/// DoT 配置轮询间隔：面板/配置文件改动最多一个周期内生效（ACL/限速/并发上限/端口/启停）。
const DOT_CONFIG_POLL: std::time::Duration = std::time::Duration::from_secs(1);
/// DoT acceptor 缓存条目上限（键 = 证书/私钥材料指纹；正常只有 1~2 项）。
const DOT_ACCEPTOR_CACHE_CAP: usize = 8;

/// 把 DNS wire 报文转发到本机 named 的 UDP 口（递归语义下附 EDNS Client Subnet /24）。
/// 分线路（需求 10）：客户端 IP 命中 geo.lines → 转发到 127.0.0.(2+i)
/// （named 侧 fwd-<line> view 以 match-destinations 承接，view 内是 per-line zone 数据）。
pub async fn udp_query(
    cfg: &crate::server::dns::DnsConfig,
    wire: Vec<u8>,
    client: Option<std::net::IpAddr>,
) -> Result<Vec<u8>> {
    // 向后兼容入口：DoT 路径不忽略客户端通告的 EDNS payload（保守，不改变 DoT 行为）。
    udp_query_opts(cfg, wire, client, false).await
}

/// [`udp_query`] 的完整形态。
///
/// `ignore_client_payload`：DoH 置 true —— RFC 8484 §6 要求 DoH 服务器**忽略**查询里
/// 通告的 UDP payload size（客户端只通告 512 时，原样转发会让 named 回 TC=1 截断，
/// DoH 客户端平白丢应答）。置 true 时把出站 OPT 的 payload 抬到 65535（无 OPT 则补一个）。
pub async fn udp_query_opts(
    cfg: &crate::server::dns::DnsConfig,
    wire: Vec<u8>,
    client: Option<std::net::IpAddr>,
    ignore_client_payload: bool,
) -> Result<Vec<u8>> {
    use tokio::net::UdpSocket;
    let port = cfg.port_or_default();
    // 客户端**原始**查询（ECS 注入/剥离之前）：应答回显 ECS 必须按它判定 ——
    // RFC 7871 §7.2.2「查询带 ECS ⇒ 应答必须带 ECS」，而注入后的 wire 我们已经
    // 改过，不能拿它当「客户端到底带没带 ECS」的依据。
    let client_query = wire.clone();
    // ECS（RFC7871）：
    // - 开关开：v4 固定 /24、v6 /56，客户端自带 ECS 也重写（禁止 /32 出网）；
    // - 开关关：剥离客户端自带的 ECS option —— 否则「关」只关掉了注入，客户端 ECS
    //   仍照转给上游，开关语义不完整（P3）。
    let wire = if cfg.ecs {
        match client {
            Some(ip) => super::ecs::inject_ecs(&wire, ip).unwrap_or(wire),
            None => wire,
        }
    } else {
        strip_ecs_option(&wire).unwrap_or(wire)
    };
    let wire = if ignore_client_payload {
        set_udp_payload(&wire, 65535)
    } else {
        wire
    };
    let fwd_dest = super::resolve_fwd_dest(cfg, client);
    let bind = if fwd_dest.is_ipv6() {
        "[::1]:0".to_string()
    } else {
        "0.0.0.0:0".to_string()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect((fwd_dest, port)).await?;
    sock.send(&wire).await?;
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv(&mut buf)).await??;
    buf.truncate(n);
    // RFC 7871 §7.2.2（递归/中介侧）：客户端查询**带** ECS 时，应答**必须**回带 ECS
    // option。上游是本机 BIND 9 —— 它不实现 ECS、不会在应答里回 option，所以只能由
    // 本层按客户端原始查询回显（FAMILY/SOURCE/ADDRESS 与查询一致、SCOPE=0）。
    // `apply_response_ecs` 在查询**没带** ECS 时原样返回，故这里可以无条件调用。
    // （此前该函数已写好但从未接线 —— 应答侧 ECS 等于没实现。）
    // 回显会加一个 OPT（约 11~15 字节）：UDP 收到的应答最大 65535，加上后可能越过
    // 65535 —— DoT 侧用 `answer.len() as u16` 写长度前缀，越界会静默截断成坏帧，
    // 因此越过上限时放弃回显（宁可少一个 option 也不能发坏帧）。
    let echoed = super::ecs::apply_response_ecs(&client_query, &buf);
    Ok(if echoed.len() <= 65535 { echoed } else { buf })
}

/// H1 请求钩子：命中 DoH 则应答 `Ok(resp)`；未命中（非 DoH 域名/路径）返回 `Err(req)`
/// 原样交还调用方继续正常站点流程（443 复用下的 SNI/Host 分离语义）。
pub async fn h1_try_handle(
    req: Request<Incoming>,
    snap: &Config,
    peer: std::net::SocketAddr,
) -> Result<Response<BoxBody>, Request<Incoming>> {
    // panel.toml overrides config.toml [dns] — same as named reconcile / admin API
    let dns_cfg = super::effective(snap);
    if !dns_cfg.enabled || !dns_cfg.doh.enabled {
        return Err(req);
    }
    // 先判路径/Host（不消耗请求）——未命中原样交还 h1 正常流程（443 SNI/Host 复用语义）
    let path_ok = doh_path_ok(req.uri().path(), &dns_cfg.doh.path);
    let host_ok = doh_host_allowed(
        &dns_cfg.doh.hostnames,
        request_authority(req.headers(), req.uri()),
    );
    if !path_ok || !host_ok {
        return Err(req);
    }
    // 命中 DoH：才消耗请求收集 body（RFC8484 POST body = 完整 DNS wire 报文）
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    // Fast-reject known oversized POST via Content-Length (avoid buffering multi-MB junk).
    if method == http::Method::POST {
        if let Some(cl) = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
        {
            if cl > DOH_WIRE_CAP {
                return Ok(resp_text(StatusCode::PAYLOAD_TOO_LARGE, "dns message too large"));
            }
        }
    }
    let (_, body) = req.into_parts();
    // 有界收集：chunked / 伪造 Content-Length 也不能让 body 无上限增长（OOM 防护）。
    let body_bytes = match http_body_util::Limited::new(body, DOH_WIRE_CAP).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Ok(resp_text(
                StatusCode::PAYLOAD_TOO_LARGE,
                "dns message too large",
            ))
        }
    };
    match doh_prepared(&dns_cfg, &method, &uri, &headers, body_bytes, peer).await {
        // 上面已判 path/host，这里必然 Some；None 时兜底 415（防御）
        None => Ok(resp_text(StatusCode::UNSUPPORTED_MEDIA_TYPE, "doh not applicable")),
        Some(resp) => Ok(resp),
    }
}

/// DoH 是否**可能**处理该请求（只看 path/Host，不看 body）。
///
/// 供 h2/h3 在**收请求体之前**判定：DoH 请求体很小，而普通上传可能很大 ——
/// 若不分青红皂白先收齐，等于给普通上传套上 `REQUEST_BODY_CAP`(8MiB) 上限。
/// 判定条件必须与 [`doh_prepared`] 的前几个早退分支完全一致，否则会出现
/// 「预判说不处理、实际处理（或反之）」的错位。
pub fn is_doh_request(
    dns_cfg: &crate::server::dns::DnsConfig,
    path: &str,
    host: Option<&http::HeaderValue>,
) -> bool {
    dns_cfg.enabled
        && dns_cfg.doh.enabled
        && doh_path_ok(path, &dns_cfg.doh.path)
        && doh_host_allowed(
            &dns_cfg.doh.hostnames,
            host.and_then(|h| h.to_str().ok()),
        )
}

/// [`is_doh_request`] 的 h2/h3 形态：HTTP/2/3 的权威字段是伪头 `:authority`
/// （crate 把它放进 `Request::uri().authority()`，HeaderMap 里**没有** `Host`）。
/// 只按 Host 头判定会让「配置了 hostnames 白名单」的部署在 h2/h3 下永远 404。
#[allow(dead_code)] // h2/h3 接线改用本入口（跨文件需求），接线前保持可用。
pub fn is_doh_request_uri(dns_cfg: &crate::server::dns::DnsConfig, uri: &http::Uri) -> bool {
    dns_cfg.enabled
        && dns_cfg.doh.enabled
        && doh_path_ok(uri.path(), &dns_cfg.doh.path)
        && doh_host_allowed(
            &dns_cfg.doh.hostnames,
            uri.authority().map(|a| a.as_str()),
        )
}

/// h2/h3 路径的 DoH 入口（body 已由协议层收集为 Bytes）。
/// 返回 Some(resp) = 已按 DoH 应答；None = 非 DoH 请求（路径/Host 不匹配）。
pub async fn doh_prepared(
    dns_cfg: &crate::server::dns::DnsConfig,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: bytes::Bytes,
    peer: std::net::SocketAddr,
) -> Option<Response<BoxBody>> {
    if !dns_cfg.enabled || !dns_cfg.doh.enabled {
        return None;
    }
    if !doh_path_ok(uri.path(), &dns_cfg.doh.path) {
        return None;
    }
    // Host 或 `:authority`（h2/h3）。两者都取不到 ⇒ 拒绝（fail-closed）。
    let host = request_authority(headers, uri);
    if !doh_host_allowed(&dns_cfg.doh.hostnames, host) {
        return None;
    }
    // 递归 ACL（P1-5）：DoH 转发到本机 named，源地址恒为 127.0.0.1，而 named 的
    // allow-recursion 里永远有 127.0.0.1（转发源）—— 不查 ACL 就等于「谁能连上
    // 这个口，谁就拿到无限制递归」。语义与 `[dns] recursion_acl` 一致：空 = 仅本机。
    if !doh_peer_allowed(dns_cfg, peer) {
        warn_throttled(
            "doh-acl",
            &format!("doh: reject {peer}: 不在 [dns] recursion_acl 白名单"),
        );
        return Some(resp_text(StatusCode::FORBIDDEN, "doh: not allowed"));
    }
    // CORS 预检：RFC 8484 把「浏览器 Web 应用经 CORS 访问 DNS」列为主要用例；
    // POST application/dns-message 属非 safelisted Content-Type，必触发预检。
    if *method == http::Method::OPTIONS {
        return Some(doh_options());
    }
    let wire: Vec<u8> = match method {
        &http::Method::GET => {
            let mut picked = None;
            for kv in uri.query().unwrap_or("").split('&') {
                if let Some(v) = kv.strip_prefix("dns=") {
                    picked = Some(v.to_string());
                }
            }
            match picked {
                Some(b) if b.len() > 90_000 => {
                    return Some(resp_text(StatusCode::PAYLOAD_TOO_LARGE, "dns message too large"));
                }
                Some(b) => match b64url_decode(&b) {
                    // RFC 8484 §6：DNS 消息最小 12 字节头部。非法/截断输入一律 400
                    // （旧实现回 413「too large」，语义错误）。
                    Some(w) if (12..=65535).contains(&w.len()) => w,
                    Some(_) | None => {
                        return Some(resp_text(StatusCode::BAD_REQUEST, "bad dns message"))
                    }
                },
                None => return Some(resp_text(StatusCode::BAD_REQUEST, "bad dns message")),
            }
        }
        &http::Method::POST => {
            let ct = headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct_is_dns_message(ct) {
                return Some(resp_text(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "need application/dns-message",
                ));
            }
            if body.len() < 12 {
                return Some(resp_text(StatusCode::BAD_REQUEST, "bad dns message"));
            }
            if body.len() > 65535 {
                return Some(resp_text(StatusCode::PAYLOAD_TOO_LARGE, "dns message too large"));
            }
            body.to_vec()
        }
        _ => return Some(doh_method_not_allowed()),
    };
    // DNS wire over UDP cannot exceed 65535; reject oversized DoH payloads early.
    if wire.len() > 65535 {
        return Some(resp_text(StatusCode::PAYLOAD_TOO_LARGE, "dns message too large"));
    }
    // 分线路 DoH：客户端 IP 决定转发 dest（resolve_fwd_dest）；RFC 8484 §6 忽略客户端 payload。
    match udp_query_opts(dns_cfg, wire, Some(peer.ip()), true).await {
        Ok(answer) => {
            // RFC 8484 §5.1：显式给 freshness，且 MUST ≤ Answer 段最小 TTL；
            // POST 应答不缓存。Vary 让中间缓存不要把不同 Origin 的 CORS 预检串味。
            let cache = if *method == http::Method::POST {
                "no-store".to_string()
            } else {
                format!("max-age={}", min_answer_ttl(&answer).unwrap_or(0))
            };
            Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "application/dns-message")
                    .header(http::header::CACHE_CONTROL, cache)
                    .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .body(crate::server::h1::full(answer))
                    .unwrap(),
            )
        }
        // RFC 9110 §15.6.5：等待上游超时 = 504；连接失败等其它错误 = 502。
        // 对外固定文案，细节只进日志（不再把 OS 错误串回显给匿名客户端）。
        Err(e) if e.is::<tokio::time::error::Elapsed>() => {
            log::warn!("doh: upstream timeout: {e:#}");
            Some(resp_text(StatusCode::GATEWAY_TIMEOUT, "dns upstream timeout"))
        }
        Err(e) => {
            log::warn!("doh: upstream error: {e:#}");
            Some(resp_text(StatusCode::BAD_GATEWAY, "dns upstream error"))
        }
    }
}

/// 请求权威名：`Host` 头优先，其次 URI 的 authority（h2/h3 的伪头 `:authority`）。
fn request_authority<'a>(headers: &'a http::HeaderMap, uri: &'a http::Uri) -> Option<&'a str> {
    headers
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()))
}

/// DoH 路径判定：配置值必须至少两层（拒绝 `/`，与 `admin.path` 的同款保护；
/// 配置层校验缺失时这里先 fail-closed），请求路径与配置完全相等。
fn doh_path_ok(path: &str, configured: &str) -> bool {
    let c = configured.trim();
    if c.len() < 2 || c == "/" || !c.starts_with('/') {
        return false;
    }
    path == c
}

/// Content-Type 精确匹配 `application/dns-message`：大小写不敏感，按 `;` 截断参数
/// （旧实现 `starts_with` 既漏大小写又接受 `application/dns-messageX`）。
fn ct_is_dns_message(ct: &str) -> bool {
    ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/dns-message")
}

fn doh_options() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(http::header::ALLOW, "GET, POST, OPTIONS")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "content-type")
        .header("access-control-max-age", "86400")
        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(full(String::new()))
        .unwrap()
}

fn doh_method_not_allowed() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(http::header::ALLOW, "GET, POST, OPTIONS")
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(full("GET or POST only".to_string()))
        .unwrap()
}

fn host_without_port(raw: &str) -> &str {
    // Strip port without breaking IPv6 literals: `[::1]:443` or `example.com:443`.
    if let Some(rest) = raw.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        raw.rsplit_once(':')
            .and_then(|(h, p)| p.parse::<u16>().ok().map(|_| h))
            .unwrap_or(raw)
    }
}

/// DoH Host 白名单。**空白名单 = 拒绝**（P1-5）：旧实现返回 true，等于「任意 Host，
/// 只要请求 /dns-query 就是 DoH 端点」—— 仓库与面板默认都是空，任何站点都会命中。
/// 需要放开时显式写 `"*"`。
fn doh_host_allowed(whitelist: &[String], host_hdr: Option<&str>) -> bool {
    if whitelist.is_empty() {
        return false;
    }
    let raw = match host_hdr {
        Some(h) if !h.trim().is_empty() => h.trim(),
        _ => return false,
    };
    let host = host_without_port(raw);
    // Whitelist entries may be written as `host`, `host:port` or `*` (explicit any).
    whitelist.iter().any(|entry| {
        let e = entry.trim();
        if e == "*" {
            return true;
        }
        let allow = host_without_port(e);
        allow.eq_ignore_ascii_case(host) || e.eq_ignore_ascii_case(raw)
    })
}

/// DoH 递归准入：与 `[dns] recursion_acl` 同语义（空 = 仅本机）。
///
/// 为什么 DoH 必须查：请求由本进程转发给 named，源地址恒为 127.0.0.1，而 named 的
/// `allow-recursion` 里硬编码了 127.0.0.1 —— 不查 ACL 时「运维以为递归只给本机、
/// 公网任意人却能经 DoH 拿到完整递归」。IPv4-mapped IPv6 的归一化复用 `access::is_allowed`。
fn doh_peer_allowed(cfg: &crate::server::dns::DnsConfig, peer: std::net::SocketAddr) -> bool {
    if cfg.recursion_acl.is_empty() {
        return peer.ip().is_loopback();
    }
    crate::server::access::is_allowed(
        &crate::config::IpAccessConfig {
            allow: cfg.recursion_acl.clone(),
            deny: Vec::new(),
        },
        peer,
    )
}

fn resp_text(st: StatusCode, msg: &str) -> Response<BoxBody> {
    Response::builder()
        .status(st)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(full(msg.to_string()))
        .unwrap()
}

/// 应答的缓存寿命（秒）：Answer 段最小 TTL；Answer 为空（NXDOMAIN 等负应答）时退回
/// Authority 段（SOA 的 negative TTL）；解析失败/两段皆空 → None。
///
/// RFC 8484 §5.1 要求 DoH 响应的 freshness lifetime **≤ Answer 段最小 TTL**，
/// 否则中间 HTTP 缓存可能把已过 TTL 的记录继续发出去。
fn min_answer_ttl(msg: &[u8]) -> Option<u32> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let ns = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_dns_name(msg, off)?;
        off = off.checked_add(4)?;
        if off > msg.len() {
            return None;
        }
    }
    let count = if an > 0 { an } else { ns };
    let mut min: Option<u32> = None;
    for _ in 0..count {
        let name_end = skip_dns_name(msg, off)?;
        if name_end + 10 > msg.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([
            msg[name_end + 4],
            msg[name_end + 5],
            msg[name_end + 6],
            msg[name_end + 7],
        ]);
        min = Some(min.map_or(ttl, |m| m.min(ttl)));
        let rdlen = u16::from_be_bytes([msg[name_end + 8], msg[name_end + 9]]) as usize;
        off = name_end.checked_add(10)?.checked_add(rdlen)?;
        if off > msg.len() {
            return None;
        }
    }
    min
}

// ------------------------------------------------ 出站 EDNS 处理（ECS 剥离 / payload）

const OPT_RR_TYPE: u16 = 41;
const ECS_OPTION_CODE: u16 = 8;

/// OPT RR 在报文里的位置与字段。
struct OptLoc {
    start: usize,
    end: usize,
    /// Class 字段即「UDP payload size」。
    payload: u16,
    ttl: [u8; 4],
    /// rdata 在报文里的偏移（重写时按 TLV 遍历）。
    rdata_start: usize,
    rdlen: usize,
}

/// 跳过一个（可能带压缩指针的）域名，返回名字之后的偏移。
fn skip_dns_name(msg: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let l = *msg.get(off)?;
        if l & 0xC0 == 0xC0 {
            return Some(off + 2);
        }
        if l == 0 {
            return Some(off + 1);
        }
        off = off.checked_add(1 + l as usize)?;
        if off > msg.len() {
            return None;
        }
    }
}

/// question 段结束后的偏移（跳过 QDCOUNT 个问题）。
fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_dns_name(msg, off)?;
        off = off.checked_add(4)?;
        if off > msg.len() {
            return None;
        }
    }
    Some(off)
}

/// 从 question 段之后扫所有 RR，找到 OPT（type=41）。
fn find_opt_rr(msg: &[u8]) -> Option<OptLoc> {
    let mut cur = question_end(msg)?;
    loop {
        let name_end = skip_dns_name(msg, cur)?;
        if name_end + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[name_end], msg[name_end + 1]]);
        let payload = u16::from_be_bytes([msg[name_end + 2], msg[name_end + 3]]);
        let ttl = [
            msg[name_end + 4],
            msg[name_end + 5],
            msg[name_end + 6],
            msg[name_end + 7],
        ];
        let rdlen = u16::from_be_bytes([msg[name_end + 8], msg[name_end + 9]]) as usize;
        let end = name_end.checked_add(10)?.checked_add(rdlen)?;
        if end > msg.len() {
            return None;
        }
        if rtype == OPT_RR_TYPE {
            return Some(OptLoc {
                start: cur,
                end,
                payload,
                ttl,
                rdata_start: name_end + 10,
                rdlen,
            });
        }
        cur = end;
    }
}

/// 用新的 OPT rdata 重建报文（保留原 OPT 的 payload/ttl；`opt=None` 时追加一个）。
fn splice_opt_rdata(msg: &[u8], opt: Option<&OptLoc>, payload: u16, ttl: [u8; 4], rdata: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(msg.len() + rdata.len() + 11);
    match opt {
        Some(o) => {
            out.extend_from_slice(&msg[..o.start]);
            out.extend_from_slice(&msg[o.end..]);
        }
        None => out.extend_from_slice(msg),
    }
    out.push(0u8);
    out.extend_from_slice(&OPT_RR_TYPE.to_be_bytes());
    out.extend_from_slice(&payload.to_be_bytes());
    out.extend_from_slice(&ttl);
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    if out.len() >= 12 {
        let ar = u16::from_be_bytes([out[10], out[11]]);
        let ar = if opt.is_none() { ar.wrapping_add(1) } else { ar.max(1) };
        out[10..12].copy_from_slice(&ar.to_be_bytes());
    }
    out
}

/// 剥离查询里客户端自带的 ECS option（RFC 7871 code=8），其余 option 原样保留。
/// 返回 None = 无 OPT/无 ECS/解析失败（调用方原样转发）。
fn strip_ecs_option(msg: &[u8]) -> Option<Vec<u8>> {
    let opt = find_opt_rr(msg)?;
    let rdata = &msg[opt.rdata_start..opt.rdata_start + opt.rdlen];
    let mut kept: Vec<u8> = Vec::with_capacity(rdata.len());
    let mut i = 0usize;
    let mut had_ecs = false;
    while i + 4 <= rdata.len() {
        let code = u16::from_be_bytes([rdata[i], rdata[i + 1]]);
        let olen = u16::from_be_bytes([rdata[i + 2], rdata[i + 3]]) as usize;
        if i + 4 + olen > rdata.len() {
            // 畸形 option：无法安全剥离，原样转发（P3 语义项，不影响安全边界）。
            return None;
        }
        if code == ECS_OPTION_CODE {
            had_ecs = true;
        } else {
            kept.extend_from_slice(&rdata[i..i + 4 + olen]);
        }
        i += 4 + olen;
    }
    if i < rdata.len() {
        return None;
    }
    if !had_ecs {
        return None;
    }
    Some(splice_opt_rdata(msg, Some(&opt), opt.payload, opt.ttl, &kept))
}

/// 把出站查询的 EDNS UDP payload size 抬到 `size`（无 OPT 则补一个空 OPT）。
/// RFC 8484 §6：DoH 服务器必须忽略查询里通告的 payload size（客户端通告 512 时，
/// 原样转发会让 named 回 TC=1）。
fn set_udp_payload(msg: &[u8], size: u16) -> Vec<u8> {
    match find_opt_rr(msg) {
        Some(opt) if opt.payload == size => msg.to_vec(),
        Some(opt) => {
            let rdata = msg[opt.rdata_start..opt.rdata_start + opt.rdlen].to_vec();
            splice_opt_rdata(msg, Some(&opt), size, opt.ttl, &rdata)
        }
        None => splice_opt_rdata(msg, None, size, [0u8; 4], &[]),
    }
}

/// 高频失败日志的**时间节流**（同一类别最快 60s 一条）。
///
/// 为什么需要：DoT 的拒绝/握手失败判定全都在 **TLS 握手之前**，也就是完全由**未认证**
/// 的对端驱动 —— 每个被拒的连接/查询各写一条 warn，用 `nc` 对着 853 猛连就能按自己的
/// 速率写日志（几万条/秒 × 一条近百字节 = GB/天）。本机磁盘长期 95%、日志轮转阈值只有
/// 2MB，这条路径足以把磁盘写满、并把真正有用的日志挤掉。
/// 与 `dns::warn_once`（按 tag 记住**消息**）同一目的，但这里的消息天然带对端地址、
/// 每条都不同 ⇒ 那条路去重不了；只能按「类别 + 时间」节流。
/// 节流只作用于**失败/拒绝**（攻击者可控）的日志，成功的握手与每条查询的 info 仍在。
#[cfg(feature = "tls_boring")]
fn warn_throttled(tag: &str, msg: &str) {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static LAST: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);
    let mut g = LAST.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    let due = m
        .get(tag)
        .map(|t| now.duration_since(*t) >= Duration::from_secs(60))
        .unwrap_or(true);
    if !due {
        return;
    }
    m.insert(tag.to_string(), now);
    drop(g);
    log::warn!("{msg}");
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        let _ = T;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------- DoT listener

/// DoT 客户端白名单的解析：`[dns.dot] allow` 非空用它；否则沿用 `[dns] recursion_acl`；
/// 两者都空 ⇒ **仅回环**（与 `[dns] recursion_acl`「空 = 仅本机」的文档语义一致）。
fn dot_effective_allow(cfg: &crate::server::dns::DnsConfig) -> Vec<String> {
    if !cfg.dot.allow.is_empty() {
        return cfg.dot.allow.clone();
    }
    cfg.recursion_acl.clone()
}

/// 准入判定：白名单为空 ⇒ 仅回环（安全默认）。IP/CIDR 解析复用 HTTP 侧那一套
/// （`access::is_allowed`，含 v4-mapped v6 归一化）。
fn dot_peer_allowed(cfg: &crate::server::dns::DnsConfig, peer: std::net::SocketAddr) -> bool {
    let allow = dot_effective_allow(cfg);
    if allow.is_empty() {
        return peer.ip().is_loopback();
    }
    crate::server::access::is_allowed(
        &crate::config::IpAccessConfig {
            allow,
            deny: Vec::new(),
        },
        peer,
    )
}

fn dot_allow_desc(cfg: &crate::server::dns::DnsConfig) -> String {
    let a = dot_effective_allow(cfg);
    if a.is_empty() {
        "loopback-only".to_string()
    } else {
        a.join(",")
    }
}

const DOT_DEFAULT_RATE: f64 = 20.0;
const DOT_DEFAULT_BURST: f64 = 40.0;
const DOT_DEFAULT_MAX_CONNS: usize = 128;

/// 0 视为「用默认值」——因为整段 `[dns.dot]` 缺失时 serde 走 `DotCfg::default()`（全 0），
/// 若把 0 当「不限」就会在「只想开 DoT、没写限速」时静默变成无限制。
fn dot_rate(cfg: &crate::server::dns::DnsConfig) -> f64 {
    if cfg.dot.rate_per_sec == 0 {
        DOT_DEFAULT_RATE
    } else {
        cfg.dot.rate_per_sec as f64
    }
}

fn dot_burst(cfg: &crate::server::dns::DnsConfig) -> f64 {
    if cfg.dot.burst == 0 {
        DOT_DEFAULT_BURST
    } else {
        cfg.dot.burst as f64
    }
}

fn dot_max_conns(cfg: &crate::server::dns::DnsConfig) -> usize {
    if cfg.dot.max_conns == 0 {
        DOT_DEFAULT_MAX_CONNS
    } else {
        cfg.dot.max_conns
    }
}

/// DoT 运行中的共享状态：supervisor 在配置变化时整体替换，accept 循环与连接任务读取。
struct DotLive {
    /// 当前生效的 `[dns]` 配置（面板/配置变化时发布新 Arc）。
    cfg: Arc<crate::server::dns::DnsConfig>,
    /// 并发连接上限信号量。max_conns 变化时随新 cfg 一起替换；旧连接持有的 permit
    /// 属于旧信号量，不会被计入新上限（不会出现「重建后总量翻倍」）。
    conns: Arc<tokio::sync::Semaphore>,
}

impl DotLive {
    fn from_cfg(cfg: &crate::server::dns::DnsConfig, prev: Option<&DotLive>) -> DotLive {
        let conns = match prev {
            Some(p) if dot_max_conns(&p.cfg) == dot_max_conns(cfg) => Arc::clone(&p.conns),
            _ => Arc::new(tokio::sync::Semaphore::new(dot_max_conns(cfg))),
        };
        DotLive {
            cfg: Arc::new(cfg.clone()),
            conns,
        }
    }
}

/// DoT listener 的对外运行态快照（status API 用：配置说开着 ≠ 端口真的在听）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct DotStatus {
    pub listening: bool,
    pub addr: String,
    pub port: u16,
    pub allow: String,
    pub max_conns: usize,
    pub cert: Option<String>,
}

static DOT_STATUS: std::sync::Mutex<Option<DotStatus>> = std::sync::Mutex::new(None);

fn set_dot_status(st: Option<DotStatus>) {
    *DOT_STATUS.lock().unwrap_or_else(|e| e.into_inner()) = st;
}

/// 当前 DoT listener 是否真的在监听（None = 未启用/证书不可用/绑定失败）。
/// `dns/status` 应回报它（配置说 enabled ≠ 端口真的在听）—— 跨文件需求。
#[allow(dead_code)]
pub fn dot_listener_status() -> Option<DotStatus> {
    DOT_STATUS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// DoT 监听端口：显式端口优先；0 = test_mode 派生 11853 / 生产 853。
fn dot_bind_port(dns: &crate::server::dns::DnsConfig) -> u16 {
    if dns.dot.port != 0 {
        dns.dot.port
    } else if dns.test_mode {
        11853
    } else {
        853
    }
}

/// DoT 与 named 同址同端口冲突：BIND 的 `listen-on port 53` 同时占 UDP 与 **TCP** 53，
/// 两边必有一个起不来（先绑 DoT 会让 named 起不来 —— DNS 整体宕）。配置层校验缺失时
/// 在这里显式拒绝并给出可操作错误，而不是留一条 EADDRINUSE。53/TCP 是 DNS-over-TCP
/// （RFC 7766），不是 DoT 标准口（853），配置成相同端口没有任何正确用法。
fn dot_port_conflicts_named(dns: &crate::server::dns::DnsConfig) -> bool {
    dns.dot.port != 0 && dns.dot.port == dns.port_or_default()
}

/// DoT TCP+TLS 监听（兼容入口）。
///
/// 配置源 =「panel.toml（存在则整体覆盖，与 `effective()` 同语义）→ 启动快照」，
/// 由 supervisor **周期重读**：面板“保存并应用”后 ACL/限速/并发上限/端口/启停都会生效。
/// 完整热载（config.toml 的 `[dns]` 改动、启动时未启用后来启用）用 [`dot_listener_live`]。
/// DoT TCP+TLS 监听（快照入口，**已不再由 `dns::startup` 使用** —— 它只重读 panel.toml，
/// config.toml 热载的 [dns.dot] 改动不生效；`startup` 现在 spawn [`dot_listener_live`]）。
/// 保留它是因为面板/测试仍有按「panel.toml → 启动快照」取配置的用法。
#[allow(dead_code)]
pub async fn dot_listener(dns: crate::config::DnsConfig) {
    #[cfg(feature = "tls_boring")]
    {
        let base = Arc::new(dns);
        let panel = super::state_root().join("etc/panel.toml");
        dot_supervisor(move || {
            // panel.toml 是 effective() 的权威来源：存在且可解析时整体覆盖 config.toml [dns]。
            if let Ok(text) = std::fs::read_to_string(&panel) {
                if !text.trim().is_empty() {
                    if let Ok(p) = toml::from_str::<crate::server::dns::DnsConfig>(&text) {
                        return Arc::new(p);
                    }
                }
            }
            Arc::new((*base).clone())
        })
        .await;
    }
    #[cfg(not(feature = "tls_boring"))]
    {
        let _ = dns;
        log::warn!("dns: dot listener requires tls_boring feature");
    }
}

/// DoT 监听（live 配置入口）：每次判定都取 `effective(live.snapshot())`，
/// 端口/启停变化自动重建监听，ACL/限速/并发上限每 accept 与每查询读取当前值（P1-2）。
/// `dns::startup` 应改为 spawn 它（跨文件需求），替代启动时快照入口 [`dot_listener`]。
pub async fn dot_listener_live(live: Arc<crate::server::live_config::LiveConfig>) {
    #[cfg(feature = "tls_boring")]
    {
        dot_supervisor(move || crate::server::dns::effective(&live.snapshot())).await;
    }
    #[cfg(not(feature = "tls_boring"))]
    {
        let _ = live;
        log::warn!("dns: dot listener requires tls_boring feature");
    }
}

/// DoT supervisor：轮询配置源，负责 bind/unbind 与运行参数发布。
#[cfg(feature = "tls_boring")]
async fn dot_supervisor<F>(source: F)
where
    F: Fn() -> Arc<crate::server::dns::DnsConfig>,
{
    let first = source();
    let (tx, rx) = tokio::sync::watch::channel(Arc::new(DotLive::from_cfg(&first, None)));
    let mut running: Option<tokio::task::JoinHandle<()>> = None;
    let mut running_bind: Option<(String, u16)> = None;
    let mut last_cfg_fp: u64 = 0;
    loop {
        let dc = source();
        // 运行参数（ACL/限速/并发上限/证书 spec）变化 → 发布新快照；max_conns 未变时
        // 沿用旧信号量（否则新老 permit 各算各的，总量会超上限）。
        let fp = dot_cfg_fingerprint(&dc);
        if fp != last_cfg_fp {
            let prev = tx.borrow().clone();
            let _ = tx.send(Arc::new(DotLive::from_cfg(&dc, Some(&prev))));
            last_cfg_fp = fp;
        }
        if dc.enabled && dc.dot.enabled && dot_port_conflicts_named(&dc) {
            warn_throttled(
                "dot-port-conflict",
                &format!(
                    "dns: [dns.dot].port = {} 与 named 端口相同（TCP 53 已被 BIND 占用）—— DoT 不会启动；请把 dot.port 改为 853（或 0 派生）",
                    dc.dot.port
                ),
            );
        }
        let want = dc.enabled && dc.dot.enabled && !dot_port_conflicts_named(&dc);
        let acceptor = if want {
            Some(build_dot_acceptor_cached(&dc.dot))
        } else {
            None
        };
        if let Some(Err(e)) = &acceptor {
            // 证书缺失/无效：不监听（fail-closed），周期重试 —— ACME 一旦签发完成自动拉起。
            warn_throttled(
                "dot-cert",
                &format!("dns: DoT 未启动：{e:#}（证书就绪后自动重试）"),
            );
        }
        let runnable = matches!(acceptor, Some(Ok(_)));
        let bind_ip = if dc.test_mode { "127.0.0.1" } else { "0.0.0.0" };
        let port = dot_bind_port(&dc);
        if !runnable {
            if let Some(t) = running.take() {
                t.abort();
                log::info!("dns: DoT listener stopped");
            }
            if running_bind.take().is_some() {
                set_dot_status(None);
            }
        } else if running.is_none()
            || running_bind.as_ref() != Some(&(bind_ip.to_string(), port))
        {
            if let Some(t) = running.take() {
                t.abort();
            }
            running_bind = None;
            match tokio::net::TcpListener::bind((bind_ip, port)).await {
                Ok(l) => {
                    log::info!(
                        "dns: DoT listening on {bind_ip}:{port} → named@{}:{} (allow={}, rate={}/s burst={}, max_conns={})",
                        dc.listen_addr,
                        dc.port_or_default(),
                        dot_allow_desc(&dc),
                        dot_rate(&dc),
                        dot_burst(&dc),
                        dot_max_conns(&dc)
                    );
                    set_dot_status(Some(DotStatus {
                        listening: true,
                        addr: bind_ip.to_string(),
                        port,
                        allow: dot_allow_desc(&dc),
                        max_conns: dot_max_conns(&dc),
                        cert: dc.dot.cert.clone(),
                    }));
                    running_bind = Some((bind_ip.to_string(), port));
                    running = Some(tokio::spawn(dot_accept_loop(l, rx.clone())));
                }
                Err(e) => {
                    warn_throttled(
                        "dot-bind",
                        &format!("dns: dot bind {bind_ip}:{port} failed: {e}"),
                    );
                    set_dot_status(None);
                }
            }
        }
        tokio::time::sleep(DOT_CONFIG_POLL).await;
    }
}

/// DoT 配置指纹：决定是否发布新运行参数快照（不含证书**内容**——那由 acceptor
/// 指纹按连接判定）。
#[cfg(feature = "tls_boring")]
fn dot_cfg_fingerprint(dc: &crate::server::dns::DnsConfig) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    dc.enabled.hash(&mut h);
    dc.test_mode.hash(&mut h);
    dc.port.hash(&mut h);
    dc.recursion_acl.hash(&mut h);
    dc.dot.enabled.hash(&mut h);
    dc.dot.port.hash(&mut h);
    dc.dot.allow.hash(&mut h);
    dc.dot.rate_per_sec.hash(&mut h);
    dc.dot.burst.hash(&mut h);
    dc.dot.max_conns.hash(&mut h);
    dc.dot.cert.hash(&mut h);
    dc.dot.key.hash(&mut h);
    h.finish()
}

#[cfg(feature = "tls_boring")]
static DOT_ACCEPTOR_CACHE: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<u64, Arc<boring::ssl::SslAcceptor>>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 证书/密钥材料指纹：路径 + mtime(纳秒) + 大小（同 `tls/boring_path.rs` 的做法）。
/// 路径不变、内容原地替换（ACME 续期、面板签发、手工覆盖）也会改变指纹 ⇒
/// 下一个连接重建 acceptor 并用新证书，而不是把旧证书用到过期（P1-3）。
#[cfg(feature = "tls_boring")]
fn dot_cert_fingerprint(dot: &crate::config::DotCfg) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    dot.cert.hash(&mut h);
    dot.key.hash(&mut h);
    let cert = dot.cert.as_deref().map(super::acme::resolve_cert_path);
    let key = dot.key.as_deref().map(super::acme::resolve_key_path);
    for p in [cert.as_ref(), key.as_ref()] {
        match p {
            Some(path) => {
                path.hash(&mut h);
                match std::fs::metadata(path) {
                    Ok(m) => {
                        m.len().hash(&mut h);
                        if let Ok(t) = m.modified() {
                            if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                                d.as_nanos().hash(&mut h);
                            }
                        }
                    }
                    // 打不开/缺失也编进指纹：文件「先消失后出现」不会命中旧 acceptor。
                    Err(_) => u64::MAX.hash(&mut h),
                }
            }
            None => 0u8.hash(&mut h),
        }
    }
    h.finish()
}

/// 缓存版 acceptor（accept 热路径调用；指纹来自证书/密钥材料，续期自动生效）。
#[cfg(feature = "tls_boring")]
fn build_dot_acceptor_cached(dot: &crate::config::DotCfg) -> Result<Arc<boring::ssl::SslAcceptor>> {
    let fp = dot_cert_fingerprint(dot);
    if let Some(a) = DOT_ACCEPTOR_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&fp)
    {
        return Ok(Arc::clone(a));
    }
    let a = Arc::new(build_tls_acceptor(dot)?);
    let mut map = DOT_ACCEPTOR_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() >= DOT_ACCEPTOR_CACHE_CAP {
        map.clear();
    }
    map.insert(fp, Arc::clone(&a));
    Ok(a)
}

#[cfg(feature = "tls_boring")]
fn build_tls_acceptor(dot: &crate::config::DotCfg) -> Result<boring::ssl::SslAcceptor> {
    use boring::ssl::{SslAcceptor as BoringAcceptor, SslFiletype, SslMethod};
    // cert 支持 "acme:<domain>" 前缀（Let's Encrypt 自动签发产物路径）。
    let cert_spec = dot
        .cert
        .clone()
        .ok_or_else(|| anyhow::anyhow!("dot.cert not configured"))?;
    let key_spec = dot
        .key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("dot.key not configured"))?;
    let cert = super::acme::resolve_cert_path(&cert_spec);
    let key = super::acme::resolve_key_path(&key_spec);
    // **不再回落** CWD 的 cert.pem/key.pem：那会让 `acme:<domain>` 签发失败时拿一张
    // 名字不匹配的第三方证书对外服务，客户端校验失败却查不出原因（P3）。
    // 要用手动证书就在 [dns.dot] 里显式写路径。
    if !cert.is_file() || !key.is_file() {
        anyhow::bail!(
            "dot cert/key 不可用（{} / {}）—— 请显式配置 [dns.dot] cert/key，或等待 ACME 签发完成",
            cert.display(),
            key.display()
        );
    }
    key_permission_warn(&key);
    let mut b = BoringAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    b.set_certificate_file(&cert, SslFiletype::PEM)?;
    b.set_private_key_file(&key, SslFiletype::PEM)?;
    b.check_private_key()?;
    // RFC 8310 的 ALPN 标识 "dot"：客户端（unbound/stubby/kdig 等）在 ALPN 里给出
    // `dot` 时回显所选协议；未给出/没有交集时不选（NOACK），不影响老客户端。
    b.set_alpn_select_callback(|_ssl, client_protos: &[u8]| {
        let mut i = 0usize;
        while i < client_protos.len() {
            let l = client_protos[i] as usize;
            let end = match i.checked_add(1 + l) {
                Some(e) if e <= client_protos.len() => e,
                _ => break,
            };
            let name = &client_protos[i + 1..end];
            if name == b"dot" {
                return Ok(name);
            }
            i = end;
        }
        Err(boring::ssl::AlpnError::NOACK)
    });
    // boring::ssl::SslAcceptor；异步 accept 由 tokio_boring::accept(acceptor, stream) 完成
    Ok(b.build())
}

/// 私钥文件权限提醒（group/other 可读 ⇒ 同机其它用户可拿走私钥）。
#[cfg(all(feature = "tls_boring", unix))]
fn key_permission_warn(key: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(m) = std::fs::metadata(key) {
        if m.permissions().mode() & 0o077 != 0 {
            log::warn!(
                "dns: DoT 私钥 {} 权限过宽（{:o}，other/group 可读），建议 chmod 600",
                key.display(),
                m.permissions().mode() & 0o777
            );
        }
    }
}

#[cfg(all(feature = "tls_boring", not(unix)))]
fn key_permission_warn(_key: &std::path::Path) {}

/// DoT accept 循环：每次 accept 从 live 快照取当前配置做三道准入
/// （ACL → 单 IP 限速 → 并发上限），判定失败直接丢弃（不握手，避免白耗 TLS CPU）。
#[cfg(feature = "tls_boring")]
async fn dot_accept_loop(
    listener: tokio::net::TcpListener,
    rx: tokio::sync::watch::Receiver<Arc<DotLive>>,
) {
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(x) => x,
            // 旧实现在 Err 上直接 continue：EMFILE/ENFILE 时是**紧循环**（100% CPU 空转
            // 且不记日志）。与 server::mod 主 accept 循环一致：退避 + 节流日志。
            Err(e) => {
                warn_throttled(
                    "dot-accept",
                    &format!("dot: accept failed: {e}（退避 {}ms）", DOT_ACCEPT_BACKOFF.as_millis()),
                );
                tokio::time::sleep(DOT_ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let live = rx.borrow().clone();
        let cfg = Arc::clone(&live.cfg);
        if !dot_peer_allowed(&cfg, peer) {
            warn_throttled(
                "dot-acl",
                &format!("dot: reject {peer}: 不在 DoT 白名单（见 [dns.dot] allow / [dns] recursion_acl）"),
            );
            continue;
        }
        if !crate::server::rate_limit::allow(peer.ip(), dot_rate(&cfg), dot_burst(&cfg)) {
            warn_throttled("dot-rate-accept", &format!("dot: rate limit exceeded from {}", peer.ip()));
            continue;
        }
        let permit = match live.conns.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn_throttled(
                    "dot-conns",
                    &format!(
                        "dot: 并发连接已达上限 {}，拒绝 {peer}",
                        dot_max_conns(&cfg)
                    ),
                );
                continue;
            }
        };
        let acceptor = match build_dot_acceptor_cached(&cfg.dot) {
            Ok(a) => a,
            Err(e) => {
                warn_throttled("dot-cert", &format!("dot: {peer} 被拒：{e:#}"));
                continue;
            }
        };
        let rx2 = rx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            dot_connection(rx2, sock, peer, acceptor).await;
        });
    }
}

/// 单条 DoT 连接：有截止时间的握手 + 有超时的帧循环。
#[cfg(feature = "tls_boring")]
async fn dot_connection(
    rx: tokio::sync::watch::Receiver<Arc<DotLive>>,
    sock: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    acceptor: Arc<boring::ssl::SslAcceptor>,
) {
    // 握手截止时间：`tokio_boring::accept` 无内部超时，匿名对端不发/不发完 ClientHello
    // 就能永久挂住这条连接（占 permit/fd/任务）。超时即 drop，permit 随任务结束释放。
    let mut tls = match tokio::time::timeout(
        DOT_HANDSHAKE_TIMEOUT,
        tokio_boring::accept(&acceptor, sock),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn_throttled("dot-tls", &format!("dot: tls accept failed from {peer}: {e}"));
            return;
        }
        Err(_) => {
            warn_throttled(
                "dot-tls-timeout",
                &format!("dot: TLS 握手超时（{DOT_HANDSHAKE_TIMEOUT:?}），丢弃 {peer}"),
            );
            return;
        }
    };
    log::info!("dot: tls handshake ok from {peer}");
    // RFC7858：2 字节大端长度前缀的 DNS 报文，可多查询串行处理
    loop {
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(
            DOT_FRAME_TIMEOUT,
            tokio::io::AsyncReadExt::read_exact(&mut tls, &mut len_buf),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                log::warn!("dot: read len err from {peer}: {e}");
                return;
            }
            Err(_) => {
                log::warn!("dot: read len timeout from {peer}（空闲连接已清理）");
                return;
            }
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return;
        }
        // 每轮循环都读**当前** live 配置：ACL 收紧 / 关掉 DoT 后，已建立连接在下一次
        // 查询/下一次读超时时收尾（空闲连接 10s 内必被清理），不会继续服务。
        let live = rx.borrow().clone();
        let cfg = Arc::clone(&live.cfg);
        if !cfg.enabled || !cfg.dot.enabled {
            log::info!("dot: config disabled —— 关闭连接 {peer}");
            return;
        }
        if !dot_peer_allowed(&cfg, peer) {
            warn_throttled("dot-acl", &format!("dot: ACL 收紧，关闭连接 {peer}"));
            return;
        }
        // **每条查询**都要过限速：accept 时那次只限制「连接建立」，而一条 DoT 连接
        // 可以串行灌无限条查询（RFC7858 允许复用）⇒ 面板上写的「单 IP 20/s」
        // 实际变成「单连接不限」，一个来源就能把上游打满。超限直接关连接。
        if !crate::server::rate_limit::allow(peer.ip(), dot_rate(&cfg), dot_burst(&cfg)) {
            warn_throttled(
                "dot-rate-query",
                &format!("dot: 单 IP 查询限速超限，关闭连接 from {peer}"),
            );
            return;
        }
        let mut msg = vec![0u8; len];
        // 帧体读取必须有超时：旧实现对端发 len=65535 再只发 1 字节即可**永久**挂住
        // 这条连接（permit/fd 不释放）。
        match tokio::time::timeout(
            DOT_FRAME_TIMEOUT,
            tokio::io::AsyncReadExt::read_exact(&mut tls, &mut msg),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                log::warn!("dot: read body err from {peer} len={len}: {e}");
                return;
            }
            Err(_) => {
                log::warn!("dot: read body timeout from {peer} len={len}（挂死连接已清理）");
                return;
            }
        }
        match udp_query(&cfg, msg, Some(peer.ip())).await {
            Ok(answer) => {
                let al = (answer.len() as u16).to_be_bytes();
                use tokio::io::AsyncWriteExt;
                log::info!("dot: query {} bytes -> answer {} bytes", len, answer.len());
                if tls.write_all(&al).await.is_err() || tls.write_all(&answer).await.is_err() {
                    log::warn!("dot: write answer err to {peer}");
                    return;
                }
            }
            Err(e) => {
                log::warn!("dot: udp forward err from {peer}: {e:#}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_whitelist_strips_ports() {
        let wl = vec!["127.0.0.1:19095".into(), "dns.crucible.local".into()];
        assert!(doh_host_allowed(&wl, Some("127.0.0.1:19095")));
        assert!(doh_host_allowed(&wl, Some("dns.crucible.local:443")));
        assert!(!doh_host_allowed(&wl, Some("evil.example:19095")));
        // Host 缺失 ⇒ 拒绝（不得 fail-open）。
        assert!(!doh_host_allowed(&wl, None));
        assert!(!doh_host_allowed(&wl, Some("")));
    }

    /// P1-5：空白名单 = 拒绝（旧实现 return true = 任意 Host 都能命中 DoH）。
    /// 要放开必须显式写 `*`。
    #[test]
    fn doh_empty_whitelist_rejects_and_star_allows() {
        let empty: Vec<String> = Vec::new();
        assert!(!doh_host_allowed(&empty, Some("anything.example")));
        let star = vec!["*".to_string()];
        assert!(doh_host_allowed(&star, Some("anything.example")));
        assert!(doh_host_allowed(&star, Some("anything.example:8443")));
    }

    /// P3：doh.path = "/" 会让整站变成 DoH 端点 —— 本层先 fail-closed。
    #[test]
    fn doh_path_guard() {
        assert!(doh_path_ok("/dns-query", "/dns-query"));
        assert!(!doh_path_ok("/", "/dns-query"));
        assert!(!doh_path_ok("/dns-query", "/"));
        assert!(!doh_path_ok("/dns-query", "dns-query"));
        assert!(!doh_path_ok("/dns-query", ""));
    }

    /// P3：Content-Type 大小写不敏感、按 `;` 截断、拒绝前缀相同的伪造类型。
    #[test]
    fn doh_content_type_exact() {
        assert!(ct_is_dns_message("application/dns-message"));
        assert!(ct_is_dns_message("Application/DNS-Message;charset=utf-8"));
        assert!(ct_is_dns_message(" application/dns-message ; x=1"));
        assert!(!ct_is_dns_message("application/dns-messageX"));
        assert!(!ct_is_dns_message("text/plain"));
        assert!(!ct_is_dns_message(""));
    }

    #[test]
    fn host_without_port_ipv6() {
        assert_eq!(host_without_port("[::1]:853"), "::1");
        assert_eq!(host_without_port("example.com:443"), "example.com");
        assert_eq!(host_without_port("example.com"), "example.com");
    }

    /// P2-7：DoH 响应 freshness 取 Answer 段最小 TTL；NXDOMAIN 退回 Authority。
    #[test]
    fn min_answer_ttl_scans_answer_section() {
        let mut msg = vec![0u8; 12];
        msg[5] = 1; // QDCOUNT
        msg.extend_from_slice(&[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
        msg.extend_from_slice(&[0, 1, 0, 1]); // A IN
        msg[7] = 2; // ANCOUNT
        // RR1: 名压缩指针 + A IN ttl=300 rdlen=4
        msg.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[127, 0, 0, 1]);
        // RR2: ttl=60
        msg.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[127, 0, 0, 2]);
        assert_eq!(min_answer_ttl(&msg), Some(60));
        // 截断的报文不得 panic，返回 None。
        assert_eq!(min_answer_ttl(&msg[..msg.len() - 3]), None);
        assert_eq!(min_answer_ttl(&[0u8; 5]), None);
    }

    /// P3：ECS 关闭时剥离客户端自带的 ECS option，其余 option 保留。
    #[test]
    fn strip_ecs_removes_only_ecs() {
        let mut q = vec![0u8; 12];
        q[5] = 1;
        q.extend_from_slice(&[3, b'w', b'w', b'w', 0]);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q[11] = 1; // ARCOUNT
        q.extend_from_slice(&[0]); // root
        q.extend_from_slice(&41u16.to_be_bytes()); // OPT
        q.extend_from_slice(&4096u16.to_be_bytes());
        q.extend_from_slice(&[0, 0, 0, 0]);
        // rdata: COOKIE(code=10) + ECS(code=8)
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes());
        rdata.extend_from_slice(&2u16.to_be_bytes());
        rdata.extend_from_slice(&[0xAA, 0xBB]);
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&7u16.to_be_bytes());
        rdata.extend_from_slice(&[0, 1, 24, 0, 203, 0, 113]);
        q.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        q.extend_from_slice(&rdata);
        let out = strip_ecs_option(&q).expect("must strip ECS");
        let opt = find_opt_rr(&out).unwrap();
        let new_rdata = &out[opt.rdata_start..opt.rdata_start + opt.rdlen];
        let expected: Vec<u8> = [10u16.to_be_bytes(), 2u16.to_be_bytes(), [0xAA, 0xBB]].concat();
        assert_eq!(new_rdata, expected.as_slice(), "COOKIE 保留、ECS 剥离");
        // OPT payload/TTL 保留原值。
        assert_eq!(opt.payload, 4096);
        // 无 OPT 的报文（砍掉 1 字节 root 名 + 10 字节 OPT 头 + rdata）：不能破坏原样。
        let plain = &q[..q.len() - (11 + rdata.len())];
        assert!(strip_ecs_option(plain).is_none());
    }

    /// P3：DoH 出站 payload size 抬到 65535（无 OPT 则补一个）。
    #[test]
    fn set_udp_payload_rewrites_opt() {
        let mut q = vec![0u8; 12];
        q[5] = 1;
        q.extend_from_slice(&[3, b'w', b'w', b'w', 0]);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q[11] = 1;
        q.extend_from_slice(&[0]);
        q.extend_from_slice(&41u16.to_be_bytes());
        q.extend_from_slice(&512u16.to_be_bytes());
        q.extend_from_slice(&[0, 0, 0, 0]);
        q.extend_from_slice(&0u16.to_be_bytes());
        let out = set_udp_payload(&q, 65535);
        assert_eq!(find_opt_rr(&out).unwrap().payload, 65535);
        // 无 OPT 时补一个。
        let plain = vec![
            0u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0, 1, 0, 1,
        ];
        let out2 = set_udp_payload(&plain, 65535);
        let opt = find_opt_rr(&out2).expect("OPT added");
        assert_eq!(opt.payload, 65535);
        assert_eq!(u16::from_be_bytes([out2[10], out2[11]]), 1, "ARCOUNT 计入新增 OPT");
    }
}
