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

/// 把 DNS wire 报文转发到本机 named 的 UDP 口（递归语义下附 EDNS Client Subnet /24）。
/// 分线路（需求 10）：客户端 IP 命中 geo.lines → 转发到 127.0.0.(2+i)
/// （named 侧 fwd-<line> view 以 match-destinations 承接，view 内是 per-line zone 数据）。
pub async fn udp_query(
    cfg: &crate::server::dns::DnsConfig,
    wire: Vec<u8>,
    client: Option<std::net::IpAddr>,
) -> Result<Vec<u8>> {
    use tokio::net::UdpSocket;
    let port = cfg.port_or_default();
    // ECS（RFC7871）：v4 固定 /24、v6 /56，客户端自带 ECS 也重写（禁止 /32 出网）
    // ECS (RFC7871): only inject when enabled and we have a client IP
    let wire = if cfg.ecs {
        match client {
            Some(ip) => super::ecs::inject_ecs(&wire, ip).unwrap_or(wire),
            None => wire,
        }
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
    Ok(buf)
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
    let path_ok = req.uri().path() == dns_cfg.doh.path;
    let host_ok = doh_host_allowed(
        &dns_cfg.doh.hostnames,
        req.headers().get(http::header::HOST),
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
            if cl > 65535 {
                return Ok(resp_text(StatusCode::PAYLOAD_TOO_LARGE, "dns message too large"));
            }
        }
    }
    let (_, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    if body_bytes.len() > 65535 {
        return Ok(resp_text(StatusCode::PAYLOAD_TOO_LARGE, "dns message too large"));
    }
    match doh_prepared(&dns_cfg, &method, &uri, &headers, body_bytes, peer).await {
        // 上面已判 path/host，这里必然 Some；None 时兜底 415（防御）
        None => Ok(resp_text(StatusCode::UNSUPPORTED_MEDIA_TYPE, "doh not applicable")),
        Some(resp) => Ok(resp),
    }
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
    if uri.path() != dns_cfg.doh.path {
        return None;
    }
    if !doh_host_allowed(&dns_cfg.doh.hostnames, headers.get(http::header::HOST)) {
        return None;
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
                    Some(w) if (12..=65535).contains(&w.len()) => w,
                    Some(_) => {
                        return Some(resp_text(StatusCode::PAYLOAD_TOO_LARGE, "dns message too large"));
                    }
                    None => return Some(resp_text(StatusCode::BAD_REQUEST, "bad dns message")),
                },
                None => return Some(resp_text(StatusCode::BAD_REQUEST, "bad dns message")),
            }
        }
        &http::Method::POST => {
            let ct = headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct.starts_with("application/dns-message") {
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
        _ => return Some(resp_text(StatusCode::METHOD_NOT_ALLOWED, "GET or POST only")),
    };
    // DNS wire over UDP cannot exceed 65535; reject oversized DoH payloads early.
    if wire.len() > 65535 {
        return Some(resp_text(StatusCode::PAYLOAD_TOO_LARGE, "dns message too large"));
    }
    // 分线路 DoH：客户端 IP 决定转发 dest（resolve_fwd_dest）
    match udp_query(dns_cfg, wire, Some(peer.ip())).await {
        Ok(answer) => Some(
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/dns-message")
                .body(crate::server::h1::full(answer))
                .unwrap(),
        ),
        Err(e) => Some(resp_text(
            StatusCode::BAD_GATEWAY,
            &format!("dns upstream error: {e:#}"),
        )),
    }
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

fn doh_host_allowed(whitelist: &[String], host_hdr: Option<&http::HeaderValue>) -> bool {
    if whitelist.is_empty() {
        return true;
    }
    let raw = match host_hdr.and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => return false,
    };
    let host = host_without_port(raw);
    // Whitelist entries may be written as `host` or `host:port` (config-test uses the latter).
    whitelist.iter().any(|entry| {
        let allow = host_without_port(entry.trim());
        allow.eq_ignore_ascii_case(host) || entry.eq_ignore_ascii_case(raw)
    })
}

fn resp_text(st: StatusCode, msg: &str) -> Response<BoxBody> {
    Response::builder()
        .status(st)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(msg.to_string()))
        .unwrap()
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

/// DoT TCP+TLS 监听循环（独立端口；443 SNI 复用见集成补丁）。
pub async fn dot_listener(dns: crate::config::DnsConfig) {
    let port = if dns.dot.port != 0 {
        dns.dot.port
    } else if dns.test_mode {
        11853
    } else {
        853
    };
    #[cfg(feature = "tls_boring")]
    {
        match build_tls_acceptor(&dns.dot) {
            Ok(acceptor) => run_dot(dns.clone(), port, acceptor).await,
            Err(e) => log::error!("dns: dot listener disabled: {e:#}"),
        }
    }
    #[cfg(not(feature = "tls_boring"))]
    {
        let _ = (dns, port);
        log::warn!("dns: dot listener requires tls_boring feature");
    }
}

#[cfg(feature = "tls_boring")]
fn build_tls_acceptor(
    dot: &crate::config::DotCfg,
) -> Result<boring::ssl::SslAcceptor> {
    use boring::ssl::{SslAcceptor as BoringAcceptor, SslFiletype, SslMethod};
    // cert 支持 "acme:<domain>" 前缀（Let's Encrypt 自动签发产物路径）；
    // 签发未完成或工具缺失时回落 cert.pem/key.pem（手动模式，验收路径）
    let cert_spec = dot
        .cert
        .clone()
        .ok_or_else(|| anyhow::anyhow!("dot.cert not configured"))?;
    let key_spec = dot
        .key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("dot.key not configured"))?;
    let (cert, key) = {
        let c = super::acme::resolve_cert_path(&cert_spec);
        let k = super::acme::resolve_key_path(&key_spec);
        if c.is_file() && k.is_file() {
            (c, k)
        } else {
            let fc = std::path::PathBuf::from("cert.pem");
            let fk = std::path::PathBuf::from("key.pem");
            if fc.is_file() && fk.is_file() {
                log::warn!(
                    "dns: dot cert {} 不存在，回落手动证书 cert.pem/key.pem",
                    c.display()
                );
                (fc, fk)
            } else {
                (c, k)
            }
        }
    };
    let mut b = BoringAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    b.set_certificate_file(&cert, SslFiletype::PEM)?;
    b.set_private_key_file(&key, SslFiletype::PEM)?;
    b.check_private_key()?;
    // boring::ssl::SslAcceptor；异步 accept 由 tokio_boring::accept(acceptor, stream) 完成
    Ok(b.build())
}

#[cfg(feature = "tls_boring")]
async fn run_dot(
    cfg: crate::server::dns::DnsConfig,
    listen: u16,
    acceptor: boring::ssl::SslAcceptor,
) {
    // test_mode: bind loopback only (DoT port 11853 must not be world-reachable)
    let bind_ip = if cfg.test_mode { "127.0.0.1" } else { "0.0.0.0" };
    let listener = match tokio::net::TcpListener::bind((bind_ip, listen)).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("dns: dot bind {bind_ip}:{listen} failed: {e}");
            return;
        }
    };
    log::info!(
        "dns: DoT listening on {bind_ip}:{listen} → named@{}:{}",
        cfg.listen_addr,
        cfg.port_or_default()
    );
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let acc = acceptor.clone();
        let cfg_i = cfg.clone();
        tokio::spawn(async move {
            let cfg = cfg_i;
            let mut tls = match tokio_boring::accept(&acc, sock).await {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("dot: tls accept failed from {peer}: {e}");
                    return;
                }
            };
            log::info!("dot: tls handshake ok from {peer}");
            // RFC7858：2 字节大端长度前缀的 DNS 报文，可多查询串行处理
            loop {
                let mut len_buf = [0u8; 2];
                if tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tokio::io::AsyncReadExt::read_exact(&mut tls, &mut len_buf),
                )
                .await
                .is_err()
                {
                    log::warn!("dot: read len timeout/err from {peer}");
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                if len == 0 || len > 65535 {
                    return;
                }
                let mut msg = vec![0u8; len];
                if tokio::io::AsyncReadExt::read_exact(&mut tls, &mut msg)
                    .await
                    .is_err()
                {
                    log::warn!("dot: read body err from {peer} len={len}");
                    return;
                }
                match udp_query(&cfg, msg, Some(peer.ip())).await {
                    Ok(answer) => {
                        let al = (answer.len() as u16).to_be_bytes();
                        use tokio::io::AsyncWriteExt;
                        log::info!("dot: query {} bytes -> answer {} bytes", len, answer.len());
                        if tls.write_all(&al).await.is_err() || tls.write_all(&answer).await.is_err()
                        {
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
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_whitelist_strips_ports() {
        let wl = vec!["127.0.0.1:19095".into(), "dns.crucible.local".into()];
        let hv = http::HeaderValue::from_static("127.0.0.1:19095");
        assert!(doh_host_allowed(&wl, Some(&hv)));
        let hv2 = http::HeaderValue::from_static("dns.crucible.local:443");
        assert!(doh_host_allowed(&wl, Some(&hv2)));
        let hv3 = http::HeaderValue::from_static("evil.example:19095");
        assert!(!doh_host_allowed(&wl, Some(&hv3)));
    }

    #[test]
    fn host_without_port_ipv6() {
        assert_eq!(host_without_port("[::1]:853"), "::1");
        assert_eq!(host_without_port("example.com:443"), "example.com");
        assert_eq!(host_without_port("example.com"), "example.com");
    }
}
