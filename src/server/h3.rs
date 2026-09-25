//! HTTP/3 (QUIC) via quinn + h3-quinn.
//!
//! Crypto: BoringSSL QUIC via `quinn_boring` only (no rustls fallback).
//! TCP TLS remains BoringSSL-primary. `peer_identity` returns peer DER chain (no `todo!`).
//! Request routing mirrors h1/h2：telemetry → ip_access → rate_limit → basic_auth →
//! admin（完整 API）→ page_rules（含 pass_upstream）→ apps → static（§16.1 分发顺序）。

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "tls")]
mod imp {
    use super::*;
    use crate::server::apps;
    use crate::server::h1::{BoxBody, REQUEST_BODY_CAP};
    use crate::server::connect_udp;
    use crate::server::static_files;
    use anyhow::Context;
    use bytes::{Buf, Bytes};
    use http::{Request, Response, StatusCode};
    use http_body_util::{BodyExt, Full};
    use quinn::{Endpoint, ServerConfig};
    use quinn_boring::server_crypto::BoringQuicServerCrypto;
    use rustls::pki_types::CertificateDer; // peer_identity downcast only

    /// Serve HTTP/3 on UDP `bind` using listener TLS material and static root.
    pub async fn serve(
        bind: SocketAddr,
        lc: ListenerConfig,
        live: Arc<LiveConfig>,
    ) -> Result<()> {
        let ssl = lc.ssl.as_ref().context("h3 listener requires ssl config")?;
        let cert_pem = crate::server::ssl_material::load_bytes(
            ssl.cert.as_deref().context("ssl.cert")?,
        )?;
        let key_pem = crate::server::ssl_material::load_bytes(
            ssl.key.as_deref().context("ssl.key")?,
        )?;

        log::info!("{}", BoringQuicServerCrypto::status_line());

        // 规格：0-RTT 默认关。TCP 侧是 `ssl.early_data` 显式开关（boring_path.rs），
        // QUIC 侧此前**无条件开启**（quinn-boring 的 server::Config::new 里
        // `SSL_CTX_set_early_data_enabled(1)`），于是 H3 默认接受可重放的 0-RTT 请求。
        // 现在把同一个开关透传下去：只有显式配置 early_data=true 才开放。
        let server_config = build_server_config(&cert_pem, &key_pem, ssl.early_data)?;
        if ssl.early_data {
            log::info!("h3: early data (0-RTT) explicitly enabled by ssl.early_data");
        }
        // Bind UDP then attach Boring-aware EndpointConfig (HMAC/versions).
        let socket = std::net::UdpSocket::bind(bind).context("h3 udp bind")?;
        // TASK2：整个 QUIC 端点都跑在这一条 UDP socket 上，ECN 的 socket 级设置
        // 与启动校验打在这里。默认关闭（`ListenerConfig::quic_ecn`）——
        // 它不改变 ECN 是否生效（quinn 那边本来就开着），只把状态变成可观测，
        // 详见 `server::ecn` 文件头。
        if lc.quic_ecn {
            apply_quic_ecn(&socket, bind);
        }
        let endpoint = Endpoint::new(
            quinn_boring::helpers::default_endpoint_config(),
            Some(server_config),
            socket,
            std::sync::Arc::new(quinn::TokioRuntime),
        )
        .context("h3 quinn endpoint")?;
        log::info!("h3 quinn endpoint ready on {bind} (boring crypto preferred)");

        while let Some(incoming) = endpoint.accept().await {
            let live_c = Arc::clone(&live);
            let lc_c = lc.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_incoming(incoming, live_c, lc_c).await {
                    log::warn!("h3 connection: {e:#}");
                }
            });
        }
        Ok(())
    }

    /// BoringSSL QUIC only — no silent rustls fallback (spec: H3 crypto = Boring).
    fn build_server_config(
        cert_pem: &[u8],
        key_pem: &[u8],
        early_data: bool,
    ) -> Result<ServerConfig> {
        let boring = BoringQuicServerCrypto::try_build_with_opts(cert_pem, key_pem, early_data)
            .ok_or_else(|| {
                anyhow::anyhow!("h3: Boring QUIC try_build failed (invalid PEM or provider)")
            })?;
        log::info!("h3: {}", boring.status_line());
        let crypto = boring.as_quinn_crypto().ok_or_else(|| {
            anyhow::anyhow!("h3: BoringQuicConfig built but as_quinn_crypto=None")
        })?;
        quinn_boring::helpers::server_config(crypto)
            .map_err(|e| anyhow::anyhow!("h3 boring server_config: {e}"))
    }

    /// QUIC socket 的 ECN 启动校验（由 `ListenerConfig::quic_ecn` 打开，默认关）。
    ///
    /// 这里**刻意只做入向 + 观测，不写出向码点**。原因是核对源码后的结论：
    /// quinn 自己已经完整支持 ECN —— `quinn-proto` 的 `sending_ecn` 默认为 `true`，
    /// 逐包标 `Ect0` 并做 ACK_ECN 校验与黑洞退避；`quinn-udp` 也已经设了
    /// `IP_RECVTOS`/`IPV6_RECVTCLASS` 并用 per-packet cmsg 设置出向 `IP_TOS`/`IPV6_TCLASS`。
    ///
    /// quinn 想发 Not-ECT 时是「不加 cmsg」，此时 socket 级 `IP_TOS` 会生效——
    /// 在 socket 上强写 ECT(0) 就等于覆盖它的黑洞退避。所以这里只重设入向选项
    /// （对 macOS 双栈 socket 有益：quinn-udp 那边显式忽略了那里的 `IP_RECVTOS` 失败），
    /// 再把 socket 的当前状态读出来记日志，作为「这台机器上 ECN 到底开没开」的运维证据。
    fn apply_quic_ecn(socket: &std::net::UdpSocket, bind: SocketAddr) {
        if !crate::server::ecn::platform_supported() {
            log::warn!("h3 ECN bind={bind}: platform has no IP_RECVTOS/IPV6_RECVTCLASS, skipped");
            return;
        }
        if let Err(e) = crate::server::ecn::enable_recv_ecn(socket) {
            log::warn!("h3 ECN bind={bind}: recv options failed: {e}");
        }
        match crate::server::ecn::outgoing_ecn(socket) {
            Ok(cp) => log::info!(
                "h3 ECN bind={bind}: recv-ECN observable, socket TOS={} (outgoing marking is \
                 per-packet in quinn-udp; transport-level ECN is on by default in quinn)",
                cp.as_str()
            ),
            Err(e) => log::warn!("h3 ECN bind={bind}: socket TOS readback failed: {e}"),
        }
    }

    async fn handle_incoming(
        incoming: quinn::Incoming,
        live: Arc<LiveConfig>,
        lc: ListenerConfig,
    ) -> Result<()> {
        let connection = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                // Client abandon / reset during QUIC handshake — never escalate.
                log::debug!("h3 quic handshake soft-fail: {e:#}");
                return Ok(());
            }
        };
        let peer = connection.remote_address();

        let identity = identity_from_connection(&connection);
        if let Some(leaf) = identity.first() {
            log::debug!(
                "h3 peer_identity leaf_der_len={} chain_len={} peer={peer}",
                leaf.der.len(),
                identity.len()
            );
        }

        // `::h3` / `::h3_quinn` — avoid clashing with this module name `server::h3`.
        let h3_conn = ::h3_quinn::Connection::new(connection);
        // RFC 9298 的扩展 CONNECT 需要服务端声明 SETTINGS_ENABLE_CONNECT_PROTOCOL。
        // h3 0.0.8 的默认值是 false（`h3::config::Settings::default`），不显式打开的话
        // 守规矩的客户端根本不会发 `:protocol: connect-udp`。
        let mut h3_builder = ::h3::server::builder();
        h3_builder.enable_extended_connect(true);
        let mut server = match h3_builder.build(h3_conn).await {
            Ok(s) => s,
            Err(e) => {
                // Handshake / GOAWAY / reset during setup — log and drop connection.
                log::warn!("h3 server connection peer={peer}: {e:#}");
                return Ok(());
            }
        };

        // 每连接一份的 QMux 流预算（见 qmux.rs）：闸门是每连接的，
        // 进程级的 QMUX_BUDGET 只做汇总。
        let qmux = crate::server::qmux::QmuxBudget::per_connection();

        // Stream resets / CANCEL must not tear down the process or the accept loop
        // for the whole endpoint — only this QUIC connection's request loop.
        loop {
            match server.accept().await {
                Ok(Some(resolver)) => {
                    let live_c = Arc::clone(&live);
                    let lc_c = lc.clone();
                    let qmux_c = Arc::clone(&qmux);
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_resolver(resolver, live_c, lc_c, peer, qmux_c).await
                        {
                            // Client reset, idle timeout, or cancel — common; keep serving.
                            log::debug!("h3 request soft-fail peer={peer}: {e:#}");
                        }
                    });
                }
                Ok(None) => break, // connection closed cleanly
                Err(e) => {
                    let msg = format!("{e:#}");
                    let soft = msg.contains("reset")
                        || msg.contains("Reset")
                        || msg.contains("cancel")
                        || msg.contains("Cancel")
                        || msg.contains("closed")
                        || msg.contains("timeout")
                        || msg.contains("Timeout")
                        || msg.contains("GOAWAY")
                        || msg.contains("ApplicationClosed");
                    if soft {
                        log::info!("h3 stream/connection soft-error peer={peer}: {msg}");
                        // After a connection-level error, stop accepting on this conn.
                        break;
                    }
                    log::warn!("h3 accept error peer={peer}: {msg}");
                    break;
                }
            }
        }
        Ok(())
    }

    /// 从 QUIC 连接取对端证书链（leaf 在前）。
    ///
    /// 之前这里在 `peer_identity()` 为 None 时**回退到服务器自己的证书**，
    /// 于是「对端身份」变成「本机证书」——任何拿这个结果做鉴权的调用方都会被骗。
    /// QUIC 服务端默认 `verify_peer(false)`（见 libs/quinn-boring server/mod.rs），
    /// 客户端不带证书是常态，此时正确结果是**空链**，不是服务器证书。
    fn identity_from_connection(connection: &quinn::Connection) -> Vec<quinn_boring::X509> {
        if let Some(any) = connection.peer_identity() {
            if let Some(certs) = any.downcast_ref::<Vec<CertificateDer<'static>>>() {
                let chain =
                    quinn_boring::peer_identity_from_ders(certs.iter().map(|c| c.as_ref()));
                if !chain.is_empty() {
                    return chain;
                }
            }
            if let Some(ders) = any.downcast_ref::<Vec<Vec<u8>>>() {
                let chain = quinn_boring::peer_identity_from_ders(ders.iter().map(|c| c.as_slice()));
                if !chain.is_empty() {
                    return chain;
                }
            }
        }
        Vec::new()
    }

    async fn handle_resolver(
        resolver: ::h3::server::RequestResolver<::h3_quinn::Connection, Bytes>,
        live: Arc<LiveConfig>,
        lc: ListenerConfig,
        peer: SocketAddr,
        qmux: Arc<crate::server::qmux::QmuxBudget>,
    ) -> Result<()> {
        let (req, mut stream) = match resolver.resolve_request().await {
            Ok(pair) => pair,
            Err(e) => {
                log::debug!("h3 resolve_request reset/cancel peer={peer}: {e:#}");
                return Ok(());
            }
        };
        crate::server::telemetry::record_request();

        // RFC 9298 CONNECT-UDP 必须在**收请求体之前**分流。
        //
        // 旧代码把 CONNECT 判断放在下面的 body 循环之后，而那个循环对
        // 「发完 HEADERS 就等 200」的客户端会一直阻塞在 `recv_data()` 上：
        // CONNECT-UDP 的负载本来就要等 200 之后才发，于是隧道还没建就先卡死。
        if req.method() == http::Method::CONNECT {
            // 分流提前了，但**不能连访问控制一起绕过**：原先这里直接 return
            // proxy_connect_udp，于是 ip_access / 限流 / listener Basic Auth
            // 三项检查（都在下面的 handle_h3 里）对 CONNECT 完全失效 ——
            // 任何能连上 QUIC 口的客户端都能拿到一个匿名 UDP 中继（RFC 9298），
            // 既绕过 IP 白名单也绕过监听口密码。这里按同一顺序补上。
            let path = req.uri().path().to_string();
            let t0 = std::time::Instant::now();
            let snap = live.snapshot();
            if !crate::server::access::is_allowed(&snap.ip_access, peer) {
                connect_reject(
                    &mut stream,
                    &live,
                    peer,
                    &path,
                    StatusCode::FORBIDDEN,
                    t0,
                    "ip access denied",
                )
                .await;
                return Ok(());
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
                        connect_reject(
                            &mut stream,
                            &live,
                            peer,
                            &path,
                            StatusCode::TOO_MANY_REQUESTS,
                            t0,
                            "rate limit exceeded",
                        )
                        .await;
                        return Ok(());
                    }
                }
            }
            if let Some(ba) = &lc.basic_auth {
                match crate::server::basic_auth::check_listener_headers_at(
                    req.headers(),
                    ba,
                    peer.ip(),
                ) {
                    crate::server::basic_auth::BasicCheck::Ok => {}
                    crate::server::basic_auth::BasicCheck::Unauthorized => {
                        connect_reject(
                            &mut stream,
                            &live,
                            peer,
                            &path,
                            StatusCode::UNAUTHORIZED,
                            t0,
                            "unauthorized",
                        )
                        .await;
                        return Ok(());
                    }
                    // 退避中的来源：429（并记一条访问日志），不进口令哈希路径。
                    crate::server::basic_auth::BasicCheck::Throttled(_) => {
                        connect_reject(
                            &mut stream,
                            &live,
                            peer,
                            &path,
                            StatusCode::TOO_MANY_REQUESTS,
                            t0,
                            "too many failed authentication attempts",
                        )
                        .await;
                        return Ok(());
                    }
                }
            }
            return proxy_connect_udp(&req, stream, &live, peer).await;
        }

        // QMux 流预算：超限如实回 503，而不是把这次请求算成「已服务」。
        // 守卫是 RAII 的 —— 下面所有 `return Ok(())` 的早退分支都不会漏账。
        let permit = match crate::server::qmux::stream_opened(&qmux) {
            Ok(p) => p,
            Err(rej) => {
                log::warn!(
                    "h3 qmux budget peer={peer}: {rej} (process-wide {})",
                    crate::server::qmux::QMUX_BUDGET.stats_line()
                );
                let resp = Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(())
                    .unwrap();
                let _ = stream.send_response(resp).await;
                return Ok(());
            }
        };

        // admin 前置门（与 h1/h2 同序、同语义）：**先判鉴权/CSRF，再收 body**。
        // 否则不带凭据的并发 POST 每个都占住 REQUEST_BODY_CAP（8MiB）缓冲，
        // 不用通过鉴权就能放大内存。守卫是 RAII 的，早退不会漏 qmux 账。
        {
            let snap = live.snapshot();
            if req.uri().path().starts_with(&snap.admin.path) {
                use crate::server::basic_auth::{admin_gate, retry_after_secs, AdminGate};
                let t0 = std::time::Instant::now();
                // (状态码, Retry-After, 文案)；None = 已过鉴权门，交给 admin::handle
                // 判定顺序与 h1/h2 的「ACL → CSRF → 鉴权门」一致：ACL 是**无状态**的纯判定，
                // 提前到收 body 之前做不影响限流计数，因此这里先补判一次；限流是有状态的
                // （消耗令牌），仍留在 handle_h3 里只算一次。
                let reject: Option<(StatusCode, Option<u64>, &'static str)> =
                    if !crate::server::access::is_allowed(&snap.ip_access, peer) {
                        let (st, msg) = crate::server::access::deny_response();
                        Some((st, None, msg))
                    } else if !snap.admin.listener_allowed(lc.port) {
                        // P2-21：非允许端口上的 admin 路径回 **404** 而不是 401 —— 401 会触发
                        // 浏览器 Basic 口令框，等于诱导口令在未授权/明文口上传输。
                        // h1 的这条检查位于 admin 分支之前，这里提前补上，保证三协议同语义。
                        Some((StatusCode::NOT_FOUND, None, "not found"))
                    } else if crate::server::access::cross_site_blocked(req.headers()) {
                        let (st, msg) = crate::server::access::cross_site_response();
                        Some((st, None, msg))
                    } else {
                        match admin_gate(req.headers(), &snap.admin, peer.ip()) {
                            AdminGate::Proceed => None,
                            AdminGate::Unauthorized => {
                                Some((StatusCode::UNAUTHORIZED, None, "unauthorized"))
                            }
                            AdminGate::Throttled(d) => Some((
                                StatusCode::TOO_MANY_REQUESTS,
                                Some(retry_after_secs(d)),
                                "too many failed authentication attempts",
                            )),
                        }
                    };
                if let Some((status, retry, msg)) = reject {
                    // 安全拒绝也要落访问日志（与 h1/h2 一致；下面正常路径的日志在 async
                    // 块里，提前 return 会绕过它，而这条路径正是爆破/扫描最可能命中的）。
                    crate::server::access_log::log_response(
                        &live,
                        peer,
                        "h3",
                        req.method().as_str(),
                        req.uri().path(),
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
                    if let Ok(resp) = b.body(()) {
                        if stream.send_response(resp).await.is_ok() {
                            let _ = stream.send_data(Bytes::from_static(msg.as_bytes())).await;
                        }
                    }
                    let _ = stream.finish().await;
                    return Ok(());
                }
            }
        }

        let result = async {
            // P1-9：收齐 H3 请求体（上限 8MiB）——POST/PUT 才能把 body 交给引擎/admin；
            // 且不排空请求体会卡住 QUIC 流量控制。超限直接 413。
            let mut body: Vec<u8> = Vec::new();
            let mut overflow = false;
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut buf)) => {
                        if body.len() + buf.remaining() > REQUEST_BODY_CAP {
                            overflow = true;
                            break;
                        }
                        let chunk = buf.copy_to_bytes(buf.remaining());
                        body.extend_from_slice(&chunk);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        log::debug!("h3 recv_data peer={peer}: {e}");
                        return Ok(());
                    }
                }
            }
            if overflow {
                let resp = Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(())
                    .unwrap();
                let _ = stream.send_response(resp).await;
                return Ok(());
            }

            let method = req.method().as_str().to_string();
            let path = req.uri().path().to_string();

            let t0 = std::time::Instant::now();
            let req = req.map(|()| Bytes::from(body));
            // HSTS 判定要在 handle_h3 之前取：lc 会被 move 进去。
            let is_https = lc.ssl.is_some();
            let mut response = handle_h3(req, live.clone(), lc, peer).await;
            // HTTPS(H3) 响应统一补 HSTS——与 h1/h2 同一语义，见 h2.rs 处的说明。
            if is_https {
                response
                    .headers_mut()
                    .entry(http::header::STRICT_TRANSPORT_SECURITY)
                    .or_insert_with(|| {
                        http::HeaderValue::from_static(crate::server::h1::hsts_header())
                    });
            }
            let (parts, body_out) = response.into_parts();
            let engine = parts
                .extensions
                .get::<crate::server::access_log::EngineTag>()
                .map(|t| t.0)
                .unwrap_or("http");
            // P1-11：完成侧全字段访问日志；h3 侧拿得到精确响应字节数。
            crate::server::access_log::log_response(
                &live,
                peer,
                "h3",
                &method,
                &path,
                parts.status.as_u16(),
                Some(body_out.len() as u64),
                t0.elapsed(),
                engine,
            );
            let resp = Response::from_parts(parts, ());
            if let Err(e) = stream.send_response(resp).await {
                log::debug!("h3 send_response peer={peer}: {e:#}");
                return Ok(());
            }
            if !body_out.is_empty() {
                if let Err(e) = stream.send_data(body_out).await {
                    log::debug!("h3 send_data peer={peer}: {e:#}");
                    return Ok(());
                }
            }
            if let Err(e) = stream.finish().await {
                log::debug!("h3 finish peer={peer}: {e:#}");
                return Ok(());
            }
            Ok(())
        }
        .await;
        crate::server::qmux::stream_closed(permit);
        result
    }

    /// admin::handle 返回 `Response<BoxBody>`（h1 体类型）；h3 分支收齐为 `Response<Bytes>`。
    async fn collect_to_bytes(resp: Response<BoxBody>) -> Response<Bytes> {
        let (parts, body) = resp.into_parts();
        let data = BodyExt::collect(body)
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        Response::from_parts(parts, data)
    }

    async fn handle_h3(
        req: Request<Bytes>,
        live: Arc<LiveConfig>,
        lc: ListenerConfig,
        peer: SocketAddr,
    ) -> Response<Bytes> {
        let mut req = req;
        let path = req.uri().path().to_string();

        let snap = live.snapshot();
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

        // /__metrics 排在 ip_access + 限流**之后**（此前是 handle_h3 的第一个分支，
        // 用 IP 白名单当边界的部署等于把指标公开）。与 h1/h2 同位置：basic_auth 之前
        // （listener 口令与「谁能抓指标」是两件事），指标的门在 telemetry 内部按
        // [admin].metrics_public 判定（默认要求管理员凭据）。
        if let Some(resp) = crate::server::telemetry::maybe_handle_simple(
            &req,
            &snap.telemetry,
            &snap.admin,
            peer.ip(),
        ) {
            return tag(resp, "telemetry");
        }

        // DoH：与 h1/h2 同一位置（ACL/限速之后、basic_auth 之前）与同一实现。
        // h1 用 `h1_try_handle`、h2 用 `doh_prepared`，h3 此前**两处都没有**——
        // 于是 HTTP/3 客户端请求 DoH 路径只会拿到 static 404（而 dot_doh::doh_prepared
        // 的文档注释本身就写着「h2/h3 路径的入口」）。这里补上，语义与 h2 完全一致。
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

        // P0-1：listener 级 Basic Auth（§16.1）——与 h1/h2 对齐，堵住 h3 绕过。
        if let Some(ba) = &lc.basic_auth {
            match crate::server::basic_auth::check_listener_headers_at(
                req.headers(),
                ba,
                peer.ip(),
            ) {
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
                // 失败退避（与 h1/h2 同一张表、同一响应语义）。
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

    // P2-8（§16.18）：status_path 接线（与 h1/h2 一致）。
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

    // P1-4：admin 走与 h1/h2 一致的完整 handle（旧实现只回 UI shell）。
        // 注：旧实现把 admin 放在 ip_access 之前，这里一并修正为规格顺序。
        if path.starts_with(&snap.admin.path) {
            let resp = crate::server::admin::handle(req.map(Full::new), live).await;
            // 兜底记账（与 h1/h2 同语义）：鉴权与失败退避已在 admin_gate 里完成，
            // 这里只在「过了门却仍回 401」（两次校验之间配置被热重载）时补记一次。
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
        // 改写后以新路径做后续判定与分发（与 h1/h2 的修正一致）。
        let path = req.uri().path().to_string();
        // P1-5：h1 的 pass_upstream（page rule pass 动作）在 h3 同样生效。
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
        let mut resp = h3_tail(req, live, lc, peer, &path).await;
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

    async fn h3_tail(
        req: Request<Bytes>,
        live: Arc<LiveConfig>,
        lc: ListenerConfig,
        peer: SocketAddr,
        path: &str,
    ) -> Response<Bytes> {
        // 分发顺序必须与 h1 一致（规格 §4：apps 优先于 proxy）。
        // 此前这里是 proxy 在前、apps 在后，注释还写着「与 h1 dispatch_tail 对齐」——
        // 恰好相反：同一条 URL 在 h1 交给应用引擎、在 h3 被反代走，行为随协议而变。
        // Apps via try_handle_simple only when path/ext matches a listener app route.
        if apps::would_handle(&lc, path) {
            if let Some(resp) = apps::try_handle_simple(&req, &live, &lc, peer).await {
                return tag(resp, "app");
            }
        }
        if would_proxy(&lc, path) {
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
        // Static files; metrics already handled above via telemetry::maybe_handle_simple.
        // §44 上传：与 h1 同一套语义（见 upload_api / WORKLOG §18）。
        if matches!(*req.method(), http::Method::PUT | http::Method::PATCH | http::Method::POST)
            && crate::server::upload_api::enabled_for(&lc, req.uri().path())
        {
            return tag(
                crate::server::upload_api::handle_bytes(req, &lc, peer).await,
                "upload",
            );
        }
        match static_files::serve_simple(&req, &lc).await {
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

    /// RFC 9298 CONNECT-UDP：真正的 QUIC 请求流 ↔ UDP 双向转发。
    ///
    /// 为什么这次能真做：服务端从 `resolve_request()` 拿到的是
    /// `RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>`，而 `h3_quinn::BidiStream`
    /// **实现了** `h3::quic::BidiStream`，所以 `RequestStream::split()` 可用 ——
    /// 拿到彼此独立、可并发驱动的收发两半。
    ///
    /// 旧注释说「h3-quinn 的 OpenStreams/BidiStream 有 trait 限制」是认错了对象：
    /// 没有 `split()` 的是 `OpenStreams`（只负责开流，服务端这条路径根本不用它），
    /// 而服务端拿到的 `BidiStream` 一直有。所以转发不是"被 API 挡住"，是之前没接。
    ///
    /// 失败一律回真实状态码，不回 200：目标解析失败 400、地址不允许 403、
    /// UDP 建不起来 502、非 CONNECT-UDP 或 capsule 形态 501。
    async fn proxy_connect_udp(
        req: &Request<()>,
        mut stream: ::h3::server::RequestStream<::h3_quinn::BidiStream<Bytes>, Bytes>,
        live: &Arc<LiveConfig>,
        peer: SocketAddr,
    ) -> Result<()> {
        let t0 = std::time::Instant::now();
        let path = req.uri().path().to_string();

        // 1. 是不是 CONNECT-UDP。
        //
        // h3 0.0.8 把 `:protocol` 放在请求 extensions 的 `h3::ext::Protocol` 里，
        // 不是请求头（见 h3 的 `proto/headers.rs::Pseudo::request` →
        // `server/request.rs` 的 `extensions_mut().insert(protocol)`）。
        // 旧代码读 `headers().get(":protocol")` 永远取不到值，这个判断从来没生效过。
        let proto_ext = req
            .extensions()
            .get::<::h3::ext::Protocol>()
            .map(|p| p.as_str().to_string());
        let proto_hdr = req
            .headers()
            .get("connect-udp")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let wants_udp = connect_udp::is_connect_udp(proto_ext.as_deref())
            || connect_udp::is_connect_udp(proto_hdr.as_deref());

        if !wants_udp {
            // 普通 CONNECT（TCP 隧道）不在本次范围，如实回 501。
            connect_reject(
                &mut stream,
                live,
                peer,
                &path,
                StatusCode::NOT_IMPLEMENTED,
                t0,
                "only CONNECT-UDP (:protocol: connect-udp) is implemented",
            )
            .await;
            return Ok(());
        }

        // 2. capsule 形态没实现。RFC 9297 §3 下 `Capsule-Protocol: ?1` 的流上是 capsule，
        //    不是裸长度前缀报文；按错格式解析会解出垃圾，所以直接拒绝。
        let capsule = req
            .headers()
            .get("capsule-protocol")
            .and_then(|v| v.to_str().ok());
        if connect_udp::wants_capsule_protocol(capsule) {
            connect_reject(
                &mut stream,
                live,
                peer,
                &path,
                StatusCode::NOT_IMPLEMENTED,
                t0,
                "capsule-protocol: ?1 未实现, 只支持长度前缀报文形态",
            )
            .await;
            return Ok(());
        }

        // 3. 目标解析 + 准入。
        let (host, port) = match connect_udp::parse_target_path(&path) {
            Ok(v) => v,
            Err(e) => {
                connect_reject(
                    &mut stream,
                    live,
                    peer,
                    &path,
                    StatusCode::BAD_REQUEST,
                    t0,
                    &e,
                )
                .await;
                return Ok(());
            }
        };
        let target = match connect_udp::resolve_target(&host, port) {
            Ok(t) => t,
            Err(e) => {
                // 请求语法是对的，是代理策略不允许转发到那儿 → 403 而不是 400。
                connect_reject(
                    &mut stream,
                    live,
                    peer,
                    &path,
                    StatusCode::FORBIDDEN,
                    t0,
                    &e,
                )
                .await;
                return Ok(());
            }
        };

        // 4. 建 UDP socket 并 connect 到目标。
        //    `connect()` 之后内核只收该对端的报文，省掉自己过滤源地址，
        //    也避免把任意来源的 UDP 灌进隧道。本地地址/端口由内核分配。
        let bind_any = if target.is_ipv4() {
            SocketAddr::from(([0u8, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let udp = match tokio::net::UdpSocket::bind(bind_any).await {
            Ok(s) => s,
            Err(e) => {
                connect_reject(
                    &mut stream,
                    live,
                    peer,
                    &path,
                    StatusCode::BAD_GATEWAY,
                    t0,
                    &format!("udp bind {bind_any} failed: {e}"),
                )
                .await;
                return Ok(());
            }
        };
        if let Err(e) = udp.connect(target).await {
            connect_reject(
                &mut stream,
                live,
                peer,
                &path,
                StatusCode::BAD_GATEWAY,
                t0,
                &format!("udp connect {target} failed: {e}"),
            )
            .await;
            return Ok(());
        }

        // 5. 隧道成立，才回 200。客户端从这一刻起在请求流上发长度前缀的 UDP 负载。
        let resp = match Response::builder().status(StatusCode::OK).body(()) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("h3 CONNECT-UDP build 200 peer={peer}: {e}");
                return Ok(());
            }
        };
        if let Err(e) = stream.send_response(resp).await {
            log::debug!("h3 CONNECT-UDP send 200 peer={peer}: {e:#}");
            return Ok(());
        }
        crate::server::access_log::log_response(
            live,
            peer,
            "h3",
            "CONNECT",
            &path,
            200,
            None,
            t0.elapsed(),
            "connect-udp",
        );
        log::info!("h3 CONNECT-UDP established peer={peer} target={target} path={path}");

        // 6. 拆成收发两半，跑双向转发；结束时正常收尾（FIN）而不是让 quinn reset。
        let (mut send_half, mut recv_half) = stream.split();
        let idle = std::time::Duration::from_secs(connect_udp::DEFAULT_IDLE_TIMEOUT_SECS);
        run_udp_tunnel(&mut send_half, &mut recv_half, udp, idle, peer, target).await;
        if let Err(e) = send_half.finish().await {
            log::debug!("h3 CONNECT-UDP finish peer={peer}: {e:#}");
        }
        log::info!("h3 CONNECT-UDP closed peer={peer} target={target}");
        Ok(())
    }

    /// RFC 9298 §4.3 的双向转发循环。
    ///
    /// 上行：请求流 DATA 帧里的字节按 varint 长度前缀重组，逐个 `send()` 给目标；
    /// 下行：`recv()` 到的报文加长度前缀，写回响应流。
    /// 结束条件：请求流结束（FIN/trailers）、UDP 出错、空闲超时、分帧非法。
    ///
    /// 结构上刻意让每个 `select!` 分支的处理器都**不碰**其它分支 future 借用的变量：
    /// 下行收包封在 [`recv_framed`] 里（它自己借 `buf`，只交出已分帧的 `Bytes`），
    /// 处理器因此不需要再读 `buf`，借用关系一眼可读，也不必依赖 `select!` 内部
    /// future 的存放与析构时机。
    async fn run_udp_tunnel(
        send: &mut ::h3::server::RequestStream<::h3_quinn::SendStream<Bytes>, Bytes>,
        recv: &mut ::h3::server::RequestStream<::h3_quinn::RecvStream, Bytes>,
        udp: tokio::net::UdpSocket,
        idle_timeout: std::time::Duration,
        peer: SocketAddr,
        target: SocketAddr,
    ) {
        let mut asm = connect_udp::DatagramAssembler::default();
        let mut udp_buf = vec![0u8; connect_udp::MAX_DATAGRAM];
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);

        loop {
            tokio::select! {
                // 上行：客户端 → 目标。
                chunk = recv.recv_data() => {
                    let mut buf = match chunk {
                        Ok(Some(b)) => b,
                        Ok(None) => {
                            // 请求流 FIN 或 trailers：上行结束，隧道收摊。
                            // 若还留着凑不齐的字节，说明客户端把报文截断了，记下来。
                            let leftover = asm.pending();
                            if leftover != 0 {
                                log::warn!(
                                    "h3 CONNECT-UDP peer={peer} target={target}: \
                                     stream ended with {leftover} trailing byte(s)"
                                );
                            }
                            log::debug!("h3 CONNECT-UDP peer={peer} target={target}: request stream ended");
                            return;
                        }
                        Err(e) => {
                            log::debug!("h3 CONNECT-UDP peer={peer} recv_data: {e:#}");
                            return;
                        }
                    };
                    let n = buf.remaining();
                    if n == 0 {
                        continue;
                    }
                    let bytes = buf.copy_to_bytes(n);
                    asm.push(&bytes);
                    // 一个 DATA 帧可能装多个报文、也可能只有半个前缀：
                    // 把目前完整的全部送走，剩下留在 asm 里等下一帧。
                    loop {
                        match asm.next_datagram() {
                            Ok(Some(dg)) => {
                                if let Err(e) = udp.send(&dg).await {
                                    log::debug!("h3 CONNECT-UDP peer={peer} udp send: {e}");
                                    return;
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                // 分帧非法：给一个明确的 stream error，
                                // 而不是继续按错的偏移解析下一段。
                                log::warn!("h3 CONNECT-UDP peer={peer} bad framing: {e}");
                                send.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
                                return;
                            }
                        }
                    }
                }
                // 下行：目标 → 客户端。
                framed = recv_framed(&udp, &mut udp_buf) => {
                    match framed {
                        Ok(f) => {
                            if let Err(e) = send.send_data(f).await {
                                log::debug!("h3 CONNECT-UDP peer={peer} send_data: {e:#}");
                                return;
                            }
                        }
                        Err(e) => {
                            log::debug!("h3 CONNECT-UDP peer={peer} udp recv: {e}");
                            return;
                        }
                    }
                }
                _ = &mut idle => {
                    log::debug!("h3 CONNECT-UDP peer={peer} target={target}: idle timeout");
                    return;
                }
            }
            // 有流量就把空闲时钟往后推。
            idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
        }
    }

    /// 收一个 UDP 报文并加上 RFC 9298 的长度前缀，返回可写回流的 `Bytes`。
    ///
    /// 独立成函数是为了把 `&mut buf` 的借用关在 future 内部：
    /// `select!` 的处理器拿到的只有返回值，不再需要读 `buf`。
    async fn recv_framed(
        udp: &tokio::net::UdpSocket,
        buf: &mut [u8],
    ) -> Result<Bytes, String> {
        let n = udp.recv(buf).await.map_err(|e| e.to_string())?;
        let framed = connect_udp::frame_datagram(&buf[..n])?;
        Ok(Bytes::from(framed))
    }

    /// CONNECT 类请求的失败出口：回状态码 + 记一条访问日志。
    ///
    /// 访问日志是刻意的：否则隧道（成功的和失败的）在 access log 里完全不可见，
    /// 只能靠 warn 级日志猜。
    async fn connect_reject(
        stream: &mut ::h3::server::RequestStream<::h3_quinn::BidiStream<Bytes>, Bytes>,
        live: &Arc<LiveConfig>,
        peer: SocketAddr,
        path: &str,
        status: StatusCode,
        t0: std::time::Instant,
        reason: &str,
    ) {
        log::warn!(
            "h3 CONNECT-UDP peer={peer} path={path} -> {}: {reason}",
            status.as_u16()
        );
        let resp = match Response::builder().status(status).body(()) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("h3 CONNECT-UDP build {status}: {e}");
                return;
            }
        };
        if let Err(e) = stream.send_response(resp).await {
            log::debug!("h3 CONNECT-UDP reply {status} peer={peer}: {e:#}");
        }
        crate::server::access_log::log_response(
            live,
            peer,
            "h3",
            "CONNECT",
            path,
            status.as_u16(),
            None,
            t0.elapsed(),
            "connect-udp",
        );
    }

    fn would_proxy(lc: &ListenerConfig, path: &str) -> bool {
        lc.proxy_rules.iter().any(|r| path.starts_with(&r.path))
    }

    fn tag(mut resp: Response<Bytes>, engine: &'static str) -> Response<Bytes> {
        resp.extensions_mut()
            .insert(crate::server::access_log::EngineTag(engine));
        resp
    }
}

#[cfg(feature = "tls")]
pub use imp::serve;

#[cfg(not(feature = "tls"))]
pub async fn serve(_bind: SocketAddr, _lc: ListenerConfig, _live: Arc<LiveConfig>) -> Result<()> {
    anyhow::bail!("HTTP/3 (QUIC) requires feature `tls`")
}
