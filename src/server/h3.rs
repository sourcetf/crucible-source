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

/// per-port「h3 端点当前生效的配置指纹」通道。
///
/// * 写入：`mod.rs` 的 reconciler（每 2s 算一遍）与 h3 任务自己；
/// * 读取：运行中的 [`serve`] —— 它 `select!` 这条通道，值变了就退出，
///   由调用方用**最新**的 listener 配置重新拉起端点（新证书随之生效）。
static H3_CFG_FP: once_cell::sync::Lazy<
    parking_lot::Mutex<std::collections::HashMap<u16, tokio::sync::watch::Sender<u64>>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

/// h3 端点关心的配置指纹：整份 listener 配置（Debug 形式，含 ssl.*、early_data、
/// root/autoindex/限流/口令等所有 per-listener 字段）+ 证书/私钥文件的 mtime/size。
///
/// 为什么要文件指纹：ACME/certbot 续期是**原地替换同一路径**，配置字符串完全不变；
/// 只看配置就发现不了（与 `${crate}::server::tls::boring_path` 的 acceptor 指纹同一个坑）。
pub fn h3_config_fingerprint(lc: &ListenerConfig) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    lc.port.hash(&mut h);
    format!("{lc:?}").hash(&mut h);
    if let Some(ssl) = lc.ssl.as_ref() {
        for p in [&ssl.cert, &ssl.key] {
            if let Some(v) = p.as_deref() {
                if v.contains("-----BEGIN") {
                    continue; // 内联 PEM：内容已随 Debug 进指纹
                }
                match std::fs::metadata(v) {
                    Ok(m) => {
                        m.len().hash(&mut h);
                        if let Ok(t) = m.modified() {
                            if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                                d.as_nanos().hash(&mut h);
                            }
                        }
                    }
                    Err(_) => 0u8.hash(&mut h),
                }
            }
        }
    }
    h.finish()
}

/// 把指纹喂给（可能在跑的）端点：值变了就唤醒它退出重启。
pub fn set_h3_config_fingerprint(port: u16, fp: u64) {
    let mut m = H3_CFG_FP.lock();
    match m.get(&port) {
        Some(tx) => {
            if *tx.borrow() != fp {
                let _ = tx.send(fp);
            }
        }
        None => {
            let (tx, _rx) = tokio::sync::watch::channel(fp);
            m.insert(port, tx);
        }
    }
}

/// 取本端点的指纹接收器（`serve` 用它监听配置变化）。
pub fn h3_config_watch(port: u16, fp: u64) -> tokio::sync::watch::Receiver<u64> {
    let mut m = H3_CFG_FP.lock();
    let tx = m.entry(port).or_insert_with(|| {
        let (tx, _rx) = tokio::sync::watch::channel(fp);
        tx
    });
    if *tx.borrow() != fp {
        let _ = tx.send(fp);
    }
    tx.subscribe()
}

/// 全局「同时在飞」h3 请求上限（含**正在收 body** 的阶段）。
///
/// 为什么必须有这一层：h2 有等价闸门（`h2::H2_MAX_INFLIGHT`），h3 此前只有
/// **每连接** 100 条流（`qmux::DEFAULT_MAX_ACTIVE`）×每请求 8 MiB 的 body 上限，
/// 而 QUIC 连接数**不限**（quinn 默认）⇒ 进程内存上界 = 连接数 × 100 × 8 MiB，
/// 完全由攻击者决定；更要命的是收 body 发生在 ip_access / 限流 / basic_auth
/// **之前**，未认证即可发起。一条连接的 100 条慢流 ≈ 800 MiB。
///
/// 取 256 与 h2 同值：两者共用同一台机器的内存预算，语义也一致
///（h1 有 32 MiB/请求的流式上限与连接级并发的天然约束，故不设此闸门）。
pub const H3_MAX_INFLIGHT: usize = 256;

/// 等配额的最长时间（与 h2 同语义）：拿不到就快速 503，
/// 而不是把这条连接的请求循环堵死（否则一条恶意连接能拖住整条连接上所有流）。
pub const H3_INFLIGHT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// 进程级共享的在飞闸门（`Arc<Semaphore>` 便于 `acquire_owned` 给出 RAII 守卫）。
static H3_INFLIGHT: once_cell::sync::Lazy<Arc<tokio::sync::Semaphore>> =
    once_cell::sync::Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(H3_MAX_INFLIGHT)));

/// 全局在飞闸门的引用（测试用；也为将来把配额做成可配置留出入口）。
pub fn h3_inflight_gate() -> Arc<tokio::sync::Semaphore> {
    H3_INFLIGHT.clone()
}

/// 全局「同时存活的 CONNECT-UDP 隧道」上限。
///
/// 与 [`H3_MAX_INFLIGHT`] **分开**的原因：隧道不缓冲请求体（单条隧道缓冲上界是
/// `connect_udp::MAX_HTTP_DATAGRAM` ≈ 64 KiB，不占 8 MiB 的 body 配额），但会存活到
/// idle 超时（默认 120s）。此前隧道**整个生命周期**都占用 `H3_MAX_INFLIGHT` 的一个
/// 名额（`handle_resolver` 在 CONNECT 分流**之前**就取了该名额），于是只要 listener
/// 开了 `connect_udp`，一个客户端开满 256 条长隧道就能把**进程级**在飞闸门耗光 ⇒
/// 同一进程上**所有正常 h3 请求**（含别的 listener）回 503。
/// 独立闸门既保留「隧道有进程级上界」，又不再让隧道饿死普通请求。
pub const H3_MAX_TUNNELS: usize = 256;

static H3_TUNNEL_GATE: once_cell::sync::Lazy<Arc<tokio::sync::Semaphore>> =
    once_cell::sync::Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(H3_MAX_TUNNELS)));

/// 隧道闸门的引用（测试用）。
pub fn h3_tunnel_gate() -> Arc<tokio::sync::Semaphore> {
    H3_TUNNEL_GATE.clone()
}

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
        cfg_fp: u64,
        cfg_rx: tokio::sync::watch::Receiver<u64>,
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

        // **优雅停机广播**：配置/材料变化或 listener 被移除时，先让每条活跃 h3 连接
        // 发一个 H3 GOAWAY（RFC 9114 §5.2），宽限 [`H3_SHUTDOWN_GRACE`] 让在飞请求收尾，
        // **之后**才 `ep.close()` 关掉整个 QUIC 端点、由上层用新配置重启。
        //
        // 为什么要这样（而不是像旧版直接 `ep.close()`）：`Endpoint::close()` 会对所有连接
        // 立即发 QUIC CONNECTION_CLOSE，热重载会**打断在飞的 h3 请求**（h2 走 graceful_shutdown，
        // h1 无此问题 ⇒ 三协议不一致）。GOAWAY 让客户端知道「最后一条被接受的请求 id」，
        // 从而优雅迁移/重试。
        //
        // 为什么用 broadcast + 连接级 select!（而不是「每端点连接注册表 + async Mutex」）：
        // `h3::server::Connection::shutdown()` 需要 `&mut self`，而 `accept()` 会长期持有该
        // `&mut`（见其 `poll_accept_request_stream_internal`）。把 Connection 存进注册表再用
        // 锁共享会与 accept 争锁、易死锁。改为：每个 `handle_incoming` 自己拥有 Connection，
        // 在自己的 accept 循环里 `select!` 一条广播接收器 —— 命中就发 GOAWAY 并继续服务
        // 在飞请求（新请求由 crate 自动回 H3_REQUEST_REJECTED）。**只在连接级 accept 循环
        // 增加一个 select 分支，不引入任何每请求锁**，连接热路径（handle_resolver）零改动。
        //
        // `accept()` 的取消安全性：其内部 `poll_accept_request_stream_internal` 是纯
        // `poll_fn`，状态全在 Connection 自身（`&mut self`），被 select! 丢弃的 future 不持有
        // 任何外部资源；`poll_accept_bidi` 走 `Stream::poll_next_unpin`（Pending 无副作用）
        // ⇒ 中途取消不丢请求流、不卡连接。
        // **用 `watch<bool>` 而不是 `broadcast<()>`**：停机通知必须让**宽限窗口内新建的
        // 连接**也看得到。broadcast 的接收者只能收到「订阅之后」的广播 —— 宽限期（5s）里
        // 新到的 QUIC 连接订阅得太晚，收不到 GOAWAY，只会在 `ep.close()` 时被
        // CONNECTION_CLOSE 掐断（真机复现：宽限期内建连 → `goaways=[]`、
        // `terminated=CONNECTION_CLOSE("config changed")`）。`watch` 的接收者一订阅就能
        // 读到当前值（`true` = 正在停机），于是 `handle_incoming` 入场自检即可**立即补发
        // GOAWAY**（RFC 9114 §5.2 的优雅停机语义）。
        // 注意：初始 Receiver 必须**立即丢弃**（`_` 模式），否则 `receiver_count()`
        // 永远 ≥ 1、`h3_graceful_endpoint_close` 的「无连接则不宽限」判定会失效。
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        {
            let mut rx = cfg_rx.clone();
            let ep = endpoint.clone();
            let tx_w = shutdown_tx.clone();
            // 周期性自检也要做：**不能只依赖 watch**。reconciler 只为「仍然允许 h3」的
            // listener 更新指纹（见 `mod.rs` 里那段循环），所以当 h3 被从 `http_versions`
            // 里删掉、或整个 listener 被删掉时，watch **永远不会触发** ⇒ 端点一直服务下去
            // （实测：改完配置 8 秒后 `netstat` 仍显示 UDP 在听）。每 2s 重新核对一次
            // 「这个 listener 还在、且仍然允许 h3」，不满足就关端点（上层监督任务随即退出）。
            let live_w = Arc::clone(&live);
            let key_w = crate::server::bind_key(&lc);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        r = rx.changed() => {
                            if r.is_err() {
                                return; // 发送端没了：上层监督任务已退出，端点交给它收尾
                            }
                            if *rx.borrow() != cfg_fp {
                                log::info!(
                                    "h3 endpoint config/materials changed; GOAWAY to active h3 connections, then closing QUIC endpoint to restart with new config"
                                );
                                h3_graceful_endpoint_close(&tx_w, &ep, b"config changed").await;
                                return;
                            }
                        }
                        _ = tick.tick() => {
                            let keep = live_w
                                .snapshot()
                                .listeners
                                .iter()
                                .any(|l| crate::server::bind_key(l) == key_w && l.allows_h3());
                            if !keep {
                                log::info!(
                                    "h3 endpoint 不再需要（listener 已移除或 http_versions 不再含 h3）；GOAWAY 后关闭 QUIC 端点"
                                );
                                h3_graceful_endpoint_close(&tx_w, &ep, b"h3 disabled").await;
                                return;
                            }
                        }
                    }
                }
            });
        }

        while let Some(incoming) = endpoint.accept().await {
            let live_c = Arc::clone(&live);
            let lc_c = lc.clone();
            // 每条连接一份广播接收器：配置/证书变更时 `serve` 的 watcher 会广播，
            // 连接自己的 accept 循环据此发 GOAWAY（见 `handle_incoming`）。
            let shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn(async move {
                if let Err(e) = handle_incoming(incoming, live_c, lc_c, shutdown_rx).await {
                    // 按**类别+时间**节流：这条是每条出错的 QUIC 连接一条，而 `{e:#}`
                    // 是完整错误链（可能很长）。与 tls/accept.rs 的握手失败同一处理
                    // （那里也是匿名对端可驱动）。
                    crate::server::log_throttle::warn_every(
                        "h3-conn",
                        std::time::Duration::from_secs(60),
                        &format!("h3 connection: {e:#}"),
                    );
                }
            });
        }
        Ok(())
    }

    /// 配置/证书变更或 listener 被移除时的**优雅**端点关闭：
    /// 1. 广播 shutdown（每条活跃连接的 accept 循环据此发 H3 GOAWAY）；
    /// 2. 有活跃连接时宽限 [`H3_SHUTDOWN_GRACE`]，让在飞请求把响应写完；
    /// 3. 最后 `ep.close()` 兜底（仍在宽限期内没结束的连接会被 CONNECTION_CLOSE 收掉）。
    ///
    /// 没有活跃连接时**不宽限**（配置/证书热重载在空闲时不额外等待）。
    async fn h3_graceful_endpoint_close(
        tx: &tokio::sync::watch::Sender<bool>,
        ep: &quinn::Endpoint,
        reason: &[u8],
    ) {
        // 订阅者数 = 活跃 h3 连接数（每条 `handle_incoming` 持有一个 Receiver）。
        // 先取数、再翻牌：翻牌之后新建的连接走「入场自检 → 立即 GOAWAY」，无需再宽限
        //（它们最多被宽限结束时的 `ep.close()` 兜底收掉，且 GOAWAY 已经发出）。
        let receivers = tx.receiver_count();
        tx.send_replace(true);
        if receivers > 0 {
            log::info!(
                "h3 graceful close: broadcast GOAWAY to {receivers} active connection(s), grace {}s",
                H3_SHUTDOWN_GRACE.as_secs()
            );
            tokio::time::sleep(H3_SHUTDOWN_GRACE).await;
        }
        ep.close(quinn::VarInt::from_u32(0), reason);
    }

    /// QUIC 传输层显式限额（**不依赖 quinn 的库默认值**）。
    ///
    /// 为什么必须显式写：quinn 0.11 的 `TransportConfig::default()` 里
    /// **`receive_window = VarInt::MAX`** —— 连接级接收窗口无上限。于是单连接的内存上界
    /// 变成 `max_streams × stream_receive_window`（默认 100 × 1.25MB ≈ 125MB）；
    /// 攻击者开 N 条连接、每条开满流并持续发数据（我们故意不读），内存就按连接数线性放大。
    /// 这里把连接级窗口压到 [`QUIC_CONN_WINDOW`]，其余值也写死以便审计。
    pub const QUIC_MAX_BIDI_STREAMS: u32 = 256;
    pub const QUIC_MAX_UNI_STREAMS: u32 = 256;
    /// 空闲超时秒数。RFC 9308 §3.2 要求不低于 30s；60s 兼顾移动端抖动与资源回收。
    pub const QUIC_MAX_IDLE_SECS: u64 = 60;
    /// 头部区（HPACK/QPACK 解码之后）字节上限：与 h2 的 `H2_MAX_HEADER_LIST_SIZE` 对齐。
    /// 必须显式设 —— h3 默认无上限，且校验发生在「收齐整个帧之后」。
    pub const H3_MAX_FIELD_SECTION: usize = 64 * 1024;
    /// 请求体读取的**空闲**超时（两次 `recv_data` 之间）；语义与 h2 的
    /// `H2_BODY_IDLE_TIMEOUT` 一致：只卡「读不到新字节」，不限制整个请求的总时长。
    pub const H3_BODY_IDLE_TIMEOUT_SECS: u64 = 60;
    /// 单流接收窗口（1MiB）：与 h2 的 `H2_INITIAL_WINDOW_SIZE` 对齐。
    pub const QUIC_STREAM_WINDOW: u32 = 1024 * 1024;
    /// 连接级接收窗口（8MiB）：**这一条是单连接的接收缓冲上界**，也是与 quinn 默认值
    /// 差别最大的一条（默认无上限）。
    pub const QUIC_CONN_WINDOW: u32 = 8 * 1024 * 1024;
    pub const QUIC_SEND_WINDOW: u64 = 8 * 1024 * 1024;
    /// WebTransport/QMux 方向的 datagram 接收缓冲（显式给值，否则由 quinn 默认决定）。
    pub const QUIC_DATAGRAM_RECV: usize = 1024 * 1024;

    /// 配置/证书变更（或 listener 被移除）时，先对每条活跃 h3 连接发 GOAWAY，再等这么久
    /// 让在飞请求收尾，最后才 `ep.close()`。取 5s：足够本地/同城 RTT 下把已接受的请求
    /// 响应写完，又不会让热重载明显变慢。空闲（无连接）时**不等待**（见
    /// [`h3_graceful_endpoint_close`]）。
    pub const H3_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

    /// 见上方常量的说明。
    /// **不设 keep-alive**：空闲连接按 [`QUIC_MAX_IDLE_SECS`] 回收（要长连的客户端
    /// 自己发 PING/请求），避免连接被永久钉住。
    fn quic_transport_config() -> Result<quinn::TransportConfig> {
        let mut t = quinn::TransportConfig::default();
        t.max_concurrent_bidi_streams(quinn::VarInt::from_u32(QUIC_MAX_BIDI_STREAMS));
        t.max_concurrent_uni_streams(quinn::VarInt::from_u32(QUIC_MAX_UNI_STREAMS));
        t.max_idle_timeout(Some(
            std::time::Duration::from_secs(QUIC_MAX_IDLE_SECS)
                .try_into()
                .map_err(|_| anyhow::anyhow!("h3: idle timeout 超出 quinn 允许范围"))?,
        ));
        t.stream_receive_window(quinn::VarInt::from_u32(QUIC_STREAM_WINDOW));
        t.receive_window(quinn::VarInt::from_u32(QUIC_CONN_WINDOW));
        t.send_window(QUIC_SEND_WINDOW);
        t.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECV));
        Ok(t)
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
        let mut cfg = quinn_boring::helpers::server_config(crypto)
            .map_err(|e| anyhow::anyhow!("h3 boring server_config: {e}"))?;
        // 显式 QUIC 限额（quinn 默认值是库的约定，不是我们的边界）。
        cfg.transport_config(std::sync::Arc::new(quic_transport_config()?));
        log::info!(
            "h3 quic limits: bidi={QUIC_MAX_BIDI_STREAMS} uni={QUIC_MAX_UNI_STREAMS} \
             idle={QUIC_MAX_IDLE_SECS}s stream_window={QUIC_STREAM_WINDOW} \
             conn_window={QUIC_CONN_WINDOW} send_window={QUIC_SEND_WINDOW} \
             datagram_recv={QUIC_DATAGRAM_RECV}"
        );
        Ok(cfg)
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
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
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
        // 头部区上限：**必须显式设**。h3 0.0.8 的默认是 `VarInt::MAX`（≈2^62），
        // 而它是在**收齐整个帧之后**才做 QPACK 解码与长度校验的 —— 也就是说
        // 一个声明「HEADERS 帧长 4GiB」再慢慢发的客户端，能让我们按发送速率 1:1 吃内存，
        // 直到分配失败（Rust 分配失败是 abort 进程，不是可恢复错误）。
        // 64KiB 与 h2 的 `H2_MAX_HEADER_LIST_SIZE` 对齐，正常请求足够宽裕。
        h3_builder.max_field_section_size(H3_MAX_FIELD_SECTION as u64);
        let mut server = match h3_builder.build(h3_conn).await {
            Ok(s) => s,
            Err(e) => {
                // Handshake / GOAWAY / reset during setup — log and drop connection.
                crate::server::log_throttle::warn_every(
                    "h3-server-conn",
                    std::time::Duration::from_secs(60),
                    &format!("h3 server connection peer={peer}: {e:#}"),
                );
                return Ok(());
            }
        };

        // 每连接一份的 QMux 流预算（见 qmux.rs）：闸门是每连接的，
        // 进程级的 QMUX_BUDGET 只做汇总。
        let qmux = crate::server::qmux::QmuxBudget::per_connection();

        // Stream resets / CANCEL must not tear down the process or the accept loop
        // for the whole endpoint — only this QUIC connection's request loop.
        //
        // `select!` 额外监听 shutdown 广播：配置/证书变更或 listener 被移除时，先给本连接
        // 发 H3 GOAWAY（RFC 9114 §5.2），再继续服务在飞请求。见 `serve` 里的长注释。
        let mut goaway_sent = false;
        // **入场自检**：本连接若是在停机**宽限窗口内**建起来的，watch 的当前值已经是
        // `true`（广播在订阅之前就发过了）—— broadcast 时代这种连接收不到任何通知，
        // 只会在 `ep.close()` 时被 CONNECTION_CLOSE 掐断（真机复现）。watch 让新连接
        // 一订阅就读到 `true`，于是这里立即补发 GOAWAY（RFC 9114 §5.2），
        // 与宽限前建连的老连接同语义：告知「最后接受的请求 id」、新流被拒、连接保留到
        // 宽限结束或客户端主动收尾。
        if *shutdown_rx.borrow_and_update() {
            goaway_sent = true;
            log::info!(
                "h3 peer={peer}: connection arrived inside the shutdown grace window; \
                 sending H3 GOAWAY immediately"
            );
            if let Err(e) = server.shutdown(0).await {
                log::debug!("h3 GOAWAY send failed peer={peer}: {e:#}");
                return Ok(());
            }
        }
        loop {
            let accepted = tokio::select! {
                biased;
                r = shutdown_rx.changed() => {
                    // Err = 发送端已消失（端点正在收尾，本连接交给 ep 关闭）；
                    // Ok = 值从 false 变为 true（上层要求优雅停机）。
                    if r.is_err() {
                        break;
                    }
                    if !goaway_sent {
                        goaway_sent = true;
                        log::info!(
                            "h3 peer={peer}: listener config/materials changed, sending H3 GOAWAY (graceful) before endpoint close"
                        );
                        // max_requests=0 ⇒ GOAWAY 携带「最后一条被接受的请求 id」，
                        // 在飞请求（id ≤ 该值）照常完成；之后的请求由 crate 回 H3_REQUEST_REJECTED。
                        if let Err(e) = server.shutdown(0).await {
                            log::debug!("h3 GOAWAY send failed peer={peer}: {e:#}");
                            break;
                        }
                    }
                    // **不能**发完 GOAWAY 就 break：break 会 drop `server`，
                    // `h3::server::Connection::drop` 立即关掉整条 QUIC 连接（H3_NO_ERROR），
                    // 于是 (a) 在飞请求的响应被截断、(b) 刚发出的 GOAWAY 与 CONNECTION_CLOSE
                    // 竞争、客户端常常只看到连接被关而**收不到 GOAWAY**（真机实测：
                    // 客户端报 ConnectionTerminated 而无 GOAWAY 帧）。
                    // 正确做法是继续留在 accept 循环里：GOAWAY 已发出、在飞请求继续由各自的
                    // resolver 任务写响应、新请求被 crate 拒绝；连接由**客户端**主动关闭
                    // （收到 GOAWAY 后按 RFC 9114 §5.2 收尾）或端点级 `ep.close()`
                    // （[`H3_SHUTDOWN_GRACE`] 到点后的兜底）结束。
                    continue;
                }
                res = server.accept() => res,
            };
            match accepted {
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
                    crate::server::log_throttle::warn_every(
                        "h3-accept",
                        std::time::Duration::from_secs(60),
                        &format!("h3 accept error peer={peer}: {msg}"),
                    );
                    break;
                }
            }
        }
        Ok(())
    }

    /// HEAD 感知的 DATA 发送：HEAD 请求的响应体一律不发（RFC 9110 §9.3.2）。
    ///
    /// 只给**早退分支**（503/413/鉴权拒绝）用：它们同样可能被 HEAD 命中，而 h1/h2 的
    /// 这些分支由 hyper 在协议层吞掉 body；h3 侧若照发就又是「HEAD 有正文」。
    /// 正常响应走 [`h3_send_response`]（那里已统一短路）。
    async fn send_body_unless_head<S>(
        send: &mut ::h3::server::RequestStream<S, Bytes>,
        method: &str,
        body: Bytes,
    ) -> Result<(), ::h3::error::StreamError>
    where
        S: ::h3::quic::SendStream<Bytes>,
    {
        if method == "HEAD" {
            return Ok(());
        }
        send.send_data(body).await
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

    /// RFC 9114 §4.2（与 RFC 9113 §8.2.2 同规）：HTTP/2/HTTP/3 的**连接特定字段**
    /// （`connection` / `transfer-encoding` / `upgrade` / `keep-alive` / `proxy-connection`）
    /// 一律禁用；`te` 是唯一例外，且只能取 `trailers`。违反即 malformed，
    /// 按 RFC 9114 §4.1.2 用 `H3_MESSAGE_ERROR` 的**流错误**处置。
    ///
    /// 为什么必须由本仓库补：h2 侧上游 `h2 0.4` 在 HPACK 解码时就判 malformed
    /// （`frame/headers.rs::load_hpack`，真机 raw 帧客户端发 `transfer-encoding: chunked`
    /// → RST_STREAM(PROTOCOL_ERROR)），而 h3 0.0.8 只校验字段名全小写与伪头顺序，
    /// **不查**这些被禁字段 —— 真机实测（修复前）：h3 上 `transfer-encoding: chunked` /
    /// `connection: close` / `upgrade: h2c` / `proxy-connection: ...` / `te: gzip`
    /// 全部被正常路由回 200，与 h2/h1 的宽严口径不一致。
    ///
    /// 比较口径与 h2 crate 逐字一致（`te` 值必须**恰好**是 `trailers`，不做 token 大小写
    /// 归一），保证三协议同判据（`te: TRAILERS` 在 h2 上也是 RST）。
    /// 返回违规字段名（供日志与单测）。
    fn prohibited_request_field(headers: &http::HeaderMap) -> Option<&'static str> {
        const PROHIBITED: [&str; 5] = [
            "connection",
            "transfer-encoding",
            "upgrade",
            "keep-alive",
            "proxy-connection",
        ];
        for name in PROHIBITED {
            if headers.contains_key(name) {
                return Some(name);
            }
        }
        // RFC 9113 §8.2.2 / RFC 9114 §4.2：`TE: trailers` 是唯一允许的形态。
        for value in headers.get_all(http::header::TE).iter() {
            if value.as_bytes() != b"trailers" {
                return Some("te");
            }
        }
        None
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

        // **任何路由/计费之前**先做报文合法性判定（RFC 9114 §4.1.2：malformed ⇒ 流错误）。
        // 放在这里而不是 `handle_h3` 里：CONNECT-UDP 分支在 `handle_h3` 之前分流，
        // 放后面会漏掉 CONNECT；放在闸门之前则畸形请求不吃在飞配额、也不记 telemetry
        //（与 h2 侧 crate 在帧层直接 RST、根本到不了 handler 的行为对齐）。
        if let Some(field) = prohibited_request_field(req.headers()) {
            crate::server::log_throttle::warn_every(
                "h3-prohibited-field",
                std::time::Duration::from_secs(60),
                &format!(
                    "h3 malformed request peer={peer}: prohibited connection-specific field \
                     `{field}` (RFC 9114 §4.2 / RFC 9113 §8.2.2) -> RST_STREAM H3_MESSAGE_ERROR"
                ),
            );
            // 不读 body、不发响应：RESET_STREAM(H3_MESSAGE_ERROR) 结束该流（同 crate 对
            // 大写字段名的处置，真机实测 0x10e）。
            stream.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
            return Ok(());
        }

        crate::server::telemetry::record_request();

        // **全局在飞闸门（仅普通请求）：先取名额，再收 body。**
        //
        // CONNECT-UDP 走**独立的隧道闸门**（见 [`H3_MAX_TUNNELS`]）：隧道不缓冲 body、
        // 却存活到 idle 超时，若也占用这个「body 在飞」名额，开满隧道就会把普通请求
        // 全部饿成 503。因此这里对 CONNECT **不取** `H3_INFLIGHT`，改在下面的 CONNECT
        // 分支里取 `H3_TUNNEL_GATE`（同等待时长、同 503 语义）。
        //
        // 位置很关键：普通请求必须在收 body **之前**取到名额（见 `H3_MAX_INFLIGHT`
        // 的说明 —— 否则「未认证客户端并发慢速请求」仍能把内存吃光）。守卫是 RAII，
        // 早退（包括下面的 503、413）都会自动归还，不会漏账。
        let is_connect = req.method() == http::Method::CONNECT;
        let _inflight = if is_connect {
            None
        } else {
            match tokio::time::timeout(H3_INFLIGHT_WAIT, h3_inflight_gate().acquire_owned())
                .await
            {
                Ok(Ok(p)) => Some(p),
                // 信号量关闭（进程退出中）：不加限制，交给上层收尾，别在这里制造新错误。
                Ok(Err(_)) => None,
                Err(_) => {
                    let t0 = std::time::Instant::now();
                    let resp = Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header(http::header::RETRY_AFTER, "1")
                        .body(())
                        .unwrap();
                    let _ = stream.send_response(resp).await;
                    let _ = send_body_unless_head(
                        &mut stream,
                        req.method().as_str(),
                        Bytes::from_static(b"server busy (h3 in-flight limit)\n"),
                    )
                    .await;
                    let _ = stream.finish().await;
                    crate::server::access_log::log_response(
                        &live,
                        peer,
                        "h3",
                        req.method().as_str(),
                        req.uri().path(),
                        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                        None,
                        t0.elapsed(),
                        "busy",
                        lc.access_log.as_ref(),
                    );
                    return Ok(());
                }
            }
        };

        // RFC 9298 CONNECT-UDP 必须在**收请求体之前**分流。
        //
        // 旧代码把 CONNECT 判断放在下面的 body 循环之后，而那个循环对
        // 「发完 HEADERS 就等 200」的客户端会一直阻塞在 `recv_data()` 上：
        // CONNECT-UDP 的负载本来就要等 200 之后才发，于是隧道还没建就先卡死。
        if req.method() == http::Method::CONNECT {
            // RFC 9114 §4.3.1：CONNECT 的 `:authority` / Host 值同样必须校验。
            // 这条分支在 `handle_h3` **之前**分流（见下），不在这里补判就会绕过
            // 权威名校验（h2 的 CONNECT 走 `handle_h2`，已被同判据覆盖）。
            if let Err(why) = crate::server::h2::request_authority_ok(req.uri(), req.headers()) {
                let path = req.uri().path().to_string();
                let t0 = std::time::Instant::now();
                connect_reject(
                    &mut stream,
                    &live,
                    peer,
                    lc.access_log.as_ref(),
                    &path,
                    StatusCode::BAD_REQUEST,
                    t0,
                    why,
                )
                .await;
                return Ok(());
            }
            // 开关（默认关）：CONNECT-UDP 是**公网 UDP 中继**（RFC 9298），
            // 反向代理与上传都要显式配置才开，它此前却默认可用 —— 不配任何东西就
            // 得到一条到任意公网 IP/端口的隧道（内网地址已被 `connect_udp` 拒绝，
            // 所以不是 SSRF，但仍是流量洗白/匿名代理面）。默认关、按 listener 显式打开。
            if !lc.connect_udp {
                let path = req.uri().path().to_string();
                let t0 = std::time::Instant::now();
                connect_reject(
                    &mut stream,
                    &live,
                    peer,
                    lc.access_log.as_ref(),
                    &path,
                    StatusCode::FORBIDDEN,
                    t0,
                    "connect-udp disabled on this listener (set listeners[].connect_udp = true)",
                )
                .await;
                return Ok(());
            }
            // 分流提前了，但**不能连访问控制一起绕过**：原先这里直接 return
            // proxy_connect_udp，于是 ip_access / 限流 / listener Basic Auth
            // 三项检查（都在下面的 handle_h3 里）对 CONNECT 完全失效 ——
            // 任何能连上 QUIC 口的客户端都能拿到一个匿名 UDP 中继（RFC 9298），
            // 既绕过 IP 白名单也绕过监听口密码。这里按同一顺序补上。
            let path = req.uri().path().to_string();
            let t0 = std::time::Instant::now();
            let snap = live.snapshot();
            if !crate::server::listener::ip_allowed(&snap.ip_access, &lc, peer) {
                connect_reject(
                    &mut stream,
                    &live,
                    peer,
                    lc.access_log.as_ref(),
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
                            lc.access_log.as_ref(),
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
                            lc.access_log.as_ref(),
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
                            lc.access_log.as_ref(),
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
            // QMux 流预算：**CONNECT-UDP 也必须计入**。此前预算是在这个分支 return 之后才取的，
            // 于是隧道完全绕过闸门：单条连接 256 个隧道（QUIC_MAX_BIDI_STREAMS）= 256 个 UDP fd
            // + 256 个任务，而连接数无上限。守卫是 RAII 的 —— 隧道存活期间一直持有名额，
            // 下面所有 `return Ok(())` 的早退分支也都不会漏账。
            let permit = match crate::server::qmux::stream_opened(&qmux) {
                Ok(p) => p,
                Err(rej) => {
                    // 流预算超限是**每条被拒的流**一条 —— 一条 h3 连接上可以开很多流，
                    // 所以这是按流速率可驱动的路径 ⇒ 节流（两个调用点共用同一 tag）。
                    crate::server::log_throttle::warn_every(
                        "h3-qmux-budget",
                        std::time::Duration::from_secs(60),
                        &format!(
                            "h3 qmux budget peer={peer}: {rej} (process-wide {})",
                            crate::server::qmux::QMUX_BUDGET.stats_line()
                        ),
                    );
                    let resp = Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(())
                        .unwrap();
                    let _ = stream.send_response(resp).await;
                    return Ok(());
                }
            };
            // **独立隧道闸门**（见 [`H3_MAX_TUNNELS`]）：CONNECT 不占 `H3_INFLIGHT`
            // （body 在飞）名额，但要在这里取自己的进程级上界。取不到 → 503，语义与
            // body 闸门完全一致（同等待时长、同 Retry-After、同访问日志 tag）。
            let _tunnel = match tokio::time::timeout(
                H3_INFLIGHT_WAIT,
                h3_tunnel_gate().acquire_owned(),
            )
            .await
            {
                Ok(Ok(p)) => Some(p),
                // 信号量关闭（进程退出中）：不额外设限，交给上层收尾。
                Ok(Err(_)) => None,
                Err(_) => {
                    let t0 = std::time::Instant::now();
                    let resp = Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header(http::header::RETRY_AFTER, "1")
                        .body(())
                        .unwrap();
                    let _ = stream.send_response(resp).await;
                    let _ = send_body_unless_head(
                        &mut stream,
                        req.method().as_str(),
                        Bytes::from_static(b"server busy (h3 tunnel limit)\n"),
                    )
                    .await;
                    let _ = stream.finish().await;
                    crate::server::access_log::log_response(
                        &live,
                        peer,
                        "h3",
                        req.method().as_str(),
                        req.uri().path(),
                        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                        None,
                        t0.elapsed(),
                        "busy",
                        lc.access_log.as_ref(),
                    );
                    return Ok(());
                }
            };
            let r = proxy_connect_udp(&req, stream, &live, peer, lc.access_log.as_ref()).await;
            drop(permit);
            return r;
        }

        // QMux 流预算：超限如实回 503，而不是把这次请求算成「已服务」。
        // 守卫是 RAII 的 —— 下面所有 `return Ok(())` 的早退分支都不会漏账。
        let permit = match crate::server::qmux::stream_opened(&qmux) {
            Ok(p) => p,
            Err(rej) => {
                // 同上面 CONNECT-UDP 分支：按流速率可驱动 ⇒ 节流，共用同一 tag。
                crate::server::log_throttle::warn_every(
                    "h3-qmux-budget",
                    std::time::Duration::from_secs(60),
                    &format!(
                        "h3 qmux budget peer={peer}: {rej} (process-wide {})",
                        crate::server::qmux::QMUX_BUDGET.stats_line()
                    ),
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
            if crate::server::access::is_admin_path(&snap.admin.path, req.uri().path()) {
                use crate::server::basic_auth::{admin_gate, retry_after_secs, AdminGate};
                let t0 = std::time::Instant::now();
                // (状态码, Retry-After, 文案)；None = 已过鉴权门，交给 admin::handle
                // 判定顺序与 h1/h2 的「ACL → CSRF → 鉴权门」一致：ACL 是**无状态**的纯判定，
                // 提前到收 body 之前做不影响限流计数，因此这里先补判一次；限流是有状态的
                // （消耗令牌），仍留在 handle_h3 里只算一次。
                let reject: Option<(StatusCode, Option<u64>, &'static str)> =
                    if !crate::server::listener::ip_allowed(&snap.ip_access, &lc, peer) {
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
                        lc.access_log.as_ref(),
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
                            let _ = send_body_unless_head(
                                &mut stream,
                                req.method().as_str(),
                                Bytes::from_static(msg.as_bytes()),
                            )
                            .await;
                        }
                    }
                    let _ = stream.finish().await;
                    return Ok(());
                }
            }
        }

        let result = async {
            // 请求体两种取法（与 h2 同构）：
            //  ① 普通请求 → 收齐（≤8MiB，超限 413）：admin/apps/proxy/DoH 的接口都是 Bytes 形态；
            //  ② **上传目标** → 不读 body，把 recv 半边装箱交给 upload_api 流式写盘
            //     ⇒ 单请求上限从 8MiB 抬到 MAX_UPLOAD_BYTES(2GiB)，与 h1/h2 一致。
            // 预判只看「像不像上传」，各分支仍按需自行收齐 —— 所以 page_rules 改写路径 /
            // app / proxy 抢走 URL 时最坏只是少一次流式机会，语义不分叉。
            let (mut send_half, mut recv_half) = stream.split();
            let pre_path = req.uri().path().to_string();
            let upload_like = matches!(
                *req.method(),
                http::Method::PUT | http::Method::PATCH | http::Method::POST
            ) && !apps::would_handle(&lc, &pre_path)
                && !would_proxy(&lc, &pre_path)
                && crate::server::upload_api::enabled_for(&live, &lc, &pre_path);

            let method = req.method().as_str().to_string();
            let t0 = std::time::Instant::now();
            // HSTS 判定要在 handle_h3 之前取：lc 会被 move 进去。
            let is_https = lc.ssl.is_some();

            let req: Request<H3Body> = if upload_like {
                req.map(|()| h3_body_from_recv(recv_half))
            } else {
                match h3_collect_stream(&mut recv_half, peer).await {
                    Ok(b) => req.map(|()| h3_bytes_body(b)),
                    Err(H3BodyErr::Overflow) => {
                        let resp = Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(())
                            .unwrap();
                        let _ = send_half.send_response(resp).await;
                        // 如实说明上限与出路（h1 是流式，上限 2GiB；分片上传见 §44）。
                        let _ = send_body_unless_head(
                            &mut send_half,
                            req.method().as_str(),
                            Bytes::from_static(
                                b"request body too large: h2/h3 single-request limit is 8MiB; \
use chunked uploads (Content-Range) or HTTP/1.1 for larger bodies\n",
                            ),
                        )
                        .await;
                        let _ = send_half.finish().await;
                        return Ok(());
                    }
                    // 空闲超时/读错：直接结束（drop 会向对端发 STOP_SENDING/RESET）
                    Err(H3BodyErr::Other) => return Ok(()),
                }
            };
            let path = req.uri().path().to_string();
            // §16.12：每站访问日志覆盖要在 `lc` 被 move 进 handle_h3 之前取出
            // （完成侧日志在 h3_send_response 里）。
            let access_override = lc.access_log.clone();
            let response = handle_h3(req, live.clone(), lc, peer).await;
            h3_send_response(
                &mut send_half,
                peer,
                response,
                &live,
                &method,
                &path,
                t0,
                is_https,
                access_override.as_ref(),
            )
            .await;
            Ok(())
        }
        .await;
        crate::server::qmux::stream_closed(permit);
        result
    }

    /// 统一的 h3 响应发送路径（普通请求与流式上传**共用一条**，避免两处实现漂移）。
    ///
    /// 早退只记日志、不改状态码：响应头可能已经发出去了。参数里带 `method`/`path`/`t0`
    /// 是为了完成侧那条全字段访问日志。
    async fn h3_send_response<S>(
        send: &mut ::h3::server::RequestStream<S, Bytes>,
        peer: SocketAddr,
        mut response: Response<Bytes>,
        live: &Arc<LiveConfig>,
        method: &str,
        path: &str,
        t0: std::time::Instant,
        is_https: bool,
        per: Option<&crate::config::ListenerAccessLogConfig>,
    ) where
        S: ::h3::quic::SendStream<Bytes>,
    {
            // HTTPS(H3) 响应统一补 HSTS——与 h1/h2 同一语义，见 h2.rs 处的说明。
            if is_https {
                response
                    .headers_mut()
                    .entry(http::header::STRICT_TRANSPORT_SECURITY)
                    .or_insert_with(|| {
                        http::HeaderValue::from_static(crate::server::h1::hsts_header())
                    });
            }
            let (mut parts, body_out) = response.into_parts();
            // 大文件（static 层 FileSource 标记）：分块读盘逐帧发送，避免整读进内存。
            let file_src = parts
                .extensions
                .remove::<crate::server::static_files::FileSource>();
            let engine = parts
                .extensions
                .get::<crate::server::access_log::EngineTag>()
                .map(|t| t.0)
                .unwrap_or("http");
            // P1-11：完成侧全字段访问日志；h3 侧拿得到精确响应字节数。
            crate::server::access_log::log_response(
                live,
                peer,
                "h3",
                method,
                path,
                parts.status.as_u16(),
                // 流式响应（FileSource）日志记真实长度，而不是空 body 的 0
                Some(file_src.as_ref().map(|s| s.len).unwrap_or(body_out.len() as u64)),
                t0.elapsed(),
                engine,
                per,
            );
            let resp = Response::from_parts(parts, ());
            if let Err(e) = send.send_response(resp).await {
                log::debug!("h3 send_response peer={peer}: {e:#}");
                return;
            }
            // RFC 9110 §9.3.2：HEAD 响应 **MUST NOT** 带正文（与 GET 同头、不含内容）。
            // h1/h2 由 hyper 在协议层吞掉 body（真机：`HEAD /cgia/` 在 h1/h2c 上 body 为空、
            // 引擎给的 content-length 原样保留），h3 此前把引擎产出的 body 原样写进
            // DATA 帧（真机：h3 `HEAD /cgia/` 回 209 字节正文）⇒ 跨协议不一致、违反 MUST。
            // 这里在**唯一的响应发送出口**短路：HEADERS 已带全部头（含 content-length），
            // 只是不发 DATA；FileSource 分支也一并跳过（顺带避免 `HEAD /big.bin` 的读放大）。
            if method == "HEAD" {
                if let Err(e) = send.finish().await {
                    log::debug!("h3 HEAD finish peer={peer}: {e:#}");
                }
                return;
            }
            if let Some(src) = file_src {
                // 大文件：分块读盘逐帧发送（`send_data` 自带 QUIC 流控背压）。
                // 这里不调用带类型标注的辅助函数：类型由调用点决定，
                // 内联可以完全避开 SendStream 泛型不匹配的风险。
                use tokio::io::{AsyncReadExt, AsyncSeekExt};
                match tokio::fs::File::open(&src.path).await {
                    Ok(mut f) => {
                        let mut left = src.len;
                        if src.start > 0
                            && f.seek(std::io::SeekFrom::Start(src.start)).await.is_err()
                        {
                            log::warn!("h3 stream_file seek {} peer={peer}", src.path.display());
                            left = 0;
                        }
                        let mut buf = vec![0u8; crate::server::static_files::STREAM_CHUNK];
                        while left > 0 {
                            let want = left.min(buf.len() as u64) as usize;
                            match f.read(&mut buf[..want]).await {
                                Ok(0) => {
                                    log::warn!("h3 stream_file 提前 EOF peer={peer}");
                                    break;
                                }
                                Ok(n) => {
                                    left -= n as u64;
                                    if let Err(e) = send
                                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                                        .await
                                    {
                                        log::debug!("h3 stream_file send_data peer={peer}: {e:#}");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("h3 stream_file read peer={peer}: {e:#}");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => log::warn!(
                        "h3 stream_file open {} peer={peer}: {e:#}",
                        src.path.display()
                    ),
                }
            } else if !body_out.is_empty() {
                if let Err(e) = send.send_data(body_out).await {
                    log::debug!("h3 send_data peer={peer}: {e:#}");
                    return;
                }
            }
            if let Err(e) = send.finish().await {
                log::debug!("h3 finish peer={peer}: {e:#}");
            }
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

    /// h3 请求体的「装箱」类型：既能装已收齐的 `Bytes`，也能装**流式**的 QUIC recv 半边。
    /// 错误类型擦除成 `Box<dyn Error + Send + Sync>`，两种形态共用同一个请求类型
    ///（与 h2 的 `H2Body` 同构，见 h2.rs）。
    pub type H3Body =
        http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

    /// 把已收齐的 `Bytes` 装成 [`H3Body`]。
    fn h3_bytes_body(b: Bytes) -> H3Body {
        Full::new(b)
            .map_err(|e: std::convert::Infallible| -> Box<dyn std::error::Error + Send + Sync> {
                match e {}
            })
            .boxed()
    }

    /// h3 的纯文本响应（响应体类型是 `Bytes`）。
    fn h3_plain(status: StatusCode, msg: &str) -> Response<Bytes> {
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Bytes::from(msg.to_string()))
            .unwrap()
    }

    /// 收齐请求体（≤ `cap`）→ `Request<Bytes>`；超限/读错直接给出响应。
    ///
    /// 只有上传分支**不**走这里（那里的 body 要流式写盘，见 [`h3_body_from_recv`]）；
    /// 其余分支（admin / apps / proxy / DoH）的接口都是 `Bytes` 形态。
    async fn h3_collect_bytes(
        req: Request<H3Body>,
        cap: usize,
    ) -> Result<Request<Bytes>, Response<Bytes>> {
        let (parts, mut body) = req.into_parts();
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let frame = match body.frame().await {
                Some(Ok(f)) => f,
                Some(Err(e)) => {
                    log::debug!("h3 body read: {e}");
                    return Err(h3_plain(StatusCode::BAD_REQUEST, "request body read failed"));
                }
                None => break,
            };
            let Some(data) = frame.data_ref() else { continue };
            if buf.len() + data.len() > cap {
                return Err(h3_plain(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large: h2/h3 single-request limit is 8MiB; \
use chunked uploads (Content-Range) or HTTP/1.1 for larger bodies",
                ));
            }
            buf.extend_from_slice(data);
        }
        Ok(Request::from_parts(parts, Bytes::from(buf)))
    }

    /// 流式请求体的 body 适配：后台任务循环 `recv_data()` → mpsc（容量 2 帧，天然背压）
    /// → body 侧 poll 通道。
    ///
    /// 与 h2 的 `H2RecvBody` 有两点不同，都是有意的：
    /// * **不需要手工归还流控**：h3-quinn 在 `recv_data()` 消费时自己归还，手工再调会 double-release；
    /// * h3 的 `RecvStream` 只有 async API（没有 poll 版），所以用后台任务 + 通道，
    ///   而不是像 h2 那样直接实现 `poll_data`。
    /// 任务结束（EOF/出错/超时/接收端丢弃）会 drop recv 半边 ⇒ quinn 发 STOP_SENDING，
    /// 不会把流吊住。
    fn h3_body_from_recv<R>(mut recv: ::h3::server::RequestStream<R, Bytes>) -> H3Body
    where
        // `Send + 'static` 是 tokio::spawn 的要求（泵任务要能在别的线程上跑、且不借用外部）：
        // h3-quinn 的 RecvStream 持有连接的 Arc，因此满足 ✓
        R: ::h3::quic::RecvStream + Send + 'static,
    {
        // 通道里带 `Result`：**空闲超时/读错必须让 body 侧看到 Err**，而不是干净 EOF。
        // 否则 h3 与 h2 行为分叉：h2 的 `H2RecvBody` 在空闲超时时返回 `Err`，
        // upload_api 据此回 400、**不 commit**；而 h3 若把超时当成 EOF，
        // upload_api 的 `Ok(None) => break` 会把**半截文件 commit 成完整文件**
        // （数据损坏）。两者都是 60s 超时 ⇒ 谁先触发是竞态，不能靠运气。
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, String>>(2);
        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(H3_BODY_IDLE_TIMEOUT_SECS),
                    recv.recv_data(),
                )
                .await
                {
                    Ok(Ok(Some(mut buf))) => {
                        let b = buf.copy_to_bytes(buf.remaining());
                        if b.is_empty() {
                            continue;
                        }
                        if tx.send(Ok(b)).await.is_err() {
                            return; // 接收端已丢弃（客户端断开或分支提前返回）
                        }
                    }
                    // 流正常结束（FIN）：干净 EOF，交给消费方。
                    Ok(Ok(None)) => return,
                    Ok(Err(e)) => {
                        log::debug!("h3 body task recv_data: {e:#}");
                        let _ = tx.send(Err(format!("h3 request body read failed: {e:#}"))).await;
                        return;
                    }
                    Err(_) => {
                        crate::server::log_throttle::warn_every(
                            "h3-body-idle",
                            std::time::Duration::from_secs(60),
                            "h3 body task idle timeout",
                        );
                        // 超时是**错误**，不是 EOF：如实告诉消费方（见上方注释）。
                        let _ = tx
                            .send(Err("h3 request body idle timeout".to_string()))
                            .await;
                        return;
                    }
                }
            }
        });
        // `Receiver` 是 Send 但**不是** Sync，而 BoxBody 要求 Send + Sync ⇒ 包一把锁
        //（临界区里不 await，只是 poll 通道，不会阻塞）。
        H3Body::new(H3RecvChan {
            rx: parking_lot::Mutex::new(rx),
        })
    }

    /// [`h3_body_from_recv`] 的 body 侧：把通道里的块当 DATA 帧交给消费方。
    struct H3RecvChan {
        rx: parking_lot::Mutex<tokio::sync::mpsc::Receiver<Result<Bytes, String>>>,
    }

    impl hyper::body::Body for H3RecvChan {
        type Data = Bytes;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            match self.get_mut().rx.lock().poll_recv(cx) {
                std::task::Poll::Ready(Some(Ok(b))) => {
                    std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b))))
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    std::task::Poll::Ready(Some(Err(e.into())))
                }
                std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }

    /// [`h3_collect_stream`] 的失败原因：`Overflow` 需要**调用方**回 413
    ///（recv 半边发不了响应），其余情况直接断开即可（drop 会发 STOP_SENDING/RESET）。
    enum H3BodyErr {
        Overflow,
        Other,
    }

    /// 收齐 h3 请求体（≤ `REQUEST_BODY_CAP`）。
    /// 空闲超时与 h2 同语义：只卡「读不到新字节」，不限制整个请求的总时长。
    async fn h3_collect_stream<R>(
        recv: &mut ::h3::server::RequestStream<R, Bytes>,
        peer: SocketAddr,
    ) -> Result<Bytes, H3BodyErr>
    where
        R: ::h3::quic::RecvStream,
    {
        let mut body: Vec<u8> = Vec::new();
        loop {
            let next = match tokio::time::timeout(
                std::time::Duration::from_secs(H3_BODY_IDLE_TIMEOUT_SECS),
                recv.recv_data(),
            )
            .await
            {
                Ok(n) => n,
                Err(_) => {
                    crate::server::log_throttle::warn_every(
                        "h3-body-idle",
                        std::time::Duration::from_secs(60),
                        &format!("h3 body idle timeout peer={peer}"),
                    );
                    return Err(H3BodyErr::Other);
                }
            };
            match next {
                Ok(Some(mut buf)) => {
                    if body.len() + buf.remaining() > REQUEST_BODY_CAP {
                        return Err(H3BodyErr::Overflow);
                    }
                    let chunk = buf.copy_to_bytes(buf.remaining());
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    log::debug!("h3 recv_data peer={peer}: {e}");
                    return Err(H3BodyErr::Other);
                }
            }
        }
        Ok(Bytes::from(body))
    }

    async fn handle_h3(
        req: Request<H3Body>,
        live: Arc<LiveConfig>,
        lc: ListenerConfig,
        peer: SocketAddr,
    ) -> Response<Bytes> {
        let mut req = req;
        // RFC 9114 §4.3.1：`:authority` / `Host` 的值必须在**任何路由判定之前**校验。
        // h3 crate 只校验「两者一致 / 非空」，不校验值的语义（`..`、`host:99999`、
        // `user@host` 等畸形值会被放行），而 h1 早已 400 —— 三协议必须同判。
        // 判据复用 h2 的同名函数（h1::is_valid_host_value 的等价副本）。
        if let Err(why) = crate::server::h2::request_authority_ok(req.uri(), req.headers()) {
            return tag(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Bytes::from(format!("bad request: {why}")))
                    .unwrap(),
                "h3",
            );
        }
        let path = req.uri().path().to_string();

        let snap = live.snapshot();
        if !crate::server::listener::ip_allowed(&snap.ip_access, &lc, peer) {
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
                // 只有「确实是 DoH 请求」才收 body —— 否则会给普通上传白白套上 8MiB 上限
                //（判定条件与 doh_prepared 的前几个早退分支一致）。
                //
                // 同 h2：HTTP/3 的权威字段是伪头 `:authority`（crate 放进 `uri().authority()`），
                // `HeaderMap` 里没有 `Host`。用 uri 形态的判据，否则配了 hostnames 白名单的
                // 部署在 h3 下 DoH 恒 404。
                if crate::server::dns::dot_doh::is_doh_request_uri(&dns_eff, req.uri()) {
                    let collected = match h3_collect_bytes(req, REQUEST_BODY_CAP).await {
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
                    req = Request::from_parts(parts, h3_bytes_body(body_for_rest));
                }
            }
        }

        // P0-1：listener 级 Basic Auth（§16.1）——与 h1/h2 对齐，堵住 h3 绕过。
        //
        // P2（与 h1/h2 同语义）：**admin 路径跳过 listener 级 basic_auth**。管理面由
        // admin 门单独把关（上面的 admin 前置门 + admin::handle 里的 admin_gate）。
        // 否则同端口既开站点口令又开面板时，一组 `Authorization` 头要同时过站点口令
        // 与管理员口令两道 Basic 门 ⇒ 面板在该端口不可达。admin 路径的鉴权不会变松：
        // admin_gate 对未配置用户/无凭据一律 fail-closed。
        let admin_path = crate::server::access::is_admin_path(&snap.admin.path, &path);
        if let Some(ba) = &lc.basic_auth {
            if !admin_path {
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
        }

        // P2-21（任务 4）：admin 暴露面——[admin].listeners_allow 非空时仅列出的端口可达。
    if admin_path && !snap.admin.listener_allowed(lc.port) {
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
        if crate::server::access::is_admin_path(&snap.admin.path, &path) {
            // admin::handle 是 h1 体类型（Bytes）的接口：先收齐（≤8MiB）。
            let req = match h3_collect_bytes(req, REQUEST_BODY_CAP).await {
                Ok(r) => r,
                Err(resp) => return tag(resp, "admin"),
            };
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
        if let Some((status, location)) =
            crate::server::page_rules::apply_simple(&lc, &path, &crate::server::page_rules::MatchCtx::from_request(&req))
        {
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
        // §16.11：host 维度的 owned 快照（必须在下面的 rewrite 改 `uri_mut()` 前取，
        // 见 `from_request_with_host` 的说明）。
        let pr_host = crate::server::page_rules::host_snapshot(&req);
        {
            let pr_ctx = crate::server::page_rules::MatchCtx::from_request(&req);
            if let Some(np) = crate::server::page_rules::rewrite_path(&lc, &path, &pr_ctx) {
                let pq = match req.uri().query() {
                    Some(q) => format!("{np}?{q}"),
                    None => np,
                };
                if let Ok(u) = pq.parse() {
                    *req.uri_mut() = u;
                }
            }
        }
        // 改写后以新路径做后续判定与分发（与 h1/h2 的修正一致）。
        let path = req.uri().path().to_string();
        // host 用改写前的快照：h3 的 host 只存在于 `:authority`（URI authority），
        // 客户端可以不发 Host 头；URI 被换成相对形态后 authority 消失，重建 ctx 会
        // 丢 host ⇒ 带 host 约束的 block/pass/header 静默不命中（仅 h2/h3 的漏洞面）。
        let pr_ctx = crate::server::page_rules::MatchCtx::from_request_with_host(&req, pr_host.as_deref());
        // P1-5：h1 的 pass_upstream（page rule pass 动作）在 h3 同样生效。
        if let Some((murl, upstream)) = crate::server::page_rules::pass_upstream(&lc, &path, &pr_ctx) {
            // proxy_page_rule 需要 h1 体类型（Bytes）：先收齐（≤8MiB）。
            let req = match h3_collect_bytes(req, REQUEST_BODY_CAP).await {
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
        let resp_mods = crate::server::page_rules::response_headers(&lc, &path, &pr_ctx);
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
        req: Request<H3Body>,
        live: Arc<LiveConfig>,
        lc: ListenerConfig,
        peer: SocketAddr,
        path: &str,
    ) -> Response<Bytes> {
        // 分发顺序必须与 h1 一致（规格 §4：apps 优先于 proxy），上传排在 apps/proxy **之后**、
        // 静态**之前**（与 h1/h2 相同）。这里的 `upload_like` 只是「apps/proxy 都不会接管这条 URL」
        // 的等价判定（与两个执行分支用的是同一组谓词），用来决定**要不要把 body 保持流式** ——
        // 顺序本身仍由下面各分支的先后保证。
        let upload_like = matches!(
            *req.method(),
            http::Method::PUT | http::Method::PATCH | http::Method::POST
        ) && !apps::would_handle(&lc, path)
            && !would_proxy(&lc, path)
            && crate::server::upload_api::enabled_for(&live, &lc, path);
        if upload_like {
            // 流式上传：body 不进内存，逐帧落盘（上限 2GiB，见 upload_resume::MAX_UPLOAD_BYTES）。
            return tag(
                crate::server::upload_api::handle_stream(req, &live, &lc, peer).await,
                "upload",
            );
        }
        // 其余分支都要 Bytes 形态（引擎 FFI、代理上游、静态层都按 Bytes 传参）。
        let req = match h3_collect_bytes(req, REQUEST_BODY_CAP).await {
            Ok(r) => r,
            Err(resp) => return tag(resp, "static"),
        };
        if apps::would_handle(&lc, path) {
            if let Some(resp) = apps::try_handle_simple(&req, &lc, peer).await {
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
        // §44 上传：走到这里说明 body 已被收齐（上面 apps/proxy 需要 Bytes），
        // 用 `handle_bytes` 适配（`*/` 或改写路径导致预判没命中时也会落到这里）。
        if matches!(
            *req.method(),
            http::Method::PUT | http::Method::PATCH | http::Method::POST
        ) && crate::server::upload_api::enabled_for(&live, &lc, path)
        {
            return tag(
                crate::server::upload_api::handle_bytes(req, &live, &lc, peer).await,
                "upload",
            );
        }
        // Static files; metrics already handled above via telemetry::maybe_handle_simple.
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
        per: Option<&crate::config::ListenerAccessLogConfig>,
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
                per,
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
        // RFC 9298 §3.2：客户端**应当**带 `?1`（capsule 协议），真实 MASQUE 客户端就是这么发的。
        // 之前这里直接回 501，等于对标准客户端不可用。现在两种形态都支持：
        //   `?1` → RFC 9297 capsule（type+len+payload，DATAGRAM=0x00）
        //   不带 → RFC 9298 §4.3 的裸长度前缀（早期草稿形态）
        let framing = if connect_udp::wants_capsule_protocol(capsule) {
            connect_udp::Framing::Capsules
        } else {
            connect_udp::Framing::LengthPrefixed
        };

        // 3. 目标解析 + 准入。
        let (host, port) = match connect_udp::parse_target_path(&path) {
            Ok(v) => v,
            Err(e) => {
                connect_reject(
                    &mut stream,
                    live,
                    peer,
                    per,
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
                    per,
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
                    per,
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
                per,
                &path,
                StatusCode::BAD_GATEWAY,
                t0,
                &format!("udp connect {target} failed: {e}"),
            )
            .await;
            return Ok(());
        }

        // 5. 隧道成立，才回 200。客户端从这一刻起按协商到的封装形态发 UDP 负载。
        //    capsule 模式必须在**响应**里回 `Capsule-Protocol: ?1`（RFC 9297 §3），
        //    否则客户端不知道能否用 capsule —— 它只会按裸长度前缀发。
        let mut rb = Response::builder().status(StatusCode::OK);
        if framing == connect_udp::Framing::Capsules {
            rb = rb.header("capsule-protocol", "?1");
        }
        let resp = match rb.body(()) {
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
            per,
        );
        log::info!("h3 CONNECT-UDP established peer={peer} target={target} path={path}");

        // 6. 拆成收发两半，跑双向转发；结束时正常收尾（FIN）而不是让 quinn reset。
        let (mut send_half, mut recv_half) = stream.split();
        let idle = std::time::Duration::from_secs(connect_udp::DEFAULT_IDLE_TIMEOUT_SECS);
        run_udp_tunnel(&mut send_half, &mut recv_half, udp, idle, peer, target, framing).await;
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
        framing: connect_udp::Framing,
    ) {
        let mut asm = connect_udp::DatagramAssembler::new(framing);
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
                        match asm.next_event() {
                            Ok(Some(connect_udp::TunnelEvent::Datagram(dg))) => {
                                if let Err(e) = udp.send(&dg).await {
                                    log::debug!("h3 CONNECT-UDP peer={peer} udp send: {e}");
                                    return;
                                }
                            }
                            // RFC 9297 §3.3：CLOSE capsule = 对端正常收尾（不是错误）
                            Ok(Some(connect_udp::TunnelEvent::Close)) => {
                                log::debug!("h3 CONNECT-UDP peer={peer} target={target}: 收到 CLOSE capsule");
                                return;
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
                framed = recv_framed(&udp, &mut udp_buf, framing) => {
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
        framing: connect_udp::Framing,
    ) -> Result<Bytes, String> {
        let n = udp.recv(buf).await.map_err(|e| e.to_string())?;
        let framed = match framing {
            connect_udp::Framing::Capsules => connect_udp::frame_datagram_capsule(&buf[..n])?,
            connect_udp::Framing::LengthPrefixed => connect_udp::frame_datagram(&buf[..n])?,
        };
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
        per: Option<&crate::config::ListenerAccessLogConfig>,
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
            per,
        );
    }

    fn would_proxy(lc: &ListenerConfig, path: &str) -> bool {
        // 必须与 `proxy::try_proxy` 用同一判据（带 `/` 边界）。无边界版本会把 `/apidocs`
        // 判成命中 `path = "/api"` 的规则，而 try_proxy 又拒绝匹配 ⇒ 502「rule matched but
        // produced no response」；`path = ""` 时更是整个 listener 全 502。
        lc.proxy_rules
            .iter()
            .any(|r| crate::server::proxy::path_matches_proxy_prefix(path, &r.path))
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
pub async fn serve(
    _bind: SocketAddr,
    _lc: ListenerConfig,
    _live: Arc<LiveConfig>,
    _cfg_fp: u64,
    _cfg_rx: tokio::sync::watch::Receiver<u64>,
) -> Result<()> {
    anyhow::bail!("HTTP/3 (QUIC) requires feature `tls`")
}

#[cfg(test)]
mod inflight_tests {
    use super::*;

    /// 闸门必须是**进程级共享**的：每条连接各自一份就挡不住「连接数 × 每连接 100」，
    /// 而 h3 的 QUIC 连接数是不限的。判据：一处在持有时，另一处立刻看到可用数少 1。
    #[tokio::test]
    async fn h3_inflight_gate_is_process_global() {
        let before = h3_inflight_gate().available_permits();
        assert!(before >= 1, "闸门初始可用数应 > 0，实际 {before}");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let jh = tokio::spawn(async move {
            let p = h3_inflight_gate().acquire_owned().await.expect("acquire");
            let _ = tx.send(());
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            drop(p);
        });
        rx.await.expect("子任务应拿到名额");
        assert_eq!(
            h3_inflight_gate().available_permits(),
            before - 1,
            "闸门不是进程级共享的（另一处看不到被占用的名额）"
        );
        jh.await.expect("join");
        assert!(
            h3_inflight_gate().available_permits() >= before,
            "释放后必须归还名额"
        );
    }

    /// 上限值要钉住：它是「进程能同时在飞的 h3 请求数（含正在收 body）」，
    /// 与 h2 的 256 同值 —— 同一台机器的内存预算只该有一份口径。
    #[test]
    fn h3_inflight_limit_matches_h2() {
        assert_eq!(H3_MAX_INFLIGHT, 256);
        assert_eq!(H3_MAX_INFLIGHT, crate::server::h2::H2_MAX_INFLIGHT);
    }

    /// P2 回归：CONNECT-UDP 隧道必须用**独立**闸门，不能占用 body 在飞名额
    /// （否则开满长隧道会把普通 h3 请求全部饿成 503）。判据：两个闸门是不同实例，
    /// 且隧道闸门的取用/归还只影响它自己。
    #[test]
    fn h3_tunnel_gate_is_separate_from_inflight() {
        assert_eq!(H3_MAX_TUNNELS, 256);
        assert!(
            !Arc::ptr_eq(&h3_inflight_gate(), &h3_tunnel_gate()),
            "隧道闸门不得与 body 在飞闸门是同一个信号量"
        );
        let before = h3_tunnel_gate().available_permits();
        let p = h3_tunnel_gate().try_acquire_owned().expect("acquire tunnel");
        assert_eq!(h3_tunnel_gate().available_permits(), before - 1);
        drop(p);
        assert_eq!(h3_tunnel_gate().available_permits(), before);
    }

    /// P2 回归（源码判据）：`handle_resolver` 里 `is_connect` 判定必须在取 body 在飞
    /// 名额**之前**（这样 CONNECT 不占该名额），且隧道闸门必须在 `proxy_connect_udp(`
    /// 调用之前取到（否则隧道没有自己的上界）。
    #[test]
    fn h3_connect_udp_uses_separate_tunnel_gate() {
        let src = include_str!("h3.rs");
        let pos = src.find("async fn handle_resolver").expect("handle_resolver");
        let tail = &src[pos..];
        let is_connect = tail.find("let is_connect").expect("is_connect gate");
        let inflight = tail.find("h3_inflight_gate()").expect("inflight gate");
        assert!(
            is_connect < inflight,
            "is_connect 判定必须在取 body 在飞名额之前（is_connect={is_connect} inflight={inflight}）"
        );
        let tunnel = tail.find("h3_tunnel_gate()").expect("tunnel gate");
        let tunnel_call = tail.find("proxy_connect_udp(").expect("proxy_connect_udp");
        assert!(
            tunnel < tunnel_call,
            "隧道闸门必须在 proxy_connect_udp 之前取到（tunnel={tunnel} call={tunnel_call}）"
        );
    }

    /// P2 回归：admin 路径必须跳过 listener 级 basic_auth（否则同端口「站点口令 + 面板」
    /// 时面板不可达）。判据：handle_h3 里 `check_listener_headers` 被 `if !admin_path` 包住。
    #[test]
    fn h3_admin_path_skips_listener_basic_auth() {
        let src = include_str!("h3.rs");
        let pos = src.find("async fn handle_h3").expect("handle_h3");
        let tail = &src[pos..];
        let guard = tail.find("if !admin_path {").expect("admin_path guard");
        let ba = tail.find("check_listener_headers").expect("basic_auth check");
        assert!(
            guard < ba,
            "check_listener_headers 必须被 if !admin_path 包住（guard={guard} ba={ba}）"
        );
    }

    /// P1 回归：handle_h3 必须在任何路由判定之前校验权威名（调用 h2 的同判据函数）。
    #[test]
    fn h3_validates_authority_before_routing() {
        let src = include_str!("h3.rs");
        let pos = src.find("async fn handle_h3").expect("handle_h3");
        let tail = &src[pos..];
        let check = tail
            .find("request_authority_ok")
            .expect("authority check in handle_h3");
        let acl = tail.find("listener::ip_allowed").expect("ip_access");
        assert!(check < acl, "权威名校验必须在 ACL/路由之前");
    }
}
