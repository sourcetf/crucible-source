//! L4 opaque proxy (bidirectional copy), with the guards every pre-HTTP path needs.
//!
//! **为什么例外的地方要用这个而不是自己内联 `io::copy`**：本模块的转发跑在
//! h1/h2/h3 **之前**（`l4_forward` 与 port_reuse 的 SNI 直通都是），所以不会继承它们
//! 任何一个超时。历史教训：port_reuse.rs 里曾有一份**带守卫**的实现，却没有任何调用者
//! （死代码），而 listener.rs 自己内联了一遍**不带守卫**的 —— 客户端连上什么都不发、
//! 或与一个不回包的目标互等，就能无限占用连接/FD/内存。所以现在只有这一个实现，
//! 两条路径都调它。
//!
//! §16.18「`l4`：TCP/UDP 透传或简单负载」：本模块同时提供
//!   * **TCP**：`proxy_tcp` / `proxy_tcp_any` / `forward_guarded`（现有行为不变）；
//!   * **UDP**：`serve_udp_relay`（同 listener 的 UDP 端口 → 上游，含回话地址映射与
//!     空闲回收，见其文档）。
//!
//! **多上游**：`l4_forward` 接受逗号分隔的多个 `ip:port`，`parse_upstreams` 解析后由
//! `pick_upstream` 做简单轮询（单目标时逐字保持旧行为）。**目标一律来自 listener 配置，
//! 不可由请求数据（让客户端指定目的地）影响** —— 否则就是一个 SSRF/放大代理面；
//! `ip_access` 仍是最先经过的一道门（见 `server::listener::handle_connection` 与
//! `serve_udp_relay` 内的判定）。

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::net::{TcpStream, UdpSocket};

/// §16.18：解析 listener 的 `l4_forward` 目标表 —— 逗号分隔的 `ip:port` 列表。
///
/// * 单目标（无逗号）= 历史行为逐字不变；
/// * 空项被忽略；全部为空 ⇒ 报错（配置写坏了不该“静默无上游”）。
/// 目标必须是字面 `ip:port`（规格如此，也是「目标不可由请求指定」的加固）。
pub fn parse_upstreams(spec: &str) -> Result<Vec<SocketAddr>> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for part in spec.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        let a = t.parse::<SocketAddr>().with_context(|| {
            format!("l4_forward 目标 {t:?} 不是合法的 `ip:port`")
        })?;
        out.push(a);
    }
    if out.is_empty() {
        anyhow::bail!("l4_forward {spec:?} 未解析出任何上游目标（该口会静默丢弃所有流量）");
    }
    Ok(out)
}

/// 多上游选择：单目标直接返回；多目标按全局计数器**轮询**（简单、无需健康检查）。
///
/// 轮询而非随机：行为可复现（便于运维核对），且与「目标来自配置」的安全前提一致 ——
/// 选择只影响「去哪一个已配置的上游」，与请求内容无关。
pub fn pick_upstream(addrs: &[SocketAddr]) -> SocketAddr {
    debug_assert!(!addrs.is_empty());
    if addrs.len() == 1 {
        return addrs[0];
    }
    static RR: AtomicUsize = AtomicUsize::new(0);
    let i = RR.fetch_add(1, Ordering::Relaxed);
    addrs[i % addrs.len()]
}

/// 连接目标的上限时间：目标不响应时立刻放弃，而不是把 accept 资源一直挂住。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// 两个方向共享的**空闲**超时：搬完一段数据就重新计时。
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Forward a TCP connection to an upstream until either side closes.
pub async fn proxy_tcp(client: TcpStream, upstream: SocketAddr) -> Result<()> {
    forward_guarded(client, upstream, &[])
        .await
        .with_context(|| format!("l4 forward {upstream}"))
}

/// §16.18 多上游 TCP：从 `upstreams` 里轮询选一个目标再转发。
///
/// 单元素时与 [`proxy_tcp`] 等价（选择器直接返回它），因此非多上游配置行为不变。
pub async fn proxy_tcp_any(client: TcpStream, upstreams: &[SocketAddr]) -> Result<()> {
    let target = pick_upstream(upstreams);
    forward_guarded(client, target, &[])
        .await
        .with_context(|| format!("l4 forward {target}"))
}

/// 带守卫的双向转发；`prefix` 是调用方已经从客户端读走、需要先补发给上游的字节
/// （port_reuse 的 SNI 分流用 `try_read` 真的读走了 ClientHello 前缀）。
pub async fn forward_guarded(
    client: TcpStream,
    upstream: SocketAddr,
    prefix: &[u8],
) -> std::io::Result<()> {
    let mut up = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream)).await {
        Ok(Ok(s)) => {
            // 透传路径的小包（首字节/心跳）不该被 Nagle 攒着等 ACK。
            let _ = s.set_nodelay(true);
            s
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect {upstream} 超时（{CONNECT_TIMEOUT:?}）"),
            ))
        }
    };
    if !prefix.is_empty() {
        use tokio::io::AsyncWriteExt;
        up.write_all(prefix).await?;
    }
    let (mut client_read, mut client_write) = client.into_split();
    let (mut up_read, mut up_write) = up.into_split();
    // 每个方向各一个「带空闲超时的 copy」：超时即结束该方向，try_join 随即收尾。
    let _ = tokio::try_join!(
        copy_idle(&mut client_read, &mut up_write, IDLE_TIMEOUT),
        copy_idle(&mut up_read, &mut client_write, IDLE_TIMEOUT),
    );
    Ok(())
}

/// `tokio::io::copy` + 每段数据之间的空闲超时（单段搬完就重置计时）。
///
/// `idle` 由调用方给：L4 用 [`IDLE_TIMEOUT`]，反代的 WebSocket 隧道用更宽松的
/// 上限（WS 可能长时间没有数据帧，但绝不能无限期挂住 —— 见 proxy::WS_IDLE_TIMEOUT）。
pub(crate) async fn copy_idle<R, W>(
    r: &mut R,
    w: &mut W,
    idle: std::time::Duration,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(idle, r.read(&mut buf)).await {
            Ok(Ok(0)) => {
                // EOF：对端关掉了它的**写方向**。必须把 FIN 传播给另一侧的写半部
                // （半关闭），否则依赖「读到 EOF 才回包」的协议（不少私有 TCP 协议、
                // TLS close_notify、以及先发后关的客户端）会永远等不到回应。
                // 只关写方向：反向数据仍可继续流，直到它自己也 EOF/空闲超时。
                // 真机复现：L4 目标 `read-until-EOF-then-reply`，客户端 `sendall + shutdown(WR)`
                // 后旧实现永远收不到回包（客户端 8s 超时）；补 shutdown 后立即收到 `GOT:n`。
                let _ = w.shutdown().await;
                return Ok(total);
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // 空闲超时：正常收尾（对端可在其它方向继续）。也顺手关掉本方向写，
                // 免得对端一直等我们这侧不再会有数据的 FIN。
                let _ = w.shutdown().await;
                return Ok(total);
            }
        };
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

// ───────────────────────── §16.18 UDP 中继 ─────────────────────────
//
// 语义：listener 的 UDP 端口收到**任意客户端**的报文后，为其建立一个**独立的上游会话**
// （一个 bind 到临时端口、`connect()` 到某个已配置上游的 UDP socket），把报文转发上去；
// 上游回过来的报文再经**监听端口本身**（`send_to`）发回原客户端 —— 这样客户端看到的
// 源地址仍是它最初发包的目标端口（“回话地址映射”）。
//
// 为什么每个客户端一个上游 socket（而不是共享一个 socket + `send_to`）：UDP 上游回包的
// 源地址对所有客户端是同一个（就是上游地址），共享 socket 时无法把回包区分给哪个客户端。
// per-flow `connect()` 后，该 socket 的 `recv` 天然只收到「本会话对应上游」的回包。
//
// 资源有界：每个会话一个 fd，且有**空闲回收**（两个方向都不动即关闭，见 `RELAY_IDLE`）
// 与**会话数上限**（`MAX_FLOWS`，防止客户端用海量源地址耗尽 fd）。
//
// 安全：目标来自 listener 的 `l4_forward`（不可由请求内容指定）；每个来源在建立会话前
// 先过 `ip_access`（全局 + per-listener），与 TCP 路径同一判定。

/// UDP 会话空闲回收上限：两个方向都没有报文超过该时长即关闭会话（回收 fd）。
const RELAY_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
/// 同时活跃的 UDP 会话上限。超过则**丢弃新来源的报文**（既有会话照常），
/// 避免一个客户端用海量伪造源地址把监听进程的 fd 打满。
const MAX_FLOWS: usize = 8192;

/// 一个 UDP 会话：上游 socket（已 connect）+ 最近活动时刻（毫秒，任一方向都刷新）。
struct UdpFlow {
    up: Arc<UdpSocket>,
    last: Arc<AtomicU64>,
}

fn relay_clock() -> &'static std::time::Instant {
    static BASE: OnceLock<std::time::Instant> = OnceLock::new();
    BASE.get_or_init(std::time::Instant::now)
}

fn now_ms() -> u64 {
    relay_clock().elapsed().as_millis() as u64
}

/// 为某个客户端建立会话用的上游 socket：bind 临时端口（同地址族）并 `connect` 到目标。
async fn bind_flow_socket(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let any: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().expect("static v6 any")
    } else {
        "0.0.0.0:0".parse().expect("static v4 any")
    };
    let s = UdpSocket::bind(any).await?;
    s.connect(target).await?;
    Ok(s)
}

/// 上游 → 客户端 的回包循环：带空闲回收。两个方向共享 `last`，任一方向有活动都会刷新，
/// 因此「客户端持续发、上游不回」或「上游持续回、客户端不响」都不会被误判为空闲。
fn spawn_reply_loop(
    up: Arc<UdpSocket>,
    server: Arc<UdpSocket>,
    client: SocketAddr,
    last: Arc<AtomicU64>,
    flows: Arc<Mutex<std::collections::HashMap<SocketAddr, UdpFlow>>>,
) {
    tokio::spawn(async move {
        let idle = RELAY_IDLE.as_millis().max(1) as u64;
        let mut buf = vec![0u8; 65_535];
        loop {
            let elapsed = now_ms().saturating_sub(last.load(Ordering::Relaxed));
            if elapsed >= idle {
                break;
            }
            let remaining = std::time::Duration::from_millis(idle - elapsed);
            match tokio::time::timeout(remaining, up.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    last.store(now_ms(), Ordering::Relaxed);
                    // 经**监听端口本身**回给客户端，保持客户端看到的源端口不变。
                    if let Err(e) = server.send_to(&buf[..n], client).await {
                        log::debug!("l4 udp: 回包给 {client} 失败: {e}");
                    }
                }
                Ok(Err(e)) => {
                    log::debug!("l4 udp: 上游 recv（client={client}）失败: {e}");
                    break;
                }
                Err(_) => {
                    // 读超时：若期间客户端又发过（last 被刷新）则继续等，否则收尾。
                    if now_ms().saturating_sub(last.load(Ordering::Relaxed)) >= idle {
                        break;
                    }
                }
            }
        }
        if let Ok(mut m) = flows.lock() {
            m.remove(&client);
        }
    });
}

/// §16.18 UDP 中继主循环：在 `bind`（= 该 listener 的一个地址:端口）上收包并转发。
///
/// `live` + `key` 让本函数每包都能拿到**当前**的 listener 配置（`l4_forward` 目标表、
/// `ip_access`）；listener 被删（或不再配 `l4_forward`）时返回 `Ok(())`，由调用方收尾。
/// 配置热更（改上游/改 ACL）无需重启：下一包即生效。
pub async fn serve_udp_relay(
    live: Arc<crate::server::live_config::LiveConfig>,
    key: String,
    bind: SocketAddr,
) -> Result<()> {
    let server = Arc::new(
        UdpSocket::bind(bind)
            .await
            .with_context(|| format!("l4 udp bind {bind}"))?,
    );
    log::info!("l4 udp relay ready on {bind} (listener {key})");
    let flows: Arc<Mutex<std::collections::HashMap<SocketAddr, UdpFlow>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let mut buf = vec![0u8; 65_535];
    let mut recheck = tokio::time::interval(std::time::Duration::from_secs(2));
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    recheck.tick().await; // 消费立即就绪的首拍
    loop {
        tokio::select! {
            r = server.recv_from(&mut buf) => {
                let (n, client) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        // UDP 上 ICMP 触发的 ECONNREFUSED 等不应终结中继，继续收包。
                        log::debug!("l4 udp recv {bind}: {e}");
                        continue;
                    }
                };
                let snap = live.snapshot();
                let Some(lc) = snap
                    .listeners
                    .iter()
                    .find(|l| crate::server::bind_key(l) == key)
                else {
                    return Ok(());
                };
                let Some(spec) = lc.l4_forward.as_deref() else {
                    continue;
                };
                // 与 TCP 路径同门：全局 + per-listener ip_access 都要放行。
                if !crate::server::listener::ip_allowed(&snap.ip_access, lc, client) {
                    log::debug!("l4 udp: {client} 被 ip_access 拒绝");
                    continue;
                }
                let upstreams = match parse_upstreams(spec) {
                    Ok(u) => u,
                    Err(e) => {
                        log::debug!("l4 udp: {e:#}");
                        continue;
                    }
                };
                // 已有会话：刷新活动时刻并复用其上游 socket（保证回包能对上客户端）。
                let existing = {
                    let m = flows.lock().expect("l4 udp flows poisoned");
                    m.get(&client).map(|f| {
                        f.last.store(now_ms(), Ordering::Relaxed);
                        Arc::clone(&f.up)
                    })
                };
                let up = match existing {
                    Some(u) => u,
                    None => {
                        let target = pick_upstream(&upstreams);
                        let sock = match bind_flow_socket(target).await {
                            Ok(s) => s,
                            Err(e) => {
                                log::debug!("l4 udp: 连接上游 {target} 失败: {e}");
                                continue;
                            }
                        };
                        let sock = Arc::new(sock);
                        let last = Arc::new(AtomicU64::new(now_ms()));
                        {
                            let mut m = flows.lock().expect("l4 udp flows poisoned");
                            if m.len() >= MAX_FLOWS {
                                drop(m);
                                log::warn!(
                                    "l4 udp: 活跃会话已达上限 {MAX_FLOWS}，丢弃 {client} 的新报文（回收后方可再建）"
                                );
                                continue;
                            }
                            m.insert(
                                client,
                                UdpFlow { up: Arc::clone(&sock), last: Arc::clone(&last) },
                            );
                        }
                        spawn_reply_loop(
                            Arc::clone(&sock),
                            Arc::clone(&server),
                            client,
                            last,
                            Arc::clone(&flows),
                        );
                        sock
                    }
                };
                if let Err(e) = up.send(&buf[..n]).await {
                    log::debug!("l4 udp: 转发 {client} → 上游失败: {e}");
                }
            }
            _ = recheck.tick() => {
                // listener 被删 / 不再配 l4_forward ⇒ 收尾（与 accept_loop 的存活检查同节奏）。
                let gone = {
                    let snap = live.snapshot();
                    !snap.listeners.iter().any(|l| {
                        crate::server::bind_key(l) == key && l.l4_forward.is_some()
                    })
                };
                if gone {
                    log::info!("l4 udp relay {key} removed; stopping");
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 空闲超时必须在「对端一直不发数据」时返回，而不是永久挂住（WS 隧道复用它）。
    #[tokio::test]
    async fn copy_idle_returns_after_idle_timeout() {
        let (mut r, _keep_open) = tokio::io::duplex(64);
        let mut out: Vec<u8> = Vec::new();
        let t0 = std::time::Instant::now();
        let n = copy_idle(&mut r, &mut out, Duration::from_millis(50))
            .await
            .expect("空闲超时不是错误");
        assert_eq!(n, 0);
        assert!(
            t0.elapsed() >= Duration::from_millis(40),
            "应等满空闲预算，实际 {:?}",
            t0.elapsed()
        );
        assert!(out.is_empty());
    }

    /// 有数据时照常搬运，搬完后的静默同样按空闲超时收尾。
    #[tokio::test]
    async fn copy_idle_moves_bytes_then_times_out() {
        let (mut r, mut w_peer) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = w_peer.write_all(b"hello").await;
            // 保持连接打开且不再发送：copy 写完 5 字节后必须按空闲超时返回。
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let mut out: Vec<u8> = Vec::new();
        let t0 = std::time::Instant::now();
        let n = copy_idle(&mut r, &mut out, Duration::from_millis(80))
            .await
            .unwrap();
        assert_eq!(n, 5);
        assert_eq!(out, b"hello");
        assert!(t0.elapsed() < Duration::from_secs(5), "不得等到对端关闭");
    }

    /// 读方向 EOF 必须把 FIN（半关闭）传播给写方向的另一端：否则依赖
    /// 「读到 EOF 才回包」的协议会永远挂住（真机 L4 半关闭复现过）。
    #[tokio::test]
    async fn copy_idle_propagates_half_close_on_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // 源：写 5 字节后 drop（EOF）。
        let (mut src_w, mut src_r) = tokio::io::duplex(64);
        // 汇：copy 写入这半部；它的对端应在数据之后读到 EOF。
        let (mut sink_w, mut sink_r) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            let _ = src_w.write_all(b"hello").await;
            drop(src_w); // 关写方向 → 读侧 EOF
        });
        let n = copy_idle(&mut src_r, &mut sink_w, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(n, 5);
        writer.await.unwrap();
        // 关键：copy 返回后 sink 的写方向必须已 shutdown，对端才能读到 EOF。
        // 未 shutdown 时这里会一直挂着 —— 用超时把「挂住」变成断言失败。
        let mut got: Vec<u8> = Vec::new();
        let r = tokio::time::timeout(Duration::from_secs(2), sink_r.read_to_end(&mut got)).await;
        assert!(r.is_ok(), "半关闭未传播：sink 侧一直读不到 EOF");
        assert_eq!(got, b"hello");
    }

    /// §16.18 多上游解析：单目标保持原样，多目标按顺序解析，空项忽略，非法项报错。
    #[test]
    fn parse_upstreams_splits_and_validates() {
        let one = parse_upstreams("127.0.0.1:9000").unwrap();
        assert_eq!(one, vec!["127.0.0.1:9000".parse().unwrap()]);

        let multi = parse_upstreams("10.0.0.1:80, 10.0.0.2:81 ,10.0.0.3:82").unwrap();
        assert_eq!(
            multi,
            vec![
                "10.0.0.1:80".parse().unwrap(),
                "10.0.0.2:81".parse().unwrap(),
                "10.0.0.3:82".parse().unwrap(),
            ]
        );

        assert!(parse_upstreams("").is_err(), "空列表必须报错，不能静默无上游");
        assert!(parse_upstreams(" , ").is_err());
        assert!(parse_upstreams("nonsense").is_err());
        assert!(
            parse_upstreams("127.0.0.1:80,broken").is_err(),
            "任一非法项即失败（不做“跳过坏项”的静默降级）"
        );
    }

    /// 单目标选择器直接返回它（旧行为）；多目标轮询覆盖全部目标且均分。
    #[test]
    fn pick_upstream_single_and_round_robin() {
        let one: Vec<SocketAddr> = vec!["127.0.0.1:1".parse().unwrap()];
        assert_eq!(pick_upstream(&one), one[0]);

        let many: Vec<SocketAddr> = vec![
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            "127.0.0.1:3".parse().unwrap(),
        ];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..9 {
            seen.insert(pick_upstream(&many));
        }
        assert_eq!(seen.len(), 3, "轮询必须覆盖全部上游");
    }

    /// §16.18 UDP 中继端到端：客户端 → 监听 UDP 端口 → 上游 echo → 回客户端，
    /// 且回包源地址是**监听端口**（回话地址映射正确）。
    #[tokio::test]
    async fn udp_relay_roundtrip_echo() {
        // 上游 echo（回给发来者的地址）。
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1024];
            loop {
                match upstream.recv_from(&mut b).await {
                    Ok((n, from)) => {
                        let _ = upstream.send_to(&b[..n], from).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 先占一个临时端口拿到地址，再释放给中继绑定。
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);

        let mut cfg = crate::config::Config::default();
        let mut lc = crate::config::ListenerConfig::default();
        lc.address = "127.0.0.1".into();
        lc.port = listen.port();
        lc.l4_forward = Some(up_addr.to_string());
        cfg.listeners.push(lc);
        let live = Arc::new(crate::server::live_config::LiveConfig::new(
            cfg,
            std::path::PathBuf::from("/tmp/l4-udp-test.toml"),
        ));
        let key = crate::server::bind_key(&live.snapshot().listeners[0]);

        let relay = tokio::spawn({
            let live = Arc::clone(&live);
            async move { serve_udp_relay(live, key, listen).await }
        });
        // 等中继把 UDP socket 绑上。
        tokio::time::sleep(Duration::from_millis(150)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"ping", listen).await.unwrap();
        let mut b = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut b))
            .await
            .expect("2s 内必须收到中继回包")
            .unwrap();
        assert_eq!(&b[..n], b"ping");
        assert_eq!(from, listen, "回包源地址必须是监听端口（地址映射）");
        relay.abort();
    }
}
