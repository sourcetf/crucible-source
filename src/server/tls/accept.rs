//! Unified TLS accept: peek ClientHello → route → Boring / NSS / TomCrypt / rustls.

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use crate::server::tls::client_hello::{self, HelloRoute};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

/// Peek the ClientHello, classify, and hand off to the selected stack.
/// Legacy failures must never tear down the process (TomCrypt ARGCHK used to `abort()`).
pub async fn accept_connection(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    match accept_connection_inner(stream, live, lc, peer).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // 公网 TLS 端口上「明文请求 / 扫描器 / 老客户端」是**预期流量**，不是服务端故障：
            // 因此是 warn 而不是 error。更关键的是**不能把 `{e:#}` 原文写进日志** —— boring 的
            // 失败 Debug 里带着整个 ClientHello 字节（实测单条 ≈2KB），一次匿名请求就能写 2KB，
            // 是放大上万倍的远程日志洪泛（这台机器磁盘长期紧张）。短原因见
            // `handshake_failure_reason`，完整原文降级到 debug。
            // **按时间节流**：这条同样由匿名对端驱动（任何畸形 ClientHello 都命中），
            // 每条带不同 peer ⇒ 按消息去重无效，只能按类别掐表（否则可按连接速率刷日志）。
            crate::server::log_throttle::warn_every(
                "tls-accept-softfail",
                std::time::Duration::from_secs(60),
                &format!(
                    "tls accept soft-fail peer={peer}: {}",
                    crate::server::tls::handshake_failure_reason(&e)
                ),
            );
            log::debug!("tls accept soft-fail peer={peer} 完整错误: {e:#}");
            Ok(())
        }
    }
}

async fn accept_connection_inner(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    let ssl_cfg = lc.ssl.clone().context("ssl listener without ssl config")?;

    // 规格：cert 未配置前一律走 HTTP。`[listeners.ssl]` 段落存在但没填 cert/key
    // （面板保存顺序、手写配置）时，旧行为是 build_acceptor 报错 → 连接被静默丢弃，
    // 客户端只能挂到超时。这里改为按明文 HTTP 服务（HSTS/301 由 h1 侧照常处理）。
    // 只判「未配置」：证书文件一时读不到（轮换中）不算未配置，那时仍走 TLS 失败重试。
    if ssl_cfg.cert.is_none() || ssl_cfg.key.is_none() {
        // 这是**配置状态**（不是每个对端的问题），但触发者是匿名对端（每条连接一次）
        // ⇒ 按类别+端口节流，避免一个配错的口变成日志洪泛入口。
        crate::server::log_throttle::warn_every(
            "tls-listener-no-cert",
            std::time::Duration::from_secs(60),
            &format!(
                "tls listener :{} 未配置 ssl.cert/ssl.key —— 按规格以明文 HTTP 服务 peer={peer}",
                lc.port
            ),
        );
        let peek = peek_first_record(&stream).await;
        return crate::server::h1::serve_with_prefix(stream, live, lc, peer, &peek).await;
    }

    let peek = peek_first_record(&stream).await;
    // 空 peek = 总预算内一个字节都没收到（对端连上不发 ClientHello，或已 EOF）。
    // **不能**把它交给 TLS 栈：boring 的握手没有超时，会对这条空流继续无限等
    // ClientHello ⇒ 该连接的 fd/任务被永久挂住（这正是给 peek 加总预算要堵的洞）。
    if peek.is_empty() {
        log::debug!("tls peek 空（首字节超预算或已断开）peer={peer}，丢弃");
        drop(stream);
        return Ok(());
    }

    // Defense-in-depth: never hand malformed SSLv2-framed garbage to any stack.
    if !peek.is_empty() && peek[0] & 0x80 != 0 {
        let wire = client_hello::route(&peek);
        if wire == HelloRoute::Boring {
            // debug 而非 info：这是**匿名可触发**的路径（发几个字节就命中），
            // info 级别等于给磁盘开一个「按连接数计费」的写入口（本机磁盘长期紧张）。
            log::debug!(
                "tls soft-drop incomplete/non-TLS SSLv2-framed peek peer={peer} len={}",
                peek.len()
            );
            drop(stream);
            return Ok(());
        }
    }

    // 早期规格 8：sni_only——空/错 SNI 直接静默丢弃（不发 reset 不回包，性能优先）。
    //
    // G-08：开了 `[dns.dot] reuse_tls_port` 时，DoT 客户端用**自己的 SNI**（如
    // dot.example）连同一个站点 TLS 口；sni_only 是针对站点名的过滤，不能把这条
    // 分流连接先杀掉。判据与 boring 侧完全一致（ALPN dot + dot.sni 白名单）。
    //
    // **只在 DoT 分流真的可用的栈上才跳过 sni_only**：ALPN dot 的分流实现只在
    // BoringSSL 路径（boring_path::accept_dot_reuse）。若这条 ClientHello 会被路由
    // 到 NSS/TomCrypt/rustls，放它过 sni_only 只会得到一个「错误 SNI 仍被服务」的
    // HTTP 连接（legacy 构建上 = 真实的 sni_only 绕过）。因此额外要求 wire=Boring
    // 且本二进制编译了 tls_boring。
    if ssl_cfg.sni_only && !dot_split_available(&live, &peek) {
        let want = ssl_cfg
            .sni_name
            .as_deref()
            .map(|s| s.to_string())
            .or_else(|| lc.server_name.clone());
        let Some(want) = want else {
            // 规格：sni_only 开启时**必须**配 sni_name。没配就没有可比对的期望值，
            // 按 fail-closed 全部丢弃（不能退化成「任意 SNI 都放行」），但要如实报警：
            // 否则运维只看到「站点静默不可用」，不知是配置缺项。只报一次，防刷日志。
            if !sni_unconfigured_warned() {
                log::error!(
                    "tls listener :{} 开了 ssl.sni_only 但既无 ssl.sni_name 也无 server_name —— \
                     所有连接都会按规格被丢弃；请补 ssl.sni_name",
                    lc.port
                );
            }
            drop(stream);
            return Ok(());
        };
        let got = client_hello::parse_sni(&peek);
        let ok = got.as_deref().map(|g| sni_host_eq(g, &want)).unwrap_or(false);
        if !ok {
            // 匿名可触发（任何 SNI 不匹配的连接）⇒ debug，避免按连接数刷日志。
            log::debug!("tls sni_only: dropped peer={peer} (missing/mismatched SNI)");
            drop(stream);
            return Ok(());
        }
    }

    // 早期规格 5：端口复用——明文口（或未配 ssl 的口）收到 TLS ClientHello 时，
    // 按 SNI 找到匹配 server_name 的已配置 TLS listener，用其证书直接走 TLS。
    // （本函数只在 ssl listener 上被调用；非 ssl 口的复用在 server::mod 分流。）
    let wire = client_hello::route(&peek);
    let route = client_hello::resolve(wire, &ssl_cfg);
    // 这条是**每条** TLS 连接都会走的路径（哪怕对端只发一个字节）。info 级别 =
    // 匿名客户端可按「连接速率」无限写日志（扫描器/洪水 → 磁盘被按字节数消耗，
    // 本机曾因写满盘让 GeoIP merge 死在中途）。路由信息诊断价值不足以换这个风险。
    log::debug!(
        "tls route peer={peer} wire={wire:?} stack={route:?} peek={} primary={} legacy={}",
        peek.len(),
        crate::server::tls::active_stack(),
        crate::server::tls::legacy_modules()
    );

    match route {
        HelloRoute::TomCrypt => {
            #[cfg(feature = "tls_tomcrypt")]
            {
                return crate::server::tls::tomcrypt::accept_and_serve(
                    stream, peek, &ssl_cfg, lc, peer, live,
                )
                .await;
            }
            #[cfg(not(feature = "tls_tomcrypt"))]
            anyhow::bail!("TomCrypt legacy stack not compiled in (rebuild with --enable-tomcrypt)");
        }
        HelloRoute::Nss => {
            #[cfg(feature = "tls_nss")]
            {
                return crate::server::tls::nss::accept_and_serve(
                    stream, peek, &ssl_cfg, lc, peer, live,
                )
                .await;
            }
            #[cfg(not(feature = "tls_nss"))]
            anyhow::bail!("NSS legacy stack not compiled in (rebuild with --enable-nss)");
        }
        HelloRoute::Boring => {
            #[cfg(feature = "tls_boring")]
            {
                return crate::server::tls::boring_path::accept_and_serve(
                    stream, peek, &ssl_cfg, lc, peer, live,
                )
                .await;
            }
            #[cfg(all(feature = "tls_rustls", not(feature = "tls_boring")))]
            {
                return crate::server::tls::rustls_path::accept_and_serve(
                    stream, peek, &ssl_cfg, lc, peer, live,
                )
                .await;
            }
            #[cfg(not(any(feature = "tls_boring", feature = "tls_rustls")))]
            anyhow::bail!("TLS feature disabled");
        }
    }
}

/// peek 上限（与历史行为一致，避免无界缓冲）。
const PEEK_CAP: usize = 4096;
/// 补齐首个 record 时最多再等几轮（每轮上限 300ms），防慢速攻击。
const PEEK_MAX_ROUNDS: u8 = 8;
/// peek 的**总时间预算**：首字节 + 补齐首个 record 合计最多等这么久
/// （与原来的「每轮 300ms × PEEK_MAX_ROUNDS」同量级，只是把首个字节也纳入预算）。
/// `pub(crate)`：明文分流 `listener::dispatch_plain` 的首字节嗅探复用同一个预算，
/// 两处口径必须一致，否则「TLS 口 2.4s 回收、明文口永不回收」。
pub(crate) const PEEK_TOTAL_WAIT: std::time::Duration =
    std::time::Duration::from_millis(300 * PEEK_MAX_ROUNDS as u64);

/// 读出**首个 TLS/SSLv2 record 的全部字节**。
///
/// `try_read` 只保证「有字节可读」，一次调用可能只拿到 ClientHello 的一段
/// （TCP 分段，或 ClientHello 大于 MSS/4096 字节）。旧实现只读一次就拿结果做
/// 分流与 sni_only 判定：被分段的**正常**客户端会因 SNI 解析不到而被
/// `sni_only` 静默丢弃（空 SNI 语义被误用成「读到的字节不够」）。
/// 这里按 record 头声明的长度补齐；补齐不了（对端不再发送）就按现状返回，
/// 后续判定依旧是 fail-closed。
pub(crate) async fn peek_first_record(stream: &TcpStream) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + PEEK_TOTAL_WAIT;
    let mut buf = vec![0u8; PEEK_CAP];
    let mut n = 0usize;
    // 首字节：必须有**超时**。旧实现是裸 `stream.readable().await.ok()`——对端 TCP
    // 连上后一个字节都不发，就能让这个任务连同它的 fd/缓冲永久挂住（h1 有 30s 头读
    // 超时，这条 TLS 窥探路径反而没有 ⇒ 匿名客户端可无限占用连接资源）。
    // 另外 `readable()` 允许**伪唤醒**（返回时仍无数据可读），因此一次 `WouldBlock`
    // 不能当作「对端没发」——在总预算内重试。
    loop {
        if tokio::time::timeout_at(deadline, stream.readable()).await.is_err() {
            // 预算耗尽：对端没有发来 ClientHello。
            return Vec::new();
        }
        match stream.try_read(&mut buf[n..]) {
            Ok(0) => return buf[..n].to_vec(), // EOF
            Ok(m) => {
                n += m;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                log::debug!("peek ClientHello failed: {e}");
                return buf[..n].to_vec();
            }
        }
    }
    // 补齐首个 record：按 record 头声明的长度收齐（分段的正常客户端不该被 sni_only
    // 误杀），同样受同一个总预算约束。
    let mut rounds = 0u8;
    while let Some(want) = record_need(&buf[..n]) {
        let want = want.min(PEEK_CAP);
        if n >= want || n >= PEEK_CAP || rounds >= PEEK_MAX_ROUNDS {
            break;
        }
        rounds += 1;
        // 超时/出错：对端不会再补齐这段 record，别再等。
        if tokio::time::timeout_at(deadline, stream.readable()).await.is_err() {
            break;
        }
        match stream.try_read(&mut buf[n..]) {
            Ok(m) if m > 0 => n += m,
            _ => break,
        }
    }
    buf.truncate(n);
    buf
}

/// 首个 record 在线上声明的总长度（不足以判断时返回 `None`）。
pub(crate) fn record_need(buf: &[u8]) -> Option<usize> {
    match *buf.first()? {
        // SSLv2 记录头：2 字节长度（MSB 置位）+ 负载
        first if first & 0x80 != 0 => {
            if buf.len() < 2 {
                return Some(2);
            }
            let len = (((first & 0x7f) as usize) << 8) | buf[1] as usize;
            Some(2 + len)
        }
        // TLS 记录层：type(1) version(2) len(2)
        0x16 => {
            if buf.len() < 5 {
                return Some(5);
            }
            Some(5 + u16::from_be_bytes([buf[3], buf[4]]) as usize)
        }
        _ => None,
    }
}

/// G-08：把 peek 里**连续的 TLS handshake record**（content type 0x16）重组成一条
/// handshake 消息，返回从 handshake 头开始的完整字节（含 4 字节 type+length）。
///
/// RFC 8446 §5.1：握手消息可以跨多个 TLS record 分片，record 边界与消息边界无关。
/// 只使用 peek 中已经收到的**完整** record；遇到不完整 record 就停止（调用方
/// fail-open 到 HTTP，不会等待/阻塞）。非 ClientHello 或畸形输入返回 `None`。
///
/// 这是纯函数，输入来自匿名对端：所有长度都做上界/溢出检查（越界读 = 可远程触发
/// 的 panic）。
fn reassemble_client_hello(peek: &[u8]) -> Option<Vec<u8>> {
    if peek.len() < 5 || peek[0] != 0x16 {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut p = 0usize;
    while p + 5 <= peek.len() {
        // 每个分片 record 都是 handshake content type；遇到别的类型说明不是
        // ClientHello 的连续分片（如已进入 ChangeCipherSpec），停止。
        if peek[p] != 0x16 {
            break;
        }
        let len = u16::from_be_bytes([peek[p + 3], peek[p + 4]]) as usize;
        let start = p + 5;
        let Some(end) = start.checked_add(len) else {
            break;
        };
        if end > peek.len() {
            // 该 record 尚未收全：只用已经完整的前缀。
            break;
        }
        out.extend_from_slice(&peek[start..end]);
        p = end;
        if out.len() >= 4 {
            if out[0] != 0x01 {
                return None;
            }
            let hl = ((out[1] as usize) << 16) | ((out[2] as usize) << 8) | out[3] as usize;
            if out.len() >= 4 + hl {
                out.truncate(4 + hl);
                return Some(out);
            }
        }
        // 握手消息上限 2^24；peek 本身有上限，这里显式兜底防无界累积。
        if out.len() > 16 * 1024 * 1024 {
            return None;
        }
    }
    if out.len() >= 4 {
        Some(out)
    } else {
        None
    }
}

/// G-08：从（可能跨 record 分片的）ClientHello 里取 SNI。
///
/// `client_hello::parse_sni` 只解析「单 record、record 起始」的缓冲。这里把重组后的
/// handshake 消息再包成一个合成 record 交给它，从而让 SNI 与 ALPN 使用同一份
/// 分片重组结果（否则 ALPN 在第二个 record、SNI 在第一个 record 时两者判断会分叉）。
fn client_sni(peek: &[u8]) -> Option<String> {
    let hs = reassemble_client_hello(peek)?;
    // 合成 record 的 length 字段是 u16；正常 ClientHello 远小于 64KB，超限按畸形丢弃。
    let len = u16::try_from(hs.len()).ok()?;
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.extend_from_slice(&[0x16, 0x03, 0x01]);
    rec.extend_from_slice(&len.to_be_bytes());
    rec.extend_from_slice(&hs);
    client_hello::parse_sni(&rec)
}

/// G-08：ClientHello 的 ALPN 扩展里是否声明了协议 `want`（通常是 `b"dot"`）。
///
/// 输入是 TLS record 起始的 peek 缓冲（与 [`client_hello::parse_sni`] 同一前提），
/// 允许握手消息跨 record 分片（见 [`reassemble_client_hello`]）。
/// 所有长度都做上界检查：peek 来自匿名对端，任何越界读都是可远程触发的 panic。
/// 返回 `false` 表示「没声明」或「报文不完整/畸形」—— 调用方据此走普通 HTTP，
/// 因此截断/畸形输入是 fail-open 到 HTTP（而不是误入 DNS handler）。
pub(crate) fn client_offers_alpn(peek: &[u8], want: &[u8]) -> bool {
    // G-08：RFC 8446 §5.1 允许一条握手消息**跨多个 TLS record** 分片。旧实现只看
    // 第一个 record：ALPN 扩展落在第二个 record 时会被误判成「没声明 dot」⇒ 该连接
    // 按站点 HTTP 处理，DoT 客户端在复用端口上握手成功却永远拿不到 DNS 应答
    //（真机用 MemoryBIO 把一个完整 ClientHello 拆成两个 record 复现：ALPN=null）。
    // 这里先把 peek 里连续的 0x16 record 拼回一条 handshake 消息；后续 record 尚未
    // 到达/被 PEEK_CAP 截断时按截断处理 —— fail-open 到 HTTP，绝不误入 DNS handler。
    let Some(hs) = reassemble_client_hello(peek) else {
        return false;
    };
    // Handshake: type(1)=ClientHello(0x01) length(3)（reassemble 已校验并按长度截断）
    if hs.len() < 4 || hs[0] != 0x01 {
        return false;
    }
    let body = &hs[4..];
    // legacy_version(2) random(32) session_id_len(1) ...
    if body.len() < 35 {
        return false;
    }
    let mut p = 34usize;
    let sid = body[p] as usize;
    p += 1 + sid;
    if p + 2 > body.len() {
        return false;
    }
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    if p + 1 > body.len() {
        return false;
    }
    let comp = body[p] as usize;
    p += 1 + comp;
    if p + 2 > body.len() {
        return false;
    }
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_end = p.saturating_add(ext_len).min(body.len());
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[p], body[p + 1]]);
        let elen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        let s = p + 4;
        let e = match s.checked_add(elen) {
            Some(e) if e <= ext_end => e,
            _ => break,
        };
        // ALPN (type 0x0010): u16 ProtocolNameList length, then (u8 len + name)*
        if etype == 0x0010 && e >= s + 2 {
            let list_len = u16::from_be_bytes([body[s], body[s + 1]]) as usize;
            let list_end = (s + 2).saturating_add(list_len).min(e);
            let mut q = s + 2;
            while q < list_end {
                let l = body[q] as usize;
                let name_end = match q.checked_add(1 + l) {
                    Some(n) if n <= list_end => n,
                    _ => break,
                };
                if &body[q + 1..name_end] == want {
                    return true;
                }
                q = name_end;
            }
        }
        p = e;
    }
    false
}

/// G-08：这条 TLS 连接是否应分流到 DoT handler（端口复用）。
///
/// 判据（全部满足）：
/// * `[dns] enabled` 且 `[dns.dot] enabled` 且 `reuse_tls_port = true`；
/// * ClientHello 的 ALPN 里声明了 `dot`（RFC 7858；未声明 = 普通 HTTP，零影响）；
/// * `[dns.dot] sni` 非空时，SNI 必须匹配其中一项（fail-closed：取不到 SNI 即不匹配）。
///
/// 返回的是**当前生效**的 `[dns]` 配置（panel.toml 覆盖已应用）。调用方在握手后
/// 仍要按连接重新读取，配置热载（关掉 reuse/收紧 ACL）对已建立连接同样生效。
pub(crate) fn dot_reuse_config(
    live: &LiveConfig,
    peek: &[u8],
) -> Option<Arc<crate::server::dns::DnsConfig>> {
    let dc = crate::server::dns::effective(&live.snapshot());
    if !dc.enabled || !dc.dot.enabled || !dc.dot.reuse_tls_port {
        return None;
    }
    if !client_offers_alpn(peek, b"dot") {
        return None;
    }
    if !dc.dot.sni.is_empty() {
        // G-08：与 ALPN 一样按重组后的握手消息取 SNI（支持跨 record 分片的
        // ClientHello，避免「ALPN 命中但 SNI 被误判为缺失」）。
        let sni = client_sni(peek)?;
        if !dc.dot.sni.iter().any(|n| sni_host_eq(n, &sni)) {
            log::debug!("dot reuse: ALPN=dot 但 SNI={sni:?} 不在 [dns.dot].sni 白名单，按站点流量处理");
            return None;
        }
    }
    Some(dc)
}

/// G-08：sni_only 豁免的唯一判据 —— 这条连接**真的**会走 DoT 分流。
///
/// DoT 分流只在 BoringSSL 路径实现（`boring_path::accept_dot_reuse`）；NSS/TomCrypt/
/// rustls 路径不知道 ALPN dot。若只看 `dot_reuse_config` 就跳过 sni_only，这些栈上
/// 的错误 SNI 连接会被当成普通 HTTP 服务（sni_only 被绕过）。这里把「栈可用」与
/// 「ALPN/SNI 匹配」合并成一个判据；非 boring 构建恒为 false（sni_only 行为不变）。
fn dot_split_available(live: &LiveConfig, peek: &[u8]) -> bool {
    cfg!(feature = "tls_boring")
        && client_hello::route(peek) == HelloRoute::Boring
        && dot_reuse_config(live, peek).is_some()
}

/// SNI 主机名比较：大小写不敏感，且忽略末尾的点
/// （`example.com.` 是合法的 FQDN 写法，语义与 `example.com` 相同）。
pub(crate) fn sni_host_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('.').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// 「sni_only 未配 sni_name」告警只报一次（进程内），避免每连接一条 error。
fn sni_unconfigured_warned() -> bool {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    WARNED.swap(true, std::sync::atomic::Ordering::AcqRel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_compare_ignores_case_and_trailing_dot() {
        assert!(sni_host_eq("Example.COM", "example.com"));
        assert!(sni_host_eq("example.com.", "example.com"));
        assert!(sni_host_eq(" example.com. ", "EXAMPLE.com"));
        assert!(!sni_host_eq("example.com", "other.com"));
        assert!(!sni_host_eq("evil-example.com", "example.com"));
    }

    #[test]
    fn record_need_reads_declared_lengths() {
        // TLS record: 0x16 0301 0040 → 5 + 64
        assert_eq!(record_need(&[0x16, 0x03, 0x01, 0x00, 0x40]), Some(69));
        // 头不全时先要头本身，不越界。
        assert_eq!(record_need(&[0x16, 0x03]), Some(5));
        // SSLv2 记录头（MSB 置位）。
        assert_eq!(record_need(&[0x80, 0x2e]), Some(2 + 0x2e));
        // 明文 HTTP 不做补齐。
        assert_eq!(record_need(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(record_need(&[]), None);
    }

    /// G-08：构造带 SNI / ALPN 的最小真实布局 ClientHello（record 起始）。
    fn hello_with(sni: Option<&str>, alpn: &[&[u8]]) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(name) = sni {
            let nb = name.as_bytes();
            let mut ed = Vec::new();
            ed.extend_from_slice(&((1 + 2 + nb.len()) as u16).to_be_bytes());
            ed.push(0x00);
            ed.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            ed.extend_from_slice(nb);
            ext.extend_from_slice(&0x0000u16.to_be_bytes());
            ext.extend_from_slice(&(ed.len() as u16).to_be_bytes());
            ext.extend_from_slice(&ed);
        }
        if !alpn.is_empty() {
            let mut list = Vec::new();
            for p in alpn {
                list.push(p.len() as u8);
                list.extend_from_slice(p);
            }
            let mut ed = Vec::new();
            ed.extend_from_slice(&(list.len() as u16).to_be_bytes());
            ed.extend_from_slice(&list);
            ext.extend_from_slice(&0x0010u16.to_be_bytes());
            ext.extend_from_slice(&(ed.len() as u16).to_be_bytes());
            ext.extend_from_slice(&ed);
        }
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0x00); // session id
        hs.extend_from_slice(&2u16.to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1);
        hs.push(0x00);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((4 + hs.len()) as u16).to_be_bytes());
        rec.push(0x01);
        let hl = hs.len();
        rec.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn alpn_dot_detected_in_client_hello() {
        let dot = hello_with(Some("dot.example"), &[b"dot"]);
        assert!(client_offers_alpn(&dot, b"dot"));
        assert!(!client_offers_alpn(&dot, b"h2"));

        // 多协议：dot 排在后面也必须找到。
        let both = hello_with(Some("site.example"), &[b"h2", b"http/1.1", b"dot"]);
        assert!(client_offers_alpn(&both, b"dot"));
        assert!(client_offers_alpn(&both, b"h2"));

        // 没有 ALPN 扩展 / 只有别的协议 ⇒ false（普通 HTTPS 不受影响）。
        assert!(!client_offers_alpn(&hello_with(Some("site.example"), &[]), b"dot"));
        assert!(!client_offers_alpn(
            &hello_with(Some("site.example"), &[b"h2", b"http/1.1"]),
            b"dot"
        ));
        // 前缀相同但不同的名字不能误判。
        let sneaky = hello_with(Some("x"), &[b"dotx"]);
        assert!(!client_offers_alpn(&sneaky, b"dot"));
    }

    /// 把单 record 的 ClientHello 拆成两条握手 record（RFC 8446 §5.1 允许的分片）。
    fn split_records(full: &[u8], at: usize) -> Vec<u8> {
        assert_eq!(full[0], 0x16);
        let hs = &full[5..];
        let at = at.min(hs.len());
        let (a, b) = hs.split_at(at);
        let mut out = Vec::with_capacity(full.len() + 5);
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&(a.len() as u16).to_be_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(b);
        out
    }

    /// G-08：ALPN / SNI 在跨 record 分片的 ClientHello 里也必须被找到。
    ///
    /// 旧实现只看第一个 record：ALPN 扩展（位于 ClientHello 尾部）几乎总在第二个
    /// record ⇒ 所有分片客户端都被判成「没有 dot」，在复用端口上握手成功却拿不到
    /// DNS 应答。这里对多个切分点验证（ALPN 在前/后半段都要命中）。
    #[test]
    fn alpn_and_sni_detected_across_record_fragments() {
        let full = hello_with(Some("dot.example"), &[b"h2", b"dot"]);
        for at in [1usize, 20, 40, 80, 120, 200] {
            let frag = split_records(&full, at);
            assert!(
                client_offers_alpn(&frag, b"dot"),
                "split at {at}: ALPN dot lost across records"
            );
            assert_eq!(client_sni(&frag).as_deref(), Some("dot.example"), "split at {at}");
        }
        // 第二个 record 缺失（只发第一个分片）⇒ 不能误判为 dot（fail-open 到 HTTP）。
        let first_only = &split_records(&full, 20)[..25 + 20];
        assert!(!client_offers_alpn(first_only, b"dot"));
    }

    /// 不完整/畸形输入只能返回 false（不能 panic/越界）。
    #[test]
    fn alpn_parser_survives_truncation() {
        let full = hello_with(Some("dot.example"), &[b"dot"]);
        for cut in 0..full.len() {
            assert!(!client_offers_alpn(&full[..cut], b"dot") || cut == full.len());
        }
        assert!(!client_offers_alpn(b"GET / HTTP/1.1\r\n\r\n", b"dot"));
    }
}
