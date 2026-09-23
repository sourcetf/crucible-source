//! RFC 9298: HTTP/3 Extended CONNECT（CONNECT-UDP）——目标解析、分帧与地址准入。
//!
//! 本模块只做「不碰 I/O」的部分，便于单独测试：
//! - `:path` → `(host, port)` 目标解析（[`parse_target_path`]）；
//! - 扩展 CONNECT 的判定（[`is_connect_udp`]、[`wants_capsule_protocol`]）；
//! - 目标地址准入（[`resolve_target`]、[`is_disallowed_ip`]）；
//! - RFC 9000 §16 变长整数编解码（[`encode_varint`]、[`decode_varint`]）；
//! - RFC 9298 §4.3 长度前缀报文的封装/重组（[`frame_datagram`]、[`DatagramAssembler`]）。
//!
//! 真正的 QUIC 流读写与 `tokio::select!` 双向转发在 `h3.rs::proxy_connect_udp`：
//! 只有那里能拿到 `h3::server::RequestStream`。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// RFC 9298 §4.3：单个 UDP 负载上限（UDP 报文长度字段本身最大 65535）。
pub const MAX_DATAGRAM: usize = 65535;

/// 隧道空闲上限（秒）：两个方向都没有流量时拆除。
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

/// RFC 9298 §3 默认模板前缀（`/.well-known/masque/udp/{host}/{port}/`）。
const WELL_KNOWN_PREFIX: &str = "/.well-known/masque/udp/";

/// 解析 `:path` 为上游 `(host, port)`。
///
/// 支持 RFC 9298 里的两种形态：
/// - 直连形态：`/192.0.2.1:53`、`/192.0.2.1:53/`、`/[2001:db8::1]:53`
/// - 默认模板：`/.well-known/masque/udp/192.0.2.1/53/`
///
/// 只做语法解析；地址是否允许转发由 [`resolve_target`] 判定。
pub fn parse_target_path(path: &str) -> Result<(String, u16), String> {
    let p = path.trim();
    if p.is_empty() {
        return Err("missing target".into());
    }

    // 默认模板：host 与 port 用 `/` 分隔，host 可能是 `[v6]`。
    if let Some(rest) = p.strip_prefix(WELL_KNOWN_PREFIX) {
        let rest = rest.trim_end_matches('/');
        let (h, ps) = rest
            .rsplit_once('/')
            .ok_or_else(|| "missing port".to_string())?;
        let host = unbracket(h)?;
        if host.is_empty() {
            return Err("missing target".into());
        }
        return Ok((host.to_string(), parse_port(ps)?));
    }

    let t = p.trim_start_matches('/').trim_end_matches('/');
    if t.is_empty() {
        return Err("missing target".into());
    }

    // 带方括号的 IPv6：`[2001:db8::1]:53`
    if let Some(rest) = t.strip_prefix('[') {
        let (h, tail) = rest
            .split_once(']')
            .ok_or_else(|| "bad IPv6 literal".to_string())?;
        if h.is_empty() {
            return Err("missing target".into());
        }
        let ps = tail
            .strip_prefix(':')
            .ok_or_else(|| "missing port".to_string())?;
        return Ok((h.to_string(), parse_port(ps)?));
    }

    let (h, ps) = t.rsplit_once(':').ok_or_else(|| "missing port".to_string())?;
    if h.is_empty() {
        return Err("missing target".into());
    }
    // 裸 IPv6（没有方括号）在这里会剩下带 `:` 的「主机」，语义有歧义：RFC 3986 要求
    // IPv6 字面量必须加方括号，所以这里直接回报，而不是猜。
    if h.contains(':') {
        return Err("IPv6 target must be bracketed".into());
    }
    Ok((h.to_string(), parse_port(ps)?))
}

fn parse_port(ps: &str) -> Result<u16, String> {
    let port: u16 = ps.parse().map_err(|_| "bad port".to_string())?;
    if port == 0 {
        return Err("port 0 is not a valid target".into());
    }
    Ok(port)
}

fn unbracket(h: &str) -> Result<&str, String> {
    match h.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')
            .ok_or_else(|| "bad IPv6 literal".to_string()),
        None => Ok(h),
    }
}

/// 判断 protocol 值是否要求 CONNECT-UDP。
///
/// `h3` 0.0.8 把 `:protocol` 放在请求 **extensions**（`h3::ext::Protocol`），
/// 不是请求头 —— 调用方先取出来再传进来（`h3.rs::proxy_connect_udp`）。
/// 同一个谓词也用于普通 `connect-udp` 头，便于非 h3 调用方复用。
pub fn is_connect_udp(protocol: Option<&str>) -> bool {
    protocol
        .map(|p| p.eq_ignore_ascii_case("connect-udp"))
        .unwrap_or(false)
}

/// RFC 9297 §3：`Capsule-Protocol: ?1` 表示流上是 capsule 而不是裸长度前缀报文。
///
/// 本实现只做裸长度前缀形态，遇到这个头必须如实拒绝，而不是按错格式去解析——
/// 那会把「没实现」变成「解析出垃圾数据」。
pub fn wants_capsule_protocol(value: Option<&str>) -> bool {
    value.map(|v| v.trim().eq_ignore_ascii_case("?1")).unwrap_or(false)
}

/// 把解析出的 `(host, port)` 变成目标 `SocketAddr`，并做准入判断。
///
/// 只接受 **IP 字面量**：本进程不为转发目标做 getaddrinfo。理由是
/// `dns/geoip.rs::validate_outbound_host` 里同一条：一旦代解析域名，
/// 这个 CONNECT-UDP 端点就变成了可被利用的任意 DNS 解析器。
pub fn resolve_target(host: &str, port: u16) -> Result<SocketAddr, String> {
    let ip: IpAddr = host
        .parse()
        .map_err(|_| format!("target {host} is not an IP literal"))?;
    if is_disallowed_ip(&ip) {
        return Err(format!("target {ip} is not a permitted unicast address"));
    }
    Ok(SocketAddr::new(ip, port))
}

/// 明显不应转发的目标地址（环回 / 私有 / 保留 / 多播 / 未指定……）。
///
/// 与 `dns/geoip.rs::is_disallowed_ip` 同一取向（那里是 MaxMind 下载用的出向校验），
/// 额外做两件事：
///
/// 1. 把 IPv4-mapped IPv6（`::ffff:10.0.0.1`）折回 IPv4 再判定。不做这步的话，
///    `::ffff:` 写法可以整体绕过 v4 的全部规则；
/// 2. 同样折回 **NAT64**（`64:ff9b::/96`，RFC 6052）与 **6to4**（`2002::/16`，
///    RFC 3056）里嵌的 v4。这两个前缀本身就是「v4 装进 v6」的过渡机制：包一出本机，
///    网关/转换器就把它解回内网的 v4 投递，所以 `64:ff9b::a00:1` 等价于
///    `10.0.0.1`、`2002:0a00:0001::` 等价于 `10.0.0.1` —— 不折回就是再绕过一次
///    v4 规则。Teredo（`2001:0000::/32`）内嵌地址带混淆位、CGNAT（`100.64.0.0/10`，
///    RFC 6598 共享地址空间）根本不是 v6 过渡机制但同样不是公网单播，两者无法可靠
///    折回判定，直接整体拒绝。
pub fn is_disallowed_ip(ip: &IpAddr) -> bool {
    use std::net::IpAddr::*;
    if let V6(v) = ip {
        if let Some(v4) = embedded_v4(*v) {
            return is_disallowed_ip(&V4(v4));
        }
    }
    match ip {
        V4(v) => {
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                || is_cgnat(*v)
                || v.octets()[0] == 0 // 0.0.0.0/8
        }
        V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || is_teredo_or_nat64_local(*v)
        }
    }
}

/// 过渡前缀里嵌的 IPv4。折回后就能套用全部 v4 规则（含 `|| is_cgnat(...)`）。
fn embedded_v4(v: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = v.octets();
    // `::ffff:0:0/96`（IPv4-mapped，RFC 4291 §2.5.5.2）：双栈栈上直接当 v4 投递。
    if o[..10] == [0u8; 10] && o[10] == 0xff && o[11] == 0xff {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // `64:ff9b::/96`（NAT64 well-known prefix）：后 32 位是 v4，中间 64 位必须为 0
    // （RFC 6052 §2.2 规定 WKP 只放 v4，不再嵌接口标识）。
    if o[..4] == [0x00, 0x64, 0xff, 0x9b] && o[4..12] == [0u8; 8] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // `2002::/16`（6to4，RFC 3056 §2）：第 3–6 字节是 6to4 网关之后的 v4 目标。
    if o[0] == 0x20 && o[1] == 0x02 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    // `::/96`（IPv4-compatible，RFC 4291 §2.5.5.1 已废弃）：`::127.0.0.1` 这种写法在
    // 部分协议栈（历史 Windows、KAME 时代 BSD）仍按 v4 投递，按同一取向折回。
    // 纯 `::` 与 `::1` 也会命中这里，但折回后落在 is_unspecified/is_loopback，结论不变。
    if o[..12] == [0u8; 12] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

/// `100.64.0.0/10`（RFC 6598 §7 共享地址空间）：运营商 CGNAT、云内网大量使用，
/// `is_private()` 不覆盖它。`Ipv4Addr::is_shared()` 目前仍是 unstable，故手写位判定。
fn is_cgnat(v: Ipv4Addr) -> bool {
    let o = v.octets();
    o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000
}

/// `2001:0000::/32`（Teredo）与 `64:ff9b:1::/48`（RFC 8215 本地 NAT64 前缀）：
/// 内嵌 v4 的位置不固定（Teredo 还带混淆位），无法折回，整体拒绝。
fn is_teredo_or_nat64_local(v: Ipv6Addr) -> bool {
    let o = v.octets();
    o[..4] == [0x20, 0x01, 0x00, 0x00] || o[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]
}

/// RFC 9000 §16：变长整数编码（自动取最短长度）。
///
/// `v` 必须小于 2^62（QUIC 的 varint 上界）。
pub fn encode_varint(v: u64, out: &mut Vec<u8>) -> Result<(), String> {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.push(0x40 | (v >> 8) as u8);
        out.push(v as u8);
    } else if v < (1 << 30) {
        out.push(0x80 | (v >> 24) as u8);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    } else if v < (1 << 62) {
        out.push(0xC0 | (v >> 56) as u8);
        for sh in [48u32, 40, 32, 24, 16, 8, 0] {
            out.push((v >> sh) as u8);
        }
    } else {
        return Err(format!("varint {v} out of range"));
    }
    Ok(())
}

/// RFC 9000 §16：解码一个变长整数，返回 `(值, 占用字节数)`。
///
/// 数据不足以判断长度 / 不足整段时返回 `None`——调用方继续累积，
/// 这不是错误（[`DatagramAssembler`] 就靠这个语义）。
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    // 头两位决定长度：00→1B, 01→2B, 10→4B, 11→8B。
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        v = (v << 8) | b as u64;
    }
    Some((v, len))
}

/// 把 UDP 报文封装成 RFC 9298 的长度前缀帧（长度用变长整数）。
pub fn frame_datagram(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > MAX_DATAGRAM {
        return Err(format!("datagram length {} exceeds {MAX_DATAGRAM}", payload.len()));
    }
    let mut out = Vec::with_capacity(payload.len() + 4);
    encode_varint(payload.len() as u64, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// RFC 9298 §4.3：把 QUIC 流上的字节按长度前缀重组成一个个 UDP 报文。
///
/// 一个 H3 DATA 帧里可能有多个报文、也可能只有半个前缀，所以必须缓冲——
/// 不能假设「一次 recv_data = 一个报文」（旧实现正是栽在假设上）。
#[derive(Default)]
pub struct DatagramAssembler {
    buf: Vec<u8>,
}

impl DatagramAssembler {
    /// 追加流上收到的字节。
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// 取出下一个完整报文。
    ///
    /// - `Ok(Some(_))`：一个完整报文；
    /// - `Ok(None)`：还需要更多字节；
    /// - `Err(_)`：长度前缀非法或超过 [`MAX_DATAGRAM`] —— 调用方应据此关流报错。
    pub fn next_datagram(&mut self) -> Result<Option<Vec<u8>>, String> {
        let (len, used) = match decode_varint(&self.buf) {
            Some(v) => v,
            None => return Ok(None),
        };
        // 在 u64 域比较，避免 32 位平台上 `as usize` 截断后绕过上限。
        if len > MAX_DATAGRAM as u64 {
            return Err(format!("datagram length {len} exceeds {MAX_DATAGRAM}"));
        }
        let total = used + len as usize;
        if self.buf.len() < total {
            return Ok(None);
        }
        let dg = self.buf[used..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(dg))
    }

    /// 还有多少未消费的字节（收尾/诊断用）。
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_path_forms() {
        assert_eq!(parse_target_path("/192.0.2.1:53").unwrap(), ("192.0.2.1".into(), 53));
        assert_eq!(parse_target_path("/192.0.2.1:53/").unwrap(), ("192.0.2.1".into(), 53));
        assert_eq!(parse_target_path("192.0.2.1:53").unwrap(), ("192.0.2.1".into(), 53));
        assert_eq!(parse_target_path("/[2001:db8::1]:53").unwrap(), ("2001:db8::1".into(), 53));
        assert_eq!(
            parse_target_path("/.well-known/masque/udp/192.0.2.1/53/").unwrap(),
            ("192.0.2.1".into(), 53)
        );
        assert_eq!(
            parse_target_path("/.well-known/masque/udp/[2001:db8::1]/53/").unwrap(),
            ("2001:db8::1".into(), 53)
        );
        assert!(parse_target_path("").is_err());
        assert!(parse_target_path("/192.0.2.1").is_err());
        assert!(parse_target_path("/192.0.2.1:0").is_err());
        assert!(parse_target_path("/2001:db8::1").is_err());
        assert!(parse_target_path("/host.example:53").is_ok());
    }

    #[test]
    fn admission_rejects_private_and_mapped() {
        assert!(is_disallowed_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"10.1.2.3".parse().unwrap()));
        assert!(is_disallowed_ip(&"169.254.1.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"0.0.0.0".parse().unwrap()));
        assert!(is_disallowed_ip(&"::1".parse().unwrap()));
        assert!(is_disallowed_ip(&"fd00::1".parse().unwrap()));
        // IPv4-mapped 必须折回 v4 判定，否则整条 v4 规则被绕过。
        assert!(is_disallowed_ip(&"::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"::ffff:127.0.0.1".parse().unwrap()));
        // 过渡前缀同理：NAT64 / 6to4 / IPv4-compatible 里嵌的都是 v4 地址。
        assert!(is_disallowed_ip(&"64:ff9b::a00:1".parse().unwrap())); // NAT64 → 10.0.0.1
        assert!(is_disallowed_ip(&"64:ff9b::7f00:1".parse().unwrap())); // NAT64 → 127.0.0.1
        assert!(is_disallowed_ip(&"2002:a00:1::".parse().unwrap())); // 6to4 → 10.0.0.1
        assert!(is_disallowed_ip(&"::7f00:1".parse().unwrap())); // v4-compatible → 127.0.0.1
        // 位置不固定 / 非公网单播的过渡前缀整体拒绝。
        assert!(is_disallowed_ip(&"2001::1".parse().unwrap())); // Teredo
        assert!(is_disallowed_ip(&"64:ff9b:1::1".parse().unwrap())); // 本地 NAT64
        assert!(is_disallowed_ip(&"100.64.0.1".parse().unwrap())); // CGNAT
        assert!(is_disallowed_ip(&"100.127.255.254".parse().unwrap())); // CGNAT 上界
        // 折回后是公网单播的过渡地址不误杀；CGNAT 边界外也不误杀。
        assert!(!is_disallowed_ip(&"64:ff9b::101:101".parse().unwrap()));
        assert!(!is_disallowed_ip(&"100.63.255.255".parse().unwrap()));
        assert!(!is_disallowed_ip(&"100.128.0.0".parse().unwrap()));
        // 与 geoip.rs 一致：RFC 5737 文档地址（192.0.2.0/24 等）也在拒绝之列。
        assert!(is_disallowed_ip(&"192.0.2.1".parse().unwrap()));
        // 真正的公网单播才放行。
        assert!(!is_disallowed_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_disallowed_ip(&"2001:4860:4860::8888".parse().unwrap()));
        assert!(resolve_target("example.com", 53).is_err());
        assert!(resolve_target("10.0.0.1", 53).is_err());
        assert!(resolve_target("1.1.1.1", 53).is_ok());
    }

    #[test]
    fn varint_roundtrip_all_lengths() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let mut out = Vec::new();
            encode_varint(v, &mut out).unwrap();
            assert_eq!(decode_varint(&out), Some((v, out.len())), "v={v}");
        }
    }

    /// RFC 9000 §16 的长度边界：2 位前缀给出的容量是 2^6-1 / 2^14-1 / 2^30-1 / 2^62-1。
    /// 2^30 本身**超出** 4 字节形态，必须落到 8 字节——测试曾经断言它是 4 字节，
    /// 那是把边界写错了（编码器一直是对的）。
    #[test]
    fn varint_length_boundaries() {
        let cases = [
            (0u64, 1usize),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),  // 2^30 - 1：4 字节形态的上界
            (1_073_741_824, 8),  // 2^30：刚好越界，必须 8 字节
            ((1 << 62) - 1, 8),  // 2^62 - 1：varint 上界
        ];
        for (v, want_len) in cases {
            let mut out = Vec::new();
            encode_varint(v, &mut out).unwrap();
            assert_eq!(out.len(), want_len, "v={v}");
            assert_eq!(decode_varint(&out), Some((v, want_len)), "v={v}");
        }
        // 超出 2^62 必须报错，而不是静默截断。
        let mut out = Vec::new();
        assert!(encode_varint(1 << 62, &mut out).is_err());
    }

    /// 流式解码：前缀字节数不足时必须是 None（调用方继续累积），
    /// 而不是解出一个用零填充的错误短值。
    #[test]
    fn varint_partial_prefix_is_none() {
        let mut out = Vec::new();
        encode_varint(1_073_741_824, &mut out).unwrap();
        assert_eq!(out.len(), 8);
        for n in 0..out.len() {
            assert_eq!(decode_varint(&out[..n]), None, "prefix len {n}");
        }
        assert_eq!(decode_varint(&out), Some((1_073_741_824, 8)));

        // 2 字节形态同理。
        let mut two = Vec::new();
        encode_varint(16_383, &mut two).unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(decode_varint(&two[..1]), None);
        assert_eq!(decode_varint(&two), Some((16_383, 2)));
    }

    #[test]
    fn assembler_splits_and_joins() {
        let mut a = DatagramAssembler::default();
        a.push(&frame_datagram(b"hello").unwrap());
        a.push(&frame_datagram(b"world!!").unwrap());
        assert_eq!(a.next_datagram().unwrap().unwrap(), b"hello");
        assert_eq!(a.next_datagram().unwrap().unwrap(), b"world!!");
        assert_eq!(a.next_datagram().unwrap(), None);
        assert_eq!(a.pending(), 0);

        // 半个前缀 + 半个体，跨多次 push 也要能拼回来。
        let framed = frame_datagram(&vec![7u8; 300]).unwrap();
        let mut b = DatagramAssembler::default();
        b.push(&framed[..1]);
        assert_eq!(b.next_datagram().unwrap(), None);
        b.push(&framed[1..150]);
        assert_eq!(b.next_datagram().unwrap(), None);
        b.push(&framed[150..]);
        assert_eq!(b.next_datagram().unwrap().unwrap(), vec![7u8; 300]);

        // 超限长度必须报错，而不是分配 2^30 字节。
        let mut c = DatagramAssembler::default();
        let mut huge = Vec::new();
        encode_varint(1_000_000, &mut huge).unwrap();
        c.push(&huge);
        assert!(c.next_datagram().is_err());
    }
}
