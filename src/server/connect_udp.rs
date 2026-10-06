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

/// RFC 9298 §5：UDP Proxying Payload（即被转发的 UDP 报文）上限。
///
/// 取 65527（= 65535 − 8 字节 UDP 头）。RFC 9298 §5 明文：
/// *"it is not possible to encode UDP payloads longer than 65527 bytes ... endpoints
/// MUST NOT send HTTP Datagrams with a UDP Proxying Payload field longer than 65527
/// using Context ID zero.  An endpoint that receives an HTTP Datagram using Context ID
/// zero whose UDP Proxying Payload field is longer than 65527 MUST abort the
/// corresponding stream."* 此前取 65535（偏大 8 字节），且超限时不按 RFC 中止流。
pub const MAX_DATAGRAM: usize = 65527;

/// RFC 9298 §5：HTTP Datagram 载荷 = `Context ID (i) + UDP Proxying Payload (..)`。
/// Context ID 是变长整数（最长 8 字节），故整个 HTTP Datagram 载荷上限为
/// `MAX_DATAGRAM + 8`；这也是 RFC 9297 §3.5 DATAGRAM capsule 的 `Length` 允许的最大值。
pub const MAX_HTTP_DATAGRAM: usize = MAX_DATAGRAM + 8;

/// RFC 9298 §5：Context ID 0 保留给「裸 UDP 载荷」。本实现不注册任何扩展 Context ID。
pub const CONTEXT_ID_UDP: u64 = 0;

/// RFC 9297 §3.2 的 capsule 类型：`0x00` = DATAGRAM（负载即一个 HTTP Datagram）。
pub const CAPSULE_DATAGRAM: u64 = 0x00;
/// `0x01` = CLOSE —— 对端宣告隧道正常结束。
///
/// ⚠️ 注意：RFC 9297 §5.4 的 "HTTP Capsule Types" 注册表**只登记了 0x00 DATAGRAM**，
/// 0x01 并未登记，按 §3.2「未知 capsule 必须被忽略」本应跳过。这里保留 CLOSE 语义，
/// 是为了兼容历史上把 0x01 当「隧道正常收尾」的实现（只会提前正常收尾，不会出错）。
/// 此前注释误引 "RFC 9297 §3.3"（那一节是 Error Handling，与 CLOSE 无关）。
pub const CAPSULE_CLOSE: u64 = 0x01;

/// 隧道空闲上限（秒）：两个方向都没有流量时拆除。
///
/// RFC 9298 §3.1 明文（"UDP Proxy Handling"）：
/// *"...UDP proxies MAY choose to close sockets due to a period of inactivity, but they
/// MUST close the request stream when closing the socket.  UDP proxies that close sockets
/// after a period of inactivity SHOULD NOT use a period lower than two minutes; see
/// Section 4.3 of [BEHAVE]."*
///
/// 此前取 30s：低于 RFC 明确引用 BEHAVE §4.3 给出的两分钟下限，对有长静默期的
/// 隧道（QUIC 保活、DNS-over-UDP 的长间隔重查询、游戏心跳）会在客户端看来「隧道
/// 无故被拆」，而客户端无从区分「idle 超时」与「上游故障」。120s 与 RFC 建议一致。
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 120;

/// RFC 9298 §3 默认模板前缀（`/.well-known/masque/udp/{host}/{port}/`）。
const WELL_KNOWN_PREFIX: &str = "/.well-known/masque/udp/";

/// `target_host` / `target_port` 变量的 percent-decoding（RFC 9298 §3.1）。
///
/// RFC 9298 §3.1 第一步就是：*"It extracts the 'target_host' and 'target_port' variables
/// from the URI it has reconstructed from the request headers, **decodes their
/// percent-encoding**, and establishes a tunnel..."*
/// 同节还规定：*"if 'target_host' contains an IPv6 literal, the colons (':') MUST be
/// percent-encoded.  For example, if the target host is '2001:db8::42', it will be encoded
/// in the URI as '2001%3Adb8%3A%3A42'."*
///
/// 不做这步的后果：**合规客户端的 IPv6 目标全部不可用** ——
/// `/.well-known/masque/udp/2001%3Adb8%3A%3A42/53/` 解出的 host 字面量是
/// `2001%3Adb8%3A%3A42`，`resolve_target` 里 `parse::<IpAddr>()` 必然失败 ⇒ 一律 403
/// 「not an IP literal」。RFC 里唯一指定的 IPv6 写法正好是被拒的那种。
///
/// 解码后仍拒绝「不像主机名」的结果：`%2F`/`%5C`（解码出路径分隔符，会让 host 语义
/// 歧义）、NUL 与任何空白/控制字符。这些只可能是构造出来的脏输入，直接报语法错。
fn percent_decode_target(s: &str) -> Result<String, String> {
    if !s.contains('%') {
        return Ok(s.to_string());
    }
    // 先校验 `%` 后面必须是两个十六进制位（RFC 3986 §2.1）。`percent_encoding::percent_decode_str`
    // 对非法转义（如 `%zz`）**不报错**，而是把 `%` 原样保留 —— 于是 `a%zzb` 会被当成合法
    // 主机名放过去，最终以「不是 IP 字面量」回 403（策略拒绝）而不是 400（语法错）。
    // 非法转义只可能是构造出来的脏输入，按语法错直接拒。
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let ok = i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit();
            if !ok {
                return Err("target contains invalid percent-encoding".into());
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    let decoded = percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map_err(|_| "target contains invalid percent-encoding".to_string())?
        .into_owned();
    if decoded.is_empty() {
        return Err("missing target".into());
    }
    if decoded.bytes().any(|b| {
        b == b'/' || b == b'\\' || b == 0 || b < 0x20 || b == 0x7f || b == b' '
    }) {
        return Err("target host contains an illegal character after percent-decoding".into());
    }
    Ok(decoded)
}

/// 解析 `:path` 为上游 `(host, port)`。
///
/// 支持 RFC 9298 里的两种形态：
/// - 直连形态：`/192.0.2.1:53`、`/192.0.2.1:53/`、`/[2001:db8::1]:53`
/// - 默认模板：`/.well-known/masque/udp/192.0.2.1/53/`
///
/// host/port 两个变量都先做 percent-decoding（RFC 9298 §3.1 要求；IPv6 字面量的
/// 冒号**必须**是 `%3A`，见 [`percent_decode_target`]）。
/// 只做语法解析；地址是否允许转发由 [`resolve_target`] 判定。
pub fn parse_target_path(path: &str) -> Result<(String, u16), String> {
    let p = path.trim();
    if p.is_empty() {
        return Err("missing target".into());
    }

    // 默认模板：host 与 port 用 `/` 分隔，host 可能是 `[v6]`。
    //
    // **一律先在原始文本上切分、再逐段 percent-decode**。若反过来先解码整条 path，
    // 客户端就能用 `%2F` 伪造分隔符，把「host 到 port」的边界挪到我们没打算的位置
    //（解码后的 host 里出现 `/` 也会被 [`percent_decode_target`] 拒掉）。
    if let Some(rest) = p.strip_prefix(WELL_KNOWN_PREFIX) {
        let rest = rest.trim_end_matches('/');
        let (h, ps) = rest
            .rsplit_once('/')
            .ok_or_else(|| "missing port".to_string())?;
        // 模板里 host 位置的方括号是可选的（RFC 9298 §3 的示例不带），两种都容忍。
        let h_decoded = percent_decode_target(h)?;
        let host = unbracket(&h_decoded)?;
        if host.is_empty() {
            return Err("missing target".into());
        }
        Ok((host.to_string(), parse_port(&percent_decode_target(ps)?)?))
    } else {
        let t = p.trim_start_matches('/').trim_end_matches('/');
        if t.is_empty() {
            return Err("missing target".into());
        }

        // 带方括号的 IPv6：`[2001:db8::1]:53`（方括号内的冒号可以是原样，也可以是 `%3A`）。
        if let Some(rest) = t.strip_prefix('[') {
            let (h, tail) = rest
                .split_once(']')
                .ok_or_else(|| "bad IPv6 literal".to_string())?;
            let h = percent_decode_target(h)?;
            if h.is_empty() {
                return Err("missing target".into());
            }
            let ps = tail
                .strip_prefix(':')
                .ok_or_else(|| "missing port".to_string())?;
            return Ok((h, parse_port(&percent_decode_target(ps)?)?));
        }

        // 直连形态：**在原始文本上**按最后一个 `:` 切（分隔符是原样冒号；IPv6 字面量的
        // 那些冒号按 RFC 9298 §3.1 是 `%3A`，因此不会参与这里的切分）。切完再逐段解码，
        // 解出的 host 允许含 `:`（即 IPv6 字面量）—— 边界已经由原始冒号确定了，不歧义。
        let (h_raw, ps_raw) = t.rsplit_once(':').ok_or_else(|| "missing port".to_string())?;
        // 原始 host 里还有裸冒号 ⇒ 是没加方括号、也没按 RFC 9298 §3.1 编码的 IPv6，
        // 「哪一段是端口」无法判定（`2001:db8::1` 会被切成 host `2001:db8:` + port `1`）。
        // 按 RFC 3986 §3.2.2 要求方括号、按 RFC 9298 §3.1 要求冒号为 `%3A`，二者都指向
        // 「拒绝并如实说明」，而不是猜一个可能把流量发错地址的解释。
        if h_raw.contains(':') {
            return Err("IPv6 target must be bracketed or percent-encoded".into());
        }
        let h = percent_decode_target(h_raw)?;
        if h.is_empty() {
            return Err("missing target".into());
        }
        Ok((h, parse_port(&percent_decode_target(ps_raw)?)?))
    }
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
                || v.octets()[0] >= 240 // 240.0.0.0/4 保留段（含 255.255.255.255）
                || is_benchmark_v4(*v) // 198.18.0.0/15（RFC 2544 基准测试）
        }
        V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || is_site_local(*v)
                || is_teredo_or_nat64_local(*v)
                || is_doc_v6(*v) // 2001:db8::/32（文档用）
                || is_benchmark_v6(*v) // 2001:2::/48（RFC 5180 基准测试）
                || is_orchid_v6(*v) // 2001:10::/28（ORCHID）
        }
    }
}

/// `198.18.0.0/15`（RFC 2544 基准测试；不是可路由的单播目的地）。
fn is_benchmark_v4(v: std::net::Ipv4Addr) -> bool {
    let o = v.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// `2001:db8::/32`（RFC 3849 文档地址）。显式判而不是用 `Ipv6Addr::is_documentation()`
///（后者在部分 Rust 版本仍是 unstable）。
fn is_doc_v6(v: std::net::Ipv6Addr) -> bool {
    let s = v.segments();
    s[0] == 0x2001 && s[1] == 0x0db8
}

/// `2001:2::/48`（RFC 5180 基准测试）。
fn is_benchmark_v6(v: std::net::Ipv6Addr) -> bool {
    let s = v.segments();
    s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0
}

/// `2001:10::/28`（RFC 4843 ORCHID）。
fn is_orchid_v6(v: std::net::Ipv6Addr) -> bool {
    let s = v.segments();
    s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010
}

/// `fec0::/10`（RFC 3879 已弃用的 site-local）。
///
/// 为什么必须单独判：`is_unique_local()` 只覆盖 `fc00::/7`、`is_unicast_link_local()`
/// 只覆盖 `fe80::/10`，于是 `fec0::/10` 既不算 loopback/ULA/link-local，会被当成
/// 「公网单播」放行 —— 与 v4 侧拒绝 `10/8`、`192.168/16` 的口径不一致，
/// 等于给「用 CONNECT-UDP 打内网」留了一条 v6 通道（部分环境仍按 site-local 路由）。
fn is_site_local(v: std::net::Ipv6Addr) -> bool {
    let o = v.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0xc0
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

/// RFC 9297 §3.5：把一个 UDP 报文封成 DATAGRAM capsule（`type=0x00, len, payload`）。
///
/// capsule 的载荷是 RFC 9298 §5 定义的 **HTTP Datagram** = `Context ID (i) + UDP Payload`，
/// 而**不是**裸 UDP 载荷：UDP 用 Context ID 0。此前直接把裸载荷放进 capsule，
/// 等于漏掉 Context ID ⇒
/// * 对端（合规客户端）会把 UDP 载荷的首字节当成 Context ID，非 0 即「未知 context」
///   而被丢弃（响应方向完全不可用）；
/// * 我们把客户端发来的 `Context ID(0) + UDP 载荷` 整段（多一个前导 0x00）转给目标。
pub fn frame_datagram_capsule(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > MAX_DATAGRAM {
        return Err(format!("datagram length {} exceeds {MAX_DATAGRAM}", payload.len()));
    }
    let mut out = Vec::with_capacity(payload.len() + 8);
    encode_varint(CAPSULE_DATAGRAM, &mut out)?;
    // capsule 长度覆盖整个 HTTP Datagram（Context ID + UDP 载荷）
    encode_varint(payload.len() as u64 + 1, &mut out)?;
    encode_varint(CONTEXT_ID_UDP, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// 隧道内的报文封装形态。
///
/// RFC 9298 §3.2 规定客户端**应当**带 `?1`（capsule 协议）—— 真实 MASQUE 客户端
/// （Chrome 等）就是这么发的；不带 `?1` 的裸长度前缀形态是早期草稿的写法。
/// 两种形态必须各自解析，不能混：capsule 每帧多一个**类型**字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// 早期 connect-udp 草案的裸长度前缀形态：`varint(len) + payload`。
    /// **注意**：这不是 RFC 9298 的线格式（RFC 9298 用 HTTP Datagram，见 [`Framing::Capsules`]），
    /// 也不带 Context ID。保留它只为兼容不带 `Capsule-Protocol: ?1` 的老客户端。
    LengthPrefixed,
    /// RFC 9297 §3.5：`varint(type) + varint(len) + HTTP Datagram`（type 0x00 = DATAGRAM）。
    /// capsule 载荷是 RFC 9298 §5 的 HTTP Datagram = `Context ID (i) + UDP Payload`。
    Capsules,
}

/// 从隧道字节流里解析出来的事件。
#[derive(Debug, PartialEq, Eq)]
pub enum TunnelEvent {
    /// 一个完整的 UDP 报文负载。
    Datagram(Vec<u8>),
    /// 对端发了 CLOSE capsule：隧道应**正常收尾**（不是错误）。
    Close,
}

/// RFC 9298 §4.3：把隧道字节流重组回一个个 UDP 报文。
///
/// 一个 H3 DATA 帧里可能有多个报文、也可能只有半个长度前缀/capsule，所以必须缓冲 ——
/// 不能假设「一次 recv_data = 一个报文」（旧实现正是栽在假设上）。
pub struct DatagramAssembler {
    buf: Vec<u8>,
    framing: Framing,
}

impl Default for DatagramAssembler {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            framing: Framing::LengthPrefixed,
        }
    }
}

impl DatagramAssembler {
    pub fn new(framing: Framing) -> Self {
        Self {
            buf: Vec::new(),
            framing,
        }
    }

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

    /// 解析下一个事件。两种封装形态都从这里出：
    ///
    /// * [`Framing::LengthPrefixed`]：一个长度前缀 + 负载；
    /// * [`Framing::Capsules`]：`type + len + payload`；`0x00` → 报文，`0x01` → [`TunnelEvent::Close`]，
    ///   **其它类型按 RFC 9297 §3.2 跳过**（前向兼容：不认识的 capsule 必须忽略而不是报错）。
    pub fn next_event(&mut self) -> Result<Option<TunnelEvent>, String> {
        match self.framing {
            Framing::LengthPrefixed => Ok(self.next_datagram()?.map(TunnelEvent::Datagram)),
            Framing::Capsules => {
                // **必须在自己内部循环**：未知 capsule 要「跳过并继续解析下一条」，
                // 不能返回 `Ok(None)`（那是「字节不够」的语义）——否则调用方的
                // `Ok(None) => break` 会退出，而缓冲里紧随其后的 DATAGRAM 在**没有新数据
                // 到达**时永远取不到（隧道静默卡死）。RFC 9297 §3.2 要求忽略未知 capsule，
                // 这里把「忽略」实现为「跳过并接着取」。
                loop {
                    let (ty, used) = match decode_varint(&self.buf) {
                        Some(v) => v,
                        None => return Ok(None),
                    };
                    let (len, used2) = match decode_varint(&self.buf[used..]) {
                        Some(v) => v,
                        None => return Ok(None),
                    };
                    // capsule 负载上限：DATAGRAM 的载荷 = Context ID + UDP 载荷，
                    // 上限 MAX_DATAGRAM + 8（Context ID 最长 8 字节）；其它类型（含未知）
                    // 我们只跳过，但也必须有界，否则一个伪造的大长度就能让我们无界缓存。
                    if len > MAX_HTTP_DATAGRAM as u64 {
                        return Err(format!("capsule payload {len} exceeds {MAX_HTTP_DATAGRAM}"));
                    }
                    let total = used + used2 + len as usize;
                    if self.buf.len() < total {
                        return Ok(None);
                    }
                    let payload = self.buf[used + used2..total].to_vec();
                    self.buf.drain(..total);
                    match ty {
                        CAPSULE_DATAGRAM => {
                            // RFC 9298 §5：HTTP Datagram 载荷以 Context ID 开头。
                            // Context ID 0 = 裸 UDP 载荷；非 0 = 未知 context（本实现未注册
                            // 任何扩展），按 §5 丢弃该 datagram 并继续，**不得**把 Context ID
                            // 当成 UDP 载荷的一部分转给目标。
                            match decode_varint(&payload) {
                                Some((CONTEXT_ID_UDP, cid_len)) => {
                                    let udp = &payload[cid_len..];
                                    if udp.len() > MAX_DATAGRAM {
                                        return Err(format!(
                                            "UDP payload {} exceeds {MAX_DATAGRAM}（RFC 9298 §5 要求中止流）",
                                            udp.len()
                                        ));
                                    }
                                    return Ok(Some(TunnelEvent::Datagram(udp.to_vec())));
                                }
                                Some((other, _)) => {
                                    log::debug!(
                                        "connect-udp: 丢弃未知 Context ID {other} 的 DATAGRAM capsule"
                                    );
                                    continue;
                                }
                                None => {
                                    return Err(
                                        "DATAGRAM capsule 缺少 Context ID（RFC 9298 §5）".into()
                                    );
                                }
                            }
                        }
                        CAPSULE_CLOSE => return Ok(Some(TunnelEvent::Close)),
                        other => {
                            // 未知 capsule：跳过负载并**继续**解析下一条
                            log::debug!(
                                "connect-udp: 跳过未知 capsule type=0x{other:x}（{len} 字节）"
                            );
                            continue;
                        }
                    }
                }
            }
        }
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

    /// RFC 9298 §3.1：`target_host` / `target_port` 的 percent-encoding **必须**被解码
    /// （IPv6 字面量的冒号在 RFC 里就是 `%3A`）。这条是「合规客户端的 IPv6 目标能否用」
    /// 的回归点：不decoding 时 RFC 指定的写法会被判成「not an IP literal」而 403。
    #[test]
    fn target_path_percent_decoding() {
        // RFC 9298 §3.1 的原文示例：2001:db8::42 → 2001%3Adb8%3A%3A42
        assert_eq!(
            parse_target_path("/.well-known/masque/udp/2001%3Adb8%3A%3A42/53/").unwrap(),
            ("2001:db8::42".into(), 53)
        );
        // 直连形态 + 编码冒号
        assert_eq!(
            parse_target_path("/2001%3Adb8%3A%3A42:53").unwrap(),
            ("2001:db8::42".into(), 53)
        );
        // 方括号 + 编码冒号；端口也可以被编码（数字的编码是无害的等价写法）
        assert_eq!(
            parse_target_path("/[2001%3Adb8%3A%3A1]:53").unwrap(),
            ("2001:db8::1".into(), 53)
        );
        // 直连形态的 **host/port 分隔符必须是原样冒号**：`/192.0.2.1%3A53` 无法判定
        // 那个 `%3A` 是「分隔符」还是「IPv6 字面量的一部分」，如实拒（missing port），
        // 而不是猜一个可能把流量发到别处的解释。
        assert!(parse_target_path("/192.0.2.1%3A53").is_err());
        // 域名形式的模板目标同样解码
        assert_eq!(
            parse_target_path("/.well-known/masque/udp/%68ost.example/53/").unwrap(),
            ("host.example".into(), 53)
        );

        // 解码出分隔符/空白/控制字符的输入必须拒绝：它们是构造出来的歧义输入，
        // 不能让 host 与 port 的边界随解码结果漂移。
        assert!(parse_target_path("/.well-known/masque/udp/a%2Fb/53/").is_err(), "%2F 不得进 host");
        assert!(parse_target_path("/.well-known/masque/udp/a/5%2F3/").is_err(), "%2F 不得进 port");
        assert!(parse_target_path("/a%b/53").is_err(), "非法 % 转义");
        // 上面那行是「缺端口」而 err，不能证明校验生效；用模板形态走到 host 解码：
        assert!(
            parse_target_path("/.well-known/masque/udp/a%zzb/53/").is_err(),
            "% 后非两位十六进制 → 语法错（400），而不是落到 403 的「不是 IP 字面量」"
        );
        assert!(parse_target_path("/.well-known/masque/udp/a%2/53/").is_err(), "截断的 % 转义");
        assert!(parse_target_path("/a%20b:53").is_err(), "解码出的空格非法");
        assert!(parse_target_path("/a%00b:53").is_err(), "解码出的 NUL 非法");
        assert!(parse_target_path("/%2e%2e%2fetc:53").is_err(), "解码出的路径分隔符非法");
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

    /// capsule 形态（RFC 9297 §3.5 + RFC 9298 §5）：封装/解析往返一致，
    /// 且 capsule 载荷是 `Context ID(0) + UDP 载荷`。
    #[test]
    fn capsule_roundtrip() {
        let payload = b"hello udp";
        let framed = frame_datagram_capsule(payload).unwrap();
        // wire = varint(0x00 type) + varint(1 + len) + varint(0 Context ID) + payload
        assert_eq!(framed[0], 0x00);
        assert_eq!(framed[1], payload.len() as u8 + 1, "长度必须覆盖 Context ID");
        assert_eq!(framed[2], 0x00, "HTTP Datagram 载荷必须以 Context ID 0 开头");
        let mut asm = DatagramAssembler::new(Framing::Capsules);
        asm.push(&framed);
        assert_eq!(
            asm.next_event().unwrap(),
            Some(TunnelEvent::Datagram(payload.to_vec()))
        );
        assert_eq!(asm.next_event().unwrap(), None);
    }

    /// RFC 9298 §5：capsule 载荷里的 Context ID 必须被剥掉；非 0 的 Context ID 必须按
    /// 「未知 context」丢弃（RFC 9297 §3.5 / RFC 9298 §5），不能当成 UDP 载荷转发；
    /// 空载荷（缺 Context ID）必须报错。这是「CONNECT-UDP 与合规客户端互操作」的回归点。
    #[test]
    fn capsule_context_id_is_stripped_and_unknown_skipped() {
        // Context ID 0：剥离后得到真实 UDP 载荷
        let mut framed = Vec::new();
        encode_varint(CAPSULE_DATAGRAM, &mut framed).unwrap();
        encode_varint(1 + 3, &mut framed).unwrap(); // ctxid(1) + "abc"(3)
        encode_varint(CONTEXT_ID_UDP, &mut framed).unwrap();
        framed.extend_from_slice(b"abc");
        let mut asm = DatagramAssembler::new(Framing::Capsules);
        asm.push(&framed);
        assert_eq!(asm.next_event().unwrap(), Some(TunnelEvent::Datagram(b"abc".to_vec())));

        // 非 0 Context ID：丢弃该 datagram，紧随其后的正常 DATAGRAM 仍能取到
        let mut buf = Vec::new();
        encode_varint(CAPSULE_DATAGRAM, &mut buf).unwrap();
        encode_varint(1 + 2, &mut buf).unwrap();
        encode_varint(2, &mut buf).unwrap(); // 未知 context 2
        buf.extend_from_slice(b"zz");
        buf.extend_from_slice(&frame_datagram_capsule(b"ok").unwrap());
        let mut asm2 = DatagramAssembler::new(Framing::Capsules);
        asm2.push(&buf);
        assert_eq!(asm2.next_event().unwrap(), Some(TunnelEvent::Datagram(b"ok".to_vec())));

        // 空 capsule 载荷（缺 Context ID）必须报错，而不是当成空 UDP 报文
        let mut bad = Vec::new();
        encode_varint(CAPSULE_DATAGRAM, &mut bad).unwrap();
        encode_varint(0, &mut bad).unwrap();
        let mut asm3 = DatagramAssembler::new(Framing::Capsules);
        asm3.push(&bad);
        assert!(asm3.next_event().is_err());
    }

    /// **两种形态不可混**：同样的字节按不同 Framing 解析出的含义不同。
    /// 裸长度前缀形态下 `0x00` 是「长度 0」（空报文）；capsule 形态下它才是类型 DATAGRAM。
    #[test]
    fn framing_modes_differ() {
        // 裸形态：长度 3 + "abc"
        let lp = frame_datagram(b"abc").unwrap();
        let mut a = DatagramAssembler::new(Framing::LengthPrefixed);
        a.push(&lp);
        assert_eq!(a.next_event().unwrap(), Some(TunnelEvent::Datagram(b"abc".to_vec())));

        // 同样字节喂给 capsule 解析器：头字节 0x03 变成「类型 3」、下一字节 0x61 变成
        // 「长度 97」⇒ 字节不足，取不到事件。重点是**不会**把它误判成报文 "abc"。
        let mut b = DatagramAssembler::new(Framing::Capsules);
        b.push(&lp);
        assert_eq!(b.next_event().unwrap(), None, "同一串字节在 capsule 形态下不是报文");
    }

    /// RFC 9297 §3.2：**未知 capsule 类型必须跳过负载**（前向兼容），而不是报错。
    #[test]
    fn unknown_capsule_is_skipped() {
        let mut buf = Vec::new();
        encode_varint(0x1234, &mut buf).unwrap(); // 未知类型
        encode_varint(2, &mut buf).unwrap();
        buf.extend_from_slice(b"xx");
        // 后面跟一个正常 DATAGRAM，必须能接着取到
        buf.extend_from_slice(&frame_datagram_capsule(b"real").unwrap());

        let mut asm = DatagramAssembler::new(Framing::Capsules);
        asm.push(&buf);
        // 第一个事件 = 跳过未知后取到的 DATAGRAM
        assert_eq!(
            asm.next_event().unwrap(),
            Some(TunnelEvent::Datagram(b"real".to_vec()))
        );
    }

    /// RFC 9297 §3.3：CLOSE capsule ⇒ `TunnelEvent::Close`（隧道**正常**收尾，不是错误）。
    #[test]
    fn close_capsule_signals_close() {
        let mut buf = Vec::new();
        encode_varint(CAPSULE_CLOSE, &mut buf).unwrap();
        encode_varint(0, &mut buf).unwrap();
        let mut asm = DatagramAssembler::new(Framing::Capsules);
        asm.push(&buf);
        assert_eq!(asm.next_event().unwrap(), Some(TunnelEvent::Close));
    }

    /// 增量到达（TCP/QUIC 式分片）也要能拼出来：逐字节喂。
    #[test]
    fn capsule_incremental_parse() {
        let framed = frame_datagram_capsule(b"abcd").unwrap();
        let mut asm = DatagramAssembler::new(Framing::Capsules);
        let mut got = None;
        for b in &framed {
            asm.push(&[*b]);
            if let Some(ev) = asm.next_event().unwrap() {
                got = Some(ev);
            }
        }
        assert_eq!(got, Some(TunnelEvent::Datagram(b"abcd".to_vec())));
    }

    /// 伪造的超大 capsule 长度必须报错（否则无界等待/缓存）。
    #[test]
    fn oversized_capsule_rejected() {
        let mut buf = Vec::new();
        encode_varint(CAPSULE_DATAGRAM, &mut buf).unwrap();
        // 上限是 MAX_HTTP_DATAGRAM（= UDP 载荷上限 + 最长 Context ID）
        encode_varint(MAX_HTTP_DATAGRAM as u64 + 1, &mut buf).unwrap();
        let mut asm = DatagramAssembler::new(Framing::Capsules);
        asm.push(&buf);
        assert!(asm.next_event().is_err());
    }
}
