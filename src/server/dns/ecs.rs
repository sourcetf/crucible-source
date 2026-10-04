//! EDNS Client Subnet（RFC 7871）—— DoH/DoT 转发路径的 ECS 注入与应答回显。
//!
//! 入站（客户端 → 本进程 DoH/DoT 层）：
//! - 客户端查询**没带** ECS：按本机策略生成 —— IPv4 /24、IPv6 /56（同 8 字节边界）。
//! - 客户端查询**带了** ECS：RFC 7871 §7.1.1/§11.1 要求出站 SOURCE 不得比入站长
//!   （**MUST NOT 扩展客户端前缀**）。出站 SOURCE = min(入站 SOURCE, 本机上限
//!   /24 或 /56)，地址同步截断/清零；SCOPE 恒为 0（我们是递归器，非权威）。
//! - 入站 SOURCE=0 是隐私退出（§7.1.2/§7.5）：出站保持 SOURCE=0 且不带地址，
//!   **绝不**用查询源 IP 重新生成 —— 那正是用户明确要求不要做的事。
//! - 畸形 ECS（未知 FAMILY、地址长度与 SOURCE 不符、同一 OPT 里多个 ECS）不转发
//!   该 option；[`malformed_ecs`] 供调用方按 §7.2.1 回 FORMERR 时判定。
//!
//! 出站（应答 → 客户端，RFC 7871 §7.2.2）：[`apply_response_ecs`] 在应答里回显
//! ECS option —— 上游响应已带 ECS 者原样保留，否则按查询的 FAMILY/SOURCE/ADDRESS
//! 回显、SCOPE=0（BIND 不会回 ECS，权威 scope 本层无法知道；见下）。
//!
//! 传输限制（诚实降级，勿把本模块当"递归已传 ECS"）：
//! 注入点在本进程 DoH/DoT 层，收件人是**本机 BIND 9**（127.0.0.1 / 分线路
//! 127.0.0.(2+i)）。BIND 9.20 不实现 ECS，也不会把未知 EDNS option 带进它自己的
//! 递归/转发查询 —— 因此注入的 ECS 只到了本机 named 就被丢弃，**到不了真正的上游**；
//! 应答回显也只能由本层合成（SCOPE 只能给 0）。要让 ECS 真正生效，需把上游换成支持
//! ECS 的递归器（如 Unbound send-client-subnet），或在 Rust 侧实现上游递归。
//! 本模块只保证 wire 格式与出站策略正确，不假装传输层已经支持。

use std::net::IpAddr;

use crate::server::geoip_panel::iputil::unmap_v4_mapped;

const OPT_RR_TYPE: u16 = 41;
const ECS_OPTION_CODE: u16 = 8;
/// IPv4 出站 SOURCE 上限（绝不出现 /32）。
const DEFAULT_V4_SOURCE: u8 = 24;
/// IPv6 出站 SOURCE 上限（同 8 字节边界，无部分字节）。
const DEFAULT_V6_SOURCE: u8 = 56;
/// 插入新 OPT 时的默认 UDP payload。
const DEFAULT_UDP_PAYLOAD: u16 = 4096;

/// 解析出的 ECS option（FAMILY/SOURCE/SCOPE + 地址原文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcsOption {
    pub family: u16,
    pub source: u8,
    pub scope: u8,
    pub address: Vec<u8>,
}

/// 报文里找到的 OPT RR。
struct OptFound {
    start: usize,
    end: usize,
    payload: u16,
    ttl: [u8; 4],
    rdata: Vec<u8>,
}

/// OPT rdata 里各 EDNS option 的解析结果。
///
/// `tail`：无法按 TLV 解析的剩余字节（olen 越界或不足 4 字节的表尾）。原实现遇到
/// 越界直接 `break`，把其后的 COOKIE/Padding 等 option **静默丢弃**后照样转发；
/// 这里原样保留，转发时不丢任何调用方数据。
#[derive(Default)]
struct ParsedOptions {
    others: Vec<u8>,
    ecs: Option<EcsOption>,
    ecs_count: usize,
    tail: Vec<u8>,
}

/// 在 DNS 查询报文上挂/改 EDNS Client Subnet。失败返回 None（调用方回退为不带 ECS 转发）。
pub fn inject_ecs(msg: &[u8], client: IpAddr) -> Option<Vec<u8>> {
    let off = question_end(msg)?;
    let opt = find_opt(msg, off);
    let client = unmap_v4_mapped(client);
    let (payload, ttl, parsed) = match &opt {
        Some(o) => (o.payload, o.ttl, parse_options(&o.rdata)),
        None => (DEFAULT_UDP_PAYLOAD, [0u8; 4], ParsedOptions::default()),
    };

    let ecs = match parsed.ecs {
        // 畸形 ECS（含多个 ECS option）：不注入、不放行任何客户端地址；
        // 调用方可用 malformed_ecs() 判定并按 §7.2.1 回 FORMERR。
        Some(_) if parsed.ecs_count > 1 => None,
        Some(e) if !ecs_valid(&e) => None,
        // 隐私退出：保持 SOURCE=0、地址为空。
        Some(e) if e.source == 0 => Some(ecs_option_wire(e.family, 0, 0, &[])),
        // 保留客户端前缀长度，只允许收窄到本机上限；地址取自入站 ECS（不是查询源 IP）。
        Some(e) => {
            let src = clamp_source(e.family, e.source);
            let addr = truncate_address(e.family, &e.address, src);
            Some(ecs_option_wire(e.family, src, 0, &addr))
        }
        // 入站缺失：按本机策略从客户端地址生成。
        None => {
            let (family, src, addr) = default_ecs(&client);
            Some(ecs_option_wire(family, src, 0, &addr))
        }
    };

    let mut rdata = parsed.others;
    rdata.extend_from_slice(&parsed.tail);
    if let Some(x) = ecs {
        rdata.extend_from_slice(&x);
    }
    Some(splice_opt(msg, opt.as_ref(), payload, ttl, &rdata))
}

/// 供调用方判定：查询里的 ECS 是否畸形（RFC 7871 §6/§7.2.1 应回 FORMERR）。
///
/// 判据：同一 OPT 里出现多个 ECS option；FAMILY 不是 1/2；SOURCE 超出该族位宽；
/// ADDRESS 字节数少于 SOURCE 所需、或超出该族完整长度；SOURCE 之外的尾随位非零。
pub fn malformed_ecs(msg: &[u8]) -> bool {
    let Some(off) = question_end(msg) else {
        return false;
    };
    let Some(opt) = find_opt(msg, off) else {
        return false;
    };
    let parsed = parse_options(&opt.rdata);
    match parsed.ecs {
        Some(e) => parsed.ecs_count > 1 || !ecs_valid(&e),
        None => false,
    }
}

/// RFC 7871 §7.2.2：客户端查询**带** ECS 时，应答必须回带 ECS option。
///
/// - 查询没带 ECS → 应答原样返回。
/// - 应答已带 ECS（上游权威返回的 FAMILY/SOURCE/SCOPE）→ 原样返回，不覆盖上游 scope。
/// - 应答未带（BIND 的常态）→ 按查询的 FAMILY/SOURCE/ADDRESS 回显，SCOPE=0。
///
/// 调用方应传入**注入前**的原始查询 wire（客户端真实请求）。
pub fn apply_response_ecs(query: &[u8], response: &[u8]) -> Vec<u8> {
    let Some(q_off) = question_end(query) else {
        return response.to_vec();
    };
    let q_ecs = match find_opt(query, q_off) {
        Some(o) => parse_options(&o.rdata).ecs,
        None => None,
    };
    let Some(q) = q_ecs else {
        return response.to_vec();
    };
    let Some(r_off) = question_end(response) else {
        return response.to_vec();
    };
    let opt = find_opt(response, r_off);
    if let Some(o) = &opt {
        let parsed = parse_options(&o.rdata);
        // 上游已经回了 ECS：保留上游的 scope（我们不知道真实 scope，无权改写）。
        if parsed.ecs.is_some() && parsed.ecs_count == 1 {
            return response.to_vec();
        }
    }
    // 按查询回显：FAMILY/SOURCE/ADDRESS 与查询一致，SCOPE=0。
    let mut rdata = match &opt {
        Some(o) => parse_options(&o.rdata).others,
        None => Vec::new(),
    };
    let addr = truncate_address(q.family, &q.address, q.source);
    rdata.extend_from_slice(&ecs_option_wire(q.family, q.source, 0, &addr));
    match opt {
        Some(o) => splice_opt(response, Some(&o), o.payload, o.ttl, &rdata),
        None => splice_opt(response, None, DEFAULT_UDP_PAYLOAD, [0u8; 4], &rdata),
    }
}

/// 按 FAMILY 收窄 SOURCE PREFIX-LENGTH（只缩不放）。
fn clamp_source(family: u16, source: u8) -> u8 {
    match family {
        2 => source.min(DEFAULT_V6_SOURCE),
        _ => source.min(DEFAULT_V4_SOURCE),
    }
}

/// 从客户端地址生成默认 ECS（v4-mapped 已折回 v4）。
fn default_ecs(client: &IpAddr) -> (u16, u8, Vec<u8>) {
    match client {
        IpAddr::V4(v4) => {
            let src = DEFAULT_V4_SOURCE;
            (1, src, truncate_address(1, &v4.octets(), src))
        }
        IpAddr::V6(v6) => {
            let src = DEFAULT_V6_SOURCE;
            (2, src, truncate_address(2, &v6.octets(), src))
        }
    }
}

/// 地址截断到 SOURCE 位：保留 ceil(source/8) 字节，最后一个字节的高位以外清零。
fn truncate_address(family: u16, addr: &[u8], source: u8) -> Vec<u8> {
    let full = if family == 2 { 16 } else { 4 };
    let need = ((source as usize) + 7) / 8;
    let n = need.min(full);
    let mut out = vec![0u8; n];
    for (dst, src) in out.iter_mut().zip(addr.iter().take(n)) {
        *dst = *src;
    }
    if let Some(last) = out.last_mut() {
        let rem = source % 8;
        if rem != 0 {
            *last &= 0xFFu8 << (8 - rem);
        }
    }
    out
}

/// RFC 7871 §6 合法性：FAMILY ∈ {1,2}；SOURCE ≤ 位宽；ADDRESS 长度足够且不超过该族
/// 完整长度（实现允许发完整长度地址，尾随零必须为零）；SOURCE 外尾随位为零。
fn ecs_valid(e: &EcsOption) -> bool {
    let max_bits: u8 = match e.family {
        1 => 32,
        2 => 128,
        _ => return false,
    };
    if e.source > max_bits {
        return false;
    }
    let need = ((e.source as usize) + 7) / 8;
    if e.address.len() < need {
        return false;
    }
    let full = if e.family == 2 { 16 } else { 4 };
    if e.address.len() > full {
        return false;
    }
    if e.address[need..].iter().any(|b| *b != 0) {
        return false;
    }
    if e.source % 8 != 0 && e.address.len() >= need && need > 0 {
        let mask = 0xFFu8 << (8 - (e.source % 8));
        if e.address[need - 1] & !mask != 0 {
            return false;
        }
    }
    true
}

/// ECS option wire：FAMILY(2) + SRC PREFIX(1) + SCOPE(1) + ADDRESS
fn ecs_option_wire(family: u16, source: u8, scope: u8, addr: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + addr.len());
    data.extend_from_slice(&family.to_be_bytes());
    data.push(source);
    data.push(scope);
    data.extend_from_slice(addr);
    wrap_option(data)
}

fn wrap_option(data: Vec<u8>) -> Vec<u8> {
    let mut o = Vec::with_capacity(4 + data.len());
    o.extend_from_slice(&ECS_OPTION_CODE.to_be_bytes());
    o.extend_from_slice(&(data.len() as u16).to_be_bytes());
    o.extend_from_slice(&data);
    o
}

/// 用新的 OPT rdata 替换/追加 OPT，并同步 ARCOUNT。
fn splice_opt(msg: &[u8], opt: Option<&OptFound>, payload: u16, ttl: [u8; 4], rdata: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(msg.len() + rdata.len() + 11);
    match opt {
        Some(o) => {
            out.extend_from_slice(&msg[..o.start]);
            out.extend_from_slice(&msg[o.end..]);
        }
        None => out.extend_from_slice(msg),
    }
    // 追加 OPT RR：root 名 + OPT + class(payload) + ttl + rdlen + rdata
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

/// 跳过一个（可能带压缩指针的）域名，返回名字之后的偏移。
fn skip_name(msg: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let l = *msg.get(off)?;
        if l & 0xC0 == 0xC0 {
            return Some(off + 2);
        }
        if l == 0 {
            return Some(off + 1);
        }
        off = off.checked_add(1 + l as usize)?;
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
        off = skip_name(msg, off)?;
        off = off.checked_add(4)?;
        if off > msg.len() {
            return None;
        }
    }
    Some(off)
}

/// 从 `off` 起扫所有 RR 段找 OPT（type=41）。
fn find_opt(msg: &[u8], mut cur: usize) -> Option<OptFound> {
    while cur + 1 <= msg.len() {
        let name_end = skip_name(msg, cur)?;
        if name_end + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[name_end], msg[name_end + 1]]);
        let cls = u16::from_be_bytes([msg[name_end + 2], msg[name_end + 3]]);
        let ttl = [
            msg[name_end + 4],
            msg[name_end + 5],
            msg[name_end + 6],
            msg[name_end + 7],
        ];
        let rdlen = u16::from_be_bytes([msg[name_end + 8], msg[name_end + 9]]) as usize;
        let end = name_end + 10 + rdlen;
        if end > msg.len() {
            break;
        }
        if rtype == OPT_RR_TYPE {
            return Some(OptFound {
                start: cur,
                end,
                payload: cls,
                ttl,
                rdata: msg[name_end + 10..end].to_vec(),
            });
        }
        cur = end;
    }
    None
}

fn parse_options(rdata: &[u8]) -> ParsedOptions {
    let mut p = ParsedOptions::default();
    let mut i = 0usize;
    while i + 4 <= rdata.len() {
        let code = u16::from_be_bytes([rdata[i], rdata[i + 1]]);
        let olen = u16::from_be_bytes([rdata[i + 2], rdata[i + 3]]) as usize;
        if i + 4 + olen > rdata.len() {
            // 畸形 option：剩余字节原样保留（原来直接 break 丢光其后的 option）。
            p.tail = rdata[i..].to_vec();
            return p;
        }
        if code == ECS_OPTION_CODE {
            p.ecs_count += 1;
            if p.ecs.is_none() {
                if olen >= 4 {
                    let body = &rdata[i + 4..i + 4 + olen];
                    p.ecs = Some(EcsOption {
                        family: u16::from_be_bytes([body[0], body[1]]),
                        source: body[2],
                        scope: body[3],
                        address: body[4..].to_vec(),
                    });
                } else {
                    // 截断的 ECS option（连 4 字节头都不全）：family=0 令其必判畸形。
                    p.ecs = Some(EcsOption {
                        family: 0,
                        source: 0,
                        scope: 0,
                        address: Vec::new(),
                    });
                }
            }
        } else {
            p.others.extend_from_slice(&rdata[i..i + 4 + olen]);
        }
        i += 4 + olen;
    }
    if i < rdata.len() {
        p.tail = rdata[i..].to_vec();
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn minimal_query() -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[2] = 0x01; // RD
        m[4] = 0;
        m[5] = 1; // QDCOUNT=1
        m.extend_from_slice(&[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        m.extend_from_slice(&[0, 1, 0, 1]); // A IN
        m
    }

    fn ecs_option_bytes(family: u16, source: u8, scope: u8, addr: &[u8]) -> Vec<u8> {
        ecs_option_wire(family, source, scope, addr)
    }

    /// 在查询上追加 OPT（含给定 rdata）：ARCOUNT=1。
    fn query_with_opt(mut q: Vec<u8>, rdata: &[u8]) -> Vec<u8> {
        q[11] = 1;
        q.push(0);
        q.extend_from_slice(&OPT_RR_TYPE.to_be_bytes());
        q.extend_from_slice(&4096u16.to_be_bytes());
        q.extend_from_slice(&[0, 0, 0, 0]);
        q.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        q.extend_from_slice(rdata);
        q
    }

    fn out_ecs(out: &[u8]) -> Option<EcsOption> {
        let off = question_end(out)?;
        let opt = find_opt(out, off)?;
        parse_options(&opt.rdata).ecs
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn absent_inbound_generates_v4_24() {
        let q = minimal_query();
        let out = inject_ecs(&q, v4(203, 0, 113, 255)).unwrap();
        let e = out_ecs(&out).expect("must inject ECS");
        assert_eq!((e.family, e.source, e.scope), (1, 24, 0));
        assert_eq!(e.address, vec![203, 0, 113]);
        // /32 绝不允许：不存在 src=32
        assert!(!out.windows(3).any(|w| w[0] <= 1 && w[1] == 32));
    }

    #[test]
    fn absent_inbound_v4_mapped_client_folds_to_v4() {
        let q = minimal_query();
        let client = "::ffff:198.51.100.7".parse().unwrap();
        let out = inject_ecs(&q, client).unwrap();
        let e = out_ecs(&out).expect("must inject ECS");
        assert_eq!((e.family, e.source), (1, 24));
        assert_eq!(e.address, vec![198, 51, 100]);
    }

    #[test]
    fn absent_inbound_v6_uses_56() {
        let q = minimal_query();
        let client: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let out = inject_ecs(&q, client).unwrap();
        let e = out_ecs(&out).expect("must inject ECS");
        assert_eq!((e.family, e.source), (2, 56));
        assert_eq!(e.address, vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00]);
    }

    /// RFC 7871 §7.1.1：客户端 /16 不能被扩成 /24，地址取入站 ECS 而非查询源 IP。
    #[test]
    fn inbound_short_prefix_is_preserved_not_expanded() {
        let q = query_with_opt(
            minimal_query(),
            &ecs_option_bytes(1, 16, 0, &[203, 0]),
        );
        let out = inject_ecs(&q, v4(198, 51, 100, 7)).unwrap();
        let e = out_ecs(&out).expect("must keep ECS");
        assert_eq!((e.family, e.source, e.scope), (1, 16, 0));
        assert_eq!(e.address, vec![203, 0]);
        assert!(!out.windows(3).any(|w| w == [198, 51, 100]));
    }

    /// RFC 7871 §7.1.2/§7.5：入站 /0 = 隐私退出，出站必须保持 /0 且不带地址。
    #[test]
    fn inbound_zero_is_privacy_exit() {
        let q = query_with_opt(minimal_query(), &ecs_option_bytes(1, 0, 0, &[]));
        let out = inject_ecs(&q, v4(198, 51, 100, 7)).unwrap();
        let e = out_ecs(&out).expect("must keep ECS with source 0");
        assert_eq!((e.family, e.source, e.scope), (1, 0, 0));
        assert!(e.address.is_empty());
        assert!(!out.windows(3).any(|w| w == [198, 51, 100]));
    }

    /// 入站 /32 只收窄到本机 /24（不扩），地址来自入站 ECS。
    #[test]
    fn inbound_long_prefix_is_capped_to_24() {
        let q = query_with_opt(
            minimal_query(),
            &ecs_option_bytes(1, 32, 0, &[203, 0, 113, 5]),
        );
        let out = inject_ecs(&q, v4(198, 51, 100, 7)).unwrap();
        let e = out_ecs(&out).expect("must keep ECS");
        assert_eq!((e.family, e.source), (1, 24));
        assert_eq!(e.address, vec![203, 0, 113]);
    }

    #[test]
    fn inbound_v6_48_is_kept() {
        let addr = (0x20u8, 0x01, 0x0d, 0xb8, 0x00, 0x2a);
        let q = query_with_opt(
            minimal_query(),
            &ecs_option_bytes(2, 48, 0, &[addr.0, addr.1, addr.2, addr.3, addr.4, addr.5]),
        );
        let out = inject_ecs(&q, v4(198, 51, 100, 7)).unwrap();
        let e = out_ecs(&out).expect("must keep ECS");
        assert_eq!((e.family, e.source), (2, 48));
        assert_eq!(e.address, vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x2a]);
    }

    /// 未知 FAMILY 的 ECS 属畸形：不注入、不放行地址，但查询其余部分照常转发。
    #[test]
    fn malformed_unknown_family_is_not_forwarded() {
        let q = query_with_opt(minimal_query(), &ecs_option_bytes(3, 24, 0, &[1, 2, 3]));
        assert!(malformed_ecs(&q));
        let out = inject_ecs(&q, v4(198, 51, 100, 7)).unwrap();
        assert!(out_ecs(&out).is_none());
        assert!(!out.windows(3).any(|w| w == [198, 51, 100]));
    }

    #[test]
    fn malformed_ecs_detects_duplicate_and_short_address() {
        let mut dup = query_with_opt(minimal_query(), &ecs_option_bytes(1, 24, 0, &[1, 2, 3]));
        // 再塞第二个 ECS option 到同一 OPT rdata 尾部（手工：把 rdlen 后追加）。
        let extra = ecs_option_bytes(1, 24, 0, &[4, 5, 6]);
        let n = dup.len();
        dup[n - 1] += extra.len() as u8; // rdlen 低位（测试里 rdata 很小，不会进位）
        dup.extend_from_slice(&extra);
        assert!(malformed_ecs(&dup));
        // ADDRESS 少于 SOURCE 所需字节。
        let short = query_with_opt(minimal_query(), &ecs_option_bytes(1, 24, 0, &[1, 2]));
        assert!(malformed_ecs(&short));
        // 正常查询不带 ECS：不是畸形。
        assert!(!malformed_ecs(&minimal_query()));
    }

    /// 无 ECS 的查询：应答原样返回。
    #[test]
    fn response_untouched_without_query_ecs() {
        let q = minimal_query();
        let mut resp = q.clone();
        resp[2] |= 0x80;
        assert_eq!(apply_response_ecs(&q, &resp), resp);
    }

    /// RFC 7871 §7.2.2：查询带 ECS，应答必须回显（SCOPE=0）。
    #[test]
    fn response_echoes_query_ecs() {
        let q = query_with_opt(
            minimal_query(),
            &ecs_option_bytes(1, 24, 0, &[203, 0, 113]),
        );
        let mut resp = minimal_query();
        resp[2] |= 0x80; // QR
        let out = apply_response_ecs(&q, &resp);
        let e = out_ecs(&out).expect("response must carry ECS");
        assert_eq!((e.family, e.source, e.scope), (1, 24, 0));
        assert_eq!(e.address, vec![203, 0, 113]);
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 1, "ARCOUNT 要计入新增 OPT");
    }

    /// 查询带 /0 隐私退出：应答同样回显 /0（不带地址）。
    #[test]
    fn response_echoes_zero_source() {
        let q = query_with_opt(minimal_query(), &ecs_option_bytes(1, 0, 0, &[]));
        let mut resp = minimal_query();
        resp[2] |= 0x80;
        let out = apply_response_ecs(&q, &resp);
        let e = out_ecs(&out).expect("response must echo ECS");
        assert_eq!((e.family, e.source, e.scope), (1, 0, 0));
        assert!(e.address.is_empty());
    }

    /// 上游已回 ECS（含真实 scope）→ 不覆盖。
    #[test]
    fn response_keeps_upstream_ecs_scope() {
        let q = query_with_opt(
            minimal_query(),
            &ecs_option_bytes(1, 24, 0, &[203, 0, 113]),
        );
        let mut resp = minimal_query();
        resp[2] |= 0x80;
        let resp = query_with_opt(resp, &ecs_option_bytes(1, 24, 20, &[203, 0, 113]));
        let out = apply_response_ecs(&q, &resp);
        assert_eq!(out, resp);
        let e = out_ecs(&out).unwrap();
        assert_eq!(e.scope, 20);
    }

    #[test]
    fn response_replaces_existing_opt_options_without_ecs() {
        // 应答 OPT 里已有 COOKIE（code=10），回显 ECS 时不能丢。
        let mut cookie = Vec::new();
        cookie.extend_from_slice(&10u16.to_be_bytes());
        cookie.extend_from_slice(&4u16.to_be_bytes());
        cookie.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let q = query_with_opt(minimal_query(), &ecs_option_bytes(1, 24, 0, &[203, 0, 113]));
        let mut resp = minimal_query();
        resp[2] |= 0x80;
        let resp = query_with_opt(resp, &cookie);
        let out = apply_response_ecs(&q, &resp);
        assert!(out.windows(4).any(|w| w == [0, 10, 0, 4]), "COOKIE 必须保留");
        let e = out_ecs(&out).expect("ECS 必须回显");
        assert_eq!(e.address, vec![203, 0, 113]);
    }
}
