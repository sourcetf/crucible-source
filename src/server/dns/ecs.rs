//! EDNS Client Subnet（RFC7871）注入 —— 递归解析时把客户端子网传给上游/缓存。
//!
//! 规则（需求硬性条款）：
//! - IPv4 一律 **/24**（清零主机位），**绝不出现 /32**
//! - IPv6 一律 /56（业界惯例，同 8 字节边界，无部分字节）
//! - 客户端查询里已有的 ECS 一律**重写**为本机策略（防 /32 泄漏到上游）
//! - scope prefix-length = 0（我们是递归器，非权威）

use std::net::IpAddr;

const OPT_RR_TYPE: u16 = 41;
const ECS_OPTION_CODE: u16 = 8;

/// 在 DNS 查询报文上挂/改 EDNS Client Subnet。失败返回 None（调用方回退为不带 ECS 转发）。
pub fn inject_ecs(msg: &[u8], client: IpAddr) -> Option<Vec<u8>> {
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
    // 扫 additional 段找 OPT（type=41）
    let mut cur = off;
    let mut opt: Option<(usize, usize)> = None; // (start_of_rr, end_of_rr)
    while cur + 1 <= msg.len() {
        let name_end = skip_name(msg, cur)?;
        if name_end + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[name_end], msg[name_end + 1]]);
        let rdlen = u16::from_be_bytes([msg[name_end + 8], msg[name_end + 9]]) as usize;
        let end = name_end + 10 + rdlen;
        if end > msg.len() {
            break;
        }
        if rtype == OPT_RR_TYPE {
            opt = Some((cur, end));
            break;
        }
        cur = end;
    }

    // 旧 OPT 的 payload/DO 位/其他 options（去掉旧 ECS）
    let (payload, ttl_and_flags, other_opts): (u16, [u8; 4], Vec<u8>) = match opt {
        Some((s, _e)) => {
            let ne = skip_name(msg, s)?;
            let cls = u16::from_be_bytes([msg[ne + 2], msg[ne + 3]]);
            let ttl = [msg[ne + 4], msg[ne + 5], msg[ne + 6], msg[ne + 7]];
            let rdlen = u16::from_be_bytes([msg[ne + 8], msg[ne + 9]]) as usize;
            let rdata = &msg[ne + 10..ne + 10 + rdlen];
            let mut others = Vec::new();
            let mut i = 0usize;
            while i + 4 <= rdata.len() {
                let code = u16::from_be_bytes([rdata[i], rdata[i + 1]]);
                let olen = u16::from_be_bytes([rdata[i + 2], rdata[i + 3]]) as usize;
                if i + 4 + olen > rdata.len() {
                    break;
                }
                if code != ECS_OPTION_CODE {
                    others.extend_from_slice(&rdata[i..i + 4 + olen]);
                }
                i += 4 + olen;
            }
            (cls, ttl, others)
        }
        None => (4096, [0; 4], Vec::new()),
    };

    let ecs = ecs_option(client);
    let mut rdata = other_opts;
    rdata.extend_from_slice(&ecs);

    let mut out: Vec<u8> = Vec::with_capacity(msg.len() + 32);
    match opt {
        Some((s, e)) => {
            out.extend_from_slice(&msg[..s]);
            out.extend_from_slice(&msg[e..]);
        }
        None => out.extend_from_slice(msg),
    }
    // 追加 OPT RR：root 名 + OPT + class(payload) + ttl + rdlen + rdata
    out.extend_from_slice(&[0u8]);
    out.extend_from_slice(&OPT_RR_TYPE.to_be_bytes());
    out.extend_from_slice(&payload.to_be_bytes());
    out.extend_from_slice(&ttl_and_flags);
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    // ARCOUNT +1 when inserting OPT; ensure >=1 when replacing a found OPT.
    if opt.is_none() {
        let ar = u16::from_be_bytes([msg[10], msg[11]]).wrapping_add(1);
        out[10] = ar.to_be_bytes()[0];
        out[11] = ar.to_be_bytes()[1];
    } else if u16::from_be_bytes([out[10], out[11]]) == 0 {
        out[10] = 0;
        out[11] = 1;
    }
    Some(out)
}

/// ECS option wire：FAMILY(2) + SRC PREFIX(1) + SCOPE(1) + ADDRESS
fn ecs_option(client: IpAddr) -> Vec<u8> {
    match client {
        IpAddr::V4(v4) => {
            let b = v4.octets();
            // FAMILY=1 (2B) + SOURCE=24 + SCOPE=0 + /24 address (3B). Never /32.
            let mut data = Vec::with_capacity(7);
            data.extend_from_slice(&1u16.to_be_bytes());
            data.push(24);
            data.push(0);
            data.extend_from_slice(&b[..3]);
            wrap_option(data)
        }
        IpAddr::V6(v6) => {
            let b = v6.octets();
            // FAMILY=2 + SOURCE=56 + SCOPE=0 + /56 address (7B).
            let mut data = Vec::with_capacity(11);
            data.extend_from_slice(&2u16.to_be_bytes());
            data.push(56);
            data.push(0);
            data.extend_from_slice(&b[..7]);
            wrap_option(data)
        }
    }
}

fn wrap_option(data: Vec<u8>) -> Vec<u8> {
    let mut o = Vec::with_capacity(4 + data.len());
    o.extend_from_slice(&ECS_OPTION_CODE.to_be_bytes());
    o.extend_from_slice(&(data.len() as u16).to_be_bytes());
    o.extend_from_slice(&data);
    o
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

    #[test]
    fn ecs_v4_is_24_no_32() {
        let q = minimal_query();
        let out = inject_ecs(
            &q,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 255)),
        )
        .unwrap();
        // 找到 OPT 中的 ECS：family=1, src=24
        let s = out.len();
        let body = &out[s - 32..];
        assert!(body.windows(2).any(|w| w == [0, 8]));
        assert!(out.windows(3).any(|w| w == [0, 1, 24] || w == [1, 56, 0]));
        // /32 绝不允许：不存在 src=32
        assert!(!out.windows(3).any(|w| w[0] <= 1 && w[1] == 32));
    }

    #[test]
    fn ecs_replaces_existing_32() {
        // 客户端自带 /32 ECS（坏）——必须被重写为 /24
        let mut q = minimal_query();
        q[11] = 1; // ARCOUNT=1
        // OPT: root + type=41 + class=4096 + ttl0 + rdlen=9
        // + {code=8, len=5, family=1, src=32, scope=0, addr=203}
        q.extend_from_slice(&[
            0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 9, 0, 8, 0, 5, 0, 1, 32, 0, 203,
        ]);
        let out = inject_ecs(&q, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))).unwrap();
        assert!(!out.windows(3).any(|w| w[0] <= 1 && w[1] == 32));
        assert!(out.windows(3).any(|w| w == [0, 1, 24]));
    }
}
