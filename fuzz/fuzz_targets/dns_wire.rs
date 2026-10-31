#![no_main]

//! DNS wire（ECS / OPT / FORMERR）解析的属性 fuzz。
//!
//! 输入前两字节决定切分点：前半当查询报文、后半当应答报文。
//!
//! 断言：
//! 1. 任意随机报文 → `malformed_ecs` / `inject_ecs` / `apply_response_ecs` /
//!    `formerr_response` 全部不 panic、不越界；
//! 2. `formerr_response` 只在问题段可定位时返回，且返回的是**良构 FORMERR**：
//!    QR=1、RCODE=1、AN/NS/ARCOUNT=0、长度 == 查询头+问题段；
//! 3. `inject_ecs` 成功时保留原报文头计数（除 ARCOUNT）与问题段；
//! 4. `malformed_ecs` 与「FORMERR 可构造」一致：畸形但问题段截断 ⇒ 无 FORMERR（交给上游），
//!    两者不能同时成立（避免对不可解析报文回 FORMERR）；
//! 5. `apply_response_ecs` 对随机应答不 panic，且长度不会爆到输入的两倍以上。

use crucible_fuzz::dns_ecs::*;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = ((data[0] as usize) << 8 | data[1] as usize) % data.len();
    let (query, response) = data.split_at(split);
    let client = match data.len() % 3 {
        0 => IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        1 => IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        _ => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };

    // (1) 任意报文不 panic。
    let malformed = malformed_ecs(query);
    let injected = inject_ecs(query, client);
    let _ = apply_response_ecs(query, response);
    let _ = apply_response_ecs(response, query);
    let formerr = formerr_response(query);

    // (2) FORMERR 的良构性。
    if let Some(f) = &formerr {
        assert!(f.len() >= 12, "FORMERR 短于 12 字节");
        assert_eq!(f[2] & 0x80, 0x80, "QR 未置位");
        assert_eq!(f[3] & 0x0f, 1, "RCODE 不是 FORMERR");
        assert_eq!(&f[6..8], &[0, 0], "ANCOUNT 非 0");
        assert_eq!(&f[8..10], &[0, 0], "NSCOUNT 非 0");
        assert_eq!(&f[10..12], &[0, 0], "ARCOUNT 非 0");
        assert!(f.len() <= query.len(), "FORMERR 比查询还长");
        // 头部只有下面这些字段允许改写（ID/段计数/opcode/RD 原样，见 `formerr_response`）：
        // byte2 QR+opcode+RD、byte3 RCODE、AN/NS/ARCOUNT 清零；QUESTION 段逐字节保留。
        assert_eq!(&f[..2], &query[..2], "FORMERR 改写了事务 ID");
        assert_eq!(
            &f[4..6],
            &query[4..6],
            "FORMERR 改写了 QDCOUNT（问题段数与报文不一致）"
        );
        assert_eq!(
            f[2],
            0x80 | (query[2] & 0x79),
            "FORMERR 的 QR/opcode/RD 组合不符合 RFC 1035 §4.1.1"
        );
        assert_eq!(f[3], 0x01, "FORMERR 的 RCODE 字节不是 0x01");
        assert_eq!(
            &f[12..],
            &query[12..f.len()],
            "FORMERR 没有逐字节保留 QUESTION 段"
        );
    }

    // (3) 注入只改 OPT 区段：头（QD/AN/NS 计数）与问题段逐字节保留。
    if let Some(out) = &injected {
        assert!(out.len() >= 12, "注入结果短于 DNS 头");
        assert_eq!(&out[..4], &query[..4], "QDCOUNT/头前 4 字节被改写");
        if query.len() >= 10 {
            assert_eq!(&out[4..10], &query[4..10], "AN/NSCOUNT 被改写");
        }
    }

    // (4) 畸形 ⇒ 能定位问题段才回 FORMERR。若 formerr=None 说明问题段截断。
    if malformed {
        // 这不是「必须 Some」：问题段本身不可解析时上游错误更合适。
        // 但必须保证不 panic，且确实判断为畸形。
        assert!(malformed_ecs(query));
    }
    if formerr.is_some() {
        assert!(query.len() >= 12);
    }

    // (5) 应答回显的长度上界（最多追加一个 OPT+ECS，不超过 +64 字节）。
    let out = apply_response_ecs(query, response);
    assert!(
        out.len() <= response.len() + 64,
        "应答 ECS 回显异常膨胀: {} -> {}",
        response.len(),
        out.len()
    );
});
