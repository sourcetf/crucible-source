//! HTTP Basic authentication helpers.

use crate::config::{AdminConfig, BasicAuthConfig};
use crate::server::password;
use http::header::{self, HeaderMap};
use http::{Request, StatusCode};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// True when admin panel must require credentials.
///
/// 恒为 true（fail-closed）：admin 面板是远程控制面（改配置、写文件、跑 DNS、
/// 签发证书）。此前实现是「有用户才鉴权」，于是配置里没有 `[[admin.users]]` 时
/// 整个面板**完全无认证**，任何能访问 `/__admin` 的人都能改配置、上传文件、
/// 下发 DNS 与证书操作。配置缺失是运维疏忽，不能变成免认证后门。
pub fn admin_requires_auth(_admin: &AdminConfig) -> bool {
    true
}

/// 泛型化：admin 入口可能收到 Request<Incoming>（h1）或 Request<BoxBody>（h2/h3 复用
/// 完整 admin::handle），鉴权只读 headers，与 body 类型无关。
pub fn check_admin<T>(req: &Request<T>, admin: &AdminConfig) -> bool {
    check_admin_headers(req.headers(), admin)
}

pub fn check_admin_headers(headers: &HeaderMap, admin: &AdminConfig) -> bool {
    if admin.users.is_empty() {
        // 未配置任何用户 → 拒绝，而不是放行。启动时会打 warn 提示补配置。
        log::warn!("admin: no [[admin.users]] configured; admin panel is inaccessible");
        return false;
    }
    // Only users with a real hash participate; empty-hash entries never grant access.
    let active: Vec<_> = admin
        .users
        .iter()
        .filter(|u| !u.password_hash.is_empty())
        .collect();
    if active.is_empty() {
        // Users listed but none have passwords yet — deny (force set password first).
        return false;
    }
    // 同一请求会走两次这里（入口门 + admin::handle），见 ADMIN_OK 的说明：
    // 刚刚验过的那条凭据直接命中，第二次不再跑 argon2id。
    let auth = headers.get(header::AUTHORIZATION);
    let fp = admin_users_fp(admin);
    if let Some(v) = auth {
        if admin_ok_hit(fp, v.as_bytes()) {
            return true;
        }
    }
    let ok = active
        .iter()
        .any(|u| check_user_pass_headers(headers, &u.username, &u.password_hash));
    if ok {
        if let Some(v) = auth {
            admin_ok_remember(fp, v.as_bytes());
        }
    }
    ok
}

// ===== 「刚刚验过」的成功备忘（口令只验一次）=====

/// 刚通过的 admin 凭据备忘。
///
/// 为什么需要：同一份 headers 目前会验**两次** —— 先是三协议入口的
/// [`admin_gate`]（为了不通过鉴权就一个字节 body 都不收），再是 `admin::handle`
/// 开头的那次鉴权。两次都跑 argon2id 等于把管理口令校验的 CPU 成本翻倍，而这
/// 在管理面是纯浪费：headers 没变、用户表没变，结论必然一样。
///
/// 安全性要点：
/// - 只记**成功**的凭据。失败路径（含「用户不存在」）照旧每次都真跑 argon2，
///   对外仍与「口令错误」不可区分，恒定时间语义不变。
/// - 键里带用户表指纹：改口令/加删用户/换 realm 立刻失效，不存在「改了口令还能
///   凭旧结论进门」。
/// - 命中的前提是本次请求带的 `Authorization` 与刚刚验过的那条**逐字节相同** ——
///   也就是说对方已经持有有效凭据，备忘不会给任何人多一分权限。
static ADMIN_OK: Lazy<Mutex<Option<AdminOkMemo>>> = Lazy::new(|| Mutex::new(None));

/// 备忘有效期：覆盖「过门 → 收 body（上限 32MiB，慢链路要几秒）→ admin::handle」
/// 这段窗口；再长没有必要（下一个请求重新验一次的成本本就该付）。
const ADMIN_OK_TTL: Duration = Duration::from_secs(30);

struct AdminOkMemo {
    /// 用户表指纹，见 [`admin_users_fp`]。
    fp: u64,
    /// 通过校验的 `Authorization` 头原文。
    auth: Vec<u8>,
    at: Instant,
}

/// 用户表指纹（用户名 + 口令哈希 + realm）：任何一项变了指纹就变，备忘自动失效。
fn admin_users_fp(admin: &AdminConfig) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    admin.realm.hash(&mut h);
    for u in &admin.users {
        u.username.hash(&mut h);
        u.password_hash.hash(&mut h);
    }
    h.finish()
}

fn admin_ok_hit(fp: u64, auth: &[u8]) -> bool {
    let g = ADMIN_OK.lock();
    match &*g {
        Some(m) => m.fp == fp && m.auth.as_slice() == auth && m.at.elapsed() <= ADMIN_OK_TTL,
        None => false,
    }
}

fn admin_ok_remember(fp: u64, auth: &[u8]) {
    *ADMIN_OK.lock() = Some(AdminOkMemo {
        fp,
        auth: auth.to_vec(),
        at: Instant::now(),
    });
}

/// h1 入口：listener 级 Basic Auth（带来源 IP 的失败退避，见文末 FailTable）。
/// 泛型化：admin 入口可能收到 Request<Incoming>（h1）或 Request<BoxBody>（h2/h3 复用
/// 完整 admin::handle），鉴权只读 headers，与 body 类型无关。
pub fn check_listener<T>(req: &Request<T>, ba: &BasicAuthConfig, ip: IpAddr) -> BasicCheck {
    check_listener_headers_at(req.headers(), ba, ip)
}

/// 供 h2/h3 复用：无 Request 包装，直接对 headers 校验 listener 级 Basic Auth。
pub fn check_listener_headers(headers: &HeaderMap, ba: &BasicAuthConfig) -> bool {
    check_user_pass_headers(headers, &ba.username, &ba.password_hash)
}

/// 带退避的 listener 级校验（h2/h3 与 h1 共用同一语义）。
pub fn check_listener_headers_at(
    headers: &HeaderMap,
    ba: &BasicAuthConfig,
    ip: IpAddr,
) -> BasicCheck {
    // 退避期内**不跑 argon2**：否则「退避」只是回个错，CPU 照样被每次尝试烧掉，
    // 攻击者用错口令并发打过来仍然能把 argon2 打满。
    if let Some(d) = LISTENER_FAILS.blocked(ip) {
        return BasicCheck::Throttled(d);
    }
    if check_listener_headers(headers, ba) {
        LISTENER_FAILS.note_success(ip);
        BasicCheck::Ok
    } else {
        LISTENER_FAILS.note_failure(ip);
        BasicCheck::Unauthorized
    }
}

fn check_user_pass_headers(headers: &HeaderMap, username: &str, password_hash: &str) -> bool {
    if password_hash.is_empty() {
        return false;
    }
    let Some(val) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = val.to_str() else {
        return false;
    };
    let Some(b64) = s.strip_prefix("Basic ") else {
        return false;
    };
    let decoded = decode_base64(b64.trim()).unwrap_or_default();
    let text = String::from_utf8_lossy(&decoded);
    let Some((user, pass)) = text.split_once(':') else {
        return false;
    };
    if !ct_eq_str(user, username) {
        return false;
    }
    password::verify_password(pass, password_hash).unwrap_or(false)
}

/// 用户名常量时间比较（P2，§16.13）：密码本身已由 argon2id/yescrypt 恒时验证，
/// 这里消除用户名比较的分支时序。长度不等时提前返回——只泄漏长度差，可接受。
fn ct_eq_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = val(bytes[i + 2])?;
        let d = val(bytes[i + 3])?;
        out.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((c << 6) | d);
        }
        i += 4;
    }
    Some(out)
}

// ===== 失败退避 / 失败锁定（按来源 IP）=====
//
// 为什么必须加：每次校验都要跑一遍 argon2id（yescrypt 同样慢），这是**故意**的
// 口令哈希成本，但此前没有任何失败计数——于是两件事同时成立：
//   1. 在线爆破：可以无限次尝试管理口令；
//   2. CPU 放大：`POST /__admin/...` 不带凭据/带错口令并发打过来，每个请求都换一次
//      百毫秒级的 argon2，几台肉鸡就能把 CPU 打满（连带拖垮所有 listener 的静态服务）。
// 参数刻意保守，避免误伤真人管理员：只在**同一来源 IP 同一作用域**连续失败到阈值后
// 才开始退避，退避有上界（≤64s），任何一次成功立刻清零，超过窗口没失败也清零。

/// Listener 级校验的失败计数。
static LISTENER_FAILS: Lazy<FailTable> = Lazy::new(FailTable::new);
/// admin 路径校验的失败计数。
///
/// 为什么与 listener 分开记：两条链路可以在同一 IP 上「先成功后失败」——
/// listener Basic 过了、admin Basic 没过。若共用一份计数，每次请求的 listener 成功
/// 都会把 admin 的失败计数清零，admin 口令爆破就永远不会触发退避。
static ADMIN_FAILS: Lazy<FailTable> = Lazy::new(FailTable::new);

/// 连续失败多少次后进入退避（前几次立即返回错误，够真人改对口令）。
const FAIL_THRESHOLD: u32 = 8;
/// 退避时长上界（防止把合法管理员长期锁在门外）。
const MAX_BLOCK: Duration = Duration::from_secs(300);
/// 计数有效期：距上次失败超过这么久则计数清零。
const FAIL_WINDOW: Duration = Duration::from_secs(900);
/// 表容量上限（无界内存防护）：只记「正在失败」的来源，正常流量下几乎为空；
/// 满时淘汰最旧一条（见 note_failure）。
const FAIL_TABLE_CAP: usize = 4096;

/// listener 级 Basic Auth 的判定结果。
///
/// 比 bool 多一档 `Throttled`：退避期回 429 而不是 401 —— 401 会让浏览器反复弹
/// 口令框重试，反而放大请求量；429 带 Retry-After，客户端能正确退让。
pub enum BasicCheck {
    Ok,
    Unauthorized,
    Throttled(Duration),
}

/// admin 路径入口的**廉价**门（不跑 argon2、不碰请求体）。
pub enum AdminGate {
    Proceed,
    Unauthorized,
    Throttled(Duration),
}

/// admin 路径在**收请求体之前**的鉴权门（三协议必须一致）。
///
/// 为什么要有它：h1 会先收满 32MiB body 再交给 admin::handle，而 admin::handle 的
/// 第一件事才是鉴权 —— 于是一个不带凭据的并发 POST 就能让每个连接各占 32MiB
/// （h2/h3 各 8MiB），不需要通过鉴权即可放大内存。
/// 判定顺序：退避 → 有没有携带 Basic 凭据（纯头部解析，零哈希成本）→ 完整校验。
///
/// 注意这里会跑一次 argon2id，而 admin::handle 里还会再「验」一次（同一份 headers、
/// 同一份配置）—— 那一次由成功备忘 [`ADMIN_OK`] 直接命中，不会重复跑哈希，
/// 因此合法管理请求的口令校验成本仍然是**一次** argon2id；代价为零而收益是
/// 「带任意垃圾凭据的请求也拿不到 32MiB/请求 的缓冲」。
/// 本函数的校验结果同时是失败计数/退避的唯一记账点。
pub fn admin_gate(headers: &HeaderMap, admin: &AdminConfig, ip: IpAddr) -> AdminGate {
    if let Some(d) = ADMIN_FAILS.blocked(ip) {
        return AdminGate::Throttled(d);
    }
    if !has_basic_credentials(headers) {
        // 没凭据 → 立刻回 401，不跑哈希也不收 body。
        return AdminGate::Unauthorized;
    }
    if check_admin_headers(headers, admin) {
        ADMIN_FAILS.note_success(ip);
        AdminGate::Proceed
    } else {
        ADMIN_FAILS.note_failure(ip);
        AdminGate::Unauthorized
    }
}

/// admin::handle 返回后的**兜底**记账。
///
/// gate 已经用同一份 headers/配置验过凭据并记过账，所以正常路径这里什么都不做；
/// 只有「gate 通过、admin::handle 却回了 401」这种边角（两次校验之间配置被热重载、
/// 口令被改）才补一次失败计数，避免这种请求白跑。
pub fn note_admin_result(ip: IpAddr, status: StatusCode) {
    if status == StatusCode::UNAUTHORIZED {
        ADMIN_FAILS.note_failure(ip);
    }
}

/// 429 响应用的 `Retry-After`（秒，最小 1）。
pub fn retry_after_secs(d: Duration) -> u64 {
    d.as_secs().max(1)
}

/// 是否携带 Basic 凭据（只看头，**不验口令**）。解析口径与
/// `check_user_pass_headers` 一致，避免「门放行、校验必然失败」的错配。
fn has_basic_credentials(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Basic "))
        .is_some_and(|b64| !b64.trim().is_empty())
}

struct FailState {
    count: u32,
    last: Instant,
    blocked_until: Instant,
}

/// 一张按 IP 记录的失败表。用 Mutex<HashMap> 而不是无锁结构：命中退避的请求本来
/// 就应该被挡住、不该有吞吐，热路径上也只是加锁查一次 map。
struct FailTable {
    map: Mutex<HashMap<IpAddr, FailState>>,
}

impl FailTable {
    /// 注意别写成 `const fn`：`HashMap::new` 在当前工具链里还不是 const fn。
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// 处于退避期则返回剩余时长；顺带把过窗口的记录清掉（惰性回收，无后台任务）。
    fn blocked(&self, ip: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        let mut map = self.map.lock();
        let (last, until) = match map.get(&ip) {
            Some(s) => (s.last, s.blocked_until),
            None => return None,
        };
        if now.duration_since(last) > FAIL_WINDOW {
            map.remove(&ip);
            return None;
        }
        (until > now).then(|| until - now)
    }

    fn note_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut map = self.map.lock();
        // 内存防护：满时淘汰最旧的一条，**绝不整表清空**——整表清空等于攻击者用
        // 垃圾来源 IP 刷满表就把所有人的退避状态一起重置（限流/退避反而被主动解除）。
        // 淘汰顺序刻意优先挑「未处于退避期」的最旧条目：退避中的条目留在表里，
        // 否则背着一身失败计数的攻击者只要继续刷表，就能把自己的封禁挤掉。
        if map.len() >= FAIL_TABLE_CAP && !map.contains_key(&ip) {
            let victim = map
                .iter()
                .filter(|(_, s)| s.blocked_until <= now)
                .min_by_key(|(_, s)| s.last)
                .map(|(k, _)| *k)
                .or_else(|| {
                    map.iter()
                        .min_by_key(|(_, s)| s.last)
                        .map(|(k, _)| *k)
                });
            if let Some(v) = victim {
                map.remove(&v);
            }
        }
        let e = map.entry(ip).or_insert(FailState {
            count: 0,
            last: now,
            blocked_until: now,
        });
        if now.duration_since(e.last) > FAIL_WINDOW {
            e.count = 0;
        }
        e.count = e.count.saturating_add(1);
        e.last = now;
        e.blocked_until = if e.count >= FAIL_THRESHOLD {
            // 阈值以上指数退避（1s、2s、4s…），封顶 MAX_BLOCK：退避有上界，
            // 合法管理员打错口令最多等一小会儿，不会被永久锁死。
            let over = (e.count - FAIL_THRESHOLD).min(6);
            now + Duration::from_secs(1u64 << over).min(MAX_BLOCK)
        } else {
            now
        };
    }

    fn note_success(&self, ip: IpAddr) {
        self.map.lock().remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ba_with(hash: &str) -> BasicAuthConfig {
        BasicAuthConfig {
            realm: "t".into(),
            username: "u".into(),
            password_hash: hash.into(),
        }
    }

    fn admin_with_hash(hash: &str) -> AdminConfig {
        AdminConfig {
            realm: "r".into(),
            path: "/__admin".into(),
            users: vec![crate::config::AdminUser {
                username: "u".into(),
                password_hash: hash.into(),
            }],
            listeners_allow: vec![],
            metrics_public: false,
        }
    }

    fn b64(s: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let b = s.as_bytes();
        let mut out = String::new();
        for c in b.chunks(3) {
            let n = ((c[0] as u32) << 16)
                | ((*c.get(1).unwrap_or(&0) as u32) << 8)
                | (*c.get(2).unwrap_or(&0) as u32);
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
        }
        out
    }

    fn headers_with_basic(user: &str, pass: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Basic {}", b64(&format!("{user}:{pass}"))))
                .unwrap(),
        );
        h
    }

    /// 无凭据 → 立即拒绝（收 body 之前就该挡住，且不跑口令哈希）。
    #[test]
    fn admin_gate_rejects_missing_credentials() {
        // 空 hash 的配置：真出现在 check_admin_headers 里也不会跑 argon2。
        let cfg = admin_with_hash("");
        let h = HeaderMap::new();
        assert!(matches!(
            admin_gate(&h, &cfg, "10.9.9.9".parse().unwrap()),
            AdminGate::Unauthorized
        ));
        // 非 Basic 方案同样拒绝。
        let mut h2 = HeaderMap::new();
        h2.insert(
            header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer xyz"),
        );
        assert!(matches!(
            admin_gate(&h2, &cfg, "10.9.9.10".parse().unwrap()),
            AdminGate::Unauthorized
        ));
    }

    /// 口令正确才 Proceed；错误口令被 gate 直接拒（不会带着 body 进 admin::handle）。
    #[test]
    fn admin_gate_verifies_credentials_before_body() {
        let hash = password::hash_password("pw").unwrap();
        let cfg = admin_with_hash(&hash);
        let ip: IpAddr = "10.9.9.16".parse().unwrap();
        assert!(matches!(
            admin_gate(&headers_with_basic("u", "pw"), &cfg, ip),
            AdminGate::Proceed
        ));
        assert!(matches!(
            admin_gate(&headers_with_basic("u", "nope"), &cfg, ip),
            AdminGate::Unauthorized
        ));
    }

    /// 阈值内的失败不退避；达到阈值后同一 IP 被 429 挡住。
    #[test]
    fn admin_failures_escalate_to_throttle_for_same_ip() {
        let ip: IpAddr = "10.9.9.11".parse().unwrap();
        let other: IpAddr = "10.9.9.12".parse().unwrap();
        // 空 hash 恒失败且不跑 argon2，计数路径与真实失败一致。
        let cfg = admin_with_hash("");
        let h = headers_with_basic("u", "wrong");
        for i in 0..FAIL_THRESHOLD {
            assert!(
                matches!(admin_gate(&h, &cfg, ip), AdminGate::Unauthorized),
                "attempt {i} must be rejected"
            );
        }
        assert!(matches!(admin_gate(&h, &cfg, ip), AdminGate::Throttled(_)));
        // 别的 IP 不受影响（不做全局封锁）。
        assert!(matches!(
            admin_gate(&h, &cfg, other),
            AdminGate::Unauthorized
        ));
        // 成功即清零（用 listener 表验证同一套清零语义）。
        // 退避是**累积**到 FAIL_THRESHOLD 次才生效的（首次失败不封锁），所以这里要凑满次数
        // ——此前只记 1 次就断言「已封锁」，是个一直没被跑到的过期断言（cargo test 这一步
        // 因磁盘/工具链原因长期没在验收里真正执行过）。
        for _ in 0..FAIL_THRESHOLD {
            LISTENER_FAILS.note_failure(other);
        }
        assert!(LISTENER_FAILS.blocked(other).is_some());
        LISTENER_FAILS.note_success(other);
        assert!(LISTENER_FAILS.blocked(other).is_none());
    }

    /// 成功备忘只对「同一凭据 + 同一用户表」生效：换口令立刻失效，失败从不被记。
    #[test]
    fn admin_ok_memo_is_scoped_to_credentials_and_user_table() {
        let hash = password::hash_password("pw").unwrap();
        let cfg = admin_with_hash(&hash);
        let h = headers_with_basic("u", "pw");
        assert!(check_admin_headers(&h, &cfg));
        // 第二次就是 admin::handle 里那次：结论必须仍为真（备忘命中只是省掉哈希）。
        assert!(check_admin_headers(&h, &cfg));
        let auth = h.get(header::AUTHORIZATION).unwrap().as_bytes().to_vec();
        assert!(admin_ok_hit(admin_users_fp(&cfg), &auth));

        // 换口令（同一用户名）→ 用户表指纹变，旧的成功结论不可复用。
        let cfg2 = admin_with_hash(&password::hash_password("other").unwrap());
        assert!(!check_admin_headers(&h, &cfg2));
        assert_ne!(admin_users_fp(&cfg), admin_users_fp(&cfg2));

        // 失败路径不写备忘：错口令即使此前有成功记录也不能凭它进门。
        let wrong = headers_with_basic("u", "nope");
        assert!(!check_admin_headers(&wrong, &cfg));
        assert!(!admin_ok_hit(
            admin_users_fp(&cfg),
            wrong.get(header::AUTHORIZATION).unwrap().as_bytes()
        ));
    }

    /// 无凭据 / 空凭据永远不命中备忘（备忘只在真验过之后才写）。
    #[test]
    fn admin_ok_memo_rejects_missing_credentials() {
        let hash = password::hash_password("pw").unwrap();
        let cfg = admin_with_hash(&hash);
        assert!(!admin_ok_hit(admin_users_fp(&cfg), b""));
        assert!(!check_admin_headers(&HeaderMap::new(), &cfg));
    }

    /// listener 校验在退避期内快速失败（不再进口令哈希路径）。
    #[test]
    fn listener_check_throttles_after_threshold() {
        let ip: IpAddr = "10.9.9.15".parse().unwrap();
        // 空 hash 恒失败且不跑 argon2，计数路径与真实失败一致。
        let ba = ba_with("");
        let h = headers_with_basic("u", "wrong");
        for _ in 0..FAIL_THRESHOLD {
            assert!(matches!(
                check_listener_headers_at(&h, &ba, ip),
                BasicCheck::Unauthorized
            ));
        }
        assert!(matches!(
            check_listener_headers_at(&h, &ba, ip),
            BasicCheck::Throttled(_)
        ));
    }

    /// 成功一次就清零（真人不该被自己几次手误锁死）。
    #[test]
    fn success_clears_failures() {
        let ip: IpAddr = "10.9.9.13".parse().unwrap();
        for _ in 0..FAIL_THRESHOLD {
            LISTENER_FAILS.note_failure(ip);
        }
        assert!(LISTENER_FAILS.blocked(ip).is_some());
        LISTENER_FAILS.note_success(ip);
        assert!(LISTENER_FAILS.blocked(ip).is_none());
    }

    /// 表满时淘汰最旧，而不是清空全表（否则攻击者刷满表即解除全部退避）。
    #[test]
    fn table_full_evicts_oldest_but_keeps_throttled_entries() {
        let t = FailTable::new();
        let victim: IpAddr = "10.0.0.1".parse().unwrap();
        // 推到阈值以上若干次，让退避时长升到秒级上限 —— 测试期间它必须一直处于
        // 「退避中」，这样淘汰逻辑只能用「未退避的最旧条目」来腾位置。
        for _ in 0..(FAIL_THRESHOLD + 6) {
            t.note_failure(victim);
        }
        assert!(t.blocked(victim).is_some(), "victim must be throttled");
        for i in 0..(FAIL_TABLE_CAP as u32 + 16) {
            let ip: IpAddr = IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000 + i));
            t.note_failure(ip);
        }
        assert!(t.map.lock().len() <= FAIL_TABLE_CAP, "cap must hold");
        assert!(
            t.map.lock().len() > FAIL_TABLE_CAP / 2,
            "must not wipe the table"
        );
        // 退避中的条目仍在（未被整表清空、也没被自己的刷表挤掉）。
        assert!(
            t.blocked(victim).is_some(),
            "throttle state must survive eviction"
        );
    }
}
