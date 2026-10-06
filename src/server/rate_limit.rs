//! Simple token-bucket rate limiter (per-peer or per-peer+path key).

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    last: Instant,
}

static BUCKETS: Lazy<Mutex<HashMap<String, Bucket>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 内存防护（P2）：键（IP 或 IP|path）数上限。per_path 模式下键空间可被任意 URL 撑爆。
const BUCKET_CAP: usize = 100_000;
/// 容量淘汰的比例（1/64）：批量淘汰把一次排序的代价摊薄，
/// 避免「每个新键都做一次 O(n) 扫描」变成新的 CPU 放大点。
const BUCKET_EVICT_DIV: usize = 64;

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        other => other,
    }
}

pub fn allow(ip: IpAddr, rate_per_sec: f64, burst: f64) -> bool {
    allow_key(&normalize_ip(ip).to_string(), rate_per_sec, burst)
}

/// per_path 模式的桶键：**路径不进 key 原文**，改用 64 位指纹。
///
/// 为什么必须这样（P1，无认证可触发）：hyper 允许请求目标长到 ~64KiB（`MAX_URI_LEN`），
/// 而桶表上限是 [`BUCKET_CAP`]=10 万键 —— 原样把路径拼进 key 时，一个客户端只要
/// 「每条请求换一个新路径、路径撑到 URI 上限」就能把表填满：
/// 实测复刻（逐字照搬本文件逻辑）**10 万键 × 65KB ≈ 6.2GB RSS**。指纹把每键压到
/// 固定的 `ip + 16 个十六进制字符`（10 万键 ≈ 4MB 上界），限流粒度不变
/// （64 位空间里 10 万键的碰撞概率约 3e-10，且碰撞只会让两条不同路径共享一个桶 =
/// 更严一点，不会放行）。
pub fn allow_path(ip: IpAddr, path: &str, rate_per_sec: f64, burst: f64) -> bool {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.trim_end_matches('/').hash(&mut h);
    let key = format!("{}|{:016x}", normalize_ip(ip), h.finish());
    allow_key(&key, rate_per_sec, burst)
}

fn allow_key(key: &str, rate_per_sec: f64, burst: f64) -> bool {
    let now = Instant::now();
    let mut map = BUCKETS.lock();
    // P2：惰性淘汰——超限时先清 60s 未活跃桶。
    if map.len() >= BUCKET_CAP {
        map.retain(|_, b| now.duration_since(b.last) < Duration::from_secs(60));
    }
    // 仍然满（表被活跃键占满，典型是 per_path 模式被任意 URL 刷）：按「最久未活跃」
    // 批量淘汰，**绝不整表清空**。整表清空等于攻击者只要把键空间填满，所有 IP 的令牌桶
    // 就一起被重置为满 —— 限流被他主动解除、自己反而被放行，正是攻击者想要的结果。
    // 只丢最旧的键：正在被使用的键（含攻击者自己的活跃键）保留，限流语义不退化。
    if map.len() >= BUCKET_CAP {
        evict_oldest(&mut map, (BUCKET_CAP / BUCKET_EVICT_DIV).max(1));
    }
    let b = map.entry(key.to_string()).or_insert(Bucket {
        tokens: burst,
        last: now,
    });
    let elapsed = now.duration_since(b.last).as_secs_f64();
    b.tokens = (b.tokens + elapsed * rate_per_sec).min(burst);
    b.last = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

/// 按「最久未活跃」淘汰 `count` 个键。独立成函数，单测可用少量键直接验证淘汰顺序，
/// 不必真的塞满 [`BUCKET_CAP`] 个桶。
fn evict_oldest(map: &mut HashMap<String, Bucket>, count: usize) {
    if count == 0 || map.is_empty() {
        return;
    }
    let mut ages: Vec<(Instant, String)> = map.iter().map(|(k, b)| (b.last, k.clone())).collect();
    ages.sort_by_key(|(t, _)| *t);
    for (_, k) in ages.into_iter().take(count) {
        map.remove(&k);
    }
}

pub fn cleanup(older_than: Duration) {
    let mut map = BUCKETS.lock();
    let now = Instant::now();
    map.retain(|_, b| now.duration_since(b.last) < older_than);
}

pub fn deny_response() -> (http::StatusCode, &'static str) {
    (http::StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 桶耗尽即拒绝（限流本身有效）。
    #[test]
    fn bucket_denies_after_burst() {
        let ip: IpAddr = "10.123.45.67".parse().unwrap();
        assert!(allow(ip, 1.0, 1.0));
        assert!(!allow(ip, 1.0, 1.0), "burst exhausted must be denied");
    }

    /// 容量淘汰只丢最旧的键，不整表清空 —— 否则攻击者刷满键空间就能把全部
    /// IP 的限流状态一起重置（限流反被解除）。
    #[test]
    fn eviction_keeps_recent_buckets() {
        let mut m: HashMap<String, Bucket> = HashMap::new();
        let base = Instant::now();
        for i in 0..100u64 {
            m.insert(
                format!("k{i}"),
                Bucket {
                    tokens: 1.0,
                    last: base + Duration::from_millis(i),
                },
            );
        }
        evict_oldest(&mut m, 10);
        assert_eq!(m.len(), 90, "only the requested batch is dropped");
        assert!(!m.contains_key("k0"), "oldest goes first");
        assert!(m.contains_key("k99"), "newest survives");
    }

    /// per_path 的桶键必须**定长**（IP + 路径指纹），不能把可达 64KiB 的请求路径
    /// 原样存进表里 —— 否则 10 万键 × 65KB ≈ 6.2GB RSS，一个客户端就能把进程撑爆
    /// （复刻实验见报告）。
    #[test]
    fn path_key_is_fixed_size_regardless_of_path_length() {
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let long = format!("/{}", "a".repeat(60_000));
        let short = "/a";
        let mut m: HashMap<String, Bucket> = HashMap::new();
        // 直接调 allow_key 之外的可测入口不方便（内部用全局表），这里验证键构造本身。
        for p in [long.as_str(), short] {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            use std::hash::{Hash, Hasher};
            p.trim_end_matches('/').hash(&mut h);
            let key = format!("{}|{:016x}", normalize_ip(ip), h.finish());
            m.insert(key.clone(), Bucket { tokens: 1.0, last: Instant::now() });
            assert!(
                key.len() <= 64,
                "per_path 桶键必须定长（实测 {} 字节）",
                key.len()
            );
        }
        assert_eq!(m.len(), 2, "不同路径仍是不同桶（限流粒度不变）");
    }
}
