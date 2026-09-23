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

pub fn allow_path(ip: IpAddr, path: &str, rate_per_sec: f64, burst: f64) -> bool {
    let key = format!("{}|{}", normalize_ip(ip), path.trim_end_matches('/'));
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
}
