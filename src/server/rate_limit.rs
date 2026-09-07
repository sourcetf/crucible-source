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
    let mut map = BUCKETS.lock();
    // P2：惰性淘汰——超限时先清 60s 未活跃桶；仍超限（活跃攻击）则整表清空，
    // 限流语义短暂退化为"全部放行"，好过内存被 per-IP 桶打爆。
    if map.len() >= BUCKET_CAP {
        let cutoff = Instant::now();
        map.retain(|_, b| cutoff.duration_since(b.last) < Duration::from_secs(60));
        if map.len() >= BUCKET_CAP {
            map.clear();
        }
    }
    let now = Instant::now();
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

pub fn cleanup(older_than: Duration) {
    let mut map = BUCKETS.lock();
    let now = Instant::now();
    map.retain(|_, b| now.duration_since(b.last) < older_than);
}

pub fn deny_response() -> (http::StatusCode, &'static str) {
    (http::StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")
}
