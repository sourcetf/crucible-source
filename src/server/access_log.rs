//! Access log enable/level/realtime with in-memory ring for Admin tail.
//!
//! 行格式（§16.12 全字段）：`{ts} {proto} {peer} "{method} {path}" {status} {bytes} {dur_ms}ms {engine}`
//! —— 在响应完成侧统一记录（请求入口拿不到 status/bytes/duration）。
//! engine 标签由 dispatch 各分支经响应 extensions 注入 [`EngineTag`]。

use crate::server::live_config::LiveConfig;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

static RING: Lazy<Mutex<VecDeque<String>>> = Lazy::new(|| Mutex::new(VecDeque::with_capacity(512)));

/// dispatch 分支把"这条响应由谁产出"写进响应 extensions：
/// admin / telemetry / app / proxy / static / dns-doh 等，未注入时记为 http。
#[derive(Clone, Copy)]
pub struct EngineTag(pub &'static str);

#[allow(clippy::too_many_arguments)]
pub fn log_response(
    live: &Arc<LiveConfig>,
    peer: SocketAddr,
    proto: &str,
    method: &str,
    path: &str,
    status: u16,
    bytes: Option<u64>,
    dur: Duration,
    engine: &str,
) {
    let cfg = live.snapshot();
    if !cfg.access_log.enable {
        return;
    }
    // 无 chrono 依赖：unix 秒.毫秒，足够 Admin tail 按序展示。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let ts = format!("{}.{:03}", now / 1000, now % 1000);
    let bytes_field = match bytes {
        Some(n) => n.to_string(),
        None => "-".to_string(),
    };
    let line = format!(
        "{ts} {proto} {peer} \"{method} {path}\" {status} {bytes_field} {}ms {engine}",
        dur.as_millis()
    );
    match cfg.access_log.level.as_str() {
        "debug" | "trace" => log::debug!("{line}"),
        "warn" => log::warn!("{line}"),
        _ => log::info!("{line}"),
    }
    if cfg.access_log.realtime {
        let mut ring = RING.lock();
        if ring.len() >= 512 {
            ring.pop_front();
        }
        ring.push_back(line);
    }
}

/// Snapshot of recent access lines for Admin realtime window (SSE/WS can wrap this).
pub fn recent_lines(limit: usize) -> Vec<String> {
    let ring = RING.lock();
    ring.iter().rev().take(limit).cloned().collect::<Vec<_>>().into_iter().rev().collect()
}
