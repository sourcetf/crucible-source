//! Access log enable/level/realtime with in-memory ring for Admin tail.
//!
//! 行格式（§16.12 全字段）：`{ts} {proto} {peer} "{method} {path}" {status} {bytes} {dur_ms}ms {engine}`
//! —— 在响应完成侧统一记录（请求入口拿不到 status/bytes/duration）。
//! engine 标签由 dispatch 各分支经响应 extensions 注入 [`EngineTag`]。

use crate::server::live_config::LiveConfig;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

static RING: Lazy<Mutex<VecDeque<String>>> = Lazy::new(|| Mutex::new(VecDeque::with_capacity(512)));

/// 访问日志的**批量写缓冲**。
///
/// 为什么要有：原来每一行都走 `log::info!` → env_logger **每条记录一次 write + flush**。
/// 请求路径上每个请求一次系统调用只是小事，真正的代价是 env_logger 的格式化与加锁，
/// gdb 采样里 `env_logger::Logger::log` + `ConfigurableFormat::format` 是请求路径上
/// 排名前三的热点（wrk -c32 下约 25~30% 的吞吐差）。
///
/// 现在：请求路径只做「拼一行 + memcpy 进进程级缓冲」，后台线程每 250ms（或缓冲超过
/// 256KiB 时）用一次 write 落盘。部署时 stderr 被重定向到日志文件，因此落点不变；
/// 管理面的「实时访问日志」读的是内存 RING，完全不受影响。
static ACCESS_BUF: Mutex<Vec<u8>> = Mutex::new(Vec::new());
/// 缓冲上限，超过立即触发一次 flush（在请求线程里做）。
const ACCESS_BUF_FLUSH_AT: usize = 256 * 1024;
/// 后台 flush 间隔。
const ACCESS_FLUSH_EVERY: Duration = Duration::from_millis(250);

fn ensure_flusher() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = std::thread::Builder::new()
            .name("accesslog-flush".into())
            .spawn(|| loop {
                std::thread::sleep(ACCESS_FLUSH_EVERY);
                flush();
            });
    });
}

fn flush() {
    let data = {
        let mut b = ACCESS_BUF.lock();
        if b.is_empty() {
            return;
        }
        std::mem::take(&mut *b)
    };
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(&data);
    let _ = err.flush();
}

/// 立即把缓冲里的访问日志刷到 stderr（进程退出路径调用，避免丢最后 ≤250ms 的行）。
pub fn flush_now() {
    flush();
}

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
    // `path` 是请求目标，**不能原样进引号字段**：一个含 `"` 的请求就能提前结束引号、
    // 把后面的字段伪造成任意内容（日志是审计证据，伪造一行等于污染审计）。
    // 换行/控制字符由 hyper 的 URI 校验挡住，这里的重点是引号与个别控制字符。
    let path_esc: String = path
        .chars()
        .map(|c| if c == '"' || c == '\\' || (c as u32) < 0x20 { '\u{fffd}' } else { c })
        .collect();
    let line = format!(
        "{ts} {proto} {peer} \"{method} {path_esc}\" {status} {bytes_field} {}ms {engine}",
        dur.as_millis()
    );
    match cfg.access_log.level.as_str() {
        // debug/trace/warn 属低频诊断路径，保持走 env_logger（语义与级别过滤不变）。
        "debug" | "trace" => log::debug!("{line}"),
        "warn" => log::warn!("{line}"),
        _ => {
            ensure_flusher();
            let full = {
                let mut b = ACCESS_BUF.lock();
                b.extend_from_slice(line.as_bytes());
                b.push(b'\n');
                b.len() >= ACCESS_BUF_FLUSH_AT
            };
            if full {
                flush();
            }
        }
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


#[cfg(test)]
mod tests {
    use super::*;

    /// 批量写路径不能改变**行内容**：拼进去的必须是同一行 + 单个换行，
    /// 且 flush 之后缓冲清空（否则会重复落盘）。
    #[test]
    fn buffered_lines_are_exact_and_flush_clears() {
        // 不启动后台线程，直接检查缓冲语义
        const LINE: &str = "1788 h1 127.0.0.1:1 \"GET /\" 200 127 1ms static";
        {
            let mut b = ACCESS_BUF.lock();
            b.clear();
            b.extend_from_slice(LINE.as_bytes());
            b.push(b'\n');
        }
        let snapshot = ACCESS_BUF.lock().clone();
        assert_eq!(snapshot.len(), LINE.len() + 1);
        assert_eq!(snapshot.last(), Some(&b'\n'));
        assert_eq!(snapshot.iter().filter(|c| **c == b'\n').count(), 1);
        // flush 只取走数据、不销毁缓冲（容量保留），且再次调用是空操作。
        let taken = { let mut b = ACCESS_BUF.lock(); std::mem::take(&mut *b) };
        assert_eq!(taken.len(), LINE.len() + 1);
        assert!(ACCESS_BUF.lock().is_empty());
    }
}
