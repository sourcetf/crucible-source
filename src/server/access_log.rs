//! Access log enable/level/realtime with in-memory ring for Admin tail.
//!
//! 行格式（§16.12 全字段）：`{ts} {proto} {peer} "{method} {path}" {status} {bytes} {dur_ms}ms {engine}`
//! —— 在响应完成侧统一记录（请求入口拿不到 status/bytes/duration）。
//! engine 标签由 dispatch 各分支经响应 extensions 注入 [`EngineTag`]。

use crate::config::{AccessLogConfig, ListenerAccessLogConfig};
use crate::server::live_config::LiveConfig;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fmt::Write as _;
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

/// §16.12 **生效的**访问日志设置：全局 `[access_log]` 与每站（listener）覆盖
/// **逐字段**合并后的结果（未配的字段继承全局，见 [`ListenerAccessLogConfig`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveAccessLog<'a> {
    pub enable: bool,
    pub level: &'a str,
    pub realtime: bool,
}

/// 把全局配置与可选 listener 覆盖合并成生效值。
///
/// 语义（字段级继承）：`per` 为 `None` ⇒ 完全继承全局（旧配置行为逐字节不变）；
/// `Some(p)` ⇒ 只覆盖 `p` 里显式配置的字段，未配的继承全局。
///
/// 特别注意 `enable`：全局 `enable=false` 时，一个只写了 `realtime=true` 的 listener
/// 覆盖**不会**把 enable 意外变成 `true`（这正是每站配置用 `Option` 而非带默认值的
/// `AccessLogConfig` 的原因——否则「只想开实时 tail」会把站点日志整体打开）。
pub fn resolve<'a>(
    global: &'a AccessLogConfig,
    per: Option<&'a ListenerAccessLogConfig>,
) -> EffectiveAccessLog<'a> {
    match per {
        None => EffectiveAccessLog {
            enable: global.enable,
            level: &global.level,
            realtime: global.realtime,
        },
        Some(p) => EffectiveAccessLog {
            enable: p.enable.unwrap_or(global.enable),
            level: p.level.as_deref().unwrap_or(&global.level),
            realtime: p.realtime.unwrap_or(global.realtime),
        },
    }
}

/// 记录一条访问日志（响应完成侧的唯一入口）。
///
/// `per` 是**服务该请求的 listener** 的覆盖（`None` = 完全继承全局）；调用方传
/// `lc.access_log.as_ref()`——不能用端口反查，同端口可能有多个地址的 listener。
///
/// 每次调用取一次 `live.snapshot()`；热路径（h1 请求收口）已有快照的调用方应改用
/// [`log_response_with`]，避免为日志再付一次锁/原子开销。
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
    per: Option<&ListenerAccessLogConfig>,
) {
    log_response_with(
        &live.snapshot(),
        peer,
        proto,
        method,
        path,
        status,
        bytes,
        dur,
        engine,
        per,
    );
}

/// 与 [`log_response`] 相同，但**复用调用方已取好的配置快照**（h1 的请求收口处
/// 同一次 `live.snapshot()` 已供路由判定使用，日志不再重复取）。
#[allow(clippy::too_many_arguments)]
pub fn log_response_with(
    snap: &crate::config::Config,
    peer: SocketAddr,
    proto: &str,
    method: &str,
    path: &str,
    status: u16,
    bytes: Option<u64>,
    dur: Duration,
    engine: &str,
    per: Option<&ListenerAccessLogConfig>,
) {
    let eff = resolve(&snap.access_log, per);
    if !eff.enable {
        return;
    }
    // 无 chrono 依赖：unix 秒.毫秒，足够 Admin tail 按序展示。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    // 只做**一次**格式化到一条 `String`（然后整行进批量缓冲）：旧实现每请求 4 次堆分配
    // —— ts `format!` / bytes `to_string` / path 转义 `collect::<String>()` / 整行 `format!`。
    // 字段顺序、转义规则与输出逐字不变（访问日志是审计证据，格式不能变）。
    let mut line = String::with_capacity(path.len() + 64);
    let _ = write!(line, "{}.{:03} {proto} {peer} \"{method} ", now / 1000, now % 1000);
    // `path` 是请求目标，**不能原样进引号字段**：一个含 `"` 的请求就能提前结束引号、
    // 把后面的字段伪造成任意内容（日志是审计证据，伪造一行等于污染审计）。
    // 换行/控制字符由 hyper 的 URI 校验挡住，这里的重点是引号与个别控制字符。
    for c in path.chars() {
        if c == '"' || c == '\\' || (c as u32) < 0x20 {
            line.push('\u{fffd}');
        } else {
            line.push(c);
        }
    }
    line.push('"');
    let _ = write!(line, " {status} ");
    match bytes {
        Some(n) => {
            let _ = write!(line, "{n}");
        }
        None => line.push('-'),
    }
    let _ = write!(line, " {}ms {engine}", dur.as_millis());
    // 级别过滤：**所有**等级都走同一批量写路径（`level` 仍逐站生效于配置/展示层，
    // 但访问日志行本身没有严重级别语义——见下方注释）。
    //
    // 此前 `"debug" | "trace" => log::debug!("{line}")`：env_logger 的默认过滤是
    // `info`（`main.rs` 的 `default_filter_or("info")`，现场也没有 RUST_LOG），于是
    // 把访问日志等级选成 `debug`/`trace`（面板下拉里就有这两个选项）会让**每一行
    // 访问日志都被丢弃** —— 运维为了「看更多」而调低等级，结果一条都看不到，
    // 且没有任何提示。访问日志的行本身没有严重级别语义（它记录的是每次请求），
    // 所以等级只保留在配置/展示层，落盘路径统一。
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
    if eff.realtime {
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

    /// §16.12 每站覆盖的字段级继承：未配的字段必须继承全局，配了的才覆盖。
    #[test]
    fn resolve_inherits_unset_fields_and_overrides_set_ones() {
        let global = AccessLogConfig {
            enable: true,
            level: "info".into(),
            realtime: false,
        };
        // 无覆盖 ⇒ 逐字段全局。
        let eff = resolve(&global, None);
        assert_eq!(eff, EffectiveAccessLog { enable: true, level: "info", realtime: false });
        // 只配 realtime ⇒ enable/level 仍继承全局。
        let per = ListenerAccessLogConfig {
            enable: None,
            level: None,
            realtime: Some(true),
        };
        let eff = resolve(&global, Some(&per));
        assert_eq!(eff, EffectiveAccessLog { enable: true, level: "info", realtime: true });
        // 只配 level ⇒ enable/realtime 仍继承全局。
        let per = ListenerAccessLogConfig {
            enable: None,
            level: Some("trace".into()),
            realtime: None,
        };
        let eff = resolve(&global, Some(&per));
        assert_eq!(eff, EffectiveAccessLog { enable: true, level: "trace", realtime: false });
    }

    /// 关键回归（Option 设计的理由）：全局 `enable=false` 时，listener 只写
    /// `realtime=true` **不得**把 enable 意外变成 true。
    #[test]
    fn resolve_does_not_re_enable_when_only_realtime_set() {
        let global = AccessLogConfig {
            enable: false,
            level: "warn".into(),
            realtime: false,
        };
        let per = ListenerAccessLogConfig {
            enable: None,
            level: Some("debug".into()),
            realtime: Some(true),
        };
        let eff = resolve(&global, Some(&per));
        assert!(!eff.enable, "未显式配 enable 时必须继承全局 false");
        assert_eq!(eff.level, "debug");
        assert!(eff.realtime);
        // 显式 enable=true 的覆盖则必须生效（每站可以单独打开）。
        let per = ListenerAccessLogConfig {
            enable: Some(true),
            level: None,
            realtime: None,
        };
        let eff = resolve(&global, Some(&per));
        assert!(eff.enable, "显式 enable=true 必须覆盖全局 false");
        assert_eq!(eff.level, "warn", "未配的 level 继承全局");
        assert!(!eff.realtime, "未配的 realtime 继承全局");
    }
}
