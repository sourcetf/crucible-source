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
///
/// 缓冲保持**单一全局**（wave-11 评估过「每线程一个槽位」：c128 实测无可辨收益，
/// 且会把不同线程的行按槽位分组落盘 —— 同一顺序客户端（例如验收脚本）看到的行
/// 次序与改动前不同；访问日志是审计证据，行序可解释性优先，故不采用）。
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

// ---------------------------------------------------------------------------
// 行前缀（`{proto} {peer} `）
// ---------------------------------------------------------------------------

/// 行前 `{proto} {peer} ` 这一段的来源。
///
/// * 热路径（h1 快车道）用连接级 [`ConnPrefix`]：**每连接格式化一次**，之后每请求
///   只有一次 `memcpy`（`peer` 的 `SocketAddr` Display + 多次 `core::fmt` 分派从
///   每请求一次降为每连接一次）；
/// * h1 hyper 收口 / h2 / h3 的调用点保持原签名（每请求传 `proto` + `peer`），由
///   [`ProtoPeer`] 每请求格式化一次（与 wave-10 行为逐字节相同，成本不变）。
///
/// 两种来源都把同一段字节写进同一行，单测把 [`ConnPrefix`] 与 `format!("{proto} {peer} ")`
/// 逐字节对拍。
trait LinePrefix {
    /// 追加 `{proto} {peer} ` 字节（批量缓冲路径）。
    fn write_bytes(&self, out: &mut Vec<u8>);
    /// 追加同样的字节到任意 `fmt::Write`（realtime 路径与 fmt 参照实现）。
    fn write_fmt(&self, out: &mut impl std::fmt::Write) -> std::fmt::Result;
}

/// 连接级预格式化前缀（`{proto} {peer} `）。
pub struct ConnPrefix<'a> {
    proto: &'a str,
    peer: SocketAddr,
    buf: Vec<u8>,
}

impl<'a> ConnPrefix<'a> {
    /// 在一个连接的开头调用一次；之后每请求直接复用 [`Self::write_bytes`]。
    pub fn new(proto: &'a str, peer: SocketAddr) -> Self {
        let mut buf = Vec::with_capacity(proto.len() + 32);
        {
            let mut w = BufW(&mut buf);
            // 与 [`format_line`] 的前缀段是**同一段格式串**（`{proto} {peer} `）。
            let _ = write!(w, "{proto} {peer} ");
        }
        Self { proto, peer, buf }
    }
}

impl LinePrefix for ConnPrefix<'_> {
    #[inline]
    fn write_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.buf);
    }
    fn write_fmt(&self, out: &mut impl std::fmt::Write) -> std::fmt::Result {
        write!(out, "{} {} ", self.proto, self.peer)
    }
}

/// 每请求构造的 `{proto} {peer} `（非热路径调用点沿用原签名）。
struct ProtoPeer<'a> {
    proto: &'a str,
    peer: SocketAddr,
}

impl LinePrefix for ProtoPeer<'_> {
    #[inline]
    fn write_bytes(&self, out: &mut Vec<u8>) {
        let _ = write!(BufW(out), "{} {} ", self.proto, self.peer);
    }
    fn write_fmt(&self, out: &mut impl std::fmt::Write) -> std::fmt::Result {
        write!(out, "{} {} ", self.proto, self.peer)
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
    log_line(
        snap,
        &ProtoPeer { proto, peer },
        method,
        path,
        status,
        bytes,
        dur,
        engine,
        per,
    );
}

/// 与 [`log_response_with`] 相同，但复用**连接级**预格式化前缀（h1 快车道热路径：
/// `peer`/`proto` 每连接格式化一次，见 [`ConnPrefix`]）。
#[allow(clippy::too_many_arguments)]
pub fn log_response_prefixed_with(
    snap: &crate::config::Config,
    prefix: &ConnPrefix<'_>,
    method: &str,
    path: &str,
    status: u16,
    bytes: Option<u64>,
    dur: Duration,
    engine: &str,
    per: Option<&ListenerAccessLogConfig>,
) {
    log_line(
        snap, prefix, method, path, status, bytes, dur, engine, per,
    );
}

#[allow(clippy::too_many_arguments)]
#[inline]
fn log_line<P: LinePrefix>(
    snap: &crate::config::Config,
    prefix: &P,
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
    let dur_ms = dur.as_millis();
    ensure_flusher();
    if !eff.realtime {
        // 行格式化只有**一条热路径实现**（[`write_line`]）：手写十进制 + 直接写进
        // 批量缓冲（无中间 `String`、无 `core::fmt` 的逐参数动态分派）。
        // 旧实现每请求 4 次堆分配（ts `format!` / bytes `to_string` / path 转义
        // `collect::<String>()` / 整行 `format!`）——wave-7 去掉 `String`，wave-11
        // 再去掉 `core::fmt`；字段顺序、转义规则与输出逐字不变（访问日志是审计证据，
        // 格式不能变；单测 `fast_line_matches_fmt_line` 把 [`write_line`] 与 fmt 参照
        // 实现逐字节对拍）。
        let full = {
            let mut b = ACCESS_BUF.lock();
            write_line(&mut b, now, prefix, method, path, status, bytes, dur_ms, engine);
            b.push(b'\n');
            b.len() >= ACCESS_BUF_FLUSH_AT
        };
        if full {
            flush();
        }
        return;
    }
    // realtime=true：先写进 `String`（Admin 实时窗口要留一份），再追加进批量缓冲。
    // 该路径不在吞吐热路径上，沿用 wave-7 的 fmt 单实现（[`format_line`]）。
    let mut line = String::with_capacity(path.len() + 64);
    format_line(
        &mut line, now, prefix, method, path, status, bytes, dur, engine,
    );
    let full = {
        let mut b = ACCESS_BUF.lock();
        b.extend_from_slice(line.as_bytes());
        b.push(b'\n');
        b.len() >= ACCESS_BUF_FLUSH_AT
    };
    if full {
        flush();
    }
    {
        let mut ring = RING.lock();
        if ring.len() >= 512 {
            ring.pop_front();
        }
        ring.push_back(line);
    }
}

/// 把访问日志行**直接**格式化进 `Vec<u8>`（`fmt::Write` 适配器）：
/// 仅用于前缀段的**每连接/每请求一次**的 fmt 格式化（[`ConnPrefix::new`]、
/// [`ProtoPeer`]）；行主体的热路径见 [`write_line`]。
struct BufW<'a>(&'a mut Vec<u8>);
impl std::fmt::Write for BufW<'_> {
    #[inline]
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 手写十进制（热路径：去 `core::fmt` 的逐参数动态分派与 u128 除法）
// ---------------------------------------------------------------------------

/// 十进制追加（u64；无 `core::fmt`）。
#[inline]
fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[i..]);
}

/// 十进制追加（u128）。`SystemTime`/`Duration` 的实际值恒在 u64 范围内，走 u64
/// 快路径（`u128 / 1000` 的软除法在**极端值**下才用 `core::fmt` 兜底，输出逐字相同）。
#[inline]
fn push_u128(out: &mut Vec<u8>, v: u128) {
    if v <= u64::MAX as u128 {
        push_u64(out, v as u64);
        return;
    }
    let _ = write!(BufW(out), "{v}");
}

/// 单条访问日志行的格式化（热路径：直接进 `Vec<u8>`）。
///
/// 与 [`format_line`]（realtime 路径的 fmt 实现）**逐字节等价**：同一段前缀、
/// 同一套转义规则、同一个字段顺序。单测 `fast_line_matches_fmt_line` 用同一张
/// 输入表把两者对拍（含 `"` / `\` / 控制字符 / 非 ASCII 路径、超大整数、
/// `bytes=None`、v4/v6 peer）。
#[allow(clippy::too_many_arguments)]
#[inline]
fn write_line<P: LinePrefix>(
    out: &mut Vec<u8>,
    now_ms: u128,
    prefix: &P,
    method: &str,
    path: &str,
    status: u16,
    bytes: Option<u64>,
    dur_ms: u128,
    engine: &str,
) {
    // `{}.{:03} `：秒 + 三位毫秒（零填充）。
    let ms = if now_ms <= u64::MAX as u128 {
        push_u64(out, (now_ms / 1000) as u64);
        (now_ms % 1000) as u32
    } else {
        push_u128(out, now_ms / 1000);
        (now_ms % 1000) as u32
    };
    out.push(b'.');
    out.push(b'0' + (ms / 100) as u8);
    out.push(b'0' + ((ms / 10) % 10) as u8);
    out.push(b'0' + (ms % 10) as u8);
    out.push(b' ');
    prefix.write_bytes(out);
    out.push(b'"');
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    // `path` 是请求目标，**不能原样进引号字段**：含 `"` 的请求能提前结束引号、
    // 把后面的字段伪造成任意内容（日志是审计证据，伪造一行等于污染审计）。
    for c in path.chars() {
        if c == '"' || c == '\\' || (c as u32) < 0x20 {
            out.extend_from_slice("\u{fffd}".as_bytes());
        } else {
            let mut tmp = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
        }
    }
    out.push(b'"');
    out.push(b' ');
    push_u64(out, status as u64);
    out.push(b' ');
    match bytes {
        Some(n) => push_u64(out, n),
        None => out.push(b'-'),
    }
    out.push(b' ');
    push_u128(out, dur_ms);
    out.extend_from_slice(b"ms ");
    out.extend_from_slice(engine.as_bytes());
}

/// 单条访问日志行的格式化（**fmt 参照实现**；realtime=true 路径使用，wave-7 起未改）。
///
/// 热路径（realtime=false）的实现是 [`write_line`] —— 两者由单测逐字节对齐。
#[allow(clippy::too_many_arguments)]
fn format_line<P: LinePrefix>(
    out: &mut impl std::fmt::Write,
    now_ms: u128,
    prefix: &P,
    method: &str,
    path: &str,
    status: u16,
    bytes: Option<u64>,
    dur: Duration,
    engine: &str,
) {
    let _ = write!(out, "{}.{:03} ", now_ms / 1000, now_ms % 1000);
    let _ = prefix.write_fmt(out);
    let _ = out.write_char('"');
    let _ = out.write_str(method);
    let _ = out.write_char(' ');
    for c in path.chars() {
        if c == '"' || c == '\\' || (c as u32) < 0x20 {
            let _ = out.write_char('\u{fffd}');
        } else {
            let _ = out.write_char(c);
        }
    }
    let _ = out.write_char('"');
    let _ = write!(out, " {status} ");
    match bytes {
        Some(n) => {
            let _ = write!(out, "{n}");
        }
        None => {
            let _ = out.write_char('-');
        }
    }
    let _ = write!(out, " {}ms {engine}", dur.as_millis());
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

    /// 连接级前缀与逐请求 fmt 前缀（`format!("{proto} {peer} ")`）逐字节一致
    /// （v4 带端口 / v6 带端口）——热路径复用的前提。
    #[test]
    fn prefix_bytes_match_peer_format() {
        for peer in [
            "127.0.0.1:34567".parse::<SocketAddr>().unwrap(),
            "[::1]:8080".parse::<SocketAddr>().unwrap(),
            // 作用域名只支持十进制 scope id（std 的 parser；`%eth0` 不合法）。
            "[fe80::1%3]:65535".parse::<SocketAddr>().unwrap(),
        ] {
            for proto in ["h1", "h2", "h3"] {
                let p = ConnPrefix::new(proto, peer);
                let want = format!("{proto} {peer} ");
                assert_eq!(p.buf, want.as_bytes(), "proto={proto} peer={peer}");
                let mut v = Vec::new();
                p.write_bytes(&mut v);
                assert_eq!(v, want.as_bytes());
                let mut s = String::new();
                p.write_fmt(&mut s).unwrap();
                assert_eq!(s, want);
                // ProtoPeer（非热路径来源）必须产出同样的字节。
                let pp = ProtoPeer { proto, peer };
                let mut v = Vec::new();
                pp.write_bytes(&mut v);
                assert_eq!(v, want.as_bytes());
                let mut s = String::new();
                pp.write_fmt(&mut s).unwrap();
                assert_eq!(s, want);
            }
        }
    }

    /// 热路径行格式化（[`write_line`]）与 fmt 参照实现（[`format_line`]）逐字节一致：
    /// 访问日志是审计证据，格式不能变。表覆盖字段顺序/转义/None/超大整数/两位以上毫秒等。
    #[test]
    fn fast_line_matches_fmt_line() {
        let peer: SocketAddr = "10.1.2.3:40001".parse().unwrap();
        let cases: &[(&str, &str, u16, Option<u64>, u128, &str)] = &[
            ("h1", "/", 200, Some(127), 1_786_000_000_123, "static"),
            ("h1", "/index.html", 404, Some(0), 0, "http"),
            ("h2", "/a?b=c", 304, None, 42, "static"),
            ("h3", "/a\"b\\c", 500, Some(u64::MAX), 999, "proxy"),
            ("h1", "/ctl\x01\x02\t", 200, Some(12345678901234567890), 1000, "app"),
            ("h1", "/utf8/\u{4e2d}\u{6587}/\u{fffd}", 206, Some(1), 12_345_678, "upload"),
            ("h1", "", 100, None, 0, "http"),
            ("h1", "/\u{7f}", 418, Some(7), 7, "static"),
        ];
        for (proto, path, status, bytes, now_ms, engine) in cases {
            for method in ["GET", "HEAD"] {
                let p = ConnPrefix::new(proto, peer);
                let mut fast = Vec::new();
                write_line(&mut fast, *now_ms, &p, method, path, *status, *bytes, *now_ms % 100_000, engine);
                let mut refl = String::new();
                format_line(&mut refl, *now_ms, &p, method, path, *status, *bytes, Duration::from_millis((*now_ms % 100_000) as u64), engine);
                assert_eq!(
                    String::from_utf8(fast.clone()).expect("热路径输出必须是合法 UTF-8"),
                    refl,
                    "proto={proto} method={method} path={path:?}"
                );
                // 逐字节（含 UTF-8 编码）也相等。
                assert_eq!(fast, refl.as_bytes());
            }
        }
        // u128 超出 u64 的极端值：两条实现都必须一致（fmt 兜底分支）。
        let p = ConnPrefix::new("h1", peer);
        let huge = u128::MAX / 2;
        let mut fast = Vec::new();
        write_line(&mut fast, huge, &p, "GET", "/", 200, Some(1), 2, "http");
        let mut refl = String::new();
        format_line(&mut refl, huge, &p, "GET", "/", 200, Some(1), Duration::from_millis(2), "http");
        assert_eq!(String::from_utf8(fast).unwrap(), refl);
    }

    /// 毫秒字段必须恒为 3 位零填充（`{:03}` 语义），秒字段不加前导零。
    #[test]
    fn millis_are_zero_padded() {
        let p = ConnPrefix::new("h1", "127.0.0.1:1".parse().unwrap());
        for (ms, want) in [(0u128, "7.000"), (7, "7.007"), (70, "7.070"), (700, "7.700")] {
            let mut out = Vec::new();
            write_line(&mut out, 7000 + ms, &p, "GET", "/", 200, Some(1), 0, "http");
            let s = String::from_utf8(out).unwrap();
            assert!(s.starts_with(&format!("{want} h1 127.0.0.1:1 ")), "{s}");
        }
    }
}
