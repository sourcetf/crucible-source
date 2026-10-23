//! Access log enable/level/realtime with in-memory ring for Admin tail.
//!
//! 行格式（§16.12 全字段）：`{ts} {proto} {peer} "{method} {path}" {status} {bytes} {dur_ms}ms {engine}`
//! —— 在响应完成侧统一记录（请求入口拿不到 status/bytes/duration）。
//! engine 标签由 dispatch 各分支经响应 extensions 注入 [`EngineTag`]。

use crate::config::{AccessLogConfig, ListenerAccessLogConfig};
use crate::server::live_config::LiveConfig;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
/// wave-14 起写入侧换成**顺序提交槽**（[`Ring`]）：每请求领一个完成序号、
/// 格式化进独占槽（无全局锁、无每请求分配），drainer 严格按序号把槽搬进这里
/// 的进程级缓冲。行序仍等于请求完成顺序（审计证据），但每请求不再争同一把
/// Mutex / 同一个 Vec。wave-11 评估过的「每线程一个缓冲」会改变行序，**不采用**。
/// 缓冲上限，超过立即触发一次 flush（在请求线程里做）。
const ACCESS_BUF_FLUSH_AT: usize = 256 * 1024;
/// 后台 flush 间隔。
const ACCESS_FLUSH_EVERY: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------
// 顺序提交槽（wave-14）：去掉「全局 Mutex + 共享 Vec 追加」的跨核争用
// ---------------------------------------------------------------------------
//
// 为什么不用 `Mutex<Vec<u8>>` 直接写：perf6 的差分实测把剩余日志成本拆成
// 时钟 −0.27% / 落盘 I/O −0.64% / **全局 Mutex + 共享 Vec 追加 −1.74%**。
// 两三个 worker 线程每请求都要锁同一个 mutex 并改同一个 Vec 的 len/ptr，
// 这是纯跨 CCD 的 cache-line ping-pong，格式化本身反而是本地的。
//
// 但不能退回「每线程一个缓冲」：perf6 用 `logdiff` 实测到行序变化（同一条
// 300KB 请求的行被排到文件最后），访问日志是审计证据，**行序必须等于
// 请求完成（log 调用）顺序**。
//
// 本实现：每个写者先从全局 `next_seq` 领一个**完成序号**（这一次 fetch_add
// 就是每请求唯一的跨线程原子写），把整行格式化进自己独占的槽（无锁、无分配）；
// 然后按序号发布长度。只有「当前队头」的写者（或后台 flusher）会把槽按序
// 搬进批量缓冲并落盘。因此：
//   * 行序 == 领号顺序 == log 调用顺序（与改动前锁内追加的顺序语义一致）；
//   * 格式化、memcpy 都在线程本地/独占 cache line 上，不再争全局锁；
//   * 槽是预分配的固定数组 —— 没有每请求堆分配；
//   * 超长行（> SLOT_CAP）走 spill：等队头轮到自己后直接按序写缓冲（此时才
//     分配一个临时 Vec；门禁负载不会触发）。
const SLOT_CAP: usize = 1024;
const SLOT_COUNT: usize = 64;
const SLOT_MASK: usize = SLOT_COUNT - 1;
/// `Slot::len` 的空槽标记（真实行远小于 4GiB）。
const SLOT_EMPTY: u32 = u32::MAX;

struct Slot {
    /// 已格式化的字节数；`SLOT_EMPTY` = 槽空闲。Release 发布、Acquire 消费。
    len: AtomicU32,
    /// 写者独占：发布 `len` 之后 lease 结束；drain 侧只在 acquire-load 到非空
    /// `len` 后读这块内存。没有任何时刻两个线程同时读写同一个 slot。
    buf: UnsafeCell<[u8; SLOT_CAP]>,
}

impl Slot {
    const fn new() -> Self {
        Self {
            len: AtomicU32::new(SLOT_EMPTY),
            buf: UnsafeCell::new([0u8; SLOT_CAP]),
        }
    }
}

// 安全性：见上 —— 每个 seq 同一时刻只有一个写者，drain 侧在 `len` 的
// release/acquire 之后才读 `buf`，读的 seq 与写者一一对应；且 `drained`
// 的推进保证槽在被复用前已经 drain 完。
unsafe impl Sync for Slot {}

/// 按完成序号保序的批量缓冲。生产用一个进程级实例（[`ORDERED`]）；单测各自
/// `Ring::new` 一个实例（槽数组 `Box::leak`），互不干扰 —— 全局缓冲会被后台
/// flusher 或别的用例的日志抢走，无法做确定性断言。
struct Ring {
    slots: &'static [Slot],
    /// 下一个要分配的完成序号（单调，不回绕）。
    next_seq: AtomicU64,
    /// 所有 `< drained` 的行都已经搬进 `buf`（或已落盘）。
    drained: AtomicU64,
    /// 批量落盘缓冲；同时充当 drain 串行化锁：队头写者 `try_lock` 成功就直接
    /// 原地追加（旧版另有一把 drain 锁，队头每请求要多付一次 CAS）。
    buf: Mutex<Vec<u8>>,
    /// 只给「落盘」用：保证两次 flush 的 stderr 写入顺序 == 取走数据的顺序。
    /// 正常 append 路径不碰它。
    writing: Mutex<()>,
}

impl Ring {
    const fn new(slots: &'static [Slot]) -> Self {
        Self {
            slots,
            next_seq: AtomicU64::new(0),
            drained: AtomicU64::new(0),
            buf: Mutex::new(Vec::new()),
            writing: Mutex::new(()),
        }
    }

    #[inline]
    fn slot(&self, seq: u64) -> &Slot {
        &self.slots[(seq as usize) & SLOT_MASK]
    }

    /// 等待槽位可复用（环形缓冲已绕一圈且该序号已 drain）。正常路径 seq 远小于
    /// `drained + SLOT_COUNT`，这里只做一次比较。
    ///
    /// 环形缓冲满时**由等待者自己推进 drain**（顺序仍由队头决定）：队头写者
    /// 恰好被抢占/错过唤醒时，仅靠「队头写者顺手 drain」会永久卡住。这里让任何
    /// 需要槽位的线程都能兜底搬运；若队头槽尚未发布，`drain_ready` 会立刻返回，
    /// 循环让出 CPU 等那个写者发布。
    #[inline]
    fn wait_for_slot(&self, seq: u64) {
        if seq < SLOT_COUNT as u64 {
            return;
        }
        while self.drained.load(Ordering::Acquire) + SLOT_COUNT as u64 <= seq {
            if let Some(mut b) = self.buf.try_lock() {
                let _ = self.drain_ready(&mut b);
            } else {
                std::thread::yield_now();
            }
        }
    }

    /// 把已就绪的槽按 seq 顺序追加到 `out`（调用方必须持有 `buf` 锁）。
    /// 返回缓冲是否达到批量落盘阈值。
    fn drain_ready(&self, out: &mut Vec<u8>) -> bool {
        // 最多两轮：第二轮重新读 `next_seq`，把「第一轮快照之后才发布」的行也
        // 顺手搬走（否则它们要等到环形缓冲满或 250ms flusher 才被处理）。
        // 上限两轮是刻意的：突发流量下不把 drainer 永久钉在循环里。
        for _pass in 0..2 {
            let mut head = self.drained.load(Ordering::Relaxed);
            let end = self.next_seq.load(Ordering::Acquire);
            if head >= end {
                break;
            }
            let mut blocked = false;
            while head < end {
                let slot = self.slot(head);
                let len = slot.len.load(Ordering::Acquire);
                if len == SLOT_EMPTY {
                    // 行还没发布（写者被抢占）——停在这里，等它发布后自己来 drain。
                    blocked = true;
                    break;
                }
                debug_assert!((len as usize) <= SLOT_CAP);
                let bytes = unsafe { &*slot.buf.get() };
                out.extend_from_slice(&bytes[..len as usize]);
                out.push(b'\n');
                slot.len.store(SLOT_EMPTY, Ordering::Relaxed);
                head += 1;
                self.drained.store(head, Ordering::Release);
            }
            if blocked {
                break;
            }
        }
        out.len() >= ACCESS_BUF_FLUSH_AT
    }

    /// 取走 `buf` 并写 stderr。`writing` 把「取数据 + 写数据」串成一个整体，
    /// 即使两个线程同时越过阈值/flusher 到期，落盘字节顺序也不会倒置。
    fn write_out(&self) {
        let _w = self.writing.lock();
        let data = {
            let mut b = self.buf.lock();
            if b.is_empty() {
                return;
            }
            std::mem::take(&mut *b)
        };
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(&data);
        let _ = err.flush();
    }

    /// 队头写者（或 spill）在发布后调用：抢到 `buf` 就把连续就绪的行搬走；
    /// 抢不到说明另一个线程正在搬，直接返回（对方会继续，见 drain_ready 的
    /// 队头推进逻辑）。
    fn drain_here(&self) {
        if let Some(mut b) = self.buf.try_lock() {
            let full = self.drain_ready(&mut b);
            drop(b);
            if full {
                self.write_out();
            }
        }
    }

    fn flush(&self) {
        // flusher 是 250ms 周期，也是「行已提交但队头写者恰好被抢占」时的
        // 兜底 drainer：先搬槽，再整块落盘。
        {
            let mut b = self.buf.lock();
            let _ = self.drain_ready(&mut b);
        }
        self.write_out();
    }

    /// 超长行（> SLOT_CAP）的按序直写：等队头轮到自己，再在 `buf` 锁内直接追加。
    /// 调用方已把该 seq 的槽标记为空（drain 侧不会跳过它，因为它正好是队头时
    /// `drained` 会停在这里）。
    #[allow(clippy::too_many_arguments)]
    fn spill_line<P: LinePrefix>(
        &self,
        seq: u64,
        now_ms: u128,
        prefix: &P,
        method: &str,
        path: &str,
        status: u16,
        bytes: Option<u64>,
        dur_ms: u128,
        engine: &str,
    ) {
        let mut line = Vec::with_capacity(SLOT_CAP * 2);
        write_line(&mut line, now_ms, prefix, method, path, status, bytes, dur_ms, engine);
        while self.drained.load(Ordering::Acquire) != seq {
            std::thread::yield_now();
        }
        let full = {
            let mut b = self.buf.lock();
            b.extend_from_slice(&line);
            b.push(b'\n');
            // 行已经进缓冲，drained 才能前移（`< drained` 的行都在 buf 里的不变量）。
            self.drained.store(seq + 1, Ordering::Release);
            b.len() >= ACCESS_BUF_FLUSH_AT
        };
        if full {
            self.write_out();
        }
        // 继续把后面已经就绪的行搬走（不能留给 250ms flusher）。
        let mut b = self.buf.lock();
        let _ = self.drain_ready(&mut b);
    }

    /// 与 [`Ring::spill_line`] 相同，但用于 realtime 路径已经格式化好的行。
    fn spill_bytes(&self, seq: u64, line: &[u8]) {
        while self.drained.load(Ordering::Acquire) != seq {
            std::thread::yield_now();
        }
        let full = {
            let mut b = self.buf.lock();
            b.extend_from_slice(line);
            b.push(b'\n');
            self.drained.store(seq + 1, Ordering::Release);
            b.len() >= ACCESS_BUF_FLUSH_AT
        };
        if full {
            self.write_out();
        }
        let mut b = self.buf.lock();
        let _ = self.drain_ready(&mut b);
    }

    /// 热路径：格式化进独占槽 -> 发布 -> 若自己是队头则顺手 drain。
    #[allow(clippy::too_many_arguments)]
    fn commit_line<P: LinePrefix>(
        &self,
        now_ms: u128,
        prefix: &P,
        method: &str,
        path: &str,
        status: u16,
        bytes: Option<u64>,
        dur_ms: u128,
        engine: &str,
    ) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        self.wait_for_slot(seq);
        let slot = self.slot(seq);
        let mut guard = SeqGuard {
            slot,
            published: false,
        };
        let (len, overflow) = {
            // SAFETY: 这个 seq 的槽在发布前由本线程独占（见 `Slot` 的 Sync 说明）。
            let buf = unsafe { &mut *slot.buf.get() };
            let mut w = SlotW::new(buf);
            write_line(&mut w, now_ms, prefix, method, path, status, bytes, dur_ms, engine);
            (w.len, w.overflow)
        };
        if overflow {
            // 超长行：槽留空，等队头轮到自己后直写（保持顺序；仅此路径分配）。
            slot.len.store(SLOT_EMPTY, Ordering::Release);
            guard.published = true;
            self.spill_line(seq, now_ms, prefix, method, path, status, bytes, dur_ms, engine);
        } else {
            slot.len.store(len as u32, Ordering::Release);
            guard.published = true;
            if self.drained.load(Ordering::Acquire) == seq {
                self.drain_here();
            }
        }
    }

    /// 提交一段已经格式化好的行（realtime=true 路径）。
    fn commit_slice(&self, line: &[u8]) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        self.wait_for_slot(seq);
        let slot = self.slot(seq);
        if line.len() <= SLOT_CAP {
            let buf = unsafe { &mut *slot.buf.get() };
            buf[..line.len()].copy_from_slice(line);
            slot.len.store(line.len() as u32, Ordering::Release);
            if self.drained.load(Ordering::Acquire) == seq {
                self.drain_here();
            }
        } else {
            slot.len.store(SLOT_EMPTY, Ordering::Release);
            self.spill_bytes(seq, line);
        }
    }

    /// 单测：取走缓冲 + 继续 drain 剩余已就绪的槽（模拟 flusher 的兜底）。
    #[cfg(test)]
    fn take_all(&self, out: &mut Vec<u8>) {
        let mut b = self.buf.lock();
        let _ = self.drain_ready(&mut b);
        out.extend_from_slice(&b);
        b.clear();
    }
}

static SLOTS: [Slot; SLOT_COUNT] = [const { Slot::new() }; SLOT_COUNT];
/// 进程级顺序批量缓冲（生产路径）。
static ORDERED: Ring = Ring::new(&SLOTS);

/// 格式化过程中 panic 时也必须发布槽（否则 `drained` 永远停在它，环形缓冲
/// 绕一圈后所有日志调用都会卡住）。正常路径不会触发。
struct SeqGuard<'a> {
    slot: &'a Slot,
    published: bool,
}

impl Drop for SeqGuard<'_> {
    fn drop(&mut self) {
        if !self.published {
            self.slot.len.store(0, Ordering::Release);
        }
    }
}


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
    // 先搬顺序槽里已就绪的行，再整块落盘（见 [`Ring::flush`]）。
    ORDERED.flush();
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
/// 单行格式化的目标（`Vec<u8>` 或顺序槽里的固定缓冲）。两个实现都提供
/// 无格式化的字节追加，热路径不经过 `core::fmt`。
trait ByteSink {
    fn push_byte(&mut self, b: u8);
    fn push_slice(&mut self, s: &[u8]);
}

impl ByteSink for Vec<u8> {
    #[inline]
    fn push_byte(&mut self, b: u8) {
        self.push(b);
    }
    #[inline]
    fn push_slice(&mut self, s: &[u8]) {
        self.extend_from_slice(s);
    }
}

/// 写进顺序槽的固定缓冲。容量不足时只置 overflow，不在热路径上 panic/分配。
struct SlotW<'a> {
    buf: &'a mut [u8],
    len: usize,
    overflow: bool,
}

impl<'a> SlotW<'a> {
    #[inline]
    fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            len: 0,
            overflow: false,
        }
    }
}

impl ByteSink for SlotW<'_> {
    #[inline]
    fn push_byte(&mut self, b: u8) {
        if self.len < self.buf.len() {
            self.buf[self.len] = b;
            self.len += 1;
        } else {
            self.overflow = true;
        }
    }
    #[inline]
    fn push_slice(&mut self, s: &[u8]) {
        match self.len.checked_add(s.len()) {
            Some(end) if end <= self.buf.len() => {
                self.buf[self.len..end].copy_from_slice(s);
                self.len = end;
            }
            _ => self.overflow = true,
        }
    }
}

trait LinePrefix {
    /// 追加 `{proto} {peer} ` 字节（批量缓冲路径）。
    fn write_bytes<S: ByteSink>(&self, out: &mut S);
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
            let mut w = FmtW(&mut buf);
            // 与 [`format_line`] 的前缀段是**同一段格式串**（`{proto} {peer} `）。
            let _ = write!(w, "{proto} {peer} ");
        }
        Self { proto, peer, buf }
    }
}

impl LinePrefix for ConnPrefix<'_> {
    #[inline]
    fn write_bytes<S: ByteSink>(&self, out: &mut S) {
        out.push_slice(&self.buf);
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
    fn write_bytes<S: ByteSink>(&self, out: &mut S) {
        let _ = write!(FmtW(out), "{} {} ", self.proto, self.peer);
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
        // 顺序槽（无中间 `String`、无 `core::fmt` 的逐参数动态分派、无全局锁）。
        // 旧实现每请求 4 次堆分配（ts `format!` / bytes `to_string` / path 转义
        // `collect::<String>()` / 整行 `format!`）——wave-7 去掉 `String`，wave-11
        // 再去掉 `core::fmt`，wave-14 去掉「全局 Mutex + 共享 Vec 追加」。字段顺序、
        // 转义规则与输出逐字不变（访问日志是审计证据，格式不能变；单测
        // `fast_line_matches_fmt_line` 把 [`write_line`] 与 fmt 参照实现逐字节对拍，
        // `slot_lines_preserve_completion_order` 锁定行序）。
        ORDERED.commit_line(
            now, prefix, method, path, status, bytes, dur_ms, engine,
        );
        return;
    }
    // realtime=true：先写进 `String`（Admin 实时窗口要留一份），再按同一顺序
    // 提交进批量缓冲。该路径不在吞吐热路径上，沿用 wave-7 的 fmt 单实现
    // （[`format_line`]）。
    let mut line = String::with_capacity(path.len() + 64);
    format_line(
        &mut line, now, prefix, method, path, status, bytes, dur, engine,
    );
    ORDERED.commit_slice(line.as_bytes());
    {
        let mut ring = RING.lock();
        if ring.len() >= 512 {
            ring.pop_front();
        }
        ring.push_back(line);
    }
}

/// `fmt::Write` 适配器：把 fmt 输出接进任意 [`ByteSink`]。
/// 仅用于前缀段的**每连接/每请求一次**的 fmt 格式化（[`ConnPrefix::new`]、
/// [`ProtoPeer`]）；行主体的热路径见 [`write_line`]。
struct FmtW<'a, S: ByteSink>(&'a mut S);
impl<S: ByteSink> std::fmt::Write for FmtW<'_, S> {
    #[inline]
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.push_slice(s.as_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 手写十进制（热路径：去 `core::fmt` 的逐参数动态分派与 u128 除法）
// ---------------------------------------------------------------------------

/// 十进制追加（u64；无 `core::fmt`）。
#[inline]
fn push_u64<S: ByteSink>(out: &mut S, mut v: u64) {
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
    out.push_slice(&buf[i..]);
}

/// 十进制追加（u128）。`SystemTime`/`Duration` 的实际值恒在 u64 范围内，走 u64
/// 快路径；极端值用同一套手写循环（u128 软除法只在这个不会发生的分支里）。
#[inline]
fn push_u128<S: ByteSink>(out: &mut S, v: u128) {
    if v <= u64::MAX as u128 {
        push_u64(out, v as u64);
        return;
    }
    let mut buf = [0u8; 40];
    let mut i = buf.len();
    let mut v = v;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.push_slice(&buf[i..]);
}

/// 单条访问日志行的格式化（热路径：直接进 `Vec<u8>`）。
///
/// 与 [`format_line`]（realtime 路径的 fmt 实现）**逐字节等价**：同一段前缀、
/// 同一套转义规则、同一个字段顺序。单测 `fast_line_matches_fmt_line` 用同一张
/// 输入表把两者对拍（含 `"` / `\` / 控制字符 / 非 ASCII 路径、超大整数、
/// `bytes=None`、v4/v6 peer）。
#[allow(clippy::too_many_arguments)]
#[inline]
fn write_line<S: ByteSink, P: LinePrefix>(
    out: &mut S,
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
    out.push_byte(b'.');
    out.push_byte(b'0' + (ms / 100) as u8);
    out.push_byte(b'0' + ((ms / 10) % 10) as u8);
    out.push_byte(b'0' + (ms % 10) as u8);
    out.push_byte(b' ');
    prefix.write_bytes(out);
    out.push_byte(b'"');
    out.push_slice(method.as_bytes());
    out.push_byte(b' ');
    // `path` 是请求目标，**不能原样进引号字段**：含 `"` 的请求能提前结束引号、
    // 把后面的字段伪造成任意内容（日志是审计证据，伪造一行等于污染审计）。
    for c in path.chars() {
        if c == '"' || c == '\\' || (c as u32) < 0x20 {
            out.push_slice("\u{fffd}".as_bytes());
        } else {
            let mut tmp = [0u8; 4];
            out.push_slice(c.encode_utf8(&mut tmp).as_bytes());
        }
    }
    out.push_byte(b'"');
    out.push_byte(b' ');
    push_u64(out, status as u64);
    out.push_byte(b' ');
    match bytes {
        Some(n) => push_u64(out, n),
        None => out.push_byte(b'-'),
    }
    out.push_byte(b' ');
    push_u128(out, dur_ms);
    out.push_slice(b"ms ");
    out.push_slice(engine.as_bytes());
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

    /// 单测专用实例：独立槽数组 + 独立缓冲，不受全局 `ORDERED` / 后台
    /// flusher / 其它用例日志的干扰（全局缓冲无法做确定性断言）。
    fn new_test_ring() -> &'static Ring {
        let slots: Vec<Slot> = (0..SLOT_COUNT).map(|_| Slot::new()).collect();
        let slots: &'static [Slot] = Box::leak(slots.into_boxed_slice());
        Box::leak(Box::new(Ring::new(slots)))
    }

    fn ring_lines(ring: &Ring) -> Vec<u8> {
        let mut v = Vec::new();
        ring.take_all(&mut v);
        v
    }

    /// 批量写路径不能改变**行内容**：拼进去的必须是同一行 + 单个换行，
    /// 且 flush 之后缓冲清空（否则会重复落盘）。
    #[test]
    fn buffered_lines_are_exact_and_flush_clears() {
        let ring = new_test_ring();
        // 不启动后台线程，直接检查缓冲语义
        const LINE: &str = "1788 h1 127.0.0.1:1 \"GET /\" 200 127 1ms static";
        {
            let mut b = ring.buf.lock();
            b.clear();
            b.extend_from_slice(LINE.as_bytes());
            b.push(b'\n');
        }
        let snapshot = ring.buf.lock().clone();
        assert_eq!(snapshot.len(), LINE.len() + 1);
        assert_eq!(snapshot.last(), Some(&b'\n'));
        assert_eq!(snapshot.iter().filter(|c| **c == b'\n').count(), 1);
        // flush 只取走数据、不销毁缓冲（容量保留），且再次调用是空操作。
        let taken = { let mut b = ring.buf.lock(); std::mem::take(&mut *b) };
        assert_eq!(taken.len(), LINE.len() + 1);
        assert!(ring.buf.lock().is_empty());
    }

    /// wave-14 的硬约束：多线程提交后，落盘行序必须等于**领号（完成）顺序**，
    /// 每个线程内部的行序当然也必须保持；不丢行、不重复、不撕裂。
    #[test]
    fn slot_lines_preserve_completion_order() {
        let ring = new_test_ring();
        let threads = 4usize;
        let per = 500usize;
        let mut hs = Vec::new();
        for t in 0..threads {
            hs.push(std::thread::spawn(move || {
                for i in 0..per {
                    let line = format!("T{t}:{i}");
                    ring.commit_slice(line.as_bytes());
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let all = ring_lines(ring);
        let text = String::from_utf8(all).expect("日志必须是合法 UTF-8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), threads * per, "行数必须一条不少");
        let mut next = vec![0usize; threads];
        for l in &lines {
            let (t, i) = l.split_once(':').expect("行格式 T{t}:{i}");
            let t: usize = t[1..].parse().unwrap();
            let i: usize = i.parse().unwrap();
            assert_eq!(i, next[t], "线程 {t} 的行序被打乱：见到 {i}，期望 {}", next[t]);
            next[t] += 1;
        }
        for (t, n) in next.iter().enumerate() {
            assert_eq!(*n, per, "线程 {t} 有丢行");
        }
    }

    /// 超长行（> SLOT_CAP）走 spill 时也必须严格按序，且内容逐字节完整。
    #[test]
    fn oversized_line_spills_in_order() {
        let ring = new_test_ring();
        ring.commit_slice(b"before");
        let big = vec![b'x'; SLOT_CAP + 200];
        ring.commit_slice(&big);
        ring.commit_slice(b"after");
        let all = ring_lines(ring);
        let text = String::from_utf8(all).expect("日志必须是合法 UTF-8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "spill 行不能丢/不能拆");
        assert_eq!(lines[0], "before");
        assert_eq!(lines[1].len(), SLOT_CAP + 200);
        assert!(lines[1].bytes().all(|b| b == b'x'));
        assert_eq!(lines[2], "after");
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
