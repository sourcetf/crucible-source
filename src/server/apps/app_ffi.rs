//! dlopen-based app engine FFI (RTLD_GLOBAL).
//!
//! §7.3 最终态：**所有**引擎都走有界线程池（通用 clamp(4..=8)，rack/psgi 串行单线程，
//! cgi 独立窄池）+ 按内容分锁。
//!
//! 这里曾经给 c/go/rust 留了一条「同线程内联、跳过 env 锁」的快路。那条快路的前提是错的：
//! 它以为这些引擎拿 `.env` 变量走的是「extra JSON 下发、不碰进程级 env」，而 C 侧的
//! `appengine_apply_extra` 落地方式就是 **setenv**（libs/app-engines/common/appengine_common.c
//! 与 samples/{c,rust}-plugin 都是）——于是这条快路成了进程 env 唯一不受 [`env_lock`] 保护、
//! 也从不把值恢复回去的写者。现在 c/go/rust 与其它引擎同路（见 [`execute`]）。
//! ABI 的 headers 块与请求 body/content_type 全量透传（旧实现把引擎设置
//! 的响应头整体丢弃，导致 ngx.header / WSGI 自定义头失效、POST 空 body）；
//! 但定界头（Content-Length）不原样透传 —— 见 response_from_outcome 的说明。

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::env_lock;
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[repr(C)]
struct AppEngineResult {
    status: c_int,
    headers: *mut c_char,
    headers_len: usize,
    body: *mut u8,
    body_len: usize,
    error: *mut c_char,
}

type InitFn = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
type ExecFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const u8,
    usize,
    *const c_char,
    *const c_char,
    c_int,
    *const c_char,
    *const c_char,
    *mut AppEngineResult,
) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut AppEngineResult);
type ShutdownFn = unsafe extern "C" fn();
type AbiVersionFn = unsafe extern "C" fn() -> c_int;
/// 可选符号（见 `appengine.h`）：把**启动期基底环境**交给引擎。
type SetBaseEnvFn = unsafe extern "C" fn(*const c_char) -> c_int;
/// 可选符号（见 `appengine.h`）：引擎自报「不依赖进程 env」（子进程 envp 只由
/// 基底 + 本请求 `.env` 拼出、从不 setenv、从不继承 `environ`）。非 0 = 是。
///
/// 用**引擎自报**而不是宿主按引擎名维护名单：陈旧 .so 同样链接了 common 里的
/// `appengine_set_base_env`（符号在 ≠ 引擎真的用它），按名放行会让那只 .so 在
/// 进程 env 锁外跑 ⇒ 跨应用 `.env` 泄漏回归。取自报后，陈旧 .so 缺这个符号 ⇒
/// 自动留在锁内（正确性优先，只是少一点并发）。
type EnvIsolationFn = unsafe extern "C" fn() -> c_int;

/// Host-side ABI version. **Must** equal `APPENGINE_ABI_VERSION` in
/// `libs/app-engines/include/appengine.h` (and in the go/rust plugin samples).
///
/// Why this check is load-bearing (measured P0): C gives the loader no arity
/// information, so a `.so` built against an **older** `appengine_execute`
/// signature is happily dlopen'd (all symbols resolve, `RTLD_NOW` passes) and
/// then called with the host's argument list. A `.so` built before the
/// `headers` parameter existed reads `out` from the `headers` argument slot —
/// `appengine_result_alloc()` then memsets 48 bytes over the request-header
/// heap string, and the resulting glibc `sysmalloc` assertion aborted the
/// **whole webserver** (all listeners down), with every `/c/` request returning
/// a bogus 500. Requiring the version symbol turns this silent corruption into
/// a clean "rebuild engines" 502.
const APPENGINE_ABI_VERSION: c_int = 2;

/// `RTLD_NODELETE` 的平台值。
///
/// 为什么自己定义：OpenBSD 的 `<dlfcn.h>` 有它（0x400），但 `libc` crate 的 OpenBSD
/// 绑定没有导出。各平台取值不同，按平台写死；未知平台取 0（退化为普通 dlclose，
/// 至少在那些平台上不会因常数写错而误置其它 flag）。
#[cfg(target_os = "openbsd")]
const RTLD_NODELETE_EXT: libc::c_int = 0x400;
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const RTLD_NODELETE_EXT: libc::c_int = 0x1000;
#[cfg(target_os = "macos")]
const RTLD_NODELETE_EXT: libc::c_int = 0x80;
#[cfg(not(any(
    target_os = "openbsd",
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "macos"
)))]
const RTLD_NODELETE_EXT: libc::c_int = 0;

struct EngineLib {
    engine: String,
    path: String,
    // libloading::Library 自动 dlclose on Drop (其内部用 NonNull<c_void>)
    _lib: libloading::Library,
    #[allow(dead_code)]
    init: InitFn,
    exec: ExecFn,
    free: FreeFn,
    shutdown: ShutdownFn,
    /// 本 .so **自报**「不依赖进程 env」⇒ 宿主可以对它**跳过** [`env_lock`] 的进程 env 互斥。
    ///
    /// 判据（两个可选符号都成立）：`appengine_set_base_env` 调用成功（引擎拿到了启动期基底）
    /// **且** `appengine_env_isolation()` 返回非 0（引擎声明它按子进程/子请求传 `.env`、
    /// 从不 setenv、从不继承 `environ`）。
    ///
    /// 必须按 **每个 .so** 实测，不能按引擎名硬编码：声明 lock-free 的引擎配上一只**旧**
    /// `.so`（仍旧 `appengine_apply_extra` → setenv + 继承 environ；但 common.c 里的
    /// `appengine_set_base_env` 符号**照样存在**）时若跳锁，那只 .so 就会在别人 `.env`
    /// 生效的窗口里读到别人的私密值 —— 跨应用泄漏又回来了。取自报后，这种 .so 自动留锁。
    env_free: bool,
}

unsafe impl Send for EngineLib {}
unsafe impl Sync for EngineLib {}

impl Drop for EngineLib {
    fn drop(&mut self) {
        // Deferred reconcile unload: last Arc drops → shutdown + (libloading 自动 dlclose).
        unsafe { (self.shutdown)() };
    }
}


/// 缓存键 = .so 路径字符串（同引擎多 lib 并存时不串台）。
static LIBS: Lazy<Mutex<HashMap<String, Arc<EngineLib>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 每个 .so 路径一把装载锁。
///
/// 原来的 check-then-insert 不是原子的：两个并发冷请求会各 dlopen 一次、
/// 各跑一次 `appengine_init`，而 map 里只留后者——先到的那个 Arc 被 drop 时
/// 会调用 `appengine_shutdown()`，把仍在被另一个请求执行中的实例状态拆掉。
/// 分路径加锁既消除重复装载，又不让不同引擎互相阻塞。
static LOAD_LOCKS: Lazy<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------- 临时性能剖析（CRUCIBLE_APP_PROF=1）
//
// 只在 `CRUCIBLE_APP_PROF=1` 时统计；默认零开销（一次 OnceLock 读取）。
// 每 2s 把各阶段累计 ns/count 打到 stderr，用于定位引擎路径的 µs 分解。
// 这是本 wave 的测量脚手架，定位完成后删除。
#[doc(hidden)]
pub mod prof {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    pub const S_ALL: usize = 0;
    pub const S_EXEC_PREP: usize = 1;
    pub const S_DISPATCH_PRE: usize = 2;
    pub const S_QUEUE_WAIT: usize = 3;
    pub const S_EXEC_WAIT: usize = 4;
    pub const S_RESP_BUILD: usize = 5;
    pub const S_JOB_TOTAL: usize = 6;
    pub const S_JOB_LOAD: usize = 7;
    pub const S_JOB_ENVLOCK: usize = 8;
    pub const S_CALL_TOTAL: usize = 9;
    pub const S_CALL_PREP: usize = 10;
    pub const S_ENGINE_CALL: usize = 11;
    pub const S_CALL_RESULT: usize = 12;
    pub const S_TRY_PREP: usize = 13;
    pub const S_TRY_DEPS: usize = 14;
    pub const S_FALLBACK_PREP: usize = 15;
    pub const S_RESOLVE_LIB: usize = 16;
    pub const S_REL_SCRIPT: usize = 17;
    pub const S_STAT: usize = 18;
    pub const S_QUAR: usize = 19;
    pub const S_LIB_AVAIL: usize = 20;
    pub const S_TRY_INSERT: usize = 21;
    pub const S_TRY_ALL: usize = 22;
    pub const S_N: usize = 23;

    pub const NAMES: [&str; S_N] = [
        "all",
        "exec_prep",
        "dispatch_pre",
        "queue_wait",
        "exec_wait",
        "resp_build",
        "job_total",
        "job_load",
        "job_envlock",
        "call_total",
        "call_prep",
        "engine_call",
        "call_result",
        "try_prep",
        "try_deps",
        "fallback_prep",
        "resolve_lib",
        "rel_script",
        "stat",
        "quar",
        "lib_avail",
        "try_insert",
        "try_all",
    ];

    static NS: [AtomicU64; S_N] = [const { AtomicU64::new(0) }; S_N];
    static CNT: [AtomicU64; S_N] = [const { AtomicU64::new(0) }; S_N];
    static ENABLED: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| match std::env::var("CRUCIBLE_APP_PROF") {
            Ok(v) => v.trim() == "1",
            Err(_) => false,
        });
    static REPORTER: std::sync::Once = std::sync::Once::new();

    #[inline]
    pub fn enabled() -> bool {
        *ENABLED
    }

    pub struct Span {
        idx: usize,
        start: Instant,
    }

    impl Drop for Span {
        fn drop(&mut self) {
            if *ENABLED {
                NS[self.idx].fetch_add(self.start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                CNT[self.idx].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    pub fn span(idx: usize) -> Option<Span> {
        if !*ENABLED {
            return None;
        }
        REPORTER.call_once(|| {
            std::thread::Builder::new()
                .name("app-prof".into())
                .spawn(|| {
                    let mut prev = [0u64; S_N];
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        let mut line = String::from("app-prof:");
                        for i in 0..S_N {
                            let ns = NS[i].load(Ordering::Relaxed);
                            let cnt = CNT[i].load(Ordering::Relaxed);
                            let d = ns.saturating_sub(prev[i]);
                            prev[i] = ns;
                            let per = if cnt > 0 { d as f64 / 1000.0 / cnt as f64 } else { 0.0 };
                            line.push_str(&format!(" {}={:.2}us/{}", NAMES[i], per, cnt));
                        }
                        eprintln!("{line}");
                    }
                })
                .ok();
        });
        Some(Span {
            idx,
            start: Instant::now(),
        })
    }

    /// 立即记录一次（起点已经取过）。
    #[inline]
    pub fn note(idx: usize, start: Instant) {
        if *ENABLED {
            NS[idx].fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            CNT[idx].fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ------------------------------------------------------------------ 看门狗（墙钟）

/// 单次 FFI 调用的墙钟上限。
///
/// 背景：`appengine_execute` 是**同步** C 调用，一个死循环/自死锁的引擎会永久占住
/// worker 线程；若它同时持有宿主 env 锁（非自报 env-free 的引擎），整站锁引擎都会
/// 排队到永远（真机：`while true do end` 的 lua 让其它锁引擎全部超时）。
///
/// 默认 60s（与 fastcgi 的 FCGI_TIMEOUT 同量级；cgi/sidecar 是 30s），
/// `CRUCIBLE_APP_ENGINE_TIMEOUT_SECS=0` 关闭看门狗（回到「无限等」的旧行为）。
/// 调大可以容纳「正常的长请求」，但代价是卡死时等待更久。
const ENGINE_WATCHDOG_DEFAULT_SECS: u64 = 60;

fn engine_call_timeout() -> Option<Duration> {
    match env_lock::read_static_env("CRUCIBLE_APP_ENGINE_TIMEOUT_SECS") {
        None => Some(Duration::from_secs(ENGINE_WATCHDOG_DEFAULT_SECS)),
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(Duration::from_secs(n)),
            Err(_) => {
                log::warn!(
                    "app_ffi: CRUCIBLE_APP_ENGINE_TIMEOUT_SECS={raw:?} 不是合法秒数，回退默认 {ENGINE_WATCHDOG_DEFAULT_SECS}s"
                );
                Some(Duration::from_secs(ENGINE_WATCHDOG_DEFAULT_SECS))
            }
        },
    }
}

/// 单次 FFI 调用在**线程池队列里**的等待上限（与「引擎执行」上限分开的第二段 deadline）。
///
/// 为什么必须分开（P1，真机复现）：旧实现把「入池排队 + 引擎执行」算进同一个 deadline，
/// 于是**池饱和时排队时间会冒充执行超时** —— 8 条合法长请求（各 4s）占满通用池后，第 9 个
/// 请求排队 4s + 执行 4s（共 8s）> 6s ⇒ 判超时 ⇒ 隔离该 **健康** 引擎 + 毒化 env 锁
///（之后 `/wsgi-b/` 0.5ms 502，只有重启能恢复）。排队**不是**「引擎卡死」的证据。
///
/// 默认与执行上限**同值**（即 `CRUCIBLE_APP_ENGINE_TIMEOUT_SECS`，保持既有容忍度），可用
/// `CRUCIBLE_APP_ENGINE_QUEUE_TIMEOUT_SECS` 单独调小：池饱和时客户端尽快拿到**可重试的
/// 503**，而不是等满执行上限。`0` = 不设排队上限（只受执行上限约束）。
/// 执行上限被关闭（`CRUCIBLE_APP_ENGINE_TIMEOUT_SECS=0`）时默认也关闭排队上限。
fn engine_queue_timeout() -> Option<Duration> {
    let exec = engine_call_timeout();
    match env_lock::read_static_env("CRUCIBLE_APP_ENGINE_QUEUE_TIMEOUT_SECS") {
        None => exec,
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(Duration::from_secs(n)),
            Err(_) => {
                log::warn!(
                    "app_ffi: CRUCIBLE_APP_ENGINE_QUEUE_TIMEOUT_SECS={raw:?} 不是合法秒数，回退（与执行上限同值）"
                );
                exec
            }
        },
    }
}

/// 「在线程池队列里等待超过排队 deadline」的独立错误类型。
///
/// 调用方（`apps::engine_error` / `simple_engine_error`）据此回 **503 + Retry-After**
/// 而不是通用 502：引擎**健康**，只是 worker 全被合法长请求占着 —— 这类失败是**可重试**的，
/// 与「引擎卡死被隔离」（502，必须重启 webserver）必须区分。**不**隔离、**不**毒化 env 锁
///（没有任何「引擎卡死」的证据）—— 见 `exec_dispatch` 的两段 deadline。
#[derive(Debug)]
pub struct EnginePoolBusy {
    pub engine: String,
    pub waited_secs: u64,
}

impl std::fmt::Display for EnginePoolBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "engine `{}` worker pool busy: queued longer than {}s",
            self.engine, self.waited_secs
        )
    }
}

impl std::error::Error for EnginePoolBusy {}

/// 排队超时的 503 响应体（h1 与 h2/h3 共用同一常量 ⇒ 跨协议逐字一致；不含服务器路径）。
pub const ENGINE_BUSY_BODY: &str =
    "503 Service Unavailable: engine worker pool busy (queue wait exceeded); retry shortly\n";

/// 两段 deadline 的状态机取值（见 `exec_dispatch`）。
///
/// 只有 worker 会把 `Queued` 换成 `Started`（CAS，成功后才发 started 信号、并承诺执行）；
/// 只有请求方会把 `Queued` 换成 `Cancelled`（排队超时的 CAS）。两个方向的 CAS 互斥，
/// 因此不存在「客户端已收到 503 但引擎仍被调用（副作用已发生）」或「引擎已开始执行却
/// 被当成排队超时」的模糊态。
const CALL_QUEUED: u8 = 0;
const CALL_STARTED: u8 = 1;
const CALL_CANCELLED: u8 = 2;

/// 超时后被隔离的 .so 集合（键 = lib 路径，与 [`LIBS`] 相同）。
///
/// 超时后**不能**再调用同一只 .so：卡死的调用可能还在跑（我们无法安全地中断任意 C
/// 代码——杀线程会在任意指令处损坏堆/解释器状态），再并发进来只会把损失放大。
/// 隔离是**永久**的（fail-closed）：该引擎后续请求立即 502，恢复靠重启 webserver。
/// 只损失这一只 .so；其它引擎（含自报 env-free 的 cgi）不受影响。
static QUARANTINED: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

fn is_quarantined(lib_key: &str) -> bool {
    QUARANTINED.lock().contains(lib_key)
}

fn quarantine(lib_key: &str, engine: &str, secs: u64) {
    let first = QUARANTINED.lock().insert(lib_key.to_string());
    if first {
        log::error!(
            "app_ffi: engine `{engine}` ({lib_key}) 单次调用超过 {secs}s 未返回 → **隔离该 .so**。\
             卡死调用继续占着它的 worker 线程（进程内无法安全终止），但该引擎的新请求会立即 502；\
             若它持有 env 锁，锁已毒化（其它引擎同样快速 502）。重启 webserver 恢复。"
        );
    }
}

/// 该 .so 是否自报 env-free（用于决定超时是否毒化 env 锁）。
/// 装载尚未完成时（卡在 dlopen/init）取不到，按「非 env-free」处理（保守毒化）。
fn lib_is_env_free(lib_key: &str) -> bool {
    LIBS.lock()
        .get(lib_key)
        .map(|l| l.env_free)
        .unwrap_or(false)
}

/// §7.2 引擎单次执行的结果（状态码 + 头块 + body）。
pub struct ExecOutcome {
    pub status: i32,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

pub async fn execute(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    let _p_all = prof::span(prof::S_ALL);
    let p_prep = prof::span(prof::S_EXEC_PREP);
    // P1-1：.env 变量由 apps::try_handle 注入 extensions。所有引擎（含 c/go/rust）都经
    // env_lock 把它们装进**进程环境**：C 侧的 appengine_apply_extra 就是 setenv，没有
    // 哪条引擎路径是「只下发、不碰进程 env」的。
    // Arc clone（O(1)）；旧实现 `(*d.vars).clone()` 每请求深拷贝整份 .env。
    let env_vars: Arc<Vec<(String, String)>> = req
        .extensions()
        .get::<crate::server::apps::deps::DepsEnv>()
        .map(|d| d.vars.clone())
        .unwrap_or_default();
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // ABI 请求头块（Cookie/Authorization/User-Agent/X-Request-Id…）：
    // 此前引擎侧**完全看不到任何请求头**，Flask session / Django 登录等真实应用
    // 因此不可用。h1 路径从已解析的 parts.headers 直接构造。
    let headers_block = request_headers_block(&parts.headers, parts.uri.authority());
    // §7.10 热路径：GET/HEAD 无 body 时不 collect，保持 rust≈static 的延迟。
    // 任务 6（OOM 防护）：引擎请求体上限 32MiB，超限 413。
    let body_bytes = if request_has_body(&parts.method, &parts.headers) {
        match http_body_util::Limited::new(body, crate::server::h1::APP_BODY_CAP).collect().await
        {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(full("request body too large"))
                    .unwrap())
            }
        }
    } else {
        Bytes::new()
    };
    let outcome = {
        drop(p_prep);
        exec_dispatch(
            &method,
            &path,
            &query,
            &content_type,
            &body_bytes,
            lc,
            app,
            peer,
            env_vars.as_slice(),
            &headers_block,
        )
        .await?
    };
    let _p_resp = prof::span(prof::S_RESP_BUILD);
    Ok(response_from_outcome(outcome))
}

/// `Request<Bytes>` 变体（H2/H3 simple 路径）——P1-9：请求体已在协议层收齐，
/// 连同 .env 变量（P1-1）一起交给引擎，不再恒传空 body。
pub async fn execute_simple(
    req: &Request<Bytes>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    deps: &crate::server::apps::deps::DepsEnv,
) -> Result<ExecOutcome> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // h2/h3 字节路径同样携带完整请求头（与 h1 同一数据流）。
    let headers_block = request_headers_block(req.headers(), req.uri().authority());
    exec_dispatch(
        &method,
        &path,
        &query,
        &content_type,
        req.body(),
        lc,
        app,
        peer,
        deps.vars.as_slice(),
        &headers_block,
    )
    .await
}

/// 构造引擎 ABI 的请求头块：每行 `Name: Value`、行间 `\r\n`（返回内容不含 NUL）。
///
/// * hop-by-hop 头（Connection/Keep-Alive/TE/Transfer-Encoding/Upgrade/Trailer/
///   `Proxy-*`）按 RFC 7230 逐跳语义不透传给应用；`Content-Length`/
///   `Content-Type` 有独立形参（CGI 环境里是 CONTENT_LENGTH/CONTENT_TYPE），
///   不重复进块，避免引擎把同名头当 HTTP_* 再写一遍。
/// * 名字非 token、值含 CR/LF/NUL 或其它控制字符的头一律跳过（头注入防线）。
/// * 块总量 64KiB、单值 16KiB 封顶，与 C 侧解析器的上界一致。
fn request_headers_block(headers: &http::HeaderMap, authority: Option<&http::uri::Authority>) -> Vec<u8> {
    const VALUE_CAP: usize = 16 * 1024;
    const BLOCK_CAP: usize = 64 * 1024;
    // 预分配，避免逐条 extend 的多次 realloc；`HeaderName::as_str()` 已是小写，
    // 但这里用 eq_ignore_ascii_case 比较（不假设实现细节，也**不再逐头分配** lowercase）。
    let mut out = Vec::with_capacity(headers.len().saturating_mul(24).saturating_add(16));
    let mut has_host = false;
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        let is_proxy = n.len() >= 6 && n.as_bytes()[..6].eq_ignore_ascii_case(b"proxy-");
        let hop_by_hop = is_proxy
            || n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("keep-alive")
            || n.eq_ignore_ascii_case("te")
            || n.eq_ignore_ascii_case("transfer-encoding")
            || n.eq_ignore_ascii_case("upgrade")
            || n.eq_ignore_ascii_case("trailer")
            || n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("content-type");
        if hop_by_hop {
            continue;
        }
        if !n.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
            continue;
        }
        let v = value.as_bytes();
        if v.len() > VALUE_CAP
            || v.iter()
                .any(|&b| b == b'\r' || b == b'\n' || b == b'\0' || (b < 0x20 && b != b'\t') || b == 0x7f)
        {
            continue;
        }
        if out.len() + n.len() + v.len() + 4 > BLOCK_CAP {
            break;
        }
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    // HTTP/2、HTTP/3 的权威信息在 `:authority` 伪头（hyper 映射到 `uri.authority()`），
    // **没有**字面 `Host` 头。CGI 语义里 `HTTP_HOST` 就是请求的 Host —— 缺了它，引擎在
    // h2/h3 上拿不到 `HTTP_HOST`（h1 有），Flask/Django/内容协商等按 Host 判定的应用
    // 行为跨协议不一致。缺 `Host` 时用 authority 补一条。
    if !has_host {
        if let Some(a) = authority {
            let s = a.as_str();
            if !s.is_empty()
                && s.bytes().all(|b| b.is_ascii_graphic())
                && out.len() + s.len() + 8 <= BLOCK_CAP
            {
                out.extend_from_slice(b"host: ");
                out.extend_from_slice(s.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    out
}

async fn exec_dispatch(
    method: &str,
    path: &str,
    query: &str,
    content_type: &str,
    body: &Bytes,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    env_vars: &[(String, String)],
    headers: &[u8],
) -> Result<ExecOutcome> {
    let p_dispatch = prof::span(prof::S_DISPATCH_PRE);
    let engine = app.engine.to_ascii_lowercase();
    let p_lib = prof::span(prof::S_RESOLVE_LIB);
    let lib_path = resolve_lib(app, &engine)?;
    drop(p_lib);
    // docroot / server_name 在热路径上**只借不克隆**：内联路径不需要任何 owned 拷贝，
    // 池路径再克隆（见下方 `docroot_owned`）。
    let docroot: &Path = app.docroot.as_deref().unwrap_or(lc.root.as_path());
    // §3.3 语义：docroot 已是应用级根（www-apps/<engine>），script 必须用剥掉
    // app 前缀后的相对路径（/lua/index.lua → index.lua）；目录/根请求回落 app.index。
    // 旧实现整条 request path 直接 join，导致 docroot 双重前缀（lua/wsgi 等真读
    // 文件的引擎 500，而 rust/c/go 样例插件不读文件被掩盖）。
    // §7.1 防穿越：script 必须留在 docroot 下（裸 join 可 /engine/../../ 读任意文件）。
    let p_rel = prof::span(prof::S_REL_SCRIPT);
    let rel = rel_script_path(app, path);
    let script = resolve_script_cached(docroot, rel.trim_start_matches('/'))?;
    drop(p_rel);
    // **非普通文件一律不交给引擎**：docroot 里存在 FIFO/字符设备/目录时，引擎侧多是
    // `fopen`/`luaL_loadfile` 直接打开它 —— FIFO 无写端时 open() 会**永久阻塞**，
    // 而 FFI 引擎调用没有墙钟超时，且调用期间持有宿主的 env 锁 ⇒ 一次请求就把
    // **所有**依赖 env 锁的引擎（wsgi/asgi/lua/python/c/asp/aspnet…）永久挂死
    // （真机实测：docroot 里一个 FIFO 的 `.aspx` 让随后 wsgi/asgi/lua 全部超时）。
    // 这里在中央入口挡住，比逐个引擎补 `is_regular_file` 更完整（C 引擎仍各自保留
    // 自己的检查作为纵深防御）。**目录不算**：无 `index` 配置且引擎无默认首页时
    // `script` 会解析成 docroot 目录本身（c/go 样例就忽略 script），目录上 fopen 只会
    // 返回 EISDIR，不会阻塞。文件**不存在**时也不做判断：cgi 引擎还会按
    // docroot/index.cgi → cgi-bin/index.cgi 回落，语义不变。
    let port = lc.port;
    let server_name: &str = lc.server_name.as_deref().unwrap_or("crucible");

    let lib_key_cow = lib_path.to_string_lossy();
    // 入池前先拒绝已被看门狗隔离的 .so：快速 502，不占 worker、不让请求排队。
    let p_quar = prof::span(prof::S_QUAR);
    let quarantined = is_quarantined(lib_key_cow.as_ref());
    drop(p_quar);
    if quarantined {
        bail!(
            "engine `{engine}` is quarantined (a previous call exceeded the wall clock); \
             restart webserver to recover"
        );
    }
    // ---- §22.4.2 native_inline：c/go/rust 在请求线程内联执行 ----
    // 这两次跨线程唤醒（入池 + 回传）在 c8 门禁下实测占每请求 ~60µs 的等待；
    // 内联后用同一份 env 锁语义（空组可并发/不同组互斥）直接调用。
    if inline_engine(&engine) {
        drop(p_dispatch);
        return inline_exec(
            &engine, &lib_path, lib_key_cow.as_ref(), &script, docroot, method, path, query,
            content_type, body, peer, port, server_name, env_vars, headers,
        );
    }
    // 池路径需要 owned 键（closure 是 'static；lib_path 也要 move 进去）。
    let lib_key = lib_key_cow.into_owned();

    // ---- 进程池路径（其它引擎；c/go/rust 可用 CRUCIBLE_APP_INLINE=0 强制走这里）----
    let docroot_owned = docroot.to_path_buf();
    let server_name_owned = server_name.to_string();
    let m = method.to_string();
    let p = path.to_string();
    let q = query.to_string();
    let ct = content_type.to_string();
    let b = body.clone();

    let serial = serial_engine(&engine);
    let engine_for_pool = engine.clone();
    // P1-1：闭包必须持有 owned 环境变量（'static），在闭包内转 &[(&str,&str)]。
    let env_vars_owned: Vec<(String, String)> = env_vars.to_vec();
    let headers_owned: Vec<u8> = headers.to_vec();
    // **两段 deadline 的状态机**（见 `engine_queue_timeout`）：`Queued` → 由 worker 在真正
    // 开始执行时置 `Started`；请求方在排队超时时 CAS `Queued → Cancelled`。
    //   * CAS 成功 ⇒ 调用**从未开始执行**，给客户端可重试的 503，绝不隔离/毒化；
    //     作业随后被 worker 取出时看到 `Cancelled`，直接返回（不跑引擎、不碰 env 锁）。
    //   * CAS 失败 ⇒ 排队与开始执行在超时边缘赛跑中「已开始」：调用取消不了，按执行
    //     deadline 继续等结果（执行时钟从此刻起算，语义仍正确）。
    let stage = Arc::new(std::sync::atomic::AtomicU8::new(CALL_QUEUED));
    let stage_job = Arc::clone(&stage);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let stage_engine = engine.clone();
    let quarantined_key = lib_key.clone();
    let job = move || {
        // 排队结束、承诺执行：CAS `Queued → Started`。失败只可能是 `Cancelled`
        // （请求方已就排队超时回了可重试的 503）⇒ 直接返回，不跑引擎、不碰 env 锁。
        if stage_job
            .compare_exchange(
                CALL_QUEUED,
                CALL_STARTED,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            bail!(
                "engine `{stage_engine}` call cancelled while queued \
                 (client already received a retryable 503)"
            );
        }
        // 通知「开始执行」：请求方据此把 deadline 从「排队」切到「执行」。
        // （接收方可能已因排队超时放弃 ⇒ send 失败无害。）
        let _ = started_tx.send(());
        let _pj = prof::span(prof::S_JOB_TOTAL);
        // 先按需装载（快路径 = 一次表查找）再决策：`env_free` 是 .so 的属性。
        let p_load = prof::span(prof::S_JOB_LOAD);
        let lib = load_engine(&engine, &lib_path)?;
        // 二次检查：入池到执行之间，另一个并发调用可能刚被判定超时并隔离本 .so。
        if is_quarantined(&quarantined_key) {
            bail!(
                "engine `{engine}` is quarantined (a previous call exceeded the wall clock); \
                 restart webserver to recover"
            );
        }
        drop(p_load);
        if lib.env_free {
            return call_exec(
                &lib, &engine, &script, &docroot_owned, &m, &p, &q, &ct, &b, peer, port,
                &server_name_owned, &env_vars_owned, &headers_owned,
            );
        }
        let vars: Vec<(&str, &str)> = env_vars_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        match env_lock::with_temp_env_named(&engine, &vars, || {
            call_exec(
                &lib, &engine, &script, &docroot_owned, &m, &p, &q, &ct, &b, peer, port,
                &server_name_owned, &env_vars_owned, &headers_owned,
            )
        }) {
            Ok(r) => r,
            // env 锁被看门狗毒化：快速失败，**不进入等待**（活动组可能被永不返回的调用占着）。
            Err(e) => bail!("engine `{engine}` unavailable: {e}"),
        }
    };
    let pool: Arc<EnginePool> = if serial {
        // rack/psgi：串行单线程池（解释器非线程安全）。
        serial_pool(&engine_for_pool)
    } else if let Some(n) = dedicated_pool_threads(&engine_for_pool) {
        // cgi：独立窄池（见 dedicated_pool_threads），不占通用池、也不被通用池拖累。
        named_pool(&engine_for_pool, n)
    } else {
        Arc::clone(&*GENERIC_POOL)
    };
    // **同步提交**（见 `EnginePool::submit`）：到这里作业已在队列里，第一段的「等 started」
    // 才是真的在等排队。
    let result_rx = pool.submit(job)?;
    drop(p_dispatch);
    let p_queue = prof::span(prof::S_QUEUE_WAIT);
    let exec_timeout = engine_call_timeout();
    let queue_timeout = engine_queue_timeout();
    if exec_timeout.is_none() && queue_timeout.is_none() {
        // 看门狗整体关闭（两个上限都为 None）：回到「无限等」的旧行为。
        return result_rx
            .await
            .map_err(|_| anyhow::anyhow!("engine worker dropped"))?;
    }
    // ---- 第一段：入池排队（见 `engine_queue_timeout` 的成因）----
    if let Some(qt) = queue_timeout {
        match tokio::time::timeout(qt, started_rx).await {
            Ok(_) => {} // 已开始执行，进入第二段
            Err(_) => {
                if stage
                    .compare_exchange(
                        CALL_QUEUED,
                        CALL_CANCELLED,
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    log::warn!(
                        "app_ffi: engine `{engine_for_pool}` 在池队列里等待超过 {}s（worker 全被占）\
                         → 该请求回可重试的 503；**不隔离**该引擎、**不毒化** env 锁（无卡死证据）",
                        qt.as_secs()
                    );
                    return Err(anyhow::Error::new(EnginePoolBusy {
                        engine: engine_for_pool.clone(),
                        waited_secs: qt.as_secs(),
                    }));
                }
                // 竞态：started 信号与排队超时同时发生（调用已在执行）⇒ 落到第二段，
                // 按执行 deadline 等结果。
                log::debug!(
                    "app_ffi: engine `{engine_for_pool}` 排队超时与开始执行竞态 → 按执行 deadline 继续"
                );
            }
        }
    } else {
        // 排队上限被显式关闭：无限等开始（执行上限仍然生效）。
        let _ = started_rx.await;
    }
    drop(p_queue);
    let _p_exec = prof::span(prof::S_EXEC_WAIT);
    // ---- 第二段：引擎执行（deadline **只**算执行）----
    // 超时的**取舍**（本方案的诚实边界）：
    //   * 卡死的 C 调用无法被安全中断（杀线程会在任意指令处损坏状态）⇒ 该 worker 线程
    //     被放弃；`replace_abandoned_worker` 会补一条替补，把池宽顶回去（上限
    //     [`MAX_REPLACEMENT_WORKERS`]）——健康引擎不再因别人的卡死调用而饿死；
    //   * 该 .so 永久隔离（fail-closed），不会再产生新的超时调用；线程数因此有界
    //     （初始池宽 + 补位上限），不会「每超时一次就无界新增」；
    //   * 非自报 env-free 的引擎在超时时可能还持有宿主的进程 env 锁（Slot 永不 Drop），
    //     因此**毒化** env 锁：之后依赖 env 锁的引擎立即 502，绝不阻塞等待、也绝不
    //     在「可能装着别人 .env」的进程 env 上继续运行；
    //   * 自报 env-free 的 .so（cgi/cgi_script/python 这类）不碰进程 env，超时只隔离
    //     它自己，其它引擎（含其它 env-free 引擎）照常工作。
    // 正常长请求不受影响：只要在 deadline 内返回就与旧行为完全一致。
    match exec_timeout {
        None => result_rx
            .await
            .map_err(|_| anyhow::anyhow!("engine worker dropped"))?,
        Some(t) => match tokio::time::timeout(t, result_rx).await {
            Ok(Ok(r)) => Ok(r?),
            Ok(Err(_recv)) => bail!("engine worker dropped"),
            Err(_elapsed) => {
                quarantine(&lib_key, &engine_for_pool, t.as_secs());
                // 卡死的调用永久占着一条 worker：补一条替补，别让它吃掉健康引擎的池产能。
                pool.replace_abandoned_worker(&engine_for_pool);
                if !lib_is_env_free(&lib_key) {
                    env_lock::poison(&format!(
                        "engine `{engine_for_pool}` exceeded {}s wall clock while holding the process-env lock",
                        t.as_secs()
                    ));
                }
                bail!(
                    "engine `{engine_for_pool}` exceeded {}s wall clock — quarantined \
                     (the stuck thread cannot be safely killed; restart webserver to recover)",
                    t.as_secs()
                )
            }
        },
    }
}

/// §22.4.2 native_inline：c/go/rust 在**请求线程**内联执行引擎调用。
///
/// 为什么这样做（测量依据）：走进程池时，c8 门禁下每请求在「入池 → worker 唤醒」上
/// 实测等待 ~63µs（`app-prof` queue_wait），而引擎本身只跑 ~2µs；两次跨线程唤醒
/// 是延迟比的绝对主项。内联后同一份工作由请求线程直接完成。
///
/// 正确性：与池路径**同一套** env 语义 —— 非 env-free 的 .so 仍进
/// `with_temp_env_named`（空 `.env` 组可并发、不同内容组互斥），不是「跳过锁」。
/// 代价（诚实边界）：同步 C 调用无法被看门狗中断；卡死的 c/go/rust 调用会占住
/// 一条 tokio worker 线程（池路径则是隔离 + 补位）。可用 `CRUCIBLE_APP_INLINE=0`
/// 退回池路径。c/go/rust 是 in-process 编译插件（§7.3 最终态），样例调用在 1µs 量级。
#[allow(clippy::too_many_arguments)]
fn inline_exec(
    engine: &str,
    lib_path: &Path,
    lib_key: &str,
    script: &Path,
    docroot: &Path,
    method: &str,
    path: &str,
    query: &str,
    content_type: &str,
    body: &Bytes,
    peer: SocketAddr,
    port: u16,
    server_name: &str,
    env_vars: &[(String, String)],
    headers: &[u8],
) -> Result<ExecOutcome> {
    let _pj = prof::span(prof::S_JOB_TOTAL);
    let p_load = prof::span(prof::S_JOB_LOAD);
    let lib = load_engine(engine, lib_path)?;
    if is_quarantined(lib_key) {
        bail!(
            "engine `{engine}` is quarantined (a previous call exceeded the wall clock); \
             restart webserver to recover"
        );
    }
    drop(p_load);
    if lib.env_free {
        return call_exec(
            &lib, engine, script, docroot, method, path, query, content_type, body, peer, port,
            server_name, env_vars, headers,
        );
    }
    let vars: Vec<(&str, &str)> = env_vars
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    match env_lock::with_temp_env_named(engine, &vars, || {
        call_exec(
            &lib, engine, script, docroot, method, path, query, content_type, body, peer, port,
            server_name, env_vars, headers,
        )
    }) {
        Ok(r) => r,
        Err(e) => bail!("engine `{engine}` unavailable: {e}"),
    }
}

/// POST/PUT/PATCH 或带 Content-Length/Transfer-Encoding 的请求才收 body。
fn request_has_body(m: &http::Method, h: &http::HeaderMap) -> bool {
    if matches!(*m, http::Method::POST | http::Method::PUT | http::Method::PATCH) {
        return true;
    }
    if h.contains_key(http::header::TRANSFER_ENCODING) {
        return true;
    }
    h.get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
        > 0
}


/// §3.3：请求路径 → 引擎脚本相对路径。
/// 剥掉命中的 app 前缀（前缀必须整体匹配，/ 边界对齐，避免 /phplint 命中 /php）；
/// 目录/根请求回落 `app.index`，未配置时按引擎给默认首页。
pub(crate) fn rel_script_path(app: &AppRouteConfig, path: &str) -> String {
    let mut p = path.to_string();
    for prefix in &app.paths {
        if prefix.is_empty() {
            continue;
        }
        // 归一化尾斜杠：配置写 `/php/` 时不能拿 `/php//` 去比前缀，否则应用前缀
        // 永远剥不掉（脚本路径变成 docroot/php/x.php → 404）。与 apps::match_app 同口径。
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() {
            // "/"（或全斜杠）：整段路径原样，无前缀可剥。
            continue;
        }
        if p == prefix || p.starts_with(&format!("{prefix}/")) {
            p = p[prefix.len()..].to_string();
            if !p.starts_with('/') {
                p.insert(0, '/');
            }
            break;
        }
    }
    if p == "/" || p.is_empty() || p.ends_with('/') {
        if let Some(idx) = app.index.as_deref() {
            return format!("/{idx}");
        }
        if let Some(def) = default_index(&app.engine.to_ascii_lowercase()) {
            return format!("/{def}");
        }
    }
    p
}

/// 未配置 `index` 时的引擎默认首页（与 config.toml §3.4 样例一致）。
fn default_index(engine: &str) -> Option<&'static str> {
    match engine {
        "lua" => Some("index.lua"),
        "wsgi" | "asgi" | "python" => Some("index.py"),
        "psgi" => Some("index.psgi"),
        "rack" => Some("index.ru"),
        "cgi" => Some("index.cgi"),
        "ruby" => Some("index.rb"),
        "perl" => Some("index.pl"),
        "php" => Some("index.php"),
        "tsx" => Some("index.tsx"),
        "asp" => Some("index.asp"),
        "aspnet" => Some("index.aspx"),
        "jsp" | "do" => Some("index.jsp"),
        _ => None,
    }
}

/// 引擎 `.so` 的解析（唯一一条链，`native_http::lib_available` 也用它 —— 判活与加载
/// 必须看**同一个**路径，否则「判活说没有、加载说找得到」会让分发走错分支）：
///   1. 配置里的 `apps[].lib`（原样，运维负责）；
///   2. 启动期环境变量 `APPENGINE_<ENGINE>_LIB`（原样）；
///   3. 默认 `<仓库根>/target/app-engines/libapp_<engine>.so`（**绝对**路径，见 [`default_lib_path`]）。
pub fn resolve_lib(app: &AppRouteConfig, engine: &str) -> Result<PathBuf> {
    if let Some(p) = &app.lib {
        return Ok(p.clone());
    }
    let env_key = format!("APPENGINE_{}_LIB", engine.to_ascii_uppercase());
    if let Some(p) = env_lock::read_static_env(&env_key) {
        return Ok(PathBuf::from(p));
    }
    Ok(default_lib_path(engine))
}

/// 未显式配置 lib 时的默认路径：`<仓库根>/target/app-engines/libapp_<engine>.so`。
///
/// 为什么必须**锚定**而不是 cwd 相对（P2，真机形态）：旧实现是
/// `PathBuf::from("target/app-engines/libapp_x.so")`（**相对路径**），`is_file()` 的结论
/// 随进程 cwd 漂移 —— 从非仓库根目录启动的实例里 `/rust/`、`/c/` 这类**没写 lib** 的应用
/// 三协议一致 502（判活失败 ⇒ 落到 sidecar/无后端），而从仓库根启动就正常。同一个配置文件
/// 在两台机器/两种启动方式上行为不同，是配置无法表达的不确定性。
///
/// 锚点优先用编译期 `CARGO_MANIFEST_DIR`（构建该二进制时的仓库根，绝对路径、不随 cwd 漂移）。
/// 「二进制被搬到别处部署」时该目录可能不存在，此时退回 cwd 相对（旧行为）——保证不是更差；
/// 两种情况都返回**绝对路径**，判定只在调用时刻稳定。
fn default_lib_path(engine: &str) -> PathBuf {
    project_root()
        .join("target")
        .join("app-engines")
        .join(format!("libapp_{engine}.so"))
}

/// `target/app-engines/` 的锚点：仓库根（见 [`default_lib_path`]）。
///
/// 结果进程内不变（编译期 manifest 路径 + 目录存在性），缓存到 OnceLock ——
/// 旧实现每次 `resolve_lib` 都做一次 `is_dir()`（stat ≈1.7µs），而 `lib_available`
/// 与 `exec_dispatch` 各解析一次 ⇒ 未写 `lib` 的应用每请求白付两次 stat。
fn project_root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        if manifest.join("libs").join("app-engines").is_dir() {
            return manifest;
        }
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    })
    .clone()
}

// ---------------------------------------------------------------- 脚本路径热缓存
//
// 为什么需要：`admin_files::script_rel` → `safe_join` 对 **root 和结果路径各做一次
// `fs::canonicalize`**，再把结果 `exists()`。本机实测（`canon` 微基准）一次
// canonicalize **6.1–7.5µs**、stat 1.7µs ⇒ 每个引擎请求光「解析脚本路径 + FIFO 闸门」
// 就 ~14µs，是引擎路径相对 static 的最大单项开销（见 enginelat-wave17 报告）。
//
// 缓存的是「路径解析结果 + 非普通文件拒绝判定」，不是文件内容：引擎每次仍自己打开
// 脚本读最新内容。TTL（默认 250ms，`CRUCIBLE_APP_PATH_TTL_MS=0` 关闭）内如果脚本
// 被换成 FIFO/符号链接，闸门判定最多滞后一个 TTL —— 这是为延迟门禁做的**有界**取舍，
// 报告里有诚实说明。缓存键 = (docroot, rel) 的 64 位哈希 + 逐字节复核（防碰撞）。
struct ScriptCacheEntry {
    docroot: PathBuf,
    rel: String,
    path: PathBuf,
    rejected: Option<String>,
    at: std::time::Instant,
}

static SCRIPT_CACHE: Lazy<Mutex<HashMap<u64, ScriptCacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn path_cache_ttl() -> Duration {
    static TTL: Lazy<Duration> = Lazy::new(|| {
        match env_lock::read_static_env("CRUCIBLE_APP_PATH_TTL_MS") {
            Some(v) => match v.trim().parse::<u64>() {
                Ok(ms) => Duration::from_millis(ms),
                Err(_) => Duration::from_millis(250),
            },
            None => Duration::from_millis(250),
        }
    });
    *TTL
}

fn fnv1a(bytes: &[u8], mut h: u64) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

fn script_cache_key(docroot: &Path, rel: &str) -> u64 {
    let mut h = fnv1a(docroot.as_os_str().as_encoded_bytes(), 0xcbf2_9ce4_8422_2325);
    h = fnv1a(&[0xff], h);
    fnv1a(rel.as_bytes(), h)
}

/// 解析脚本路径（含 §7.1 防穿越与 FIFO/设备闸门），带 TTL 热缓存。
fn resolve_script_cached(docroot: &Path, rel: &str) -> Result<PathBuf> {
    let ttl = path_cache_ttl();
    if ttl.is_zero() {
        return resolve_script_exact(docroot, rel);
    }
    let key = script_cache_key(docroot, rel);
    {
        let map = SCRIPT_CACHE.lock();
        if let Some(e) = map.get(&key) {
            if e.at.elapsed() < ttl && e.docroot == docroot && e.rel == rel {
                return match &e.rejected {
                    Some(msg) => Err(anyhow::anyhow!("{msg}")),
                    None => Ok(e.path.clone()),
                };
            }
        }
    }
    let resolved = resolve_script_exact(docroot, rel);
    let mut map = SCRIPT_CACHE.lock();
    // 有界：URL 路径由客户端决定，不能无界增长（超限整体清空，代价只是一次冷解析）。
    if map.len() >= 4096 {
        map.clear();
    }
    map.insert(
        key,
        ScriptCacheEntry {
            docroot: docroot.to_path_buf(),
            rel: rel.to_string(),
            path: resolved.as_ref().map(|p| p.clone()).unwrap_or_default(),
            rejected: resolved.as_ref().err().map(|e| format!("{e:#}")),
            at: std::time::Instant::now(),
        },
    );
    resolved
}

/// 未缓存的脚本解析：与旧实现逐字一致（safe_join + 非普通文件拒绝）。
fn resolve_script_exact(docroot: &Path, rel: &str) -> Result<PathBuf> {
    let p_rel = prof::span(prof::S_REL_SCRIPT);
    let script = crate::server::admin_files::script_rel(docroot, rel)
        .map_err(|e| anyhow::anyhow!("script path rejected: {e:#}"))?;
    drop(p_rel);
    let p_stat = prof::span(prof::S_STAT);
    let md = std::fs::metadata(&script).ok();
    drop(p_stat);
    if let Some(md) = md {
        if !md.is_file() && !md.is_dir() {
            bail!(
                "script is not a regular file (refusing to exec): {}",
                script.display()
            );
        }
    }
    Ok(script)
}

// ---------------------------------------------------------------- 线程池 (§7.3)

type PoolJob = Box<dyn FnOnce() + Send + 'static>;

/// 每个池最多补几条「替补 worker」。
///
/// 被看门狗判超时的 C 调用无法安全终止（杀线程会在任意指令处损坏堆/解释器状态），
/// 只能把那条 worker 线程连同它烧的 CPU 一起放弃。旧实现没有任何补充：卡死调用
/// 永远占着**通用池**的一个名额，连坏 8 只 .so 后所有 FFI 引擎一起排队。
/// 现在超时即补一条 worker 顶替产能；上限保证线程数有界（卡死线程数 ≤ 补位上限，
/// 且同一只 .so 一旦隔离就不会再产生新的超时调用）。
const MAX_REPLACEMENT_WORKERS: usize = 32;

struct EnginePool {
    tx: std::sync::mpsc::Sender<PoolJob>,
    /// 池名（线程名/日志用）。
    name: String,
    /// 工作队列的接收端：替补 worker 与初始 worker 共用同一条队列。
    rx: Arc<Mutex<std::sync::mpsc::Receiver<PoolJob>>>,
    /// 已补的替补 worker 数（见 [`MAX_REPLACEMENT_WORKERS`]）。
    replaced: std::sync::atomic::AtomicUsize,
}

static GENERIC_POOL: Lazy<Arc<EnginePool>> =
    Lazy::new(|| Arc::new(EnginePool::start(generic_pool_threads(), "appffi")));
/// 命名池表：键是 `引擎#线程数`（既是 rack/psgi 的串行池，也是 cgi 那类独立窄池）。
static SERIAL_POOLS: Lazy<Mutex<HashMap<String, Arc<EnginePool>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn generic_pool_threads() -> usize {
    // 本 wave 测量用覆盖：`CRUCIBLE_APP_POOL_THREADS`（1..=64）。
    if let Some(raw) = env_lock::read_static_env("CRUCIBLE_APP_POOL_THREADS") {
        if let Ok(n) = raw.trim().parse::<usize>() {
            if n > 0 {
                return n.min(64);
            }
        }
    }
    let cpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    // 池宽决定「同时能有多少个引擎请求在飞」。这些线程绝大部分时间阻塞在 I/O 上
    // （等 sidecar 回包、等 fork 出来的 CGI 子进程），不是 CPU 密集，所以与核数脱钩、
    // 给足冗余更划算：实测本机只有 1 核 → 旧下限 2 条线程，两个 `sleep 120` 的 CGI
    // 就把池占满，**其它引擎的请求全部排队**（验收里 lua/asp/python 被饿到客户端超时）。
    // 单个 CGI 最长可占 30s（CGI_TIMEOUT_MS），所以下限提到 4、上限 8。
    cpu.clamp(4, 8)
}

fn serial_engine(engine: &str) -> bool {
    matches!(engine, "rack" | "psgi")
}

/// c/go/rust 是否在请求线程内联执行（§22.4.2 native_inline）。
///
/// 默认**开**；`CRUCIBLE_APP_INLINE=0` 退回进程池（运维/回归开关）。
/// 其它引擎保持原线程池语义（解释器不是线程安全的 / 需要临时 env 锁）。
fn inline_engine(engine: &str) -> bool {
    if !matches!(engine, "c" | "rust" | "go") {
        return false;
    }
    !matches!(
        env_lock::read_static_env("CRUCIBLE_APP_INLINE").as_deref(),
        Some("0")
    )
}

impl EnginePool {
    fn start(threads: usize, name: &str) -> EnginePool {
        let (tx, rx) = std::sync::mpsc::channel::<PoolJob>();
        let pool = EnginePool {
            tx,
            name: name.to_string(),
            rx: Arc::new(Mutex::new(rx)),
            replaced: std::sync::atomic::AtomicUsize::new(0),
        };
        for i in 0..threads.max(1) {
            pool.spawn_worker(i);
        }
        pool
    }

    /// 起一条 worker（初始 worker 与超时后的替补共用）。线程 detach：池本身常驻，
    /// 队列的发送端关闭时 `recv` 返回 Err、线程自然退出。
    fn spawn_worker(&self, idx: usize) {
        let rx = Arc::clone(&self.rx);
        let name = self.name.clone();
        let _ = std::thread::Builder::new()
            .name(format!("cruc-{name}-{idx}"))
            .spawn(move || loop {
                let job = {
                    let guard = rx.lock();
                    guard.recv()
                };
                match job {
                    Ok(j) => j(),
                    Err(_) => break,
                }
            });
    }

    /// 一次执行超时：放弃那条卡住的 worker，并补一条替补把池宽顶回去。
    ///
    /// 为什么必须补：卡死调用不返回，原 worker 永远不会再取队列；不补的话每次超时
    /// 都永久吃掉一份池产能（通用池被 8 只卡死 .so 吃光后，健康引擎全部 503）。
    /// 为什么必须限：替补线程数 = 被放弃的 worker 数，卡死调用数由「同一 .so 隔离一次」
    /// 约束，但仍可能在多 .so/并发超时下叠加，硬上限保证线程数有界。
    ///
    /// 如果卡死的调用**最终**返回了，这条替补就变成一条空闲 worker：线程数比初始多
    /// 一条，但不再有任何调用会超时（该 .so 已隔离），属于可接受的有界余量。
    fn replace_abandoned_worker(&self, engine: &str) {
        use std::sync::atomic::Ordering;
        let n = self.replaced.fetch_add(1, Ordering::SeqCst);
        if n >= MAX_REPLACEMENT_WORKERS {
            log::warn!(
                "app_ffi: engine `{engine}` 超时放弃的 worker 已达替补上限 {MAX_REPLACEMENT_WORKERS}（池 `{}`）；\
                 不再新增线程（线程数有界）",
                self.name
            );
            return;
        }
        self.spawn_worker(1000 + n);
        log::warn!(
            "app_ffi: engine `{engine}` 的调用超时且无法安全中止 → 放弃该 worker 线程，\
             为池 `{}` 补充替补 worker（{}/{}）",
            self.name,
            n + 1,
            MAX_REPLACEMENT_WORKERS
        );
    }

    /// 提交一个引擎调用作业，返回「等结果」的接收端。
    ///
    /// **必须同步提交**：`submit` 一返回，作业就已经在池队列里（旧实现是 `async fn run`，
    /// 只有被 poll 时才 `tx.send` —— 两段 deadline 里「排队阶段」必须真的在排队，否则
    /// 「等 started 信号」永远等不到，作业也永远不会执行）。`Err` = 池已关闭。
    fn submit<T, F>(&self, f: F) -> Result<tokio::sync::oneshot::Receiver<Result<T>>>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let (otx, orx) = tokio::sync::oneshot::channel();
        self.tx
            .send(Box::new(move || {
                let _ = otx.send(f());
            }))
            .map_err(|_| anyhow::anyhow!("engine thread pool closed"))?;
        Ok(orx)
    }
}

/// 按名字取一个固定宽度的引擎池（同名同宽度复用）。
fn named_pool(engine: &str, threads: usize) -> Arc<EnginePool> {
    SERIAL_POOLS
        .lock()
        .entry(format!("{engine}#{threads}"))
        .or_insert_with(|| Arc::new(EnginePool::start(threads, engine)))
        .clone()
}

fn serial_pool(engine: &str) -> Arc<EnginePool> {
    named_pool(engine, 1)
}

/// 需要**独立池**的引擎：`None` = 走通用池。
///
/// 为什么 cgi 要独立：CGI 引擎每个请求 fork 一个子进程、最长可占 30s（CGI_TIMEOUT_MS），
/// 是所有引擎里唯一会长时间占住线程的。它跟通用池混在一起时，几个慢脚本就能把通用池
/// 占满 —— 实测（本机 1 核 → 通用池只有 2 条线程）两个 `sleep 120` 的脚本就让
/// lua/asp/python 的请求全部排队到客户端超时。独立池既隔离了这种阻塞，
/// 也顺手把「同时 fork 多少个子进程」限住（内存可控）。
fn dedicated_pool_threads(engine: &str) -> Option<usize> {
    match engine {
        "cgi" => Some(4),
        _ => None,
    }
}

// ---------------------------------------------------------------- dlopen / exec

fn load_engine(engine: &str, lib_path: &Path) -> Result<Arc<EngineLib>> {
    // 热路径**不分配**：HashMap<String, _> 支持用 &str 查询。
    let key = lib_path.to_string_lossy();
    // 快路径：已装载
    {
        let map = LIBS.lock();
        if let Some(l) = map.get(key.as_ref()) {
            return Ok(Arc::clone(l));
        }
    }
    // 慢路径：按路径串行化，避免并发重复 dlopen + 重复 appengine_init。
    let path_lock = {
        let mut locks = LOAD_LOCKS.lock();
        Arc::clone(locks.entry(key.to_string()).or_default())
    };
    let _guard = path_lock.lock();
    // 等到锁之后必须复查：这段时间里另一个线程可能已经装载完成。
    {
        let map = LIBS.lock();
        if let Some(l) = map.get(key.as_ref()) {
            return Ok(Arc::clone(l));
        }
    }
    if !lib_path.is_file() {
        bail!("missing engine lib {}", lib_path.display());
    }
    // libloading 0.8 type-safe: Symbol<T> 在获取时校验符号类型与 T 签名，
    // 杜绝 std::mem::transmute 的隐藏 UB。
    //
    // 但 `Library::new` 在 unix 上等价于 `open(path, RTLD_LAZY | RTLD_LOCAL)`
    //（libloading 0.8.9 `os/unix/mod.rs:135` 源码核对），与规格 §7.1 铁律 3 / §16.8
    // 要求的 `RTLD_NOW | RTLD_GLOBAL` **相反**：
    //   * LAZY ⇒ 引擎 .so 里缺失/未解析的符号不在装载时报错，而是拖到第一次
    //     `appengine_execute` 跳到未解析 PLT —— 崩的是整个 webserver 进程，而不是
    //     干净地回 502（NOW 正是为了「加载期失败」）；
    //   * LOCAL ⇒ 引擎及其依赖不进全局作用域，多个 `.so` 之间靠
    //     `dlsym(RTLD_DEFAULT)` 共享符号的用法失效。
    // 因此这里显式用 os::unix::Library::open 传 flag，再转回安全包装（From 已实现）。
    #[cfg(unix)]
    let lib: libloading::Library = {
        let raw = unsafe {
            libloading::os::unix::Library::open(
                Some(lib_path),
                // RTLD_NODELETE：热重载卸载引擎时**不解除映射**。
                //
                // 为什么必须加：`reconcile` 在没有引用时会 `shutdown()` + dlclose。
                // 但嵌入式解释器（本项目的 libapp_rack.so 嵌 MRI、libapp_python.so 嵌
                // CPython、libapp_perl.so 嵌 Perl）会在 dlopen 时**创建后台线程/注册
                // atexit 与 GC 定时器**，它们的代码/数据指针仍指向该 .so。dlclose 之后
                // 这些线程一跑就 SIGSEGV —— 实测：`GET /rack/` 之后几十秒内**整个服务器
                // 进程崩溃**（core 454MB），全部监听口一起下线。
                // NODELETE 让映射常驻（每个引擎几百 KB，代价可忽略），shutdown 钩子照常
                // 执行、符号解析与状态清理语义不变，只是不再有「代码被抽走」的窗口。
                libc::RTLD_NOW | libc::RTLD_GLOBAL | RTLD_NODELETE_EXT,
            )
        }
        .map_err(|e| anyhow::anyhow!("dlopen {}: {e}", lib_path.display()))?;
        raw.into()
    };
    // 非 unix 无 dlopen flags 可用（Windows 用 LOAD_WITH_ALTERED_SEARCH_PATH 语义），
    // 保持 libloading 默认。
    #[cfg(not(unix))]
    let lib: libloading::Library = unsafe { libloading::Library::new(lib_path) }
        .map_err(|e| anyhow::anyhow!("dlopen {}: {e}", lib_path.display()))?;
    // type-safe: 编译期校验符号签名 (Symbol<T> 内部实现)
    macro_rules! sym {
        ($ty:ty, $name:literal) => {
            unsafe { lib.get::<$ty>(concat!($name, "\0").as_bytes()) }
                .map_err(|e| anyhow::anyhow!("missing symbol {}: {e}", $name))?
        };
    }
    // ABI 校验必须在 dlsym `appengine_execute` 之后、调用它之前完成 —— 见
    // `APPENGINE_ABI_VERSION` 的说明：签名不匹配的陈旧 .so 会以**堆破坏**的形式
    // 崩掉整个进程，而不是干净地报错。
    //   * 缺符号 = 该 .so 早于 ABI 版本符号的引入（陈旧构建）→ 拒绝加载；
    //   * 版本不等 = 签名/结构布局已变 → 拒绝加载。
    // 两者都回「重建引擎」的明确错误（客户端 502，日志有细节），绝不调用它。
    let abi: AbiVersionFn = *sym!(AbiVersionFn, "appengine_abi_version");
    let found_abi = unsafe { abi() };
    if found_abi != APPENGINE_ABI_VERSION {
        bail!(
            "engine ABI mismatch for {}: .so reports {found_abi}, host expects {} \
             (stale/foreign .so) — rebuild app engines (`make engines`)",
            lib_path.display(),
            APPENGINE_ABI_VERSION
        );
    }
    let init: InitFn = *sym!(InitFn, "appengine_init");
    let exec: ExecFn = *sym!(ExecFn, "appengine_execute");
    let free: FreeFn = *sym!(FreeFn, "appengine_result_free");
    let shutdown: ShutdownFn = *sym!(ShutdownFn, "appengine_shutdown");
    let eng = CString::new(engine).context("engine name nul")?;
    let hint = CString::new(lib_path.to_string_lossy().as_bytes()).context("hint nul")?;
    let rc = unsafe { (init)(eng.as_ptr(), hint.as_ptr()) };
    if rc != 0 {
        bail!("appengine_init failed: {rc}");
    }
    // 可选符号 `appengine_set_base_env` + `appengine_env_isolation`：把**启动期基底环境**
    // （不含任何请求期临时 .env）交给引擎，并要求引擎**明确自报**它按子进程/子请求传 `.env`。
    // 只有两者都成立才允许对该 .so 跳过 env 锁（见 `EngineLib::env_free`）。
    // 缺失 → 旧引擎行为完全不变（继续继承 environ + 由 host 置于锁内）。
    let mut env_free = false;
    #[cfg(unix)]
    unsafe {
        let set_ok = match lib.get::<SetBaseEnvFn>(b"appengine_set_base_env\0") {
            Ok(set_base) => {
                let block = env_lock::base_env_block();
                // block 恒以 NUL 结尾（空基底时是单个 NUL），`as_ptr` 有效。
                let brc = set_base(block.as_ptr() as *const c_char);
                if brc != 0 {
                    log::warn!(
                        "appengine_set_base_env rc={brc} for {}（继续，引擎退回继承 environ ⇒ 该引擎留在 env 锁内）",
                        lib_path.display()
                    );
                }
                brc == 0
            }
            Err(_) => false,
        };
        if set_ok {
            match lib.get::<EnvIsolationFn>(b"appengine_env_isolation\0") {
                Ok(isolation) => env_free = isolation() != 0,
                // 有 set_base_env 但没有自报符号：不认为是 lock-free（陈旧 .so 的典型形态）。
                Err(_) => log::debug!(
                    "engine {} 有 appengine_set_base_env 但未自报 appengine_env_isolation —— 留在 env 锁内（{}）",
                    engine,
                    lib_path.display()
                ),
            }
        }
    }
    let lib = Arc::new(EngineLib {
        engine: engine.to_string(),
        path: key.to_string(),
        // libloading 库句柄 (NonNull<c_void> + Drop dlclose)
        _lib: lib,
        init,
        exec,
        free,
        shutdown,
        env_free,
    });
    LIBS.lock().insert(key.into_owned(), Arc::clone(&lib));
    Ok(lib)
}

/// 每线程复用的 ABI 字符串暂存（避免每请求 ~9 次 malloc/free）。
///
/// 安全性：一次调用内先 reserve 到总需求 ⇒ 追加过程中不会 realloc，指针在
/// `(lib.exec)` 调用期间保持有效；ABI 约定引擎不得保留这些指针。
thread_local! {
    static ABI_SCRATCH: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// 把 `parts` 拼成 NUL 结尾的 C 字符串序列，回调里给出指针表。
fn with_abi_cstrings<R>(parts: [&[u8]; 10], f: impl FnOnce([*const c_char; 10]) -> R) -> Result<R> {
    if parts.iter().any(|p| p.contains(&0u8)) {
        bail!("engine argument contains NUL");
    }
    ABI_SCRATCH.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        let need: usize = parts.iter().map(|p| p.len() + 1).sum();
        if buf.capacity() < need {
            buf.reserve(need);
        }
        let mut ptrs = [std::ptr::null(); 10];
        for (i, part) in parts.iter().enumerate() {
            // capacity 已保证 ⇒ extend 不会搬家，指针有效。
            ptrs[i] = unsafe { buf.as_ptr().add(buf.len()) } as *const c_char;
            buf.extend_from_slice(part);
            buf.push(0);
        }
        Ok(f(ptrs))
    })
}

#[allow(clippy::too_many_arguments)]
fn call_exec(
    lib: &EngineLib,
    engine: &str,
    script: &Path,
    docroot: &Path,
    method: &str,
    path: &str,
    query: &str,
    content_type: &str,
    body: &Bytes,
    peer: SocketAddr,
    port: u16,
    server_name: &str,
    env_vars: &[(String, String)],
    headers: &[u8],
) -> Result<ExecOutcome> {
    let _p_call = prof::span(prof::S_CALL_TOTAL);
    let p_prep = prof::span(prof::S_CALL_PREP);
    // P1-1：extra 语义升级——带 .env 变量时传 JSON {"engine":...,"env":{...}}，
    // 由 libs/app-engines/common 解析注入执行环境；无变量时保持 legacy 纯引擎名
    //（现有 C 侧 common 不消费 extra，旧插件不受影响）。
    let extra_json: Option<String> = if env_vars.is_empty() {
        None
    } else {
        let mut env_obj = serde_json::Map::new();
        for (k, v) in env_vars {
            env_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        Some(
            serde_json::json!({"engine": engine, "env": serde_json::Value::Object(env_obj)})
                .to_string(),
        )
    };
    let extra: &[u8] = match &extra_json {
        Some(s) => s.as_bytes(),
        None => engine.as_bytes(),
    };
    // Path 在 linux/openbsd 上通常就是 UTF-8：Cow::Borrowed，无分配。
    let script_s = script.to_string_lossy();
    let docroot_s = docroot.to_string_lossy();
    let mut ipbuf = [0u8; 64];
    let ip_len = {
        use std::io::Write as _;
        let mut cur = std::io::Cursor::new(&mut ipbuf[..]);
        let _ = write!(cur, "{}", peer.ip());
        cur.position() as usize
    };
    let parts: [&[u8]; 10] = [
        script_s.as_bytes(),
        docroot_s.as_bytes(),
        method.as_bytes(),
        path.as_bytes(),
        query.as_bytes(),
        content_type.as_bytes(),
        &ipbuf[..ip_len],
        server_name.as_bytes(),
        extra,
        headers,
    ];
    let (body_ptr, body_len) = if body.is_empty() {
        (std::ptr::null(), 0usize)
    } else {
        (body.as_ptr(), body.len())
    };
    drop(p_prep);
    let p_engine = prof::span(prof::S_ENGINE_CALL);
    let out = with_abi_cstrings(parts, |p| -> Result<ExecOutcome> {
        let mut out = AppEngineResult {
            status: 500,
            headers: std::ptr::null_mut(),
            headers_len: 0,
            body: std::ptr::null_mut(),
            body_len: 0,
            error: std::ptr::null_mut(),
        };
        unsafe {
            let rc = (lib.exec)(
                p[0],
                p[1],
                p[2],
                p[3],
                p[4],
                p[5],
                body_ptr,
                body_len,
                p[6],
                p[7],
                port as c_int,
                p[8],
                if headers.is_empty() {
                    std::ptr::null()
                } else {
                    p[9]
                },
                &mut out,
            );
            drop(p_engine);
            let _p_result = prof::span(prof::S_CALL_RESULT);
            if rc != 0 {
                let msg = if !out.error.is_null() {
                    CStr::from_ptr(out.error).to_string_lossy().into_owned()
                } else {
                    format!("exec rc={rc}")
                };
                (lib.free)(&mut out);
                bail!("{msg}");
            }
            // rc == 0 表示「引擎服务过这个请求」，但引擎**仍可能**填了 error：典型是
            // WSGI/ASGI/uWSGI 的「应用抛异常 → 500 + 固定文本」，traceback **只在 error 里**
            // （不再回显给客户端 —— 那会泄露绝对路径与源码行）。这类细节必须进本地日志，
            // 否则排障就断了；而它又是**每请求一条**、可被对端驱动（脚本总是抛异常即可）
            // ⇒ 走同一套按引擎的时间节流。
            let engine_reported = if out.error.is_null() {
                None
            } else {
                Some(CStr::from_ptr(out.error).to_string_lossy().into_owned())
            };
            let headers = parse_result_headers(out.headers, out.headers_len);
            // ABI 没有 body 容量字段，宿主无法真正校验 `body_len`（引擎写错长度时
            // `from_raw_parts` 会越界读堆内存并把内容发给客户端）。这里至少加一条
            // 上界：超过上游响应上限的长度一定是 bug，宁可 502 也不能跳进越界读。
            let body_out = if out.body.is_null() || out.body_len == 0 {
                Bytes::new()
            } else if out.body_len > crate::server::h1::UPSTREAM_BODY_CAP {
                let n = out.body_len;
                (lib.free)(&mut out);
                bail!(
                    "engine {engine} returned body_len {n} > {} (ABI violation)",
                    crate::server::h1::UPSTREAM_BODY_CAP
                );
            } else {
                Bytes::copy_from_slice(std::slice::from_raw_parts(out.body, out.body_len))
            };
            let status = out.status;
            (lib.free)(&mut out);
            if let Some(msg) = engine_reported {
                crate::server::log_throttle::warn_every(
                    &format!("engine-app-err::{engine}"),
                    std::time::Duration::from_secs(60),
                    &format!("{engine}: 应用级错误（客户端只收到固定文本，细节仅本地）: {msg}"),
                );
            }
            Ok(ExecOutcome {
                status,
                headers,
                body: body_out,
            })
        }
    })?;
    out
}

/// 解析 ABI headers 块（"Name: value\r\n" NUL 结尾），带注入净化。
fn parse_result_headers(ptr: *mut c_char, len: usize) -> Vec<(String, String)> {
    if ptr.is_null() {
        return Vec::new();
    }
    let text: String = unsafe {
        // ABI 契约里这个块是**以 NUL 结尾**的文本块（appengine_result_set_headers 用
        // strlen 填 headers_len）。**不能**直接拿 len 去建 slice —— len 是 C 侧塞进来的：
        // 引擎若直接把 out->headers 指向自己的缓冲却忘了填 headers_len（或填的是上一版
        // 结果残留的长度），`from_raw_parts(ptr, len)` 就会读出一大段分配之外的内存，
        // 而那些字节随后会被当作响应头发出去（堆内容泄露 + 可能 OOM）。
        // 一律先按 NUL 定界取真实长度，len 只当上限用（`len == 0` 时与旧行为等价）。
        let real = CStr::from_ptr(ptr).to_bytes().len();
        let n = if len == 0 || len > real { real } else { len };
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr as *const u8, n)).into_owned()
    };
    // 显式标注：下面的 content-type 去重会先**读** `out`（`iter_mut().find()`）再决定是否
    // push，元素类型无法从 push 反推，省略标注会 E0282。
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if valid_header_kv(k, v) {
                // `Content-Type` 按 RFC 是**单值**头。脚本引擎（`ngx.header`、CGI 打印两行
                // `Content-Type:`、WSGI 里手写 headers）很容易输出两份，而调用方是
                // `builder.header(k, v)` —— hyper 会**追加**而不是替换 ⇒ 响应带两个
                // content-type，缓存/代理与客户端可能各挑一个（实测 CGI 脚本可复现）。
                // 这里统一去重：**后者胜出**（CGI 语义），且对**所有**引擎生效。
                // 只针对 content-type —— `Set-Cookie` 等同名多头是合法的，不能一起合。
                if k.eq_ignore_ascii_case("content-type") {
                    if let Some(slot) = out
                        .iter_mut()
                        .find(|(ek, _)| ek.eq_ignore_ascii_case("content-type"))
                    {
                        *slot = (k.to_string(), v.to_string());
                        continue;
                    }
                }
                out.push((k.to_string(), v.to_string()));
            }
        }
        if out.len() >= 64 {
            break;
        }
    }
    out
}

/// 头注入防护：名 token 字符；值可见 ASCII/tab；长度受限。
pub fn valid_header_kv(k: &str, v: &str) -> bool {
    !k.is_empty()
        && k.len() <= 256
        && k.bytes().all(|b| b.is_ascii_graphic() && b != b':')
        && v.len() <= 8192
        && v.bytes().all(|b| (0x20..=0x7e).contains(&b) || b == b'\t')
}

/// 引擎给的状态码 → hyper 状态码。
///
/// 只接受 **200..=599**：0/1xx 不能作为最终响应 —— hyper 1.x 服务端 encode 对
/// `is_informational()` 的最终响应会改成 500 并返回 `user_unsupported_status_code`，
/// 直接掐掉连接（客户端看到断连/重试，而不是一个干净的 5xx）。`from_u16` 对 3 位以外
/// 的非法值也会失败，统一回 500。
fn status_code(status: i32) -> StatusCode {
    if !(200..=599).contains(&status) {
        log::debug!("app_ffi: engine returned invalid status {status}; using 500");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::from_u16(status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// FFI 结果 → 完整响应；引擎未给 Content-Type 时回退 text/plain。
pub fn response_from_outcome(outcome: ExecOutcome) -> Response<BoxBody> {
    let (headers, has_ct) = sanitize_engine_headers(&outcome.headers, outcome.body.len());
    let mut builder = Response::builder().status(status_code(outcome.status));
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    if !has_ct {
        builder = builder.header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    }
    builder.body(full(outcome.body)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(full("engine response build error"))
            .unwrap()
    })
}

/// 逐跳头（RFC 9110 §7.6.1）：只为当前连接服务，不得从引擎响应泄漏给客户端。
fn is_engine_hop_by_hop(lower: &str) -> bool {
    matches!(
        lower,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// 引擎返回的响应头净化。返回 `(保留的头, 是否已有 Content-Type)`。
///
/// 规则（与 `proxy.rs` / `fastcgi::sanitize_response_headers` / `sidecar_engine`
/// 同一套口径）：
///   * 丢弃逐跳头（`Connection`/`Keep-Alive`/`TE`/`Transfer-Encoding`/`Upgrade`/
///     `Trailer`/`Proxy-*`）与 `Connection:` **点名**的头；
///   * `Content-Length` 只有恰好等于真实 body 长度时才透传（否则响应走私/连接失步，
///     见本文件 response_from_outcome 的历史注释）。
///
/// 为什么 FFI 引擎也要做：引擎是进程内可信代码，但它给的头块会被原样写进最终响应。
/// `Transfer-Encoding: chunked`（或 `Connection: close`）与重建后的 `Full<Bytes>`
/// body 语义不符时，hyper 服务端会按 TE 分支重排/与 CL 冲突掐连接，且把逐跳语义
/// 泄漏给客户端 —— 此前 app_ffi 只处理了 Content-Length（agent-9 遗留项）。
fn sanitize_engine_headers(
    headers: &[(String, String)],
    body_len: usize,
) -> (Vec<(String, String)>, bool) {
    let conn_tokens: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let mut out: Vec<(String, String)> = Vec::with_capacity(headers.len());
    let mut has_ct = false;
    for (k, v) in headers {
        let lower = k.to_ascii_lowercase();
        if is_engine_hop_by_hop(&lower) || conn_tokens.iter().any(|t| t == &lower) {
            continue;
        }
        if k.eq_ignore_ascii_case("content-type") {
            has_ct = true;
        }
        if lower == "content-length" {
            let declared = v.trim().parse::<u64>().ok();
            if declared != Some(body_len as u64) {
                continue;
            }
        }
        out.push((k.clone(), v.clone()));
    }
    (out, has_ct)
}

/// `Response<Bytes>` 变体（H2/H3 simple 路径）。
pub fn simple_response_from_outcome(outcome: ExecOutcome) -> Response<Bytes> {
    let (headers, has_ct) = sanitize_engine_headers(&outcome.headers, outcome.body.len());
    let mut builder = Response::builder().status(status_code(outcome.status));
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    if !has_ct {
        builder = builder.header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    }
    builder.body(outcome.body).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Bytes::from_static(b"engine response build error"))
            .unwrap()
    })
}

/// 强制卸载指定引擎的全部 .so（admin / 配置清理入口）。
#[allow(dead_code)]
pub fn shutdown_engine(engine: &str) {
    // 只把条目取出来，**释放 LIBS 锁后再 drop**：drop 会执行 C 侧
    // `appengine_shutdown()` + dlclose，而外部 .so 的 shutdown 可能阻塞
    //（等自己的线程/IO）。持锁执行会把所有 `load_engine` 快路径一起卡死。
    let removed: Vec<Arc<EngineLib>> = {
        let mut map = LIBS.lock();
        let keys: Vec<String> = map
            .iter()
            .filter(|(_, l)| l.engine == engine)
            .map(|(k, _)| k.clone())
            .collect();
        keys.into_iter().filter_map(|k| map.remove(&k)).collect()
    };
    drop(removed); // 锁外 Drop → shutdown + dlclose
}

/// §7.3 热卸载：配置不再引用、且无在途请求（强引用仅剩缓存表）的引擎 →
/// shutdown + dlclose。有在途请求时仅出表，句柄随最后一个引用释放。
pub fn reconcile_unload(active: &[(String, String)]) {
    // 同上：先出表、放锁，再在锁外 drop（shutdown 可能阻塞）。
    let stale: Vec<Arc<EngineLib>> = {
        let mut map = LIBS.lock();
        let keys: Vec<String> = map
            .iter()
            .filter(|(_, l)| !active.iter().any(|(e, p)| e == &l.engine && p == &l.path))
            .map(|(k, _)| k.clone())
            .collect();
        keys.into_iter().filter_map(|k| map.remove(&k)).collect()
    };
    for lib in stale {
        if Arc::strong_count(&lib) == 1 {
            log::info!("app_ffi: unload engine {} ({})", lib.engine, lib.path);
        } else {
            log::debug!(
                "app_ffi: engine {} in-flight; defer dlclose via Drop",
                lib.engine
            );
        }
        // Drop impl performs shutdown+dlclose（无在途请求时；否则最后一个引用 Drop 时执行）。
        drop(lib);
    }
}

#[cfg(test)]
mod status_and_rel_tests {
    use super::*;

    fn app_with_paths(paths: &[&str]) -> AppRouteConfig {
        AppRouteConfig {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            enabled: true,
            engine: "php".into(),
            socket: None,
            extensions: vec!["php".into()],
            index: None,
            php_bin: None,
            workers: 1,
            source_dir: None,
            out_dir: None,
            entry: vec![],
            watch: false,
            docroot: None,
            lib: None,
            deps_dir: None,
            init_timeout_secs: None,
            libc: None,
        }
    }

    /// 引擎响应头净化：逐跳头 + `Connection:` 点名的头必须剥掉；与真实 body 不符的
    /// Content-Length 丢弃、相符的保留；其余头（Set-Cookie 等）原样保留。
    #[test]
    fn sanitize_engine_headers_drops_hop_by_hop_and_bad_cl() {
        let h = vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Connection".to_string(), "close, x-internal".to_string()),
            ("Keep-Alive".to_string(), "timeout=5".to_string()),
            ("x-internal".to_string(), "secret".to_string()),
            ("Set-Cookie".to_string(), "a=1".to_string()),
            ("Content-Length".to_string(), "999".to_string()),
        ];
        let (out, has_ct) = sanitize_engine_headers(&h, 5);
        assert!(has_ct);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("transfer-encoding")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("connection")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("keep-alive")));
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("x-internal")), "Connection 点名的头也要剥");
        assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("content-length")), "不符的 CL 丢弃");
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("set-cookie")));
        // CL 恰好等于真实长度 → 保留
        let h2 = vec![("Content-Length".to_string(), "5".to_string())];
        let (out2, _) = sanitize_engine_headers(&h2, 5);
        assert_eq!(out2.len(), 1);
    }

    /// 0/1xx 不能变成合法最终响应（hyper 会掐连接）；非法/越界值回 500。
    #[test]
    fn invalid_statuses_map_to_500() {        assert_eq!(status_code(0), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(100), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(199), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(99), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(200), StatusCode::OK);
        assert_eq!(status_code(204), StatusCode::NO_CONTENT);
        assert_eq!(status_code(500), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(599), StatusCode::from_u16(599).unwrap());
        assert_eq!(status_code(600), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(-1), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// `paths = ["/php/"]` 与 `"/php"` 必须等价：脚本相对路径都要剥掉前缀。
    #[test]
    fn rel_script_path_normalizes_trailing_slash_prefix() {
        let app = app_with_paths(&["/php/"]);
        assert_eq!(rel_script_path(&app, "/php/index.php"), "/index.php");
        assert_eq!(rel_script_path(&app, "/php/sub/a.php"), "/sub/a.php");
        // 目录请求回落 index（这里只验证前缀已剥掉）
        assert_eq!(rel_script_path(&app, "/php/"), "/index.php");
        // 非前缀不误伤（/phplint 不属于 /php）
        assert_eq!(rel_script_path(&app, "/phplint/x.php"), "/phplint/x.php");
    }

    /// 无尾斜杠写法保持原有行为（回归）。
    #[test]
    fn rel_script_path_plain_prefix() {
        let app = app_with_paths(&["/php"]);
        assert_eq!(rel_script_path(&app, "/php/index.php"), "/index.php");
        let app = app_with_paths(&["/lua/"]);
        assert_eq!(rel_script_path(&app, "/lua/main.lua"), "/main.lua");
    }

    /// ABI 头块：hop-by-hop 与 Content-Type/Length 不透传；其余头按
    /// `Name: Value\r\n` 逐条落地（同名多头保留）。
    #[test]
    fn request_headers_block_filters_hop_by_hop_and_body_meta() {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::HOST, "apps.example:9095".parse().unwrap());
        h.insert("x-request-id", "task-1".parse().unwrap());
        h.insert(http::header::COOKIE, "sid=abc".parse().unwrap());
        h.insert(http::header::USER_AGENT, "crucible-test/1".parse().unwrap());
        h.insert(http::header::CONNECTION, "keep-alive".parse().unwrap());
        h.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        h.insert("proxy-connection", "1".parse().unwrap());
        h.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        h.insert(http::header::CONTENT_LENGTH, "3".parse().unwrap());
        h.append(http::header::SET_COOKIE, "a=1".parse().unwrap());
        h.append(http::header::SET_COOKIE, "b=2".parse().unwrap());
        let s = String::from_utf8(request_headers_block(&h, None)).unwrap();
        // http::HeaderMap 把名字规范化为小写，块里就是小写形态。
        assert!(s.contains("host: apps.example:9095\r\n"), "{s}");
        assert!(s.contains("x-request-id: task-1\r\n"), "{s}");
        assert!(s.contains("cookie: sid=abc\r\n"), "{s}");
        assert!(s.contains("user-agent: crucible-test/1\r\n"), "{s}");
        // 同名多头保留两条（Set-Cookie 语义）
        assert_eq!(s.matches("set-cookie: ").count(), 2, "{s}");
        let low = s.to_ascii_lowercase();
        for bad in [
            "connection:",
            "transfer-encoding",
            "proxy-",
            "content-type",
            "content-length",
        ] {
            assert!(!low.contains(bad), "must skip {bad}: {s}");
        }
    }

    /// h2/h3 没有字面 `Host` 头（权威在 `:authority`）：请求头块必须用 authority 补出
    /// `host:`，否则引擎在 h2/h3 上拿不到 HTTP_HOST（h1 有），跨协议不一致。
    #[test]
    fn request_headers_block_synthesizes_host_from_authority() {
        let auth: http::uri::Authority = "apps.example:9095".parse().unwrap();
        let s = String::from_utf8(request_headers_block(&http::HeaderMap::new(), Some(&auth)))
            .unwrap();
        assert!(s.contains("host: apps.example:9095\r\n"), "{s}");
        // 已有 Host → 不重复
        let mut h2 = http::HeaderMap::new();
        h2.insert(http::header::HOST, "x.example".parse().unwrap());
        let s2 = String::from_utf8(request_headers_block(&h2, Some(&auth))).unwrap();
        assert_eq!(s2.matches("host:").count(), 1, "{s2}");
        assert!(s2.contains("x.example"), "{s2}");
        // 无 authority 且无 Host → 空块
        let s3 = String::from_utf8(request_headers_block(&http::HeaderMap::new(), None)).unwrap();
        assert!(s3.is_empty(), "{s3}");
    }

    /// obs-text（0x80-0xFF）头值合法且必须保留；块内不含 NUL（call_exec 依赖
    /// 这一点才能安全地用 CString 包装）。
    #[test]
    fn request_headers_block_allows_obs_text_and_has_no_nul() {
        let mut h = http::HeaderMap::new();
        h.insert("x-latin1", http::HeaderValue::from_bytes(b"caf\xe9").unwrap());
        h.insert("x-request-id", "task-1".parse().unwrap());
        let raw = request_headers_block(&h, None);
        assert!(
            raw.windows(4).any(|w| w == b"caf\xe9"),
            "obs-text value must survive: {raw:?}"
        );
        assert!(!raw.contains(&0u8));
    }

    /// 默认 lib 路径必须是**绝对路径**（锚定仓库根），且 `lib_available`
    /// （`native_http`）与它看的是同一条链 —— 否则 cwd≠仓库根时「判活说没有」。
    #[test]
    fn default_lib_path_is_absolute_and_anchored() {
        let app = app_with_paths(&["/rust"]);
        let p = resolve_lib(&app, "rust").expect("no err");
        assert!(
            p.is_absolute(),
            "默认 lib 路径必须是绝对路径（不随 cwd 漂移）: {p:?}"
        );
        assert!(
            p.to_string_lossy().ends_with("target/app-engines/libapp_rust.so"),
            "{p:?}"
        );
        // 显式 apps[].lib 优先（原样返回，运维负责）
        let mut app2 = app_with_paths(&["/rust"]);
        app2.lib = Some(PathBuf::from("/tmp/custom.so"));
        assert_eq!(
            resolve_lib(&app2, "rust").unwrap(),
            PathBuf::from("/tmp/custom.so")
        );
    }

    /// 排队超时的错误类型必须能被调用方（`apps::engine_error`/`simple_engine_error`）
    /// `downcast_ref` 认出（anyhow 链）—— 否则客户端会拿到 502 而不是可重试的 503。
    #[test]
    fn engine_pool_busy_is_downcastable() {
        let e = anyhow::Error::new(EnginePoolBusy {
            engine: "wsgi".into(),
            waited_secs: 6,
        });
        let e = e.context("wrap 一层 context 也要认得出");
        assert!(e.downcast_ref::<EnginePoolBusy>().is_some(), "{e:#}");
        assert!(ENGINE_BUSY_BODY.starts_with("503 Service Unavailable"));
        // 两段 deadline 的默认关系：没设 QUEUE 变量时与执行上限同值（60s）。
        assert_eq!(engine_queue_timeout(), engine_call_timeout());
    }

    /// 看门狗超时后**补充 worker** 的机制：池宽 1 时，第一条作业卡住（模拟永不返回的
    /// C 调用），`replace_abandoned_worker` 必须让池重新能服务后续作业 —— 这是
    /// 「一个卡死引擎不再饿死健康引擎」的承重墙。上限由 replaced 计数保证（另见
    /// [`MAX_REPLACEMENT_WORKERS`]）。
    #[test]
    fn abandoned_worker_is_replaced_so_pool_keeps_serving() {
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let pool = EnginePool::start(1, "utpool");
        let (started_tx, started_rx) = channel::<()>();
        let (release_tx, release_rx) = channel::<()>();
        let _stuck = pool
            .submit(move || -> Result<()> {
                started_tx.send(()).unwrap();
                let _ = release_rx.recv(); // 模拟卡死的 C 调用
                Ok(())
            })
            .expect("submit stuck job");
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("stuck job must start on the only worker");

        // 看门狗判超时 → 放弃该 worker 并补一条替补。
        pool.replace_abandoned_worker("ut");
        assert_eq!(pool.replaced.load(std::sync::atomic::Ordering::SeqCst), 1);

        // 替补必须能取到并完成新作业（旧实现在这里会永远排队）。
        let (done_tx, done_rx) = channel::<()>();
        let _job2 = pool
            .submit(move || -> Result<()> {
                done_tx.send(()).unwrap();
                Ok(())
            })
            .expect("submit second job");
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("replacement worker must serve new jobs");

        // 释放卡住的作业，让测试线程干净退出（池 Drop 后 worker 因 recv Err 退出）。
        release_tx.send(()).unwrap();
    }
}
