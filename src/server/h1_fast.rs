//! HTTP/1.1 静态请求「快车道」（hybrid；agent-fastpath / 工号 1009 / wave-9）。
//!
//! # 为什么存在
//!
//! bench-wave8 的分解（同源冻结树差分二进制，c64 口径）：每请求服务端 CPU
//! `final` 17.55µs → 手写循环 + 1 次 `lstat` + 预编码字节 `proto` **13.28µs**（−4.27µs，
//! −24%），其中 hyper 的连接驱动 ≈1.44µs、请求/响应对象模型与编码 ≈2.8µs。只要
//! 「不做架构级改动」就够不到规格门禁（h2o/ours ≤1.2），而应用层 micro-opt 已到顶
//! （访问日志 0.75µs、路由割肉 0）。本模块把 bench 原型（仅测量、未进生产路径）做成
//! **生产路径可用的保守实现**。
//!
//! # 设计（hybrid，保守优先）
//!
//! 只在**已建立连接**上、且只对**它完全理解的请求形状**接管：
//!
//! * 形状：HTTP/1.0 或 1.1 + `GET`/`HEAD` + origin-form 目标 + **无 body**
//!   （无 `Content-Length`/`Transfer-Encoding`）+ 无 `Expect`/`Upgrade`/`Range`/`If-*`/`TE`，
//!   且 `Host` 校验与 h1 慢路径同一判据（`h1::is_valid_host_value` 逐字复用）。
//! * 响应：来自 `static_files::serve_simple`（与 h1 `static_files::serve` 逐项对齐的
//!   唯一静态实现）的 **200 小文件**响应，在填充时**预编码成字节**（状态行 + 全部头），
//!   命中时只做 **1 次 `lstat` 身份复核**（len+ino+mtime，与 Wave-7 FAST_CACHE 同一红线）。
//! * 其余一切（POST/PUT、chunked、CL、Expect、Upgrade/WS、Range/条件请求、目录 301/
//!   autoindex/404、admin/DoH/telemetry/状态页、限流/ACL/basic_auth 配置、TLS-Upgrade、
//!   QMux、以及**任何解析不确定的输入**）**一律回退**：把连接（连同已读但未处理的字节）
//!   原样交回 hyper 的 `serve_connection`，行为与改动前**逐字节相同**（回退路径不打折）。
//! * 快车道不绕过任何安全/审计：ACL（`listener::ip_allowed`）、telemetry 计数、
//!   admin 路径、DoH 分流、状态页都按 h1 的同一顺序、同一判据先判；服务成功的请求
//!   由本模块调用同一份 `access_log::log_response_with`（engine="static"）。
//!
//! # 语义红线（与 hyper 逐项对齐，均已实测/单测）
//!
//! * keep-alive：HTTP/1.1 默认保持，`Connection` 头逐行按 hyper 的同一赋值语义
//!   （`keep_alive = !contains(close)`）判定；HTTP/1.0 的**逐行赋值**结果同样照用
//!   （起 false，行内含 `keep-alive` 置 true）——**1.0 + `Connection: keep-alive` 时
//!   hyper 是保持连接的**（`conn.rs::fix_keep_alive` 检查的是**响应** head 的版本，
//!   而应用响应的版本是默认的 1.1 ⇒ 它插入 `connection: keep-alive` 后才把响应版本
//!   改成 1.0；实测 1.0+KA 连接会被复用，pipelined 第二请求照常服务）。1.0 未请求
//!   keep-alive 时恒关连接且不补 `Connection` 头（同 hyper）。
//! * 响应行版本：请求 1.0 ⇒ `HTTP/1.0`，1.1 ⇒ `HTTP/1.1`（同 hyper `enforce_version`）。
//! * `Connection: close`：1.1 响应补 `connection: close`（hyper 同款）；1.0 不补（同 hyper）。
//! * `Date`：hyper 在头末尾自动补（按秒缓存）；快车道同样按秒缓存补在末尾。
//! * HEAD：头与 GET 逐字相同（含 Content-Length=文件长度），不发 body（同 hyper
//!   `Encoder::length` + req_method=HEAD）。
//! * Host：多行/非法/（1.1 origin-form）缺失 ⇒ **回退**，由 hyper 路径回 400（不自行编造）。
//! * 头结束符只认 `\r\n\r\n`；一旦在待解析区段里看到**裸 LF**（`\n` 前不是 `\r`）
//!   就立刻回退（hyper/httparse 把裸 LF 当行结束，实测 `GET / HTTP/1.1\nHost: h\n\n`
//!   会正常 200；若继续等 `\r\n\r\n` 就会挂到 30s 超时且一个字节都不发 —— 与 hyper
//!   路径不一致，等于把「不理解的形状」当假死）。
//! * 上限：请求头 ≤16KiB、头行 ≤100（与 h1.rs `max_headers(100)` 一致）、目标 ≤8KiB；
//!   超限一律回退（由 hyper 按它的上限决定 431/414）。行数/大小上限**只紧不松**。
//! * 超时：读下一个请求头有 30s 总预算（同 h1 `HEADER_READ_TIMEOUT`），超时/EOF 即关闭。
//! * pipelining：天然支持（顺序解析、顺序写响应）；遇到不理解的请求就带着剩余字节回退。
//!
//! # 开关与灰度
//!
//! `CRUCIBLE_H1_FASTPATH=0|false|off` 关闭（进程级，读一次）。默认**开**（本 wave 的
//! 目标就是把门禁做进生产路径）；关掉后行为 == 改动前（`h1.rs` 直接走 hyper）。
//! 另：只有**纯静态** listener（无 apps / page_rules / proxy_rules / file_open /
//! basic_auth / rate_limit，非 port_reuse）才启用；`/__metrics`、admin、DoH、状态页等
//! 路径级闸门逐请求判。
//!
//! # 覆盖率的可观测性
//!
//! 进程级原子计数器（每 60s 且计数有变化时 info 一条）：
//! `conns / served / fb_parse / fb_gate / fb_miss / filled`。回退连接走 hyper，
//! 行为不变，只是不提速。

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use bytes::Bytes;
use http::{header, HeaderMap, HeaderValue, StatusCode};
use http_body_util::Full;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// 与 `h1::HEADER_READ_TIMEOUT` 同值的**总预算**：从开始等一个请求头算起，30s 内没收全
/// 就关连接（hyper 的 `header_read_timeout` 同样是「整段头」的预算，且同样覆盖空闲
/// keep-alive 的等待）。
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// 单个请求头（含请求行与结尾空行）的字节上限；超出 → 回退 hyper。
const MAX_HEAD: usize = 16 * 1024;
/// 头行数上限：与 h1.rs 的 `Builder::max_headers(MAX_HEADERS = 100)` 对齐。
const MAX_HEADER_LINES: usize = 100;
/// origin-form 目标长度上限（超过交回 hyper，由它决定 414 与否）。
const MAX_TARGET: usize = 8 * 1024;
/// 只缓存小文件响应字节（与 `static_files` 的 SMALL_FILE_MAX 同值/同策略）。
const SMALL_FILE_MAX: usize = 256 * 1024;
/// 条目 TTL：与 `static_files` 的 `CANON_TTL`/FAST_CACHE 同一窗口（2s）。
const CACHE_TTL: Duration = Duration::from_secs(2);
/// 每个 (root, hsts) 的条目数上限，超限整体清空（同 FAST_CAP 策略）。
const CACHE_CAP: usize = 256;
/// 目录 URL 的索引文件名候选，必须与 `static_files::INDEX_FILES` 保持一致
/// （这里只用于「按 ETag 反查真实文件身份」，判错只会导致**少缓存**，不会放行错误内容）。
const INDEX_FILES: &[&str] = &["index.html", "index.htm"];

// ---------------------------------------------------------------------------
// 开关与连接级资格
// ---------------------------------------------------------------------------

/// 进程级开关：`CRUCIBLE_H1_FASTPATH=0|false|off`（大小写不敏感）关闭；读一次。
pub(crate) fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    // 必须走启动期缓存读法（`env_lock::read_static_env`）：这是**请求路径**上的第一次读，
    // 而应用引擎/`.env` 注入会在请求期间 setenv，libc 的 environ realloc 会让并发 getenv
    // 踩到已释放内存（此前已修过同类 P0：core 栈顶 _libc_getenv）。裸 std::env::var 会把它引回来。
    *ON.get_or_init(|| match crate::server::apps::env_lock::read_static_env("CRUCIBLE_H1_FASTPATH") {
        Some(v) => {
            let v = v.trim();
            !(v.is_empty()
                || v == "0"
                || v.eq_ignore_ascii_case("false")
                || v.eq_ignore_ascii_case("off")
                || v.eq_ignore_ascii_case("no"))
        }
        // 默认开：本 wave 的目标就是把门禁做进生产路径；关掉后行为 == 改动前。
        None => true,
    })
}

/// 连接级资格：只有「纯静态站点」才值得/才允许走快车道。
///
/// 任何一项不满足都说明这条连接上的请求可能落到非静态分支（引擎/反代/规则改写/
/// 鉴权/限流/上传），那些语义由 hyper + 应用层处理，快车道**不试图理解**。
pub(crate) fn conn_eligible(lc: &ListenerConfig) -> bool {
    lc.apps.is_empty()
        && !crate::server::page_rules::has_rules(&lc)
        && lc.proxy_rules.is_empty()
        && lc.file_open.is_empty()
        && lc.basic_auth.is_none()
        && !lc.port_reuse
        && lc.rate_limit.as_ref().map_or(true, |r| !r.enabled)
}

// ---------------------------------------------------------------------------
// 覆盖率/回退计数（可观测性）
// ---------------------------------------------------------------------------

static CONNS: AtomicU64 = AtomicU64::new(0);
static SERVED: AtomicU64 = AtomicU64::new(0);
static FB_PARSE: AtomicU64 = AtomicU64::new(0);
static FB_GATE: AtomicU64 = AtomicU64::new(0);
static FB_MISS: AtomicU64 = AtomicU64::new(0);
static FILLED: AtomicU64 = AtomicU64::new(0);

fn ensure_reporter() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_ok() {
        tokio::spawn(async move {
            let mut last = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let now = (
                    CONNS.load(Ordering::Relaxed),
                    SERVED.load(Ordering::Relaxed),
                    FB_PARSE.load(Ordering::Relaxed),
                    FB_GATE.load(Ordering::Relaxed),
                    FB_MISS.load(Ordering::Relaxed),
                    FILLED.load(Ordering::Relaxed),
                );
                if now != last {
                    log::info!(
                        "h1 fastpath: conns={} served={} fb_parse={} fb_gate={} fb_miss={} filled={} (fallbacks continue on hyper)",
                        now.0, now.1, now.2, now.3, now.4, now.5
                    );
                    last = now;
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// 响应字节缓存（填充自 serve_simple 的 200 小文件响应）
// ---------------------------------------------------------------------------

/// 文件身份指纹 = ETag 的四个字段（len, ino, mtime.secs, mtime.nanos）。
///
/// 与 `static_files::FastEntry` 的 FileId（len+ino+mtime）等价 —— 只是能从响应 ETag
/// 直接重建（`validators()` 的 ETag 就是这四个字段的十六进制），因此填充路径不需要
/// 拿到私有的 `FileId`/`resolve_path`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Id {
    len: u64,
    ino: u64,
    secs: u64,
    nanos: u32,
}

#[cfg(unix)]
fn ino_of(m: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}
#[cfg(not(unix))]
fn ino_of(_m: &fs::Metadata) -> u64 {
    0
}

/// 把 metadata 折算成与 ETag 同源的指纹（`validators()` 的公式：len / mtime / ino）。
fn id_of(m: &fs::Metadata) -> Id {
    let (secs, nanos) = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0));
    Id {
        len: m.len(),
        ino: ino_of(m),
        secs,
        nanos,
    }
}

/// 解析 `validators()` 生成的 ETag：`"{len:x}-{secs:x}-{nanos:x}-{ino:x}"`。
fn parse_etag_id(etag: &str) -> Option<Id> {
    let s = etag.strip_prefix('"')?.strip_suffix('"')?;
    let mut it = s.split('-');
    let len = u64::from_str_radix(it.next()?, 16).ok()?;
    let secs = u64::from_str_radix(it.next()?, 16).ok()?;
    let nanos = u32::from_str_radix(it.next()?, 16).ok()?;
    let ino = u64::from_str_radix(it.next()?, 16).ok()?;
    if it.next().is_some() {
        return None;
    }
    Some(Id {
        len,
        ino,
        secs,
        nanos,
    })
}

struct Entry {
    /// 复核用的真实文件路径（解析自 serve_simple 服务的那个文件）。
    fs_path: PathBuf,
    id: Id,
    /// 预编码响应：状态行 + 全部头（**不含** Date —— Date 在发送时按秒缓存补，
    /// 也不含 Connection —— 四个变体各一份）。
    head_11: Bytes,
    /// 1.1 + `connection: close`（hyper 的 `enforce_version` 在头尾补该行后接 Date）。
    head_11_close: Bytes,
    /// 1.0 状态行 + 同一批头（hyper 对 1.0 请求强制 1.0 响应；未请求 keep-alive 时
    /// 恒关连接且**不补** Connection 头）。
    head_10: Bytes,
    /// 1.0 + `Connection: keep-alive`：hyper 保持连接并在头尾补该行（`fix_keep_alive`
    /// 走的是响应 head 的 1.1 分支，见模块说明），位置与 hyper 一致：所有响应头之后、
    /// `date` 之前 —— 这里就是本变体的末尾（`date` 由 [`append_date`] 追加）。
    head_10_ka: Bytes,
    body: Bytes,
    at: Instant,
}

/// 缓存：root → (hsts?) → url path → entry。三级键避免每请求构造复合 Key 的分配。
static CACHE: Lazy<Mutex<HashMap<PathBuf, HashMap<bool, HashMap<String, Arc<Entry>>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

impl Entry {
    /// 该条目的存活窗口是否还没过（`now` 为调用方时钟；同 `CACHE_TTL`）。
    fn is_stale_at(&self, now: Instant) -> bool {
        now.duration_since(self.at) >= CACHE_TTL
    }
}

/// 命中缓存（不做复核；复核见 [`revalidate`]）。
///
/// `now` 由调用方给出（本次请求的 `t0`）：省一次 `Instant::now()`。两者同为单调时钟，
/// 差 ≤ 本请求已耗时（µs 级），对 2s 的 TTL 判定没有可观测差异。
fn lookup(root: &Path, hsts: bool, path: &str, now: Instant) -> Option<Arc<Entry>> {
    let c = CACHE.lock();
    let e = c.get(root)?.get(&hsts)?.get(path)?.clone();
    if now.duration_since(e.at) >= CACHE_TTL {
        return None;
    }
    Some(e)
}

/// 从缓存删掉一条（复核失败时用，避免每次请求都白做一次失败的 lstat）。
fn drop_entry(root: &Path, hsts: bool, path: &str) {
    let mut c = CACHE.lock();
    if let Some(m) = c.get_mut(root) {
        if let Some(inner) = m.get_mut(&hsts) {
            inner.remove(path);
        }
    }
}

/// 发射前复核：**1 次 `lstat`** + 身份指纹比对（符号链接/非普通文件/指纹变化一律失效，
/// 语义与 `static_files::FastEntry` 的复核逐字对齐：ETag 含 inode，替换必失效）。
fn revalidate(e: &Entry) -> bool {
    match fs::symlink_metadata(&e.fs_path) {
        Ok(m) => !m.file_type().is_symlink() && m.is_file() && id_of(&m) == e.id,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// 请求解析（只理解「完全理解」的形状；任何歧义 → None → 回退）
// ---------------------------------------------------------------------------

struct ParsedReq<'a> {
    /// true = HEAD（头照发、不发 body）。
    is_head: bool,
    /// true = HTTP/1.0（响应用 1.0 状态行，且恒关连接）。
    http_10: bool,
    /// origin-form 的目标（含 query）。
    target: &'a str,
    /// 路径部分（不含 query）。
    path: &'a str,
    /// 是否保持连接（1.0 恒 false —— 与 hyper 对 1.0 的处理一致）。
    keep_alive: bool,
    /// `Host` 头值（至多一个；1.1 origin-form 必有）。
    host: Option<&'a str>,
}

#[inline]
fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// `Connection` 头值里是否含指定 token（逗号分隔、trim、ASCII 大小写不敏感）——
/// 与 hyper `headers.rs::connection_has` 同语义。
fn connection_has(value: &[u8], needle: &[u8]) -> bool {
    for part in value.split(|&b| b == b',') {
        let t: &[u8] = {
            let mut s = 0;
            let mut e = part.len();
            while s < e && (part[s] == b' ' || part[s] == b'\t') {
                s += 1;
            }
            while e > s && (part[e - 1] == b' ' || part[e - 1] == b'\t') {
                e -= 1;
            }
            &part[s..e]
        };
        if t.eq_ignore_ascii_case(needle) {
            return true;
        }
    }
    false
}

fn find_crlf(hay: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < hay.len() {
        if hay[i] == b'\r' && hay[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 头结束符扫描结果（见 [`scan_head`]）。
enum HeadScan {
    /// 还没看到请求头结束符，需要继续读。
    NeedMore,
    /// 请求头在 `n` 字节处结束（`n` = 结束符**之后**一位，即该请求可被消费的长度）。
    Complete(usize),
    /// 出现了**裸 LF**（`\n` 且前一位不是 `\r`）：不是本模块完全理解的形状（它的
    /// 结束符判据是 `\r\n\r\n`），立刻回退 hyper —— hyper/httparse 把裸 LF 当行结束，
    /// 实测 `GET / HTTP/1.1\nHost: h\n\n` 会正常 200/404；而继续等 `\r\n\r\n` 只会挂到
    /// 30s 超时、一个字节都不发（真实缺陷：LF-only 客户端在快车道开时收不到响应，
    /// 快车道关时立刻 200）。回退时已读字节全部原样交回，hyper 得到的是同一个请求。
    NotUnderstood,
}

/// 扫描待解析区段：找 `\r\n\r\n` 结束符，同时拒绝裸 LF。
///
/// `from` 是「上一次已扫过的长度」，函数会**回退 3 字节**重扫，避免跨读边界的
/// 结束符被漏掉；因此每读一批新字节只会重扫 3 字节旧数据，慢速客户端下不会 O(n²)。
fn scan_head(buf: &[u8], from: usize) -> HeadScan {
    let mut i = from.saturating_sub(3);
    while i < buf.len() {
        let b = buf[i];
        // 裸 LF：`i == 0` 时也算（请求头不能以 LF 开头；前导 CRLF 不会命中这里，
        // 因为它的 LF 前一位是 CR）。
        if b == b'\n' && (i == 0 || buf[i - 1] != b'\r') {
            return HeadScan::NotUnderstood;
        }
        // 说明（fastsec-wave10 实测）：**不**在这里对控制字符做「提前回退」。hyper 对
        // 请求行/头名里的非法字节确实会**看到就报错**（`GET\x00 ...` 无结束符时立刻
        // 400），但它的报错时机取决于读边界（`h1/role.rs::is_complete_fast`：只有
        // 「上一次是部分读」且本批数据里出现结束符才重跑 httparse）⇒ 同一串字节经
        // ReplayIo 一次性喂入时 hyper 会立刻 400，走 socket 分两次读入时则一直等到
        // 30s 超时 —— 两种时机**不可能同时对齐**。实测表见
        // `.agents/1009/reports/fastsec-wave10.md`「未闭差异 D」。
        if i + 4 <= buf.len()
            && b == b'\r'
            && buf[i + 1] == b'\n'
            && buf[i + 2] == b'\r'
            && buf[i + 3] == b'\n'
        {
            return HeadScan::Complete(i + 4);
        }
        i += 1;
    }
    HeadScan::NeedMore
}

/// 解析一个完整请求头（`head` 以 CRLFCRLF 结束）。返回 `None` = 回退 hyper。
fn parse_request(head: &[u8]) -> Option<ParsedReq<'_>> {
    // ── 请求行：`METHOD SP TARGET SP VERSION`（严格；多余空白/异形一律回退）──
    let eol = find_crlf(head)?;
    let line = &head[..eol];
    let sp1 = line.iter().position(|&b| b == b' ')?;
    let method = &line[..sp1];
    let rest = &line[sp1 + 1..];
    let sp2 = rest.iter().position(|&b| b == b' ')?;
    let target = &rest[..sp2];
    let version = &rest[sp2 + 1..];
    let is_head = match method {
        b"GET" => false,
        b"HEAD" => true,
        _ => return None,
    };
    let http_10 = match version {
        b"HTTP/1.1" => false,
        b"HTTP/1.0" => true,
        // 其他版本（HTTP/1.2、缺版本号、HTTP/2.0 等）交回 hyper 处理其既定语义。
        _ => return None,
    };
    if target.len() > MAX_TARGET || !target.starts_with(b"/") {
        return None;
    }
    // origin-form 只允许可见 ASCII、不含 `#`（fragment 不允许出现在 request-target）。
    if target.iter().any(|&b| b < 0x21 || b == 0x7f || b == b'#') {
        return None;
    }
    let target = std::str::from_utf8(target).ok()?;
    let path = match target.find('?') {
        Some(i) => &target[..i],
        None => target,
    };

    // ── 头字段 ──
    let mut rest = &head[eol + 2..];
    let mut host: Option<&str> = None;
    let mut host_count = 0usize;
    // hyper 的判定是逐行**赋值**：1.1 起 true，遇 close 置 false（后续行可再置回）；
    // 1.0 起 false，遇 keep-alive 置 true。这里逐行复刻；1.0 最后统一强制 false。
    let mut keep_alive = !http_10;
    let mut lines = 0usize;
    loop {
        let Some(i) = find_crlf(rest) else { return None };
        let field = &rest[..i];
        rest = &rest[i + 2..];
        if field.is_empty() {
            break; // 头结束（head 已保证以 CRLFCRLF 收尾）
        }
        lines += 1;
        if lines > MAX_HEADER_LINES {
            return None;
        }
        // obs-fold（续行）不被 hyper 接受，交回它按自己的规则处置。
        if field[0] == b' ' || field[0] == b'\t' {
            return None;
        }
        let colon = field.iter().position(|&b| b == b':')?;
        let name = &field[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_token(b)) {
            return None;
        }
        let raw_value = &field[colon + 1..];
        // 去 OWS（httparse 同样会 trim）。
        let mut v: &[u8] = raw_value;
        while let [b' ' | b'\t', r @ ..] = v {
            v = r;
        }
        while let [r @ .., b' ' | b'\t'] = v {
            v = r;
        }
        // 值里出现控制字符（除 HTAB）→ 回退（httparse 也会拒；不自行解释）。
        if v.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return None;
        }
        if name.eq_ignore_ascii_case(b"host") {
            host_count += 1;
            if host_count > 1 {
                // 多行 Host：h1 路径回 400（host_header_ok），交回 hyper。
                return None;
            }
            let h = std::str::from_utf8(v).ok()?;
            // 值存在就必须合法（与 h1::is_valid_host_value 同一判据、同一函数）。
            if !crate::server::h1::is_valid_host_value(h) {
                return None;
            }
            host = Some(h);
        } else if name.eq_ignore_ascii_case(b"connection") {
            // hyper 的 `headers::connection_has` 先做 `HeaderValue::to_str()`：**只要值里
            // 有一个字节不是 visible-ASCII（0x20..0x7e 或 HTAB），整条值就放弃** ——
            // 等价于「这条 Connection 行没有任何 token」。本模块是逐字节找 token 的，
            // 于是在 `Connection: \xff, close` 上会得出**相反**的 keep-alive 结论（实测
            // A/B 差异：快车道关连接并丢弃 pipelined 的第二请求，hyper 保持连接并正常
            // 服务第二个请求；`Connection: \xff, keep-alive` 在 1.0 上同理）。
            // 这种值属于「不完全理解」⇒ 一律回退，由 hyper 按其自身判据处置。
            // （<0x20 / 0x7f 的控制字符已在上面统一拒绝，走不到这里。）
            if v.iter().any(|&b| b >= 0x80) {
                return None;
            }
            if keep_alive {
                keep_alive = !connection_has(v, b"close");
            } else {
                keep_alive = connection_has(v, b"keep-alive");
            }
        } else if name.eq_ignore_ascii_case(b"content-length")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
            || name.eq_ignore_ascii_case(b"expect")
            || name.eq_ignore_ascii_case(b"upgrade")
            || name.eq_ignore_ascii_case(b"range")
            || name.eq_ignore_ascii_case(b"if-match")
            || name.eq_ignore_ascii_case(b"if-none-match")
            || name.eq_ignore_ascii_case(b"if-modified-since")
            || name.eq_ignore_ascii_case(b"if-unmodified-since")
            || name.eq_ignore_ascii_case(b"if-range")
            || name.eq_ignore_ascii_case(b"te")
            || name.eq_ignore_ascii_case(b"trailer")
        {
            // 「有 body / 有升级 / 有条件/Range / 有 hop-by-hop 扩展」的形状一律回退：
            // 这些语义（framing、100-continue、206/304、WS 隧道）全部由 hyper + 应用层处理。
            return None;
        }
    }
    // HTTP/1.1 origin-form 必须带 Host；HTTP/1.0 不要求（但带了就必须合法，上面已判）。
    if !http_10 && host.is_none() {
        return None;
    }
    // 1.0 的 keep-alive：**逐行赋值的结果照用**（默认 false，行内含 `keep-alive` 置 true）。
    //
    // 曾经这里强制 `keep_alive = false`（注释声称「hyper 对 1.0 一律 disable keep-alive」）
    // —— 实测该断言是错的：1.0 + `Connection: keep-alive` 时 hyper 保持连接、响应里带
    // `connection: keep-alive`、pipelined 的第二请求照常服务（A/B 对拍逐字节证据见
    // `.agents/1009/reports/fastsec-wave10.md`）。强制 false 的后果是快车道**静默丢弃**
    // 这种客户端 pipelined 的后续请求（响应少一条、连接被关），与 hyper 路径不再一致。
    // 关闭语义在 `serve` 里按同样口径决定（1.0+KA 恒不关，见那里的注释）。
    Some(ParsedReq {
        is_head,
        http_10,
        target,
        path,
        keep_alive,
        host,
    })
}

/// 与 `access::is_admin_path` **逐字等价**但零分配的管理路径判定。
///
/// 原实现每请求 `format!("{}/", admin_path.trim_end_matches('/'))` 一次堆分配；
/// 快车道请求路径上唯一的每请求分配就在这里。展开后是同一判据：
/// `path == admin_path || path.starts_with(trim_end_matches(admin_path, '/') + "/")`。
/// 单测 `admin_path_matches_access_impl` 用同一张用例表把两个实现逐项对齐
/// （包括 `admin_path` 为空/纯斜杠/带尾斜杠等边界）。
fn is_admin_path_fast(admin_path: &str, path: &str) -> bool {
    if path == admin_path {
        return true;
    }
    let base = admin_path.trim_end_matches('/');
    path.len() >= base.len() + 1 && path.as_bytes()[base.len()] == b'/' && path.starts_with(base)
}

/// 把原始头区段重建为 `HeaderMap`（仅填充路径使用，见 [`fill_entry`]）。
fn header_map_from_head(head: &[u8]) -> Option<HeaderMap> {
    let eol = find_crlf(head)?;
    let mut rest = &head[eol + 2..];
    let mut hm = HeaderMap::new();
    loop {
        let i = find_crlf(rest)?;
        let field = &rest[..i];
        rest = &rest[i + 2..];
        if field.is_empty() {
            break;
        }
        let colon = field.iter().position(|&b| b == b':')?;
        let name = http::header::HeaderName::from_bytes(&field[..colon]).ok()?;
        let mut v: &[u8] = &field[colon + 1..];
        while let [b' ' | b'\t', r @ ..] = v {
            v = r;
        }
        while let [r @ .., b' ' | b'\t'] = v {
            v = r;
        }
        let value = HeaderValue::from_bytes(v).ok()?;
        hm.append(name, value);
    }
    Some(hm)
}

// ---------------------------------------------------------------------------
// 填充：走一次完整静态解析（serve_simple），把 200 小文件响应预编码入缓存
// ---------------------------------------------------------------------------

/// 目录 URL 的索引候选相对路径（用于按 ETag 反查真实文件）。判错只会少缓存。
fn candidate_rels(url_path: &str) -> Vec<String> {
    let rel = url_path.trim_start_matches('/');
    if url_path.ends_with('/') {
        INDEX_FILES.iter().map(|n| format!("{rel}{n}")).collect()
    } else {
        vec![rel.to_string()]
    }
}

/// 用 `static_files::serve_simple` 产出响应；若它是「可缓存的 200 小文件」就预编码入缓存。
///
/// 为什么走 `serve_simple`：它是与 h1 `static_files::serve` 逐项对齐的静态实现，
/// 且是 `pub` 的泛型接口（不需要构造 hyper 的 `Request<Incoming>`）——**不复制**任何
/// 路径解析/containment/符号链接判定逻辑（那才是安全红线所在）。
/// 反查真实文件身份：响应 ETag 里就含 (len,ino,mtime)，对候选路径逐个 `lstat` 比对，
/// 命中即拿到复核用路径；对不上（符号链接索引、非常规名、并发改动）**不入缓存**。
async fn fill_entry(
    lc: &ListenerConfig,
    head: &[u8],
    is_head: bool,
    target: &str,
    path: &str,
) -> Option<Arc<Entry>> {
    if is_head {
        // HEAD 未命中不做填充（响应 body 为空，拿不到缓存字节）；交回 hyper。
        return None;
    }
    let hsts = lc.ssl.is_some();
    let uri: http::Uri = target.parse().ok()?;
    let hm = header_map_from_head(head)?;
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .ok()?;
    let (mut parts, body) = req.into_parts();
    parts.headers = hm;
    let req = http::Request::from_parts(parts, body);
    let resp = crate::server::static_files::serve_simple::<Full<Bytes>>(&req, lc)
        .await
        .ok()?;
    if resp.status() != StatusCode::OK {
        return None;
    }
    // 流式/大文件来源不缓存（没有完整字节）。
    if resp
        .extensions()
        .get::<crate::server::static_files::FileSource>()
        .is_some()
    {
        return None;
    }
    let (parts, data) = resp.into_parts();
    if data.len() > SMALL_FILE_MAX {
        return None;
    }
    // 0 字节文件**不进快车道**（回退 hyper）：hyper 对「空 body 且长度未知」的 GET 响应会
    // 丢掉应用给的 `content-length: 0`，改在头区段**末尾**补一行（实测 `GET /empty.txt`
    // 经 hyper 的线序 `…last-modified\r\nconnection: close\r\ncontent-length: 0\r\ndate:`），
    // 而 HEAD 走 inline 分支（CL 留在 content-type 之后）——同一份预编码模板只能对齐一种，
    // 且 0 字节文件没有提速价值。直接回退 ⇒ A/B 逐字节一致（见 perf5-wave10 报告）。
    if data.is_empty() {
        return None;
    }
    let etag = parts.headers.get(header::ETAG)?.to_str().ok()?;
    let id = parse_etag_id(etag)?;
    if id.len != data.len() as u64 {
        return None;
    }
    // 按 ETag 反查真实文件（身份三要素必须逐位相等）。
    let mut fs_path: Option<PathBuf> = None;
    for rel in candidate_rels(path) {
        let cand = lc.root.join(&rel);
        if let Ok(m) = fs::symlink_metadata(&cand) {
            if !m.file_type().is_symlink() && m.is_file() && id_of(&m) == id {
                fs_path = Some(cand);
                break;
            }
        }
    }
    let fs_path = fs_path?;

    // 预编码：状态行（1.1/1.0 两份）+ 头区段 + HSTS（TLS 站点，与 h1 收口处同判据）。
    let mut headers_bytes: Vec<u8> = Vec::with_capacity(320);
    for (n, v) in parts.headers.iter() {
        headers_bytes.extend_from_slice(n.as_str().as_bytes());
        headers_bytes.extend_from_slice(b": ");
        headers_bytes.extend_from_slice(v.as_bytes());
        headers_bytes.extend_from_slice(b"\r\n");
    }
    if hsts && !parts.headers.contains_key(header::STRICT_TRANSPORT_SECURITY) {
        headers_bytes.extend_from_slice(b"strict-transport-security: ");
        headers_bytes.extend_from_slice(crate::server::h1::hsts_header().as_bytes());
        headers_bytes.extend_from_slice(b"\r\n");
    }
    let status_line = |v10: bool| -> Vec<u8> {
        let mut s = Vec::with_capacity(24);
        s.extend_from_slice(if v10 { b"HTTP/1.0 " } else { b"HTTP/1.1 " });
        s.extend_from_slice(parts.status.as_u16().to_string().as_bytes());
        s.push(b' ');
        s.extend_from_slice(parts.status.canonical_reason().unwrap_or("<none>").as_bytes());
        s.extend_from_slice(b"\r\n");
        s
    };
    let mut head_11 = status_line(false);
    head_11.extend_from_slice(&headers_bytes);
    let mut head_11_close = head_11.clone();
    head_11_close.extend_from_slice(b"connection: close\r\n");
    let mut head_10 = status_line(true);
    head_10.extend_from_slice(&headers_bytes);
    // 1.0 + `Connection: keep-alive`：hyper 在响应头末尾补 `connection: keep-alive`
    // （位置：应用头之后、`date` 之前 —— hyper 的 HeaderMap 迭代顺序里该头落在最后，
    // 由 A/B 对拍逐字节确认）。
    let mut head_10_ka = head_10.clone();
    head_10_ka.extend_from_slice(b"connection: keep-alive\r\n");

    let e = Arc::new(Entry {
        fs_path,
        id,
        head_11: Bytes::from(head_11),
        head_11_close: Bytes::from(head_11_close),
        head_10: Bytes::from(head_10),
        head_10_ka: Bytes::from(head_10_ka),
        body: data,
        at: Instant::now(),
    });
    {
        let mut c = CACHE.lock();
        let inner = c
            .entry(lc.root.clone())
            .or_default()
            .entry(hsts)
            .or_default();
        if inner.len() >= CACHE_CAP {
            inner.clear();
        }
        inner.insert(path.to_string(), Arc::clone(&e));
    }
    FILLED.fetch_add(1, Ordering::Relaxed);
    Some(e)
}

// ---------------------------------------------------------------------------
// Date（按秒缓存，线程本地；hyper 的自动 date 头同款）
// ---------------------------------------------------------------------------

thread_local! {
    static DATE_CACHE: std::cell::RefCell<(u64, [u8; 48], usize)> =
        std::cell::RefCell::new((u64::MAX, [0u8; 48], 0));
}

/// 追加 `date: <http-date>\r\n`（每个线程每秒最多格式化一次）。
fn append_date(out: &mut Vec<u8>) {
    let now = SystemTime::now();
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    DATE_CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.0 != secs {
            let line = format!("date: {}\r\n", httpdate::fmt_http_date(now));
            let n = line.len().min(c.1.len());
            c.1[..n].copy_from_slice(&line.as_bytes()[..n]);
            c.2 = n;
            c.0 = secs;
        }
        out.extend_from_slice(&c.1[..c.2]);
    });
}

// ---------------------------------------------------------------------------
// 头读取
// ---------------------------------------------------------------------------

enum HeadRead {
    /// 收全一个请求头，值为「head 结束后的偏移」（= 请求可被消费的长度）。
    Complete(usize),
    /// 超限：交回 hyper（连同已读字节）。
    Fallback,
    /// EOF / IO 错误 / 头读超时：关闭连接（hyper 同样只是关闭）。
    Closed,
}

/// 读取并扫描一个完整请求头；`sleep` 是**连接级**的 30s 预算定时器（见 [`serve`]）。
///
/// 语义与每请求 `tokio::time::timeout_at(deadline, ...)` **逐项相同**：等待一个请求头
/// 有一个 30s 总预算（与 hyper 的 `header_read_timeout`、h1 的 `HEADER_READ_TIMEOUT`
/// 同值），期间每批新字节都**在同一预算内**继续收，超时/EOF/IO 错误即关闭连接；
/// 上限（16KiB / 头行数）与回退判据也一字未动。
///
/// 差别只在**实现**：连接级 `Sleep` 每请求 `reset` 一次截止时间（tokio 文档明确支持
/// 在完成前/完成后调用 `reset`；已注册的定时器只改截止时间，不必「先注册再取消」）。
/// 每请求少一次定时器注册/取消（c128 饱和口径实测 −0.2 ~ −0.4µs/req），换来的不是语义——
/// 这个 30s 预算在快车道与 hyper 路径上都原样存在（slowloris 防线不放宽）。
async fn read_head<IO: AsyncRead + Unpin>(
    io: &mut IO,
    buf: &mut Vec<u8>,
    scan_from: &mut usize,
    sleep: &mut Pin<Box<tokio::time::Sleep>>,
) -> HeadRead {
    match scan_head(buf, *scan_from) {
        HeadScan::Complete(n) => return HeadRead::Complete(n),
        // 裸 LF：不理解 ⇒ 立刻回退（含已读字节），由 hyper 按它自己的（更宽的）行结束
        // 判据处理。**不能**继续等 `\r\n\r\n`：那会挂到 30s 且不发响应。
        HeadScan::NotUnderstood => return HeadRead::Fallback,
        HeadScan::NeedMore => {}
    }
    // 本次等待的预算从**现在**起算（与 `timeout_at(now + 30s, ...)` 同一时刻）。
    sleep
        .as_mut()
        .reset(tokio::time::Instant::now() + HEADER_READ_TIMEOUT);
    loop {
        if buf.len() >= MAX_HEAD {
            return HeadRead::Fallback;
        }
        if buf.capacity() - buf.len() < 1024 {
            buf.reserve(8 * 1024);
        }
        let before = buf.len();
        tokio::select! {
            biased;
            r = io.read_buf(buf) => match r {
                Ok(0) => return HeadRead::Closed,
                Ok(_) => {
                    *scan_from = before;
                    match scan_head(buf, *scan_from) {
                        HeadScan::Complete(n) => return HeadRead::Complete(n),
                        HeadScan::NotUnderstood => return HeadRead::Fallback,
                        HeadScan::NeedMore => {}
                    }
                }
                Err(_) => return HeadRead::Closed,
            },
            // 30s 预算耗尽（= `timeout_at` 的 `Err(_)` 分支）：关闭连接。
            _ = sleep.as_mut() => return HeadRead::Closed,
        }
    }
}

// ---------------------------------------------------------------------------
// 回退用 IO 包装：把已读字节先喂给 hyper，之后透传底层流
// ---------------------------------------------------------------------------

/// `prefix`（已从 socket 读走、尚未交给 hyper 的字节）先出，随后透传 `inner`。
pub(crate) struct ReplayIo<IO> {
    prefix: Vec<u8>,
    pos: usize,
    inner: IO,
}

impl<IO> ReplayIo<IO> {
    pub(crate) fn new(inner: IO, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for ReplayIo<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.pos);
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos >= self.prefix.len() {
                self.prefix = Vec::new();
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for ReplayIo<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 主循环
// ---------------------------------------------------------------------------

enum Fb {
    Gate,
    Miss,
}

/// 快车道主循环。返回 `Some(io)` = 需要交回 hyper 继续（含已读字节的 replay 包装）；
/// `None` = 本条连接已处理完/已关闭。
pub(crate) async fn serve<IO>(
    mut io: IO,
    live: Arc<LiveConfig>,
    lc: Arc<ListenerConfig>,
    peer: SocketAddr,
    gen0: u64,
) -> Option<ReplayIo<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ensure_reporter();
    CONNS.fetch_add(1, Ordering::Relaxed);
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut scratch: Vec<u8> = Vec::with_capacity(2 * 1024);
    let mut path_buf = String::with_capacity(256);
    let mut scan_from = 0usize;
    // 连接级 30s 头读预算定时器（`read_head` 每请求 reset；见其说明）。
    let mut sleep = Box::pin(tokio::time::sleep_until(
        tokio::time::Instant::now() + HEADER_READ_TIMEOUT,
    ));
    // 连接级「上一条命中」：keep-alive 上客户端通常反复请求同一路径，用于省掉
    // 全局缓存的锁 + 哈希查找（复核/lstat 一个不少；见命中处注释）。
    let mut last: Option<(String, Arc<Entry>)> = None;
    // 本连接上「快车道不可服务」的路径备忘：404/目录/非普通文件/空 body/超限、
    // 以及解析后回退的形状。首次照付一次 `fill_entry`，之后同路径**直接回退 hyper**，
    // 不再每请求白做一次静态解析（否则 404 类请求要付「fill + hyper 完整服务」两份成本）。
    // 只影响提速与否，不影响任何响应字节（回退路径逐字节不变）。
    let mut miss_memo: Option<String> = None;
    let hsts = lc.ssl.is_some();
    let access_override = lc.access_log.clone();
    // 连接级访问日志前缀（`h1 {peer} `）：peer 的 Display + `core::fmt` 从每请求一次
    // 降为每连接一次（懒构造：日志关闭的连接不构造）。行内容与逐请求实现逐字节相同
    // （见 `access_log::ConnPrefix` 与其单测）。
    let mut log_prefix: Option<crate::server::access_log::ConnPrefix<'_>> = None;

    loop {
        let n = match read_head(&mut io, &mut buf, &mut scan_from, &mut sleep).await {
            HeadRead::Complete(n) => n,
            HeadRead::Fallback => {
                FB_PARSE.fetch_add(1, Ordering::Relaxed);
                return Some(ReplayIo::new(io, buf));
            }
            HeadRead::Closed => return None,
        };
        let req = match parse_request(&buf[..n]) {
            Some(r) => r,
            None => {
                FB_PARSE.fetch_add(1, Ordering::Relaxed);
                return Some(ReplayIo::new(io, buf));
            }
        };
        let t0 = Instant::now();
        let snap = live.snapshot();

        // ── 路径级闸门（顺序与 h1::handle_request_inner 一致；命中即回退 hyper）──
        let mut fb = None;
        if !crate::server::listener::ip_allowed(&snap.ip_access, &lc, peer) {
            // ACL 拒绝：交回 hyper 走同一套 403 响应与日志。
            fb = Some(Fb::Gate);
        } else if snap.telemetry.enabled && req.path == snap.telemetry.path {
            fb = Some(Fb::Gate);
        } else if snap.dns.enabled && snap.dns.doh.enabled {
            // DoH（RFC 8484）：只有「路径 == DoH 路径 且 Host 在 DoH 白名单」时才是 DoH 请求
            // （TLS 口会应答、明文口回 400）——两种都由 hyper 路径处理。
            let eff = crate::server::dns::effective(&snap);
            if eff.doh.enabled && eff.doh.path.trim() == req.path && !eff.doh.hostnames.is_empty() {
                let hv = req.host.and_then(|h| HeaderValue::from_str(h).ok());
                if crate::server::dns::dot_doh::is_doh_request(&eff, req.path, hv.as_ref()) {
                    fb = Some(Fb::Gate);
                }
            }
        }
        if fb.is_none() && is_admin_path_fast(&snap.admin.path, req.path) {
            fb = Some(Fb::Gate);
        }
        if fb.is_none() && lc.status_path.as_deref() == Some(req.path) {
            fb = Some(Fb::Gate);
        }
        if let Some(kind) = fb {
            match kind {
                Fb::Gate => FB_GATE.fetch_add(1, Ordering::Relaxed),
                Fb::Miss => FB_MISS.fetch_add(1, Ordering::Relaxed),
            };
            return Some(ReplayIo::new(io, buf));
        }
        // 说明：h1 慢路径在 `snap.geoip.enabled` 时调用的 `admin_geoip::try_handle_public`
        // 是**恒 `None` 的 stub**（安全策略：GeoIP API 仅管理员可见；h2/h3 也从不调用）。
        // 因此快车道跳过它与 hyper 路径可观测行为完全一致；若将来它成为真实路由，
        // 必须在这里补同一判据（并在 h2/h3 同步）。

        // ── 缓存命中 + 1 次 lstat 复核 ──
        //
        // 连接级快速路径：同一路径重复请求（keep-alive 的常态）时直接用上一轮的条目，
        // 省掉全局缓存的锁 + 三次哈希查找。**语义与全局命中逐字相同**：TTL 用同一
        // `CACHE_TTL`（同一 `Entry::at`）、身份复核仍是每请求 1 次 `revalidate`（lstat），
        // 复核失败同样走 `drop_entry` + 重新解析；路径不同/过期/复核失败都回落到下面的
        // 全局查找。条目内容与原「全局命中」拿到的是同一个 `Arc<Entry>`。
        let mut entry = None;
        if let Some((p, e)) = last.take() {
            if p == req.path && !e.is_stale_at(t0) && revalidate(&e) {
                entry = Some(Arc::clone(&e));
                last = Some((p, e));
            }
        }
        if entry.is_none() {
            entry = lookup(&lc.root, hsts, req.path, t0);
            if let Some(e) = &entry {
                if !revalidate(e) {
                    drop_entry(&lc.root, hsts, req.path);
                    entry = None;
                }
            }
        }
        // ── 未命中：走一次完整静态解析（填充），能缓存就继续快车道，否则回退 ──
        if entry.is_none() && miss_memo.as_deref() != Some(req.path) {
            entry = fill_entry(&lc, &buf[..n], req.is_head, req.target, req.path).await;
            if entry.is_none() {
                miss_memo = Some(req.path.to_string());
            }
        }
        let Some(entry) = entry else {
            FB_MISS.fetch_add(1, Ordering::Relaxed);
            return Some(ReplayIo::new(io, buf));
        };
        // 记住本次命中；**仅在路径或条目变化时**重建（重复路径零分配）：
        // `to_string()` 每请求一次会是新的 malloc/free，那正好抵消这条捷径。
        let same_as_last =
            matches!(&last, Some((p, e)) if p == req.path && Arc::ptr_eq(e, &entry));
        if !same_as_last {
            last = Some((req.path.to_string(), Arc::clone(&entry)));
        }

        // ── 决定关闭语义（与 hyper 逐项对齐）──
        //
        // * 1.1：`keep_alive=false`（`Connection: close`）或 listener 配置换代（h1 同款：
        //   换代 ⇒ 本请求后关连接，让客户端重连拿到新配置）。
        // * 1.0：`keep_alive=true`（显式 `Connection: keep-alive`）时 hyper **恒不关**：
        //   它的 `fix_keep_alive` 只看**响应** head 的版本（应用响应默认 1.1）⇒ 会补
        //   `connection: keep-alive`，并且即使换代时 h1 的服务闭包往响应里插了
        //   `Connection: close`，hyper 的 `insert(keep-alive)` 也会把它覆盖掉 —— 实测
        //   1.0+KA 连接在配置换代后仍被复用。这里复刻同一结果（不关、用 head_10_ka）。
        //   1.0 未请求 keep-alive 时恒关（响应不带任何 Connection 头，同 hyper）。
        let close_after = if req.http_10 {
            !req.keep_alive
        } else {
            !req.keep_alive || live.listeners_generation() != gen0
        };
        let is_head = req.is_head;
        let http_10 = req.http_10;
        // `req` 借用 `buf`，下面 `buf.drain` 前必须把要用的字段取出来（keep_alive 现在
        // 在关闭语义里区分 1.0/1.1，不能只靠 `close_after`）。
        let keep_alive = req.keep_alive;
        path_buf.clear();
        path_buf.push_str(req.path);
        let method_str = if is_head { "HEAD" } else { "GET" };
        // 请求被完全理解并即将由本模块应答：从输入缓冲消费掉。
        buf.drain(..n);
        scan_from = 0;

        // ── 写响应：预编码头 + date + 空行 (+ body)；一次 write_all ──
        let head_bytes: &[u8] = if http_10 {
            if keep_alive {
                &entry.head_10_ka
            } else {
                &entry.head_10
            }
        } else if close_after {
            &entry.head_11_close
        } else {
            &entry.head_11
        };
        scratch.clear();
        scratch.extend_from_slice(head_bytes);
        append_date(&mut scratch);
        scratch.extend_from_slice(b"\r\n");
        if !is_head {
            scratch.extend_from_slice(&entry.body);
        }
        if io.write_all(&scratch).await.is_err() {
            return None;
        }
        if io.flush().await.is_err() {
            return None;
        }
        crate::server::telemetry::record_request();
        let log_prefix =
            log_prefix.get_or_insert_with(|| crate::server::access_log::ConnPrefix::new("h1", peer));
        crate::server::access_log::log_response_prefixed_with(
            &snap,
            log_prefix,
            method_str,
            &path_buf,
            200,
            Some(entry.body.len() as u64),
            t0.elapsed(),
            "static",
            access_override.as_ref(),
        );
        SERVED.fetch_add(1, Ordering::Relaxed);
        if close_after {
            let _ = io.shutdown().await;
            return None;
        }
    }
}

// ---------------------------------------------------------------------------
// 单测
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn head(s: &str) -> Vec<u8> {
        s.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn parses_plain_get_and_head() {
        for (raw, is_head, http_10) in [
            ("GET / HTTP/1.1\nHost: a.example\n\n", false, false),
            ("HEAD /x/y.html HTTP/1.1\nHost: a.example:8080\n\n", true, false),
            ("GET / HTTP/1.0\n\n", false, true),
            ("GET /a?b=c HTTP/1.1\nhost: 127.0.0.1\nConnection: keep-alive\n\n", false, false),
        ] {
            let b = head(raw);
            let p = parse_request(&b).expect(raw);
            assert_eq!(p.is_head, is_head, "{raw}");
            assert_eq!(p.http_10, http_10, "{raw}");
            assert!(p.keep_alive || http_10, "{raw}");
        }
        let b = head("GET /a?b=c HTTP/1.1\nHost: h\n\n");
        let p = parse_request(&b).unwrap();
        assert_eq!(p.path, "/a");
        assert_eq!(p.target, "/a?b=c");
    }

    #[test]
    fn rejects_shapes_we_do_not_understand() {
        for raw in [
            // 方法 / 版本
            "POST / HTTP/1.1\nHost: h\n\n",
            "get / HTTP/1.1\nHost: h\n\n",
            "GET / HTTP/9.9\nHost: h\n\n",
            "GET / HTTP/1.1\nHost: h\n", // 未收尾
            // 目标形状
            "GET http://h/ HTTP/1.1\nHost: h\n\n",
            "GET * HTTP/1.1\nHost: h\n\n",
            "GET /#f HTTP/1.1\nHost: h\n\n",
            "GET  / HTTP/1.1\nHost: h\n\n",
            // Host 规则
            "GET / HTTP/1.1\n\n",
            "GET / HTTP/1.1\nHost: h\nHost: h2\n\n",
            "GET / HTTP/1.1\nHost: a b\n\n",
            "GET / HTTP/1.1\nHost: ..\n\n",
            "GET / HTTP/1.0\nHost: h\nHost: h2\n\n",
            // body / 升级 / 条件 / hop-by-hop
            "GET / HTTP/1.1\nHost: h\nContent-Length: 0\n\n",
            "GET / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n",
            "GET / HTTP/1.1\nHost: h\nExpect: 100-continue\n\n",
            "GET / HTTP/1.1\nHost: h\nUpgrade: websocket\nConnection: Upgrade\n\n",
            "GET / HTTP/1.1\nHost: h\nRange: bytes=0-1\n\n",
            "GET / HTTP/1.1\nHost: h\nIf-None-Match: \"x\"\n\n",
            "GET / HTTP/1.1\nHost: h\nTE: trailers\n\n",
            // obs-fold / 畸形头
            "GET / HTTP/1.1\nHost: h\nX: 1\n  cont\n\n",
            "GET / HTTP/1.1\nHost: h\nBad Name: v\n\n",
            "GET / HTTP/1.1\nHost: h\nX: a\x01b\n\n",
        ] {
            let b = head(raw);
            assert!(parse_request(&b).is_none(), "必须回退 hyper: {raw:?}");
        }
    }

    /// 对抗清单（fastsec-wave10，逐条与真机 A/B 对拍一致）：**完全理解的形状**才返回
    /// `Some`，其余一律 `None`（回退 hyper）。这是「不许尽力解读」的单一判据表 ——
    /// 新增解析分支时先把形状加进这张表，再改实现。
    #[test]
    fn adversarial_shape_attribution() {
        fn ok(raw: &str) -> bool {
            parse_request(&head(raw)).is_some()
        }
        // ── 必须被理解（由快车道应答）──
        for raw in [
            "GET / HTTP/1.1\nHost: h\n\n",
            "HEAD / HTTP/1.1\nHost: h\n\n",
            "GET /a/b.html HTTP/1.1\nHost: h\n\n",
            "GET /a?b=c&d=%20 HTTP/1.1\nHost: h\n\n",
            "GET /?q HTTP/1.1\nHost: h\n\n",
            "GET //plain.txt HTTP/1.1\nHost: h\n\n",
            "GET ///plain.txt HTTP/1.1\nHost: h\n\n",
            "GET /a/./b HTTP/1.1\nHost: h\n\n",
            "GET / HTTP/1.0\n\n",              // 1.0 无需 Host
            "GET / HTTP/1.0\nHost: h\n\n",
            "GET / HTTP/1.0\nConnection: keep-alive\n\n",
            "GET / HTTP/1.0\nConnection: close\n\n",
            "GET / HTTP/1.1\nHost: [::1]:8080\n\n",
            "GET / HTTP/1.1\nHost: h.\n\n",
            "GET / HTTP/1.1\nHost: a_b\n\n",
            "GET / HTTP/1.1\nHost: h:8080\n\n",
            "GET / HTTP/1.1\nHost: h\nX_Y: v\n\n",
            "GET / HTTP/1.1\nHost: h\n1X: v\n\n",
            "GET / HTTP/1.1\nHost: h\nX:: v\n\n",
            "GET / HTTP/1.1\nHost: h\nConnection: close\n\n",
            "GET / HTTP/1.1\nHost: h\nConnection: keep-alive\n\n",
            "GET / HTTP/1.1\nHost: h\nConnection: a, CLOSE ,b\n\n",
            "GET / HTTP/1.0\nConnection: keep-alive\n\n",
            // 未知 token（含 `Upgrade` 但无 `Upgrade:` 头）：hyper 也只对 close/keep-alive
            // 感兴趣，实测两态逐字节一致 ⇒ 快车道照常接管。
            "GET / HTTP/1.1\nHost: h\nConnection: Upgrade\n\n",
            "GET / HTTP/1.1\nHost: h\nConnection: Foo\n\n",
            "GET / HTTP/1.1\nHost: h\nProxy-Connection: keep-alive\n\n",
        ] {
            assert!(ok(raw), "应当被理解（快车道应答）: {raw:?}");
        }
        // obs-text（原始字节 0x80-0xff）在头值里：httparse 接受，快车道同样接受。
        let mut raw = b"GET / HTTP/1.1\r\nHost: h\r\nX: a".to_vec();
        raw.push(0xff);
        raw.extend_from_slice(b"b\r\n\r\n");
        assert!(parse_request(&raw).is_some(), "obs-text 头值应当被理解");
        // 但 `Connection` 头里的 obs-text 例外：hyper 的 to_str() 会整条放弃 ⇒ 回退。
        let ctl_conn = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: \xff, close\r\n\r\n".to_vec();
        assert!(
            parse_request(&ctl_conn).is_none(),
            "Connection 头含原始 obs-text(0xff) 必须回退"
        );
        // 头行数：Host + 97 = 98 行（≤100）⇒ 理解；再加到 102 行 ⇒ 回退。
        let mut few = String::from("GET / HTTP/1.1\nHost: h\n");
        for i in 0..97 {
            few.push_str(&format!("X-{i}: v\n"));
        }
        few.push('\n');
        assert!(ok(&few), "98 行头应当被理解");
        let mut many = String::from("GET / HTTP/1.1\nHost: h\n");
        for i in 0..101 {
            many.push_str(&format!("X-{i}: v\n"));
        }
        many.push('\n');
        assert!(!ok(&many), "102 行头必须回退（MAX_HEADER_LINES=100）");
        // 目标 > MAX_TARGET（8KiB）⇒ 回退（由 hyper 决定 414/404）。
        let long = format!("GET /{} HTTP/1.1\nHost: h\n\n", "a".repeat(8193));
        assert!(parse_request(&head(&long)).is_none(), "超长目标必须回退");
        // ── 必须回退（任何歧义/未完全理解的形状）──
        for raw in [
            // NUL / 控制字符
            "GET /a\x00b HTTP/1.1\nHost: h\n\n",
            "GET / HTTP/1.1\nHost: h\nX: a\x00b\n\n",
            "GET / HTTP/1.1\nHost: h\nX\x00Y: v\n\n",
            "GET / HTTP/1.1\nHost: h\nX: a\x0bb\n\n",
            "GET / HTTP/1.1\nHost: h\nX: a\x0cb\n\n",
            "GET / HTTP/1.1\nHost: h\nX: a\x7fb\n\n",
            "GET / HTTP/1.1\nHost: h\nX: a\rb\n\n",
            // 请求行空白
            "GET\t/ HTTP/1.1\nHost: h\n\n",
            "GET /\tHTTP/1.1\nHost: h\n\n",
            "GET \t/ HTTP/1.1\nHost: h\n\n",
            "GET  / HTTP/1.1\nHost: h\n\n",
            "GET / HTTP/1.1 \nHost: h\n\n",
            " GET / HTTP/1.1\nHost: h\n\n",
            "GET / HTTP/1.1\t\nHost: h\n\n",
            "GET /\nHost: h\n\n",
            "GET /HTTP/1.1\nHost: h\n\n",
            // 目标形状
            "GET http://h/ HTTP/1.1\nHost: h\n\n",
            "GET https://h/ HTTP/1.1\nHost: h\n\n",
            "GET * HTTP/1.1\nHost: h\n\n",
            "GET plain.txt HTTP/1.1\nHost: h\n\n",
            "GET /plain.txt#frag HTTP/1.1\nHost: h\n\n",
            // 头名
            "GET / HTTP/1.1\nHost: h\n: v\n\n",
            "GET / HTTP/1.1\nHost: h\nX@Y: v\n\n",
            "GET / HTTP/1.1\nHost: h\nX/Y: v\n\n",
            "GET / HTTP/1.1\nHost: h\nX Y v\n\n",
            "GET / HTTP/1.1\nHost: h\nX : v\n\n",
            "GET / HTTP/1.1\nHost: h\nX\t: v\n\n",
            // Host
            "GET / HTTP/1.1\n\n",
            "GET / HTTP/1.1\nHost: \n\n",
            "GET / HTTP/1.1\nHost: a,b\n\n",
            "GET / HTTP/1.1\nHost: a/b\n\n",
            "GET / HTTP/1.1\nHost: a@b\n\n",
            "GET / HTTP/1.1\nHost: h:notaport\n\n",
            "GET / HTTP/1.1\nHost: h\nHOST: h\n\n",
            "GET / HTTP/1.0\nHost: a\nHost: b\n\n",
            // Connection 值里有 obs-text（≥0x80）：hyper 的 `to_str()` 失败 ⇒ 整条值等于
            // 「无 token」，与逐字节找 token 的结论相反 ⇒ 必须回退（真机 A/B 实测差异见
            // `.agents/1009/reports/fastsec-wave10.md` 缺陷 3）。`\u{80}` 在 UTF-8 下是
            // 0xC2 0x80（两个字节都 ≥0x80）；原始 0xFF 的字节级用例见下面的 `raw` 断言。
            "GET / HTTP/1.1\nHost: h\nConnection: \u{80}, close\n\n",
            "GET / HTTP/1.1\nHost: h\nConnection: close, \u{80}\n\n",
            "GET / HTTP/1.0\nConnection: \u{80}, keep-alive\n\n",
            // 方法 / 版本
            "POST / HTTP/1.1\nHost: h\nContent-Length: 0\n\n",
            "PUT / HTTP/1.1\nHost: h\nContent-Length: 0\n\n",
            "DELETE / HTTP/1.1\nHost: h\n\n",
            "OPTIONS * HTTP/1.1\nHost: h\n\n",
            "TRACE / HTTP/1.1\nHost: h\n\n",
            "get / HTTP/1.1\nHost: h\n\n",
            "head / HTTP/1.1\nHost: h\n\n",
            "GETX / HTTP/1.1\nHost: h\n\n",
            " / HTTP/1.1\nHost: h\n\n",
            "GET / HTTP/1.2\nHost: h\n\n",
            "GET / HTTP/0.9\nHost: h\n\n",
            "GET / http/1.1\nHost: h\n\n",
            // Content-Length：任何形式都不解读
            "GET / HTTP/1.1\nHost: h\nContent-Length: 0\n\n",
            "GET / HTTP/1.1\nHost: h\nContent-Length: +5\n\n",
            "GET / HTTP/1.1\nHost: h\nContent-Length: -5\n\n",
            "GET / HTTP/1.1\nHost: h\nContent-Length: 5 5\n\n",
            "GET / HTTP/1.1\nHost: h\nContent-Length: 0x5\n\n",
            "GET / HTTP/1.1\nHost: h\nContent-Length: 5\nContent-Length: 6\n\n",
            "GET / HTTP/1.1\nHost: h\nContent-Length: 5, 5\n\n",
            "GET / HTTP/1.1\nHost: h\nContent-Length: 18446744073709551615\n\n",
            // Transfer-Encoding / Trailer / TE
            "POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\n",
            "POST / HTTP/1.1\nHost: h\nTransfer-Encoding: CHUNKED\n\n",
            "POST / HTTP/1.1\nHost: h\nTransfer-Encoding: identity\n\n",
            "POST / HTTP/1.1\nHost: h\nTransfer-Encoding: gzip, chunked\n\n",
            "POST / HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\nContent-Length: 6\n\n",
            "POST / HTTP/1.1\nHost: h\nTrailer: X\n\n",
            "GET / HTTP/1.1\nHost: h\nTE: trailers\n\n",
            // Expect / Upgrade
            "POST / HTTP/1.1\nHost: h\nExpect: 100-continue\n\n",
            "GET / HTTP/1.1\nHost: h\nExpect: 100-continue\n\n",
            "GET / HTTP/1.1\nHost: h\nUpgrade: websocket\nConnection: Upgrade\n\n",
            "GET / HTTP/1.1\nHost: h\nUpgrade: h2c\n\n",
            // 注意：只有 `Connection: Upgrade` 而没有 `Upgrade:` 头**不是**升级请求
            // （hyper 的 wants_upgrade 只看 `Upgrade:` 头），实测两态一致 ⇒ 归入「理解」。
            // Range / 条件请求
            "GET / HTTP/1.1\nHost: h\nRange: bytes=0-1\n\n",
            "GET / HTTP/1.1\nHost: h\nIf-None-Match: \"x\"\n\n",
            "GET / HTTP/1.1\nHost: h\nIf-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\n\n",
            "GET / HTTP/1.1\nHost: h\nIf-Match: \"x\"\n\n",
            "GET / HTTP/1.1\nHost: h\nIf-Range: \"x\"\n\n",
            "GET / HTTP/1.1\nHost: h\nIf-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\n\n",
        ] {
            assert!(!ok(raw), "必须回退 hyper（不理解的形状）: {raw:?}");
        }
        // 目标 > MAX_TARGET（8KiB）：回退，由 hyper 决定 414/404
        let long = format!("GET /{} HTTP/1.1\nHost: h\n\n", "a".repeat(8193));
        assert!(!parse_request(&head(&long)).is_some());
        // 说明：`\n` 收尾的请求头根本到不了 parse_request —— `read_head`/`scan_head`
        // 在发现裸 LF 时就回退了（见 bare_lf_head_is_not_understood）。
    }

    #[test]
    fn connection_tokens_follow_hyper_assignment() {
        let b = head("GET / HTTP/1.1\nHost: h\nConnection: close\n\n");
        assert!(!parse_request(&b).unwrap().keep_alive);
        let b = head("GET / HTTP/1.1\nHost: h\nConnection: keep-alive\n\n");
        assert!(parse_request(&b).unwrap().keep_alive);
        // 多个 Connection 行逐行赋值（复刻 hyper role.rs 的 keep_alive 更新语义）
        let b = head("GET / HTTP/1.1\nHost: h\nConnection: close\nConnection: keep-alive\n\n");
        assert!(parse_request(&b).unwrap().keep_alive);
        let b = head("GET / HTTP/1.1\nHost: h\nConnection: a, CLOSE ,b\n\n");
        assert!(!parse_request(&b).unwrap().keep_alive);
        // 1.0：逐行赋值结果照用（默认 false；显式 keep-alive ⇒ true）。
        // hyper 实测：1.0+KA 保持连接并在响应头补 `connection: keep-alive`
        // （`fix_keep_alive` 检查的是响应 head 的版本 = 应用默认 1.1）。
        let b = head("GET / HTTP/1.0\n\n");
        assert!(!parse_request(&b).unwrap().keep_alive);
        let b = head("GET / HTTP/1.0\nConnection: keep-alive\n\n");
        assert!(parse_request(&b).unwrap().keep_alive);
        let b = head("GET / HTTP/1.0\nConnection: KEEP-ALIVE\n\n");
        assert!(parse_request(&b).unwrap().keep_alive);
        let b = head("GET / HTTP/1.0\nConnection: close\n\n");
        assert!(!parse_request(&b).unwrap().keep_alive);
        // 逐行：close 先、keep-alive 后 ⇒ 又打开（hyper 的赋值语义，勿"修"成恒关）
        let b = head("GET / HTTP/1.0\nConnection: close\nConnection: keep-alive\n\n");
        assert!(parse_request(&b).unwrap().keep_alive);
        // 单行 `keep-alive, close`：hyper 的 connection_keep_alive 只找 keep-alive token
        // （close 不参与该分支）⇒ 保持（A/B 实测一致，勿"修"成正交判据）。
        let b = head("GET / HTTP/1.0\nConnection: keep-alive, close\n\n");
        assert!(parse_request(&b).unwrap().keep_alive);
    }

    #[test]
    fn head_end_scan() {
        // scan_head 的三种结果逐条断言（枚举无 PartialEq，用 match）。
        let cases: [(&[u8], usize, Option<usize>); 5] = [
            (b"GET / HTTP/1.1\r\n\r\n", 0, Some(18)),
            (b"abc\r\n\r\ndef", 0, Some(7)),
            // from 会回退 3 字节（跨上一次扫描边界的结束符不能漏）⇒ 从 4 续扫命中的是**第一个**结束符。
            (b"abc\r\n\r\nx\r\n\r\n", 4, Some(7)),
            // 从第一个结束符之后起扫才是第二个（8..12，排他末尾 12）。
            (b"abc\r\n\r\nx\r\n\r\n", 8, Some(12)),
            (b"abc\r\n\r\nx\r\n\r\n", 12, None),
        ];
        for (buf, from, want) in cases {
            match (scan_head(buf, from), want) {
                (HeadScan::Complete(n), Some(w)) => assert_eq!(n, w, "{buf:?}"),
                (HeadScan::NeedMore, None) => {}
                (got, want) => {
                    let g = match got {
                        HeadScan::NeedMore => "NeedMore".to_string(),
                        HeadScan::Complete(n) => format!("Complete({n})"),
                        HeadScan::NotUnderstood => "NotUnderstood".to_string(),
                    };
                    panic!("scan_head({buf:?}, {from}) = {g}, want {want:?}");
                }
            }
        }
        assert!(matches!(
            scan_head(b"no end", 0),
            HeadScan::NeedMore
        ));
    }

    /// 裸 LF（`\n` 前不是 `\r`）必须被识别为「不理解的形状」，立刻回退 ——
    /// 否则 LF-only 请求（hyper 正常 200）在快车道上会挂到 30s 且一个字节都不发。
    #[test]
    fn bare_lf_head_is_not_understood() {
        for buf in [
            &b"GET / HTTP/1.1\nHost: h\n\n"[..],
            &b"GET / HTTP/1.1\r\nHost: h\n\n"[..],
            &b"GET / HTTP/1.1\r\nHost: h\r\n\n"[..],
            &b"\nGET / HTTP/1.1\r\nHost: h\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: h\r\nX: a\nb\r\n\r\n"[..],
        ] {
            assert!(
                matches!(scan_head(buf, 0), HeadScan::NotUnderstood),
                "裸 LF 必须回退: {buf:?}"
            );
        }
        // 前导 CRLF（RFC 9112 §2.2 允许的健壮性：请求行前可忽略空行）**不是**裸 LF，
        // 结束符仍要能找到（parse_request 会拒掉这种带前导空行的形状 ⇒ 回退 hyper）。
        assert!(matches!(
            scan_head(b"\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n", 0),
            HeadScan::Complete(29)
        ));
        // 正常形态不受影响。
        assert!(matches!(
            scan_head(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", 0),
            HeadScan::Complete(27)
        ));
        // 控制字符**不**提前回退（等结束符后由 parse_request 拒绝 / 交回 hyper）：
        // hyper 对这类前缀的报错时机取决于读边界，见 `scan_head` 内注释与
        // `.agents/1009/reports/fastsec-wave10.md`「未闭差异 D」。
        assert!(matches!(
            scan_head(b"GET\x00 / HTTP/1.1\r\n", 0),
            HeadScan::NeedMore
        ));
        assert!(matches!(
            scan_head(b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x01b\r\n\r\n", 0),
            HeadScan::Complete(35)
        ));
        // HT 与 CR/LF 是合法字节（OWS / 行结束），不能误判。
        assert!(matches!(
            scan_head(b"GET / HTTP/1.1\r\nHost: h\r\nX: \tv\t\r\n\r\n", 0),
            HeadScan::Complete(35)
        ));
    }

    /// 零分配的管理路径判据必须与 `access::is_admin_path` 逐项一致（同一张用例表，
    /// 含空串/纯斜杠/尾斜杠/段边界等边界）。
    #[test]
    fn admin_path_matches_access_impl() {
        let admins = ["/__admin", "/__admin/", "/", "", "//", "/a/b", "/a/b/", "/a//"];
        let paths = [
            "", "/", "//", "/__admin", "/__admin/", "/__admin/x", "/__adminx",
            "/__adminx/api/files", "/a", "/a/", "/a/b", "/a/b/", "/a/b/c", "/a/bc",
            "/ab/c", "/x", "/a//b",
        ];
        for a in admins {
            for p in paths {
                assert_eq!(
                    is_admin_path_fast(a, p),
                    crate::server::access::is_admin_path(a, p),
                    "admin={a:?} path={p:?}"
                );
            }
        }
    }

    #[test]
    fn etag_id_roundtrip() {
        let id = Id {
            len: 127,
            ino: 0x2a1,
            secs: 0x68f1,
            nanos: 123456,
        };
        let etag = format!(
            "\"{:x}-{:x}-{:x}-{:x}\"",
            id.len, id.secs, id.nanos, id.ino
        );
        assert_eq!(parse_etag_id(&etag), Some(id));
        assert_eq!(parse_etag_id("\"7f-1-2-3-4\""), None);
        assert_eq!(parse_etag_id("7f-1-2-3"), None);
        assert_eq!(parse_etag_id("\"zz-1-2-3\""), None);
    }

    #[test]
    fn candidate_rels_for_files_and_dirs() {
        assert_eq!(candidate_rels("/index.html"), vec!["index.html".to_string()]);
        assert_eq!(
            candidate_rels("/"),
            vec!["index.html".to_string(), "index.htm".to_string()]
        );
        assert_eq!(
            candidate_rels("/sub/"),
            vec!["sub/index.html".to_string(), "sub/index.htm".to_string()]
        );
        assert_eq!(candidate_rels("//a"), vec!["a".to_string()]);
    }

    // ── 端到端（tokio duplex）：真起一个进程内实例，验证线上字节 ──

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "crucible-h1fast-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("index.html"), b"hello-fastpath").unwrap();
            fs::write(root.join("plain.txt"), b"plain").unwrap();
            Self { root }
        }

        fn live(&self) -> (Arc<LiveConfig>, Arc<ListenerConfig>) {
            let toml = format!(
                "[access_log]\nenable = false\n[[listeners]]\naddress = \"127.0.0.1\"\nport = 1\nroot = \"{}\"\nhttp_versions = [\"h1\"]\n",
                self.root.display()
            );
            let cfg: crate::config::Config = ::toml::from_str(&toml).expect("cfg");
            let lc = Arc::new(cfg.listeners[0].clone());
            let live = Arc::new(LiveConfig::new(
                cfg,
                PathBuf::from("/tmp/crucible-h1fast-test.toml"),
            ));
            (live, lc)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// 用 duplex 起一条连接，发 `requests`，收全部响应字节直到对端关闭或读超时。
    async fn run(lc: &Arc<ListenerConfig>, live: &Arc<LiveConfig>, requests: &[&str]) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let live = Arc::clone(live);
        let lc = Arc::clone(lc);
        let task = tokio::spawn(async move {
            serve(server, live, lc, "127.0.0.1:12345".parse().unwrap(), 0).await
        });
        use tokio::io::AsyncWriteExt as _;
        for r in requests {
            client.write_all(head(r).as_slice()).await.unwrap();
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
                Ok(Err(_)) => break,
            }
        }
        task.await.unwrap();
        out
    }

    fn count_headers(resp: &[u8], name: &str) -> usize {
        let s = String::from_utf8_lossy(resp);
        s.to_ascii_lowercase().matches(&format!("\n{name}:")).count()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serves_keepalive_get_and_head_from_cache() {
        let fx = Fixture::new("ka");
        let (live, lc) = fx.live();
        let out = run(
            &lc,
            &live,
            &[
                "GET / HTTP/1.1\nHost: h\n\n",
                "GET /index.html HTTP/1.1\nHost: h\n\n",
                "HEAD / HTTP/1.1\nHost: h\n\n",
                "GET /plain.txt HTTP/1.1\nHost: h\nConnection: close\n\n",
            ],
        )
        .await;
        let s = String::from_utf8_lossy(&out);
        assert_eq!(s.matches("HTTP/1.1 200 OK").count(), 4, "{s}");
        assert_eq!(s.matches("hello-fastpath").count(), 2, "{s}"); // GET / 与 GET /index.html
        assert_eq!(s.matches("hello-fastpath").count(), 2);
        assert!(out.windows(8).any(|w| w == b"hello-fa")); // HEAD 不发 body，但 GET 发
        // HEAD 响应必须有 content-length: 14 但没有 body
        assert!(s.contains("content-length: 14"), "{s}");
        // Connection: close 只在最后一个响应上
        assert_eq!(count_headers(&out, "connection"), 1, "{s}");
        assert!(s.contains("connection: close"), "{s}");
        // Date 每个响应都有（hyper 自动补）
        assert_eq!(count_headers(&out, "date"), 4, "{s}");
        assert!(out.ends_with(b"plain"), "最后响应带 body: {s}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http10_closes_and_uses_10_status_line() {
        let fx = Fixture::new("h10");
        let (live, lc) = fx.live();
        let out = run(&lc, &live, &["GET / HTTP/1.0\n\n"]).await;
        let s = String::from_utf8_lossy(&out);
        assert!(s.starts_with("HTTP/1.0 200 OK"), "{s}");
        assert!(!s.to_ascii_lowercase().contains("connection:"), "{s}");
        assert!(s.ends_with("hello-fastpath"), "{s}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipelined_requests_answered_in_order() {
        let fx = Fixture::new("pipe");
        let (live, lc) = fx.live();
        let out = run(
            &lc,
            &live,
            &[
                "GET /plain.txt HTTP/1.1\nHost: h\n\nGET /index.html HTTP/1.1\nHost: h\n\n",
            ],
        )
        .await;
        let s = String::from_utf8_lossy(&out);
        let a = s.find("plain").unwrap();
        let b = s.find("hello-fastpath").unwrap();
        assert!(a < b, "响应必须按请求顺序: {s}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fallback_returns_untouched_bytes() {
        let fx = Fixture::new("fb");
        let (live, lc) = fx.live();
        let (mut client, server) = tokio::io::duplex(4096);
        let live2 = Arc::clone(&live);
        let lc2 = Arc::clone(&lc);
        let task = tokio::spawn(async move {
            let replay = serve(server, live2, lc2, "127.0.0.1:1".parse().unwrap(), 0).await;
            // 回退必须原样带回完整请求字节（一个都不能少）
            let mut replay = replay.expect("必须回退");
            let mut got = Vec::new();
            use tokio::io::AsyncReadExt as _;
            // 只读 prefix 部分即可（内部 pos 前进到 prefix 末尾）
            let n = replay.prefix.len();
            let mut tmp = vec![0u8; n];
            replay.read_exact(&mut tmp).await.unwrap();
            got.extend_from_slice(&tmp);
            got
        });
        use tokio::io::AsyncWriteExt as _;
        // wire 上是 CRLF（head() 会把 \n 替换掉）；比较对象必须同为 CRLF，否则是测试自己写错。
        let wire = head("POST /x HTTP/1.1\nHost: h\nContent-Length: 3\n\nabc");
        client.write_all(wire.as_slice()).await.unwrap();
        let got = task.await.unwrap();
        assert_eq!(
            std::str::from_utf8(&got).unwrap(),
            std::str::from_utf8(&wire).unwrap(),
            "回退字节必须原样"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_path_falls_back() {
        let fx = Fixture::new("miss");
        let (live, lc) = fx.live();
        let out = run(&lc, &live, &["GET /nope HTTP/1.1\nHost: h\n\n"]).await;
        assert!(out.is_empty(), "404 由 hyper 回，快车道只回退: {out:?}");
    }

    /// 回归（fastsec-wave10 缺陷 1）：HTTP/1.0 + `Connection: keep-alive`。
    ///
    /// hyper 实测**保持连接**、响应带 `connection: keep-alive`、pipelined 的第二请求
    /// 照常服务；旧实现把它当「1.0 恒关」，于是第一个响应缺 `connection: keep-alive`
    /// 且连接被关 —— 第二个请求被整条丢弃（A/B 对拍差异）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http10_keepalive_stays_open_with_header() {
        let fx = Fixture::new("h10ka");
        let (live, lc) = fx.live();
        let out = run(
            &lc,
            &live,
            &[
                "GET /plain.txt HTTP/1.0\nConnection: keep-alive\n\n",
                "GET /plain.txt HTTP/1.0\nConnection: close\n\n",
            ],
        )
        .await;
        let s = String::from_utf8_lossy(&out);
        assert_eq!(s.matches("HTTP/1.0 200 OK").count(), 2, "{s}");
        assert_eq!(count_headers(&out, "connection"), 1, "{s}");
        assert!(s.contains("connection: keep-alive\r\n"), "{s}");
        // `connection: keep-alive` 之后必须紧跟 date（与 hyper 的头发射顺序一致）
        assert!(s.contains("connection: keep-alive\r\ndate: "), "{s}");
        // 第二个请求（Connection: close）也必须被服务 ⇒ 连接确实没被提前关掉
        // （4 = `text/plain` ×2 + body `plain` ×2；用「头结束符后紧跟 body」来数更准）
        assert_eq!(s.matches("\r\n\r\nplain").count(), 2, "{s}");
    }

    /// 回归（fastsec-wave10 缺陷 2）：LF-only 请求头（`\n\n` 收尾）。
    ///
    /// hyper/httparse 把裸 LF 当行结束（实测 `GET / HTTP/1.1\nHost: h\n\n` 正常 200），
    /// 本模块只认 `\r\n\r\n` ⇒ 必须在看到裸 LF 时**立刻**把已读字节原样交回 hyper，
    /// 而不是挂到 30s 头读超时（那样客户端一个字节都收不到）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_lf_head_falls_back_with_all_bytes() {
        let fx = Fixture::new("lf");
        let (live, lc) = fx.live();
        let (mut client, server) = tokio::io::duplex(4096);
        let live2 = Arc::clone(&live);
        let lc2 = Arc::clone(&lc);
        let task = tokio::spawn(async move {
            let replay = serve(server, live2, lc2, "127.0.0.1:1".parse().unwrap(), 0).await;
            replay.expect("裸 LF 必须回退").prefix
        });
        use tokio::io::AsyncWriteExt as _;
        let wire = b"GET /plain.txt HTTP/1.1\nHost: h\n\n".to_vec();
        client.write_all(&wire).await.unwrap();
        let got = task.await.unwrap();
        assert_eq!(got, wire, "回退字节必须原样（一个都不能少）");
    }
}
