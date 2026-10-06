//! Static file serving, autoindex, small-file cache, Range support.

use crate::config::{Config, FileOpenMode, ListenerConfig};
use crate::server::h1::{empty, full, BoxBody};
use anyhow::{bail, Result};
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Cap for non-streaming full-file reads (DoS guard). Larger files must use Range or fail.
const MAX_FULL_READ: u64 = 16 * 1024 * 1024;
/// Cap for a single Range response body.
const MAX_RANGE_BYTES: u64 = 32 * 1024 * 1024;

/// 大文件响应的「流式来源」标记：响应体为空，真正的内容由各协议的发送路径分块从磁盘读
/// （h1 → [`crate::server::h1::stream_file`]；h2/h3 → 各自的 DATA 帧循环）。
///
/// 为什么需要它：`Response<BoxBody>` / `Response<Bytes>` 都把 body 放在内存里，于是
/// >[`MAX_FULL_READ`] 的文件只能回 413（浏览器点一个 20MB 的文件直接报错）。
/// 用「空 body + 附件里的来源描述」表达流式，改动面最小：静态层不需要认识三个协议，
/// 各协议的发送路径各加一小段循环即可。
#[derive(Clone, Debug)]
pub struct FileSource {
    pub path: PathBuf,
    pub start: u64,
    pub len: u64,
}

/// 流式发送时每个 DATA 帧的字节数（64KiB：够大以避免帧开销，够小以保持背压）。
pub const STREAM_CHUNK: usize = 64 * 1024;

use std::time::SystemTime;

const SMALL_FILE_MAX: u64 = 256 * 1024;
const CACHE_CAP: usize = 256;

struct CacheEntry {
    id: FileId,
    data: Bytes,
    content_type: String,
}

static SMALL_CACHE: Lazy<Mutex<HashMap<PathBuf, CacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// 解析结果缓存：`(root, 解码后的相对路径) → 已验证的 canonical 绝对路径`。
///
/// 为什么需要：`resolve_path` 每个请求都要 `realpath`（root 一次 + 目标一次，未命中的
/// 路径还要逐级向上 `exists()`），而 realpath 内部是**逐段 lstat/readlink**。
/// gdb 采样（10 次采样、wrk -c32）显示 `realpath`/`stat`/`resolve_path` 合计占了
/// 请求路径上的最大一块 CPU —— 每请求约 5~10 个 syscall 只为了把同一个路径
/// 反复验证一遍。
///
/// 安全性：只有**通过 containment 校验**的结果才会入缓存，因此缓存永远不可能返回
/// root 之外的真实路径；条目带 TTL（默认 2s）且有容量上限，符号链接被改动后最坏
/// 情况下多服务 2 秒「曾经验证过的真实路径」（不可能是新指向的外部文件）。
/// 命中后调用方仍会 `fs::metadata` 取 mtime/etag，文件被删会正常 404。
struct CanonEntry {
    canon: PathBuf,
    at: std::time::Instant,
}

static CANON_CACHE: Lazy<Mutex<HashMap<(PathBuf, String), CanonEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 解析缓存 TTL 与容量（超过容量时整表清空，代价可忽略）。
const CANON_TTL: std::time::Duration = std::time::Duration::from_secs(2);
const CANON_CAP: usize = 4096;



fn read_file_capped(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::metadata(path)?;
    if meta.len() > MAX_FULL_READ {
        bail!(
            "file too large for full read ({} > {MAX_FULL_READ}); use Range",
            meta.len()
        );
    }
    Ok(fs::read(path)?)
}

/// 大文件（>SMALL_FILE_MAX）整读走 `spawn_blocking`，别在 async worker 上同步读盘。
///
/// 为什么：`fs::read` 最大 16MiB，而 bench/生产形态只给 2 个 tokio worker；一次冷读
/// 就能让整个进程（三协议共用 runtime）停止调度数十毫秒。小文件仍走 [`read_cached`]
/// 的同步读（≤256KiB，通常已在页缓存里，且要把锁保持在 await 之外）。
async fn read_file_async(path: PathBuf) -> Result<Bytes> {
    tokio::task::spawn_blocking(move || read_file_capped(&path).map(Bytes::from))
        .await
        .map_err(|e| anyhow::anyhow!("blocking read task failed: {e}"))?
}

/// 目录请求缺少尾斜杠 → 301 Location（保留 query）。
///
/// 为什么必须有：`/dir` 与 `/dir/` 在浏览器里是**不同的基地址**。直接把目录索引
/// （index.html）或 autoindex 列表回给 `/dir` 时，页面里的相对链接（`./a.css`、`a.png`）
/// 会以 `/` 为基解析成 `/a.css` → 全部 404（典型症状：子目录页面样式/图片全丢）。
/// 301 到带尾斜杠的同一路径后相对链接才正确；query 原样保留（否则带参数的目录页丢参数）。
///
/// 语义与 nginx / h2o 的 `file.dir` 一致：**只要解析出来是目录**且路径不以 `/` 结尾就跳转
/// （无论该目录最后会不会回 index.html 或目录列表）。返回 `None` 表示无需跳转。
fn dir_redirect_location(uri: &http::Uri) -> Option<http::HeaderValue> {
    let path = uri.path();
    if path.ends_with('/') {
        return None;
    }
    let mut target = String::with_capacity(path.len() + 16);
    target.push_str(path);
    target.push('/');
    if let Some(q) = uri.query() {
        target.push('?');
        target.push_str(q);
    }
    http::HeaderValue::from_str(&target).ok()
}

pub async fn serve(req: &Request<Incoming>, lc: &ListenerConfig) -> Result<Response<BoxBody>> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        // RFC 9110 §15.5.6：405 **必须**带 Allow，告诉客户端该资源支持哪些方法
        // （此前只回状态码 + 文案，自动化客户端无从得知）。
        // 头必须与 h2/h3 的 `serve_simple` 405 **逐字一致**：此前 h1 这条漏了
        // `Content-Type`，于是同一个 `POST /index.html` 在 h1 上是「无 Content-Type」、
        // 在 h2/h3 上是 `text/plain; charset=utf-8` —— 跨协议头不一致（规格 §4/§16 要求
        // 同一资源在任何协议下行为一致，缓存/CDN/自动化客户端会据此分叉）。
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full("method not allowed"))
            .unwrap());
    }
    let path = req.uri().path();
    let fs_path = resolve_path(&lc.root, path)?;
    let meta = fs::metadata(&fs_path)?;
    if meta.is_dir() {
        // 目录缺尾斜杠 → 301 补上（保留 query）。必须在 index/autoindex 之前：
        // 否则 `/dir` 会直接回 index.html，页面里的相对链接以 `/` 为基解析 → 全 404。
        if let Some(loc) = dir_redirect_location(req.uri()) {
            return Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(header::LOCATION, loc)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(full("<h1>301 Moved Permanently</h1>"))
                .unwrap());
        }
        // 目录索引优先（h2o/nginx 默认）：docroot 带 index.html 时根路径必须返回它，
        // 而不是目录列表或 404。索引文件走与普通文件**完全相同**的闸门
        // （file_open/engine_owns/app_private_path），不放宽任何安全判定。
        if let Some((idx, idx_meta)) = directory_index(&fs_path, &lc.root) {
            let mode = lc.file_open_mode(path);
            if !engine_owns(lc, path, mode) && !app_private_path(lc, path, mode) {
                return serve_file(req, &idx, &idx_meta, mode).await;
            }
        }
        if lc.autoindex.allows(path) {
            return Ok(autoindex(&fs_path, path, lc.autoindex.enabled && lc.autoindex.enable_upload)?);
        }
        bail!("directory");
    }
    // 只服务**普通文件**：docroot 里若存在 FIFO / unix socket / 设备节点，
    // 对它 open/read 会**永久阻塞**，白白占住一个阻塞池 worker（连续几个就能把池抽干）。
    // （`resolve_path` 的 canonicalize 只保证在 root 内，不保证类型。）
    if !meta.is_file() {
        bail!("not a regular file");
    }
    let mode = lc.file_open_mode(path);
    // §16.2：static 层不得替引擎把「应执行的脚本」当普通文件吐出去（见 engine_owns）。
    if engine_owns(lc, path, mode) {
        bail!("path is owned by an app engine");
    }
    // 应用 docroot 里的运维/私密文件（部署脚本、配置、密钥、库文件）也不静态服务，
    // 见 app_private_path 的说明。
    if app_private_path(lc, path, mode) {
        bail!("app docroot private file is not served");
    }
    serve_file(req, &fs_path, &meta, mode).await
}

/// §16.2 `app_owns_path`：auto/execute 下命中的应用引擎路径不得当纯静态/下载返回。
///
/// h1/h2/h3 的分发都用**原始** URL 路径去问 `apps::would_handle`，而 static 层
/// 却按「percent-decode + 折叠 `.`/空段」后的路径解析文件。两者不一致时
/// （`/./php/x.php`、`//php/x.php`、`/php/x.ph%70`、`/php/x%2Ephp`）引擎匹配不上、
/// 静态层却解析到同一个文件，于是 .php/.jsp 源码被原样吐出（脚本源码泄露：
/// 数据库口令、密钥等全在里面）。这里用与 file_open 键同一套归一化再问一次引擎。
///
/// preview/download 是管理员显式指定的「静态展示/下载」，优先级本就高于引擎（§16.2），
/// 因此不算引擎所有。
fn engine_owns(lc: &ListenerConfig, url_path: &str, mode: FileOpenMode) -> bool {
    if matches!(mode, FileOpenMode::Preview | FileOpenMode::Download) {
        return false;
    }
    match normalize_url_path(url_path) {
        Some(normalized) => {
            crate::server::apps::would_handle(lc, &normalized)
                // 引擎被 `enabled = false` 关掉时 `would_handle` 为 false，但该路径下的脚本/
                // 源码**仍然不能被当静态文件服务** —— 否则「临时停掉 php 引擎」等于把
                // `index.php` 的源码（含口令）公开下载。判据见 apps::route_owns_path。
                || crate::server::apps::route_owns_path(lc, &normalized)
        }
        // 归一化失败（含 `..` 等，resolve_path 本已拒绝）：fail-closed。
        None => true,
    }
}

/// 应用 docroot 内的「运维/私密文件」不得静态服务。
///
/// 背景（实测基线）：`GET /php/init.sh` → **200**（`application/x-sh`，部署脚本原文）。
/// 引擎只「拥有」自己声明的扩展名（`/php` 是 `["php", ""]`），`init.sh` 既不是 php、
/// 也不是隐藏文件 ⇒ 静态层照常服务。同类还有 `*.sql`/`*.ini`/`*.log`/`*.pem`/`Makefile`/
/// `Cargo.toml` 等 —— 它们都是「放在 docroot 里方便引擎读」的东西，而不是给公网下载的。
///
/// 判据：**落在应用路由前缀下** + **引擎不拥有该文件** + 命中私密扩展名/文件名。
/// 只在这个范围内拒绝是有意的：站点自己的 `backup.sql`（不在应用目录里）仍可正常分享，
/// 而应用目录里的密钥/脚本不该被顺手端出去。`file_open = preview/download` 是显式的
/// 「我就是要暴露它」，因此优先级更高（与本文件的 engine_owns 同一取向）。
fn app_private_path(lc: &ListenerConfig, url_path: &str, mode: FileOpenMode) -> bool {
    if matches!(mode, FileOpenMode::Preview | FileOpenMode::Download) {
        return false;
    }
    let Some(normalized) = normalize_url_path(url_path) else {
        return true; // 归一化失败 → fail-closed（resolve_path 本来也会拒）
    };
    if !crate::server::apps::under_app_prefix(lc, &normalized) {
        return false;
    }
    if crate::server::apps::would_handle(lc, &normalized) {
        return false; // 引擎拥有它 → 交给引擎（该执行执行、该 404 404）
    }
    let name = normalized.rsplit('/').next().unwrap_or("");
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    APP_PRIVATE_EXTS.iter().any(|e| *e == ext)
        || APP_PRIVATE_NAMES.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// 应用 docroot 里「不给公网」的扩展名（凭据/脚本/配置/库/备份/私钥）。
const APP_PRIVATE_EXTS: &[&str] = &[
    // 脚本（引擎不拥有它们时也没有理由对外）
    "sh", "bash", "zsh", "ksh", "csh", "tcsh", "fish", "ps1", "psm1",
    // 配置 / 凭据 / 密钥
    "ini", "cfg", "conf", "cnf", "env", "toml", "lock", "pem", "key", "crt", "cer", "p12",
    "pfx", "jks", "keystore", "htpasswd", "netrc",
    // 数据 / 库 / 备份 / 日志
    "sql", "sqlite", "sqlite3", "db", "db3", "mdb", "dump", "bak", "backup", "orig", "old",
    "log", "swp", "swn", "pid", "sock",
];

/// 应用 docroot 里「不给公网」的具体文件名（没有扩展名可判的）。
const APP_PRIVATE_NAMES: &[&str] = &[
    "Makefile", "makefile", "GNUmakefile", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "passwd", "shadow",
    "authorized_keys", "known_hosts",
];

/// 与 `config::normalize_path_key` / [`resolve_path`] 同一套 URL 路径归一化：
/// percent-decode + 丢弃空段与 `.` 段；含 `..` 或 `\` 段返回 `None`。
fn normalize_url_path(p: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(p).decode_utf8_lossy();
    let mut parts: Vec<&str> = Vec::new();
    for seg in decoded.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." => return None,
            s => parts.push(s),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

// ---------------------------------------------------------------------------
// 条件请求（RFC 9110 §13）：ETag / Last-Modified / If-Match /
// If-Unmodified-Since / If-None-Match / If-Modified-Since / If-Range
// ---------------------------------------------------------------------------

/// 文件 inode（Unix）；非 Unix 平台返回 0（该项目主目标是 OpenBSD）。
/// 用于把「原子替换」识别成新表示：`rename` 后 inode 必变（实测确认）。
#[cfg(unix)]
fn file_ino(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}
#[cfg(not(unix))]
fn file_ino(_meta: &fs::Metadata) -> u64 {
    0
}

/// 文件「身份指纹」：(长度, inode, mtime)。小文件缓存与 ETag 都用它。
///
/// 为什么不能只看 mtime：本机（WSL ext4 与 OpenBSD）的文件时间戳走**粗粒度时钟**
/// （jiffy），实测同一毫秒内的两次写盘得到**完全相同**的 `mtime_ns` —— 于是
/// 「同一 tick 内的等长改写」在只比 mtime 时会被误判成「没变」，缓存与条件请求
/// 都会把**旧内容**当成当前表示。inode 能把**原子替换**（rename：部署脚本
/// `sed -i`/`cp`、以及本项目的上传 commit 都是这个形态）区分开。
///
/// 诚实边界：**同 inode 原地改写 + 同长度 + 同 tick** 仍然分辨不出（要彻底解决
/// 只能读内容算哈希，代价与收益不成比例）。这条边界写在这里而不是假装不存在。
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileId {
    len: u64,
    ino: u64,
    mtime: SystemTime,
}

fn file_id(meta: &fs::Metadata) -> FileId {
    FileId {
        len: meta.len(),
        ino: file_ino(meta),
        mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
    }
}

/// 当前表示的验证器：`(ETag, 截断到秒的 mtime)`。
///
/// ETag 取 `"{len:x}-{mtime_secs:x}-{mtime_nanos:x}-{ino:x}"`（长度 + mtime + inode）。
///
/// * `mtime_nanos` + `ino` 都是为了识别「文件被换掉了」：只到秒的 `{len}-{secs}`
///   对同一秒内的**等长改写**会生成完全相同的 ETag，于是 `If-None-Match` 错误回 304、
///   `If-Range` 错误放行旧偏移的 Range —— 客户端拿到旧内容。上传的原子 rename、
///   部署脚本的 `sed -i` 都属于这类（可复现：同目录 `rename` 覆盖同长度文件）。
///   时间戳粒度不足时（粗粒度时钟），inode 仍然能兜住原子替换这条主流路径。
/// * `Last-Modified` / `If-Modified-Since` / `If-Range`(日期形式) 仍用**秒级**截断：
///   HTTP 日期只有秒精度，不截断会把同一秒内的请求判成「已修改」，条件请求永远拿不到 304。
///
/// **诚实边界**：这仍是*弱*验证器语义（同 inode 原地改写 + 同长度 + 同 tick 识别不出），
/// 按业界惯例不加 `W/` 前缀。真正强验证器需内容哈希（每请求全量读文件，代价与收益不成比例）。
fn validators(meta: &fs::Metadata) -> (String, Option<SystemTime>) {
    let mtime_full = meta.modified().ok();
    let mtime = mtime_full.map(trunc_to_secs);
    let (secs, nanos) = mtime_full
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0));
    (
        format!(
            "\"{:x}-{:x}-{:x}-{:x}\"",
            meta.len(),
            secs,
            nanos,
            file_ino(meta)
        ),
        mtime,
    )
}

fn trunc_to_secs(t: SystemTime) -> SystemTime {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(d.as_secs()),
        // 早于 epoch（不该出现，但别 panic）：原样返回
        Err(_) => t,
    }
}

/// ETag 列表匹配（RFC 9110 §8.8.3.2）：`*` 匹配任何现有表示；逗号分隔列表逐个比；
/// `*` 之外的列表项必须**整体**相等（含引号）。
///
/// `strong = true`（`If-Match`）按**强比较**：任一方带 `W/` 弱标记即不匹配
/// （RFC 9110 §13.1.1「If-Match 用强比较，弱验证器永不匹配」）；
/// `strong = false`（`If-None-Match`）按弱比较：双方任一为弱即按相等处理。
fn etag_list_matches(header_value: &str, etag: &str, strong: bool) -> bool {
    let v = header_value.trim();
    if v == "*" {
        return true;
    }
    let etag_weak = etag.trim().starts_with("W/");
    let want = etag.trim().trim_start_matches("W/");
    v.split(',').any(|c| {
        let c = c.trim();
        if c.is_empty() {
            return false;
        }
        let cand = c.trim_start_matches("W/");
        // 强比较下任一方是弱验证器就不算匹配
        if strong && (c.starts_with("W/") || etag_weak) {
            return false;
        }
        cand == want
    })
}

/// 前置条件求值结果（RFC 9110 §13.2.2 的求值顺序）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cond {
    Proceed,
    NotModified,
    PreconditionFailed,
}

/// 按 RFC 9110 §13.2.2 的顺序求值：If-Match → If-Unmodified-Since →
/// If-None-Match → If-Modified-Since。`method_allows_304`：GET/HEAD 才有 304 语义
/// （其它方法命中 If-None-Match 应回 412；本项目静态层只服务 GET/HEAD，传 true）。
fn eval_conditions(
    headers: &http::HeaderMap,
    etag: &str,
    mtime: Option<SystemTime>,
    method_allows_304: bool,
) -> Cond {
    // 1) If-Match：不匹配 → 412（强比较：弱验证器永不匹配，RFC 9110 §13.1.1）
    if let Some(v) = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()) {
        if !etag_list_matches(v, etag, true) {
            return Cond::PreconditionFailed;
        }
    } else if let Some(v) = headers
        .get(header::IF_UNMODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
    {
        // 2) If-Unmodified-Since（仅在无 If-Match 时求值）：已修改 → 412
        if let (Some(m), Ok(t)) = (mtime, httpdate::parse_http_date(v)) {
            if m > t {
                return Cond::PreconditionFailed;
            }
        }
    }
    // 3) If-None-Match：命中 → 304（GET/HEAD）或 412（其它方法）。**弱比较**
    //（RFC 9110 §13.1.2：与 If-Match 相反，这里弱验证器也算匹配）。
    if let Some(v) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if etag_list_matches(v, etag, false) {
            return if method_allows_304 {
                Cond::NotModified
            } else {
                Cond::PreconditionFailed
            };
        }
    } else if method_allows_304 {
        // 4) If-Modified-Since（仅在无 If-None-Match 时求值）：未修改 → 304
        if let Some(v) = headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
        {
            if let (Some(m), Ok(t)) = (mtime, httpdate::parse_http_date(v)) {
                if m <= t {
                    return Cond::NotModified;
                }
            }
        }
    }
    Cond::Proceed
}

/// `If-Range`（RFC 9110 §13.1.5）：给了验证器但与当前表示不符（含无法解析、含 `W/`
/// 弱标记 —— 强比较不成立）→ 必须**忽略 Range 回 200 全量**。返回 true 表示 Range 可用。
///
/// entity-tag 形式按**强比较**逐字节相等（§13.1.5「using the strong comparison
/// function」）；日期形式必须与本表示的 `Last-Modified`（秒精度，见 [`validators`]）
/// **精确相等** —— RFC 的两条判据是「日期是强验证器」+「与 Last-Modified 完全一致」，
/// 宽松的 `mtime <= date` 会让时钟偏快的客户端用一个「未来日期」蒙过校验，拿到新文件的
/// 旧偏移片段（内容错乱）。日期无法解析/表示没有 mtime → 条件为假（忽略 Range）。
fn if_range_allows(headers: &http::HeaderMap, etag: &str, mtime: Option<SystemTime>) -> bool {
    let Some(raw) = headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let v = raw.trim();
    if v.starts_with("W/") {
        // 弱验证器不能用于 If-Range（强比较），保守忽略 Range
        return false;
    }
    if v.starts_with('"') {
        return v == etag.trim();
    }
    match httpdate::parse_http_date(v) {
        // 只有与 Last-Modified 完全一致才算未修改（RFC 9110 §13.1.5 第 2 步）
        Ok(t) => match mtime {
            Some(m) => trunc_to_secs(t) == m,
            None => false,
        },
        // 既不是 entity-tag 也不是合法日期：无法匹配 → 忽略 Range
        Err(_) => false,
    }
}

/// HEAD 请求 + `Range`：按 RFC 9110 §9.3.2/§14.2 返回与 GET **相同**的状态与
/// `Content-Range`（206 / 416），但不读一个字节的正文。
///
/// 为什么不能在 Range 之前就短路回 200：`curl -I -r 0-9` 这类客户端靠 206 +
/// `Content-Range` 判断服务端是否支持区间，回 200 会让它们认为「不支持续传」；
/// 而此前为了避免 32MiB 的读放大，HEAD 被放在了 Range 判定之前。
/// 这里改为「只算区间、不读数据」：既满足协议语义，也没有任何读放大。
/// HEAD 版的 Range 响应（不读盘）：按 GET 会返回的状态/头作答。
///
/// 多段时必须报 `multipart/byteranges` 的 `Content-Type` 与**精确**的 `Content-Length`
/// ——那个长度由 [`multipart_plan`] 的排版算出来，不需要读任何数据。
fn head_range_response(
    path: &Path,
    len: u64,
    range: &str,
    ct: &str,
    disposition: Option<&str>,
    etag: &str,
    mtime: Option<SystemTime>,
) -> Option<Response<BoxBody>> {
    match head_range_outcome(len, range, ct) {
        RangeOutcome::Ignore => None,
        RangeOutcome::Unsatisfiable => Some(add_validators(
            Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                // RFC 9110 §14.4：416 必须带 `Content-Range: bytes */<length>`
                .header(header::CONTENT_RANGE, format!("bytes */{len}"))
                .body(empty())
                .unwrap(),
            etag,
            mtime,
        )),
        RangeOutcome::Single { start, end, .. } => {
            let mut b = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                .header(header::CONTENT_LENGTH, end - start + 1)
                .header(header::ACCEPT_RANGES, "bytes");
            if let Some(d) = disposition {
                b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
                b = b.header("x-content-type-options", "nosniff");
            }
            Some(add_validators(b.body(empty()).unwrap(), etag, mtime))
        }
        RangeOutcome::Multi {
            content_type,
            content_length,
            ..
        } => {
            // 与 GET 的多段响应同头（顶层无 Content-Range）。长度由 head_range_outcome
            // 用 multipart 排版算出来（不需要读数据），这里直接用。
            let mut b = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, content_length)
                .header(header::ACCEPT_RANGES, "bytes");
            if let Some(d) = disposition {
                b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
                b = b.header("x-content-type-options", "nosniff");
            }
            Some(add_validators(b.body(empty()).unwrap(), etag, mtime))
        }
    }
}

/// 给响应补上验证器头（200/206/304 都要带，客户端靠它做条件请求）。
fn with_validators(
    mut b: http::response::Builder,
    etag: &str,
    mtime: Option<SystemTime>,
) -> http::response::Builder {
    b = b.header(header::ETAG, etag);
    if let Some(m) = mtime {
        b = b.header(header::LAST_MODIFIED, httpdate::fmt_http_date(m));
    }
    b
}

pub async fn serve_simple<T>(req: &Request<T>, lc: &ListenerConfig) -> Result<Response<Bytes>> {
    // 与 h1 的 static_files::serve 对齐：非 GET/HEAD 一律 405。
    // 此前 serve_simple 根本不看方法，于是 h2/h3 上 `POST/PUT/DELETE /index.html`
    // 会拿到 200 + 文件正文（同一 URL 在 h1 上是 405）——行为随协议而变。
    let method = req.method();
    if method != Method::GET && method != Method::HEAD {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Bytes::from_static(b"method not allowed"))
            .unwrap());
    }
    let path = req.uri().path();
    let mut fs_path = resolve_path(&lc.root, path)?;
    let mut meta = fs::metadata(&fs_path)?;
    if meta.is_dir() {
        // 与 h1 一致：目录缺尾斜杠先 301（保留 query），再谈 index/autoindex。
        // 此前 h2/h3 完全没有这道跳转：`GET /dir` 直接回目录内容，页面相对链接全错。
        if let Some(loc) = dir_redirect_location(req.uri()) {
            return Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(header::LOCATION, loc)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Bytes::from_static(b"<h1>301 Moved Permanently</h1>"))
                .unwrap());
        }
        // 与 h1 相同：index.html/index.htm 优先（否则 h1 与 h2/h3 行为不一致）。
        if let Some((idx, idx_meta)) = directory_index(&fs_path, &lc.root) {
            fs_path = idx;
            meta = idx_meta;
        }
    }
    if meta.is_dir() {
        if lc.autoindex.allows(path) {
            let html = autoindex_html(&fs_path, path, lc.autoindex.enabled && lc.autoindex.enable_upload)?;
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Bytes::from(html))
                .unwrap());
        }
        bail!("directory");
    }
    // 只服务**普通文件**：docroot 里若有 FIFO / unix socket / 设备节点，open/read 会
    // **永久阻塞**（`fs::read` 在 async 任务里是同步调用，直接占死一个 tokio worker；
    // 本机只有 2 个 worker，两个这样的请求就能让服务整体失去响应）。
    // h1 的 `serve` 早已有这道判据，h2/h3 这条路径此前漏了 —— 同一路径 h1 安全、
    // h2/h3 被卡死（浏览器默认走 h2/h3）。
    if !meta.is_file() {
        bail!("not a regular file");
    }
    // h2/h3 必须与 h1 用同一套 file_open 语义。
    // 此前 serve_simple 完全无视 file_open：管理员把 /uploads/x.html 配成
    // preview/download（强制 text/plain + inline/attachment + nosniff，防上传文件被
    // 当页面执行）时，h2/h3 上这条缓解被静默忽略——而浏览器默认就走 h2/h3。
    let mode = lc.file_open_mode(path);
    let mut ct = mime_guess::from_path(&fs_path)
        .first_or_octet_stream()
        .to_string();
    if mode == FileOpenMode::Preview && is_script_ext(&fs_path) {
        ct = "text/plain; charset=utf-8".into();
    }
    let disposition = match mode {
        FileOpenMode::Download => Some("attachment"),
        FileOpenMode::Preview => Some("inline"),
        _ => None,
    };
    // §16.2：static 层不得替引擎把「应执行的脚本」当普通文件吐出去（见 engine_owns）。
    if engine_owns(lc, path, mode) {
        bail!("path is owned by an app engine");
    }
    if app_private_path(lc, path, mode) {
        bail!("app docroot private file is not served");
    }

    let len = meta.len();
    // 条件请求（RFC 9110 §13）：在任何 body 读取/Range 处理**之前**判。304 不带 body、
    // 也不带 Content-Length（RFC 9110 §15.4.5）。
    let (etag, mtime) = validators(&meta);
    match eval_conditions(req.headers(), &etag, mtime, true) {
        Cond::NotModified => {
            return Ok(
                with_validators(
                    Response::builder().status(StatusCode::NOT_MODIFIED),
                    &etag,
                    mtime,
                )
                .body(Bytes::new())
                .unwrap(),
            )
        }
        Cond::PreconditionFailed => {
            return Ok(Response::builder()
                .status(StatusCode::PRECONDITION_FAILED)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Bytes::from_static(b"precondition failed"))
                .unwrap())
        }
        Cond::Proceed => {}
    }
    // HEAD 短路必须与 h1 一致：此前 HEAD 照样整读文件并
    // 经 DATA 帧把正文发上线——RFC 9110 §9.3.2 禁止 HEAD 响应带内容，且一个
    // `HEAD /big.bin` 就能造成最多 16MiB 的读放大 + 上线放大。
    // 与 h1 同样保留 Range 语义（206/416 + Content-Range），只是不读数据。
    if method == Method::HEAD {
        if if_range_allows(req.headers(), &etag, mtime) {
            if let Some(rr) = req.headers().get(header::RANGE).and_then(|v| v.to_str().ok()) {
                match head_range_outcome(len, rr, &ct) {
                    RangeOutcome::Ignore => {}
                    RangeOutcome::Unsatisfiable => {
                        return Ok(with_validators(
                            Response::builder()
                                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                                .header(header::CONTENT_RANGE, format!("bytes */{len}")),
                            &etag,
                            mtime,
                        )
                        .body(Bytes::new())
                        .unwrap());
                    }
                    RangeOutcome::Single { start, end, .. } => {
                        let mut b = with_validators(
                            Response::builder()
                                .status(StatusCode::PARTIAL_CONTENT)
                                .header(header::CONTENT_TYPE, ct)
                                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                                .header(header::CONTENT_LENGTH, end - start + 1)
                                .header(header::ACCEPT_RANGES, "bytes"),
                            &etag,
                            mtime,
                        );
                        if let Some(d) = disposition {
                            b = b.header(header::CONTENT_DISPOSITION, disposition_value(&fs_path, d));
                            b = b.header("x-content-type-options", "nosniff");
                        }
                        return Ok(b.body(Bytes::new()).unwrap());
                    }
                    RangeOutcome::Multi {
                        content_type,
                        content_length,
                        ..
                    } => {
                        let mut b = with_validators(
                            Response::builder()
                                .status(StatusCode::PARTIAL_CONTENT)
                                .header(header::CONTENT_TYPE, content_type)
                                .header(header::CONTENT_LENGTH, content_length)
                                .header(header::ACCEPT_RANGES, "bytes"),
                            &etag,
                            mtime,
                        );
                        if let Some(d) = disposition {
                            b = b.header(
                                header::CONTENT_DISPOSITION,
                                disposition_value(&fs_path, d),
                            );
                            b = b.header("x-content-type-options", "nosniff");
                        }
                        return Ok(b.body(Bytes::new()).unwrap());
                    }
                }
            }
        }
        let mut b = with_validators(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CONTENT_LENGTH, len)
                .header(header::ACCEPT_RANGES, "bytes"),
            &etag,
            mtime,
        );
        if let Some(d) = disposition {
            b = b.header(header::CONTENT_DISPOSITION, disposition_value(&fs_path, d));
            b = b.header("x-content-type-options", "nosniff");
        }
        return Ok(b.body(Bytes::new()).unwrap());
    }

    // Range/206：h2/h3 此前完全不支持 Range。浏览器/播放器默认走 h2/h3，
    // 于是「下载断点续传」在主协议上不可用，而且超过 MAX_FULL_READ 的文件
    // 只能拿到下面的 413（等于完全下不动）。这里补上与 h1 相同的 Range 语义
    //（单段 + multipart/byteranges，见 `eval_range`）。
    // `If-Range` 门：验证器不符时必须忽略 Range 回 200 全量（否则续传客户端会拿到
    // 新文件的一段旧偏移数据 —— 静默的文件内容错乱）。
    if if_range_allows(req.headers(), &etag, mtime) {
        if let Some(rr) = req.headers().get(header::RANGE).and_then(|v| v.to_str().ok()) {
            match eval_range(&fs_path, len, rr, &ct).await? {
                RangeOutcome::Ignore => {}
                RangeOutcome::Unsatisfiable => {
                    return Ok(with_validators(
                        Response::builder()
                            .status(StatusCode::RANGE_NOT_SATISFIABLE)
                            .header(header::CONTENT_RANGE, format!("bytes */{len}")),
                        &etag,
                        mtime,
                    )
                    .body(Bytes::new())
                    .unwrap());
                }
                RangeOutcome::Single { start, end, body } => {
                    let mut b = with_validators(
                        Response::builder()
                            .status(StatusCode::PARTIAL_CONTENT)
                            .header(header::CONTENT_TYPE, ct)
                            .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                            .header(header::CONTENT_LENGTH, body.len())
                            .header(header::ACCEPT_RANGES, "bytes"),
                        &etag,
                        mtime,
                    );
                    if let Some(d) = disposition {
                        // 206 同样要带 disposition + nosniff：preview/download 的强制
                        // 语义不能因为客户端多发一个 Range 头就被绕过。
                        b = b.header(header::CONTENT_DISPOSITION, disposition_value(&fs_path, d));
                        b = b.header("x-content-type-options", "nosniff");
                    }
                    return Ok(b.body(body).unwrap());
                }
                RangeOutcome::Multi {
                    content_type,
                    content_length,
                    body,
                } => {
                    // 多段：顶层不带 Content-Range（RFC 9110 §15.3.7.2）。
                    let mut b = with_validators(
                        Response::builder()
                            .status(StatusCode::PARTIAL_CONTENT)
                            .header(header::CONTENT_TYPE, content_type)
                            .header(header::CONTENT_LENGTH, content_length)
                            .header(header::ACCEPT_RANGES, "bytes"),
                        &etag,
                        mtime,
                    );
                    let _ = body.len();
                    if let Some(d) = disposition {
                        b = b.header(header::CONTENT_DISPOSITION, disposition_value(&fs_path, d));
                        b = b.header("x-content-type-options", "nosniff");
                    }
                    return Ok(b.body(body).unwrap());
                }
            }
        }
    }

    // 超大文件：不进内存，改为「流式来源」标记由发送路径分块读盘。
    // 此前一律 413（浏览器点一个 >16MiB 的文件就下不动，必须手动 Range 分段），
    // 而 Range 路径本来就是内存受限的（MAX_RANGE_BYTES=32MiB），无法替代整体下载。
    if len > MAX_FULL_READ {
        let mut b = with_validators(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CONTENT_LENGTH, len)
                .header(header::ACCEPT_RANGES, "bytes"),
            &etag,
            mtime,
        );
        if let Some(d) = disposition {
            b = b.header(header::CONTENT_DISPOSITION, disposition_value(&fs_path, d));
            b = b.header("x-content-type-options", "nosniff");
        }
        let mut resp = b.body(Bytes::new()).unwrap();
        resp.extensions_mut().insert(FileSource {
            path: fs_path.clone(),
            start: 0,
            len,
        });
        return Ok(resp);
    }
    // 只有小文件才进缓存，否则 256 条 × 16MiB 会把常驻内存撑到数 GiB。
    let data = if len <= SMALL_FILE_MAX {
        read_cached(&fs_path, &meta)?
    } else {
        // >256KiB 的整读走 spawn_blocking（同 h1 路径）。
        read_file_async(fs_path.clone()).await?
    };
    let mut b = with_validators(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, ct)
            .header(header::CONTENT_LENGTH, data.len())
            .header(header::ACCEPT_RANGES, "bytes"),
        &etag,
        mtime,
    );
    if let Some(d) = disposition {
        b = b.header(header::CONTENT_DISPOSITION, disposition_value(&fs_path, d));
        b = b.header("x-content-type-options", "nosniff");
    }
    Ok(b.body(data).unwrap())
}

fn resolve_path(root: &Path, url_path: &str) -> Result<PathBuf> {
    let rel = url_path.trim_start_matches('/');
    let decoded = percent_encoding::percent_decode_str(rel)
        .decode_utf8_lossy()
        .to_string();
    // P2-1：显式穿越段一律拒绝（解码后再判一次，防 %2e%2e 绕过）。
    if decoded.split(['/','\\']).any(|seg| seg == "..") {
        bail!("path escape");
    }
    // 上传临时文件**不得下载**：`.{目标名}.upload.part` 与目标名一一对应且可猜，
    // 否则任何客户端都能轮询 `GET /.secret.pdf.upload.part` 读走别人正在上传
    //（或已中断）的内容 —— 而那正是最可能含敏感数据的一份。
    if let Some(name) = decoded.rsplit('/').next() {
        if name.starts_with('.') && name.ends_with(".upload.part") {
            bail!("upload temp file is not served");
        }
    }
    // 隐藏文件/目录一律不服务（唯一例外：ACME 的 `/.well-known/`，其内容是公开校验串）。
    //
    // 实测过的泄露：生产 listener（`root = www-apps`）上 `GET /rust/.env`、`GET /c/.env`
    // 都是 **200** —— 这些 `.env` 正是 `deps.rs` 读进**引擎进程环境变量**的 `KEY=VAL`
    //（数据库口令之类）；`.git/config`、`.htpasswd`、`.crucible_manifest` 同理。它们既不在
    // 可执行扩展名名单里、也不归引擎，静态层于是照单全收。判据放在 `resolve_path` 里，
    // h1 与 h2/h3 两条服务路径同时生效。
    for seg in decoded.split(['/', '\\']) {
        if seg.is_empty() || seg == "." || !seg.starts_with('.') {
            continue;
        }
        if seg.eq_ignore_ascii_case(".well-known") {
            continue; // ACME http-01：必须可服务
        }
        bail!("hidden path is not served");
    }
    // 解析缓存：命中即返回（跳过 realpath/stat 链）。
    let ckey = (root.to_path_buf(), decoded.clone());
    {
        let now = std::time::Instant::now();
        let cache = CANON_CACHE.lock();
        if let Some(e) = cache.get(&ckey) {
            if now.duration_since(e.at) < CANON_TTL {
                return Ok(e.canon.clone());
            }
        }
    }
    let joined = root.join(&decoded);
    let canon_root = canon_root_cached(root);
    // P2-1：symlink 经 canonicalize 解析后强制 containment——指向 root 外的符号链接
    // 一律拒绝；root 内互链允许（web 服务器惯例）。未存在路径按最深存在的父目录
    // canonicalize 后拼回剩余段（旧实现的 unwrap_or(joined) 会跳过 containment 校验）。
    let canon = if joined.exists() {
        joined.canonicalize()?
    } else {
        let mut base = joined.clone();
        let mut rest: Vec<std::ffi::OsString> = Vec::new();
        while !base.exists() {
            let parent = base
                .parent()
                .map(|p| p.to_path_buf())
                .ok_or_else(|| anyhow::anyhow!("path escape"))?;
            rest.push(base.file_name().unwrap_or_default().to_os_string());
            base = parent;
        }
        let mut canon_base = base.canonicalize()?;
        for seg in rest.iter().rev() {
            canon_base.push(seg);
        }
        canon_base
    };
    if !canon.starts_with(&canon_root) {
        bail!("path escape");
    }
    // 只有通过 containment 的结果才入缓存。
    {
        let mut cache = CANON_CACHE.lock();
        if cache.len() >= CANON_CAP {
            cache.clear();
        }
        cache.insert(
            ckey,
            CanonEntry {
                canon: canon.clone(),
                at: std::time::Instant::now(),
            },
        );
    }
    Ok(canon)
}

/// docroot 自身的 canonical 路径（缓存 + TTL；失败时退回原路径）。
fn canon_root_cached(root: &Path) -> PathBuf {
    static ROOT_CACHE: Lazy<Mutex<HashMap<PathBuf, (PathBuf, std::time::Instant)>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));
    let now = std::time::Instant::now();
    if let Some((c, at)) = ROOT_CACHE.lock().get(root).cloned() {
        if now.duration_since(at) < CANON_TTL {
            return c;
        }
    }
    let c = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    ROOT_CACHE
        .lock()
        .insert(root.to_path_buf(), (c.clone(), now));
    c
}

/// P1-12（§16.2）：脚本/源码扩展——file_open=preview 命中时强制 text/plain 展示源码
///（mime_guess 会给 application/x-httpd-php 之类，浏览器可能按插件处理）；媒体/图片/
/// 文档保持原类型供内联预览。
const SCRIPT_EXTS: &[&str] = &[
    "php", "phtml", "php3", "php4", "php5", "inc", "cgi", "pl", "pm", "py", "rb", "ru",
    "lua", "tcl", "sh", "bash", "zsh", "ksh", "c", "cc", "cpp", "cxx", "h", "hpp",
    "rs", "go", "java", "jsp", "jspx", "asp", "aspx", "asa", "shtml", "ts", "tsx",
    "vue", "jsx", "sql", "conf", "ini", "yaml", "yml", "toml", "env",
    // 浏览器会**主动渲染/执行**的类型。原先只列脚本语言，漏了这些，
    // 于是「preview 强制 text/plain」对 .html/.js/.svg 完全不生效：
    // 管理员把 /uploads/x.html 配成 preview，拿到的仍是 text/html + inline，
    // 上传的页面照常在站点 origin 下渲染并执行脚本（存储型 XSS）。
    "html", "htm", "xhtml", "hta", "js", "mjs", "cjs", "svg", "xml", "xsl", "xslt",
];

fn is_script_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| SCRIPT_EXTS.iter().any(|s| e.eq_ignore_ascii_case(s)))
        .unwrap_or(false)
}

/// `Content-Disposition` 值；文件名转义引号/反斜杠/控制字符，防响应头破坏/注入。
fn disposition_value(path: &Path, d: &str) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let safe_name: String = name
        .chars()
        .map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' { c } else { '_' })
        .collect();
    format!("{d}; filename=\"{safe_name}\"")
}

/// 给已构建好的响应补验证器头（206/416 这类由辅助函数造出来的响应）。
fn add_validators(
    mut resp: Response<BoxBody>,
    etag: &str,
    mtime: Option<SystemTime>,
) -> Response<BoxBody> {
    if let Ok(v) = http::HeaderValue::from_str(etag) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    if let Some(m) = mtime {
        if let Ok(v) = http::HeaderValue::from_str(&httpdate::fmt_http_date(m)) {
            resp.headers_mut().insert(header::LAST_MODIFIED, v);
        }
    }
    resp
}

async fn serve_file(
    req: &Request<Incoming>,
    path: &Path,
    meta: &std::fs::Metadata,
    mode: FileOpenMode,
) -> Result<Response<BoxBody>> {
    let len = meta.len();
    let mut ct = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();
    if mode == FileOpenMode::Preview && is_script_ext(path) {
        ct = "text/plain; charset=utf-8".into();
    }

    let disposition = match mode {
        FileOpenMode::Download => Some("attachment"),
        FileOpenMode::Preview => Some("inline"),
        _ => None,
    };

    // 条件请求（RFC 9110 §13）：在任何 body 读取 / Range 处理之前判。
    let (etag, mtime) = validators(meta);
    match eval_conditions(req.headers(), &etag, mtime, true) {
        Cond::NotModified => {
            return Ok(add_validators(
                Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(empty())
                    .unwrap(),
                &etag,
                mtime,
            ))
        }
        Cond::PreconditionFailed => {
            return Ok(Response::builder()
                .status(StatusCode::PRECONDITION_FAILED)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(full("precondition failed"))
                .unwrap())
        }
        Cond::Proceed => {}
    }

    // HEAD 在 Range 与整读**之前**短路，但**不吞掉 Range 语义**（RFC 9110 §9.3.2
    // 要求 HEAD 与 GET 同状态、同头）。此前 HEAD 恒回 200：`curl -I -r 0-9` 会据此判定
    // 「服务端不支持区间」；而把 HEAD 放到 Range 之后又会造成最多 32MiB 的读放大
    // （`HEAD /big.bin` + `Range: bytes=0-33554431`）。这里的折中是：**只算区间、不读数据**。
    if req.method() == Method::HEAD {
        if if_range_allows(req.headers(), &etag, mtime) {
            if let Some(rr) = req.headers().get(header::RANGE).and_then(|v| v.to_str().ok()) {
                if let Some(resp) = head_range_response(path, len, rr, &ct, disposition, &etag, mtime)
                {
                    return Ok(resp);
                }
            }
        }
        let mut b = with_validators(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CONTENT_LENGTH, len)
                .header(header::ACCEPT_RANGES, "bytes"),
            &etag,
            mtime,
        );
        if let Some(d) = disposition {
            b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
            b = b.header("x-content-type-options", "nosniff");
        }
        return Ok(b.body(empty()).unwrap());
    }

    // If-Range 门：验证器不符 → 忽略 Range 回 200 全量（避免续传客户端把新旧内容拼错）。
    if if_range_allows(req.headers(), &etag, mtime) {
        if let Some(range) = req.headers().get(header::RANGE) {
            if let Ok(r) = range.to_str() {
                if let Some(resp) = range_response(path, len, r, &ct, disposition).await? {
                    return Ok(add_validators(resp, &etag, mtime));
                }
            }
        }
    }

    // 大文件：不再整读进内存，也不再回 413（h2/h3 侧此前已修，h1 侧漏了 ——
    // 浏览器点一个 >16MiB 的文件不带 Range，走的就是这条路径，会直接报错）。
    // 这里只留下「流式来源」标记，真正的分块读盘在 `h1::stream_file`。
    if len > MAX_FULL_READ {
        let mut b = with_validators(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CONTENT_LENGTH, len)
                .header(header::ACCEPT_RANGES, "bytes"),
            &etag,
            mtime,
        );
        if let Some(d) = disposition {
            b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
            b = b.header("x-content-type-options", "nosniff");
        }
        let mut resp = b.body(empty()).unwrap();
        resp.extensions_mut().insert(FileSource {
            path: path.to_path_buf(),
            start: 0,
            len,
        });
        return Ok(resp);
    }

    let data = if len <= SMALL_FILE_MAX {
        read_cached(path, meta)?
    } else {
        // >256KiB 的整读走 spawn_blocking：同步 `fs::read` 最大 16MiB，在 2-worker 的
        // bench 形态下会把整个 runtime（三协议共用）卡住数十毫秒。
        read_file_async(path.to_path_buf()).await?
    };

    let mut b = with_validators(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, ct)
            .header(header::CONTENT_LENGTH, data.len())
            .header(header::ACCEPT_RANGES, "bytes"),
        &etag,
        mtime,
    );
    if let Some(d) = disposition {
        // 预览与下载响应禁 MIME 嗅探（浏览器不得把 text/plain 拉去执行）。
        b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
        b = b.header("x-content-type-options", "nosniff");
    }
    Ok(b.body(full(data)).unwrap())
}

fn read_cached(path: &Path, meta: &std::fs::Metadata) -> Result<Bytes> {
    let id = file_id(meta);
    {
        let cache = SMALL_CACHE.lock();
        if let Some(e) = cache.get(path) {
            // 用 FileId（长度+inode+mtime）而不是裸 mtime：粗粒度时钟下同一 tick 内的
            // 等长改写会得到相同 mtime，只比 mtime 时缓存会把**旧内容**当当前表示
            // 发出去（同一个文件在 autoindex/preview 页面上"改了不生效"）。
            if e.id == id {
                return Ok(e.data.clone());
            }
        }
    }
    let data = Bytes::from(read_file_capped(path)?);
    let ct = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();
    let mut cache = SMALL_CACHE.lock();
    if cache.len() >= CACHE_CAP {
        cache.clear();
    }
    cache.insert(
        path.to_path_buf(),
        CacheEntry {
            id,
            data: data.clone(),
            content_type: ct,
        },
    );
    Ok(data)
}

/// RFC 7233 单段 Range 的解析结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeSpec {
    /// 语法不规范（非法数字 / 多段 / 非 `bytes=`）：RFC 允许服务器忽略 Range，回 200 全量。
    Ignore,
    /// 语法合法但不可满足（start>=len、start>end、空文件、`bytes=-0`）→ 416。
    Unsatisfiable,
    /// 可满足的单段（已按 [`MAX_RANGE_BYTES`] 收窄，保证内存上限）。
    Slice { start: u64, end: u64 },
}

/// 一个已解析、已收窄的字节区间（闭区间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

/// 把「已解析的单段」收进 [`MAX_RANGE_BYTES`] 上限（超限时按 suffix/显式对齐收窄）。
fn clamp_slice(start: u64, end: u64, suffix: bool) -> ByteRange {
    if end - start + 1 > MAX_RANGE_BYTES {
        let cap = MAX_RANGE_BYTES - 1;
        // suffix 请求要的是文件尾部，收窄时保持尾部对齐；显式请求保持头部对齐。
        if suffix {
            ByteRange { start: end - cap, end }
        } else {
            ByteRange { start, end: start + cap }
        }
    } else {
        ByteRange { start, end }
    }
}

/// 解析一个**纯 ASCII 数字**的 u64 位置。非纯数字（空串、前导 `+`、含空白、含字母）
/// 一律 `None` —— RFC 9110 §14.1.1 的 `first-pos`/`last-pos` 只允许 DIGIT。
///
/// 为什么不能直接用 `str::parse::<u64>()`：Rust 的整型解析**接受前导 `+`**（`"+5".parse()`
/// 得到 5）与前后空白，于是 `Range: bytes=+5-9` 会被当成合法区间 5-9 回 206；而按 §14.2
/// 畸形/不可满足之外、语法不成立的 Range 必须**忽略**（回 200 全量）。同理超长数字串
/// （`parse` 溢出 Err）也归入忽略，而不是 panic。
fn digits_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// 解析**单段** Range（RFC 7233 §2.1）：支持 `bytes=N-M`、`bytes=N-`、`bytes=-N`。
fn parse_range(range: &str, len: u64) -> RangeSpec {
    let range = range.trim();
    // range unit（`bytes`）是 token，按 RFC 9110 §14.2 大小写不敏感；不认识的
    // unit 必须**忽略**整个 Range（回 200），不能当非法请求报错。
    let Some((unit, rest)) = range.split_once('=') else {
        return RangeSpec::Ignore;
    };
    if !unit.eq_ignore_ascii_case("bytes") {
        return RangeSpec::Ignore;
    }
    if rest.contains(',') {
        return RangeSpec::Ignore;
    }
    let Some((start_s, end_s)) = rest.split_once('-') else {
        return RangeSpec::Ignore;
    };
    let suffix = start_s.is_empty();
    let (start, end) = if suffix {
        // suffix 形式：bytes=-N → 最后 N 字节
        let Some(n) = digits_u64(end_s) else {
            return RangeSpec::Ignore;
        };
        if n == 0 || len == 0 {
            return RangeSpec::Unsatisfiable;
        }
        (len.saturating_sub(n), len.saturating_sub(1))
    } else {
        let Some(s) = digits_u64(start_s) else {
            return RangeSpec::Ignore;
        };
        // 末端为空 = 合法的开放末端（`bytes=5-`）；末端非空但不是纯数字 = 畸形
        // （`bytes=5-abc`、`bytes=5-1x`）→ 按 §14.2 **忽略整个 Range**，而不是把它
        // 当成开放末端回 206（旧实现的行为）。
        if end_s.is_empty() {
            (s, len.saturating_sub(1))
        } else {
            let Some(e) = digits_u64(end_s) else {
                return RangeSpec::Ignore;
            };
            (s, e.min(len.saturating_sub(1)))
        }
    };
    if len == 0 || start >= len || start > end {
        return RangeSpec::Unsatisfiable;
    }
    // DoS 护栏：单段响应体的内存上限。超限**不能**回 416 —— `bytes=N-`
    // （curl -C - 等续传客户端的写法）在大文件上必然超限，回 416 会让
    // 「下载断点续传」彻底不可用（curl 会直接判定 "doesn't support byte ranges"）。
    // RFC 7233 §4.1 允许服务器只回请求区间的一个子集，客户端按 Content-Range
    // 里的实际区间继续请求剩余部分，所以这里改为按上限收窄而不是拒绝。
    let s = clamp_slice(start, end, suffix);
    RangeSpec::Slice { start: s.start, end: s.end }
}

/// 多段 Range 的解析结果（RFC 9110 §14.1.1/§14.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MultiRange {
    /// 整条 Range 语法不成立 / 单位不认识 → 按 §14.2 **忽略**（回 200 全量）。
    Ignore,
    /// 语法成立但**没有任何可满足的区间** → 416（带 `Content-Range: bytes */len`）。
    Unsatisfiable,
    /// 一个或多个可满足区间（已排序、已合并、已按 [`MAX_RANGE_BYTES`] 收窄）。
    ///
    /// `coalesced_single == true` 表示「客户端只请求了一段」（此时**必须**回单段 206，
    /// 不能回 multipart/byteranges —— §15.3.7.2 明确禁止对单段请求回 multipart）。
    Ranges {
        ranges: Vec<ByteRange>,
        coalesced_single: bool,
    },
}

/// 解析完整 Range 头（含**多段**），按 RFC 9110 §14.1.1 的 `byte-ranges-specifier` 语法。
///
/// 为什么必须支持多段而不是像旧实现那样「见到逗号就忽略整条 Range」：
/// * §14.2 说服务器 MAY ignore 多段（那是给 DoS 留的口子），但**忽略**的后果是回 200
///   **全量** —— 对 `Range: bytes=0-0,-1`（PDF 阅读器/视频播放器常用的首尾探测）意味着
///   把整个大文件推给客户端，比正确回 multipart 更糟；
/// * 规格 §16.2 明确要求「Range / HEAD / 206 Partial Content 全支持」。
///
/// 内存护栏不变：合并后的每个区间与区间总长都受 [`MAX_RANGE_BYTES`] 约束（见
/// [`clamp_slice`] 与 `MAX_TOTAL_RANGE_BYTES`），绝不会因为多段而放大内存。
pub(crate) fn parse_ranges(range: &str, len: u64) -> MultiRange {
    let range = range.trim();
    let Some((unit, rest)) = range.split_once('=') else {
        return MultiRange::Ignore;
    };
    if !unit.eq_ignore_ascii_case("bytes") {
        return MultiRange::Ignore;
    }
    // 单段直接复用单段解析（含畸形判据与收窄语义），保证既有行为逐字不变。
    if !rest.contains(',') {
        return match parse_range(range, len) {
            RangeSpec::Ignore => MultiRange::Ignore,
            RangeSpec::Unsatisfiable => MultiRange::Unsatisfiable,
            RangeSpec::Slice { start, end } => MultiRange::Ranges {
                ranges: vec![ByteRange { start, end }],
                coalesced_single: true,
            },
        };
    }
    // 多段：任一 spec 语法不成立 → 整条忽略（§14.2「invalid ranges-specifier」）。
    let mut specs: Vec<ByteRange> = Vec::with_capacity(4);
    for part in rest.split(',') {
        let part = part.trim();
        if part.is_empty() {
            // `bytes=0-9,` / `bytes=0-9,,20-29`：尾部/中间空元素属语法不成立
            return MultiRange::Ignore;
        }
        let Some((start_s, end_s)) = part.split_once('-') else {
            return MultiRange::Ignore;
        };
        let suffix = start_s.is_empty();
        let (start, end) = if suffix {
            let Some(n) = digits_u64(end_s) else {
                return MultiRange::Ignore;
            };
            if n == 0 || len == 0 {
                continue; // `bytes=-0` 单段不可满足，跳过（其余段仍可能满足）
            }
            (len.saturating_sub(n), len.saturating_sub(1))
        } else {
            let Some(s) = digits_u64(start_s) else {
                return MultiRange::Ignore;
            };
            if end_s.is_empty() {
                (s, len.saturating_sub(1))
            } else {
                let Some(e) = digits_u64(end_s) else {
                    return MultiRange::Ignore;
                };
                (s, e.min(len.saturating_sub(1)))
            }
        };
        if len == 0 || start >= len || start > end {
            continue; // 该段不可满足，跳过（不影响其它段）
        }
        specs.push(clamp_slice(start, end, suffix));
    }
    if specs.is_empty() {
        return MultiRange::Unsatisfiable;
    }
    // §15.3.7.2：服务器 MAY 合并重叠或「间隔小于 multipart 开销（约 80 字节）」的区间。
    // 这里用 128 字节做阈值（略保守：合并后最多多发 O(阈值) 字节，却省掉 ~80 字节
    // 的 part 头 + 一次读盘）。必须先按 start 排序再合并。
    specs.sort_by_key(|r| (r.start, r.end));
    let mut merged: Vec<ByteRange> = Vec::with_capacity(specs.len());
    for r in specs {
        match merged.last_mut() {
            Some(last) if r.start <= last.end.saturating_add(1).saturating_add(128) => {
                // 与上一段重叠或间隔很小 → 合并（取并集）
                if r.end > last.end {
                    last.end = r.end;
                }
            }
            _ => merged.push(r),
        }
    }
    // 合并后仍只有一段 → 按单段回（§15.3.7.2 禁止对单段请求回 multipart，合并成一段同理）。
    let single = merged.len() == 1;
    MultiRange::Ranges {
        ranges: merged,
        coalesced_single: single,
    }
}

/// 读文件的一个闭区间切片。调用方保证 `end - start + 1 ≤ MAX_RANGE_BYTES`。
fn read_slice(path: &Path, start: u64, end: u64) -> Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let take = usize::try_from(end - start + 1)
        .map_err(|_| anyhow::anyhow!("range too large for this platform"))?;
    let mut f = fs::File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; take];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// 多段响应体的**总字节**上限。单段上限是 [`MAX_RANGE_BYTES`]，多段若不加总量限制，
/// 一个 `Range: bytes=0-33554431,0-33554431,…`（同一区间重复 N 次）就能把内存放大 N 倍。
pub(crate) const MAX_TOTAL_RANGE_BYTES: u64 = MAX_RANGE_BYTES;
/// 多段响应最多回几段（超过就按 §15.3.7 只回靠前的那几段；段头本身也要占内存）。
pub(crate) const MAX_RANGE_PARTS: usize = 16;

/// Range 求值结果（单段与多段共用，供 h1/h2/h3 三条发送路径各自渲染）。
pub(crate) enum RangeOutcome {
    /// 「忽略 Range」：语法不成立、或整条 Range 没有可满足的段 ⇒ 调用方回 200 全量。
    /// 注意与 `Unsatisfiable` 的区别（§14.2：语法成立但不可满足才回 416）。
    Ignore,
    /// 416（带 `Content-Range: bytes */len`）。
    Unsatisfiable,
    /// 单段 206；`len` 是正文长度（HEAD 时为 0 但 `end - start + 1` 仍是准确长度）。
    Single { start: u64, end: u64, body: Bytes },
    /// 多段 206（`multipart/byteranges`）。`content_length` 是正文的精确长度，
    /// **不依赖 body**（HEAD 的 body 为空，但长度头必须准确）。
    Multi {
        content_type: String,
        content_length: u64,
        body: Bytes,
    },
}

/// 生成 multipart/byteranges 的边界串。用内容摘要做边界：同一请求稳定（便于调试/缓存），
/// 且不会与文件内容里出现的任意字符串冲突（长度 40 的十六进制 + 前缀足够）。
fn byteranges_boundary(len: u64, ranges: &[ByteRange]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    len.hash(&mut h);
    for r in ranges {
        r.start.hash(&mut h);
        r.end.hash(&mut h);
    }
    format!("__crucible_byteranges_{:016x}__", h.finish())
}

/// multipart/byteranges 的「排版计划」：先算好每个 part 的头部与尾部字节，
/// 这样 **HEAD 也能算出精确的 `Content-Length` 而不读一个字节**（RFC 9110 §9.3.2
/// 要求 HEAD 与 GET 同头）。
struct MultipartPlan {
    boundary: String,
    heads: Vec<(Vec<u8>, ByteRange)>,
    tail: Vec<u8>,
}

impl MultipartPlan {
    fn content_type(&self) -> String {
        format!("multipart/byteranges; boundary={}", self.boundary)
    }
    /// 计划中的正文总长度（每个 part = 头部 + 数据 + 末尾边界）。
    fn body_len(&self) -> u64 {
        let head: u64 = self
            .heads
            .iter()
            .map(|(h, r)| h.len() as u64 + r.len())
            .sum();
        head + self.tail.len() as u64
    }
}

/// 按 RFC 9110 §14.6/§15.3.7.2 规划 `multipart/byteranges` 正文。
///
/// * 顶层**不带** `Content-Range`（§15.3.7.2：多段响应不得在 HTTP 头里带它，改在每个
///   part 的头部里带）；
/// * 每个 part 带自己的 `Content-Type`（与 200 响应的类型一致）与 `Content-Range`；
/// * 段间用 `\r\n--boundary` 分隔，末尾 `\r\n--boundary--\r\n`（RFC 2046 的语法）。
/// * 段数/总字节已由调用方收敛到 [`MAX_RANGE_PARTS`]/[`MAX_TOTAL_RANGE_BYTES`]。
fn multipart_plan(len: u64, ranges: &[ByteRange], ct: &str) -> MultipartPlan {
    let boundary = byteranges_boundary(len, ranges);
    let mut heads = Vec::with_capacity(ranges.len());
    for r in ranges {
        let head = format!(
            "\r\n--{boundary}\r\nContent-Type: {ct}\r\nContent-Range: bytes {}-{}/{len}\r\n\r\n",
            r.start, r.end
        );
        heads.push((head.into_bytes(), *r));
    }
    let tail = format!("\r\n--{boundary}--\r\n").into_bytes();
    MultipartPlan {
        boundary,
        heads,
        tail,
    }
}

/// 渲染 multipart 正文（真正读盘）。调用方保证总量在内存上限内。
fn render_multipart(path: &Path, plan: &MultipartPlan) -> Result<Bytes> {
    let mut out: Vec<u8> = Vec::with_capacity(plan.body_len() as usize);
    for (head, r) in &plan.heads {
        out.extend_from_slice(head);
        out.extend_from_slice(&read_slice(path, r.start, r.end)?);
    }
    out.extend_from_slice(&plan.tail);
    Ok(Bytes::from(out))
}

/// 把「已解析合并的区间列表」收敛到内存护栏内（段数 + 总字节）。
fn cap_ranges(ranges: &[ByteRange]) -> Vec<ByteRange> {
    let mut acc: u64 = 0;
    let mut out: Vec<ByteRange> = Vec::new();
    for r in ranges {
        acc = acc.saturating_add(r.len());
        if acc > MAX_TOTAL_RANGE_BYTES || out.len() >= MAX_RANGE_PARTS {
            // §15.3.7：服务器可以不回全部请求的区间（客户端按收到的 Content-Range 续请求）。
            break;
        }
        out.push(*r);
    }
    out
}

/// Range 求值的统一入口（h1/h2/h3 共用）：解析 → 收窄/合并 → 读盘 → 产出结果。
async fn eval_range(path: &Path, len: u64, range: &str, ct: &str) -> Result<RangeOutcome> {
    match parse_ranges(range, len) {
        MultiRange::Ignore => Ok(RangeOutcome::Ignore),
        MultiRange::Unsatisfiable => Ok(RangeOutcome::Unsatisfiable),
        MultiRange::Ranges { ranges, .. } => {
            let capped = cap_ranges(&ranges);
            match capped.len() {
                // 一段都没收敛出来（理论不可达：单段已被收窄到上限内）→ 保守回 200
                0 => Ok(RangeOutcome::Ignore),
                1 => {
                    let r = capped[0];
                    // 单段仍走 spawn_blocking（≤32MiB 同步读，别卡 async worker）
                    let body = read_slice_async(path.to_path_buf(), r.start, r.end).await?;
                    Ok(RangeOutcome::Single {
                        start: r.start,
                        end: r.end,
                        body,
                    })
                }
                // §15.3.7.2：单段（含合并成一段）**必须**回单段 206，不得回 multipart。
                _ => {
                    let p = path.to_path_buf();
                    let ct_s = ct.to_string();
                    let out = tokio::task::spawn_blocking(move || {
                        let plan = multipart_plan(len, &capped, &ct_s);
                        let body = render_multipart(&p, &plan)?;
                        Ok::<_, anyhow::Error>(RangeOutcome::Multi {
                            content_type: plan.content_type(),
                            content_length: body.len() as u64,
                            body,
                        })
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("blocking multipart task failed: {e}"))??;
                    Ok(out)
                }
            }
        }
    }
}

/// HEAD 版的 Range 结果（不读盘）：按 GET 会返回的状态与头作答。
/// 多段时报 206 + `multipart/byteranges` 的 `Content-Type` 与**精确**长度。
fn head_range_outcome(len: u64, range: &str, ct: &str) -> RangeOutcome {
    match parse_ranges(range, len) {
        MultiRange::Ignore => RangeOutcome::Ignore,
        MultiRange::Unsatisfiable => RangeOutcome::Unsatisfiable,
        MultiRange::Ranges { ranges, .. } => {
            let capped = cap_ranges(&ranges);
            match capped.len() {
                0 => RangeOutcome::Ignore,
                1 => RangeOutcome::Single {
                    start: capped[0].start,
                    end: capped[0].end,
                    body: Bytes::new(),
                },
                _ => {
                    let plan = multipart_plan(len, &capped, ct);
                    RangeOutcome::Multi {
                        content_type: plan.content_type(),
                        content_length: plan.body_len(),
                        body: Bytes::new(),
                    }
                }
            }
        }
    }
}

/// Range 切片读取的 async 包装：`read_slice` 一次最多同步读 32MiB
/// （`vec![0u8; take]` + `read_exact`），在 async worker 上是明确的阻塞点。
async fn read_slice_async(path: PathBuf, start: u64, end: u64) -> Result<Bytes> {
    tokio::task::spawn_blocking(move || read_slice(&path, start, end).map(Bytes::from))
        .await
        .map_err(|e| anyhow::anyhow!("blocking range read task failed: {e}"))?
}

async fn range_response(
    path: &Path,
    len: u64,
    range: &str,
    ct: &str,
    disposition: Option<&str>,
) -> Result<Option<Response<BoxBody>>> {
    // P2-2（RFC7233）+ RFC 9110 §14.1.1/§15.3.7：单段（含 suffix 与开放末端）与多段都支持；
    // 语法不成立 → 忽略（回 200 全量）；语法成立但不可满足 → 416（带 `Content-Range: bytes */len`）。
    match eval_range(path, len, range, ct).await? {
        RangeOutcome::Ignore => Ok(None),
        RangeOutcome::Unsatisfiable => Ok(Some(
            Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{len}"))
                .body(empty())
                .unwrap(),
        )),
        RangeOutcome::Single { start, end, body } => {
            let mut b = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                .header(header::CONTENT_LENGTH, body.len())
                .header(header::ACCEPT_RANGES, "bytes");
            if let Some(d) = disposition {
                // 206 也必须带 disposition + nosniff：否则「preview 强制
                // text/plain + nosniff」这条缓解只要客户端多发一个 Range 头就失效
                // （200/HEAD 都有，唯独 206 漏了）。
                b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
                b = b.header("x-content-type-options", "nosniff");
            }
            Ok(Some(b.body(full(body)).unwrap()))
        }
        RangeOutcome::Multi {
            content_type,
            content_length,
            body,
        } => {
            // §15.3.7.2：多段响应**不得**在顶层带 Content-Range（改在每个 part 里）。
            let mut b = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, content_length)
                .header(header::ACCEPT_RANGES, "bytes");
            if let Some(d) = disposition {
                b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
                b = b.header("x-content-type-options", "nosniff");
            }
            Ok(Some(b.body(full(body)).unwrap()))
        }
    }
}

fn autoindex(dir: &Path, url: &str, enable_upload: bool) -> Result<Response<BoxBody>> {
    let html = autoindex_html(dir, url, enable_upload)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full(html))
        .unwrap())
}

/// 目录索引文件名（按顺序探测），与 h2o/nginx 默认一致。
///
/// 为什么必须有：此前 h1 与 h2/h3 两条静态路径在 `meta.is_dir()` 时只有
/// 「autoindex 列表」或「404」两种结果 —— **从不服务 index.html**。而仓库自带的
/// `www/index.html`、`www-static-fair/index.html` 都是入口文件：既不 list（autoindex 关时）
/// 也不 serve，根路径直接 404；开着 autoindex 时则返回目录列表，而 `bench/h2o-fair.conf`
/// 让 h2o 服务同一目录的 index.html —— 公平基准比的不是同一个响应体（规格 §22）。
const INDEX_FILES: &[&str] = &["index.html", "index.htm"];

/// 在目录里找索引文件。
///
/// **必须做 containment 校验**：`dir` 已由 [`resolve_path`] 校验过，但 `dir.join(name)`
/// 的结果**没有**经过 canonicalize —— docroot 里一个 `index.html -> /etc/passwd` 的符号链接
/// 就能让 `GET /dir/` 直接把 root 外的文件吐出去（直连文件那条路有 containment，索引这条路
/// 此前漏了）。判据与 `resolve_path` 一致：canonicalize 后必须仍在 root 内（root 内互链允许，
/// 与 web 服务器惯例一致）。
fn directory_index(dir: &Path, root: &Path) -> Option<(PathBuf, fs::Metadata)> {
    let canon_root = canon_root_cached(root);
    for name in INDEX_FILES {
        let p = dir.join(name);
        let Ok(canon) = p.canonicalize() else {
            continue; // 不存在 / 断链
        };
        if !canon.starts_with(&canon_root) {
            log::debug!(
                "static: 拒绝 root 外的目录索引符号链接 {} -> {}",
                p.display(),
                canon.display()
            );
            continue;
        }
        if let Ok(m) = fs::metadata(&canon) {
            if m.is_file() {
                // 返回 canonical 路径：与 `resolve_path` 对直连文件的处理一致
                //（MIME / disposition 都按真实目标名判）。
                return Some((canon, m));
            }
        }
    }
    None
}

fn autoindex_html(dir: &Path, url: &str, enable_upload: bool) -> Result<String> {
    // 只编码路径段内的不安全字符；目录的 `/` 在编码之外拼接，
    // 避免 `test%2F` 这类整段被错误编码的子目录链接（规格 §8）。
    const SEG: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'%')
        .add(b'&')
        .add(b'\'')
        .add(b'<')
        .add(b'>')
        .add(b'?')
        .add(b'`')
        .add(b'{')
        .add(b'}')
        .add(b'\\');
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let mut entries: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        // 上传临时文件（`.{目标名}.upload.part`）不进目录列表：它们不可下载（见 resolve_path），
        // 但把名字列出来等于告诉所有人「谁正在往这里传什么文件、传到一半」。
        // 目录列表**不列任何点开头的名字**（`.env`、`.git`、`.htpasswd`…）。
        // 它们本来就下载不了（`resolve_path` 拒隐藏段），但列出来等于告诉访问者
        // 「这里有个 .env、它叫什么」—— 本仓库自己的注释就写着部署的 `.env` 里放 DB 口令。
        // （原来只排除了 `.x.upload.part`，隐藏文件照列。）
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            !n.starts_with('.')
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());
    let base = if url.ends_with('/') {
        url.to_string()
    } else {
        format!("{url}/")
    };
    let mut body = String::from("<!DOCTYPE html><html><head><meta charset=utf-8><title>Index</title></head><body><ul>");
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let enc = percent_encoding::utf8_percent_encode(&name, SEG).to_string();
        let href = if is_dir {
            format!("{base}{enc}/")
        } else {
            format!("{base}{enc}")
        };
        let label = if is_dir {
            format!("{}/", esc(&name))
        } else {
            esc(&name)
        };
        // href 里的 base 是**原始请求路径**，而 http 的 URI 校验允许路径中出现
        // 未编码的 `"`（`"`/`{`/`}` 被显式列为合法）。目录名里含 `"` 时
        // （Linux 文件名允许；`..` 段已在 resolve_path 拒绝），
        // `href="{base}{name}"` 会被这个引号逃出属性 → 注入 HTML。
        // esc() 是 HTML 转义，浏览器解析属性值时会还原成同样的 URL，故不影响解析。
        body.push_str(&format!("<li><a href=\"{}\">{label}</a></li>", esc(&href)));
    }

    // §44 上传 UI：只有开了 enable_upload 才渲染。分片 PUT + Content-Range，
    // 未收齐回 202/409 并带 x-upload-offset，据此续传（不重传已完成部分）。
    if enable_upload {
        body.push_str("<hr><p><b>上传</b>（支持断点续传：中断后再选同一文件会从中断处继续）</p>");
        body.push_str("<input type=\"file\" id=\"upf\"><button id=\"upb\">上传</button><span id=\"upm\"></span>");
        body.push_str(
            r#"<script>
async function crucibleUpload(){
  const f=document.getElementById('upf').files[0];
  const msg=document.getElementById('upm');
  if(!f){ msg.textContent='先选择文件'; return; }
  const CH=4*1024*1024;
  const url=location.pathname.replace(/[/]*$/,'/')+encodeURIComponent(f.name);
  let off=0;
  while(off<f.size){
    const end=Math.min(off+CH,f.size);
    const r=await fetch(url,{method:'PUT',
      headers:{'Content-Range':'bytes '+off+'-'+(end-1)+'/'+f.size},
      body:f.slice(off,end)});
    if(r.status===201||r.status===200){ msg.textContent='完成'; location.reload(); return; }
    if(r.status===202||r.status===409){
      const nx=parseInt(r.headers.get('x-upload-offset')||'',10);
      const next=(isNaN(nx)?end:nx);
      if(next<=off){ msg.textContent='服务端偏移异常，已停止'; return; }
      off=next; msg.textContent='已上传 '+(100*off/f.size).toFixed(1)+'%';
      continue;
    }
    msg.textContent='失败 '+r.status+': '+(await r.text());
    return;
  }
  msg.textContent='完成'; location.reload();
}
document.getElementById('upb').onclick=crucibleUpload;
</script>"#,
        );
    }
    body.push_str("</ul></body></html>");
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 目录索引：index.html 存在时必须优先返回它（此前只有列表/404 两条路）。
    /// 同时校验 root 外的符号链接索引被拒（`index.html -> /etc/passwd` 不得服务）。
    #[test]
    fn directory_index_prefers_index_html() {
        let dir = std::env::temp_dir().join(format!("crucible-idx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        assert!(directory_index(&dir, &dir).is_none());
        fs::write(dir.join("index.htm"), b"htm").unwrap();
        assert!(directory_index(&dir, &dir).unwrap().0.ends_with("index.htm"));
        fs::write(dir.join("index.html"), b"html").unwrap();
        let (p, m) = directory_index(&dir, &dir).unwrap();
        assert!(p.ends_with("index.html"));
        assert_eq!(m.len(), 4);

        // root 外的符号链接索引必须被拒（返回 None 或跳过它）
        #[cfg(unix)]
        {
            let outside = std::env::temp_dir().join(format!("crucible-idx-out-{}", std::process::id()));
            fs::write(&outside, b"secret").unwrap();
            let _ = fs::remove_file(dir.join("index.htm"));
            let _ = fs::remove_file(dir.join("index.html"));
            std::os::unix::fs::symlink(&outside, dir.join("index.html")).unwrap();
            assert!(
                directory_index(&dir, &dir).is_none(),
                "root 外的符号链接索引不得被服务"
            );
            // 指向 root 内的符号链接仍允许（web 服务器惯例）
            let inside = dir.join("real.html");
            fs::write(&inside, b"ok").unwrap();
            let _ = fs::remove_file(dir.join("index.html"));
            std::os::unix::fs::symlink(&inside, dir.join("index.html")).unwrap();
            assert!(directory_index(&dir, &dir).is_some(), "root 内互链仍应服务");
            let _ = fs::remove_file(&outside);
        }
        let _ = fs::remove_dir_all(&dir);
    }
        #[test]
    fn parse_range_basic_suffix_and_open_end() {
        assert_eq!(parse_range("bytes=0-9", 100), RangeSpec::Slice { start: 0, end: 9 });
        assert_eq!(parse_range("bytes=5-", 100), RangeSpec::Slice { start: 5, end: 99 });
        assert_eq!(parse_range("bytes=-10", 100), RangeSpec::Slice { start: 90, end: 99 });
        // 末端越界按 RFC 收窄到文件末尾
        assert_eq!(parse_range("bytes=0-999", 100), RangeSpec::Slice { start: 0, end: 99 });
        // range unit 大小写不敏感
        assert_eq!(parse_range("Bytes=0-9", 100), RangeSpec::Slice { start: 0, end: 9 });
    }

    #[test]
    fn parse_range_unsatisfiable_and_ignored() {
        assert_eq!(parse_range("bytes=100-", 100), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range("bytes=5-3", 100), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 100), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range("bytes=0-", 0), RangeSpec::Unsatisfiable);
        // 非法 / 多段：忽略 Range（回 200 全量），不能报 416
        assert_eq!(parse_range("items=0-9", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("bytes=0-9,20-29", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("bytes=abc-", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("bytes=", 100), RangeSpec::Ignore);
        // 畸形 last-pos / 前导 `+` / 内含空白：必须**忽略**整个 Range（回 200 全量），
        // 不能当成开放末端（`bytes=5-abc` → 206 bytes 5-1023，旧实现的 bug）或合法区间
        // （`bytes=+5-9` → 206，Rust parse 接受前导 `+`）。
        assert_eq!(parse_range("bytes=5-abc", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("bytes=5-1x", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("bytes=+5-9", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("bytes= 5-9", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("bytes=5- 9", 100), RangeSpec::Ignore);
        // 超长数字（parse 溢出）也不能 panic，按忽略处理
        assert_eq!(
            parse_range("bytes=99999999999999999999999-", 100),
            RangeSpec::Ignore
        );
        // 合法的开放末端仍必须工作
        assert_eq!(parse_range("bytes=5-", 100), RangeSpec::Slice { start: 5, end: 99 });
    }

    /// 大文件的 `bytes=N-`（curl -C - 等续传客户端的写法）必须回 206 的**子段**，
    /// 不能回 416 —— 否则 >MAX_RANGE_BYTES 的文件断点续传彻底不可用。
    #[test]
    fn parse_range_clamps_to_cap_instead_of_416() {
        let len = 100 * 1024 * 1024; // 100MiB
        match parse_range("bytes=0-", len) {
            RangeSpec::Slice { start, end } => {
                assert_eq!(start, 0);
                assert_eq!(end - start + 1, MAX_RANGE_BYTES);
            }
            other => panic!("expected slice, got {other:?}"),
        }
        // 从文件末尾前一个字节续传：不足上限，原样返回
        match parse_range(&format!("bytes={}-", len - 1), len) {
            RangeSpec::Slice { start, end } => assert_eq!((start, end), (len - 1, len - 1)),
            other => panic!("expected slice, got {other:?}"),
        }
        // suffix 收窄时保持尾部对齐
        match parse_range(&format!("bytes=-{len}"), len) {
            RangeSpec::Slice { start, end } => {
                assert_eq!(end, len - 1);
                assert_eq!(end - start + 1, MAX_RANGE_BYTES);
            }
            other => panic!("expected slice, got {other:?}"),
        }
    }

    /// engine_owns 依赖的归一化必须与 resolve_path / file_open 键一致，
    /// 否则 `/./php/x.php`、`/php/x.ph%70` 会绕过引擎判定被当静态文件吐源码。
    #[test]
    fn normalize_url_path_matches_resolution() {
        assert_eq!(normalize_url_path("/./php/x.php").as_deref(), Some("/php/x.php"));
        assert_eq!(normalize_url_path("//php/x.php").as_deref(), Some("/php/x.php"));
        assert_eq!(normalize_url_path("/php/x.ph%70").as_deref(), Some("/php/x.php"));
        assert_eq!(normalize_url_path("/php/x%2Ephp").as_deref(), Some("/php/x.php"));
        assert_eq!(normalize_url_path("/a/../b"), None);
        assert_eq!(normalize_url_path("/"), Some("/".to_string()));
    }

    /// ETag 列表匹配：`*`、弱比较、逗号列表、整体相等（含引号）。
    #[test]
    fn etag_list_matching() {
        let etag = "\"1f4-65a1b2c3\"";
        assert!(etag_list_matches("\"1f4-65a1b2c3\"", etag, false));
        assert!(etag_list_matches("\"aaa\", \"1f4-65a1b2c3\"", etag, false));
        assert!(etag_list_matches("W/\"1f4-65a1b2c3\"", etag, false));
        assert!(etag_list_matches("*", etag, false));
        assert!(!etag_list_matches("\"aaa\"", etag, false));
        assert!(!etag_list_matches("\"1f4\"", etag, false));
        assert!(!etag_list_matches("", etag, false));
    }

    /// RFC 9110 §13.2.2 求值顺序：If-Match → If-Unmodified-Since →
    /// If-None-Match → If-Modified-Since。
    #[test]
    fn conditional_eval_order_and_304() {
        let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let etag = "\"10-6553f100\"";
        let h = http::HeaderMap::new();
        assert_eq!(eval_conditions(&h, etag, Some(mtime), true), Cond::Proceed);

        let mut h = http::HeaderMap::new();
        h.insert(header::IF_NONE_MATCH, "\"10-6553f100\"".parse().unwrap());
        assert_eq!(eval_conditions(&h, etag, Some(mtime), true), Cond::NotModified);
        // 非 GET/HEAD 命中 If-None-Match → 412 而不是 304
        assert_eq!(
            eval_conditions(&h, etag, Some(mtime), false),
            Cond::PreconditionFailed
        );

        // If-Match 优先于 If-None-Match
        let mut h2 = http::HeaderMap::new();
        h2.insert(header::IF_NONE_MATCH, "\"10-6553f100\"".parse().unwrap());
        h2.insert(header::IF_MATCH, "\"deadbeef\"".parse().unwrap());
        assert_eq!(
            eval_conditions(&h2, etag, Some(mtime), true),
            Cond::PreconditionFailed
        );

        // If-Modified-Since：同一秒（秒精度）→ 304；更早 → 已修改 → Proceed
        let mut h3 = http::HeaderMap::new();
        h3.insert(
            header::IF_MODIFIED_SINCE,
            httpdate::fmt_http_date(mtime).parse().unwrap(),
        );
        assert_eq!(eval_conditions(&h3, etag, Some(mtime), true), Cond::NotModified);
        let older = mtime - std::time::Duration::from_secs(3600);
        let mut h4 = http::HeaderMap::new();
        h4.insert(
            header::IF_MODIFIED_SINCE,
            httpdate::fmt_http_date(older).parse().unwrap(),
        );
        assert_eq!(eval_conditions(&h4, etag, Some(mtime), true), Cond::Proceed);

        // If-Unmodified-Since：已修改 → 412
        let mut h5 = http::HeaderMap::new();
        h5.insert(
            header::IF_UNMODIFIED_SINCE,
            httpdate::fmt_http_date(older).parse().unwrap(),
        );
        assert_eq!(
            eval_conditions(&h5, etag, Some(mtime), true),
            Cond::PreconditionFailed
        );
    }

    /// If-Range：不符 / 弱标记 / 无法解析 → 必须忽略 Range（回 200 全量），
    /// 否则续传客户端会把新文件的旧偏移片段拼进结果里。
    #[test]
    fn if_range_gate_blocks_stale_resume() {
        let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let etag = "\"10-6553f100\"";
        let mk = |v: &str| {
            let mut h = http::HeaderMap::new();
            h.insert(header::IF_RANGE, v.parse().unwrap());
            h
        };
        assert!(if_range_allows(&http::HeaderMap::new(), etag, Some(mtime)));
        assert!(if_range_allows(&mk("\"10-6553f100\""), etag, Some(mtime)));
        assert!(!if_range_allows(&mk("\"other\""), etag, Some(mtime)));
        // 弱验证器不能用于 If-Range（强比较）
        assert!(!if_range_allows(&mk("W/\"10-6553f100\""), etag, Some(mtime)));
        // 日期形式：同秒可用、更早不可用
        assert!(if_range_allows(
            &mk(&httpdate::fmt_http_date(mtime)),
            etag,
            Some(mtime)
        ));
        let older = mtime - std::time::Duration::from_secs(60);
        assert!(!if_range_allows(
            &mk(&httpdate::fmt_http_date(older)),
            etag,
            Some(mtime)
        ));
        // 垃圾值 → 保守忽略 Range
        assert!(!if_range_allows(&mk("garbage"), etag, Some(mtime)));
    }

    /// mtime 必须截断到秒（HTTP 日期只有秒精度），否则 If-Modified-Since 会把
    /// 同一秒内的请求误判成「已修改」，条件请求永远拿不到 304。
    #[test]
    fn validators_truncate_mtime_to_seconds() {
        let meta = fs::metadata("src/server/static_files.rs")
            .or_else(|_| fs::metadata("Cargo.toml"))
            .expect("cwd 应为 crate 根");
        let (etag, mtime) = validators(&meta);
        assert!(etag.starts_with('"') && etag.ends_with('"'), "etag={etag}");
        let m = mtime.expect("mtime");
        let rt = httpdate::parse_http_date(&httpdate::fmt_http_date(m)).expect("roundtrip");
        assert_eq!(trunc_to_secs(rt), m, "mtime 未截断到秒");
    }

    /// If-Range 的**日期**形式必须与 Last-Modified 精确相等（RFC 9110 §13.1.5 第 2 步）。
    /// 更宽松的 `mtime <= date` 会让时钟偏快的客户端用未来日期蒙过校验，
    /// 从而拿到新文件的旧偏移片段。
    #[test]
    fn if_range_date_must_match_exactly() {
        let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let etag = "\"10-6553f100\"";
        let mk = |v: &str| {
            let mut h = http::HeaderMap::new();
            h.insert(header::IF_RANGE, v.parse().unwrap());
            h
        };
        // 精确相等 → 可用
        assert!(if_range_allows(
            &mk(&httpdate::fmt_http_date(mtime)),
            etag,
            Some(mtime)
        ));
        // 未来日期（时钟偏快的客户端）→ **不可用**（旧实现 m <= t 会错误放行）
        let future = mtime + std::time::Duration::from_secs(3600);
        assert!(
            !if_range_allows(&mk(&httpdate::fmt_http_date(future)), etag, Some(mtime)),
            "未来日期不得通过 If-Range（否则续传拿到旧偏移的新内容）"
        );
        // 更早 → 不可用
        let older = mtime - std::time::Duration::from_secs(60);
        assert!(!if_range_allows(
            &mk(&httpdate::fmt_http_date(older)),
            etag,
            Some(mtime)
        ));
    }

    /// 强/弱比较的区分（RFC 9110 §8.8.3.2）：`If-Match` 用强比较（弱验证器永不匹配），
    /// `If-None-Match` 用弱比较（弱验证器也能匹配 → 304）。
    #[test]
    fn if_match_strong_vs_if_none_match_weak() {
        let etag = "\"1f4-65a1b2c3-123\"";
        assert!(etag_list_matches("\"1f4-65a1b2c3-123\"", etag, true));
        assert!(
            !etag_list_matches("W/\"1f4-65a1b2c3-123\"", etag, true),
            "If-Match 是强比较：弱验证器不得匹配"
        );
        assert!(
            etag_list_matches("W/\"1f4-65a1b2c3-123\"", etag, false),
            "If-None-Match 是弱比较：弱验证器应当匹配"
        );
        // 本地 ETag 本身带 W/ 时，强比较同样不成立
        assert!(!etag_list_matches("\"1f4-65a1b2c3-123\"", "W/\"1f4-65a1b2c3-123\"", true));
        assert!(etag_list_matches("\"1f4-65a1b2c3-123\"", "W/\"1f4-65a1b2c3-123\"", false));
        // `*` 两种比较都匹配任何现有表示
        assert!(etag_list_matches("*", etag, true));
        assert!(etag_list_matches("*", etag, false));
    }

    /// ETag / 小文件缓存必须能识别「**原子替换**成同长度文件」。
    ///
    /// 这是真实部署形态：上传 commit 是 `rename`，`sed -i`/`cp` 也会换 inode。
    /// 只比 mtime 时，粗粒度时钟（jiffy）下同一 tick 内的等长改写会得到**完全相同**的
    /// mtime → `If-None-Match` 误回 304、缓存发旧内容。inode 能兜住这条路径。
    #[test]
    fn etag_and_cache_detect_atomic_replace() {
        let dir = std::env::temp_dir().join(format!("crucible-etag-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.txt");
        fs::write(&p, b"AAAA").unwrap();
        let m1 = fs::metadata(&p).unwrap();
        let (e1, _) = validators(&m1);
        assert_eq!(read_cached(&p, &m1).unwrap().as_ref(), b"AAAA");

        // 原子替换：写临时文件再 rename（同长度）
        let t = dir.join(".a.txt.upload.part");
        fs::write(&t, b"BBBB").unwrap();
        fs::rename(&t, &p).unwrap();
        let m2 = fs::metadata(&p).unwrap();
        let (e2, _) = validators(&m2);
        assert_ne!(
            e1, e2,
            "原子替换（inode 变化）必须产生不同 ETag —— 否则 If-None-Match 会误回 304 让客户端吃旧内容"
        );
        // 缓存必须重读，不能把旧内容当当前表示发出去
        assert_eq!(
            read_cached(&p, &m2).unwrap().as_ref(),
            b"BBBB",
            "原子替换后小文件缓存必须刷新（否则发送的是旧内容）"
        );
        // 内容确实没变时，缓存仍应命中（避免每次都重读）
        assert_eq!(read_cached(&p, &m2).unwrap().as_ref(), b"BBBB");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 多段 Range：解析、合并（重叠/近邻）、单段回落、不可满足、畸形忽略。
    #[test]
    fn multi_range_parse_and_coalesce() {
        // 两段明显分开且间隔 > 128 → 保持两段
        match parse_ranges("bytes=0-9,1000-1009", 4096) {
            MultiRange::Ranges { ranges, coalesced_single } => {
                assert!(!coalesced_single);
                assert_eq!(ranges.len(), 2);
                assert_eq!((ranges[0].start, ranges[0].end), (0, 9));
                assert_eq!((ranges[1].start, ranges[1].end), (1000, 1009));
            }
            other => panic!("expected 2 ranges, got {other:?}"),
        }
        // 重叠 → 合并成一段
        match parse_ranges("bytes=0-99,50-149", 4096) {
            MultiRange::Ranges { ranges, coalesced_single } => {
                assert!(coalesced_single, "重叠段必须合并成一段");
                assert_eq!(ranges.len(), 1);
                assert_eq!((ranges[0].start, ranges[0].end), (0, 149));
            }
            other => panic!("expected merged single, got {other:?}"),
        }
        // 间隔很小（< 128）→ 合并
        match parse_ranges("bytes=0-9,20-29", 4096) {
            MultiRange::Ranges { coalesced_single, .. } => assert!(coalesced_single),
            other => panic!("expected coalesced, got {other:?}"),
        }
        // 乱序输入 → 输出按 start 升序
        match parse_ranges("bytes=2000-2009,0-9", 4096) {
            MultiRange::Ranges { ranges, .. } => {
                assert!(ranges[0].start < ranges[1].start, "必须按位置排序");
            }
            other => panic!("expected 2 ranges, got {other:?}"),
        }
        // 部分段不可满足（超出文件尾）→ 丢弃该段，其余仍满足
        match parse_ranges("bytes=0-9,99999-", 100) {
            MultiRange::Ranges { ranges, .. } => {
                assert_eq!(ranges.len(), 1);
                assert_eq!((ranges[0].start, ranges[0].end), (0, 9));
            }
            other => panic!("expected 1 satisfiable range, got {other:?}"),
        }
        // 全部不可满足 → 416（不是忽略）
        assert_eq!(parse_ranges("bytes=200-300,400-500", 100), MultiRange::Unsatisfiable);
        // 畸形（空元素 / 非数字 / 单位错）→ 忽略整条
        assert_eq!(parse_ranges("bytes=0-9,", 100), MultiRange::Ignore);
        assert_eq!(parse_ranges("bytes=0-9,,20-29", 100), MultiRange::Ignore);
        assert_eq!(parse_ranges("bytes=0-abc,20-29", 100), MultiRange::Ignore);
        assert_eq!(parse_ranges("items=0-9,20-29", 100), MultiRange::Ignore);
        // 单段走同一入口时行为不变（含 suffix 与开放末端）
        match parse_ranges("bytes=-10", 100) {
            MultiRange::Ranges { ranges, coalesced_single } => {
                assert!(coalesced_single);
                assert_eq!((ranges[0].start, ranges[0].end), (90, 99));
            }
            other => panic!("expected suffix single, got {other:?}"),
        }
    }

    /// 多段响应的**内存护栏**：段数与总字节都必须在 `MAX_RANGE_BYTES` 量级封顶，
    /// 否则「同一区间重复 N 次」的请求能把内存放大 N 倍。
    #[test]
    fn multi_range_is_capped() {
        let mut s = String::from("bytes=");
        for i in 0..2000u64 {
            if i > 0 {
                s.push(',');
            }
            // 每段 64KiB，间隔远大于合并阈值
            let start = i * 1024 * 1024;
            s.push_str(&format!("{}-{}", start, start + 65535));
        }
        match parse_ranges(&s, 4 * 1024 * 1024 * 1024) {
            MultiRange::Ranges { ranges, .. } => {
                let capped = cap_ranges(&ranges);
                assert!(capped.len() <= MAX_RANGE_PARTS, "段数必须封顶");
                let total: u64 = capped.iter().map(|r| r.len()).sum();
                assert!(
                    total <= MAX_TOTAL_RANGE_BYTES,
                    "总字节必须封顶（实得 {total}）"
                );
            }
            other => panic!("expected ranges, got {other:?}"),
        }
    }

    /// HEAD 的多段响应必须给出**精确**的 `Content-Length`（不读数据）。
    #[test]
    fn head_multi_range_length_matches_render() {
        let dir = std::env::temp_dir().join(format!("crucible-mp-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("mp.bin");
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        fs::write(&p, &data).unwrap();
        let range = "bytes=0-9,2000-2009";
        let outcome = head_range_outcome(4096, range, "application/octet-stream");
        let (ct, cl) = match outcome {
            RangeOutcome::Multi {
                content_type,
                content_length,
                ..
            } => (content_type, content_length),
            other => panic!("expected multi, got {}", matches!(other, RangeOutcome::Ignore)),
        };
        assert!(ct.starts_with("multipart/byteranges; boundary="), "ct={ct}");
        let boundary = ct.split("boundary=").nth(1).unwrap().to_string();
        let ranges = match parse_ranges(range, 4096) {
            MultiRange::Ranges { ranges, .. } => cap_ranges(&ranges),
            _ => unreachable!(),
        };
        let plan = multipart_plan(4096, &ranges, "application/octet-stream");
        let body = render_multipart(&p, &plan).unwrap();
        assert_eq!(body.len() as u64, cl, "HEAD 的 Content-Length 必须与真实正文一致");
        assert_eq!(plan.body_len(), cl);
        // 分片头必须带各自的 Content-Range；顶层不带
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("bytes 0-9/4096"), "{text}");
        assert!(text.contains("bytes 2000-2009/4096"), "{text}");
        assert!(text.contains(&format!("--{boundary}")));
        assert!(text.trim_end().ends_with(&format!("--{boundary}--")));
        // 各片数据必须正确
        assert!(body.windows(10).any(|w| w == &data[0..10]));
        assert!(body.windows(10).any(|w| w == &data[2000..2010]));
        let _ = fs::remove_dir_all(&dir);
    }

    /// 目录跳转：`/dir` → 301 `/dir/`（保留 query）；`/dir/` 不跳。
    #[test]
    fn dir_redirect_preserves_query() {
        let uri: http::Uri = "/up?x=1&y=2".parse().unwrap();
        let loc = dir_redirect_location(&uri).expect("应产生跳转");
        assert_eq!(loc.to_str().unwrap(), "/up/?x=1&y=2");
        let uri: http::Uri = "/up/".parse().unwrap();
        assert!(dir_redirect_location(&uri).is_none(), "带尾斜杠不应跳转");
        let uri: http::Uri = "/".parse().unwrap();
        assert!(dir_redirect_location(&uri).is_none(), "根路径不跳转");
        let uri: http::Uri = "/a/b".parse().unwrap();
        assert_eq!(dir_redirect_location(&uri).unwrap(), "/a/b/");
    }
}
