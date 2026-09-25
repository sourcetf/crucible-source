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

use std::time::SystemTime;

const SMALL_FILE_MAX: u64 = 256 * 1024;
const CACHE_CAP: usize = 256;

struct CacheEntry {
    mtime: SystemTime,
    data: Bytes,
    content_type: String,
}

static SMALL_CACHE: Lazy<Mutex<HashMap<PathBuf, CacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));


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

pub async fn serve(req: &Request<Incoming>, lc: &ListenerConfig) -> Result<Response<BoxBody>> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(full("method not allowed"))
            .unwrap());
    }
    let path = req.uri().path();
    let fs_path = resolve_path(&lc.root, path)?;
    let meta = fs::metadata(&fs_path)?;
    if meta.is_dir() {
        if lc.autoindex.allows(path) {
            return Ok(autoindex(&fs_path, path, lc.autoindex.enabled && lc.autoindex.enable_upload)?);
        }
        bail!("directory");
    }
    let mode = lc.file_open_mode(path);
    // §16.2：static 层不得替引擎把「应执行的脚本」当普通文件吐出去（见 engine_owns）。
    if engine_owns(lc, path, mode) {
        bail!("path is owned by an app engine");
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
        Some(normalized) => crate::server::apps::would_handle(lc, &normalized),
        // 归一化失败（含 `..` 等，resolve_path 本已拒绝）：fail-closed。
        None => true,
    }
}

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

pub async fn serve_simple<T>(req: &Request<T>, lc: &ListenerConfig) -> Result<Response<Bytes>> {
    // 与 h1 的 static_files::serve 对齐：非 GET/HEAD 一律 405。
    // 此前 serve_simple 根本不看方法，于是 h2/h3 上 `POST/PUT/DELETE /index.html`
    // 会拿到 200 + 文件正文（同一 URL 在 h1 上是 405）——行为随协议而变。
    let method = req.method();
    if method != Method::GET && method != Method::HEAD {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Bytes::from_static(b"method not allowed"))
            .unwrap());
    }
    let path = req.uri().path();
    let fs_path = resolve_path(&lc.root, path)?;
    let meta = fs::metadata(&fs_path)?;
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

    let len = meta.len();
    // HEAD 短路必须与 h1 一致（h1 已修，h2/h3 漏了）：此前 HEAD 照样整读文件并
    // 经 DATA 帧把正文发上线——RFC 9110 §9.3.2 禁止 HEAD 响应带内容，且一个
    // `HEAD /big.bin` 就能造成最多 16MiB 的读放大 + 上线放大。
    if method == Method::HEAD {
        let mut b = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, ct)
            .header(header::CONTENT_LENGTH, len)
            .header(header::ACCEPT_RANGES, "bytes");
        if let Some(d) = disposition {
            b = b.header(header::CONTENT_DISPOSITION, disposition_value(&fs_path, d));
            b = b.header("x-content-type-options", "nosniff");
        }
        return Ok(b.body(Bytes::new()).unwrap());
    }

    // Range/206：h2/h3 此前完全不支持 Range。浏览器/播放器默认走 h2/h3，
    // 于是「下载断点续传」在主协议上不可用，而且超过 MAX_FULL_READ 的文件
    // 只能拿到下面的 413（等于完全下不动）。这里补上与 h1 相同的单段 Range 语义。
    if let Some(rr) = req.headers().get(header::RANGE).and_then(|v| v.to_str().ok()) {
        match parse_range(rr, len) {
            RangeSpec::Slice { start, end } => {
                let buf = read_slice(&fs_path, start, end)?;
                let mut b = Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(header::CONTENT_TYPE, ct)
                    .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                    .header(header::CONTENT_LENGTH, buf.len())
                    .header(header::ACCEPT_RANGES, "bytes");
                if let Some(d) = disposition {
                    // 206 同样要带 disposition + nosniff：preview/download 的强制
                    // 语义不能因为客户端多发一个 Range 头就被绕过。
                    b = b.header(header::CONTENT_DISPOSITION, disposition_value(&fs_path, d));
                    b = b.header("x-content-type-options", "nosniff");
                }
                return Ok(b.body(Bytes::from(buf)).unwrap());
            }
            RangeSpec::Unsatisfiable => {
                return Ok(Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{len}"))
                    .body(Bytes::new())
                    .unwrap());
            }
            RangeSpec::Ignore => {}
        }
    }

    // 超大文件：h2/h3 没有流式实现，不能整读进内存。
    // 明确回 413（此前 read_file_capped 报错被上层统一映射成 404，
    // 把「文件太大」误报成「文件不存在」）。带 Range 的请求已在上面走 206，
    // 所以大文件仍可分段/续传下载。
    if len > MAX_FULL_READ {
        return Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Bytes::from(format!(
                "file too large for this protocol ({len} bytes > {MAX_FULL_READ}); use Range\n"
            )))
            .unwrap());
    }
    // 只有小文件才进缓存，否则 256 条 × 16MiB 会把常驻内存撑到数 GiB。
    let data = if len <= SMALL_FILE_MAX {
        read_cached(&fs_path, &meta)?
    } else {
        Bytes::from(read_file_capped(&fs_path)?)
    };
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ct)
        .header(header::CONTENT_LENGTH, data.len())
        .header(header::ACCEPT_RANGES, "bytes");
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
    let joined = root.join(&decoded);
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
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
    Ok(canon)
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

    // HEAD 必须在 Range 与整读**之前**短路。hyper 会丢弃 HEAD 的 body，但这里
    // 仍会 range_response（最多 32MiB 的 vec![0u8; take] + read_exact）或
    // read_file_capped（最多 16MiB）把数据读一遍再扔掉 —— 一个 ~120 字节的
    // `HEAD /big.bin` + `Range: bytes=0-33554431` 就是一次 32MiB 放大。
    if req.method() == Method::HEAD {
        let mut b = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, ct)
            .header(header::CONTENT_LENGTH, len)
            .header(header::ACCEPT_RANGES, "bytes");
        if let Some(d) = disposition {
            b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
            b = b.header("x-content-type-options", "nosniff");
        }
        return Ok(b.body(empty()).unwrap());
    }

    if let Some(range) = req.headers().get(header::RANGE) {
        if let Ok(r) = range.to_str() {
            if let Some(resp) = range_response(path, len, r, &ct, disposition)? {
                return Ok(resp);
            }
        }
    }

    // 整读上限必须在这里显式回 413：此前直接落到 read_file_capped，它 bail 出来的
    // Err 被 dispatch_tail 统一映射成 404「not found」——「文件太大」被谎报成
    // 「文件不存在」（h2/h3 侧已修，h1 侧漏了；纯 GET 一个 >16MiB 的文件，
    // 浏览器不带 Range，就是这条路径）。本实现无流式 body，只能如实回 413，
    // 并带上 Accept-Ranges 提示改用 Range 分段取（带 Range 的请求走上面的 206）。
    if len > MAX_FULL_READ {
        let mut b = Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::ACCEPT_RANGES, "bytes");
        if let Some(d) = disposition {
            b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
            b = b.header("x-content-type-options", "nosniff");
        }
        return Ok(b
            .body(full(format!(
                "file too large for a single response ({len} bytes > {MAX_FULL_READ}); use Range\n"
            )))
            .unwrap());
    }

    let data = if len <= SMALL_FILE_MAX {
        read_cached(path, meta)?
    } else {
        Bytes::from(read_file_capped(path)?)
    };

    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ct)
        .header(header::CONTENT_LENGTH, data.len())
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some(d) = disposition {
        // 预览与下载响应禁 MIME 嗅探（浏览器不得把 text/plain 拉去执行）。
        b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
        b = b.header("x-content-type-options", "nosniff");
    }
    Ok(b.body(full(data)).unwrap())
}

fn read_cached(path: &Path, meta: &std::fs::Metadata) -> Result<Bytes> {
    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    {
        let cache = SMALL_CACHE.lock();
        if let Some(e) = cache.get(path) {
            if e.mtime == mtime {
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
            mtime,
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

/// 解析单段 Range（RFC 7233 §2.1）：支持 `bytes=N-M`、`bytes=N-`、`bytes=-N`。
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
        let Ok(n) = end_s.parse::<u64>() else {
            return RangeSpec::Ignore;
        };
        if n == 0 || len == 0 {
            return RangeSpec::Unsatisfiable;
        }
        (len.saturating_sub(n), len.saturating_sub(1))
    } else {
        let Ok(s) = start_s.parse::<u64>() else {
            return RangeSpec::Ignore;
        };
        let e = match end_s.parse::<u64>() {
            Ok(e) => e.min(len.saturating_sub(1)),
            Err(_) => len.saturating_sub(1), // 开放末端 bytes=5-
        };
        (s, e)
    };
    if len == 0 || start >= len || start > end {
        return RangeSpec::Unsatisfiable;
    }
    // DoS 护栏：单段响应体的内存上限。超限**不能**回 416 —— `bytes=N-`
    // （curl -C - 等续传客户端的写法）在大文件上必然超限，回 416 会让
    // 「下载断点续传」彻底不可用（curl 会直接判定 "doesn't support byte ranges"）。
    // RFC 7233 §4.1 允许服务器只回请求区间的一个子集，客户端按 Content-Range
    // 里的实际区间继续请求剩余部分，所以这里改为按上限收窄而不是拒绝。
    if end - start + 1 > MAX_RANGE_BYTES {
        let cap = MAX_RANGE_BYTES - 1;
        // suffix 请求要的是文件尾部，收窄时保持尾部对齐；显式请求保持头部对齐。
        return if suffix {
            RangeSpec::Slice { start: end - cap, end }
        } else {
            RangeSpec::Slice { start, end: start + cap }
        };
    }
    RangeSpec::Slice { start, end }
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

fn range_response(
    path: &Path,
    len: u64,
    range: &str,
    ct: &str,
    disposition: Option<&str>,
) -> Result<Option<Response<BoxBody>>> {
    // P2-2（RFC7233）：支持 suffix（bytes=-N）与显式 end；start>=len / start>end → 416
    //（带 Content-Range: bytes */len）；非法格式与多段不启用 Range 语义（回 200 全量）。
    match parse_range(range, len) {
        RangeSpec::Ignore => Ok(None),
        RangeSpec::Unsatisfiable => Ok(Some(
            Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{len}"))
                .body(empty())
                .unwrap(),
        )),
        RangeSpec::Slice { start, end } => {
            let buf = read_slice(path, start, end)?;
            let mut b = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, ct)
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                .header(header::CONTENT_LENGTH, buf.len())
                .header(header::ACCEPT_RANGES, "bytes");
            if let Some(d) = disposition {
                // 206 也必须带 disposition + nosniff：否则「preview 强制
                // text/plain + nosniff」这条缓解只要客户端多发一个 Range 头就失效
                // （200/HEAD 都有，唯独 206 漏了）。
                b = b.header(header::CONTENT_DISPOSITION, disposition_value(path, d));
                b = b.header("x-content-type-options", "nosniff");
            }
            Ok(Some(b.body(full(Bytes::from(buf))).unwrap()))
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
    let mut entries: Vec<_> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
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
        body.push_str(
            "<hr><p><b>上传</b>（支持断点续传：中断后再选同一文件会从中断处继续）</p>"
                .as_ref(),
        );
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
}
