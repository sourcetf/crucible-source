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
            return Ok(autoindex(&fs_path, path)?);
        }
        bail!("directory");
    }
    let mode = lc.file_open_mode(path);
    serve_file(req, &fs_path, &meta, mode).await
}

pub async fn serve_simple<T>(req: &Request<T>, lc: &ListenerConfig) -> Result<Response<Bytes>> {
    let path = req.uri().path();
    let fs_path = resolve_path(&lc.root, path)?;
    let meta = fs::metadata(&fs_path)?;
    if meta.is_dir() {
        if lc.autoindex.allows(path) {
            let html = autoindex_html(&fs_path, path)?;
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

    // 超大文件：h2/h3 没有 Range/流式实现，不能整读进内存。
    // 明确回 413（此前 read_file_capped 报错被上层统一映射成 404，
    // 把「文件太大」误报成「文件不存在」）。
    let len = meta.len();
    if len > MAX_FULL_READ {
        return Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Bytes::from(format!(
                "file too large for this protocol ({len} bytes > {MAX_FULL_READ}); use HTTP/1.1 with Range\n"
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
        .header(header::CONTENT_LENGTH, data.len());
    if let Some(d) = disposition {
        let name = fs_path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
        let safe_name: String = name
            .chars()
            .map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' { c } else { '_' })
            .collect();
        b = b.header(
            header::CONTENT_DISPOSITION,
            format!("{d}; filename=\"{safe_name}\""),
        );
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

    let data = if len <= SMALL_FILE_MAX {
        read_cached(path, meta)?
    } else {
        Bytes::from(read_file_capped(path)?)
    };

    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ct)
        .header(header::CONTENT_LENGTH, data.len());
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

fn range_response(
    path: &Path,
    len: u64,
    range: &str,
    ct: &str,
    disposition: Option<&str>,
) -> Result<Option<Response<BoxBody>>> {
    // P2-2（RFC7233）：支持 suffix（bytes=-N）与显式 end；start>=len / start>end → 416
    //（带 Content-Range: bytes *  /len）；多段与非法格式不启用 Range 语义（回 200 全量，
    //  RFC 允许服务器忽略 Range）；单段上限超 MAX_RANGE_BYTES → 416 提示客户端缩小范围。
    let range = range.trim();
    let Some(rest) = range.strip_prefix("bytes=") else {
        return Ok(None);
    };
    if rest.contains(',') {
        return Ok(None);
    }
    let Some((start_s, end_s)) = rest.split_once('-') else {
        return Ok(None);
    };
    let not_satisfiable = || {
        Some(
            Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{len}"))
                .body(empty())
                .unwrap(),
        )
    };
    let (start, end) = if start_s.is_empty() {
        // suffix 形式：bytes=-N → 最后 N 字节
        let Ok(n) = end_s.parse::<u64>() else {
            return Ok(None);
        };
        if n == 0 || len == 0 {
            return Ok(not_satisfiable());
        }
        (len.saturating_sub(n), len.saturating_sub(1))
    } else {
        let Ok(s) = start_s.parse::<u64>() else {
            return Ok(None);
        };
        let e = match end_s.parse::<u64>() {
            Ok(e) => e.min(len.saturating_sub(1)),
            Err(_) => len.saturating_sub(1), // 开放末端 bytes=5-
        };
        (s, e)
    };
    if len == 0 || start >= len || start > end {
        return Ok(not_satisfiable());
    }
    let take_u64 = end - start + 1;
    if take_u64 > MAX_RANGE_BYTES {
        return Ok(not_satisfiable());
    }
    let mut f = fs::File::open(path)?;
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::Start(start))?;
    let take = take_u64 as usize;
    let mut buf = vec![0u8; take];
    f.read_exact(&mut buf)?;
    let mut b = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(header::CONTENT_TYPE, ct)
        .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
        .header(header::CONTENT_LENGTH, take);
    if let Some(d) = disposition {
        b = b.header(header::CONTENT_DISPOSITION, d);
    }
    Ok(Some(b.body(full(Bytes::from(buf))).unwrap()))
}

fn autoindex(dir: &Path, url: &str) -> Result<Response<BoxBody>> {
    let html = autoindex_html(dir, url)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full(html))
        .unwrap())
}

fn autoindex_html(dir: &Path, url: &str) -> Result<String> {
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
        body.push_str(&format!("<li><a href=\"{href}\">{label}</a></li>"));
    }
    body.push_str("</ul></body></html>");
    Ok(body)
}
