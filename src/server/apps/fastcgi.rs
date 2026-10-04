//! Minimal FastCGI client over Unix or TCP streams.
//! 实现足够的 Responder 角色：BEGIN_REQUEST + PARAMS + STDIN → STDOUT/END_REQUEST。

use anyhow::{bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[cfg(unix)]
use tokio::net::UnixStream;

const FCGI_VERSION: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_RESPONDER: u16 = 1;
const FCGI_KEEP_CONN: u8 = 1;

/// Socket address: `unix:/abs/path` or `tcp:host:port` / `127.0.0.1:9000`.
#[derive(Debug, Clone)]
pub enum FcgiAddr {
    #[cfg(unix)]
    Unix(std::path::PathBuf),
    Tcp(String),
}

impl FcgiAddr {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some(p) = s.strip_prefix("unix:") {
            #[cfg(unix)]
            {
                return Ok(FcgiAddr::Unix(std::path::PathBuf::from(p)));
            }
            #[cfg(not(unix))]
            {
                let _ = p;
                bail!("unix FastCGI sockets require Unix OS");
            }
        }
        let addr = s.strip_prefix("tcp:").unwrap_or(s);
        Ok(FcgiAddr::Tcp(addr.to_string()))
    }
}

pub struct FcgiRequest {
    pub method: String,
    pub script_filename: String,
    pub document_root: String,
    pub request_uri: String,
    pub query_string: String,
    pub content_type: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub server_name: String,
    pub server_port: u16,
    pub https: bool,
    /// CGI SCRIPT_NAME 语义：脚本相对文档根的路径（如 `/index.php`），**不是**客户端 URI。
    pub script_name: String,
    /// CGI PATH_INFO：脚本名之后的剩余路径段，无则为空串。
    pub path_info: String,
    /// 客户端请求头：按 CGI 语义转成 `HTTP_*` params（hop-by-hop 头除外）。
    pub headers: HeaderMap,
    pub body: Bytes,
    pub extra_params: HashMap<String, String>,
}

pub struct FcgiResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// 一次 FastCGI 往返的墙钟上限。
///
/// 上游是 php-fpm，也可能是运维配置的 `engine = "fastcgi"` + `socket = <任意地址>`：
/// 一个「接受连接但永不发 FCGI_END_REQUEST」的上游会让请求任务永久挂着（且内存随
/// 累积的 STDOUT 增长）。这条路径此前**没有任何超时**。
const FCGI_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// STDOUT + STDERR 的合计上限：上游一直灌数据时不能把内存吃光。
const FCGI_OUTPUT_CAP: usize = 32 * 1024 * 1024;

pub async fn exchange(addr: &FcgiAddr, req: &FcgiRequest) -> Result<FcgiResponse> {
    match tokio::time::timeout(FCGI_TIMEOUT, exchange_inner(addr, req)).await {
        Ok(r) => r,
        Err(_) => bail!("fastcgi: 上游响应超时（{FCGI_TIMEOUT:?}）"),
    }
}

async fn exchange_inner(addr: &FcgiAddr, req: &FcgiRequest) -> Result<FcgiResponse> {
    match addr {
        #[cfg(unix)]
        FcgiAddr::Unix(path) => {
            let mut stream = UnixStream::connect(path)
                .await
                .with_context(|| format!("connect unix {}", path.display()))?;
            exchange_stream(&mut stream, req).await
        }
        FcgiAddr::Tcp(addr) => {
            let mut stream = TcpStream::connect(addr)
                .await
                .with_context(|| format!("connect tcp {addr}"))?;
            exchange_stream(&mut stream, req).await
        }
    }
}

async fn exchange_stream<S>(stream: &mut S, req: &FcgiRequest) -> Result<FcgiResponse>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let request_id: u16 = 1;
    let mut out = BytesMut::new();

    // BEGIN_REQUEST
    let mut br = [0u8; 8];
    br[0] = (FCGI_RESPONDER >> 8) as u8;
    br[1] = (FCGI_RESPONDER & 0xff) as u8;
    br[2] = FCGI_KEEP_CONN;
    write_record(&mut out, FCGI_BEGIN_REQUEST, request_id, &br);

    // PARAMS
    let params = build_params(req);
    // 分块写 PARAMS（避免超大记录）；最后空 PARAMS 结束
    for chunk in params.chunks(65528) {
        write_record(&mut out, FCGI_PARAMS, request_id, chunk);
    }
    write_record(&mut out, FCGI_PARAMS, request_id, &[]);

    // STDIN
    for chunk in req.body.chunks(65528) {
        write_record(&mut out, FCGI_STDIN, request_id, chunk);
    }
    write_record(&mut out, FCGI_STDIN, request_id, &[]);

    stream.write_all(&out).await.context("fcgi write")?;
    stream.flush().await.ok();

    let mut stdout = BytesMut::new();
    let mut stderr = BytesMut::new();
    loop {
        let (rtype, rid, content) = read_record(stream).await?;
        if rid != request_id && rid != 0 {
            continue;
        }
        // 每个分片都要卡总上限：上游一直灌数据时，此前 stdout/stderr 会无限增长到 OOM。
        if stdout.len() + stderr.len() > FCGI_OUTPUT_CAP {
            bail!("fastcgi: 上游输出超过上限 {FCGI_OUTPUT_CAP} 字节");
        }
        match rtype {
            FCGI_STDOUT => {
                if content.is_empty() {
                    // empty stdout record ends stdout stream, keep reading END
                } else {
                    stdout.extend_from_slice(&content);
                }
            }
            FCGI_STDERR => {
                stderr.extend_from_slice(&content);
            }
            FCGI_END_REQUEST => break,
            _ => {}
        }
    }

    if !stderr.is_empty() {
        log::debug!(
            "fcgi stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
    }

    parse_cgi_response(stdout.freeze())
}

fn write_record(buf: &mut BytesMut, rtype: u8, request_id: u16, content: &[u8]) {
    let clen = content.len();
    let pad = (8 - (clen % 8)) % 8;
    buf.put_u8(FCGI_VERSION);
    buf.put_u8(rtype);
    buf.put_u8((request_id >> 8) as u8);
    buf.put_u8((request_id & 0xff) as u8);
    buf.put_u8((clen >> 8) as u8);
    buf.put_u8((clen & 0xff) as u8);
    buf.put_u8(pad as u8);
    buf.put_u8(0);
    buf.extend_from_slice(content);
    for _ in 0..pad {
        buf.put_u8(0);
    }
}

fn write_nv(buf: &mut BytesMut, name: &str, value: &str) {
    let nb = name.as_bytes();
    let vb = value.as_bytes();
    write_len(buf, nb.len());
    write_len(buf, vb.len());
    buf.extend_from_slice(nb);
    buf.extend_from_slice(vb);
}

fn write_len(buf: &mut BytesMut, len: usize) {
    if len < 128 {
        buf.put_u8(len as u8);
    } else {
        let n = len as u32;
        buf.put_u8(((n >> 24) | 0x80) as u8);
        buf.put_u8((n >> 16) as u8);
        buf.put_u8((n >> 8) as u8);
        buf.put_u8(n as u8);
    }
}

async fn read_record<S>(stream: &mut S) -> Result<(u8, u16, Vec<u8>)>
where
    S: AsyncReadExt + Unpin,
{
    let mut hdr = [0u8; 8];
    stream.read_exact(&mut hdr).await.context("fcgi header")?;
    if hdr[0] != FCGI_VERSION {
        bail!("bad fcgi version {}", hdr[0]);
    }
    let rtype = hdr[1];
    let rid = ((hdr[2] as u16) << 8) | hdr[3] as u16;
    let clen = ((hdr[4] as usize) << 8) | hdr[5] as usize;
    let pad = hdr[6] as usize;
    let mut content = vec![0u8; clen];
    if clen > 0 {
        stream
            .read_exact(&mut content)
            .await
            .context("fcgi content")?;
    }
    if pad > 0 {
        let mut p = vec![0u8; pad];
        stream.read_exact(&mut p).await.context("fcgi pad")?;
    }
    Ok((rtype, rid, content))
}

fn parse_cgi_response(raw: Bytes) -> Result<FcgiResponse> {
    // CGI/1.1: headers then blank line then body
    let sep = find_header_sep(&raw);
    let (head, body) = if let Some(i) = sep {
        (raw.slice(..i), raw.slice(i..))
    } else {
        (Bytes::new(), raw)
    };
    // skip blank line bytes in body
    let body = if body.starts_with(b"\r\n\r\n") {
        body.slice(4..)
    } else if body.starts_with(b"\n\n") {
        body.slice(2..)
    } else {
        body
    };

    let mut status = StatusCode::OK;
    let mut headers = HeaderMap::new();
    let head_str = String::from_utf8_lossy(&head);
    for line in head_str.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("Status") {
                if let Some(code) = v.split_whitespace().next() {
                    if let Ok(n) = code.parse::<u16>() {
                        status = StatusCode::from_u16(n).unwrap_or(StatusCode::OK);
                    }
                }
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                headers.append(name, val);
            }
        }
    }
    if !headers.contains_key(header::CONTENT_TYPE) {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    }
    Ok(FcgiResponse {
        status,
        headers,
        body,
    })
}

/// 组装 FastCGI PARAMS —— 它就是 CGI 环境，php-fpm 把每个 param 交给脚本
/// （`$_SERVER` / `getenv()`）。此前这里**一个 `HTTP_*` 都不发**：PHP 拿不到
/// `Cookie` / `Host` / `Authorization` / `User-Agent` / `Accept`，`$_COOKIE` 恒空、
/// 依赖会话与登录的应用直接不可用（.env 之外的请求头全部丢失）。
///
/// 规则（CGI/1.1）：
///   * `Content-Type` → `CONTENT_TYPE`、`Content-Length` → `CONTENT_LENGTH`（单独变量）；
///   * 其余客户端请求头 → `HTTP_<大写，- 变 _>`；同名头用 `", "` 连接（Cookie 常见）；
///   * hop-by-hop 头不下发——它们只约束当前这条 HTTP 连接，转发给上游会破坏语义。
fn build_params(req: &FcgiRequest) -> BytesMut {
    let mut params = BytesMut::new();
    write_nv(&mut params, "REQUEST_METHOD", &req.method);
    write_nv(&mut params, "SCRIPT_FILENAME", &req.script_filename);
    write_nv(&mut params, "DOCUMENT_ROOT", &req.document_root);
    write_nv(&mut params, "REQUEST_URI", &req.request_uri);
    write_nv(&mut params, "QUERY_STRING", &req.query_string);
    write_nv(&mut params, "CONTENT_TYPE", &req.content_type);
    write_nv(&mut params, "CONTENT_LENGTH", &req.body.len().to_string());
    write_nv(&mut params, "REMOTE_ADDR", &req.remote_addr);
    write_nv(&mut params, "REMOTE_PORT", &req.remote_port.to_string());
    write_nv(&mut params, "SERVER_NAME", &req.server_name);
    write_nv(&mut params, "SERVER_PORT", &req.server_port.to_string());
    write_nv(&mut params, "SERVER_PROTOCOL", "HTTP/1.1");
    write_nv(&mut params, "SERVER_SOFTWARE", "crucible");
    write_nv(&mut params, "GATEWAY_INTERFACE", "CGI/1.1");
    write_nv(&mut params, "REQUEST_SCHEME", if req.https { "https" } else { "http" });
    write_nv(&mut params, "HTTPS", if req.https { "on" } else { "off" });
    // SCRIPT_NAME 是「相对文档根的脚本路径」、PATH_INFO 是脚本名之后剩余的路径段
    // （路由型框架靠它做 pretty URL）。调用方已算好，这里只负责下发。
    write_nv(&mut params, "SCRIPT_NAME", &req.script_name);
    if !req.path_info.is_empty() {
        write_nv(&mut params, "PATH_INFO", &req.path_info);
    }

    // HTTP_*：保持首次出现顺序，同名合并（避免 HashMap 迭代顺序造成难复现的差异）。
    let mut http_params: Vec<(String, String)> = Vec::new();
    for (name, value) in req.headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop(&lower) || lower == "content-length" || lower == "content-type" {
            continue;
        }
        let key = format!("HTTP_{}", lower.to_ascii_uppercase().replace('-', "_"));
        let val = String::from_utf8_lossy(value.as_bytes()).into_owned();
        match http_params.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => {
                v.push_str(", ");
                v.push_str(&val);
            }
            None => http_params.push((key, val)),
        }
    }
    for (k, v) in &http_params {
        write_nv(&mut params, k, v);
    }
    // .env（deps）变量放在最后：它们是运维给应用的环境约定，不能被请求头覆盖。
    for (k, v) in &req.extra_params {
        write_nv(&mut params, k, v);
    }
    params
}

/// hop-by-hop 头（RFC 9110 §7.6.1）：只为当前连接服务，不得转发给上游。
fn is_hop_by_hop(lower: &str) -> bool {
    matches!(
        lower,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn find_header_sep(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n"))
}

/// Health-check：尝试连接 socket。
pub async fn probe(addr: &FcgiAddr) -> bool {
    match addr {
        #[cfg(unix)]
        FcgiAddr::Unix(path) => UnixStream::connect(path).await.is_ok(),
        FcgiAddr::Tcp(a) => TcpStream::connect(a).await.is_ok(),
    }
}

pub fn script_under_docroot(docroot: &Path, uri_path: &str) -> anyhow::Result<std::path::PathBuf> {
    let rel = uri_path.trim_start_matches('/');
    // 防穿越：script 必须留在 docroot 下（旧实现裸 join，可 /php/../../ 执行 docroot 外脚本）。
    crate::server::admin_files::script_rel(docroot, rel)
}
