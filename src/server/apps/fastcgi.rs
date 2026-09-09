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
    pub server_name: String,
    pub server_port: u16,
    pub https: bool,
    pub body: Bytes,
    pub extra_params: HashMap<String, String>,
}

pub struct FcgiResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub async fn exchange(addr: &FcgiAddr, req: &FcgiRequest) -> Result<FcgiResponse> {
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
    let mut params = BytesMut::new();
    write_nv(&mut params, "REQUEST_METHOD", &req.method);
    write_nv(&mut params, "SCRIPT_FILENAME", &req.script_filename);
    write_nv(&mut params, "DOCUMENT_ROOT", &req.document_root);
    write_nv(&mut params, "REQUEST_URI", &req.request_uri);
    write_nv(&mut params, "QUERY_STRING", &req.query_string);
    write_nv(&mut params, "CONTENT_TYPE", &req.content_type);
    write_nv(
        &mut params,
        "CONTENT_LENGTH",
        &req.body.len().to_string(),
    );
    write_nv(&mut params, "REMOTE_ADDR", &req.remote_addr);
    write_nv(&mut params, "SERVER_NAME", &req.server_name);
    write_nv(&mut params, "SERVER_PORT", &req.server_port.to_string());
    write_nv(&mut params, "SERVER_PROTOCOL", "HTTP/1.1");
    write_nv(&mut params, "GATEWAY_INTERFACE", "CGI/1.1");
    write_nv(
        &mut params,
        "HTTPS",
        if req.https { "on" } else { "off" },
    );
    // SCRIPT_NAME / PATH_INFO 简化：整段 URI 当 SCRIPT_NAME
    write_nv(
        &mut params,
        "SCRIPT_NAME",
        req.request_uri
            .split('?')
            .next()
            .unwrap_or(&req.request_uri),
    );
    for (k, v) in &req.extra_params {
        write_nv(&mut params, k, v);
    }
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
