//! Legacy CGI spawn engine (explicit `cgi_script` route only).
//!
//! **C/Go/Rust must not call [`execute_binary`] on success paths** — see §7.3 / §19.

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::admin_files::script_rel;
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use tokio::task;

/// Spawn `binary` with CGI/1.1 environment; parse Status/headers/body.
pub async fn execute_binary(
    binary: &Path,
    method: &Method,
    uri: &Uri,
    body: Bytes,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    let path = uri.path();
    let query = uri.query().unwrap_or("");
    let docroot = app.docroot.clone().unwrap_or_else(|| lc.root.clone());
    let script_name = script_rel(&docroot, path.trim_start_matches('/'))
        .map_err(|e| anyhow::anyhow!("cgi script path rejected: {e:#}"))?;
    let port = lc.port;
    let server_name = lc.server_name.clone().unwrap_or_else(|| "localhost".into());
    let bin = binary.to_path_buf();
    let method = method.as_str().to_string();
    let query = query.to_string();
    let path_info = path.to_string();
    let peer_s = peer.ip().to_string();

    let raw = task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut cmd = Command::new(&bin);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("GATEWAY_INTERFACE", "CGI/1.1")
            .env("REQUEST_METHOD", &method)
            .env("PATH_INFO", &path_info)
            .env("QUERY_STRING", &query)
            .env("SCRIPT_FILENAME", script_name.display().to_string())
            .env("SCRIPT_NAME", script_name.display().to_string())
            .env("REMOTE_ADDR", &peer_s)
            .env("SERVER_NAME", &server_name)
            .env("SERVER_PROTOCOL", "HTTP/1.1")
            .env("SERVER_PORT", port.to_string())
            .env("CONTENT_LENGTH", body.len().to_string());
        let mut child = cmd.spawn().context("cgi_script spawn")?;
        if !body.is_empty() {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(&body)?;
            }
        }
        Ok(child.wait_with_output().context("cgi_script wait")?.stdout)
    })
    .await
    .context("cgi_script join")??;

    parse_cgi_response(raw)
}

pub async fn handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let docroot = app.docroot.clone().unwrap_or_else(|| lc.root.clone());
    let script = script_rel(&docroot, parts.uri.path().trim_start_matches('/'))
        .context("cgi_script script path")?;
    if !script.is_file() {
        bail!("cgi_script: script not found {}", script.display());
    }
    execute_binary(
        &script,
        &parts.method,
        &parts.uri,
        body_bytes,
        lc,
        app,
        peer,
    )
    .await
}

fn parse_cgi_response(raw: Vec<u8>) -> Result<Response<BoxBody>> {
    // 二进制安全：头按文本解析，body 保留原始字节（旧实现 from_utf8_lossy 全文转换会损坏二进制输出）。
    let (hdr_text, body): (String, Vec<u8>) = match find_header_end(&raw) {
        Some(pos) => (
            String::from_utf8_lossy(&raw[..pos]).into_owned(),
            raw[pos..].to_vec(),
        ),
        None => (String::new(), raw),
    };
    if hdr_text.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header("X-Crucible-Engine", "cgi_script")
            .body(full(Bytes::from(body)))?);
    }

    let mut status = StatusCode::OK;
    let mut content_type = "text/plain; charset=utf-8".to_string();
    for line in hdr_text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("Status:") {
            if let Ok(code) = rest.trim().split_whitespace().next().unwrap_or("200").parse() {
                status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
            }
        } else if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("Content-Type") {
                content_type = v.trim().to_string();
            }
        }
    }

    Ok(Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header("X-Crucible-Engine", "cgi_script")
        .body(full(Bytes::from(body)))?)
}

/// 在原始字节里定位空行分隔（\r\n\r\n 或 \n\n），返回 body 起始偏移。
fn find_header_end(raw: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < raw.len() {
        if raw[i] == b'\n' {
            if raw[i + 1] == b'\n' {
                return Some(i + 2);
            }
            if raw[i + 1] == b'\r' && i + 2 < raw.len() && raw[i + 2] == b'\n' {
                return Some(i + 3);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_body() {
        let r = parse_cgi_response(b"hello\n".to_vec()).unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
}
