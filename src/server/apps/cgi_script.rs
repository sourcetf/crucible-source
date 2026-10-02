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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::task;

/// CGI 脚本单次响应的输出上限（stdout）。与其它引擎的 APP_BODY_CAP 同量级：
/// 超限说明脚本失控，宁可回 502 也不能把内存交给它。
const CGI_OUTPUT_CAP: usize = 32 * 1024 * 1024;

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
        // 让脚本与**它的子进程**同属一个新进程组（组长 = 子进程 pid）。看门狗要杀的
        // 是**整组**而不是单个进程：`#!/bin/sh` 脚本里起 `sleep`/`cat` 这类子命令时，
        // 杀 shell 并不会杀掉孙进程，而孙进程**继承了 stdout 管道** ⇒ 我们这端永远等不到
        // EOF、请求继续挂着。实测踩过（sleep 100 的脚本 50s 仍不返回）。
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = cmd.spawn().context("cgi_script spawn")?;
        if !body.is_empty() {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(&body)?;
            }
        }
        // 关掉 stdin：CGI 脚本靠 EOF 才知道请求体结束（否则它会一直等着读）。
        drop(child.stdin.take());
        // 超时：std 没有 `wait_timeout`，用一个看门狗线程到点 SIGKILL **整个进程组** ——
        // 组内进程全死光，下面阻塞的 `read` 才会返回 EOF（只杀脚本本身不够，见上）。
        // 在此之前这条路径**没有任何超时**：一个不退出（或只往 stdout 猛写）的脚本
        // 会永久占住一个 spawn_blocking 线程，重复几次就把阻塞池抽干。
        // 上限与 app_ffi 的 CGI_TIMEOUT_MS 口径一致。
        const CGI_TIMEOUT_SECS: u64 = 30;
        // 组长 pid == 子进程 pid（上面 process_group(0)）
        let pgid = child.id() as i32;
        let done = Arc::new(AtomicBool::new(false));
        let timed_out = Arc::new(AtomicBool::new(false));
        {
            let done = done.clone();
            let timed_out = timed_out.clone();
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(CGI_TIMEOUT_SECS);
                while std::time::Instant::now() < deadline {
                    if done.load(Ordering::Relaxed) {
                        return; // 子进程已被 wait 收走，无需再管
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                if !done.load(Ordering::Relaxed) {
                    timed_out.store(true, Ordering::Relaxed);
                    // 负 pid = 杀**整个进程组**（含脚本起的孙进程）——只杀脚本本身时，
                    // 孙进程仍持有 stdout 管道，读端就永远等不到 EOF。
                    // 安全：pgid 就是紧接着 spawn 出来的那个子进程 pid（process_group(0)），
                    // 且 done 未置位 ⇒ 这一组还在跑。
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                }
            });
        }
        // 有界读取：此前是 `wait_with_output()`，stdout 有多少收多少 ——
        // 一个往 stdout 猛写的脚本能把内存吃光，所以读的时候就要卡住上限。
        let mut stdout = Vec::new();
        if let Some(mut so) = child.stdout.take() {
            use std::io::Read;
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = match so.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e).context("cgi_script read stdout"),
                };
                if stdout.len() + n > CGI_OUTPUT_CAP {
                    let _ = child.kill();
                    bail!("cgi_script 输出超过上限 {CGI_OUTPUT_CAP} 字节（疑似脚本失控）");
                }
                stdout.extend_from_slice(&buf[..n]);
            }
        }
        let status = child.wait().context("cgi_script wait")?;
        done.store(true, Ordering::Relaxed);
        if timed_out.load(Ordering::Relaxed) {
            bail!("cgi_script 超时（{CGI_TIMEOUT_SECS}s）已被终止");
        }
        if !status.success() && stdout.is_empty() {
            bail!("cgi_script 退出异常（{:?}）且无输出", status.code());
        }
        Ok(stdout)
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
    // 与其它引擎一致：请求体必须**限量**收集（其余引擎都走 Limited::new(body, APP_BODY_CAP)）。
    // 这里是唯一的例外 —— 无上限 collect 意味着 h1 上任何 chunked/超大 POST 到 CGI 路由
    // 都能把请求体全量读进内存（同一个威胁模型下的漏网点）。
    let body_bytes = http_body_util::Limited::new(body, crate::server::h1::APP_BODY_CAP)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("cgi_script: 请求体超出 {} 字节上限: {e}", crate::server::h1::APP_BODY_CAP))?
        .to_bytes();
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
