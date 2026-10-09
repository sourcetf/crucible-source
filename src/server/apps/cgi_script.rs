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

/// 杀死**整个进程组**并回收直接子进程。
///
/// 为什么需要：两条早期错误路径（stdout 读错、输出超限）此前只 `child.kill()`（读错那条
/// 甚至不 kill），既不 kill 进程组也不 `wait` —— 直接子进程留下**僵尸**（`Child` 被 drop
/// 不回收），脚本起的孙进程（持有 stdout 管道）要等 30s 看门狗才死。`done` 置位后看门狗
/// 不再重复动作。
fn kill_and_reap(child: &mut std::process::Child, pgid: i32, done: &AtomicBool) {
    #[cfg(unix)]
    unsafe {
        // 负 pid = 整组（含孙进程），与看门狗同一口径。
        libc::kill(-pgid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
    done.store(true, Ordering::Relaxed);
}

/// Spawn `binary` with CGI/1.1 environment; parse Status/headers/body.
///
/// CGI/1.1 要求把请求头映射为 `HTTP_*`、`CONTENT_TYPE` 单独给（不是 `HTTP_CONTENT_TYPE`），
/// 并把 `.env`（deps）变量并入脚本环境（规格 §7.9「.env 行 KEY=VAL 并入 CGI/FFI 环境」）。
/// 旧实现这三样都缺 —— 与 `cgi` 引擎（libapp_cgi.so，走 ABI headers + env_lock）行为分叉：
/// 同一个 CGI 脚本在 `engine="cgi"` 下能读到 `HTTP_HOST`/`CONTENT_TYPE`/`.env`，在
/// `engine="cgi_script"` 下全是空。
/// 把「应用内相对请求路径」切成 **脚本 URL 路径** 与 **PATH_INFO**（CGI/1.1 §4.1.13/§4.1.5）。
///
/// 与 nginx/Apache 的 PATH_INFO 解析同一套：从**最长**前缀开始，`docroot/<前缀>` 是常规
/// 文件的前缀就是脚本，其后剩余（必须以 `/` 开头或为空）是 PATH_INFO。
///   * `/index.cgi`               → (`/index.cgi`, "")
///   * `/index.cgi/extra/path`    → (`/index.cgi`, "/extra/path")
///   * 无任何前缀成文件（含 `..`/隐藏段等被 `safe_join` 拒绝的形态）→ `None`（调用方 404）。
///
/// 目录请求的 index 回落由 `rel_script_path` 在此之前完成（`/cgis/` → `/index.cgi`）。
fn split_path_info(docroot: &Path, rel: &str) -> Option<(String, String)> {
    // 与旧实现同一条防穿越口径：`safe_join` 会拒 `..`/绝对路径/反斜杠/隐藏段。旧实现把
    // **整条** rel 交给 safe_join 判一次；这里逐前缀判，故只要 rel 里出现 `..` 段就整体
    // 拒绝（不在「PATH_INFO 里夹 `..`」上开新口子）。
    if rel.split(['/', '\\']).any(|seg| seg == "..") {
        return None;
    }
    let rel = if rel.starts_with('/') {
        rel.to_string()
    } else {
        format!("/{rel}")
    };
    let mut end = rel.len();
    while end > 0 {
        let cand = &rel[..end];
        if let Ok(p) = script_rel(docroot, cand.trim_start_matches('/')) {
            if p.is_file() {
                return Some((cand.to_string(), rel[end..].to_string()));
            }
        }
        match rel[..end].rfind('/') {
            Some(i) => end = i,
            None => break,
        }
    }
    None
}

/// 命中的**应用前缀**（`paths` 里最长匹配、尾斜杠已归一化）。catch-all（`paths` 为空或
/// 不匹配）时为 `""`（此时脚本 URL 就是请求路径本身）。
fn matched_app_prefix<'a>(app: &'a AppRouteConfig, path: &str) -> &'a str {
    let mut best: Option<&str> = None;
    for p in &app.paths {
        let p = p.trim_end_matches('/');
        if p.is_empty() {
            continue;
        }
        if path == p || path.starts_with(&format!("{p}/")) {
            if best.is_none_or(|b| p.len() > b.len()) {
                best = Some(p);
            }
        }
    }
    best.unwrap_or("")
}

/// cgi_script 请求的脚本解析（h1 与 h2/h3 两条分发路径共用，保证跨协议同口径）：
/// 返回 `(docroot 下的脚本绝对路径, SCRIPT_NAME, PATH_INFO)`。
pub(crate) fn resolve_target(
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    path: &str,
) -> Result<(std::path::PathBuf, String, String)> {
    let docroot = app.docroot.clone().unwrap_or_else(|| lc.root.clone());
    let rel = crate::server::apps::app_ffi::rel_script_path(app, path);
    let (script_url_rel, path_info) = split_path_info(&docroot, &rel).ok_or_else(|| {
        anyhow::anyhow!(
            "cgi_script: script not found {}",
            script_rel(&docroot, rel.trim_start_matches('/'))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| rel.clone())
        )
    })?;
    let script = script_rel(&docroot, script_url_rel.trim_start_matches('/'))
        .context("cgi_script script path")?;
    // CGI/1.1 §4.1.13：`SCRIPT_NAME` 是标识脚本的 **URI 路径**（如 `/cgis/index.cgi`），
    // 不是脚本的文件系统路径。应用前缀（`paths`）+ 应用内脚本相对路径。
    let script_name = format!("{}{}", matched_app_prefix(app, path), script_url_rel);
    Ok((script, script_name, path_info))
}

pub async fn execute_binary(
    binary: &Path,
    method: &Method,
    uri: &Uri,
    headers: &http::HeaderMap,
    body: Bytes,
    env_vars: &[(String, String)],
    lc: &ListenerConfig,
    peer: SocketAddr,
    script_name: String,
    path_info: String,
) -> Result<Response<BoxBody>> {
    let query = uri.query().unwrap_or("");
    // `SCRIPT_NAME`/`PATH_INFO` 由 [`resolve_target`] 解析后显式传入（h1 与 h2/h3 共用）。
    let port = lc.port;
    let server_name = lc.server_name.clone().unwrap_or_else(|| "localhost".into());
    let bin = binary.to_path_buf();
    let script_filename = binary.display().to_string();
    let method = method.as_str().to_string();
    let query = query.to_string();
    let peer_s = peer.ip().to_string();
    // 请求头 + authority + .env 一并搬进阻塞任务（HeaderMap 是 Send+Sync，克隆开销小）。
    let headers = headers.clone();
    let authority = uri.authority().map(|a| a.to_string());
    let env_vars: Vec<(String, String)> = env_vars.to_vec();

    let raw = task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut cmd = Command::new(&bin);
        // **干净环境**：先 `env_clear()` 再铺「启动期基底 + 本请求 `.env`」，最后下面用
        // `.env()` 覆盖 CGI 变量。这样并发请求正在生效的临时 `.env`（进程 env 里的临时值）
        // 绝不会被这个 CGI 子进程继承 —— 于是本引擎**无需**参与 `env_lock` 的进程 env 互斥，
        // 一个慢的空请求也就不会挡住随后带 `.env` 的请求（见 env_lock 的说明）。
        // 旧实现直接继承 `environ`（Command 默认），会把别的请求的 `.env` 一起带走。
        crate::server::apps::env_lock::apply_clean_env(&mut cmd, &env_vars);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("GATEWAY_INTERFACE", "CGI/1.1")
            .env("REQUEST_METHOD", &method)
            .env("PATH_INFO", &path_info)
            .env("QUERY_STRING", &query)
            .env("SCRIPT_FILENAME", &script_filename)
            .env("SCRIPT_NAME", &script_name)
            .env("REMOTE_ADDR", &peer_s)
            .env("SERVER_NAME", &server_name)
            .env("SERVER_PROTOCOL", "HTTP/1.1")
            .env("SERVER_PORT", port.to_string())
            .env("CONTENT_LENGTH", body.len().to_string());
        // 请求头 → HTTP_*（CGI/1.1）。Content-Type/Length 走专门变量，不重复成 HTTP_*。
        let mut has_host = false;
        for (k, v) in headers.iter() {
            let name = k.as_str();
            if name.eq_ignore_ascii_case("content-type")
                || name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            let Ok(vs) = v.to_str() else { continue };
            let mut key = String::with_capacity(name.len() + 5);
            key.push_str("HTTP_");
            for ch in name.chars() {
                key.push(if ch == '-' { '_' } else { ch.to_ascii_uppercase() });
            }
            if key == "HTTP_HOST" {
                has_host = true;
            }
            cmd.env(key, vs);
        }
        // h2/h3 的权威在 `:authority`（无字面 Host 头）——补一条，避免 HTTP_HOST 缺失。
        if !has_host {
            if let Some(a) = authority.as_deref() {
                cmd.env("HTTP_HOST", a);
            }
        }
        if let Some(ct) = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            cmd.env("CONTENT_TYPE", ct);
        }
        // .env（deps）变量已由上面的 `apply_clean_env` 铺进子进程环境；这里不再重复
        // `cmd.env` —— 否则应用 `.env` 里的同名键会覆盖上面的 CGI 变量（CGI 变量才是权威）。
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
                    Err(e) => {
                        kill_and_reap(&mut child, pgid, &done);
                        return Err(e).context("cgi_script read stdout");
                    }
                };
                if stdout.len() + n > CGI_OUTPUT_CAP {
                    kill_and_reap(&mut child, pgid, &done);
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
    // 脚本解析（剥应用前缀 → 最长「已存在文件」前缀定界 → PATH_INFO）与 h2/h3 的
    // `apps::cgi_script_simple` 共用 [`resolve_target`]，保证跨协议同口径。
    let (script, script_name, path_info) = resolve_target(lc, app, parts.uri.path())?;
    // .env（deps）变量随请求 extensions 下发（try_handle 注入），与 cgi 引擎一致并入脚本环境。
    let env_vars = parts
        .extensions
        .get::<crate::server::apps::deps::DepsEnv>()
        .map(|d| (*d.vars).clone())
        .unwrap_or_default();
    execute_binary(
        &script,
        &parts.method,
        &parts.uri,
        &parts.headers,
        body_bytes,
        &env_vars,
        lc,
        peer,
        script_name,
        path_info,
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
    // CGI 脚本可以设置任意响应头（Set-Cookie 最常见）。旧实现只透传 Status 与
    // Content-Type，其余全丢 —— CGI 语义不完整（其它引擎都全量透传头块）。
    // 头名/值用 `app_ffi::valid_header_kv` 做注入净化（token 名、可见 ASCII 值），
    // Content-Type 按 RFC 单值语义后者胜出。
    let mut extra: Vec<(String, String)> = Vec::new();
    for line in hdr_text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("Status:") {
            if let Ok(code) = rest.trim().split_whitespace().next().unwrap_or("200").parse() {
                status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
            }
        } else if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("Content-Type") {
                if !v.is_empty() {
                    content_type = v.to_string();
                }
            } else if crate::server::apps::app_ffi::valid_header_kv(k, v) {
                extra.push((k.to_string(), v.to_string()));
            }
        }
    }

    let mut builder = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header("X-Crucible-Engine", "cgi_script");
    for (k, v) in &extra {
        builder = builder.header(k.as_str(), v.as_str());
    }
    Ok(builder.body(full(Bytes::from(body)))?)
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

    fn app_with_paths(paths: &[&str]) -> AppRouteConfig {
        AppRouteConfig {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            enabled: true,
            engine: "cgi_script".into(),
            socket: None,
            extensions: vec!["cgi".into(), "".into()],
            index: Some("index.cgi".into()),
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

    /// CGI/1.1 §4.1.13：`/cgis/index.cgi` → SCRIPT_NAME=/cgis/index.cgi、PATH_INFO=""；
    /// `/cgis/index.cgi/extra/path` → PATH_INFO=/extra/path（本波修复点；旧实现在第二种
    /// 形态上直接 404「script not found」，且 SCRIPT_NAME 是**文件系统路径**）。
    #[test]
    fn split_path_info_defines_script_and_tail() {
        let dir = std::env::temp_dir().join(format!(
            "crucible-cgis-ut-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("index.cgi"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.join("sub/run.cgi"), b"#!/bin/sh\n").unwrap();
        assert_eq!(
            split_path_info(&dir, "/index.cgi"),
            Some(("/index.cgi".to_string(), String::new()))
        );
        assert_eq!(
            split_path_info(&dir, "/index.cgi/extra/path"),
            Some(("/index.cgi".to_string(), "/extra/path".to_string()))
        );
        // 子目录脚本 + 尾部
        assert_eq!(
            split_path_info(&dir, "/sub/run.cgi/a"),
            Some(("/sub/run.cgi".to_string(), "/a".to_string()))
        );
        // 无任何前缀是文件 → None（调用方 404）
        assert_eq!(split_path_info(&dir, "/nope.cgi"), None);
        assert_eq!(split_path_info(&dir, "/index.cgi/../etc/passwd"), None, "`..` 整条拒绝");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 应用前缀取**最长**匹配（配置同时有 `/a` 与 `/a/b` 时不许错认），catch-all → 空前缀。
    #[test]
    fn matched_app_prefix_takes_longest() {
        let app = app_with_paths(&["/a", "/a/b/"]);
        assert_eq!(matched_app_prefix(&app, "/a/b/index.cgi"), "/a/b");
        assert_eq!(matched_app_prefix(&app, "/a/index.cgi"), "/a");
        assert_eq!(matched_app_prefix(&app, "/ax/index.cgi"), "");
        let catch_all = app_with_paths(&[]);
        assert_eq!(matched_app_prefix(&catch_all, "/cgis/index.cgi"), "");
    }
}
