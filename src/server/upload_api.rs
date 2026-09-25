//! 上传端点（规格 §44）：`PUT/PATCH/POST` + `Content-Range` 断点续传。
//!
//! 设计要点（与 WORKLOG §18.2 一致）：
//! * **只在**该路径 `autoindex.enabled && enable_upload` 且路径前缀匹配时接管（其余方法仍 405）；
//! * 路径安全：`admin_files::safe_join` 做 containment（拒 `..`/绝对路径/反斜杠），
//!   再加一道**扩展名闸门**——`would_execute` 类扩展名默认拒收（§44「不得有 webshell」）；
//! * 落盘：`upload_resume` 的同目录临时文件 + 原子 rename；未收齐回 **202 + `X-Upload-Offset`**，
//!   偏移不符回 **409 + `X-Upload-Offset`**（客户端据此续传）；
//! * 鉴权/限速/ACL 由调用方（h1/h2/h3 的 dispatcher）在此之前完成 —— 本模块只管落盘语义。

use crate::config::ListenerConfig;
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use std::path::PathBuf;

use super::h1::{full, BoxBody};
use super::upload_resume::{self, UploadErr, MAX_UPLOAD_BYTES};

/// 默认拒收的可执行/可解析扩展名（webshell 面）。想上传这些必须改配置或先改名。
const EXEC_EXTS: &[&str] = &[
    "php", "php3", "php4", "php5", "php7", "phtml", "phar", "jsp", "jspx", "jspf", "asp",
    "aspx", "ashx", "asmx", "cgi", "fcgi", "pl", "pm", "py", "rb", "lua", "sh", "bash", "zsh",
    "ksh", "so", "dll", "exe", "com", "bat", "cmd", "ps1", "jar", "war", "class", "tsx", "js",
    "mjs", "cjs", "html", "htm", "xhtml", "svg", "xml", "xsl", "xslt",
];

fn has_exec_ext(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((_, ext)) => EXEC_EXTS.iter().any(|e| e.eq_ignore_ascii_case(ext)),
        None => false,
    }
}

/// 该请求是否应交给上传处理（调用方在 ACL/限速/鉴权之后、静态分发之前问一次）。
pub fn enabled_for(lc: &ListenerConfig, path: &str) -> bool {
    let a = &lc.autoindex;
    if !a.enabled || !a.enable_upload {
        return false;
    }
    // paths 为空视为整站；否则任一路径前缀匹配即可（与 autoindex 的语义一致）。
    a.paths.is_empty() || a.paths.iter().any(|p| path.starts_with(p.as_str()))
}

fn resp(status: StatusCode, msg: &str, offset: Option<u64>) -> Response<BoxBody> {
    let mut b = Response::builder().status(status);
    if let Some(off) = offset {
        b = b.header("x-upload-offset", off.to_string());
    }
    b.header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(msg.to_string()))
        .unwrap_or_else(|_| Response::new(full("upload error".to_string())))
}

/// 处理上传。body 泛型化以便 h1（Incoming）/h2/h3（Bytes）共用同一条路径。
pub async fn handle<B>(req: Request<B>, lc: &ListenerConfig, _peer: std::net::SocketAddr) -> Response<BoxBody>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::fmt::Display,
{
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    if !matches!(method, Method::PUT | Method::PATCH | Method::POST) {
        return resp(StatusCode::METHOD_NOT_ALLOWED, "method not allowed", None);
    }
    // 扩展名闸门：在**落盘之前**拒，避免任何可执行内容进入 docroot。
    if has_exec_ext(&path) {
        return resp(
            StatusCode::FORBIDDEN,
            "该扩展名被上传策略拒绝（可执行/可解析内容不允许上传；请改名或调整策略）",
            None,
        );
    }
    // containment：safe_join 拒绝 `..`/绝对路径/反斜杠/Windows 盘符。
    let rel = path.trim_start_matches('/');
    let target: PathBuf = match crate::server::admin_files::safe_join(&lc.root, rel) {
        Ok(p) => p,
        Err(e) => return resp(StatusCode::BAD_REQUEST, &format!("路径不合法: {e}"), None),
    };

    // Content-Range（可选）：`bytes <start>-<end>/<total|*>`；缺省 = 全量、start=0。
    let (start, total) = match req.headers().get(header::CONTENT_RANGE) {
        Some(v) => match v.to_str().ok().and_then(upload_resume::parse_content_range) {
            Some((s, _e, t)) => (s, t),
            None => {
                return resp(
                    StatusCode::BAD_REQUEST,
                    "Content-Range 无法解析（应形如 bytes 0-1023/4096）",
                    None,
                )
            }
        },
        None => (0, None),
    };
    let sess = match upload_resume::session_for(&target, start, total) {
        Ok(s) => s,
        Err(UploadErr::OffsetMismatch(cur)) => {
            return resp(
                StatusCode::CONFLICT,
                "偏移与已收字节数不符（按 X-Upload-Offset 续传，或从 0 全量重传）",
                Some(cur),
            )
        }
        Err(UploadErr::TooLarge) => {
            return resp(StatusCode::PAYLOAD_TOO_LARGE, "超过单文件上限", None)
        }
        Err(UploadErr::TooManySessions) => {
            return resp(StatusCode::SERVICE_UNAVAILABLE, "上传会话过多，稍后再试", None)
        }
        Err(UploadErr::TotalMismatch) => resp(
            StatusCode::BAD_REQUEST,
            "同名上传会话的 total 与本次不一致（请改名或先取消）",
            None,
        ),
        Err(UploadErr::Io(e)) => resp(StatusCode::INTERNAL_SERVER_ERROR, &e, None),
    };

    // 流式读 body：逐帧 append。offset 用会话当前值 —— 因此并发分片必须带 Content-Range
    // 且服务端按顺序接纳（偏移不符会直接回 409，客户端据此校正重发）。
    let mut body = req.into_body();
    loop {
        let frame = match body.frame().await {
            Some(Ok(f)) => f,
            Some(Err(e)) => {
                return resp(StatusCode::BAD_REQUEST, &format!("读取请求体失败: {e}"), Some(sess.received()))
            }
            None => break,
        };
        let Some(data) = frame.data_ref() else { continue };
        if data.is_empty() {
            continue;
        }
        let off = sess.received();
        if let Err(e) = upload_resume::append(&sess, off, data) {
            return match e {
                UploadErr::OffsetMismatch(cur) => resp(StatusCode::CONFLICT, "偏移不符", Some(cur)),
                UploadErr::TooLarge => resp(StatusCode::PAYLOAD_TOO_LARGE, "超过单文件上限", None),
                other => resp(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("写入失败: {other:?}"),
                    Some(sess.received()),
                ),
            };
        }
    }

    let received = sess.received();
    if received > MAX_UPLOAD_BYTES {
        return resp(StatusCode::PAYLOAD_TOO_LARGE, "超过单文件上限", None);
    }
    if sess.complete() {
        // 收齐 → 原子落盘（同目录 rename）
        return match upload_resume::commit(&sess) {
            Ok(()) => resp(StatusCode::CREATED, "uploaded", None),
            Err(e) => resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("落盘失败: {e:?}"), None),
        };
    }
    // 未收齐（分片上传）：202 + 当前偏移，客户端据此续传
    resp(StatusCode::ACCEPTED, "partial; continue with X-Upload-Offset", Some(received))
}

/// 便于测试与静态检查：暴露扩展名闸门。
pub fn exec_ext_rejected(path: &str) -> bool {
    has_exec_ext(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_extensions_rejected() {
        for p in ["/up/x.php", "/up/a.PHP", "/up/shell.jsp", "/up/x.cgi", "/up/x.tsx", "/up/x.html"] {
            assert!(exec_ext_rejected(p), "{p} 应被拒");
        }
        for p in ["/up/x.txt", "/up/data.bin", "/up/photo.png", "/up/noext"] {
            assert!(!exec_ext_rejected(p), "{p} 应放行");
        }
    }

    #[test]
    fn enabled_only_when_configured() {
        // 用默认配置构造：enable_upload 默认 false → 必须不接管
        let lc = crate::config::ListenerConfig::default();
        assert!(!enabled_for(&lc, "/up/x.txt"));
    }

    #[test]
    fn response_carries_offset_header() {
        let r = resp(StatusCode::ACCEPTED, "partial", Some(1234));
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        assert_eq!(r.headers().get("x-upload-offset").unwrap(), "1234");
    }
}
