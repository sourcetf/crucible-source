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

/// 扩展名闸门。
///
/// **必须取「最后一个非空、且不是 `.` 的段」**：落盘路径会经过 `safe_join` 的 Path 归一化，
/// 而旧实现只看原始路径的最后一个段 —— 于是
/// `PUT /up/shell.php/`、`/up/shell.php/.`、`/up/shell.php//` 都让 name 变成空串，
/// 扩展名判成「没有」，闸门放行，而文件实际写到 `<root>/up/shell.php` ⇒ **webshell 落盘**
/// （同一条路径随后由引擎执行）。这是审计报的 P0，实测可复现。
fn has_exec_ext(path: &str) -> bool {
    let name = path
        .rsplit('/')
        .find(|s| !s.is_empty() && *s != ".")
        .unwrap_or("");
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
    // paths 为空视为整站；否则必须**按路径边界**匹配 —— 与 `AutoindexConfig::allows` 同一套：
    // 旧实现用裸 `starts_with`，配置 `paths = ["/up"]` 会把 `/uploads/...`、`/upfoo/...`
    // 也算成上传目录，上传面比运营方以为的更宽。
    a.paths.is_empty()
        || a.paths.iter().any(|p| {
            let p = p.trim_end_matches('/');
            path == p || path.starts_with(&format!("{p}/"))
        })
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
    // 路径安全第一道：拒绝**编码过的分隔符**（`%2f`/`%5c`）与解码后含 `..` 段的路径。
    // 没有这道时 `PUT /..%2f..%2fetc%2fpasswd` 会被当作**一个字面文件名**落在 docroot 里
    //（实测返回 201 ✗）——虽然没逃逸出 root，但客户端意图是穿越、目录里也会留脏名字，
    // 必须拒。判据与 static 层的 normalize_url_path 同一套。
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return resp(StatusCode::BAD_REQUEST, "路径含编码分隔符(%2f/%5c)，拒绝", None);
    }
    let decoded = percent_encoding::percent_decode_str(&path).decode_utf8_lossy();
    if decoded.split(['/', '\\']).any(|seg| seg == "..") {
        return resp(StatusCode::BAD_REQUEST, "路径含 .. 段，拒绝", None);
    }
    // containment 第二道：safe_join 拒绝 `..`/绝对路径/反斜杠/Windows 盘符。
    let rel = path.trim_start_matches('/');
    let target: PathBuf = match crate::server::admin_files::safe_join(&lc.root, rel) {
        Ok(p) => p,
        Err(e) => return resp(StatusCode::BAD_REQUEST, &format!("路径不合法: {e}"), None),
    };

    // Content-Range（可选）：`bytes <start>-<end>/<total|*>`；缺省 = 全量、start=0。
    let mut wildcard_total = false;
    let (start, total) = match req.headers().get(header::CONTENT_RANGE) {
        Some(v) => match v.to_str().ok().and_then(upload_resume::parse_content_range) {
            Some((s, _e, t)) => {
                // `bytes N-M/*` = 总长未知：**不能**把首片当完整文件
                wildcard_total = v
                    .to_str()
                    .map(|s| s.trim().ends_with("/*"))
                    .unwrap_or(false);
                (s, t)
            }
            None => {
                return resp(
                    StatusCode::BAD_REQUEST,
                    "Content-Range 无法解析（应形如 bytes 0-1023/4096）",
                    None,
                )
            }
        },
        None => {
            // 没有 Content-Range 时，Content-Length **就是**总量（`curl -T` 的常见形态）。
            // 之前这里给 None → `complete()` 恒假 → 客户端发完全部 body 也只拿到 202、
            // 文件永远留在 .upload.part（build42 端到端实测踩到）。只有分块传输
            // （既无 Content-Range 也无 Content-Length）才按“长度未知”处理，
            // 那种情况在读不到更多帧之后视为完成（见下面的 finished 判断）。
            let cl = req
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            (0, cl)
        }
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
        Err(UploadErr::TotalMismatch) => {
            return resp(
                StatusCode::BAD_REQUEST,
                "同名上传会话的 total 与本次不一致（请改名或先取消）",
                None,
            )
        }
        Err(UploadErr::Io(e)) => {
            // 其他分支都是 return（类型 `!`），这一支也必须 return，否则 match 各臂类型不一致
            //（build42 实测 E0308）。
            return resp(StatusCode::INTERNAL_SERVER_ERROR, &e, None);
        }
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
    // 完成判定要分三种情况，别把「未知长度」压成一个：
    //  ① `total = Some(n)` → 收够 n 才算完成（分片上传走 202 + X-Upload-Offset）；
    //  ② 完全没有 Content-Range/Length（total=None 且非 `*/`）→ 读到 EOF 就是完整文件
    //     （`curl -T` 的分块传输形态）；
    //  ③ `Content-Range: bytes N-M/*` → 总长**未知**：服务端无法判断何时算完，
    //     因此**永不在本请求里判完成**，一律 202 + X-Upload-Offset，客户端必须用
    //     带具体 total 的请求（`bytes N-M/T` 或 Content-Length）收尾。
    //     旧实现把 ③ 并进 ② → 首片就 201（静默截断 + 会话被 commit，后续分片 409，永远拼不回）。
    // 用**本次请求**声明的 total 判定（不是会话里的那个：会话的 total 是首次创建时定的，
    // 用 `*/` 开的会话 total 恒为 None，于是收尾片即使给了具体 total 也会被判成未完成 → 永久 202）。
    let wildcard = wildcard_total || sess.is_wildcard_total();
    if let Some(t) = total {
        // 客户端一旦给出具体 total，就不再是「未知长度」会话了
        sess.clear_wildcard_total();
        if received >= t {
            return match upload_resume::commit(&sess) {
                Ok(()) => resp(StatusCode::CREATED, "uploaded", None),
                Err(e) => {
                    resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("落盘失败: {e:?}"), None)
                }
            };
        }
    } else if wildcard {
        sess.mark_wildcard_total();
    } else {
        // 没有 Content-Range/Length：读到 EOF 就是完整文件（`curl -T` 的分块传输形态）
        return match upload_resume::commit(&sess) {
            Ok(()) => resp(StatusCode::CREATED, "uploaded", None),
            Err(e) => resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("落盘失败: {e:?}"), None),
        };
    }
    // 未收齐（分片上传）：202 + 当前偏移，客户端据此续传
    resp(StatusCode::ACCEPTED, "partial; continue with X-Upload-Offset", Some(received))
}

/// h2/h3 用：这两个协议在协议层已把请求体收齐（`Request<Bytes>`），而返回体是 `Response<Bytes>`。
///
/// 这里不重构 `handle`，只做一层薄适配：把 `Bytes` 包成 `Full` 交给同一条 `handle` 路径
/// （逻辑仍只有一份），再把响应体收集回 `Bytes`（响应都是很小的文案，收集无成本）。
pub async fn handle_bytes(
    req: Request<Bytes>,
    lc: &ListenerConfig,
    peer: std::net::SocketAddr,
) -> Response<Bytes> {
    let (parts, body) = req.into_parts();
    let full_req = Request::from_parts(parts, Full::new(body));
    let resp = handle(full_req, lc, peer).await;
    let (parts, body) = resp.into_parts();
    let bytes = BodyExt::collect(body)
        .await
        .ok()
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    Response::from_parts(parts, bytes)
}

/// h2/h3 的**流式**入口：body 直接透传给 [`handle`]（不先收齐进内存），响应仍收成 `Bytes`。
///
/// 与 `handle_bytes` 的唯一区别就是不把 body 变成 `Full<Bytes>` —— 这样 h2/h3 上的
/// 大文件上传可以逐帧落盘（上限 `MAX_UPLOAD_BYTES`=2GiB），而不是先撞 `REQUEST_BODY_CAP`(8MiB)。
pub async fn handle_stream<B>(
    req: Request<B>,
    lc: &ListenerConfig,
    peer: std::net::SocketAddr,
) -> Response<Bytes>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::fmt::Display,
{
    let resp = handle(req, lc, peer).await;
    let (parts, body) = resp.into_parts();
    let bytes = BodyExt::collect(body)
        .await
        .ok()
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    Response::from_parts(parts, bytes)
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
