//! Response header mutation helpers.

use http::{header::HeaderName, HeaderMap, HeaderValue};

/// 响应头注入的**统一黑名单**（所有把配置/规则/上游字符串写进响应头的地方都必须过这里）。
///
/// 被拒的是两类：
/// * 报文定界头 `content-length` / `transfer-encoding`：写一个与真实 body 不符的
///   Content-Length，h1 上 hyper 会按真实 body 成帧却把该头**原样写出**
///   （一致性检查只在 debug_assertions 下）⇒ 客户端按错误长度截断/粘连后续报文，
///   即响应走私；
/// * 连接/逐跳管理头 `connection` / `host` / `keep-alive` / `te` / `trailer` /
///   `upgrade` / `proxy-*`：属 RFC 9110 §7.6.1 的逐跳语义，由连接两端自己决定，
///   不允许配置注入（`Connection:` 点名的名字另由调用方按 conn_tokens 过滤）。
///
/// 大小写不敏感；`set-cookie`/`cache-control`/`content-type`/CSP 等正常业务头不受限。
pub fn response_header_injectable(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "host"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
    )
}

pub fn set_header(map: &mut HeaderMap, name: &str, value: &str) {
    // 与 page_rules::response_headers / proxy 的注入点共用同一名单：即便某个调用方
    // （或未来新增的调用方）没在源头过滤，这里也兜一层，定界/逐跳头永远进不了响应。
    if !response_header_injectable(name) {
        log::warn!("响应头被拒绝（定界头/逐跳头不得由配置注入）: name={name:?}");
        return;
    }
    match (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        (Ok(n), Ok(v)) => {
            map.insert(n, v);
        }
        // **静默丢弃**是最糟的：运维在 page_rules 里配了一个响应头（可能是安全头），
        // 而 HeaderValue 拒绝非 ASCII 字节 ⇒ 头永远不出现，日志里也什么都没有。
        // 配置期只挡了控制字符（page_rules），非 ASCII 会走到这里，所以必须留痕。
        (n, v) => {
            log::warn!(
                "响应头被丢弃（名字或值不是合法的 HTTP 头）: name={name:?} value={value:?}: name_ok={} value_ok={}",
                n.is_ok(),
                v.is_ok()
            );
        }
    }
}

pub fn append_security_headers(map: &mut HeaderMap) {
    set_header(map, "X-Content-Type-Options", "nosniff");
    set_header(map, "X-Frame-Options", "SAMEORIGIN");
    set_header(map, "Referrer-Policy", "no-referrer-when-downgrade");
}

/// page_rules cache/header 注入:按顺序写入响应头。
/// 黑名单过滤在 [`set_header`] 内完成 —— 所有调用方（h1 的 apply_response、
/// h2/h3 的建议调用点）自动受同一名单保护。
pub fn apply_response(map: &mut HeaderMap, mods: &[(String, String)]) {
    for (name, value) in mods {
        set_header(map, name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blacklist_covers_framing_and_hop_headers_case_insensitively() {
        for bad in [
            "Content-Length",
            "content-length",
            "Transfer-Encoding",
            "CONNECTION",
            "Connection",
            "Host",
            "Keep-Alive",
            "TE",
            "Trailer",
            "Upgrade",
            "Proxy-Authenticate",
        ] {
            assert!(!response_header_injectable(bad), "{bad} 必须被拒");
        }
        for ok in [
            "X-Frame-Options",
            "Cache-Control",
            "Set-Cookie",
            "Content-Type",
            "Content-Security-Policy",
        ] {
            assert!(response_header_injectable(ok), "{ok} 是正常业务头，必须放行");
        }
    }

    /// 即便调用方绕过了源头过滤，`apply_response`/`set_header` 也必须拦下定界头。
    #[test]
    fn apply_response_cannot_override_content_length() {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("10"),
        );
        apply_response(
            &mut map,
            &[
                ("Content-Length".into(), "5".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
                ("X-Ok".into(), "1".into()),
            ],
        );
        assert_eq!(map.get("content-length").unwrap(), "10", "CL 不得被覆盖/注入");
        assert!(map.get("transfer-encoding").is_none(), "TE 不得被注入");
        assert_eq!(map.get("x-ok").unwrap(), "1", "正常头照常注入");
    }
}
