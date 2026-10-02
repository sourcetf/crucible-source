//! Response header mutation helpers.

use http::{header::HeaderName, HeaderMap, HeaderValue};

pub fn set_header(map: &mut HeaderMap, name: &str, value: &str) {
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
pub fn apply_response(map: &mut HeaderMap, mods: &[(String, String)]) {
    for (name, value) in mods {
        set_header(map, name, value);
    }
}
