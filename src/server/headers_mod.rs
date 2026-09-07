//! Response header mutation helpers.

use http::{header::HeaderName, HeaderMap, HeaderValue};

pub fn set_header(map: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        map.insert(n, v);
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
