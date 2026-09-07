//! RFC 9298: HTTP/3 Extended CONNECT (CONNECT-UDP + connect-udp:protocol=).
//! Stub：实际代理逻辑由 h3.rs::handle_connect_protocol 调用，详见那个文件。
//! 本模块保留 protocol 检测与目标地址解析供复用。

use std::str::FromStr;

/// 解析 `:path` (如 "/192.0.2.1:53") 为上游 (host, port)。
pub fn parse_target_path(path: &str) -> Result<(String, u16), String> {
    let p = path.trim_start_matches('/');
    if p.is_empty() { return Err("missing target".into()); }
    if let Some((h, ps)) = p.rsplit_once(':') {
        let port = u16::from_str(ps).map_err(|_| "bad port".into())?;
        Ok((h.to_string(), port))
    } else {
        Err("missing port".into())
    }
}

/// 判断 protocol 头是否要求 CONNECT-UDP。
pub fn is_connect_udp(protocol: Option<&str>) -> bool {
    protocol.map(|p| p.eq_ignore_ascii_case("connect-udp")).unwrap_or(false)
}
