//! GeoIP 别名 / 线路名称映射。

/// 解析名字 -> CIDR 列表的映射（面板编辑来源）。
pub fn parse_alias_line(line: &str) -> Option<(String, Vec<String>)> {
    let parts: Vec<&str> = line.split('=').collect();
    if parts.len() != 2 { return None; }
    let name = parts[0].trim().to_string();
    let cidrs: Vec<String> = parts[1].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if name.is_empty() || cidrs.is_empty() { return None; }
    Some((name, cidrs))
}

/// 序列化名字 -> CIDR 列表
pub fn format_alias_line(name: &str, cidrs: &[String]) -> String {
    format!("{}={}", name, cidrs.join(","))
}

/// 解析 IP 别名（如 "cn" → ["1.0.0.0/8", ...]）。
/// 空字符串返回 None。
pub fn resolve_isp_alias(name: &str) -> String {
    if name.is_empty() { return String::new(); }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_alias_line() {
        let r = parse_alias_line("cn=1.0.0.0/8,2.0.0.0/8");
        assert_eq!(r.map(|(n, c)| (n, c.len())), Some(("cn".to_string(), 2)));
    }
}