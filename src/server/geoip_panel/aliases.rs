//! ISP / region alias tables for GeoIP labels.

/// 解析名字 -> CIDR 列表的映射（面板编辑来源）。
pub fn parse_alias_line(line: &str) -> Option<(String, Vec<String>)> {
    let parts: Vec<&str> = line.split('=').collect();
    if parts.len() != 2 { return None; }
    let name = parts[0].trim().to_string();
    let cidrs: Vec<String> = parts[1].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if name.is_empty() || cidrs.is_empty() { return None; }
    Some((name, cidrs))
}

/// P1-7（G8）：国家/地区别名（中文名 / 英文全称 / 常见缩写 → ISO2）。
/// 筛选入口归一化用：用户输入「中国」「China」「CN」都应命中 CN 段。
static COUNTRY_ALIASES: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    HashMap::from([
        ("中国", "CN"),
        ("中华人民共和国", "CN"),
        ("CHINA", "CN"),
        ("美国", "US"),
        ("美利坚", "US"),
        ("UNITED STATES", "US"),
        ("USA", "US"),
        ("日本", "JP"),
        ("JAPAN", "JP"),
        ("韩国", "KR"),
        ("SOUTH KOREA", "KR"),
        ("KOREA", "KR"),
        ("德国", "DE"),
        ("GERMANY", "DE"),
        ("法国", "FR"),
        ("FRANCE", "FR"),
        ("英国", "GB"),
        ("UNITED KINGDOM", "GB"),
        ("UK", "GB"),
        ("新加坡", "SG"),
        ("SINGAPORE", "SG"),
        ("香港", "HK"),
        ("HONG KONG", "HK"),
        ("台湾", "TW"),
        ("TAIWAN", "TW"),
        ("俄罗斯", "RU"),
        ("RUSSIA", "RU"),
        ("印度", "IN"),
        ("INDIA", "IN"),
        ("加拿大", "CA"),
        ("CANADA", "CA"),
        ("澳大利亚", "AU"),
        ("AUSTRALIA", "AU"),
        ("巴西", "BR"),
        ("BRAZIL", "BR"),
        ("荷兰", "NL"),
        ("NETHERLANDS", "NL"),
    ])
});

/// 国家/地区名归一化：命中别名表返回 ISO2（如 "CN"），否则原样返回（trim）。
/// 仅做整词（大写化后全等）匹配，不做子串——避免 "US" 误吞 "RUSSIA"。
pub fn resolve_country_alias(name: &str) -> String {
    let t = name.trim();
    let upper = t.to_ascii_uppercase();
    for (key, iso) in COUNTRY_ALIASES.iter() {
        if upper == *key {
            return (*iso).to_string();
        }
    }
    t.to_string()
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
    fn country_alias_normalizes() {
        assert_eq!(resolve_country_alias("中国"), "CN");
        assert_eq!(resolve_country_alias("china"), "CN");
        assert_eq!(resolve_country_alias("  United States "), "US");
        assert_eq!(resolve_country_alias("RUSSIA"), "RU");
        // 非别名原样保留（含子串陷阱：RUSSIA 不应被 US 吞掉）
        assert_eq!(resolve_country_alias("Someplace"), "Someplace");
    }
}
