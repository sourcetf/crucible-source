//! ISP / region alias tables for GeoIP labels.

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// (匹配键, 显示别名)，**按 key 长度降序**存放：匹配取第一个命中 = 最长键优先。
///
/// 原实现是 `Lazy<HashMap>` 遍历（`RandomState` 迭代序随进程/运行变化）：org 名同时
/// 包含多个键时（如 "AMAZON.COM" 同时含 AMAZON 与 AMAZON.COM、"GOOGLE AMAZON ..."）
/// 同一输入可能得到不同别名，面板标签不稳定。等长键之间以本数组声明序为准（确定）。
static ISP_ALIASES: &[(&str, &str)] = &[
    ("CHINA MOBILE", "China Mobile"),
    ("DIGITALOCEAN", "DigitalOcean"),
    ("CHINA UNICOM", "China Unicom"),
    ("AMAZON.COM", "AWS"),
    ("CLOUDFLARE", "Cloudflare"),
    ("CHINANET", "China Telecom"),
    ("MICROSOFT", "Microsoft Azure"),
    ("AMAZON", "AWS"),
    ("GOOGLE", "Google Cloud"),
];

/// Resolve a display alias for an ISP name (case-insensitive substring match).
pub fn resolve_isp_alias(name: &str) -> String {
    let upper = name.to_ascii_uppercase();
    for (key, alias) in ISP_ALIASES {
        if upper.contains(key) {
            return (*alias).to_string();
        }
    }
    name.trim().to_string()
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

    /// ISP 别名必须确定：最长键优先，多键同现时结果不随 HashMap 随机序漂移。
    #[test]
    fn isp_alias_is_deterministic_longest_match() {
        assert_eq!(resolve_isp_alias("AMAZON.COM"), "AWS");
        assert_eq!(resolve_isp_alias("AMAZON-02"), "AWS");
        assert_eq!(resolve_isp_alias("CLOUDFLARENET"), "Cloudflare");
        assert_eq!(resolve_isp_alias("CHINANET-JS"), "China Telecom");
        assert_eq!(resolve_isp_alias("CHINA UNICOM BACKBONE"), "China Unicom");
        assert_eq!(resolve_isp_alias("GOOGLE CLOUD"), "Google Cloud");
        assert_eq!(resolve_isp_alias("DIGITALOCEAN-ASN"), "DigitalOcean");
        // 多键同现：同一输入重复 100 次结果必须一致（旧实现依赖 HashMap 迭代序）。
        let first = resolve_isp_alias("GOOGLE AMAZON");
        for _ in 0..100 {
            assert_eq!(resolve_isp_alias("GOOGLE AMAZON"), first);
        }
        // 未命中任何键：原样返回（仅 trim）。
        assert_eq!(resolve_isp_alias(" Level3 "), "Level3");
    }
}
