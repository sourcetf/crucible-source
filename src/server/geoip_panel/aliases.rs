//! ISP / region alias tables for GeoIP labels.

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// (匹配键, 显示别名)。
///
/// 匹配规则是「最长键优先，等长键以本数组声明序为准」，但**不依赖**数组恰好按长度
/// 降序排列（见 [`resolve_isp_alias`]）：本表历史上就被手工维护成「近似降序」
/// （`CHINANET` 8 排在 `MICROSOFT` 9 之前），一旦某天新增一个更长的键忘了挪位置，
/// 依赖声明序的实现就会选错别名。实现改为显式取最长命中，声明序只用于等长 tie-break。
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
///
/// 最长键优先：`AMAZON.COM` 必须压过 `AMAZON`、`CHINA UNICOM` 必须压过别的子串。
/// 显式比较键长（而不是依赖声明序）后，结果与输入无关、与数组排列无关，可重复。
pub fn resolve_isp_alias(name: &str) -> String {
    let upper = name.to_ascii_uppercase();
    let mut best: Option<(&str, usize)> = None; // (alias, key_len)
    for (key, alias) in ISP_ALIASES {
        if upper.contains(key) {
            // 等长键保留先声明者（`>` 而非 `>=`），保证确定性。
            if best.map_or(true, |(_, len)| key.len() > len) {
                best = Some((alias, key.len()));
            }
        }
    }
    match best {
        Some((alias, _)) => alias.to_string(),
        None => name.trim().to_string(),
    }
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

    /// 最长键优先必须与数组声明序无关：`CHINANET`(8) 在表里排在 `MICROSOFT`(9) 之前，
    /// 旧实现（取第一个命中）会把同时含两者的 org 判成 China Telecom；正确结果是更长的
    /// `MICROSOFT` → Microsoft Azure。修复后按显式键长比较，声明序只做等长 tie-break。
    #[test]
    fn isp_alias_longest_match_independent_of_order() {
        assert_eq!(resolve_isp_alias("CHINANET MICROSOFT"), "Microsoft Azure");
        assert_eq!(resolve_isp_alias("AMAZON GOOGLE"), "AWS"); // 等长(6) → 先声明 AMAZON
        assert_eq!(resolve_isp_alias("AMAZON.COM"), "AWS");
    }
}
