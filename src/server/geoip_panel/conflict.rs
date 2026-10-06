//! Country / MOAS conflict detection for GeoIP merge (§23.5).

use super::covering::CoveringPrefix;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct CountryVote {
    pub country: String,
    pub weight: i64,
    pub commit_unix: i64,
}

/// Vote on country from covering rows; flag conflict when runner-up ≥ 30% of winner.
/// Ties prefer higher `commit_unix`, then weight. Empty countries are ignored.
pub fn detect_country_conflict(rows: &[CoveringPrefix]) -> (String, bool) {
    let mut votes: HashMap<String, (i64, i64)> = HashMap::new();
    for row in rows {
        if row.country.is_empty() {
            continue;
        }
        // §3.3：特殊国家码（ZZ/XX/A1/A2）不参与地理结论 —— 这里必须与合并侧
        // （covering.rs::sanitize 走的 country_vote_ok）用**同一判定**。否则一张权重很高的
        // 特殊码行（geoip_enrich_iana_special.py 会以 weight 980 写入 ZZ）会在投票里胜出，
        // 被调用方（merge_pipeline）拿去覆盖掉已经过滤好的合并结果，那道过滤就形同不存在。
        if !super::covering::country_vote_ok(&row.country) {
            continue;
        }
        let entry = votes.entry(row.country.clone()).or_insert((0, 0));
        entry.0 += row.weight.max(1);
        entry.1 = entry.1.max(row.commit_unix);
    }
    if votes.is_empty() {
        return (String::new(), false);
    }
    let mut ranked: Vec<(String, i64, i64)> = votes
        .into_iter()
        .map(|(c, (w, cu))| (c, w, cu))
        .collect();
    // Prefer higher weight, then newer commit_unix, **then country name ascending**。
    //
    // 最后一个键是**确定性**收尾，不是审美：`votes` 是 `HashMap`，`into_iter()` 顺序随
    // 进程（RandomState）变化；`sort_by` 稳定，于是「权重与 commit 都相同」的两个国家
    // 之间谁排第一完全随机 ⇒ 胜者随机。而调用方（`covering::merge_pipeline`）会把这个
    // 胜者**无条件写进 `merged.country`** —— 同一 IP、同一份库，不同进程/重启可能给出
    // 不同国家码（并连带触发/不触发城市抑制），违反「结果确定」。国家码字典序收尾后
    // 平票必胜最小者，结果可重复。
    ranked.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then(b.2.cmp(&a.2))
            .then(a.0.cmp(&b.0))
    });
    let (winner, w, _) = ranked[0].clone();
    if ranked.len() < 2 {
        return (winner, false);
    }
    let (_, second, _) = &ranked[1];
    let conflict = *second * 100 >= w * 30;
    (winner, conflict)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(country: &str, weight: i64, commit_unix: i64) -> CoveringPrefix {
        CoveringPrefix {
            country: country.into(),
            weight,
            commit_unix,
            bits: 24,
            prefix: "10.0.0.0/24".into(),
            ..Default::default()
        }
    }

    /// 平票（权重与 commit 全同）必须给出**确定**的胜者，不能随 HashMap 迭代序漂移。
    #[test]
    fn tie_break_is_deterministic() {
        let rows = vec![row("US", 100, 5), row("CN", 100, 5)];
        let first = detect_country_conflict(&rows).0;
        for _ in 0..200 {
            assert_eq!(detect_country_conflict(&rows).0, first, "平票胜者必须稳定");
        }
        // 字典序收尾 ⇒ 最小国家码（CN）胜。
        assert_eq!(first, "CN");
    }

    /// 权重更高者胜；次高 ≥ 30% 判冲突。
    #[test]
    fn weight_wins_and_conflict_threshold() {
        assert_eq!(detect_country_conflict(&[row("US", 100, 1), row("CN", 10, 1)]).0, "US");
        // 10 < 30% * 100 ⇒ 无冲突
        assert!(!detect_country_conflict(&[row("US", 100, 1), row("CN", 10, 1)]).1);
        // 30 >= 30% * 100 ⇒ 冲突
        assert!(detect_country_conflict(&[row("US", 100, 1), row("CN", 30, 1)]).1);
    }

    /// 特殊国家码（ZZ/XX/A1/A2）不参与投票（与合并侧 country_vote_ok 同判定）。
    #[test]
    fn special_country_codes_ignored() {
        let (c, conflict) = detect_country_conflict(&[row("ZZ", 990, 1), row("US", 10, 1)]);
        assert_eq!(c, "US");
        assert!(!conflict);
    }
}
