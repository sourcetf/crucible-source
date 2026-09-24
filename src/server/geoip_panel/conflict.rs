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
    // Prefer higher weight, then newer commit_unix.
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
    let (winner, w, _) = ranked[0].clone();
    if ranked.len() < 2 {
        return (winner, false);
    }
    let (_, second, _) = &ranked[1];
    let conflict = *second * 100 >= w * 30;
    (winner, conflict)
}
