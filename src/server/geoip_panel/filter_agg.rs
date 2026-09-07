//! Filter and aggregate GeoIP query results.

use std::collections::HashMap;

/// Aggregate lookup rows by country code (ISO or free-text country field).
pub fn aggregate_by_country(rows: &[String]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for row in rows {
        let country = row.trim();
        if country.is_empty() {
            continue;
        }
        *counts.entry(country.to_string()).or_default() += 1;
    }
    let mut out: Vec<(String, usize)> = counts.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}
