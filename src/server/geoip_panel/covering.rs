//! Prefix covering / merge helpers for GeoIP data (§23.5).

use anyhow::Result;
use rusqlite::Connection;

/// One covering prefix row used during field merge.
#[derive(Clone, Debug, Default)]
pub struct CoveringPrefix {
    pub prefix: String,
    pub bits: u32,
    pub weight: i64,
    pub commit_unix: i64,
    pub country: String,
    pub province: String,
    pub region: String,
    pub city: String,
    pub district: String,
    pub isp: String,
    pub dc: String,
    pub asn: String,
    pub as_org: String,
    pub net_org: String,
    pub cloud_provider: String,
    pub cloud_region: String,
    pub cloud_service: String,
    pub hosting: String,
    pub division_code: String,
    pub e_country: i64,
    pub e_province: i64,
    pub e_city: i64,
    pub e_district: i64,
    pub e_isp: i64,
    pub e_asn: i64,
    pub e_as_org: i64,
    pub e_net_org: i64,
    pub e_cloud_provider: i64,
    pub e_cloud_region: i64,
    pub e_cloud_service: i64,
    pub e_hosting: i64,
}

/// Merged covering result with how many prefixes participated.
#[derive(Clone, Debug, Default)]
pub struct MergedFields {
    pub country: String,
    pub province: String,
    pub region: String,
    pub city: String,
    pub district: String,
    pub isp: String,
    pub dc: String,
    pub asn: String,
    pub as_org: String,
    pub net_org: String,
    pub cloud_provider: String,
    pub cloud_region: String,
    pub cloud_service: String,
    pub hosting: String,
    pub division_code: String,
    pub prefix: String,
    pub bits: u32,
    pub weight: i64,
    pub commit_unix: i64,
    pub prefixes_merged: usize,
}

pub fn overlapping_prefix_count(conn: &Connection, ip: &str) -> Result<usize> {
    Ok(load_covering_prefixes(conn, ip)?.len())
}

pub fn load_covering_prefixes(conn: &Connection, ip: &str) -> Result<Vec<CoveringPrefix>> {
    let mut out = load_from_geoip(conn, ip)?;
    // Also merge ipv4/ipv6 range tables when present (§23 dual schema).
    if let Ok(extra) = load_from_range_table(conn, "ipv4", ip) {
        out.extend(extra);
    }
    if ip.contains(':') {
        if let Ok(extra) = load_from_range_table(conn, "ipv6", ip) {
            out.extend(extra);
        }
    }
    Ok(out)
}

fn map_covering_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CoveringPrefix> {
    Ok(CoveringPrefix {
        prefix: row.get(0)?,
        bits: row.get::<_, i64>(1)? as u32,
        weight: row.get(2)?,
        commit_unix: row.get(3)?,
        country: row.get(4)?,
        province: row.get(5)?,
        region: row.get(6)?,
        city: row.get(7)?,
        district: row.get(8)?,
        isp: row.get(9)?,
        dc: row.get(10)?,
        asn: row.get(11)?,
        as_org: row.get(12)?,
        net_org: row.get(13)?,
        cloud_provider: row.get(14)?,
        cloud_region: row.get(15)?,
        cloud_service: row.get(16)?,
        hosting: row.get(17)?,
        division_code: row.get(18)?,
        e_country: row.get(19)?,
        e_province: row.get(20)?,
        e_city: row.get(21)?,
        e_district: row.get(22)?,
        e_isp: row.get(23)?,
        e_asn: row.get(24)?,
        e_as_org: row.get(25)?,
        e_net_org: row.get(26)?,
        e_cloud_provider: row.get(27)?,
        e_cloud_region: row.get(28)?,
        e_cloud_service: row.get(29)?,
        e_hosting: row.get(30)?,
    })
}

fn load_from_geoip(conn: &Connection, ip: &str) -> Result<Vec<CoveringPrefix>> {
    // §23.8：数值范围索引查询（start_i/end_i；TEXT BETWEEN 无法走索引）。
    // v6 走 ipv6 表路径——geoip 表只存 v4 行。
    let target_i: i64 = match ip.parse::<std::net::Ipv4Addr>() {
        Ok(v4) => i64::from(u32::from(v4)),
        Err(_) => return Ok(Vec::new()),
    };
    let mut stmt = conn.prepare(
        "SELECT COALESCE(prefix, ip_start || '-' || ip_end),
                COALESCE(bits, 0),
                COALESCE(weight, 0),
                COALESCE(commit_unix, 0),
                COALESCE(country, ''),
                COALESCE(province, region, ''),
                COALESCE(region, ''),
                COALESCE(city, ''),
                COALESCE(district, ''),
                COALESCE(isp, ''),
                COALESCE(dc, ''),
                COALESCE(asn, ''),
                COALESCE(as_org, ''),
                COALESCE(net_org, ''),
                COALESCE(cloud_provider, ''),
                COALESCE(cloud_region, ''),
                COALESCE(cloud_service, ''),
                COALESCE(hosting, ''),
                COALESCE(division_code, ''),
                COALESCE(e_country, 0),
                COALESCE(e_province, 0),
                COALESCE(e_city, 0),
                COALESCE(e_district, 0),
                COALESCE(e_isp, 0),
                COALESCE(e_asn, 0),
                COALESCE(e_as_org, 0),
                COALESCE(e_net_org, 0),
                COALESCE(e_cloud_provider, 0),
                COALESCE(e_cloud_region, 0),
                COALESCE(e_cloud_service, 0),
                COALESCE(e_hosting, 0),
                ip_start,
                ip_end
         FROM geoip
         WHERE start_i <= ?1 AND end_i >= ?1
         ORDER BY COALESCE(commit_unix, 0) ASC, COALESCE(weight, 0) ASC, COALESCE(bits, 0) ASC",
    )?;
    let rows = stmt.query_map([target_i], |row| {
        let mut p = map_covering_row(row)?;
        let start: String = row.get(31)?;
        let end: String = row.get(32)?;
        Ok((p, start, end))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (p, start, end) = r?;
        if crate::server::geoip_panel::iputil::ipv4_in_range(ip, &start, &end)
            || crate::server::geoip_panel::iputil::ipv6_in_range(ip, &start, &end)
        {
            out.push(p);
        }
    }
    Ok(out)
}

fn load_from_range_table(conn: &Connection, table: &str, ip: &str) -> Result<Vec<CoveringPrefix>> {
    // table name is internal only (ipv4/ipv6). Column order MUST match map_covering_row
    // (index 10 = dc; ipv4/ipv6 schema has no dc column → empty string).
    // Filter in Rust — SQLite TEXT compare breaks on "9." vs "10.".
    let sql = format!(
        "SELECT COALESCE(prefix, start || '-' || end),
                COALESCE(bits, 0),
                COALESCE(weight, 0),
                COALESCE(commit_unix, 0),
                COALESCE(country, ''),
                COALESCE(province, region, ''),
                COALESCE(region, ''),
                COALESCE(city, ''),
                COALESCE(district, ''),
                COALESCE(isp, ''),
                '',
                COALESCE(asn, ''),
                COALESCE(as_org, ''),
                COALESCE(net_org, ''),
                COALESCE(cloud_provider, ''),
                COALESCE(cloud_region, ''),
                COALESCE(cloud_service, ''),
                COALESCE(hosting, ''),
                COALESCE(division_code, ''),
                COALESCE(e_country, 0),
                COALESCE(e_province, 0),
                COALESCE(e_city, 0),
                COALESCE(e_district, 0),
                COALESCE(e_isp, 0),
                COALESCE(e_asn, 0),
                COALESCE(e_as_org, 0),
                COALESCE(e_net_org, 0),
                COALESCE(e_cloud_provider, 0),
                COALESCE(e_cloud_region, 0),
                COALESCE(e_cloud_service, 0),
                COALESCE(e_hosting, 0),
                start,
                end
         FROM {table}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| {
        let p = map_covering_row(row)?;
        let start: String = row.get(31)?;
        let end: String = row.get(32)?;
        Ok((p, start, end))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (p, start, end) = r?;
        let hit = if table == "ipv4" || !ip.contains(':') {
            crate::server::geoip_panel::iputil::ipv4_in_range(ip, &start, &end)
        } else {
            crate::server::geoip_panel::iputil::ipv6_in_range(ip, &start, &end)
        };
        if hit {
            out.push(p);
        }
    }
    Ok(out)
}

/// Field preference key: 标准合并语义 = 信任权重优先，其次 field epoch/commit，再 bits。
type FieldScore = (i64, i64, i64);

/// §3.3 查询期过滤：忽略特殊国家码（ZZ/XX/A1/A2）——不参与地理结论。
fn country_vote_ok(cc: &str) -> bool {
    let c = cc.trim().to_ascii_uppercase();
    !matches!(c.as_str(), "ZZ" | "XX" | "A1" | "A2")
}

/// §3.3 查询期过滤：丢弃「country=CN 但城市写外国名」的 QQWry 污染票。
fn cn_city_polluted(row_country: &str, city: &str) -> bool {
    if !row_country.eq_ignore_ascii_case("CN") {
        return false;
    }
    const FOREIGN: &[&str] = &[
        "美国", "日本", "英国", "德国", "法国", "韩国", "俄罗斯", "加拿大",
        "澳大利亚", "新加坡", "印度", "荷兰",
    ];
    FOREIGN.iter().any(|f| city.contains(f))
}

fn sanitize<'a>(field: &str, row_country: &str, value: &'a str) -> &'a str {
    if field == "country" && !country_vote_ok(value) {
        return "";
    }
    if field == "city" && cn_city_polluted(row_country, value) {
        return "";
    }
    value
}

pub fn merge_covering_fields(rows: &[CoveringPrefix]) -> CoveringPrefix {
    let mut out = CoveringPrefix::default();
    let mut scores = [FieldScore::default(); 15];

    for row in rows {
        prefer_field(
            &mut out.country,
            &mut scores[0],
            sanitize("country", &row.country, &row.country),
            row.e_country,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.province,
            &mut scores[1],
            &row.province,
            row.e_province,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.region,
            &mut scores[2],
            &row.region,
            0,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.city,
            &mut scores[3],
            sanitize("city", &row.country, &row.city),
            row.e_city,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.district,
            &mut scores[4],
            &row.district,
            row.e_district,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.isp,
            &mut scores[5],
            &row.isp,
            row.e_isp,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.dc,
            &mut scores[6],
            &row.dc,
            0,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.asn,
            &mut scores[7],
            &row.asn,
            row.e_asn,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.as_org,
            &mut scores[8],
            &row.as_org,
            row.e_as_org,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.net_org,
            &mut scores[9],
            &row.net_org,
            row.e_net_org,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.cloud_provider,
            &mut scores[10],
            &row.cloud_provider,
            row.e_cloud_provider,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.cloud_region,
            &mut scores[11],
            &row.cloud_region,
            row.e_cloud_region,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.cloud_service,
            &mut scores[12],
            &row.cloud_service,
            row.e_cloud_service,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.hosting,
            &mut scores[13],
            &row.hosting,
            row.e_hosting,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        prefer_field(
            &mut out.division_code,
            &mut scores[14],
            &row.division_code,
            0,
            row.commit_unix,
            row.weight,
            row.bits,
        );
        if out.prefix.is_empty() || row.bits >= out.bits {
            out.prefix = row.prefix.clone();
            out.bits = row.bits;
        }
        out.weight = out.weight.max(row.weight);
        out.commit_unix = out.commit_unix.max(row.commit_unix);
    }
    out
}

pub fn merge_covering(rows: &[CoveringPrefix]) -> MergedFields {
    let m = merge_covering_fields(rows);
    MergedFields {
        country: m.country,
        province: m.province,
        region: m.region,
        city: m.city,
        district: m.district,
        isp: m.isp,
        dc: m.dc,
        asn: m.asn,
        as_org: m.as_org,
        net_org: m.net_org,
        cloud_provider: m.cloud_provider,
        cloud_region: m.cloud_region,
        cloud_service: m.cloud_service,
        hosting: m.hosting,
        division_code: m.division_code,
        prefix: m.prefix,
        bits: m.bits,
        weight: m.weight,
        commit_unix: m.commit_unix,
        prefixes_merged: rows.len(),
    }
}

/// Prefer newer commit_unix (or field epoch), then weight + path-priority gain, then bits.
/// §23.6 path-priority: longer prefixes get `bits * PATH_PRIORITY_GAIN` added to weight.
pub const PATH_PRIORITY_GAIN: i64 = 10;

fn prefer_field(
    dst: &mut String,
    dst_score: &mut FieldScore,
    src: &str,
    field_epoch: i64,
    commit_unix: i64,
    weight: i64,
    bits: u32,
) {
    if src.is_empty() {
        return;
    }
    let epoch = if field_epoch > 0 {
        field_epoch
    } else {
        commit_unix
    };
    let effective_weight = weight.saturating_add((bits as i64).saturating_mul(PATH_PRIORITY_GAIN));
    // 标准：score = weight * 10^10 + commit_unix 的元组等价形式（权重优先）。
    let score: FieldScore = (effective_weight, epoch, bits as i64);
    if dst.is_empty() || score >= *dst_score {
        *dst = src.to_string();
        *dst_score = score;
    }
}

pub fn lookup_merged(conn: &Connection, ip: &str) -> Result<MergedFields> {
    let rows = load_covering_prefixes(conn, ip)?;
    let mut merged = merge_covering(&rows);
    if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
        let (country, conflict) = super::conflict::detect_country_conflict(&rows);
        if !country.is_empty() {
            merged.country = country;
        }
        if super::anycast::suppress_locality(conflict, super::anycast::is_anycast_conn(conn, ip_addr)) {
            merged.province.clear();
            merged.city.clear();
            merged.district.clear();
        }
    }
    if let Ok(panel) = super::db::open_panel(std::path::Path::new("data/geoip/panel.sqlite")) {
        let _ = super::ops::apply_panel_edits(&panel, &mut merged);
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        country: &str,
        commit_unix: i64,
        weight: i64,
        e_country: i64,
    ) -> CoveringPrefix {
        CoveringPrefix {
            country: country.into(),
            commit_unix,
            weight,
            e_country,
            bits: 24,
            prefix: "10.0.0.0/24".into(),
            ..Default::default()
        }
    }

    #[test]
    fn prefer_higher_commit_unix() {
        // effective_weight = weight + bits * PATH_PRIORITY_GAIN
        // US: 90 + 24*10 = 330, CN: 10 + 24*10 = 250 -> US wins (weight priority)
        let rows = vec![row("US", 100, 90, 0), row("CN", 200, 10, 0)];
        let m = merge_covering(&rows);
        assert_eq!(m.country, "US");
    }

    #[test]
    fn empty_never_overwrites() {
        let rows = vec![
            CoveringPrefix {
                country: "CN".into(),
                city: "Hangzhou".into(),
                commit_unix: 100,
                weight: 50,
                bits: 16,
                ..Default::default()
            },
            CoveringPrefix {
                country: "".into(),
                city: "".into(),
                isp: "Demo".into(),
                commit_unix: 999,
                weight: 99,
                bits: 32,
                ..Default::default()
            },
        ];
        let m = merge_covering(&rows);
        assert_eq!(m.country, "CN");
        assert_eq!(m.city, "Hangzhou");
        assert_eq!(m.isp, "Demo");
    }

    #[test]
    fn field_epoch_beats_commit_unix() {
        let rows = vec![
            row("US", 500, 10, 0),
            row("JP", 100, 10, 600),
        ];
        let m = merge_covering(&rows);
        assert_eq!(m.country, "JP");
    }

    #[test]
    fn merge_exposes_cloud_and_locality_fields() {
        let rows = vec![CoveringPrefix {
            country: "US".into(),
            province: "California".into(),
            city: "San Jose".into(),
            district: "".into(),
            isp: "Tencent".into(),
            asn: "132203".into(),
            as_org: "Tencent".into(),
            cloud_provider: "腾讯云".into(),
            cloud_region: "us-sanjose-1".into(),
            cloud_service: "cvm".into(),
            hosting: "".into(),
            division_code: "".into(),
            bits: 16,
            prefix: "119.28.0.0/16".into(),
            commit_unix: 1,
            weight: 80,
            ..Default::default()
        }];
        let m = merge_covering(&rows);
        assert_eq!(m.cloud_provider, "腾讯云");
        assert_eq!(m.cloud_region, "us-sanjose-1");
        assert_eq!(m.province, "California");
        assert_eq!(m.prefixes_merged, 1);
        assert_eq!(m.bits, 16);
    }
}
