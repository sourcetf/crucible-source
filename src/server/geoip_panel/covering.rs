//! Prefix covering / merge helpers for GeoIP data (§23.5).

use crate::server::geoip_panel::db::open;
use rusqlite::Connection;
use std::path::Path;

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

pub fn lookup_merged(_conn: &Connection, _ip: &str) -> anyhow::Result<MergedFields> {
    Ok(MergedFields::default())
}

/// 加载覆盖前缀（覆盖面查询结果行）
pub struct CoveringRow {
    pub prefix: String,
    pub bits: u32,
    pub weight: i64,
    pub country: String,
    pub province: String,
    pub city: String,
    pub district: String,
    pub isp: String,
    pub asn: String,
    pub as_org: String,
    pub cloud_provider: String,
    pub cloud_region: String,
    pub cloud_service: String,
    pub hosting: String,
    pub division_code: String,
    pub dc: String,
}

/// 从 covering 数据库加载 IP 覆盖前缀
/// 覆盖数据库位于 data/geoip/current/geoip.sqlite 或其它路径
pub fn load_covering_prefixes(db_path: &Path, _ip: &str) -> anyhow::Result<Vec<CoveringRow>> {
    let conn = open(db_path)?;
    // 确保 covering 表存在（首次运行或从旧版迁移时可能缺失）
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS covering (
            source TEXT, prefix TEXT, bits INTEGER, weight INTEGER,
            country TEXT, province TEXT, city TEXT, district TEXT,
            isp TEXT, asn TEXT, as_org TEXT, cloud_provider TEXT,
            cloud_region TEXT, cloud_service TEXT, hosting TEXT,
            division_code TEXT, dc TEXT,
            commit_unix INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_covering_prefix ON covering(prefix);",
    )?;

    let mut stmt = conn.prepare(
        "SELECT prefix, bits, weight, country, province, city, district, isp, asn, \
         as_org, cloud_provider, cloud_region, cloud_service, hosting, division_code, dc \
         FROM covering"
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(CoveringRow {
                prefix: row.get(0)?,
                bits: row.get(1)?,
                weight: row.get(2)?,
                country: row.get(3)?,
                province: row.get(4)?,
                city: row.get(5)?,
                district: row.get(6)?,
                isp: row.get(7)?,
                asn: row.get(8)?,
                as_org: row.get(9)?,
                cloud_provider: row.get(10)?,
                cloud_region: row.get(11)?,
                cloud_service: row.get(12)?,
                hosting: row.get(13)?,
                division_code: row.get(14)?,
                dc: row.get(15)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}