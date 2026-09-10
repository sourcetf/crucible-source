//! GeoIP covering / 覆盖合并器（stub 实现）。
//! 实际在 OpenBSD 完整实现中合并 CERNET、RIR、云厂商等数据源。

use crate::server::geoip_panel::db::open;
use rusqlite::Connection;
use std::path::Path;

/// 合并后的字段
#[derive(Debug, Clone, Default)]
pub struct MergedFields {
    pub country: String,
    pub province: String,
    pub city: String,
    pub district: String,
    pub isp: String,
    pub asn: String,
    pub as_org: String,
    pub net_org: String,
    pub cloud_provider: String,
    pub cloud_region: String,
    pub cloud_service: String,
    pub hosting: String,
    pub division_code: String,
    pub bits: u32,
    pub prefixes_merged: usize,
    pub dc: String,
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