//! GeoIP covering / 覆盖合并器（stub 实现）。
//! 实际在 OpenBSD 完整实现中合并 CERNET、RIR、云厂商等数据源。

use rusqlite::Connection;

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