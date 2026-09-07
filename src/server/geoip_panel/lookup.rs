//! GeoIP lookup — covering merge, label, anycast (§23 / §23.2).

use super::covering::{self, MergedFields};
use super::db;
use anyhow::Result;
use std::net::IpAddr;
use std::path::Path;

/// Unified query result schema per §23.2.
#[derive(Debug, Clone, Default)]
pub struct GeoResult {
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
    pub label: String,
    pub dc: String,
}

impl GeoResult {
    pub fn from_merged(m: MergedFields) -> Self {
        let mut r = Self {
            country: m.country,
            province: m.province,
            city: m.city,
            district: m.district,
            isp: m.isp,
            asn: m.asn,
            as_org: m.as_org,
            net_org: m.net_org,
            cloud_provider: m.cloud_provider,
            cloud_region: m.cloud_region,
            cloud_service: m.cloud_service,
            hosting: m.hosting,
            division_code: m.division_code,
            bits: m.bits,
            prefixes_merged: m.prefixes_merged,
            label: String::new(),
            dc: m.dc,
        };
        r.label = format_label(&r);
        r
    }
}

/// Human-readable label per §23.2.
///
/// - Cloud: `{cloud_provider} {cloud_region|city}` + optional isp + `AS{asn} {as_org}`
/// - Else: `{province} {city} {district} {isp}` + hosting + ASN
pub fn format_label(r: &GeoResult) -> String {
    if !r.cloud_provider.is_empty() {
        let mut head = r.cloud_provider.clone();
        let region_or_city = if !r.cloud_region.is_empty() {
            r.cloud_region.as_str()
        } else {
            r.city.as_str()
        };
        if !region_or_city.is_empty() {
            head.push(' ');
            head.push_str(region_or_city);
        }
        let mut parts = vec![head];
        if !r.isp.is_empty() {
            parts.push(r.isp.clone());
        }
        if !r.asn.is_empty() {
            parts.push(format_asn(&r.asn, &r.as_org));
        }
        return parts.join(" / ");
    }

    let mut geo: Vec<&str> = Vec::new();
    for p in [&r.province, &r.city, &r.district, &r.isp] {
        if !p.is_empty() {
            geo.push(p);
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if !geo.is_empty() {
        parts.push(geo.join(" "));
    }
    if !r.hosting.is_empty() {
        parts.push(r.hosting.clone());
    }
    if !r.asn.is_empty() {
        parts.push(format_asn(&r.asn, &r.as_org));
    }
    parts.join(" / ")
}

fn format_asn(asn: &str, as_org: &str) -> String {
    let mut s = format!("AS{asn}");
    if !as_org.is_empty() {
        s.push(' ');
        s.push_str(as_org);
    }
    s
}

pub fn lookup(db_path: &Path, ip: IpAddr) -> Result<Option<GeoResult>> {
    let conn = db::open(db_path)?;
    let m = covering::lookup_merged(&conn, &ip.to_string())?;
    if m.country.is_empty()
        && m.city.is_empty()
        && m.isp.is_empty()
        && m.asn.is_empty()
        && m.cloud_provider.is_empty()
    {
        return Ok(None);
    }
    Ok(Some(GeoResult::from_merged(m)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_label_cloud() {
        let r = GeoResult {
            cloud_provider: "腾讯云".into(),
            cloud_region: "us-sanjose-1".into(),
            asn: "132203".into(),
            as_org: "Tencent".into(),
            ..Default::default()
        };
        assert_eq!(format_label(&r), "腾讯云 us-sanjose-1 / AS132203 Tencent");
    }

    #[test]
    fn format_label_geo() {
        let r = GeoResult {
            province: "浙江省".into(),
            city: "杭州市".into(),
            isp: "中国联通".into(),
            asn: "24409".into(),
            as_org: "China Unicom".into(),
            ..Default::default()
        };
        assert_eq!(
            format_label(&r),
            "浙江省 杭州市 中国联通 / AS24409 China Unicom"
        );
    }
}
