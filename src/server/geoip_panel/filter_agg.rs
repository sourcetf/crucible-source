//! GeoIP 面板筛选聚合（§23.10 模块职责表点名本文件：「面板筛选聚合」）。
//!
//! P2-18：本模块从 `ops.rs` 迁移而来（逐字搬迁，行为不变）。`ops.rs` 通过
//! `pub use` 重新导出 [`FilterRow`] 与 [`filter_prefixes`]，因此既有调用点
//!（`admin_geoip::handle_filter_with_live`、`ops.rs` 内单测）完全不受影响。

use anyhow::Result;
use rusqlite::Connection;

/// 一条筛选结果（Admin 面板表格展示用）。
pub struct FilterRow {
    pub prefix: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub cloud_provider: String,
    pub weight: i64,
}

/// 转义 LIKE 元字符（`%` `_` `\`），避免面板输入的 `%` 被当成通配符。
/// 配合 SQL 侧的 `ESCAPE '\'` 使用。
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Filter geoip rows by country/isp/cloud（Admin 面板筛选；结果携带字段供表格渲染）。
///
/// 三张表都要查：`geoip`（主表）与 §23 双 schema 的 `ipv4`/`ipv6` range 表。
/// 旧实现只 `FROM geoip` —— 写入 `ipv4`/`ipv6` 表的行（v6 demo/镜像数据）在面板里
/// 永远筛不到，表现为「库里有数据、筛选结果为空」。列名差异（ip_start/ip_end vs
/// start/end、缺 dc）在子查询里对齐。
///
/// §23.6 追加两个维度（规格「按国家/城市/地区/运营商/**IPv4|v6** 等筛」）：
/// - `family`：`v4`/`ipv4`/`4` 只留 IPv4，`v6`/`ipv6`/`6` 只留 IPv6，其余（空）不过滤。
///   判定用**前缀文本**是否含 `:`（IPv6 字面量必含冒号；主表 `geoip` 与 range 表
///   `ipv4`/`ipv6` 三路 UNION 之后 `prefix` 列口径统一，故在派生表外层过滤即可，
///   无需按表名区分）。
/// - `prefix`：对（可能已 COALESCE 的）前缀做**包含**匹配，便于按 `1.2.4.0/24`
///   或某个网段片段定位。与 country 等一样做 LIKE 元字符转义。
pub fn filter_prefixes(
    conn: &Connection,
    country: Option<&str>,
    isp: Option<&str>,
    cloud: Option<&str>,
    family: Option<&str>,
    prefix: Option<&str>,
    limit: usize,
) -> Result<Vec<FilterRow>> {
    let lim = limit.min(500);
    let c = country.unwrap_or("").to_ascii_lowercase();
    let i = isp.unwrap_or("").to_ascii_lowercase();
    let cl = cloud.unwrap_or("").to_ascii_lowercase();
    // 归一化 family：只保留三种语义（v4 / v6 / 空）。其余值（含拼写错误）按空处理，
    // 不做「静默当 v4」——那是把运维的笔误变成错误结果。
    let fam = match family.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "v4" | "ipv4" | "4" => "v4",
        "v6" | "ipv6" | "6" => "v6",
        _ => "",
    };
    let pfx = prefix.unwrap_or("").to_ascii_lowercase();
    // 过滤下推到 SQL。原实现是 `ORDER BY weight DESC LIMIT 5000` 之后再在 Rust 里
    // 按 country/isp/cloud 过滤 —— 命中的行只要排在权重前 5000 之外就被**静默截断**
    // （面板显示「没有结果」，其实数据存在）。这里的 LIMIT 作用在过滤后的结果集上。
    // 大小写：SQLite 的 LIKE 对 ASCII 不区分大小写（等价于原来的 to_ascii_lowercase
    // 包含匹配）；lower() 只为把意图写死，非 ASCII 与原来一样不做大小写折叠。
    let where_clause = "WHERE (?1 = ''
                 OR lower(COALESCE(country, '')) LIKE '%' || ?1 || '%' ESCAPE '\\'
                 OR lower(COALESCE(province, '')) LIKE '%' || ?1 || '%' ESCAPE '\\'
                 OR lower(COALESCE(city, '')) LIKE '%' || ?1 || '%' ESCAPE '\\')
           AND (?2 = '' OR lower(COALESCE(isp, '')) LIKE '%' || ?2 || '%' ESCAPE '\\')
           AND (?3 = '' OR lower(COALESCE(cloud_provider, '')) LIKE '%' || ?3 || '%' ESCAPE '\\')";
    let sql = format!(
        "SELECT prefix, country, province, city, isp, cloud_provider, weight FROM (
             SELECT COALESCE(prefix, ip_start || '-' || ip_end) AS prefix,
                    COALESCE(country, '') AS country, COALESCE(province, '') AS province,
                    COALESCE(city, '') AS city, COALESCE(isp, '') AS isp,
                    COALESCE(cloud_provider, '') AS cloud_provider,
                    COALESCE(weight, 0) AS weight
               FROM geoip {where_clause}
             UNION ALL
             SELECT COALESCE(prefix, start || '-' || end), COALESCE(country, ''),
                    COALESCE(province, ''), COALESCE(city, ''), COALESCE(isp, ''),
                    COALESCE(cloud_provider, ''), COALESCE(weight, 0)
               FROM ipv4 {where_clause}
             UNION ALL
             SELECT COALESCE(prefix, start || '-' || end), COALESCE(country, ''),
                    COALESCE(province, ''), COALESCE(city, ''), COALESCE(isp, ''),
                    COALESCE(cloud_provider, ''), COALESCE(weight, 0)
               FROM ipv6 {where_clause}
         )
         WHERE (?5 = ''
                OR (?5 = 'v6' AND instr(prefix, ':') > 0)
                OR (?5 = 'v4' AND instr(prefix, ':') = 0))
           AND (?6 = '' OR lower(prefix) LIKE '%' || ?6 || '%' ESCAPE '\\')
         ORDER BY weight DESC LIMIT ?4"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params![
            like_escape(&c),
            like_escape(&i),
            like_escape(&cl),
            lim as i64,
            fam,
            like_escape(&pfx)
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        },
    )?;
    let mut out = Vec::new();
    for row in rows {
        let (prefix, country, province, city, isp, cloud_provider, weight) = row?;
        out.push(FilterRow {
            prefix,
            country,
            province,
            city,
            isp,
            cloud_provider,
            weight,
        });
    }
    Ok(out)
}
