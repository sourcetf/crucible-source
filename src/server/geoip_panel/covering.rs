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

pub fn load_covering_prefixes(conn: &Connection, ip: &str) -> Result<Vec<CoveringPrefix>> {
    // 入口归一化：v4-mapped（`::ffff:a.b.c.d`）折回 v4，并把地址重写成规范字符串。
    //
    // 为什么必须在这里做：本函数按**地址族分流**（v4 走 geoip/ipv4 表、v6 走 ipv6 表），
    // 且 `load_from_geoip` 用 `ip.parse::<Ipv4Addr>()` 判族。带 `::ffff:` 前缀的 v4 客户端
    // 会被当成纯 v6 去查 ipv6 表 —— 库里有该 v4 段却返回空（面板显示「无结果」），
    // 与 `apply_panel_edits` / `anycast::is_anycast_conn` / `rate_limit` / `access` /
    // `basic_auth` 早就统一的口径不一致。admin_geoip 恰好在调用前 unmap 了，所以这条
    // 静默缺口只在其它调用方（`lookup::lookup`、`overlapping_prefix_count` 以及未来调用者）
    // 上暴露 —— 归一化放在唯一的入口处，谁调都安全。
    // 非 IP 字面量（畸形输入）保持原样：下面各查询会自行判空。
    let ip_norm = match crate::server::geoip_panel::iputil::parse_ip(ip) {
        Some(a) => crate::server::geoip_panel::iputil::unmap_v4_mapped(a).to_string(),
        None => ip.to_string(),
    };
    let ip = ip_norm.as_str();
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
         -- 与下面 range 表那条查询**口径一致**：老行（迁移前建的）start_i/end_i 为 NULL，
         -- 而 `NULL <= ?` 结果是 NULL ⇒ 这些行会被整条排除掉。range 表那条早就为这个加了
         -- `IS NULL` 放行（见文件下方的注释），geoip 这张表漏了 —— 同一个库两条路径给出
         -- 不同的覆盖结果（面板 lookup 少行/空）。
         WHERE start_i IS NULL OR (start_i <= ?1 AND end_i >= ?1)
         -- rowid 收尾：合并侧 prefer_field/prefix 用 `>=`（同分时后行胜），而
         -- (commit_unix,weight,bits) 相同的行在 SQLite 里顺序未定义 —— 少了唯一键，
         -- 同一查询在不同查询计划（是否走 idx_geoip_numeric）下可能选出不同字段值。
         ORDER BY COALESCE(commit_unix, 0) ASC, COALESCE(weight, 0) ASC, COALESCE(bits, 0) ASC, rowid ASC",
    )?;
    let rows = stmt.query_map([target_i], |row| {
        let p = map_covering_row(row)?;
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
    // §23.8：数值范围列预过滤（idx_*_numeric）。`start_i IS NULL` 的老行必须放行——
    // 否则未回填的行会静默消失（精确包含判定仍在 Rust 侧，放行多余行无害）。
    // 列语义见 iputil::range_numeric_key；解析失败时 key=0，反正下面 Rust 判定必拒。
    let key = crate::server::geoip_panel::iputil::range_numeric_key(ip).unwrap_or(0);
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
         FROM {table}
         WHERE start_i IS NULL OR (start_i <= ?1 AND end_i >= ?1)
         -- 与 load_from_geoip 的 ORDER BY **逐键一致**（含 rowid 唯一键收尾）。
         -- 原来这条完全没有 ORDER BY：SQLite 对无 ORDER BY 的扫描返回顺序取决于查询计划
         -- （走 idx_*_numeric 索引 vs 全表扫描 ⇒ 索引序 vs rowid 序），而合并侧同分取后行，
         -- 于是「同一份数据在不同计划/建索引前后」会合并出不同的字段值与命中前缀。
         ORDER BY COALESCE(commit_unix, 0) ASC, COALESCE(weight, 0) ASC, COALESCE(bits, 0) ASC, rowid ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([key], |row| {
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
///
/// `pub(crate)`：冲突投票（conflict.rs）必须用**同一判定**，否则它会用未过滤的票
/// 选出 ZZ 之类的特殊码，再覆盖掉这里已过滤好的合并结果（等于整道滤白做）。
pub(crate) fn country_vote_ok(cc: &str) -> bool {
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

/// 用当前生效的路径优先级增益做字段合并（运行期入口）。
pub fn merge_covering_fields(rows: &[CoveringPrefix]) -> CoveringPrefix {
    merge_covering_fields_with_gain(rows, path_priority_gain())
}

/// 用**显式**增益做字段合并（单测 / golden 向量 / 与 Python 离线侧对齐）。
///
/// 评分口径（G-10，Rust 与 `scripts/geoip_common.py::merge_covering` 逐字一致）：
/// `(weight + bits * gain, epoch, bits)`，同分时**后行胜**（`>=`；行序由
/// `load_covering_prefixes` 的 `ORDER BY commit,weight,bits,rowid` 固定，等价于
/// 第 4 个确定性 tiebreak 分量 = 行序号）。空值永不覆盖非空。
pub fn merge_covering_fields_with_gain(rows: &[CoveringPrefix], gain: i64) -> CoveringPrefix {
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
            gain,
        );
        prefer_field(
            &mut out.province,
            &mut scores[1],
            &row.province,
            row.e_province,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.region,
            &mut scores[2],
            &row.region,
            0,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.city,
            &mut scores[3],
            sanitize("city", &row.country, &row.city),
            row.e_city,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.district,
            &mut scores[4],
            &row.district,
            row.e_district,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.isp,
            &mut scores[5],
            &row.isp,
            row.e_isp,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.dc,
            &mut scores[6],
            &row.dc,
            0,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.asn,
            &mut scores[7],
            &row.asn,
            row.e_asn,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.as_org,
            &mut scores[8],
            &row.as_org,
            row.e_as_org,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.net_org,
            &mut scores[9],
            &row.net_org,
            row.e_net_org,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.cloud_provider,
            &mut scores[10],
            &row.cloud_provider,
            row.e_cloud_provider,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.cloud_region,
            &mut scores[11],
            &row.cloud_region,
            row.e_cloud_region,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.cloud_service,
            &mut scores[12],
            &row.cloud_service,
            row.e_cloud_service,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.hosting,
            &mut scores[13],
            &row.hosting,
            row.e_hosting,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
        );
        prefer_field(
            &mut out.division_code,
            &mut scores[14],
            &row.division_code,
            0,
            row.commit_unix,
            row.weight,
            row.bits,
            gain,
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

/// §23.6 路径优先级增益的默认值（`[geoip] path_priority_gain` 的 serde 默认）。
///
/// G-17：原来是编译期常量，运维无法按数据源调整。现在由
/// `[geoip] path_priority_gain`（config.toml）或 `data/geoip/panel.toml`
/// （面板设置，优先级更高）决定，启动/热载时经 [`set_path_priority_gain`] 生效。
/// 默认 10 与旧行为逐位一致（零变化）。
pub const DEFAULT_PATH_PRIORITY_GAIN: i64 = 10;

/// 当前生效的路径优先级增益。
///
/// 用原子量而不是把 gain 穿进每个调用点：`merge_covering` 在请求热路径上被
/// 页面规则 country 维度与面板 lookup 调用，签名保持不变才能避免改动 10+ 个
/// 跨协议调用方；配置热载/面板保存是低频事件，写侧一次 store 即可。
static PATH_PRIORITY_GAIN: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(DEFAULT_PATH_PRIORITY_GAIN);

/// 当前生效的路径优先级增益（默认 [`DEFAULT_PATH_PRIORITY_GAIN`]）。
pub fn path_priority_gain() -> i64 {
    PATH_PRIORITY_GAIN.load(std::sync::atomic::Ordering::Relaxed)
}

/// 设置路径优先级增益（配置加载 / 面板保存 / 热载时调用）。
pub fn set_path_priority_gain(gain: i64) {
    PATH_PRIORITY_GAIN.store(gain, std::sync::atomic::Ordering::Relaxed);
}

/// 单个字段的评分：`(weight + bits * gain, epoch, bits)`，同分后行胜。
///
/// 公开给 golden 向量单测与跨语言对照用；`epoch` 取字段 epoch（`e_*`），
/// 为 0 时回落该行的 `commit_unix`。saturating 运算防止畸形大权重溢出。
pub fn field_score(weight: i64, bits: u32, epoch: i64, gain: i64) -> FieldScore {
    let effective_weight = weight.saturating_add((bits as i64).saturating_mul(gain));
    (effective_weight, epoch, bits as i64)
}

fn prefer_field(
    dst: &mut String,
    dst_score: &mut FieldScore,
    src: &str,
    field_epoch: i64,
    commit_unix: i64,
    weight: i64,
    bits: u32,
    gain: i64,
) {
    if src.is_empty() {
        return;
    }
    let epoch = if field_epoch > 0 {
        field_epoch
    } else {
        commit_unix
    };
    // 标准：score = weight * 10^10 + commit_unix 的元组等价形式（权重优先）。
    // G-10：`bits * gain` 参与第一分量；三端（Rust 运行期 / Python 离线 / golden
    // 向量）必须是同一公式，否则同一个 IP 在离线库与面板里会选出不同字段。
    let score: FieldScore = field_score(weight, bits, epoch, gain);
    if dst.is_empty() || score >= *dst_score {
        *dst = src.to_string();
        *dst_score = score;
    }
}

pub fn lookup_merged(conn: &Connection, ip: &str) -> Result<MergedFields> {
    let rows = load_covering_prefixes(conn, ip)?;
    Ok(merge_pipeline(conn, ip, &rows))
}

/// 与 [`lookup_merged`] 相同，但**把命中的 covering 行一并返回**。
///
/// 面板的 lookup 接口既要合并结果、又要展示命中的前缀列表；原先它自己再调一次
/// [`load_covering_prefixes`] —— 同一个请求把 ipv4/ipv6 全表扫了两遍（这两张表
/// 没有可用的数值范围索引，见 [`load_from_range_table`]）。这里让两条需求共用
/// 同一次扫描。
pub fn lookup_merged_with_rows(
    conn: &Connection,
    ip: &str,
) -> Result<(MergedFields, Vec<CoveringPrefix>)> {
    let rows = load_covering_prefixes(conn, ip)?;
    let merged = merge_pipeline(conn, ip, &rows);
    Ok((merged, rows))
}

/// 合并 + 冲突投票抑制 + 面板编辑覆盖。抽出来是为了让 [`lookup_merged`] 与
/// [`lookup_merged_with_rows`] 共用同一套语义（唯一差别是后者把行也返回）。
fn merge_pipeline(conn: &Connection, ip: &str, rows: &[CoveringPrefix]) -> MergedFields {
    let mut merged = merge_covering(rows);
    if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
        let (country, conflict) = super::conflict::detect_country_conflict(rows);
        if !country.is_empty() {
            merged.country = country;
        }
        if super::anycast::suppress_locality(conflict, super::anycast::is_anycast_conn(conn, ip_addr)) {
            merged.province.clear();
            merged.city.clear();
            merged.district.clear();
        }
    }
    // 面板覆盖失败必须留痕：旧实现 `let _ = ...` 静默吞掉 —— 库锁/表缺失时
    // 手工勘误整体不生效，面板却一切正常（与「假成功」同类）。lookup 是热路径，
    // 相同错误只告警一次（消息变化才再打），避免把日志刷爆。
    match super::db::open_panel(&super::db::panel_db_path()) {
        Ok(panel) => {
            if let Err(e) = super::ops::apply_panel_edits(&panel, ip, &mut merged) {
                warn_once(&format!("geoip panel edits skipped: {e:#}"));
            }
        }
        Err(e) => warn_once(&format!("geoip panel db unavailable: {e:#}")),
    }
    merged
}

/// 按消息去重的一次性告警（同一条只打一次；消息变了重新打）。
fn warn_once(msg: &str) {
    static LAST: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.as_deref() != Some(msg) {
        log::warn!("{msg}");
        *last = Some(msg.to_string());
    }
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

    fn panel_db() -> rusqlite::Connection {
        crate::server::geoip_panel::db::open_panel(std::path::Path::new(":memory:")).unwrap()
    }

    /// P1 回归：面板手工覆盖必须压过高权源数据（lookup 真的返回覆盖值）。
    ///
    /// 旧实现 `w >= merged.weight`：merged.weight 是源权重 max（生产层 300–990），
    /// 面板默认 200 ⇒ 条件恒假，覆盖静默失效；字符串 LIKE 又让 /8 的段级编辑命中
    /// 不了 /24 的查询。现在两者都修：命中即应用、人工最高优先。
    #[test]
    fn panel_edit_overrides_high_weight_merged_row() {
        let panel = panel_db();
        panel
            .execute(
                "INSERT INTO panel_edits(prefix, field, value, weight)
                 VALUES('10.0.0.0/8','country','XP',200)",
                [],
            )
            .unwrap();
        let rows = vec![CoveringPrefix {
            country: "US".into(),
            province: "California".into(),
            city: "San Jose".into(),
            weight: 990,
            commit_unix: 100,
            bits: 24,
            prefix: "10.1.2.0/24".into(),
            ..Default::default()
        }];
        let mut merged = merge_covering(&rows);
        assert_eq!(merged.country, "US");
        assert_eq!(merged.weight, 990, "源数据权重 990，远高于面板默认 200");
        // 查询 10.1.2.3：merged.prefix=10.1.2.0/24，/8 的段级覆盖必须命中。
        crate::server::geoip_panel::ops::apply_panel_edits(&panel, "10.1.2.3", &mut merged).unwrap();
        assert_eq!(merged.country, "XP", "人工覆盖必须压过 990 权重的融合结果");
    }

    /// 旧 LIKE 语义的第二类错误：存 1.2.3.4 会误命中 1.2.3.40/32（`1.2.3.40/32`
    /// LIKE `1.2.3.4%` 为真）。CIDR 包含下它只该命中 1.2.3.4 自己。
    #[test]
    fn panel_edit_host_does_not_leak_to_neighboring_host() {
        let panel = panel_db();
        panel
            .execute(
                "INSERT INTO panel_edits(prefix, field, value, weight)
                 VALUES('1.2.3.4/32','country','XX',200)",
                [],
            )
            .unwrap();
        let rows = vec![CoveringPrefix {
            country: "US".into(),
            weight: 80,
            bits: 32,
            prefix: "1.2.3.40/32".into(),
            ..Default::default()
        }];
        let mut merged = merge_covering(&rows);
        crate::server::geoip_panel::ops::apply_panel_edits(&panel, "1.2.3.40", &mut merged).unwrap();
        assert_eq!(merged.country, "US", "1.2.3.4 的编辑不得命中 1.2.3.40");
        // 反向：1.2.3.4 自己的查询要命中。
        let rows2 = vec![CoveringPrefix {
            country: "US".into(),
            weight: 80,
            bits: 32,
            prefix: "1.2.3.4/32".into(),
            ..Default::default()
        }];
        let mut merged2 = merge_covering(&rows2);
        crate::server::geoip_panel::ops::apply_panel_edits(&panel, "1.2.3.4", &mut merged2).unwrap();
        assert_eq!(merged2.country, "XX");
    }

    /// 多条编辑命中同一字段：weight 高者胜；同权重取后录入（id）者，结果确定。
    #[test]
    fn panel_edits_resolve_by_weight_then_id() {
        let panel = panel_db();
        panel
            .execute(
                "INSERT INTO panel_edits(prefix, field, value, weight)
                 VALUES('10.0.0.0/8','city','Low',100)",
                [],
            )
            .unwrap();
        panel
            .execute(
                "INSERT INTO panel_edits(prefix, field, value, weight)
                 VALUES('10.1.0.0/16','city','High',300)",
                [],
            )
            .unwrap();
        panel
            .execute(
                "INSERT INTO panel_edits(prefix, field, value, weight)
                 VALUES('10.1.2.0/24','city','High2',300)",
                [],
            )
            .unwrap();
        let rows = vec![CoveringPrefix {
            city: "Src".into(),
            weight: 990,
            bits: 24,
            prefix: "10.1.2.0/24".into(),
            ..Default::default()
        }];
        let mut merged = merge_covering(&rows);
        crate::server::geoip_panel::ops::apply_panel_edits(&panel, "10.1.2.3", &mut merged).unwrap();
        assert_eq!(merged.city, "High2");
    }

    /// 没有源数据命中时不做「勘误」：面板覆盖只修正融合结果，不凭空造数据。
    #[test]
    fn panel_edit_not_applied_without_covering_rows() {
        let panel = panel_db();
        panel
            .execute(
                "INSERT INTO panel_edits(prefix, field, value, weight)
                 VALUES('10.0.0.0/8','country','XP',200)",
                [],
            )
            .unwrap();
        let mut merged = MergedFields::default();
        crate::server::geoip_panel::ops::apply_panel_edits(&panel, "10.1.2.3", &mut merged).unwrap();
        assert_eq!(merged.country, "");
    }

    /// v6 覆盖行（写在 `ipv6` range 表）必须能被 v6 查询命中。
    #[test]
    fn v6_range_table_row_is_found() {
        let conn = crate::server::geoip_panel::db::open(std::path::Path::new(":memory:")).unwrap();
        conn.execute(
            "INSERT INTO ipv6(start, end, bits, weight, country, city, prefix, start_i, end_i)
             VALUES('2001:db8::','2001:db8::ffff', 112, 80, 'US', 'Doc', '2001:db8::/112',
                    -6917232468739227648, -6917232468739227648)",
            [],
        )
        .unwrap();
        let rows = load_covering_prefixes(&conn, "2001:db8::1").unwrap();
        assert_eq!(rows.len(), 1, "v6 range row must be found");
        assert_eq!(rows[0].prefix, "2001:db8::/112");
    }

    /// 回归：v4-mapped 字符串（`::ffff:a.b.c.d`）必须在 `load_covering_prefixes` 内折回 v4。
    /// 修复前这里按地址族分流把 v4-mapped 当纯 v6 去查 ipv6 表 ⇒ 库里有该 v4 段却返回 0 行
    /// （面板显示「无结果」）。与 apply_panel_edits/anycast/rate_limit 口径统一。
    #[test]
    fn v4_mapped_string_lookup_finds_v4_row() {
        let conn = crate::server::geoip_panel::db::open(std::path::Path::new(":memory:")).unwrap();
        conn.execute(
            "INSERT INTO geoip(ip_start, ip_end, bits, weight, country, prefix, start_i, end_i)
             VALUES('10.0.0.0','10.255.255.255', 8, 80, 'US', '10.0.0.0/8', 167772160, 184549375)",
            [],
        )
        .unwrap();
        // 直接给 v4-mapped 字符串：修复前返回空。
        let rows = load_covering_prefixes(&conn, "::ffff:10.1.2.3").unwrap();
        assert_eq!(rows.len(), 1, "v4-mapped lookup must find the v4 row");
        assert_eq!(rows[0].country, "US");
        // 大写 / 压缩形态的 v6 也应被规范化后正常查询（不改变结果）。
        let rows6 = load_covering_prefixes(&conn, "::FFFF:10.1.2.3").unwrap();
        assert_eq!(rows6.len(), 1);
    }

    /// G-10：与 Python 离线合并共享同一组 golden 向量。
    ///
    /// 向量文件由 Python `scripts/geoip_golden_test.py` 读取并跑**同一份输入**；
    /// 两侧都必须得到 `expected`。任何一侧改了评分公式而另一侧没跟上，这个测试
    /// 或 Python 侧的 `OK: N golden cases` 就会失败。
    #[test]
    fn golden_vectors_match_python_expectations() {
        let raw = include_str!("../../../scripts/geoip_golden_vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        let default_gain = doc["path_priority_gain"]
            .as_i64()
            .unwrap_or(DEFAULT_PATH_PRIORITY_GAIN);
        let empty = serde_json::Map::new();
        for case in doc["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let gain = case
                .get("gain")
                .and_then(|v| v.as_i64())
                .unwrap_or(default_gain);
            let mut rows = Vec::new();
            for r in case["rows"].as_array().unwrap() {
                let s = |k: &str| {
                    r.get(k)
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string()
                };
                let i = |k: &str| r.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
                let u = |k: &str| r.get(k).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                rows.push(CoveringPrefix {
                    country: s("country"),
                    province: s("province"),
                    region: s("region"),
                    city: s("city"),
                    district: s("district"),
                    isp: s("isp"),
                    dc: s("dc"),
                    asn: s("asn"),
                    as_org: s("as_org"),
                    net_org: s("net_org"),
                    cloud_provider: s("cloud_provider"),
                    cloud_region: s("cloud_region"),
                    cloud_service: s("cloud_service"),
                    hosting: s("hosting"),
                    division_code: s("division_code"),
                    e_country: i("e_country"),
                    e_province: i("e_province"),
                    e_city: i("e_city"),
                    e_district: i("e_district"),
                    e_isp: i("e_isp"),
                    e_asn: i("e_asn"),
                    e_as_org: i("e_as_org"),
                    e_net_org: i("e_net_org"),
                    e_cloud_provider: i("e_cloud_provider"),
                    e_cloud_region: i("e_cloud_region"),
                    e_cloud_service: i("e_cloud_service"),
                    e_hosting: i("e_hosting"),
                    bits: u("bits"),
                    weight: i("weight"),
                    commit_unix: i("commit_unix"),
                    ..Default::default()
                });
            }
            let got = merge_covering_fields_with_gain(&rows, gain);
            let expected = case.get("expected").and_then(|v| v.as_object()).unwrap_or(&empty);
            let pairs = [
                ("country", got.country.as_str()),
                ("province", got.province.as_str()),
                ("region", got.region.as_str()),
                ("city", got.city.as_str()),
                ("district", got.district.as_str()),
                ("isp", got.isp.as_str()),
                ("dc", got.dc.as_str()),
                ("asn", got.asn.as_str()),
                ("as_org", got.as_org.as_str()),
                ("net_org", got.net_org.as_str()),
                ("cloud_provider", got.cloud_provider.as_str()),
                ("cloud_region", got.cloud_region.as_str()),
                ("cloud_service", got.cloud_service.as_str()),
                ("hosting", got.hosting.as_str()),
                ("division_code", got.division_code.as_str()),
            ];
            for (field, value) in pairs {
                let want = expected
                    .get(field)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                assert_eq!(value, want, "golden case {name:?} gain={gain} field={field}");
            }
        }
    }

    /// G-17：路径优先级增益必须真的改变选择结果（0 / 10 / 50 三档）。
    #[test]
    fn path_priority_gain_changes_field_selection() {
        let rows = vec![
            CoveringPrefix {
                country: "AA".into(),
                weight: 700,
                bits: 8,
                commit_unix: 5,
                ..Default::default()
            },
            CoveringPrefix {
                country: "BB".into(),
                weight: 0,
                bits: 24,
                commit_unix: 5,
                ..Default::default()
            },
        ];
        assert_eq!(
            merge_covering_fields_with_gain(&rows, 0).country,
            "AA",
            "gain=0 时纯权重：/8 的 700 胜 /24 的 0"
        );
        assert_eq!(
            merge_covering_fields_with_gain(&rows, 10).country,
            "AA",
            "默认 gain=10 时 /8 仍胜（700+80 > 0+240）"
        );
        assert_eq!(
            merge_covering_fields_with_gain(&rows, 50).country,
            "BB",
            "gain=50 时 /24 胜（0+1200 > 700+400）"
        );
    }

    /// 默认增益就是 10（旧行为零变化）。不断言运行时全局值：单测并行时别的用例
    /// 可能正在验证 set_path_priority_gain 的写侧。
    #[test]
    fn default_gain_is_ten() {
        assert_eq!(DEFAULT_PATH_PRIORITY_GAIN, 10);
    }

    /// 合并确定性：同 (commit_unix, weight, bits) 的多行（含跨 geoip / ipv4 两张表）
    /// 合并结果必须可重复。修复前 range 表查询无 ORDER BY、geoip 表 ORDER BY 无唯一键收尾，
    /// 同分行的先后取决于查询计划；现在两侧都以 rowid 收尾。
    #[test]
    fn merge_is_deterministic_for_equal_scores() {
        let conn = crate::server::geoip_panel::db::open(std::path::Path::new(":memory:")).unwrap();
        for cc in ["AA", "BB", "CC", "DD", "EE", "FF", "GG", "HH"] {
            conn.execute(
                "INSERT INTO geoip(ip_start, ip_end, bits, weight, commit_unix, country, prefix, start_i, end_i)
                 VALUES('10.0.0.0','10.255.255.255', 8, 100, 5, ?1, '10.0.0.0/8', 167772160, 184549375)",
                rusqlite::params![cc],
            )
            .unwrap();
        }
        let first = merge_covering(&load_covering_prefixes(&conn, "10.1.2.3").unwrap()).country;
        for _ in 0..50 {
            let again = merge_covering(&load_covering_prefixes(&conn, "10.1.2.3").unwrap()).country;
            assert_eq!(again, first, "同分行的合并结果必须稳定");
        }
        // 唯一键 rowid 收尾 ⇒ 同分取最后插入（HH）。
        assert_eq!(first, "HH");
    }
}
