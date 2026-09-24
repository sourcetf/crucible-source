//! DNS 控制面（bind9/named 后端）——补充需求 §4 的核心实现。
//!
//! 设计：
//! - named 以**自守护**方式运行（conf/zones/keys 全落盘 state/dns/），webserver 退出后 DNS 继续服务（需求 12）
//! - zone/RR 数据存 SQLite（state/dns/db/dns.sqlite），named.conf 与 zone 文件由本模块生成
//! - 生成配置必须过 `named -g` 探活校验（本包无 named-checkconf）才允许 rndc reload（防呆）
//! - [dns] 配置来自 config.toml；面板编辑覆盖写 state/dns/etc/panel.toml（authority高于 config.toml 的 [dns]）
//! - DNSSEC 走 bind9 KASP（dnssec-policy）：算法/轮换周期/多 key(ZSK/KSK/CSK)/NSEC3/CDS 全映射（需求 3/4/5/8）
//! - override 走 RPZ response-policy（需求 7）；分线路走 named view + match-clients CIDR（需求 10，
//!   全部默认线路时 geo.lines 为空 → 不生成 view，零开销）

use crate::config::Config;
use anyhow::{anyhow, bail, Context as _, Result};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod acme;
pub mod admin_api;
pub mod dot_doh;
pub mod ecs;
pub mod geoip;

/// DNS 总配置（config.toml `[dns]` / 面板 panel.toml）。serde 全默认：缺省即关闭、零行为变化。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Let's Encrypt 自动签发（需求 8）
    #[serde(default)]
    pub acme: acme::AcmeCfg,
    /// 测试模式：named 监听 127.0.0.1:5353 / rndc 1953（不与系统 named 的 53 冲突）
    #[serde(default)]
    pub test_mode: bool,
    #[serde(default)]
    pub modes: DnsModes,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// 0 = 按 test_mode 取 5353/53
    #[serde(default)]
    pub port: u16,
    /// 0 = 按 test_mode 取 1953/953
    #[serde(default)]
    pub rndc_port: u16,
    /// 递归白名单 CIDR（空 = 仅本机）。modes.recursive=false 时无意义
    #[serde(default)]
    pub recursion_acl: Vec<String>,
    /// 全局 AXFR 传出白名单（IPv4/IPv6/CIDR；空 = none）
    #[serde(default)]
    pub axfr_out_acl: Vec<String>,
    #[serde(default)]
    pub dnssec: DnssecCfg,
    /// RPZ override 记录（public DNS 的记录覆盖，需求 7）
    #[serde(default)]
    pub rpz: Vec<RpzRule>,
    /// 分线路（需求 10）；lines 为空 = 全默认线路，不启用 view（性能条款）
    #[serde(default)]
    pub geo: GeoCfg,
    #[serde(default)]
    pub dot: DotCfg,
    #[serde(default)]
    pub doh: DohCfg,
    #[serde(default)]
    pub rootzone: RootZoneCfg,
    /// EDNS Client Subnet 开关（需求 12）：递归时传递，权威时接收。默认打开。
    #[serde(default = "default_true")]
    pub ecs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsModes {
    /// 根服务器模式：服务 root zone（权威 "."）
    #[serde(default)]
    pub root: bool,
    /// public 递归模式
    #[serde(default)]
    pub recursive: bool,
    /// 权威模式：是否服务用户 zones（规格 §16.1 要求面板可开关）。
    ///
    /// 默认 **true**：旧配置普遍没写这个字段，而「不写就停止服务所有 zone」会把
    /// 已有部署打挂；默认开等于保持既有语义，显式 false 才是真的关掉。
    /// 兼容配置缩写 `auth`。
    #[serde(default = "default_true", alias = "auth")]
    pub authoritative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnssecCfg {
    #[serde(default)]
    pub enabled: bool,
    /// RSASHA256 | RSASHA512 | ECDSAP256SHA256 | ECDSAP384SHA384 | ED25519
    #[serde(default = "default_dnssec_alg")]
    pub algorithm: String,
    /// 是否定期轮换（需求 3）
    #[serde(default)]
    pub rotation_enabled: bool,
    /// ZSK 轮换周期（天），rotation_enabled 时生效
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u64,
    /// KSK 轮换周期（天）；None = unlimited
    #[serde(default)]
    pub ksk_lifetime_days: Option<u64>,
    /// 多 key 结构（需求 4）：每项 { role: ksk|zsk|csk, lifetime_days? }；空 = 默认 ksk+zsk
    #[serde(default)]
    pub keys: Vec<DnsKeyCfg>,
    /// 需求 5：默认 NSEC3
    #[serde(default = "default_true")]
    pub nsec3: bool,
    #[serde(default)]
    pub nsec3_iterations: u32,
    #[serde(default)]
    pub nsec3_optout: bool,
    /// 发布 CDS/CDNSKEY（需求 8）
    #[serde(default = "default_true")]
    pub cds: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsKeyCfg {
    /// ksk | zsk | csk
    pub role: String,
    #[serde(default)]
    pub lifetime_days: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpzRule {
    /// 触发名（如 ads.example.com 或 *.ads.example.com）
    pub name: String,
    /// CNAME/A/AAAA/TXT 或特殊 action：nxdomain | nodata
    pub rtype: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoCfg {
    #[serde(default)]
    pub enabled: bool,
    /// 线路组：name + 该线路的客户端 CIDR 列表（由 geoip SQLite 预计算填充或面板手填）
    #[serde(default)]
    pub lines: Vec<GeoLine>,
    /// MaxMind GeoLite2 自动同步 + ASN/ISP/geo 线路匹配 (需求 9 扩展)
    #[serde(default)]
    pub mmdb: GeoMmdbCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoMmdbCfg {
    /// libmaxminddb 解析 MMDB；空 path 且 license_key 非空 → 自动下载 GeoLite2-City + GeoLite2-ASN
    #[serde(default)]
    pub db_path_city: String,
    #[serde(default)]
    pub db_path_asn: String,
    /// MaxMind License Key —— 为空跳过自动同步
    #[serde(default)]
    pub license_key: String,
    /// 同步间隔（天）；0 = 不自动同步
    #[serde(default = "default_geo_sync_days")]
    pub sync_days: u64,
    /// ASN 字符串 (e.g. "AS13335" 或 "13335") → 线路名
    #[serde(default)]
    pub asn_to_line: Vec<(String, String)>,
    /// ISO 国家码 → 线路名
    #[serde(default)]
    pub country_to_line: Vec<(String, String)>,
    /// ISP/组织名子串 → 线路名 (大小写不敏感包含匹配)
    #[serde(default)]
    pub isp_contains: Vec<(String, String)>,
}

pub fn default_geo_sync_days() -> u64 {
    7
}

impl GeoMmdbCfg {
    /// 数据库就绪 (db_path 存在或 license_key 非空可 auto-fetch)
    pub fn is_active(&self) -> bool {
        !self.db_path_city.is_empty()
            || !self.db_path_asn.is_empty()
            || (!self.license_key.is_empty() && self.sync_days > 0)
    }
    /// 本地 db_path 或 license_key 推算的默认 city db 路径
    pub fn city_db(&self) -> String {
        if !self.db_path_city.is_empty() {
            self.db_path_city.clone()
        } else {
            format!("{}/GeoLite2-City.mmdb", state_root().join("geo").display())
        }
    }
    pub fn asn_db(&self) -> String {
        if !self.db_path_asn.is_empty() {
            self.db_path_asn.clone()
        } else {
            format!("{}/GeoLite2-ASN.mmdb", state_root().join("geo").display())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLine {
    pub name: String,
    pub cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DotCfg {
    #[serde(default)]
    pub enabled: bool,
    /// 0 = 853（test_mode 下 11853）
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DohCfg {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_doh_path")]
    pub path: String,
    /// 限定 Host/SNI；空 = 任意 host
    #[serde(default)]
    pub hostnames: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RootZoneCfg {
    /// 刷新频率小时数，默认 24（需求 2 默认 daily）
    #[serde(default = "default_root_refresh_hours")]
    pub refresh_hours: u64,
    #[serde(default = "default_root_url")]
    pub url: String,
    /// AXFR 源服务器（IPv4/IPv6）——用于 IXFR 增量更新（需求 2）
    #[serde(default)]
    pub axfr_servers: Vec<String>,
    /// false = 不自动刷新 root zone（仅 modes.root=true 时有意义）。
    /// 默认 true：需求 2 要求「默认 daily」自动增量更新。
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_listen_addr() -> String {
    "127.0.0.1".into()
}
fn default_dnssec_alg() -> String {
    "ECDSAP256SHA256".into()
}
fn default_rotation_days() -> u64 {
    30
}
fn default_true() -> bool {
    true
}
fn default_doh_path() -> String {
    "/dns-query".into()
}
fn default_root_refresh_hours() -> u64 {
    24
}
fn default_root_url() -> String {
    "https://www.internic.net/domain/root.zone".into()
}

impl DnsConfig {
    pub fn port_or_default(&self) -> u16 {
        if self.port != 0 {
            self.port
        } else if self.test_mode {
            5353
        } else {
            53
        }
    }
    pub fn rndc_port_or_default(&self) -> u16 {
        if self.rndc_port != 0 {
            self.rndc_port
        } else if self.test_mode {
            1953
        } else {
            953
        }
    }
}

/// DNS 状态根目录（默认 `state/dns`）：named.conf / rndc.conf / panel.toml /
/// zones / keys / db 全在这里。
///
/// `CRUCIBLE_DNS_STATE_ROOT` 环境变量可整体改写它。**测试实例必须用独立目录**，
/// 共用生产根目录会同时踩两个坑：
///   1. [`effective`] 只要见到 `etc/panel.toml` 就把它**整体**当成 DNS 配置返回，
///      `config-test.toml` 的整个 `[dns]` 段形同不存在——`[dns.dot] port` 改不动，
///      测试实例照样去绑生产 DoT 853，和在生产实例并存时直接 bind 失败；
///   2. `db/dns.sqlite` 与 `zones/` 共用——`dns_smoke.sh` / `dns_verify.sh` 通过
///      `/api/dns/zones` 建的 `smoke.test`/`verify.test` 会**落进生产 DNS 库**。
pub fn state_root() -> PathBuf {
    if let Some(p) = env_state_root() {
        return p;
    }
    // 绝对化：named 由本进程 spawn（继承 cwd），但 key/zones 目录写入
    // 乃至外部工具（dnssec-keygen）都以绝对路径调用，避免 cwd 漂移踩坑。
    let rel = PathBuf::from("state/dns");
    if rel.is_absolute() {
        return rel;
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(rel),
        Err(_) => rel,
    }
}

/// 读取 `CRUCIBLE_DNS_STATE_ROOT`；空值视为未设置。相对路径按 cwd 绝对化。
fn env_state_root() -> Option<PathBuf> {
    let raw = std::env::var("CRUCIBLE_DNS_STATE_ROOT").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        return Some(p);
    }
    Some(std::env::current_dir().ok()?.join(p))
}

/// 生效配置：config.toml [dns] 为基底，panel.toml（面板编辑）存在则整体覆盖。
pub fn effective(cfg: &Config) -> DnsConfig {
    let panel = state_root().join("etc/panel.toml");
    if let Ok(text) = std::fs::read_to_string(&panel) {
        // Ignore empty / whitespace-only panel files (would deserialize to all-defaults
        // and silently disable DNS that is enabled in config.toml).
        if !text.trim().is_empty() {
            if let Ok(p) = toml::from_str::<DnsConfig>(&text) {
                return p;
            }
        }
    }
    cfg.dns.clone()
}

// ---------------------------------------------------------------- SQLite store

pub fn store() -> Result<Connection> {
    let dir = state_root().join("db");
    std::fs::create_dir_all(&dir)?;
    let conn = Connection::open(dir.join("dns.sqlite"))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS zones(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            kind TEXT NOT NULL DEFAULT 'master',
            primaries TEXT DEFAULT '',
            axfr_acl TEXT DEFAULT '',
            refresh_hours INTEGER DEFAULT 24,
            created TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS records(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone TEXT NOT NULL,
            line TEXT DEFAULT '',
            name TEXT NOT NULL,
            rtype TEXT NOT NULL,
            ttl INTEGER DEFAULT 3600,
            rdata TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);",
    )?;
    Ok(conn)
}

const RR_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "NS", "MX", "TXT", "SRV", "CAA", "SOA", "DS", "DNSKEY", "RRSIG", "CDS",
    "CDNSKEY", "NSEC3", "NSEC3PARAM", "PTR", "TLSA", "SVCB", "HTTPS",
];

/// 名字/记录合法性（RFC 放宽版：字母数字 - _ . * @ 与合法 CIDR 不校验处不拦）
fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && !n.contains("..")
        && n.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*' | b'@')
        })
}

/// named.conf ACL / allow-transfer 单项：仅关键字或 IP/CIDR，拒绝 `; { } "` 注入。
fn valid_acl_item(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    match s {
        "any" | "none" | "localhost" | "localnets" => return true,
        _ => {}
    }
    // IPv4 or IPv4/prefix
    if let Some((ip, pref)) = s.split_once('/') {
        if pref.parse::<u8>().ok().filter(|&p| p <= 32).is_none() {
            // maybe IPv6 CIDR — fall through
        } else if ip.parse::<std::net::Ipv4Addr>().is_ok() {
            return true;
        }
    } else if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    // IPv6 or IPv6/prefix (no brackets in bind acl literals we emit)
    if let Some((ip, pref)) = s.split_once('/') {
        if pref.parse::<u8>().ok().filter(|&p| p <= 128).is_some()
            && ip.parse::<std::net::Ipv6Addr>().is_ok()
        {
            return true;
        }
    } else if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    false
}

/// slave primaries：host 或 host:port / [ipv6]:port；拒绝 named.conf 元字符。
/// 把配置里接受的 primaries 写法翻译成 **BIND 的 primaries 语法**。
///
/// [`valid_primary`] 允许 `host:port` 与 `[v6]:port`（对面板友好），但 BIND 的
/// primaries 里**没有 `host:port` 这种写法** —— 端口要写成 `host port N`。
/// 原样输出会让 named 以语法错误拒载**整份 named.conf**（与之前 primaries 里多一个
/// 分号属于同一类：一处格式错、全份配置失效，所有 zone 一起不可用）。
fn primary_for_named(p: &str) -> String {
    let s = p.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((ip, port)) = rest.split_once("]:") {
            return format!("{ip} port {port}");
        }
        return s.to_string(); // [v6] 无端口
    }
    // 裸 IPv6 含多个冒号，不能按 host:port 切
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return s.to_string();
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if !host.is_empty() && port.parse::<u16>().is_ok() {
            return format!("{host} port {port}");
        }
    }
    s.to_string()
}

fn valid_primary(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if s.contains(';')
        || s.contains('{')
        || s.contains('}')
        || s.contains('"')
        || s.contains('\\')
        || s.contains('\n')
        || s.contains('\r')
        || s.contains(' ')
    {
        return false;
    }
    // [v6]:port
    if let Some(rest) = s.strip_prefix('[') {
        let Some((ip, port)) = rest.split_once("]:") else {
            return rest
                .strip_suffix(']')
                .and_then(|ip| ip.parse::<std::net::Ipv6Addr>().ok())
                .is_some();
        };
        return ip.parse::<std::net::Ipv6Addr>().is_ok() && port.parse::<u16>().is_ok();
    }
    // host:port (last colon) — if host is IPv4 or hostname
    if let Some((host, port)) = s.rsplit_once(':') {
        if host.parse::<std::net::Ipv4Addr>().is_ok() || valid_hostname_label(host) {
            return port.parse::<u16>().is_ok();
        }
        // bare IPv6 without brackets — allow only if whole string parses as IPv6
        return s.parse::<std::net::Ipv6Addr>().is_ok();
    }
    s.parse::<std::net::Ipv4Addr>().is_ok()
        || s.parse::<std::net::Ipv6Addr>().is_ok()
        || valid_hostname_label(s)
}

fn valid_hostname_label(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && !n.contains("..")
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

/// geo 线路名（GeoLine.name）的合法性校验。
///
/// 这个值会被用在三个地方：`named.conf` 的 `view "{name}"`、以及
/// `root.{tag}.zone` / `rpz.{tag}.zone` / `answers.{tag}.zone` 的文件名。
/// 未校验时：`name = "../x"` 让 `zones_dir.join(..)` 写出目录之外；
/// `name` 里带 `\n` + `}; zone ...` 则直接注入 named 指令。
/// 只允许 DNS label 字符集，彻底堵死两类注入。
pub fn valid_line_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 63
        && !n.starts_with('-')
        && !n.ends_with('-')
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

pub fn add_zone(kind: &str, name: &str, primaries: &[String], axfr_acl: &[String], refresh_hours: u64) -> Result<i64> {
    if !valid_name(name) {
        bail!("bad zone name {name:?}");
    }
    if let Some(bad) = primaries.iter().find(|p| !valid_primary(p)) {
        bail!("bad primary {bad:?}");
    }
    if let Some(bad) = axfr_acl.iter().find(|a| !valid_acl_item(a)) {
        bail!("bad axfr_acl item {bad:?}");
    }
    let kind = match kind {
        "master" | "primary" => "master",
        "slave" | "secondary" => "slave",
        _ => bail!("zone kind must be master|slave"),
    };
    let conn = store()?;
    conn.execute(
        "INSERT OR REPLACE INTO zones(name,kind,primaries,axfr_acl,refresh_hours) VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params![
            name,
            kind,
            primaries.join(";"),
            axfr_acl.join(";"),
            refresh_hours as i64
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// 只清空某分区的记录、保留分区本身（导入时「全量替换」用）。
pub fn del_zone_records(name: &str) -> Result<usize> {
    let conn = store()?;
    let n = conn.execute("DELETE FROM records WHERE zone=?1", [name])?;
    Ok(n)
}

pub fn del_zone(name: &str) -> Result<()> {
    let conn = store()?;
    conn.execute("DELETE FROM zones WHERE name=?1", [name])?;
    conn.execute("DELETE FROM records WHERE zone=?1", [name])?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct ZoneRow {
    pub name: String,
    pub kind: String,
    pub primaries: Vec<String>,
    pub axfr_acl: Vec<String>,
    pub refresh_hours: i64,
}

pub fn list_zones() -> Result<Vec<ZoneRow>> {
    let conn = store()?;
    let mut st = conn.prepare("SELECT name,kind,primaries,axfr_acl,refresh_hours FROM zones ORDER BY id")?;
    let rows = st
        .query_map([], |r| {
            Ok(ZoneRow {
                name: r.get(0)?,
                kind: r.get(1)?,
                primaries: split_semi(r.get::<_, String>(2)?),
                axfr_acl: split_semi(r.get::<_, String>(3)?),
                refresh_hours: r.get(4)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn split_semi(s: String) -> Vec<String> {
    s.split(';').filter(|x| !x.is_empty()).map(String::from).collect()
}

/// 分区类型（"master"/"slave"）；分区不存在时返回空串。
///
/// 调用方按「空串 = master」处理，保持旧行为（历史调用点会在建区之前就写记录）。
pub fn zone_kind_of(zone: &str) -> Result<String> {
    let conn = store()?;
    let k = conn
        .query_row("SELECT kind FROM zones WHERE name=?1", [zone], |r| {
            r.get::<_, String>(0)
        })
        .optional()?;
    Ok(k.unwrap_or_default())
}

fn zone_row_of(zone: &str) -> Result<Option<ZoneRow>> {
    let conn = store()?;
    let z = conn
        .query_row(
            "SELECT name,kind,primaries,axfr_acl,refresh_hours FROM zones WHERE name=?1",
            [zone],
            |r| {
                Ok(ZoneRow {
                    name: r.get(0)?,
                    kind: r.get(1)?,
                    primaries: split_semi(r.get::<_, String>(2)?),
                    axfr_acl: split_semi(r.get::<_, String>(3)?),
                    refresh_hours: r.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(z)
}

/// 从区（slave）的记录：named 把传输来的区写进**它自己**的 zone 文件，DB 里没有，
/// 所以面板要显示只能读盘上那份（RFC1035 master file，复用导入用的解析器）。
///
/// 返回的行是**只读**的：id 用负数表示（DB 自增 id 恒 > 0），且 add_record/del_record
/// 对非 master 分区直接拒绝 —— 写了也会被下一次 AXFR/IXFR 覆盖，那种「保存成功但
/// 服务里查不到」的假成功比报错更糟。
pub fn list_secondary_records(zone: &str) -> Result<Vec<RecordRow>> {
    let z = zone_row_of(zone)?.with_context(|| format!("zone {zone} 不存在"))?;
    let dir = state_root().join("zones");
    // 默认 view 的文件名优先；配了 geo 多 view 时回退到前缀扫描（取第一个匹配）。
    let primary = dir.join(zone_file_name(&z, ""));
    let path = if primary.is_file() {
        primary
    } else {
        // 开了 geo 时默认 view 的文件名是 `<safe>.<tag>.default.<hash>.zone`（view 名参与
        // 文件名），同前缀可能有多份（每个 view 一份，内容相同）——优先 `.default.`，
        // 否则按名字排序取第一份，保证同样的分区每次读到同一个文件。
        let safe: String = z
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let prefix = format!("{safe}.{:08x}", fnv1a32(&z.name));
        let mut cands: Vec<PathBuf> = std::fs::read_dir(&dir)
            .with_context(|| format!("read dir {}", dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(&prefix) && n.ends_with(".zone"))
                    .unwrap_or(false)
            })
            .collect();
        cands.sort();
        cands
            .iter()
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.contains(".default."))
                    .unwrap_or(false)
            })
            .or_else(|| cands.first())
            .cloned()
            .with_context(|| format!("从区 {zone} 的 zone 文件尚未生成（传输可能还没完成）"))?
    };
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let recs = admin_api::parse_zone_text(&text, &z.name).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(recs
        .into_iter()
        .enumerate()
        .map(|(i, r)| RecordRow {
            id: -(i as i64) - 1,
            zone: z.name.clone(),
            line: String::new(),
            name: r.name,
            rtype: r.rtype,
            ttl: i64::from(r.ttl),
            rdata: r.rdata,
        })
        .collect())
}

pub fn add_record(zone: &str, line: &str, name: &str, rtype: &str, ttl: u32, rdata: &str) -> Result<()> {
    if !valid_name(zone) {
        bail!("bad zone name {zone:?}");
    }
    if !valid_name(name) {
        bail!("bad record name {name:?}");
    }
    let rtype_u = rtype.to_ascii_uppercase();
    if !RR_TYPES.contains(&rtype_u.as_str()) {
        bail!("unsupported record type {rtype_u}");
    }
    // 从区的记录由 named 的 AXFR/IXFR 维护，本地写入必被覆盖 —— 明确拒绝，
    // 免得出现「保存成功、服务里却查不到」的假成功（面板对从区是只读的）。
    let kind = zone_kind_of(zone)?;
    if !kind.is_empty() && kind != "master" {
        bail!("zone {zone:?} 是从区（{kind}），记录由 named 同步维护，不能直接编辑");
    }
    if rdata.is_empty() || rdata.len() > 4096 {
        bail!("bad rdata length");
    }
    // 头注入面：rdata 是 zone 文件文本行，换行/裸回车一律拒绝
    if rdata.contains('\n') || rdata.contains('\r') {
        bail!("rdata must be single-line");
    }
    let conn = store()?;
    conn.execute(
        "INSERT INTO records(zone,line,name,rtype,ttl,rdata) VALUES(?1,?2,?3,?4,?5,?6)",
        rusqlite::params![zone, line, name, &rtype_u, ttl as i64, rdata],
    )?;
    Ok(())
}

pub fn del_record(id: i64) -> Result<()> {
    let conn = store()?;
    // 从区记录只读（同 add_record 的守卫；负数 id 本来就查不到，这里给出明确原因）。
    let zone: Option<String> = conn
        .query_row("SELECT zone FROM records WHERE id=?1", [id], |r| r.get(0))
        .optional()?;
    if let Some(z) = zone {
        let kind = zone_kind_of(&z)?;
        if !kind.is_empty() && kind != "master" {
            bail!("zone {z:?} 是从区（{kind}），记录由 named 同步维护，不能直接删除");
        }
    }
    let n = conn.execute("DELETE FROM records WHERE id=?1", [id])?;
    // 删不存在的 id 必须报错：静默成功会让「从区只读行的删除按钮」「已被删的记录再删一次」
    // 看起来都成功了（面板又刷新不出变化），排查时全是假象。
    if n == 0 {
        bail!("记录不存在（id={id}）");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordRow {
    pub id: i64,
    pub zone: String,
    pub line: String,
    pub name: String,
    pub rtype: String,
    pub ttl: i64,
    pub rdata: String,
}

pub fn list_records(zone: &str) -> Result<Vec<RecordRow>> {
    let conn = store()?;
    let mut st = conn.prepare(
        "SELECT id,zone,line,name,rtype,ttl,rdata FROM records WHERE zone=?1 ORDER BY id",
    )?;
    let rows = st
        .query_map([zone], |r| {
            Ok(RecordRow {
                id: r.get(0)?,
                zone: r.get(1)?,
                line: r.get(2)?,
                name: r.get(3)?,
                rtype: r.get(4)?,
                ttl: r.get(5)?,
                rdata: r.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ---------------------------------------------------------------- zone 文件生成

/// RFC1035 master 文件。SOA serial = unix 时间（面板每次改动 bump）。
pub fn gen_zone_file(zone: &str, kind: &str, recs: &[RecordRow]) -> String {
    gen_zone_file_monotonic(zone, kind, recs, None)
}

/// 带 serial 单调性的版本（推荐路径）。
///
/// SOA serial 必须**严格递增**：同秒内的两次面板编辑若产生同一个 unix 秒值，
/// 从服务器 / 本模块自己的 IXFR 判定 / 任何 AXFR 消费者都会认为「无变化」而不更新。
/// 传入上一次落盘的 serial，取 `max(now, prev + 1)`。
pub fn gen_zone_file_monotonic(
    zone: &str,
    kind: &str,
    recs: &[RecordRow],
    prev_serial: Option<u64>,
) -> String {
    // 统一去尾点再拼，修复 zone 名带尾点时的 "ns1.example.com.." 双点（named 拒载）
    let zone = zone.trim_end_matches('.');
    let mut s = String::new();
    s.push_str(&format!("$ORIGIN {zone}.\n$TTL 3600\n"));
    let now = chrono_now();
    let serial = match prev_serial {
        Some(p) => now.max(p.saturating_add(1)),
        None => now,
    };
    let ns1 = format!("ns1.{zone}.");
    if kind == "master" {
        // 面板可能自带 SOA 记录（RR_TYPES 里允许）——自带则不重复插入
        let has_soa = recs.iter().any(|r| r.rtype.eq_ignore_ascii_case("SOA"));
        if !has_soa {
            s.push_str(&format!(
                "@ IN SOA {ns1} hostmaster.{zone}. (\n  {serial} ; serial\n  900 ; refresh\n  600 ; retry\n  1209600 ; expire\n  300 ; minimum\n)\n"
            ));
        }
        s.push_str(&format!("@ IN NS {ns1}\n{ns1} IN A 127.0.0.1\n"));
    }
    for r in recs {
        let name = if r.name == "@" || r.name.is_empty() { "@" } else { r.name.as_str() };
        // RFC1035：TXT/SPF 的 rdata 必须带引号且转义内部引号/反斜杠；
        // 旧实现裸写 "hello world" 会被解析成多条 rdata → zone 文件非法。
        let rdata = quoted_txt_rdata(&r.rtype, &r.rdata);
        s.push_str(&format!("{} {} IN {} {}\n", name, r.ttl, r.rtype, rdata));
    }
    s
}

/// TXT/SPF rdata 规范化：已带引号原样；否则加引号并转义。
fn quoted_txt_rdata(rtype: &str, rdata: &str) -> String {
    let t = rtype.trim().to_ascii_uppercase();
    if t != "TXT" && t != "SPF" {
        return rdata.to_string();
    }
    let d = rdata.trim();
    if d.starts_with('"') && d.ends_with('"') && d.len() >= 2 {
        return d.to_string();
    }
    let esc: String = d.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{esc}\"")
}

fn chrono_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn gen_rpz_file(rules: &[RpzRule]) -> String {
    // RPZ 语义（v3 实测修正）：
    // 1) 触发 owner 必须是**相对名**——挂在 $ORIGIN crucible.rpz. 之下才是合法触发
    //    （blocked.crucible.test → blocked.crucible.test.crucible.rpz.）；
    //    补尾点成 FQDN 反而是 out-of-zone 数据被 named 忽略（实测：rpz.lab-a.zone:5 警告）
    // 2) 自定义响应统一 CNAME → <name>.crucible.answers.（真实记录在 answers 区，NextDNS 风格）
    let mut s = String::from("$ORIGIN crucible.rpz.\n$TTL 300\n");
    s.push_str(&format!(
        "@ IN SOA localhost. root.localhost. ( {} 3600 900 86400 300 )\n@ IN NS localhost.\n",
        chrono_now()
    ));
    for r in rules {
        let rel = r.name.trim_end_matches('.').to_string();
        if rel.is_empty() {
            continue;
        }
        match r.rtype.to_ascii_lowercase().as_str() {
            "nxdomain" => s.push_str(&format!("{rel} IN CNAME .\n")),
            "nodata" => s.push_str(&format!("{rel} IN CNAME *.\n")),
            "passthru" | "pass" | "continue" => s.push_str(&format!("{rel} IN CNAME rpz-passthru.\n")),
            "a" | "aaaa" | "txt" => {
                s.push_str(&format!("{rel} IN CNAME {rel}.crucible.answers.\n"));
            }
            "cname" => {
                let v = r.value.trim().trim_end_matches('.');
                s.push_str(&format!("{rel} IN CNAME {v}.\n"));
            }
            _ => {}
        }
    }
    s
}

fn fq_trim(fq: &str) -> String {
    fq.trim_end_matches('.').to_string()
}

/// answers 区（承载 override 的自定义响应，需求 7）。
fn gen_answers_file(rules: &[RpzRule]) -> String {
    let mut s = String::from("$ORIGIN crucible.answers.\n$TTL 300\n");
    s.push_str(&format!(
        "@ IN SOA localhost. root.localhost. ( {} 3600 900 86400 300 )\n@ IN NS localhost.\n",
        chrono_now()
    ));
    for r in rules {
        let t = r.rtype.to_ascii_lowercase();
        if t == "a" || t == "aaaa" || t == "txt" {
            let name = fq_trim(&ensure_fq(&r.name));
            let rdata = if t == "txt" {
                let d = r.value.trim();
                if d.starts_with('"') { d.to_string() } else { format!("\"{}\"", d.replace('"', "\\\"")) }
            } else {
                r.value.trim().to_string()
            };
            s.push_str(&format!("{} IN {} {}\n", name, t.to_ascii_uppercase(), rdata));
        }
    }
    s
}

fn ensure_fq(n: &str) -> String {
    if n.ends_with('.') { n.to_string() } else { format!("{}.", n.trim_end_matches('.')) }
}

/// 根区最小占位（rootzone 未同步时的兜底，named 可加载）。
fn minimal_root_zone(cfg: &DnsConfig) -> String {
    // A 记录必须是合法点分地址——"any"/"0.0.0.0" 都不是（named 'bad dotted quad' 拒载根区）
    let self_ip = match cfg.listen_addr.as_str() {
        "" | "0.0.0.0" | "any" => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    format!(
        "$ORIGIN .\n. 86400 IN SOA a.root-servers.crucible. noc.crucible. ( {serial} 1800 900 604800 86400 )\n. 518400 IN NS a.root-servers.crucible.\na.root-servers.crucible. 86400 IN A {self_ip}\n",
        serial = chrono_now()
    )
}

// ---------------------------------------------------------------- named.conf 生成

fn acl_or(list: &[String], default: &str) -> String {
    let items: Vec<String> = list
        .iter()
        .filter(|c| valid_acl_item(c))
        .map(|c| format!("{c};"))
        .collect();
    if items.is_empty() {
        format!("{{ {default}; }}")
    } else {
        format!("{{ {} }}", items.join(" "))
    }
}

/// KASP 严格档：带 9.20 未确证语句（cdnskey/cds-digest-types、inline-signing）。
/// validate 探活失败自动降级到 lite 档（语句移除），保证 named 永远能起。
static KASP_STRICT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn kasp_strict() -> bool {
    KASP_STRICT.load(std::sync::atomic::Ordering::Relaxed)
}

/// 生成 named.conf。
/// - geo views（match-clients）承接直连 53 的外部客户端分线路
/// - fwd views（match-destinations 127.0.0.2+i）承接 DoT/DoH 转发查询的分线路
///   （DoT/DoH 终结在本进程，源 IP 变 127.0.0.1，只能按目标地址选 view）
/// - 默认 view 兜底；geo.lines 为空 → 单层无 view（零开销，需求 10）
pub fn gen_named_conf(cfg: &DnsConfig, zones: &[ZoneRow]) -> String {
    let port = cfg.port_or_default();
    let rndc_port = cfg.rndc_port_or_default();
    let secret = load_or_make_secret();
    let geo_on = cfg.geo.enabled
        && (!cfg.geo.lines.is_empty() || cfg.geo.mmdb.is_active());
    let mut s = String::new();

    // listen-on：基础地址 + 分线路转发 loopback（127.0.0.2..N+1）
    let mut listen = format!("{};", cfg.listen_addr);
    listen.push_str(" 127.0.0.1;");
    for i in 0..cfg.geo.lines.len().min(250) {
        listen.push_str(&format!(" 127.0.0.{};", 2 + i));
    }

    let v6_acl = if cfg.test_mode
        || cfg.listen_addr == "127.0.0.1"
        || cfg.listen_addr == "::1"
    {
        "none"
    } else {
        "any"
    };
    s.push_str(&format!(
        "// generated by Crucible dns module — do not hand-edit\noptions {{\n  directory \"{}\";\n  listen-on port {port} {{ {listen} }};\n  listen-on-v6 port {port} {{ {v6_acl}; }};\n  recursion {};",
        state_root().join("zones").display(),
        if cfg.modes.recursive { "yes" } else { "no" }
    ));

    if cfg.modes.recursive {
        s.push_str(&format!(
            "\n  allow-recursion {}; allow-query-cache {};",
            acl_or(&cfg.recursion_acl, "127.0.0.1"),
            acl_or(&cfg.recursion_acl, "127.0.0.1")
        ));
        // ECS 上游传递由本进程 DoT/DoH 层注入（ecs.rs，/24 硬约束）——
        // bind 9.20 options 无 ecs-prefix-* 语句，写了 named 会拒载。
        s.push_str("\n  qname-minimization relaxed;");
        if !geo_on && !cfg.rpz.is_empty() {
            // 无 view 时 RPZ 声明放 options；有 view 时在每个 view 内（zone 也在 view 内）
            s.push_str(" response-policy { zone \"crucible.rpz\"; } break-dnssec yes;");
        }
    } else {
        s.push_str("\n  allow-recursion { none; };");
    }
    // AXFR 传出全局白名单（需求 6）；ixfr 增量语义；minimal-responses 提吞吐
    // key-directory 属 options 层（9.20 dnssec-policy 内不接受，named -g 探活证实）
    s.push_str(&format!(
        "\n  allow-query {{ any; }};\n  allow-transfer {};\n  dnssec-validation auto;\n  minimal-responses yes;\n  ixfr-from-differences yes;\n  key-directory \"{}\";\n}};\n",
        acl_or(&cfg.axfr_out_acl, "none"),
        state_root().join("keys").display()
    ));

    s.push_str(&format!(
        "key \"rndc-key\" {{ algorithm hmac-sha256; secret \"{secret}\"; }};\ncontrols {{ inet 127.0.0.1 port {rndc_port} allow {{ 127.0.0.1; }} keys {{ \"rndc-key\"; }}; }};\n"
    ));
    // 日志路径必须**绝对**：channel 里的相对路径是相对 named 的**工作目录**解析的，
    // 而 named 由本进程以 cwd=/crucible 启动 —— `../log/named.log` 会落到 /log/ 下，
    // 打不开就静默没有日志（实测 named.log 自 9/9 起再没被写过，
    // 于是「从区没加载」「zone 不重载」这类问题全部无从排查）。
    let log_dir = state_root().join("log");
    let _ = std::fs::create_dir_all(&log_dir);
    s.push_str(&format!(
        "logging {{ channel crucible {{ file \"{}\" versions 3 size 5m; severity info; print-time yes; print-severity yes; }}; category default {{ crucible; }}; }};
",
        log_dir.join("named.log").display()
    ));

    if cfg.dnssec.enabled {
        s.push_str(&gen_kasp_policy(&cfg.dnssec));
    }

    let dnssec_zone_opts = |z: &str| -> String {
        let _ = z;
        if !cfg.dnssec.enabled {
            return String::new();
        }
        let mut o = String::from(" dnssec-policy \"crucible\";");
        if kasp_strict() {
            // inline-signing 在 9.20 与 dnssec-policy 组合为隐式行为；strict 档显式写，
            // lite 档省略（部分版本对组合有警告/拒绝）
            o.push_str(" inline-signing yes;");
        }
        o
    };

    // response-policy 放 view 内（zone 也在 view 内，bind 要求同 view）
    // view_tag：文件名唯一化（同一 zone 文件不得跨 view 复用——named 'writeable file
    // already in use' 拒载）；line_tag：记录按 geo 线路过滤
    let emit_zones = |view_tag: &str, line_tag: &str, in_view: bool, s: &mut String| {
        if cfg.modes.root {
            // 根区不套 KASP（root 模式是实验特性，签名由 rootzone 原文件决定）
            let f = if view_tag.is_empty() { "root.zone".to_string() } else { format!("root.{view_tag}.zone") };
            s.push_str(&format!("zone \".\" {{ type primary; file \"{f}\"; }};\n"));
        }
        if !cfg.rpz.is_empty() {
            if in_view && cfg.modes.recursive {
                s.push_str("response-policy { zone \"crucible.rpz\"; } break-dnssec yes;\n");
            }
            let rf = if view_tag.is_empty() { "rpz.zone".to_string() } else { format!("rpz.{view_tag}.zone") };
            let af = if view_tag.is_empty() { "answers.zone".to_string() } else { format!("answers.{view_tag}.zone") };
            s.push_str(&format!("zone \"crucible.rpz\" {{ type primary; file \"{rf}\"; }};\n"));
            s.push_str(&format!("zone \"crucible.answers\" {{ type primary; file \"{af}\"; }};\n"));
        }
        // 权威开关：modes.authoritative=false 时不声明任何用户 zone。
        // 此前这个字段从生成器里完全没被读过——面板上关掉它没有任何效果，
        // 规格 §16.1 要求的「权威/递归/根 三档可开关」实际上是假的。
        if cfg.modes.authoritative {
            for z in zones {
            let f = zone_file_name(z, view_tag);
            if z.kind == "master" {
                s.push_str(&format!(
                    "zone \"{}\" {{ type primary; file \"{f}\";{}{} }};\n",
                    z.name,
                    dnssec_zone_opts(&z.name),
                    {
                        let acl: Vec<&str> = z
                            .axfr_acl
                            .iter()
                            .map(|s| s.as_str())
                            .filter(|s| valid_acl_item(s))
                            .collect();
                        if acl.is_empty() {
                            String::new()
                        } else {
                            format!(" allow-transfer {{ {}; }};", acl.join("; "))
                        }
                    }
                ));
            } else {
                let prim: Vec<String> = z
                    .primaries
                    .iter()
                    .filter(|p| valid_primary(p))
                    .map(|p| format!("{};", primary_for_named(p)))
                    .collect();
                if prim.is_empty() { continue; }
                s.push_str(&format!(
                    "zone \"{}\" {{ type secondary; primaries {{ {} }}; file \"{f}\"; }};\n",
                    z.name,
                    prim.join(" ")
                ));
            }
            }
        }
    };

    if geo_on {
        // 顺序：geo views（外部客户端 CIDR）→ fwd views（DoT/DoH 转发 dest）→ default 兜底
        for l in &cfg.geo.lines {
            let cidrs = acl_or(&l.cidrs, "none");
            s.push_str(&format!("view \"{}\" {{\n  match-clients {};\n", l.name, cidrs));
            emit_zones(&l.name, &l.name, true, &mut s);
            s.push_str("};\n");
        }
        for (i, l) in cfg.geo.lines.iter().enumerate().take(250) {
            // fwd view 的 match-destinations 必须与 listen-on / resolve_fwd_dest 的 127.0.0.(2+i)
            // 同一映射（此前写成 129+i，fwd view 永远不会命中）
            let dest = 2 + i as u16;
            s.push_str(&format!(
                "view \"fwd-{}\" {{\n  match-destinations {{ 127.0.0.{}; }};\n",
                l.name, dest
            ));
            emit_zones(&format!("fwd-{}", l.name), &l.name, true, &mut s);
            s.push_str("};\n");
        }
        s.push_str("view \"default\" {\n  match-clients { any; };\n");
        emit_zones("default", "", true, &mut s);
        s.push_str("};\n");
    } else {
        emit_zones("", "", false, &mut s);
    }
    s
}

/// DoT/DoH 分线路转发目标：客户端 IP 命中 geo.lines[i].cidrs → 127.0.0.(2+i)
/// （named 侧 fwd-<line> view match-destinations 同一地址）；未启用/未命中 → 127.0.0.1。
/// mmdb 启用时按 line_for() 匹配 (asn/country/isp → 线路名 → 索引)
pub fn resolve_fwd_dest(cfg: &DnsConfig, client: Option<std::net::IpAddr>) -> std::net::IpAddr {
    use std::net::IpAddr;
    let Some(ip) = client else {
        return IpAddr::from([127u8, 0, 0, 1]);
    };
    if !cfg.geo.enabled {
        return IpAddr::from([127u8, 0, 0, 1]);
    }
    // mmdb 优先 (需求 9: 模块化, ASN/ISP/国家线路)
    if cfg.geo.mmdb.is_active() {
        if let Some(line) = crate::server::dns::geoip::line_for(&cfg.geo.mmdb, ip) {
            if let Some(i) = cfg.geo.lines.iter().position(|l| l.name == line) {
                return IpAddr::from([127u8, 0, 0, (2 + i.min(250)) as u8]);
            }
        }
    }
    if cfg.geo.lines.is_empty() {
        return IpAddr::from([127u8, 0, 0, 1]);
    }
    for (i, l) in cfg.geo.lines.iter().enumerate() {
        for c in &l.cidrs {
            if cidr_contains(c, ip) {
                return IpAddr::from([127u8, 0, 0, (2 + i.min(250)) as u8]);
            }
        }
    }
    IpAddr::from([127u8, 0, 0, 1])
}

/// 极小 CIDR 匹配（v4/v6，"a.b.c.d/len"；无掩码按主机地址）
pub fn cidr_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let (base, prefix): (&str, u32) = match cidr.trim().split_once('/') {
        Some((b, p)) => (b, p.trim().parse::<u32>().unwrap_or(999)),
        None => (
            cidr.trim(),
            if cidr.contains(':') { 128u32 } else { 32u32 },
        ),
    };
    let net: IpAddr = match base.parse::<IpAddr>() {
        Ok(n) => n,
        Err(_) => return false,
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(h)) => {
            let bits = 32u32;
            if prefix > bits {
                return false;
            }
            let shift = bits - prefix;
            (n.to_bits() >> shift) == (h.to_bits() >> shift)
        }
        (IpAddr::V6(n), IpAddr::V6(h)) => {
            let bits = 128u32;
            if prefix > bits {
                return false;
            }
            let shift = bits - prefix;
            (n.to_bits() >> shift) == (h.to_bits() >> shift)
        }
        _ => false,
    }
}

/// FNV-1a 32 位：给文件名加一个**可复现**的去重后缀。
/// 自己实现而不用 std 的 DefaultHasher —— 后者的输出不保证跨 Rust 版本稳定，
/// 会让生成的 zone 文件名在升级工具链后整体变一次。
fn fnv1a32(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn zone_file_name(z: &ZoneRow, line_tag: &str) -> String {
    // 只把非字母数字替换成 '_' 是不够的：`a-b.com` 和 `a_b.com`（两者都是合法
    // zone 名，且 zones.name 唯一）会映射到**同一个** .zone 文件；线路名同理
    // （`cn-north` 与 `cn_north`）。于是 write_all 覆盖写同一个文件、named.conf
    // 里两个 view 指向同一文件 —— named 会以「writeable file already in use」拒载，
    // 或者一个线路读到另一个线路的记录。后缀原始名字的哈希保证唯一。
    let safe: String = z
        .name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let tag = format!("{:08x}", fnv1a32(&z.name));
    if line_tag.is_empty() {
        format!("{safe}.{tag}.zone")
    } else {
        let safe_line: String = line_tag
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let ltag = format!("{:08x}", fnv1a32(line_tag));
        format!("{safe}.{tag}.{safe_line}.{ltag}.zone")
    }
}

/// KASP 映射（需求 3/4/5）：keys 结构/算法/轮换/NSEC3 全可配。
fn gen_kasp_policy(d: &DnssecCfg) -> String {
    let mut s = String::from("dnssec-policy \"crucible\" {\n  keys {\n");
    if d.keys.is_empty() {
        let ksk_life = d
            .ksk_lifetime_days
            .filter(|_| d.rotation_enabled)
            .map(|n| format!("{n}d"))
            .unwrap_or_else(|| "unlimited".into());
        let zsk_life = if d.rotation_enabled { format!("{}d", d.rotation_days) } else { "unlimited".into() };
        s.push_str(&format!("    ksk lifetime {ksk_life} algorithm {};\n", d.algorithm));
        s.push_str(&format!("    zsk lifetime {zsk_life} algorithm {};\n", d.algorithm));
    } else {
        for k in &d.keys {
            let life = k
                .lifetime_days
                .filter(|_| d.rotation_enabled)
                .map(|n| format!("{n}d"))
                .unwrap_or_else(|| "unlimited".into());
            s.push_str(&format!("    {} lifetime {life} algorithm {};\n", k.role, d.algorithm));
        }
    }
    s.push_str("  };\n");
    // 9.20 KASP：签名刷新/有效期是独立语句（嵌套块非法）——named -g 探活证实
    s.push_str("  signatures-refresh 3d;\n  signatures-validity 14d;\n  signatures-validity-dnskey 14d;\n");
    s.push_str("  dnskey-ttl 1h;\n  max-zone-ttl 1d;\n  publish-safety 1h;\n  retire-safety 1h;\n");
    if d.nsec3 {
        // 需求 5：默认 NSEC3（迭代数/optout 可配）——9.20 语法是单条 nsec3param 语句
        s.push_str(&format!(
            "  nsec3param iterations {} optout {} salt-length 0;\n",
            d.nsec3_iterations.min(50),
            if d.nsec3_optout { "yes" } else { "no" }
        ));
    }
    if kasp_strict() && d.cds {
        // CDS/CDNSKEY 发布（需求 8）；9.20 无 cds-digest-type 语句（CDS 默认 sha256），
        // cdnskey yes 已探活合法；lite 档自动去掉
        s.push_str("  cdnskey yes;\n");
    }
    s.push_str("};\n");
    s
}

fn load_or_make_secret() -> String {
    let p = state_root().join("etc/session.key");
    if let Ok(t) = std::fs::read_to_string(&p) {
        if let Some(line) = t.lines().find(|l| l.starts_with("secret=")) {
            return line[7..].trim().to_string();
        }
    }
    let mut buf = [0u8; 48];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut buf)
    });
    let secret: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    let _ = std::fs::create_dir_all(state_root().join("etc"));
    let _ = std::fs::write(&p, format!("secret={secret}\n"));
    let _ = set_mode_0600(&p);
    secret
}

#[cfg(unix)]
fn set_mode_0600(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
}

/// 递归 chown 给 _bind（named 运行账户）；失败不致命（仅 OpenBSD 有 _bind）。
fn chown_bind(p: &Path) {
    let _ = std::process::Command::new("chown").arg("-R").arg("_bind:_bind").arg(p).status();
}
#[cfg(not(unix))]
fn set_mode_0600(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------- 落盘 + 校验 + 生命周期

/// 全量落盘：named.conf / rndc.conf / 各 zone 文件 / rpz / rootzone 占位。
pub fn write_all(cfg: &DnsConfig) -> Result<Vec<(String, PathBuf)>> {
    // 先校验所有进入文件名 / named.conf 的用户可控字符串，再落盘。
    // validate() 会先调 write_all 再探活 named，所以检查必须放在这里，
    // 否则恶意 name 已经在盘上了（路径穿越的写入发生在探活之前）。
    for l in &cfg.geo.lines {
        if !valid_line_name(&l.name) {
            bail!("bad geo line name {:?}", l.name);
        }
    }
    for r in &cfg.rpz {
        if !valid_name(&r.name) {
            bail!("bad rpz name {:?}", r.name);
        }
    }
    let etc = state_root().join("etc");
    let zones_dir = state_root().join("zones");
    std::fs::create_dir_all(&etc)?;
    std::fs::create_dir_all(&zones_dir)?;
    std::fs::create_dir_all(state_root().join("keys"))?;
    std::fs::create_dir_all(state_root().join("log"))?;
    // OpenBSD：named 以 _bind 运行（root 直跑会被 lib 权限限制拒掉 logging/写盘），
    // named 需要写 log/zones（inline-signing journal）/keys（KASP 出key），读 named.conf
    chown_bind(&zones_dir);
    chown_bind(&state_root().join("log"));
    chown_bind(&state_root().join("keys"));

    let zones = list_zones()?;
    let conf = gen_named_conf(cfg, &zones);
    let conf_path = etc.join("named.conf");
    std::fs::write(&conf_path, &conf)?;
    // _bind 只需读；0600 会拒读 → 0640 + 属主 _bind
    let _ = std::fs::set_permissions(&conf_path, {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o640)
    });
    let _ = std::process::Command::new("chown").arg("_bind").arg(&conf_path).status();

    let secret = load_or_make_secret();
    let rndc_port = cfg.rndc_port_or_default();
    std::fs::write(
        etc.join("rndc.conf"),
        // 9.20 rndc.conf：options 里必须用 default-key（裸 key 是非法语句，named -g/rndc 实测拒绝）
        format!(
            "options {{ default-server 127.0.0.1; default-port {rndc_port}; default-key \"rndc-key\"; }};\nserver 127.0.0.1 {{ key \"rndc-key\"; }};\nkey \"rndc-key\" {{ algorithm hmac-sha256; secret \"{secret}\"; }};\n"
        ),
    )?;
    let _ = set_mode_0600(&etc.join("rndc.conf"));

    // per-view 变体落盘——必须与 gen_named_conf 的 view 列表一致（view_tag, line_tag）；
    // 同一 zone 文件不得跨 view 复用（named 'writeable file already in use' 拒载）
    let geo_on = cfg.geo.enabled
        && (!cfg.geo.lines.is_empty() || cfg.geo.mmdb.is_active());
    let mut views: Vec<(String, String)> = vec![(String::new(), String::new())];
    if geo_on {
        for l in &cfg.geo.lines {
            views.push((l.name.clone(), l.name.clone()));
        }
        for (i, l) in cfg.geo.lines.iter().enumerate().take(250) {
            views.push((format!("fwd-{}", l.name), l.name.clone()));
        }
        views.push(("default".into(), String::new()));
    }
    let mut written: Vec<(String, PathBuf)> = Vec::new();
    for (view_tag, line_tag) in &views {
        // 与 gen_named_conf 同步：权威关掉时不落用户 zone 文件
        // （否则盘上留着 orphan zone，且 named.conf 里已无引用，排障时极易误判）。
        if !cfg.modes.authoritative {
            break;
        }
        for z in &zones {
            // 从区（secondary/slave）的 zone 文件归 **named 自己**维护：
            // gen_named_conf 为它写的是 `type secondary; primaries { ... };`，
            // AXFR/IXFR 与 refresh/retry/expire 全部由 named 负责，文件内容也由它落盘。
            // 这里若照样生成，就会用本地的空记录覆盖掉 named 刚传下来的区；
            // 而且生成出来的文本没有 SOA（下面只有 kind==master 才补 SOA/NS），
            // named 会以「不是合法的 master file」拒载 —— 从区等于永远起不来。
            if z.kind != "master" {
                continue;
            }
            let recs: Vec<RecordRow> = list_records(&z.name)?.into_iter().filter(|r| r.line == *line_tag).collect();
            let path = zones_dir.join(zone_file_name(z, view_tag));
            // serial 单调：读回本次覆盖前的 SOA serial，保证严格递增，
            // 否则同秒内的第二次编辑对任何 AXFR/IXFR 消费者都是「没变」。
            // 只靠文件是不够的：文件被删/丢过时 prev 为 None → serial 直接取 now，
            // 可能正好等于 named 已加载的值 → BIND 判定「serial 没变，不重载」，
            // 于是新记录写进了文件却**永远不出现在被服务的分区里**（实测遇到过）。
            // 叠加 DB 里的高水位（meta: serial:<zone>）保证跨文件生命周期的严格递增。
            // serial 还必须**压过 named 的 signed 版本**：开了 inline-signing 后
            // BIND 每次签名都会把 serial 往上顶（实测文件 1790160412 / signed 1790160416）。
            // 我们若按 now 生成一个更小的值，BIND 会以
            //   ixfr-from-differences: new serial (…) out of range [前值+1 - …]
            //   not loaded due to errors
            // **拒载该 zone** —— 表现就是「面板加的记录写进了文件、服务里却查不到」，
            // 并且从区来拉 SOA 时主区回 SERVFAIL，从区也永远起不来。
            let path_signed = {
                let mut q = path.clone().into_os_string();
                q.push(".signed");
                std::path::PathBuf::from(q)
            };
            let fs_serial = std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| serial_from_zone_text(&t));
            let ss_serial = std::fs::read_to_string(&path_signed)
                .ok()
                .and_then(|t| serial_from_zone_text(&t));
            let file_serial = match (fs_serial, ss_serial) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            let hw = meta_get(&format!("serial:{}", z.name))
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            // 最关键的一块地板：**直接问 named 它现在认的 serial**。
            //
            // 只看文件不够 —— 开了 inline-signing 后 BIND 每次签名都会把 serial 往上顶，
            // 它的 last-seen 是签名后的值；而我们每次写完就把 .signed 删掉，
            // 等于把唯一能看出 BIND 串号的线索也断了。于是"文件 serial"可能仍低于它：
            //   zone X/IN (unsigned): ixfr-from-differences: new serial (…) out of range [前值+1 - …]
            //   zone X/IN (unsigned): not loaded due to errors
            // BIND 直接拒载整个 zone → 面板加了记录、服务里查不到；从区来拉 SOA 得 SERVFAIL、
            // 永远起不来。实测规律：同一秒内「建区 + 加记录」必现；隔一两秒则因时间戳型
            // serial 自然追平而"自愈"，所以这类问题极难手工复现。问进程可彻底消除盲区。
            let named_serial = named_zone_serial(cfg, &z.name);
            let prev_serial = file_serial
                .into_iter()
                .chain(std::iter::once(hw).filter(|v| *v > 0))
                .chain(std::iter::once(named_serial).filter(|v| *v > 0))
                .max();
            std::fs::write(
                &path,
                gen_zone_file_monotonic(&z.name, &z.kind, &recs, prev_serial),
            )?;
            // zone 文件是控制面的 source of truth：regen 后旧 journal/inline-signing
            // 产物必然失步（named 'journal out of sync' 拒载），一并清掉
            // 把刚落盘的真实 serial 记为高水位（从写出的文本读回，保证与文件一致）
            if let Some(ser) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| serial_from_zone_text(&t))
            {
                if let Err(e) = meta_set(&format!("serial:{}", z.name), &ser.to_string()) {
                    // 不能吞：这块地板失效时的表象是「zone 被 BIND 拒载、面板加的记录不生效」，
                    // 与项目里反复出现的 || echo warn / .ok()? / let _ = 属同一类静默失败。
                    log::warn!("dns: 记录 serial 高水位失败 zone={} err={e:#}", z.name);
                }
            }
            for ext in [".jnl", ".signed", ".signed.jnl"] {
                let mut j = path.clone().into_os_string();
                j.push(ext);
                let _ = std::fs::remove_file(&j);
            }
            written.push((z.name.clone(), path));
        }
        if cfg.modes.root {
            let f = if view_tag.is_empty() { "root.zone".to_string() } else { format!("root.{view_tag}.zone") };
            let path = zones_dir.join(&f);
            if !path.exists() {
                // 空文件会让 named 拒载 root zone；先写最小合法占位，rootzone_refresh 覆盖
                std::fs::write(&path, minimal_root_zone(cfg))?;
            }
        }
    }
    if !cfg.rpz.is_empty() {
        for (view_tag, _) in &views {
            let rf = if view_tag.is_empty() { "rpz.zone".to_string() } else { format!("rpz.{view_tag}.zone") };
            let path = zones_dir.join(&rf);
            std::fs::write(&path, gen_rpz_file(&cfg.rpz))?;
            let mut j = path.clone().into_os_string();
            j.push(".jnl");
            let _ = std::fs::remove_file(&j);
            written.push(("crucible.rpz".into(), path));
            // answers 区：override 自定义响应（A/AAAA/TXT）的真实记录（需求 7）
            let af = if view_tag.is_empty() { "answers.zone".to_string() } else { format!("answers.{view_tag}.zone") };
            let apath = zones_dir.join(&af);
            std::fs::write(&apath, gen_answers_file(&cfg.rpz))?;
            let mut j2 = apath.clone().into_os_string();
            j2.push(".jnl");
            let _ = std::fs::remove_file(&j2);
            written.push(("crucible.answers".into(), apath));
        }
    }
    Ok(written)
}

/// 配置校验：本包不带 named-checkconf → 用 `named -g` 探活法——
/// 起 1.2s 内退出即配置非法（stderr 回传给面板），存活则杀掉继续正常启动。
/// strict=true 写入全量语句（含 cdnskey/cds/inline-signing 等 9.20 未确证项），
/// 失败时调用方以 strict=false 重试（语句降级），named 永远能起。
pub fn validate(cfg: &DnsConfig, strict: bool) -> Result<()> {
    use std::io::Read;
    KASP_STRICT.store(strict, std::sync::atomic::Ordering::Relaxed);
    write_all(cfg)?;
    let conf = state_root().join("etc/named.conf");
    let mut child = std::process::Command::new(NAMED_BIN)
        .arg("-u")
        .arg("_bind")
        .arg("-c")
        .arg(&conf)
        .arg("-g")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("probe spawn named")?;
    std::thread::sleep(std::time::Duration::from_millis(1200));
    match child.try_wait() {
        Ok(Some(st)) => {
            let mut err = String::new();
            if let Some(mut se) = child.stderr.take() {
                let _ = se.read_to_string(&mut err);
            }
            bail!("named config invalid ({}): {}", st, last_lines(&err, 8));
        }
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        }
        Err(e) => bail!("probe wait: {e}"),
    }
}

fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

const NAMED_BIN: &str = "/usr/local/sbin/named";
const RNDC_BIN: &str = "/usr/local/sbin/rndc";
const KEYGEN_BIN: &str = "/usr/local/bin/dnssec-keygen";

fn run(bin: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("spawn {bin}"))?;
    if !out.status.success() {
        bail!(
            "{bin} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into())
}

fn named_alive(cfg: &DnsConfig) -> bool {
    rndc(cfg, &["status"]).is_ok()
}

/// 问 named 该 zone 当前的 SOA serial（权威来源；取 `serial` 与 `signed serial` 的较大者）。
///
/// 用途见 [`write_all`] 里 prev_serial 处的注释：只按文件推算 serial 会低于 BIND 已知值
/// （inline-signing 每次签名都往上顶，而我们会删掉 .signed），BIND 于是拒载整个 zone。
/// named 没跑 / 该 zone 未加载 / rndc 不可用时返回 0，调用方按"未知"处理。
fn named_zone_serial(cfg: &DnsConfig, zone: &str) -> u64 {
    let text = match rndc(cfg, &["zonestatus", zone]) {
        Ok(t) => t,
        Err(e) => {
            log::debug!("dns: zonestatus {zone} 取 serial 失败（按未知处理）: {e:#}");
            return 0;
        }
    };
    let mut best = 0u64;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            // 形如 "serial: 1790203401" 或 "signed serial: 1790203405"
            if k.trim().ends_with("serial") {
                if let Ok(n) = v.trim().parse::<u64>() {
                    best = best.max(n);
                }
            }
        }
    }
    best
}

fn rndc(cfg: &DnsConfig, args: &[&str]) -> Result<String> {
    let conf = state_root().join("etc/rndc.conf");
    let out = std::process::Command::new(RNDC_BIN)
        .arg("-c")
        .arg(&conf)
        .args(args)
        .output()
        .context("spawn rndc")?;
    if !out.status.success() {
        bail!("rndc {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into())
}

/// reconcile：落盘 → 校验（探活法，named 已在跑则跳过）→ 确保进程 → reload。
pub fn reconcile(cfg: &DnsConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    write_all(cfg)?;
    // 需求 9：MaxMind GeoLite2 数据库自同步 (cron 每日 + 启动时增量检查)
    if cfg.geo.enabled && cfg.geo.mmdb.is_active() && !cfg.geo.mmdb.license_key.is_empty() {
        if let Err(e) = crate::server::dns::geoip::ensure_synced(&cfg.geo.mmdb, false) {
            log::warn!("dns: geoip auto-sync failed: {e:#}");
        }
    }
    let alive = named_alive(cfg);
    if !alive {
        // 探活校验只在 named 未运行时做（避免探针端口冲突假阴性）；
        // 失败自动降级重试一次（去掉 9.20 未确证语句，见 validate 的 strict 参数）
        if let Err(e) = validate(cfg, true) {
            log::warn!("dns: strict validate failed, retry lite: {e:#}");
            validate(cfg, false)?;
        }
        let conf = state_root().join("etc/named.conf");
        // 权限：named 以 _bind 用户运行（root 绑端口后 drop）；zones/keys/log 需可写
        let _ = std::process::Command::new("chown")
            .arg("-R")
            .arg("_bind:_bind")
            .arg(state_root())
            .status();
        // OpenBSD lo0 默认只有 127.0.0.1/32——fwd view 的 127.0.0.(2+i) 目标需显式 alias
        if cfg.geo.enabled {
            for (i, _) in cfg.geo.lines.iter().enumerate().take(250) {
                let _ = std::process::Command::new("ifconfig")
                    .args(["lo0", "inet", &format!("127.0.0.{}", 2 + i), "alias"])
                    .status();
            }
        }
        // named daemonize fork (OpenBSD) fails writing pidfile → use -g foreground
        // + detached stdio so named survives parent (webserver) exit (需求 12).
        // named 必须用 -g 前台跑（OpenBSD 上 daemonize 写 pidfile 会失败），
        // 但 BIND 的 -g 会**强制所有日志走 stderr、忽略 logging 配置里的 file channel**。
        // 再把 stderr 丢给 /dev/null，就等于**整台 DNS 服务没有任何日志** ——
        // 「从区没加载」「zone 不重载」这类问题完全无从排查（实测踩过：named.log
        // 自 9/9 起再没被写过）。改为追加写到 state/dns/log/named.stderr.log。
        let derr = state_root().join("log").join("named.stderr.log");
        if let Some(d) = derr.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let logf = std::fs::OpenOptions::new().create(true).append(true).open(&derr).ok();
        let mut cmd = std::process::Command::new(NAMED_BIN);
        cmd.arg("-u")
            .arg("_bind")
            .arg("-c")
            .arg(&conf)
            .arg("-g")
            .stdin(std::process::Stdio::null());
        match logf {
            Some(f) => {
                let f2 = f.try_clone().ok();
                cmd.stdout(std::process::Stdio::from(f));
                match f2 {
                    Some(g) => {
                        cmd.stderr(std::process::Stdio::from(g));
                    }
                    None => {
                        cmd.stderr(std::process::Stdio::null());
                    }
                }
            }
            None => {
                cmd.stdout(std::process::Stdio::null());
                cmd.stderr(std::process::Stdio::null());
            }
        }
        let st = cmd.spawn();
        match st {
            Ok(_) => std::thread::sleep(std::time::Duration::from_millis(800)),
            Err(e) => bail!("spawn named: {e}"),
        }
    }
    // reconfig + reload 缺一不可（BIND 语义）：
    // - reconfig：应用 listen-on / view / 新增删除 zone（reload 不读这些）
    // - reload：重读已存在 zone 的新 serial 内容（reconfig 不重读文件内容）
    let rc = rndc(cfg, &["reconfig"]);
    let rl = rndc(cfg, &["reload"]);
    rc.and(rl)?;
    Ok(())
}

/// 一键生成 DNSSEC key（需求 4）。返回生成的 key 文件名。
pub fn keygen(zone: &str, role: &str, alg: &str) -> Result<String> {
    let keys = state_root().join("keys");
    std::fs::create_dir_all(&keys)?;
    // ksk/csk 用 -f ROLE；zsk 默认
    let mut args: Vec<String> = vec![
        "-K".into(),
        keys.to_string_lossy().into(),
        "-a".into(),
        alg.to_string(),
    ];
    if role == "ksk" {
        args.push("-f".into());
        args.push("KSK".into());
    } else if role == "csk" {
        args.push("-f".into());
        args.push("CSK".into());
    }
    args.push("-L".into());
    args.push("3600".into());
    args.push(zone.to_string());
    let names = run(
        KEYGEN_BIN,
        &args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    )?;
    let name = names.trim().to_string();
    if name.is_empty() {
        bail!("dnssec-keygen produced no name");
    }
    Ok(name)
}

/// 用户自定义私钥上传（需求 4）：base64 解码落 key 目录，0600。
pub fn upload_key(filename: &str, b64: &str) -> Result<PathBuf> {
    if filename.contains("..") || filename.contains('/') || filename.is_empty() {
        bail!("bad key filename");
    }
    let decoded = b64_decode(b64.trim())?;
    let dir = state_root().join("keys");
    std::fs::create_dir_all(&dir)?;
    let p = dir.join(filename);
    std::fs::write(&p, &decoded)?;
    let _ = set_mode_0600(&p);
    Ok(p)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = T
            .iter()
            .position(|t| *t == c)
            .map(|i| i as u32)
            .ok_or_else(|| anyhow!("bad base64"))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- root zone（需求 2）

/// 拉取 root.zone（curl）→ 安装 → reload（合法性由 named 加载日志 + dig 兜底）。
/// 根服务器不开放 AXFR，用整区替换等价实现 IXFR 的增量目的（报告已注明）。
pub fn rootzone_refresh(cfg: &DnsConfig) -> Result<String> {
    // 优先 IXFR（需求 2：axfr_servers 非空时），回退 curl 全量 HTTPS 下载
    if !cfg.rootzone.axfr_servers.is_empty() {
        match rootzone_ixfr(cfg) {
            Ok(p) => return Ok(p),
            Err(e) => log::warn!("dns: rootzone IXFR failed, falling back to HTTPS: {e:#}"),
        }
    }
    let zones = state_root().join("zones");
    std::fs::create_dir_all(&zones)?;
    let tmp = zones.join("root.zone.tmp");
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "120", "-o"])
        .arg(&tmp)
        .arg(&cfg.rootzone.url)
        .output()
        .context("spawn curl")?;
    if !out.status.success() {
        bail!("rootzone fetch failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let dst = zones.join("root.zone");
    std::fs::rename(&tmp, &dst)?;
    meta_set("root_last_ok", &chrono_now().to_string())?;
    let _ = rndc(cfg, &["reload", "."]);
    Ok(dst.to_string_lossy().into())
}

fn meta_set(k: &str, v: &str) -> Result<()> {
    let conn = store()?;
    conn.execute(
        "INSERT INTO meta(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=?2",
        [k, v],
    )?;
    Ok(())
}

pub fn meta_get(k: &str) -> Result<Option<String>> {
    let conn = store()?;
    let mut st = conn.prepare("SELECT v FROM meta WHERE k=?1")?;
    let mut rows = st.query_map([k], |r| r.get::<_, String>(0))?;
    Ok(rows.next().transpose()?)
}
#[derive(Debug, Clone, Serialize)]
pub struct DnssecKeyInfo {
    pub filename: String,
    pub zone: String,
    pub role: String,
    pub algorithm: String,
    pub tag: String,
    pub flags: u16,
    pub keytype: String,
    pub created: String,
    pub published: String,
    pub active: String,
    pub retired: String,
    pub removed: String,
    pub state_file: String,
    pub dnskeystate: String,
    pub goalstate: String,
}

fn dnssec_parse_key_filename(name: &str) -> Option<(String, String, String)> {
    let stem = name.strip_suffix(".key").unwrap_or(name);
    let stem = stem.strip_suffix(".private").unwrap_or(stem);
    let stem = stem.strip_suffix(".state").unwrap_or(stem);
    let rest = stem.strip_prefix('K')?;
    let dot_idx = rest.find('.')?;
    let zone = rest[..dot_idx].to_string();
    let suffix = &rest[dot_idx..];
    let plus1 = suffix.find('+')?;
    let after1 = &suffix[plus1 + 1..];
    let plus2 = after1.find('+')?;
    let alg = after1[..plus2].to_string();
    let tag = after1[plus2 + 1..].to_string();
    Some((zone, tag, alg))
}

fn parse_key_comment(line: &str, label: &str) -> Option<String> {
    if !line.starts_with("; ") { return None; }
    let after = &line[2..];
    let pattern = format!("{}: ", label);
    if !after.starts_with(&pattern) { return None; }
    let val = after[pattern.len()..].trim();
    Some(val.to_string())
}

fn parse_state_value(line: &str, label: &str) -> Option<String> {
    let pattern = format!("{}: ", label);
    if !line.starts_with(&pattern) { return None; }
    let val = line[pattern.len()..].trim();
    Some(val.to_string())
}

fn dnssec_is_keyfile(fname: &str) -> bool {
    if !fname.starts_with('K') { return false; }
    let stem = fname.strip_suffix(".key")
        .or_else(|| fname.strip_suffix(".state"))
        .or_else(|| fname.strip_suffix(".private"));
    let stem = match stem { Some(s) => s, None => return false };
    let rest = match stem.strip_prefix('K') { Some(s) => s, None => return false };
    let dot_idx = rest.find('.');
    if dot_idx.is_none() { return false; }
    let suffix = &rest[dot_idx.unwrap()..];
    suffix.contains("+0")
}

pub fn dnssec_key_list() -> Vec<DnssecKeyInfo> {
    let kp = state_root().join("keys");
    let mut map: std::collections::BTreeMap<String, DnssecKeyInfo> = std::collections::BTreeMap::new();
    if !kp.is_dir() { return Vec::new(); }
    if let Ok(entries) = std::fs::read_dir(&kp) {
        for e in entries.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            if !dnssec_is_keyfile(&fname) { continue; }
            let is_state = fname.ends_with(".state");
            let stem = if is_state {
                fname.strip_suffix(".state").unwrap_or(&fname)
            } else if fname.ends_with(".private") {
                fname.strip_suffix(".private").unwrap_or(&fname)
            } else {
                fname.strip_suffix(".key").unwrap_or(&fname)
            };
            let content = std::fs::read_to_string(kp.join(&fname)).unwrap_or_default();
            let mut info = map.entry(stem.to_string()).or_insert_with(|| DnssecKeyInfo {
                filename: format!("{}.key", stem),
                zone: String::new(),
                role: String::new(),
                algorithm: String::new(),
                tag: String::new(),
                flags: 0,
                keytype: String::new(),
                created: String::new(),
                published: String::new(),
                active: String::new(),
                retired: String::new(),
                removed: String::new(),
                state_file: format!("{}.state", stem),
                dnskeystate: String::new(),
                goalstate: String::new(),
            });
            if is_state {
                for line in content.lines() {
                    if let Some(v) = parse_state_value(line, "KSK") {
                        if v == "yes" { info.role = "KSK".into(); }
                    }
                    if let Some(v) = parse_state_value(line, "ZSK") {
                        if v == "yes" {
                            if info.role.is_empty() { info.role = "ZSK".into(); }
                            else { info.role = "CSK".into(); }
                        }
                    }
                    if let Some(v) = parse_state_value(line, "Generated") { info.created = v; }
                    if let Some(v) = parse_state_value(line, "Published") { info.published = v; }
                    if let Some(v) = parse_state_value(line, "Active") { info.active = v; }
                    if let Some(v) = parse_state_value(line, "Retired") { info.retired = v; }
                    if let Some(v) = parse_state_value(line, "Removed") { info.removed = v; }
                    if let Some(v) = parse_state_value(line, "DNSKEYState") { info.dnskeystate = v; }
                    if let Some(v) = parse_state_value(line, "GoalState") { info.goalstate = v; }
                }
            } else {
                for line in content.lines() {
                    if line.contains("key-signing key") {
                        info.role = "KSK".into();
                    } else if line.contains("zone-signing key") && info.role.is_empty() {
                        info.role = "ZSK".into();
                    }
                    if let Some(v) = parse_key_comment(line, "Created") { info.created = v; }
                    if let Some(v) = parse_key_comment(line, "Publish") { info.published = v; }
                    if let Some(v) = parse_key_comment(line, "Activate") { info.active = v; }
                    if let Some(v) = parse_key_comment(line, "Inactive") { info.retired = v; }
                    if let Some(v) = parse_key_comment(line, "Delete") { info.removed = v; }
                }
                for line in content.lines() {
                    if line.contains(" IN DNSKEY ") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 7 {
                            if let Ok(f) = parts[2].parse::<u16>() { info.flags = f; }
                            info.algorithm = parts[4].to_string();
                        }
                        if let Some((zone, tag, alg)) = dnssec_parse_key_filename(&info.filename) {
                            info.zone = zone;
                            info.tag = tag;
                            info.keytype = alg;
                        }
                        break;
                    }
                }
            }
        }
    }
    let mut result: Vec<DnssecKeyInfo> = map.into_values().collect();
    result.sort_by(|a, b| a.tag.cmp(&b.tag));
    result
}

/// 列出已加载的 DNSSEC 密钥（从 keys 目录扫描 *.key/*.private，供面板展示）。
/// 启动时调用：DNS 启用则 reconcile + 启动 DoT 监听。
pub async fn startup(live: &Arc<crate::server::live_config::LiveConfig>, cfg_path: &Path) {
    let cfg = effective(&live.snapshot());
    if !cfg.enabled {
        log::info!("dns: module disabled");
        return;
    }
    // Let's Encrypt 先行（dot cert = "acme:<domain>" 时 DoT 依赖其产出）
    acme::startup(&cfg.acme).await;
    let dc = cfg.clone();
    let r = tokio::task::spawn_blocking(move || reconcile(&dc)).await;
    match r {
        Ok(Ok(())) => log::info!("dns: named reconciled (port {})", cfg.port_or_default()),
        Ok(Err(e)) => log::error!("dns: reconcile failed: {e:#}"),
        Err(e) => log::error!("dns: reconcile join: {e}"),
    }
    if cfg.dot.enabled {
        tokio::spawn(dot_doh::dot_listener(cfg.clone()));
    }
    tokio::spawn(maintenance_loop(Arc::clone(live), cfg_path.to_path_buf()));
}

#[derive(Debug, Clone, Serialize)]
pub struct DsPublishInfo {
    pub zone: String,
    pub tag: String,
    pub algorithm: String,
}

/// DNSSEC 密钥轮换（需求 3）：检查 key 年龄，快到期时生成新 key 让 BIND KASP 接管切换。
/// ZSK：rotation_days 到期前 7 天；KSK：ksk_lifetime_days 到期前 14 天。
/// 返回需要发布 DS 的 KSK（KSK rollover → 面板提示向父区/注册商提交 DS）。
pub fn dnssec_check_and_rotate(cfg: &DnsConfig, dc: &DnsConfig) -> Result<Vec<DsPublishInfo>> {
    if !dc.dnssec.enabled || !dc.dnssec.rotation_enabled {
        return Ok(Vec::new());
    }
    let keys = dnssec_key_list();
    let now = chrono_now();
    let mut need_ds: Vec<DsPublishInfo> = Vec::new();

    for key in &keys {
        let role = key.role.as_str();
        // active 字段是 YYYYMMDDHHMMSS（UTC）或 unix epoch，取 epoch 更可靠
        let active_ts = key.active.parse::<u64>().unwrap_or_else(|_| parse_dnssec_time(&key.active));
        let lifetime_days = match role {
            "KSK" => dc.dnssec.ksk_lifetime_days.unwrap_or(dc.dnssec.rotation_days * 12),
            "ZSK" | "CSK" => dc.dnssec.rotation_days,
            _ => continue,
        };
        let lifetime_secs = lifetime_days * 86400;
        let age_secs = now.saturating_sub(active_ts);

        if role == "KSK" {
            let ksk_threshold = lifetime_secs.saturating_sub(14 * 86400);
            if age_secs > ksk_threshold {
                log::info!(
                    "dnssec: KSK tag={} nearing end of life (age {}s, threshold {}s), will rollover",
                    key.tag, age_secs, ksk_threshold
                );
                need_ds.push(DsPublishInfo {
                    zone: key.zone.clone(),
                    tag: key.tag.clone(),
                    algorithm: key.algorithm.clone(),
                });
            }
        } else if role == "ZSK" || role == "CSK" {
            let zsk_threshold = lifetime_secs.saturating_sub(7 * 86400);
            if age_secs > zsk_threshold {
                log::info!(
                    "dnssec: {} tag={} nearing end of life, generating replacement",
                    role, key.tag
                );
                match keygen(&key.zone, "zsk", &dc.dnssec.algorithm) {
                    Ok(new_name) => {
                        log::info!("dnssec: generated new ZSK for {}: {}", key.zone, new_name);
                    }
                    Err(e) => log::warn!("dnssec: keygen failed for {}: {e}", key.zone),
                }
            }
        }
    }
    Ok(need_ds)
}

/// 解析 DNSSEC .key 文件中的 YYYYMMDDHHMMSS 时间戳 → unix epoch
fn parse_dnssec_time(s: &str) -> u64 {
    // 格式：YYYYMMDDHHMMSS
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 14 {
        return 0;
    }
    let y: u64 = digits[0..4].parse().unwrap_or(0);
    let mo: u64 = digits[4..6].parse().unwrap_or(1);
    let d: u64 = digits[6..8].parse().unwrap_or(1);
    let h: u64 = digits[8..10].parse().unwrap_or(0);
    let mi: u64 = digits[10..12].parse().unwrap_or(0);
    let se: u64 = digits[12..14].parse().unwrap_or(0);
    // 简单计算（不考虑闰秒）。
    // 年份用 saturating_sub：`Activate: 00010101000000` 这类（管理员上传的 key 文件
    // 里完全可能出现）会让 y < 1970，无符号减法在 debug/overflow-checks 下直接 panic，
    // 而这条路径是从 status_json 与轮换循环可达的。
    y.saturating_sub(1970) * 365 * 86400
        + mo * 30 * 86400
        + d * 86400
        + h * 3600
        + mi * 60
        + se
}

/// Root zone AXFR 增量更新（需求 2）：比较 SOA serial → IXFR → 应用差异。
/// 不支持 IXFR 时回退全量 AXFR（dig axfr）。
///
/// 注意：`dig ixfr` 的应答是 RFC1995 **差异流**（SOA(new) / 删除段 / SOA(old) /
/// 新增段 / SOA(new)），不是完整 zone 文件。旧实现把这段原始文本直接
/// `fs::write` 成 root.zone，等于用差异覆盖整区——zone 立刻损坏、named 起不来。
/// 现在差异会被真正应用到现有 zone 上，并在替换前校验 serial；
/// 任何一步不成立就返回 false，交给调用方走全量 AXFR。
pub fn rootzone_ixfr(cfg: &DnsConfig) -> Result<String> {
    let zones = state_root().join("zones");
    std::fs::create_dir_all(&zones)?;
    let dst = zones.join("root.zone");

    let current_serial = rootzone_current_serial(&dst).unwrap_or(0);
    let server = cfg.rootzone.axfr_servers.first()
        .ok_or_else(|| anyhow::anyhow!("no axfr_servers for root zone"))?;

    // 先尝试 IXFR 差异应用（就地改 dst，成功后 atomic 替换）。
    match try_ixfr_apply(server, &dst, current_serial) {
        Ok(true) => {
            meta_set("root_last_ok", &chrono_now().to_string())?;
            let _ = rndc(cfg, &["reload", "."]);
            return Ok(dst.to_string_lossy().into());
        }
        Ok(false) => log::info!("dns: rootzone IXFR unsupported/not applicable, full AXFR fallback"),
        Err(e) => log::warn!("dns: rootzone IXFR failed ({e:#}), full AXFR fallback"),
    }

    // 全量 AXFR：dig 的 axfr 输出本身就是 master file 格式。
    let out = std::process::Command::new("dig")
        .args(["axfr".to_string(), format!("@{server}"), ".".to_string()])
        .output()
        .context("dig axfr")?;
    if !out.status.success() {
        bail!("dig axfr failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    // 校验拿到的确实是完整 zone（至少要有 SOA），避免把错误文本写进 zone 文件。
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("IN\tSOA") && !text.contains("IN SOA") {
        bail!("dig axfr output has no SOA; refusing to overwrite zone");
    }
    let tmp = zones.join("root.zone.tmp");
    std::fs::write(&tmp, &out.stdout)?;
    std::fs::rename(&tmp, &dst)?;
    meta_set("root_last_ok", &chrono_now().to_string())?;
    let _ = rndc(cfg, &["reload", "."]);
    Ok(dst.to_string_lossy().into())
}

/// 把 IXFR 差异应用到现有 zone。
///
/// 返回 `Ok(true)` = 已应用并替换成功（含「无变化」）；
/// `Ok(false)` = 该源不适用 IXFR，调用方应回退全量；
/// `Err` = 尝试过但失败（同样回退）。
fn try_ixfr_apply(server: &str, dst: &Path, current_serial: u64) -> Result<bool> {
    if current_serial == 0 || !dst.exists() {
        return Ok(false); // 没有本地 zone 可比对，直接走全量
    }
    // 正确的写法是单个 `@server` 参数；旧代码拆成 "@" + server 两个 argv，
    // dig 会把 server 当成第二个查询名。
    let out = std::process::Command::new("dig")
        .args([
            "+noall",
            "+answer",
            "ixfr",
            &current_serial.to_string(),
            &format!("@{server}"),
            ".",
        ])
        .output()
        .context("dig ixfr")?;
    if !out.status.success() {
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let records: Vec<&str> = stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    let soa_idx: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("SOA"))
        .map(|(i, _)| i)
        .collect();
    if soa_idx.is_empty() {
        return Ok(false);
    }
    // 单个 SOA：要么「无变化」，要么不是完整区。按 serial 判定，绝不写文件。
    if soa_idx.len() == 1 {
        let new_serial = soa_serial_from_line(records[soa_idx[0]]);
        if new_serial == Some(current_serial) {
            log::info!("dns: rootzone already at serial {current_serial}");
            return Ok(true);
        }
        return Ok(false);
    }

    // 多 SOA → 标准 IXFR 差异流。逐段应用：SOA(new) → 删除段 → SOA(old) →
    // 新增段 → SOA(new) …
    let target_serial = soa_serial_from_line(records[soa_idx[0]]);
    let original = std::fs::read_to_string(dst).context("read current zone")?;
    let mut lines: Vec<String> = original.lines().map(|l| l.to_string()).collect();

    let mut i = 1usize;
    let mut applied_segments = 0usize;
    while i < records.len() {
        // 删除段：直到下一个 SOA
        let del_start = i;
        while i < records.len() && !records[i].contains("SOA") {
            i += 1;
        }
        let deletions = &records[del_start..i];
        if i >= records.len() {
            break; // 没有配对的 SOA(old)，差异流不完整
        }
        i += 1; // 跳过 SOA(old)
        // 新增段：直到下一个 SOA
        let add_start = i;
        while i < records.len() && !records[i].contains("SOA") {
            i += 1;
        }
        let additions = &records[add_start..i];
        if i < records.len() {
            i += 1; // 跳过 SOA(new)，继续下一段
        }

        // 先删后加。记录按规范化文本比对（dig 与 zone 文件的 TTL/空白格式可能不同）。
        for d in deletions {
            let key = normalize_rr(d);
            if let Some(pos) = lines.iter().position(|l| normalize_rr(l) == key) {
                lines.remove(pos);
            }
        }
        for a in additions {
            lines.push((*a).to_string());
        }
        applied_segments += 1;
    }

    if applied_segments == 0 {
        return Ok(false);
    }

    // 校验：应用后的 zone 必须能解析出目标 serial，否则回退全量。
    let new_text = lines.join("\n") + "\n";
    let got_serial = serial_from_zone_text(&new_text);
    if target_serial.is_none() || got_serial != target_serial {
        log::warn!(
            "dns: IXFR apply serial check failed (want {target_serial:?} got {got_serial:?}); \
             falling back to full AXFR"
        );
        return Ok(false);
    }

    let tmp = dst.with_extension("zone.tmp");
    std::fs::write(&tmp, new_text.as_bytes())?;
    std::fs::rename(&tmp, dst)?;
    log::info!(
        "dns: rootzone IXFR applied {applied_segments} segment(s) → serial {:?}",
        target_serial
    );
    Ok(true)
}

/// 规范化一条 RR 文本用于比对：去掉注释、压缩空白、去尾点差异。
fn normalize_rr(line: &str) -> String {
    let no_comment = line.split(';').next().unwrap_or("");
    no_comment.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// 从 `... SOA mname rname SERIAL ...` 行里取 serial。
///
/// 必须同时认两种形态，因为我们**自己生成的就是后者**：
///   单行：`@ IN SOA ns1 hostmaster 1790211513 …`
///   多行括号：
///     `@ IN SOA ns1 hostmaster (`
///     `  1790211513 ; serial`
/// 旧实现只做 `toks.get(soa + 3)?.parse()`，在多行形态下那个位置是 `(` —— 解析必然失败，
/// 于是 serial_from_zone_text 对我们自己的 zone 文件永远返回 None：文件地板与 DB 高水位
/// 都是死的，serial 退化成 now（同一秒内两次写入算出同一个值，BIND 判定分区未变、
/// 继续服务旧内容）。这是"面板加了记录却查不到"最底层的成因。
fn soa_serial_from_line(line: &str) -> Option<u64> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let soa = toks.iter().position(|t| t.eq_ignore_ascii_case("SOA"))?;
    // SOA 之后：mname rname serial …
    let t = toks.get(soa + 3)?;
    if let Ok(v) = t.trim_matches(['(', ')']).parse::<u64>() {
        return Some(v);
    }
    // 括号形态：剥掉括号后再看紧随其后的少数 token。**只看 3 个**，
    // 免得越过 serial 误取 refresh/retry 之类的数字。
    toks.iter()
        .skip(soa + 4)
        .take(3)
        .find_map(|x| x.trim_matches(['(', ')']).parse::<u64>().ok())
}

/// 从完整 zone 文本里取 SOA serial。
///
/// **必须整段扫描，不能逐行找**：我们自己生成的 SOA 是括号多行形态，
/// `mname`/`rname`/`serial` 被换行隔开，逐行解析永远取不到 serial
/// （见 [`soa_serial_from_line`] 的说明）。做法与下面的 rootzone_current_serial 一致：
/// 定位 SOA token，跳过 mname/rname，取其后第一个纯数字。
fn serial_from_zone_text(text: &str) -> Option<u64> {
    let toks: Vec<&str> = text.split_whitespace().collect();
    let soa = toks.iter().position(|t| t.eq_ignore_ascii_case("SOA"))?;
    let t = toks.get(soa + 3)?;
    if let Ok(v) = t.trim_matches(['(', ')']).parse::<u64>() {
        return Some(v);
    }
    toks.iter()
        .skip(soa + 4)
        .take(3)
        .find_map(|x| x.trim_matches(['(', ')']).parse::<u64>().ok())
}

fn rootzone_current_serial(dst: &Path) -> Option<u64> {
    if !dst.exists() { return None; }
    let content = std::fs::read_to_string(dst).ok()?;
    // SOA record serial: the first pure-digit token after the rname field.
    // Handles both:
    //   . 86400 IN SOA mname. rname. ( SERIAL ... )
    //   . IN SOA mname rname SERIAL ...
    let mut in_soa = false;
    let mut past_rname = false;
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with(";") { continue; }
        if t.starts_with("$") || t.starts_with("@") { continue; }
        if t.contains(" IN SOA ") || t.contains("\tIN SOA ") {
            in_soa = true;
            // Check for serial on same line (no paren)
            let parts: Vec<&str> = t.split_whitespace().collect();
            for (i, p) in parts.iter().enumerate() {
                if *p == "SOA" && i + 3 <= parts.len() {
                    let candidate = parts.get(i + 3).map(|s| s.trim_matches(|c: char| !c.is_ascii_digit())).unwrap_or("");
                    if let Ok(n) = candidate.parse::<u64>() {
                        return Some(n);
                    }
                }
            }
            continue;
        }
        if in_soa && !past_rname {
            let parts: Vec<&str> = t.split_whitespace().collect();
            for p in &parts {
                let s = p.trim_matches(|c: char| !c.is_ascii_digit() && c != ';');
                if s.chars().all(|c| c.is_ascii_digit()) && s.len() >= 8 {
                    if let Ok(n) = s.parse::<u64>() {
                        return Some(n);
                    }
                }
            }
        }
    }
    None
}

/// 维护循环：config.toml mtime 变化 → 重新 reconcile；rootzone 到期 → 刷新（需求 2）。
/// 额外：DNSSEC 密钥轮换（需求 3）；rootzone 支持 IXFR。
pub async fn maintenance_loop(live: Arc<crate::server::live_config::LiveConfig>, cfg_path: PathBuf) {
    let mut last_mtime: Option<std::time::SystemTime> = std::fs::metadata(&cfg_path).ok().and_then(|m| m.modified().ok());
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        if let Ok(m) = std::fs::metadata(&cfg_path) {
            let mt = m.modified().ok();
            if mt.is_some() && mt != last_mtime {
                last_mtime = mt;
                if let Ok(c) = Config::load(&cfg_path) {
                    let dc = effective(&c);
                    if dc.enabled {
                        let d2 = dc.clone();
                        let r = tokio::task::spawn_blocking(move || reconcile(&d2)).await;
                        log::info!("dns: config changed → reconcile {:?}", r.as_ref().map(|_| "ok"));
                    }
                }
            }
        }
        // DNSSEC 密钥轮换检查（需求 3）
        let cfg = effective(&live.snapshot());
        if cfg.enabled && cfg.dnssec.enabled && cfg.dnssec.rotation_enabled {
            let dc = cfg.clone();
            let rotate = tokio::task::spawn_blocking(move || dnssec_check_and_rotate(&dc, &dc)).await;
            match rotate {
                Ok(Ok(ds_info)) => {
                    for ds in &ds_info {
                        log::info!("dnssec: DS rollover needed zone={} tag={}", ds.zone, ds.tag);
                    }
                }
                Ok(Err(e)) => log::warn!("dnssec: rotation check failed: {e:#}"),
                Err(e) => log::warn!("dnssec: rotation join: {e}"),
            }
        }
        // rootzone 到期刷新
        let cfg = effective(&live.snapshot());
        // rootzone.enabled 是需求 2 的开关（默认 false）：root 模式下也允许
        // 管理员只托管一个静态 root.zone 而不自动去 AXFR/下载。
        // 旧代码从不读这个字段，等于开关失效。
        if cfg.enabled && cfg.modes.root && cfg.rootzone.enabled {
            let due = match meta_get("root_last_ok") {
                Ok(Some(t)) => t
                    .parse::<u64>()
                    .map(|t| chrono_now() > t + cfg.rootzone.refresh_hours * 3600)
                    .unwrap_or(true),
                _ => true,
            };
            if due {
                let c2 = cfg.clone();
                let use_axfr = !cfg.rootzone.axfr_servers.is_empty();
                let result = if use_axfr {
                    tokio::task::spawn_blocking(move || rootzone_ixfr(&c2)).await
                        .map_err(|e| anyhow::anyhow!("{e}"))
                        .and_then(|r| r.map_err(|e| anyhow::anyhow!("{e}")))
                        .or_else(|_| {
                            let c3 = cfg.clone();
                            rootzone_refresh(&c3)
                        })
                } else {
                    tokio::task::spawn_blocking(move || rootzone_refresh(&c2)).await
                        .map_err(|e| anyhow::anyhow!("{e}"))
                        .and_then(|r| r.map_err(|e| anyhow::anyhow!("{e}")))
                };
                match result {
                    Ok(p) => log::info!("dns: rootzone refreshed → {p}"),
                    Err(e) => log::warn!("dns: rootzone refresh failed: {e:#}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod acl_primary_tests {
    use super::*;

    #[test]
    fn valid_acl_item_accepts_safe() {
        assert!(valid_acl_item("any"));
        assert!(valid_acl_item("none"));
        assert!(valid_acl_item("127.0.0.1"));
        assert!(valid_acl_item("10.0.0.0/8"));
        assert!(valid_acl_item("::1"));
        assert!(valid_acl_item("2001:db8::/32"));
    }

    #[test]
    fn valid_acl_item_rejects_injection() {
        assert!(!valid_acl_item("any; }; zone \"x\" { type primary; file \"x\";"));
        assert!(!valid_acl_item("10.0.0.1; key evil"));
        assert!(!valid_acl_item(""));
        assert!(!valid_acl_item("not_a_keyword"));
    }

    #[test]
    fn valid_primary_rejects_metachar() {
        assert!(valid_primary("192.0.2.1"));
        assert!(valid_primary("ns1.example.com"));
        assert!(valid_primary("192.0.2.1:53"));
        assert!(!valid_primary("1.2.3.4; };"));
        assert!(!valid_primary("host\"evil"));
    }
}
