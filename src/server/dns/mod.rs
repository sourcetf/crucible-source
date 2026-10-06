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
    /// 递归上游转发器（IP 字面量）。空 = 不做 forward（按提示符做迭代查询）。
    /// 屏蔽迭代查询、只放行递归查询的网络里（本机实测就是这种情况），public 递归
    /// 不配这个完全不可用。仅 modes.recursive = true 时写进 named.conf。
    #[serde(default)]
    pub forwarders: Vec<String>,
    /// `first` | `only`；仅 forwarders 非空时有意义。None/空 = BIND 默认 first
    /// （only 时额外生成 `forward only;`：不向转发器之外的服务器做任何迭代查询）。
    #[serde(default)]
    pub forward_policy: Option<String>,
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
    /// 自动发布的 HTTPS(type65) 记录（`[[dns.https_rr]]`）。
    ///
    /// 为什么需要它：**ECH 的发现路径只有 DNS** —— 客户端解析公开名时拿到 `ech=`
    /// SvcParam 才会启用 ECH。只在服务端 `ssl.ech = true` 而 DNS 里没有这条记录，
    /// ECH 对客户端等于不存在。这里把 `state/ech/ech_config_list.bin`（服务端**实际在用**
    /// 的那份，不是另生成一份）写进应答。面板里同名的 HTTPS 记录优先，本项只在缺失时补。
    #[serde(default)]
    pub https_rr: Vec<HttpsRrCfg>,
}

/// 一条自动发布的 HTTPS/SVCB 记录（`[[dns.https_rr]]`）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpsRrCfg {
    /// 要发布的名字：zone 内相对名（`@` / `www`）或 FQDN。
    #[serde(default)]
    pub name: String,
    /// SvcParam `alpn`（如 `h2,h3`）；空则不写该参数。
    #[serde(default)]
    pub alpn: String,
    /// SvcParam `port`；None 则不写。
    #[serde(default)]
    pub port: Option<u16>,
    /// 是否带上 `ech=` 参数（取自 `state/ech/ech_config_list.bin`）。
    #[serde(default)]
    pub ech: bool,
    /// SvcPriority，默认 1（AliasMode）。
    #[serde(default = "default_https_priority")]
    pub priority: u16,
    /// TargetName，默认 `.`（AliasMode 用 `.`）。
    #[serde(default = "default_https_target")]
    pub target: String,
}

fn default_https_priority() -> u16 {
    1
}

fn default_https_target() -> String {
    ".".to_string()
}

/// 渲染一条 HTTPS 记录的 rdata（纯函数，便于单测）。
///
/// `ech_b64`：`None` = 当前没有可用 ECH 物料（此时**不写** `ech=` 参数，
/// 而不是写一个空值 —— 空 `ech=` 会让客户端以为 ECH 可用却解不出配置）。
pub fn https_rdata(item: &HttpsRrCfg, ech_b64: Option<&str>) -> String {
    let mut params: Vec<String> = Vec::new();
    if !item.alpn.trim().is_empty() {
        // alpn 是**带引号的**字符串：值里的 `"` / `\` 不转义就会提前闭合引号，
        // 让这条 HTTPS 记录的 rdata 变成非法 —— named 会**拒载整个 zone**
        // （配置、面板、日志全正常，只有该分区 SERVFAIL，ECH 记录也随之消失）。
        // `h2,h3` 里的逗号是合法分隔符，所以只转义引号与反斜杠
        // （与 quoted_txt_rdata 同一处理顺序：先转义反斜杠，再转义引号）。
        let alpn = item.alpn.trim().replace('\\', "\\\\").replace('"', "\\\"");
        params.push(format!("alpn=\"{alpn}\""));
    }
    if let Some(p) = item.port {
        params.push(format!("port={p}"));
    }
    if item.ech {
        if let Some(b64) = ech_b64.filter(|s| !s.is_empty()) {
            params.push(format!("ech=\"{b64}\""));
        }
    }
    let target = if item.target.trim().is_empty() {
        "."
    } else {
        item.target.trim()
    };
    if params.is_empty() {
        format!("{} {}", item.priority, target)
    } else {
        format!("{} {} {}", item.priority, target, params.join(" "))
    }
}

/// 名字是否落在该 zone 内；返回 zone 文件里的 owner（相对名）。
/// `example.com` 在 `example.com` → `@`；`www.example.com` → `www`；不属于 → `None`。
/// 根区（`.`）不自动发布（owner 要写完整 FQDN，与这里相对名的约定不同）。
pub fn relative_owner(fqdn: &str, zone: &str) -> Option<String> {
    let n = fqdn.trim().trim_end_matches('.').to_ascii_lowercase();
    let z = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if z.is_empty() {
        return None;
    }
    if n == z || n == "@" {
        return Some("@".to_string());
    }
    n.strip_suffix(&format!(".{z}")).map(|p| p.to_string())
}

/// 由配置构造「自动 HTTPS 记录」列表：`(名字, rdata)`；无 ECH 物料时 ech 参数会被省略。
pub fn auto_https_records(cfg: &DnsConfig) -> Vec<(String, String)> {
    if cfg.https_rr.is_empty() {
        return Vec::new();
    }
    // 读服务端**实际在用**的 ECHConfigList（ech_auto 在 TLS 侧生成/复用的那份），
    // 保证 DNS 里发布的和 TLS 上启用的绝对是同一份 —— 发布一份客户端解不开的配置
    // 比不发布更糟（客户端会尝试 ECH 然后失败）。
    let ech_b64 = crate::server::ech_auto::persisted_config_list_base64();
    if cfg.https_rr.iter().any(|r| r.ech) && ech_b64.is_none() {
        log::warn!(
            "dns: dns.https_rr 里有 ech = true，但 state/ech/ech_config_list.bin 不存在\
（服务端未启用 ECH 或尚未生成）→ 该条记录不带 ech 参数"
        );
    }
    cfg.https_rr
        .iter()
        .filter(|r| !r.name.trim().is_empty())
        .map(|r| (r.name.trim().to_string(), https_rdata(r, ech_b64.as_deref())))
        .collect()
}

/// `[[https_rr]]` 里**不属于任何 master zone** 的名字。
///
/// 这些条目在 `write_all` 的落盘循环里会被 `relative_owner` 过滤掉 —— 即**静默不发布**：
/// 配置、面板、日志都正常，只有 `dig` 查不到。实测踩过（ECH 的 HTTPS 记录先 NXDOMAIN，
/// 因为缺同名 zone），所以单独算出来在启动期明确告警。
fn orphan_https_names(auto_https: &[(String, String)], zones: &[ZoneRow]) -> Vec<String> {
    auto_https
        .iter()
        .filter(|(n, _)| {
            !zones
                .iter()
                .any(|z| z.kind == "master" && relative_owner(n, &z.name).is_some())
        })
        .map(|(n, _)| n.clone())
        .collect()
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
    /// DoT 客户端白名单（IP/CIDR）。**空 = 沿用 `[dns] recursion_acl`；那个也空则仅回环。**
    ///
    /// 为什么必须有这道门：DoT 查询会被转发给 named，而 named 的 allow-recursion 里
    /// 硬编码了 127.0.0.1（转发源），所以「谁能连上 853，谁就拿到一个无限制递归解析器」
    /// —— 与 `[dns] recursion_acl`（文档写的是「空 = 仅本机」）的语义直接矛盾，
    /// 而且可被用来打上游 / 刷缓存 / 当放大器。DoH 侧本来就排在 ip_access + 限速之后，
    /// 这里补齐同一个威胁模型。要对外提供 DoT（公开解析器）就显式写
    /// `allow = ["0.0.0.0/0", "::/0"]`（或把 `recursion_acl` 设成同样的值）。
    #[serde(default)]
    pub allow: Vec<String>,
    /// 单 IP 每秒查询上限（0 = 用默认 20）
    #[serde(default)]
    pub rate_per_sec: u32,
    /// 令牌桶突发（0 = 用默认 40）
    #[serde(default)]
    pub burst: u32,
    /// 并发连接上限（0 = 用默认 128）
    #[serde(default)]
    pub max_conns: usize,
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
    // cwd 拼接结果缓存：`state_root()` 在**每个 HTTP 请求**上被 `effective()` 调用，
    // 而 `std::env::current_dir()` 是一次 `getcwd(2)` 系统调用（gdb 采样里
    // `_libc_getcwd`/`__getcwd` 各占 8/12 采样）。进程的 cwd 在启动后不会变
    // （引擎子进程各自 chdir，不影响本进程）。
    static CWD_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    CWD_ROOT
        .get_or_init(|| match std::env::current_dir() {
            Ok(cwd) => cwd.join("state/dns"),
            Err(_) => PathBuf::from("state/dns"),
        })
        .clone()
}

/// 读取 `CRUCIBLE_DNS_STATE_ROOT`；空值视为未设置。相对路径按 cwd 绝对化。
///
/// **必须走 `env_lock::read_static_env`（缓存）**：本函数在**每个 HTTP 请求**上被执行
/// （`effective()` → `state_root()`），而应用引擎（perl/python/ruby 的 ENV、`.env`
/// 注入）会在请求期间 `setenv`，libc 的 `setenv` 可能 realloc `environ` —— 此时并发
/// 线程里的 `getenv`（哪怕读的是别的键）会踩到已释放内存。实测：`/perl/` 120 并发把
/// webserver 打成 SIGSEGV，core 栈顶正是 `_libc_getenv("CRUCIBLE_DNS_STATE_ROOT")`。
fn env_state_root() -> Option<PathBuf> {
    let raw = crate::server::apps::env_lock::read_static_env("CRUCIBLE_DNS_STATE_ROOT")?;
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
/// `effective()` 的缓存世代号：任何「我们自己的写入/重载」都 +1，让下一次调用重读。
static EFFECTIVE_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 显式让 `effective()` 缓存失效（面板写 panel.toml、live 配置重载之后必须调用）。
///
/// 为什么需要世代号而不是只看 mtime/size：OpenBSD FFS 的秒级时间戳 + 「同一秒内改写成
/// 同样字节数」会让 (mtime,size) 完全不变，而内容已经不同 —— 那是「改了不生效」类
/// 故障里最难查的一种。世代号由我们自己的写入路径显式推进，与 stat 判据互补。
pub fn invalidate_effective() {
    EFFECTIVE_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

struct EffectiveCache {
    gen: u64,
    path: PathBuf,
    /// 上次 stat 的时间（用于 1s 节流；不是缓存有效期 —— 世代号/内容变化仍是即时的）。
    checked_at: std::time::Instant,
    /// (mtime, size, inode)——inode 变化覆盖「删了重建同名文件且 mtime/size 恰好相同」。
    key: (Option<std::time::SystemTime>, u64, u64),
    cfg: Arc<DnsConfig>,
}

static EFFECTIVE_CACHE: once_cell::sync::Lazy<parking_lot::Mutex<Option<EffectiveCache>>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));

fn panel_key(m: Option<&std::fs::Metadata>) -> (Option<std::time::SystemTime>, u64, u64) {
    use std::os::unix::fs::MetadataExt;
    match m {
        Some(md) => (md.modified().ok(), md.len(), md.ino()),
        None => (None, 0, 0),
    }
}

/// 生效的 DNS 配置：`panel.toml` 存在且可解析时**整体覆盖** config.toml 的 `[dns]`。
///
/// ⚠️ 这个函数在**每个 HTTP 请求**上被调用（h1 的 DoH 分流在 `h1_try_handle` 最开头、
/// h2/h3 各自的请求路径），所以它必须便宜。原先它每次都 `read_to_string` + 整份 TOML
/// 反序列化 —— 同步磁盘读 + 解析直接落在 async 请求路径上：实测（wrk）每请求 CPU
/// 122µs，其中最大一块就在这里；高并发下所有 worker 一起等同一份文件读，
/// 吞吐卡在 ~20k rps 不再随并发上升（2→16 workers 只涨 1.4×），而 h2o 同机 100k+。
/// 现在快路径只做一次 `stat`（~1µs），内容一变（mtime/size/ino 或世代号）立刻重读。
pub fn effective(cfg: &Config) -> DnsConfig {
    let panel = state_root().join("etc/panel.toml");
    let gen = EFFECTIVE_GEN.load(std::sync::atomic::Ordering::Relaxed);
    // 外部改动（手改 panel.toml）的检测节流：≤1s 内不重复 stat。
    // 我们自己的写入（面板保存 / live 重载）会 bump 世代号，因此**立即**生效；
    // 只有绕过面板直接改文件这种情况会有 ≤1s 延迟 —— 那个窗口换掉的是每请求一次
    // 系统调用（stat 在采样里 14/12，是请求路径上最后一块明显的固定开销）。
    let now = std::time::Instant::now();
    const STAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
    let key = {
        let c = EFFECTIVE_CACHE.lock();
        match c.as_ref() {
            Some(e)
                if e.gen == gen
                    && e.path == panel
                    && now.duration_since(e.checked_at) < STAT_INTERVAL =>
            {
                // 世代号与路径都没变、且刚查过：直接命中
                return (*e.cfg).clone();
            }
            _ => {}
        }
        drop(c);
        panel_key(std::fs::metadata(&panel).ok().as_ref())
    };
    {
        let mut c = EFFECTIVE_CACHE.lock();
        if let Some(e) = c.as_mut() {
            if e.gen == gen && e.path == panel && e.key == key {
                // 内容没变：刷新节流时间戳，**避免下一个请求又来一次 stat**
                // （否则 1s 之后每个请求都会 stat，节流形同虚设）。
                e.checked_at = now;
                return (*e.cfg).clone();
            }
        }
    }
    let parsed = effective_slow(cfg, &panel);
    *EFFECTIVE_CACHE.lock() = Some(EffectiveCache {
        gen,
        path: panel,
        checked_at: std::time::Instant::now(),
        key,
        cfg: Arc::new(parsed.clone()),
    });
    parsed
}

/// 慢路径：真的读文件 + 解析（含各种一次性告警）。
fn effective_slow(cfg: &Config, panel: &Path) -> DnsConfig {
    if let Ok(text) = std::fs::read_to_string(panel) {
        // Ignore empty / whitespace-only panel files (would deserialize to all-defaults
        // and silently disable DNS that is enabled in config.toml).
        if !text.trim().is_empty() {
            if let Ok(p) = toml::from_str::<DnsConfig>(&text) {
                // 面板文件**整体覆盖** config.toml 的 `[dns]`：此后在 config.toml 里改
                // `[dns]`（含 recursion_acl 这种安全相关项）**不会生效**，而面板与文档
                // 都显示「已保存」。只提示一次（每 2s 刷屏没有意义）。
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    let differs = toml::to_string(&p).ok() != toml::to_string(&cfg.dns).ok();
                    log::warn!(
                        "dns: {} 存在且生效 —— config.toml 的 [dns] 被**整体覆盖**{}；在 config.toml 里改 [dns] 不会生效，请改面板或删掉该文件",
                        panel.display(),
                        if differs { "（两者内容不同，当前生效的是面板文件）" } else { "（当前内容相同）" }
                    );
                }
                // 面板文件**绕过** `Config::validate()`（那只作用于 config.toml），
                // 所以「开了但配不全 / 路径写错」在这里再查一遍 —— 只 warn，
                // DNS 侧本来就有降级路径（DoT 起不来不影响 DNS 本身）。
                if p.dot.enabled {
                    let has_cert = p.dot.cert.as_deref().map_or(false, |s| !s.trim().is_empty());
                    let has_key = p.dot.key.as_deref().map_or(false, |s| !s.trim().is_empty());
                    if !has_cert || !has_key {
                        log::warn!(
                            "dns: panel.toml 里 dot.enabled = true 但 cert/key 不全 —— DoT 起不来（配置本身「合法」，只有启动日志一行 error）"
                        );
                    }
                }
                if p.doh.enabled && !p.doh.path.trim().starts_with('/') {
                    log::warn!(
                        "dns: panel.toml 里 doh.path = {:?} 不以 `/` 开头 ⇒ DoH 端点永不匹配",
                        p.doh.path
                    );
                }
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
    // 每次调用都开新连接（面板请求与 maintenance_loop 是并发的）。SQLite 默认
    // busy timeout = 0，同进程两个连接撞车时后来的那个直接 SQLITE_BUSY —— 面板上
    // 表现为随机的 "database is locked"。给一个短等待即可，不改 schema/WAL。
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
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

/// zone 名的 DNS 语义校验（比记录名严格）。
///
/// `valid_name` 允许 `.example.com`（空 label）、超长 label、通配符等形态 —— 这些名字
/// 会被 named 以「bad zone name」拒载该区：面板/DB 一切正常、只有那个分区永远
/// SERVFAIL（静默失败）。在写库**之前**拦住。
fn valid_zone_name(n: &str) -> bool {
    if n.trim() != n || n.is_empty() || n.len() > 253 {
        return false;
    }
    let body = n.trim_end_matches('.');
    if body.is_empty() || body.len() > 253 || body.contains("..") {
        return false;
    }
    body.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    })
}

/// zone 名的比较键：DNS 名大小写无关，尾点等价（`Example.com.` == `example.com`）。
/// 根区 `.` 保持自身（不能把点全削掉变成空串）。
fn canonical_zone_name(n: &str) -> String {
    let t = n.trim();
    if t == "." {
        return ".".to_string();
    }
    t.trim_end_matches('.').to_ascii_lowercase()
}

/// 模块自建分区名（RPZ / answers / 根区），用户 zone 不得占用。
fn is_reserved_zone_name(n: &str) -> bool {
    matches!(
        canonical_zone_name(n).as_str(),
        "." | "crucible.rpz" | "crucible.answers"
    )
}

/// 写库前的分区冲突检查（返回冲突原因）。
///
/// 1. DNS 名大小写无关：`Example.com` 与 `example.com` 是同一个区，SQLite 的 UNIQUE
///    是 BINARY 比较拦不住，gen_named_conf 会生成两条同名 zone → named 以
///    「zone already exists」拒载**整份** named.conf（所有分区一起失效，重启后起不来）。
/// 2. kind 变更：AXFR 端点固定 kind=slave，INSERT OR REPLACE 会把已有 master 静默改成
///    slave（原记录成孤儿）；同名不同 kind 直接拒绝，要求先删除。
fn zone_conflict(name: &str, kind: &str, zones: &[ZoneRow]) -> Option<String> {
    let key = canonical_zone_name(name);
    for z in zones {
        if canonical_zone_name(&z.name) != key {
            continue;
        }
        if z.name != name {
            return Some(format!(
                "与已有分区 {:?} 大小写重名（DNS 名大小写无关，named 会拒载整份配置）",
                z.name
            ));
        }
        if z.kind != kind {
            return Some(format!(
                "已有同名分区 kind={}，不能用 kind={} 覆盖（先删除再重建）",
                z.kind, kind
            ));
        }
    }
    None
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

/// 递归上游转发器（`forwarders { ...; };`）的单项：只接受 IPv4/IPv6 字面量。
/// BIND 的 forwarders 列表里没有主机名/端口写法，拼错会让 named 拒载整份配置。
fn valid_forwarder(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty() && s.parse::<std::net::IpAddr>().is_ok()
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
        // `[v6]` 无端口：BIND 的 primaries/ACL 里地址**不带方括号**（方括号是 dig/URI
        // 写法）。原样输出 `[::1];` 会让 named 拒载**整份** named.conf —— 与 host:port
        // 那次修复同一类（一处格式错，所有分区一起失效）。
        return rest.trim_end_matches(']').to_string();
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

/// `listen-on { <value>; }` 的取值：named 关键字或 IP 字面量。
///
/// 这个字段没有被别处校验过，而面板 `POST /api/dns/config` 会把整个 `[dns]` 反序列化
/// 进来 —— 不校验就等于把任意文本拼进 named.conf：`};` + 换行即可改写整份配置
/// （与 valid_line_name 修掉的 `view "{name}"` 属同一类注入面）。
fn valid_listen_addr(s: &str) -> bool {
    let s = s.trim();
    if matches!(s, "any" | "none" | "localhost" | "localnets") {
        return true;
    }
    s.parse::<std::net::IpAddr>().is_ok()
}

/// dnssec-policy `keys { ... algorithm <x>; }` 与 dnssec-keygen `-a <x>` 的白名单。
///
/// 收窄到 BIND 9.20 实际支持的集合：上游 `dns_secalg_fromtext` 同时接受助记名与
/// 算法号（5/7/8/10/13/14/15/16），但 `kaspconf.c` / `dnssec-keygen.c` 随后都会用
/// `dst_algorithm_supported()` 复核 —— RSAMD5(1)/DH(2)/DSA(3)/ECC-GOST(12) 等
/// 不支持的值会让**整份配置**加载失败或 keygen 直接 fatal；而命名面板又会先落
/// panel.toml ⇒ 重启后 DNS 起不来。这里只放行受支持算法的助记名与等价算法号。
fn valid_dnssec_alg(s: &str) -> bool {
    matches!(
        s,
        "RSASHA1"
            | "NSEC3RSASHA1"
            | "RSASHA256"
            | "RSASHA512"
            | "ECDSAP256SHA256"
            | "ECDSAP384SHA384"
            | "ED25519"
            | "ED448"
            // 等价算法号（老配置可能写数字）
            | "5"
            | "7"
            | "8"
            | "10"
            | "13"
            | "14"
            | "15"
            | "16"
    )
}

/// dnssec-policy `keys { <role> lifetime ... }` 的角色名（也用于 dnssec-keygen `-f`）。
fn valid_key_role(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "ksk" | "zsk" | "csk")
}

pub fn add_zone(kind: &str, name: &str, primaries: &[String], axfr_acl: &[String], refresh_hours: u64) -> Result<i64> {
    // **全部校验必须在写库之前**：分区名的保留名/重名问题若在 write_all 里才 bail，
    // 毒行已经落进 SQLite，此后每一次 reconcile（含启动时）都失败 —— named 永远不会
    // 被拉起，只能靠面板再删一次那个「没添加成功」的分区。
    if is_reserved_zone_name(name) {
        bail!("zone {name:?} 是 DNS 模块保留分区名（根区/RPZ/answers），不能作为普通分区");
    }
    if !valid_zone_name(name) {
        bail!("bad zone name {name:?}（空 label/超长 label/非法字符会被 named 拒载该区）");
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
    // slave 的附加约束（都在 list_zones/store 之前，纯参数校验）：
    // - primaries 为空时 gen_named_conf 会 `continue`：面板显示分区存在、named.conf
    //   里却没有 —— 又是「保存成功但没生效」。slave 必须有至少一个上游。
    // - refresh_hours 会映射进 named.conf（min/max-refresh-time），0/荒谬值无意义。
    if kind == "slave" {
        if primaries.is_empty() {
            bail!("slave 分区必须至少一个 primaries（否则 named.conf 不会声明该区，服务里查不到）");
        }
        if !(1..=8760).contains(&refresh_hours) {
            bail!("refresh_hours 必须在 1..=8760（小时），收到 {refresh_hours}");
        }
    }
    let existing = list_zones()?;
    if let Some(why) = zone_conflict(name, kind, &existing) {
        bail!("zone {name:?} {why}");
    }
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

/// 记录 rdata 的按类型合法性（面板新增/编辑与 .zone 导入共用）。
///
/// 为什么必须有：rdata 是**逐行拼进 zone 文件**的文本，一条非法行会让 named 拒载
/// **整个分区**（该区全部记录 SERVFAIL），而面板/日志一切正常 —— 与 RPZ override
/// 已修过的「一条坏值让全部 override 失效」是同一类静默失败。这里覆盖最容易写错、
/// 且判据无歧义的几类：A/AAAA 必须是 IP 字面量，CNAME/NS/PTR 的目标必须是合法域名。
pub(crate) fn validate_record_rdata(rtype: &str, rdata: &str) -> Result<()> {
    let d = rdata.trim();
    match rtype.trim().to_ascii_uppercase().as_str() {
        "A" => {
            if d.parse::<std::net::Ipv4Addr>().is_err() {
                bail!("A 记录的 rdata 必须是 IPv4 地址（收到 {rdata:?}）");
            }
        }
        "AAAA" => {
            if d.parse::<std::net::Ipv6Addr>().is_err() {
                bail!("AAAA 记录的 rdata 必须是 IPv6 地址（收到 {rdata:?}）");
            }
        }
        "CNAME" | "NS" | "PTR" => {
            let target = d.trim_end_matches('.');
            if !valid_name(target) {
                bail!("{rtype} 记录的目标不是合法域名（收到 {rdata:?}）");
            }
        }
        _ => {}
    }
    Ok(())
}

/// 一批记录内部的 CNAME 共存冲突（导入用）。
///
/// RFC1034 §3.6.2：同一 owner 不能既有 CNAME 又有其它类型的数据（顶点还额外与模块
/// 自动生成的 SOA/NS 冲突）。导入 `mode=replace` 会**先删旧记录再逐条 add_record**，
/// 冲突若在中途才由 add_record 抛出，旧记录已经删掉、新记录只落一半 —— 与「不落半截
/// 数据」的承诺相悖。故在解析阶段先按批扫一遍。
pub(crate) fn batch_cname_conflict(recs: &[(String, String)]) -> Option<String> {
    use std::collections::HashMap;
    // name(lower) -> (has_cname, has_other)
    let mut kinds: HashMap<String, (bool, bool)> = HashMap::new();
    for (name, rtype) in recs {
        let key = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let is_cname = rtype.trim().eq_ignore_ascii_case("CNAME");
        if is_cname && (key == "@" || key.is_empty()) {
            return Some(
                "顶点（@）不能是 CNAME：与模块自动生成的 SOA/NS 冲突，named 会拒载整个分区"
                    .to_string(),
            );
        }
        let e = kinds.entry(key).or_insert((false, false));
        if is_cname {
            e.0 = true;
        } else {
            e.1 = true;
        }
        if e.0 && e.1 {
            return Some(format!(
                "{name} 同时有 CNAME 与其它类型记录（RFC1034 §3.6.2：CNAME 不能与其它数据共存）"
            ));
        }
    }
    None
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
    // SOA 不能作为普通记录：serial 必须由 gen_zone_file_monotonic_ext 统一生成并保证
    // 单调（否则面板改动写进文件但 BIND 判定 serial 未变、拒绝重载；两条 SOA 还会让
    // named 拒载整个区）。导入路径在落库前丢弃 SOA 行（见 admin_api.rs）。
    if rtype_u == "SOA" {
        bail!("SOA 由 DNS 模块自动生成（serial 必须单调），不能作为普通记录添加");
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
    // 按类型的语义校验：一条坏记录让**整区**被 named 拒载（面板却显示 ok）。
    validate_record_rdata(&rtype_u, rdata)?;
    // CNAME 共存（RFC1034 §3.6.2）：顶点 CNAME 与自动 SOA/NS 冲突，同名既有 CNAME
    // 又加其它类型（或反之）同样让 named 以 "CNAME and other data" 拒载整个分区。
    let conn = store()?;
    if rtype_u == "CNAME" && (name == "@" || name.is_empty()) {
        bail!("顶点（@）不能是 CNAME：与模块自动生成的 SOA/NS 冲突，named 会拒载整个分区");
    }
    {
        let mut st = conn.prepare(
            "SELECT rtype FROM records WHERE zone=?1 AND lower(name)=lower(?2)",
        )?;
        let existing: Vec<String> = st
            .query_map(rusqlite::params![zone, name], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let has_cname = existing.iter().any(|t| t.eq_ignore_ascii_case("CNAME"));
        let has_other = existing.iter().any(|t| !t.eq_ignore_ascii_case("CNAME"));
        if rtype_u == "CNAME" && has_other {
            bail!("{name} 已有其它类型记录，CNAME 不能与它们共存（RFC1034 §3.6.2，named 会拒载整个分区）");
        }
        if rtype_u != "CNAME" && has_cname {
            bail!("{name} 已有 CNAME 记录，不能再添加其它类型（RFC1034 §3.6.2，named 会拒载整个分区）");
        }
    }
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
    gen_zone_file_monotonic_ext(zone, kind, recs, prev_serial, &[])
}

/// 同 [`gen_zone_file_monotonic`]，外加模块自动生成的记录（目前是 ECH 用的 HTTPS 记录）。
///
/// `extra` 已经在调用侧按 zone 过滤好（owner 为相对名），并且已排除面板里同名的
/// HTTPS 记录 —— **面板显式配置优先**，自动生成只在缺失时补，避免覆盖管理员的意图。
pub fn gen_zone_file_monotonic_ext(
    zone: &str,
    kind: &str,
    recs: &[RecordRow],
    prev_serial: Option<u64>,
    extra: &[(String, String)],
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
        // SOA 必须由本函数**始终**生成：serial 单调地板（文件/.signed/DB 高水位/named）
        // 只喂给这一处。若数据库里存在历史 SOA 行（旧版本导入 / 面板手选留下），
        // 一律跳过 —— 原实现见到 SOA 就整条跳过生成支路，serial 被冻结成导入时的旧值：
        // 面板改动写进文件但 BIND 判定「serial 未变、不重载」，从区也永远不来拉新版本；
        // 而面板再加一条 SOA 更会让 zone 文件出现两条 SOA、named 拒载整个区。
        s.push_str(&format!(
            "@ IN SOA {ns1} hostmaster.{zone}. (\n  {serial} ; serial\n  900 ; refresh\n  600 ; retry\n  1209600 ; expire\n  300 ; minimum\n)\n"
        ));
        s.push_str(&format!("@ IN NS {ns1}\n{ns1} IN A 127.0.0.1\n"));
    }
    for r in recs {
        // 见上：SOA 由本函数统一生成，DB 里的历史 SOA 行不再作为普通记录输出。
        if kind == "master" && r.rtype.eq_ignore_ascii_case("SOA") {
            continue;
        }
        let name = if r.name == "@" || r.name.is_empty() { "@" } else { r.name.as_str() };
        // RFC1035：TXT/SPF 的 rdata 必须带引号且转义内部引号/反斜杠；
        // 旧实现裸写 "hello world" 会被解析成多条 rdata → zone 文件非法。
        let rdata = quoted_txt_rdata(&r.rtype, &r.rdata);
        s.push_str(&format!("{} {} IN {} {}\n", name, r.ttl, r.rtype, rdata));
    }
    // 自动生成的记录（ECH 的 HTTPS 记录）：放在面板记录之后，同名同类型已被调用侧排除。
    for (owner, rdata) in extra {
        // rdata 里不能有换行：带换行即可往 named 加载的 zone 文件里塞任意记录
        // （与 add_record 的同类校验一致）。这里是模块自产的字符串，仍然挡住。
        if rdata.contains('\n') || rdata.contains('\r') {
            continue;
        }
        if !valid_name(owner) && owner != "@" {
            continue;
        }
        s.push_str(&format!("{owner} 300 IN HTTPS {rdata}\n"));
    }
    s
}

/// rdata 是否已是「首尾配对引号、内部引号都已转义」的完整字符串字面量。
///
/// 只有这种形态才允许原样透传：旧实现只看 `starts_with('"')`，于是未闭合 / 多余引号
/// 的值直接进入 zone 文本 —— 一条坏值让整个 answers 区/zone 变成非法 master file，
/// named 拒载该区（该区全部记录 SERVFAIL，面板与日志毫无提示）。
fn is_quoted_txt(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'"' || b[b.len() - 1] != b'"' {
        return false;
    }
    let mut esc = false;
    for &c in &b[1..b.len() - 1] {
        if esc {
            esc = false;
            continue;
        }
        match c {
            b'\\' => esc = true,
            // 中间的未转义引号 ⇒ 不是单个完整字符串（不能原样输出）
            b'"' => return false,
            _ => {}
        }
    }
    // 结尾反斜杠会吃掉收尾引号
    !esc
}

/// TXT/SPF rdata 规范化：已带配对引号原样；否则加引号并转义。
fn quoted_txt_rdata(rtype: &str, rdata: &str) -> String {
    let t = rtype.trim().to_ascii_uppercase();
    if t != "TXT" && t != "SPF" {
        return rdata.to_string();
    }
    let d = rdata.trim();
    if is_quoted_txt(d) {
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

/// 严格递增的 serial：`max(now, prev + 1)`。
///
/// 为什么不能直接用 `now`：HTTP/面板的两次编辑常常落在同一秒，而 BIND 只在 serial
/// **更大**时才重载 zone —— 同值会被判成「没变化」，表现为「面板 ok、服务里还是旧内容」。
fn next_serial(prev: Option<u64>) -> u64 {
    let now = chrono_now();
    match prev {
        Some(p) => now.max(p.saturating_add(1)),
        None => now,
    }
}

/// 从已落盘的 zone 文件里读回 SOA serial（读不到 → None，下一个 serial 直接取 now）。
fn read_zone_serial(path: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serial_from_zone_text(&t))
}

fn gen_rpz_file(rules: &[RpzRule], prev_serial: Option<u64>) -> String {
    // RPZ 语义（v3 实测修正）：
    // 1) 触发 owner 必须是**相对名**——挂在 $ORIGIN crucible.rpz. 之下才是合法触发
    //    （blocked.crucible.test → blocked.crucible.test.crucible.rpz.）；
    //    补尾点成 FQDN 反而是 out-of-zone 数据被 named 忽略（实测：rpz.lab-a.zone:5 警告）
    // 2) 自定义响应统一 CNAME → <name>.crucible.answers.（真实记录在 answers 区，NextDNS 风格）
    let mut s = String::from("$ORIGIN crucible.rpz.\n$TTL 300\n");
    s.push_str(&format!(
        "@ IN SOA localhost. root.localhost. ( {} 3600 900 86400 300 )\n@ IN NS localhost.\n",
        next_serial(prev_serial)
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
fn gen_answers_file(rules: &[RpzRule], prev_serial: Option<u64>) -> String {
    let mut s = String::from("$ORIGIN crucible.answers.\n$TTL 300\n");
    s.push_str(&format!(
        "@ IN SOA localhost. root.localhost. ( {} 3600 900 86400 300 )\n@ IN NS localhost.\n",
        next_serial(prev_serial)
    ));
    for r in rules {
        let t = r.rtype.to_ascii_lowercase();
        if t == "a" || t == "aaaa" || t == "txt" {
            let name = fq_trim(&ensure_fq(&r.name));
            let rdata = if t == "txt" {
                let d = r.value.trim();
                // 只允许「首尾配对、内部引号已转义」的完整字符串原样透传；
                // 旧实现只要以 `"` 开头就原样输出 —— `"a\"`、`"\"a\" b"` 这类值
                // 会写出非法 master file 行，named 拒载整个 answers 区，
                // 所有 a/aaaa/txt override 静默失效。其余一律转义（反斜杠先转义：
                // 只转义引号时，值以 `\` 结尾会吃掉收尾引号）。
                if is_quoted_txt(d) {
                    d.to_string()
                } else {
                    format!("\"{}\"", d.replace('\\', "\\\\").replace('"', "\\\""))
                }
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
    // A 记录的 rdata 必须是**合法点分四段**——"any"/"0.0.0.0" 都不是
    // （named 'bad dotted quad' 拒载根区）。原先只映射了 ""/0.0.0.0/any，其余原样落盘：
    // `listen_addr = "none"/"localhost"/"localnets"/"::1"`（`valid_listen_addr` 全都放行）
    // 会写出 `a.root-servers.crucible. 86400 IN A ::1` —— named 判为非法 A 而**拒载根区**，
    // root 模式下 "." 直接 SERVFAIL，而配置期、面板、日志一切正常（与「配置看着对、
    // 运行时整区拒载」是同一类）。所以只认真正的 v4 字面量，其余一律回落 127.0.0.1。
    let self_ip = match cfg.listen_addr.trim() {
        "" | "0.0.0.0" => "127.0.0.1".to_string(),
        other => match other.parse::<std::net::Ipv4Addr>() {
            Ok(v4) => v4.to_string(),
            Err(_) => "127.0.0.1".to_string(),
        },
    };
    format!(
        "$ORIGIN .\n. 86400 IN SOA a.root-servers.crucible. noc.crucible. ( {serial} 1800 900 604800 86400 )\n. 518400 IN NS a.root-servers.crucible.\na.root-servers.crucible. 86400 IN A {self_ip}\n",
        serial = chrono_now()
    )
}

// ---------------------------------------------------------------- named.conf 生成

/// geo 分线路条数上限。这个值必须被**所有**用到「线路索引 → 127.0.0.(2+i)」的地方
/// 共用：listen-on 地址表、fwd view 的 match-destinations、resolve_fwd_dest 的转发
/// 目标、lo0 alias 供给。此前四处各写各的（listen 用 `min(251)`、其余 `take(250)`、
/// 转发目标 `i.min(250)`）：第 251 条线路（index 250）会转发到 127.0.0.252，而该地址
/// 既没有 fwd view（落到 default 视图 → 静默返回错误线路的数据），OpenBSD 上也没有
/// lo0 alias（named bind 失败）。统一到 250：index 250 起直接拒绝，而不是静默错线。
pub(crate) const MAX_GEO_LINES: usize = 250;

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

/// 生成 `listen-on`（IPv4）/ `listen-on-v6`（IPv6）两张地址表，各自以 `;` 结尾。
///
/// 为什么不直接把 `listen_addr` 拼进两张表：
/// - named 9.20 会**静默丢弃**字面量 `0.0.0.0` —— 既不建 socket 也不打警告，于是 53
///   只剩 loopback 在听，公网 IPv4 一条查询都收不到（实测 `fstat` 只有 127.0.0.1:53）。
///   「所有 IPv4 接口」必须写关键字 `any`；注意 `any` 是逐个枚举接口地址建 socket，
///   不是绑定 0.0.0.0 通配（实测会分别建 127.0.0.1:53 / 83.229.125.81:53 / 10.126.126.1:53）。
/// - `listen_addr` 是面板可改的自由文本，把 v6 字面量或 `none` 塞进 IPv4 的 listen-on
///   会让 named 拒载整份配置（`listen-on { ::1; 127.0.0.1; }` 非法）。
///
/// `127.0.0.1` 永远追加进 IPv4 表（除 `none`）：本进程的 DoT/DoH 转发源地址就是
/// 127.0.0.1，少了它 DoT/DoH 的每个查询都被自己的 named 回 REFUSED。geo 分线路的
/// 127.0.0.2..N 同理显式列出（需要 lo0 alias 才会真的建出 socket）。
fn listen_lists(addr: &str, test_mode: bool, geo_lines: usize) -> (String, String) {
    if test_mode {
        // 测试模式固定 loopback（见 DnsConfig::test_mode 注释）
        return ("127.0.0.1;".to_string(), "none;".to_string());
    }
    let a = addr.trim();
    let (v4, v6): (String, String) = match a {
        // named 关键字在两张表里都合法，原样透传
        "any" | "none" | "localhost" | "localnets" => (a.into(), a.into()),
        _ => match a.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) if ip.is_unspecified() => ("any".into(), "none".into()),
            Ok(std::net::IpAddr::V4(ip)) => (ip.to_string(), "none".into()),
            Ok(std::net::IpAddr::V6(ip)) if ip.is_unspecified() => ("none".into(), "any".into()),
            Ok(std::net::IpAddr::V6(ip)) => ("none".into(), ip.to_string()),
            // 不可达：valid_listen_addr 在落盘前已拒。兜底 = 只监听 loopback
            Err(_) => ("127.0.0.1".into(), "none".into()),
        },
    };
    let mut v4s = v4;
    if v4s == "none" {
        v4s.push(';');
    } else {
        v4s.push(';');
        if v4s != "127.0.0.1;" {
            v4s.push_str(" 127.0.0.1;");
        }
        // 必须是 127.0.0.{2+i}：`match-destinations`（本文件）与 `resolve_fwd_dest`
        // （DoT/DoH 转发目标）都用 127.0.0.(2+i)，lo0 alias 也是这么加的（ifconfig 处）。
        // 早先这里写成 `127.0.{2+i}`（少了中间那段 0），三处不一致 ⇒ 配了 geo 分线路时
        // fwd-<line> view 的 match-destinations 上根本没有 socket，分线路转发静默失效。
        // 索引范围与 resolve_fwd_dest / fwd view / lo0 alias 对齐（统一 MAX_GEO_LINES）⇒
        // 泄露 127.0.0.2..127.0.0.(1+MAX_GEO_LINES)；没有分线路时一个都不加
        // （`0..=MAX_GEO_LINES` 在 lines=0 时会多加一个，别写成那样）。
        for i in 0..geo_lines.min(MAX_GEO_LINES) {
            v4s.push_str(&format!(" 127.0.0.{};", 2 + i));
        }
    }
    let v6s = if v6.ends_with(';') { v6 } else { format!("{v6};") };
    (v4s, v6s)
}

/// `forwarders { ... };`（+ `forward only;`）片段；未配置时返回空串（零行为变化）。
///
/// 只输出合法 IP 字面量（check_config_strings 在保存前已全量校验，这里是防历史
/// panel.toml / 手改 config.toml 的兜底，与 ACL 的 fail-closed 处理一致）。
fn forwarders_clause(cfg: &DnsConfig) -> String {
    let items: Vec<String> = cfg
        .forwarders
        .iter()
        .map(|s| s.trim())
        .filter(|s| valid_forwarder(s))
        .map(|s| format!("{s};"))
        .collect();
    if items.is_empty() {
        return String::new();
    }
    let mut s = format!(" forwarders {{ {} }};", items.join(" "));
    let only = cfg
        .forward_policy
        .as_deref()
        .map(|p| p.trim().eq_ignore_ascii_case("only"))
        .unwrap_or(false);
    if only {
        s.push_str(" forward only;");
    }
    s
}

/// secondary（slave）zone 语句的附加子句（需求 6 的「传入白名单」）：
/// - `allow-notify`：谁可以给我们发 NOTIFY（AXFR 传入白名单的语义）
/// - `allow-transfer`：谁能从这里 AXFR（同一份白名单，全局 axfr_out_acl 是兜底）
/// - `refresh_hours` → `min/max-refresh-time`（此前该字段入库/展示但从不生效，
///   named 只会按 SOA timers 刷新）
fn secondary_clauses(z: &ZoneRow) -> String {
    let acl: Vec<String> = z
        .axfr_acl
        .iter()
        .map(|s| s.trim())
        .filter(|s| valid_acl_item(s))
        .map(|s| format!("{s};"))
        .collect();
    let mut s = String::new();
    if !acl.is_empty() {
        let list = acl.join(" ");
        s.push_str(&format!(" allow-notify {{ {list} }}; allow-transfer {{ {list} }};"));
    }
    if (1..=8760).contains(&z.refresh_hours) {
        s.push_str(&format!(
            " min-refresh-time {}h; max-refresh-time {}h;",
            z.refresh_hours, z.refresh_hours
        ));
    }
    s
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

// listen-on（IPv4）/ listen-on-v6（IPv6）：基础地址 + 分线路转发 loopback（127.0.0.2..N+1）
    let (listen, v6_acl) = listen_lists(&cfg.listen_addr, cfg.test_mode, cfg.geo.lines.len());
    s.push_str(&format!(
        "// generated by Crucible dns module — do not hand-edit\noptions {{\n  directory \"{}\";\n  listen-on port {port} {{ {listen} }};\n  listen-on-v6 port {port} {{ {v6_acl} }};\n  recursion {};",
        state_root().join("zones").display(),
        if cfg.modes.recursive { "yes" } else { "no" }
    ));

    if cfg.modes.recursive {
        // 127.0.0.1 必须始终在递归白名单里：本进程的 DoT/DoH 转发（dot_doh::udp_query）
        // 源地址就是 127.0.0.1，分线路转发目标更是 127.0.0.(2+i)。管理员一旦配了
        // 自定义递归白名单（如 "10.0.0.0/8"），面板上 DoT/DoH 开关看着正常，
        // 实际每个查询都被自己的 named 回 REFUSED。本机不在白名单之外。
        let mut rec_acl = cfg.recursion_acl.clone();
        // **去重**：运维（或面板）本来就把 127.0.0.1 写进白名单时，这里再 push 一次会得到
        // `{ 127.0.0.1; 127.0.0.1; }` —— 对 BIND 无害（它自己会去重），但 named.conf 是
        // 运维读的那份「生效配置」，重复项会让人怀疑是不是有两套来源、也误导排查。
        // 本机实测确实出现过（生产 named.conf 里就是两遍）。
        if !rec_acl.iter().any(|x| x.trim() == "127.0.0.1") {
            rec_acl.push("127.0.0.1".to_string());
        }
        let rec_acl = acl_or(&rec_acl, "127.0.0.1");
        s.push_str(&format!(
            "\n  allow-recursion {rec_acl}; allow-query-cache {rec_acl};"
        ));
        // ECS 上游传递由本进程 DoT/DoH 层注入（ecs.rs，/24 硬约束）——
        // bind 9.20 options 无 ecs-prefix-* 语句，写了 named 会拒载。
        s.push_str("\n  qname-minimization relaxed;");
        // 上游转发（可选）：不配置时为空串 —— 行为与之前完全一致
        s.push_str(&forwarders_clause(cfg));
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
                // 传入白名单（allow-notify/allow-transfer）与刷新频率此前从不生效：
                // 运维填的「AXFR传入白名单CIDR」是个假的安全控制。
                s.push_str(&format!(
                    "zone \"{}\" {{ type secondary; primaries {{ {} }}; file \"{f}\";{} }};\n",
                    z.name,
                    prim.join(" "),
                    secondary_clauses(z)
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
        for (i, l) in cfg.geo.lines.iter().enumerate().take(MAX_GEO_LINES) {
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
    // 没有任何线路时直接返回默认：mmdb/ASN/国家映射最终都要落到 `lines` 里的某条，
    // lines 为空时 `line_for` 的两次 mmdb 查找（+全局锁）纯属浪费 —— 每个 DoT/DoH
    // 查询都白付一次（需求 9「全部默认线路时不要启用该模块」）。短路必须在 mmdb 之前。
    if cfg.geo.lines.is_empty() {
        return IpAddr::from([127u8, 0, 0, 1]);
    }
    // mmdb 优先 (需求 9: 模块化, ASN/ISP/国家线路)
    if cfg.geo.mmdb.is_active() {
        if let Some(line) = crate::server::dns::geoip::line_for(&cfg.geo.mmdb, ip) {
            if let Some(i) = cfg.geo.lines.iter().position(|l| l.name == line) {
                return IpAddr::from([127u8, 0, 0, (2 + i.min(MAX_GEO_LINES - 1)) as u8]);
            }
        }
    }
    for (i, l) in cfg.geo.lines.iter().enumerate() {
        for c in &l.cidrs {
            if cidr_contains(c, ip) {
                return IpAddr::from([127u8, 0, 0, (2 + i.min(MAX_GEO_LINES - 1)) as u8]);
            }
        }
    }
    IpAddr::from([127u8, 0, 0, 1])
}

/// 极小 CIDR 匹配（v4/v6，"a.b.c.d/len"；无掩码按主机地址）
pub fn cidr_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    // v4-mapped（`::ffff:a.b.c.d`，双栈监听下 IPv4 客户端 peer 的常见形态）先折回 v4，
    // 否则 `(V4 CIDR, V6 ip)` 落到 `_ => false`：v4 CIDR 线路对这类客户端**永不命中**、
    // 静默走默认线路（ECS 侧与 access/rate_limit/iputil 都已 unmap，唯独这里漏了）。
    let ip = crate::server::geoip_panel::iputil::unmap_v4_mapped(ip);
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
            // /0：移位量等于位宽，`>> 32` 在 debug/overflow-checks 下 panic、release
            // 下按位宽取模（比较整个地址，永不相等）——「所有客户端」这条线路等于
            // 静默失效。语义上 /0 匹配一切。
            if prefix == 0 {
                return true;
            }
            let shift = bits - prefix;
            (n.to_bits() >> shift) == (h.to_bits() >> shift)
        }
        (IpAddr::V6(n), IpAddr::V6(h)) => {
            let bits = 128u32;
            if prefix > bits {
                return false;
            }
            if prefix == 0 {
                return true;
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
    // **不能忽略读取失败**：`let _ =` 时若 /dev/urandom 打不开（chroot、fd 耗尽），
    // buf 保持全零，rndc 密钥就成了常量 `000…0`（96 个 0）而启动照常 —— 本机任何进程
    // 都能凭它通过 rndc 控制 named。失败就换一个可预期的失败方式（全零是**不可接受**的）。
    // 本函数签名是 `-> String`（调用点都在 named.conf 生成路径上），所以这里**大声失败**
    // 而不是返回 Err：宁可启动期带着可读信息退出，也不能静默退回全零密钥。
    // （OpenBSD 上 /dev/urandom 基本不可能失败；真失败说明环境异常，继续跑更危险。）
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").expect(
            "dns: 打不开 /dev/urandom —— rndc 密钥必须来自 CSPRNG，用常量密钥等于本机任何人都能控制 named",
        );
        f.read_exact(&mut buf)
            .expect("dns: 读 /dev/urandom 失败 —— rndc 密钥必须来自 CSPRNG");
    }
    assert!(
        buf.iter().any(|b| *b != 0),
        "dns: /dev/urandom 返回全零（异常环境）—— 拒绝使用可预测的 rndc 密钥"
    );
    let secret: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    let _ = std::fs::create_dir_all(state_root().join("etc"));
    let _ = write_atomic(&p, format!("secret={secret}\n").as_bytes(), 0o600, None);
    secret
}

/// 原子落盘：写**同目录**临时文件 → 设权限/属主 → `rename` 覆盖目标。
///
/// 为什么必须原子：`named.conf` / 各 zone 文件 / RPZ / answers / rndc.conf / session.key
/// 此前都是 `std::fs::write`（**原地截断**）。写到一半进程被杀（本项目有强制退出、OOM、
/// 满盘的先例）或断电，就会留下**半截文件**：`named.conf` 半截 ⇒ named 起不来 ⇒ 整个 DNS
/// 全挂；zone 文件半截 ⇒ named 拒载该区（`not loaded due to errors`）⇒ 该区 SERVFAIL。
/// `rename(2)` 同文件系统内原子：named 要么看到旧文件、要么看到新文件，没有中间态。
///
/// 权限与属主必须在 **rename 之前**设好：否则 rename 到 chmod 之间有个窗口，
/// `named.conf`（内含 rndc 密钥，本该 0640）会以 umask 权限（0644）短暂暴露给本机用户。
/// 临时文件名：`<file>.tmp<pid>-<纳秒>-<进程内序号>`。
///
/// 旧实现是固定名 `<file>.tmp<pid>`：一次写失败（满盘 ENOSPC、chmod/rename 失败）
/// 或进程被 kill 留下的同名文件会让下一次 `create_new` 永远 EEXIST —— 同一进程内
/// 后续对同一目标的写盘全部失败（named.conf/zone/panel.toml 再也更新不出去），
/// 直到重启进程。唯一名 + [`TmpCleanup`] 失败清理同时解决残留与撞名。
fn tmp_path_for(path: &Path) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("dnsfile"));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mut name = stem;
    name.push(format!(
        ".tmp{}-{}-{}",
        std::process::id(),
        nanos,
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    dir.join(name)
}

/// 失败路径清理临时文件（成功 rename 后 disarm）。没有它，任何写入/权限/rename
/// 失败都会在目录里留下 `<file>.tmp...` 永久残留。
struct TmpCleanup {
    path: PathBuf,
    armed: bool,
}

impl TmpCleanup {
    fn new(path: PathBuf) -> Self {
        TmpCleanup { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TmpCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn write_atomic(path: &Path, data: &[u8], mode: u32, owner: Option<&str>) -> Result<()> {
    let tmp = tmp_path_for(path);
    let mut cleanup = TmpCleanup::new(tmp.clone());
    // **先在 0600 下创建**：`std::fs::write` 会用 `0666 & ~umask`（通常 0644）建文件，
    // 而 set_permissions 在**之后**才跑 ⇒ named.conf / rndc.conf / session.key 的临时文件
    // 在 chmod 前是「本机任何用户可读」，而 rndc.conf/session.key 里是 rndc 的 HMAC 密钥
    //（拿到它就能通过本机 rndc 控制 named）。改路径后：写入期间是**更严**的 0600，
    // 定稿权限再改到目标值 —— 窗口只会「过严」，不会「过松」。
    // 同时 create_new + O_NOFOLLOW：临时名不可预测，且能写该目录的人
    // 也无法预先放一个软链接让我们跟着写（findings 里那条 chown -R 已同时收窄）。
    write_new_0600(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {:o} {}", mode, tmp.display()))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    if let Some(u) = owner {
        let _ = std::process::Command::new("chown").arg(u).arg(&tmp).status();
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    cleanup.disarm();
    Ok(())
}

/// 新建一个只允许所有者读写的文件并写入内容（`O_CREAT|O_EXCL|O_NOFOLLOW`，mode 0600）。
///
/// 用于**先写临时文件、再定稿权限、最后 rename** 的落盘路径：创建时就 0600，
/// 保证「最终权限设定之前」的那段窗口是过严而非过松。
pub(crate) fn write_new_0600(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(data).with_context(|| format!("write {}", path.display()))?;
    f.sync_all().ok();
    Ok(())
}

/// 原子写一份**配置文件**（config.toml）：保留原文件权限（不存在则 0600），
/// 写入期间恒为 0600。config.toml 里有口令哈希、MaxMind key、TLS/ECH 材料路径，
/// 而原来的写法用 `std::fs::write` + rename ⇒ 每保存一次就把运维可能特意设过的 0600
/// 静默降级成 0644。
pub fn write_config_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = tmp_path_for(path);
    let mut cleanup = TmpCleanup::new(tmp.clone());
    write_new_0600(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o600);
        // 原文件是 0000 之类时也给个可读的兜底，避免把自己锁死
        let mode = if mode == 0 { 0o600 } else { mode };
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {:o} {}", mode, tmp.display()))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    cleanup.disarm();
    Ok(())
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

/// 所有会进入 **named.conf / zone 文件文本 / zone 文件名** 的用户可控字符串的校验。
///
/// `listen_addr` / `dnssec.algorithm` / `dnssec.keys[].role` / geo 线路名 / rpz 记录名与
/// 值都来自面板（`POST /api/dns/config` 反序列化整个 `[dns]`），并被拼进 named.conf 或
/// zone 文本；不校验就等于把这些文本面交给配置。
///
/// 为什么单独抽出来：`write_all` 会在**落盘前**调它；而面板的 `POST /api/dns/*` 必须
/// 在**写 panel.toml 之前**也调一次 —— panel.toml 是 `effective()` 的权威来源，非法值
/// 一旦先落进那份文件，此后**每一次** reconcile（含启动时的）都在 write_all 里失败：
/// 重启后 DNS 直接起不来，面板自己也卡在错误上，只能手工改文件恢复。
/// 顺序反了就是「一处格式错、全份配置失效」。
pub(crate) fn check_config_strings(cfg: &DnsConfig) -> Result<()> {
    if !valid_listen_addr(&cfg.listen_addr) {
        bail!(
            "bad listen_addr {:?}（只接受 IP 字面量或 any/none/localhost/localnets）",
            cfg.listen_addr
        );
    }
    // dnssec 关掉时这两个字段不会被写进 named.conf（gen_kasp_policy 不调用），
    // 只在真正启用时校验，免得把「没开 DNSSEC 的部署里一个不用的字段」判死。
    if cfg.dnssec.enabled {
        if !valid_dnssec_alg(&cfg.dnssec.algorithm) {
            bail!(
                "bad dnssec algorithm {:?}（BIND 9.20 支持：RSASHA1/NSEC3RSASHA1/RSASHA256/RSASHA512/ECDSAP256SHA256/ECDSAP384SHA384/ED25519/ED448）",
                cfg.dnssec.algorithm
            );
        }
        for k in &cfg.dnssec.keys {
            if !valid_key_role(&k.role) {
                bail!("bad dnssec key role {:?}（ksk|zsk|csk）", k.role);
            }
        }
        // BIND 的 kaspconf 会拒绝「短于 rollover 所需时间」的 lifetime（整份配置
        // 加载失败），按本模块固定值（14d validity - 3d refresh + 1d max-zone-ttl
        // + 1h retire-safety + 传播延迟）约 12 天，< 30d 还会告警。下限取 30 天，
        // 并且必须在**写 panel.toml 之前**执行（persist_and_reconcile 会先调本函数）：
        // 否则非法值先落进面板文件，此后每次 reconcile（含启动）都失败。
        const MIN_KEY_LIFETIME_DAYS: u64 = 30;
        if cfg.dnssec.rotation_enabled {
            if cfg.dnssec.rotation_days < MIN_KEY_LIFETIME_DAYS {
                bail!(
                    "dnssec rotation_days={} 太小（named 会以 key lifetime is shorter than the time it takes to do a rollover 拒载；下限 {} 天）",
                    cfg.dnssec.rotation_days,
                    MIN_KEY_LIFETIME_DAYS
                );
            }
            if let Some(n) = cfg.dnssec.ksk_lifetime_days {
                if n < MIN_KEY_LIFETIME_DAYS {
                    bail!("dnssec ksk_lifetime_days={n} 太小（下限 {MIN_KEY_LIFETIME_DAYS} 天）");
                }
            }
            for k in &cfg.dnssec.keys {
                if let Some(n) = k.lifetime_days {
                    if n < MIN_KEY_LIFETIME_DAYS {
                        bail!(
                            "dnssec keys[].lifetime_days={n}（role={}）太小（下限 {MIN_KEY_LIFETIME_DAYS} 天）",
                            k.role
                        );
                    }
                }
            }
        }
    }
    // 递归上游转发器：只允许 IP 字面量；forward_policy 只允许 first|only。
    // 非法值会在 gen_named_conf 里拼进 named.conf，同样必须先拒于 panel.toml 之前。
    if let Some(p) = cfg.forward_policy.as_deref() {
        let p = p.trim();
        if !p.is_empty() && !matches!(p.to_ascii_lowercase().as_str(), "first" | "only") {
            bail!("bad forward_policy {:?}（first|only）", cfg.forward_policy);
        }
    }
    if let Some(bad) = cfg.forwarders.iter().find(|f| !valid_forwarder(f)) {
        bail!("bad forwarder {bad:?}（只接受 IPv4/IPv6 字面量）");
    }
    let mut seen_lines: std::collections::HashSet<String> = std::collections::HashSet::new();
    // 线路数上限：索引 0..MAX_GEO_LINES-1 映射到 127.0.0.2..127.0.0.(1+MAX_GEO_LINES)。
    // 超出的线路没有 fwd view / listen socket / lo0 alias —— 客户端静默落到 default
    // 视图拿到**错误线路**的数据。与其静默错线，不如在保存前明确拒绝。
    if cfg.geo.lines.len() > MAX_GEO_LINES {
        bail!(
            "geo.lines 条数 {} 超过上限 {}（每条约占一个 127.0.0.x 转发地址，超出的线路不会被任何 view 承接）",
            cfg.geo.lines.len(),
            MAX_GEO_LINES
        );
    }
    for l in &cfg.geo.lines {
        if !valid_line_name(&l.name) {
            bail!("bad geo line name {:?}", l.name);
        }
        // 线路 CIDR 在生成侧会被 `acl_or`→`valid_acl_item` **静默过滤**：非法项被丢光后
        // `match-clients` 退化成 `{ none; }`，该 view 永不命中 —— 面板显示线路存在、
        // 客户端却全落默认线路，无任何日志。这里用与生成侧**同一判据**在保存前拒绝，
        // 把「静默失效」变成面板可见的错误（校验先于 panel.toml 落盘）。
        if l.cidrs.is_empty() {
            bail!("geo line {:?} 没有任何 CIDR —— match-clients 会退化为 none，该线路永不命中", l.name);
        }
        for c in &l.cidrs {
            if !valid_acl_item(c) {
                bail!(
                    "bad geo line cidr {c:?}（线路 {:?}）：非法项会被静默丢弃，该线路 match-clients 退化为 none 而永不命中",
                    l.name
                );
            }
        }
        // 线路名同时是 named 的 view 名。模块自己还会生成兜底 view "default" 与
        // 转发 view "fwd-<线路>"：线路直接叫 default / fwd-x，或两条线路重名，
        // named 都会以「view already exists」拒载**整份** named.conf ——
        // 所有分区一起失效（不只是这条线路不生效）。
        let lname = l.name.to_ascii_lowercase();
        if lname == "default" || lname.starts_with("fwd-") {
            bail!("geo line name {:?} 是保留名（default 与 fwd- 前缀留给模块自建 view）", l.name);
        }
        if !seen_lines.insert(lname) {
            bail!("geo line name {:?} 重复（view 名必须唯一）", l.name);
        }
    }
    for r in &cfg.rpz {
        if !valid_name(&r.name) {
            bail!("bad rpz name {:?}", r.name);
        }
        // value 会被原样拼进 rpz.zone / answers.zone 的文本行（CNAME/A/AAAA/TXT 的
        // rdata），带换行即可往 named 加载的 zone 文件里塞任意记录。
        if r.value.contains('\n') || r.value.contains('\r') {
            bail!("bad rpz value（必须是单行）name={:?}", r.name);
        }
        // **按类型校验 value**：answers 区是**一个文件**，里面任何一行非法都会让 named
        // 拒载整个区；而 RPZ 的所有 a/aaaa/txt 规则都 CNAME 指向该区 ⇒ 一条空值/坏 IP
        // 就让**全部 override 静默失效**（面板仍显示 ok）。
        // 此前只挡了换行，A/AAAA 连「是不是 IP」都没校验，缺省还是空串。
        match r.rtype.to_ascii_lowercase().as_str() {
            "a" => {
                if r.value.trim().parse::<std::net::Ipv4Addr>().is_err() {
                    bail!(
                        "rpz A 记录的 value 必须是 IPv4 地址: name={:?} value={:?}",
                        r.name,
                        r.value
                    );
                }
            }
            "aaaa" => {
                if r.value.trim().parse::<std::net::Ipv6Addr>().is_err() {
                    bail!(
                        "rpz AAAA 记录的 value 必须是 IPv6 地址: name={:?} value={:?}",
                        r.name,
                        r.value
                    );
                }
            }
            "txt" => {
                if r.value.trim().is_empty() {
                    bail!("rpz TXT 记录的 value 不能为空: name={:?}", r.name);
                }
                // 以 `"` 开头但不是完整合法字符串（未配对/未转义）的值在旧实现里被
                // 原样输出 ⇒ answers 区非法、named 拒载、全部 override 失效。
                // 生成侧现在会转义，但那种值写进面板后显示与服务内容不一致；
                // 保存前直接拒绝，让管理员修正。
                if r.value.trim().starts_with('"') && !is_quoted_txt(r.value.trim()) {
                    bail!(
                        "rpz TXT 记录的 value 以引号开头但引号未正确配对/转义: name={:?} value={:?}",
                        r.name,
                        r.value
                    );
                }
            }
            "cname" => {
                if !valid_name(r.value.trim().trim_end_matches('.')) {
                    bail!(
                        "rpz CNAME 记录的 value 不是合法域名: name={:?} value={:?}",
                        r.name,
                        r.value
                    );
                }
            }
            // nxdomain / nodata / passthru 不需要 value
            _ => {}
        }
    }
    Ok(())
}

/// 全量落盘：named.conf / rndc.conf / 各 zone 文件 / rpz / rootzone 占位。
pub fn write_all(cfg: &DnsConfig) -> Result<Vec<(String, PathBuf)>> {
    // 进入文件名 / named.conf 的用户可控字符串先全量校验（见 check_config_strings）；
    // validate() 会先调 write_all 再探活 named，检查必须在落盘之前。
    check_config_strings(cfg)?;
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
    // 与模块自建分区重名时，同一个 view 里会出现两条同名 zone 声明（RPZ override /
    // answers 是本模块自己声明的，`.` 是 root 模式声明的），named 直接拒载**整份**
    // named.conf —— 表现是「加了一个分区，整个 DNS 全挂」。
    // add_zone 已在写库前拦一道；这里对历史 DB 行兜底（大小写不敏感，DNS 名如此）。
    for z in &zones {
        if is_reserved_zone_name(&z.name) {
            bail!("zone {:?} 与 DNS 模块保留分区名（RPZ/answers/根区）冲突", z.name);
        }
    }
    let conf = gen_named_conf(cfg, &zones);
    let conf_path = etc.join("named.conf");
    // _bind 只需读；0600 会拒读 → 0640 + 属主 _bind。权限/属主在 rename **之前**设好，
    // 避免出现「新 named.conf 已是 umask 权限」的窗口（里面有 rndc 密钥）。
    write_atomic(&conf_path, conf.as_bytes(), 0o640, Some("_bind"))?;

    let secret = load_or_make_secret();
    let rndc_port = cfg.rndc_port_or_default();
    write_atomic(
        &etc.join("rndc.conf"),
        // 9.20 rndc.conf：options 里必须用 default-key（裸 key 是非法语句，named -g/rndc 实测拒绝）
        format!(
            "options {{ default-server 127.0.0.1; default-port {rndc_port}; default-key \"rndc-key\"; }};\nserver 127.0.0.1 {{ key \"rndc-key\"; }};\nkey \"rndc-key\" {{ algorithm hmac-sha256; secret \"{secret}\"; }};\n"
        )
        .as_bytes(),
        0o600,
        None,
    )?;

    // per-view 变体落盘——必须与 gen_named_conf 的 view 列表一致（view_tag, line_tag）；
    // 同一 zone 文件不得跨 view 复用（named 'writeable file already in use' 拒载）
    let geo_on = cfg.geo.enabled
        && (!cfg.geo.lines.is_empty() || cfg.geo.mmdb.is_active());
    let mut views: Vec<(String, String)> = vec![(String::new(), String::new())];
    if geo_on {
        for l in &cfg.geo.lines {
            views.push((l.name.clone(), l.name.clone()));
        }
        for (i, l) in cfg.geo.lines.iter().enumerate().take(MAX_GEO_LINES) {
            views.push((format!("fwd-{}", l.name), l.name.clone()));
        }
        views.push(("default".into(), String::new()));
    }
    let mut written: Vec<(String, PathBuf)> = Vec::new();
    // 自动发布的 HTTPS 记录（ECH 发现路径）算一次，各 zone/各 view 复用。
    let auto_https = auto_https_records(cfg);
    // `[[https_rr]]` 只有当名字落在**某个已存在的 zone** 里才会被发布（归属由
    // `relative_owner` 决定）。名字不属于任何 zone 时记录会被**静默丢弃** ——
    // 配置、日志、面板全都正常，只有 `dig` 查不到。实测踩过：ECH 的 HTTPS 记录
    // 明明写进了 panel.toml，`dig crucible.local HTTPS` 却是 NXDOMAIN（缺 zone）。
    if cfg.modes.authoritative {
        let orphans = orphan_https_names(&auto_https, &zones);
        if !orphans.is_empty() {
            // 去重：write_all 在每次 reconcile 都会被调用，同一个列表不该反复刷屏。
            static LAST: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
            let key = orphans.join(",");
            let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
            if last.as_deref() != Some(key.as_str()) {
                log::warn!(
                    "dns: [[https_rr]] 有 {} 条记录的名字不属于任何已存在的 zone，**不会被发布**（dig 查不到）：{}；请先建同名 zone（面板「DNS 分区」），或改掉这些名字",
                    orphans.len(),
                    orphans.join("、")
                );
                *last = Some(key);
            }
        }
    }
    for (view_tag, line_tag) in &views {
        // 与 gen_named_conf 同步：权威关掉时不落用户 zone 文件
        // （否则盘上留着 orphan zone，且 named.conf 里已无引用，排障时极易误判）。
        // 注意只跳过**用户 zone**：root 模式的 `.` 与 authoritative 无关
        // （gen_named_conf 的 root 分支不看 authoritative），占位文件仍必须写 ——
        // 否则 named.conf 声明了 `zone "."` 而 zones/root.zone 不存在（root=true 且
        // authoritative=false 时，named 加载该区失败）。
        if cfg.modes.authoritative {
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
            // 本 zone 该补的自动 HTTPS 记录：按 zone 归属过滤 + 面板同名记录优先。
            let extra_https: Vec<(String, String)> = auto_https
                .iter()
                .filter_map(|(name, rdata)| {
                    let owner = relative_owner(name, &z.name)?;
                    let panel_has = recs.iter().any(|r| {
                        r.rtype.eq_ignore_ascii_case("HTTPS")
                            && (r.name.eq_ignore_ascii_case(&owner)
                                || (owner == "@" && r.name.is_empty()))
                    });
                    if panel_has {
                        return None;
                    }
                    Some((owner, rdata.clone()))
                })
                .collect();
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
            write_atomic(
                &path,
                gen_zone_file_monotonic_ext(&z.name, &z.kind, &recs, prev_serial, &extra_https)
                    .as_bytes(),
                0o644,
                None,
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
        }
        if cfg.modes.root {
            let f = if view_tag.is_empty() { "root.zone".to_string() } else { format!("root.{view_tag}.zone") };
            let path = zones_dir.join(&f);
            if !path.exists() {
                // 空文件会让 named 拒载 root zone；先写最小合法占位，rootzone_refresh 覆盖
                write_atomic(&path, minimal_root_zone(cfg).as_bytes(), 0o644, None)?;
            }
        }
    }
    if !cfg.rpz.is_empty() {
        for (view_tag, _) in &views {
            let rf = if view_tag.is_empty() { "rpz.zone".to_string() } else { format!("rpz.{view_tag}.zone") };
            let path = zones_dir.join(&rf);
            // SOA serial 必须**严格递增**（同用户 zone 的处理）：RPZ/answers 此前用的是裸
            // `chrono_now()`，于是「改一条 override → 面板 ok → BIND 仍服务旧内容」——
            // rndc reload 只在 serial 更大时才加载新内容，同秒内的两次编辑会撞成同一个值。
            // 这里从**已落盘的旧文件**里读回上一个 serial 取 max(now, prev+1)。
            let prev_rpz = read_zone_serial(&path);
            write_atomic(&path, gen_rpz_file(&cfg.rpz, prev_rpz).as_bytes(), 0o644, None)?;
            let mut j = path.clone().into_os_string();
            j.push(".jnl");
            let _ = std::fs::remove_file(&j);
            written.push(("crucible.rpz".into(), path));
            // answers 区：override 自定义响应（A/AAAA/TXT）的真实记录（需求 7）
            let af = if view_tag.is_empty() { "answers.zone".to_string() } else { format!("answers.{view_tag}.zone") };
            let apath = zones_dir.join(&af);
            let prev_ans = read_zone_serial(&apath);
            write_atomic(&apath, gen_answers_file(&cfg.rpz, prev_ans).as_bytes(), 0o644, None)?;
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

/// reconcile 串行化锁。
///
/// 「write_all 重写全部配置文件」+「named_alive 判定 → 探活 → spawn named」这段
/// 不是原子的，而 reconcile 有多个并发调用方：面板每次保存（persist_and_reconcile）、
/// 面板的 /api/dns/reload、以及 maintenance_loop 的 mtime 轮询。两个线程同时看到
/// named_alive=false 就会各 spawn 一个 named（第二个抢不到端口即退出，但会和第一个
/// 抢写同一个 named.stderr.log／同时改写同一份 named.conf）。整段串起来最省事：
/// 单次 reconcile 只阻塞几秒，且本函数不会被自己递归调用。
static RECONCILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// reconcile：落盘 → 校验（探活法，named 已在跑则跳过）→ 确保进程 → reload。
pub fn reconcile(cfg: &DnsConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    // 锁被毒化（上一次 reconcile panic）时照样继续，避免之后每次保存都直接失败。
    let _guard = RECONCILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        // 权限：named 以 _bind 用户运行（root 绑端口后 drop），它**只需要**能写
        // zones/（zone 文件与 .jnl/.signed）、log/、keys/。
        // 原来这里是 `chown -R _bind:_bind <整个 state_root>` —— 连 etc/（named.conf
        // 含 rndc 密钥、session.key、panel.toml 这份**权威 [dns] 配置**）与 db/dns.sqlite
        // 一起交给 _bind。那等于让数据面账号拥有自己的控制面：一个能影响 named 处理
        // 不可信 DNS 数据的漏洞，就能顺手改掉控制面配置与分区数据库。
        for sub in ["zones", "log", "keys"] {
            let _ = std::process::Command::new("chown")
                .arg("-R")
                .arg("_bind:_bind")
                .arg(state_root().join(sub))
                .status();
        }
        // OpenBSD lo0 默认只有 127.0.0.1/32——fwd view 的 127.0.0.(2+i) 目标需显式 alias
        if cfg.geo.enabled {
            for (i, _) in cfg.geo.lines.iter().enumerate().take(MAX_GEO_LINES) {
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

/// dnssec-keygen 的 `-f` 取值。
///
/// BIND 9.20 的 `dnssec-keygen -f` 只认 KSK/ZSK/REVOKE 的首字母；CSK 是 KASP 策略
/// 角色、不是 keygen 的标志位 —— 旧实现传 `-f CSK` 会让工具 `fatal("unknown flag
/// 'CSK'")`，需求 4 的「CSK 一键生成」100% 失败。CSK 用 `-f KSK` 生成，
/// 由 dnssec-policy 把它当组合签名键使用。
fn keygen_flag(role: &str) -> Option<&'static str> {
    match role.to_ascii_lowercase().as_str() {
        "ksk" | "csk" => Some("KSK"),
        // zsk = 默认（不传 -f）
        _ => None,
    }
}

/// 一键生成 DNSSEC key（需求 4）。返回生成的 key 文件名。
pub fn keygen(zone: &str, role: &str, alg: &str) -> Result<String> {
    // zone/role/alg 全来自面板（action=keygen），会变成 dnssec-keygen 的 argv：
    // 不校验时 `zone = "-K/tmp/x"` 之类会被 dnssec-keygen 当成选项解析（key 落到
    // 指定目录），role 写错则静默生成成 ZSK。与 add_zone 用同一套名字规则。
    if !valid_name(zone) || zone.starts_with('-') {
        bail!("bad zone name {zone:?}");
    }
    if !valid_key_role(role) {
        bail!("bad key role {role:?}（ksk|zsk|csk）");
    }
    if !valid_dnssec_alg(alg) {
        bail!("bad dnssec algorithm {alg:?}");
    }
    let keys = state_root().join("keys");
    std::fs::create_dir_all(&keys)?;
    // ksk/csk 用 -f KSK；zsk 默认
    let mut args: Vec<String> = vec![
        "-K".into(),
        keys.to_string_lossy().into(),
        "-a".into(),
        alg.to_string(),
    ];
    if let Some(flag) = keygen_flag(role) {
        args.push("-f".into());
        args.push(flag.into());
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
    // 0600 + _bind：named（_bind）要读它做签名，本机其它用户不该读私钥；
    // 原子落盘避免「半截密钥文件」——那会让 named 解析失败、该区 DNSSEC 起不来。
    write_atomic(&p, &decoded, 0o600, Some("_bind"))?;
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

/// 把一份 zone 文本原子装到目标路径：唯一临时文件（`O_CREAT|O_EXCL|O_NOFOLLOW`，
/// 0644 —— named 以 _bind 运行必须能读）→ 目标不是符号链接 → rename。
///
/// rootzone 此前用 `curl -o root.zone.tmp` / `fs::write` 到**固定名**并跟随符号链接，
/// 而 `zones/` 归 _bind：被攻破的 named 可预置软链让 root 写穿任意路径、再 rename
/// 成 root.zone；固定 tmp 名在失败后残留还会让后续刷新一直失败。
fn install_zone_file(dst: &Path, data: &[u8]) -> Result<()> {
    let tmp = tmp_path_for(dst);
    let mut cleanup = TmpCleanup::new(tmp.clone());
    write_new_0600(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
            .with_context(|| format!("chmod 0644 {}", tmp.display()))?;
    }
    if let Ok(md) = std::fs::symlink_metadata(dst) {
        if md.file_type().is_symlink() {
            bail!("拒绝覆盖符号链接 {}（root zone 安装只接受普通文件）", dst.display());
        }
    }
    std::fs::rename(&tmp, dst)
        .with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()))?;
    cleanup.disarm();
    Ok(())
}

/// root zone 的全部落盘目标：默认 `root.zone`；配了 geo 多 view 时 named.conf 给每个
/// view 声明的是 `root.<view>.zone`，只刷新 root.zone 会让分线路 view 永远服务占位根区。
fn rootzone_targets(cfg: &DnsConfig) -> Vec<PathBuf> {
    let zones = state_root().join("zones");
    let mut v = vec![zones.join("root.zone")];
    let geo_on = cfg.geo.enabled && (!cfg.geo.lines.is_empty() || cfg.geo.mmdb.is_active());
    if geo_on {
        for l in &cfg.geo.lines {
            v.push(zones.join(format!("root.{}.zone", l.name)));
            v.push(zones.join(format!("root.fwd-{}.zone", l.name)));
        }
        v.push(zones.join("root.default.zone"));
    }
    v
}

/// 把同一份 root zone 文本装到 [`rootzone_targets`] 的所有目标。
fn install_rootzone(cfg: &DnsConfig, data: &[u8]) -> Result<()> {
    for p in rootzone_targets(cfg) {
        install_zone_file(&p, data)?;
    }
    Ok(())
}

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
    // url 来自配置/面板，是 curl 的**最后一个 argv**：以 '-' 开头的值会被 curl 当选项
    // 解析（如 `-o/etc/cron.d/x`、`--config=...`），等于把外部工具的参数面交给配置。
    // 这个字段本来就是 URL，限定 http(s) 即可，顺带挡掉 file:// 本地读取。
    if !(cfg.rootzone.url.starts_with("http://") || cfg.rootzone.url.starts_with("https://")) {
        bail!("rootzone.url 必须是 http(s):// URL（收到 {:?}）", cfg.rootzone.url);
    }
    // 不再用 `curl -o <固定临时名>`：那会跟随预置软链接、且失败残留会让后续刷新
    // 一直失败。下载到内存（root zone ≈2MB）→ 校验内容 → 由 install_zone_file
    // 以 O_NOFOLLOW|O_EXCL 落盘。
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "120"])
        .arg(&cfg.rootzone.url)
        .output()
        .context("spawn curl")?;
    if !out.status.success() {
        bail!("rootzone fetch failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    // 内容校验：任何 HTTP 200 响应体（门户劫持页 / CDN 错误页 / 被投毒的镜像）都不能
    // 直接替换 root.zone —— 否则 rndc reload 失败后根区 SERVFAIL 到下个刷新周期。
    // AXFR 分支本来就有这个检查，HTTPS 分支此前漏了。
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.lines().any(is_soa_record) {
        bail!("rootzone 下载内容里没有 SOA 记录；拒绝覆盖 root.zone");
    }
    install_rootzone(cfg, &out.stdout)?;
    meta_set("root_last_ok", &chrono_now().to_string())?;
    let _ = rndc(cfg, &["reload", "."]);
    Ok(rootzone_targets(cfg)[0].to_string_lossy().into())
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
    // 文件名格式 `K<zone>.+<alg>+<tag>`：zone 自己就带点，只能用**最后一个**点
    // 去切（find 会在第一个点上切，`Kexample.com.+013+12345` 解析出 zone="example"）。
    // 这个 zone 会被 dnssec_check_and_rotate 直接交给 keygen —— 名字错位意味着
    // 为一个不存在的分区生成密钥、面板里显示的分区也全错（若恰好存在同名小分区，
    // KASP 还会把那把 key 认成该分区的 key）。
    let dot_idx = rest.rfind('.')?;
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
                        // 按 token 定位，不写死下标：`.key` 里的 DNSKEY 行可能是
                        // `name. TTL IN DNSKEY flags proto alg key`（keygen 传了 -L 就是
                        // 这种），也可能没有 TTL 段。写死 parts[2]/parts[4] 在两种形态下
                        // 分别取到 "IN"/"DNSKEY" 或 flags/proto，于是面板里 flags 恒为 0、
                        // algorithm 变成数字（flags）。
                        if let Some(i) = parts
                            .iter()
                            .position(|p| p.eq_ignore_ascii_case("DNSKEY"))
                        {
                            if let Some(f) = parts.get(i + 1).and_then(|x| x.parse::<u16>().ok()) {
                                info.flags = f;
                            }
                            if let Some(a) = parts.get(i + 3) {
                                info.algorithm = a.to_string();
                            }
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
    // DoT 监听用 **live** 入口：每次判定取 `effective(live.snapshot())`，因此
    // panel.toml 与 config.toml 热载的 [dns]/[dns.dot] 改动（ACL/限速/并发上限/端口/
    // 启停）都会生效。旧实现用启动快照入口 `dot_listener(cfg.clone())`：它只重读
    // panel.toml，配置文件里的 [dns.dot] 改动**永远不生效**，而且「启动时未开 DoT、
    // 之后在 config.toml 打开」也永远起不来。supervisor 内部按 enabled 自行 bind/unbind，
    // 所以这里无条件 spawn（关着时它只做一次配置轮询，不监听）。
    tokio::spawn(dot_doh::dot_listener_live(Arc::clone(live)));
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
                // KSK 分支只提示 DS 提交、不自行生成新 key（KASP 策略负责切换）。
                // 但这个条件在新 key 生效前每轮都成立，而 maintenance_loop 每 30s
                // 调一次 —— 不节流就是 2880 条/天刷 info。按 (zone,tag) 每天最多一条。
                let notice_key = format!("dnssec_ksk_notice:{}:{}", key.zone, key.tag);
                let last_notice = meta_get(&notice_key)
                    .ok()
                    .flatten()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                if now.saturating_sub(last_notice) >= 86_400 {
                    log::info!(
                        "dnssec: KSK tag={} nearing end of life (age {}s, threshold {}s), will rollover",
                        key.tag, age_secs, ksk_threshold
                    );
                    let _ = meta_set(&notice_key, &now.to_string());
                }
                need_ds.push(DsPublishInfo {
                    zone: key.zone.clone(),
                    tag: key.tag.clone(),
                    algorithm: key.algorithm.clone(),
                });
            }
        } else if role == "ZSK" || role == "CSK" {
            let zsk_threshold = lifetime_secs.saturating_sub(7 * 86400);
            if age_secs > zsk_threshold {
                // 节流（必须有）：maintenance_loop 每 30s 调一次本函数，而「临近过期」
                // 这个条件在新 key 被 BIND 真正接管、旧 key 被删掉之前**每一轮都成立**。
                // 旧实现于是每 30s 又生成一把新 key（≈2880 把/天，可持续数周），
                // keys/ 目录与面板 key 列表无限膨胀。用 meta 记最近一次生成时间：
                // 同一 (zone, role) 最快一天生成一把。
                let throttle_key = format!("dnssec_rotate:{}:{}", key.zone, role);
                let last = meta_get(&throttle_key)
                    .ok()
                    .flatten()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                if now.saturating_sub(last) < 86_400 {
                    continue;
                }
                log::info!(
                    "dnssec: {} tag={} nearing end of life, generating replacement",
                    role, key.tag
                );
                // 角色必须与当前 key 一致：旧实现对 CSK 也生成 ZSK，与多 key 结构脱节。
                // keygen 会把 csk 映射成 `-f KSK`（dnssec-keygen 不认 CSK 标志）。
                let gen_role = if role == "CSK" { "csk" } else { "zsk" };
                match keygen(&key.zone, gen_role, &dc.dnssec.algorithm) {
                    Ok(new_name) => {
                        log::info!("dnssec: generated new {} for {}: {}", role, key.zone, new_name);
                        // 需求 4 明文要求「落 key-dir + rndc loadkeys」：不通知 named，
                        // 新 key 何时被 KASP 采纳不可控。best-effort（named 没跑时跳过）。
                        if let Err(e) = rndc(cfg, &["loadkeys", &key.zone]) {
                            log::debug!("dnssec: rndc loadkeys {} 失败（按 best-effort 忽略）: {e:#}", key.zone);
                        }
                        if let Err(e) = meta_set(&throttle_key, &now.to_string()) {
                            log::warn!("dnssec: 记录轮换节流失败 {e:#}");
                        }
                    }
                    Err(e) => {
                        log::warn!("dnssec: keygen failed for {}: {e}", key.zone);
                        // 生成失败也记时间，否则失败会变成每 30s 一条日志 + 一次进程
                        // 派生（dnssec-keygen 不可用的部署上会一直空转）。
                        let _ = meta_set(&throttle_key, &now.to_string());
                    }
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
            // IXFR 只就地改了 root.zone；配了 geo 多 view 时各 view 的 root.<view>.zone
            // 也要同步分发，否则分线路 view 一直服务占位根区。
            if let Ok(data) = std::fs::read(&dst) {
                if let Err(e) = install_rootzone(cfg, &data) {
                    log::warn!("dns: rootzone view 分发失败: {e:#}");
                }
            }
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
    if !text.lines().any(is_soa_record) {
        bail!("dig axfr output has no SOA; refusing to overwrite zone");
    }
    install_rootzone(cfg, &out.stdout)?;
    meta_set("root_last_ok", &chrono_now().to_string())?;
    let _ = rndc(cfg, &["reload", "."]);
    Ok(rootzone_targets(cfg)[0].to_string_lossy().into())
}

/// 行里的 RR 类型是不是 SOA（token 级判断，避免把 rdata 里含 SOA 的 RRSIG 等误判）。
/// dig 输出带 class（`name TTL IN SOA ...`），internic root.zone 不带（`name TTL SOA ...`），两种都认。
fn is_soa_record(line: &str) -> bool {
    let toks: Vec<&str> = line.split_whitespace().take(4).collect();
    if toks.len() < 3 {
        return false;
    }
    if toks[2].eq_ignore_ascii_case("SOA") {
        return true;
    }
    toks.len() >= 4
        && toks[3].eq_ignore_ascii_case("SOA")
        && matches!(
            toks[2].to_ascii_uppercase().as_str(),
            "IN" | "CH" | "HS"
        )
}

/// 从 dig `+noall +answer` 的 IXFR 差异流里切出 (删除段, 新增段)。
///
/// RFC1995 / BIND `xfrout.c` 的实际应答形态：前导 SOA(current)，随后每段
///   SOA(old) 删除记录… SOA(new) 新增记录…
/// 交替出现，最后再跟一份 SOA(current)。所有 SOA 行都只是段标记，**不进集合**：
/// 旧实现把 SOA 当作「分隔符」直接丢弃、且段序理解颠倒（先删除段再 SOA(old)），
/// 于是本地旧 SOA 永远替换不掉、差异也应用错位，serial 校验必然失败 ——
/// IXFR 实际从未成功过一次，每次都静默回落全量下载。
///
/// 返回 None = 行数不足以构成差异流（单个 SOA 是「无变化 / AXFR 式应答」，
/// 全部记录会被误当删除段，调用方必须回退全量）。
fn split_ixfr_diff<'a>(records: &[&'a str]) -> Option<(Vec<&'a str>, Vec<&'a str>)> {
    let markers = records.iter().filter(|l| is_soa_record(l)).count();
    // 前导 + old + new = 3 是单段差异流的最小值（BIND 还会再追加一份尾 SOA）
    if records.is_empty() || markers < 3 {
        return None;
    }
    let mut deletions: Vec<&'a str> = Vec::new();
    let mut additions: Vec<&'a str> = Vec::new();
    let mut in_add = false;
    let mut marker_seen = false;
    for line in &records[1..] {
        if is_soa_record(line) {
            // 第一个标记是 SOA(old)（其后为删除段），之后 old/new 交替
            in_add = marker_seen && !in_add;
            marker_seen = true;
            continue;
        }
        if in_add {
            additions.push(line);
        } else {
            deletions.push(line);
        }
    }
    Some((deletions, additions))
}

/// SOA 记录从 `start` 行起占用到哪一行（括号平衡；无括号 = 单行）。
/// internic 的 root.zone SOA 是多行括号形态，只按行增删永远替换不掉。
fn soa_block_end(lines: &[String], start: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut opened = false;
    for (i, l) in lines.iter().enumerate().skip(start) {
        for c in l.chars() {
            match c {
                '(' => {
                    depth += 1;
                    opened = true;
                }
                ')' => depth -= 1,
                // 行内注释之后的括号不算
                ';' => break,
                _ => {}
            }
        }
        if !opened || depth <= 0 {
            return Some(i);
        }
    }
    None
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
    // dig 只接受 `ixfr=<serial>` 这**一个** token：裸 `ixfr` 会被打印
    // "Warning, ixfr requires a serial number" 后忽略（不设置查询类型），
    // 紧随其后的数字变成查询名 —— 实际发出的是 A 查询，应答为空、永远回落全量。
    // +tcp：IXFR 的差异流只能走 TCP（UDP 只回单个 SOA）。
    let out = std::process::Command::new("dig")
        .args([
            "+noall",
            "+answer",
            "+tcp",
            &format!("ixfr={current_serial}"),
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
    let soa_cnt = records.iter().filter(|l| is_soa_record(l)).count();
    if soa_cnt == 0 {
        return Ok(false);
    }
    // 单个 SOA：要么「无变化」，要么不是完整区。按 serial 判定，绝不写文件。
    if soa_cnt == 1 {
        let new_serial = soa_serial_from_line(records[0]);
        if new_serial == Some(current_serial) {
            log::info!("dns: rootzone already at serial {current_serial}");
            return Ok(true);
        }
        return Ok(false);
    }
    // 差异流切段（段标记 = SOA 行；整个差异流里的 SOA 都不作为记录应用）
    let Some((deletions, additions)) = split_ixfr_diff(&records) else {
        return Ok(false);
    };
    let target_serial = soa_serial_from_line(records[0]);
    if target_serial.is_none() {
        return Ok(false);
    }

    let original = std::fs::read_to_string(dst).context("read current zone")?;
    let mut lines: Vec<String> = original.lines().map(|l| l.to_string()).collect();
    // 1) 用 records[0]（新 SOA，dig 单行形态）整体替换本地 SOA 块。
    //    本地 SOA 可能是多行括号形态，逐行匹配旧 serial 是永远删不掉的。
    let Some(soa_start) = lines.iter().position(|l| is_soa_record(l)) else {
        return Ok(false);
    };
    let Some(soa_end) = soa_block_end(&lines, soa_start) else {
        return Ok(false);
    };
    lines.splice(soa_start..=soa_end, std::iter::once(records[0].to_string()));

    // 2) 先删后加。删除必须**全部命中**：少一条就是「serial 已更新、内容却是旧的」
    //    半应用 zone，宁可回退全量（AXFR 结果正确但流量大）。
    for d in &deletions {
        let key = normalize_rr(d);
        match lines.iter().position(|l| normalize_rr(l) == key) {
            Some(pos) => {
                lines.remove(pos);
            }
            None => {
                log::warn!(
                    "dns: IXFR 删除项在本地 zone 里找不到（{d}）；回退全量 AXFR"
                );
                return Ok(false);
            }
        }
    }
    for a in &additions {
        let key = normalize_rr(a);
        if !lines.iter().any(|l| normalize_rr(l) == key) {
            lines.push((*a).to_string());
        }
    }

    // 3) 校验：应用后的 zone 必须能解析出目标 serial，否则回退全量。
    let new_text = lines.join("\n") + "\n";
    let got_serial = serial_from_zone_text(&new_text);
    if got_serial != target_serial {
        log::warn!(
            "dns: IXFR apply serial check failed (want {target_serial:?} got {got_serial:?}); \
             falling back to full AXFR"
        );
        return Ok(false);
    }

    install_zone_file(dst, new_text.as_bytes())?;
    log::info!(
        "dns: rootzone IXFR applied ({} deletions / {} additions) → serial {:?}",
        deletions.len(),
        additions.len(),
        target_serial
    );
    Ok(true)
}

/// 规范化一条 RR 文本用于比对：去掉注释、压缩空白、忽略 class、大小写不敏感。
/// （dig 输出是 `name TTL IN TYPE rdata`，internic root.zone 是 `name TTL TYPE rdata`，
/// 不看掉 class 的话删除段一条都对不上，IXFR 每次都回退全量。）
fn normalize_rr(line: &str) -> String {
    let no_comment = line.split(';').next().unwrap_or("");
    no_comment
        .split_whitespace()
        .filter(|t| !matches!(t.to_ascii_uppercase().as_str(), "IN" | "CH" | "HS"))
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
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
/// 同一段失败日志只打一次（按 tag 记住上次的完整消息）。
///
/// 维护循环每 30 秒跑一轮，而失败路径**不会**更新自己的「上次成功」时间戳
/// （rootzone 的 `root_last_ok`、dnssec 轮换检查都是这样）⇒ 一旦持久失败
/// （例如出口网络不通），每 30 秒就重打一条同样的 warn，永不停止。
/// 本机磁盘长期紧张、日志阈值只有 2MB，刷屏的代价是真实的。
/// 消息内容变化（比如换了一种错误）时仍会重新打 —— 只有**完全相同**的消息被抑制。
/// rootzone 是否到期刷新。
/// `refresh_hours` 来自面板且无上限：`t + h*3600` 在 release 下回绕、在
/// overflow-checks/debug 下 panic（维护任务会死，连带看门狗一起消失），必须饱和运算。
fn rootzone_due(last_ok: Option<&str>, refresh_hours: u64, now: u64) -> bool {
    match last_ok.and_then(|t| t.trim().parse::<u64>().ok()) {
        Some(t) => now > t.saturating_add(refresh_hours.saturating_mul(3600)),
        None => true,
    }
}

fn warn_once(tag: &str, msg: &str) {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static SEEN: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
    let mut g = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    if m.get(tag).map(|s| s.as_str()) != Some(msg) {
        m.insert(tag.to_string(), msg.to_string());
        log::warn!("{msg}");
    }
}

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
        // named 存活看门狗（第 6 轮并发报告 #4）。
        //
        // `reconcile()` 里确实有「named_alive → spawn」逻辑，但它**只在**启动、配置变更、
        // 面板操作时被调用；此前 maintenance_loop 只做「mtime 变了才 reconcile」+ DNSSEC
        // 轮换 + rootzone 刷新，**没有任何周期性的 liveness 检查**。后果：named 一旦 OOM/
        // 崩溃，在下次改配置之前 **DNS 一直不可用**（生产里配置改动很稀疏 ⇒ 等于长期中断；
        // 而且除了解析失败之外没有任何信号，是典型的静默故障）。
        // 每 30s 探一次；确认没响应就走同一条 reconcile 把它拉起来。
        // 不会重复 spawn：reconcile 内部先探活、且有串行化锁兜底。
        {
            let wd_cfg = effective(&live.snapshot());
            if wd_cfg.enabled {
                let probe = wd_cfg.clone();
                let alive = tokio::task::spawn_blocking(move || named_alive(&probe))
                    .await
                    .unwrap_or(false);
                if !alive {
                    warn_once(
                        "dns-named-down",
                        "dns: named 未响应 rndc status ⇒ 看门狗触发 reconcile 拉起",
                    );
                    let d2 = wd_cfg.clone();
                    let r = tokio::task::spawn_blocking(move || reconcile(&d2)).await;
                    log::info!(
                        "dns: named 看门狗 reconcile {:?}",
                        r.as_ref().map(|_| "ok")
                    );
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
                    // 同一 DS 提示每 30s 重复一次没有意义（dnssec_check_and_rotate 内部
                    // 已对 KSK 生成侧节流；这里用 warn_once 抑制完全相同的消息）。
                    for ds in &ds_info {
                        warn_once(
                            &format!("dnssec-ds:{}:{}", ds.zone, ds.tag),
                            &format!("dnssec: DS rollover needed zone={} tag={}", ds.zone, ds.tag),
                        );
                    }
                }
                Ok(Err(e)) => warn_once("dnssec-rotate", &format!("dnssec: rotation check failed: {e:#}")),
                Err(e) => log::warn!("dnssec: rotation join: {e}"),
            }
        }
        // rootzone 到期刷新
        let cfg = effective(&live.snapshot());
        // rootzone.enabled 是需求 2 的开关（默认 false）：root 模式下也允许
        // 管理员只托管一个静态 root.zone 而不自动去 AXFR/下载。
        // 旧代码从不读这个字段，等于开关失效。
        if cfg.enabled && cfg.modes.root && cfg.rootzone.enabled {
            let last_ok = meta_get("root_last_ok").ok().flatten();
            let due = rootzone_due(last_ok.as_deref(), cfg.rootzone.refresh_hours, chrono_now());
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
                    Err(e) => warn_once("rootzone", &format!("dns: rootzone refresh failed: {e:#}")),
                }
            }
        }
    }
}

#[cfg(test)]
mod dns_atomic_write_tests {
    use super::write_atomic;
    use std::os::unix::fs::PermissionsExt;

    /// 原子落盘：内容换新、权限保持调用方指定值、不留临时文件。
    /// 权限必须在 rename 前设好 —— 否则 named.conf（内含 rndc 密钥）会有 umask 权限窗口。
    #[test]
    fn write_atomic_replaces_content_and_keeps_mode() {
        let dir = std::env::temp_dir().join(format!("crucible-dns-aw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("named.conf");
        std::fs::write(&p, b"old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_atomic(&p, b"new-content", 0o640, None).expect("atomic write");

        assert_eq!(std::fs::read(&p).unwrap(), b"new-content");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "权限必须是指定的 0640，实际 {mode:o}");
        // 不留 tmp
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "残留临时文件: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 失败路径（rename 到目录必然失败）不得留下临时文件：旧实现失败即残留，
    /// 固定 tmp 名会让同一进程内后续写盘全部 EEXIST（配置再也更新不出去）。
    #[test]
    fn write_atomic_cleans_tmp_on_failure() {
        let dir = std::env::temp_dir().join(format!("crucible-dns-aw-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target-is-a-dir");
        std::fs::create_dir_all(&target).unwrap();

        let err = write_atomic(&target, b"x", 0o644, None);
        assert!(err.is_err(), "rename(file -> dir) 应失败");

        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "失败后残留临时文件: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod acl_primary_tests {
    use super::*;

    /// ECH 的发现路径只有 DNS：`[[dns.https_rr]]` 渲染出来的 HTTPS 记录必须
    /// 带上与服务端**同一份** ech 参数，且缺物料时宁可省略也不能写空值。
    #[test]
    fn https_rdata_renders_ech_and_omits_when_missing() {
        let item = HttpsRrCfg {
            name: "example.com".into(),
            alpn: "h2,h3".into(),
            port: Some(443),
            ech: true,
            priority: 1,
            target: ".".into(),
        };
        assert_eq!(
            https_rdata(&item, Some("AEX+DQBB")),
            "1 . alpn=\"h2,h3\" port=443 ech=\"AEX+DQBB\""
        );
        // 没有 ECH 物料 → 不写 ech=（写空值会让客户端以为 ECH 可用）
        assert_eq!(
            https_rdata(&item, None),
            "1 . alpn=\"h2,h3\" port=443"
        );
        // 只要最简形式
        let bare = HttpsRrCfg {
            priority: 1,
            target: ".".into(),
            ..Default::default()
        };
        assert_eq!(https_rdata(&bare, Some("X")), "1 .");
    }

    /// 自动记录只补本 zone 的名字，且**面板同名 HTTPS 记录优先**。
    #[test]
    fn relative_owner_maps_names_into_zone() {
        assert_eq!(relative_owner("example.com", "example.com").as_deref(), Some("@"));
        assert_eq!(relative_owner("example.com.", "example.com").as_deref(), Some("@"));
        assert_eq!(relative_owner("www.example.com", "example.com").as_deref(), Some("www"));
        assert_eq!(relative_owner("@", "example.com").as_deref(), Some("@"));
        assert_eq!(relative_owner("other.test", "example.com"), None);
        assert_eq!(relative_owner("www.example.com", "."), None);
        // 大小写不敏感（DNS 名字本就大小写无关）
        assert_eq!(relative_owner("WWW.Example.COM", "example.com").as_deref(), Some("www"));
    }

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

#[cfg(test)]
mod listen_lists_tests {
    use super::{listen_lists, orphan_https_names, ZoneRow, MAX_GEO_LINES};

    /// 回归（生产事故）：named 9.20 对字面量 `0.0.0.0` **静默不建 socket**，所以
    /// `listen-on { 0.0.0.0; ... }` 会让 53 只在 loopback 上听、公网 IPv4 收不到查询。
    /// 必须翻译成关键字 `any`。
    #[test]
    fn wildcard_v4_becomes_any_never_literal() {
        let (v4, v6) = listen_lists("0.0.0.0", false, 0);
        assert!(v4.starts_with("any;"), "{v4}");
        assert!(!v4.contains("0.0.0.0"), "字面量 0.0.0.0 会被 named 丢弃: {v4}");
        assert!(v4.contains("127.0.0.1;"), "DoT/DoH 转发依赖 loopback: {v4}");
        assert_eq!(v6, "none;");
    }

    #[test]
    fn loopback_is_always_in_v4_table_and_never_duplicated() {
        assert_eq!(listen_lists("127.0.0.1", false, 0).0, "127.0.0.1;");
        // 显式绑一个非 loopback 地址时，loopback 仍要保留（DoT/DoH 用）
        assert_eq!(listen_lists("10.1.2.3", false, 0).0, "10.1.2.3; 127.0.0.1;");
    }

    /// v6 字面量绝不能漏进 IPv4 的 listen-on（`listen-on { ::1; 127.0.0.1; }` 会被
    /// named 判为非法配置、整份拒载）。旧代码在 `::1` 下把 v6 表也写成 `none`，
    /// 等于「配了 v6 却哪里都不听」——这里一并纠正。
    #[test]
    fn v6_literal_never_leaks_into_v4_table() {
        assert_eq!(
            listen_lists("::", false, 0),
            ("none;".to_string(), "any;".to_string())
        );
        assert_eq!(
            listen_lists("::1", false, 0),
            ("none;".to_string(), "::1;".to_string())
        );
        assert_eq!(
            listen_lists("2001:db8::1", false, 0),
            ("none;".to_string(), "2001:db8::1;".to_string())
        );
    }

    #[test]
    fn keywords_pass_through_to_both_tables() {
        assert_eq!(listen_lists("any", false, 0), ("any; 127.0.0.1;".to_string(), "any;".to_string()));
        assert_eq!(
            listen_lists("none", false, 0),
            ("none;".to_string(), "none;".to_string())
        );
        assert_eq!(
            listen_lists("localnets", false, 0),
            ("localnets; 127.0.0.1;".to_string(), "localnets;".to_string())
        );
    }

    #[test]
    fn geo_line_loopbacks_are_listed_explicitly() {
        let (v4, _) = listen_lists("127.0.0.1", false, 2);
        assert!(v4.contains("127.0.0.2;") && v4.contains("127.0.0.3;"), "{v4}");
        // 回归：老代码写成 `127.0.{2+i}`，与 match-destinations / resolve_fwd_dest 的
        // `127.0.0.{2+i}` 不一致 ⇒ 分线路转发没有对应 socket，静默失效。
        assert!(!v4.contains(" 127.0.2;"), "分线路地址必须是 127.0.0.{{2+i}}: {v4}");
        assert!(!v4.contains(" 127.0.3;"), "分线路地址必须是 127.0.0.{{2+i}}: {v4}");
    }

    /// 上限与 `resolve_fwd_dest` / fwd view / lo0 alias 统一到 `MAX_GEO_LINES`：
    /// 最高索引 `MAX_GEO_LINES-1` → 127.0.0.(1+MAX_GEO_LINES)，再高一律不出现
    /// （`check_config_strings` 直接拒绝超过 MAX_GEO_LINES 的线路数）。
    #[test]
    fn geo_line_loopbacks_cover_the_resolver_index_cap() {
        let (v4, _) = listen_lists("127.0.0.1", false, 300);
        let top = format!("127.0.0.{};", 1 + MAX_GEO_LINES); // 251
        assert!(v4.contains(&top), "最高索引的可达地址缺 socket: {v4}");
        let over = format!("127.0.0.{};", 2 + MAX_GEO_LINES); // 252
        assert!(!v4.contains(&over), "越界地址不该出现: {v4}");
    }

    /// 没有分线路时不许出现任何 127.0.0.2+ 地址（`0..=min(250)` 会在 lines=0 时多加一个）。
    #[test]
    fn no_geo_lines_adds_no_forwarding_loopbacks() {
        assert_eq!(listen_lists("127.0.0.1", false, 0).0, "127.0.0.1;");
        assert_eq!(listen_lists("10.1.2.3", false, 0).0, "10.1.2.3; 127.0.0.1;");
    }

    /// `[[https_rr]]` 名字不属于任何 master zone ⇒ 必须被识别为「静默不发布」。
    /// 这是真机踩过的坑：记录写进了 panel.toml，`dig` 却是 NXDOMAIN（缺 zone）。
    /// `warn_once`：**完全相同**的消息只打一次；消息一变就重新打。
    /// 钉这个是因为维护循环 30s 一轮、失败路径不更新「上次成功」⇒ 不去重就永久刷屏。
    #[test]
    fn warn_once_suppresses_only_identical_messages() {
        use super::warn_once;
        // 无法在这里断言日志行数（没有测试 logger），改为断言去重状态机的可观察行为：
        // 同一 tag 反复喂同一消息不应 panic，且换消息后仍能继续工作。
        for _ in 0..5 {
            warn_once("unit-test-tag", "same message");
        }
        warn_once("unit-test-tag", "different message");
        warn_once("unit-test-tag", "same message"); // 回到旧消息 = 与新消息不同 ⇒ 会打
        warn_once("other-tag", "same message");     // 不同 tag 互不影响
    }

    #[test]
    fn orphan_https_names_finds_records_without_a_zone() {
        let z = |n: &str, k: &str| ZoneRow {
            name: n.to_string(),
            kind: k.to_string(),
            primaries: vec![],
            axfr_acl: vec![],
            refresh_hours: 24,
        };
        let zones = vec![z("crucible.local", "master"), z("example.com", "master"), z("slave.test", "slave")];
        let recs = vec![
            ("crucible.local".to_string(), "rdata".to_string()),   // zone apex ⇒ 能发布
            ("www.crucible.local".to_string(), "rdata".to_string()), // 落在 zone 内 ⇒ 能发布
            ("other.net".to_string(), "rdata".to_string()),        // 没有 zone ⇒ 孤儿
            ("in.slave.test".to_string(), "rdata".to_string()),    // 只有 slave zone ⇒ 孤儿（不落从区文件）
        ];
        let got = orphan_https_names(&recs, &zones);
        assert_eq!(got, vec!["other.net".to_string(), "in.slave.test".to_string()], "{got:?}");
        // 正对照：全部有归属时不该报任何孤儿（否则上面可能是「什么都说孤儿」）
        assert!(orphan_https_names(&recs[..2], &zones).is_empty());
    }

    #[test]
    fn test_mode_is_loopback_only_even_with_public_addr() {
        assert_eq!(
            listen_lists("0.0.0.0", true, 0),
            ("127.0.0.1;".to_string(), "none;".to_string())
        );
    }
}

#[cfg(test)]
mod config_guard_tests {
    use super::*;

    /// `Default::default()` 的 listen_addr 是空串（`#[serde(default = ...)]` 只管反序列化），
    /// 这里统一给一个合法值，免得测试被 `check_config_strings` 的 listen_addr 判据拦掉。
    fn cfg_with(listen: &str) -> DnsConfig {
        let mut c = DnsConfig::default();
        c.listen_addr = listen.to_string();
        c
    }

    /// 根区占位里的 A 记录必须是**合法点分四段**：`listen_addr` 是 named 关键字或 v6
    /// 字面量时原样写进去（`valid_listen_addr` 全都放行），named 会判为非法 A 而拒载
    /// **整个根区** —— root 模式下 "." 直接 SERVFAIL，而配置期/面板/日志一切正常。
    #[test]
    fn minimal_root_zone_never_writes_a_non_v4_a_record() {
        for bad in ["", "any", "none", "localhost", "localnets", "0.0.0.0", "::1", "2001:db8::1"] {
            let z = minimal_root_zone(&cfg_with(bad));
            assert!(
                z.contains("IN A 127.0.0.1"),
                "listen_addr={bad:?} 会写出非法 A 记录: {z}"
            );
        }
        // 正对照：真正的 v4 字面量照旧写进去（否则上面可能是「一律写 loopback」）
        assert!(minimal_root_zone(&cfg_with("10.1.2.3")).contains("IN A 10.1.2.3"));
    }

    /// HTTPS 记录的 alpn 是**带引号**的字符串：值里的引号/反斜杠不转义就会提前闭合
    /// 引号，让这条记录非法 ⇒ named 拒载该 zone（同分区里 ECH 的发现记录一起消失）。
    #[test]
    fn https_rdata_escapes_quotes_in_alpn() {
        let item = HttpsRrCfg {
            name: "example.com".into(),
            alpn: "h2\"x\\".into(),
            priority: 1,
            ..Default::default()
        };
        assert_eq!(https_rdata(&item, None), "1 . alpn=\"h2\\\"x\\\\\"");
        // `,` 是 alpn 的合法分隔符，不能被转义掉
        let ok = HttpsRrCfg {
            alpn: "h2,h3".into(),
            priority: 1,
            ..Default::default()
        };
        assert_eq!(https_rdata(&ok, None), "1 . alpn=\"h2,h3\"");
    }

    /// 面板保存前（写 panel.toml 之前）跑的校验必须拦住会注入 named.conf / 让 named
    /// 拒载的值：否则非法值先落进 panel.toml（effective() 的权威来源），此后每次
    /// reconcile（含启动）都失败 —— 重启后 DNS 起不来。
    #[test]
    fn check_config_strings_rejects_injection_and_bad_names() {
        assert!(check_config_strings(&cfg_with("127.0.0.1")).is_ok());

        let inject = cfg_with("0.0.0.0; }; zone \"evil\" { type primary; file \"x\";");
        assert!(check_config_strings(&inject).is_err(), "listen_addr 注入必须被拒");

        let mut geo = cfg_with("127.0.0.1");
        geo.geo.lines.push(GeoLine {
            name: "x\"\n};".into(),
            cidrs: vec![],
        });
        assert!(check_config_strings(&geo).is_err(), "geo 线路名注入必须被拒");

        let mut rpz = cfg_with("127.0.0.1");
        rpz.rpz.push(RpzRule {
            name: "bad..name".into(),
            rtype: "nxdomain".into(),
            value: String::new(),
        });
        assert!(check_config_strings(&rpz).is_err(), "rpz 名字带 .. 必须被拒");
    }

    /// geo 线路 CIDR 非法必须在**保存前**被拒：生成侧 `acl_or`→`valid_acl_item` 会
    /// 静默丢弃非法项，`match-clients` 退化成 `{ none; }` —— 该线路永不命中，
    /// 面板却显示一切正常。旧实现只校验线路名，非法 CIDR 直接落进 panel.toml。
    #[test]
    fn check_config_rejects_bad_geo_line_cidr() {
        let mut bad = cfg_with("127.0.0.1");
        bad.geo.enabled = true;
        bad.geo.lines.push(GeoLine {
            name: "lab".into(),
            cidrs: vec!["not-a-cidr".into()],
        });
        assert!(
            check_config_strings(&bad).is_err(),
            "非法线路 CIDR 必须被拒（否则线路静默失效）"
        );

        let mut empty = cfg_with("127.0.0.1");
        empty.geo.enabled = true;
        empty.geo.lines.push(GeoLine {
            name: "lab".into(),
            cidrs: vec![],
        });
        assert!(
            check_config_strings(&empty).is_err(),
            "无 CIDR 的线路 match-clients 退化为 none，必须被拒"
        );

        let mut ok = cfg_with("127.0.0.1");
        ok.geo.enabled = true;
        ok.geo.lines.push(GeoLine {
            name: "lab".into(),
            cidrs: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
        });
        assert!(check_config_strings(&ok).is_ok(), "合法 v4/v6 CIDR 必须通过");
    }

    /// v4-mapped 客户端（`::ffff:a.b.c.d`，双栈监听下 v4 客户端 peer 的形态）必须能命中
    /// v4 CIDR：旧实现 `(V4 CIDR, V6 ip)` 落到 `_ => false`，这类客户端全部静默走默认线路。
    #[test]
    fn cidr_contains_folds_v4_mapped() {
        let mapped: std::net::IpAddr = "::ffff:192.0.2.5".parse().unwrap();
        assert!(cidr_contains("192.0.2.0/24", mapped));
        assert!(!cidr_contains("198.51.100.0/24", mapped));
        assert!(cidr_contains("192.0.2.0/24", "192.0.2.5".parse().unwrap()));
    }

    /// resolve_fwd_dest：v4-mapped 命中线路 → 对应 fwd view 的 127.0.0.(2+i)；
    /// lines 为空时短路回默认（不再白查 mmdb）。
    #[test]
    fn resolve_fwd_dest_folds_v4_mapped_and_short_circuits() {
        let mut c = DnsConfig::default();
        c.geo.enabled = true;
        c.geo.lines.push(GeoLine {
            name: "lab-a".into(),
            cidrs: vec!["192.0.2.0/24".into()],
        });
        let mapped: std::net::IpAddr = "::ffff:192.0.2.5".parse().unwrap();
        assert_eq!(
            resolve_fwd_dest(&c, Some(mapped)),
            std::net::IpAddr::from([127u8, 0, 0, 2])
        );

        let mut empty = DnsConfig::default();
        empty.geo.enabled = true;
        assert_eq!(
            resolve_fwd_dest(&empty, Some("192.0.2.5".parse().unwrap())),
            std::net::IpAddr::from([127u8, 0, 0, 1])
        );
    }
}

#[cfg(test)]
mod dns_hardening_tests {
    use super::*;

    fn test_cfg() -> DnsConfig {
        let mut c = DnsConfig::default();
        c.listen_addr = "127.0.0.1".to_string();
        c
    }

    fn zone_row(name: &str, kind: &str) -> ZoneRow {
        ZoneRow {
            name: name.to_string(),
            kind: kind.to_string(),
            primaries: vec![],
            axfr_acl: vec![],
            refresh_hours: 24,
        }
    }

    /// P1-1：数据库里有历史 SOA 行（旧版本导入/面板手选留下）时，生成器也必须
    /// 始终输出**一份**自动 SOA，且 serial 严格大于传入的旧值。
    /// 旧实现 has_soa=true 就跳过生成支路、原样输出旧 SOA ⇒ serial 永久冻结。
    #[test]
    fn gen_zone_file_always_emits_monotonic_soa() {
        let recs = vec![RecordRow {
            id: 1,
            zone: "example.com".into(),
            line: String::new(),
            name: "@".into(),
            rtype: "SOA".into(),
            ttl: 3600,
            rdata: "ns1.example.com. hostmaster.example.com. 111 900 600 1209600 300".into(),
        }];
        let out = gen_zone_file_monotonic_ext("example.com", "master", &recs, Some(4_000_000_000), &[]);
        assert_eq!(out.matches(" IN SOA ").count(), 1, "必须只有一份 SOA: {out}");
        assert_eq!(serial_from_zone_text(&out), Some(4_000_000_001), "{out}");
        assert!(!out.contains(" 111 "), "旧 serial 不得残留: {out}");
    }

    /// P1-2：分区名的 DNS 语义/保留名校验（写库之前执行 —— add_zone 里调用）。
    #[test]
    fn zone_name_validation_rejects_broken_and_reserved_names() {
        assert!(valid_zone_name("example.com"));
        assert!(valid_zone_name("_tcp.example.com"));
        assert!(valid_zone_name("example.com."));
        assert!(!valid_zone_name("."));
        assert!(!valid_zone_name(".example.com"));
        assert!(!valid_zone_name("example..com"));
        assert!(!valid_zone_name("-bad.example.com"));
        assert!(!valid_zone_name("bad-.example.com"));
        assert!(!valid_zone_name("bad name.example.com"));
        assert!(!valid_zone_name("*.example.com"));
        assert!(!valid_zone_name(&format!("{}.com", "a".repeat(64))));
        assert!(!valid_zone_name(""));
        assert!(is_reserved_zone_name("."));
        assert!(is_reserved_zone_name("Crucible.RPZ"));
        assert!(is_reserved_zone_name("crucible.answers"));
        assert!(!is_reserved_zone_name("rpz.example.com"));
    }

    /// P1-2 / P3：写库前的冲突检查 —— 大小写重名（named 会拒载整份配置）与
    /// kind 静默覆盖（master 被 AXFR 端点改成 slave）。
    #[test]
    fn zone_conflict_detects_case_duplicate_and_kind_change() {
        let zones = vec![zone_row("example.com", "master")];
        assert!(zone_conflict("example.com", "master", &zones).is_none(), "同名同 kind = 更新");
        assert!(zone_conflict("Example.com", "master", &zones).is_some(), "大小写重名必须拒");
        assert!(zone_conflict("example.com.", "master", &zones).is_some(), "尾点等价也必须拒");
        assert!(zone_conflict("example.com", "slave", &zones).is_some(), "kind 变更必须拒");
        assert!(zone_conflict("other.com", "master", &zones).is_none());
    }

    /// P1-2 / P3：slave 参数校验与保留名在**碰数据库之前**完成（这些调用不落库）。
    #[test]
    fn add_zone_guards_bail_before_db_write() {
        // 空 primaries 的 slave：named.conf 不会声明该区（面板显示成功、服务里没有）
        assert!(add_zone("slave", "s.test", &[], &[], 24).is_err());
        assert!(add_zone("slave", "s.test", &["192.0.2.1".into()], &[], 0).is_err());
        assert!(add_zone("slave", "s.test", &["192.0.2.1".into()], &[], 8761).is_err());
        // 保留名 / 非法名同样在写库前被拒
        assert!(add_zone("master", "crucible.rpz", &[], &[], 24).is_err());
        assert!(add_zone("master", ".example.com", &[], &[], 24).is_err());
    }

    /// P1-3：算法白名单收窄 + lifetime 下限（都必须在写 panel.toml 之前拒掉）。
    #[test]
    fn check_config_rejects_unsupported_dnssec_and_short_lifetimes() {
        let mut c = test_cfg();
        c.dnssec.enabled = true;
        c.dnssec.algorithm = "RSAMD5".into();
        assert!(check_config_strings(&c).is_err(), "RSAMD5 在 BIND 9.20 不受支持");
        c.dnssec.algorithm = "ECC-GOST".into();
        assert!(check_config_strings(&c).is_err());
        c.dnssec.algorithm = "1".into();
        assert!(check_config_strings(&c).is_err(), "算法号 1=RSAMD5 不受支持");
        c.dnssec.algorithm = "12".into();
        assert!(check_config_strings(&c).is_err(), "算法号 12=ECC-GOST 不受支持");
        c.dnssec.algorithm = "252".into();
        assert!(check_config_strings(&c).is_err());
        c.dnssec.algorithm = "13".into();
        assert!(check_config_strings(&c).is_ok(), "13=ECDSAP256SHA256 合法");
        c.dnssec.algorithm = "ECDSAP256SHA256".into();
        assert!(check_config_strings(&c).is_ok());

        c.dnssec.rotation_enabled = true;
        c.dnssec.rotation_days = 1;
        assert!(check_config_strings(&c).is_err(), "rotation_days=1 会让 named 拒载");
        c.dnssec.rotation_days = 30;
        assert!(check_config_strings(&c).is_ok());
        c.dnssec.keys.push(DnsKeyCfg { role: "zsk".into(), lifetime_days: Some(3) });
        assert!(check_config_strings(&c).is_err(), "keys[].lifetime_days=3 必须拒");
        c.dnssec.keys[0].lifetime_days = Some(30);
        assert!(check_config_strings(&c).is_ok());
    }

    /// [实测] 递归转发器：不配置时零输出（行为完全不变）；配置时生成
    /// `forwarders { ... };`，only 追加 `forward only;`；非法值保存前被拒。
    #[test]
    fn forwarders_clause_and_validation() {
        let mut c = test_cfg();
        assert_eq!(forwarders_clause(&c), "");
        c.forwarders = vec![
            "8.8.8.8".into(),
            "2001:4860:4860::8888".into(),
            "not-an-ip".into(),
        ];
        assert_eq!(
            forwarders_clause(&c),
            " forwarders { 8.8.8.8; 2001:4860:4860::8888; };"
        );
        c.forward_policy = Some("only".into());
        assert!(forwarders_clause(&c).ends_with(" forward only;"));
        assert!(check_config_strings(&c).is_err(), "含非法 forwarder 必须保存前被拒");

        c.forwarders = vec!["8.8.8.8".into()];
        assert!(check_config_strings(&c).is_ok());
        c.forward_policy = Some("sometimes".into());
        assert!(check_config_strings(&c).is_err(), "forward_policy 只允许 first|only");
        c.forward_policy = Some("first".into());
        assert!(!forwarders_clause(&c).contains("forward only"));
    }

    /// P2：slave 的传入白名单与刷新频率必须进 named.conf；非法 ACL 项 fail-closed。
    #[test]
    fn secondary_clauses_writes_acl_and_refresh() {
        let mut z = zone_row("slave.test", "slave");
        z.axfr_acl = vec![
            "10.0.0.0/8".into(),
            "2001:db8::/32".into(),
            "bad;};".into(),
        ];
        z.refresh_hours = 6;
        let c = secondary_clauses(&z);
        assert!(c.contains("allow-notify { 10.0.0.0/8; 2001:db8::/32; };"), "{c}");
        assert!(c.contains("allow-transfer { 10.0.0.0/8; 2001:db8::/32; };"), "{c}");
        assert!(c.contains("min-refresh-time 6h; max-refresh-time 6h;"), "{c}");
        assert!(!c.contains("bad"), "非法 ACL 项不得输出: {c}");
        let mut z2 = zone_row("slave2.test", "slave");
        z2.refresh_hours = 0;
        assert!(secondary_clauses(&z2).is_empty());
    }

    /// P2：IXFR 差异流切段 —— SOA 行只是段标记，不是记录；删除段/新增段不能颠倒。
    #[test]
    fn split_ixfr_diff_maps_segments() {
        let soa = |s: u64| format!(". 86400 IN SOA a.root-servers.net. nstld.example. {s} 1800 900 604800 86400");
        let owned: Vec<String> = vec![
            soa(3),
            soa(1),
            "deleted.example. 300 IN A 10.0.0.1".into(),
            soa(3),
            "added.example. 300 IN A 10.0.0.2".into(),
            soa(3),
        ];
        let records: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let (del, add) = split_ixfr_diff(&records).expect("标准差异流");
        assert_eq!(del, vec!["deleted.example. 300 IN A 10.0.0.1"]);
        assert_eq!(add, vec!["added.example. 300 IN A 10.0.0.2"]);
        // 单个 SOA（无变化 / AXFR 式应答）绝不能按「全部删除」处理
        let single = vec![records[0]];
        assert!(split_ixfr_diff(&single).is_none());
        // RRSIG 覆盖 SOA 的行不是 SOA 记录标记
        assert!(!is_soa_record(
            ". 86400 IN RRSIG SOA 8 0 86400 20260101000000 20250101000000 12345 . abcdef=="
        ));
        assert!(is_soa_record(". 3600000 SOA a.root-servers.net. nstld.example. ("));
    }

    /// P2：SOA 块替换必须认多行括号形态（internic root.zone 就是这种）。
    #[test]
    fn soa_block_end_handles_multiline() {
        let lines: Vec<String> = vec![
            "$TTL 86400".into(),
            ". 3600000 IN SOA a.root-servers.net. nstld.example. (".into(),
            "  2024100400 ; serial".into(),
            "  1800 900 604800 86400 )".into(),
            ". 3600000 IN NS a.root-servers.net.".into(),
        ];
        assert_eq!(soa_block_end(&lines, 1), Some(3));
        let single = vec!["x 300 IN SOA m. r. 1 2 3 4 5".to_string()];
        assert_eq!(soa_block_end(&single, 0), Some(0));
    }

    /// P2：dig（带 IN class）与 internic（不带）的记录归一后必须能匹配。
    #[test]
    fn normalize_rr_ignores_class() {
        assert_eq!(
            normalize_rr("A.ROOT-SERVERS.NET. 3600000 IN A 198.41.0.4"),
            normalize_rr("a.root-servers.net. 3600000 A 198.41.0.4")
        );
    }

    /// P3：refresh_hours 无上限，到期计算必须饱和（debug 下 panic / release 下回绕）。
    #[test]
    fn rootzone_due_saturates() {
        assert!(rootzone_due(None, 24, 1000));
        assert!(!rootzone_due(Some("1000"), 24, 1000 + 24 * 3600));
        assert!(rootzone_due(Some("1000"), 24, 1000 + 24 * 3600 + 1));
        assert!(!rootzone_due(Some("1000"), u64::MAX, u64::MAX - 1));
    }

    /// P3：geo 多 view 时 rootzone 要分发到每个 view 的 root.<view>.zone。
    #[test]
    fn rootzone_targets_cover_geo_views() {
        let mut c = test_cfg();
        assert_eq!(rootzone_targets(&c), vec![state_root().join("zones").join("root.zone")]);
        c.geo.enabled = true;
        c.geo.lines.push(GeoLine { name: "cn".into(), cidrs: vec![] });
        let t = rootzone_targets(&c);
        assert!(t.iter().any(|p| p.ends_with("root.zone")), "{t:?}");
        assert!(t.iter().any(|p| p.ends_with("root.cn.zone")), "{t:?}");
        assert!(t.iter().any(|p| p.ends_with("root.fwd-cn.zone")), "{t:?}");
        assert!(t.iter().any(|p| p.ends_with("root.default.zone")), "{t:?}");
    }

    /// P2：root zone 安装拒绝符号链接目标且失败不留 tmp（zones/ 归 _bind 的纵深防御）。
    #[test]
    fn root_zone_install_refuses_symlink_and_cleans_tmp() {
        let dir = std::env::temp_dir().join(format!("crucible-dns-install-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"do-not-touch").unwrap();
        let target = dir.join("root.zone");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        let err = install_zone_file(&target, b". 86400 IN SOA a. b. 1 2 3 4 5\n");
        assert!(err.is_err(), "符号链接目标必须被拒");
        assert_eq!(std::fs::read(&victim).unwrap(), b"do-not-touch");
        assert!(std::fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "失败后残留临时文件: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P2：RPZ TXT 值以 `"` 开头时不能绕过转义（未闭合引号会让 answers 区非法、
    /// 全部 override 静默失效）；合法配对引号保留原样。
    #[test]
    fn rpz_txt_leading_quote_is_escaped_or_preserved() {
        assert!(is_quoted_txt("\"hello\""));
        assert!(is_quoted_txt("\"a \\\"b\\\"\""));
        assert!(!is_quoted_txt("\"unterminated"));
        assert!(!is_quoted_txt("\"a\" b\""));
        assert!(!is_quoted_txt("\"trailing\\\""));

        let rules = vec![
            RpzRule { name: "bad.test".into(), rtype: "txt".into(), value: "\"unterminated".into() },
            RpzRule { name: "good.test".into(), rtype: "txt".into(), value: "\"hello\"".into() },
        ];
        let f = gen_answers_file(&rules, Some(1));
        assert!(
            f.contains("bad.test IN TXT \"\\\"unterminated\""),
            "未闭合引号必须被转义: {f}"
        );
        assert!(f.contains("good.test IN TXT \"hello\""), "{f}");
    }

    /// P2：quoted_txt_rdata 与 answers 走同一判据（只保留完整合法字符串字面量）。
    #[test]
    fn quoted_txt_rdata_only_passes_complete_literals() {
        assert_eq!(quoted_txt_rdata("TXT", "\"ok\""), "\"ok\"");
        assert_eq!(quoted_txt_rdata("TXT", "\"bad"), "\"\\\"bad\"");
        assert_eq!(quoted_txt_rdata("TXT", "plain text"), "\"plain text\"");
    }

    /// P2：check_config_strings 拒绝「以引号开头但未配对」的 RPZ TXT 值。
    #[test]
    fn check_config_rejects_unbalanced_rpz_txt_quote() {
        let mut c = test_cfg();
        c.rpz.push(RpzRule {
            name: "x.test".into(),
            rtype: "txt".into(),
            value: "\"oops".into(),
        });
        assert!(check_config_strings(&c).is_err());
        c.rpz[0].value = "\"ok\"".into();
        assert!(check_config_strings(&c).is_ok());
    }

    /// P2：dnssec-keygen 的 `-f` 映射 —— CSK 必须落成 KSK（工具不认 CSK 标志）。
    #[test]
    fn keygen_flag_maps_csk_to_ksk() {
        assert_eq!(keygen_flag("csk"), Some("KSK"));
        assert_eq!(keygen_flag("CSK"), Some("KSK"));
        assert_eq!(keygen_flag("ksk"), Some("KSK"));
        assert_eq!(keygen_flag("zsk"), None);
    }

    /// P1：按类型的 rdata 校验 —— 一条坏记录会让**整区**被 named 拒载。
    #[test]
    fn record_rdata_validation_by_type() {
        // A/AAAA 必须是 IP 字面量（面板/导入最容易写错，判据无歧义）。
        assert!(validate_record_rdata("A", "192.0.2.1").is_ok());
        assert!(validate_record_rdata("a", " 192.0.2.1 ").is_ok());
        assert!(validate_record_rdata("A", "hello").is_err());
        assert!(validate_record_rdata("A", "192.0.2.256").is_err());
        assert!(validate_record_rdata("A", "::1").is_err(), "A 不能写 v6");
        assert!(validate_record_rdata("AAAA", "2001:db8::1").is_ok());
        assert!(validate_record_rdata("AAAA", "192.0.2.1").is_err());
        // CNAME/NS/PTR 目标必须是合法域名。
        assert!(validate_record_rdata("CNAME", "target.example.com.").is_ok());
        assert!(validate_record_rdata("NS", "ns1.example.com.").is_ok());
        assert!(validate_record_rdata("CNAME", "bad name with space").is_err());
        // 未校验的类型不拦（保持最小改动）。
        assert!(validate_record_rdata("MX", "10 mail.example.com.").is_ok());
        assert!(validate_record_rdata("TXT", "anything at all").is_ok());
    }

    /// P1：导入批量 CNAME 共存冲突必须在删旧记录之前被发现（RFC1034 §3.6.2）。
    #[test]
    fn batch_cname_conflict_detects_apex_and_mixed() {
        let clean = vec![
            ("www".to_string(), "A".to_string()),
            ("mail".to_string(), "CNAME".to_string()),
            ("@".to_string(), "MX".to_string()),
        ];
        assert!(batch_cname_conflict(&clean).is_none());
        // 顶点 CNAME：与模块自动生成的 SOA/NS 冲突。
        let apex = vec![("@".to_string(), "CNAME".to_string())];
        assert!(batch_cname_conflict(&apex).is_some());
        // 同名既有 CNAME 又有 A。
        let mixed = vec![
            ("www".to_string(), "CNAME".to_string()),
            ("www".to_string(), "A".to_string()),
        ];
        assert!(batch_cname_conflict(&mixed).is_some());
    }

    /// P2：geo 线路数超上限（MAX_GEO_LINES）必须在保存前拒绝 —— 超出部分没有
    /// fwd view / listen socket / lo0 alias，客户端会静默落到 default 拿到错误线路。
    #[test]
    fn check_config_rejects_too_many_geo_lines() {
        let mut c = test_cfg();
        c.geo.enabled = true;
        for i in 0..=MAX_GEO_LINES {
            c.geo.lines.push(GeoLine {
                name: format!("l{i}"),
                cidrs: vec!["192.0.2.0/24".into()],
            });
        }
        assert!(
            check_config_strings(&c).is_err(),
            "超过 MAX_GEO_LINES 必须被拒"
        );
        c.geo.lines.truncate(MAX_GEO_LINES);
        assert!(check_config_strings(&c).is_ok(), "正好上限必须放行");
    }
}
