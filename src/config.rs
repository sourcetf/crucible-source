//! Configuration model parsed from `config.toml`.
//!
//! §16.2: `file_open` 必须序列化为 listener 内联 `["/path=mode", ...]`，
//! 禁止 `[listeners.file_open]` 挂到错误 listener。

use anyhow::{Context, Result};
// DNS 模块类型 re-export（dot_doh / h1 / admin_api 经 crate::config 引用）
pub use crate::server::dns::{DnsConfig, DohCfg, DotCfg};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub access_log: AccessLogConfig,
    #[serde(default)]
    pub ip_access: IpAccessConfig,
    #[serde(default)]
    pub syncookie: SyncookieConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub tor_hs: TorHsConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_telemetry_path")]
    pub path: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_telemetry_path(),
        }
    }
}

fn default_telemetry_path() -> String {
    "/__metrics".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rate_per_sec")]
    pub rate_per_sec: f64,
    #[serde(default = "default_rate_burst")]
    pub burst: f64,
    /// When true, bucket key includes request path prefix (per-path limiting).
    #[serde(default)]
    pub per_path: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rate_per_sec: default_rate_per_sec(),
            burst: default_rate_burst(),
            per_path: false,
        }
    }
}

fn default_rate_per_sec() -> f64 {
    100.0
}

fn default_rate_burst() -> f64 {
    200.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    #[serde(default = "default_admin_realm")]
    pub realm: String,
    #[serde(default = "default_admin_path")]
    pub path: String,
    #[serde(default)]
    pub users: Vec<AdminUser>,
    /// P2-21（任务 4）：admin 面板仅在列出的端口可达；空 = 全部 listener 可达
    /// （兼容旧行为）。建议生产配置只列 TLS 端口，避免 Basic 凭据在明文口暴露。
    #[serde(default)]
    pub listeners_allow: Vec<u16>,
    /// 任务 3：`/__metrics`（Prometheus 指标）是否允许**匿名**抓取。
    ///
    /// 默认 false = 必须通过管理员 Basic 鉴权（复用 admin 那套口令校验与失败退避），
    /// 否则只回 401 —— 指标里有请求总数/活跃流这类内部信息，不该默认公开。
    /// true 时保持旧行为（公开，但仍排在 ip_access + 限流之后）。
    #[serde(default)]
    pub metrics_public: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            realm: default_admin_realm(),
            path: default_admin_path(),
            users: vec![AdminUser {
                username: default_admin_user(),
                password_hash: String::new(),
            }],
            listeners_allow: Vec::new(),
            metrics_public: false,
        }
    }
}

impl AdminConfig {
    /// P2-21：admin 是否在该端口暴露（listeners_allow 为空 = 全部可达，兼容旧行为）。
    pub fn listener_allowed(&self, port: u16) -> bool {
        self.listeners_allow.is_empty() || self.listeners_allow.contains(&port)
    }

    /// 兼容旧版扁平 `[admin] username/password_hash` 字段。
    pub fn normalize_legacy(&mut self, legacy_user: Option<String>, legacy_hash: Option<String>) {
        if !self.users.is_empty() {
            return;
        }
        if let Some(u) = legacy_user.filter(|s| !s.is_empty()) {
            self.users.push(AdminUser {
                username: u,
                password_hash: legacy_hash.unwrap_or_default(),
            });
        }
    }

    pub fn primary_user(&self) -> Option<&AdminUser> {
        self.users.first()
    }
}

fn default_admin_realm() -> String {
    "WebServer Admin".into()
}
fn default_admin_user() -> String {
    "admin".into()
}
fn default_admin_path() -> String {
    "/__admin".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub realtime: bool,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            enable: true,
            level: default_log_level(),
            realtime: false,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_log_level() -> String {
    "info".into()
}

/// §16.12 **每站（listener）** 访问日志覆盖。字段全部 `Option`，语义是**字段级**继承：
/// 某字段未配 ⇒ 继承全局 `[access_log]`；配了就覆盖该字段。
///
/// 为什么用 `Option` 而不是直接复用 [`AccessLogConfig`]：后者字段有默认值
/// （enable=true/level=info/realtime=false），若直接复用作 listener 字段，
/// 一个只想改 `realtime` 的 listener 会把没写的 `enable` 悄悄重置为默认 `true`
/// —— 全局 `enable=false` 的站点被「加一条覆盖」意外打开。字段级 `Option`
/// 才能表达「未配则继承」。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListenerAccessLogConfig {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub realtime: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpAccessConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncookieConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_syncookie_on")]
    pub value_on: String,
    #[serde(default = "default_syncookie_off")]
    pub value_off: String,
    #[serde(default = "default_syncookie_interval")]
    pub evaluate_interval_ms: u64,
}

impl Default for SyncookieConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            value_on: default_syncookie_on(),
            value_off: default_syncookie_off(),
            evaluate_interval_ms: default_syncookie_interval(),
        }
    }
}

fn default_syncookie_on() -> String {
    "1".into()
}
fn default_syncookie_off() -> String {
    "0".into()
}
fn default_syncookie_interval() -> u64 {
    5000
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub db_path: Option<PathBuf>,
    #[serde(default)]
    pub enabled: bool,
}

/// §18: `autoindex = true` 或 `autoindex = { enabled, paths }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoindexConfig {
    pub enabled: bool,
    pub paths: Vec<String>,
    /// 规格 5：autoindex 开启时可启用界面上传按钮（serde 走下方自定义实现）。
    pub enable_upload: bool,
    /// 上传并行线程数（默认 4，可配）。
    pub upload_threads: u16,
}

fn default_upload_threads() -> u16 {
    4
}

impl Default for AutoindexConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: vec!["/".into()],
            enable_upload: false,
            upload_threads: 4,
        }
    }
}

impl AutoindexConfig {
    pub fn allows(&self, url_path: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if self.paths.is_empty() || self.paths.iter().any(|p| p == "/" || p == "*") {
            return true;
        }
        self.paths
            .iter()
            .any(|p| url_path == p || url_path.starts_with(&format!("{}/", p.trim_end_matches('/'))))
    }
}

impl<'de> Deserialize<'de> for AutoindexConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum De {
            Bool(bool),
            Table {
                #[serde(default)]
                enabled: bool,
                #[serde(default)]
                paths: Vec<String>,
                #[serde(default)]
                enable_upload: bool,
                #[serde(default = "default_upload_threads")]
                upload_threads: u16,
            },
        }
        match De::deserialize(deserializer)? {
            De::Bool(b) => Ok(Self {
                enabled: b,
                paths: vec!["/".into()],
                enable_upload: false,
                upload_threads: 4,
            }),
            De::Table { enabled, paths, enable_upload, upload_threads } => Ok(Self {
                enabled,
                paths: if paths.is_empty() {
                    vec!["/".into()]
                } else {
                    paths
                },
                enable_upload,
                upload_threads: upload_threads.max(1),
            }),
        }
    }
}

impl Serialize for AutoindexConfig {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.paths == ["/".to_string()] {
            serializer.serialize_bool(self.enabled)
        } else {
            #[derive(serde::Serialize)]
            struct T<'a> {
                enabled: bool,
                paths: &'a [String],
                #[serde(default)]
                enable_upload: bool,
                #[serde(default)]
                upload_threads: u16,
            }
            T {
                enabled: self.enabled,
                paths: &self.paths,
                enable_upload: self.enable_upload,
                upload_threads: self.upload_threads,
            }
            .serialize(serializer)
        }
    }
}

/// URL path / legacy extension → open mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileOpenTable(BTreeMap<String, FileOpenMode>);

impl FileOpenTable {
    pub fn mode_for_path(&self, req_path: &str) -> FileOpenMode {
        let key = normalize_path_key(req_path);
        if let Some(m) = self.0.get(&key) {
            return *m;
        }
        let trimmed = key.trim_end_matches('/');
        if trimmed != key {
            if let Some(m) = self.0.get(trimmed) {
                return *m;
            }
        }
        if let Some(ext) = Path::new(&key)
            .extension()
            .and_then(|e| e.to_str())
            .filter(|e| !e.is_empty())
            .map(|e| e.to_ascii_lowercase())
        {
            if let Some(m) = self.0.get(&ext) {
                return *m;
            }
            if let Some(m) = self.0.get(&format!(".{ext}")) {
                return *m;
            }
        }
        self.0.get("*").copied().unwrap_or(FileOpenMode::Auto)
    }

    pub fn insert(&mut self, key: impl AsRef<str>, mode: FileOpenMode) {
        self.0.insert(store_key(key.as_ref()), mode);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn normalize_path_key(path: &str) -> String {
    let p = path.trim();
    if p.is_empty() {
        return "/".into();
    }
    // 必须与 static_files::resolve_path 的解析方式保持一致：那边是
    // 「去掉全部前导 '/' → percent-decode → join」。只做 trim 的话，
    // `//uploads/x.html`、`/uploads/./x.html`、`/uploads/x%2Ehtml`
    // 都会查不到 file_open 表（落到 Auto = 按真实 MIME 内联返回），
    // 而文件本身照样被解析并送出 —— 管理员配的 preview/download 被绕过。
    let decoded = percent_encoding::percent_decode_str(p.trim_start_matches('/'))
        .decode_utf8_lossy()
        .to_string();
    let mut parts: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        return "/".into();
    }
    format!("/{}", parts.join("/"))
}

/// file_open 表里键的归一化：路径键走 [`normalize_path_key`]，扩展名键（`html`、`.html`）
/// 与通配 `*` 原样保留（但折叠大小写——`mime_guess` 不区分大小写，`/x.PHP` 照样会被
/// 按 php 处理，若键不折叠就查不到 `php` 规则）。
fn store_key(k: &str) -> String {
    let k = k.trim();
    if k.contains('/') {
        normalize_path_key(k)
    } else {
        k.to_ascii_lowercase()
    }
}

mod file_open_serde {
    use super::*;
    use serde::de::Error;

    #[derive(Deserialize)]
    struct Entry {
        path: String,
        mode: FileOpenMode,
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<FileOpenTable, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum De {
            Inline(Vec<String>),
            Entries(Vec<Entry>),
            Map(BTreeMap<String, FileOpenMode>),
        }
        let table = match De::deserialize(deserializer)? {
            De::Inline(rows) => parse_inline_rows(&rows).map_err(D::Error::custom)?,
            De::Entries(entries) => {
                let mut m = BTreeMap::new();
                for e in entries {
                    m.insert(store_key(&e.path), e.mode);
                }
                m
            }
            De::Map(m) => m.into_iter().map(|(k, v)| (store_key(&k), v)).collect(),
        };
        Ok(FileOpenTable(table))
    }

    pub fn serialize<S>(table: &FileOpenTable, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut rows: Vec<String> = table
            .0
            .iter()
            .map(|(k, v)| format!("{k}={}", mode_str(*v)))
            .collect();
        rows.sort();
        let mut seq = serializer.serialize_seq(Some(rows.len()))?;
        for row in rows {
            seq.serialize_element(&row)?;
        }
        seq.end()
    }

    fn parse_inline_rows(rows: &[String]) -> Result<BTreeMap<String, FileOpenMode>> {
        let mut m = BTreeMap::new();
        for row in rows {
            let (k, v) = row
                .split_once('=')
                .with_context(|| format!("invalid file_open entry: {row}"))?;
            m.insert(store_key(k), parse_mode(v.trim())?);
        }
        Ok(m)
    }

    fn parse_mode(s: &str) -> Result<FileOpenMode> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(FileOpenMode::Auto),
            "preview" => Ok(FileOpenMode::Preview),
            "download" => Ok(FileOpenMode::Download),
            "execute" => Ok(FileOpenMode::Execute),
            other => anyhow::bail!("unknown file_open mode: {other}"),
        }
    }

    fn mode_str(m: FileOpenMode) -> &'static str {
        match m {
            FileOpenMode::Auto => "auto",
            FileOpenMode::Preview => "preview",
            FileOpenMode::Download => "download",
            FileOpenMode::Execute => "execute",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub address: String,
    pub port: u16,
    pub root: PathBuf,
    #[serde(default)]
    pub ssl: Option<SslConfig>,
    #[serde(default)]
    pub apps: Vec<AppRouteConfig>,
    #[serde(default, with = "file_open_serde")]
    pub file_open: FileOpenTable,
    #[serde(default)]
    pub autoindex: AutoindexConfig,
    #[serde(default = "default_http_versions")]
    pub http_versions: Vec<String>,
    #[serde(default)]
    pub basic_auth: Option<BasicAuthConfig>,
    #[serde(default)]
    pub proxy_rules: Vec<ProxyRuleConfig>,
    #[serde(default)]
    pub page_rules: Vec<PageRuleConfig>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub status_path: Option<String>,
    #[serde(default)]
    pub address_v6: Option<String>,
    #[serde(default)]
    pub port_reuse: bool,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// §16.1：**每 listener 独立**的 IP 访问控制。
    ///
    /// 此前 `ListenerConfig` **没有**这个字段，于是 `[listeners.ip_access]`（规格 §16.1
    /// 明确要求 per-listener）被 serde **静默忽略** —— 配置看着像生效、实际只用全局
    /// `[ip_access]`（验收 agent 黑盒复现：listener 配 `allow = ["10.0.0.0/8"]`，从
    /// 127.0.0.1 访问仍回 200）。
    ///
    /// 语义：`None` = 只用全局 `[ip_access]`（旧行为，零变化）；`Some` = 该 listener
    /// 在全局档位之上**再收窄**（两份都要放行才放行，见 `server::listener::ip_allowed`）。
    /// 收窄而非覆盖，是为了「全局白名单 + 个别 listener 再加一道」符合直觉，也避免某个
    /// listener 少配一处就把全局策略整体放宽。
    #[serde(default)]
    pub ip_access: Option<IpAccessConfig>,
    /// §16.18 L4 不透明转发：配置后整条连接双向透传（不做 HTTP/TLS 解析）。
    #[serde(default)]
    pub l4_forward: Option<String>,
    /// TASK2：该 listener 的 QUIC/UDP socket 是否做 ECN 的 socket 级设置与启动校验
    /// （默认关）。
    ///
    /// 打开后：重设入向 `IP_RECVTOS` / `IPV6_RECVTCLASS`（让入向码点可观测，
    /// 对 macOS 双栈 socket 有用），并把该 socket 的当前 ECN 状态写进启动日志。
    ///
    /// 注意：**它不改变 ECN 是否生效**——quinn 的传输层 ECN 本来就默认开着
    /// （`sending_ecn = true`），出向标记是 quinn-udp 的 per-packet cmsg。
    /// 本开关只是把「这台机器上到底开没开」变成可观测的，见 `server/ecn.rs` 文件头。
    /// 默认关是因为它不带来行为变化，属于运维核查项而不是功能开关。
    #[serde(default)]
    pub quic_ecn: bool,
    /// 是否在该监听器上提供 **QMux v1**（`draft-ietf-quic-qmux-02`）。
    ///
    /// QMux 在一条双向字节流（本实现：TLS over TCP）上复用出多条逻辑流。本实现服务的是
    /// **HTTP/1.1 over QMux**，因此要求 `http_versions` 含 `h1`（配置校验会拦）。
    ///
    /// * TLS 监听器：ALPN 里加入 `h1-02qx`（见 `qmux::conn::QMUX_ALPN`）。服务端偏好仍是
    ///   h2 > http/1.1 > h1-02qx ⇒ **只提供旧协议的客户端行为不变**；想要 QMux 的客户端
    ///   在 ALPN 里只给 `h1-02qx`。
    /// * 明文监听器：按草案 §10.1，用首 8 字节的协议魔数（`\xffQMX\r\n\r\n`）识别 ——
    ///   与既有的 h2 prior-knowledge 嗅探同一条路径。
    ///
    /// 默认 **false**：不开就没有这个协议面（零行为变化）。
    #[serde(default)]
    pub qmux: bool,
    /// 是否在该监听器上提供 **CONNECT-UDP（RFC 9298 / MASQUE）中继**。
    ///
    /// 打开后，H3 客户端可以用 `:protocol = connect-udp` + `:path = /<IP>:<端口>`
    /// 让本服务代它收发 UDP。**这是公网的 UDP 中继面**：内网/环回/链路本地/ULA/CGNAT/
    /// NAT64/6to4/Teredo 等地址一律拒绝（`server::connect_udp::is_disallowed_ip`），
    /// 所以不构成 SSRF、也不能用来放大（响应只回隧道给发起者）；但它是**流量洗白/
    /// 匿名代理**面，等于用本机 IP 去打第三方 UDP 服务。
    ///
    /// 默认 **false** 的理由和其它「开了就对外服务」的项一致（proxy 要显式规则、
    /// 上传要 autoindex+enable_upload）：中继面对运维必须是**显式**决定，
    /// 而不是不配任何东西就存在。开启时建议同时配 `ip_access` / basic_auth。
    #[serde(default)]
    pub connect_udp: bool,
    /// §16.12 **每站（listener）** 访问日志覆盖（enable/level/realtime）。
    ///
    /// `None` = 完全继承全局 `[access_log]`（旧配置零变化）；`Some` = 逐字段覆盖
    /// （未写的字段继承全局）。此前访问日志**只有全局**，`[listeners.access_log]`
    /// 会被 serde 静默忽略。判定入口见 `server::access_log::log_response`。
    #[serde(default)]
    pub access_log: Option<ListenerAccessLogConfig>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".into(),
            port: 0,
            root: PathBuf::from("."),
            ssl: None,
            apps: Vec::new(),
            file_open: FileOpenTable::default(),
            autoindex: AutoindexConfig::default(),
            http_versions: default_http_versions(),
            basic_auth: None,
            proxy_rules: Vec::new(),
            page_rules: Vec::new(),
            server_name: None,
            status_path: None,
            address_v6: None,
            port_reuse: false,
             rate_limit: None,
            ip_access: None,
            l4_forward: None,
            quic_ecn: false,
            qmux: false,
            connect_udp: false,
            access_log: None,
        }
    }
}

impl ListenerConfig {
    pub fn file_open_mode(&self, req_path: &str) -> FileOpenMode {
        self.file_open.mode_for_path(req_path)
    }

    pub fn allows_h1(&self) -> bool {
        self.http_versions
            .iter()
            .any(|v| v.eq_ignore_ascii_case("h1") || v.eq_ignore_ascii_case("http/1.1"))
    }

    pub fn allows_h2(&self) -> bool {
        self.http_versions
            .iter()
            .any(|v| v.eq_ignore_ascii_case("h2") || v.eq_ignore_ascii_case("http/2"))
    }

    pub fn allows_h3(&self) -> bool {
        self.http_versions
            .iter()
            .any(|v| v.eq_ignore_ascii_case("h3") || v.eq_ignore_ascii_case("http/3"))
    }
}

fn default_http_versions() -> Vec<String> {
    vec!["h1".into(), "h2".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    // serde alias：规格 §18 的样例写作 `certificate` / `private_key`，
    // 而内部字段名是 cert/key。没有别名时 serde 会**静默忽略**这两个键，
    // 结果是「按规格书写了 TLS 配置，运行期却被当成未配置证书 → 明文 HTTP」。
    #[serde(default, alias = "certificate")]
    pub cert: Option<String>,
    #[serde(default, alias = "private_key")]
    pub key: Option<String>,
    #[serde(default)]
    pub cert_ec: Option<String>,
    #[serde(default)]
    pub key_ec: Option<String>,
    #[serde(default)]
    pub versions: Vec<String>,
    /// §18 规格样例写法：`min_version = "1.2"`（与 `max_version = "1.3"` 组成版本区间）。
    /// 与 `versions` 等价但更符合运维直觉；两者同时出现时以显式的 `versions` 为准。
    #[serde(default)]
    pub min_version: Option<String>,
    /// §18：版本区间上界（含）。缺省表示不限制上界。
    #[serde(default)]
    pub max_version: Option<String>,
    #[serde(default)]
    pub ciphers: Vec<String>,
    #[serde(default)]
    pub prefer_tls13: bool,
    #[serde(default)]
    pub ech: bool,
    /// ECH config / keys PEM (path or inline); used by BoringSSL when `ech = true`.
    #[serde(default)]
    pub ech_keys: Option<String>,
    #[serde(default)]
    pub psk: bool,
    /// P1-10：TLS-PSK 身份（配置后严格匹配客户端 identity；空=接受任意 identity）。
    #[serde(default)]
    pub psk_identity: Option<String>,
    /// P1-10：PSK 材料（偶长 hex / base64 / 文件路径）；优先于 CRUCIBLE_TLS_PSK 环境变量。
    #[serde(default)]
    pub psk_key: Option<String>,
    /// P1-8：OCSP stapling DER 文件路径（leaf+issuer 链生成；支持 PEM 自动剥壳；空=关闭）。
    #[serde(default)]
    pub ocsp_der_path: Option<String>,
    /// Enable post-quantum hybrid group X25519MLKEM768 (BoringSSL default when groups empty).
    #[serde(default)]
    pub pqc: bool,
    /// Explicit TLS 1.3 group list (`:`-separated names, e.g. `X25519MLKEM768:X25519:P-256`).
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub enable_nss: bool,
    #[serde(default)]
    pub enable_tomcrypt: bool,
    /// §1a：SNI 仅匹配模式——不回落证书，直接 421 Misdirected Request。
    #[serde(default)]
    pub sni_only: bool,
    /// §1a：指定 SNI 名称（精确字符串），用于 sni_only 模式。
    #[serde(default)]
    pub sni_name: Option<String>,
    /// Early 规格 1a：ECH 自动配置——public-name（对外身份，如 v.qq.com）。
    #[serde(default)]
    pub ech_public_name: Option<String>,
    /// ECH **外层（cover）证书**：客户端不发送 / 未接受 ECH 时，握手退回外层参数，
    /// 客户端按 `ech_public_name` 校验证书 —— 因此需要一张**覆盖 public_name** 的证书。
    ///
    /// 配置后：listener 的**默认证书 = cover**（不带 ECH 的客户端走这条），
    /// 当服务端在 servername 回调里看到的名字**不是** `ech_public_name` 时
    /// （即 ECH 被接受、看到的是解密后的**内层真实名**），切换到 `ssl.cert`/`key` 的真实证书。
    /// 未配置时行为与之前完全一致（只有一张证书）。
    #[serde(default)]
    pub ech_cover_cert: Option<String>,
    /// 配合 [`Self::ech_cover_cert`] 的私钥（两者必须成对，缺失一个即配置错误）。
    #[serde(default)]
    pub ech_cover_key: Option<String>,
    /// **cover 的备用 EC 证书**（P-256 等）。BoringSSL 按客户端的
    /// `signature_algorithms` 在 RSA / EC 证书里选，所以外层必须是**完整的一层**：
    /// 只配 RSA 的 cover 时，一个**只提供 ECDSA** 的*非 ECH* 客户端会落回内层那张 EC
    /// 证书（`ssl.cert_ec`）⇒ 主动探测者换一组 sigalgs 就能确认真实域名，外层形同虚设。
    ///
    /// 因此：**配了 `ssl.cert_ec` 就必须同时配本项**（缺失会被配置期 fail-fast 拦下，
    /// 不做静默降级）。未配 `ssl.cert_ec`（纯 RSA 部署）时本项可省。
    #[serde(default)]
    pub ech_cover_cert_ec: Option<String>,
    /// 配合 [`Self::ech_cover_cert_ec`] 的私钥（两者必须成对）。
    #[serde(default)]
    pub ech_cover_key_ec: Option<String>,
    /// **cover 证书**的 OCSP staple（DER/PEM 路径）。OCSP 响应是**逐证书**的，而 ECH 会在
    /// 内外层证书间切换 ⇒ 两份 staple 必须分开给：`ssl.ocsp_der_path` 属于真实证书
    /// （`ssl.cert`），本项属于 cover。未配置时：cover 路径**不装订**
    /// （不装订是安全的——客户端会自行查询 OCSP；装了**错配**的那份才是有害的）。
    #[serde(default)]
    pub ech_cover_ocsp_der_path: Option<String>,
    /// ECH HPKE 对称套件（如 HKDF-SHA384/AES-256-GCM）。
    #[serde(default)]
    pub ech_cipher_suite: Option<String>,
    /// ECH maximum_name_length（默认 64）。
    #[serde(default)]
    pub ech_max_name_length: Option<u16>,
    /// ECH advertise：YES 时生成/加载配置并在 HTTPS(type65) DNS 记录发布。
    #[serde(default = "default_true")]
    pub ech_advertise: bool,
    /// 早期规格 3：0-RTT 默认关闭；显式开启才接受 early data。
    #[serde(default)]
    pub early_data: bool,
}

/// 与 serde 默认值**严格对齐**的 `Default`（唯一非平凡项是 `ech_advertise = true`）。
///
/// 存在的意义：`SslConfig` 字段多，测试里逐个列举字段会导致「每加一个字段就断三处」。
/// 有了它，测试可以用 `..Default::default()`，新增字段不再破坏它们。
impl Default for SslConfig {
    fn default() -> Self {
        Self {
            cert: None,
            key: None,
            cert_ec: None,
            key_ec: None,
            versions: Vec::new(),
            min_version: None,
            max_version: None,
            ciphers: Vec::new(),
            prefer_tls13: false,
            ech: false,
            ech_keys: None,
            psk: false,
            psk_identity: None,
            psk_key: None,
            ocsp_der_path: None,
            pqc: false,
            groups: Vec::new(),
            enable_nss: false,
            enable_tomcrypt: false,
            sni_only: false,
            sni_name: None,
            ech_public_name: None,
            ech_cover_cert: None,
            ech_cover_key: None,
            ech_cover_cert_ec: None,
            ech_cover_key_ec: None,
            ech_cover_ocsp_der_path: None,
            ech_cipher_suite: None,
            ech_max_name_length: None,
            // serde 侧是 `default_true`，这里必须一致，否则用 Default 构造的配置
            // 会与「不写该字段的 TOML」语义不同。
            ech_advertise: true,
            early_data: false,
        }
    }
}

/// TLS 版本名 → 序号（0=TLS1.0 … 3=TLS1.3）。接受 `1.2` / `tls1.2` / `TLSv1.2` 等写法。
fn tls_version_index(s: &str) -> Option<u8> {
    match s.to_ascii_lowercase().replace(['.', '_', ' '], "").as_str() {
        "1" | "10" | "tls1" | "tlsv1" | "tls10" | "tlsv10" | "sslv3" | "ssl3" => Some(0),
        "11" | "tls11" | "tlsv11" => Some(1),
        "12" | "tls12" | "tlsv12" => Some(2),
        "13" | "tls13" | "tlsv13" => Some(3),
        _ => None,
    }
}

/// 序号 → 运行期 `parse_version` 认得的规范名（见 tls/boring_path.rs）。
fn tls_version_name(i: u8) -> String {
    match i {
        0 => "tls1.0".to_string(),
        1 => "tls1.1".to_string(),
        3 => "tls1.3".to_string(),
        _ => "tls1.2".to_string(),
    }
}

impl SslConfig {
    /// OCSP 自动获取使用的「站点身份」主机名。
    ///
    /// 用途有两个：作为 `state/ocsp/{host}.der` 缓存键，以及日志里标识是哪个站点。
    /// 取值优先 `sni_name`（本 listener 配置的 SNI 身份），其次 `ech_public_name`
    /// （同样是管理员配置的对外身份）。两者都没配 → 返回 None，
    /// 自动装订路径据此跳过（没有稳定身份就无法安全复用缓存）。
    pub fn ocsp_host(&self) -> Option<String> {
        self.sni_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.ech_public_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
            .map(|s| s.to_string())
    }

    /// 规格 1a：ECH advertise 就绪。
    ///
    /// 密钥材料可以来自两条路：管理员显式给的 `ssl.ech_keys`，
    /// 或 **自动配置**（`ech_auto`：复用/生成 `state/ech/ech_keys.pem`，需要 public-name）。
    /// 早期实现要求 `ech_keys.is_some()`，于是开了 advertise 但没手填 keys 时
    /// 前端永远拿不到 HTTPS 记录——而自动配置正是为这条路准备的。
    pub fn ech_advertise_enabled(&self) -> bool {
        self.ech
            && self.ech_advertise
            && (self.ech_keys.is_some()
                || self
                    .ech_public_name
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRouteConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub engine: String,
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub php_bin: Option<String>,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default)]
    pub source_dir: Option<PathBuf>,
    #[serde(default)]
    pub out_dir: Option<PathBuf>,
    #[serde(default)]
    pub entry: Vec<String>,
    #[serde(default)]
    pub watch: bool,
    #[serde(default)]
    pub docroot: Option<PathBuf>,
    #[serde(default)]
    pub lib: Option<PathBuf>,
    #[serde(default)]
    pub deps_dir: Option<PathBuf>,
    #[serde(default = "default_init_timeout_opt")]
    pub init_timeout_secs: Option<u64>,
    #[serde(default = "default_libc_opt")]
    pub libc: Option<String>,
}

fn default_workers() -> usize {
    4
}
/// 回源 TLS 默认强制校验证书链与主机名。
fn default_proxy_ssl_mode() -> String {
    "verify".into()
}
fn default_init_timeout_opt() -> Option<u64> {
    Some(120)
}
fn default_libc_opt() -> Option<String> {
    Some("auto".into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileOpenMode {
    Auto,
    Preview,
    Download,
    Execute,
}

impl Default for FileOpenMode {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub realm: String,
    pub username: String,
    pub password_hash: String,
}

/// 早期规格 A.3：Hidden Service（独立 tor 进程，SocksPort 0——HS 不出站）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TorHsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `[(虚拟端口, 本地端口)]`，对应 torrc 的 `HiddenServicePort`。
    ///
    /// 虚拟端口就是访客在 .onion 上看到的端口：只映射 8080 时访客必须用
    /// `http://<onion>.onion:8080/`；要让 `http://<onion>.onion/` 直接可用，
    /// 就必须有一条 `(80, 本地端口)`。tor 对未映射端口的拒绝（日志里的
    /// `No virtual port mapping exists for port 80`）不是服务器故障。
    #[serde(default)]
    pub ports: Vec<(u16, u16)>,
    #[serde(default)]
    pub data_dir: Option<String>,
    #[serde(default)]
    pub tor_bin: Option<String>,
    /// 可选：`tor` 进程的运行用户（对应 torrc 的 `User`）。
    ///
    /// 不设时 tor 以 webserver 的身份运行（生产上 webserver 是 root ⇒ tor 也是 root，
    /// tor 自己会为此告警）。设成 `_tor` 之类的专用账号后，启动前会把
    /// `state/tor-hs`（HS 密钥、hostname、torrc、日志）整棵树 chown 给该用户并把
    /// `User` 写进 torrc —— tor 被攻破也拿不到 root。账号不存在 ⇒ 配置期直接报错。
    #[serde(default)]
    pub user: Option<String>,
}

/// 与 serde 默认值**严格对齐**的 `Default`（`ssl_mode` 默认 `verify` —— 最严格档）。
///
/// 存在的意义同 `SslConfig::default`：字段多，测试/面板逐字段列举会在每次新增字段时断掉。
impl Default for ProxyRuleConfig {
    fn default() -> Self {
        Self {
            path: String::new(),
            upstream: String::new(),
            ssl_mode: default_proxy_ssl_mode(),
            modify_request_headers: std::collections::HashMap::new(),
            modify_response_headers: std::collections::HashMap::new(),
            via_tor: false,
            tor_socks: None,
            connection_pool: false,
            upstream_http_version: None,
            upstream_tls_version: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRuleConfig {
    pub path: String,
    pub upstream: String,
    /// 回源 TLS 校验模式。默认 `verify`：不写该字段时按最安全处理。
    /// 此前 `#[serde(default)]` 得到空串，而 `OnionSslMode::parse` 把未知/空串
    /// 映射为 NoVerify——于是手写 config.toml 的 https 上游默认**不校验证书**。
    #[serde(default = "default_proxy_ssl_mode")]
    pub ssl_mode: String,
    /// Inject/replace request headers before forwarding upstream.
    #[serde(default)]
    pub modify_request_headers: std::collections::HashMap<String, String>,
    /// Inject/replace response headers before returning to client.
    #[serde(default)]
    pub modify_response_headers: std::collections::HashMap<String, String>,
    /// 规格 11：回源 TLS 版本（tls1.2/tls1.3；不配=自动）。
    #[serde(default)]
    pub upstream_tls_version: Option<String>,
    /// 规格 11：回源 HTTP 版本（h1/h2；不配=h1 自动）。
    #[serde(default)]
    pub upstream_http_version: Option<String>,
    /// 早期规格 3：连接池/多路复用默认禁用，显式 true 才启用。
    #[serde(default)]
    pub connection_pool: bool,
    /// 早期规格 A.1：强制走 Tor（needs_tor）。
    #[serde(default)]
    pub via_tor: bool,
    /// 覆盖 SOCKS 端点：`unix:/path`（或裸路径）→ SOCKS5 over UDS；
    /// `host:port` → SOCKS5 over TCP，**仅允许 loopback**（非回环一律拒绝：
    /// 那等于把 tor 出口做成开放代理，也绕过了 .onion 的证书即公钥校验）。
    ///
    /// 空 = 按以下优先链自动选择（`proxy.rs::connect_tor_socks`）：
    /// 1. `CRUCIBLE_TOR_FFI_LIB`（可选 dlopen 直连，需库导出 `crucible_tor_connect`）；
    /// 2. 默认 UDS 探测链：`state/tor-client/socks.sock`、`/run/tor/socks`、
    ///    `/var/run/tor/socks`、`/run/tor/socks.sock`；
    /// 3. 环境变量 `CRUCIBLE_TOR_SOCKS_UNIX` / `CRUCIBLE_TOR_SOCKS`；
    /// 4. 兜底 TCP `127.0.0.1:9050`（仅 loopback）。
    ///
    /// **不含 in-process arti**：早先这里写着「arti」，但实现里从来没有过 —— 引入
    /// `arti-client` 会带进一整套 rustls/static-sqlite 依赖，与本项目「BoringSSL 为主、
    /// 不引入第二套 TLS 栈」的取向相冲。需要内置 tor 就用 1/2/3 之一，或跑系统 tor。
    #[serde(default)]
    pub tor_socks: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRuleConfig {
    pub match_url: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
    /// §16.11 优先级：数值**越大越先评估**。缺省 `0`。
    ///
    /// 同一 listener 内规则按此**稳定**排序（等值保持配置顺序），因此
    /// **旧配置（无 priority 字段）评估顺序 = 配置书写顺序，行为逐字节不变**。
    /// 旧实现是「按书写顺序首个命中者胜」，无优先级可言；面板/手写配置里
    /// 想「把某条规则提到前面」只能整体重排，这条给出显式手段。
    #[serde(default)]
    pub priority: i64,
    /// §16.11 匹配维度 —— **host**：精确（大小写不敏感，忽略端口）/ `*.suffix`
    /// 通配子域（含 apex）/ `*` 全匹配。缺省 `None` = 不约束 host。
    ///
    /// 这些维度（host/method/header）此前**完全没有**：评估只按 URL 前缀。它们必须
    /// 由**所有协议**的请求上下文提供（h1/h2/h3 都能拿到 method/host/header），否则
    /// 只在 h1 的 `apply` 里接维度会让 `{method:POST,action:block}` 在 h1 拦、h2/h3
    /// 放行 —— 正是本项目要猎杀的跨协议不一致。见 `server::page_rules::MatchCtx`。
    #[serde(default)]
    pub host: Option<String>,
    /// §16.11 匹配维度 —— **方法**：大小写不敏感，逗号分隔多值（如 `"GET, HEAD"`）。
    #[serde(default)]
    pub method: Option<String>,
    /// §16.11 匹配维度 —— **请求头**：`Name`（存在即命中）或 `Name: value`
    /// （值精确匹配）。头名大小写不敏感。
    #[serde(default)]
    pub header: Option<String>,
}

/// 兼容旧版 `[admin] username/password_hash` 扁平字段。
#[derive(Debug, Deserialize)]
struct ConfigRaw {
    #[serde(default)]
    admin: AdminConfigRaw,
    #[serde(default)]
    access_log: AccessLogConfig,
    #[serde(default)]
    ip_access: IpAccessConfig,
    #[serde(default)]
    syncookie: SyncookieConfig,
    #[serde(default)]
    geoip: GeoIpConfig,
    #[serde(default)]
    tor_hs: TorHsConfig,
    #[serde(default)]
    telemetry: TelemetryConfig,
    #[serde(default)]
    dns: DnsConfig,
    #[serde(default)]
    listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminConfigRaw {
    #[serde(default)]
    realm: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    users: Vec<AdminUser>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password_hash: String,
    #[serde(default)]
    listeners_allow: Vec<u16>,
    #[serde(default)]
    metrics_public: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        // 基准目录必须**绝对化**：`--config config.toml`（规格 §0 的启动命令就是这种写法）
        // 时 parent 为空 ⇒ 原来的 base 是 `"."`，于是 root/docroot/lib/deps_dir/证书路径
        // 全部保持相对。相对路径在下面这些地方各自按不同 CWD 解析，必然错位：
        //   * `deps::ensure_app_deps` 用 `current_dir(docroot)` 之后再执行
        //     `<相对 docroot>/init.sh` ⇒ 子进程 CWD 下再拼一层，init.sh 永远 ENOENT，
        //     deps/ 永不构建（实测：所有 app 都打 `sh: ./www-apps/x/init.sh: No such file`）；
        //   * 任何运行期 chdir/降权之后，静态文件与证书路径也会跟着漂移。
        // 这里统一取进程 CWD 与配置目录合成绝对基准（不要求文件存在，故不用 canonicalize）。
        let base = match path.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(p) if p.is_absolute() => p.to_path_buf(),
            Some(p) => std::env::current_dir()
                .with_context(|| "config: current_dir for relative --config path")?
                .join(p),
            None => std::env::current_dir()
                .with_context(|| "config: current_dir for bare --config filename")?,
        };
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let raw_cfg: ConfigRaw = toml::from_str(&raw).context("parse config.toml")?;
        let mut admin = AdminConfig {
            realm: if raw_cfg.admin.realm.is_empty() {
                default_admin_realm()
            } else {
                raw_cfg.admin.realm
            },
            path: if raw_cfg.admin.path.is_empty() {
                default_admin_path()
            } else {
                raw_cfg.admin.path
            },
            users: raw_cfg.admin.users,
            listeners_allow: raw_cfg.admin.listeners_allow,
            metrics_public: raw_cfg.admin.metrics_public,
        };
        admin.normalize_legacy(
            (!raw_cfg.admin.username.is_empty()).then_some(raw_cfg.admin.username),
            Some(raw_cfg.admin.password_hash),
        );
        let mut cfg = Config {
            admin,
            access_log: raw_cfg.access_log,
            ip_access: raw_cfg.ip_access,
            syncookie: raw_cfg.syncookie,
            geoip: raw_cfg.geoip,
            tor_hs: raw_cfg.tor_hs,
            telemetry: raw_cfg.telemetry,
            dns: raw_cfg.dns,
            listeners: raw_cfg.listeners,
        };
        cfg.resolve_paths(&base)?;
        // 防自曝：listener 的 root **解析后**不得等于配置目录、也不得是它的祖先 ——
        // 否则该 listener 会把 config.toml 本体公开给未鉴权访问者（口令哈希、
        // MaxMind license_key、TLS/ECH 材料路径全在里面），并可升级为面板接管。
        //
        // 面板侧（admin.rs）本来就有这道检查，但它只比字面量 `"."`/`".."`：
        // `"./"`、`".//"`、`"../"`、`"sub/.."`、绝对路径写成配置目录…… 全部绕过，
        // 而 `base.join("./")` 归一化后**正好是配置目录**。这里改成解析后比较。
        check_roots_do_not_expose_config(&cfg, &base)?;
        check_tor_hs_data_dir(&cfg, &base)?;
        cfg.normalize_tls_version_ranges()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// §18：把 `min_version` / `max_version` 区间展开成 `versions` 列表。
    ///
    /// 运行期只读 `ssl.versions`（boring_path/client_hello 都是），所以这里做一次性归一化，
    /// 避免每个消费点各写一遍区间逻辑。`versions` 显式非空时不动它（显式优先）。
    fn normalize_tls_version_ranges(&mut self) -> Result<()> {
        for l in &mut self.listeners {
            let Some(ssl) = &mut l.ssl else { continue };
            if !ssl.versions.is_empty() {
                continue;
            }
            let Some(min) = ssl.min_version.as_deref().map(str::trim).filter(|s| !s.is_empty())
            else {
                continue;
            };
            let lo = tls_version_index(min).with_context(|| {
                format!(
                    "listener {}:{} 的 ssl.min_version {:?} 无法识别（支持 1.0/1.1/1.2/1.3 或 tls1.x 写法）",
                    l.address, l.port, min
                )
            })?;
            let hi = match ssl
                .max_version
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(max) => tls_version_index(max).with_context(|| {
                    format!(
                        "listener {}:{} 的 ssl.max_version {:?} 无法识别（支持 1.0/1.1/1.2/1.3 或 tls1.x 写法）",
                        l.address, l.port, max
                    )
                })?,
                None => 3, // 不写上界 = 到 TLS1.3
            };
            if lo > hi {
                anyhow::bail!(
                    "listener {}:{} 的 ssl.min_version={min:?} 高于 max_version={:?}（区间为空，该口无法完成任何握手）",
                    l.address,
                    l.port,
                    ssl.max_version.as_deref().unwrap_or("")
                );
            }
            ssl.versions = (lo..=hi).map(tls_version_name).collect();
        }
        Ok(())
    }

    fn resolve_paths(&mut self, base: &Path) -> Result<()> {
        for l in &mut self.listeners {
            if !l.root.is_absolute() {
                l.root = base.join(&l.root);
            }
            if let Some(ssl) = &mut l.ssl {
                // 这些 TLS 材料字段必须**同一基准**：以前只有前 4 个按配置目录解析，
                // 其余走 `ssl_material::load_bytes` 的相对路径（基准是**进程 cwd**）。
                // 从非配置目录启动（rc.d / cron / 手工 cd 后启动）时，cert 正常而
                // ECH/cover/OCSP 材料找不到 ⇒ ECH 静默消失、cover 构建失败，
                // 而配置本身看不出任何问题。
                resolve_ssl_material(&mut ssl.cert, base);
                resolve_ssl_material(&mut ssl.key, base);
                resolve_ssl_material(&mut ssl.cert_ec, base);
                resolve_ssl_material(&mut ssl.key_ec, base);
                resolve_ssl_material(&mut ssl.ech_keys, base);
                resolve_ssl_material(&mut ssl.ech_cover_cert, base);
                resolve_ssl_material(&mut ssl.ech_cover_key, base);
                resolve_ssl_material(&mut ssl.ech_cover_cert_ec, base);
                resolve_ssl_material(&mut ssl.ech_cover_key_ec, base);
                resolve_ssl_material(&mut ssl.ocsp_der_path, base);
                resolve_ssl_material(&mut ssl.ech_cover_ocsp_der_path, base);
            }
            for app in &mut l.apps {
                if let Some(d) = &app.docroot {
                    if !d.is_absolute() {
                        app.docroot = Some(base.join(d));
                    }
                }
                if let Some(lib) = &mut app.lib {
                    if !lib.is_absolute() {
                        *lib = base.join(&*lib);
                    }
                }
                if let Some(d) = &app.deps_dir {
                    if !d.is_absolute() {
                        app.deps_dir = Some(base.join(d));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        let mut roots = BTreeMap::<String, u16>::new();
        for l in &self.listeners {
            // L4 透传 listener 的 root 字段无业务意义，不参与唯一性校验
            if l.l4_forward.is_some() { continue; }
            let key = l.root.display().to_string();
            if let Some(prev) = roots.insert(key.clone(), l.port) {
                anyhow::bail!(
                    "duplicate listener root {} on ports {} and {}",
                    key,
                    prev,
                    l.port
                );
            }
        }
        {
            use std::collections::HashSet;
            let mut seen = HashSet::new();
            for l in &self.listeners {
                if l.port == 0 {
                    anyhow::bail!("listener port must not be 0");
                }
                let key = (l.address.clone(), l.port);
                if !seen.insert(key) {
                    anyhow::bail!(
                        "duplicate listener address:port {}:{}",
                        l.address,
                        l.port
                    );
                }
                // QMux 上跑的是 HTTP/1.1：h1 关掉时 qmux 无法工作，配置期就拦住
                //（否则表现是「ALPN 协商到 h1-02qx 却立刻失败」，很难查）。
                if l.qmux && !l.allows_h1() {
                    anyhow::bail!(
                        "listener {}:{} 开了 qmux 但 http_versions 不含 h1（QMux 上跑的是 HTTP/1.1）",
                        l.address,
                        l.port
                    );
                }
            }
        }

        // address / address_v6 必须是**合法 IP 字面量**：写 "localhost" 或拼错时
        // `--check-config` 会打印 config OK（它只构建 acceptor），而启动/热重载时该端口
        // 永远绑不上 —— 热重载下进程会**继续运行且一个端口都不在服务**，只在日志里留一条
        // 折叠过的 warn。配置期直接拒，把错误提前到加载时。
        for l in &self.listeners {
            if l.address.parse::<std::net::IpAddr>().is_err() {
                anyhow::bail!(
                    "listener {}:{} 的 address {:?} 不是合法 IP 字面量（不要写域名；IPv6 直接写地址本体，如 ::）",
                    l.address,
                    l.port,
                    l.address
                );
            }
            if let Some(v6) = l.address_v6.as_deref() {
                let t = v6.trim();
                if !t.is_empty() && t.parse::<std::net::IpAddr>().is_err() {
                    anyhow::bail!(
                        "listener {}:{} 的 address_v6 {:?} 不是合法 IP 字面量",
                        l.address,
                        l.port,
                        v6
                    );
                }
            }
        }

        for l in &self.listeners {
            let Some(ssl) = &l.ssl else { continue };
            // ECH cover 证书必须成对：只给一半会在握手时静默回落到「不能用于 public_name
            // 的真实证书」，客户端报证书不匹配 —— 与「只写 cert 不写 key」同类，配置期拦。
            let cover_cert = ssl.ech_cover_cert.as_deref().map_or(false, |s| !s.trim().is_empty());
            let cover_key = ssl.ech_cover_key.as_deref().map_or(false, |s| !s.trim().is_empty());
            if cover_cert != cover_key {
                anyhow::bail!(
                    "listener {}:{}: ssl.ech_cover_cert 与 ssl.ech_cover_key 必须成对配置",
                    l.address,
                    l.port
                );
            }
            if cover_cert && ssl.ech_public_name.is_none() {
                anyhow::bail!(
                    "listener {}:{}: 配了 ECH cover 证书但没有 ssl.ech_public_name —— \
证书选择靠它区分「外层名」与「ECH 解密后的内层真实名」，缺了它必然选错证书",
                    l.address,
                    l.port
                );
            }
            // 外层 EC 也必须成对（与上面 cover_cert/cover_key 同理）。
            let cover_ec_cert =
                ssl.ech_cover_cert_ec.as_deref().map_or(false, |s| !s.trim().is_empty());
            let cover_ec_key =
                ssl.ech_cover_key_ec.as_deref().map_or(false, |s| !s.trim().is_empty());
            if cover_ec_cert != cover_ec_key {
                anyhow::bail!(
                    "listener {}:{}: ssl.ech_cover_cert_ec 与 ssl.ech_cover_key_ec 必须成对配置",
                    l.address,
                    l.port
                );
            }
            // 内外层必须**配成同一组密钥类型**（要么都有 EC，要么都没有）。
            //
            // 依据：本 BoringSSL 的 `SSL_CTX_use_certificate` 只有**单个** legacy credential
            // 槽（文档原文 "configures the single "legacy credential""，多证书要走未导出的
            // `SSL_CREDENTIAL_*` API）。所以同一层里后设置的生效，两层类型不一致时
            // ECH 接受前后证书类型会变；而且外层缺 EC 时，容器里唯一的 EC 证书正好是
            // **内层**那张 —— 实测（127.0.0.1:18443）三条探针（ECH / 非 ECH+RSA /
            // 非 ECH+仅 ECDSA）拿到的指纹**完全相同**，即内层真实证书被泄漏给非 ECH 客户端。
            let inner_ec = ssl.cert_ec.as_deref().map_or(false, |s| !s.trim().is_empty());
            if cover_cert && inner_ec != cover_ec_cert {
                anyhow::bail!(
                    "listener {}:{}: ssl.cert_ec 与 ssl.ech_cover_cert_ec 必须同时配或同时不配 —— \
本 BoringSSL 每层只保留最后设置的那张证书（单 credential 槽），内外层密钥类型不一致时，\
ECH 接受前后证书类型会变，且外层缺 EC 时容器里就是**内层**那张 EC 证书（非 ECH 客户端与\
主动探测者都会拿到内层真实证书，cover 形同虚设）",
                    l.address,
                    l.port
                );
            }
            // cover 证书 + `ech = false`：容器默认证书是 **cover**，而切换回调只在
            // `ech_accepted()` 为真时换成真实证书 —— ECH 关掉时它**永远为假**，
            // 于是这个 listener 对外**只发 cover 证书**，真实证书一次都用不上，
            // 客户端按本 listener 的真实名/身份校验证书会失败。这不是「配置冗余」，
            // 是静默发错证书（`load_identity` 的注释里写明了 cover 的用途只在
            // 「非 ECH 客户端 / ECH 被拒」这一条路径上，没有内层就无从谈起）。
            if cover_cert && !ssl.ech {
                anyhow::bail!(
                    "listener {}:{}: 配了 ECH cover 证书却没有开 ssl.ech —— \
cover 只用于「未使用 / 被拒 ECH」的连接，ECH 关闭时它会成为**唯一的**证书\
（真实证书永不出现），客户端按真实身份校验必然失败。要么把 ssl.ech 打开并配好材料，\
要么删掉 cover 证书",
                    l.address,
                    l.port
                );
            }
        }

        // QMux/Hidden Service 之类的「开了但配不全」在运行期只会静默不生效，
        // 配置期一律拦住（见各自 validate 的注释）。
        crate::server::tor_hs::validate(&self.tor_hs)?;

        // ip_access 的空条目：运行期 `access::cidr_or_exact("")` 现在**永不匹配**（fail-closed），
        // 而历史上它曾等于「匹配所有地址」。两种语义下空项都是错的，所以配置期一律拒：
        //   * 旧语义：`allow = ["1.2.3.4", ""]` 变成「放行所有人」（白名单静默失效），
        //     `deny` 里多打一个逗号则变成「全站 403」；
        //   * 现语义：`allow` 里一个空项会让其余条目失去意义？不会 —— 但 `deny = [""]`
        //     会变成一个**永不生效**的封禁项（你以为封住了，实际没封）。
        // 两种都不会有任何报错，只表现为「站点突然全 403 / 白名单形同虚设 / 封禁没生效」。
        // 面板保存路径（admin.rs::check_ip_access_entry）已经拒空串，这里补上配置期这一道。
        //
        // §16.1：per-listener `[listeners.ip_access]` 同样校验（同一套判据，只是 what 不同）
        // —— 它此前因字段不存在被 serde 静默忽略，加字段后必须一起过校验，否则只是把
        // 「静默无效」变成「静默无效 + 新增一处可写但运行期永不匹配的表」。
        check_ip_access_entries("[ip_access]", &self.ip_access)?;
        for l in &self.listeners {
            if let Some(ia) = &l.ip_access {
                check_ip_access_entries(
                    &format!("listener {}:{} 的 [listeners.ip_access]", l.address, l.port),
                    ia,
                )?;
            }
        }

        // TLS 相关的 fail-fast：这几条错了不会「报错」，而是**静默降级或整站不可用**，
        // 必须在加载期拦住（用户明确要求：拒绝异常配置，而不是运行期悄悄跳过）。
        for l in &self.listeners {
            let Some(ssl) = &l.ssl else { continue };
            let has_cert = ssl.cert.as_deref().map_or(false, |s| !s.trim().is_empty());
            let has_key = ssl.key.as_deref().map_or(false, |s| !s.trim().is_empty());
            // ① 证书与私钥必须成对。只写 cert 不写 key 时，TLS 建不起来，而 accept 侧会把
            //    「未配置证书」当作「按明文 HTTP 服务」（规格要求 cert 未配置前一律走 HTTP）
            //    —— 于是少写一行 key = 该口静默变明文。这比启动失败危险得多。
            if has_cert != has_key {
                anyhow::bail!(
                    "listener {}:{} 的 TLS 证书与私钥必须成对配置（cert/key 只给了一个；                     缺 key 会让该口静默退化成明文 HTTP）",
                    l.address, l.port
                );
            }
            // ② sni_only 必须在名字可比对：只开 sni_only 而不给 sni_name / server_name 时，
            //    每个连接都会因「SNI 不匹配」被丢弃（fail-closed，但整个站点不可用），
            //    运维在日志里只看到一句「无可用 SNI」。
            if ssl.sni_only
                && ssl.sni_name.as_deref().unwrap_or("").trim().is_empty()
                && l.server_name.as_deref().unwrap_or("").trim().is_empty()
            {
                anyhow::bail!(
                    "listener {}:{} 开了 sni_only 但既没有 sni_name 也没有 server_name ——                      这样所有连接都会被丢弃",
                    l.address, l.port
                );
            }
            // ③ TLS 版本串写错只会被静默忽略（与预期不符，甚至以为关掉了 TLS1.0）。只认这几种写法。
            for v in &ssl.versions {
                let n = v.trim().to_ascii_lowercase();
                if !matches!(
                    n.as_str(),
                    "tls1" | "tls1.0" | "tls1.1" | "tls1.2" | "tls1.3"
                        | "tlsv1" | "tlsv1.0" | "tlsv1.1" | "tlsv1.2" | "tlsv1.3"
                ) {
                    anyhow::bail!(
                        "listener {}:{} 的 TLS 版本 {v:?} 无法识别（支持 tls1.0/tls1.1/tls1.2/tls1.3）",
                        l.address,
                        l.port
                    );
                }
            }
        }

        // deps_dir 必须位于该应用 docroot 之内。
        //
        // 依据：deps::ensure_app_deps 在 init.sh 存在时会 **递归删除 deps_dir 再重建**，
        // 并从 `<deps_dir>/bin/index` 执行 sidecar 二进制。若 deps_dir 指向 docroot
        // 之外的任意目录（面板 /api/apps/save 可直接写该字段），一次应用请求就能
        // 删掉任意目录树，并让服务端执行放在那里的可执行文件。
        for l in &self.listeners {
            for app in &l.apps {
                let Some(deps) = &app.deps_dir else { continue };
                let Some(docroot) = &app.docroot else {
                    // 无 docroot 时 deps_dir 没有合法的相对基准，直接拒绝。
                    anyhow::bail!(
                        "app deps_dir {} requires a docroot on listener :{}",
                        deps.display(),
                        l.port
                    );
                };
                // 用规范化路径比较（两者此时都已解析为绝对路径）；目录可能尚不存在，
                // 故回退到「按组件消除 ..」的字典序规范化，避免绕过。
                let norm = |p: &std::path::Path| -> std::path::PathBuf {
                    let mut out = std::path::PathBuf::new();
                    for c in p.components() {
                        match c {
                            std::path::Component::ParentDir => {
                                out.pop();
                            }
                            std::path::Component::CurDir => {}
                            other => out.push(other.as_os_str()),
                        }
                    }
                    out
                };
                let nd = norm(deps);
                let nr = norm(docroot);
                if nd == nr || !nd.starts_with(&nr) {
                    anyhow::bail!(
                        "app deps_dir {} must be inside its docroot {} (listener :{})",
                        deps.display(),
                        docroot.display(),
                        l.port
                    );
                }
            }
        }

        // 应用路由 `paths` 必须是以 `/` 开头的绝对前缀（空串/相对前缀都永不匹配）。
        //
        // 依据：`apps::prefix_matches` 做的是**字面前缀比较**（`path == p || path.starts_with(p+"/")`，
        // 且 `prefix_matches("")` 恒假）。`paths = ["php"]`（缺前导斜杠）或 `paths = [""]`
        // 都不会匹配任何请求 ⇒ 该路由**静默不生效**：面板/手写 toml 看起来都正常，只有请求
        // 打不上去才发现。面板保存路径（`admin.rs::check_app_route`）已拒，但**原始 TOML 编辑器**
        // （`/api/config/toml`）与手写 config.toml 只过 `validate()` —— 这里补上配置期这一道。
        // 空 `paths` 数组（= 整站）仍合法，故只逐项检查已有元素。
        for l in &self.listeners {
            for (ai, app) in l.apps.iter().enumerate() {
                for (pi, p) in app.paths.iter().enumerate() {
                    let t = p.trim();
                    if t.is_empty() {
                        anyhow::bail!(
                            "listener {}:{}: apps[{ai}].paths[{pi}] 是空串 —— `prefix_matches(\"\")` 恒不匹配，该路由永不生效（要整站请把 paths 留成空数组或写 \"/\"）",
                            l.address,
                            l.port
                        );
                    }
                    if !t.starts_with('/') {
                        anyhow::bail!(
                            "listener {}:{}: apps[{ai}].paths[{pi}] = {p:?} 必须以 `/` 开头 —— 相对前缀永不匹配请求（路由静默不生效）",
                            l.address,
                            l.port
                        );
                    }
                }
            }
        }

        // ── 管理面 / 限流 / proxy / autoindex / TLS 材料 的成组校验 ──
        //
        // 这一组的共同点：**写错时配置合法、服务也起得来**，但运行期要么静默失效、
        // 要么按最坏方式生效。每一条都对应一个已观察到的坏表现，所以放在配置期拦。

        // ① 至少一个 listener。空列表能通过校验并通过 reload，随后所有 accept 循环
        //    退出 ⇒ 进程活着、端口全空、日志只有一行 "removed from config; shutting down"
        //    —— 面板上误删最后一个 listener 就能造出这种静默停服。
        // ①a geoip 假开关：`enabled = true` 但没有 db_path 时，
        // `geoip_panel` 侧只认 `db_path.is_some()` ⇒ 面板显示已启用、查询全部落空。
        if self.geoip.enabled
            && self
                .geoip
                .db_path
                .as_deref()
                .map_or(true, |p| p.as_os_str().is_empty())
        {
            anyhow::bail!(
                "geoip.enabled = true 但没有配置 geoip.db_path —— 查询会全部落空（面板仍显示已启用）"
            );
        }

        // ①c `[dns]` 的「开了但配不全」**不能**在 `validate()` 里当错误拦：
        // `state/dns/etc/panel.toml` 存在时会把 `[dns]` **整体覆盖**（见 `dns::effective`），
        // 于是 config.toml 里那份 `[dns.dot]` 可能根本不被使用 —— 拿它当判据会**误拒**
        // 一个实际可用的配置（实测：生产的 DoT 证书来自 panel.toml，config.toml 只写了
        // `enabled/port`，被我这条校验拦到起不来）。检查放在 `dns::effective()` 里，
        // 对着**真正生效**的那份配置做，且只 warn（DNS 侧本来就有降级路径）。
        //
        // 这条注释本身就是教训：新增配置期校验前，必须用「生产配置 + 生效路径」核对。

        // `[[dns.https_rr]].name` 为空 ⇒ 渲染出的记录名是空串。
        for (i, r) in self.dns.https_rr.iter().enumerate() {
            if r.name.trim().is_empty() {
                anyhow::bail!("[dns].https_rr[{i}].name 不能为空（渲染出的 HTTPS 记录名会是空串）");
            }
        }

        // ①b 其余路径型配置项同理：写错就是「静默不匹配」（页面 404 / DoH 端点消失）。
        {
            let tp = self.telemetry.path.trim();
            if self.telemetry.enabled && (tp.is_empty() || !tp.starts_with('/')) {
                anyhow::bail!(
                    "telemetry.path = {:?} 必须是非空、以 `/` 开头的路径（写错 ⇒ /__metrics 静默 404）",
                    self.telemetry.path
                );
            }
            if self.dns.doh.enabled {
                let dp = self.dns.doh.path.trim();
                if dp.is_empty() || !dp.starts_with('/') {
                    anyhow::bail!(
                        "dns.doh.path = {:?} 必须是非空、以 `/` 开头的路径（写错 ⇒ DoH 端点永远不匹配）",
                        self.dns.doh.path
                    );
                }
            }
        }

        if self.listeners.is_empty() {
            anyhow::bail!("listeners 为空：至少需要一个监听口（空列表会让全部 accept 循环退出，进程活着但不再服务）");
        }

        // ② admin.path：必须是以 `/` 开头的绝对路径，且不能是 `/`。
        //    `"/"` 会让 `is_admin_path` 对**一切**路径成立（面板门接管整站：全站 401/404）；
        //    `"admin"`（缺前导斜杠）则永不匹配 ⇒ 面板静默 404，没有任何提示。
        {
            let ap = self.admin.path.trim();
            if ap.is_empty() || !ap.starts_with('/') {
                anyhow::bail!("admin.path = {:?} 必须以 `/` 开头（否则管理面永不匹配，表现为面板静默 404）", self.admin.path);
            }
            if ap == "/" {
                anyhow::bail!("admin.path 不能是 `/`：那会让管理面匹配一切路径并接管整站（所有请求都走鉴权/CSRF 门）");
            }
        }

        // ③ realm 会被拼进 `WWW-Authenticate: Basic realm="…"`。含换行/引号/非 ASCII 时
        //    header 构造失败，而代码里随后是 `.unwrap()` ⇒ **每个匿名请求 panic**。
        //    面板侧本来就有这道检查（admin_config_edit），手写 config.toml 却漏了。
        for (what, realm) in realm_fields(self) {
            if !safe_header_value(&realm) {
                anyhow::bail!(
                    "{what} 含不能放进 HTTP 头的字符（只允许可打印 ASCII，且不含双引号与反斜杠）：{:?} —— 构造 WWW-Authenticate 头会失败，未认证请求会直接 panic",
                    realm
                );
            }
        }

        for l in &self.listeners {
            // ④ TLS 材料路径必须真实存在（内联 PEM 除外）：路径打错时 reload 通过、
            //    但每次握手都在 build_acceptor 里失败并被 soft-fail 丢弃 ⇒
            //    该端口等于下线，日志里只有一行 warn（本项目吃过这个）。
            if let Some(ssl) = &l.ssl {
                for (what, field) in [
                    ("ssl.cert", &ssl.cert),
                    ("ssl.key", &ssl.key),
                    ("ssl.cert_ec", &ssl.cert_ec),
                    ("ssl.key_ec", &ssl.key_ec),
                    // `ech_keys` 也必须存在：路径打错时配置加载通过，但那之后再无 ECH 密钥
                    //（`apply_ech` 只 warn 后返回）⇒ 容器始终是 cover 证书，真实证书永不出现，
                    // 客户端按真实身份校验必然失败。与「只写 cert 不写 key」同类，配置期拦。
                    ("ssl.ech_keys", &ssl.ech_keys),
                    ("ssl.ech_cover_cert", &ssl.ech_cover_cert),
                    ("ssl.ech_cover_key", &ssl.ech_cover_key),
                    ("ssl.ech_cover_cert_ec", &ssl.ech_cover_cert_ec),
                    ("ssl.ech_cover_key_ec", &ssl.ech_cover_key_ec),
                ] {
                    let Some(v) = field.as_deref() else { continue };
                    let t = v.trim();
                    if t.is_empty() {
                        anyhow::bail!("listener {}:{}: {what} 是空串（要留空请删掉该字段）", l.address, l.port);
                    }
                    if t.contains("-----BEGIN") {
                        continue; // 内联 PEM 内容，不做存在性检查
                    }
                    if !std::path::Path::new(t).exists() {
                        anyhow::bail!(
                            "listener {}:{}: {what} 指向的文件不存在：{t} —— 配置能加载但该端口的每次 TLS 握手都会失败（连接被静默丢弃）",
                            l.address,
                            l.port
                        );
                    }
                }
            }

            // ⑤ rate_limit=0/负数：令牌永远不会被补回，burst 用完后**永久 429**。
            //    `burst = 0` 则第一个请求就被拒。运维看到的是「站点上线几分钟后全 429」。
            if let Some(rl) = &l.rate_limit {
                if rl.enabled && !(rl.rate_per_sec > 0.0) {
                    anyhow::bail!(
                        "listener {}:{}: rate_limit.rate_per_sec = {} 必须 > 0（0 或负数 ⇒ 令牌不再补充，burst 用完后该端口永久 429）",
                        l.address, l.port, rl.rate_per_sec
                    );
                }
                if rl.enabled && !(rl.burst > 0.0) {
                    anyhow::bail!(
                        "listener {}:{}: rate_limit.burst = {} 必须 > 0（0 ⇒ 第一个请求就被拒）",
                        l.address, l.port, rl.burst
                    );
                }
            }

            // ⑤b page_rules 的 redirect target 会进 Location 响应头。`HeaderValue` 拒绝
            //     控制字符与非 ASCII，而 `http::Builder` 把错误**推迟到 `.body()`** ——
            //     手写配置里一个带换行/非 ASCII 的 target，会让每个命中该规则的请求在 hyper
            //     的 service future 里 panic（连接被直接丢弃）。代码侧已改成不 unwrap 的降级
            //     路径，这里再加一道配置期拦截，让错误在加载时就报出来。
            for (i, r) in l.page_rules.iter().enumerate() {
                if r.action == "redirect" {
                    let t = r.target.as_deref().unwrap_or("/");
                    let loc = match t.split_once(':') {
                        Some(("301" | "307" | "308", u)) => u,
                        _ => t,
                    };
                    if !safe_header_value(loc) {
                        anyhow::bail!(
                            "listener {}:{}: page_rules[{i}]（redirect）的 target 不能作为 Location 响应头（含控制字符、非 ASCII、引号或反斜杠）: {loc:?}",
                            l.address, l.port
                        );
                    }
                }
            }
            // ⑤c page_rules 的 match_url：只有**结尾**的 `*` 是受支持的通配
            //     （page_rules::path_matches 用 strip_suffix('*') + starts_with）。
            //     中间的 `*` 会被当普通字符比较 ⇒ 规则**永不匹配**，而面板里看起来
            //     完全正常（保存成功、规则列表也在），只有请求打不上去才发现。
            for (i, r) in l.page_rules.iter().enumerate() {
                if let Some(pos) = r.match_url.find('*') {
                    if pos != r.match_url.len() - 1 {
                        anyhow::bail!(
                            "listener {}:{}: page_rules[{i}].match_url {:?} 里的 `*` 只在结尾受支持（中间的 `*` 按字面比较，规则永不匹配）",
                            l.address, l.port, r.match_url
                        );
                    }
                }
                if !r.match_url.starts_with('/') && !r.match_url.starts_with("http") {
                    anyhow::bail!(
                        "listener {}:{}: page_rules[{i}].match_url {:?} 必须以 `/` 开头（路径规则）",
                        l.address, l.port, r.match_url
                    );
                }
            }
            // ⑤d l4_forward：必须能解析成 ip:port。否则每次连接才在 listener 里 parse 失败，
            //     连接被静默丢弃（配置加载却是成功的）。
            if let Some(dest) = &l.l4_forward {
                if dest.parse::<std::net::SocketAddr>().is_err() {
                    anyhow::bail!(
                        "listener {}:{}: l4_forward {dest:?} 不是合法的 `ip:port`（该口会静默丢弃所有连接）",
                        l.address, l.port
                    );
                }
            }
            // port_reuse 的 301 会把 server_name 拼进 Location（`https://<server_name>/…`），
            // 同样必须是安全的 header 值。只在 port_reuse 下检查，避免误伤别的用法。
            if l.port_reuse {
                if let Some(sn) = l.server_name.as_deref() {
                    if !safe_header_value(sn) {
                        anyhow::bail!(
                            "listener {}:{}: port_reuse 下 server_name 会进 Location 响应头，但不能作为 header 值（含控制字符/非 ASCII）: {sn:?}",
                            l.address, l.port
                        );
                    }
                }
            }

            // ⑥a 路径型配置项必须以 `/` 开头：`status_path = "status"` 永不命中
            //      （`h1.rs` 用的是精确比较）⇒ 页面静默 404，没有任何提示。
            for (what, p) in [
                ("status_path", l.status_path.as_deref()),
            ] {
                if let Some(v) = p {
                    let t = v.trim();
                    if t.is_empty() || !t.starts_with('/') {
                        anyhow::bail!(
                            "listener {}:{}: {what} = {:?} 必须是非空、以 `/` 开头的路径",
                            l.address, l.port, v
                        );
                    }
                }
            }

            // ⑥ proxy 规则：`path` 为空串时 `path_matches_proxy_prefix` 恒假 ⇒ 规则永不生效
            //    且无任何告警；`upstream` 为空则在连接阶段报错（502）。
            for r in &l.proxy_rules {
                let pth = r.path.trim();
                if pth.is_empty() || !pth.starts_with('/') {
                    anyhow::bail!(
                        "listener {}:{}: proxy 规则 path = {:?} 必须是非空、以 `/` 开头的路径前缀（空串会让该规则永不匹配）",
                        l.address, l.port, r.path
                    );
                }
                if r.upstream.trim().is_empty() {
                    anyhow::bail!(
                        "listener {}:{}: proxy 规则 path={pth} 的 upstream 为空",
                        l.address, l.port
                    );
                }
            }

            // ⑦ autoindex.paths 里的空串等于「整站」：`allows()` 用
            //    `path.starts_with("/")` 判断，空串裁掉尾斜杠后恒真 ⇒ 上传面覆盖整个 listener。
            if l.autoindex.enabled {
                for pth in &l.autoindex.paths {
                    // 注意 `"/"` 是**合法且明确**的写法（= 整个 listener），必须放行；
                    // 要拦的是**空条目**（多打一个逗号/写了空串）—— 它在
                    // `trim_end_matches('/')` 之后同样是空，运行期 `starts_with("/")`
                    // 恒真 ⇒ 上传与目录列表覆盖整站，而运维以为自己只开了 `/up`。
                    let t = pth.trim();
                    if t.is_empty() {
                        anyhow::bail!(
                            "listener {}:{}: autoindex.paths 含空条目（要整站请显式写 \"/\"）",
                            l.address, l.port
                        );
                    }
                    if !t.starts_with('/') {
                        anyhow::bail!(
                            "listener {}:{}: autoindex.paths 的条目 {:?} 必须以 `/` 开头",
                            l.address, l.port, pth
                        );
                    }
                }
            }
        }

        Ok(())
    }

    pub fn to_toml_string(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }
}

/// 所有会进 `WWW-Authenticate: Basic realm="…"` 的 realm（管理面 + 每个 listener 的 basic_auth）。
///
/// 返回 `(字段名, realm)`，字段名用于报错定位。
fn realm_fields(cfg: &Config) -> Vec<(String, String)> {
    let mut out = vec![("admin.realm".to_string(), cfg.admin.realm.clone())];
    for l in &cfg.listeners {
        if let Some(ba) = &l.basic_auth {
            out.push((
                format!("listener {}:{}: basic_auth.realm", l.address, l.port),
                ba.realm.clone(),
            ));
        }
    }
    out
}

/// realm 必须能安全放进 HTTP 头字段值：可打印 ASCII，且不含 `"` 与 `\`
///（quoted-string 里的转义字符）。UTF-8 与换行都会让 header 构造失败 ——
/// 而调用点随后 `.unwrap()`，等于「配置里一个中文 realm 就能让每个匿名请求 panic」。
fn safe_header_value(s: &str) -> bool {
    // `'"'` 与 `'\\'` 在 quoted-string 里是转义/结束符，
    // 其余可打印 ASCII 原样保留；非 ASCII 与换行会让 header 构造失败。
    let ok = |b: u8| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\';
    !s.is_empty() && s.bytes().all(ok)
}

/// 校验一份 `ip_access`（全局或 per-listener）的 allow/deny 条目。
///
/// `what` 只用于报错定位（`"[ip_access]"` 或 `"listener A:B 的 [listeners.ip_access]"`）。
/// 判据与运行期 `access::cidr_or_exact` 对齐：空串/非法条目在运行期**永不匹配**，
/// 放在 `deny` 里等于静默失效、放在 `allow` 里等于把白名单收成空集 —— 都必须在加载期拒。
fn check_ip_access_entries(what: &str, cfg: &IpAccessConfig) -> Result<()> {
    for (name, list) in [("allow", &cfg.allow), ("deny", &cfg.deny)] {
        for (i, p) in list.iter().enumerate() {
            if p.trim().is_empty() {
                anyhow::bail!(
                    "{what}.{name}[{i}] 是空串 —— 空项在任何一种语义下都是错的\
（曾等于「匹配所有地址」：deny 让全站 403、allow 放行所有人；现在则永不匹配：封禁静默失效），\
请删掉这一项或显式写 \"*\""
                );
            }
            // 非法条目（拼错、前缀越界）在运行期**永不匹配**（`access::cidr_or_exact`
            // 解析失败一律返回 false）⇒ `deny` 会**静默失效**，比不写更糟（你以为封住了）。
            // 配置期直接拒，并把「要匹配全部请写 *」说清楚。
            if !ip_access_entry_is_valid(p) {
                anyhow::bail!(
                    "{what}.{name}[{i}] 不是合法 IP/CIDR：{p:?} —— 运行期这类条目**永不匹配**（deny 会静默失效）；要匹配全部地址请显式写 \"*\""
                );
            }
        }
    }
    Ok(())
}

/// `ip_access` 条目是否可解析。
///
/// 运行期 `access::cidr_or_exact` 对解析失败的条目一律返回 false —— 也就是**永不匹配**。
/// 放在 `deny` 里等于静默失效（运维以为封住了）。`"*"` 是显式的「匹配所有地址」。
/// 前缀还必须落在该地址族的合法范围（`/33`、`/129` 同样永不匹配）。
fn ip_access_entry_is_valid(p: &str) -> bool {
    let t = p.trim();
    if t == "*" {
        return true;
    }
    use std::net::IpAddr;
    match t.split_once('/') {
        Some((net, bits)) => match (net.trim().parse::<IpAddr>(), bits.trim().parse::<u8>()) {
            (Ok(IpAddr::V4(_)), Ok(b)) => b <= 32,
            (Ok(IpAddr::V6(_)), Ok(b)) => b <= 128,
            _ => false,
        },
        None => t.parse::<IpAddr>().is_ok(),
    }
}

/// 判据（对每个 listener 的 root，经过 `resolve_paths` 后已是绝对路径）：
/// root **等于**配置目录 ⇒ 目录列表/静态服务会把 `config.toml` 端出去；
/// root 是配置目录的**祖先** ⇒ 连 `config.toml` 与 `state/`（TLS/ECH 私钥、rndc key）
/// 一起暴露。两种都拒绝，并在错误里说清为什么会危险。
///
/// 比较用「按组件消除 `..`/`.`」的字典序规范化（不要求目录存在，也不跟随符号链接）——
/// 这是配置期就该拦住的形态问题；真实路径解析留给运行期的 canonicalize 一致性检查。
/// 词汇归一化（不碰文件系统）：去掉 `.`、用 `a/../` 抵消，`..` 冒到顶就停下。
///
/// 判据必须是「归一化后比较」而不是字面量比较：`"./"`、`".//"`、`"sub/.."`、`"/"` 这几种
/// 写法在字面量上各不相同，归一化后却是同一个目录。
fn norm_path(p: &Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `[tor_hs].data_dir` 会被整棵树 `chmod 0700`，并在配了 `[tor_hs].user` 时 `chown -R`
/// 给那个**低权**账号。所以它既不能是文件系统根，也不能是配置目录本身或它的祖先：
///
/// * `data_dir = "/"` ⇒ `chmod 0700 /` + `chown -R / _tor` —— tor 一旦被攻破，主机上
///   **一切**（`/root`、`/etc`、别人的数据）的属主都归了它；
/// * `data_dir = "/crucible"` ⇒ 把 `config.toml`（admin 口令哈希、MaxMind key）、
///   `state/` 下的 TLS/ECH 私钥与 rndc 密钥一并交给它。
///
/// 这两条在运行期都**不会有任何报错**，只有事后审计才看得出来，所以在配置期就拒。
/// 判据与 `check_roots_do_not_expose_config` 同一套（归一化后比较）。
fn check_tor_hs_data_dir(cfg: &Config, config_dir: &Path) -> Result<()> {
    let Some(raw) = cfg
        .tor_hs
        .data_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(()); // 未配置：用 state/tor-hs/hs，我们自己的目录
    };
    let d = norm_path(Path::new(raw));
    if d.as_os_str().is_empty() {
        anyhow::bail!(
            "[tor_hs].data_dir = {raw:?} 归一化后为空（`.` / `..` / `sub/..` 这类）—— \
它会被 chmod 0700 + chown -R 给 tor 账号，无法判断边界，请写明确的目录"
        );
    }
    if d == Path::new("/") {
        anyhow::bail!(
            "[tor_hs].data_dir = {raw:?} 是文件系统根 —— 该目录会被 chmod 0700，并在配了 \
[tor_hs].user 时 chown -R 给那个低权账号，等于把整台主机交出去。请指向一个专属目录（如 /var/tor/hs）"
        );
    }
    let base = norm_path(config_dir);
    // 允许的唯一「配置目录之内」的位置是 `<配置目录>/state` 的**真后代**（默认就是
    // `state/tor-hs/hs`）。`state` 本身不能给出去 —— 那正是 ECH/TLS 私钥与 rndc 密钥所在。
    // `state_root()` 是相对 cwd 的 `state/`，所以字面量 `state` 也要单独挡一次。
    let state = base.join("state");
    let state_rel = Path::new("state");
    let is_our_state_subdir = (d.starts_with(&state) && d != state)
        || (d.starts_with(state_rel) && d != state_rel);
    if base.starts_with(&d) {
        anyhow::bail!(
            "[tor_hs].data_dir = {raw:?} 是配置目录 {} 本身或它的祖先 —— 该目录会被 chmod 0700 + \
chown -R 给 tor 账号，config.toml（admin 口令哈希、MaxMind key）与 state/ 下的 TLS/ECH 私钥、\
rndc 密钥都会落到它手里。请把 data_dir 指到配置目录之外",
            base.display()
        );
    }
    if d == state || d == state_rel {
        anyhow::bail!(
            "[tor_hs].data_dir = {raw:?} 就是 state/ 目录本身 —— state/ 下有 ECH/TLS 私钥与 \
rndc 密钥，整棵树 chown -R 给 tor 账号等于把它们交出去。请指向 state/ 下的**子目录**（默认 state/tor-hs/hs）"
        );
    }
    if d.starts_with(&base) && !is_our_state_subdir {
        anyhow::bail!(
            "[tor_hs].data_dir = {raw:?} 落在配置目录 {} 里、又不在 state/ 之下 —— 配置目录里是\
源码与 www 文档根，整棵树 chmod 0700 + chown -R 给 tor 账号会把站点文件与私钥一并交出去。\
请用 state/ 下的子目录，或配置目录之外的专属目录",
            base.display()
        );
    }
    Ok(())
}

fn check_roots_do_not_expose_config(cfg: &Config, config_dir: &Path) -> Result<()> {
    let norm = norm_path;
    let base = norm(config_dir);
    for l in &cfg.listeners {
        let r = norm(&l.root);
        if r == base {
            anyhow::bail!(
                "listener {}:{} 的 root 解析后就是配置目录 {} —— 该端口会把 config.toml （管理员口令哈希、MaxMind key、TLS/ECH 材料路径）当作静态文件公开出去。请把 root 指向 www 目录",
                l.address,
                l.port,
                base.display()
            );
        }
        if base.starts_with(&r) {
            anyhow::bail!(
                "listener {}:{} 的 root {} 是配置目录 {} 的祖先 —— 该端口会连同 config.toml 与 state/（TLS/ECH 私钥、rndc key）一起暴露。请把 root 指向具体的 www 目录",
                l.address,
                l.port,
                r.display(),
                base.display()
            );
        }
        // **root 落在 state/ 里**同样必须拒绝：state/ 下有 ECH 私钥（state/ech）、
        // rndc 密钥（state/dns/etc/rndc.conf）与 DNS 分区库。上面两条只挡了
        // 「root == 配置目录」与「root 是配置目录的祖先」，而 `root = "state"` 这种
        // **后代**会逃过检查 ⇒ 该端口把私钥当静态文件发出去（未认证可读），
        // 面板的文件 API 也能读写它们。
        let state_dir = base.join("state");
        if r == state_dir || r.starts_with(&state_dir) {
            anyhow::bail!(
                "listener {}:{} 的 root {} 落在 state/ 里 —— 该目录含 ECH 私钥、rndc 密钥与 DNS 分区库，把它当 docroot 等于未认证公开这些密钥。请把 root 指向具体的 www 目录",
                l.address,
                l.port,
                r.display()
            );
        }
    }
    Ok(())
}

fn resolve_ssl_material(field: &mut Option<String>, base: &Path) {
    let Some(v) = field.as_ref() else {
        return;
    };
    if v.contains("-----BEGIN") || Path::new(v).is_absolute() {
        return;
    }
    *field = Some(base.join(v).display().to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **仓库自带的 `config-test.toml` 必须始终可加载。**
    ///
    /// 为什么要有这条：它是 `scripts/start_server_test.sh` 与 `scripts/acceptance_test_ports.sh`
    /// 依赖的测试档。第 3 轮我给「listener 的 root 不许落在 `state/` 里」加了配置期校验后，
    /// 它里面的 `root = "state/l4auto"` 让**整份配置加载失败** ⇒ 那两个脚本全部起不来，
    /// 而**直到几轮之后**我为了做端到端测试去启动测试实例时才发现（也就是说那几轮里
    /// 验收脚本一直是坏的）。加校验时只想到了生产配置，没人检查测试档。
    ///
    /// 这条把「仓库里的配置」与「校验代码」钉在一起：以后再加校验，只要它误伤了自带配置，
    /// `cargo test` 当场就红。
    ///
    /// 依赖测试证书（`*.pem` 被 .gitignore 忽略、不入库）—— 缺件时按本仓库既有惯例
    /// **明确跳过并说明原因**（与 upload 测试的 `test_fs_has_room()` 同一风格），
    /// 而不是留下一个恒失败的测试。
    #[test]
    fn repo_test_config_still_loads() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let cfg_path = root.join("config-test.toml");
        if !cfg_path.is_file() {
            eprintln!("跳过：没有 {}（不在仓库里？）", cfg_path.display());
            return;
        }
        // config-test.toml 引用了这些不入库的材料；缺任何一个都无法完整加载。
        let need = [
            "cert.pem",
            "key.pem",
            "cert_ec.pem",
            "key_ec.pem",
            "state/ech/ech_keys.pem",
        ];
        let missing: Vec<&str> = need
            .iter()
            .copied()
            .filter(|p| !root.join(p).is_file())
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "跳过：测试材料缺失 {missing:?}（先跑 sh scripts/generate_test_certs.sh）"
            );
            return;
        }
        if let Err(e) = Config::load(&cfg_path) {
            panic!(
                "仓库自带的 config-test.toml 必须可加载，实际失败：{e:#}\n\
（如果这是新加的校验误伤了它，请改配置而不是放宽校验 —— 但先想清楚测试档为何要那样写）"
            );
        }
    }

    /// cert 不给 key：必须加载失败（否则该 TLS 口会静默退化成明文 HTTP）。
    #[test]
    fn tls_cert_without_key_is_rejected() {
        let toml = r#"
[[listeners]]
address = "127.0.0.1"
port = 14443
root = "/tmp/x1"
[listeners.ssl]
cert = "cert.pem"
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        let err = cfg.validate().expect_err("cert 无 key 必须报错");
        assert!(format!("{err}").contains("成对"), "错误信息应说明成对: {err}");
    }

    /// 防自曝：root **解析后**等于配置目录（或它的祖先）必须被拒。
    ///
    /// 面板侧本来有这道检查，但它只比字面量 `.`/`..` —— `"./"` 一个字就能绕过，
    /// 而 `base.join("./")` 归一化后正好是配置目录 ⇒ 该端口把 config.toml
    ///（含管理员口令哈希）当静态文件公开。
    #[test]
    fn root_must_not_expose_config_dir() {
        let cfg_dir = std::path::Path::new("/crucible");
        // 模拟 `resolve_paths` 之后的样子（函数拿到的就是绝对路径）
        let mk = |root: &str| -> Config {
            let resolved = cfg_dir.join(root).display().to_string();
            toml::from_str(&format!(
                "[[listeners]]
address = \"0.0.0.0\"
port = 1
root = {resolved:?}
"
            ))
            .expect("parse")
        };
        for bad in ["./", ".//", ".", "..", "../", "/", "/crucible", "sub/.."] {
            let cfg = mk(bad);
            let err = check_roots_do_not_expose_config(&cfg, cfg_dir)
                .err()
                .unwrap_or_else(|| panic!("root={bad} 必须被拒"));
            eprintln!("[root-check] {bad} -> {err}");
        }
        for ok in ["www", "www-apps/php", "/srv/www", "../srv/www"] {
            let cfg = mk(ok);
            assert!(
                check_roots_do_not_expose_config(&cfg, cfg_dir).is_ok(),
                "root={ok} 不该被拒"
            );
        }
    }

    /// `[tor_hs].data_dir` 会被 `chmod 0700` 并（配了 user 时）`chown -R` 给低权账号 ⇒
    /// 文件系统根、配置目录本身、配置目录的祖先都必须拒绝；两者都不会有运行期报错，
    /// 只有事后才看得出来（`chown -R / _tor` / config.toml 与 state/ 私钥归 tor）。
    #[test]
    fn tor_hs_data_dir_must_not_be_root_or_cover_config_dir() {
        let cfg_dir = std::path::Path::new("/crucible");
        let mk = |dir: &str| -> Config {
            toml::from_str(&format!(
                "[tor_hs]
enabled = true
data_dir = {dir:?}
ports = [[80, 8080]]
"
            ))
            .expect("parse")
        };
        for bad in [
            "/", "//", "/.", "/..", ".", "..", "sub/..", "/crucible", "/crucible/",
            "/crucible/state", "/crucible/www", "state",
        ] {
            let err = check_tor_hs_data_dir(&mk(bad), cfg_dir)
                .err()
                .unwrap_or_else(|| panic!("data_dir={bad} 必须被拒"));
            eprintln!("[tor-hs-data-dir] {bad} -> {err}");
        }
        for ok in [
            "/var/tor/hs",
            "/onion",
            "/srv/tor",
            "state/tor-hs/hs",
            "/crucible/state/tor-hs",
        ] {
            assert!(
                check_tor_hs_data_dir(&mk(ok), cfg_dir).is_ok(),
                "data_dir={ok} 不该被拒"
            );
        }
        // 未配置：用 state/tor-hs/hs（我们自己的目录），必须放行。
        let none: Config = toml::from_str("[tor_hs]\nenabled = true\nports = [[80, 8080]]\n")
            .expect("parse");
        assert!(check_tor_hs_data_dir(&none, cfg_dir).is_ok());
    }

    /// 第三/四批新增的几条配置期检查：写错就是**静默失效**，都必须在加载期拦下。
    #[test]
    fn path_fields_and_fake_switches_are_rejected() {
        let base = "[[listeners]]\naddress = \"127.0.0.1\"\nport = 14443\nroot = \"/tmp/pf\"\n";
        let mk = |extra: &str| -> Config {
            toml::from_str(&format!("{base}{extra}")).expect("parse")
        };
        // status_path 缺前导 `/` ⇒ h1 的精确比较永不命中（页面静默 404）
        let e = mk("status_path = \"status\"\n")
            .validate()
            .expect_err("status_path 缺 / 必须报错");
        assert!(format!("{e}").contains("status_path"), "{e}");
        assert!(mk("status_path = \"/status\"\n").validate().is_ok());

        // telemetry.path 同理
        let e = mk("[telemetry]\nenabled = true\npath = \"metrics\"\n")
            .validate()
            .expect_err("telemetry.path 缺 / 必须报错");
        assert!(format!("{e}").contains("telemetry.path"), "{e}");

        // geoip 假开关：enabled 但没有 db_path
        let e = mk("[geoip]\nenabled = true\n")
            .validate()
            .expect_err("geoip 无 db_path 必须报错");
        assert!(format!("{e}").contains("geoip"), "{e}");
        assert!(mk("[geoip]\nenabled = true\ndb_path = \"/tmp/x.mmdb\"\n")
            .validate()
            .is_ok());
    }

    /// `[[dns.https_rr]].name` 为空 ⇒ 渲染出的 HTTPS 记录名是空串（等于往 zone 里写垃圾）。
    #[test]
    fn empty_https_rr_name_is_rejected() {
        let base = "[[listeners]]\naddress = \"127.0.0.1\"\nport = 14443\nroot = \"/tmp/hr\"\n";
        let mk = |extra: &str| -> Config {
            toml::from_str(&format!("{base}{extra}")).expect("parse")
        };
        let e = mk("[[dns.https_rr]]\nname = \"\"\nech = true\n")
            .validate()
            .expect_err("https_rr 空 name 必须报错");
        assert!(format!("{e}").contains("https_rr"), "{e}");
        assert!(mk("[[dns.https_rr]]\nname = \"v.example.com\"\nech = true\n")
            .validate()
            .is_ok());
    }

    /// CONNECT-UDP（公网 UDP 中继）必须**默认关闭**，且能按 listener 打开。
    ///
    /// 这条断言的意义：中继面对运维必须是显式决定 —— 旧行为是「不配任何东西就可用」，
    /// 与 proxy（要显式规则）、上传（要 autoindex+enable_upload）都不一致。
    #[test]
    fn connect_udp_defaults_off_and_is_per_listener() {
        assert!(!ListenerConfig::default().connect_udp, "默认必须关闭");
        let base = "address = \"0.0.0.0\"
port = 1
root = \"/tmp\"
";
        let off: ListenerConfig = toml::from_str(base).expect("parse");
        assert!(!off.connect_udp, "未写该字段必须等价于关闭");
        let on: ListenerConfig =
            toml::from_str(&format!("{base}connect_udp = true
")).expect("parse");
        assert!(on.connect_udp, "显式打开必须生效");
    }

    /// ECH cover 证书的三种非法组合必须在配置期拦住。
    ///
    /// 第三种（cover 配了但 `ech = false`）最隐蔽：容器默认证书是 cover，而切换回调只在
    /// `ech_accepted()` 为真时换回真实证书 —— ECH 关掉时它**恒为假**，于是这个 listener
    /// 对外只发 cover，真实证书一次都不出现，客户端按真实身份校验证书必然失败，
    /// 而配置、面板、日志全都没有异常。
    #[test]
    fn ech_cover_cert_requires_pair_public_name_and_ech() {
        // 校验会 stat TLS 材料路径（路径写错 ⇒ 该端口每次握手都失败），
        // 所以这里用**真实存在的临时文件**，内容无关紧要。
        let dir = std::env::temp_dir().join(format!("crucible-cover-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let q = '"';
        let mk = |n: &str| -> String {
            let p = dir.join(n);
            std::fs::write(&p, b"x").expect("write");
            p.display().to_string().replace('\\', "/")
        };
        let (cert, key, cover, cover_key) = (
            mk("cert.pem"),
            mk("key.pem"),
            mk("cover.pem"),
            mk("cover.key.pem"),
        );
        let base = format!(
            "
[[listeners]]
address = {q}127.0.0.1{q}
port = 14443
root = {q}/tmp/covercheck{q}
",
            q = q
        );
        let cases: [(&str, String, &str); 3] = [
            (
                "只配 cert 不配 key",
                format!(
                    "ssl = {{ cert = {q}{cert}{q}, key = {q}{key}{q}, ech = true, ech_public_name = {q}v.example.com{q}, ech_cover_cert = {q}{cover}{q} }}
",
                    q = q
                ),
                "成对",
            ),
            (
                "cover 但没有 public_name",
                format!(
                    "ssl = {{ cert = {q}{cert}{q}, key = {q}{key}{q}, ech = true, ech_cover_cert = {q}{cover}{q}, ech_cover_key = {q}{cover_key}{q} }}
",
                    q = q
                ),
                "ech_public_name",
            ),
            (
                "cover 配了但 ech = false",
                format!(
                    "ssl = {{ cert = {q}{cert}{q}, key = {q}{key}{q}, ech = false, ech_public_name = {q}v.example.com{q}, ech_cover_cert = {q}{cover}{q}, ech_cover_key = {q}{cover_key}{q} }}
",
                    q = q
                ),
                "ssl.ech",
            ),
        ];
        for (what, ssl, want) in cases {
            let cfg: Config = toml::from_str(&format!("{base}{ssl}")).expect("parse");
            let err = cfg
                .validate()
                .err()
                .unwrap_or_else(|| panic!("{what} 必须报错"));
            let msg = format!("{err}");
            // 断言命中的是**对应的那条**检查，而不是碰巧别的错误
            assert!(msg.contains(want), "{what} 的错误信息应含 {want:?}: {msg}");
            eprintln!("[cover-check] {what} -> {msg}");
        }
        // 正对照：三项都配齐时必须通过 —— 否则上面三条可能只是「什么配置都报错」。
        let ok: Config = toml::from_str(&format!(
            "{base}ssl = {{ cert = {q}{cert}{q}, key = {q}{key}{q}, ech = true, ech_public_name = {q}v.example.com{q}, ech_cover_cert = {q}{cover}{q}, ech_cover_key = {q}{cover_key}{q} }}
",
            q = q
        ))
        .expect("parse");
        assert!(ok.validate().is_ok(), "配齐 cover/public_name/ech 时不该报错");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// §21.34：外层 cover 必须是**完整的一层** —— 配了内层 EC（`cert_ec`）就必须同时配
    /// `ech_cover_cert_ec`/`ech_cover_key_ec`，否则配置期直接拒绝。
    ///
    /// 为什么（实测复现过）：BoringSSL 按客户端 `signature_algorithms` 在 RSA/EC 证书里选，
    /// 且客户端同时支持两者时**优先 ECDSA**。外层只有 RSA 时，容器里的 EC 证书是**内层**那张
    /// ⇒ 普通客户端（默认就带 ECDSA sigalgs）和只提供 ECDSA 的探测者**都会拿到内层真实证书**，
    /// cover 完全失效、ECH 白做。这不是理论问题：在 127.0.0.1:18443 的临时实例上，三条探针
    /// （ECH / 非 ECH+RSA / 非 ECH+仅 ECDSA）拿到的指纹**完全相同**。
    #[test]
    fn ech_cover_ec_required_when_inner_ec_configured() {
        let dir = std::env::temp_dir().join(format!("crucible-cover-ec-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let q = '"';
        let mk = |n: &str| -> String {
            let p = dir.join(n);
            std::fs::write(&p, b"x").expect("write");
            p.display().to_string().replace('\\', "/")
        };
        let (cert, key) = (mk("cert.pem"), mk("key.pem"));
        let (cert_ec, key_ec) = (mk("cert_ec.pem"), mk("key_ec.pem"));
        let (cover, cover_key) = (mk("cover.pem"), mk("cover.key.pem"));
        let (cover_ec, cover_ec_key) = (mk("cover_ec.pem"), mk("cover_ec.key.pem"));
        let base = format!(
            "
[[listeners]]
address = {q}127.0.0.1{q}
port = 14444
root = {q}/tmp/coverec{q}
",
            q = q
        );

        // ① 内层有 EC、外层只有 RSA ⇒ 必须报错（错误信息要指向新字段，而不是碰巧别的检查）
        let bad: Config = toml::from_str(&format!(
            "{base}ssl = {{ cert = {q}{cert}{q}, key = {q}{key}{q}, cert_ec = {q}{cert_ec}{q}, key_ec = {q}{key_ec}{q}, \
ech = true, ech_public_name = {q}v.example.com{q}, ech_cover_cert = {q}{cover}{q}, ech_cover_key = {q}{cover_key}{q} }}
",
            q = q
        ))
        .expect("parse");
        let err = bad.validate().err().expect("内层 EC + 外层无 EC 必须报错");
        let msg = format!("{err}");
        assert!(
            msg.contains("ech_cover_cert_ec"),
            "错误信息应指向 ssl.ech_cover_cert_ec: {msg}"
        );

        // ② 外层 EC 只给一半 ⇒ 报错（成对）
        let half: Config = toml::from_str(&format!(
            "{base}ssl = {{ cert = {q}{cert}{q}, key = {q}{key}{q}, cert_ec = {q}{cert_ec}{q}, key_ec = {q}{key_ec}{q}, \
ech = true, ech_public_name = {q}v.example.com{q}, ech_cover_cert = {q}{cover}{q}, ech_cover_key = {q}{cover_key}{q}, \
ech_cover_cert_ec = {q}{cover_ec}{q} }}
",
            q = q
        ))
        .expect("parse");
        let msg2 = format!("{}", half.validate().err().expect("外层 EC 只给一半必须报错"));
        assert!(msg2.contains("成对"), "错误信息应说明成对: {msg2}");

        // ②b 反向不一致：外层给了 EC 而内层没有 ⇒ 同样拒绝（类型集合必须一致）
        let rev: Config = toml::from_str(&format!(
            "{base}ssl = {{ cert = {q}{cert}{q}, key = {q}{key}{q}, \
ech = true, ech_public_name = {q}v.example.com{q}, ech_cover_cert = {q}{cover}{q}, ech_cover_key = {q}{cover_key}{q}, \
ech_cover_cert_ec = {q}{cover_ec}{q}, ech_cover_key_ec = {q}{cover_ec_key}{q} }}
",
            q = q
        ))
        .expect("parse");
        let msg2b = format!("{}", rev.validate().err().expect("外层 EC 而内层无 EC 必须报错"));
        assert!(
            msg2b.contains("同时配或同时不配"),
            "错误信息应说明类型集合必须一致: {msg2b}"
        );

        // ③ 正对照：内/外层各自的 RSA+EC 都配齐 ⇒ 必须通过。
        //    没有这条，上面两条可能只是「什么配置都报错」。
        let ok: Config = toml::from_str(&format!(
            "{base}ssl = {{ cert = {q}{cert}{q}, key = {q}{key}{q}, cert_ec = {q}{cert_ec}{q}, key_ec = {q}{key_ec}{q}, \
ech = true, ech_public_name = {q}v.example.com{q}, ech_cover_cert = {q}{cover}{q}, ech_cover_key = {q}{cover_key}{q}, \
ech_cover_cert_ec = {q}{cover_ec}{q}, ech_cover_key_ec = {q}{cover_ec_key}{q} }}
",
            q = q
        ))
        .expect("parse");
        assert!(ok.validate().is_ok(), "内/外层 RSA+EC 配齐时不该报错");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ip_access 里的空串必须被配置期拒绝：运行期它等于「匹配所有地址」，
    /// `deny = [""]` 会让全站 403、`allow = [""]` 会放行所有人 —— 两种都只有
    /// 「站点突然全 403 / 白名单形同虚设」这一个表现，且毫无报错。
    #[test]
    fn empty_ip_access_entries_are_rejected() {
        // 用 raw string 拼 TOML，免得转义把测试自己搞错
        let load = |extra: &str| -> Config {
            toml::from_str(&format!(
                r#"
[[listeners]]
address = "127.0.0.1"
port = 14443
root = "/tmp/ipacc"
{extra}
"#
            ))
            .expect("parse")
        };
        let e = load("[ip_access]\nallow = [\"1.2.3.4\", \"  \"]")
            .validate()
            .expect_err("allow 里的空串必须报错");
        assert!(format!("{e}").contains("allow[1]"), "{e}");

        let e = load("[ip_access]\ndeny = [\"\"]")
            .validate()
            .expect_err("deny 里的空串必须报错");
        assert!(format!("{e}").contains("deny[0]"), "{e}");

        // 正常配置（含显式 "*"）不受影响
        assert!(
            load("[ip_access]\nallow = [\"10.0.0.0/8\", \"*\"]")
                .validate()
                .is_ok(),
            "合法条目不该被拦"
        );
    }

    /// §16.1：per-listener `[listeners.ip_access]` 必须被**解析**（此前字段不存在，
    /// serde 静默忽略 ⇒ 配置看着生效、实际无效），且非法条目要在配置期拒。
    #[test]
    fn per_listener_ip_access_is_parsed_and_validated() {
        let base = r#"
[[listeners]]
address = "127.0.0.1"
port = 14443
root = "/tmp/ipacc-l"
"#;
        // ① 能解析出字段（旧实现这里恒为 None → 运行期只看全局）。
        let cfg: Config = toml::from_str(&format!(
            "{base}[listeners.ip_access]\nallow = [\"10.0.0.0/8\"]\ndeny = []\n"
        ))
        .expect("parse");
        let ia = cfg.listeners[0]
            .ip_access
            .as_ref()
            .expect("per-listener ip_access 必须被解析（否则就是静默忽略）");
        assert_eq!(ia.allow, vec!["10.0.0.0/8".to_string()]);
        assert!(cfg.validate().is_ok(), "合法 per-listener ip_access 不该被拦");

        // ② 空串条目必须被配置期拒（否则运行期永不匹配 / 静默放宽）。
        let bad: Config = toml::from_str(&format!(
            "{base}[listeners.ip_access]\nallow = [\"\"]\n"
        ))
        .expect("parse");
        let e = bad.validate().expect_err("per-listener 空条目必须报错");
        let msg = format!("{e}");
        assert!(
            msg.contains("listeners.ip_access") && msg.contains("allow[0]"),
            "错误信息应定位到 listener 的 ip_access: {msg}"
        );

        // ③ 非法 CIDR 前缀同样拒。
        let bad2: Config = toml::from_str(&format!(
            "{base}[listeners.ip_access]\ndeny = [\"10.0.0.0/33\"]\n"
        ))
        .expect("parse");
        assert!(bad2.validate().is_err(), "越界前缀必须报错");
    }

    /// sni_only 但没有可比对的名字：必须加载失败（否则所有连接被丢弃）。
    #[test]
    fn sni_only_without_name_is_rejected() {
        let toml = r#"
[[listeners]]
address = "127.0.0.1"
port = 14443
root = "/tmp/x2"
[listeners.ssl]
sni_only = true
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        let err = cfg.validate().expect_err("sni_only 无名字必须报错");
        assert!(format!("{err}").contains("sni_only"), "错误信息应提到 sni_only: {err}");
    }

    /// 版本串写错：必须加载失败，而不是被静默忽略。
    #[test]
    fn unknown_tls_version_is_rejected() {
        let toml = r#"
[[listeners]]
address = "127.0.0.1"
port = 14443
root = "/tmp/x3"
[listeners.ssl]
cert = "cert.pem"
key = "key.pem"
versions = ["tls9.9"]
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        let err = cfg.validate().expect_err("非法 TLS 版本必须报错");
        assert!(format!("{err}").contains("TLS 版本"), "错误信息应提到版本: {err}");
    }

    #[test]
    fn file_open_inline_array_roundtrip() {
        let raw = r#"
            file_open = ["/php/demo.php=preview", "/static/manual.pdf=preview", "zip=download"]
        "#;
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, with = "file_open_serde")]
            file_open: FileOpenTable,
        }
        let w: Wrap = toml::from_str(raw).unwrap();
        assert_eq!(
            w.file_open.mode_for_path("/php/demo.php"),
            FileOpenMode::Preview
        );
        assert_eq!(
            w.file_open.mode_for_path("/static/manual.pdf"),
            FileOpenMode::Preview
        );
        assert_eq!(
            w.file_open.mode_for_path("/archive.zip"),
            FileOpenMode::Download
        );
    }

    #[test]
    fn file_open_serializes_inline_array() {
        let mut t = FileOpenTable::default();
        t.insert("/a.txt", FileOpenMode::Download);
        t.insert("/b.pdf", FileOpenMode::Preview);
        #[derive(Serialize)]
        struct Wrap {
            #[serde(with = "file_open_serde")]
            file_open: FileOpenTable,
        }
        let s = toml::to_string(&Wrap { file_open: t }).unwrap();
        assert!(s.contains("\"/a.txt=download\""));
        assert!(s.contains("\"/b.pdf=preview\""));
        assert!(!s.contains("[listeners.file_open]"));
    }

    #[test]
    fn listeners_file_open_do_not_share() {
        let raw = r#"
            [[listeners]]
            address = "0.0.0.0"
            port = 9095
            root = "/crucible/www-apps"
            file_open = ["/php/demo.php=preview"]

            [[listeners]]
            address = "0.0.0.0"
            port = 8443
            root = "/crucible/www"
            file_open = ["/secret.zip=download"]
        "#;
        let cfg: ConfigRaw = toml::from_str(raw).unwrap();
        assert_eq!(cfg.listeners.len(), 2);
        assert_eq!(
            cfg.listeners[0].file_open.mode_for_path("/php/demo.php"),
            FileOpenMode::Preview
        );
        assert_eq!(
            cfg.listeners[1].file_open.mode_for_path("/secret.zip"),
            FileOpenMode::Download
        );
        assert_eq!(
            cfg.listeners[0].file_open.mode_for_path("/secret.zip"),
            FileOpenMode::Auto
        );
    }

    #[test]
    fn autoindex_bool_or_struct() {
        #[derive(Deserialize)]
        struct Wrap {
            autoindex: AutoindexConfig,
        }
        let a: Wrap = toml::from_str("autoindex = true").unwrap();
        assert!(a.autoindex.enabled);
        let b: Wrap =
            toml::from_str(r#"autoindex = { enabled = true, paths = ["/pub"] }"#).unwrap();
        assert!(b.autoindex.enabled);
        assert_eq!(b.autoindex.paths, vec!["/pub".to_string()]);
    }

    #[test]
    fn admin_users_legacy_migration() {
        let raw = r#"
            [admin]
            username = "legacy"
            password_hash = "hash"
        "#;
        let raw_cfg: ConfigRaw = toml::from_str(raw).unwrap();
        let mut admin = AdminConfig {
            realm: default_admin_realm(),
            path: default_admin_path(),
            users: raw_cfg.admin.users,
            listeners_allow: Vec::new(),
            metrics_public: false,
        };
        admin.normalize_legacy(
            Some(raw_cfg.admin.username),
            Some(raw_cfg.admin.password_hash),
        );
        assert_eq!(admin.users.len(), 1);
        assert_eq!(admin.users[0].username, "legacy");
    }

    /// §18 样例字段名：`certificate` / `private_key` 必须被识别（无别名时 serde 静默丢弃，
    /// 结果是「按规格配了证书却按明文 HTTP 服务」）。
    #[test]
    fn ssl_spec18_field_aliases_are_accepted() {
        #[derive(Deserialize)]
        struct Wrap {
            ssl: SslConfig,
        }
        let w: Wrap = toml::from_str(
            r#"
            [ssl]
            certificate = "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"
            private_key = "-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----\n"
        "#,
        )
        .unwrap();
        assert!(w.ssl.cert.as_deref().unwrap().contains("BEGIN CERTIFICATE"));
        assert!(w.ssl.key.as_deref().unwrap().contains("BEGIN PRIVATE KEY"));
    }

    /// §18：`min_version = "1.2"` 应展开成 tls1.2 + tls1.3 两条。
    #[test]
    fn tls_min_max_version_expand_to_versions() {
        let mut cfg = Config::default();
        cfg.listeners = vec![ListenerConfig {
            ssl: Some(SslConfig {
                min_version: Some("1.2".into()),
                ..Default::default()
            }),
            ..Default::default()
        }];
        cfg.normalize_tls_version_ranges().unwrap();
        let v = &cfg.listeners[0].ssl.as_ref().unwrap().versions;
        assert_eq!(v, &vec!["tls1.2".to_string(), "tls1.3".to_string()]);

        // 上下界同时给出 → 只要 1.2
        let mut cfg = Config::default();
        cfg.listeners = vec![ListenerConfig {
            ssl: Some(SslConfig {
                min_version: Some("TLSv1.2".into()),
                max_version: Some("1.2".into()),
                ..Default::default()
            }),
            ..Default::default()
        }];
        cfg.normalize_tls_version_ranges().unwrap();
        assert_eq!(
            &cfg.listeners[0].ssl.as_ref().unwrap().versions,
            &vec!["tls1.2".to_string()]
        );

        // 显式 versions 优先，区间不覆盖它
        let mut cfg = Config::default();
        cfg.listeners = vec![ListenerConfig {
            ssl: Some(SslConfig {
                versions: vec!["tls1.3".into()],
                min_version: Some("1.2".into()),
                ..Default::default()
            }),
            ..Default::default()
        }];
        cfg.normalize_tls_version_ranges().unwrap();
        assert_eq!(
            &cfg.listeners[0].ssl.as_ref().unwrap().versions,
            &vec!["tls1.3".to_string()]
        );
    }

    #[test]
    fn tls_min_version_above_max_is_rejected() {
        let mut cfg = Config::default();
        cfg.listeners = vec![ListenerConfig {
            ssl: Some(SslConfig {
                min_version: Some("1.3".into()),
                max_version: Some("1.2".into()),
                ..Default::default()
            }),
            ..Default::default()
        }];
        assert!(cfg.normalize_tls_version_ranges().is_err());
    }

    /// `--config config.toml`（无目录）时基准目录必须是**绝对**路径，否则 docroot/init.sh
    /// 这些相对路径会在子进程 chdir 后错位（实测 deps/ 永不构建）。
    #[test]
    fn relative_config_path_resolves_to_absolute_base() {
        let dir = std::env::temp_dir().join(format!("crucible-cfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            r#"
[[listeners]]
address = "127.0.0.1"
port = 18081
root = "www"
"#,
        )
        .unwrap();
        // 用「目录 + 文件名」形式，模拟 `--config <dir>/config.toml`
        let cfg = Config::load(&path).unwrap();
        assert!(cfg.listeners[0].root.is_absolute());
        // 裸文件名形式（CWD = dir）——base 必须仍是绝对路径
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let cfg2 = Config::load(Path::new("config.toml"));
        std::env::set_current_dir(&cwd).unwrap();
        let cfg2 = cfg2.unwrap();
        assert!(
            cfg2.listeners[0].root.is_absolute(),
            "relative --config must still yield absolute root: {:?}",
            cfg2.listeners[0].root
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
