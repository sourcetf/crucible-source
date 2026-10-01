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
            l4_forward: None,
            quic_ecn: false,
            qmux: false,
            connect_udp: false,
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
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub cert_ec: Option<String>,
    #[serde(default)]
    pub key_ec: Option<String>,
    #[serde(default)]
    pub versions: Vec<String>,
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
        let base = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
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
        cfg.validate()?;
        Ok(cfg)
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

        // ip_access 的空条目：运行期 `access::cidr_or_exact("")` 把空串当成**匹配所有地址**
        // （`pattern.is_empty() || pattern == "*" => true`），于是手写配置里一个空项
        // （`allow = ["1.2.3.4", ""]`、deny 里多打一个逗号）会变成「整站 403」或「放行所有人」
        // ——两种结果都不会有任何报错，只表现为「站点突然全 403 / 白名单形同虚设」。
        // 面板保存路径（admin.rs::check_ip_access_entry）已经拒空串，这里补上配置期这一道。
        for (name, list) in [
            ("allow", &self.ip_access.allow),
            ("deny", &self.ip_access.deny),
        ] {
            for (i, p) in list.iter().enumerate() {
                if p.trim().is_empty() {
                    anyhow::bail!(
                        "[ip_access].{name}[{i}] 是空串 —— 运行期空串等于「匹配所有地址」\
（deny 会让全站 403、allow 会放行所有人），请删掉这一项或显式写 \"*\""
                    );
                }
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
                    ("ssl.ech_cover_cert", &ssl.ech_cover_cert),
                    ("ssl.ech_cover_key", &ssl.ech_cover_key),
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

/// 判据（对每个 listener 的 root，经过 `resolve_paths` 后已是绝对路径）：
/// root **等于**配置目录 ⇒ 目录列表/静态服务会把 `config.toml` 端出去；
/// root 是配置目录的**祖先** ⇒ 连 `config.toml` 与 `state/`（TLS/ECH 私钥、rndc key）
/// 一起暴露。两种都拒绝，并在错误里说清为什么会危险。
///
/// 比较用「按组件消除 `..`/`.`」的字典序规范化（不要求目录存在，也不跟随符号链接）——
/// 这是配置期就该拦住的形态问题；真实路径解析留给运行期的 canonicalize 一致性检查。
fn check_roots_do_not_expose_config(cfg: &Config, config_dir: &Path) -> Result<()> {
    let norm = |p: &Path| -> std::path::PathBuf {
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
}
