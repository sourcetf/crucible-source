//! Let's Encrypt 自动签发（需求 8：DoT/DoH 域名证书）。
//!
//! 设计：
//! - 启动时**先**拉起 HTTP-01 挑战监听（:80，独立 mini h1，有连接上限/头读超时），
//!   再在后台执行签发；失败按 5min→30min→2h→6h→24h 退避重试，不等待 60 天。
//!   :80 与主 listener 的集成（早退路由）见修复总结的跨文件需求。
//! - 工具链探测顺序：acme.sh → acme-client(OpenBSD) → certbot；三者全缺时
//!   降级为提示手动证书（`dns.dot.cert/key` 直接给 PEM 路径——验收与无外网
//!   环境的推荐路径）。三条路径 CA/参数一致（acme.sh `--server letsencrypt`）。
//! - 证书落盘 `state/dns/acme/<domain>/{fullchain.pem,privkey.pem}`；
//!   `dns.dot.cert = "acme:<domain>"` 即自动指向该路径；安装后校验配对/权限。
//! - 续期：`renew_days`（下限 30 天）+ 抖动；失败走短退避。DoT 侧按材料 mtime
//!   自动重载证书，续期后无需重启。
//! - DoH 的证书走 web listener 的 TLS（SNI 分流复用 443），若需独立证书
//!   在对应 listener ssl 里为 DoH 域名配证书即可

use crate::config::Config;
use std::path::PathBuf;
use std::sync::Arc;

/// ACME 配置（[dns.acme]）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcmeCfg {
    #[serde(default)]
    pub enabled: bool,
    /// 申请证书的域名（如 dns.example.com）
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub email: String,
    /// HTTP-01 challenge 目录（默认 state/dns/acme/www）
    #[serde(default)]
    pub webroot: Option<String>,
    /// 续期检查间隔（天，默认 60）
    #[serde(default = "default_renew_days")]
    pub renew_days: u64,
    /// ACME directory URL（空/None = Let's Encrypt production）。
    ///
    /// 用途：LE staging（`https://acme-staging-v02.api.letsencrypt.org/directory`）
    /// 预检、以及本地测试 CA（pebble：`https://localhost:14000/dir`）。此前该值写死
    /// 成 acme.sh 的 `--server letsencrypt` 别名 —— 测试/预发环境**无法**把整条
    /// 探测链指向自定义 CA，只能在生产 CA 上做真机验证。
    #[serde(default)]
    pub server: Option<String>,
    /// 跳过 ACME 服务端 TLS 证书校验（仅测试 CA，如 pebble 的自签目录端点）。
    /// 生产必须保持 false（默认）。
    #[serde(default)]
    pub insecure: bool,
    /// HTTP-01 挑战监听端口；0 = 80。非 root 测试实例可改高端口（pebble 的
    /// `httpPort` 必须与之对齐），否则 bind :80 失败、首次签发必然失败。
    #[serde(default)]
    pub http_port: u16,
    /// 挑战类型："http-01"（默认）或 "dns-01"（G-07）。
    ///
    /// dns-01 的 TXT 写进**本机权威区**：acme.sh 的自定义 dnsapi hook 把
    /// `_acme-challenge.<domain>` TXT 写进本进程的 spool 目录，由 worker 通过模块
    /// zone API（records 表 + reconcile）写入/清理 —— 不依赖 nsupdate/动态更新。
    #[serde(default = "default_challenge")]
    pub challenge: String,
}

pub fn default_challenge() -> String {
    "http-01".to_string()
}

impl AcmeCfg {
    /// 是否 dns-01 挑战（大小写/前后空白不敏感）。
    pub fn challenge_is_dns01(&self) -> bool {
        self.challenge.trim().eq_ignore_ascii_case("dns-01")
    }
    /// 校验后的规范化挑战名；未知值返回 None。
    pub fn challenge_kind(&self) -> Option<&'static str> {
        match self.challenge.trim().to_ascii_lowercase().as_str() {
            "" | "http-01" => Some("http-01"),
            "dns-01" => Some("dns-01"),
            _ => None,
        }
    }
}

fn default_renew_days() -> u64 {
    60
}

// 整节缺失时 serde 走 `Default::default()`，必须与字段级默认一致：
// derive 的 Default 给 renew_days=0（status 面板显示 0，语义上等于「每次检查都续期」），
// 与文档默认 60 天相反。
impl Default for AcmeCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            domain: String::new(),
            email: String::new(),
            webroot: None,
            renew_days: default_renew_days(),
            server: None,
            insecure: false,
            http_port: 0,
            challenge: default_challenge(),
        }
    }
}

pub fn acme_root() -> PathBuf {
    super::state_root().join("acme")
}

/// Domain label used as a single path segment under state/dns/acme/.
/// Rejects empty, absolute, separators, and `..` (path traversal).
pub fn safe_domain_segment(domain: &str) -> Option<&str> {
    let d = domain.trim().trim_end_matches('.');
    if d.is_empty() || d.len() > 253 {
        return None;
    }
    if d == "." || d == ".." || d.contains("..") {
        return None;
    }
    if d.contains('/') || d.contains('\\') || d.bytes().any(|b| b == 0) {
        return None;
    }
    // Hostnames: alnum, hyphen, underscore, dot only.
    if !d.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
        return None;
    }
    Some(d)
}

pub fn cert_path(domain: &str) -> PathBuf {
    let seg = safe_domain_segment(domain).unwrap_or("_invalid");
    acme_root().join(seg).join("fullchain.pem")
}

pub fn key_path(domain: &str) -> PathBuf {
    let seg = safe_domain_segment(domain).unwrap_or("_invalid");
    acme_root().join(seg).join("privkey.pem")
}

/// cert 证书路径解析：`acme:<domain>` 前缀 → ACME 签发路径；其它按字面路径。
/// DoT/DoH 配置统一走这里，方便面板一键切换自动/手动证书。
pub fn resolve_cert_path(spec: &str) -> PathBuf {
    if let Some(domain) = spec.strip_prefix("acme:") {
        cert_path(domain.trim())
    } else {
        PathBuf::from(spec)
    }
}

pub fn resolve_key_path(spec: &str) -> PathBuf {
    if let Some(domain) = spec.strip_prefix("acme:") {
        key_path(domain.trim())
    } else {
        PathBuf::from(spec)
    }
}

/// 启动入口：（1）**先**拉起 HTTP-01 :80 并等待 bind 结果（2）后台执行签发/续期循环。
///
/// 顺序为什么必须这样：旧实现在 `await` 完整个外部工具签发流程（可能数十秒）之后才
/// bind :80 —— 而首次签发时 :80 上根本没有服务（web listener 还没起，也不服务 ACME
/// webroot），LE 的 HTTP-01 校验必然拉取失败 ⇒ 全新部署永远拿不到证书，还要等
/// `renew_days`（默认 60 天）后的下一轮。签发放后台同时保证不阻塞启动。
pub async fn startup(cfg: &AcmeCfg, dns: std::sync::Arc<super::DnsConfig>) {
    if !cfg.enabled || cfg.domain.is_empty() {
        return;
    }
    if safe_domain_segment(&cfg.domain).is_none() {
        log::warn!("dns-acme: refusing unsafe domain {:?}", cfg.domain);
        return;
    }
    if cfg.challenge_kind().is_none() {
        log::warn!(
            "dns-acme: 未知 challenge {:?}（只支持 http-01 / dns-01），跳过签发",
            cfg.challenge
        );
        return;
    }
    let domain = cfg.domain.clone();
    let webroot = cfg
        .webroot
        .clone()
        .unwrap_or_else(|| acme_root().join("www").display().to_string());
    // (1) HTTP-01 challenge 监听：仅 http-01 需要；dns-01 不占 :80。
    if !cfg.challenge_is_dns01() {
        let port = if cfg.http_port == 0 { 80 } else { cfg.http_port };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(http01_listener(webroot.clone(), port, Some(ready_tx)));
        match tokio::time::timeout(std::time::Duration::from_secs(3), ready_rx).await {
            Ok(Ok(true)) => log::info!("dns-acme: http-01 challenge listener ready on :{port}"),
            Ok(Ok(false)) => log::warn!("dns-acme: bind :{port} failed —— HTTP-01 不可用，签发会失败"),
            _ => log::warn!("dns-acme: http-01 listener bind 未在 3s 内确认，继续尝试签发"),
        }
    } else {
        log::info!("dns-acme: challenge=dns-01（TXT 写入本机权威区，不监听 :80）");
    }
    // (2) 签发/续期循环（后台）：失败按退避重试而不是死等 renew_days；成功按 renew_days
    //     ±抖动再查。renew_days 下限钳到 30 天（LE 证书 90 天，面板把它设成 1 会持续
    //     撞 CA 的失败限额 5 次/小时）。
    let days = cfg.renew_days.max(30);
    let c = cfg.clone();
    let dns_cfg = std::sync::Arc::clone(&dns);
    tokio::spawn(async move {
        let mut fails: u32 = 0;
        loop {
            let c2 = c.clone();
            let d2 = std::sync::Arc::clone(&dns_cfg);
            let r = tokio::task::spawn_blocking(move || issue_if_missing(&c2, &d2)).await;
            match r {
                Ok(Ok(())) => {
                    if fails == 0 {
                        log::info!("dns-acme: cert ready for {domain}");
                    } else {
                        log::info!("dns-acme: issue recovered for {domain}（重试 {fails} 次后成功）");
                    }
                    fails = 0;
                }
                Ok(Err(e)) => {
                    fails = fails.saturating_add(1);
                    log::warn!(
                        "dns-acme: issue failed for {domain}: {e:#}（{}s 后重试；renew_days={days}）",
                        with_jitter(fail_backoff_secs(fails))
                    );
                }
                Err(e) => {
                    fails = fails.saturating_add(1);
                    log::warn!("dns-acme: issue join: {e}（{}s 后重试）", fail_backoff_secs(fails));
                }
            }
            let delay = if fails == 0 {
                with_jitter(days.saturating_mul(86400))
            } else {
                with_jitter(fail_backoff_secs(fails))
            };
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
    });
}

/// 签发失败后的退避阶梯（秒）：5min → 30min → 2h → 6h → 24h 封顶。
/// 旧实现失败后要再等一整个 `renew_days`（默认 60 天）才重试；配置错误时每次重启
/// 又立刻打一次 CA。短退避让「:80 端口被占」这类可修复问题能自愈，同时不刷 CA。
const ACME_FAIL_BACKOFF: [u64; 5] = [300, 1800, 7200, 21600, 86400];

fn fail_backoff_secs(fails: u32) -> u64 {
    let i = (fails.saturating_sub(1) as usize).min(ACME_FAIL_BACKOFF.len() - 1);
    ACME_FAIL_BACKOFF[i]
}

/// 加 0..~10% 随机抖动：避免多实例/重启风暴在同一秒一起打 CA（LE 失败限额 5 次/小时）。
fn with_jitter(secs: u64) -> u64 {
    use rand_core::{OsRng, RngCore};
    let span = (secs / 10).max(1);
    secs.saturating_add(OsRng.next_u64() % span)
}

/// 进程级签发互斥：面板「立即签发」与续期循环可能并发，同一域名同时 `--issue`
/// 会触发 CA 的 duplicate-certificate 限额（LE 5 次/周）。（在 [`issue`] 内加锁，
/// 两条路径都经过它。）
static ISSUE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 证书已存在（且私钥在、30 天内不会过期）→ 跳过；否则调外部工具签发。
///
/// 私钥也必须在：只有 `fullchain.pem`、私钥丢失/损坏时旧实现永远不会重新签发，
/// DoT 拿着配不上对的材料握手失败。
fn issue_if_missing(cfg: &AcmeCfg, dns: &super::DnsConfig) -> anyhow::Result<()> {
    // 面板「立即签发」与自动续期共用本函数：域名没填时给出可定位的错误
    // （旧面板路径对空域名报 "unsafe domain \"\"" 之类，看不出是配置缺失）。
    if cfg.domain.trim().is_empty() {
        anyhow::bail!("[dns.acme] domain 未配置 —— 请先在面板填写证书域名");
    }
    if safe_domain_segment(&cfg.domain).is_none() {
        anyhow::bail!("unsafe ACME domain {:?}", cfg.domain);
    }
    if cfg.challenge_kind().is_none() {
        anyhow::bail!(
            "[dns.acme] challenge 只支持 http-01 | dns-01（收到 {:?}）",
            cfg.challenge
        );
    }
    let cp = cert_path(&cfg.domain);
    let kp = key_path(&cfg.domain);
    if cp.is_file() && kp.is_file() && cert_valid(&cp) {
        return Ok(());
    }
    issue(cfg, dns)
}

/// openssl x509 -checkend 30 天探测有效期。
pub fn cert_valid(p: &std::path::Path) -> bool {
    std::process::Command::new("openssl")
        .args(["x509", "-in"])
        .arg(p)
        .args(["-noout", "-checkend", "2592000"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 运行外部签发工具并捕获输出：成功返回 Some(output)；失败按类别记日志（含
/// `rateLimited` 单独标记）、把可读摘要收进 `failures`（最终回给面板）并返回 None。
fn run_client(
    cmd: &mut std::process::Command,
    who: &str,
    failures: &mut Vec<String>,
) -> Option<std::process::Output> {
    match cmd.output() {
        Ok(o) if o.status.success() => Some(o),
        Ok(o) => {
            let summary = log_client_failure(who, &o);
            failures.push(format!("{who}: {summary}"));
            None
        }
        Err(e) => {
            log::warn!("dns-acme: {who} 无法启动: {e}");
            failures.push(format!("{who}: 无法启动: {e}"));
            None
        }
    }
}

/// 失败输出只留尾部（有界，避免把工具刷屏日志整段写进我们的日志），
/// 命中速率限制时单独标记 —— 否则一周内无法签发而面板毫无提示。
fn log_client_failure(who: &str, o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr);
    let low = err.to_ascii_lowercase();
    let summary = summarize_client_failure(&err);
    let rate_limited = low.contains("ratelimited")
        || low.contains("rate limit")
        || low.contains("too many certificates")
        || low.contains("too many failed");
    if rate_limited {
        log::warn!("dns-acme: {who} 命中 CA 速率限制（rateLimited，可能一周内无法签发）: {summary}");
    } else {
        log::warn!("dns-acme: {who} 退出失败: {summary}");
    }
    summary
}

/// 把外部客户端 stderr 压缩成可读摘要（G-25）。
///
/// 现状问题：acme.sh/curl 在 HTTP 错误时会把 CA 返回的 **HTML 错误页**整段打到
/// stderr，旧实现取末 800 字符 —— 日志里是一堆 `<html><body><h1>…`，真正的
/// `error code: 7` / `detail: …` 被挤到 800 字符之外（或淹没在标签里），排障只能
/// 反推 exit code。
///
/// 规则（确定性、纯函数，便于单测）：
/// 1. 逐行去掉 HTML 标签；丢弃纯标签/空白行；
/// 2. 优先保留含关键字的行：`error code:` / `detail` / `error` / `failed` /
///    `invalid` / `refused` / `timeout` / `too many` / `rate.?limit`；
/// 3. 一个关键字行都没有时，退化为「去标签后的全文尾部 800 字符」；
/// 4. 结果仍是单行化（换行压成 ` | `）且有界（≤800 字符），日志不会被刷屏。
fn summarize_client_failure(stderr: &str) -> String {
    fn strip_tags(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut in_tag = false;
        for ch in line.chars() {
            match ch {
                '<' => in_tag = true,
                '>' if in_tag => in_tag = false,
                c if !in_tag => out.push(c),
                _ => {}
            }
        }
        out.replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .trim()
            .to_string()
    }
    let key = |s: &str| {
        let l = s.to_ascii_lowercase();
        l.contains("error code:")
            || l.contains("detail")
            || l.contains("error")
            || l.contains("failed")
            || l.contains("invalid")
            || l.contains("refused")
            || l.contains("timeout")
            || l.contains("too many")
            || l.contains("rate limit")
            || l.contains("ratelimited")
    };
    let mut picked: Vec<String> = Vec::new();
    let mut plain: Vec<String> = Vec::new();
    for raw in stderr.lines() {
        let s = strip_tags(raw);
        if s.is_empty() {
            continue;
        }
        if key(&s) {
            picked.push(s.clone());
        }
        plain.push(s);
    }
    let joined = if picked.is_empty() {
        // 没有关键字行：用去标签后的纯文本（去掉连续空白），保留尾部。
        let text = plain.join(" ");
        let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let tail: String = compact
            .chars()
            .rev()
            .take(800)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        tail
    } else {
        // 关键字行可能很多（HTML 每行都含 "error"），取尾部并去重。
        let mut out: Vec<String> = Vec::new();
        for s in picked {
            if out.last().map(|p| p == &s).unwrap_or(false) {
                continue;
            }
            out.push(s);
        }
        // 从末尾取，保证最近的错误在前因后果上完整；总长 ≤800。
        let mut acc: Vec<String> = Vec::new();
        let mut len = 0usize;
        for s in out.into_iter().rev() {
            if len + s.len() + 3 > 800 && !acc.is_empty() {
                break;
            }
            len += s.len() + 3;
            acc.push(s);
        }
        acc.into_iter().rev().collect::<Vec<_>>().join(" | ")
    };
    if joined.is_empty() {
        "<empty stderr>".to_string()
    } else {
        joined
    }
}

/// 依次探测 acme.sh / acme-client / certbot 签发（http-01 或 dns-01）。
///
/// 要点：三条工具路径的 CA/参数保持一致（acme.sh 显式 `--server letsencrypt` +
/// `ec-256`；certbot 不传 `--cert-path/--key-path`——那两个参数只在 `certonly --csr`
/// 语义下有效，普通 certonly 会静默忽略，制造「退出 0 但 out_dir 没文件」的假成功）。
///
/// dns-01（G-07）：acme.sh 走自定义 dnsapi hook（`--dns dns_crucible --dnssleep 2`），
/// hook 把 `_acme-challenge.<domain>` TXT 交给本进程 worker（spool 协议），worker
/// 通过模块 zone API 写入/清理；certbot 走 `--manual --preferred-challenges dns`
/// + auth/cleanup hook。
/// acme-client 没有 hook 机制（只做 webroot http-01），dns-01 下跳过。
fn issue(cfg: &AcmeCfg, dns: &super::DnsConfig) -> anyhow::Result<()> {
    // 面板「立即签发」与续期循环共用本函数：同一时刻只允许一个签发进程，
    // 避免并发 --issue 触发 CA 的 duplicate-certificate 限额。
    let _guard = ISSUE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // **拿锁后必须重新检查证书**：`issue_if_missing` 在锁外检查「证书不存在」，
    // 而启动期自动签发与面板「立即签发」会并发 —— 真机实测：启动那次先拿锁、签发
    // 成功并安装证书；面板那次在锁外看到旧状态，拿锁后又跑一遍 acme.sh。acme.sh
    // 发现目录里已有未过期证书会直接退出非 0（stderr 为空），面板因此报「签发失败」
    // —— 证书其实已经签好了（假失败），还白打了一次 CA。
    if let Some(d) = safe_domain_segment(&cfg.domain) {
        let cp = acme_root().join(d).join("fullchain.pem");
        let kp = acme_root().join(d).join("privkey.pem");
        if cp.is_file() && kp.is_file() && cert_valid(&cp) {
            log::info!("dns-acme: 证书已有效，跳过重复签发（{}）", cfg.domain);
            return Ok(());
        }
    }
    let domain = safe_domain_segment(&cfg.domain)
        .ok_or_else(|| anyhow::anyhow!("unsafe ACME domain {:?}", cfg.domain))?;
    let kind = cfg
        .challenge_kind()
        .ok_or_else(|| anyhow::anyhow!("unknown ACME challenge {:?}", cfg.challenge))?;
    let dns01 = kind == "dns-01";
    let out_dir = acme_root().join(domain);
    let www = cfg
        .webroot
        .clone()
        .unwrap_or_else(|| acme_root().join("www").display().to_string());
    std::fs::create_dir_all(&out_dir)?;
    std::fs::create_dir_all(std::path::Path::new(&www).join(".well-known/acme-challenge"))?;

    // dns-01 的写路径：hook 把请求写进 spool 目录，本进程的 worker 线程通过模块
    // 自己的 zone API（records 表 + reconcile）写入 `_acme-challenge.<domain>` TXT。
    //
    // 为什么不用 nsupdate/动态更新：BIND 的动态更新会把 zone serial 顶到当前 unix 秒，
    // 与模块「按 unix 秒生成文件 serial」冲突 —— 文件 serial 与内存 serial 相同，
    // `rndc reload` 判定无变化而跳过；真机实测出现「签发期间加的记录一直 NXDOMAIN」。
    // 本模块的 zone 文件由 DB 全量生成，动态更新本来就会被下一次 reconcile 覆盖，
    // 因此走 DB 是唯一自洽的路径（也符合任务允许的「通过现有 zone API」）。
    let _dns01_spool = if dns01 {
        Some(Dns01Spool::start(dns).map_err(|e| anyhow::anyhow!("dns-01 spool: {e:#}"))?)
    } else {
        None
    };
    let spool_env = _dns01_spool
        .as_ref()
        .map(|s| s.dir.display().to_string())
        .unwrap_or_default();
    if dns01 {
        log::info!(
            "dns-acme: dns-01 挑战经模块 zone API 写入（spool {}，domain {}）",
            spool_env,
            dns.port_or_default()
        );
    }

    // 「客户端找到但执行失败」的清单：最终错误里必须区分「一个都没装」与
    // 「装了但失败」。旧实现两种情况都报 `no acme client available` —— 面板按钮
    // 明明有 acme.sh 却回「没有客户端」，真正原因（rateLimited 等）只在服务日志里。
    let mut attempted: Vec<String> = Vec::new();
    // 失败摘要：最终错误回给面板，避免面板只能看到「见服务日志」（G-25）。
    let mut failures: Vec<String> = Vec::new();
    // ACME directory：空 = LE production（acme.sh 的 `letsencrypt` 别名）。自定义值
    // （staging / pebble / 私有 CA）原样传给客户端；certbot 只接受 URL，故仅在显式
    // 配置时传 `--server`（否则用 certbot 自己的默认 CA，避免把 `letsencrypt` 这个
    // acme.sh 别名喂给 certbot 导致「无法解析服务器」）。
    let custom_server = cfg
        .server
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let acme_server = custom_server.clone().unwrap_or_else(|| "letsencrypt".to_string());
    // 1) acme.sh（用户目录安装或 /usr/local）；HOME 缺失时无法定位 ~/.acme.sh，跳过。
    // 走 env_lock 缓存读 HOME：本函数跑在 spawn_blocking 线程里，与请求路径上应用引擎
    // 的 setenv（perl/python/ruby 的 ENV 注入）并发 —— libc setenv 可能 realloc environ，
    // 此刻任何其它线程的 getenv 都会踩到已释放内存（仓库里已实测出同类 SIGSEGV）。
    let home = crate::server::apps::env_lock::read_static_env("HOME").unwrap_or_default();
    if !home.trim().is_empty() {
        // dns-01：把自定义 dnsapi hook 放进 acme.sh 的工作目录（`_findHook` 会找
        // `$LE_WORKING_DIR/dnsapi/dns_crucible.sh`）。
        let hook_ready = if dns01 {
            match write_acme_dnsapi_hook(&home) {
                Ok(p) => {
                    log::info!("dns-acme: dnsapi hook {}", p.display());
                    true
                }
                Err(e) => {
                    log::warn!("dns-acme: 写入 dnsapi hook 失败: {e:#}");
                    false
                }
            }
        } else {
            true
        };
        for bin in ["/usr/local/bin/acme.sh", "$HOME/.acme.sh/acme.sh"] {
            let bin = bin.replace("$HOME", &home);
            if std::path::Path::new(&bin).is_file() {
                if dns01 && !hook_ready {
                    attempted.push(format!("acme.sh（{bin}，dnsapi hook 写入失败）"));
                    continue;
                }
                let mut cmd = std::process::Command::new(&bin);
                cmd.arg("--issue")
                    .arg("-d").arg(&cfg.domain)
                    .arg("--server").arg(&acme_server)
                    .arg("-m").arg(&cfg.email)
                    .arg("--keylength").arg("ec-256")
                    .env("LE_WORKING_DIR", format!("{home}/.acme.sh"));
                if dns01 {
                    // --dnssleep 让 acme.sh **跳过**它自己的公共 DNS 查询（本机权威区
                    // 不在公网 DNS 里，查了必然失败），只等 worker 写库 + reconcile 生效。
                    cmd.arg("--dns").arg("dns_crucible").arg("--dnssleep").arg("2");
                    // --log：把 acme.sh 的挑战流程写进 .acme.sh/acme.sh.log，排障/验收
                    // 可以确认 hook 的 add/del 是否真的被执行。
                    cmd.arg("--log");
                    cmd.env("CRUCIBLE_ACME_HOOK_DIR", &spool_env);
                } else {
                    cmd.arg("--webroot").arg(&www);
                }
                if cfg.insecure {
                    // acme.sh `--insecure`：不校验 ACME 目录端点的证书（pebble 自签）。
                    cmd.arg("--insecure");
                }
                if run_client(&mut cmd, "acme.sh --issue", &mut failures).is_some() {
                    let r = install_acme_sh(&bin, &cfg.domain, &out_dir);
                    if dns01 {
                        post_issue_reconcile(dns, "issue");
                    }
                    return r;
                }
                attempted.push(format!("acme.sh（{bin}）"));
            }
        }
    } else {
        log::warn!("dns-acme: HOME 未设置，跳过 acme.sh（无法定位其工作目录）");
    }
    // 2) OpenBSD acme-client（base 或 pkg）。它没有 dns-01 hook 机制，dns-01 下跳过。
    if dns01 {
        log::info!("dns-acme: acme-client 不支持 dns-01 hook，跳过（用 acme.sh 或 certbot）");
    } else if std::path::Path::new("/usr/local/sbin/acme-client").is_file()
        || std::path::Path::new("/usr/sbin/acme-client").is_file()
    {
        let bin = if std::path::Path::new("/usr/sbin/acme-client").is_file() {
            "/usr/sbin/acme-client"
        } else {
            "/usr/local/sbin/acme-client"
        };
        // acme-client 需要 /etc/acme 配置与账户；挑战目录 webroot
        let mut cmd = std::process::Command::new(bin);
        cmd.arg("-v").arg("-C").arg(&www).arg("-D").arg(&cfg.domain).arg(&cfg.domain);
        if run_client(&mut cmd, "acme-client", &mut failures).is_some() {
            // acme-client 默认产出 /etc/acme/<domain>/{fullchain,privkey}.pem
            let src = std::path::Path::new("/etc/acme").join(&cfg.domain);
            let _ = std::fs::copy(src.join("fullchain.pem"), out_dir.join("fullchain.pem"));
            let _ = std::fs::copy(src.join("privkey.pem"), out_dir.join("privkey.pem"));
            ensure_installed(&out_dir, "acme-client")?;
            return Ok(());
        }
        attempted.push(format!("acme-client（{bin}）"));
    }
    // 3) certbot：证书固定落在 /etc/letsencrypt/live/<domain>/，必须显式拷进 out_dir 并确认。
    if let Ok(found) = which("certbot") {
        let mut hook_ok = true;
        let mut cmd = std::process::Command::new(&found);
        cmd.arg("certonly");
        if dns01 {
            // certbot 的 manual dns 模式：auth/cleanup hook 从环境变量拿
            // CERTBOT_DOMAIN / CERTBOT_VALIDATION。
            match write_certbot_dns_hook(&home) {
                Ok(hook) => {
                    cmd.arg("--manual")
                        .arg("--preferred-challenges").arg("dns")
                        .arg("--manual-auth-hook").arg(format!("{} auth", hook.display()))
                        .arg("--manual-cleanup-hook")
                        .arg(format!("{} cleanup", hook.display()));
                }
                Err(e) => {
                    log::warn!("dns-acme: 写入 certbot dns hook 失败: {e:#}");
                    hook_ok = false;
                }
            }
        } else {
            cmd.arg("--webroot").arg("-w").arg(&www);
        }
        if !hook_ok {
            attempted.push("certbot（dns hook 写入失败）".to_string());
        } else {
            cmd.arg("-d").arg(&cfg.domain)
                .arg("-m").arg(&cfg.email)
                .arg("--agree-tos")
                .arg("--non-interactive");
            // certbot 的 `--server` 只接受 URL（acme.sh 的 `letsencrypt` 别名对它非法）。
            if let Some(s) = &custom_server {
                cmd.arg("--server").arg(s);
            }
            if cfg.insecure {
                cmd.arg("--no-verify-ssl");
            }
            if dns01 {
                cmd.env("CRUCIBLE_ACME_HOOK_DIR", &spool_env);
            }
            if run_client(&mut cmd, "certbot", &mut failures).is_some() {
                let src = std::path::Path::new("/etc/letsencrypt/live").join(domain);
                let _ = std::fs::copy(src.join("fullchain.pem"), out_dir.join("fullchain.pem"));
                let _ = std::fs::copy(src.join("privkey.pem"), out_dir.join("privkey.pem"));
                ensure_installed(&out_dir, "certbot")?;
                if dns01 {
                    post_issue_reconcile(dns, "issue");
                }
                return Ok(());
            }
            attempted.push(format!("certbot（{found}）"));
        }
    }
    let manual = format!(
        "手动模式：把证书放到 {} 与 {}，或在 dns.dot.cert/key 直接写路径",
        out_dir.join("fullchain.pem").display(),
        out_dir.join("privkey.pem").display()
    );
    if dns01 {
        // 失败路径也要收尾：hook 可能已写入 TXT（或上次泄漏），reconcile 会按 DB
        // 重写 zone 并删掉 journal（挑战记录随之中止）。
        post_issue_reconcile(dns, "issue-failure");
    }
    if attempted.is_empty() {
        anyhow::bail!(
            "no acme client available (tried acme.sh / acme-client / certbot) — {manual}"
        );
    }
    // 找到但失败：失败原因（含 rateLimited 标记）已由 log_client_failure 写进服务日志，
    // 这里把「是哪个客户端失败」+ 最后一段**可读摘要**（HTML 已剥掉）带回面板。
    let last = failures
        .last()
        .map(|s| format!("；最近失败：{s}"))
        .unwrap_or_default();
    anyhow::bail!(
        "ACME 客户端已找到但执行失败：{}{}（完整日志见服务日志 `dns-acme:` 行）—— {manual}",
        attempted.join("、"),
        last
    )
}

/// dns-01 收尾：签发结束后用模块的 DB/zone 生成器 reconcile 一次。
///
/// 为什么必须做：hook 写入的挑战 TXT 直接进 records 表，签发结束（含失败）后要
/// 保证 DB/zone 文件/内存三者一致：删掉可能残留的 `_acme-challenge` TXT（hook 崩溃、
/// acme.sh 被 kill 时 rm 不会执行），再按 DB 重写 zone 并 reload。
fn post_issue_reconcile(dns: &super::DnsConfig, who: &str) {
    cleanup_challenge_records(&dns.acme.domain);
    match super::reconcile(dns) {
        Ok(()) => log::info!(
            "dns-acme: post-{who} reconcile ok（清理挑战记录 / 同步 zone 文件与 serial）"
        ),
        Err(e) => log::warn!("dns-acme: post-{who} reconcile failed: {e:#}"),
    }
}

/// dns-01 请求 spool 目录：hook 写 `.req`，worker 处理后写 `.ack`。
fn dns01_spool_dir() -> std::path::PathBuf {
    acme_root().join("dns01-spool")
}

/// dns-01 spool worker 的生命周期守卫：随 [`issue`] 返回一起停线程并清目录。
struct Dns01Spool {
    dir: std::path::PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Dns01Spool {
    fn start(dns: &super::DnsConfig) -> anyhow::Result<Self> {
        let dir = dns01_spool_dir();
        std::fs::create_dir_all(&dir)?;
        // 上次崩溃残留的 req/ack 一律清掉（否则 worker 会把陈旧挑战写进 zone）。
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = std::sync::Arc::clone(&stop);
        let d2 = dns.clone();
        let dir2 = dir.clone();
        let handle = std::thread::Builder::new()
            .name("acme-dns01".into())
            .spawn(move || dns01_worker(dir2, d2, stop2))
            .map_err(|e| anyhow::anyhow!("spawn dns-01 worker: {e}"))?;
        Ok(Self { dir, stop, handle: Some(handle) })
    }
}

impl Drop for Dns01Spool {
    fn drop(&mut self) {
        self.stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// worker 主循环：每 50ms 扫一次 `.req`，处理后原子写 `.ack` 并删除请求。
fn dns01_worker(
    dir: std::path::PathBuf,
    dns: super::DnsConfig,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let mut did = false;
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                // 请求文件名：`req-<随机>.req`；ack 是 `req-<随机>.ack`（扩展名不同）。
                if p.extension().and_then(|x| x.to_str()) != Some("req") {
                    continue;
                }
                did = true;
                let id = p
                    .file_stem()
                    .and_then(|x| x.to_str())
                    .unwrap_or("req")
                    .to_string();
                let text = std::fs::read_to_string(&p).unwrap_or_default();
                let mut lines = text.lines();
                let op = lines.next().unwrap_or("").trim().to_string();
                let name = lines.next().unwrap_or("").trim().to_string();
                let value = lines.next().unwrap_or("").trim().to_string();
                let res = dns01_apply(&dns, &op, &name, &value);
                let body = match res {
                    Ok(()) => "ok\n".to_string(),
                    Err(e) => format!("err {e}\n"),
                };
                let ack = dir.join(format!("{id}.ack"));
                let tmp = dir.join(format!("{id}.ack.tmp"));
                if std::fs::write(&tmp, body.as_bytes()).is_ok() {
                    let _ = std::fs::rename(&tmp, &ack);
                }
                let _ = std::fs::remove_file(&p);
            }
        }
        if !did {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// 执行一条 dns-01 请求：校验名字/值，定位最长匹配的 master 分区，写/删 TXT 记录
/// 并 reconcile。返回给 hook 的错误必须是可读的（acme.sh 会把 stderr 打出来）。
fn dns01_apply(
    dns: &super::DnsConfig,
    op: &str,
    name: &str,
    value: &str,
) -> Result<(), String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if !name.starts_with("_acme-challenge.") {
        return Err(format!("refusing non-challenge name: {name}"));
    }
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("bad TXT value（只接受 base64url 字符）".to_string());
    }
    let zones = super::list_zones().map_err(|e| format!("list zones: {e:#}"))?;
    let mut best: Option<(String, String)> = None;
    for z in zones.iter().filter(|z| z.kind == "master") {
        if let Some(rel) = super::relative_owner(&name, &z.name) {
            let better = best
                .as_ref()
                .map(|(zn, _)| z.name.len() > zn.len())
                .unwrap_or(true);
            if better {
                best = Some((z.name.clone(), rel));
            }
        }
    }
    let (zone, rel) = best.ok_or_else(|| format!("no master zone contains {name}"))?;
    match op {
        "add" => {
            super::add_record(&zone, "", &rel, "TXT", 60, value)
                .map_err(|e| format!("add_record: {e:#}"))?;
        }
        "del" | "rm" | "cleanup" => {
            let found = super::list_records(&zone)
                .map_err(|e| format!("list records: {e:#}"))?
                .into_iter()
                .find(|r| {
                    r.rtype.eq_ignore_ascii_case("TXT")
                        && r.name.eq_ignore_ascii_case(&rel)
                        && r.rdata.trim_matches('"') == value
                });
            if let Some(r) = found {
                super::del_record(r.id).map_err(|e| format!("del_record: {e:#}"))?;
            }
        }
        other => return Err(format!("bad op {other:?}")),
    }
    super::reconcile(dns).map_err(|e| format!("reconcile: {e:#}"))?;
    Ok(())
}

/// 签发结束后清掉配置域名对应的**全部** `_acme-challenge` TXT（hook 泄漏/崩溃兜底）。
fn cleanup_challenge_records(domain: &str) {
    let Some(ch) = super::DnsConfig {
        acme: AcmeCfg { domain: domain.to_string(), ..Default::default() },
        ..Default::default()
    }
    .acme_challenge_fqdn()
    else {
        return;
    };
    if let Ok(zones) = super::list_zones() {
        for z in zones.iter().filter(|z| z.kind == "master") {
            if let Some(rel) = super::relative_owner(&ch, &z.name) {
                if let Ok(recs) = super::list_records(&z.name) {
                    for r in recs {
                        if r.rtype.eq_ignore_ascii_case("TXT")
                            && r.name.eq_ignore_ascii_case(&rel)
                        {
                            let _ = super::del_record(r.id);
                        }
                    }
                }
            }
        }
    }
}

/// 写 hook 脚本共用的 spool 协议函数（shell）。
const SPOOL_FUNCS: &str = r#"_crucible_spool() {
  _op="$1"; _name="$2"; _val="$3"
  case "$_name" in
    _acme-challenge.*) ;;
    *) echo "crucible-dns01: refusing non-challenge name: $_name" >&2; return 1 ;;
  esac
  case "$_val" in
    ''|*[!A-Za-z0-9_-]*) echo "crucible-dns01: bad TXT value" >&2; return 1 ;;
  esac
  _tmp=$(mktemp "$CRUCIBLE_ACME_HOOK_DIR/.tmp.XXXXXX") || {
    echo "crucible-dns01: mktemp failed in $CRUCIBLE_ACME_HOOK_DIR" >&2
    return 1
  }
  _base=${_tmp##*/}
  _id=${_base#.tmp.}
  _req="$CRUCIBLE_ACME_HOOK_DIR/req-$_id.req"
  _ack="$CRUCIBLE_ACME_HOOK_DIR/req-$_id.ack"
  printf '%s\n%s\n%s\n' "$_op" "$_name" "$_val" > "$_tmp" && mv "$_tmp" "$_req"
  _i=0
  while [ ! -f "$_ack" ] && [ "$_i" -lt 300 ]; do sleep 0.1; _i=$((_i+1)); done
  if [ ! -f "$_ack" ]; then
    echo "crucible-dns01: timeout waiting for webserver to apply $_op $_name" >&2
    rm -f "$_req"
    return 1
  fi
  if grep -q '^ok' "$_ack"; then rm -f "$_ack" "$_req"; return 0; fi
  cat "$_ack" >&2; rm -f "$_ack" "$_req"; return 1
}
"#;

/// 写出 acme.sh 的自定义 dnsapi hook（dns-01）。
///
/// 约定：acme.sh `--dns dns_crucible` 会 source `$LE_WORKING_DIR/dnsapi/dns_crucible.sh`
/// 并调用 `dns_crucible_add <fulldomain> <txtvalue>` / `dns_crucible_rm ...`。
/// hook 只把请求写进 `$CRUCIBLE_ACME_HOOK_DIR`，由本进程 worker 通过 zone API 落库。
fn write_acme_dnsapi_hook(home: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = std::path::Path::new(home).join(".acme.sh/dnsapi");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("dns_crucible.sh");
    let script = format!(
        "#!/bin/sh\n# Generated by Crucible (dns-01 hook). Do not hand-edit.\n{}dns_crucible_add() {{ _crucible_spool add \"$1\" \"$2\"; }}\ndns_crucible_rm() {{ _crucible_spool del \"$1\" \"$2\"; }}\n",
        SPOOL_FUNCS
    );
    std::fs::write(&path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
    }
    Ok(path)
}

/// 写出 certbot 的 manual dns auth/cleanup hook（dns-01）。
fn write_certbot_dns_hook(home: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = std::path::Path::new(home).join(".crucible-acme");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("certbot-dns-hook.sh");
    let script = format!(
        "#!/bin/sh\n# Generated by Crucible (certbot dns-01 manual hook). Do not hand-edit.\n# $1 = auth|cleanup; certbot passes CERTBOT_DOMAIN / CERTBOT_VALIDATION.\n{}_name=\"_acme-challenge.${{CERTBOT_DOMAIN}}\"\nif [ \"$1\" = \"cleanup\" ]; then\n  _crucible_spool del \"$_name\" \"$CERTBOT_VALIDATION\"\nelse\n  _crucible_spool add \"$_name\" \"$CERTBOT_VALIDATION\"\nfi\n",
        SPOOL_FUNCS
    );
    std::fs::write(&path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
    }
    Ok(path)
}

/// 确认证书与私钥**真的落到了** `out_dir`，且两者配对、私钥权限不过宽。
///
/// 为什么必须有这一步：安装路径上每一次 `std::fs::copy` 都是 `let _ =`（吞错），
/// 而 `Ok(())` 无条件返回 —— 于是「外部客户端签好了、安装却失败/源文件名不符」会被
/// 当成成功：启动日志打 `cert ready for <domain>`、续期循环打 `renewed <domain>`，
/// 而 DoT 侧 `state/dns/acme/<domain>/fullchain.pem` 根本不存在。这与项目里反复出现的
/// 假成功（面板 ok、服务里查不到）是同一类，且掩盖的是「证书没续上」这种到期才会爆的问题。
pub fn ensure_installed(out_dir: &std::path::Path, who: &str) -> anyhow::Result<()> {
    let fc = out_dir.join("fullchain.pem");
    let kp = out_dir.join("privkey.pem");
    if !fc.is_file() || !kp.is_file() {
        anyhow::bail!(
            "{who}: 证书未落盘（缺 {} 或 {}）—— 安装步骤失败",
            fc.display(),
            kp.display()
        );
    }
    tighten_key_permissions(&kp);
    // 证书/私钥必须配对：不匹配的 DoT 材料会在每次握手才失败，错误很难定位。
    // openssl 不可用/不是 PEM 时返回 None（跳过），不因此误判签发失败。
    if let Some(false) = cert_key_pubkey_matches(&fc, &kp) {
        anyhow::bail!(
            "{who}: {} 与 {} 的公钥不匹配（安装到了错误的一对证书/私钥）",
            fc.display(),
            kp.display()
        );
    }
    Ok(())
}

/// 私钥权限收紧到 0600（宽于 0600 ⇒ 同机其它用户可读走私钥）。
fn tighten_key_permissions(kp: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(kp) {
            if m.permissions().mode() & 0o077 != 0 {
                log::warn!(
                    "dns-acme: 私钥 {} 权限过宽（{:o}），收紧到 0600",
                    kp.display(),
                    m.permissions().mode() & 0o777
                );
                let _ = std::fs::set_permissions(kp, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = kp;
    }
}

/// 用 openssl 比对证书与私钥的公钥（RSA/EC 通用；`x509 -pubkey` vs `pkey -pubout`）。
/// 返回 None = 无法判定（openssl 缺失、文件非 PEM 等）。
fn cert_key_pubkey_matches(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Option<bool> {
    let a = std::process::Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert)
        .args(["-noout", "-pubkey"])
        .output()
        .ok()?;
    let b = std::process::Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(key)
        .args(["-pubout"])
        .output()
        .ok()?;
    if !a.status.success() || !b.status.success() {
        return None;
    }
    Some(a.stdout == b.stdout)
}

pub(crate) fn install_acme_sh(
    bin: &str,
    domain: &str,
    out_dir: &std::path::Path,
) -> anyhow::Result<()> {
    // acme.sh 的安装/续期都以 HOME 为工作目录；HOME 缺失时 src_dir 会变成
    // `/.acme.sh/<domain>_ecc`（永远不存在）—— 直接给出可操作的错误。
    // 走 env_lock 缓存读：本函数从 spawn_blocking 线程调用，与请求路径上应用引擎的
    // setenv 并发（裸 getenv 会踩 realloc 后的 environ，仓库已实测出同类 SIGSEGV）。
    let home = crate::server::apps::env_lock::read_static_env("HOME").unwrap_or_default();
    if home.trim().is_empty() {
        anyhow::bail!("HOME 未设置，无法定位 acme.sh 工作目录（~/.acme.sh/{domain}_ecc）");
    }
    let src_dir = format!("{home}/.acme.sh/{domain}_ecc");
    // acme.sh --install-cert 拷贝到目标路径（幂等）。
    // 注意：**不能传 `--installcmd`** —— acme.sh 没有这个选项，未知参数直接
    // `_err "Unknown parameter"` 退出非 0，让 --install-cert 恒失败（旧实现靠后面的
    // 手工拷贝兜底才没出事）；DoT 已支持按 mtime 自动重载证书，也不需要 reload 命令。
    let st = std::process::Command::new(bin)
        .arg("--install-cert")
        .arg("-d").arg(domain)
        .arg("--ecc")
        .arg("--fullchain-file").arg(out_dir.join("fullchain.pem"))
        .arg("--key-file").arg(out_dir.join("privkey.pem"))
        .env("LE_WORKING_DIR", format!("{home}/.acme.sh"))
        .output();
    let ok = st.map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        // install-cert 失败时直接拷贝（acme.sh 的 ECC 产物文件名固定）。
        let src = std::path::Path::new(&src_dir);
        let _ = std::fs::copy(src.join("fullchain.cer"), out_dir.join("fullchain.pem"));
        let _ = std::fs::copy(src.join(format!("{domain}.key")), out_dir.join("privkey.pem"));
    }
    ensure_installed(out_dir, "acme.sh")?;
    Ok(())
}

/// 面板「立即签发」的统一入口（admin API 改调它，替代自己拼 acme.sh 命令）：
/// 与自动续期同一套 CA/参数（`--server letsencrypt`、`ec-256`，不带 `--force`），
/// 并走同一个进程级互斥。证书仍有效时直接返回 Ok（不重复打 CA 限额）。
pub fn issue_now(cfg: &AcmeCfg, dns: &super::DnsConfig) -> anyhow::Result<()> {
    issue_if_missing(cfg, dns)
}

fn which(name: &str) -> anyhow::Result<String> {
    // 走 env_lock 缓存读 PATH（同 issue()/install_acme_sh()）：本函数在 spawn_blocking
    // 线程执行，裸 getenv 与请求路径的 setenv 并发会踩已释放的 environ。
    let path = crate::server::apps::env_lock::read_static_env("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let cand = std::path::Path::new(dir).join(name);
        if cand.is_file() {
            return Ok(cand.display().to_string());
        }
    }
    anyhow::bail!("{name} not in PATH")
}

/// HTTP-01 挑战连接的硬上限：超限直接丢弃新连接（本题材只需要极少量并发）。
const HTTP01_MAX_CONNS: usize = 64;
/// 读 HTTP 头的截止时间（防 slowloris 把连接挂在头部阶段）。
const HTTP01_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// 单连接总寿命上限（keep-alive 已关，正常请求毫秒级完成）。
const HTTP01_CONN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// :80（或配置的 `http_port`）HTTP-01 challenge 静态服务（极简 h1，只 serve
/// .well-known/acme-challenge/*）。
/// 独立于 web listener——80 端口本模块独占；绑定结果通过 `ready` 通知调用方
/// （签发必须在 bind 成功之后开始，否则首次签发必然失败）。
/// 连接有上限与超时：旧实现无条件 spawn、无任何超时，任何人可对 :80 slowloris 耗尽 fd。
async fn http01_listener(webroot: String, port: u16, ready: Option<tokio::sync::oneshot::Sender<bool>>) {
    let mut ready = ready;
    let root = std::sync::Arc::new(std::path::PathBuf::from(&webroot));
    let conns = std::sync::Arc::new(tokio::sync::Semaphore::new(HTTP01_MAX_CONNS));
    // 同时监听 IPv6 与 IPv4：CA 的 HTTP-01 校验按 A/AAAA 解析结果选地址。旧实现只绑
    // 0.0.0.0；域名有 AAAA（challtestsrv 默认 ::1、真实双栈站点很常见）时 CA 连
    // [::1]:port 直接 connection refused，校验必然失败（真实机 pebble 复现：
    // 记录 A=127.0.0.1/AAAA=::1，pebble 选 ::1，HTTP-01 永远 INVALID）。
    // 先试 [::]（Linux 默认 dual-stack，同时覆盖 IPv4），再试 0.0.0.0（OpenBSD
    // v6only=1 时需要单独绑）；至少一个成功才通知 ready。
    let mut listeners: Vec<tokio::net::TcpListener> = Vec::new();
    let mut last_err: Option<std::io::Error> = None;
    for addr in [format!("[::]:{port}"), format!("0.0.0.0:{port}")] {
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => {
                log::info!("dns-acme: http-01 challenge listener on {addr} webroot={webroot}");
                listeners.push(l);
            }
            Err(e) => last_err = Some(e),
        }
    }
    if listeners.is_empty() {
        log::error!(
            "dns-acme: bind :{port} failed（HTTP-01 不可用，签发将失败；若主 listener 要占该端口需把它接入挑战路由）: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        );
        if let Some(tx) = ready.take() {
            let _ = tx.send(false);
        }
        return;
    }
    if let Some(tx) = ready.take() {
        let _ = tx.send(true);
    }
    for l in listeners {
        tokio::spawn(http01_accept_loop(
            l,
            std::sync::Arc::clone(&root),
            std::sync::Arc::clone(&conns),
        ));
    }
}

/// 单地址的 HTTP-01 accept 循环（IPv4/IPv6 各一个任务）。
async fn http01_accept_loop(
    listener: tokio::net::TcpListener,
    root: std::sync::Arc<std::path::PathBuf>,
    conns: std::sync::Arc<tokio::sync::Semaphore>,
) {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use hyper::{Request, Response, StatusCode};
    use hyper::body::Incoming;
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // 与主 accept 循环同一修法：Err 上立即重试是紧循环。
                log::warn!("dns-acme: http-01 accept failed: {e}（退避 100ms）");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let permit = match conns.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                log::warn!("dns-acme: http-01 连接数达上限（{HTTP01_MAX_CONNS}），丢弃 {peer}");
                continue;
            }
        };
        let root = std::sync::Arc::clone(&root);
        tokio::spawn(async move {
            let _permit = permit;
            let io = TokioIo::new(sock);
            let svc = service_fn(move |req: Request<Incoming>| {
                let root = std::sync::Arc::clone(&root);
                async move {
                    // 只允许 GET /.well-known/acme-challenge/*
                    let path = req.uri().path();
                    let ok = req.method() == hyper::Method::GET
                        && path.starts_with("/.well-known/acme-challenge/");
                    if !ok {
                        return Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(http_body_util::Full::new(hyper::body::Bytes::from_static(b"not found")))
                                .unwrap(),
                        );
                    }
                    // 防穿越：去掉前缀后逐段检查
                    let rel = path.trim_start_matches("/.well-known/acme-challenge/");
                    if rel.contains("..") || rel.contains('/') {
                        return Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(http_body_util::Full::new(hyper::body::Bytes::from_static(b"not found")))
                            .unwrap());
                    }
                    let p = root.join(".well-known/acme-challenge").join(rel);
                    match tokio::fs::read(&p).await {
                        Ok(data) => Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/octet-stream")
                            .body(http_body_util::Full::new(hyper::body::Bytes::from(data)))
                            .unwrap()),
                        Err(_) => Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(http_body_util::Full::new(hyper::body::Bytes::from_static(b"not found")))
                            .unwrap()),
                    }
                }
            });
            let _ = tokio::time::timeout(
                HTTP01_CONN_TIMEOUT,
                hyper::server::conn::http1::Builder::new()
                    // hyper 1.x 的 header_read_timeout **必须**搭配 Timer，否则每个连接
                    // 在 common/time.rs 直接 panic（"timeout set, but no timer set"）——
                    // 真实机复现：HTTP-01 监听器 accept 后每条请求都 panic 一个 tokio
                    // worker、连接被 RST，LE/pebble 的校验永远失败（ACME 首次签发必挂）。
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(HTTP01_HEADER_TIMEOUT)
                    .keep_alive(false)
                    .serve_connection(io, svc),
            )
            .await;
        });
    }
}

/// 供 admin API：当前证书状态。
pub fn status(cfg: &AcmeCfg) -> serde_json::Value {
    if cfg.domain.is_empty() {
        return serde_json::json!({"enabled": cfg.enabled, "domain": "", "issued": false});
    }
    let cp = cert_path(&cfg.domain);
    serde_json::json!({
        "enabled": cfg.enabled,
        "domain": cfg.domain,
        "email": cfg.email,
        "issued": cp.is_file(),
        "cert": cp.display().to_string(),
        "valid": if cp.is_file() { cert_valid(&cp) } else { false },
        "renew_days": cfg.renew_days,
        "challenge": cfg.challenge_kind().unwrap_or("invalid"),
    })
}

/// 供 Config 引用的占位（避免未使用告警）。
#[allow(dead_code)]
fn _unused(_c: &Config) {}

#[cfg(test)]
mod tests {
    use super::{
        ensure_installed, fail_backoff_secs, safe_domain_segment, summarize_client_failure,
        with_jitter, AcmeCfg,
    };

    /// G-25：HTML 错误页必须被压成可读摘要，`error code:` / `detail` 行优先保留。
    #[test]
    fn html_error_page_is_summarized() {
        let stderr = "<!DOCTYPE html>\n<html><head><title>502 Bad Gateway</title></head>\n\
<body>\n<h1>502 Bad Gateway</h1>\n<hr><center>nginx</center>\n</body>\n</html>\n\
[Mon Oct 20] Please add '--debug' or '--log'.\n\
[Mon Oct 20] Error code: 7\n\
[Mon Oct 20] Detail: Fetching https://acme-v02.api.letsencrypt.org/directory: Connection refused\n";
        let s = summarize_client_failure(stderr);
        assert!(!s.contains('<'), "HTML 标签必须被剥掉: {s}");
        assert!(!s.contains("DOCTYPE"), "{s}");
        assert!(s.contains("Error code: 7"), "关键行必须保留: {s}");
        assert!(s.contains("Connection refused"), "{s}");
        assert!(s.len() <= 800, "摘要必须有界: {}", s.len());
    }

    /// 完全没有关键字行时退化为去标签后的尾部文本，且仍然有界/非空。
    #[test]
    fn plain_stderr_falls_back_to_clean_tail() {
        let s = summarize_client_failure("<b>boom</b>   something   odd\n\n");
        assert_eq!(s, "boom something odd");
        assert_eq!(summarize_client_failure(""), "<empty stderr>");
        let long = "x".repeat(2000);
        assert!(summarize_client_failure(&long).len() <= 800);
    }

    /// G-07：challenge 解析 —— 默认 http-01、dns-01 大小写/空白不敏感、未知值可检出。
    #[test]
    fn challenge_kind_parsing() {
        let mut c = AcmeCfg::default();
        assert_eq!(c.challenge_kind(), Some("http-01"));
        assert!(!c.challenge_is_dns01());
        c.challenge = " DNS-01 ".into();
        assert!(c.challenge_is_dns01());
        assert_eq!(c.challenge_kind(), Some("dns-01"));
        c.challenge = "tls-alpn-01".into();
        assert_eq!(c.challenge_kind(), None);
    }

    #[test]
    fn domain_ok() {
        assert_eq!(safe_domain_segment("example.com"), Some("example.com"));
        assert_eq!(safe_domain_segment("a.b-c_d.example."), Some("a.b-c_d.example"));
    }

    #[test]
    fn domain_rejects_traversal() {
        assert!(safe_domain_segment("../etc").is_none());
        assert!(safe_domain_segment("foo/bar").is_none());
        assert!(safe_domain_segment("..").is_none());
        assert!(safe_domain_segment("").is_none());
        assert!(safe_domain_segment("evil.com/../../tmp").is_none());
    }

    /// 「签发成功」必须意味着证书真的在盘上：两个文件缺一（拷贝失败/源文件名不符）
    /// 就要报错，而不是让调用方打一句 `cert ready` 然后 DoT 静默失败。
    #[test]
    fn install_must_verify_files_exist() {
        let dir = std::env::temp_dir().join(format!("crucible-acme-inst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 空目录 ⇒ 必须失败（旧实现在这里返回 Ok）
        assert!(ensure_installed(&dir, "test").is_err());
        std::fs::write(dir.join("fullchain.pem"), b"cert").unwrap();
        // 只有证书、没有私钥 ⇒ 仍然失败
        assert!(ensure_installed(&dir, "test").is_err());
        std::fs::write(dir.join("privkey.pem"), b"key").unwrap();
        // 两个都在（内容不是 PEM，公钥比对无法判定 ⇒ 跳过，不误判）⇒ 通过
        assert!(ensure_installed(&dir, "test").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 失败退避必须单调不减且封顶 24h（旧实现失败后要等 60 天）。
    #[test]
    fn fail_backoff_is_bounded_and_monotonic() {
        assert_eq!(fail_backoff_secs(1), 300);
        assert_eq!(fail_backoff_secs(2), 1800);
        assert_eq!(fail_backoff_secs(3), 7200);
        assert_eq!(fail_backoff_secs(4), 21600);
        assert_eq!(fail_backoff_secs(5), 86400);
        assert_eq!(fail_backoff_secs(99), 86400);
        assert_eq!(fail_backoff_secs(0), 300);
    }

    /// 抖动只加不减且不超过 +10%（多实例不同一秒打 CA）。
    #[test]
    fn jitter_is_additive_and_bounded() {
        for _ in 0..50 {
            let j = with_jitter(1000);
            assert!((1000..=1100).contains(&j), "jitter out of range: {j}");
        }
        assert!(with_jitter(0) <= 1);
    }
}
