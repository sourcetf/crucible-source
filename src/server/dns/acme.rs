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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
}

fn default_renew_days() -> u64 {
    60
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
pub async fn startup(cfg: &AcmeCfg) {
    if !cfg.enabled || cfg.domain.is_empty() {
        return;
    }
    if safe_domain_segment(&cfg.domain).is_none() {
        log::warn!("dns-acme: refusing unsafe domain {:?}", cfg.domain);
        return;
    }
    let domain = cfg.domain.clone();
    let webroot = cfg
        .webroot
        .clone()
        .unwrap_or_else(|| acme_root().join("www").display().to_string());
    // (1) HTTP-01 challenge 监听：先起，等 bind 结果（有界等待，超时也继续 —— 不阻塞启动）。
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(http01_listener(webroot.clone(), Some(ready_tx)));
    match tokio::time::timeout(std::time::Duration::from_secs(3), ready_rx).await {
        Ok(Ok(true)) => log::info!("dns-acme: http-01 challenge listener ready on :80"),
        Ok(Ok(false)) => log::warn!("dns-acme: bind :80 failed —— HTTP-01 不可用，签发会失败"),
        _ => log::warn!("dns-acme: http-01 listener bind 未在 3s 内确认，继续尝试签发"),
    }
    // (2) 签发/续期循环（后台）：失败按退避重试而不是死等 renew_days；成功按 renew_days
    //     ±抖动再查。renew_days 下限钳到 30 天（LE 证书 90 天，面板把它设成 1 会持续
    //    撞 CA 的失败限额 5 次/小时）。
    let days = cfg.renew_days.max(30);
    let c = cfg.clone();
    tokio::spawn(async move {
        let mut fails: u32 = 0;
        loop {
            let c2 = c.clone();
            let r = tokio::task::spawn_blocking(move || issue_if_missing(&c2)).await;
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
fn issue_if_missing(cfg: &AcmeCfg) -> anyhow::Result<()> {
    // 面板「立即签发」与自动续期共用本函数：域名没填时给出可定位的错误
    // （旧面板路径对空域名报 "unsafe domain \"\"" 之类，看不出是配置缺失）。
    if cfg.domain.trim().is_empty() {
        anyhow::bail!("[dns.acme] domain 未配置 —— 请先在面板填写证书域名");
    }
    if safe_domain_segment(&cfg.domain).is_none() {
        anyhow::bail!("unsafe ACME domain {:?}", cfg.domain);
    }
    let cp = cert_path(&cfg.domain);
    let kp = key_path(&cfg.domain);
    if cp.is_file() && kp.is_file() && cert_valid(&cp) {
        return Ok(());
    }
    issue(cfg)
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
/// `rateLimited` 单独标记）并返回 None。
fn run_client(cmd: &mut std::process::Command, who: &str) -> Option<std::process::Output> {
    match cmd.output() {
        Ok(o) if o.status.success() => Some(o),
        Ok(o) => {
            log_client_failure(who, &o);
            None
        }
        Err(e) => {
            log::warn!("dns-acme: {who} 无法启动: {e}");
            None
        }
    }
}

/// 失败输出只留尾部（有界，避免把工具刷屏日志整段写进我们的日志），
/// 命中速率限制时单独标记 —— 否则一周内无法签发而面板毫无提示。
fn log_client_failure(who: &str, o: &std::process::Output) {
    let err = String::from_utf8_lossy(&o.stderr);
    let low = err.to_ascii_lowercase();
    let tail: String = err.chars().rev().take(800).collect::<Vec<_>>().into_iter().rev().collect();
    let rate_limited = low.contains("ratelimited")
        || low.contains("rate limit")
        || low.contains("too many certificates")
        || low.contains("too many failed");
    if rate_limited {
        log::warn!("dns-acme: {who} 命中 CA 速率限制（rateLimited，可能一周内无法签发）: {tail}");
    } else {
        log::warn!("dns-acme: {who} 退出失败: {tail}");
    }
}

/// 依次探测 acme.sh / acme-client / certbot，用 HTTP-01 签发。
///
/// 要点：三条工具路径的 CA/参数保持一致（acme.sh 显式 `--server letsencrypt` +
/// `ec-256`；certbot 不传 `--cert-path/--key-path`——那两个参数只在 `certonly --csr`
/// 语义下有效，普通 certonly 会静默忽略，制造「退出 0 但 out_dir 没文件」的假成功）。
fn issue(cfg: &AcmeCfg) -> anyhow::Result<()> {
    // 面板「立即签发」与续期循环共用本函数：同一时刻只允许一个签发进程，
    // 避免并发 --issue 触发 CA 的 duplicate-certificate 限额。
    let _guard = ISSUE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let domain = safe_domain_segment(&cfg.domain)
        .ok_or_else(|| anyhow::anyhow!("unsafe ACME domain {:?}", cfg.domain))?;
    let out_dir = acme_root().join(domain);
    let www = cfg
        .webroot
        .clone()
        .unwrap_or_else(|| acme_root().join("www").display().to_string());
    std::fs::create_dir_all(&out_dir)?;
    std::fs::create_dir_all(std::path::Path::new(&www).join(".well-known/acme-challenge"))?;

    // 「客户端找到但执行失败」的清单：最终错误里必须区分「一个都没装」与
    // 「装了但失败」。旧实现两种情况都报 `no acme client available` —— 面板按钮
    // 明明有 acme.sh 却回「没有客户端」，真正原因（rateLimited 等）只在服务日志里。
    let mut attempted: Vec<String> = Vec::new();
    // 1) acme.sh（用户目录安装或 /usr/local）；HOME 缺失时无法定位 ~/.acme.sh，跳过。
    // 走 env_lock 缓存读 HOME：本函数跑在 spawn_blocking 线程里，与请求路径上应用引擎
    // 的 setenv（perl/python/ruby 的 ENV 注入）并发 —— libc setenv 可能 realloc environ，
    // 此刻任何其它线程的 getenv 都会踩到已释放内存（仓库里已实测出同类 SIGSEGV）。
    let home = crate::server::apps::env_lock::read_static_env("HOME").unwrap_or_default();
    if !home.trim().is_empty() {
        for bin in ["/usr/local/bin/acme.sh", "$HOME/.acme.sh/acme.sh"] {
            let bin = bin.replace("$HOME", &home);
            if std::path::Path::new(&bin).is_file() {
                let mut cmd = std::process::Command::new(&bin);
                cmd.arg("--issue")
                    .arg("-d").arg(&cfg.domain)
                    .arg("--webroot").arg(&www)
                    .arg("--server").arg("letsencrypt")
                    .arg("-m").arg(&cfg.email)
                    .arg("--keylength").arg("ec-256")
                    .env("LE_WORKING_DIR", format!("{home}/.acme.sh"));
                if run_client(&mut cmd, "acme.sh --issue").is_some() {
                    return install_acme_sh(&bin, &cfg.domain, &out_dir);
                }
                attempted.push(format!("acme.sh（{bin}）"));
            }
        }
    } else {
        log::warn!("dns-acme: HOME 未设置，跳过 acme.sh（无法定位其工作目录）");
    }
    // 2) OpenBSD acme-client（base 或 pkg）
    if std::path::Path::new("/usr/local/sbin/acme-client").is_file()
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
        if run_client(&mut cmd, "acme-client").is_some() {
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
        let mut cmd = std::process::Command::new(&found);
        cmd.arg("certonly")
            .arg("--webroot").arg("-w").arg(&www)
            .arg("-d").arg(&cfg.domain)
            .arg("-m").arg(&cfg.email)
            .arg("--agree-tos")
            .arg("--non-interactive");
        if run_client(&mut cmd, "certbot").is_some() {
            let src = std::path::Path::new("/etc/letsencrypt/live").join(domain);
            let _ = std::fs::copy(src.join("fullchain.pem"), out_dir.join("fullchain.pem"));
            let _ = std::fs::copy(src.join("privkey.pem"), out_dir.join("privkey.pem"));
            ensure_installed(&out_dir, "certbot")?;
            return Ok(());
        }
        attempted.push(format!("certbot（{found}）"));
    }
    let manual = format!(
        "手动模式：把证书放到 {} 与 {}，或在 dns.dot.cert/key 直接写路径",
        out_dir.join("fullchain.pem").display(),
        out_dir.join("privkey.pem").display()
    );
    if attempted.is_empty() {
        anyhow::bail!(
            "no acme client available (tried acme.sh / acme-client / certbot) — {manual}"
        );
    }
    // 找到但失败：失败原因（含 rateLimited 标记）已由 log_client_failure 写进服务日志，
    // 这里把「是哪个客户端失败」带回面板，附上日志检索关键字。
    anyhow::bail!(
        "ACME 客户端已找到但执行失败：{}（stderr 尾部见服务日志 `dns-acme:` 行）—— {manual}",
        attempted.join("、")
    )
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
pub fn issue_now(cfg: &AcmeCfg) -> anyhow::Result<()> {
    issue_if_missing(cfg)
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

/// :80 HTTP-01 challenge 静态服务（极简 h1，只 serve .well-known/acme-challenge/*）。
/// 独立于 web listener——80 端口本模块独占；绑定结果通过 `ready` 通知调用方
/// （签发必须在 bind 成功之后开始，否则首次签发必然失败）。
/// 连接有上限与超时：旧实现无条件 spawn、无任何超时，任何人可对 :80 slowloris 耗尽 fd。
async fn http01_listener(webroot: String, ready: Option<tokio::sync::oneshot::Sender<bool>>) {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use hyper::{Request, Response, StatusCode};
    use hyper::body::Incoming;

    let mut ready = ready;
    let listener = match tokio::net::TcpListener::bind("0.0.0.0:80").await {
        Ok(l) => {
            if let Some(tx) = ready.take() {
                let _ = tx.send(true);
            }
            l
        }
        Err(e) => {
            log::error!(
                "dns-acme: bind :80 failed（HTTP-01 不可用，签发将失败；若主 listener 要占 80 需把它接入挑战路由）: {e}"
            );
            if let Some(tx) = ready.take() {
                let _ = tx.send(false);
            }
            return;
        }
    };
    log::info!("dns-acme: http-01 challenge listener on :80 webroot={webroot}");
    let root = std::path::PathBuf::from(&webroot);
    let conns = std::sync::Arc::new(tokio::sync::Semaphore::new(HTTP01_MAX_CONNS));
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
        let root = root.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let io = TokioIo::new(sock);
            let svc = service_fn(move |req: Request<Incoming>| {
                let root = root.clone();
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
    })
}

/// 供 Config 引用的占位（避免未使用告警）。
#[allow(dead_code)]
fn _unused(_c: &Config) {}

#[cfg(test)]
mod tests {
    use super::{ensure_installed, fail_backoff_secs, safe_domain_segment, with_jitter};

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
