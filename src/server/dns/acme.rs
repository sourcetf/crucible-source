//! Let's Encrypt 自动签发（需求 8：DoT/DoH 域名证书）。
//!
//! 设计：
//! - HTTP-01 挑战：本模块独占 :80（与 web listener 无冲突），serve challenge 目录
//! - 工具链探测顺序：acme.sh → acme-client(OpenBSD) → certbot；三者全缺时
//!   降级为提示手动证书（`dns.dot.cert/key` 直接给 PEM 路径——验收与无外网
//!   环境的推荐路径）
//! - 证书落盘 `state/dns/acme/<domain>/{fullchain.pem,privkey.pem}`；
//!   `dns.dot.cert = "acme:<domain>"` 即自动指向该路径
//! - 续期：60 天间隔定时重签（LE 证书有效期 90 天）
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

/// 启动入口：enabled 时（1）签发缺失证书（2）拉起 HTTP-01 :80（3）续期循环。
pub async fn startup(cfg: &AcmeCfg) {
    if !cfg.enabled || cfg.domain.is_empty() {
        return;
    }
    if safe_domain_segment(&cfg.domain).is_none() {
        log::warn!("dns-acme: refusing unsafe domain {:?}", cfg.domain);
        return;
    }
    let domain = cfg.domain.clone();
    // 先同步签发（阻塞可接受：启动阶段；失败不致命——DoT 用手动证书或报错）
    let c = cfg.clone();
    let r = tokio::task::spawn_blocking(move || issue_if_missing(&c)).await;
    match r {
        Ok(Ok(())) => log::info!("dns-acme: cert ready for {domain}"),
        Ok(Err(e)) => log::warn!(
            "dns-acme: issue failed for {domain}: {e:#}（可手动配置 dns.dot.cert/key）"
        ),
        Err(e) => log::warn!("dns-acme: join: {e}"),
    }
    // HTTP-01 challenge 监听（LE 验证时才真正被请求）
    let webroot = cfg
        .webroot
        .clone()
        .unwrap_or_else(|| acme_root().join("www").display().to_string());
    tokio::spawn(http01_listener(webroot));
    // 续期循环
    let days = cfg.renew_days.max(1);
    let c = cfg.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(days * 86400)).await;
            let c2 = c.clone();
            let r = tokio::task::spawn_blocking(move || issue_if_missing(&c2)).await;
            match r {
                Ok(Ok(())) => log::info!("dns-acme: renewed {}", c.domain),
                Ok(Err(e)) => log::warn!("dns-acme: renew failed: {e:#}"),
                Err(e) => log::warn!("dns-acme: renew join: {e}"),
            }
        }
    });
}

/// 证书已存在且 30 天内不会过期 → 跳过；否则调外部工具签发。
fn issue_if_missing(cfg: &AcmeCfg) -> anyhow::Result<()> {
    if safe_domain_segment(&cfg.domain).is_none() {
        anyhow::bail!("unsafe ACME domain {:?}", cfg.domain);
    }
    let cp = cert_path(&cfg.domain);
    if cp.is_file() && cert_valid(&cp) {
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

/// 依次探测 acme.sh / acme-client / certbot，用 HTTP-01 签发。
fn issue(cfg: &AcmeCfg) -> anyhow::Result<()> {
    let domain = safe_domain_segment(&cfg.domain)
        .ok_or_else(|| anyhow::anyhow!("unsafe ACME domain {:?}", cfg.domain))?;
    let out_dir = acme_root().join(domain);
    let www = cfg
        .webroot
        .clone()
        .unwrap_or_else(|| acme_root().join("www").display().to_string());
    std::fs::create_dir_all(&out_dir)?;
    std::fs::create_dir_all(std::path::Path::new(&www).join(".well-known/acme-challenge"))?;

    // 1) acme.sh（用户目录安装或 /usr/local）
    for bin in ["/usr/local/bin/acme.sh", "$HOME/.acme.sh/acme.sh"] {
        let bin = bin.replace("$HOME", &std::env::var("HOME").unwrap_or_default());
        if std::path::Path::new(&bin).is_file() {
            let st = std::process::Command::new(&bin)
                .arg("--issue")
                .arg("-d").arg(&cfg.domain)
                .arg("--webroot").arg(&www)
                .arg("--server").arg("letsencrypt")
                .arg("-m").arg(&cfg.email)
                .arg("--keylength").arg("ec-256")
                .status();
            if st.map(|s| s.success()).unwrap_or(false) {
                return install_acme_sh(&bin, &cfg.domain, &out_dir);
            }
        }
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
        let st = std::process::Command::new(bin)
            .arg("-v")
            .arg("-C").arg(&www)
            .arg("-D").arg(&cfg.domain)
            .arg(&cfg.domain)
            .status();
        if st.map(|s| s.success()).unwrap_or(false) {
            // acme-client 默认产出 /etc/acme/<domain>/{fullchain,privkey}.pem
            let src = std::path::Path::new("/etc/acme").join(&cfg.domain);
            let _ = std::fs::copy(src.join("fullchain.pem"), out_dir.join("fullchain.pem"));
            let _ = std::fs::copy(src.join("privkey.pem"), out_dir.join("privkey.pem"));
            return Ok(());
        }
    }
    // 3) certbot
    if let Ok(found) = which("certbot") {
        let st = std::process::Command::new(&found)
            .arg("certonly")
            .arg("--webroot").arg("-w").arg(&www)
            .arg("-d").arg(&cfg.domain)
            .arg("-m").arg(&cfg.email)
            .arg("--agree-tos")
            .arg("--non-interactive")
            .arg("--cert-path").arg(out_dir.join("fullchain.pem"))
            .arg("--key-path").arg(out_dir.join("privkey.pem"))
            .status();
        if st.map(|s| s.success()).unwrap_or(false) {
            return Ok(());
        }
    }
    anyhow::bail!(
        "no acme client available (tried acme.sh / acme-client / certbot) — \
         手动模式：把证书放到 {} 与 {}，或在 dns.dot.cert/key 直接写路径",
        out_dir.join("fullchain.pem").display(),
        out_dir.join("privkey.pem").display()
    )
}

fn install_acme_sh(
    bin: &str,
    domain: &str,
    out_dir: &std::path::Path,
) -> anyhow::Result<()> {
    // acme.sh --install-cert 拷贝到目标路径（幂等）
    let home = std::env::var("HOME").unwrap_or_default();
    let src_dir = format!("{home}/.acme.sh/{domain}_ecc");
    let st = std::process::Command::new(bin)
        .arg("--install-cert")
        .arg("-d").arg(domain)
        .arg("--ecc")
        .arg("--fullchain-file").arg(out_dir.join("fullchain.pem"))
        .arg("--key-file").arg(out_dir.join("privkey.pem"))
        .arg("--installcmd")
        .env("LE_WORKING_DIR", format!("{home}/.acme.sh"))
        .status();
    // --installcmd 不存在时直接拷贝
    if !st.map(|s| s.success()).unwrap_or(false) {
        let src = std::path::Path::new(&src_dir);
        let _ = std::fs::copy(src.join("fullchain.cer"), out_dir.join("fullchain.pem"));
        let _ = std::fs::copy(src.join(format!("{domain}.key")), out_dir.join("privkey.pem"));
    }
    Ok(())
}

fn which(name: &str) -> anyhow::Result<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let cand = std::path::Path::new(dir).join(name);
        if cand.is_file() {
            return Ok(cand.display().to_string());
        }
    }
    anyhow::bail!("{name} not in PATH")
}

/// :80 HTTP-01 challenge 静态服务（极简 h1，只 serve .well-known/acme-challenge/*）。
/// 独立于 web listener——80 端口本模块独占；绑定失败仅告警（80 被占时 ACME 无法 HTTP-01）。
async fn http01_listener(webroot: String) {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use hyper::{Request, Response, StatusCode};
    use hyper::body::Incoming;

    let listener = match tokio::net::TcpListener::bind("0.0.0.0:80").await {
        Ok(l) => l,
        Err(e) => {
            log::warn!("dns-acme: bind :80 failed（HTTP-01 不可用）: {e}");
            return;
        }
    };
    log::info!("dns-acme: http-01 challenge listener on :80 webroot={webroot}");
    let root = std::path::PathBuf::from(&webroot);
    loop {
        let (sock, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let root = root.clone();
        tokio::spawn(async move {
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
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
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
    use super::safe_domain_segment;

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
}
