//! Crucible webserver entry point.

mod config;
mod server;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;

use config::Config;
use server::live_config::LiveConfig;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 启动即清理上一代崩溃残留的引擎子进程（php-fpm / sidecar / go-shm-server）。
    server::apps::child_registry::cleanup_orphans_at_startup();

    // QUIC/H3 (quinn) uses rustls even when TCP TLS is BoringSSL-primary.
    #[cfg(feature = "tls")]
    {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    }

    // `--gen-cert`：用**我们链接进来的 BoringSSL** 生成一张自签证书（含 SAN），
    // 不需要 openssl / bssl 等外部 CLI。
    //
    // 为什么要有它：本项目明确「openssl 不作为依赖」，而现场（OpenBSD）通常也没有 bssl；
    // 要按 RFC 9849 部署 ECH 就得有「外层 cover 证书」与「内层真实证书」两张**不同的**证书
    // （见 WORKLOG §21.24/§21.27 的 ECH 自检），没有生成手段就只能手工凑。这个子命令用
    // 与测试同一条 BoringSSL 代码路径产出证书，运维一条命令即可，不引入任何外部工具。
    //
    // 用法：webserver --gen-cert <CN> --out-cert <pem> --out-key <pem> [--days N] [--ec]
    //
    // `--ec` 生成 P-256 证书。**ECH 部署必须两层都齐**：BoringSSL 按客户端 sigalgs 在
    // RSA / EC 两张证书里选，所以内层（真实）与外层（cover）**各自都要有 RSA 和 EC 两张**；
    // 只给外层一张 RSA，只提供 ECDSA 的客户端就会落回内层那张 EC 证书 —— 外层形同虚设
    // （见 WORKLOG §21.34）。默认 RSA 2048（兼容性最好）。
    if let Some(cn) = arg_value("--gen-cert") {
        let out_cert = arg_value("--out-cert").context("--gen-cert 需要 --out-cert <path>")?;
        let out_key = arg_value("--out-key").context("--gen-cert 需要 --out-key <path>")?;
        let days: u32 = arg_value("--days")
            .and_then(|v| v.parse().ok())
            .unwrap_or(3650);
        let ec = std::env::args().any(|a| a == "--ec");
        gen_self_signed(&cn, &out_cert, &out_key, days, ec)?;
        return Ok(());
    }

    let config_path = parse_config_path();
    let cfg = Config::load(&config_path)
        .with_context(|| format!("load config {}", config_path.display()))?;

    // `--check-config`：**只做「加载 + 校验」然后退出**，不绑定端口、不起服务。
    //
    // 为什么要它：新增配置期校验时，若只能靠「重启看看会不会挂」来验证，代价就是**停机**——
    // 我为 `autoindex.paths = ["/"]` 与 `[dns.dot]` 两条校验各打挂过一次生产。
    // 有了这个开关，部署流程可以先用**新二进制**对着**当前生产配置**验一遍，通过再换二进制：
    //   ./bin/webserver.new --config /crucible/config.toml --check-config && 停 → 换 → 起
    if std::env::args().any(|a| a == "--check-config") {
        // 不止校验配置：**真的为每个 SSL listener 构建一次 acceptor**。
        //
        // 为什么：`ssl.ciphers` / `ssl.groups` 这类字段没法在配置期用「名字白名单」校验
        //（BoringSSL 的名字集合很大，硬编码白名单只会误拒合法名字 —— 本项目已经被
        // 「新校验误拒生产配置」打过两次），而写错名字的后果是「配置加载通过、该端口每次
        // 握手都被 soft-fail 丢弃、日志每个连接一行 warn」—— 正是那种「配置看着对、
        // 端口实际下线」。这里跑一遍握手前的构建路径，让它**在预检阶段**就报错。
        // 构建只读本地材料、不发网络请求（OCSP 取回在独立续期线程里），无副作用。
        #[cfg(feature = "tls_boring")]
        for l in &cfg.listeners {
            if let Some(ssl) = l.ssl.as_ref() {
                server::tls::boring_path::build_acceptor(ssl, l).with_context(|| {
                    format!(
                        "listener {}:{} 的 TLS acceptor 构建失败（证书/密钥/ECH/密码套件/群）",
                        l.address, l.port
                    )
                })?;
            }
        }
        println!(
            "config OK: {} (listeners={}, apps={}, tls acceptors built={})",
            config_path.display(),
            cfg.listeners.len(),
            cfg.listeners.iter().map(|l| l.apps.len()).sum::<usize>(),
            cfg.listeners.iter().filter(|l| l.ssl.is_some()).count()
        );
        return Ok(());
    }

    log::info!(
        "Crucible starting; config={} listeners={}",
        config_path.display(),
        cfg.listeners.len()
    );

    let dns_cfg_path = config_path.clone();
    let live = Arc::new(LiveConfig::new(cfg, config_path));
    // 退出路径要用（见文件尾）：Arc 会被 move 进下面的 async 块，这里留一份句柄。
    let live_for_shutdown = live.clone();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    let result = rt.block_on(async move {
        // DNS(bind9) 控制面：启用 [dns] 时 reconcile named、启动 DoT 监听与维护循环
        server::dns::startup(&live, &dns_cfg_path).await;
        tokio::select! {
            r = server::run(live) => r,
            _ = shutdown_signal() => Ok(()),
        }
    });
    // 退出路径：终止注册的引擎子进程，防止孤儿 fpm / sidecar 堆积。
    server::apps::child_registry::kill_all();
    // tor（Hidden Service）是 `--RunAsDaemon` 的独立进程，不在 child_registry 里：
    // 不主动停，它就以孤儿形式继续挂着 —— 服务已经停了，.onion 却仍然可解析、连进去是死连接。
    server::tor_hs::stop_on_shutdown(&live_for_shutdown.snapshot().tor_hs);
    // 关停必须有**截止时间**。
    //
    // `Runtime` 被 drop 时会等所有 `spawn_blocking` 任务收尾，而那些任务里是同步 IO
    // （引擎 sidecar 的阻塞 UnixStream、CGI 子进程、各种 fs/DB 调用）——对端不响应就永久
    // 卡住。实测：一个实例收到 SIGTERM 后**关掉了监听端口却带着一个连接残留 6 小时**没退出，
    // 表现是 `pgrep` 里总有多余的 webserver 进程（它不监听、不服务任何请求），
    // 部署后旧实例就这样赖着不走。所以：先是 shutdown_timeout 限时收尾，再留一个看门狗
    // 兜底（万一连析构路径也在做同步 IO），保证进程一定会退出。
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let exit_code = if result.is_ok() { 0 } else { 1 };
    std::thread::spawn(move || {
        if done_rx
            .recv_timeout(std::time::Duration::from_secs(8))
            .is_err()
        {
            log::warn!(
                "shutdown: 8s 内未能正常退出 → 强制 exit({exit_code})（有阻塞任务未收尾）"
            );
            std::process::exit(exit_code);
        }
    });
    rt.shutdown_timeout(std::time::Duration::from_secs(3));
    // 正常路径：main 返回即进程退出，看门狗线程随之消失。
    drop(done_tx);
    result
}

/// SIGTERM（scripts 重启用）或 Ctrl-C。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn parse_config_path() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" || a == "-c" {
            if let Some(p) = args.next() {
                return PathBuf::from(p);
            }
        } else if let Some(p) = a.strip_prefix("--config=") {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("config.toml")
}

/// 取 `--flag value` 或 `--flag=value` 形式的值（找不到返回 None）。
fn arg_value(flag: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == flag {
            return args.next();
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_string());
        }
    }
    None
}

/// 生成自签证书（RSA 2048 或 `--ec` 的 P-256，SHA-256 + SAN=CN），私钥文件权限 0600。
#[cfg(feature = "tls_boring")]
fn gen_self_signed(
    cn: &str,
    out_cert: &str,
    out_key: &str,
    days: u32,
    ec: bool,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use boring::asn1::Asn1Time;
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::PKey;
    use boring::x509::extension::SubjectAlternativeName;
    use boring::x509::{X509Builder, X509NameBuilder};

    if cn.trim().is_empty() {
        anyhow::bail!("--gen-cert 的 CN 不能为空");
    }
    // 密钥类型：RSA 2048（默认，兼容性最好）或 P-256（`--ec`）。
    // ECH 要求内/外层各备 RSA+EC 两张，所以两种类型都得能生成。
    let (pkey, kind) = if ec {
        let group = boring::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .context("取 P-256 曲线失败")?;
        let eck = boring::ec::EcKey::generate(&group).context("生成 P-256 密钥失败")?;
        (
            PKey::from_ec_key(eck).context("EC → PKey 失败")?,
            "EC-P256",
        )
    } else {
        let rsa = boring::rsa::Rsa::generate(2048).context("生成 RSA 2048 失败")?;
        (PKey::from_rsa(rsa).context("RSA → PKey 失败")?, "RSA2048")
    };

    let mut nb = X509NameBuilder::new().context("X509NameBuilder")?;
    nb.append_entry_by_nid(Nid::COMMONNAME, cn.trim())
        .context("append CN")?;
    let name = nb.build();

    let mut b = X509Builder::new().context("X509Builder")?;
    b.set_version(2).context("set_version")?;
    b.set_subject_name(&name).context("set_subject")?;
    b.set_issuer_name(&name).context("set_issuer")?;
    b.set_pubkey(&pkey).context("set_pubkey")?;
    // 先绑定再取引用：`set_not_before` 要的是 `&Asn1TimeRef`，而 `?` 在实参位置会被
    // 推断成「`?` 的结果必须是 Asn1TimeRef」（E0308）。
    let nb = Asn1Time::days_from_now(0).context("not_before")?;
    b.set_not_before(&nb).context("set_not_before")?;
    let na = Asn1Time::days_from_now(days).context("not_after")?;
    b.set_not_after(&na).context("set_not_after")?;
    // SAN：现代客户端（以及本项目的 `cert_covers`）优先看 SAN，只给 CN 的证书会被判「不覆盖」。
    let san = SubjectAlternativeName::new()
        .dns(cn.trim())
        .build(&b.x509v3_context(None, None))
        .context("build SAN")?;
    b.append_extension(&san).context("append SAN")?;
    b.sign(&pkey, MessageDigest::sha256()).context("sign")?;
    let cert = b.build();

    std::fs::write(out_cert, cert.to_pem().context("cert → PEM")?)
        .with_context(|| format!("写 {out_cert}"))?;
    std::fs::write(
        out_key,
        pkey.private_key_to_pem_pkcs8().context("key → PEM")?,
    )
    .with_context(|| format!("写 {out_key}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 私钥必须 0600：这两张证书里有一张是「内层真实证书」，泄露等于把真实身份交出去。
        std::fs::set_permissions(out_key, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {out_key}"))?;
    }
    let fp = cert
        .digest(MessageDigest::sha256())
        .map(|d| {
            d.iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>()
        })
        .unwrap_or_default();
    println!(
        "OK: CN={cn} SAN={cn} 类型={kind} 有效期={days}天 证书={out_cert} 私钥={out_key}(0600) sha256={fp}"
    );
    Ok(())
}

#[cfg(not(feature = "tls_boring"))]
fn gen_self_signed(
    _cn: &str,
    _out_cert: &str,
    _out_key: &str,
    _days: u32,
    _ec: bool,
) -> anyhow::Result<()> {
    anyhow::bail!("--gen-cert 需要 tls_boring 特性（本二进制未编译 BoringSSL）")
}

#[cfg(all(test, feature = "tls_boring"))]
mod gen_cert_tests {
    /// `--gen-cert` 的证书必须可用：文件写出、**私钥 0600**、且能被 BoringSSL 解析回来
    /// （CN/SAN 与我们要求的一致）。
    ///
    /// 为什么要这条：这个子命令是为「按 RFC 9849 部署 ECH 需要两张不同证书」准备的，
    /// 如果它写出的证书解析不了、或私钥权限过宽，运维拿去配 `ech_cover_cert` 只会得到
    /// 一次静默的握手失败（本项目吃过太多次「配置看起来对、运行期不生效」）。
    #[test]
    fn gen_self_signed_writes_usable_material() {
        let dir = std::env::temp_dir().join(format!("crucible-gencert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let cert_p = dir.join("cover.pem");
        let key_p = dir.join("cover.key.pem");
        super::gen_self_signed(
            "cover.example.com",
            &cert_p.display().to_string(),
            &key_p.display().to_string(),
            3650,
            false,
        )
        .expect("gen");

        let cert = boring::x509::X509::from_pem(&std::fs::read(&cert_p).expect("read cert"))
            .expect("parse cert");
        let cn = cert
            .subject_name()
            .entries_by_nid(boring::nid::Nid::COMMONNAME)
            .next()
            .map(|e| String::from_utf8_lossy(e.data().as_slice()).to_string());
        assert_eq!(cn.as_deref(), Some("cover.example.com"));
        let san = cert
            .subject_alt_names()
            .map(|s| {
                s.iter()
                    .filter_map(|n| n.dnsname().map(|d| d.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert_eq!(san, vec!["cover.example.com".to_string()], "SAN 必须带 CN（cert_covers 看 SAN）");

        if let Ok(pk) = boring::pkey::PKey::private_key_from_pem(&std::fs::read(&key_p).expect("read key")) {
            assert!(pk.rsa().is_ok(), "应当是 RSA 私钥");
        } else {
            panic!("私钥 PEM 解析失败");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_p).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "私钥必须是 0600");
        }

        // `--ec`（P-256）：ECH 部署要求内层与外层**各自**都有 RSA 与 EC 两张证书，
        // 否则只提供 ECDSA 的客户端会落回另一层的 EC 证书（外层泄漏，见 WORKLOG §21.34）。
        // 这条钉住「EC 分支真的产出 EC 密钥」，而不是又生成一张 RSA。
        let ec_cert_p = dir.join("real-ec.pem");
        let ec_key_p = dir.join("real-ec.key.pem");
        super::gen_self_signed(
            "prod.example.com",
            &ec_cert_p.display().to_string(),
            &ec_key_p.display().to_string(),
            3650,
            true,
        )
        .expect("gen ec");
        let ec_pk =
            boring::pkey::PKey::private_key_from_pem(&std::fs::read(&ec_key_p).expect("read ec key"))
                .expect("parse ec key");
        assert!(ec_pk.ec_key().is_ok(), "--ec 必须产出 EC 私钥（而不是 RSA）");
        let ec_cert = boring::x509::X509::from_pem(&std::fs::read(&ec_cert_p).expect("read ec cert"))
            .expect("parse ec cert");
        // 证书公钥类型也必须跟着变（只看私钥文件会漏掉「证书里仍是 RSA 公钥」这种半改）
        assert!(
            ec_cert.public_key().expect("pubkey").ec_key().is_ok(),
            "--ec 的证书公钥必须是 EC"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
