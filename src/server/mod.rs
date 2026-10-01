//! Accept loop, multi-listener, optional SO_BUSY_POLL (Linux only).

// ── 新增特性模块 ─────────────────────────────────────────────────────────────
pub mod ecn;
pub mod connect_udp;
pub mod port_reuse;
pub mod ech_auto;
// OCSP 自动获取 + 后台续期（boring_path::apply_ocsp_auto 依赖）。
// 此前这个文件存在但**从未声明**，于是 boring_path 里那整条自动装订路径
// 一直解析不到 `crate::server::ocsp_fetcher`，编译直接失败。
/// OCSP 装订材料抓取：只服务于 BoringSSL 路径（`StapleSlot` 用 boring 的 X509/hash 类型），
/// 所以跟着 `tls_boring` 一起门控。rustls 配置下不编译（它也没有别的调用方）。
#[cfg(feature = "tls_boring")]
pub mod ocsp_fetcher;
pub mod type65_api;

// ── existing modules ───────────────────────────────────────────────────────────
pub mod access;
pub mod access_log;
pub mod admin;
pub mod admin_config_edit;
pub mod admin_files;
pub mod admin_geoip;
pub mod apps;
pub mod basic_auth;
pub mod dns;
pub mod geoip_panel;
pub mod h1;
// 已删除：h1_static.rs 是死代码（无调用者），且一旦接线会绕过 static_files 的全部加固
pub mod h2;
pub mod h3;
pub mod l4;
pub mod listener;
pub mod live_config;
pub mod options_catalog;
pub mod page_rules;
pub mod password;
pub mod proxy;
pub mod prefixed_stream;
pub mod rate_limit;
pub mod ssl_material;
pub mod tor_hs;
pub mod static_files;
pub mod upload_api;
pub mod upload_resume;
pub mod qmux;
pub mod syncookie;
pub mod telemetry;
pub mod tls;
pub mod headers_mod;
pub mod onion_ca;

use anyhow::{Context, Result};
use live_config::LiveConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

pub async fn run(live: Arc<LiveConfig>) -> Result<()> {
    // 热重载：每 2s 检查 config.toml mtime
    live_config::spawn_mtime_watcher(Arc::clone(&live), std::time::Duration::from_secs(2));
    crate::server::apps::reconcile_apps_runtime(&live);

    crate::server::syncookie::spawn_evaluator(Arc::clone(&live));
    // 早期规格 A.3：Hidden Service（独立 tor 进程，SocksPort 0）——enabled 时拉起。
    // ensure_hs 幂等（进程在 + torrc 与配置一致才复用，否则重启 tor），启动/热重载/巡检都调它。
    //
    // 这一行此前**不存在**（只有一句 "tor_hs::spawn_from_config: deferred
    // (tor_hs removed)" 的注释，而模块明明在），于是配 `[tor_hs] enabled = true`
    // 什么都不会发生、也不报错 —— 一个彻底静默的假开关。
    crate::server::tor_hs::spawn_from_config(live.snapshot().tor_hs.clone());
    // 巡检：tor 崩了要能自愈（此前没有任何东西看管它 —— 进程一死 .onion 就静默不可达）。
    crate::server::tor_hs::spawn_watchdog(Arc::clone(&live));

    // 热重载路径的调用挂在 `LiveConfig::reload()` 里（与 reconcile_apps_runtime 同一位置），
    // 那里本来就是「重载后动作」的落点。
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            crate::server::rate_limit::cleanup(std::time::Duration::from_secs(600));
            // 上传会话回收：**这个调用此前从没被任何地方调用过** ——
            // 会话只能在 commit/abort 里被删，而客户端断连/读 body 出错/超限这些路径
            // 既不 commit 也不 abort，于是 256 个被弃会话之后所有「新文件名」上传恒回 503，
            // 且每个会话都在 docroot 里留下永久的 `.part` 文件（磁盘无界增长）。
            let swept = crate::server::upload_resume::sweep_expired();
            if swept > 0 {
                log::info!("upload: swept {swept} 个过期上传会话（连同 .part 文件）");
            }
        }
    });

    // GeoIP 定时同步（此前是「P1-6 deferred：ops::spawn_cron_scheduler 未实现」）。
    //
    // 落点说明：`geoip::ensure_synced` 原本只在**启动**与**面板保存（reconcile）**时被调用，
    // 并靠 `sync_days` 与磁盘上的时间戳做「多久算过期」的判定。于是一台**长期运行且从不改
    // 配置**的服务器永远不会再同步 —— 而 geo.mmdb.sync_days 的文案恰恰是「cron 每日」。
    // 这里补上周期性触发：每 6 小时查一次，是否真的下载由 ensure_synced 自己按
    // sync_days 判断（重复调用是廉价的：只 stat 时间戳）。
    {
        let live_geo = Arc::clone(&live);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
                let snap = live_geo.snapshot();
                let mmdb = &snap.dns.geo.mmdb;
                if !snap.dns.enabled || !snap.dns.geo.enabled || !mmdb.is_active() {
                    continue;
                }
                match crate::server::dns::geoip::ensure_synced(mmdb, false) {
                    Ok(()) => log::debug!("geoip: 周期同步检查完成（未过期则不下载）"),
                    Err(e) => log::warn!("geoip: 周期同步失败: {e:#}"),
                }
            }
        });
    }

    let active: Arc<tokio::sync::Mutex<std::collections::HashSet<u16>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));

    // Initial listeners.
    let cfg = live.snapshot();
    // ECH 启动期自检（三条方向互补的检查，见 `ech_selfcheck_problems`）：
    // ① 要广告却没人发布 ② 启用了却内外层共用一张证书 ③ 发布了却没人服务。
    // 三者共同点是「面板/日志看起来都正常」，只有把两处配置放在一起比才看得出来。
    for problem in ech_selfcheck_problems(&cfg) {
        log::warn!("{problem}");
    }
    for (idx, lc) in cfg.listeners.iter().enumerate() {
        if let Err(e) = spawn_listener_port(
            Arc::clone(&live),
            lc.clone(),
            idx,
            Arc::clone(&active),
        )
        .await
        {
            return Err(e);
        }
    }
    if active.lock().await.is_empty() {
        anyhow::bail!("no listeners configured");
    }

    // Hot-spawn newly added ports after config reload (removed ports exit accept_loop).
    {
        let live_r = Arc::clone(&live);
        let active_r = Arc::clone(&active);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let snap = live_r.snapshot();
                for (idx, lc) in snap.listeners.iter().enumerate() {
                    if active_r.lock().await.contains(&lc.port) {
                        continue;
                    }
                    match spawn_listener_port(
                        Arc::clone(&live_r),
                        lc.clone(),
                        idx,
                        Arc::clone(&active_r),
                    )
                    .await
                    {
                        Ok(()) => log::info!("hot-spawned listener port {}", lc.port),
                        Err(e) => log::warn!("hot-spawn listener port {} failed: {e:#}", lc.port),
                    }
                }
            }
        });
    }

    // Stay alive; accept loops + reconciler own the work.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn spawn_listener_port(
    live: Arc<LiveConfig>,
    lc: crate::config::ListenerConfig,
    idx: usize,
    active: Arc<tokio::sync::Mutex<std::collections::HashSet<u16>>>,
) -> Result<()> {
    let port = lc.port;
    {
        let mut a = active.lock().await;
        if !a.insert(port) {
            return Ok(());
        }
    }
    // OpenBSD: [::] 不含 v4-mapped，双栈需显式双 bind。
    // address 默认 0.0.0.0（v4 全网卡），address_v6 可选 ::= 全网卡 v6。
    let mut addrs: Vec<String> = vec![lc.address.clone()];
    if let Some(v6) = lc.address_v6.as_deref() {
        if !v6.is_empty() {
            addrs.push(v6.to_string());
        }
    }
    let mut listeners: Vec<(SocketAddr, tokio::net::TcpListener)> = Vec::new();
    for a in &addrs {
        let addr: SocketAddr = if a.contains(':') {
            // IPv6 字面量（含 "::"）—— 用 bracketed 形式解析
            format!("[{a}]:{}", lc.port)
        } else {
            format!("{a}:{}", lc.port)
        }
        .parse()
        .with_context(|| format!("parse listener {a}:{}", lc.port))?;
        match TcpListener::bind(addr).await {
            Ok(l) => listeners.push((addr, l)),
            Err(e) => {
                active.lock().await.remove(&port);
                // 已绑定的要关闭（Drop 自动）
                return Err(e).with_context(|| format!("bind {addr}"));
            }
        }
    }
    let addr = listeners[0].0;
    maybe_set_busy_poll(&listeners[0].1);
    for (a, _) in &listeners { log::info!("listener[{idx}] ready on {a} root={}", lc.root.display()); }

    for (a, listener) in listeners {
        let live_c = Arc::clone(&live);
        let active_c = Arc::clone(&active);
        tokio::spawn(async move {
            let res = accept_loop(listener, live_c, port).await;
            active_c.lock().await.remove(&port);
            log::warn!("accept_loop {a} ended: {res:?}");
        });
    }

    if lc.allows_h3() {
        let udp_addr = addr;
        let lc_h3 = lc.clone();
        let live_h3 = Arc::clone(&live);
        tokio::spawn(async move {
            loop {
                if !live_h3.snapshot().listeners.iter().any(|l| l.port == port) {
                    log::info!("h3 listener port {port} removed; stopping");
                    break;
                }
                if let Err(e) =
                    crate::server::h3::serve(udp_addr, lc_h3.clone(), Arc::clone(&live_h3)).await
                {
                    log::warn!("h3 listener {udp_addr}: {e:#}; retry in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        });
    }
    Ok(())
}

async fn accept_loop(listener: TcpListener, live: Arc<LiveConfig>, port: u16) -> Result<()> {
    loop {
        // Hot-reload: if this port disappeared from config, stop accepting.
        {
            let snap = live.snapshot();
            if !snap.listeners.iter().any(|l| l.port == port) {
                log::info!(
                    "listener port {port} removed from config; shutting down accept loop"
                );
                return Ok(());
            }
        }
        let accept = listener.accept();
        tokio::pin!(accept);
        let (stream, peer) = loop {
            tokio::select! {
                res = &mut accept => break res?,
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                    let snap = live.snapshot();
                    if !snap.listeners.iter().any(|l| l.port == port) {
                        log::info!(
                            "listener port {port} removed from config; shutting down accept loop"
                        );
                        return Ok(());
                    }
                }
            }
        };
        maybe_set_busy_poll_stream(&stream);
        // P2-7：SYN 速率信号源——syncookie 评估器按 tick 差值估算速率并动态切换 sysctl。
        crate::server::syncookie::note_syn();
        let live_c = Arc::clone(&live);
        tokio::spawn(async move {
            if let Err(e) = listener::handle_connection(stream, live_c, port, peer).await {
                log::debug!("connection {peer} error: {e:#}");
            }
        });
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "linux_busy_poll"))]
fn maybe_set_busy_poll(listener: &TcpListener) {
    use std::os::fd::AsRawFd;
    // SO_BUSY_POLL = 100µs — Linux only; do not use SO_INCOMING_CPU.
    const SO_BUSY_POLL: libc::c_int = 46;
    let fd = listener.as_raw_fd();
    let val: libc::c_int = 100;
    unsafe {
        let rc = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        );
        if rc != 0 {
            log::debug!("SO_BUSY_POLL set failed: {}", std::io::Error::last_os_error());
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "linux_busy_poll")))]
fn maybe_set_busy_poll(_listener: &TcpListener) {
    // OpenBSD / others: SO_BUSY_POLL unavailable or disabled by configure.
}

#[cfg(all(target_os = "linux", feature = "linux_busy_poll"))]
fn maybe_set_busy_poll_stream(stream: &tokio::net::TcpStream) {
    use std::os::fd::AsRawFd;
    const SO_BUSY_POLL: libc::c_int = 46;
    let fd = stream.as_raw_fd();
    let val: libc::c_int = 100;
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        );
    }
}

#[cfg(not(all(target_os = "linux", feature = "linux_busy_poll")))]
fn maybe_set_busy_poll_stream(_stream: &tokio::net::TcpStream) {}

// ============ ECH 启动期自检（三条，方向互补） ============
//
// 这一组检查存在的理由都一样：ECH 的「配置」分散在**两处** —— listener 的 `ssl.*`
// 与 `[dns] [[dns.https_rr]]`，而它们都会在面板/日志里显示为「已启用」，于是
// 「一边改了另一边没跟上」这种组合可以长期无人察觉（属于本项目一直避免的
// 「开关是假的」那一类）。三个方向都覆盖：
//   1. listener 声称要广告，但 DNS 里没有对应记录（发布了才算数）；
//   2. 启用了 ECH，却没配 cover 证书（内外层共用一张真证书，伪装不存在）；
//   3. DNS 里发布了 `ech=`，但没有 listener 在服务它（客户端白试一次再回落）。
//
// 每个检查都返回**问题描述**而不是直接 log：这样单测能断言「什么配置会报、什么配置不报」，
// 不必去抓日志（`log::warn!` 在测试里没有 logger，抓不到就等于没测）。

/// 该 listener **实际在服务哪个 public_name**：优先 `ssl.ech_public_name`，
/// 其次磁盘上已落盘的 ECH 配置（`ssl.ech_keys` 显式配置路径下，public_name 只写在
/// 密钥文件里的 ECHConfig 中，配置项本身可以没有）。
///
/// 为什么需要这层回落：自检要对照「DNS 发布的名字」与「服务端服务/广告的名字」，
/// 只认配置项会把 `ech_keys` 形态误判成「什么都没在服务」（反之也会让提示里出现
/// `public_name(?)` 这种没用的信息）。
fn served_public_name(ssl: &crate::config::SslConfig) -> Option<String> {
    if let Some(n) = ssl.ech_public_name.as_deref() {
        let t = n.trim().trim_end_matches('.');
        if !t.is_empty() {
            return Some(t.to_ascii_lowercase());
        }
    }
    if ssl.ech_keys.is_some() {
        // 名字在密钥文件的 ECHConfig 里；解析细节归 `ech_auto` 管
        //（别在这里拿 `persisted_config_list()` 去 parse —— 那是 List 不是 Config）。
        return crate::server::ech_auto::persisted_public_name();
    }
    None
}

/// 启动期自检：开了 ECH 广告、却没有对应的 `[[dns.https_rr]]` 发布条目。
///
/// `ech_advertise` 的字面含义是「发布到 DNS」，但真正的发布动作在
/// `[dns] [[dns.https_rr]]`（见 `dns::auto_https_records`）。少了这层检查，
/// 「ECH 已启用」与「客户端拿不到 ECHConfig」可以同时成立而无人察觉。
fn ech_selfcheck_problems(cfg: &crate::config::Config) -> Vec<String> {
    let mut out = Vec::new();

    let published: Vec<String> = cfg
        .dns
        .https_rr
        .iter()
        .filter(|r| r.ech)
        .map(|r| r.name.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();

    // 方向 1：要广告但没发布。
    //
    // 判据用 `ssl.ech && ssl.ech_advertise` +「服务中的 public_name」（含密钥文件回落），
    // 而不是 `ech_advertise_enabled()`：后者要求 `ssl.ech_public_name` 非空，于是
    // `ech_keys` 显式配置（public_name 只写在密钥文件里）这种形态会被整条跳过 ——
    // 而默认 `ech_advertise = true` 下正是它最容易「以为发了、其实没人发」。
    for lc in &cfg.listeners {
        let Some(ssl) = lc.ssl.as_ref() else { continue };
        if !(ssl.ech && ssl.ech_advertise) {
            continue;
        }
        let Some(name) = served_public_name(ssl) else { continue };
        if !published.contains(&name) {
            out.push(format!(
                "ECH: listener {}:{} 开了 ech_advertise（服务中的 public_name={name}），但 [dns] 里没有对应的 [[dns.https_rr]]（name=\"{name}\"、ech=true）—— **ECH 不会被发布**，客户端解析不到 ech= 参数就等同于没有 ECH。补上该配置，或把 ech_advertise 关掉以免误解",
                lc.address, lc.port
            ));
        }
    }

    // 方向 2（内外层不得共用一张证书）：启用了 ECH 却没有 cover 证书。
    //
    // 没有 cover 时，非 ECH 客户端（**以及任何主动探测者**）拿到的就是内层那张**真实证书**
    // —— 「外层看起来像公共名」这层伪装不存在，探测者把 SNI 写成 public_name 就能确认本机
    // 持有该站证书。不提升为配置错误：同一张通配证书覆盖内外层名在某些部署里是刻意的，
    // 这里要防的是**默认/无意**地共用一张。
    for lc in &cfg.listeners {
        let Some(ssl) = lc.ssl.as_ref() else { continue };
        if !ssl.ech {
            continue;
        }
        // 没材料就没 ECH 可谈（`apply_ech` 在 ech=true 但两者都缺时会自己 warn），不重复报。
        let has_material = ssl.ech_keys.is_some()
            || ssl
                .ech_public_name
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
        if !has_material {
            continue;
        }
        if ssl.ech_cover_cert.is_some() && ssl.ech_cover_key.is_some() {
            continue;
        }
        out.push(format!(
            "ECH: listener {}:{} 已启用 ECH，但没有配置 cover 证书（ssl.ech_cover_cert / ech_cover_key）—— 外层（非 ECH 客户端与主动探测者）会拿到与内层**相同的**真实证书，public_name({}) 那层伪装等于不存在。按本项目对 ECH 的部署要求（内外层不共用一张 SSL），应当为 public_name 单独配一张 cover 证书",
            lc.address,
            lc.port,
            served_public_name(ssl).unwrap_or_else(|| "未声明".into())
        ));
    }

    // 方向 3（方向 1 的反面）：DNS 里发布了 ech=，却没有 listener 在服务它。
    //
    // 发布而不服务比干脆不发布更糟：客户端拿到 `ech=` 会先试 ECH、被拒后再回落外层 ——
    // 白白多一次往返，还把「本机在做 ECH」写进了公开 DNS。
    let serving: Vec<String> = cfg
        .listeners
        .iter()
        .filter_map(|lc| lc.ssl.as_ref())
        // 自动配置路径（只有 public_name、没有 ech_keys）同样会服务 ECH，所以判据是
        // 「ech = true 且有材料来源」，而不是「有 ech_keys」。
        .filter(|ssl| {
            ssl.ech
                && (ssl.ech_keys.is_some()
                    || ssl
                        .ech_public_name
                        .as_deref()
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false))
        })
        .filter_map(served_public_name)
        .collect();
    for name in &published {
        if !serving.contains(name) {
            out.push(format!(
                "ECH: [dns] 里发布了 {name} 的 ech=（HTTPS 记录），但没有 listener 在服务它的 ECH（需要该 listener 配了 ssl.ech = true 且有 ech_keys/public_name，并让 public_name 与这条记录同名）—— 客户端会先试 ECH 再回落，等于既没拿到隐私又多一次往返"
            ));
        }
    }

    out
}

#[cfg(test)]
mod ech_selfcheck_tests {
    use super::ech_selfcheck_problems;
    use crate::config::Config;

    fn cfg_of(toml_extra: &str) -> Config {
        // 所有用例共用一份最小 listener，附加片段再叠上去。
        let base = r#"
[[listeners]]
address = "127.0.0.1"
port = 8443
root = "/tmp/echcheck"
"#;
        toml::from_str(&format!("{base}{toml_extra}")).expect("parse")
    }

    /// 方向 1：开了 ech_advertise（默认 true）+ public_name，却没有 https_rr 记录 ⇒ 必须报。
    #[test]
    fn advertise_without_https_rr_is_reported() {
        let cfg = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = true, ech_public_name = \"v.example.com\" }\n",
        );
        let problems = ech_selfcheck_problems(&cfg);
        assert!(
            problems.iter().any(|p| p.contains("ECH 不会被发布")),
            "应报告「要广告但没发布」: {problems:?}"
        );
        // 补上对应记录后，方向 1 不再报（方向 2 仍会因为没 cover 证书而报 —— 那是另一条）。
        let cfg2 = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = true, ech_public_name = \"v.example.com\" }\n\n[[dns.https_rr]]\nname = \"v.example.com\"\nech = true\n",
        );
        let p2 = ech_selfcheck_problems(&cfg2);
        assert!(
            !p2.iter().any(|p| p.contains("ECH 不会被发布")),
            "记录了就不该再报方向 1: {p2:?}"
        );
    }

    /// 方向 2：启用 ECH 却没配 cover 证书 ⇒ 必须报；配全 cover 后不再报。
    #[test]
    fn ech_without_cover_cert_is_reported() {
        let cfg = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = true, ech_keys = \"state/ech/ech_keys.pem\" }\n",
        );
        assert!(
            ech_selfcheck_problems(&cfg)
                .iter()
                .any(|p| p.contains("没有配置 cover 证书")),
            "缺 cover 证书必须报"
        );
        let cfg_ok = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = true, ech_keys = \"state/ech/ech_keys.pem\", ech_cover_cert = \"cover.pem\", ech_cover_key = \"cover.key.pem\" }\n",
        );
        assert!(
            !ech_selfcheck_problems(&cfg_ok)
                .iter()
                .any(|p| p.contains("没有配置 cover 证书")),
            "配全 cover 后不该再报"
        );
        // `ech = false` 的 listener 不参与（开关关掉就没有内外层共用问题）。
        let cfg_off = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = false, ech_public_name = \"v.example.com\" }\n",
        );
        assert!(
            !ech_selfcheck_problems(&cfg_off)
                .iter()
                .any(|p| p.contains("没有配置 cover 证书")),
            "ech = false 不该报 cover 证书问题"
        );
    }

    /// 方向 3：DNS 发布了 ech= 但没人服务 ⇒ 必须报；有对应 listener 后不报。
    #[test]
    fn published_but_not_served_is_reported() {
        let cfg = cfg_of("\n[[dns.https_rr]]\nname = \"v.example.com\"\nech = true\n");
        assert!(
            ech_selfcheck_problems(&cfg)
                .iter()
                .any(|p| p.contains("没有 listener 在服务")),
            "发布了却没人服务必须报"
        );
        let cfg_ok = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = true, ech_keys = \"state/ech/ech_keys.pem\", ech_public_name = \"v.example.com\" }\n\n[[dns.https_rr]]\nname = \"v.example.com\"\nech = true\n",
        );
        assert!(
            !ech_selfcheck_problems(&cfg_ok)
                .iter()
                .any(|p| p.contains("没有 listener 在服务")),
            "服务端就绪后不该再报方向 3"
        );
    }
}

#[cfg(all(test, feature = "tls_boring"))]
mod capacity_tests {
    /// acceptor 缓存上限必须 ≥ 允许的 listener 数。
    ///
    /// 指纹里含 `lc.port`，每个 listener 至少占一项；上限小于 listener 数时，
    /// 缓存满会**整表清空** ⇒ 命中率归零，每次握手都重建 acceptor（性能悬崖）。
    /// 放在 `server` 模块里是因为 `admin_config_edit` 是本模块的私有子模块。
    #[test]
    fn acceptor_cache_cap_covers_max_listeners() {
        assert!(
            crate::server::tls::boring_path::ACCEPTOR_CACHE_CAP
                >= crate::server::admin_config_edit::MAX_LISTENERS,
            "acceptor 缓存上限必须覆盖最大 listener 数"
        );
    }
}
