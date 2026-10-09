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
pub mod log_throttle;
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
    // 启动期环境快照：spawn 类引擎（cgi/cgi_script）用它构造**干净**子进程环境
    // （启动期基底 + 本请求 `.env`），从而不继承进程 env 里别人的临时 `.env`，
    // 也就不必参与 env_lock 的进程 env 互斥（慢空请求不再挡住带 .env 的请求）。
    // **必须在任何请求期 `.env` 安装之前**调用。
    crate::server::apps::env_lock::init_base_env();
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

    let active: Arc<tokio::sync::Mutex<std::collections::HashSet<String>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));

    // Initial listeners.
    let cfg = live.snapshot();
    // ECH 启动期自检（四条方向互补的检查，见 `ech_selfcheck_problems`）：
    // ① 要广告却没人发布 ② 启用了却内外层共用一张证书 ③ 发布了却没人服务
    // ④ 外层 cover 漏了 EC（内层会被逼出来）。
    // 共同点是「面板/日志看起来都正常」，只有把两处配置放在一起比才看得出来。
    // 注意 ①③ 读的是**生效**的 DNS 配置（panel.toml 会整体覆盖 config.toml 的 [dns]）。
    let dns_effective = crate::server::dns::effective(&cfg);
    for problem in ech_selfcheck_problems(&cfg, &dns_effective) {
        log::warn!("{problem}");
    }
    // ECH 发布面一致性：显式 `ssl.ech_keys` 形态下把密钥文件里的 ECHConfig 派生的
    // ECHConfigList 落盘到 DNS/面板读取的固定路径（否则 DNS 可能发布缺失或另一把钥匙的
    // 配置）。必须在生成 DNS 记录之前调用。
    let n = crate::server::ech_auto::sync_explicit_keys_for_listeners(&cfg.listeners);
    if n > 0 {
        log::info!("ech: 启动期从显式 ech_keys 派生并落盘 {n} 份 ECHConfigList");
    }
    // B-F2：管理面默认对**所有** listener 开放（`listeners_allow` 为空 = 不限制），
    // 而管理面走 Basic 认证 ⇒ 任何**明文 HTTP** 端口都成了凭据输入面（口令明文上线），
    // 防爆破面也扩到全部端口。默认值站在不安全的一侧，至少要在启动日志里说清楚。
    if cfg.admin.listeners_allow.is_empty() {
        log::warn!(
            "admin: [admin].listeners_allow 未配置 —— 管理面在**所有** listener 上可达（含明文 HTTP 端口）；建议显式列出端口，例如 listeners_allow = [8443]"
        );
    }
    for (idx, lc) in cfg.listeners.iter().enumerate() {
        // 不再「任一地址绑定失败就整体退出」：部分可用也先服务起来，失败的地址由
        // reconciler 每 2s 重试（此前一个绑不上的地址会让**整个进程**起不来）。
        if let Err(e) = spawn_listener_port(
            Arc::clone(&live),
            lc.clone(),
            idx,
            Arc::clone(&active),
        )
        .await
        {
            log::warn!(
                "listener[{idx}] 有地址未能绑定（其余地址照常服务，2s 后重试）: {e:#}"
            );
        }
    }
    // 区分两种「一个 listener 都没起来」：
    //   ① 配置里**根本没有** listener ⇒ 这是配置错误，直接退出（原来的 `bail!` 只该管这一种）；
    //   ② 配置里有 listener 但**所有地址都绑定失败**（启动期端口被旧实例占着、地址瞬时不可用）
    //      ⇒ 保持进程存活，交给下面的 reconciler 每 2s 重试。原实现把这两种混为一谈：
    //      `active.is_empty()` 即 `bail!("no listeners configured")` —— 一条**误导性**的错误
    //      信息，且让「旧实例还在关闭、新实例抢不到端口」这种**瞬时**冲突变成启动即退出
    //      （只能靠 systemd/rc 反复拉起）。reconciler 本就是为「绑定失败后重试」设计的，
    //      这里不该在它有机会跑之前就把进程杀掉。
    if cfg.listeners.is_empty() {
        anyhow::bail!("no listeners configured");
    }
    if active.lock().await.is_empty() {
        log::error!(
            "所有 listener 地址在启动时都未能绑定：进程保持存活，reconciler 每 2s 重试（端口被占用/地址暂不可用可自愈）；若长期如此请检查 address/port"
        );
    }

    // Hot-spawn newly added ports after config reload (removed ports exit accept_loop).
    {
        let live_r = Arc::clone(&live);
        let active_r = Arc::clone(&active);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // 端口 bind 失败（被占用等）会**每 2s 重试一次**：同一个端口的同一条错误
            // 只报一次，否则一天 4 万条 warn 会把真正的问题淹掉（错误内容变了再报）。
            let mut bind_err: std::collections::HashMap<u16, String> = std::collections::HashMap::new();
            loop {
                tick.tick().await;
                let snap = live_r.snapshot();
                // h3 端点：配置（含证书材料）变了就通知在跑的那个重启 ——
                // `serve()` 只在启动时读一次证书，不重启就永远用旧证书/旧设置（C-3）。
                for l in snap.listeners.iter() {
                    if l.http_versions.iter().any(|v| v.eq_ignore_ascii_case("h3")) {
                        crate::server::h3::set_h3_config_fingerprint(
                            l.port,
                            crate::server::h3::h3_config_fingerprint(l),
                        );
                    }
                }
                for (idx, lc) in snap.listeners.iter().enumerate() {
                    let key = crate::server::bind_key(lc);
                    // 按**地址**判存活（见 `addr_key`）：只要还有地址没绑上就重建，
                    // 已绑上的地址会在 spawn 里被跳过，不会被重复 bind。
                    let need = match listener_addrs(lc) {
                        Ok(addrs) => {
                            let a = active_r.lock().await;
                            // 地址没绑上 ⇒ 重建；**或 h3 端点不在跑**（例如 http_versions
                            // 去掉 h3 后端点停了，之后又重新加回）⇒ 也要重建，否则 QUIC 面
                            // 永远不恢复（端点任务已退出，仅靠地址记账看不出来）。
                            addrs.iter().any(|ad| !a.contains(&addr_key(&key, ad)))
                                || (lc.allows_h3() && !a.contains(&format!("h3|{key}")))
                        }
                        Err(_) => true,
                    };
                    if !need {
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
                        Ok(()) => {
                            bind_err.remove(&lc.port);
                            log::info!("hot-spawned listener {}", key)
                        }
                        Err(e) => {
                            let msg = format!("{e:#}");
                            if bind_err.get(&lc.port).map(String::as_str) != Some(msg.as_str()) {
                                log::warn!(
                                    "hot-spawn listener {} failed（同一条错误只报一次）: {msg}",
                                    key
                                );
                                bind_err.insert(lc.port, msg);
                            } else {
                                log::debug!("hot-spawn port {} 仍失败（已折叠）", lc.port);
                            }
                            // 一个端口都没绑上 ⇒ 进程活着但**什么也不服务**（站点、管理面、
                            // DNS 控制面全停），而面板显示「已保存」。这种情况不能折叠在
                            // warn 里，必须升级成 error 让人看见。
                            if active_r.lock().await.is_empty() {
                                log::error!(
                                    "当前**没有任何监听在服务**（配置里的地址/端口都绑定失败）—— 站点/API/DNS 控制面全部不可用；请检查 address 是否为可绑定的 IP、端口是否被占用"
                                );
                            }
                        }
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

/// 监听的**绑定键**：本实现按 `(address, address_v6, port)` 绑定，因此存活判定必须用它，
/// 而不是只用 `port`（审计 C-2）。
///
/// 只按 port 判的后果：把 `address` 从 `0.0.0.0` 改成 `127.0.0.1`（端口不变）后 reload
/// 报成功、socket 却**不重建**，仍全网卡监听（以为收紧了暴露面，实际没有）；
/// 同端口不同地址的两个 listener 也只会绑第一个，第二个**永不监听且无告警**。
pub fn bind_key(lc: &crate::config::ListenerConfig) -> String {
    format!(
        "{}|{}|{}",
        lc.address,
        lc.address_v6.as_deref().unwrap_or(""),
        lc.port
    )
}

/// 单个**地址**的存活键 = `bind_key` + 该地址。
///
/// 为什么必须按地址记账（而不是只按 `bind_key`）：一个 listener 可以同时绑 v4 与 v6
/// **两个** socket，对应**两个独立** accept 任务。只按 `bind_key` 记存活时，其中一个
/// 任务退出（例如某个 accept 撞上 EMFILE）就会把整个 key 从 `active` 抹掉，而另一个
/// 任务**仍持有自己的 socket**；reconciler 于是重建整个 listener：v4 绑得上、v6 报
/// EADDRINUSE，`spawn_listener_port` 返回 Err 并把**刚绑上的 v4 一起丢掉** —— 每 2s
/// 重试、永远失败，该监听口的 v4 半边**永久**不可用，只能重启进程恢复。
/// 按地址记账后，失败的地址单独重试，已经服务中的地址不受牵连。
fn addr_key(key: &str, addr: &std::net::SocketAddr) -> String {
    format!("{key}@{addr}")
}

/// 这个 listener 需要绑定的全部地址（与 `spawn_listener_port` 的绑定逻辑共用同一份构造，
/// 避免两处各写一遍导致记账与绑定不一致）。
fn listener_addrs(
    lc: &crate::config::ListenerConfig,
) -> Result<Vec<std::net::SocketAddr>> {
    // OpenBSD: [::] 不含 v4-mapped，双栈需显式双 bind。
    // address 默认 0.0.0.0（v4 全网卡），address_v6 可选 ::= 全网卡 v6。
    let mut addrs: Vec<String> = vec![lc.address.clone()];
    if let Some(v6) = lc.address_v6.as_deref() {
        if !v6.is_empty() {
            addrs.push(v6.to_string());
        }
    }
    addrs
        .into_iter()
        .map(|a| {
            let s = if a.contains(':') {
                format!("[{a}]:{}", lc.port)
            } else {
                format!("{a}:{}", lc.port)
            };
            s.parse::<std::net::SocketAddr>()
                .with_context(|| format!("parse listener {a}:{}", lc.port))
        })
        .collect()
}

/// 绑定一个 TCP 监听 socket；可显式设置 `IPV6_V6ONLY`（见下）。
///
/// **为什么需要这个函数（而不是直接 `tokio::net::TcpListener::bind`）**：
/// 本实现的双栈语义是「v4 与 v6 **各绑一个** socket」（`listener_addrs` 先 v4 后 v6，
/// 见其注释）。OpenBSD 上 `[::]` 默认就是 v6-only（`net.inet6.ip6.v6only=1`），两个 bind
/// 互不冲突；但 **Linux 默认 `v6only=0`** —— 先绑 `0.0.0.0:P` 再绑 `[::]:P` 时，内核把
/// 后者视为与 v4 通配冲突，返回 `EADDRINUSE`（验收 agent 黑盒复现：整个 IPv6 监听面丢失，
/// 日志只有一条 `bind [::]:P: Address already in use`）。
///
/// 显式 `IPV6_V6ONLY=1` 让 Linux 与 OpenBSD 行为一致：v6 socket 只管 v6、v4 socket 管 v4。
/// `v6only` 只在「同一 listener 同时绑 v4 与 v6」时为真（此时必须切开两个 socket）；
/// 只配单个 v6 地址时不改默认，保留「Linux 上 `[::]` 单栈即可覆盖双栈」的既有行为
/// （避免把 `address = "::"` 这种单地址配置意外收窄成 v6-only）。
fn bind_tcp(addr: SocketAddr, v6only: bool) -> std::io::Result<std::net::TcpListener> {
    use std::os::fd::{FromRawFd, RawFd};

    let family = if addr.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let fd: RawFd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // 从这里起任何失败都要先 close(fd)，否则 fd 泄漏。
    let close = |fd: RawFd| unsafe {
        libc::close(fd);
    };
    let set_int =
        |fd: RawFd, level: libc::c_int, name: libc::c_int, val: libc::c_int| -> std::io::Result<()> {
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    name,
                    &val as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        };

    // SO_REUSEADDR：与 tokio 在 unix 上的 bind 行为保持一致（TIME_WAIT 友好）。
    if let Err(e) = set_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1) {
        close(fd);
        return Err(e);
    }
    if v6only {
        // 只有 v6 socket 谈得上 IPV6_V6ONLY；对 v4 socket 设它会得到 ENOPROTOOPT。
        if let Err(e) = set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1) {
            close(fd);
            return Err(e);
        }
    }

    // 组装 sockaddr。BSD 的 sockaddr_in/sockaddr_in6 有 len 字段、Linux 没有 → 用 cfg 处理。
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            let sin = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in)
            };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            #[cfg(any(
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "macos",
                target_os = "ios"
            ))]
            {
                sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sin6 = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
            };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sin6.sin6_scope_id = v6.scope_id();
            #[cfg(any(
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "macos",
                target_os = "ios"
            ))]
            {
                sin6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &storage as *const libc::sockaddr_storage as *const libc::sockaddr,
            len,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        close(fd);
        return Err(e);
    }
    if unsafe { libc::listen(fd, 1024) } != 0 {
        let e = std::io::Error::last_os_error();
        close(fd);
        return Err(e);
    }
    // 非阻塞（tokio 要求）+ CLOEXEC（避免被引擎子进程继承监听 fd）。
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok(unsafe { std::net::TcpListener::from_raw_fd(fd) })
}

async fn spawn_listener_port(
    live: Arc<LiveConfig>,
    lc: crate::config::ListenerConfig,
    idx: usize,
    active: Arc<tokio::sync::Mutex<std::collections::HashSet<String>>>,
) -> Result<()> {
    let port = lc.port;
    // 绑定键含地址：同端口不同地址是**两个** listener，改地址也能正确重建（C-2）。
    let key = bind_key(&lc);
    let addrs = listener_addrs(&lc)?;
    // 双栈（同时有 v4 与 v6 地址）时，v6 socket 必须显式 V6ONLY，否则 Linux 上两个 bind
    // 会冲突（见 `bind_tcp`）。单地址/单栈配置不改默认。
    let dual_stack = addrs.iter().any(|a| a.is_ipv4()) && addrs.iter().any(|a| a.is_ipv6());
    // 逐地址登记 + 逐地址绑定：**部分失败不牵连已经绑上的地址**（见 `addr_key` 的说明）。
    let mut listeners: Vec<(SocketAddr, tokio::net::TcpListener)> = Vec::new();
    let mut first_err: Option<anyhow::Error> = None;
    // 有多少地址**已经**在跑（本次被跳过）。用于区分「本次没绑任何新地址」的两种含义：
    //   ① 全都已经在跑（正常，无需重建 TCP）  ② 全都绑失败（真失败）。
    let mut already_active = 0usize;
    for addr in addrs.iter().copied() {
        let akey = addr_key(&key, &addr);
        {
            let mut a = active.lock().await;
            if a.contains(&akey) {
                already_active += 1;
                continue; // 这个地址已有活着的 accept 任务
            }
            a.insert(akey.clone());
        }
        // 用 `bind_tcp` 而不是 `TcpListener::bind`：只有前者能在 bind 前设 IPV6_V6ONLY。
        let bound = bind_tcp(addr, addr.is_ipv6() && dual_stack)
            .and_then(tokio::net::TcpListener::from_std);
        match bound {
            Ok(l) => listeners.push((addr, l)),
            Err(e) => {
                // 只注销**这个地址**的账，让 reconciler 2s 后单独重试它；
                // 兄弟地址（例如已经绑上的 v4）不受影响。
                active.lock().await.remove(&akey);
                if first_err.is_none() {
                    first_err = Some(anyhow::Error::new(e).context(format!("bind {addr}")));
                }
            }
        }
    }
    // h3/QUIC 的 UDP 绑定地址：优先用本次新绑的第一个地址；若本次没绑新的（全部已在跑），
    // 用配置里的第一个地址 —— 它必然已经在 active 里（否则不会被跳过），UDP 与 TCP 不冲突。
    let h3_addr = listeners
        .first()
        .map(|(a, _)| *a)
        .or_else(|| addrs.first().copied());
    // 这个 listener 是否有任何一个地址在服务（本次新绑 或 早已在跑）。用于区分
    // 「没绑新地址是因为全在跑」与「全绑失败」（后者 first_err 为 Some，另有返回）。
    let bound_or_active = !listeners.is_empty() || already_active > 0;

    if !listeners.is_empty() {
        maybe_set_busy_poll(&listeners[0].1);
        for (a, _) in &listeners {
            log::info!("listener[{idx}] ready on {a} root={}", lc.root.display());
        }
    }

    for (a, listener) in listeners {
        let live_c = Arc::clone(&live);
        let active_c = Arc::clone(&active);
        let key_c = key.clone();
        let akey_c = addr_key(&key, &a);
        tokio::spawn(async move {
            // 把**实际绑定的地址**（而不是配置里的字符串）交给连接分发：
            // 同端口不同地址的两个 listener 各自服务自己的站点（C-2）。
            let res = accept_loop(listener, live_c, key_c.clone(), a).await;
            // 只注销**自己这个地址**的账 —— 抹掉整个 `key` 会让兄弟地址失去记账，
            // 下次重建时兄弟地址被重复 bind（EADDRINUSE）并把已绑上的一起丢掉。
            active_c.lock().await.remove(&akey_c);
            log::warn!("accept_loop {a} ended: {res:?}");
        });
    }
    // HTTP/3 端点：**必须在下面的 `first_err` 提前返回之前**启动。
    //
    // 旧实现把 `if let Some(e) = first_err { return Err(e) }` 排在这里之前 ⇒ 只要**任一**
    // 地址绑不上（双栈冲突、某地址被别的进程占用、权限不足…），该 listener 的 h3/QUIC
    // 端点就永远起不来，而且日志里**没有任何** h3 相关报错（验收 agent 对照复现：去掉
    // `address_v6` 后 h3 UDP 立刻正常、`h3 GET / → 200`）。地址绑定失败只该影响**那个
    // 地址**的 TCP/HTTP 面，不该牵连同 listener 的 QUIC 端点。
    if lc.allows_h3() {
      if let Some(udp_addr) = h3_addr {
        // 去重：reconciler 会因某个地址没绑上而每 2s 重调本函数；若每次都能再 spawn 一个
        // h3 任务，就会重复 bind 同一个 UDP 端口。用 active 集合里的合成键 `h3|<key>` 记账，
        // 任务退出（listener 被删）时自行注销，保证同一 listener 只跑一个 h3 端点。
        let h3key = format!("h3|{key}");
        let should_spawn = {
            let mut a = active.lock().await;
            if a.contains(&h3key) {
                false
            } else {
                a.insert(h3key.clone());
                true
            }
        };
        if should_spawn {
            let live_h3 = Arc::clone(&live);
            let active_h3 = Arc::clone(&active);
            let h3key_c = h3key.clone();
            let key_h3 = key.clone();
            tokio::spawn(async move {
                loop {
                    // 每轮都从 live 快照**重新取**配置（不再克隆一次用到天荒地老）：
                    // `serve()` 因配置/材料变化主动返回后，这里就能用新配置重启端点。
                    let Some(cur) = live_h3
                        .snapshot()
                        .listeners
                        .iter()
                        .find(|l| crate::server::bind_key(l) == key_h3)
                        .cloned()
                    else {
                        log::info!("h3 listener {key_h3} removed; stopping");
                        break;
                    };
                    // **http_versions 去掉 "h3"** 也必须停：原来只判「listener 还在不在」，
                    // 于是把 h3 从 http_versions 里删掉后，QUIC 端点每轮照旧重新 bind+serve
                    // —— UDP/QUIC 面继续在服务（面板显示 h3 已关），只有删掉整个 listener 才停。
                    if !cur.allows_h3() {
                        log::info!("h3 listener {key_h3}: http_versions 不再含 h3，停止 QUIC 端点");
                        break;
                    }
                    let fp = crate::server::h3::h3_config_fingerprint(&cur);
                    crate::server::h3::set_h3_config_fingerprint(port, fp);
                    let rx = crate::server::h3::h3_config_watch(port, fp);
                    if let Err(e) =
                        crate::server::h3::serve(udp_addr, cur, Arc::clone(&live_h3), fp, rx).await
                    {
                        log::warn!("h3 listener {udp_addr}: {e:#}; retry in 5s");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
                // 端点已停：注销 h3 记账，这样 listener 被重新加回（或 http_versions 重新
                // 含 h3）时 reconciler 能再次拉起它（见 reconciler 的 `need` 判定）。
                active_h3.lock().await.remove(&h3key_c);
            });
        }
      }
    }

    // 有地址没绑上：把错误交回调用方（记日志 + 让 reconciler 重试该地址），
    // 但**不要**因此丢掉上面已经起来的那些地址，也**不要**因此跳过 h3 端点。
    if let Some(e) = first_err {
        return Err(e);
    }
    // 本次既没绑上任何新地址、也没有任何地址已在跑 ⇒ 所有地址都绑失败（first_err 必为
    // Some，上面已返回）。保留这道兜底只为防御 `addrs` 为空这种不可能情形。
    if !bound_or_active {
        return Err(anyhow::anyhow!("listener {key}: 没有可绑定的地址"));
    }
    Ok(())
}

async fn accept_loop(
    listener: TcpListener,
    live: Arc<LiveConfig>,
    key: String,
    local: std::net::SocketAddr,
) -> Result<()> {
    // 配置重查定时器：**整个循环只建一次**。
    //
    // 原实现在内层 `select!` 里写 `tokio::time::sleep(2s)` —— 每**接受一条连接**就
    // 新建一个 Sleep、连接处理完再把它 drop，于是连接 churn 场景下每秒钟注册/注销
    // 上万次 timer-wheel 项（还要拿 timer 分片锁），纯属 accept 热路径上的白工。
    // 改用一次性 interval：`Interval::tick` 是 cancel-safe 的，每 2s 到期后在任意一次
    // select 里被选中即可，不会因为中间的 accept 而丢失这一拍。
    //
    // 顺带去掉「每连接一次」的配置存活检查（`live.snapshot()` + `bind_key` 的 String
    // 分配）：它的作用与下面 tick 分支里的检查**完全重复**，只是把「listener 被删后
    // 停 accept」的时延从「下一条连接」提前到「下一条连接」。改为只在 tick 里检查后，
    // 删除检测仍在 ≤2s 内完成（与 reconciler 的 2s 节奏一致），而 accept 热路径上不再有
    // 快照 + 字符串分配。行为差异仅在「listener 被删后、下一条连接恰好落在 tick 之前」
    // 这一窗口内会多 accept 一两条连接——那两条会由 `handle_connection` 的
    // `listener vanished` 分支正常收尾。
    let mut recheck = tokio::time::interval(std::time::Duration::from_secs(2));
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    recheck.tick().await; // interval 的首个 tick 立即就绪，先消费掉
    'accept: loop {
        let accept = listener.accept();
        tokio::pin!(accept);
        let (stream, peer) = loop {
            tokio::select! {
                res = &mut accept => match res {
                    Ok(pair) => break pair,
                    Err(e) => {
                        // **绝不因为一次 accept 错误就终结监听口**（第 6 轮并发报告的 P0）。
                        // EMFILE/ENFILE（fd 被瞬时打满 —— 例如大量零字节空连接就能做到）、
                        // ECONNABORTED（对端在 accept 返回前 RST）、EINTR 全都是**可恢复**的。
                        // 原实现是 `res?` 直接 return Err：该监听口此后**永久**不再 accept，
                        // 站点半边消失，而运维侧只看到一条被折叠的 warn（实测复现：
                        // 空连接打满 fd ⇒ 命中 EMFILE 的口永久下线，且重建也救不回来）。
                        // 退避 100ms 后重建 accept future 重来 —— 监听口始终存活。
                        // 日志按 30s 窗口折叠：这条路径是**匿名可触发**的，不能按请求速率刷日志。
                        crate::server::log_throttle::warn_every(
                            "accept-retry",
                            std::time::Duration::from_secs(30),
                            &format!(
                                "accept_loop {local} accept 失败（退避重试，监听口保持存活）: {e}"
                            ),
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue 'accept; // 重建 accept future；旧的已出错不能再 poll
                    }
                },
                _ = recheck.tick() => {
                    let snap = live.snapshot();
                    if !snap.listeners.iter().any(|l| crate::server::bind_key(l) == key) {
                        log::info!(
                            "listener {key} removed/changed in config; shutting down accept loop"
                        );
                        return Ok(());
                    }
                }
            }
        };
        maybe_set_busy_poll_stream(&stream);
        // TCP_NODELAY：**必须**开。默认（Nagle）下小响应会被攒着等 ACK，与对端
        // 延迟 ACK 叠加后每个 keep-alive 请求白等 1–40ms —— 实测在本机把 p50 从
        // ~0.3ms 抬到 2.2ms、吞吐从 ~110k 掉到 ~27k（同机 h2o 早就是默认开启）。
        // 这不是"优化"而是**正确性级别**的默认值：HTTP 响应本来就不该等 Nagle 攒包。
        // 失败只记日志（个别平台/套接字类型可能不支持），不影响连接。
        if let Err(e) = stream.set_nodelay(true) {
            log::debug!("set_nodelay({peer}): {e}");
        }
        // P2-7：SYN 速率信号源——syncookie 评估器按 tick 差值估算速率并动态切换 sysctl。
        crate::server::syncookie::note_syn();
        let live_c = Arc::clone(&live);
        tokio::spawn(async move {
            if let Err(e) = listener::handle_connection(stream, live_c, local, peer).await {
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

/// 启动期自检：ECH 的「配置面」与「发布面」是否自洽（四个方向，见函数内注释）。
///
/// `ech_advertise` 的字面含义是「发布到 DNS」，但真正的发布动作在
/// `[dns] [[dns.https_rr]]`（见 `dns::auto_https_records`）。少了这层检查，
/// 「ECH 已启用」与「客户端拿不到 ECHConfig」可以同时成立而无人察觉。
///
/// `dns` 参数必须是**生效**的那份（`dns::effective(cfg)`）：`state/dns/etc/panel.toml`
/// 存在时会整体覆盖 config.toml 的 `[dns]`，拿 `cfg.dns` 判断会产生假告警
/// （生产实测：https_rr 写进 panel.toml 后 dig 已能查到 ech=，这里还在报「没发布」）。
fn ech_selfcheck_problems(
    cfg: &crate::config::Config,
    dns: &crate::server::dns::DnsConfig,
) -> Vec<String> {
    let mut out = Vec::new();

    // 读**生效**的 DNS 配置：`state/dns/etc/panel.toml` 存在时会整体覆盖 config.toml 的
    // `[dns]`（C-17），拿 cfg.dns 判断会得到「记录明明已发布却一直报没发布」的假告警
    // —— 生产实测：https_rr 写进 panel.toml 后，dig 能查到 ech=，这里还在 warn。
    let published: Vec<String> = dns
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

    // 方向 4（§21.34）：外层 cover 漏了 EC 那一半。
    //
    // BoringSSL 按客户端 `signature_algorithms` 在 RSA/EC 里选，且**优先 ECDSA**。内层配了
    // `cert_ec` 而外层没配 `ech_cover_cert_ec` 时，容器里唯一的 EC 证书是**内层**那张 ⇒
    // 默认客户端（同时支持 RSA/ECDSA）与只提供 ECDSA 的探测者**都会拿到内层真实证书**，
    // cover 等于不存在。配置期已 fail-fast 拦这一条，这里再报一次是为了那些**旧配置**
    // （reload 前就已存在、或从面板改出来的）也能在启动日志里看见。
    for lc in &cfg.listeners {
        let Some(ssl) = lc.ssl.as_ref() else { continue };
        if !ssl.ech || ssl.ech_cover_cert.is_none() {
            continue;
        }
        let inner_ec = ssl.cert_ec.as_deref().map_or(false, |s| !s.trim().is_empty());
        let cover_ec = ssl
            .ech_cover_cert_ec
            .as_deref()
            .map_or(false, |s| !s.trim().is_empty());
        if inner_ec && !cover_ec {
            out.push(format!(
                "ECH: listener {}:{} 配了 ssl.cert_ec（内层 EC）但没有 ssl.ech_cover_cert_ec —— BoringSSL 按客户端 sigalgs 在 RSA/EC 里选且优先 ECDSA，外层只有 RSA 时**非 ECH 客户端与主动探测者都会拿到内层真实证书**，cover 形同虚设。补上 ech_cover_cert_ec/ech_cover_key_ec（可用 `webserver --gen-cert <public_name> --ec` 生成）",
                lc.address, lc.port
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
        let problems = ech_selfcheck_problems(&cfg, &cfg.dns);
        assert!(
            problems.iter().any(|p| p.contains("ECH 不会被发布")),
            "应报告「要广告但没发布」: {problems:?}"
        );
        // 补上对应记录后，方向 1 不再报（方向 2 仍会因为没 cover 证书而报 —— 那是另一条）。
        let cfg2 = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = true, ech_public_name = \"v.example.com\" }\n\n[[dns.https_rr]]\nname = \"v.example.com\"\nech = true\n",
        );
        let p2 = ech_selfcheck_problems(&cfg2, &cfg2.dns);
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
            ech_selfcheck_problems(&cfg, &cfg.dns)
                .iter()
                .any(|p| p.contains("没有配置 cover 证书")),
            "缺 cover 证书必须报"
        );
        let cfg_ok = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = true, ech_keys = \"state/ech/ech_keys.pem\", ech_cover_cert = \"cover.pem\", ech_cover_key = \"cover.key.pem\" }\n",
        );
        assert!(
            !ech_selfcheck_problems(&cfg_ok, &cfg_ok.dns)
                .iter()
                .any(|p| p.contains("没有配置 cover 证书")),
            "配全 cover 后不该再报"
        );
        // `ech = false` 的 listener 不参与（开关关掉就没有内外层共用问题）。
        let cfg_off = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = false, ech_public_name = \"v.example.com\" }\n",
        );
        assert!(
            !ech_selfcheck_problems(&cfg_off, &cfg_off.dns)
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
            ech_selfcheck_problems(&cfg, &cfg.dns)
                .iter()
                .any(|p| p.contains("没有 listener 在服务")),
            "发布了却没人服务必须报"
        );
        let cfg_ok = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", ech = true, ech_keys = \"state/ech/ech_keys.pem\", ech_public_name = \"v.example.com\" }\n\n[[dns.https_rr]]\nname = \"v.example.com\"\nech = true\n",
        );
        assert!(
            !ech_selfcheck_problems(&cfg_ok, &cfg_ok.dns)
                .iter()
                .any(|p| p.contains("没有 listener 在服务")),
            "服务端就绪后不该再报方向 3"
        );
    }

    /// 方向 4（§21.34）：内层有 EC、外层 cover 漏了 EC ⇒ 必须报 —— 这一条是**真机复现**过的
    /// 内层泄漏：BoringSSL 优先 ECDSA，外层只有 RSA 时非 ECH 客户端拿到的是内层 EC 证书。
    /// 补上 `ech_cover_cert_ec` 后必须不再报（否则「补了还报」会让运维忽略这条告警）。
    #[test]
    fn cover_ec_missing_while_inner_ec_is_reported() {
        let bad = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", cert_ec = \"cert_ec.pem\", key_ec = \"key_ec.pem\", \
ech = true, ech_keys = \"state/ech/ech_keys.pem\", ech_public_name = \"v.example.com\", \
ech_cover_cert = \"cover.pem\", ech_cover_key = \"cover.key.pem\" }\n",
        );
        assert!(
            ech_selfcheck_problems(&bad, &bad.dns)
                .iter()
                .any(|p| p.contains("ech_cover_cert_ec")),
            "内层 EC + 外层无 EC 必须报方向 4"
        );
        let ok = cfg_of(
            "ssl = { cert = \"cert.pem\", key = \"key.pem\", cert_ec = \"cert_ec.pem\", key_ec = \"key_ec.pem\", \
ech = true, ech_keys = \"state/ech/ech_keys.pem\", ech_public_name = \"v.example.com\", \
ech_cover_cert = \"cover.pem\", ech_cover_key = \"cover.key.pem\", \
ech_cover_cert_ec = \"cover_ec.pem\", ech_cover_key_ec = \"cover_ec.key.pem\" }\n",
        );
        assert!(
            !ech_selfcheck_problems(&ok, &ok.dns)
                .iter()
                .any(|p| p.contains("ech_cover_cert_ec")),
            "外层 EC 补齐后不该再报方向 4"
        );
    }
}

#[cfg(test)]
mod bind_key_tests {
    use crate::config::ListenerConfig;

    /// 绑定键必须**含地址**（审计 C-2）。
    ///
    /// 只按 port 判的后果是真机实测过的那种静默失效：改 `address` 后 reload 报成功、
    /// socket 不重建。这条测试把「同端口不同地址 ⇒ 不同键」钉住，没有它，
    /// 有人把 bind_key 简化成 `port.to_string()` 也不会有测试变红。
    #[test]
    fn bind_key_includes_address_v6_and_port() {
        let mut a = ListenerConfig::default();
        a.address = "0.0.0.0".into();
        a.port = 8443;

        let mut same = a.clone();
        assert_eq!(
            crate::server::bind_key(&a),
            crate::server::bind_key(&same),
            "同参数必须稳定（去重/存活判定依赖它）"
        );

        same = a.clone();
        same.address = "127.0.0.1".into();
        assert_ne!(
            crate::server::bind_key(&a),
            crate::server::bind_key(&same),
            "同端口不同地址必须是不同的键（否则改地址不重建 socket）"
        );

        same = a.clone();
        same.address_v6 = Some("::".into());
        assert_ne!(
            crate::server::bind_key(&a),
            crate::server::bind_key(&same),
            "address_v6 必须参与键"
        );

        same = a.clone();
        same.port = 9443;
        assert_ne!(
            crate::server::bind_key(&a),
            crate::server::bind_key(&same),
            "端口必须参与键"
        );
    }
}

#[cfg(all(test, unix))]
mod bind_tcp_tests {
    use super::bind_tcp;

    fn v6only_of(l: &std::net::TcpListener) -> libc::c_int {
        use std::os::fd::AsRawFd;
        let mut val: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                l.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt IPV6_V6ONLY: {}", std::io::Error::last_os_error());
        val
    }

    /// V3-2 回归：**同端口**先绑 v4 通配、再绑 v6 通配必须都成功。
    ///
    /// 这正是验收 agent 黑盒复现的缺陷：Linux 默认 `v6only=0`，`[::]:P` 会与
    /// `0.0.0.0:P` 冲突（EADDRINUSE）⇒ 整个 IPv6 面丢失。修复靠对 v6 socket 显式设
    /// `IPV6_V6ONLY=1`。没有这条测试，有人把 `v6only` 参数去掉也不会有测试变红。
    #[test]
    fn dual_stack_same_port_binds_both() {
        let v4 = bind_tcp("0.0.0.0:0".parse().unwrap(), false).expect("v4 wildcard bind");
        let port = v4.local_addr().unwrap().port();
        let v6 = bind_tcp(format!("[::]:{port}").parse().unwrap(), true);
        assert!(
            v6.is_ok(),
            "dual-stack：同端口 v6 必须能绑（V6ONLY=1），实际 {:?}",
            v6.err()
        );
        assert_eq!(v6only_of(&v6.unwrap()), 1, "dual-stack v6 socket 必须 V6ONLY=1");
    }

    /// 只配单个 v6 地址时不设 V6ONLY —— 保留 Linux 上「`[::]` 单栈即覆盖双栈」的行为。
    #[test]
    fn single_v6_keeps_default_v6only() {
        let l = bind_tcp("[::]:0".parse().unwrap(), false).expect("v6 bind");
        // Linux 默认 v6only=0（双栈）；这里只断言「没有被我们改成 1」。
        assert_eq!(v6only_of(&l), 0, "单 v6 地址不应被强制 V6ONLY=1");
    }

    #[test]
    fn v4_socket_binds_and_is_v4() {
        let l = bind_tcp("127.0.0.1:0".parse().unwrap(), false).expect("v4 bind");
        assert!(l.local_addr().unwrap().is_ipv4());
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
