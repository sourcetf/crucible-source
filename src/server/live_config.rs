//! Hot-reloadable configuration snapshot + periodic mtime watch.

use crate::config::Config;
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub struct LiveConfig {
    // P2-6 性能：快照持有 Arc<Config>，热路径 snapshot() 只做一次 Arc clone，
    // 不再每请求整树深拷贝 Config（写侧低频：reload/replace 才构造新 Arc）。
    inner: RwLock<Arc<Config>>,
    path: PathBuf,
    last_mtime: RwLock<Option<SystemTime>>,
    /// 上一次生效的「全部 listener 指纹」。
    listeners_fp: RwLock<u64>,
    /// listener 配置**变化**的次数（只在指纹真的变了时 +1）。
    ///
    /// 为什么需要它：h1/h2 的 **已建立连接** 在 accept 时就拿走了一份 `ListenerConfig`
    /// 快照，之后整条连接的所有请求都用它 —— 也就是说 `root`/`basic_auth`/`page_rules`/
    /// `file_open`/限流 这些 **per-listener 策略**改了之后，对**已建立**的连接永远不生效
    /// （只有新连接拿到新配置）。改 `basic_auth` 的口令因此「改了但没生效」，这是安全相关的
    /// 过期状态。用这个计数器让连接在**下一个请求**上主动收尾（h1 回 `Connection: close`、
    /// h2 发 GOAWAY），客户端下次请求就走新的 accept 路径。
    listeners_gen: std::sync::atomic::AtomicU64,
}

/// 全部 listener 的配置指纹（顺序无关）。
///
/// 直接复用 [`crate::server::h3::h3_config_fingerprint`]：它已经把整份 listener 配置
/// （Debug 形式，含 ssl/early_data/root/autoindex/口令/限流等所有 per-listener 字段）
/// 连同**证书文件的 mtime+size** 一起哈希了 —— 证书原地续期（配置字符串不变）也能被发现。
/// 只在配置 reload/replace 时算一次，不在热路径上。
fn listeners_fingerprint(cfg: &Config) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut items: Vec<(String, u16, u64)> = cfg
        .listeners
        .iter()
        .map(|l| {
            (
                l.address.clone(),
                l.port,
                crate::server::h3::h3_config_fingerprint(l),
            )
        })
        .collect();
    // 排序后再哈希：listener 在配置里的先后顺序变了不算「配置变了」。
    items.sort();
    items.hash(&mut h);
    h.finish()
}


fn persist_admin_hash_structured(path: &Path, username: &str, hash: &str) -> anyhow::Result<()> {
    use crate::server::admin_config_edit as cfg_edit;
    // Build a one-shot LiveConfig-like write via tree APIs used by admin_config_edit.
    let mut tree = cfg_edit::load_tree(path)?;
    // Reuse persist logic by mutating tree then validating write.
    let table = tree
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root not a table"))?;
    let admin = table
        .entry("admin".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let at = admin
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("[admin] not a table"))?;
    let users = at
        .entry("users".to_string())
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let arr = users
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("admin.users not array"))?;
    let mut found = false;
    for u in arr.iter_mut() {
        if u.get("username").and_then(|x| x.as_str()) == Some(username) {
            if let Some(t) = u.as_table_mut() {
                t.insert("password_hash".into(), toml::Value::String(hash.to_string()));
                found = true;
            }
        }
    }
    if !found {
        let mut m = toml::map::Map::new();
        m.insert("username".into(), toml::Value::String(username.into()));
        m.insert("password_hash".into(), toml::Value::String(hash.to_string()));
        arr.push(toml::Value::Table(m));
    }
    let text = toml::to_string_pretty(&tree).map_err(|e| anyhow::anyhow!("toml encode: {e}"))?;
    let tmp_validate = unique_tmp_path(path, "validate");
    // 同 write_tree：校验副本含口令哈希等，必须 0600（否则窗口内世界可读）。
    crate::server::dns::write_new_0600(&tmp_validate, text.as_bytes())?;
    let parsed = crate::config::Config::load(&tmp_validate).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_validate);
        anyhow::anyhow!("config validate: {e}")
    })?;
    let _ = std::fs::remove_file(&tmp_validate);
    parsed.validate()?;
    // 原子写 + **保留原权限**：config.toml 含口令哈希 / MaxMind key / TLS·ECH 材料路径，
    // 原来是 `fs::write`（umask 0644）+ rename，每保存一次就把运维可能特意设过的 0600
    // 静默降级成 0644。见 `crate::server::dns::write_config_atomic`。
    crate::server::dns::write_config_atomic(path, text.as_bytes())?;
    Ok(())
}

/// 生成唯一的临时文件路径：`<name>.<tag>.<pid>-<seq>-<nanos>`。
///
/// 固定名（`config.toml.tmp` / `config.toml.validate`）在并发保存时会互相踩：
/// A 写 → B 写 → A 校验的其实是 B 的内容 → A 把它 rename 到位还报「A 已保存」，
/// 而 B 的 rename 随后 ENOENT；`.validate` 变体还可能被另一个写者中途删除，
/// 导致 Config::load 失败并误报「校验失败（未写盘）」。
pub(crate) fn unique_tmp_path(path: &std::path::Path, tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.toml");
    let tmp_name = format!("{name}.{tag}.{}-{seq}-{nanos}", std::process::id());
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(tmp_name),
        _ => std::path::PathBuf::from(tmp_name),
    }
}

impl LiveConfig {
    pub fn new(cfg: Config, path: PathBuf) -> Self {
        let mtime = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok();
        let fp = listeners_fingerprint(&cfg);
        Self {
            inner: RwLock::new(Arc::new(cfg)),
            path,
            last_mtime: RwLock::new(mtime),
            listeners_fp: RwLock::new(fp),
            listeners_gen: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// listener 配置的变化次数（见 [`Self::listeners_gen`] 的说明）。
    pub fn listeners_generation(&self) -> u64 {
        self.listeners_gen.load(std::sync::atomic::Ordering::Acquire)
    }

    /// 新配置生效前调用：listener 指纹真的变了才推进代数。
    ///
    /// 只在**指纹变化**时推进（而不是每次 reload 都推）—— 否则改一条 GeoIP/DNS 配置、
    /// 甚至只是保存一次内容相同的文件，都会把所有已建立的 h1/h2 连接赶下线。
    fn note_listeners(&self, cfg: &Config) {
        let fp = listeners_fingerprint(cfg);
        let mut cur = self.listeners_fp.write();
        if *cur != fp {
            *cur = fp;
            self.listeners_gen
                .fetch_add(1, std::sync::atomic::Ordering::Release);
        }
    }

    pub fn snapshot(&self) -> Arc<Config> {
        Arc::clone(&self.inner.read())
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn reload(&self) -> anyhow::Result<()> {
        // 配置重载后 DNS 的「生效配置」也可能变（config.toml 的 [dns] 在无 panel.toml 时
        // 就是权威来源）—— 让 effective() 的缓存失效，避免继续用旧快照。
        crate::server::dns::invalidate_effective();
        let cfg = Config::load(&self.path)?;
        let old_binds: std::collections::BTreeSet<(String, u16)> = {
            let cur = self.inner.read();
            cur.listeners
                .iter()
                .map(|l| (l.address.clone(), l.port))
                .collect()
        };
        let new_binds: std::collections::BTreeSet<(String, u16)> = cfg
            .listeners
            .iter()
            .map(|l| (l.address.clone(), l.port))
            .collect();
        if old_binds != new_binds {
            let added: Vec<_> = new_binds.difference(&old_binds).cloned().collect();
            let removed: Vec<_> = old_binds.difference(&new_binds).cloned().collect();
            log::info!(
                "config reload: listener binds changed (added={added:?} removed={removed:?});                  removed ports stop accepting; added ports are hot-spawned by reconciler"
            );
        }
        if let Ok(meta) = std::fs::metadata(&self.path) {
            *self.last_mtime.write() = meta.modified().ok();
        }
        // 先推进 listener 代数再换快照：并发的请求若在新快照可见之后才读代数，会看到
        // 「配置已新、代数已增」，于是它这一条连接会收尾 —— 这正是我们要的。
        // 反过来（先换代后读指纹）也不需要额外同步：两者都在同一把 RwLock 的临界区里。
        self.note_listeners(&cfg);
        *self.inner.write() = Arc::new(cfg);
        // acceptor 缓存的键只有配置**字符串**（证书/密钥路径），而缓存本身从不失效：
        // 同一路径上换了证书（certbot 续期、面板覆盖 ssl.cert）时指纹不变，
        // 进程会一直用旧证书/旧 ECH 配置服务到重启为止。热路径不能加 stat
        // （accept_and_serve 每连接都会查一次缓存），所以在配置重载这个低频点上显式清空。
        // acceptor 缓存是 BoringSSL 路径的东西（rustls 配置下那个模块整个不编译）。
        #[cfg(feature = "tls_boring")]
        crate::server::tls::boring_path::clear_acceptor_cache();
        crate::server::apps::reconcile_apps_runtime(self);
        // 热重载后确保 Hidden Service 仍按新配置在跑（改 ports/enabled/tor_bin 时生效）。
        // `ensure_hs` 幂等：hostname 已存在则复用，不会重启已在跑的 tor。
        crate::server::tor_hs::spawn_from_config(self.snapshot().tor_hs.clone());
        log::info!("config reloaded from {}", self.path.display());
        Ok(())
    }

    /// 用一份**已经构造好**的配置替换内存快照（面板局部修改用）。
    ///
    /// 它必须与 [`LiveConfig::reload`] 有一模一样的副作用，否则将来有人拿它做局部热更时
    /// 会**静默绕过** acceptor 缓存清理与 mtime 记账：证书/ECH 材料已经变了，
    /// 进程却继续用旧 acceptor 服务（就是 C-1 那个陷阱）。
    pub fn replace(&self, cfg: Config) {
        #[cfg(feature = "tls_boring")]
        crate::server::tls::boring_path::clear_acceptor_cache();
        if let Ok(m) = std::fs::metadata(&self.path).and_then(|m| m.modified()) {
            *self.last_mtime.write() = Some(m);
        }
        self.note_listeners(&cfg);
        *self.inner.write() = Arc::new(cfg);
        // **与 reload 保持一致**（见上面的文档承诺）：漏掉这两步时，用 replace 做局部热更
        // 会静默保住旧的应用引擎进程与旧的 Hidden Service 状态（例如新配置把某个 app
        // 关掉/换个端口，运行时却照旧）。
        crate::server::apps::reconcile_apps_runtime(self);
        crate::server::tor_hs::spawn_from_config(self.snapshot().tor_hs.clone());
    }

    pub fn update_admin_hash(&self, hash: String) {
        // 记录**实际被改的那个账号**：内存改的是 users[0]，而落盘以前硬编码写 "admin"。
        // 二者不一致时（首个账号不叫 admin）密码会被写进一个新建的 "admin" 条目，
        // reload 后运维就会得到一个多出来的账号，而原本那个账号密码没变。
        let target_user = {
            // Arc 化后写侧：clone 出可变副本改完整体换回（低频操作，整树 clone 可接受）。
            let mut guard = self.inner.write();
            let mut cfg = Arc::try_unwrap(Arc::clone(&guard)).unwrap_or_else(|arc| (*arc).clone());
            let name = if let Some(u) = cfg.admin.users.first_mut() {
                u.password_hash = hash.clone();
                let n = u.username.trim().to_string();
                if n.is_empty() { "admin".to_string() } else { n }
            } else {
                cfg.admin.users.push(crate::config::AdminUser {
                    username: "admin".into(),
                    password_hash: hash.clone(),
                });
                "admin".to_string()
            };
            *guard = Arc::new(cfg);
            name
        };
        // 持久化到 config 文件：否则 mtime watcher 重载 / 重启后新密码被冲掉。
        self.persist_admin_hash(&target_user, &hash);
    }

    fn persist_admin_hash(&self, username: &str, hash: &str) {
        // Structured TOML edit via admin_config_edit (no first-line scan).
        if let Err(e) = persist_admin_hash_structured(&self.path, username, hash) {
            log::warn!("persist_admin_hash failed: {e:#}");
        } else {
            let _ = self.reload();
        }
    }

    /// 若 mtime 变化则 reload；供后台轮询调用。
    pub fn reload_if_changed(&self) -> anyhow::Result<bool> {
        let meta = std::fs::metadata(&self.path)?;
        let mtime = meta.modified()?;
        let prev = *self.last_mtime.read();
        if prev == Some(mtime) {
            return Ok(false);
        }
        self.reload()?;
        Ok(true)
    }
}

pub type SharedLive = Arc<LiveConfig>;

/// 按端口取**当前生效**的 listener 配置（`None` = 该端口已从配置里删掉）。
///
/// 用途：请求路径上的决策（上传闸门、落盘 root 等）必须用**现在**的配置，而不是
/// 建连时那份快照 —— h1/h2 的长连接可以活几小时，期间面板改的配置不会自己生效。
pub fn listener_by_port(live: &LiveConfig, port: u16) -> Option<crate::config::ListenerConfig> {
    live.snapshot()
        .listeners
        .iter()
        .find(|l| l.port == port)
        .cloned()
}

/// 周期性监视 config.toml mtime（OpenBSD 无可靠 inotify 时用轮询即可）。
pub fn spawn_mtime_watcher(live: Arc<LiveConfig>, interval: Duration) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // 坏配置会**一直**留在磁盘上，而轮询间隔是 2s：不同一个错误去重就是
        // 约 4.3 万条/天，既淹没日志又会吃掉 `daily.local` 的轮转代数。
        // 同一条错误只 warn 一次，内容变了或恢复正常后再重新报。
        let mut last_err: Option<String> = None;
        loop {
            tick.tick().await;
            match live.reload_if_changed() {
                Ok(true) => {
                    last_err = None;
                }
                Ok(false) => {}
                Err(e) => {
                    let msg = format!("{e:#}");
                    if last_err.as_deref() != Some(msg.as_str()) {
                        log::warn!(
                            "config watch reload failed（同一条错误只报一次）: {msg}"
                        );
                        last_err = Some(msg);
                    } else {
                        log::debug!("config watch reload failed（与上次相同，已折叠）: {msg}");
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod listeners_generation_tests {
    use super::*;

    fn cfg(extra: &str, listeners: &str) -> Config {
        toml::from_str(&format!("{extra}\n{listeners}")).expect("parse")
    }

    fn one(root: &str) -> Config {
        cfg(
            "",
            &format!("[[listeners]]\naddress = \"127.0.0.1\"\nport = 9095\nroot = {root:?}\n"),
        )
    }

    /// **只**在 listener 配置变化时推进代数。
    ///
    /// 这是「h1/h2 已建立连接要不要收尾」的唯一判据，方向性必须两边都对：
    /// 漏推 ⇒ 改 basic_auth 口令对已有连接不生效（安全相关）；多推 ⇒ 改一条 DNS/日志配置
    /// 就把所有在线连接赶下线（可用性）。所以两个方向都要盯住。
    #[test]
    fn only_listener_changes_bump_the_generation() {
        let path = PathBuf::from("/nonexistent/crucible-test.toml");
        let lc = LiveConfig::new(one("www"), path);
        assert_eq!(lc.listeners_generation(), 0, "初始为 0");

        // 非 listener 字段变化：**不得**推进（否则改日志级别就会踢掉所有连接）。
        lc.replace(cfg(
            "[access_log]\nlevel = \"debug\"",
            "[[listeners]]\naddress = \"127.0.0.1\"\nport = 9095\nroot = \"www\"\n",
        ));
        assert_eq!(
            lc.listeners_generation(),
            0,
            "只改了 [access_log]，不能推进 listener 代数"
        );

        // listener 的 root 变了：必须推进（root 是 per-listener 策略）。
        lc.replace(one("www-other"));
        assert_eq!(
            lc.listeners_generation(),
            1,
            "listener.root 变了必须推进（h1/h2 才会收尾换新配置）"
        );

        // 同样的配置再 replace 一次：指纹没变 ⇒ 不再推进（避免每次保存都踢连接）。
        lc.replace(one("www-other"));
        assert_eq!(lc.listeners_generation(), 1, "配置没变不该重复推进");
    }

    /// listener 在配置里的**先后顺序**变了不算变化：指纹收集后先排序再哈希。
    /// 否则运维只是把两个 listener 段落调个位置，全体在线连接就会被踢下线。
    #[test]
    fn listener_order_does_not_count_as_a_change() {
        let path = PathBuf::from("/nonexistent/crucible-test.toml");
        let a = cfg(
            "",
            "[[listeners]]\naddress = \"127.0.0.1\"\nport = 9095\nroot = \"a\"\n\n\
             [[listeners]]\naddress = \"127.0.0.1\"\nport = 9081\nroot = \"b\"\n",
        );
        let b = cfg(
            "",
            "[[listeners]]\naddress = \"127.0.0.1\"\nport = 9081\nroot = \"b\"\n\n\
             [[listeners]]\naddress = \"127.0.0.1\"\nport = 9095\nroot = \"a\"\n",
        );
        let lc = LiveConfig::new(a, path);
        assert_eq!(lc.listeners_generation(), 0);
        lc.replace(b);
        assert_eq!(
            lc.listeners_generation(),
            0,
            "只是调换了 listener 段落顺序，不该推进"
        );
    }
}
