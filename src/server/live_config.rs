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
    std::fs::write(&tmp_validate, &text)?;
    let parsed = crate::config::Config::load(&tmp_validate).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_validate);
        anyhow::anyhow!("config validate: {e}")
    })?;
    let _ = std::fs::remove_file(&tmp_validate);
    parsed.validate()?;
    let tmp = unique_tmp_path(path, "tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
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
        Self {
            inner: RwLock::new(Arc::new(cfg)),
            path,
            last_mtime: RwLock::new(mtime),
        }
    }

    pub fn snapshot(&self) -> Arc<Config> {
        Arc::clone(&self.inner.read())
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn reload(&self) -> anyhow::Result<()> {
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
        *self.inner.write() = Arc::new(cfg);
        // acceptor 缓存的键只有配置**字符串**（证书/密钥路径），而缓存本身从不失效：
        // 同一路径上换了证书（certbot 续期、面板覆盖 ssl.cert）时指纹不变，
        // 进程会一直用旧证书/旧 ECH 配置服务到重启为止。热路径不能加 stat
        // （accept_and_serve 每连接都会查一次缓存），所以在配置重载这个低频点上显式清空。
        crate::server::tls::boring_path::clear_acceptor_cache();
        crate::server::apps::reconcile_apps_runtime(self);
        log::info!("config reloaded from {}", self.path.display());
        Ok(())
    }

    pub fn replace(&self, cfg: Config) {
        *self.inner.write() = Arc::new(cfg);
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

/// 周期性监视 config.toml mtime（OpenBSD 无可靠 inotify 时用轮询即可）。
pub fn spawn_mtime_watcher(live: Arc<LiveConfig>, interval: Duration) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match live.reload_if_changed() {
                Ok(true) => {}
                Ok(false) => {}
                Err(e) => log::warn!("config watch reload failed: {e:#}"),
            }
        }
    });
}
