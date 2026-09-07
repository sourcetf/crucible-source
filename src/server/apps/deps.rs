//! App deps: init.sh + .env → deps/; hot path uses mtime-only try_cached.

use crate::config::AppRouteConfig;
use crate::server::live_config::LiveConfig;
use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// .env 解析结果（§16.3/§7.9）：KEY=VAL 注入引擎执行环境。
/// 热路径零开销：vars 随 mtime 缓存驻留内存，命中时不重新读 .env 文件。
#[derive(Clone, Debug, Default)]
pub struct DepsEnv {
    pub vars: Arc<Vec<(String, String)>>,
}

/// deps/ 目录的 manifest（§7.9：记录 init/env sha + app_libc；只在校验时读，不进热路径）
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Manifest {
    init_mtime_secs: u64,
    env_mtime_secs: u64,
    init_sha: String,
    env_sha: String,
    app_libc: String,
}

#[derive(Clone, Debug)]
struct CacheKey {
    init_mtime: Option<SystemTime>,
    env_mtime: Option<SystemTime>,
    env: Arc<Vec<(String, String)>>,
}

static DEPS_CACHE: Lazy<Mutex<HashMap<PathBuf, CacheKey>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// per-docroot 串行化 ensure_app_deps，避免并发请求互相 wipe deps 目录。
/// P1-2 改造后 ensure 全程 async，必须用 tokio::sync::Mutex——
/// 跨 .await 持有 parking_lot 锁会让 future 变 !Send，无法进 tokio::spawn。
type EnsureLocks = Lazy<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>>;
static DEPS_ENSURE_LOCKS: EnsureLocks = Lazy::new(|| Mutex::new(HashMap::new()));

/// Hot path: compare mtimes only — never SHA256 / spawn_blocking per request.
/// 命中时同时返回该 docroot 的 .env 变量（P1-1）。
pub async fn try_cached(live: &Arc<LiveConfig>, app: &AppRouteConfig) -> Result<DepsEnv> {
    let docroot = resolve_docroot(live, app)?;
    let init = docroot.join("init.sh");
    let envp = docroot.join(".env");
    let deps_dir = app
        .deps_dir
        .clone()
        .unwrap_or_else(|| docroot.join("deps"));

    let init_m = mtime_of(&init);
    let env_m = mtime_of(&envp);

    {
        let cache = DEPS_CACHE.lock();
        if let Some(prev) = cache.get(&docroot) {
            if prev.init_mtime == init_m && prev.env_mtime == env_m && deps_dir.is_dir() {
                return Ok(DepsEnv { vars: Arc::clone(&prev.env) });
            }
        }
    }

    // 串行化同一 docroot 的 ensure：并发请求不再互相 wipe deps 目录。
    let ensure_lock = DEPS_ENSURE_LOCKS
        .lock()
        .entry(docroot.clone())
        .or_default()
        .clone();
    let _guard = ensure_lock.lock().await;
    // double-check：等锁期间可能已被其他请求构建好
    {
        let cache = DEPS_CACHE.lock();
        if let Some(prev) = cache.get(&docroot) {
            if prev.init_mtime == init_m && prev.env_mtime == env_m && deps_dir.is_dir() {
                return Ok(DepsEnv { vars: Arc::clone(&prev.env) });
            }
        }
    }

    // 冷路径才解析 .env（读一次文件），解析结果随缓存驻留。
    let env_vars = Arc::new(parse_env_file(&envp));
    ensure_app_deps(
        &docroot,
        &deps_dir,
        &init,
        app.init_timeout_secs.unwrap_or(120),
    )
    .await?;
    write_manifest(
        &deps_dir,
        &Manifest {
            init_mtime_secs: system_time_secs(init_m),
            env_mtime_secs: system_time_secs(env_m),
            init_sha: content_fingerprint(&init),
            env_sha: content_fingerprint(&envp),
            app_libc: app.libc.clone().unwrap_or_else(|| "auto".into()),
        },
    );
    DEPS_CACHE.lock().insert(
        docroot,
        CacheKey {
            init_mtime: init_m,
            env_mtime: env_m,
            env: Arc::clone(&env_vars),
        },
    );
    Ok(DepsEnv { vars: env_vars })
}

/// 极简 .env 解析：忽略空行与 # 注释；KEY=VAL；值剥成对引号；KEY 仅允许 [A-Za-z0-9_]。
fn parse_env_file(p: &Path) -> Vec<(String, String)> {
    let Ok(text) = fs::read_to_string(p) else {
        return Vec::new();
    };
    let mut vars = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if k.is_empty() || !k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            continue;
        }
        let mut v = v.trim();
        if v.len() >= 2
            && ((v.starts_with('"') && v.ends_with('"'))
                || (v.starts_with('\'') && v.ends_with('\'')))
        {
            v = &v[1..v.len() - 1];
        }
        vars.push((k.to_string(), v.to_string()));
    }
    vars
}

fn system_time_secs(t: Option<SystemTime>) -> u64 {
    t.and_then(|x| x.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_manifest(deps_dir: &Path, m: &Manifest) {
    let _ = fs::create_dir_all(deps_dir);
    let path = deps_dir.join(".crucible_manifest");
    let body = format!(
        "init_mtime={}\nenv_mtime={}\ninit_sha={}\nenv_sha={}\napp_libc={}\n",
        m.init_mtime_secs, m.env_mtime_secs, m.init_sha, m.env_sha, m.app_libc
    );
    let _ = fs::write(path, body);
}

fn resolve_docroot(live: &Arc<LiveConfig>, app: &AppRouteConfig) -> Result<PathBuf> {
    if let Some(d) = &app.docroot {
        return Ok(d.clone());
    }
    // Fall back to first listener root (core skeleton).
    let cfg = live.snapshot();
    cfg.listeners
        .first()
        .map(|l| l.root.clone())
        .context("no docroot")
}


fn content_fingerprint(p: &Path) -> String {
    match fs::read(p) {
        Ok(bytes) => {
            // 非热路径：仅在 ensure 重建时计算；用 DefaultHasher 避免额外依赖。
            let mut h = DefaultHasher::new();
            bytes.hash(&mut h);
            format!("{:016x}", h.finish())
        }
        Err(_) => "missing".into(),
    }
}

fn mtime_of(p: &Path) -> Option<SystemTime> {
    fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// P1-2：init.sh 执行改为 tokio::process + timeout(init_timeout_secs)——
/// 超时杀进程并报错，不再永久持有 per-docroot 锁、不再卡死 tokio worker。
/// P2-10：目录 wipe/重建放 spawn_blocking（大目录删除会阻塞 reactor）。
async fn ensure_app_deps(
    docroot: &Path,
    deps_dir: &Path,
    init: &Path,
    timeout_secs: u64,
) -> Result<()> {
    if !init.is_file() {
        // 无 init.sh：仅保证 deps 目录存在（应用可能自带 deps 产物）。
        fs::create_dir_all(deps_dir).with_context(|| format!("create {}", deps_dir.display()))?;
        return Ok(());
    }
    let prep_deps = deps_dir.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        if prep_deps.exists() {
            let _ = fs::remove_dir_all(&prep_deps);
        }
        fs::create_dir_all(&prep_deps)?;
        Ok(())
    })
    .await
    .with_context(|| format!("deps prep join {}", deps_dir.display()))??;

    let mut child = tokio::process::Command::new("sh")
        .arg(init)
        .current_dir(docroot)
        .env("DEPS_DIR", deps_dir)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn {}", init.display()))?;
    let timeout = Duration::from_secs(timeout_secs.max(1));
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => {
            let status = status.with_context(|| format!("wait {}", init.display()))?;
            if !status.success() {
                anyhow::bail!("init.sh failed: {status}");
            }
            Ok(())
        }
        Err(_) => {
            // 超时：杀掉 init.sh 并回收，随后锁随 guard 释放。
            let _ = child.kill().await;
            anyhow::bail!(
                "init.sh timed out after {}s: {}",
                timeout_secs,
                init.display()
            )
        }
    }
}
