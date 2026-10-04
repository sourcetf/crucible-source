//! App deps: init.sh + .env → deps/; hot path uses mtime-only try_cached.

use crate::config::{AppRouteConfig, ListenerConfig};
use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
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
    /// §22.4.3：CachedDeps 必须区分 `app_libc`（它决定应用侧 gcc/go/cargo 的构建产物）。
    /// 只比 mtime 时，热重载把 libc 从 auto 改成 glibc/musl 会继续复用旧 deps/。
    libc: String,
    /// `deps_dir` 配置变化同样必须让缓存失效（否则仍读旧目录的产物）。
    deps_dir: PathBuf,
}

static DEPS_CACHE: Lazy<Mutex<HashMap<PathBuf, CacheKey>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// init.sh 失败退避（per-docroot）：坏掉的 init.sh（语法错/卡死/装不上依赖）若每个
/// 请求都重跑一次带 `init_timeout_secs`（默认 120s）超时的 ensure，而并发请求都堵在
/// 下面那把 per-docroot 锁上 → 路由吞吐塌到 1/120s。失败后 30s 内直接返回 Err
///（调用方语义不变：记日志 + 用空环境继续服务），不再反复等满超时。
const ENSURE_FAIL_BACKOFF: Duration = Duration::from_secs(30);
static ENSURE_FAILED_AT: Lazy<Mutex<HashMap<PathBuf, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// per-docroot 串行化 ensure_app_deps，避免并发请求互相 wipe deps 目录。
/// P1-2 改造后 ensure 全程 async，必须用 tokio::sync::Mutex——
/// 跨 .await 持有 parking_lot 锁会让 future 变 !Send，无法进 tokio::spawn。
type EnsureLocks = Lazy<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>>;
static DEPS_ENSURE_LOCKS: EnsureLocks = Lazy::new(|| Mutex::new(HashMap::new()));

/// Hot path: compare mtimes only — never SHA256 / spawn_blocking per request.
/// 命中时同时返回该 docroot 的 .env 变量（P1-1）。
pub async fn try_cached(lc: &ListenerConfig, app: &AppRouteConfig) -> Result<DepsEnv> {
    // 绝对化（防御性，见 `absolutize`）：ensure 里 `current_dir(docroot)` + `sh <init>`
    // 只有在 init/deps_dir 也是绝对路径时才不会在子进程 CWD 下再拼一次相对路径。
    let docroot = resolve_docroot(lc, app);
    let init = docroot.join("init.sh");
    let envp = docroot.join(".env");
    let deps_dir = absolutize(
        &app.deps_dir
            .clone()
            .unwrap_or_else(|| docroot.join("deps")),
    );
    let libc = app.libc.clone().unwrap_or_else(|| "auto".into());

    let init_m = mtime_of(&init);
    let env_m = mtime_of(&envp);

    let hit = |prev: &CacheKey| -> bool {
        prev.init_mtime == init_m
            && prev.env_mtime == env_m
            && prev.libc == libc
            && prev.deps_dir == deps_dir
            && deps_dir.is_dir()
    };

    {
        let cache = DEPS_CACHE.lock();
        if let Some(prev) = cache.get(&docroot) {
            if hit(prev) {
                return Ok(DepsEnv {
                    vars: Arc::clone(&prev.env),
                });
            }
        }
    }

    // 失败退避：30s 内不再重跑 init.sh（避免每个请求都等满超时；请求侧会记日志并
    // 用空环境继续，见 apps::try_handle / try_handle_simple）。
    if let Some(at) = ENSURE_FAILED_AT.lock().get(&docroot).copied() {
        if at.elapsed() < ENSURE_FAIL_BACKOFF {
            anyhow::bail!(
                "deps ensure failed recently ({}s backoff): {}",
                ENSURE_FAIL_BACKOFF.as_secs(),
                docroot.display()
            );
        }
    }

    // 串行化同一 docroot 的 ensure：并发请求不再互相 wipe deps 目录。
    let ensure_lock = DEPS_ENSURE_LOCKS
        .lock()
        .entry(docroot.clone())
        .or_default()
        .clone();
    let _guard = ensure_lock.lock().await;
    // double-check：等锁期间可能已被其他请求构建好；也可能刚有人失败正在退避。
    {
        let cache = DEPS_CACHE.lock();
        if let Some(prev) = cache.get(&docroot) {
            if hit(prev) {
                return Ok(DepsEnv {
                    vars: Arc::clone(&prev.env),
                });
            }
        }
    }
    if let Some(at) = ENSURE_FAILED_AT.lock().get(&docroot).copied() {
        if at.elapsed() < ENSURE_FAIL_BACKOFF {
            anyhow::bail!(
                "deps ensure failed recently ({}s backoff, queued): {}",
                ENSURE_FAIL_BACKOFF.as_secs(),
                docroot.display()
            );
        }
    }

    // 冷路径才解析 .env（读一次文件），解析结果随缓存驻留。
    let env_vars = Arc::new(parse_env_file(&envp));
    let ensure_result = ensure_app_deps(
        &docroot,
        &deps_dir,
        &init,
        app.init_timeout_secs.unwrap_or(120),
    )
    .await;
    if let Err(e) = ensure_result {
        ENSURE_FAILED_AT.lock().insert(docroot.clone(), Instant::now());
        return Err(e);
    }
    ENSURE_FAILED_AT.lock().remove(&docroot);
    write_manifest(
        &deps_dir,
        &Manifest {
            init_mtime_secs: system_time_secs(init_m),
            env_mtime_secs: system_time_secs(env_m),
            init_sha: content_fingerprint(&init),
            env_sha: content_fingerprint(&envp),
            app_libc: libc.clone(),
        },
    );
    DEPS_CACHE.lock().insert(
        docroot,
        CacheKey {
            init_mtime: init_m,
            env_mtime: env_m,
            env: Arc::clone(&env_vars),
            libc,
            deps_dir,
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
        // 键必须是合法环境变量名 `[A-Za-z_][A-Za-z0-9_]*`。
        // 数字开头的名字（`1BAD=x`）在 shell 里根本不是赋值语句，setenv 收下只会让下游
        // 脚本行为诡异；dotenv 生态同样拒绝。首字符单独判，其余字符允许数字。
        let mut bytes = k.bytes();
        let head_ok = matches!(bytes.next(), Some(c) if c.is_ascii_alphabetic() || c == b'_');
        let tail_ok = bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_');
        if !head_ok || !tail_ok {
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

/// 应用 docroot：配置优先，其次**当前 listener** 的 root。
///
/// 回落取的是 `lc.root` 而**不是** `live.listeners.first().root`。多 listener 部署下
/// 后者会把「另一个站点」的 docroot 当成这个应用的根，于是它会读到**别人的 `.env`**
/// （通常就是数据库口令、API key）并把它注入自己的执行环境 —— 跨站点/跨租户的凭据泄露，
/// 而且只在多 listener 时出现，单站点测试永远发现不了。
/// 与 `php::resolve_docroot(lc, app)` 同一套判据。
///
/// 返回值**保证绝对路径**（见 [`absolutize`]）：下游 `sh <init.sh>` 以 docroot 为 CWD，
/// 相对路径会被子进程再拼一次（cwd/docroot/init.sh）而必然 ENOENT；缓存键/清单也必须
/// 与 ensure 使用同一绝对路径。
fn resolve_docroot(lc: &ListenerConfig, app: &AppRouteConfig) -> PathBuf {
    absolutize(&app.docroot.clone().unwrap_or_else(|| lc.root.clone()))
}

/// 相对路径 → 绝对路径（以进程当前目录为基准，**词法**拼接，不 canonicalize）。
///
/// 协调员已修 `src/config.rs`（base 绝对化）；这里是**防御性**兜底：任何直接构造的
/// `ListenerConfig`（测试、内置默认、未来调用方）走这条路径时也不会踩
/// 「子进程 CWD 下再拼一次相对路径」的坑。
///
/// 不 canonicalize 是有意的：`deps_dir` 常常还不存在，canonicalize 会失败回退，
/// 于是「docroot 解析了符号链接、deps_dir 没解析」两者前缀不一致，
/// `path_inside(docroot, deps_dir)` 会对合法配置误报「outside docroot」。
/// 词法绝对化让 docroot 与 deps_dir 用同一基准，比较始终一致。
fn absolutize(p: &Path) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(p)
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
    // 兜底（Config::validate 已拦一次）：下面会递归删除 deps_dir。
    // 任何不在 docroot 之内的路径都拒绝，避免删掉任意目录树。
    if !path_inside(docroot, deps_dir) {
        anyhow::bail!(
            "refusing deps_dir {} outside docroot {}",
            deps_dir.display(),
            docroot.display()
        );
    }
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

    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg(init)
        .current_dir(docroot)
        .env("DEPS_DIR", deps_dir)
        .kill_on_drop(true);
    // `init.sh` 干的通常就是 pip/npm/make —— 它们会再 fork 出孙进程。自成**进程组**后
    // 超时才能整组杀掉：只杀 `sh` 本身时，孙进程会留下来继续跑（还占着 docroot，而失败后
    // 下一次 ensure 又要 `remove_dir_all` 这个目录），CPU/磁盘/内存白占且没有任何人回收。
    // 与 cgi_script.rs 是同一套做法（那里的注释记了实测：只杀壳会留下握着 stdout 的孙进程）。
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", init.display()))?;
    // 组长 pid == 子进程 pid（上面 process_group(0)）
    #[cfg(unix)]
    let pgid = child.id().map(|p| p as i32);
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
            // 超时：**整组**杀掉（见 spawn 处的说明），再回收壳进程。
            // 安全：pgid 就是紧接着 spawn 出来的那个子进程 pid，且此刻还没 wait 过它。
            #[cfg(unix)]
            if let Some(pgid) = pgid {
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
            }
            let _ = child.kill().await;
            anyhow::bail!(
                "init.sh timed out after {}s: {}",
                timeout_secs,
                init.display()
            )
        }
    }
}

/// `child` 是否位于 `root` 之内（按组件消除 `..` 后比较，不要求路径已存在）。
fn path_inside(root: &Path, child: &Path) -> bool {
    fn norm(p: &Path) -> std::path::PathBuf {
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
    }
    let (nr, nc) = (norm(root), norm(child));
    nc != nr && nc.starts_with(&nr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppRouteConfig, AutoindexConfig, FileOpenTable, ListenerConfig};

    fn listener(root: &str) -> ListenerConfig {
        ListenerConfig {
            address: "0.0.0.0".into(),
            address_v6: None,
            port: 19123,
            root: PathBuf::from(root),
            autoindex: AutoindexConfig::default(),
            http_versions: vec!["h1".into()],
            server_name: None,
            ssl: None,
            file_open: FileOpenTable::default(),
            apps: vec![],
            basic_auth: None,
            proxy_rules: vec![],
            page_rules: vec![],
            status_path: None,
            port_reuse: false,
            rate_limit: None,
            l4_forward: None,
            quic_ecn: false,
            qmux: false,
            connect_udp: false,
        }
    }

    fn app(docroot: Option<&str>) -> AppRouteConfig {
        AppRouteConfig {
            paths: vec!["/py".into()],
            enabled: true,
            engine: "wsgi".into(),
            socket: None,
            extensions: vec![],
            index: None,
            php_bin: None,
            workers: 1,
            source_dir: None,
            out_dir: None,
            entry: vec![],
            watch: false,
            docroot: docroot.map(PathBuf::from),
            lib: None,
            deps_dir: None,
            init_timeout_secs: None,
            libc: None,
        }
    }

    /// 相对 docroot 必须绝对化：init 路径随 `current_dir(docroot)` + `sh <init>` 执行，
    /// 相对路径会在子进程 CWD 下再拼一次 ⇒ `sh ./www-apps/x/init.sh` ENOENT（实测日志）。
    #[test]
    fn docroot_is_always_absolute() {
        let lc = listener("www-apps-deps-abs-test");
        let d = resolve_docroot(&lc, &app(None));
        assert!(d.is_absolute(), "relative docroot leaked: {d:?}");
        assert!(d.ends_with("www-apps-deps-abs-test"));

        // 显式 docroot 优先于 lc.root
        let d = resolve_docroot(&lc, &app(Some("www-apps-deps-explicit")));
        assert!(d.is_absolute());
        assert!(d.ends_with("www-apps-deps-explicit"));

        // 绝对路径原样保留（不做多余 IO）
        let abs = std::env::temp_dir();
        let d = resolve_docroot(&lc, &app(Some(abs.to_str().unwrap())));
        assert_eq!(d, abs);
    }

    /// .env 解析：注释/空行/带引号值/非法 KEY 都要按约定处理。
    #[test]
    fn parse_env_file_rules() {
        let dir = std::env::temp_dir().join("crucible_deps_env_test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(".env");
        fs::write(
            &p,
            "# comment\n\nDB_PASS='secret value'\nAPI=\"k=v\"\n1BAD=x\nOK=plain # not a comment\n",
        )
        .unwrap();
        let vars = parse_env_file(&p);
        assert!(vars.contains(&("DB_PASS".to_string(), "secret value".to_string())));
        assert!(vars.contains(&("API".to_string(), "k=v".to_string())));
        assert!(vars.contains(&("OK".to_string(), "plain # not a comment".to_string())));
        assert!(!vars.iter().any(|(k, _)| k == "1BAD"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// init.sh 失败必须退避：第二次请求不再重跑 init.sh（否则每个请求都等满
    /// init_timeout_secs，且并发请求全堵在 per-docroot 锁上）。
    #[tokio::test]
    async fn ensure_failure_records_backoff() {
        let dir = std::env::temp_dir().join("crucible_deps_backoff_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("init.sh"), "#!/bin/sh\nexit 3\n").unwrap();
        let root = dir.to_str().unwrap();
        let lc = listener(root);
        let app = app(Some(root));

        let first = try_cached(&lc, &app).await;
        assert!(first.is_err(), "init.sh exit 3 必须报错");
        let t0 = Instant::now();
        let second = try_cached(&lc, &app).await;
        let err = format!("{:#}", second.expect_err("失败后必须仍在退避窗口内"));
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "第二次调用必须直接走退避（不重跑 init.sh）：{:?}",
            t0.elapsed()
        );
        assert!(err.contains("backoff"), "错误应是退避而非重跑: {err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
