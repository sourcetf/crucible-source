//! C/Go/Rust 无 .so 时的持久 Unix HTTP sidecar（Hyper 代理 + 简易连接池）。
//! 禁止 CGI fallback —— spawn 失败直接返回错误。

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

static SIDECARS: Lazy<Mutex<HashMap<String, Sidecar>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// **跨注册表**共享的「sidecar 创建中」锁：键 = **sock 路径**（见 [`sidecar_spawn_lock`]）。
///
/// 为什么键是 sock 路径而不是 key 字符串：h1（本文件的 `SIDECARS`）与 h2/h3
/// （`sidecar_engine::SIDECARS_SIMPLE`）各有自己的注册表，但服务**同一个** sock 路径
/// （`state/native/{port-app_idx-engine}/app.sock`）。两条协议**同时**首次请求同一个应用时，
/// 各自的注册表都查不到、`sock_alive` 都还是 false ⇒ 两边都走到 `remove_file`+spawn：
/// 后 spawn 的把先 spawn 的监听 socket 抢走（`remove_file` + 重新 bind），先起的进程变成
/// 谁也不管的孤儿，且两条注册表各记一个进程（真机：并发首发 count=2）。
/// 同一把 per-sock 锁 + 拿锁后重查（自己表 → `sock_alive`）把窄窗关掉：同一时刻只有一个
/// spawner 能走到 spawn，另一个拿锁后必然看到已 bind 的 sock ⇒ 复用。
/// key 集合由配置决定（数量有界），无需淘汰。
#[cfg(unix)]
static SIDECAR_SPAWN_LOCKS: Lazy<Mutex<HashMap<PathBuf, std::sync::Arc<tokio::sync::Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 取（或建）某个 sock 路径的创建锁。
///
/// `pub(crate)`：`sidecar_engine::ensure_sidecar_simple`（h2/h3 字节路径）必须用**同一把**
/// 锁 —— 两条注册表的互斥只能靠共享锁实现（各自的表看不见对方）。
#[cfg(unix)]
pub(crate) fn sidecar_spawn_lock(sock: &Path) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    SIDECAR_SPAWN_LOCKS
        .lock()
        .entry(sock.to_path_buf())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

struct Sidecar {
    sock: PathBuf,
    #[allow(dead_code)]
    child: Child,
    /// 启动该 sidecar 时应用的完整身份（`.env` 摘要 + docroot + 引擎 + 二进制 mtime）。
    ///
    /// 长驻 sidecar 的进程 env / cwd / 可执行映像只在 spawn 时定型：`.env` 改动、配置
    /// 重载换了 app（app_idx 相同但 docroot 不同）、或 `deps/bin/index` 被重建后，旧进程
    /// 必须重启，否则「新配置 + 旧环境/旧 docroot/旧代码」会一直服务下去。身份任一项不同
    /// 即杀旧拉新；**跨注册表/跨协议**复用也以此为准（见 `.envfp`）。
    identity: SidecarIdentity,
}

/// `.env` 变量集的内容指纹（与键序无关；进程内比较用）。
///
/// 为什么不用「配置里的 .env 路径 mtime」：deps 的 `.env` 解析结果才是真正装进环境的
/// 东西（含引号剥离/空值语义），指纹直接对**最终键值**做，和 `apply_clean_env` 的实际
/// 输入严格等价。
pub(crate) fn env_fingerprint(vars: &[(String, String)]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut sorted: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    sorted.sort_unstable();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for (k, v) in sorted {
        k.hash(&mut h);
        // 分隔符参与哈希：防止 ("A","BC") 与 ("AB","C") 拼出同一指纹。
        0xffu8.hash(&mut h);
        v.hash(&mut h);
    }
    h.finish()
}

/// 目录/路径的内容指纹（跨进程稳定；进程内比较用）。
///
/// 为什么用「路径字符串的哈希」而不是「目录 mtime/inode」：跨注册表复用的判据要求
/// **同一条 sock 路径**上的 sidecar 在 docroot 变更后必须被识别为陈旧。docroot 变化
/// 属于配置变更（不落盘任何目录 mtime），直接对最终规范化路径做哈希最忠实、无副作用。
pub(crate) fn path_fingerprint(p: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    p.to_string_lossy().hash(&mut h);
    h.finish()
}

/// 引擎名进入指纹文件时的安全化（文件按空白分词，引擎名不得含空白）。
/// 引擎名只用于「同一 sock 期望同一引擎」的核验，未知字符统一替换为 `_`。
fn sanitize_engine(engine: &str) -> String {
    let mut s: String = engine
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        s.push('-');
    }
    s
}

/// `deps/bin/index`（或显式 `deps_dir`）的 mtime（纳秒；文件缺失 = 0）。
///
/// 二进制被重建（mtime 变）后，运行中的长驻 sidecar 仍是**旧可执行映像**，必须重启
/// 才能换到新代码 —— 否则「已构建新 sidecar，但线上还在跑旧的」会一直不自愈。
fn mtime_nanos(p: &Path) -> u64 {
    fs::metadata(p)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// sidecar 二进制（自动探测 `deps/bin/index`）的 mtime。
pub(crate) fn sidecar_binary_mtime(app: &AppRouteConfig, lc: &ListenerConfig) -> u64 {
    sidecar_binary(app, lc).map(|p| mtime_nanos(&p)).unwrap_or(0)
}

/// sidecar 二进制（自动探测 `deps/bin/index`）的字节长度（文件缺失 = 0）。
///
/// 与 mtime 合成二元组使用：只记 mtime 会漏掉「mtime 未变、内容已换」的重建
/// （构建系统原地覆盖同名文件、运维把二进制回滚成旧的、或文件系统只在写入时才更
/// mtime 而尺寸变化发生在精度之外）。尺寸与 mtime 一起进身份，重启判据更严。
pub(crate) fn sidecar_binary_size(app: &AppRouteConfig, lc: &ListenerConfig) -> u64 {
    sidecar_binary(app, lc)
        .and_then(|p| fs::metadata(&p).ok())
        .map(|m| m.len())
        .unwrap_or(0)
}

/// 一条受管 sidecar 的**完整身份**：跨注册表/跨协议复用前必须五项全等。
///
/// 五项缺一不可（R-06）：
///   * `env_fp`：spawn 时注入进程 env 的 `.env`（含启动期基底之外本 app 的键）摘要；
///   * `docroot_fp`：进程 `cwd` / `DOCUMENT_ROOT`（配置改 docroot 后旧进程必须重启）；
///   * `bin_mtime`：`deps/bin/index` 的 mtime（二进制重建后旧映像必须重启）；
///   * `bin_size`：`deps/bin/index` 的字节长度（与 mtime 合成二元组，防「mtime 未变、内容已换」）；
///   * `engine`：引擎名（防御性；sock 路径本身已含引擎，仍显式核验）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SidecarIdentity {
    pub env_fp: u64,
    pub docroot_fp: u64,
    pub bin_mtime: u64,
    pub bin_size: u64,
    pub engine: String,
}

impl SidecarIdentity {
    /// 由「本次请求的应用配置 + 已规范化 docroot + `.env`」计算期望身份。
    pub(crate) fn compute(
        app: &AppRouteConfig,
        lc: &ListenerConfig,
        docroot: &Path,
        env_vars: &[(String, String)],
    ) -> Self {
        Self {
            env_fp: env_fingerprint(env_vars),
            docroot_fp: path_fingerprint(docroot),
            bin_mtime: sidecar_binary_mtime(app, lc),
            bin_size: sidecar_binary_size(app, lc),
            engine: sanitize_engine(&app.engine),
        }
    }
}

// ---------------------------------------------------- sidecar 身份指纹文件 ---
//
// 为什么需要（P2/R-06）：h1 与 h2/h3 各有一张 sidecar 注册表，却服务**同一个** UDS 路径。
// 「sock 活着就复用」让后到的协议无法核验先到协议那次 spawn 用的环境 —— 长驻进程的
// 进程 env / cwd / 可执行映像都只在 spawn 时定型。现在 spawner 在 sock 旁写
// `app.sock.envfp`（内容 = `.env` 摘要 + docroot + 引擎 + 二进制 mtime + 二进制 size + pid），
// **跨注册表/跨协议复用前一律核验全部五项**；任一项不一致就杀掉所有者并重建
//（见 [`evict_sidecar_for_env_change`]）。全等 → 不重启（来回切协议不会抖动）。

/// 与 UDS 相邻的指纹文件路径（`.../app.sock` → `.../app.sock.envfp`）。
pub(crate) fn sidecar_env_fp_path(sock: &Path) -> PathBuf {
    let mut os = sock.as_os_str().to_os_string();
    os.push(".envfp");
    PathBuf::from(os)
}

/// 指纹文件内容（v3）：`v3 <env_fp> <docroot_fp> <bin_mtime> <bin_size> <engine> [spawner pid]`
/// （前四个为 16 位十六进制）。v2（`v2 <env_fp> <docroot_fp> <bin_mtime> <engine> [pid]`，
/// 无二进制 size）与 v1（`v1 <env_fp> [pid]`，只有 `.env` 摘要）仍可解析出 pid 供回收，
/// 但它们的身份缺少新字段（size=0 / docroot=0 / 引擎为空）⇒ 永不与新期望相等
/// （当作不一致，重启一次）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SidecarEnvFp {
    pub identity: SidecarIdentity,
    pub pid: Option<i32>,
}

pub(crate) fn read_sidecar_env_fp(sock: &Path) -> Option<SidecarEnvFp> {
    let text = fs::read_to_string(sidecar_env_fp_path(sock)).ok()?;
    let t: Vec<&str> = text.split_whitespace().collect();
    match t.first().copied()? {
        "v3" => {
            let env_fp = u64::from_str_radix(t.get(1)?, 16).ok()?;
            let docroot_fp = u64::from_str_radix(t.get(2)?, 16).ok()?;
            let bin_mtime = u64::from_str_radix(t.get(3)?, 16).ok()?;
            let bin_size = u64::from_str_radix(t.get(4)?, 16).ok()?;
            let engine = (*t.get(5)?).to_string();
            let pid = t.get(6).and_then(|s| s.parse::<i32>().ok());
            Some(SidecarEnvFp {
                identity: SidecarIdentity {
                    env_fp,
                    docroot_fp,
                    bin_mtime,
                    bin_size,
                    engine,
                },
                pid,
            })
        }
        "v2" => {
            let env_fp = u64::from_str_radix(t.get(1)?, 16).ok()?;
            let docroot_fp = u64::from_str_radix(t.get(2)?, 16).ok()?;
            let bin_mtime = u64::from_str_radix(t.get(3)?, 16).ok()?;
            let engine = (*t.get(4)?).to_string();
            let pid = t.get(5).and_then(|s| s.parse::<i32>().ok());
            Some(SidecarEnvFp {
                identity: SidecarIdentity {
                    env_fp,
                    docroot_fp,
                    bin_mtime,
                    // v2 没有二进制 size：填 0 ⇒ 与真实期望（非零 size）永不相等，重启一次。
                    bin_size: 0,
                    engine,
                },
                pid,
            })
        }
        "v1" => {
            let env_fp = u64::from_str_radix(t.get(1)?, 16).ok()?;
            let pid = t.get(2).and_then(|s| s.parse::<i32>().ok());
            Some(SidecarEnvFp {
                identity: SidecarIdentity {
                    env_fp,
                    docroot_fp: 0,
                    bin_mtime: 0,
                    bin_size: 0,
                    engine: String::new(),
                },
                pid,
            })
        }
        _ => None,
    }
}

/// 复用前核验：指纹文件存在且与本次请求的**完整身份**一致（四项全等）。
pub(crate) fn sidecar_fp_matches(sock: &Path, expected: &SidecarIdentity) -> bool {
    read_sidecar_env_fp(sock)
        .map(|i| i.identity == *expected)
        .unwrap_or(false)
}

/// 「这个 sock 上的 sidecar 属于本进程」的缓存：sock → `.envfp` 里的 pid。
///
/// `is_direct_child` 要跑一次 `ps`；h1 与 h2/h3 各有注册表，**跨协议复用**时对方协议
/// 的 `SIDECARS` 里没有条目，每次请求都会走到核验点。没有缓存就会变成「每请求一个
/// `ps` 进程」（真机可测的性能回归）。pid 变了（sidecar 被杀后重建）或条目失效时
/// 重新核验；sock 数量由配置决定，有界。
static OWNED_SOCKS: Lazy<Mutex<HashMap<PathBuf, i32>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// `.envfp` 里记录的 spawner pid 是否仍是**本进程的直系子进程**。
///
/// 受管 sidecar 只可能由本进程 spawn；不是直系子进程 = 上一代 webserver 留下的孤儿
///（SIGKILL 后 reparent / 关机漏杀）。这种进程不能复用：它的进程 env / docroot /
/// 生命周期都属于上一代，而且新实例的 `kill_all` 也管不到它（会永久泄漏）。
/// 无 pid 记录（旧版指纹文件）时保持旧行为（只看指纹）。
fn sidecar_owned_by_this_process(sock: &Path) -> bool {
    let Some(pid) = read_sidecar_env_fp(sock).and_then(|i| i.pid) else {
        return true;
    };
    {
        let cache = OWNED_SOCKS.lock();
        if cache.get(sock) == Some(&pid) {
            return true;
        }
    }
    if crate::server::apps::child_registry::is_direct_child(pid) {
        let mut cache = OWNED_SOCKS.lock();
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(sock.to_path_buf(), pid);
        true
    } else {
        false
    }
}

/// sidecar 被替换/回收后清掉归属缓存（下一次按新 `.envfp` 重新核验）。
fn forget_owned_sock(sock: &Path) {
    OWNED_SOCKS.lock().remove(sock);
}

/// 受管 sidecar 可复用 = 身份四项全等 **且** 进程属于本进程这一代。
pub(crate) fn sidecar_reusable(sock: &Path, identity: &SidecarIdentity) -> bool {
    sidecar_fp_matches(sock, identity) && sidecar_owned_by_this_process(sock)
}

/// spawn 成功、sock 就绪后写指纹文件（原子写：临时文件 + rename）。
///
/// 写失败只记日志、不影响服务：最坏情况是下一次复用把它当作「无法核验」→ 重启一次。
pub(crate) fn write_sidecar_env_fp(sock: &Path, identity: &SidecarIdentity, pid: u32) {
    let p = sidecar_env_fp_path(sock);
    let tmp = p.with_extension("envfp.tmp");
    let body = format!(
        "v3 {:016x} {:016x} {:016x} {:016x} {} {}\n",
        identity.env_fp,
        identity.docroot_fp,
        identity.bin_mtime,
        identity.bin_size,
        identity.engine,
        pid
    );
    let res = fs::write(&tmp, body.as_bytes()).and_then(|_| fs::rename(&tmp, &p));
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        log::warn!(
            "native_http: 写 sidecar 身份指纹失败 {}: {e}（下次复用会重启一次）",
            p.display()
        );
    }
}

/// `pid` 是否仍是**本进程的直接子进程**（sidecar 由本 webserver 的某个注册表 spawn，
/// 跨注册表也一样）。防 pid 复用误杀：只杀 ppid == 自己 的进程。
#[cfg(unix)]
fn pid_is_own_child(pid: i32) -> bool {
    if pid <= 1 || pid == std::process::id() as i32 {
        return false;
    }
    let out = std::process::Command::new("ps")
        .arg("-o")
        .arg("ppid=")
        .arg("-p")
        .arg(pid.to_string())
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse::<i32>()
            .ok()
            == Some(std::process::id() as i32),
        Err(_) => false,
    }
}

/// 杀一个已核验身份/命令行的 sidecar pid（SIGTERM → 短等 → SIGKILL）。
///
/// 正常路径优先走两个注册表的 `kill_managed_*_by_sock`（那边有 `Child` 句柄、能 wait
/// 回收，避免僵尸）。只有「指纹文件里的 pid 不在任何注册表」时才走这里。
///
/// 两类 pid：
///   * 本进程直系子进程（注册表丢了，例如 spawn 后崩溃前的竞态）——按 ppid 核验；
///   * **上一代遗留**的受管 sidecar（reparent 后 ppid=1/子收割者）——`is_direct_child`
///     为假，但 `.envfp` 就写在我们的 state 目录里；交给 `kill_stale_managed_sidecar`
///     用「命令行锚定本仓库 + 引擎形态」复核后清理。旧实现对这类进程只打一句
///     「不是本进程的子进程，不动它」就 `remove_file(sock)` 重建 ⇒ 旧进程继续活着、
///     持有旧监听 inode，成为**永远不会被回收**的孤儿（deploy3 §4.3 的形态）。
#[cfg(unix)]
fn kill_sidecar_pid(sock: &Path, pid: i32) {
    if crate::server::apps::child_registry::kill_stale_managed_sidecar(pid, sock) {
        return;
    }
    if !pid_is_own_child(pid) {
        log::warn!("native_http: sidecar pid={pid} 不是本进程的子进程（或已退出），不动它");
        return;
    }
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..40 {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
}

/// 同一个 sock 上的 sidecar 存在、但**身份四项**（`.env`/docroot/二进制 mtime/引擎）与本次
/// 请求不完全一致 → 杀掉重建。
///
/// 调用前提：已持有该 sock 的 [`sidecar_spawn_lock`]（跨注册表串行化）。
/// 顺序：先让两个注册表各自 kill 自己表里的进程（能 wait 回收）→ 都不认领时按指纹
/// 文件里的 pid 杀（已核验 ppid）→ 删除监听 socket，让调用方重新 spawn。
pub(crate) fn evict_sidecar_for_env_change(sock: &Path, new_identity: &SidecarIdentity) {
    let info = read_sidecar_env_fp(sock);
    let old_identity = info.as_ref().map(|i| i.identity.clone());
    let old_pid = info.as_ref().and_then(|i| i.pid);
    let mut reaped = false;
    if let Some(mut child) = take_managed_sidecar_by_sock(sock) {
        crate::server::apps::child_registry::kill_child(&mut child);
        reaped = true;
    }
    if !reaped {
        if let Some(mut child) =
            crate::server::apps::sidecar_engine::take_managed_sidecar_simple_by_sock(sock)
        {
            crate::server::apps::child_registry::kill_child(&mut child);
            reaped = true;
        }
    }
    if !reaped {
        if let Some(pid) = old_pid {
            kill_sidecar_pid(sock, pid);
        }
    }
    forget_owned_sock(sock);
    let _ = fs::remove_file(sock);
    log::warn!(
        "native_http: sidecar {} 不可复用（运行中身份 {:?} / 本次 {:?}，或进程不属于本进程）→ 杀掉旧进程并重建",
        sock.display(),
        old_identity.map(|i| i),
        new_identity
    );
}

/// Try FFI-less native sidecar for c/go/rust when `.so` is missing.
///
/// `env_vars` = 本请求 app 的 `.env`（deps 解析结果）。长驻 sidecar 在 spawn 时把它装进
/// 进程 env（**启动期基底 + 本 app 的 .env**，见 `apply_clean_env`），JSP/Jetty 这类
/// 读 `System.getenv` 的应用由此看到自己的 `.env`（此前一律拿空集：应用环境里没有
/// 自己的键）。`.env` 变化（内容指纹不同）或 docroot 变化 → 杀旧拉新。
pub async fn try_handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    env_vars: &[(String, String)],
) -> Result<Response<BoxBody>> {
    #[cfg(not(unix))]
    {
        let _ = (req, lc, app, peer, app_idx, env_vars);
        bail!("native_http sidecar requires Unix (OpenBSD/Linux)");
    }

    #[cfg(unix)]
    {
        let key = format!("{}-{}-{}", lc.port, app_idx, app.engine);
        let sock = ensure_sidecar(&key, lc, app, env_vars).await?;
        // 两条分支必须同语义：显式 socket 与自动探测的 `deps/bin/index` 都剥掉应用
        // 路由前缀（sidecar 挂在 `/jsp`、`/go` 这类前缀下，内部只认应用相对路径）。
        // 样例应用（c/go/rust）不回读请求路径做路由，剥前缀同样安全。
        let target = uds_target_uri(app, req.uri());
        proxy_unix(req, &sock, peer, Some(target), &[]).await
    }
}

#[cfg(unix)]
async fn ensure_sidecar(
    key: &str,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    env_vars: &[(String, String)],
) -> Result<PathBuf> {
    let docroot_current = abs_canon(&app.docroot.clone().unwrap_or_else(|| lc.root.clone()));
    // 完整身份（`.env` + docroot + 二进制 mtime + 引擎）：跨注册表/跨协议复用前核验，
    // 也用于本注册表内的快路径（`.env` 改 / 配置换 docroot / 二进制重建都要重启）。
    let identity = SidecarIdentity::compute(app, lc, &docroot_current, env_vars);
    // state/sock 的计算必须**早于**创建锁：锁是按 **sock 路径**取的（跨注册表共享，
    // 见 `sidecar_spawn_lock`）。mkdir 在锁外做无害（幂等）。
    let state = abs_path(&PathBuf::from(format!("state/native/{key}")));
    fs::create_dir_all(&state).context("mkdir native state")?;
    let sock = abs_canon(&state.join("app.sock"));
    {
        let map = SIDECARS.lock();
        if let Some(s) = map.get(key) {
            if sock_alive(&s.sock) && s.identity == identity {
                return Ok(s.sock.clone());
            }
        }
    }
    // 快路径未命中：串行化创建（拿锁后必须重查 SIDECARS —— 等锁期间可能已经有人建好了）。
    // 这是并发首请求只 spawn 一个进程的关键；锁按 **sock 路径** 取，所以**另一条协议**
    // （h2/h3 的 `SIDECARS_SIMPLE`）也在同一把锁上互斥 —— 只有这样才能关掉「两条注册表
    // 同时首发各 spawn 一个」的窄窗（各自只看得到自己的表，共享锁是唯一交汇点）。
    let lock = sidecar_spawn_lock(&sock);
    let _guard = lock.lock().await;
    {
        let map = SIDECARS.lock();
        if let Some(s) = map.get(key) {
            if sock_alive(&s.sock) && s.identity == identity {
                return Ok(s.sock.clone());
            }
        }
    }
    // Remove dead entry（顺带收掉它的子进程：只从表里删掉等于把它变成没人管的孤儿，
    // sock 死了不代表进程已经退出）。**身份变化**也走这里：旧进程带着旧 `.env`/旧 docroot/
    // 旧映像，必须回收重建（否则跨应用错配或旧代码会一直服务下去）。
    if let Some(mut dead) = SIDECARS.lock().remove(key) {
        log::info!(
            "native_http: sidecar {key} 需要重启（.env/docroot/二进制 mtime/引擎 或 sock 不可用），回收旧进程"
        );
        crate::server::apps::child_registry::kill_child(&mut dead.child);
    }

    let docroot = docroot_current;
    // **别的协议/别的注册表**（h2/h3 的 `sidecar_engine::SIDECARS_SIMPLE`）已经在同一个
    // sock 路径上服务：先核验它 spawn 时写下的**身份指纹**（sock 旁的 `app.sock.envfp`）。
    //   * 全等 → 直接复用；
    //   * 不一致/文件缺失 → `.env`/docroot/二进制 mtime/引擎 已变或 spawn 者版本过旧，
    //     旧进程是陈旧的：杀掉并重建（`evict_sidecar_for_env_change` 会同时清理两个注册表）。
    // 绝不直接 `remove_file` + spawn（那会偷走对方的监听 socket、留下孤儿进程）。
    if sock_alive(&sock) {
        // 「身份全等」还不够：进程必须属于**本进程这一代**（`.envfp` 里的 pid 是直系
        // 子进程）。上一代遗留的 sidecar 复用后会永久脱离 kill_all 的管理（孤儿），
        // 必须杀掉重建。
        if sidecar_reusable(&sock, &identity) {
            log::debug!("native_http: sidecar {key} 已由其它注册表拉起（sock 存活、身份指纹全等且进程属于本进程），复用");
            return Ok(sock);
        }
        evict_sidecar_for_env_change(&sock, &identity);
    }

    let deps_bin = app
        .deps_dir
        .clone()
        .unwrap_or_else(|| docroot.join("deps"))
        .join("bin")
        .join("index");
    if !deps_bin.is_file() {
        bail!(
            "native sidecar binary missing: {} (no CGI fallback)",
            deps_bin.display()
        );
    }

    let _ = fs::remove_file(&sock);
    let log_path = state.join("sidecar.log");
    let log_file = fs::File::create(&log_path).context("sidecar.log")?;

    let mut cmd = Command::new(&deps_bin);
    // **干净环境**：sidecar 是**长驻**进程，spawn 只发生在「缓存里没有 / 上一个死了」时，
    // 而这个时刻完全可能落在**另一个应用**的请求期 `.env` 窗口内（进程 env 里装着别人的
    // 密钥）。默认继承 environ 会把这些密钥永久烤进 sidecar 的环境（真机实测：wsgi 应用
    // 的 .env 窗口里拉起 JSP sidecar，wrapper 里 `env` 能看到 WINDOWMARK/SECRET_A）。
    // 用「启动期基底 + **本 app 的 .env**」构造 envp：运维环境照旧、别人的请求期临时值
    // 一律不继承，而本 app 自己的键（JSP 的 `System.getenv`、ruby sidecar 的 `ENV`）
    // 可见 —— 这正是 §7.9 要求的「.env 注入引擎执行环境」。
    crate::server::apps::env_lock::apply_clean_env(&mut cmd, env_vars);
    {
        let engine = app.engine.to_string();
        crate::server::apps::sandbox::apply_for_app(
            &mut cmd,
            &engine,
            &app.sandbox_effective(&lc.global_sandbox),
            Some(&docroot),
            Some(&state),
            None,
            Some(&deps_bin),
        )?;
    }
    cmd.current_dir(&docroot)
        .env("WEBSERVER_LISTEN_UNIX", sock.display().to_string())
        // 路由前缀：sidecar 自行决定是否剥离（JSP/Jetty 据此把 /jsp/x.jsp 映射到 docroot/x.jsp）。
        .env("WEBSERVER_APP_PREFIXES", app.paths.join(","))
        .env("WEBSERVER_WORKERS", app.workers.max(1).to_string())
        .env("DOCUMENT_ROOT", docroot.display().to_string())
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log_file));
    let mut child = crate::server::apps::child_registry::spawn_tracked(
        &mut cmd,
        &format!("native sidecar {key}"),
    )
    .with_context(|| format!("spawn sidecar {}", deps_bin.display()))?;

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if sock_alive(&sock) {
            // 先落身份指纹再进表/返回：并发的另一协议拿锁后会读它核验（见
            // `sidecar_fp_matches`）。写失败只影响下次复用（会重启一次）。
            write_sidecar_env_fp(&sock, &identity, child.id());
            SIDECARS.lock().insert(
                key.to_string(),
                Sidecar {
                    sock: sock.clone(),
                    child,
                    identity: identity.clone(),
                },
            );
            return Ok(sock);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    // 超时失败路径必须**收拾掉刚拉起的子进程**：只 `bail!` 的话 child 被 drop 但不
    // 终止（child_registry 的注释也点明了 Drop 不会杀进程），于是每次「sock 未就绪」
    // 都会留下一个活着却永远不被复用的 sidecar —— 反复请求就能把进程数堆起来。
    // kill_child = SIGTERM → 短暂等待 → SIGKILL → wait 回收 → 注销注册表。
    crate::server::apps::child_registry::kill_child(&mut child);
    bail!(
        "native sidecar sock not ready: {} (see {}; spawned child killed)",
        sock.display(),
        log_path.display()
    );
}

#[cfg(unix)]
fn sock_alive(sock: &Path) -> bool {
    use std::os::unix::net::UnixStream;
    UnixStream::connect(sock).is_ok()
}

/// 代理超时后杀掉**受管**（`SIDECARS` 表里登记的）sidecar 进程，返回是否真的杀了。
///
/// 为什么必须杀（实测）：挂死的 sidecar（死锁 / SIGSTOP）仍在 listen，`sock_alive()`
/// 的 connect 被内核 backlog 接住并成功 ⇒ 缓存判定「活着」，之后的每个请求都要再等满
/// `SIDECAR_TIMEOUT` 才 502，**不会自愈**。杀掉后下一个请求会重新 spawn。
///
/// 只按 **sock 路径** 在受管表里找：显式 `apps[].socket`（运维的 Jetty）不在表里，
/// 不会被误杀（那是别人管理的进程，宿主没有终止权）。SIGTERM → 短等 → SIGKILL → 回收
/// 由 `child_registry::kill_child` 完成。
#[cfg(unix)]
pub(crate) fn kill_managed_sidecar_by_sock(sock: &Path) -> bool {
    let Some(mut dead) = take_managed_sidecar_by_sock(sock) else {
        return false;
    };
    log::warn!(
        "native_http: sidecar {} 代理超时（客户端已 502）→ 终止受管进程，后续请求将重启",
        sock.display()
    );
    crate::server::apps::child_registry::kill_child(&mut dead);
    true
}

/// 从本注册表「摘除」某个 sock 的受管 sidecar（不杀、不记日志），返回 Child 供调用方
/// 用适合自己的语义回收（超时 / `.env` 指纹变化）。
///
/// 为什么拆出来：指纹变化的重启路径也要杀旧进程，但它**不是**超时 —— 复用
/// `kill_managed_sidecar_by_sock` 会打出「代理超时（客户端已 502）」的误导日志。
#[cfg(unix)]
pub(crate) fn take_managed_sidecar_by_sock(sock: &Path) -> Option<Child> {
    let key = {
        let map = SIDECARS.lock();
        map.iter().find(|(_, s)| s.sock == sock).map(|(k, _)| k.clone())
    }?;
    SIDECARS.lock().remove(&key).map(|s| s.child)
}

#[cfg(unix)]
/// P2-5：每 sidecar 常驻 h1 连接池——避免每请求新建 UDS 连接 + 握手；
/// 坏连接在 send 失败路径回收重连。键 = sock 路径。
static UDS_POOL: Lazy<
    Mutex<HashMap<PathBuf, Vec<hyper::client::conn::http1::SendRequest<Full<Bytes>>>>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));
#[cfg(unix)]
const UDS_POOL_CAP: usize = 16;

/// h1 引擎 sidecar 代理的墙钟上限：整段（发送 + 响应头 + 收集响应体）共用一个 deadline。
///
/// 这是 h1 引擎代理**唯一**没有超时的路径：proxy.rs 有 UPSTREAM_*_TIMEOUT，fastcgi.rs 有
/// FCGI_TIMEOUT，sidecar_engine 的 h2/h3 字节路径有 SIDECAR_TIMEOUT，CGI/deps 各有
/// init_timeout —— 只有这里裸奔。一个「接受连接但永不回包」的 sidecar 会让请求任务、UDS
/// 池槽位与 fd 永久挂着；重复请求可无界堆积任务（fd/task 泄漏级联）。与
/// `sidecar_engine::SIDECAR_TIMEOUT` 同值同语义。
#[cfg(unix)]
const SIDECAR_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(unix)]
async fn checkout_unix(sock: &Path) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    if let Some(sender) = UDS_POOL.lock().get_mut(sock).and_then(Vec::pop) {
        if sender.is_ready() {
            return Ok(sender);
        }
        // 池里取出的连接已坏：丢弃走新建。
    }
    let stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect {}", sock.display()))?;
    let (sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .context("h1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("native_http conn: {e}");
        }
    });
    Ok(sender)
}

#[cfg(unix)]
fn checkin_unix(sock: &Path, sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>) {
    if sender.is_ready() {
        let mut map = UDS_POOL.lock();
        let v = map.entry(sock.to_path_buf()).or_default();
        if v.len() < UDS_POOL_CAP {
            v.push(sender);
        }
    }
}

#[cfg(unix)]
/// 显式 `apps[].socket`（UDS sidecar）的目标路径：**剥掉应用路由前缀**。
///
/// 为什么必须剥：sidecar 是「挂在某个路径前缀下的应用」（JSP 挂在 `/jsp`、ActionBridge
/// 挂在 `/do`），Jetty 侧的 WebAppContext 是 `/`，它期望的是**应用内相对路径**。
/// 原样转发 `/jsp/index.jsp` 会让 Jetty 去 `<docroot>/jsp/index.jsp` 找文件 —— 不存在，
/// 于是恒 404（实测：`curl /jsp/` 拿到的是 Jetty 自己的 404 页，`/do/` 同样）。
/// 目录请求回落到 `index`（`/jsp/` → `/index.jsp`），与 FFI/cgi_script 同一套判据。
///
/// 只对**显式配置的 socket** 生效；自动探测的 `deps/bin/index` sidecar（c/go/rust 的
/// 无 .so 回退）保持原路径语义不变（那些样例应用自己打印 `r.URL.Path`）。
fn uds_target_uri(app: &AppRouteConfig, uri: &http::Uri) -> http::Uri {
    let rel = crate::server::apps::app_ffi::rel_script_path(app, uri.path());
    let s = match uri.query() {
        Some(q) => format!("{rel}?{q}"),
        None => rel,
    };
    s.parse::<http::Uri>().unwrap_or_else(|_| uri.clone())
}

async fn proxy_unix(
    req: Request<Incoming>,
    sock: &Path,
    peer: SocketAddr,
    target: Option<http::Uri>,
    extra_headers: &[(String, String)],
) -> Result<Response<BoxBody>> {
    

    let (parts, body) = req.into_parts();
    let is_head = parts.method == http::Method::HEAD;
    // 任务 6（OOM 防护）+ slowloris：sidecar 请求体上限 32MiB，帧间空闲 60s ⇒
    // 413/408/400（与 h1 的 proxy/static 收口同口径；旧实现只有 Limited，慢 body
    // 让请求任务与 32MiB 缓冲无限期挂着）。
    let bytes = match crate::server::apps::collect_app_body(body, crate::server::h1::APP_BODY_CAP)
        .await
    {
        Ok(b) => b,
        Err(e) => return Ok(e.into_response()),
    };
    let peer_ip = peer.ip().to_string();

    let target = target.unwrap_or_else(|| parts.uri.clone());
    let build = || -> Result<http::Request<Full<Bytes>>> {
        let mut builder = Request::builder()
            .method(parts.method.clone())
            .uri(target.clone());
        for (k, v) in parts.headers.iter() {
            let lower = k.as_str().to_ascii_lowercase();
            // **丢弃客户端自带的转发头**，否则客户端可以把任意 IP 放在最左边，
            // 后端拿它做日志/ACL 就是伪造点（proxy.rs 的 WS 路径早就是「跳过再写」，
            // 这里此前是「追加语义」，把客户端值原样传下去了）。
            // `x-crucible-env-*` 同理：只能由宿主按本 app 的 deps 生成（见 extra_headers）。
            if matches!(
                lower.as_str(),
                "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" | "x-real-ip"
            ) || lower.starts_with("x-crucible-env-")
            {
                continue;
            }
            builder = builder.header(k, v);
        }
        // 只写真实 peer（sidecar 是本地应用后端，它要的就是「谁连到了 webserver」）。
        builder = builder.header("x-forwarded-for", peer_ip.clone());
        // `.env` 转发头（只由宿主根据本 app 的 deps 生成；见 sidecar_engine 的
        // `env_forward_headers`）。对这些头同样先写覆盖：客户端伪造无效。
        for (k, v) in extra_headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder.body(Full::new(bytes.clone()))
            .context("build upstream req")
    };

    // P2-5：池化 checkout；坏连接重建后重试一次。
    // 池化 checkout；**只**在发送前检查连接可用性，不对已发出的请求重试。
    //
    // hyper 在「请求已写入、上游随即关闭」时同样返回 Err——旧代码对任何 Err 都
    // 无条件重建连接再发一次，非幂等请求（POST 等）会在上游被执行两次。
    // 真需要上游重试应由调用方按方法幂等性显式决定，传输层不该擅自复制请求。
    let mut sender = checkout_unix(sock).await?;
    if !sender.is_ready() {
        sender = checkout_unix(sock).await?;
    }
    // 整段一个 deadline（见 SIDECAR_TIMEOUT 说明）。超时后这条连接已不可复用，直接丢弃、
    // 不 checkin —— 否则一个卡死的 sidecar 连接会被放回池里毒化后续请求。
    //
    // 超时还必须**杀掉受管的 sidecar 进程**：挂死的进程（死锁/被 SIGSTOP）仍然占着监听
    // socket，`sock_alive()` 的 connect 会落进 backlog 而成功 ⇒ 该 sidecar 在缓存里永远
    // 「活着」，之后每个请求都要再等满 30s 才 502，**永不恢复**（真机实测：SIGSTOP 后两次
    // 连续请求都是 30s+502，进程一直挂着）。杀掉之后下一个请求走 ensure_sidecar 重新拉起。
    // 只动 SIDECARS 里登记的（宿主自己 spawn 的）进程；显式 `apps[].socket`
    //（运维自己起的 Jetty）不在表里，绝不会被误杀。
    let (rparts, rbytes) = tokio::time::timeout(SIDECAR_TIMEOUT, async {
        let resp = sender.send_request(build()?).await.context("sidecar request")?;
        let (rparts, rbody) = resp.into_parts();
        // 任务 6（OOM 防护）：sidecar 响应体上限 64MiB。
        let rbytes = http_body_util::Limited::new(rbody, crate::server::h1::UPSTREAM_BODY_CAP)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("collect upstream body: {e}"))?
            .to_bytes();
        Ok::<_, anyhow::Error>((rparts, rbytes))
    })
    .await
    .map_err(|_| {
        // 跨协议兜底：sidecar 也可能是 h2/h3 字节路径（sidecar_engine 注册表）拉起的，
        // 它挂在同一个 sock 路径上。只杀自己表里的话，这条协议在「对方起的进程挂死」时
        // 永远不自愈（反向同理，见 sidecar_engine::proxy_uds_simple）。任一侧杀成功后，
        // 下一个请求（任一协议）都会重新拉起。
        if !kill_managed_sidecar_by_sock(sock) {
            crate::server::apps::sidecar_engine::kill_managed_sidecar_simple_by_sock(sock);
        }
        anyhow::anyhow!("sidecar timeout after {SIDECAR_TIMEOUT:?}")
    })??;
    checkin_unix(sock, sender);
    // 上游响应头必须净化后再透传：sidecar 是「挂在某个路径前缀下的应用」，它回的
    // `Content-Length`/`Transfer-Encoding` 与我们重建的 body 不符时会造成响应走私
    // （与 proxy.rs / sidecar_engine.rs 同一套净化；本路径此前漏了）。
    let headers = super::fastcgi::sanitize_response_headers(
        rparts.headers,
        rbytes.len(),
        is_head,
    );
    let mut out = Response::builder().status(rparts.status);
    for (k, v) in headers.iter() {
        out = out.header(k, v);
    }
    Ok(out.body(full(rbytes)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(full("native_http response build error"))
            .unwrap()
    }))
}

fn abs_path(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}
fn abs_canon(p: &Path) -> PathBuf {
    let a = abs_path(p);
    fs::canonicalize(&a).unwrap_or(a)
}

/// Whether a default/configured `.so` exists for in-process FFI.
///
/// **必须与 `app_ffi::resolve_lib` 走同一条解析链**（显式 `apps[].lib` → `APPENGINE_*_LIB`
/// → `<仓库根>/target/app-engines/libapp_<e>.so`）：本函数决定「分发走 FFI 还是 sidecar/502」，
/// `resolve_lib` 决定「实际 dlopen 哪只 .so」—— 两者看不同路径时（旧实现这里只看 **cwd 相对**
/// 的 `target/app-engines/…`，且**不认** `APPENGINE_*_LIB`），运维用 `APPENGINE_*_LIB` 指路
/// 或从非仓库根目录启动时，判活与加载会得出**相反**结论（真机：cwd=scratch 的实例里
/// `/rust/`、`/c/` 三协议一致 502；配了 `APPENGINE_RUST_LIB` 时判活仍说「没有」）。
pub fn lib_available(app: &AppRouteConfig, engine: &str) -> bool {
    // `is_file()` 是一次 stat（本机 ~1.7µs）；分发判活每个引擎请求至少调一次。
    // 用 1s TTL 缓存「该路径当前是否存在」：新建 .so 最迟 1s 内被发现；缓存窗口内
    // 删除 .so 会走 FFI 装载失败（干净 502），不会误执行。
    // `CRUCIBLE_APP_LIB_TTL_MS=0` 关闭缓存（回到逐请求 stat）。
    static TTL: Lazy<std::time::Duration> = Lazy::new(|| {
        match crate::server::apps::env_lock::read_static_env("CRUCIBLE_APP_LIB_TTL_MS") {
            Some(v) => v
                .trim()
                .parse::<u64>()
                .map(std::time::Duration::from_millis)
                .unwrap_or(std::time::Duration::from_millis(1000)),
            None => std::time::Duration::from_millis(1000),
        }
    });
    static CACHE: Lazy<Mutex<HashMap<PathBuf, (bool, std::time::Instant)>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));
    let Ok(path) = crate::server::apps::app_ffi::resolve_lib(app, engine) else {
        return false;
    };
    if TTL.is_zero() {
        return path.is_file();
    }
    {
        let map = CACHE.lock();
        if let Some((ok, at)) = map.get(&path) {
            if at.elapsed() < *TTL {
                return *ok;
            }
        }
    }
    let ok = path.is_file();
    let mut map = CACHE.lock();
    if map.len() >= 1024 {
        map.clear();
    }
    map.insert(path, (ok, std::time::Instant::now()));
    ok
}

/// Sidecar binary from init.sh (`deps/bin/index`) for c/go/rust when FFI .so is unavailable.
pub fn sidecar_available(app: &AppRouteConfig, lc: &ListenerConfig) -> bool {
    sidecar_binary(app, lc).is_some()
}

pub fn sidecar_binary(app: &AppRouteConfig, lc: &ListenerConfig) -> Option<PathBuf> {
    let docroot = app
        .docroot
        .clone()
        .unwrap_or_else(|| lc.root.clone());
    let deps_bin = app
        .deps_dir
        .clone()
        .unwrap_or_else(|| docroot.join("deps"))
        .join("bin")
        .join("index");
    let p = abs_path(&deps_bin);
    p.is_file().then_some(p)
}

/// Configured Unix domain socket for HTTP sidecar (e.g. JSP Jetty/Python shim).
pub fn uds_socket_available(app: &AppRouteConfig) -> bool {
    uds_socket_path(app).is_some_and(|p| {
        #[cfg(unix)]
        {
            sock_alive(&p)
        }
        #[cfg(not(unix))]
        {
            let _ = p;
            false
        }
    })
}

pub fn uds_socket_path(app: &AppRouteConfig) -> Option<PathBuf> {
    let raw = app.socket.as_ref()?;
    let p = raw.strip_prefix("unix:").unwrap_or(raw.as_str());
    let path = abs_path(Path::new(p));
    path.exists().then_some(path)
}/// Proxy one request to a pre-started UDS HTTP sidecar (`apps[].socket`).
///
/// 显式 socket 是**运维自己起的**进程（如 Jetty）：宿主无法再注入它的进程 env，因此
/// 本 app 的 `.env` 以 `x-crucible-env-<key>` 请求头（percent-encoded 值）转发，
/// 由 sidecar 侧自行读取（约定见 `sidecar_engine::env_forward_headers`）。
pub async fn try_handle_uds(
    req: Request<Incoming>,
    app: &AppRouteConfig,
    peer: SocketAddr,
    extra_headers: &[(String, String)],
) -> Result<Response<BoxBody>> {
    #[cfg(not(unix))]
    {
        let _ = (req, app, peer, extra_headers);
        bail!("UDS sidecar requires Unix (OpenBSD/Linux)");
    }
    #[cfg(unix)]
    {
        let sock = uds_socket_path(app).context("apps[].socket missing")?;
        let target = uds_target_uri(app, req.uri());
        proxy_unix(req, &sock, peer, Some(target), extra_headers).await
    }
}

#[cfg(test)]
mod sidecar_env_fp_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// 指纹文件：落盘/读取/比较/覆盖（跨注册表复用判据的存储面）。
    /// v3 身份含 `.env`/docroot/二进制 mtime/二进制 size/引擎五项；任一项不同即不一致。
    #[test]
    fn env_fp_file_roundtrip_and_mismatch() {
        let dir = std::env::temp_dir().join(format!(
            "crucible-fp-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("app.sock");
        assert!(read_sidecar_env_fp(&sock).is_none(), "文件不存在 = 无法核验");
        let id = SidecarIdentity {
            env_fp: 7,
            docroot_fp: 0xabc,
            bin_mtime: 0x123,
            bin_size: 0x456,
            engine: "go".to_string(),
        };
        assert!(!sidecar_fp_matches(&sock, &id));
        write_sidecar_env_fp(&sock, &id, 4242);
        assert_eq!(
            read_sidecar_env_fp(&sock),
            Some(SidecarEnvFp {
                identity: id.clone(),
                pid: Some(4242)
            })
        );
        assert!(sidecar_fp_matches(&sock, &id));
        // 五项各自不同都必须判不一致（R-06：跨注册表复用不只看 .env）。
        for mutated in [
            SidecarIdentity { env_fp: 8, ..id.clone() },
            SidecarIdentity { docroot_fp: 0xdead, ..id.clone() },
            SidecarIdentity { bin_mtime: 0x999, ..id.clone() },
            SidecarIdentity { bin_size: 0xaaa, ..id.clone() },
            SidecarIdentity { engine: "rust".to_string(), ..id.clone() },
        ] {
            assert!(
                !sidecar_fp_matches(&sock, &mutated),
                "身份任一项不同必须判不一致: {mutated:?}"
            );
        }
        // 覆盖写（原子的临时文件 + rename）
        let id2 = SidecarIdentity {
            env_fp: 0xdead_beef,
            docroot_fp: 1,
            bin_mtime: 2,
            bin_size: 3,
            engine: "c".to_string(),
        };
        write_sidecar_env_fp(&sock, &id2, 4243);
        let read = read_sidecar_env_fp(&sock).unwrap();
        assert_eq!(read.identity, id2);
        assert_eq!(read.pid, Some(4243));
        let _ = fs::remove_dir_all(&dir);
    }

    /// v2 旧指纹文件（有 docroot/引擎/mtime，但**无**二进制 size）仍能解析出 pid 供回收，
    /// 但绝不被判为与新身份一致（size=0 ≠ 真实非零 size）⇒ 跨注册表复用重启一次。
    #[test]
    fn legacy_v2_fingerprint_parses_but_never_matches() {
        let dir = std::env::temp_dir().join(format!(
            "crucible-fp-v2-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("app.sock");
        fs::write(
            sidecar_env_fp_path(&sock),
            "v2 0000000000000007 0000000000000123 0000000000000099 go 555\n",
        )
        .unwrap();
        let got = read_sidecar_env_fp(&sock).expect("v2 必须可解析");
        assert_eq!(got.pid, Some(555));
        assert_eq!(got.identity.env_fp, 7);
        assert_eq!(got.identity.docroot_fp, 0x123);
        assert_eq!(got.identity.bin_mtime, 0x99);
        assert_eq!(got.identity.bin_size, 0);
        assert!(
            !sidecar_fp_matches(
                &sock,
                &SidecarIdentity {
                    env_fp: 7,
                    docroot_fp: 0x123,
                    bin_mtime: 0x99,
                    bin_size: 0x99,
                    engine: "go".to_string(),
                },
            ),
            "v2 缺二进制 size（=0），永不与真实完整身份相等"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// v1 旧指纹文件（只有 `.env` 摘要）仍能解析出 pid 供回收，但绝不被判为与新身份一致。
    #[test]
    fn legacy_v1_fingerprint_parses_but_never_matches() {
        let dir = std::env::temp_dir().join(format!(
            "crucible-fp-v1-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("app.sock");
        fs::write(sidecar_env_fp_path(&sock), "v1 0000000000000007 555\n").unwrap();
        let got = read_sidecar_env_fp(&sock).expect("v1 必须可解析");
        assert_eq!(got.pid, Some(555));
        assert_eq!(got.identity.env_fp, 7);
        // v1 里没有 docroot/引擎/二进制 mtime/size：真实期望身份永不与之相等 ⇒
        // 跨注册表复用会判「无法核验」并重启一次。
        assert!(
            !sidecar_fp_matches(
                &sock,
                &SidecarIdentity {
                    env_fp: 7,
                    docroot_fp: 0x1234,
                    bin_mtime: 0x99,
                    bin_size: 0x42,
                    engine: "go".to_string(),
                },
            ),
            "v1 缺 docroot/引擎/二进制 mtime/size，永不与真实完整身份相等"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// 引擎名安全化：含空白/未知字符的引擎名不破坏指纹文件的分词。
    #[test]
    fn engine_sanitization_has_no_whitespace() {
        assert_eq!(sanitize_engine("go"), "go");
        assert_eq!(sanitize_engine("my engine"), "my_engine");
        assert_eq!(sanitize_engine(""), "-");
    }

    /// 路径指纹：同路径同值、不同路径不同值。
    #[test]
    fn path_fingerprint_distinguishes_paths() {
        let a = path_fingerprint(Path::new("/srv/x"));
        let b = path_fingerprint(Path::new("/srv/y"));
        assert_eq!(a, path_fingerprint(Path::new("/srv/x")));
        assert_ne!(a, b);
    }

    /// 指纹与键序无关；内容不同则不同（不能有拼接碰撞）。
    #[test]
    fn env_fingerprint_is_order_independent_and_collision_resistant() {
        let a = vec![
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string()),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(env_fingerprint(&a), env_fingerprint(&b));
        let c = vec![
            ("A".to_string(), "1B=2".to_string()),
        ];
        assert_ne!(env_fingerprint(&a), env_fingerprint(&c));
    }
}
