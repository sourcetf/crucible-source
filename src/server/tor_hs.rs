//! Hidden Service（站点 .onion 入站；早期规格 A.3）。
//!
//! 独立 tor 进程：`SocksPort 0`（故意不开出站 SOCKS —— HS 不出站，避免与反代出站策略
//! 搅在一起）；`HiddenServiceDir` 由配置指定；启动后读 hostname 文件得到 `.onion` 名，
//! 写 `state/tor-hs/hostname.log` 供面板显示。
//!
//! 反代**出站**走 `proxy.rs::connect_tor_socks`（FFI → UDS → loopback SOCKS），
//! 不复用本 torrc —— 两者是独立的两条链路。
//!
//! # 本轮修复（此前这份实现**完全没接线**，接线后又暴露出一串问题）
//!
//! * `spawn_from_config` 全树零调用点（`mod.rs` 里只有一句 "tor_hs removed" 的注释，
//!   而文件明明存在）⇒ 配 `[tor_hs] enabled = true` **什么都不会发生**，且无任何告警。
//! * `state_dir()` 返回**相对路径** `state/tor-hs`，是全仓库唯一没绝对化的 state 目录
//!   ⇒ cwd 漂移（rc.d 的工作目录、手工 cd 启动）会把 HS 密钥写错地方，而 tor 的
//!   hostname 就在那里面。现在用 `current_dir()` 绝对化（与 dns/ech_auto 一致）。
//! * `tor` 进程非零退出（未安装 / torrc 非法 / 目录权限）此前被忽略，只是干等 30s 然后报
//!   "hostname not generated in time" —— 掩盖了真正的原因。现在直接报退出码 + tor 自己
//!   的输出（stderr 优先，其次 notice.log）。
//! * `HiddenServiceDir` 权限：tor **硬要求** 0700，0755 会直接
//!   `Failed to parse/validate config: Failed to configure rendezvous options` 退出。
//! * **幂等 ≠ 存活**：原来只要 `hostname` 文件在就「复用已有 HS」直接返回，**从不检查
//!   tor 进程还活着没有、torrc 是否已经和配置不一致**。实测：改 `ports` 后重启服务，
//!   日志照样打 `复用已有 HS`，磁盘上的 torrc 仍是旧端口，tor 进程还是上一次启动的那个
//!   —— 面板显示一切正常，而新的端口映射根本没生效。现在复用必须同时满足
//!   「进程在 + torrc 与配置一致」，否则重启 tor（HS 密钥在磁盘上，重启后 .onion 名不变）。
//! * tor 的日志此前无处可看：`--RunAsDaemon` 之后 stdout 作废，torrc 里又没有 `Log`，
//!   于是 `data/notice.log` 是空的（tor 默认"notice 到 stdout"，而 stdout 被丢弃）。
//!   现在 torrc 里显式 `Log notice file state/tor-hs/notice.log`，出错时直接读它。
//! * 关停时不再留孤儿 tor：tor 是 `--RunAsDaemon` 的独立进程，webserver 退出不会带走它，
//!   于是「服务已停但 .onion 还挂着、连进去是死的」——现在退出路径显式停掉自己那份 tor。

use crate::config::TorHsConfig;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// 串行化 `ensure_hs`：启动路径、配置热重载、巡检三处都会调它。
///
/// 不加锁的话两个并发调用会**同时**判定「tor 不在跑」然后各起一个 tor ——第二个必然
/// 因 DataDirectory 锁（`Could not lock data directory`）退出，日志里冒出莫名其妙的失败。
static HS_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn hs_lock() -> &'static tokio::sync::Mutex<()> {
    HS_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// 「tor 以 root 运行」的建议只提示一次（巡检每 60s 会路过那段代码）。
static ROOT_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// HS 的状态目录（**绝对**路径，见文件头说明）。
pub fn state_dir() -> PathBuf {
    let rel = PathBuf::from("state/tor-hs");
    if rel.is_absolute() {
        return rel;
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(rel),
        Err(_) => rel,
    }
}

/// 把目录设为 0700（tor 对 HiddenServiceDir 的硬要求，见文件头说明）。
fn set_mode_0700(p: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(p, perm).with_context(|| format!("chmod 0700 {}", p.display()))?;
    }
    let _ = p;
    Ok(())
}

/// HS 的 HiddenServiceDir（配置优先，其次 `state/tor-hs/hs`）。
fn hs_data_dir(cfg: &TorHsConfig) -> PathBuf {
    cfg.data_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir().join("hs"))
}

/// 读取已生成的 `.onion` 名（供面板显示）。`None` = 还没生成 / 未启用。
///
/// 优先读 tor 自己维护的 `hostname` 文件（权威），退回我们写的 `hostname.log`
/// （面板历史上只写过、**没有任何读方**，这里补上）。
pub fn current_onion_name(cfg: &TorHsConfig) -> Option<String> {
    if !cfg.enabled {
        return None;
    }
    let hs_dir = hs_data_dir(cfg);
    for p in [hs_dir.join("hostname"), state_dir().join("hostname.log")] {
        if let Ok(s) = std::fs::read_to_string(&p) {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// tor 进程是否在跑（面板/状态端点用）。`Some(pid)` = 我们自己那份 tor 活着。
pub fn running_pid(cfg: &TorHsConfig) -> Option<i32> {
    if !cfg.enabled {
        return None;
    }
    tor_pid(&state_dir())
}

/// torrc 全文。**单独成函数**是为了能比较「配置想要的 torrc」与「磁盘上 tor 正在用的
/// torrc」——两者不一致就必须重启 tor，否则改了配置却毫无效果（见文件头）。
fn torrc_text(cfg: &TorHsConfig, dir: &Path, hs_dir: &Path) -> String {
    let mut s = format!(
        "SocksPort 0\nDataDirectory {}\nHiddenServiceDir {}\n",
        dir.join("data").display(),
        hs_dir.display()
    );
    for (virt, local) in &cfg.ports {
        s.push_str(&format!("HiddenServicePort {virt} 127.0.0.1:{local}\n"));
    }
    // 显式写日志文件：--RunAsDaemon 之后 stdout 被丢弃，不写这行等于没有任何 tor 日志。
    s.push_str(&format!("Log notice file {}\n", dir.join("notice.log").display()));
    if let Some(u) = cfg.user.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        s.push_str(&format!("User {u}\n"));
    }
    s
}

/// 从 pidfile 读出**我们这份** tor 的 pid；不在跑 / 不是我们的 → `None`。
///
/// 不能只看 pidfile：进程可能已经死了（pid 还被复用给别的进程）。所以再用 `ps` 核对
/// 一次命令行——必须是 `.../tor -f <我们的 torrc>`。注意 OpenBSD 的 `ps -o args=`
/// 会按终端宽度截断（实测 80 列），而 torrc 路径就在命令行最前面，所以按「首词是 tor
/// 且包含 torrc 路径」判断，而不是拿整串去相等比较。
fn tor_pid(dir: &Path) -> Option<i32> {
    let pid: i32 = std::fs::read_to_string(dir.join("pid"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if pid <= 0 {
        return None;
    }
    let out = std::process::Command::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("args=")
        .output()
        .ok()?;
    // 进程不存在时 OpenBSD 的 ps 退出码为 1（实测），不要用 stdout 判空。
    if !out.status.success() {
        return None;
    }
    let args = String::from_utf8_lossy(&out.stdout);
    let first = args.split_whitespace().next().unwrap_or("");
    if !(first == "tor" || first.ends_with("/tor")) {
        return None; // pid 被复用给了别的进程 —— 宁可当成没在跑，也不去杀它
    }
    let torrc = dir.join("torrc").to_string_lossy().to_string();
    if !args.contains(&torrc) {
        return None;
    }
    Some(pid)
}

/// 给 tor 发信号（失败只记日志：进程可能刚好自己退了）。
fn signal_tor(pid: i32, sig: &str) -> bool {
    std::process::Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 停掉我们这份 tor（同步版：退出路径用；tor_hs 的异步路径用 `stop_tor_async`）。
///
/// TERM → 最多等 5s → KILL。只认 pidfile + `ps` 核对过的那一个 pid。
fn stop_tor_blocking(dir: &Path) -> Result<()> {
    let Some(pid) = tor_pid(dir) else {
        let _ = std::fs::remove_file(dir.join("pid"));
        return Ok(());
    };
    log::info!("tor_hs: 停止旧 tor (pid {pid})");
    signal_tor(pid, "TERM");
    for _ in 0..50 {
        if tor_pid(dir).is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if tor_pid(dir).is_some() {
        log::warn!("tor_hs: tor {pid} 5s 未退出 → SIGKILL");
        signal_tor(pid, "KILL");
        for _ in 0..20 {
            if tor_pid(dir).is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    let _ = std::fs::remove_file(dir.join("pid"));
    Ok(())
}

/// 异步版停止（不要在 tokio worker 上睡 5s —— 这台机器只有 2 个 worker 线程）。
async fn stop_tor_async(dir: &Path) -> Result<()> {
    let Some(pid) = tor_pid(dir) else {
        let _ = std::fs::remove_file(dir.join("pid"));
        return Ok(());
    };
    log::info!("tor_hs: 停止旧 tor (pid {pid})");
    signal_tor(pid, "TERM");
    for _ in 0..50 {
        if tor_pid(dir).is_none() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if tor_pid(dir).is_some() {
        log::warn!("tor_hs: tor {pid} 5s 未退出 → SIGKILL");
        signal_tor(pid, "KILL");
        for _ in 0..20 {
            if tor_pid(dir).is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    let _ = std::fs::remove_file(dir.join("pid"));
    Ok(())
}

/// 复用判据（纯函数，便于单测）：给定 hostname / 存活 pid / torrc 是否一致，决定复用还是重启。
///
/// 返回 `None` = 可以复用；`Some(原因)` = 必须重启（原因进日志）。
fn restart_reason(hostname: Option<&str>, running: Option<i32>, torrc_same: bool) -> Option<&'static str> {
    match (hostname, running) {
        (None, _) => Some("还没有 hostname（首次生成或文件被删）"),
        (Some(_), None) => Some("tor 进程不在（崩过 / 被 OOM / 被手工杀掉）"),
        (Some(_), Some(_)) if !torrc_same => Some("torrc 与当前配置不一致（改了 ports / user 等）"),
        (Some(_), Some(_)) => None,
    }
}

/// 把 `state/tor-hs`（或配置指定的 data_dir）整棵树 chown 给指定用户。
///
/// 配了 `[tor_hs].user` 时必须在启动 tor 之前做完：tor 解析完配置就降权，之后它是以该用户
/// 的身份去读 HiddenServiceDir 和写日志文件的，root 独占的目录会让它直接启动失败。
fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;
        // 先深后浅：目录在子项改完后改（避免目录先变成别人的、我们反而下不去）。
        let mut dirs: Vec<PathBuf> = Vec::new();
        let mut stack = vec![path.to_path_buf()];
        while let Some(d) = stack.pop() {
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        chown(&p, Some(uid), Some(gid))
                            .with_context(|| format!("chown {}", p.display()))?;
                    }
                }
            }
            dirs.push(d);
        }
        for d in dirs.into_iter().rev() {
            chown(&d, Some(uid), Some(gid)).with_context(|| format!("chown {}", d.display()))?;
        }
    }
    let _ = (path, uid, gid);
    Ok(())
}

/// 查用户的 uid/gid（tor 的 `User` 只认名字，chown 要数字；两者都得有）。
fn resolve_user(user: &str) -> Result<(u32, u32)> {
    let ask = |flag: &str| -> Result<u32> {
        let out = std::process::Command::new("id")
            .arg(flag)
            .arg(user)
            .output()
            .with_context(|| format!("查用户 {user}：id {flag} {user}"))?;
        if !out.status.success() {
            bail!("[tor_hs].user = \"{user}\" 不存在（id {flag} 失败）");
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        s.parse::<u32>()
            .with_context(|| format!("解析 id {flag} {user} 的输出 {s:?}"))
    };
    Ok((ask("-u")?, ask("-g")?))
}

/// 启动 HS tor（若未在跑或配置变了）：写 torrc → `--RunAsDaemon` → 轮询 hostname 文件。
///
/// **幂等**：hostname 已存在 **且** tor 进程在跑 **且** torrc 与配置一致 ⇒ 直接复用。
/// 三者缺一就重启 tor（HS 密钥在磁盘上，.onion 名不变）。
pub async fn ensure_hs(cfg: &TorHsConfig) -> Result<String> {
    if cfg.ports.is_empty() {
        bail!("tor_hs: [tor_hs].ports 为空 —— 至少需要一条 (虚拟端口, 本地端口)");
    }
    for (virt, local) in &cfg.ports {
        if *virt == 0 || *local == 0 {
            bail!("tor_hs: 端口不能为 0（virt={virt} local={local}）");
        }
    }
    let _guard = hs_lock().lock().await;
    let dir = state_dir();
    let hs_dir = hs_data_dir(cfg);
    std::fs::create_dir_all(&hs_dir).with_context(|| format!("create {}", hs_dir.display()))?;
    std::fs::create_dir_all(dir.join("data")).context("create tor-hs data dir")?;
    // **tor 硬要求 HiddenServiceDir 必须是 0700**：目录权限过宽时它直接
    // `Failed to parse/validate config: Failed to configure rendezvous options` 并退出
    // （实测：0755 会失败）。顺带把 state/tor-hs 本身也收紧（里面是 HS 密钥与 hostname）。
    set_mode_0700(&hs_dir)?;
    set_mode_0700(&dir)?;

    let user = cfg.user.as_deref().map(str::trim).filter(|u| !u.is_empty());
    if let Some(u) = user {
        let (uid, gid) = resolve_user(u)?;
        chown_tree(&dir, uid, gid)?;
        if dir != hs_dir {
            let parent = hs_dir.parent().unwrap_or(&dir);
            chown_tree(parent, uid, gid)?;
        }
    } else if unsafe { libc::geteuid() } == 0 && !ROOT_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        // 只提示一次：巡检每 60s 也会走到这里，warn 每 60s 刷一条没人受得了。
        // （tor 自己也会为此告警，但那条落在 notice.log 里，面板上看不到。）
        log::warn!(
            "tor_hs: 未配置 [tor_hs].user，tor 将以 root 运行（tor 自身也会为此告警）；\
             建议设 user = \"_tor\" 做降权"
        );
    }

    let hostname_file = hs_dir.join("hostname");
    let existing = std::fs::read_to_string(&hostname_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let torrc_path = dir.join("torrc");
    let wanted = torrc_text(cfg, &dir, &hs_dir);
    let torrc_same = std::fs::read_to_string(&torrc_path)
        .map(|s| s == wanted)
        .unwrap_or(false);
    let running = tor_pid(&dir);

    match restart_reason(existing.as_deref(), running, torrc_same) {
        None => {
            let name = existing.clone().unwrap_or_default();
            // debug 级：巡检每 60s 调一次，info 会刷屏（"serving" 那条已经打过一次了）
            log::debug!("tor_hs: 复用已有 HS {name}（tor pid {}）", running.unwrap_or(0));
            let _ = std::fs::write(dir.join("hostname.log"), format!("{name}\n"));
            return Ok(name);
        }
        Some(why) => {
            log::info!("tor_hs: 重启 tor —— {why}");
            if running.is_some() {
                stop_tor_async(&dir).await?;
            }
            // 配置里的 user 变化时，torrc 里的 User 行会跟着变（torrc_same 已经判过）；
            // 旧的 data/ 可能属于别的用户，重新 chown 一次保证新旧都能读。
            if let Some(u) = user {
                let (uid, gid) = resolve_user(u)?;
                chown_tree(&dir, uid, gid)?;
            }
        }
    }

    std::fs::write(&torrc_path, &wanted).with_context(|| format!("write {}", torrc_path.display()))?;

    let tor = cfg.tor_bin.clone().unwrap_or_else(|| "tor".into());
    let pidfile = dir.join("pid");
    let _ = std::fs::remove_file(&pidfile); // 残留 pidfile 会让 tor 拒绝/误判
    // 捕获 stdout/stderr：tor 的致命配置错误（权限、语法）走 stderr，
    // 而 `notice.log` 此时可能还没建出来 —— 只读 notice.log 等于什么都没报出来。
    let out = tokio::process::Command::new(&tor)
        .arg("-f")
        .arg(&torrc_path)
        .arg("--RunAsDaemon")
        .arg("1")
        .arg("--PidFile")
        .arg(&pidfile)
        .output()
        .await
        .with_context(|| {
            format!("启动 tor 失败（tor_bin={tor}）：请确认已安装 tor，或用 [tor_hs].tor_bin 指定路径")
        })?;
    let status = out.status;
    // 退出码必须看：tor 未安装 / torrc 非法 / 端口被占时它会立刻退出，
    // 旧实现忽略退出码 ⇒ 干等 30s 后报「hostname not generated in time」，把真因埋掉。
    if !status.success() {
        let said = tor_said(&dir, &out.stderr, &out.stdout);
        // 落盘一份，便于事后排查（面板/日志只看一行）
        let _ = std::fs::write(dir.join("tor-error.log"), said.join("\n") + "\n");
        bail!(
            "tor 以 {:?} 退出（torrc={}）。tor 说：{}",
            status.code(),
            torrc_path.display(),
            if said.is_empty() {
                "（无输出；见 state/tor-hs/tor-error.log）".to_string()
            } else {
                said.join(" | ")
            }
        );
    }

    // 等待 onion 生成（首次建 HS 密钥可能 ~10-30s；重启已有密钥是秒级）
    for _ in 0..60 {
        if hostname_file.is_file() {
            let name = std::fs::read_to_string(&hostname_file)?.trim().to_string();
            if !name.is_empty() {
                std::fs::write(dir.join("hostname.log"), format!("{name}\n"))?;
                log::info!("tor_hs: onion ready {name}");
                return Ok(name);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    bail!(
        "tor_hs: 等待 30s 仍未生成 hostname（{}）—— 检查 {}",
        hostname_file.display(),
        dir.join("notice.log").display()
    )
}

/// 收集 tor 说的话：**先致命（`[err]`）、再警告、最后过程**。
///
/// 为什么要把 notice.log 也算进来（而不是只在 stderr/stdout 为空时兜底）：`--RunAsDaemon`
/// 之后 tor 的致命错误常常**只写进它自己的日志文件**，我们捕获的 stderr/stdout 里只剩启动
/// notice —— 实测「`/dev/null can't be opened. Exiting.`」这条唯一的真因就在 notice.log，
/// 而旧实现因为 stderr 非空就完全没读它，报出来的是一串「Tor can't help you if you use it
/// wrong」之类的噪音。现在：两处都读，按 `[err]` > `[warn]` > 其它排序，各取最近几条。
fn tor_said(dir: &Path, stderr: &[u8], stdout: &[u8]) -> Vec<String> {
    let mut all: Vec<String> = Vec::new();
    for (label, bytes) in [("stderr", stderr), ("stdout", stdout)] {
        for line in String::from_utf8_lossy(bytes).lines() {
            let l = line.trim();
            if !l.is_empty() {
                all.push(format!("[{label}] {l}"));
            }
        }
    }
    for p in [dir.join("notice.log"), dir.join("data").join("notice.log")] {
        let Ok(log) = std::fs::read_to_string(&p) else {
            continue;
        };
        let tag = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "log".into());
        // 日志可能很长：只看尾部若干行
        let lines: Vec<&str> = log.lines().collect();
        let tail_from = lines.len().saturating_sub(40);
        for line in &lines[tail_from..] {
            let l = line.trim();
            if !l.is_empty() {
                all.push(format!("[{tag}] {l}"));
            }
        }
        break;
    }

    // 分组收集，**组内保持时间顺序**，组的顺序就是优先级：致命 → 警告 → 其余。
    // （第一版在最后统一 reverse()，把优先级顺序整个翻掉了 —— 我的单测抓到了这一点：
    //   `[err]` 行虽然出现，却排在了一串 notice 之后。）
    let mut out: Vec<String> = Vec::new();
    for pat in ["[err]", "[warn]"] {
        let group: Vec<String> = all.iter().filter(|l| l.contains(pat)).cloned().collect();
        let keep = group.len().saturating_sub(3); // 只留最近 3 条
        out.extend(group[keep..].iter().cloned());
    }
    let rest: Vec<String> = all
        .iter()
        .filter(|l| !l.contains("[err]") && !l.contains("[warn]"))
        .cloned()
        .collect();
    let keep = rest.len().saturating_sub(4);
    out.extend(rest[keep..].iter().cloned());
    out.truncate(9);
    out
}

/// 面板/启动钩子：读 `[tor_hs]` 配置并确保 HS 运行；错误仅记录不中断服务。
///
/// **调用点**：`server::run` 的启动路径 + 配置热重载路径。`ensure_hs` 幂等（判据见
/// `restart_reason`），所以热重载重复调用是安全的。
pub fn spawn_from_config(hs: crate::config::TorHsConfig) {
    if !hs.enabled {
        // 热重载里把 enabled 改回 false，也必须**真的把 tor 停掉**：否则面板显示"未启用"，
        // 而 .onion 仍然挂着、对一个已经不该有入站入口的服务开放。
        let dir = state_dir();
        if tor_pid(&dir).is_some() {
            log::info!("tor_hs: enabled 变成 false → 停止 tor");
            if let Err(e) = stop_tor_blocking(&dir) {
                log::warn!("tor_hs: 停止 tor 失败：{e:#}");
            }
        }
        return;
    }
    tokio::spawn(async move {
        match ensure_hs(&hs).await {
            Ok(name) => log::info!("tor_hs: serving {name}"),
            Err(e) => log::warn!("tor_hs: {e:#}"),
        }
    });
}

/// 巡检：每 60s 确认 tor 还在，不在就拉起来（崩了 / 被 OOM / 被手工杀掉都能自愈）。
///
/// 以前没有任何东西看管 tor：进程一死，.onion 就静默地不可达，直到有人重启服务。
/// `ensure_hs` 是幂等的（进程在 + torrc 一致 ⇒ 只读几个文件 + 一次 `ps`），所以巡检的
/// 正常开销可以忽略。**每轮都读实时配置**：热重载改了 ports/user 时，巡检必须跟着新配置走，
/// 而不是拿着一份过期快照把 tor 改回旧配置。
pub fn spawn_watchdog(live: std::sync::Arc<crate::server::live_config::LiveConfig>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        // 前 30s 让启动路径先把 HS 建起来（首次生成密钥要 10~30s），别一上来就抢锁
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        loop {
            tick.tick().await;
            let cfg = live.snapshot().tor_hs.clone();
            if !cfg.enabled {
                continue;
            }
            if let Err(e) = ensure_hs(&cfg).await {
                log::warn!("tor_hs: 巡检拉起失败：{e:#}");
            }
        }
    });
}

/// 退出路径：停掉**我们自己启动的**那份 tor。
///
/// tor 是 `--RunAsDaemon` 的独立进程：不主动停，webserver 退出后它还挂着，于是
/// 「服务已停但 .onion 仍然可解析、连进去必然是死连接」——既误导用户，也等于对外宣告
/// 这台机器还在跑。只停 pidfile 指向且 `ps` 核对过的那个 pid（绝不误杀别人的 tor）。
pub fn stop_on_shutdown(cfg: &TorHsConfig) {
    if !cfg.enabled {
        return;
    }
    let dir = state_dir();
    if tor_pid(&dir).is_none() {
        return;
    }
    if let Err(e) = stop_tor_blocking(&dir) {
        log::warn!("tor_hs: 退出时停止 tor 失败：{e:#}");
    }
}

/// 配置期校验（由 `Config::validate` 调用）。
///
/// 此前 `[tor_hs]` **完全不在校验范围内**：ports 为空、虚拟端口重复（tor 会拒载整份 torrc）、
/// `tor_bin` 指到不存在的路径，都要等运行期才以难懂的方式暴露。
pub fn validate(cfg: &TorHsConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    if cfg.ports.is_empty() {
        bail!("[tor_hs] enabled = true 但 ports 为空 —— 至少需要一条 (虚拟端口, 本地端口)");
    }
    let mut seen_virt = std::collections::HashSet::new();
    for (virt, local) in &cfg.ports {
        if *virt == 0 || *local == 0 {
            bail!("[tor_hs] ports 里出现 0 端口：({virt}, {local})");
        }
        if !seen_virt.insert(*virt) {
            bail!("[tor_hs] 虚拟端口 {virt} 重复 —— tor 会拒载该 torrc");
        }
    }
    if let Some(tor) = cfg.tor_bin.as_deref() {
        let p = Path::new(tor);
        // 只给绝对路径做存在性检查；裸名字交给 PATH 查找（运行期的报错已经足够清楚）
        if p.is_absolute() && !p.exists() {
            bail!("[tor_hs] tor_bin={tor} 不存在");
        }
    }
    if let Some(u) = cfg.user.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        resolve_user(u)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, ports: Vec<(u16, u16)>) -> TorHsConfig {
        TorHsConfig {
            enabled,
            ports,
            data_dir: None,
            tor_bin: None,
            user: None,
        }
    }

    #[test]
    fn validate_requires_ports_and_rejects_dupes() {
        assert!(validate(&cfg(false, vec![])).is_ok(), "未启用时不校验");
        assert!(validate(&cfg(true, vec![])).is_err(), "启用但无 ports 应报错");
        assert!(validate(&cfg(true, vec![(80, 8080)])).is_ok());
        assert!(validate(&cfg(true, vec![(0, 8080)])).is_err(), "0 端口应报错");
        assert!(
            validate(&cfg(true, vec![(80, 8080), (80, 8081)])).is_err(),
            "重复虚拟端口应报错"
        );
        assert!(validate(&cfg(true, vec![(80, 8080), (443, 8443)])).is_ok());
    }

    #[test]
    fn validate_checks_absolute_tor_bin() {
        assert!(validate(&TorHsConfig {
            enabled: true,
            ports: vec![(80, 8080)],
            data_dir: None,
            tor_bin: Some("/nonexistent/tor".into()),
            user: None,
        })
        .is_err());
        // 裸名字不在这里判（交给 PATH）
        assert!(validate(&TorHsConfig {
            enabled: true,
            ports: vec![(80, 8080)],
            data_dir: None,
            tor_bin: Some("tor".into()),
            user: None,
        })
        .is_ok());
    }

    /// state 目录必须是**绝对**路径（避免 cwd 漂移把 HS 密钥写错地方）。
    #[test]
    fn state_dir_is_absolute() {
        let d = state_dir();
        assert!(d.is_absolute(), "state_dir 必须是绝对路径，实际 {d:?}");
        let s = d.to_string_lossy().replace('\\', "/");
        assert!(s.ends_with("state/tor-hs"), "{s}");
    }

    /// 未启用时不该报告任何 .onion 名。
    #[test]
    fn disabled_reports_no_onion() {
        assert!(current_onion_name(&cfg(false, vec![(80, 8080)])).is_none());
        assert!(running_pid(&cfg(false, vec![(80, 8080)])).is_none());
    }

    /// `tor_said` 必须把**致命行**捞出来，哪怕它只在 notice.log 里。
    ///
    /// 这条用例的形状来自真机：`user = "_tor"` 那次 tor 退出码 1，而捕获到的 stderr/stdout
    /// 只有启动 notice（没有原因），唯一的真因
    /// `[err] /dev/null can't be opened. Exiting.` 只写在 notice.log —— 旧实现因为
    /// stderr 非空就完全没读它，报出来的是一串噪音。
    #[test]
    fn tor_said_prioritizes_fatal_lines_from_notice_log() {
        let dir = std::env::temp_dir().join(format!("crucible-torhs-said-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("notice.log"),
            "Oct 01 03:04:09.489 [notice] Tor can't help you if you use it wrong!
Oct 01 03:04:09.489 [notice] Read configuration file \"/crucible/state/tor-hs/torrc\".
Oct 01 03:04:09.000 [err] /dev/null can't be opened. Exiting.
",
        )
        .unwrap();
        let stdout = b"Oct 01 03:04:09.489 [notice] Tor 0.4.9.11 running on OpenBSD
";
        let said = tor_said(&dir, b"", stdout);
        let joined = said.join(" | ");
        assert!(
            joined.contains("/dev/null can't be opened"),
            "致命行必须出现在报告里：{joined}"
        );
        // 致命行应排在过程性 notice 之前
        let fatal_pos = said.iter().position(|l| l.contains("[err]"));
        let notice_pos = said.iter().position(|l| l.contains("running on OpenBSD"));
        assert!(
            fatal_pos < notice_pos,
            "致命行要排在 notice 前面：{said:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 复用的三个条件缺一不可（这是本轮修的核心 bug：原来只看 hostname 文件在不在）。
    #[test]
    fn reuse_requires_alive_tor_and_matching_torrc() {
        let on = Some("abc.onion");
        assert!(restart_reason(on, Some(123), true).is_none(), "全都满足才复用");
        assert!(restart_reason(on, None, true).is_some(), "tor 死了必须重启");
        assert!(restart_reason(on, Some(123), false).is_some(), "torrc 变了必须重启");
        assert!(restart_reason(None, Some(123), true).is_some(), "没有 hostname 必须重启");
        assert!(restart_reason(None, None, false).is_some());
        // 空字符串的 hostname 在调用点已被过滤成 None，这里只保证不 panic
        assert!(restart_reason(Some(""), Some(1), true).is_none());
    }

    /// torrc 必须包含端口映射、日志文件、以及（配置了的话）User —— 少一样就是一个真 bug：
    /// 少端口 = 访客连不上；少日志 = 出事时什么都看不到；少 User = 降权没生效。
    #[test]
    fn torrc_contains_ports_log_and_user() {
        let dir = Path::new("/tmp/hsdir");
        let hs = Path::new("/tmp/hsdir/hs");
        let base = cfg(true, vec![(80, 8080), (443, 8443)]);
        let t = torrc_text(&base, dir, hs);
        assert!(t.contains("HiddenServicePort 80 127.0.0.1:8080"), "{t}");
        assert!(t.contains("HiddenServicePort 443 127.0.0.1:8443"), "{t}");
        assert!(t.contains("HiddenServiceDir /tmp/hsdir/hs"), "{t}");
        assert!(t.contains("SocksPort 0"), "HS 不出站：{t}");
        assert!(t.contains("Log notice file"), "必须有文件日志：{t}");
        assert!(!t.contains("User "), "没配 user 就不该有 User 行：{t}");

        let with_user = TorHsConfig {
            user: Some("_tor".into()),
            ..base.clone()
        };
        let t2 = torrc_text(&with_user, dir, hs);
        assert!(t2.contains("\nUser _tor\n"), "{t2}");
        // 空白的 user 等于没配（别写出 `User ` 这种 tor 会拒载的行）
        let blank = TorHsConfig {
            user: Some("   ".into()),
            ..base
        };
        assert!(!torrc_text(&blank, dir, hs).contains("User"));
    }

    /// 两个 torrc 只有在配置真的不同时才不相等 —— 这是「热重载不会平白重启 tor」的依据。
    #[test]
    fn torrc_is_stable_for_same_config() {
        let dir = Path::new("/tmp/hsdir");
        let hs = Path::new("/tmp/hsdir/hs");
        let a = cfg(true, vec![(80, 8080)]);
        assert_eq!(torrc_text(&a, dir, hs), torrc_text(&a.clone(), dir, hs));
        let b = cfg(true, vec![(81, 8080)]);
        assert_ne!(torrc_text(&a, dir, hs), torrc_text(&b, dir, hs));
    }

    /// `tor_pid` 对不存在的 pid / 非 tor 的 pid 必须返回 None（绝不误杀无关进程）。
    #[test]
    fn tor_pid_rejects_foreign_or_dead_pids() {
        let dir = std::env::temp_dir().join("crucible-torhs-test-pid");
        let _ = std::fs::create_dir_all(&dir);
        // 不存在的 pid
        let _ = std::fs::write(dir.join("pid"), "999998\n");
        assert_eq!(tor_pid(&dir), None);
        // 自己的 pid（是测试进程，不是 tor）
        let _ = std::fs::write(dir.join("pid"), format!("{}\n", std::process::id()));
        assert_eq!(tor_pid(&dir), None, "自己不是 tor，不能被当成 tor");
        // 垃圾内容
        let _ = std::fs::write(dir.join("pid"), "not-a-pid\n");
        assert_eq!(tor_pid(&dir), None);
        // 没有 pidfile
        let _ = std::fs::remove_file(dir.join("pid"));
        assert_eq!(tor_pid(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 配了不存在的 user ⇒ 配置期报错（别等到 tor 启动时才炸）。
    #[test]
    fn validate_rejects_unknown_user() {
        let bad = TorHsConfig {
            enabled: true,
            ports: vec![(80, 8080)],
            data_dir: None,
            tor_bin: None,
            user: Some("no-such-user-crucible-1008".into()),
        };
        assert!(validate(&bad).is_err());
        // 空白 user 视为没配
        let blank = TorHsConfig {
            user: Some("  ".into()),
            ..bad.clone()
        };
        assert!(validate(&blank).is_ok());
    }
}
