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
///
/// **绝不跟随符号链接**：`state/tor-hs`（及 hs 子目录）在第一次 chown 后就归 `_tor`
/// 所有，该账号可以把目录项换成指向 /etc 的链接；若这里用 `set_permissions`（跟随），
/// root 下一次巡检就会替它执行 `chmod 0700 /etc`。用 O_NOFOLLOW 打开目录 fd 再 fchmod，
/// 链接一律拒绝（ELOOP → 报错，不触碰目标）。
fn set_mode_0700(p: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(p.as_os_str().as_bytes())
            .with_context(|| format!("路径含 NUL: {}", p.display()))?;
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            bail!("chmod 0700 {}: {e}（符号链接或不可打开）", p.display());
        }
        let rc = unsafe { libc::fchmod(fd, 0o700) };
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        if rc != 0 {
            bail!("chmod 0700 {}: {e}", p.display());
        }
    }
    let _ = p;
    Ok(())
}

/// 以 O_NOFOLLOW 写文件：目录归 `_tor` 后它可以把 `torrc` / `hostname.log` 换成符号链接，
/// 诱使 root 把内容写到任意路径（例如用 torrc 文本覆盖 /etc/rc.conf）。这里的所有写入
/// 都落在这个目录树里，必须拒绝链接；普通文件不存在则创建（0600）。
fn write_file_nofollow(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("写 {}（O_NOFOLLOW）", path.display()))?;
        // O_NOFOLLOW 挡不住**硬链接**：`_tor` 可把 /etc 下的 root 文件硬链成 torrc 的名字，
        // 我们 O_TRUNC 的就是那个 root inode（是否能建硬链取决于内核策略，不能依赖）。
        // 我们自己的文件链接数恒为 1，>1 一律拒绝。
        if f.metadata()
            .map(|m| m.nlink() > 1)
            .unwrap_or(false)
        {
            bail!(
                "拒绝写入 {}：链接数 > 1（疑似被硬链到其它文件，跳过而不是截断它）",
                path.display()
            );
        }
        f.write_all(data)
            .with_context(|| format!("写 {}", path.display()))?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).with_context(|| format!("写 {}", path.display()))
    }
}

/// 以 O_NOFOLLOW 读文件（链接/不存在 → `None`）。
///
/// 与写入同理：`hostname`、`notice.log`、`pid` 都可能被 `_tor` 换成指向 root 文件的链接
/// （读出来会被写进日志/面板 ⇒ 信息泄露）。读不到就当作没有，不跟随。
fn read_to_string_nofollow(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .ok()?;
        // 硬链接同样会绕过 O_NOFOLLOW：链接数 >1 时读到的可能是 root 文件的内容
        // （会被写进日志/面板），一律当作不可读。
        if f.metadata().map(|m| m.nlink() > 1).unwrap_or(true) {
            return None;
        }
        let mut s = String::new();
        f.read_to_string(&mut s).ok()?;
        Some(s)
    }
    #[cfg(not(unix))]
    {
        std::fs::read_to_string(path).ok()
    }
}

/// HS 的 HiddenServiceDir（配置优先，其次 `state/tor-hs/hs`）。
fn hs_data_dir(cfg: &TorHsConfig) -> PathBuf {
    cfg.data_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir().join("hs"))
}

/// 运行期对 `[tor_hs].data_dir` 的兜底校验：**必须绝对**。
///
/// 相对 data_dir 会让 `ensure_hs` 按**进程 cwd** 解析，并把这棵树 chmod 0700 + chown 给
/// `_tor` —— 正是 `config.rs::check_tor_hs_data_dir` 想拦住的场景（把 cwd 下已有目录整体
/// 交给低权账号），而该校验对相对路径的两个 `starts_with` 都不成立。配置期修好之前，
/// 运行期 fail-closed：要么配绝对路径（指向 HS 专用目录），要么用默认 state/tor-hs/hs。
fn ensure_absolute_data_dir(p: &Path) -> Result<()> {
    if p.is_absolute() {
        return Ok(());
    }
    bail!(
        "[tor_hs].data_dir = {:?} 是相对路径：会按进程 cwd 解析并把该目录整棵 chmod 0700 + \
         chown 给 tor 账号；请改为绝对路径（默认 state/tor-hs/hs 由程序自己绝对化）",
        p.display()
    )
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
        if let Some(s) = read_to_string_nofollow(&p) {
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
    let pid: i32 = read_to_string_nofollow(&dir.join("pid"))?
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
///
/// # 符号链接安全（P1）
///
/// 第一次 chown 之后目录属主就是低权的 tor 账号（或被攻破的 tor），它能在树里放**任意
/// 符号链接**。任何跟随链接的实现（`Path::is_dir()` / `std::fs::chown` / `read_dir` 都跟随）
/// 都会被利用：`ln -s / …/state/tor-hs/x` 后，root 会在 ≤60s 的巡检里把 `/etc`（或
/// `/etc/master.passwd`、`/root/.ssh/authorized_keys`）的属主交给它 —— 本地提权直达 root。
///
/// 因此这里改成**基于目录 fd 的遍历**：
/// * 顶层与每个子目录都用 `open/openat(O_NOFOLLOW|O_DIRECTORY)` 固定 inode，路径被换成
///   链接时直接失败，绝不跟过去；
/// * 逐项用 `fstatat(AT_SYMLINK_NOFOLLOW)` 判类型，**符号链接一律跳过并告警**；
/// * 文件/目录本身用 `fchownat(..., AT_SYMLINK_NOFOLLOW)`（等价 lchown）改属主，不跟随；
/// * 目录在子项改完后才 chown（先深后浅），顶层目录直接 fchown 它的 fd。
fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("chown_tree: 路径含 NUL: {}", path.display()))?;
        let dirfd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if dirfd < 0 {
            let e = std::io::Error::last_os_error();
            bail!(
                "chown_tree: 打开目录 {} 失败（符号链接 / 权限 / 不存在？）: {e}",
                path.display()
            );
        }
        // 目录 fd 交给 chown_dir_fd 接管（成功由 closedir 关闭，失败路径它会自己关）。
        chown_dir_fd(dirfd, uid, gid, path)?;
    }
    let _ = (path, uid, gid);
    Ok(())
}

/// 递归处理 `dirfd` 指向的目录：先子项（文件立即、目录递归后再改），**最后目录自身**。
/// 接管 `dirfd` 的所有权。
#[cfg(unix)]
fn chown_dir_fd(dirfd: libc::c_int, uid: u32, gid: u32, path: &Path) -> Result<()> {
    let dir = unsafe { libc::fdopendir(dirfd) };
    if dir.is_null() {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(dirfd) };
        bail!("chown_tree: fdopendir({}) 失败: {e}", path.display());
    }
    let children = chown_children(dir, dirfd, uid, gid, path);
    // 子项全部改完（或中途失败）才改目录自身；失败时不改，避免「目录先成别人的、下不去」。
    let self_result = if children.is_ok() {
        let rc = unsafe { libc::fchown(dirfd, uid as libc::uid_t, gid as libc::gid_t) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    } else {
        Ok(())
    };
    unsafe { libc::closedir(dir) };
    children.with_context(|| format!("chown_tree 子项 {}", path.display()))?;
    if let Err(e) = self_result {
        bail!("chown {}: {e}", path.display());
    }
    Ok(())
}

/// `chown_dir_fd` 的子项遍历（不含目录自身）。参数 `dir`/`dirfd` 指向同一目录。
#[cfg(unix)]
fn chown_children(
    dir: *mut libc::DIR,
    dirfd: libc::c_int,
    uid: u32,
    gid: u32,
    path: &Path,
) -> Result<()> {
    loop {
        // readdir 的 EOF 与错误都以 NULL 返回；按 EOF 处理 —— 剩下的项下一轮巡检重做，
        // 属于「晚一点恢复」而不是破坏。
        let ent = unsafe { libc::readdir(dir) };
        if ent.is_null() {
            return Ok(());
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        if rc != 0 {
            bail!(
                "fstatat {}/{}: {}",
                path.display(),
                name.to_string_lossy(),
                std::io::Error::last_os_error()
            );
        }
        let file_type = st.st_mode & libc::S_IFMT;
        if file_type == libc::S_IFLNK {
            // 符号链接：**跳过**，连链接自身的属主都不改（更不跟随目标）。
            // `_tor` 拥有目录后可以放进任何链接，跟随一次就足以把 /etc 交出去。
            log::warn!(
                "tor_hs: chown_tree 跳过符号链接 {}/{}（绝不跟随、不改其目标属主）",
                path.display(),
                name.to_string_lossy()
            );
            continue;
        }
        if file_type != libc::S_IFDIR && st.st_nlink > 1 {
            // 硬链接是同一个 inode 的第二个名字：fchownat 会改到「别处」那个文件的属主
            // （符号链接保护挡不住它）。HS 目录里我们自己的文件链接数恒为 1，跳过并告警。
            log::warn!(
                "tor_hs: chown_tree 跳过硬链接 {}/{}（nlink={}，可能是对 root 文件的链接）",
                path.display(),
                name.to_string_lossy(),
                st.st_nlink
            );
            continue;
        }
        let child_path = path.join(name.to_string_lossy().as_ref());
        if file_type == libc::S_IFDIR {
            // O_NOFOLLOW：检查（fstatat）与打开之间被换成链接时直接失败，绝不递归进目标。
            let child_fd = unsafe {
                libc::openat(
                    dirfd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if child_fd < 0 {
                let e = std::io::Error::last_os_error();
                bail!(
                    "chown_tree: openat {} 失败（是否被换成符号链接？）: {e}",
                    child_path.display()
                );
            }
            chown_dir_fd(child_fd, uid, gid, &child_path)?;
        } else {
            let rc = unsafe {
                libc::fchownat(
                    dirfd,
                    name.as_ptr(),
                    uid as libc::uid_t,
                    gid as libc::gid_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                bail!(
                    "chown {}: {}",
                    child_path.display(),
                    std::io::Error::last_os_error()
                );
            }
        }
    }
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
    ensure_absolute_data_dir(&hs_dir)?;
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
            // `data_dir` 配在 state/tor-hs 之外时，只把 **HS 目录本身**交给该用户。
            // **绝不能**去 chown 它的父目录：`data_dir = "/onion"` 时 `parent()` 就是 `/`，
            // 那等于 `chown -R / _tor` —— tor 一旦被攻破，整个文件系统（config.toml、
            // TLS/ECH 私钥、admin 口令哈希、/root）的属主都变成了这个低权账号；写
            // `/var/tor/hs` 则会把父目录里**别的东西**的属主一并改掉。
            // 父目录只需要路径可搜索（x 位），不需要归 tor 所有 —— 那是运维的目录策略。
            chown_tree(&hs_dir, uid, gid)?;
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
    let existing = read_to_string_nofollow(&hostname_file)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let torrc_path = dir.join("torrc");
    let wanted = torrc_text(cfg, &dir, &hs_dir);
    let torrc_same = read_to_string_nofollow(&torrc_path)
        .map(|s| s == wanted)
        .unwrap_or(false);
    let running = tor_pid(&dir);

    match restart_reason(existing.as_deref(), running, torrc_same) {
        None => {
            let name = existing.clone().unwrap_or_default();
            // debug 级：巡检每 60s 调一次，info 会刷屏（"serving" 那条已经打过一次了）
            log::debug!("tor_hs: 复用已有 HS {name}（tor pid {}）", running.unwrap_or(0));
            let _ = write_file_nofollow(&dir.join("hostname.log"), format!("{name}\n").as_bytes());
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

    write_file_nofollow(&torrc_path, wanted.as_bytes())?;

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
        let _ = write_file_nofollow(&dir.join("tor-error.log"), (said.join("\n") + "\n").as_bytes());
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

    // 等待 onion 生成（首次建 HS 密钥可能 ~10-30s；重启已有密钥是秒级）。
    // 读取用 O_NOFOLLOW：`hostname` 若被换成指向 root 文件的链接，内容会进日志/面板。
    for _ in 0..60 {
        if let Some(name) = read_to_string_nofollow(&hostname_file) {
            let name = name.trim().to_string();
            if !name.is_empty() {
                write_file_nofollow(&dir.join("hostname.log"), format!("{name}\n").as_bytes())?;
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
        let Some(log) = read_to_string_nofollow(&p) else {
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
        //
        // 这一段**不能**在调用线程上同步做：`spawn_from_config` 是从
        // `LiveConfig::reload()/replace()` 里调的，也就是跑在 tokio worker 上，而
        // `tor_pid` 会 spawn 一个 `ps`、`stop_tor_blocking` 最长要 `thread::sleep` 7s
        //（TERM 等 5s + KILL 等 2s）。本机只有 2 条 worker，一次「关掉 tor_hs」的配置保存
        // 就足以让服务整整 7s 不响应任何请求。整段挪进阻塞池，并借 `hs_lock` 与正在
        // `ensure_hs` 的那一侧串行（否则可能把它刚拉起来的 tor 又杀掉）。
        //
        // 但**必须先问一句「有没有 runtime」**：`tokio::spawn` 在没有 reactor 的线程上会
        // 直接 panic（实测：`upload_api::tests::enabled_for_follows_live_config` 走
        // `LiveConfig::replace()` 撞上这里）。没有 runtime 时（单测、离线工具）本来就
        // 没有 worker 会被阻塞，同步做才是对的 —— 异步只是为了避免占用 worker。
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move {
                let _g = hs_lock().lock().await;
                let _ = tokio::task::spawn_blocking(|| {
                    stop_tor_if_running("enabled 变成 false")
                })
                .await;
            });
        } else {
            stop_tor_if_running("enabled 变成 false");
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
                // 巡检是「enabled = false 之后 tor 还挂着」的最后一道闸：热重载里那次停止是
                // **异步**的（不能阻塞 worker，见 `spawn_from_config`），只要它在那一瞬间
                // 读丢了 pidfile 或 kill 失败，.onion 就会一直挂在一个「已关闭」的服务上，
                // 再没有任何东西来拉闸。这里每轮确认一次：只认 pidfile + `ps` 核对过的
                // 那个 pid（别人的 tor 绝不会被误杀）；没在跑时 `tor_pid` 只读一个 pidfile
                // 就返回，代价可忽略。
                let _g = hs_lock().lock().await;
                let _ = tokio::task::spawn_blocking(|| {
                    stop_tor_if_running("巡检发现 enabled=false 但 tor 仍在")
                })
                .await;
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
    // **不再**用 `cfg.enabled` 提前返回：`spawn_from_config` 的「enabled 变 false → 停 tor」
    // 现在是异步的（不能阻塞只有 2 条的 tokio worker），进程完全可能在它跑完之前就退出；
    // 那一刻内存里的配置已经是「未启用」，但那台 tor 是我们自己起的、.onion 还挂着。
    // 停不停只认 pidfile + `ps` 命令行里有没有我们的 torrc（`tor_pid`），与 enabled 无关，
    // 也绝不会误杀别人的 tor。
    let _ = cfg;
    stop_tor_if_running("进程退出");
}

/// 幂等停止：**只有** pidfile 指向且 `ps` 命令行里带着我们 torrc 的那个 pid 才会被动
/// （`tor_pid` 的判据），所以别人的 tor 绝不会被误杀；没在跑时只读一个 pidfile 就返回。
///
/// `why` 只进日志（`&'static str` 是为了能直接塞进 `spawn_blocking`）。三处调用点
/// （enabled 变 false、巡检、进程退出）共用一段代码，避免「改了一处忘了另一处」。
fn stop_tor_if_running(why: &'static str) {
    let dir = state_dir();
    if tor_pid(&dir).is_none() {
        return;
    }
    log::info!("tor_hs: {why} → 停止 tor");
    if let Err(e) = stop_tor_blocking(&dir) {
        log::warn!("tor_hs: 停止 tor 失败（{why}）：{e:#}");
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

    /// P1 回归：chown_tree **绝不跟随符号链接**。
    ///
    /// 被攻破的 `_tor` 账号在树里放 `ln -s /etc …` 后，巡检（≤60s）不得把 /etc 的
    /// 属主交出去。测试用的链接指向 root 拥有的目录/文件：旧实现（`is_dir()` 跟随 +
    /// `chown` 跟随）会 EPERM 报错，新实现跳过链接、正常返回。
    #[cfg(unix)]
    #[test]
    fn chown_tree_skips_symlinks_without_following_targets() {
        use std::os::unix::fs::{symlink, MetadataExt};
        // 以 root 跑测试时跳过：万一实现有 bug，会真的把 /etc 的属主改掉（不可逆）。
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let base = std::env::temp_dir().join(format!("crucible-torhs-chown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::write(base.join("sub/regular.txt"), b"x").unwrap();
        symlink("/etc", base.join("escape_dir")).unwrap();
        symlink("/etc/passwd", base.join("escape_file")).unwrap();
        symlink("/nonexistent-crucible-target", base.join("dangling")).unwrap();
        let uid = unsafe { libc::geteuid() } as u32;
        let gid = unsafe { libc::getegid() } as u32;
        chown_tree(&base, uid, gid).expect("符号链接必须被跳过，绝不 chown 链接目标");
        for link in ["escape_dir", "escape_file", "dangling"] {
            let md = std::fs::symlink_metadata(base.join(link)).unwrap();
            assert!(md.file_type().is_symlink(), "{link} 应仍是符号链接");
        }
        // 普通项照常处理（同一 uid，chown 自身永远允许）
        assert_eq!(
            std::fs::metadata(base.join("sub/regular.txt")).unwrap().uid(),
            uid
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// P1 同类：chmod / 写入也不得穿过符号链接（目录归 `_tor` 后它可以换掉目录项）。
    #[cfg(unix)]
    #[test]
    fn nofollow_helpers_refuse_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base =
            std::env::temp_dir().join(format!("crucible-torhs-nofollow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("real_dir")).unwrap();
        std::fs::set_permissions(
            base.join("real_dir"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink(base.join("real_dir"), base.join("dir_link")).unwrap();
        assert!(set_mode_0700(&base.join("dir_link")).is_err(), "chmod 不得跟随链接");
        let mode = std::fs::metadata(base.join("real_dir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "链接目标权限不得被改");

        std::fs::write(base.join("real_file"), b"keep").unwrap();
        symlink(base.join("real_file"), base.join("file_link")).unwrap();
        assert!(
            write_file_nofollow(&base.join("file_link"), b"evil").is_err(),
            "写不得跟随链接"
        );
        assert_eq!(
            read_to_string_nofollow(&base.join("real_file")).as_deref(),
            Some("keep"),
            "链接目标内容不得被覆盖"
        );
        // 普通文件正常读/写
        assert!(write_file_nofollow(&base.join("plain"), b"ok").is_ok());
        assert_eq!(
            read_to_string_nofollow(&base.join("plain")).as_deref(),
            Some("ok")
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// P3 回归：相对 data_dir 运行期必须拒绝（否则整棵 cwd 目录会 chmod/chown 给 tor）。
    #[test]
    fn relative_data_dir_is_rejected_at_runtime() {
        assert!(ensure_absolute_data_dir(Path::new("www")).is_err());
        assert!(ensure_absolute_data_dir(Path::new("./state/hs")).is_err());
        assert!(ensure_absolute_data_dir(Path::new("/var/tor/hs")).is_ok());
    }
}
