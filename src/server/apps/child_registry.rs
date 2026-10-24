//! 子进程注册表 + 孤儿清理：webserver 崩溃/重启后防止 php-fpm、native sidecar、
//! go-shm-server 等子进程泄漏（曾积累 3 代 fpm master + 4 个 go-shm-server）。
//!
//! 三层防线：
//! 1. `spawn_tracked` —— spawn 时注册 pid；
//! 2. SIGTERM/SIGINT 处理器 —— 退出前 `kill_all()` 终止全部注册子进程
//!    （由 `server::run` 安装）；
//! 3. `cleanup_orphans_at_startup()` —— 启动时清理无主孤儿（父 webserver 已死，
//!    子进程被 reparent 到 init 永不退出）。
//!
//! OpenBSD 无 /proc，进程枚举统一走 `ps -axww -o pid=,command=`。

use anyhow::Result;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::process::{Child, Command};

/// 一条已登记的子进程。
///
/// `start` 是**进程启动时间**（Linux `/proc/<pid>/stat` 第 22 字段；OpenBSD
/// `kinfo_proc.p_ustart_sec/usec`），在 spawn 时抓取。长运行期里 pid 会被复用，
/// 只凭 pid 发信号可能杀掉无关进程；启动时间不同 ⇒ 绝不发信号。
#[derive(Clone, Debug)]
struct ChildEntry {
    name: String,
    /// 程序名（spawn 时 basename）。非直系子进程只有在命令行仍含它时才动手。
    program: String,
    start: Option<u64>,
}

/// pid -> 登记信息。
///
/// **判活不依赖 `ps -p`**：Linux 上 `ps -axww -o command= -p PID` 的 `-a/-x/-p`
/// 选择项是并集，实际会返回**整张进程表**，于是「命令行里有没有程序名」的判据
/// 无常成立（误杀/误判）；OpenBSD 的 `ps -p` 对不存在 pid 的退出码/输出语义又不同。
/// 现在统一为 `kill(pid, 0)` 判存在 + `/proc`（Linux）/ `sysctl(KERN_PROC_PID)`
/// （OpenBSD）读 ppid/启动时间/命令行。
static REGISTRY: Lazy<Mutex<HashMap<i32, ChildEntry>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn register(pid: i32, name: &str) {
    REGISTRY.lock().insert(
        pid,
        ChildEntry {
            name: name.to_string(),
            program: String::new(),
            start: proc_start(pid),
        },
    );
}

/// spawn 时用这个：额外记录**程序名**，供退出时复核。
fn register_with_program(pid: i32, name: &str, program: &str) {
    let base = std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| program.to_string());
    REGISTRY.lock().insert(
        pid,
        ChildEntry {
            name: name.to_string(),
            program: base,
            start: proc_start(pid),
        },
    );
}

/// 进程身份快照（跨平台的最小集合）。
#[derive(Clone, Copy, Debug)]
struct ProcInfo {
    ppid: i32,
    /// 平台相关但同进程内稳定的启动时间。
    start: u64,
    zombie: bool,
}

/// pid 还活着、且身份仍然对得上（没记录启动时间则退回「还活着就动手」）。
///
/// **自己的直系子进程一律算匹配**（`ppid == self`）：`spawn_tracked` 登记的是**壳程序**
/// 的命令行，而壳常常立刻 `exec` 成别的程序（`deps/bin/index` wrapper → sh → python3 /
/// java / ruby；实测 JSP sidecar），exec 之后命令行里**再也不含**登记的程序名 —— 只按名字
/// 判会把**自己的直系子进程**误判成「pid 已被复用」而跳过不杀：真机实测，一个忽略
/// SIGTERM 的 sidecar 在 SIGTERM 优雅关机后**存活下来**（日志里正是
/// `skip ...（pid 已被复用或已退出，命令行无 index）`）。`ppid == self` 只有在「子进程
/// 已退出且 pid 立刻被复用」时才会不成立，比名字强得多（那种情况才退回名字判据）。
fn alive_and_matches(pid: i32, program: &str, start: Option<u64>) -> bool {
    if pid <= 1 {
        return false;
    }
    if !process_alive(pid) {
        return false; // 已退出（ESRCH）；EPERM 视为存活
    }
    let info = match proc_info(pid) {
        Some(info) => info,
        // kill(2) 说存在但读不到身份（正好退出 / 平台不支持 / 权限）：
        // 拿不到证据就**不发信号**，这是防误杀的安全方向。
        None => return false,
    };
    if info.zombie {
        return false; // 已退出、只等 reap
    }
    if let Some(want) = start {
        if info.start != want {
            // pid 已被复用给另一个进程 —— 哪怕命令行/程序名一样也不能杀。
            return false;
        }
    }
    if info.ppid == std::process::id() as i32 {
        return true; // 本进程的直接子进程：身份确定
    }
    if program.is_empty() {
        return true; // 旧式注册（无程序名）→ 保持旧行为
    }
    match proc_cmdline(pid) {
        Some(cmd) => command_contains_program(&cmd, program),
        None => false,
    }
}

/// 命令行是否仍包含登记的程序名（按 token basename 比较，避免 `myphp-fpm`
/// 或某个参数里恰好含 `php-fpm` 就命中 —— 误命中会导致误杀，宁严勿宽）。
fn command_contains_program(cmd: &str, program: &str) -> bool {
    cmd.split_whitespace().any(|tok| {
        let base = tok.rsplit('/').next().unwrap_or(tok);
        base == program
    })
}

/// 进程是否存在：`kill(pid, 0)` 跨 Linux/OpenBSD 语义一致；`EPERM` = 存在但无权限。
fn process_alive(pid: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    // SAFETY: signal 0 performs existence/permission checks only.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Linux：`/proc/<pid>/stat`。comm 字段可能含空格与 `)`，因此从**最后一个** `)` 之后解析。
#[cfg(target_os = "linux")]
fn proc_info(pid: i32) -> Option<ProcInfo> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rparen = stat.rfind(')')?;
    let mut fields = stat[rparen + 1..].split_whitespace();
    let state = fields.next()?; // field 3 (state)
    let ppid: i32 = fields.next()?.parse().ok()?; // field 4
    // fields 5..=21 then field 22 (starttime).
    let start: u64 = fields.nth(17)?.parse().ok()?;
    Some(ProcInfo {
        ppid,
        start,
        zombie: state == "Z",
    })
}

/// OpenBSD：`sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, pid})` 返回 `kinfo_proc`。
/// 不存在时 sysctl 返回 -1/ESRCH；`p_pid` 再核对一次，防止内核返回空结构。
#[cfg(target_os = "openbsd")]
fn proc_info(pid: i32) -> Option<ProcInfo> {
    let mut mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut kp: libc::kinfo_proc = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::kinfo_proc>();
    // SAFETY: `kp`/`len` are valid for the duration of the call; MIB is 4 ints.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut kp as *mut _ as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len < std::mem::size_of::<libc::kinfo_proc>() || kp.p_pid != pid {
        return None;
    }
    let start = (kp.p_ustart_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add(kp.p_ustart_usec as u64);
    // SZOMB = 5 (sys/proc.h) — libc 没有导出这个常量。
    Some(ProcInfo {
        ppid: kp.p_ppid,
        start,
        zombie: kp.p_stat == 5,
    })
}

/// 其它 Unix 的保守回退：只读 ppid（用于本仓库真正支持的 Linux/OpenBSD 之外）。
#[cfg(not(any(target_os = "linux", target_os = "openbsd")))]
fn proc_info(pid: i32) -> Option<ProcInfo> {
    let out = Command::new("ps")
        .arg("-o")
        .arg("ppid=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .ok()?;
    let ppid = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(ProcInfo {
        ppid,
        start: 0,
        zombie: false,
    })
}

/// 启动时间；平台无此信息时返回 `None`（此时只依赖 ppid/程序名判据）。
fn proc_start(pid: i32) -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "openbsd"))]
    {
        proc_info(pid).map(|i| i.start)
    }
    #[cfg(not(any(target_os = "linux", target_os = "openbsd")))]
    {
        let _ = pid;
        None
    }
}

/// 完整命令行：Linux `/proc/<pid>/cmdline`；OpenBSD `sysctl(KERN_PROC_ARGS)`。
#[cfg(target_os = "linux")]
fn proc_cmdline(pid: i32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let parts: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    Some(parts.join(" "))
}

#[cfg(target_os = "openbsd")]
fn proc_cmdline(pid: i32) -> Option<String> {
    let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_PROC_ARGS, pid];
    for cap in [4096usize, 65536usize] {
        let mut buf = vec![0u8; cap];
        let mut len = cap;
        // SAFETY: buf/len describe a writable allocation of `cap` bytes.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(len);
            let parts: Vec<String> = buf
                .split(|b| *b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect();
            if !parts.is_empty() {
                return Some(parts.join(" "));
            }
            return None;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "openbsd")))]
fn proc_cmdline(pid: i32) -> Option<String> {
    let out = Command::new("ps")
        .arg("-axww")
        .arg("-o")
        .arg("command=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn unregister(pid: i32) {
    REGISTRY.lock().remove(&pid);
}

/// 终止所有已注册子进程（SIGTERM → 短等 → SIGKILL）。
/// 在 spawn_blocking 中调用（内含 thread::sleep）。
pub fn kill_all() {
    let entries: Vec<(i32, ChildEntry)> = REGISTRY
        .lock()
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    for (pid, entry) in &entries {
        // pid 复用防线：启动时间（若可用）+ 程序名双重核对。
        if !alive_and_matches(*pid, &entry.program, entry.start) {
            if entry.start.is_some() {
                log::warn!(
                    "child_registry: skip {} pid={pid}（pid 已被复用或已退出，启动时间/程序名不符）",
                    entry.name
                );
            } else {
                log::info!("child_registry: skip {} pid={pid}（已退出）", entry.name);
            }
            continue;
        }
        log::info!("child_registry: SIGTERM {} pid={pid}", entry.name);
        let _ = unsafe { libc::kill(*pid, libc::SIGTERM) };
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    for (pid, entry) in &entries {
        if alive_and_matches(*pid, &entry.program, entry.start) {
            log::warn!("child_registry: SIGKILL {} pid={pid}", entry.name);
            let _ = unsafe { libc::kill(*pid, libc::SIGKILL) };
        }
    }
    REGISTRY.lock().clear();
}

/// spawn 并注册。注意：`Child` 被 drop 不会终止进程，生命周期靠 registry 兜底。
pub fn spawn_tracked(cmd: &mut Command, name: &str) -> Result<Child> {
    let program = cmd.get_program().to_string_lossy().to_string();
    let child = cmd.spawn()?;
    register_with_program(child.id() as i32, name, &program);
    Ok(child)
}

/// 杀死 Child 并从注册表注销（用于替换/移除 runtime 时）。
/// 先 SIGTERM 让 fpm/sidecar 优雅退出并清理 socket，再 SIGKILL 兜底。
pub fn kill_child(child: &mut Child) {
    let pid = child.id() as i32;
    // 已经退出的句柄：只回收，**不**向该 pid 发信号。
    // 为什么要先判：pid 在「子进程已退出、但句柄还存着」的窗口里可能已被内核复用给
    // 无关进程（长运行期 + 频繁重启 sidecar/php 的场景），`kill(pid, SIGTERM)` 会误伤
    // 它。`try_wait` 命中「已退出」就只剩 wait 回收这一步；仍在跑（Ok(None)）或
    // 状态不可知（Err，例如被别处 wait 过）时维持旧路径（SIGTERM → SIGKILL）。
    if let Ok(Some(_)) = child.try_wait() {
        let _ = child.wait();
        unregister(pid);
        return;
    }
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..10 {
        match child.try_wait() {
            Ok(Some(_)) => break,
            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    unregister(pid);
}

/// 若 pid 存活且命令行包含 `expect`，则终止之（防 pid 复用误杀）。
/// 判活走 `kill(pid, 0)`，命令行走 `/proc` / `sysctl(KERN_PROC_ARGS)` —— 不用 `ps -p`
///（Linux procps 的 `-a/-x/-p` 是并集，会返回整表；OpenBSD 语义又不同）。
pub fn kill_if_matches(pid: i32, expect: &str) {
    if !process_alive(pid) {
        return; // 已退出
    }
    let Some(cmdline) = proc_cmdline(pid) else {
        return;
    };
    if !cmdline.contains(expect) {
        return;
    }
    log::info!("child_registry: killing stale pid={pid} cmd={cmdline}");
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    std::thread::sleep(std::time::Duration::from_millis(150));
    if process_alive(pid) {
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// 启动时清理无主孤儿：当没有任何其它存活 webserver 实例时，
/// 终止引用本仓库 state/ 目录或 app-engines 二进制的遗留进程。
/// （若存在存活实例，这些进程归它所有，不动。）
pub fn cleanup_orphans_at_startup() {
    let root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let root_str = root
        .canonicalize()
        .unwrap_or(root)
        .display()
        .to_string();
    let self_pid = std::process::id() as i32;

    let Some(text) = ps_all() else {
        return;
    };

    let mut live_webserver = false;
    let mut orphans: Vec<(i32, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((pid_s, cmd)) = line.split_once(' ') else {
            continue;
        };
        let Ok(pid) = pid_s.trim().parse::<i32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        // 其它存活 webserver 实例（含测试实例）拥有这些 sidecar → 跳过清理。
        if cmdline_is_webserver_instance(cmd) {
            live_webserver = true;
        }
        let stale = (cmd.contains("php-fpm") && cmd.contains(&format!("{root_str}/state/")))
            || cmd.contains(&format!("{root_str}/target/app-engines/"))
            || (cmd.contains("jsp_sidecar") && cmd.contains(&format!("{root_str}/state/")))
            || (cmd.contains("deps/bin") && cmd.contains(&format!("{root_str}/www-apps/")));
        if stale {
            orphans.push((pid, cmd.to_string()));
        }
    }

    if live_webserver && !orphans.is_empty() {
        log::info!(
            "child_registry: {} orphan candidate(s) skipped — another webserver instance is live",
            orphans.len()
        );
        return;
    }
    for (pid, cmd) in &orphans {
        log::info!("child_registry: cleanup orphan pid={pid} cmd={cmd}");
        let _ = unsafe { libc::kill(*pid, libc::SIGTERM) };
    }
    if !orphans.is_empty() {
        std::thread::sleep(std::time::Duration::from_millis(300));
        for (pid, cmd) in &orphans {
            if unsafe { libc::kill(*pid, 0) } == 0 {
                log::warn!("child_registry: SIGKILL orphan pid={pid} cmd={cmd}");
                let _ = unsafe { libc::kill(*pid, libc::SIGKILL) };
            }
        }
    }
}

/// 「这条命令行是另一个存活 webserver 实例」——启动期孤儿清理据此决定动不动手。
///
/// 判据必须与 CLI 一致：`parse_config_path()`（src/main.rs）同时接受
/// `--config <path>` **和** `-c <path>`（文档化别名）。旧实现只认字面 `"--config"`
/// 子串，于是 `webserver -c cfg.toml` 的实例被当成「不存在」—— 它拉起的 php-fpm /
/// sidecar（命令行都引用本仓库的 state/ 或 target/app-engines/，见 stale 判据）会被
/// 新实例的启动清理 SIGTERM/SIGKILL 掉，那个实例随即开始 502，直到它自己重新拉起子进程。
///
/// 按 token 判定（而不是整串 contains）避免把参数里恰好含 `-c`/`--config` 的无关命令
/// 也算成 webserver 实例（会让清理该做时不做，属保守方向）。
fn cmdline_is_webserver_instance(cmd: &str) -> bool {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let is_webserver = tokens
        .iter()
        .any(|t| *t == "webserver" || t.ends_with("/webserver"));
    let has_config_flag = tokens
        .iter()
        .any(|t| *t == "-c" || *t == "--config" || t.starts_with("--config="));
    is_webserver && has_config_flag
}

/// `ps -axww -o pid=,command=` 全量列表（**仅启动期孤儿枚举**用）。
///
/// 这里刻意保留 ps：`-axww -o pid=,command=` 在 Linux procps 与 OpenBSD ps 上
/// 语义一致（枚举全表），O12 的问题出在 `-p` 选择项与 `-a/-x` 的并集语义。
/// 判活/身份核对已全部改为 `kill(2)` + `/proc` / `kinfo_proc`，不再调用
/// `ps -p`。
fn ps_all() -> Option<String> {
    let out = Command::new("ps")
        .arg("-axww")
        .arg("-o")
        .arg("pid=,command=")
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Registry-mutating tests must not race each other (tests run in parallel
    /// threads inside one process).
    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn registry_register_unregister_roundtrip() {
        let _g = TEST_LOCK.lock();
        register(999999, "test");
        assert!(REGISTRY.lock().contains_key(&999999));
        unregister(999999);
        assert!(!REGISTRY.lock().contains_key(&999999));
    }

    /// pid 复用防线：`alive_and_matches` 对**不存在的 pid** 必须为假（不能盲目发信号），
    /// 对「记录了程序名但命令行读不到」也必须是假。
    /// 真机教训：长运行期里 php 被反复重启、旧 pid 永久留在表里，退出时可能杀掉复用者。
    /// 这条测试**不依赖**机器上是否跑着 php-fpm（旧实现用 `ps -p`，Linux 上会退化
    /// 成整表匹配，测试在共享机上会随机失败）。
    #[test]
    fn kill_all_matches_guard_semantics() {
        assert!(
            !alive_and_matches(999999, "php-fpm", None),
            "不存在的 pid 不能算匹配"
        );
        assert!(!alive_and_matches(1, "php-fpm", None), "pid<=1 必须拒绝");
        // 自身进程：命令行里肯定不含 "php-fpm" ⇒ 也必须为假（这是防误杀的关键一条）
        let me = std::process::id() as i32;
        assert!(
            !alive_and_matches(me, "php-fpm", None),
            "命令行不含程序名时不能动手（否则就是误杀）"
        );
        // 记录为空串（旧式 register）⇒ 退回旧行为：活着即 true
        assert!(alive_and_matches(me, "", None), "旧式注册应保持旧行为");
    }

    /// 直系子进程即使 `exec` 成别的程序（命令行不再含登记的程序名）也必须算「匹配」。
    /// 真机教训：`deps/bin/index` wrapper → `exec python3` 之后名字变成 python3，旧判据
    /// 让 kill_all 跳过自己的 sidecar ⇒ SIGTERM 关机后 sidecar 存活成孤儿。
    #[cfg(unix)]
    #[test]
    fn own_child_matches_even_after_exec() {
        use std::process::Command as C;
        let mut child = C::new("/bin/sh")
            .arg("-c")
            .arg("exec sleep 30")
            .spawn()
            .expect("spawn sh");
        let pid = child.id() as i32;
        assert!(
            alive_and_matches(pid, "/bin/sh", None),
            "自己的直系子进程必须匹配（exec 后名字已变）"
        );
        // 名字判据只对**非直系**进程生效（pid 复用防线）；直系子进程由 ppid 身份直接认定。
        assert!(
            alive_and_matches(pid, "php-fpm", None),
            "直系子进程身份优先于名字判据"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// 启动时间（/proc starttime、OpenBSD p_ustart）必须参与 pid 复用判定：
    /// 同一 pid 但启动时间不同 ⇒ 不是当初那个进程，绝不能发信号。
    #[cfg(any(target_os = "linux", target_os = "openbsd"))]
    #[test]
    fn start_time_guards_against_pid_reuse() {
        let mut child = Command::new("sleep").arg("30").spawn().expect("spawn sleep");
        let pid = child.id() as i32;
        let info = proc_info(pid).expect("/proc or kinfo_proc entry");
        assert!(
            alive_and_matches(pid, "sleep", Some(info.start)),
            "启动时间一致 + 直系子进程必须匹配"
        );
        assert!(
            !alive_and_matches(pid, "sleep", Some(info.start.wrapping_add(1))),
            "启动时间不同 = pid 已被复用，必须拒绝"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// 真机行为：kill_all 只杀自己直系子进程；一个**非直系的同名外部进程**
    /// （pid 复用场景）即使登记在表里，只要启动时间/程序名对不上就不能被误杀。
    #[cfg(any(target_os = "linux", target_os = "openbsd"))]
    #[test]
    fn kill_all_spares_reused_external_pid() {
        let _g = TEST_LOCK.lock();
        // `sh -c 'sleep 30 & echo $!'` 退出后，sleep 被 reparent 到 init ⇒ 不是我们的
        // 直系子进程，模拟「pid 已被复用给无关进程」。
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30 >/dev/null 2>&1 & echo $!")
            .output()
            .expect("spawn external sleep");
        let ext_pid: i32 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("external pid");
        let info = proc_info(ext_pid).expect("external proc info");
        // 等到它不再是本测试进程的直接子进程。
        for _ in 0..200 {
            if proc_info(ext_pid).map(|i| i.ppid) != Some(std::process::id() as i32) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        REGISTRY.lock().insert(
            ext_pid,
            ChildEntry {
                name: "old-php-fpm".to_string(),
                program: "php-fpm".to_string(),
                start: Some(info.start.wrapping_add(424242)),
            },
        );
        kill_all();
        assert!(
            process_alive(ext_pid),
            "pid 复用/程序名不符的外部进程不能被 kill_all 误杀"
        );
        let _ = unsafe { libc::kill(ext_pid, libc::SIGKILL) };
    }

    /// 真机行为：登记过的**自己的直系子进程**必须被 kill_all 杀掉（SIGTERM→SIGKILL）。
    #[test]
    fn kill_all_kills_tracked_own_child() {
        let _g = TEST_LOCK.lock();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("exec sleep 30");
        let mut child = spawn_tracked(&mut cmd, "sleep-child").expect("spawn tracked");
        let pid = child.id() as i32;
        kill_all();
        let mut exited = false;
        for _ in 0..200 {
            if let Ok(Some(_)) = child.try_wait() {
                exited = true;
                break;
            }
            if !process_alive(pid) {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(exited, "kill_all 必须终止自己的直系子进程");
        let _ = child.wait();
    }

    /// 启动期孤儿清理的「另一实例存活」判据：`--config` 与 `-c` 两种写法都必须认出
    /// （旧实现只认 `--config` ⇒ `webserver -c cfg` 的实例的子进程会被误杀）。
    #[test]
    fn live_instance_detection_accepts_both_config_flags() {
        for cmd in [
            "/home/u/crucible/target/release/webserver --config /home/u/crucible/config.toml",
            "/home/u/crucible/target/release/webserver -c /home/u/crucible/config.toml",
            "webserver --config=/x/config.toml",
            "webserver -c /x/config.toml -v",
        ] {
            assert!(cmdline_is_webserver_instance(cmd), "应判为存活实例: {cmd}");
        }
        for cmd in [
            "/usr/bin/vim /home/u/crucible/config.toml",
            "php-fpm -c /etc/php.ini",
            "python3 server.py --config /x",
            "/home/u/crucible/target/release/webserver --check-config",
        ] {
            assert!(!cmdline_is_webserver_instance(cmd), "不应判为存活实例: {cmd}");
        }
    }
}
