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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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
        // kill(2) 说存在但读不到内核身份（平台差异 / 权限 / 正好退出）。
        //
        // **不能直接放弃**：真实生产事故（OpenBSD 7.9，deploy3-wave19 §4.3）里
        // `KERN_PROC_PID` 的 MIB 形态不对 ⇒ `proc_info` 对**所有** pid 返回 None ⇒
        // spawn 时登记的启动时间是 None、关机时把自己刚 spawn 的存活 sidecar 全判成
        // 「已退出」跳过 ⇒ php-fpm/jsp/ruby/rack 全部 reparent 成孤儿（日志
        // `skip …（已退出）`）。这里退回到最小判据：**只认自己的直系子进程**
        //（`ps -o ppid= -p PID`，Linux/OpenBSD 语义一致，且不带 `-a/-x`，没有
        // 「选择项并集返回整表」的陷阱）。非直系仍然不发信号 —— 防误杀方向不变。
        None => return pid_is_direct_child(pid),
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

/// pid 是否仍是本进程的**直接子进程**（不依赖 `/proc` / `kinfo_proc`）。
///
/// `ps -o ppid= -p PID` 在 Linux procps 与 OpenBSD ps 上语义一致；这里**不带**
/// `-a/-x`，所以没有本模块文件头警告的「选择项并集 = 返回整表」问题（那只是
/// `-a/-x` 与 `-p` 混用的陷阱）。
fn pid_is_direct_child(pid: i32) -> bool {
    if pid <= 1 || pid == std::process::id() as i32 {
        return false;
    }
    let out = match Command::new("ps")
        .arg("-o")
        .arg("ppid=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<i32>().ok())
        == Some(std::process::id() as i32)
}

/// 公开的最小身份判据：`pid` 是否为本进程的直系子进程。
///
/// 受管 sidecar 只可能由本进程 spawn；`.envfp` 里记录的 pid 若不是直系子进程，
/// 就是上一代 webserver 的遗留（SIGKILL / 关机漏杀），不能把它当「自己的」复用。
pub(crate) fn is_direct_child(pid: i32) -> bool {
    pid_is_direct_child(pid)
}

/// pid 的完整命令行（Linux `/proc`；OpenBSD `KERN_PROC_ARGS`）。供引擎 spawn 前
/// 复核上一代遗留进程（防 pid 复用误杀）。
pub(crate) fn cmdline(pid: i32) -> Option<String> {
    proc_cmdline(pid)
}

/// 存活且不是僵尸。
fn process_running(pid: i32) -> bool {
    if !process_alive(pid) {
        return false;
    }
    match proc_info(pid) {
        Some(info) => !info.zombie,
        None => true, // 读不到身份时按「可能还在跑」处理（宁可多等一次 SIGKILL）
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

/// OpenBSD：`sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, pid, elem_size, elem_count})`。
///
/// **MIB 形态是 OpenBSD 特有**：KERN_PROC 子树要求
/// `{CTL_KERN, KERN_PROC, op, arg, sizeof(kinfo_proc), count}` **六级**（man 2 sysctl
/// 的 KERN_PROC 段；与 FreeBSD 的四级 `{CTL_KERN, KERN_PROC, op, arg}` 不同）。
/// 旧实现只给四级，内核一律返回 `EINVAL` —— 本波在远程 OpenBSD 7.9 用 C 探针实测：
/// 四级 `rc=-1 errno=22`，同一进程六级 `rc=0` 且 `p_pid/p_ppid/p_stat/p_ustart` 正确。
///
/// 生产后果（deploy3-wave19 §4.3 的根因）：`proc_start()` 恒 None、`proc_info()` 恒
/// None ⇒ 关机时 `alive_and_matches` 把**存活的直系子进程**判成「已退出」跳过 ⇒
/// php-fpm / jsp / ruby / rack 全部 reparent 成 ppid=1 孤儿，新实例再复用旧 socket。
///
/// 注意：**不存在的 pid** 在此 MIB 下返回 `rc=0, len=0`（不是 ESRCH），所以必须核对
/// `len` 与 `p_pid`。
#[cfg(target_os = "openbsd")]
fn proc_info(pid: i32) -> Option<ProcInfo> {
    if pid <= 0 {
        return None;
    }
    let mut mib: [libc::c_int; 6] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid,
        std::mem::size_of::<libc::kinfo_proc>() as libc::c_int,
        1,
    ];
    let mut kp: libc::kinfo_proc = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::kinfo_proc>();
    // SAFETY: `kp`/`len` are valid for the duration of the call; MIB is 6 ints.
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

/// OpenBSD 命令行：`sysctl({CTL_KERN, KERN_PROC_ARGS, pid, KERN_PROC_ARGV})`。
///
/// 旧实现只给 `{CTL_KERN, KERN_PROC_ARGS, pid}` **三级**，缺少操作码
/// （`KERN_PROC_ARGV`/`KERN_PROC_ENV`）⇒ 内核返回 `EINVAL`（本波 C 探针实测：
/// 三级 `errno=22`；补上第四级后 `rc=0` 且 argv 正确）。后果是 OpenBSD 上
/// `proc_cmdline()` 恒 None —— pid 复用防线（程序名判据）与启动清理的命令行判据
/// 全部失效。
///
/// 输出布局：`char *argv[]` 指针数组（NULL 结尾）紧跟字符串本体；指针指向**同一块**
/// 输出缓冲区（内核会把指针重定位到用户缓冲区）。
#[cfg(target_os = "openbsd")]
fn proc_cmdline(pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    let mut mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC_ARGS,
        pid,
        libc::KERN_PROC_ARGV,
    ];
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
            return argv_from_openbsd_block(&buf);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

/// 解析 OpenBSD `KERN_PROC_ARGV` 输出块（指针数组 + 字符串）。
#[cfg(target_os = "openbsd")]
fn argv_from_openbsd_block(buf: &[u8]) -> Option<String> {
    let psize = std::mem::size_of::<usize>();
    let base = buf.as_ptr() as usize;
    let mut parts: Vec<String> = Vec::new();
    let mut off = 0usize;
    while off + psize <= buf.len() {
        let mut raw = [0u8; std::mem::size_of::<usize>()];
        raw.copy_from_slice(&buf[off..off + psize]);
        let ptr = usize::from_ne_bytes(raw);
        if ptr == 0 {
            break;
        }
        let Some(start) = ptr.checked_sub(base) else {
            break;
        };
        if start >= buf.len() {
            break;
        }
        let end = buf[start..]
            .iter()
            .position(|b| *b == 0)
            .map(|i| start + i)
            .unwrap_or(buf.len());
        parts.push(String::from_utf8_lossy(&buf[start..end]).into_owned());
        off += psize;
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
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

/// 启动时清理无主孤儿：当没有任何其它存活 webserver 实例时，终止**本仓库**遗留的
/// 引擎子进程（php-fpm / php-cgi / JSP jar / python shim / ruby/rack sidecar /
/// deps/bin/index / go-shm-server / tsx 转译器）。
///
/// 判据 = **路径锚点**（cwd、cwd 下 `www-apps`/`libs`/`target` 的 canonical 路径，
/// 后者让「cwd 是符号链接布局的隔离实例」也能认出命令行里的仓库真实路径）
/// **+ 引擎形态**（可执行文件/脚本是已知引擎产物，或解释器 + 我们的脚本），
/// 不再只看 `php-fpm`/`jsp_sidecar` 这类名字。这样：
///   * `java -jar …/jsp-sidecar.jar --socket …/state/native/…/app.sock`（连字符）命中；
///   * `ruby34: …/www-apps/ruby/sidecar.rb`（setproctitle）命中；
///   * `vim /crucible/www-apps/ruby/sidecar.rb`、别的目录里的同名 `sidecar.rb`
///     不命中（可执行文件不是引擎）。
///
/// 若存在存活 webserver 实例，这些进程归它所有 → 一个都不动（部署环境多实例）。
/// 无存活实例时清理完还会删除 state 下无人监听的 stale socket（进程已死、
/// socket 文件还在），避免下一次 spawn 前复用/误判。
pub fn cleanup_orphans_at_startup() {
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let root = root.canonicalize().unwrap_or(root);
    let self_pid = std::process::id() as i32;

    let Some(text) = ps_all() else {
        return;
    };

    let anchors = owned_anchors(&root);
    let pools = php_pool_names(&root);
    let (live_webserver, mut orphans) = scan_orphan_candidates(&text, &anchors, &pools, self_pid);

    // sock/pidfile 路径判据：受管 sidecar 的 `.envfp` 与 php-fpm 的 `.pid` 都记录了
    // 所有者 pid。命令行被截断/改名时，ps 判据可能认不出，但**我们自己的 state 目录**
    // 里写着 pid —— 活着且命令行仍锚定本仓库就清理。
    for (pid, why) in pidfile_orphan_candidates(&root) {
        if pid != self_pid && !orphans.iter().any(|(p, _)| *p == pid) {
            orphans.push((pid, why));
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
        std::thread::sleep(std::time::Duration::from_millis(500));
        for (pid, cmd) in &orphans {
            if process_running(*pid) {
                log::warn!("child_registry: SIGKILL orphan pid={pid} cmd={cmd}");
                let _ = unsafe { libc::kill(*pid, libc::SIGKILL) };
            }
        }
    }
    if !live_webserver {
        remove_stale_state_sockets(&root);
    }
}

/// 本进程「拥有」的路径锚点（用于启动清理与遗留 sidecar 回收）。
fn owned_anchors(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |p: PathBuf| {
        let s = p.canonicalize().unwrap_or(p).display().to_string();
        if !s.is_empty() && !out.contains(&s) {
            out.push(s);
        }
    };
    push(root.to_path_buf());
    // 仓库布局的已知子目录：cwd 是隔离目录（符号链接到仓库）时，受管 sidecar 命令行
    // 里出现的是 canonical 后的仓库路径 —— 只锚 cwd 会认不出自己的 ruby/jsp 子进程。
    // 生产 cwd=/crucible 时这些与 root 同前缀，无副作用。
    for sub in ["www-apps", "libs", "target", "state"] {
        let p = root.join(sub);
        if p.exists() {
            push(p);
        }
    }
    out
}

/// `state/php/<port>-<idx>.conf` 里的 pool 段名（= php-fpm worker 命令行里的
/// `pool <name>`）。这是唯一能识别「master 已死、worker 仍活着」的路径判据：
/// worker 的 cmdline 不含任何 state 路径。
fn php_pool_names(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root.join("state/php")) else {
        return out;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
                continue;
            };
            let name = name.trim();
            if !name.is_empty() && !name.eq_ignore_ascii_case("global") {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `ps -axww -o pid=,ppid=,command=` 的一行。
struct ProcRow {
    pid: i32,
    ppid: i32,
    cmd: String,
}

fn parse_ps_rows(text: &str) -> Vec<ProcRow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // 列之间是**多个空格**（ps 按宽度补齐）：不能用 `splitn(3, char::is_whitespace)`
        // —— 那会在第二列拿到空串，整张表都被丢掉（本波真机复现：启动清理只剩
        // pidfile 判据在工作，live-instance 检测恒 false，多实例下误杀）。
        let Some((pid_s, rest)) = split_first_token(line) else {
            continue;
        };
        let Some((ppid_s, cmd)) = split_first_token(rest) else {
            continue;
        };
        let (Ok(pid), Ok(ppid)) = (pid_s.parse::<i32>(), ppid_s.parse::<i32>()) else {
            continue;
        };
        rows.push(ProcRow {
            pid,
            ppid,
            cmd: cmd.to_string(),
        });
    }
    rows
}

/// 切出第一个空白分隔的 token，返回 (token, 去掉其后的空白)。
fn split_first_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(char::is_whitespace) {
        Some(pos) => Some((&s[..pos], s[pos..].trim_start())),
        None => Some((s, "")),
    }
}

/// 扫描进程表：返回（是否存在其它存活 webserver 实例，孤儿候选）。
fn scan_orphan_candidates(
    text: &str,
    anchors: &[String],
    pools: &[String],
    self_pid: i32,
) -> (bool, Vec<(i32, String)>) {
    let rows = parse_ps_rows(text);
    let mut live_webserver = false;
    for row in &rows {
        if row.pid != self_pid && cmdline_is_webserver_instance(&row.cmd) {
            live_webserver = true;
        }
    }
    let mut orphans: Vec<(i32, String)> = Vec::new();
    let mut orphan_pids: HashSet<i32> = HashSet::new();
    for row in &rows {
        if row.pid == self_pid {
            continue;
        }
        if is_our_engine_process(&row.cmd, anchors, pools) {
            if orphan_pids.insert(row.pid) {
                orphans.push((row.pid, row.cmd.clone()));
            }
        }
    }
    // php-fpm worker 没有路径锚点（cmdline 只有 `php-fpm: pool <name>`），靠 conf 里的
    // pool 名识别；只在「父 master 也是本仓库的孤儿」或「已被 reparent 到 init」时动手，
    // 避免碰到活着的另一实例的 worker（那种情况上面的 live_webserver 已整体跳过）。
    for row in &rows {
        if row.pid == self_pid || orphan_pids.contains(&row.pid) {
            continue;
        }
        if php_pool_matches(&row.cmd, pools) && (row.ppid == 1 || orphan_pids.contains(&row.ppid)) {
            if orphan_pids.insert(row.pid) {
                orphans.push((row.pid, row.cmd.clone()));
            }
        }
    }
    (live_webserver, orphans)
}

/// 这条命令行是不是**本仓库**的引擎进程（用于启动清理 / 遗留 sidecar 回收）。
fn is_our_engine_process(cmd: &str, anchors: &[String], pools: &[String]) -> bool {
    if php_pool_matches(cmd, pools) {
        return true;
    }
    if anchors.is_empty() || !anchors.iter().any(|a| cmd.contains(a.as_str())) {
        return false;
    }
    let argv0 = cmd.split_whitespace().next().unwrap_or("");
    // OpenBSD 的 setproctitle 形如 `php-fpm-8.4: …` / `ruby34: …`：去掉末尾冒号。
    let prog = argv0
        .trim_end_matches(':')
        .rsplit('/')
        .next()
        .unwrap_or(argv0);

    // 1) 可执行文件/脚本本身就是我们的产物。
    if cmd.contains("/deps/bin/index") || prog == "go-shm-server" {
        return true;
    }
    if prog == "sidecar.rb" || prog == "jsp_sidecar.py" || prog == "jsp_sidecar.sh" {
        return true;
    }
    if cmd.contains("/libs/jsp-sidecar/jsp_sidecar.sh") {
        return true;
    }
    // shebang 执行的脚本（`#!/bin/sh` 包装、`deps/bin/index` 还在 sh 阶段）：
    // argv0 是解释器，脚本路径在后。
    if prog == "sh" || prog == "bash" || prog == "dash" {
        return cmd.contains("/sidecar.rb")
            || cmd.contains("jsp_sidecar.sh")
            || cmd.contains("/deps/bin/index");
    }

    // 2) 解释器 + 我们的脚本/产物（exec 之后进程名变成解释器的情况）。
    if prog.starts_with("php-fpm") || prog.starts_with("php-cgi") {
        // master 的命令行带 `-y /…/state/php/<key>.conf`；worker 由 pool 规则处理。
        return cmd.contains("/state/php/") || cmd.contains("/state/");
    }
    if prog == "java" {
        return cmd.contains("jsp-sidecar.jar");
    }
    if prog.starts_with("ruby") {
        return cmd.contains("/sidecar.rb");
    }
    if prog == "python3" || prog == "python" {
        return cmd.contains("jsp_sidecar.py");
    }
    // node/esbuild/tsc/swc/npx：只认跑我们源码/产物的那些（防误杀编辑器或别的项目）。
    if matches!(prog, "node" | "esbuild" | "tsc" | "swc" | "npx") {
        return cmd.contains("/www-apps/")
            || cmd.contains("/state/tsx")
            || cmd.contains("/target/app-engines/");
    }
    false
}

/// `php-fpm: pool <name>` / `php-fpm-8.4: pool <name>`（name 来自本仓库的 conf）。
fn php_pool_matches(cmd: &str, pools: &[String]) -> bool {
    if pools.is_empty() {
        return false;
    }
    let argv0 = cmd.split_whitespace().next().unwrap_or("").trim_end_matches(':');
    let prog = argv0.rsplit('/').next().unwrap_or("");
    if !(prog.starts_with("php-fpm") || prog.starts_with("php-cgi")) {
        return false;
    }
    pools
        .iter()
        .any(|p| !p.is_empty() && cmd.contains(&format!("pool {p}")))
}

/// 由 state 目录里的 pidfile/指纹文件给出的孤儿候选（补 ps 判据的盲区）。
fn pidfile_orphan_candidates(root: &Path) -> Vec<(i32, String)> {
    let mut out: Vec<(i32, String)> = Vec::new();
    let anchors = owned_anchors(root);
    let pools = php_pool_names(root);
    let self_pid = std::process::id() as i32;

    let mut push = |pid: i32, cmd: String, from: &Path, out: &mut Vec<(i32, String)>| {
        if pid <= 1 || pid == self_pid || !process_running(pid) {
            return;
        }
        if is_our_engine_process(&cmd, &anchors, &pools) {
            out.push((pid, format!("{cmd} [from {}]", from.display())));
        }
    };

    // 受管 native sidecar：state/native/<key>/app.sock.envfp = "v1 <fp> <pid>"
    if let Ok(rd) = std::fs::read_dir(root.join("state/native")) {
        for ent in rd.flatten() {
            let envfp = ent.path().join("app.sock.envfp");
            let Ok(text) = std::fs::read_to_string(&envfp) else {
                continue;
            };
            let mut it = text.split_whitespace();
            if it.next() != Some("v1") {
                continue;
            }
            let _fp = it.next();
            let Some(pid) = it.next().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            if let Some(cmd) = proc_cmdline(pid) {
                push(pid, cmd, &envfp, &mut out);
            }
        }
    }
    // php-fpm master：state/php/<key>.pid（conf 里的 `pid = …` 指向它）。
    if let Ok(rd) = std::fs::read_dir(root.join("state/php")) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("pid") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            let Ok(pid) = text.trim().parse::<i32>() else {
                continue;
            };
            if let Some(cmd) = proc_cmdline(pid) {
                push(pid, cmd, &p, &mut out);
            }
        }
    }
    out
}

/// 启动清理（无存活实例时）删除 state 下**无人监听**的 stale socket：
/// `state/native/*/app.sock`、`state/php/*.sock`、`state/go-ipc/*/notify.sock`。
/// 仍然活着的 socket 一律保留（可能是别的实例/运维进程）。
fn remove_stale_state_sockets(root: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let alive = |p: &Path| UnixStream::connect(p).is_ok();
        for dir in ["state/native", "state/php", "state/go-ipc"] {
            let Ok(rd) = std::fs::read_dir(root.join(dir)) else {
                continue;
            };
            for ent in rd.flatten() {
                let p = ent.path();
                let files: Vec<PathBuf> = if p.is_dir() {
                    match std::fs::read_dir(&p) {
                        Ok(rd2) => rd2
                            .flatten()
                            .map(|e| e.path())
                            .filter(|f| {
                                f.file_name()
                                    .and_then(|s| s.to_str())
                                    .is_some_and(|n| n.ends_with(".sock"))
                            })
                            .collect(),
                        Err(_) => continue,
                    }
                } else if p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.ends_with(".sock"))
                {
                    vec![p]
                } else {
                    continue;
                };
                for sock in files {
                    if alive(&sock) {
                        continue;
                    }
                    if std::fs::remove_file(&sock).is_ok() {
                        log::info!("child_registry: removed stale socket {}", sock.display());
                    }
                    let mut envfp = sock.as_os_str().to_os_string();
                    envfp.push(".envfp");
                    let _ = std::fs::remove_file(PathBuf::from(envfp));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = root;
    }
}

/// 杀掉一个**不属于本进程**、但确实是我们这个受管 socket 上一代遗留的 sidecar。
///
/// 触发点：`sock_alive()` 为真且 `.envfp` 指纹一致 —— 旧实现直接复用，于是上一代
/// webserver 留下的进程（SIGKILL 后 reparent / 关机漏杀）被新实例永久沿用，
/// 「skip …（已退出）却复用 socket」正是这条路径（deploy2b §5.3 / deploy3 §4.3）。
///
/// 防误杀：必须同时满足 ①pid 存活且**不是**本进程直系子进程；②命令行含本 sock 的
/// 绝对路径，或锚定在 sock 所属 state 根上；③命令行是已知引擎形态。
pub(crate) fn kill_stale_managed_sidecar(pid: i32, sock: &Path) -> bool {
    if pid <= 1 || pid == std::process::id() as i32 {
        return false;
    }
    if pid_is_direct_child(pid) {
        return false; // 是本进程的：交给注册表的 kill_child（能 wait 回收）
    }
    if !process_running(pid) {
        return false;
    }
    let Some(cmd) = proc_cmdline(pid) else {
        return false;
    };
    let Some(root) = sock_state_root(sock) else {
        return false;
    };
    let anchors = owned_anchors(&root);
    let pools = php_pool_names(&root);
    let anchored_here = cmd.contains(&sock.display().to_string())
        || anchors.iter().any(|a| cmd.contains(a.as_str()));
    if !anchored_here || !is_our_engine_process(&cmd, &anchors, &pools) {
        log::warn!(
            "child_registry: stale sidecar pid={pid} 命令行与 {} 不符，不动它: {cmd}",
            sock.display()
        );
        return false;
    }
    log::warn!(
        "child_registry: killing stale sidecar pid={pid}（上一代遗留，拒绝复用 socket {}）",
        sock.display()
    );
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..40 {
        if !process_running(pid) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    true
}

/// 全表搜索：命令行包含 `needle` 的 pid（仅引擎 spawn 前的上一代遗留回收用）。
///
/// 调用方必须再用 `cmdline(pid)` 复核程序形态并确认不是本进程直系子进程；
/// 本函数只做「按命令行里的绝对路径缩小候选」。
pub(crate) fn pids_with_cmdline(needle: &str) -> Vec<i32> {
    if needle.is_empty() {
        return Vec::new();
    }
    let Some(text) = ps_all() else {
        return Vec::new();
    };
    parse_ps_rows(&text)
        .into_iter()
        .filter(|r| r.pid > 1 && r.cmd.contains(needle))
        .map(|r| r.pid)
        .collect()
}

/// 受管 UDS 路径 → 所属 state 根（`…/state/native/<key>/app.sock` → `…`）。
fn sock_state_root(sock: &Path) -> Option<PathBuf> {
    let s = sock.to_string_lossy();
    let idx = s.find("/state/")?;
    Some(PathBuf::from(&s[..idx]))
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
    let mut tokens = cmd.split_whitespace();
    let Some(argv0) = tokens.next() else {
        return false;
    };
    // **argv0 必须是 webserver 自身**。旧实现是「任意 token 以 /webserver 结尾 +
    // 任意 token 是 -c/--config」——于是任何外壳命令行都会误命中，例如
    //   `bash -c '… /crucible/target/release/webserver …'`（`-c` 是 shell 自己的旗标）
    // 或 `timeout 900 python3 test.py /path/webserver`。
    // 误判 = 「另一个实例活着」= 启动清理整体跳过 = 真孤儿没人收（本波在共享测试机
    // 上实测复现：harness 的 bash 壳让每次 SIGKILL 重启都跳过清理）。真正的
    // webserver 进程 argv0 就是它自己，wrapper/shell 不可能是「存活实例」。
    let base = argv0
        .trim_end_matches(':')
        .rsplit('/')
        .next()
        .unwrap_or(argv0);
    if base != "webserver" {
        return false;
    }
    tokens.any(|t| t == "-c" || t == "--config" || t.starts_with("--config="))
}

/// `ps -axww -o pid=,ppid=,command=` 全量列表（**仅启动期孤儿枚举**用）。
///
/// 这里刻意保留 ps：`-axww -o …=` 在 Linux procps 与 OpenBSD ps 上语义一致
///（枚举全表），O12 的问题出在 `-p` 选择项与 `-a/-x` 的并集语义。
/// 判活/身份核对已全部改为 `kill(2)` + `/proc` / `kinfo_proc`，不再调用
/// `ps -p`。`ppid` 用于识别 php-fpm pool worker（命令行不含路径，只能靠
/// 「父 master 也是本仓库孤儿」或「已被 reparent」判定）。
fn ps_all() -> Option<String> {
    let out = Command::new("ps")
        .arg("-axww")
        .arg("-o")
        .arg("pid=,ppid=,command=")
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

    /// Spawn a long-lived, already-reparented process whose command line contains a
    /// token with basename `name`.
    ///
    /// A shell **script** is used on purpose: Ubuntu's coreutils may be built as a
    /// multi-call binary, so `exec -a php-fpm sleep 30` dies immediately with
    /// "unknown program 'php-fpm'" (making the "same program name" precondition
    /// racy). The script's own `/proc/<pid>/cmdline` is
    /// `/bin/sh /tmp/…/<name>`, which contains the token deterministically.
    #[cfg(any(target_os = "linux", target_os = "openbsd"))]
    fn spawn_reparented_named_sleeper(name: &str) -> (i32, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("crucible-childreg-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let script = dir.join(name);
        std::fs::write(&script, "#!/bin/sh\nwhile :; do sleep 1; done\n")
            .expect("write helper script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod helper script");
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("{} >/dev/null 2>&1 & echo $!", script.display()))
            .output()
            .expect("spawn external process");
        let pid = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("external pid");
        (pid, dir)
    }

    /// 真机行为：kill_all 只杀自己直系子进程；一个**非直系且同名**的外部进程
    /// （pid 复用场景）即使登记在表里、程序名完全一致，只要启动时间对不上就不能被误杀。
    /// 启动时间是 pid 复用判据的主防线；同名只是第二道防线。
    #[cfg(any(target_os = "linux", target_os = "openbsd"))]
    #[test]
    fn kill_all_spares_reused_external_pid() {
        let _g = TEST_LOCK.lock();
        let (ext_pid, dir) = spawn_reparented_named_sleeper("php-fpm");
        let info = proc_info(ext_pid).expect("external proc info");
        // 等到它不再是本测试进程的直接子进程。
        for _ in 0..200 {
            if proc_info(ext_pid).map(|i| i.ppid) != Some(std::process::id() as i32) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // 前提确认：命令行里确实有 "php-fpm"（否则这条测试没有覆盖同名场景）。
        let cmdline = proc_cmdline(ext_pid).unwrap_or_default();
        assert!(
            command_contains_program(&cmdline, "php-fpm"),
            "外部进程命令行应含登记名: {cmdline}"
        );
        // 正对照：启动时间一致 ⇒ 身份确实是当初 spawn 的那个进程（可以被 kill_all 杀）。
        assert!(
            alive_and_matches(ext_pid, "php-fpm", Some(info.start)),
            "启动时间一致时同一进程应匹配"
        );
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
            "启动时间对不上（pid 已被复用）时，同名外部进程也不能被 kill_all 误杀"
        );
        let _ = unsafe { libc::kill(ext_pid, libc::SIGKILL) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 程序名判据**独立于**启动时间：一个非直系外部进程即便启动时间对得上
    /// （例如登记时读到的是它），只要命令行里的 token basename 与登记程序名不符，
    /// 也不能发信号。`kill_all` 的两道防线（启动时间、程序名）必须各自可用，
    /// 不能只靠其中一道。
    #[cfg(any(target_os = "linux", target_os = "openbsd"))]
    #[test]
    fn external_process_with_other_program_name_is_spared() {
        let (ext_pid, dir) = spawn_reparented_named_sleeper("other-daemon");
        for _ in 0..200 {
            if proc_info(ext_pid).map(|i| i.ppid) != Some(std::process::id() as i32) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let info = proc_info(ext_pid).expect("external proc info");
        // 启动时间**完全一致**（模拟「这个 pid 确实是我们当年 spawn 的那个」），
        // 但登记的程序名不同 ⇒ 名字判据必须拒绝，绝不能误杀。
        assert!(
            !alive_and_matches(ext_pid, "php-fpm", Some(info.start)),
            "非直系进程且程序名不符时必须拒绝发信号"
        );
        // 正对照：同一条记录若程序名写成 cmdline 里真实存在的 token，判据为真
        // （说明上面的 false 确实来自程序名，而不是启动时间/ppid 的副作用）。
        assert!(
            alive_and_matches(ext_pid, "other-daemon", Some(info.start)),
            "启动时间一致且程序名匹配时（模拟登记过的 daemon）应认为仍是同一进程"
        );
        let _ = unsafe { libc::kill(ext_pid, libc::SIGKILL) };
        let _ = std::fs::remove_dir_all(&dir);
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
            // 外壳/测试命令行里出现 webserver 路径 + 自己的 `-c`：**不是**活实例。
            // 误判会让启动清理整体跳过（真孤儿没人收）。
            "/bin/bash -c . '/x/snapshot.sh' 2>/dev/null || timeout 900 python3 orphan_test.py /home/u/crucible/target-base/release/webserver sigkill 3",
            "timeout 900 python3 orphan_test.py /home/u/crucible/target/release/webserver",
            "sh -c /crucible/bin/webserver --config /crucible/config.toml",
            "/usr/bin/tail -f /crucible/target/release/webserver -c 10",
        ] {
            assert!(!cmdline_is_webserver_instance(cmd), "不应判为存活实例: {cmd}");
        }
    }

    /// 启动清理必须认识生产上的全部 sidecar 形态（deploy3-wave19 §4.3 的漏网清单：
    /// `java -jar …/jsp-sidecar.jar`、`ruby34: …/www-apps/*/sidecar.rb`）。
    #[test]
    fn startup_matcher_recognizes_all_remote_sidecar_forms() {
        let anchors = vec!["/crucible".to_string()];
        let pools = vec!["9095-0".to_string()];
        for cmd in [
            "/usr/local/jdk-17/bin/java -jar /crucible/libs/jsp-sidecar/target/jsp-sidecar.jar --socket /crucible/state/native/9095-7-jsp/app.sock --docroot /crucible/www-apps/jsp",
            "ruby34: /crucible/www-apps/ruby/sidecar.rb (ruby34)",
            "/usr/local/bin/ruby34 /crucible/www-apps/rack/sidecar.rb",
            "php-fpm-8.4: master process (/crucible/state/php/9095-0.conf) (php-fpm-8.4)",
            "php-fpm-8.4: pool 9095-0 (php-fpm-8.4)",
            "/crucible/target/app-engines/go-shm-server",
            "/crucible/www-apps/go/deps/bin/index",
            "/crucible/www-apps/ruby/deps/bin/index",
            "python3 /crucible/libs/jsp-sidecar/jsp_sidecar.py --socket /crucible/state/native/x/app.sock --docroot /crucible/www-apps/jsp",
            "/bin/sh /crucible/libs/jsp-sidecar/jsp_sidecar.sh /crucible/state/native/x/app.sock /crucible/www-apps/jsp",
            "/usr/bin/esbuild /crucible/www-apps/tsx/index.tsx --outdir=/crucible/state/tsx",
        ] {
            assert!(
                is_our_engine_process(cmd, &anchors, &pools),
                "必须识别为本仓库引擎进程: {cmd}"
            );
        }
    }

    /// 反向：同名但**不在本仓库路径下**的进程、以及只是「命令行里提到了文件」的
    /// 编辑器/分页器，一律不能动（部署环境多实例；手工起的同名 sidecar）。
    #[test]
    fn startup_matcher_spares_foreign_same_name_processes() {
        let anchors = vec!["/crucible".to_string()];
        let pools = vec!["9095-0".to_string()];
        for cmd in [
            "ruby34: /opt/otherapp/sidecar.rb (ruby34)",
            "/usr/local/bin/ruby34 /home/other/www-apps/rack/sidecar.rb",
            "php-fpm-8.4: master process (/etc/php-fpm.d/www.conf)",
            "php-fpm-8.4: pool www",
            "/usr/local/jdk-17/bin/java -jar /opt/other/jsp-sidecar.jar --socket /tmp/x.sock",
            "python3 /opt/other/jsp_sidecar.py --socket /tmp/y.sock",
            "vim /crucible/www-apps/ruby/sidecar.rb",
            "grep -r sidecar.rb /crucible/www-apps",
            "tail -f /crucible/state/native/9095-7-jsp/sidecar.log",
            "/usr/bin/esbuild /home/other/app.ts --outdir=/tmp/out",
        ] {
            assert!(
                !is_our_engine_process(cmd, &anchors, &pools),
                "绝不能误杀: {cmd}"
            );
        }
    }

    /// pool 名来自本仓库 `state/php/*.conf` 的段名；这是唯一能认出「master 已死、
    /// worker 仍活着」的判据（worker 命令行不含任何路径）。
    #[test]
    fn php_pool_names_reads_conf_sections() {
        let dir = std::env::temp_dir().join(format!("crucible-pools-{}", std::process::id()));
        let state = dir.join("state/php");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("9095-0.conf"),
            "[global]\npid = /x/9095-0.pid\n\n[9095-0]\npm = static\n",
        )
        .unwrap();
        std::fs::write(
            state.join("9095-1.conf"),
            "[global]\n\n[9095-1]\npm = static\n",
        )
        .unwrap();
        std::fs::write(state.join("notes.txt"), "[not-a-conf]\n").unwrap();
        assert_eq!(php_pool_names(&dir), vec!["9095-0", "9095-1"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `owned_anchors` 必须跟随符号链接到真实仓库路径：隔离实例的 cwd 是 scratch
    /// 目录（`www-apps` 等是符号链接），受管 sidecar 命令行里出现的是 canonical
    /// 之后的仓库路径 —— 只锚 cwd 会认不出自己的子进程。
    #[cfg(unix)]
    #[test]
    fn owned_anchors_follow_symlinked_layout() {
        let base = std::env::temp_dir().join(format!("crucible-anchors-{}", std::process::id()));
        let root = base.join("run");
        let real = base.join("repo");
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::create_dir_all(real.join("www-apps")).unwrap();
        std::os::unix::fs::symlink(real.join("www-apps"), root.join("www-apps")).unwrap();
        let anchors = owned_anchors(&root);
        let want = real.join("www-apps").canonicalize().unwrap().display().to_string();
        assert!(anchors.contains(&want), "anchors={anchors:?} want {want}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `is_direct_child` 的最小判据（ps -o ppid= -p）与 spawn 语义一致。
    #[cfg(unix)]
    #[test]
    fn is_direct_child_sees_spawned_child_only() {
        let mut child = Command::new("sleep").arg("5").spawn().expect("spawn sleep");
        let pid = child.id() as i32;
        assert!(is_direct_child(pid), "自己 spawn 的子进程必须认出");
        assert!(!is_direct_child(1), "pid 1 不是我们的子进程");
        assert!(
            !is_direct_child(std::process::id() as i32),
            "自己不是自己的子进程"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// 启动扫描：孤儿候选按「路径 + 引擎形态」命中；另一个存活 webserver 实例
    /// 会被识别（调用方据此整体跳过清理）。
    #[test]
    fn startup_scan_detects_orphans_and_live_instance() {
        let anchors = vec!["/crucible".to_string()];
        let pools = vec!["9095-0".to_string()];
        // 注意列之间的**多个空格**（ps 按宽度补齐）：这正是曾经让整张表被丢弃的形态。
        let text = "\
            10     1 /usr/local/jdk-17/bin/java -jar /crucible/libs/jsp-sidecar/target/jsp-sidecar.jar --socket /crucible/state/native/9095-7-jsp/app.sock\n\
            11     1 ruby34: /crucible/www-apps/ruby/sidecar.rb (ruby34)\n\
            12    10 php-fpm-8.4: pool 9095-0 (php-fpm-8.4)\n\
            13     1 /usr/bin/vim /crucible/config.toml\n";
        let (live, orphans) = scan_orphan_candidates(text, &anchors, &pools, 999);
        assert!(!live, "没有 webserver 实例");
        let pids: Vec<i32> = orphans.iter().map(|(p, _)| *p).collect();
        assert_eq!(pids, vec![10, 11, 12], "孤儿={orphans:?}");

        let text2 = "\
            20     1 /crucible/bin/webserver --config /crucible/config.toml\n\
            10     1 ruby34: /crucible/www-apps/ruby/sidecar.rb (ruby34)\n";
        let (live, orphans) = scan_orphan_candidates(text2, &anchors, &pools, 999);
        assert!(live, "必须识别出另一个存活实例");
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].0, 10);
    }

    /// stale socket：无人监听（connect 失败）才删；仍然活着的 socket 保留。
    #[cfg(unix)]
    #[test]
    fn stale_socket_removal_only_removes_dead_sockets() {
        let root = std::env::temp_dir().join(format!("crucible-socks-{}", std::process::id()));
        let native = root.join("state/native/k");
        std::fs::create_dir_all(&native).unwrap();
        let dead = native.join("app.sock");
        std::fs::write(&dead, b"").unwrap();
        let live = root.join("state/php/live.sock");
        std::fs::create_dir_all(live.parent().unwrap()).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&live).unwrap();
        remove_stale_state_sockets(&root);
        assert!(!dead.exists(), "死 socket 必须删除");
        assert!(live.exists(), "活 socket 不能删");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 上一代遗留的受管 sidecar：不是本进程子进程，但命令行锚定在本 sock 的 state
    /// 根上 ⇒ 杀掉；别的目录里的同名脚本 ⇒ 一根毫毛都不动。
    #[cfg(unix)]
    #[test]
    fn stale_sidecar_kill_is_path_anchored() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("crucible-stale-{}", std::process::id()));
        let root = base.join("repo");
        let state = root.join("state/native/k");
        std::fs::create_dir_all(&state).unwrap();
        let sock = state.join("app.sock");

        let ours = root.join("www-apps/ruby/sidecar.rb");
        std::fs::create_dir_all(ours.parent().unwrap()).unwrap();
        std::fs::write(&ours, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
        std::fs::set_permissions(&ours, std::fs::Permissions::from_mode(0o755)).unwrap();

        let foreign = base.join("other/sidecar.rb");
        std::fs::create_dir_all(foreign.parent().unwrap()).unwrap();
        std::fs::write(&foreign, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o755)).unwrap();

        let spawn_reparented = |p: &std::path::Path| -> i32 {
            let out = Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("{} >/dev/null 2>&1 & echo $!", p.display()))
                .output()
                .expect("spawn detached");
            let pid: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
            for _ in 0..200 {
                if !pid_is_direct_child(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            pid
        };

        let foreign_pid = spawn_reparented(&foreign);
        let ours_pid = spawn_reparented(&ours);
        assert!(
            !kill_stale_managed_sidecar(foreign_pid, &sock),
            "别的目录里的同名 sidecar 不能杀"
        );
        assert!(process_alive(foreign_pid), "外部同名进程必须存活");
        assert!(
            kill_stale_managed_sidecar(ours_pid, &sock),
            "本仓库 state 根下的遗留 sidecar 必须回收"
        );
        let mut gone = false;
        for _ in 0..100 {
            if !process_running(ours_pid) {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(gone, "遗留 sidecar 必须被终止");
        let _ = unsafe { libc::kill(foreign_pid, libc::SIGKILL) };
        let _ = std::fs::remove_dir_all(&base);
    }
}
