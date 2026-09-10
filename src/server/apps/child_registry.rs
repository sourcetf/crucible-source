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
use parking_lot::Mutex;
use std::collections::HashMap;
use std::process::{Child, Command};

static CHILD_REGISTRY: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, u32>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// 启动跟踪的子进程。key 为 php-fpm port / sidecar key 等唯一标识。
/// 返回的 Child 由调用方持有，`kill_on_drop(true)` 确保进程退出时自动清理。
pub fn spawn_tracked(cmd: &mut Command, key: &str) -> Result<tokio::process::Child> {
    let mut child = cmd.spawn()?;
    // 进程退出时自动 kill，防止僭居子进程。
    child.kill_on_drop(true);
    if let Some(pid) = child.id() {
        CHILD_REGISTRY.lock().insert(key.to_string(), pid);
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    for (pid, name) in &entries {
        if unsafe { libc::kill(*pid, 0) } == 0 {
            log::warn!("child_registry: SIGKILL {name} pid={pid}");
            let _ = unsafe { libc::kill(*pid, libc::SIGKILL) };
        }
    }
    REGISTRY.lock().clear();
}

/// spawn 并注册。注意：`Child` 被 drop 不会终止进程，生命周期靠 registry 兜底。
pub fn spawn_tracked(cmd: &mut Command, name: &str) -> Result<Child> {
    let child = cmd.spawn()?;
    register(child.id() as i32, name);
    Ok(child)
}

/// 退出时 kill 所有注册子进程（兜底；正常由 kill_on_drop 处理）。
pub fn kill_all() {
    let mut guard = CHILD_REGISTRY.lock();
    for (key, pid) in guard.drain() {
        let _ = kill_by_pid(pid);
        log::debug!("killed child {} (pid {pid}) on shutdown", key);
    }
}

/// 用进程 ID 发 SIGTERM。
fn kill_by_pid(pid: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
    #[cfg(not(unix))]
    {
        // Windows：无法通过 PID 发信号；进程终止由子进程自身处理。
        let _ = pid;
        Ok(())
    }
}

/// 若 pid 存活且命令行包含 `expect`，则终止之（防 pid 复用误杀）。
pub fn kill_if_matches(pid: i32, expect: &str) {
    if pid <= 1 {
        return;
    }
    if unsafe { libc::kill(pid, 0) } != 0 {
        return; // 已退出
    }
    let Some(cmdline) = ps_command(pid) else {
        return;
    };
    if !cmdline.contains(expect) {
        return;
    }
    log::info!("child_registry: killing stale pid={pid} cmd={cmdline}");
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    std::thread::sleep(std::time::Duration::from_millis(150));
    if unsafe { libc::kill(pid, 0) } == 0 {
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// 启动时清理无主孤儿：当没有任何其它存活 webserver 实例时，
/// 终止引用本仓库 state/ 目录或 app-engines 二进制的遗留进程。
/// （若存在存活实例，这些进程归它所有，不动。）
pub fn cleanup_orphans_at_startup() {
    let state_dir = match std::env::current_dir() {
        Ok(d) => d.join("state"),
        Err(_) => return,
    };
    let php_dir = state_dir.join("php");
    if !php_dir.is_dir() {
        return;
    }
    // 读取目录（忽略错误）
    let entries = match std::fs::read_dir(&php_dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "pid").unwrap_or(false) {
            let _ = cleanup_pid_file(&path);
        }
    }
}

fn cleanup_pid_file(pid_path: &std::path::Path) -> Result<()> {
    let pid_str = std::fs::read_to_string(pid_path)?;
    if let Ok(pid) = pid_str.trim().parse::<i32>() {
        // 发送 SIGTERM；如果进程存活则清理，否则仅删文件
        #[cfg(unix)]
        {
            if unsafe { libc::kill(pid, 0) == 0 } {
                unsafe { libc::kill(pid, libc::SIGTERM) };
            }
        }
    }
    let _ = std::fs::remove_file(pid_path);
    Ok(())
}