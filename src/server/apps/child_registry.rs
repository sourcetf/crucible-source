//! Child process registry：跟踪 php-fpm / sidecar / go-shm-server 等子进程。
//! 退出时统一 kill 防止孤儿堆积。

use anyhow::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::process::Command;

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

/// 启动时清理上一代崩溃残留的子进程。
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