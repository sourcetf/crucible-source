//! Child process registry：跟踪 php-fpm / sidecar / go-shm-server 等子进程。
//! 退出时统一 kill 防止孤儿堆积。

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::process::Command;

static CHILD_REGISTRY: once_cell::sync::Lazy<tokio::sync::Mutex<ChildInfo>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(ChildInfo::default()));

#[derive(Default)]
struct ChildInfo {
    slots: HashMap<String, tokio::process::Child>,
    keys: Vec<String>,
}

/// 启动跟踪的子进程。key 为 php-fpm port / sidecar key 等唯一标识。
pub fn spawn_tracked(mut cmd: &mut Command, key: &str) -> Result<tokio::process::Child> {
    let child = cmd.spawn()?;
    let key = key.to_string();
    tokio::spawn(async move {
        if let Err(e) = child.wait().await {
            log::warn!("child {} exited: {e}", key);
        }
        let mut guard = CHILD_REGISTRY.blocking_lock();
        guard.slots.remove(&key);
        guard.keys.retain(|k| k != &key);
    });
    {
        let mut guard = CHILD_REGISTRY.blocking_lock();
        guard.slots.insert(key.clone(), child.id().map(|_| child).unwrap());
        guard.keys.push(key);
    }
    Ok(child)
}

/// 退出时 kill 所有注册子进程。
pub fn kill_all() {
    let mut guard = CHILD_REGISTRY.blocking_lock();
    for (key, mut child) in guard.slots.drain() {
        let _ = child.kill();
        log::debug!("killed child {} on shutdown", key);
    }
    guard.keys.clear();
}

/// 启动时清理上一代崩溃残留的子进程。
pub fn cleanup_orphans_at_startup() {
    // 在 OpenBSD，named / php-fpm 等进程可能是上一代 crash 的残留。
    // 检查常见的 pid 文件并 kill。
    let state_dir = std::env::current_dir()
        .map(|d| d.join("state"))
        .ok();
    if let Some(state_dir) = state_dir {
        // 清理 php-fpm pid 文件
        if let Some(php_dir) = state_dir.join("php").if_exists() {
            for entry in std::fs::read_dir(php_dir).ok() {
                if let Ok(e) = entry {
                    if let Some(pid_file) = e.path().extension().filter(|e| e == "pid") {
                        let _ = cleanup_pid_file(e.path().parent().unwrap_or(&e.path()));
                    }
                }
            }
        }
    }
}

trait PathExt {
    fn if_exists(&self) -> Option<std::path::PathBuf>;
}

impl PathExt for std::path::PathBuf {
    fn if_exists(&self) -> Option<std::path::PathBuf> {
        if self.exists() { Some(self.clone()) } else { None }
    }
}

fn cleanup_pid_file(dir: &std::path::Path) -> Result<()> {
    use std::io::Read;
    let pid_files: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "pid").unwrap_or(false))
        .collect();
    for pf in pid_files {
        let mut file = std::fs::File::open(pf.path())?;
        let mut pid_str = String::new();
        file.read_to_string(&mut pid_str)?;
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            // 发送 SIGTERM 给进程
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        }
        std::fs::remove_file(pf.path())?;
    }
    Ok(())
}
