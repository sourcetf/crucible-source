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

static REGISTRY: Lazy<Mutex<HashMap<i32, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn register(pid: i32, name: &str) {
    REGISTRY.lock().insert(pid, name.to_string());
}

pub fn unregister(pid: i32) {
    REGISTRY.lock().remove(&pid);
}

/// 终止所有已注册子进程（SIGTERM → 短等 → SIGKILL）。
/// 在 spawn_blocking 中调用（内含 thread::sleep）。
pub fn kill_all() {
    let entries: Vec<(i32, String)> = REGISTRY
        .lock()
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    for (pid, name) in &entries {
        log::info!("child_registry: SIGTERM {name} pid={pid}");
        let _ = unsafe { libc::kill(*pid, libc::SIGTERM) };
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

/// 杀死 Child 并从注册表注销（用于替换/移除 runtime 时）。
/// 先 SIGTERM 让 fpm/sidecar 优雅退出并清理 socket，再 SIGKILL 兜底。
pub fn kill_child(child: &mut Child) {
    let pid = child.id() as i32;
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
        // 其它存活 webserver 实例（含测试实例）拥有这些 sidecar → 跳过清理
        if cmd.contains("webserver") && cmd.contains("--config") {
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

/// `ps -axww -o pid=,command=` 全量列表。
fn ps_all() -> Option<String> {
    let out = Command::new("ps")
        .arg("-axww")
        .arg("-o")
        .arg("pid=,command=")
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn ps_command(pid: i32) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_register_unregister_roundtrip() {
        register(999999, "test");
        assert!(REGISTRY.lock().contains_key(&999999));
        unregister(999999);
        assert!(!REGISTRY.lock().contains_key(&999999));
    }
}
