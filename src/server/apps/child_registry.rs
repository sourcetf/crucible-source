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

/// pid -> (逻辑名, 程序名)。程序名用于退出时按 pid 复核命令行 —— OpenBSD 无 /proc，
/// 长运行期里 pid 会被复用，只凭 pid 发信号可能杀掉一个无关进程
///（`kill_if_matches`/`tor_pid` 早就这么做，`kill_all` 此前没有）。
static REGISTRY: Lazy<Mutex<HashMap<i32, (String, String)>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn register(pid: i32, name: &str) {
    REGISTRY.lock().insert(pid, (name.to_string(), String::new()));
}

/// spawn 时用这个：额外记录**程序名**，供退出时复核。
fn register_with_program(pid: i32, name: &str, program: &str) {
    let base = std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| program.to_string());
    REGISTRY.lock().insert(pid, (name.to_string(), base));
}

/// pid 还活着、且命令行里仍能看到当初记录的程序名（没记录程序名则退回「还活着就动手」）。
fn alive_and_matches(pid: i32, program: &str) -> bool {
    if pid <= 1 {
        return false;
    }
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false; // 已退出
    }
    if program.is_empty() {
        return true; // 旧式注册（无程序名）→ 保持旧行为
    }
    match ps_command(pid) {
        Some(cmd) => cmd.contains(program),
        None => false,
    }
}

pub fn unregister(pid: i32) {
    REGISTRY.lock().remove(&pid);
}

/// 终止所有已注册子进程（SIGTERM → 短等 → SIGKILL）。
/// 在 spawn_blocking 中调用（内含 thread::sleep）。
pub fn kill_all() {
    let entries: Vec<(i32, String, String)> = REGISTRY
        .lock()
        .iter()
        .map(|(k, v)| (*k, v.0.clone(), v.1.clone()))
        .collect();
    for (pid, name, prog) in &entries {
        // pid 复用防线：命令行里仍能看到当初记的程序名才动手。
        if !alive_and_matches(*pid, prog) {
            if prog.is_empty() {
                log::info!("child_registry: skip {name} pid={pid}（已退出）");
            } else {
                log::warn!(
                    "child_registry: skip {name} pid={pid}（pid 已被复用或已退出，命令行无 {prog}）"
                );
            }
            continue;
        }
        log::info!("child_registry: SIGTERM {name} pid={pid}");
        let _ = unsafe { libc::kill(*pid, libc::SIGTERM) };
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    for (pid, name, prog) in &entries {
        if alive_and_matches(*pid, prog) {
            log::warn!("child_registry: SIGKILL {name} pid={pid}");
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

    /// pid 复用防线：`alive_and_matches` 对**不存在的 pid** 必须为假（不能盲目发信号），
    /// 对「记录了程序名但命令行读不到」也必须是假。
    /// 真机教训：长运行期里 php 被反复重启、旧 pid 永久留在表里，退出时可能杀掉复用者。
    #[test]
    fn kill_all_matches_guard_semantics() {
        assert!(!alive_and_matches(999999, "php-fpm"), "不存在的 pid 不能算匹配");
        assert!(!alive_and_matches(1, "php-fpm"), "pid<=1 必须拒绝");
        // 自身进程：命令行里肯定不含 "php-fpm" ⇒ 也必须为假（这是防误杀的关键一条）
        let me = std::process::id() as i32;
        assert!(
            !alive_and_matches(me, "php-fpm"),
            "命令行不含程序名时不能动手（否则就是误杀）"
        );
        // 记录为空串（旧式 register）⇒ 退回旧行为：活着即 true
        assert!(alive_and_matches(me, ""), "旧式注册应保持旧行为");
    }
}
