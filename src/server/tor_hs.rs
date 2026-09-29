//! Hidden Service（站点 .onion 入站；早期规格 A.3）。
//!
//! 独立 tor 进程：`SocksPort 0`（故意不开出站 SOCKS —— HS 不出站，避免与反代出站策略
//! 搅在一起）；`HiddenServiceDir` 由配置指定；启动后读 hostname 文件得到 `.onion` 名，
//! 写 `state/tor-hs/hostname.log` 供面板显示。
//!
//! 反代**出站**走 `proxy.rs::connect_tor_socks`（FFI → UDS → loopback SOCKS），
//! 不复用本 torrc —— 两者是独立的两条链路。
//!
//! # 本轮的修复（此前这份实现**完全没接线**）
//!
//! * `spawn_from_config` 全树零调用点（`mod.rs` 里只有一句 "tor_hs removed" 的注释，
//!   而文件明明存在）⇒ 配 `[tor_hs] enabled = true` **什么都不会发生**，且无任何告警。
//! * `state_dir()` 返回**相对路径** `state/tor-hs`，是全仓库唯一没绝对化的 state 目录
//!   ⇒ cwd 漂移（rc.d 的工作目录、手工 cd 启动）会把 HS 密钥写错地方，而 tor 的
//!   hostname 就在那里面。现在用 `current_dir()` 绝对化（与 dns/ech_auto 一致）。
//! * `tor` 进程非零退出（未安装 / torrc 非法）此前被忽略，只是干等 30s 然后报
//!   "hostname not generated in time" —— 掩盖了真正的原因。现在直接报退出码 + notice.log 末尾。

use crate::config::TorHsConfig;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

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

/// 启动 HS tor（若未在跑）：写 torrc → `--RunAsDaemon` → 轮询 hostname 文件。
///
/// 幂等：hostname 已存在且非空则直接复用它（不重启 tor）。
pub async fn ensure_hs(cfg: &TorHsConfig) -> Result<String> {
    if cfg.ports.is_empty() {
        bail!("tor_hs: [tor_hs].ports 为空 —— 至少需要一条 (虚拟端口, 本地端口)");
    }
    for (virt, local) in &cfg.ports {
        if *virt == 0 || *local == 0 {
            bail!("tor_hs: 端口不能为 0（virt={virt} local={local}）");
        }
    }
    let dir = state_dir();
    let hs_dir = hs_data_dir(cfg);
    std::fs::create_dir_all(&hs_dir).with_context(|| format!("create {}", hs_dir.display()))?;
    std::fs::create_dir_all(dir.join("data")).context("create tor-hs data dir")?;

    let hostname_file = hs_dir.join("hostname");
    if hostname_file.is_file() {
        let existing = std::fs::read_to_string(&hostname_file)?.trim().to_string();
        if !existing.is_empty() {
            log::info!("tor_hs: 复用已有 HS {existing}");
            let _ = std::fs::write(dir.join("hostname.log"), format!("{existing}\n"));
            return Ok(existing);
        }
    }

    let tor = cfg.tor_bin.clone().unwrap_or_else(|| "tor".into());
    let mut torrc = format!(
        "SocksPort 0\nDataDirectory {}\nHiddenServiceDir {}\n",
        dir.join("data").display(),
        hs_dir.display()
    );
    for (virt, local) in &cfg.ports {
        torrc.push_str(&format!("HiddenServicePort {virt} 127.0.0.1:{local}\n"));
    }
    let torrc_path = dir.join("torrc");
    std::fs::write(&torrc_path, torrc)
        .with_context(|| format!("write {}", torrc_path.display()))?;

    let pidfile = dir.join("pid");
    let status = tokio::process::Command::new(&tor)
        .arg("-f")
        .arg(&torrc_path)
        .arg("--RunAsDaemon")
        .arg("1")
        .arg("--PidFile")
        .arg(&pidfile)
        .status()
        .await
        .with_context(|| {
            format!(
                "启动 tor 失败（tor_bin={tor}）：请确认已安装 tor，或用 [tor_hs].tor_bin 指定路径"
            )
        })?;
    // 退出码必须看：tor 未安装 / torrc 非法 / 端口被占时它会立刻退出，
    // 旧实现忽略退出码 ⇒ 干等 30s 后报「hostname not generated in time」，把真因埋掉。
    if !status.success() {
        let tail = std::fs::read_to_string(dir.join("data").join("notice.log"))
            .ok()
            .map(|s| {
                let lines: Vec<&str> = s.lines().rev().take(5).collect();
                lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
            })
            .unwrap_or_default();
        bail!(
            "tor 进程以 {:?} 退出（torrc={}）。tor 的 notice.log 末尾: {}",
            status.code(),
            torrc_path.display(),
            if tail.is_empty() { "（无）" } else { &tail }
        );
    }

    // 等待 onion 生成（首次建 HS 密钥可能 ~10-30s）
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
        "tor_hs: 等待 30s 仍未生成 hostname（{}）—— 检查 data/notice.log",
        hostname_file.display()
    )
}

/// 面板/启动钩子：读 `[tor_hs]` 配置并确保 HS 运行；错误仅记录不中断服务。
///
/// **调用点**（此前一个都没有）：`server::run` 的启动路径 + 配置热重载路径。
/// `ensure_hs` 幂等，所以热重载重复调用是安全的（hostname 存在即复用，不会重启 tor）。
pub fn spawn_from_config(hs: crate::config::TorHsConfig) {
    if !hs.enabled {
        return;
    }
    tokio::spawn(async move {
        match ensure_hs(&hs).await {
            Ok(name) => log::info!("tor_hs: serving {name}"),
            Err(e) => log::warn!("tor_hs: {e:#}"),
        }
    });
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
        })
        .is_err());
        // 裸名字不在这里判（交给 PATH）
        assert!(validate(&TorHsConfig {
            enabled: true,
            ports: vec![(80, 8080)],
            data_dir: None,
            tor_bin: Some("tor".into()),
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
    }
}