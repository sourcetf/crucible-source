//! Hidden Service（站点 .onion 入站；早期规格 A.3）。
//!
//! 独立 tor 进程：SocksPort 0（故意不开出站 SOCKS——HS 不出站，避免与反代
//! 出站策略搅在一起，见 C 坑表）；HiddenServiceDir 由配置指定；启动后读取
//! hostname 文件得到 .onion 名并写 state/tor-hs/hostname.log 供面板显示。
//! 反代出站使用 tor_client.rs（arti/UDS/loopback），不复用本 torrc。

use anyhow::{bail, Context, Result};
use crate::config::TorHsConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;


fn state_dir() -> PathBuf {
    PathBuf::from("state/tor-hs")
}

/// 启动 HS tor（若未在跑）：写 torrc → --RunAsDaemon → 轮询 hostname 文件。
/// 幂等：hostname 已存在且进程活着则直接返回。
pub async fn ensure_hs(cfg: &TorHsConfig) -> Result<String> {
    if cfg.ports.is_empty() {
        bail!("tor_hs: no ports configured");
    }
    let dir = state_dir();
    let hs_dir = cfg
        .data_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("hs"));
    std::fs::create_dir_all(&hs_dir)?;
    std::fs::create_dir_all(dir.join("data"))?;

    let hostname_file = hs_dir.join("hostname");
    if hostname_file.is_file() {
        let existing = std::fs::read_to_string(&hostname_file)?.trim().to_string();
        if !existing.is_empty() {
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
    std::fs::write(&torrc_path, torrc)?;

    let pidfile = dir.join("tor.pid");
    let _ = tokio::process::Command::new(&tor)
        .arg("-f")
        .arg(&torrc_path)
        .arg("--RunAsDaemon")
        .arg("1")
        .arg("--PidFile")
        .arg(&pidfile)
        .status()
        .await
        .with_context(|| format!("spawn {}", tor))?;

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
    bail!("tor_hs: hostname not generated in time")
}

/// 面板/启动钩子：读 [tor_hs] 配置并确保 HS 运行；错误仅记录不中断服务。
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
