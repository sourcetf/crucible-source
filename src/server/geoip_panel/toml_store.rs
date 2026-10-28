//! GeoIP panel TOML persistence (`data/geoip/panel.toml` by default) — G-18.
//!
//! 历史背景：本文件早就存在但**没有任何调用点**（死代码），面板设置实际写回
//! `config.toml [geoip]` 或 `panel.sqlite panel_sources`。现在它承担：
//!
//! 1. 面板设置（enabled / db_path / path_priority_gain / 源权重）的持久化；
//! 2. 启动/热载时的覆盖：`panel.toml` > `config.toml [geoip]` > 默认值；
//! 3. 源权重的双写（`POST /api/geoip/sources` 同时更新 sqlite 与 panel.toml）。
//!
//! 兼容性：`panel.sqlite` 仍是数据存储（手工覆盖、冲突、审计、cron、源刷新
//! 时间戳），旧库**无需迁移**即可继续读；panel.toml 缺失时行为与旧版完全一致。

use crate::server::geoip_panel::config::{PanelConfig, SourceSetting};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_PANEL_PATH: &str = "data/geoip/panel.toml";

/// Resolve panel TOML path (env override → default).
///
/// `read_static_env`（启动期缓存）而不是裸 `std::env::var`：本函数在**每个 GeoIP 请求**
/// 上被调用，而应用引擎会在请求期间 `setenv`，libc 的 environ realloc 会让并发
/// `getenv` 踩到已释放内存（见 `apps/env_lock` 的说明与 dns state_root 的实测崩溃）。
pub fn panel_path() -> PathBuf {
    crate::server::apps::env_lock::read_static_env("CRUCIBLE_GEOIP_PANEL")
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PANEL_PATH))
}

/// Load panel settings from disk; missing file yields defaults (no overrides).
pub fn load(path: &Path) -> Result<PanelConfig> {
    if !path.is_file() {
        return Ok(PanelConfig::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("read geoip panel {}", path.display()))?;
    let cfg: PanelConfig = toml::from_str(&text)
        .with_context(|| format!("parse geoip panel {}", path.display()))?;
    cfg.validate()
        .with_context(|| format!("validate geoip panel {}", path.display()))?;
    Ok(cfg)
}

/// Load panel settings from the resolved default path (missing file → defaults).
pub fn load_effective() -> Result<PanelConfig> {
    load(&panel_path())
}

/// 计算真正生效的 `[geoip]`：`panel.toml` 覆盖 `config.toml`，缺失键保持 config。
///
/// 校验在覆盖**之前**由 `Config::validate` 对 config.toml 做；这里校验 panel.toml
/// 自身的值，避免一份坏面板配置在启动时静默生效。
pub fn effective_geoip(base: &crate::config::GeoIpConfig) -> Result<crate::config::GeoIpConfig> {
    let path = panel_path();
    let panel = load(&path)?;
    let mut out = base.clone();
    panel.apply_to(&mut out);
    Ok(out)
}

/// Save panel settings to disk (creates parent dirs).
///
/// 原子写：先写同目录临时文件再 rename。直接 `fs::write` 是「先截断再写」——
/// 磁盘写满（本机长期 95%）或进程在写到一半时挂掉，会把已有 panel.toml 毁成
/// 空文件/半截文件，下次 load 解析失败即丢全部设置。rename 同目录是原子的，
/// 失败时旧文件原样保留。
pub fn save(path: &Path, cfg: &PanelConfig) -> Result<()> {
    cfg.validate()
        .with_context(|| format!("validate geoip panel {}", path.display()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let text = serialize_panel_toml(cfg)?;
    // 同目录临时文件：rename 只有在同一文件系统内才是原子的。
    let tmp = tmp_path(path);
    if let Err(e) = fs::write(&tmp, text) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("write geoip panel {}", tmp.display()));
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| {
            format!("rename {} -> {}", tmp.display(), path.display())
        });
    }
    Ok(())
}

/// 保存到解析后的默认路径。
pub fn save_effective(cfg: &PanelConfig) -> Result<()> {
    save(&panel_path(), cfg)
}

/// 更新一个源的面板设置（双写 `panel.toml`；sqlite 由调用方更新）。
pub fn update_source(name: &str, weight: Option<i64>, enabled: Option<bool>) -> Result<()> {
    if weight.is_none() && enabled.is_none() {
        return Ok(());
    }
    let path = panel_path();
    let mut cfg = load(&path)?;
    cfg.set_source(name, weight, enabled);
    save(&path, &cfg)
}

/// 源名 → 面板覆盖（panel.toml 读取失败时返回空表：源管理不应因坏 toml 整体不可用）。
pub fn source_overrides() -> std::collections::BTreeMap<String, SourceSetting> {
    match load_effective() {
        Ok(c) => c.sources,
        Err(e) => {
            log::warn!("geoip panel.toml 读取失败（源权重覆盖忽略）: {e:#}");
            std::collections::BTreeMap::new()
        }
    }
}

/// 同名临时文件路径（`panel.toml` → `panel.toml.tmp`）。
fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

fn serialize_panel_toml(cfg: &PanelConfig) -> Result<String> {
    let body = toml::to_string_pretty(cfg).context("encode geoip panel.toml")?;
    Ok(format!(
        "# Crucible GeoIP panel settings (overrides config.toml [geoip])\n\
         # 由面板 /api/geoip/settings 维护；也可手工编辑后重启/热载。\n\
         {body}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "crucible_geoip_toml_{tag}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parse_roundtrip_all_fields() {
        let dir = tmp_dir("roundtrip");
        let path = dir.join("panel.toml");
        let mut cfg = PanelConfig {
            enabled: Some(true),
            db_path: Some(PathBuf::from("/data/geoip/current/geoip.sqlite")),
            path_priority_gain: Some(50),
            ..Default::default()
        };
        cfg.set_source("demo", Some(80), Some(false));
        save(&path, &cfg).unwrap();
        let back = load(&path).unwrap();
        assert_eq!(back, cfg);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_yields_no_overrides() {
        let dir = tmp_dir("missing");
        let cfg = load(&dir.join("nope.toml")).unwrap();
        assert_eq!(cfg, PanelConfig::default());
        let _ = fs::remove_dir_all(&dir);
    }

    /// 手写 panel.toml：只需要一个键也能加载，缺失键不产生覆盖。
    #[test]
    fn handwritten_partial_file_loads() {
        let dir = tmp_dir("partial");
        let path = dir.join("panel.toml");
        fs::write(&path, "path_priority_gain = 0\n").unwrap();
        let cfg = load(&path).unwrap();
        assert_eq!(cfg.path_priority_gain, Some(0));
        assert_eq!(cfg.enabled, None);
        assert!(cfg.db_path.is_none());
        let mut geoip = crate::config::GeoIpConfig {
            enabled: true,
            db_path: Some(PathBuf::from("/keep.sqlite")),
            path_priority_gain: 10,
        };
        cfg.apply_to(&mut geoip);
        assert!(geoip.enabled, "panel.toml 未写 enabled ⇒ 保留 config 值");
        assert_eq!(geoip.db_path.as_deref(), Some(Path::new("/keep.sqlite")));
        assert_eq!(geoip.path_priority_gain, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_values_are_rejected_with_file_name() {
        let dir = tmp_dir("invalid");
        let path = dir.join("panel.toml");
        fs::write(&path, "path_priority_gain = -3\n").unwrap();
        let e = load(&path).unwrap_err();
        assert!(format!("{e:#}").contains("path_priority_gain"), "{e:#}");
        fs::write(&path, "not toml = [\n").unwrap();
        assert!(load(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// save 后：文件内容正确、同目录临时文件不残留（原子写不该留下 .tmp）。
    #[test]
    fn save_is_atomic_and_leaves_no_tmp() {
        let dir = tmp_dir("atomic");
        let path = dir.join("panel.toml");
        let cfg = PanelConfig {
            enabled: Some(true),
            db_path: Some(PathBuf::from("data/geoip/panel.sqlite")),
            path_priority_gain: Some(10),
            ..Default::default()
        };
        save(&path, &cfg).unwrap();
        assert!(path.is_file());
        assert!(!tmp_path(&path).exists(), "临时文件不应残留");
        assert_eq!(load(&path).unwrap(), cfg);
        let _ = fs::remove_dir_all(&dir);
    }

    /// 源设置增删只动 panel.toml 中该源的键（UPSERT 语义）。
    #[test]
    fn source_setting_roundtrip() {
        let dir = tmp_dir("sources");
        let path = dir.join("panel.toml");
        let mut cfg = PanelConfig::default();
        cfg.set_source("qqwry", Some(40), Some(true));
        save(&path, &cfg).unwrap();
        let mut back = load(&path).unwrap();
        assert_eq!(back.sources["qqwry"].weight, Some(40));
        back.set_source("qqwry", Some(70), None);
        save(&path, &back).unwrap();
        let back2 = load(&path).unwrap();
        assert_eq!(back2.sources["qqwry"].weight, Some(70));
        assert_eq!(back2.sources["qqwry"].enabled, Some(true));
        let _ = fs::remove_dir_all(&dir);
    }
}
