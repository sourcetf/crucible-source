//! GeoIP panel TOML persistence (`data/geoip/panel.toml` by default).

use crate::server::geoip_panel::config::PanelConfig;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_PANEL_PATH: &str = "data/geoip/panel.toml";

/// Resolve panel TOML path (env override → default).
pub fn panel_path() -> PathBuf {
    std::env::var("CRUCIBLE_GEOIP_PANEL")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PANEL_PATH))
}

/// Load panel settings from disk; missing file yields defaults.
pub fn load(path: &Path) -> Result<PanelConfig> {
    if !path.is_file() {
        return Ok(PanelConfig::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("read geoip panel {}", path.display()))?;
    parse_panel_toml(&text)
}

/// Save panel settings to disk (creates parent dirs).
///
/// 原子写：先写同目录临时文件再 rename。直接 `fs::write` 是「先截断再写」——
/// 磁盘写满（本机长期 95%）或进程在写到一半时挂掉，会把已有 panel.toml 毁成
/// 空文件/半截文件，下次 load 解析失败即丢全部设置。rename 同目录是原子的，
/// 失败时旧文件原样保留。
pub fn save(path: &Path, cfg: &PanelConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let text = serialize_panel_toml(cfg);
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

/// 同名临时文件路径（`panel.toml` → `panel.toml.tmp`）。
fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

fn parse_panel_toml(text: &str) -> Result<PanelConfig> {
    let mut cfg = PanelConfig::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            match k {
                "enabled" => cfg.enabled = v == "true" || v == "1" || v.eq_ignore_ascii_case("yes"),
                "db_path" => {
                    if v.is_empty() {
                        cfg.db_path = None;
                    } else {
                        cfg.db_path = Some(PathBuf::from(v));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(cfg)
}

fn serialize_panel_toml(cfg: &PanelConfig) -> String {
    let db = cfg
        .db_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    format!(
        "# Crucible GeoIP panel settings\nenabled = {}\ndb_path = \"{}\"\n",
        if cfg.enabled { "true" } else { "false" },
        db.replace('\\', "/")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let cfg = PanelConfig {
            enabled: true,
            db_path: Some(PathBuf::from("/data/geoip/current/geoip.sqlite")),
        };
        let text = serialize_panel_toml(&cfg);
        let back = parse_panel_toml(&text).unwrap();
        assert!(back.enabled);
        assert_eq!(back.db_path, cfg.db_path);
    }

    /// save 后：文件内容正确、同目录临时文件不残留（原子写不该留下 .tmp）。
    #[test]
    fn save_is_atomic_and_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!("crucible_geoip_toml_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("panel.toml");
        let cfg = PanelConfig {
            enabled: true,
            db_path: Some(PathBuf::from("data/geoip/panel.sqlite")),
        };
        save(&path, &cfg).unwrap();
        assert!(path.is_file());
        assert!(!tmp_path(&path).exists(), "临时文件不应残留");
        assert_eq!(load(&path).unwrap().db_path, cfg.db_path);
        let _ = fs::remove_dir_all(&dir);
    }
}
