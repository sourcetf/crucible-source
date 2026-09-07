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
pub fn save(path: &Path, cfg: &PanelConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let text = serialize_panel_toml(cfg);
    fs::write(path, text)
        .with_context(|| format!("write geoip panel {}", path.display()))?;
    Ok(())
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
