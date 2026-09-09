//! GeoIP 配置 TOML 持久化。
use anyhow::{Context, Result};
use std::path::Path;

pub fn load_config(path: &Path) -> Result<toml::Value> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read config: {}", path.display()))?;
    toml::from_str(&content).context("parse TOML")
}

pub fn save_config(path: &Path, value: &toml::Value) -> Result<()> {
    let content = toml::to_string(value).context("serialize TOML")?;
    std::fs::write(path, content).context("write config")?;
    Ok(())
}