//! GeoIP panel configuration (TOML-backed settings).

use crate::config::Config;

/// Minimal GeoIP panel settings.
#[derive(Clone, Debug, Default)]
pub struct PanelConfig {
    pub enabled: bool,
    pub db_path: Option<std::path::PathBuf>,
}

/// Load panel config from server `Config`.
pub fn from_server_config(cfg: &Config) -> PanelConfig {
    PanelConfig {
        enabled: cfg.geoip.enabled,
        db_path: cfg.geoip.db_path.clone(),
    }
}
