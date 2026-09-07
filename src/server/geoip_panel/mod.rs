//! Fine-grained GeoIP panel backend (minimal SQLite).

pub mod aliases;
pub mod anycast;
pub mod config;
pub mod conflict;
pub mod covering;
pub mod db;
pub mod filter_agg;
pub mod iputil;
pub mod lookup;
pub mod ops;
pub mod schema;
pub mod sources;
pub mod toml_store;

use crate::config::Config;

pub fn enabled(cfg: &Config) -> bool {
    cfg.geoip.enabled && cfg.geoip.db_path.is_some()
}
