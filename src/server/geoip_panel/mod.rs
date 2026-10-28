//! Fine-grained GeoIP panel backend (minimal SQLite).

pub mod aliases;
pub mod anycast;
pub mod config;
pub mod conflict;
pub mod covering;
pub mod db;
pub mod iputil;
pub mod lookup;
pub mod ops;
pub mod sources;
pub mod toml_store;

// G-19：`enabled(&Config)` 曾在这里，但全树无调用者。真正的开关判定有两处，
// 且语义更细，不需要这层包装：
//   * 页面规则 country 维度：`Config::inject_shared_listener_config` 只在
//     `geoip.enabled` 时注入 `ListenerConfig::geoip_db`；
//   * 面板/状态：`Config::load` 先应用 `panel.toml` 覆盖，`snap.geoip.enabled`
//     就是真正生效值（见 `admin_geoip::handle_status_with_live`）。
