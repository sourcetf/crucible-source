//! GeoIP panel settings (`panel.toml`) — G-18.
//!
//! §21/§23.6：面板设置（开关、库路径、路径优先级增益、源权重）以前要么只存在
//! `panel.sqlite`（`panel_sources`），要么由 `/api/geoip/save` 写回 `config.toml`，
//! 与「配置由 TOML 驱动」不一致。现在统一持久化到 `data/geoip/panel.toml`：
//!
//! 优先级：`panel.toml` > `config.toml [geoip]` > 代码默认值。
//! `panel.sqlite` 只保留**数据**（手工覆盖 `panel_edits`、冲突、审计、cron、
//! 源刷新时间戳等）；旧库照常可读，不需要迁移。

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// 单个数据源的面板设置（覆盖 `panel_sources` 里的同名行）。
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SourceSetting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// `data/geoip/panel.toml` 的内容。
///
/// 所有字段都是 `Option`：**只有显式写下的键**才覆盖 `config.toml [geoip]`；
/// 缺失键保持 config 的值（这样手写一份只含 `path_priority_gain` 的
/// panel.toml 不会把 enabled/db_path 意外清空）。
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PanelConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_priority_gain: Option<i64>,
    /// 源权重 / 启停（按源名）。面板 `POST /api/geoip/sources` 同步写这里，
    /// 读取时覆盖 `panel_sqlite.panel_sources` 的旧值。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sources: BTreeMap<String, SourceSetting>,
}

impl PanelConfig {
    /// 校验面板设置（在加载与保存两处都执行）。
    ///
    /// 这些值会直接参与运行期合并/查库，非法值必须在入口拒绝并指名文件：
    /// - `db_path` 空串会让每次 lookup 都打开失败（面板显示「无数据」而非「配置错」）；
    /// - `path_priority_gain` 的合法区间与 `[geoip]` 校验相同（0..=1000）；
    /// - 源名不能为空、权重不能为负。
    pub fn validate(&self) -> Result<()> {
        if let Some(p) = &self.db_path {
            if p.as_os_str().is_empty() {
                anyhow::bail!("panel.toml: db_path 不能为空串（要清空请删掉该键）");
            }
        }
        if let Some(g) = self.path_priority_gain {
            if !(0..=1000).contains(&g) {
                anyhow::bail!("panel.toml: path_priority_gain = {g} 越界（允许 0..=1000）");
            }
        }
        for (name, s) in &self.sources {
            if name.trim().is_empty() {
                anyhow::bail!("panel.toml: [sources] 含空源名");
            }
            if let Some(w) = s.weight {
                if w < 0 {
                    anyhow::bail!("panel.toml: [sources.{name}].weight = {w} 不能为负");
                }
            }
        }
        Ok(())
    }

    /// 把面板设置叠加到 `config.toml [geoip]` 之上（本文件的字段优先）。
    pub fn apply_to(&self, geoip: &mut crate::config::GeoIpConfig) {
        if let Some(v) = self.enabled {
            geoip.enabled = v;
        }
        if let Some(p) = &self.db_path {
            geoip.db_path = Some(p.clone());
        }
        if let Some(g) = self.path_priority_gain {
            geoip.path_priority_gain = g;
        }
    }

    /// 写入/更新一个源的面板设置（双写到 `panel.toml`，不碰 sqlite）。
    pub fn set_source(&mut self, name: &str, weight: Option<i64>, enabled: Option<bool>) {
        let e = self.sources.entry(name.to_string()).or_default();
        if weight.is_some() {
            e.weight = weight;
        }
        if enabled.is_some() {
            e.enabled = enabled;
        }
    }
}

// G-19：`from_server_config`/`effective_from_config` 已删除。它们只是把
// `Config.geoip` 复制成 `PanelConfig`，全树无调用者；运行期真正生效的值由
// `Config::load → toml_store::effective_geoip` 直接写在 `Config.geoip` 上，
// 状态接口读快照即可（避免两套「有效值」互相漂移）。

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_to_overrides_only_present_keys() {
        let mut geoip = crate::config::GeoIpConfig {
            enabled: false,
            db_path: Some(PathBuf::from("/a.sqlite")),
            path_priority_gain: 10,
        };
        let panel = PanelConfig {
            path_priority_gain: Some(50),
            ..Default::default()
        };
        panel.apply_to(&mut geoip);
        assert!(!geoip.enabled, "缺失 enabled 不得改动 config 值");
        assert_eq!(geoip.db_path.as_deref(), Some(std::path::Path::new("/a.sqlite")));
        assert_eq!(geoip.path_priority_gain, 50);
        let panel2 = PanelConfig {
            enabled: Some(true),
            db_path: Some(PathBuf::from("/b.sqlite")),
            path_priority_gain: Some(0),
            ..Default::default()
        };
        panel2.apply_to(&mut geoip);
        assert!(geoip.enabled);
        assert_eq!(geoip.db_path.as_deref(), Some(std::path::Path::new("/b.sqlite")));
        assert_eq!(geoip.path_priority_gain, 0);
    }

    #[test]
    fn validate_rejects_bad_values() {
        let bad = |c: PanelConfig| c.validate().is_err();
        assert!(bad(PanelConfig {
            db_path: Some(PathBuf::new()),
            ..Default::default()
        }));
        assert!(bad(PanelConfig {
            path_priority_gain: Some(-1),
            ..Default::default()
        }));
        assert!(bad(PanelConfig {
            path_priority_gain: Some(1001),
            ..Default::default()
        }));
        assert!(bad(PanelConfig {
            sources: BTreeMap::from([(
                " ".to_string(),
                SourceSetting {
                    weight: None,
                    enabled: None,
                }
            )]),
            ..Default::default()
        }));
        assert!(PanelConfig::default().validate().is_ok());
    }

    #[test]
    fn set_source_updates_only_given_keys() {
        let mut c = PanelConfig::default();
        c.set_source("demo", Some(80), Some(true));
        assert_eq!(c.sources["demo"].weight, Some(80));
        assert_eq!(c.sources["demo"].enabled, Some(true));
        c.set_source("demo", None, Some(false));
        assert_eq!(c.sources["demo"].weight, Some(80), "weight 未给则保留");
        assert_eq!(c.sources["demo"].enabled, Some(false));
    }
}
