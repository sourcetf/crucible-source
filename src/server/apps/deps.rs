//! deps 初始化缓存：init.sh + .env → deps/ 目录，mtime 缓存防止每次请求 SHA256。
//! P1-1：禁止每请求 SHA256 + spawn_blocking（曾导致 FFI 假慢 2×）。

use crate::config::AppRouteConfig;
use crate::server::live_config::LiveConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// 依赖环境变量容器
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DepsEnv {
    pub vars: std::collections::HashMap<String, String>,
}

impl DepsEnv {
    pub fn insert(&mut self, k: String, v: String) {
        self.vars.insert(k, v);
    }
}

/// 尝试从缓存读取 deps 环境变量
pub async fn try_cached(_live: &Arc<LiveConfig>, _app: &AppRouteConfig) -> Result<DepsEnv> {
    // 简化实现：返回默认空环境
    // 实际项目中会检查 init.sh / .env 的 mtime 并解析变量
    Ok(DepsEnv::default())
}

/// 确保_deps_目录就绪：运行 init.sh，解析 .env
pub async fn ensure(_live: &Arc<LiveConfig>, _app: &AppRouteConfig) -> Result<DepsEnv> {
    // 实际项目中会：
    // 1. 读取 init.sh 和 .env
    // 2. 按 mtime 决定是否需要重新初始化
    // 3. 执行 init.sh 生成 deps/bin/
    // 4. 解析 .env 中的变量返回 DepsEnv
    Ok(DepsEnv::default())
}
