//! Admin 结构化配置编辑管线（webui 后端核心）。
//!
//! 设计要点（对齐规格 §3「几乎全部进 config.toml（热重载）」+ §8 Admin 能力）：
//! - 保存走「读原始 TOML 树 → 端点局部修改 → toml 序列化 → 临时文件 Config::load 全量校验
//!   （含 root 唯一）→ 原子 rename → live.reload()」；不把内存快照直接序列化回盘，
//!   避免无关字段被快照的路径解析结果覆盖。
//! - 校验失败一律不落盘（临时文件删除，原配置保持不变），错误信息回传 UI。
//! - 所有编辑端点共享同一条管线；并发写以「最后一次保存为准」，读盘总是最新。

use crate::config::Config;
use crate::server::live_config::LiveConfig;
use anyhow::{bail, Context, Result};
use serde_json::Value as Json;
use std::path::Path;
use std::sync::Arc;
use toml::Value as Toml;

/// JSON → TOML 值递归转换。null 一律拒绝（config 里没有合法的 null 形态）。
pub fn json_to_toml(v: &Json) -> Result<Toml> {
    Ok(match v {
        Json::Null => bail!("config 字段不接受 null（请省略该键）"),
        Json::Bool(b) => Toml::Boolean(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Toml::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Toml::Float(f)
            } else {
                bail!("数字字面量无法表示为 TOML 数值")
            }
        }
        Json::String(s) => Toml::String(s.clone()),
        Json::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for item in a {
                out.push(json_to_toml(item)?);
            }
            Toml::Array(out)
        }
        Json::Object(o) => {
            let mut t = toml::map::Map::new();
            for (k, val) in o {
                t.insert(k.clone(), json_to_toml(val)?);
            }
            Toml::Table(t)
        }
    })
}

/// 读取磁盘上当前的 config.toml 原始树（保留本端点未涉及的节）。
pub fn load_tree(path: &Path) -> Result<Toml> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

/// 校验 + 原子写盘 + 热重载。校验失败时临时文件删除、磁盘保持原状。
pub fn write_tree(live: &Arc<LiveConfig>, tree: &Toml) -> Result<()> {
    let out = toml::to_string_pretty(tree).context("serialize config.toml")?;
    let path = live.path().clone();
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, &out).with_context(|| format!("write {}", tmp.display()))?;
    if let Err(e) = Config::load(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        bail!("校验失败（未写盘）: {e:#}");
    }
    std::fs::rename(&tmp, &path).with_context(|| format!("replace {}", path.display()))?;
    live.reload().context("reload config")?;
    Ok(())
}

/// 校验并写入一份「全文 TOML」；供 raw 编辑器使用。
///
/// §CRITICAL-1 fix: 与磁盘当前文件 diff-merge，而非全量覆盖。
/// 只替换传入 text 中显式声明的顶级 key；传入文本中没有的顶级 key（listeners/dns/geoip）
/// 从磁盘原文件保留，避免 admin 误操作导致 listener 全表被删。
pub fn write_toml_text(live: &Arc<LiveConfig>, text: &str) -> Result<()> {
    use std::collections::HashSet;
    let patch: Toml = toml::from_str(text).context("TOML 解析失败")?;
    let base = load_tree(live.path())?;

    // 只取 patch 中显式出现的顶级 key；其余从 base 保留
    let patch_keys: HashSet<String> = patch
        .as_table()
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default();

    let mut merged = toml::map::Map::new();
    // 先抄 base 里 patch 未覆盖的 key
    if let Some(base_t) = base.as_table() {
        for (k, v) in base_t {
            if !patch_keys.contains(k) {
                merged.insert(k.clone(), v.clone());
            }
        }
    }
    // 再叠上 patch 的 key（覆盖 base）
    if let Some(patch_t) = patch.as_table() {
        for (k, v) in patch_t {
            merged.insert(k.clone(), v.clone());
        }
    }
    let tree = Toml::Table(merged.clone());
    write_tree(live, &tree)
}

fn root_table_mut(tree: &mut Toml) -> Result<&mut toml::map::Map<String, Toml>> {
    tree.as_table_mut().context("config 顶层不是表")
}

/// 取 `listeners` 数组的可变引用；缺失时创建。
pub fn listeners_mut(tree: &mut Toml) -> Result<&mut Vec<Toml>> {
    let table = root_table_mut(tree)?;
    let v = table
        .entry("listeners".to_string())
        .or_insert_with(|| Toml::Array(Vec::new()));
    v.as_array_mut()
        .context("listeners 不是数组（请检查 config.toml 中 [[listeners]] 写法）")
}

fn port_of(entry: &Toml) -> Option<i64> {
    entry.get("port").and_then(|p| p.as_integer())
}

/// 按 port 查找 listener 下标。
pub fn listener_index_by_port(tree: &Toml, port: u16) -> Option<usize> {
    tree.get("listeners")?
        .as_array()?
        .iter()
        .position(|t| port_of(t) == Some(port as i64))
}

/// 新增或整体替换一个 listener 表。orig_port 为 None 或不存在时追加到末尾。
pub fn upsert_listener(tree: &mut Toml, orig_port: Option<u16>, listener: Toml) -> Result<()> {
    let port = listener
        .get("port")
        .and_then(|p| p.as_integer())
        .context("listener 缺少 port")? as u16;
    let arr = listeners_mut(tree)?;
    let idx = orig_port
        .and_then(|p| arr.iter().position(|t| port_of(t) == Some(p as i64)))
        .or_else(|| arr.iter().position(|t| port_of(t) == Some(port as i64)));
    match idx {
        Some(i) => arr[i] = listener,
        None => arr.push(listener),
    }
    Ok(())
}

/// 按 port 删除 listener。
pub fn remove_listener(tree: &mut Toml, port: u16) -> Result<bool> {
    let arr = listeners_mut(tree)?;
    let before = arr.len();
    arr.retain(|t| port_of(t) != Some(port as i64));
    Ok(arr.len() != before)
}

/// 定位某 listener 的可变表。
pub fn listener_table_mut<'a>(tree: &'a mut Toml, port: u16) -> Result<&'a mut toml::map::Map<String, Toml>> {
    let arr = listeners_mut(tree)?;
    let idx = arr
        .iter()
        .position(|t| port_of(t) == Some(port as i64))
        .with_context(|| format!("listener {port} 不存在"))?;
    arr[idx]
        .as_table_mut()
        .with_context(|| format!("listener {port} 不是表"))
}

/// 设置 listener 内某个键（value 为 None 时移除该键）。
pub fn set_listener_key(
    tree: &mut Toml,
    port: u16,
    key: &str,
    value: Option<Toml>,
) -> Result<()> {
    let table = listener_table_mut(tree, port)?;
    match value {
        Some(v) => {
            table.insert(key.into(), v);
        }
        None => {
            table.remove(key);
        }
    }
    Ok(())
}

/// 顶层小节（access_log / ip_access / geoip）整体替换。
pub fn set_top_level_table(tree: &mut Toml, key: &str, value: Toml) -> Result<()> {
    root_table_mut(tree)?.insert(key.into(), value);
    Ok(())
}

/// 把 admin 密码哈希持久化进 config.toml（§3.1：UI 只收集明文，服务端加盐哈希）。
pub fn persist_admin_password(
    live: &Arc<LiveConfig>,
    username: &str,
    hash: &str,
) -> Result<()> {
    let mut tree = load_tree(live.path())?;
    let table = root_table_mut(&mut tree)?;
    let admin = table
        .entry("admin".to_string())
        .or_insert_with(|| Toml::Table(toml::map::Map::new()));
    let at = admin
        .as_table_mut()
        .context("[admin] 不是表")?;
    let users = at
        .entry("users".to_string())
        .or_insert_with(|| Toml::Array(Vec::new()));
    let arr = users
        .as_array_mut()
        .context("admin.users 不是数组")?;
    let mut found = false;
    for u in arr.iter_mut() {
        let name_matches = u.get("username").and_then(|x| x.as_str()) == Some(username);
        if name_matches {
            if let Some(t) = u.as_table_mut() {
                t.insert("password_hash".into(), Toml::String(hash.to_string()));
                found = true;
            }
        }
    }
    if !found {
        let mut t = toml::map::Map::new();
        t.insert("username".into(), Toml::String(username.to_string()));
        t.insert("password_hash".into(), Toml::String(hash.to_string()));
        arr.push(Toml::Table(t));
    }
    write_tree(live, &tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_to_toml_roundtrip_shapes() {
        let j: Json = serde_json::from_str(
            r#"{"port":9095,"root":"www-apps","ssl":{"prefer_tls13":true},"file_open":["/x=preview"],"apps":[{"engine":"php","paths":["/php"]}]}"#,
        )
        .unwrap();
        let t = json_to_toml(&j).unwrap();
        assert_eq!(t.get("port").unwrap().as_integer(), Some(9095));
        assert_eq!(
            t.get("ssl").unwrap().get("prefer_tls13").unwrap().as_bool(),
            Some(true)
        );
        assert_eq!(
            t.get("file_open").unwrap().as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn upsert_and_remove_listener() {
        let mut tree: Toml = toml::from_str(
            "[[listeners]]\naddress=\"0.0.0.0\"\nport=1\nroot=\"a\"\n[[listeners]]\naddress=\"0.0.0.0\"\nport=2\nroot=\"b\"\n",
        )
        .unwrap();
        let l: Toml = toml::from_str("address=\"0.0.0.0\"\nport=3\nroot=\"c\"").unwrap();
        upsert_listener(&mut tree, None, l).unwrap();
        assert_eq!(listener_index_by_port(&tree, 3), Some(2));
        let l2: Toml = toml::from_str("address=\"0.0.0.0\"\nport=9\nroot=\"c\"").unwrap();
        upsert_listener(&mut tree, Some(3), l2).unwrap();
        assert_eq!(listener_index_by_port(&tree, 3), None);
        assert_eq!(listener_index_by_port(&tree, 9), Some(2));
        assert!(remove_listener(&mut tree, 9).unwrap());
        assert!(!remove_listener(&mut tree, 9).unwrap());
    }
}
