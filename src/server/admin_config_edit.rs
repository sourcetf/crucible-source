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
use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value as Json;
use std::path::Path;
use std::sync::Arc;
use toml::Value as Toml;

// ---------- 结构性上限（对所有写盘路径生效） ----------
//
// 为什么集中放在管线里而不是只放在各保存端点：`/api/config/toml`（原始 TOML 正文）与
// [`persist_admin_password`] 都绕过端点级校验直接落盘 —— 只守住结构化端点等于没上限。
// 取值远高于正常配置（本仓库 config.toml 只有 1 个 listener / 18 个 apps），
// 只用于挡住「一次误操作或恶意请求把配置写成十万条」这类把 Config::load、TOML 序列化
// 与热重载一起拖死的输入；越界报错说明是哪一项、超了多少，不做静默丢弃。

/// listener 数量上限（每个 listener 都会起 accept 循环 + TLS 站点）。
pub const MAX_LISTENERS: usize = 128;
/// 单 listener 的 app 路由上限（每条路由都可能拉起引擎进程/FFI 实例）。
pub const MAX_APPS_PER_LISTENER: usize = 64;
/// 单 listener 的 proxy_rules / page_rules / file_open 条数上限
/// （proxy 每条规则要做前缀匹配，page_rules 每条请求都要遍历）。
pub const MAX_RULES_PER_LISTENER: usize = 512;
/// 管理员账号上限（验证成本是 argon2/yescrypt，且面板用户表会整体下发）。
pub const MAX_ADMIN_USERS: usize = 64;
/// 单个账号字段（username / password_hash）长度上限。
/// hash 是 `$argon2id$…`/`$y$…` 文本（实测量级 < 200 字节），1024 已很宽松。
pub const MAX_ADMIN_USER_FIELD_LEN: usize = 1024;
/// ip_access 的 allow/deny 单项上限（每个请求都要线性扫描这两张表）。
pub const MAX_IP_ACCESS_ITEMS: usize = 1024;
/// Basic realm 上限：realm 会被拼进 `WWW-Authenticate: Basic realm="…"`，
/// 过长只是浪费头空间（非法字符在下方 validate_admin_identity 里拒绝）。
pub const MAX_REALM_LEN: usize = 128;
/// admin 面板路径上限。
pub const MAX_ADMIN_PATH_LEN: usize = 128;
/// 原始 TOML 编辑器（`POST /api/config/toml`）的正文上限。
///
/// 为什么必须设：h1 入口允许 32MiB 体，落盘前要整份 parse + 序列化 + Config::load +
/// 热重载，32MiB 的 TOML 足够让这几步各占几十 MB 内存与秒级 CPU（面板自带 UI 却只发
/// 几 KB）。2MiB 是实际配置的百倍量级，够用。
pub const MAX_TOML_TEXT_BYTES: usize = 2 * 1024 * 1024;

/// JSON → TOML 值递归转换。
///
/// **null 的语义是「省略该键」**（对象里跳过、数组里跳过），顶层 null 才是错误。
///
/// 为什么这样定：TOML 没有 null 形态，而**面板对每个空选填项都会发 `null`**
/// （前端 `v || null`，且从 `/api/config/json` 读回来的对象本身就带 null）。
/// 此前这里对 null 一律 `bail!`，于是「保存站点 / 保存 TLS / 保存应用引擎」
/// 三块核心能力**恒 400**——面板上点了就报错，运维只能手改 config.toml。
pub fn json_to_toml(v: &Json) -> Result<Toml> {
    json_to_toml_opt(v)?.ok_or_else(|| anyhow!("config 字段不接受 null（请省略该键）"))
}

/// 与 [`json_to_toml`] 同义，但把 null 表示为 `None`（供容器类型跳过该元素/键）。
fn json_to_toml_opt(v: &Json) -> Result<Option<Toml>> {
    Ok(match v {
        Json::Null => None,
        Json::Bool(b) => Some(Toml::Boolean(*b)),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(Toml::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Some(Toml::Float(f))
            } else {
                bail!("数字字面量无法表示为 TOML 数值")
            }
        }
        Json::String(s) => Some(Toml::String(s.clone())),
        Json::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for item in a {
                if let Some(t) = json_to_toml_opt(item)? {
                    out.push(t);
                }
            }
            Some(Toml::Array(out))
        }
        Json::Object(o) => {
            let mut t = toml::map::Map::new();
            for (k, val) in o {
                if let Some(tv) = json_to_toml_opt(val)? {
                    t.insert(k.clone(), tv);
                }
            }
            Some(Toml::Table(t))
        }
    })
}

/// 读取磁盘上当前的 config.toml 原始树（保留本端点未涉及的节）。
pub fn load_tree(path: &Path) -> Result<Toml> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

/// 数组字段的长度（缺失 / 非数组按 0 计，类型错误留给 Config::load 报）。
fn arr_len(v: Option<&Toml>) -> usize {
    v.and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0)
}

/// realm / admin.path 的合法性。
///
/// 为什么在写盘前判：realm 会被拼进 `WWW-Authenticate: Basic realm="…"` 头
/// （admin.rs / h1 / h2 / h3 / telemetry 五处），含换行等控制字符时 `HeaderValue`
/// 构造失败、`Response::builder().body().unwrap()` 直接 panic —— 一次面板保存就能让
/// 管理面每次鉴权失败都打崩一个任务；含引号则会往挑战值里注入一个额外 auth-param。
/// path 只要求「以 / 开头、不是 /」：`/` 会让 h1 的 `starts_with(admin.path)` 匹配**所有**
/// 请求（管理面板顶掉整站，未配用户时等于把面板公开到根路径）。
fn validate_admin_identity(tree: &Toml) -> Result<()> {
    let Some(admin) = tree.get("admin").and_then(|a| a.as_table()) else {
        return Ok(());
    };
    if let Some(realm) = admin.get("realm").and_then(|r| r.as_str()) {
        if realm.len() > MAX_REALM_LEN {
            bail!("admin.realm 过长（{} > {MAX_REALM_LEN} 字节）", realm.len());
        }
        if !realm.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            bail!("admin.realm 只能是可见 ASCII（不能含控制字符/换行/中文）—— 它会被写进 WWW-Authenticate 头");
        }
        // `"` / `\` 虽在可见 ASCII 内，但会破坏 `realm="…"` 这个 auth-param 的引号结构
        // （可被用来往挑战值里再塞一个参数），面板输入框里也没有正当用途。
        if realm.contains('"') || realm.contains('\\') {
            bail!("admin.realm 不能含引号或反斜杠: {realm:?}");
        }
    }
    if let Some(p) = admin.get("path").and_then(|r| r.as_str()) {
        if p.len() > MAX_ADMIN_PATH_LEN {
            bail!("admin.path 过长（{} > {MAX_ADMIN_PATH_LEN} 字节）", p.len());
        }
        if !p.starts_with('/') {
            bail!("admin.path 必须以 / 开头（当前 {p:?}），否则面板永远不可达");
        }
        if p.trim_matches('/').is_empty() {
            bail!("admin.path 不能是 /（会让管理面板顶掉整站根路径）");
        }
        if p.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20) || p.contains('?') || p.contains('#')
        {
            bail!("admin.path 含空白/控制字符/查询符: {p:?}");
        }
    }
    let users = arr_len(admin.get("users"));
    if users > MAX_ADMIN_USERS {
        bail!("admin.users 过多（{users} > {MAX_ADMIN_USERS}）—— 每个账号都会在鉴权时做一次口令哈希校验");
    }
    // 账号字段：用户名/哈希同样只会被写进 config.toml（没有专门的端点，走原始 TOML 编辑器
    // 或口令持久化），所以在这里统一判长度与控制字符 —— 含换行的用户名/哈希会让
    // Config::load 通过、但面板与日志里的账号信息错位，哈希本身也可能被截断显示。
    if let Some(arr) = admin.get("users").and_then(|u| u.as_array()) {
        for (i, u) in arr.iter().enumerate() {
            for key in ["username", "password_hash"] {
                let Some(v) = u.get(key).and_then(|x| x.as_str()) else {
                    continue;
                };
                if v.len() > MAX_ADMIN_USER_FIELD_LEN {
                    bail!(
                        "admin.users[{i}].{key} 过长（{} > {MAX_ADMIN_USER_FIELD_LEN} 字节）",
                        v.len()
                    );
                }
                if v.chars().any(|c| c.is_control()) {
                    bail!("admin.users[{i}].{key} 含控制字符");
                }
            }
        }
    }
    Ok(())
}

/// 落盘前的结构性校验：数量上限 + admin 身份字段。
///
/// 只做「大小/形状」，字段语义仍由 `Config::load`（真实配置解析）负责 ——
/// 两道都过才会 rename 覆盖磁盘。
fn validate_tree_shape(tree: &Toml) -> Result<()> {
    if tree.as_table().is_none() {
        bail!("config 顶层不是表");
    }
    let listeners = tree.get("listeners").and_then(|v| v.as_array());
    if let Some(arr) = listeners {
        if arr.len() > MAX_LISTENERS {
            bail!("listeners 过多（{} > {MAX_LISTENERS}）", arr.len());
        }
        for (i, l) in arr.iter().enumerate() {
            let port = l.get("port").and_then(|p| p.as_integer()).unwrap_or(-1);
            let check = |key: &str, max: usize| -> Result<()> {
                let n = arr_len(l.get(key));
                if n > max {
                    bail!("listeners[{i}]（port={port}）的 {key} 过多（{n} > {max}）");
                }
                Ok(())
            };
            check("apps", MAX_APPS_PER_LISTENER)?;
            check("proxy_rules", MAX_RULES_PER_LISTENER)?;
            check("page_rules", MAX_RULES_PER_LISTENER)?;
            check("file_open", MAX_RULES_PER_LISTENER)?;
        }
    }
    if let Some(ia) = tree.get("ip_access") {
        for key in ["allow", "deny"] {
            let n = arr_len(ia.get(key));
            if n > MAX_IP_ACCESS_ITEMS {
                bail!("ip_access.{key} 过多（{n} > {MAX_IP_ACCESS_ITEMS}）—— 每个请求都要线性扫描该表");
            }
        }
    }
    validate_admin_identity(tree)
}

/// 校验 + 原子写盘 + 热重载。校验失败时临时文件删除、磁盘保持原状。
pub fn write_tree(live: &Arc<LiveConfig>, tree: &Toml) -> Result<()> {
    validate_tree_shape(tree)?;
    let out = toml::to_string_pretty(tree).context("serialize config.toml")?;
    let path = live.path().clone();
    // 唯一临时名：并发保存时固定名会互相覆盖（见 unique_tmp_path 的说明）。
    // 先写临时文件通过校验，再用「保留权限」的原子写定稿（原来直接 fs::write + rename
    // 会把 config.toml 的权限降级成 umask 值）。
    let tmp = crate::server::live_config::unique_tmp_path(&path, "tmp");
    // 0600 写校验副本：它含**完整** config.toml 内容（口令哈希、MaxMind key、材料路径），
    // 用 `fs::write` 会按 umask 是 0644 —— 校验窗口内本机任何用户可读。
    crate::server::dns::write_new_0600(&tmp, out.as_bytes())
        .with_context(|| format!("write {}", tmp.display()))?;
    if let Err(e) = Config::load(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        bail!("校验失败（未写盘）: {e:#}");
    }
    let _ = std::fs::remove_file(&tmp);
    crate::server::dns::write_config_atomic(&path, out.as_bytes())
        .with_context(|| format!("replace {}", path.display()))?;
    live.reload().context("reload config")?;
    Ok(())
}

/// 校验并写入一份「全文 TOML」；供 raw 编辑器使用。
///
/// §CRITICAL-1 fix: 与磁盘当前文件 diff-merge，而非全量覆盖。
/// 只替换传入 text 中显式声明的顶级 key；传入文本中没有的顶级 key（listeners/dns/geoip）
/// 从磁盘原文件保留，避免 admin 误操作导致 listener 全表被删。
/// 一次「原始 TOML 编辑器」的合并结果是否会把**所有**管理员账号删掉。
///
/// `write_toml_text` 是「按顶级 key 覆盖」：patch 里出现 `[admin]` 就会把**整张 admin 表**
/// 换掉，于是「只带 realm 的 [admin]」会把 `[[admin.users]]` 一起删掉。而用户表为空时
/// `check_admin_headers` 是 fail-closed ⇒ 重载成功后所有请求 401，管理面永久锁死。
/// 只有「本来有账号、改完没有账号」才算危险（本来就是空账号表的配置无从进入这条路径，
/// 因为面板已经不可用）；旧的扁平 `[admin] password_hash` 视作「有账号」。
fn raw_edit_drops_all_admins(base: &Toml, merged: &Toml) -> bool {
    let count = |t: &Toml| -> (usize, bool) {
        match t.get("admin").and_then(|v| v.as_table()) {
            None => (0, false),
            Some(a) => {
                let users = a
                    .get("users")
                    .and_then(|u| u.as_array())
                    .map_or(0, |x| x.len());
                let legacy = a
                    .get("password_hash")
                    .and_then(|v| v.as_str())
                    .map_or(false, |h| !h.trim().is_empty());
                (users, legacy)
            }
        }
    };
    let (before, before_legacy) = count(base);
    let (after, after_legacy) = count(merged);
    let had = before > 0 || before_legacy;
    let has = after > 0 || after_legacy;
    had && !has
}

pub fn write_toml_text(live: &Arc<LiveConfig>, text: &str) -> Result<()> {
    use std::collections::HashSet;
    // 正文长度上限：入口体上限是 32MiB，而这份文本要 parse + 序列化 + Config::load +
    // 热重载各走一遍（见 MAX_TOML_TEXT_BYTES 的说明）。
    if text.len() > MAX_TOML_TEXT_BYTES {
        bail!(
            "TOML 正文过大（{} > {MAX_TOML_TEXT_BYTES} 字节）",
            text.len()
        );
    }
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
    // **账号锁死守卫**（审计第三轮）：本函数是「全文替换 + 按顶级 key 覆盖」——
    // patch 里只要出现 `[admin]`，**整张 admin 表**就会被 patch 的内容替换掉，
    // 于是「粘贴一段只带 realm 的 [admin]」会把 `[[admin.users]]` 一起删掉。
    // 而 `check_admin_headers` 在用户表为空时 fail-closed ⇒ 重载成功后**所有**请求
    // 401，管理面永久锁死（只能上机器改 config.toml 再重启）。
    // 结构化端点早就避开这一点（admin.rs 有注释说明「从空表重建会把用户数组删掉」），
    // 这条路径此前没有。兼容旧的扁平 `[admin] password_hash` 写法。
    if raw_edit_drops_all_admins(&base, &tree) {
        bail!(
            "这次保存会把管理员账号**全部删掉**（patch 里的 [admin] 覆盖了原有的 [[admin.users]]）—— 保存后所有请求都会被拒（401），管理面永久锁死、只能改磁盘上的 config.toml 再重启。请在 patch 里带上至少一个 [[admin.users]]，或不要提交 [admin] 这一段"
        );
    }
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

/// 字段级合并：以磁盘上该 listener 现有的 `key` 表为基底，用 `incoming` 覆盖/新增；
/// **`incoming` 里没有的键保留原值**。返回合并后的表（`None` = 删除该节，保持旧语义）。
///
/// 为什么需要：面板的 TLS 表单只包含它认识的字段，而 `ech_cover_cert` / `ech_cover_key` /
/// `ech_cover_cert_ec` / `ech_cover_key_ec` / `ech_cover_ocsp_der_path` / `ocsp_der_path`
/// 等**不在表单里**。此前 `set_listener_key(..., "ssl", Some(表单表))` 是整表替换 ⇒
/// 点一次「保存 TLS」就把这些字段静默删掉：ECH 外层（cover）证书消失，主动探测者
/// 能拿到内层真实证书，且面板既看不到也无法重新录入。
pub fn merge_listener_table(
    tree: &mut Toml,
    port: u16,
    key: &str,
    incoming: Option<Toml>,
) -> Result<Option<Toml>> {
    let Some(inc) = incoming else { return Ok(None) };
    let inc_tbl = match inc.as_table() {
        Some(t) => t.clone(),
        // 非表类型：保持原样（调用方负责校验），不做合并
        None => return Ok(Some(inc)),
    };
    let existing = {
        let t = listener_table_mut(tree, port)?;
        t.get(key).and_then(|v| v.as_table()).cloned()
    };
    let mut base = existing.unwrap_or_default();
    for (k, v) in inc_tbl {
        base.insert(k, v);
    }
    Ok(Some(Toml::Table(base)))
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
    /// 面板对空选填项发 null：必须按「省略该键」处理（否则保存站点/TLS/引擎恒 400）。
    #[test]
    fn json_to_toml_skips_nulls_in_containers() {
        let j: Json = serde_json::from_str(
            r#"{"port":9095,"root":"www-apps","cert":null,"versions":["tls1.2",null],"ssl":{"key":null,"prefer_tls13":true},"apps":[null,{"engine":"php"}]}"#,
        )
        .unwrap();
        let t = json_to_toml(&j).unwrap();
        assert_eq!(t.get("port").unwrap().as_integer(), Some(9095));
        assert!(t.get("cert").is_none(), "null 键必须被省略");
        assert_eq!(t.get("versions").unwrap().as_array().unwrap().len(), 1);
        let ssl = t.get("ssl").unwrap();
        assert!(ssl.get("key").is_none());
        assert_eq!(ssl.get("prefer_tls13").unwrap().as_bool(), Some(true));
        assert_eq!(t.get("apps").unwrap().as_array().unwrap().len(), 1);
        // 顶层 null 仍是错误（请求体本身不对）
        assert!(json_to_toml(&Json::Null).is_err());
    }

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

    // ---------- 结构性上限 / admin 身份字段 ----------

    /// 集合超量必须**明确报错并指出哪一项**，而不是写下去之后再让 Config::load 或
    /// 运行期慢慢崩。
    #[test]
    fn shape_rejects_oversized_collections() {
        let many_listeners: String = (0..MAX_LISTENERS + 1)
            .map(|i| format!("[[listeners]]\naddress=\"0.0.0.0\"\nport={}\nroot=\"r{i}\"\n", 1000 + i))
            .collect();
        let tree: Toml = toml::from_str(&many_listeners).unwrap();
        let e = validate_tree_shape(&tree).unwrap_err().to_string();
        assert!(e.contains("listeners 过多"), "unexpected: {e}");

        let apps: String = (0..MAX_APPS_PER_LISTENER + 1)
            .map(|i| format!("[[listeners.apps]]\nengine=\"php\"\npaths=[\"/p{i}\"]\n"))
            .collect();
        let tree: Toml =
            toml::from_str(&format!("[[listeners]]\nport=9095\nroot=\"r\"\n{apps}")).unwrap();
        let e = validate_tree_shape(&tree).unwrap_err().to_string();
        assert!(e.contains("apps 过多"), "unexpected: {e}");

        let allows: String = (0..MAX_IP_ACCESS_ITEMS + 1)
            .map(|i| format!("\"10.0.{}.{}\",", i / 256, i % 256))
            .collect();
        let tree: Toml = toml::from_str(&format!("[ip_access]\nallow=[{allows}]\n")).unwrap();
        let e = validate_tree_shape(&tree).unwrap_err().to_string();
        assert!(e.contains("ip_access.allow 过多"), "unexpected: {e}");
    }

    #[test]
    fn shape_accepts_this_repos_style_config() {
        let tree: Toml = toml::from_str(
            "[admin]\nrealm=\"WebServer Admin\"\npath=\"/__admin\"\n\n[ip_access]\nallow=[\"127.0.0.1\",\"10.0.0.0/8\"]\ndeny=[]\n\n[[listeners]]\nport=9095\nroot=\"www-apps\"\nfile_open=[\"php=execute\"]\n\n[[listeners.apps]]\nengine=\"php\"\npaths=[\"/php\"]\n",
        )
        .unwrap();
        validate_tree_shape(&tree).expect("normal config must pass");
    }

    /// realm 会被拼进 `WWW-Authenticate` 头：含换行/非 ASCII 时构造 HeaderValue 失败，
    /// 后续 `.body().unwrap()` 直接 panic。必须在落盘前拒绝。
    /// 原始 TOML 编辑器不得把账号全删掉（那会让面板永久 401）。
    #[test]
    fn raw_edit_dropping_all_admins_is_detected() {
        let base: Toml = toml::from_str(
            "[admin]
realm=\"r\"
[[admin.users]]
username=\"admin\"
password_hash=\"h\"
",
        )
        .unwrap();
        // 只带 realm 的 patch ⇒ 整张 admin 表被换掉、账号没了 ⇒ 必须判为危险
        let merged: Toml = toml::from_str("[admin]
realm=\"r\"
").unwrap();
        assert!(raw_edit_drops_all_admins(&base, &merged), "删光账号必须被发现");
        // 带上账号就不危险
        let ok: Toml = toml::from_str(
            "[admin]
realm=\"r\"
[[admin.users]]
username=\"a\"
password_hash=\"h\"
",
        )
        .unwrap();
        assert!(!raw_edit_drops_all_admins(&base, &ok));
        // 本来就是空的（无账号表）⇒ 不算「删光」（否则会误拒无关编辑）
        let empty: Toml = toml::from_str("[ip_access]
allow=[]
").unwrap();
        assert!(!raw_edit_drops_all_admins(&empty, &empty));
        // 旧式扁平 password_hash 也算「有账号」
        let flat: Toml = toml::from_str("[admin]
password_hash=\"h\"
").unwrap();
        let flat_ok: Toml = toml::from_str("[admin]
password_hash=\"h2\"
").unwrap();
        assert!(!raw_edit_drops_all_admins(&flat, &flat_ok));
        assert!(raw_edit_drops_all_admins(&flat, &empty), "扁平哈希被删掉同样要拦");
    }

    #[test]
    fn admin_identity_rejects_header_unsafe_values() {
        for bad in [
            "[admin]\nrealm=\"a\\nb\"\n",
            "[admin]\nrealm=\"中文\"\n",
            "[admin]\nrealm=\"a\\\"b\"\n",
        ] {
            let tree: Toml = toml::from_str(bad).unwrap();
            let e = validate_tree_shape(&tree).unwrap_err().to_string();
            assert!(e.contains("admin.realm"), "must reject {bad:?}, got {e}");
        }
        assert!(
            validate_tree_shape(&toml::from_str("[admin]\npath=\"abc\"\n").unwrap()).is_err(),
            "path 不以 / 开头 → 面板不可达"
        );
        assert!(
            validate_tree_shape(&toml::from_str("[admin]\npath=\"/\"\n").unwrap()).is_err(),
            "path=/ 会让面板顶掉整站"
        );
        assert!(validate_tree_shape(&toml::from_str("[admin]\nrealm=\"A B\"\n").unwrap()).is_ok());
    }
}
