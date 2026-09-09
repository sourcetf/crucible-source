//! Admin 文件管理：在 listener root 下 list/read/write，防路径穿越。

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// 将用户相对路径解析到 `root` 下；拒绝 `..` 与越界。
pub fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    let root = fs::canonicalize(root).unwrap_or_else(|_| abs(root));
    let mut out = root.clone();
    let rel = rel.trim_start_matches('/').trim_start_matches('\\');
    // Web 上下文路径分隔符只可能是 /；反斜杠是 Windows 分隔符，出现即拒绝
    // （防 ..\\windows 式穿越在 Unix component 匹配下漏网——回归测试 script_rel_rejects_traversal）
    if rel.contains('\\') {
        bail!("backslash in path rejected");
    }
    if rel.is_empty() || rel == "." {
        return Ok(root);
    }
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => bail!("path traversal rejected"),
            Component::RootDir | Component::Prefix(_) => bail!("absolute path rejected"),
        }
    }
    // 已存在则 canonicalize 再校验前缀；新建文件则校验父目录
    if out.exists() {
        let canon = fs::canonicalize(&out).with_context(|| format!("canon {}", out.display()))?;
        if !canon.starts_with(&root) {
            bail!("path escapes root");
        }
        Ok(canon)
    } else {
        let parent = out.parent().unwrap_or(&root);
        let parent_canon = if parent.exists() {
            fs::canonicalize(parent)?
        } else {
            parent.to_path_buf()
        };
        if !parent_canon.starts_with(&root) && parent_canon != root {
            bail!("path escapes root");
        }
        Ok(out)
    }
}

pub fn list_dir(root: &Path, rel: &str) -> Result<Vec<DirEntryInfo>> {
    let dir = safe_join(root, rel)?;
    if !dir.is_dir() {
        bail!("not a directory");
    }
    let mut entries = Vec::new();
    for e in fs::read_dir(&dir)? {
        let e = e?;
        let meta = e.metadata()?;
        entries.push(DirEntryInfo {
            name: e.file_name().to_string_lossy().into_owned(),
            is_dir: meta.is_dir(),
            size: meta.len(),
        });
    }
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });
    Ok(entries)
}

pub fn read_file(root: &Path, rel: &str, max_bytes: usize) -> Result<(Vec<u8>, bool)> {
    let path = safe_join(root, rel)?;
    if !path.is_file() {
        bail!("not a file");
    }
    let data = fs::read(&path)?;
    let binary = is_likely_binary(&data);
    if data.len() > max_bytes {
        bail!("file too large ({} > {max_bytes})", data.len());
    }
    Ok((data, binary))
}

pub fn write_file(root: &Path, rel: &str, data: &[u8]) -> Result<()> {
    let path = safe_join(root, rel)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, data).with_context(|| format!("write {}", path.display()))?;
    // TOCTOU: after write, canonicalize and re-check containment (symlink race).
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| abs(root));
    let written = fs::canonicalize(&path).with_context(|| format!("re-canon {}", path.display()))?;
    if !written.starts_with(&root_canon) {
        let _ = fs::remove_file(&path);
        anyhow::bail!("write escaped root after create (symlink race?)");
    }
    Ok(())
}

/// 在 root 下创建目录（含父目录）；已存在同名目录时报错。
pub fn mkdir(root: &Path, rel: &str) -> Result<()> {
    let path = safe_join(root, rel)?;
    if path.is_dir() {
        bail!("directory already exists");
    }
    fs::create_dir_all(&path).with_context(|| format!("mkdir {}", path.display()))
}

/// 删除 root 下的文件或目录（目录递归）。
/// 安全：拒绝删除 docroot 本身；越界由 safe_join 拦截（§10）。
pub fn delete_path(root: &Path, rel: &str) -> Result<()> {
    let path = safe_join(root, rel)?;
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| abs(root));
    if path == root_canon {
        bail!("refusing to delete docroot itself");
    }
    if path.is_dir() {
        fs::remove_dir_all(&path).with_context(|| format!("rmdir {}", path.display()))
    } else if path.is_file() {
        fs::remove_file(&path).with_context(|| format!("rm {}", path.display()))
    } else {
        bail!("not found")
    }
}

/// P2-14（§16.14）：root 内重命名/移动文件或目录。from/to 都经 safe_join 校验；
/// 目标已存在时拒绝（防误覆盖），docroot 本身不可改名。
pub fn rename_path(root: &Path, from_rel: &str, to_rel: &str) -> Result<()> {
    let from = safe_join(root, from_rel)?;
    let to = safe_join(root, to_rel)?;
    if !from.exists() {
        bail!("source not found");
    }
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| abs(root));
    if from == root_canon {
        bail!("refusing to rename docroot itself");
    }
    if to.exists() {
        bail!("target already exists");
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    let res = fs::rename(&from, &to)
        .with_context(|| format!("rename {} -> {}", from.display(), to.display()));
    // TOCTOU：rename 后复核目标仍位于 root 内（symlink 竞态），越界则回滚。
    if res.is_ok() {
        let to_canon = fs::canonicalize(&to).unwrap_or_else(|_| to.clone());
        if !to_canon.starts_with(&root_canon) {
            let _ = fs::rename(&to_canon, &from);
            anyhow::bail!("rename escaped root after move (symlink race?)");
        }
    }
    res
}

fn is_likely_binary(data: &[u8]) -> bool {
    if data.contains(&0) {
        return true;
    }
    let sample = &data[..data.len().min(512)];
    let nontext = sample
        .iter()
        .filter(|&&b| b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f)
        .count();
    nontext > sample.len() / 8
}

fn abs(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

/// True if a GET of `rel` under `root` would execute via an app engine (webshell gate).
pub fn would_execute_on_get(lc: &crate::config::ListenerConfig, rel: &str) -> bool {
    use crate::config::FileOpenMode;
    let path = if rel.starts_with('/') {
        rel.to_string()
    } else {
        format!("/{rel}")
    };
    // P1-3（§16.2 定案）：file_open=preview/download 的路径不算可执行——放行上传，
    // GET 时静态展示/下载、绝不执行（would_handle 对 preview/download 本就返回 false）。
    crate::server::apps::would_handle(lc, &path)
}

/// Alias of [`safe_join`] for resolving script-relative paths under a root.
pub fn script_rel(root: &Path, rel: &str) -> Result<PathBuf> {
    safe_join(root, rel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppRouteConfig, FileOpenMode, FileOpenTable, ListenerConfig};
    use std::path::PathBuf;

    fn listener_with_rust_app() -> ListenerConfig {
        ListenerConfig {
            address: "127.0.0.1".into(),
            address_v6: None,
            port: 9095,
            root: PathBuf::from("www-apps"),
            autoindex: crate::config::AutoindexConfig::default(),
            http_versions: vec!["h1".into()],
            server_name: None,
            ssl: None,
            file_open: FileOpenTable::default(),
            apps: vec![AppRouteConfig {
                paths: vec!["/rust".into()],
                enabled: true,
                engine: "rust".into(),
                socket: None,
                extensions: vec!["rs".into(), "".into()],
                index: None,
                php_bin: None,
                workers: 4,
                source_dir: None,
                out_dir: None,
                entry: vec![],
                watch: false,
                docroot: Some(PathBuf::from("www-apps/rust")),
                lib: Some(PathBuf::from("target/app-engines/libapp_rust.so")),
                deps_dir: None,
                init_timeout_secs: None,
                libc: None,
            }],
            basic_auth: None,
            proxy_rules: vec![],
            page_rules: vec![],
            status_path: None,
            port_reuse: false,
            rate_limit: None,
            l4_forward: None,
        }
    }

    #[test]
    fn would_execute_on_get_rust_path() {
        let lc = listener_with_rust_app();
        assert!(would_execute_on_get(&lc, "rust/index.rs"));
        assert!(would_execute_on_get(&lc, "/rust/foo.rs"));
    }

    #[test]
    fn would_execute_respects_file_open_preview() {
        let mut lc = listener_with_rust_app();
        lc.file_open
            .insert("/rust/index.rs", FileOpenMode::Preview);
        // P1-3：preview 不算可执行 → 上传放行（GET 时静态展示，不执行）。
        assert!(!would_execute_on_get(&lc, "rust/index.rs"));
    }

    #[test]
    fn would_execute_respects_file_open_download() {
        let mut lc = listener_with_rust_app();
        lc.file_open
            .insert("/rust/index.rs", FileOpenMode::Download);
        // P1-3：download 同样放行上传、GET 下载不执行。
        assert!(!would_execute_on_get(&lc, "rust/index.rs"));
        assert!(!would_execute_on_get(&lc, "/rust/index.rs"));
    }

    #[test]
    fn would_execute_force_execute_mode() {
        let mut lc = listener_with_rust_app();
        lc.file_open
            .insert("/rust/index.rs", FileOpenMode::Execute);
        assert!(would_execute_on_get(&lc, "rust/index.rs"));
    }

    #[test]
    fn would_execute_false_outside_app_route() {
        let lc = listener_with_rust_app();
        assert!(!would_execute_on_get(&lc, "static/hello.txt"));
        assert!(!would_execute_on_get(&lc, "/index.html"));
    }

    #[test]
    fn would_execute_false_when_app_disabled() {
        let mut lc = listener_with_rust_app();
        lc.apps[0].enabled = false;
        assert!(!would_execute_on_get(&lc, "rust/index.rs"));
    }

    #[test]
    fn script_rel_rejects_traversal() {
        assert!(script_rel(Path::new("."), "../etc/passwd").is_err());
        assert!(script_rel(Path::new("."), "..\\windows\\system32").is_err());
        assert!(script_rel(Path::new("."), "foo/../../secret").is_err());
        assert!(script_rel(Path::new("."), "..").is_err());
    }

    #[test]
    fn script_rel_allows_normal_rel() {
        let root = std::env::temp_dir().join("crucible_admin_test");
        let _ = std::fs::create_dir_all(&root);
        let p = script_rel(&root, "php/demo.php").expect("join");
        assert!(p.ends_with("demo.php") || p.to_string_lossy().contains("demo.php"));
        let nested = script_rel(&root, "a/b/c.txt").expect("nested");
        assert!(nested.to_string_lossy().contains("c.txt"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn script_rel_rejects_dotdot_components() {
        let root = std::env::temp_dir().join("crucible_admin_test2");
        let _ = std::fs::create_dir_all(&root);
        assert!(script_rel(&root, "../outside").is_err());
        assert!(script_rel(&root, "ok/../../../etc").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
