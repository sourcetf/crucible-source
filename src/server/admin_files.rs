//! Admin 文件管理：在 listener root 下 list/read/write，防路径穿越。

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// 相对路径长度上限（字节）。为什么不设更小：Windows 长路径前非长路径的 MAX_PATH 是 260、
/// 加上 root 前缀很容易接近，4096 只是挡住「把整段 JSON/超大 body 当路径传进来」这类输入
/// （正常文件名远小于它）。越界报错而不是截断 —— 截断会落到另一个文件上。
pub const MAX_REL_PATH_LEN: usize = 4096;

/// 单次写入上限（字节）。与 h1 的 admin 体上限（`ADMIN_BODY_CAP` = 32MiB）一致：
/// 入口已经收不下更大体，这里再判一次是为了「入口上限将来放宽 / 别的调用点绕过入口」时
/// 也不会把磁盘写爆，并给出可读原因（而不是写到一半 ENOSPC）。
pub const MAX_WRITE_BYTES: usize = 32 * 1024 * 1024;

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
    // 长度 / NUL 先判：两者在 fs 层都会以难读的 OS 错误冒泡（Windows 上超长路径
    // 还可能落到 \\?\ 语义之外的神秘失败），在入口给出可读原因。
    if rel.len() > MAX_REL_PATH_LEN {
        bail!(
            "path too long ({} > {MAX_REL_PATH_LEN} bytes)",
            rel.len()
        );
    }
    if rel.contains('\0') {
        bail!("NUL byte in path rejected");
    }
    // Web 上下文路径分隔符只可能是 /；反斜杠是 Windows 分隔符，出现即拒绝
    // （防 ..\\windows 式穿越在 Unix component 匹配下漏网——回归测试 script_rel_rejects_traversal）
    if rel.contains('\\') {
        bail!("backslash in path rejected");
    }
    // Windows：`name:stream` 是 NTFS 交替数据流（ADS）语法，正常文件名不允许冒号。
    // 这里必须显式拒绝，否则 webshell 闸门（would_execute_on_get）可被绕过：
    // `php/shell.php::$DATA` 的扩展名是 `php::$DATA` → 闸门按不存在该扩展名放行，
    // 而 `::$DATA` 指的就是**默认数据流**（即 `shell.php` 本体）→ 写下去的就是
    // 可执行的 shell.php。Linux 上冒号是合法文件名，故只按平台收紧。
    #[cfg(windows)]
    {
        if rel.contains(':') {
            bail!("colon in path rejected (NTFS alternate data stream)");
        }
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
        // 目标**尚不存在**：不能只做词法包含检查。
        //
        // 旧实现：父目录存在就 canonicalize 父目录，父目录不存在就直接用词法拼接的
        // parent 去比前缀 —— 而词法拼接的前缀当然落在 root 里，于是 `root/link/sub/x`
        // （`link` 是指向 root 外的符号链接、`sub` 还不存在）被判为"合法"，
        // 随后的 create_dir_all/fs::write 会顺着 link 把目录/文件建到 root 外
        //（典型后果：`mkdir link/../../etc/x` 被拒，但 `mkdir link/etc/x` 逃逸成功）。
        // 改为与 static_files::resolve_path 同一策略：对**最深的已存在祖先**做
        // canonicalize（符号链接在此被解析）并强制 containment，再把剩余还不存在的
        // 段原样拼回去。
        let mut base = out.clone();
        let mut rest: Vec<std::ffi::OsString> = Vec::new();
        while !base.exists() {
            let parent = base
                .parent()
                .map(|p| p.to_path_buf())
                .ok_or_else(|| anyhow::anyhow!("path escapes root"))?;
            rest.push(base.file_name().unwrap_or_default().to_os_string());
            base = parent;
        }
        let mut canon_base =
            fs::canonicalize(&base).with_context(|| format!("canon {}", base.display()))?;
        if !canon_base.starts_with(&root) && canon_base != root {
            bail!("path escapes root");
        }
        for seg in rest.iter().rev() {
            canon_base.push(seg);
        }
        Ok(canon_base)
    }
}

/// 在 `root_canon` 内**逐级**创建目录树（`dir` 必须来自 [`safe_join`]）。
///
/// 逐级建、逐级 canonicalize 复核，是为了把「校验 → 创建」之间的 TOCTOU 窗口压到最小：
/// 任何一级解析后跑出 root 就立刻删掉这一级并报错，而不是等 create_dir_all 把整棵树
/// 建在 root 外。旧实现直接 create_dir_all，创建后不复核 —— 一旦中间段是符号链接，
/// 逃逸既不会报错也不会回滚。
fn create_dir_all_within(root_canon: &Path, dir: &Path) -> Result<()> {
    let mut base = dir.to_path_buf();
    let mut missing: Vec<PathBuf> = Vec::new();
    while !base.exists() {
        missing.push(base.clone());
        match base.parent() {
            Some(p) => base = p.to_path_buf(),
            None => bail!("path escapes root"),
        }
    }
    // 最深的已存在祖先必须是 root 内的真实路径（符号链接已被 canonicalize 解析掉）。
    let existing =
        fs::canonicalize(&base).with_context(|| format!("canon {}", base.display()))?;
    if !existing.starts_with(root_canon) {
        bail!("path escapes root");
    }
    for d in missing.iter().rev() {
        match fs::create_dir(d) {
            Ok(()) => {}
            // 竞态下别人先建了 -> 交给下面的复核判定，不作为错误。
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("mkdir {}", d.display())),
        }
        let canon = fs::canonicalize(d).with_context(|| format!("re-canon {}", d.display()))?;
        if !canon.starts_with(root_canon) {
            // 只回滚刚建的这一级（remove_dir 只删空目录，不会动 root 外已有的内容）。
            let _ = fs::remove_dir(d);
            bail!("mkdir escaped root (symlink race?)");
        }
    }
    Ok(())
}

pub fn list_dir(root: &Path, rel: &str) -> Result<Vec<DirEntryInfo>> {
    let dir = safe_join(root, rel)?;
    if !dir.is_dir() {
        bail!("not a directory");
    }
    let mut entries = Vec::new();
    for e in fs::read_dir(&dir)? {
        let e = e?;
        // 单个条目 metadata 失败不能拖垮整个目录：悬空符号链接（或正在被并发删除的
        // 文件）会让 `e.metadata()?` 返回错，旧实现直接 `?` 冒泡 —— 面板上
        // 「该目录永久无法列出」，一条坏链接就能把文件管理锁死。
        // 退回 file_type（不跟随符号链接）并把大小记 0。
        let (is_dir, size) = match e.metadata() {
            Ok(m) => (m.is_dir(), m.len()),
            Err(_) => (e.file_type().map(|t| t.is_dir()).unwrap_or(false), 0),
        };
        entries.push(DirEntryInfo {
            name: e.file_name().to_string_lossy().into_owned(),
            is_dir,
            size,
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
    // 先按元数据判上限再读：旧实现是 `fs::read` 之后才比较长度，于是「读一个比上限大得多的
    // 文件」会先把整文件读进内存（root 下放一个几 GB 的文件就能把内存打爆），
    // 之后的 bail 只是事后报错，不省内存。
    let len = fs::metadata(&path)?.len();
    if len > max_bytes as u64 {
        bail!("file too large ({len} > {max_bytes})");
    }
    let data = fs::read(&path)?;
    let binary = is_likely_binary(&data);
    // 读期间文件可能被并发改写/替换 → 再核一次真实长度（上限语义不能被 TOCTOU 绕过）。
    if data.len() > max_bytes {
        bail!("file too large ({} > {max_bytes})", data.len());
    }
    Ok((data, binary))
}

pub fn write_file(root: &Path, rel: &str, data: &[u8]) -> Result<()> {
    if data.len() > MAX_WRITE_BYTES {
        bail!(
            "write too large ({} > {MAX_WRITE_BYTES} bytes)",
            data.len()
        );
    }
    let path = safe_join(root, rel)?;
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| abs(root));
    if let Some(parent) = path.parent() {
        // 与 mkdir 同一套「逐级创建 + 复核」：别顺着符号链接把父目录建到 root 外。
        create_dir_all_within(&root_canon, parent)?;
    }
    // 原子写：旧实现直接 `fs::write`（= 先截断再写），写到一半失败（ENOSPC、被 OOM/强制退出
    // 打断，本项目都有先例）会把**原本完好的文件**毁成一个半截文件 —— 面板报「保存失败」，
    // 而磁盘上那份**旧文件已经被截断**，等于一次失败的保存造成永久数据丢失。
    // 改为同目录临时文件 + rename（与 upload_resume / DNS 落盘同一套）；临时名带 pid + 单调
    // 计数，不可预测（避免 docroot 里有写权限的应用预先放同名符号链接把我们重定向到 root 外）。
    let tmp = path.with_file_name(temp_write_name(&path));
    if let Err(e) = fs::write(&tmp, data) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("write {}", tmp.display()));
    }
    // 内容持久化之后才让它以目标名出现（否则崩溃会留下「长度对、内容却是空洞」的目标文件）。
    // 用**可写**句柄再 sync：只读句柄上的 FlushFileBuffers 在 Windows 上会直接失败。
    if let Ok(f) = fs::OpenOptions::new().write(true).open(&tmp) {
        let _ = f.sync_all();
    }
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename {}", path.display()));
    }
    // TOCTOU: after write, canonicalize and re-check containment (symlink race).
    let written = fs::canonicalize(&path).with_context(|| format!("re-canon {}", path.display()))?;
    if !written.starts_with(&root_canon) {
        let _ = fs::remove_file(&path);
        anyhow::bail!("write escaped root after create (symlink race?)");
    }
    Ok(())
}

/// 同目录写盘临时名：以 `.` 开头 ⇒ 静态层与上传都不服务它、autoindex 也不列出。
fn temp_write_name(path: &Path) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("f");
    format!(
        ".{base}.crucible-write.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// 在 root 下创建目录（含父目录）；已存在同名目录时报错。
pub fn mkdir(root: &Path, rel: &str) -> Result<()> {
    let path = safe_join(root, rel)?;
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| abs(root));
    if path.is_dir() {
        bail!("directory already exists");
    }
    create_dir_all_within(&root_canon, &path)?;
    // 后置复核（与 write_file/rename_path 一致的 TOCTOU 兜底）：建完再解析一次，
    // 跑出 root 就回滚刚建的目录。旧实现的 mkdir 完全没有创建后校验，
    // 顺符号链接建到 root 外时既不报错也不回滚。
    let made = fs::canonicalize(&path).with_context(|| format!("re-canon {}", path.display()))?;
    if !made.starts_with(&root_canon) {
        let _ = fs::remove_dir(&path);
        bail!("mkdir escaped root after create (symlink race?)");
    }
    // 目标原本是**普通文件**时，`create_dir_all_within` 的「最深已存在祖先」直接
    // 命中该文件，一级都不建就返回 Ok，面板会显示「已创建」但磁盘上仍是文件。
    // 建完必须复核类型。
    if !made.is_dir() {
        bail!("target already exists and is not a directory");
    }
    Ok(())
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
        create_dir_all_within(&root_canon, parent)?;
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

/// 把请求里的相对路径归一化成「GET 时真正会用到的 web 路径」。
///
/// 去掉空段与 `.`、折叠重复 `/`；遇到 `..` 或含反斜杠的段返回 `None`
/// （`safe_join` 会拒绝它们）。
///
/// 闸门必须归一化：`safe_join` 会把 `/./php/shell.php` 解析成
/// `<root>/php/shell.php`，而闸门原先拿**原始字符串**去做路由前缀匹配 ——
/// `/./php/shell.php` 不以 `/php/` 开头，于是闸门放行、文件却落进可执行目录，
/// 直接拿到 GET 执行权（webshell）。`%2F.%2Fphp%2F…` URL 解码后同理。
fn web_path_of(rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => return None,
            s if s.contains('\\') => return None,
            s => parts.push(s),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// True if a GET of `rel` under `root` would execute via an app engine (webshell gate).
pub fn would_execute_on_get(lc: &crate::config::ListenerConfig, rel: &str) -> bool {
    // 归一化失败（`..` / 反斜杠）时 fail-closed：宁可拒绝一次上传，
    // 也不要放过一条会落进可执行目录的路径。
    let Some(path) = web_path_of(rel) else {
        return true;
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
            ip_access: None,
            l4_forward: None,
            quic_ecn: false,
            qmux: false,
            connect_udp: false,
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

    /// 超长相对路径必须报错（而不是交给 OS 报一个平台相关的怪错），
    /// 且不能因为截断而落到别的文件上。
    #[test]
    fn safe_join_rejects_oversized_and_nul_paths() {
        let root = std::env::temp_dir().join("crucible_admin_pathlen_test");
        let _ = std::fs::create_dir_all(&root);
        let long = "a".repeat(MAX_REL_PATH_LEN + 1);
        let e = safe_join(&root, &long).unwrap_err().to_string();
        assert!(e.contains("path too long"), "unexpected: {e}");
        assert!(safe_join(&root, &format!("sub/{}{}", "b".repeat(64), "\u{0}x")).is_err());
        // 边界内仍正常。
        assert!(safe_join(&root, &"a".repeat(MAX_REL_PATH_LEN)).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 写入上限：超限直接拒绝（不写半截文件）。
    #[test]
    fn write_file_rejects_oversized_payload() {
        let root = std::env::temp_dir().join("crucible_admin_writecap_test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let big = vec![b'x'; MAX_WRITE_BYTES + 1];
        let e = write_file(&root, "big.bin", &big).unwrap_err().to_string();
        assert!(e.contains("write too large"), "unexpected: {e}");
        assert!(!root.join("big.bin").exists(), "must not leave a partial file");
        assert!(write_file(&root, "ok.txt", b"small").is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 覆盖写要真正落盘（原子写回归），且目录里不留临时文件。
    #[test]
    fn write_file_overwrites_atomically() {
        let root = std::env::temp_dir().join("crucible_admin_atomic_write_test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_file(&root, "a.txt", b"first").unwrap();
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"first");
        write_file(&root, "a.txt", b"second-longer").unwrap();
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"second-longer");
        let leftovers: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("crucible-write"))
            .collect();
        assert!(leftovers.is_empty(), "临时文件残留: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 符号链接逃逸回归：`root/link` → root 外的目录，且中间段 `sub` 不存在。
    /// 词法前缀检查看不出问题（旧实现因此放行），create_dir_all/fs::write 会顺着
    /// link 把目录与文件建到 root 外。加固后必须直接报错且不留下任何外部痕迹。
    #[cfg(unix)]
    #[test]
    fn mkdir_and_write_cannot_escape_via_symlinked_ancestor() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join("crucible_admin_escape_test");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("link")).unwrap();

        assert!(mkdir(&root, "link/sub/dir").is_err(), "mkdir must refuse escaping path");
        assert!(
            !outside.join("sub").exists(),
            "mkdir must not create anything outside root"
        );
        assert!(
            write_file(&root, "link/sub/x.txt", b"pwn").is_err(),
            "write must refuse escaping path"
        );
        assert!(!outside.join("sub").join("x.txt").exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// `mkdir` 落在**已存在的普通文件**上时必须报错：否则 create_dir_all_within 把该
    /// 文件当成「最深的已存在祖先」，一级都不建却返回 Ok，面板显示「已创建」。
    #[test]
    fn mkdir_over_existing_file_must_fail() {
        let root = std::env::temp_dir().join("crucible_admin_mkdir_file_test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();

        assert!(mkdir(&root, "a.txt").is_err(), "mkdir over a file must fail");
        assert!(root.join("a.txt").is_file(), "the file must stay untouched");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 悬空符号链接（或并发被删的条目）不能让整个目录列表失败 ——
    /// 旧实现 `e.metadata()?` 会把错误冒泡，一条坏链接就此锁死面板的文件管理。
    #[cfg(unix)]
    #[test]
    fn list_dir_tolerates_dangling_symlink() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join("crucible_admin_listdir_test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("ok.txt"), b"x").unwrap();
        symlink(root.join("does-not-exist"), root.join("dangling")).unwrap();

        let entries = list_dir(&root, "").expect("list_dir must survive a dangling symlink");
        assert!(entries.iter().any(|e| e.name == "ok.txt"));
        assert!(entries.iter().any(|e| e.name == "dangling"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Windows：NTFS ADS 语法必须被拒 —— 否则 `x.php::$DATA` 的扩展名是
    /// `php::$DATA`（闸门判为不可执行而放行），实际写入的却是 `x.php` 本体。
    #[cfg(windows)]
    #[test]
    fn safe_join_rejects_ntfs_ads() {
        let root = std::env::temp_dir().join("crucible_admin_ads_test");
        let _ = std::fs::create_dir_all(&root);
        assert!(safe_join(&root, "shell.php::$DATA").is_err());
        assert!(safe_join(&root, "sub/x.txt:evil").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
