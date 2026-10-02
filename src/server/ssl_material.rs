//! TLS 材料：文件系统路径或粘贴 PEM 正文。

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// 若内容含 `-----BEGIN` 则视为粘贴 PEM；否则当路径读取。
pub fn load_bytes(path_or_pem: &str) -> Result<Vec<u8>> {
    let s = path_or_pem.trim();
    if s.contains("-----BEGIN") {
        Ok(s.as_bytes().to_vec())
    } else {
        fs::read(s).with_context(|| format!("read TLS material {s}"))
    }
}

pub fn load_string(path_or_pem: &str) -> Result<String> {
    Ok(String::from_utf8_lossy(&load_bytes(path_or_pem)?).into_owned())
}

/// 可选写入：把粘贴的 PEM 落盘到指定路径（Admin 保存用）。
pub fn write_pem_file(path: &Path, pem: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // 面板「粘贴 PEM」落盘的内容**可能是私钥**（cert/key 都走这里），所以创建时就 0600，
    // 而不是 umask 权限（0644）。当前没有调用者，但留一个「默认 0644 写私钥」的 helper
    // 迟早会被用上。
    {
        use std::io::Write;
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .with_context(|| format!("create {}", path.display()))?
        };
        #[cfg(not(unix))]
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        f.write_all(pem.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(())
}

pub fn is_pem_body(s: &str) -> bool {
    s.contains("-----BEGIN")
}
