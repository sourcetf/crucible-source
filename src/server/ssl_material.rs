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
    fs::write(path, pem.as_bytes())
        .with_context(|| format!("write {}", path.display()))
}

pub fn is_pem_body(s: &str) -> bool {
    s.contains("-----BEGIN")
}
