//! TLS 材料：文件系统路径或粘贴 PEM 正文。

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// 材料文件大小上限：cert/key/ocsp/psk/ech 全都远小于此；超过即视为路径写错而非材料。
const MAX_MATERIAL_BYTES: u64 = 8 * 1024 * 1024;

/// 若内容含 `-----BEGIN` 则视为粘贴 PEM；否则当路径读取。
pub fn load_bytes(path_or_pem: &str) -> Result<Vec<u8>> {
    let s = path_or_pem.trim();
    if s.contains("-----BEGIN") {
        Ok(s.as_bytes().to_vec())
    } else {
        // 只接受**普通文件**并限制大小：`fs::read` 无上界，而路径是运维可配字符串。
        // 指到 /dev/zero 会把内存吃光，指到 FIFO 会**永久阻塞**（本服务只有 2 条
        // tokio worker，一次阻塞就够整站失去响应）；这些都不是「证书材料」的合法形态。
        // 符号链接照常（metadata 跟随链接 → 目标是普通文件即可，ACME 的 live/ 目录靠它）。
        let meta = fs::metadata(s).with_context(|| format!("stat TLS material {s}"))?;
        if !meta.is_file() {
            anyhow::bail!("TLS material {s} 不是普通文件（拒绝 FIFO/设备/目录）");
        }
        if meta.len() > MAX_MATERIAL_BYTES {
            anyhow::bail!(
                "TLS material {s} 过大（{} 字节 > 上限 {MAX_MATERIAL_BYTES}）",
                meta.len()
            );
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_body_passes_through_without_touching_fs() {
        let pem = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
        // 期望值是 trim() 之后的字节：load_bytes 一开始就 `let s = path_or_pem.trim()`
        // 并对**这个**字符串判断/返回（这行为早于本文件的改动）。对 PEM 没有影响 ——
        // 任何 PEM 解析器都不在意尾部空白 —— 所以这里跟着它写，而不是断言一个假的事实。
        assert_eq!(load_bytes(pem).unwrap(), pem.trim().as_bytes());
        // 正对照：返回值确实以 BEGIN 行开头、以 END 行结尾（去掉尾空白后就是原文）。
        let got = load_bytes(pem).unwrap();
        assert!(got.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(got.ends_with(b"-----END CERTIFICATE-----"));
    }

    /// 非普通文件（这里是目录；FIFO/字符设备同理）必须被拒 —— `fs::read` 对 FIFO
    /// 会永久阻塞、对 /dev/zero 会吃光内存。
    #[test]
    fn non_regular_file_is_rejected() {
        let dir = std::env::temp_dir();
        let err = load_bytes(&dir.display().to_string()).unwrap_err();
        assert!(format!("{err:#}").contains("不是普通文件"), "{err:#}");
    }

    #[test]
    fn missing_file_errors() {
        let p = std::env::temp_dir().join("crucible-definitely-missing-cert.pem");
        let _ = std::fs::remove_file(&p);
        assert!(load_bytes(&p.display().to_string()).is_err());
    }
}
