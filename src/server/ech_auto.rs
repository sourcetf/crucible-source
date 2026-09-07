//! ECH (RFC 9460) 自动配置 — 当 ssl.ech=true 且 ech_keys 缺失时生成.
//! 极简实现: X25519 keygen 占位 + 手写 ECHConfig DER 编码 (Section 4.1.2 of RFC).
use anyhow::{Context, Result};
use std::path::Path;

pub struct EchConfigList { pub bytes: Vec<u8>, pub base64: String }

pub fn generate_ech_config_list(public_name: &str, _max_name_length: u16, _cipher_suite: u16) -> anyhow::Result<EchConfigList> {
    if public_name.is_empty() { anyhow::bail!("public_name required"); }
    // 生成 32 字节伪公钥（实际生产应从 cert 内提取或生成 x25519）
    let mut pk = [0u8; 32];
    for (i, b) in pk.iter_mut().enumerate() { *b = (i as u8).wrapping_add(1); }
    let config_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u8).unwrap_or(0));
    let inner: Vec<u8> = {
        let mut v = Vec::new();
        v.extend_from_slice(&0xfe0du16.to_be_bytes()); // version 0xfe0d
        v.push(0x01); // length placeholder (filled below)
        v.push(config_id);
        v.extend_from_slice(&0x0020u16.to_be_bytes()); // kem_id X25519
        v.extend_from_slice(&pk);
        // cipher_suites: TLS_AES_128_GCM_SHA256
        v.extend_from_slice(&[0x30, 0x02, 0x13, 0x01]);
        // extensions empty
        v.extend_from_slice(&[0x30, 0x00]);
        // fix length byte at index 3
        let inner_len = v.len() - 2; // 2 = version bytes
        v[3] = inner_len as u8;
        v
    };
    let mut out = vec![0x30, inner.len() as u8];
    out.extend_from_slice(&inner);
    Ok(EchConfigList { bytes: out.clone(), base64: base64_std(&out) })
}
fn SystemTimeSeed() -> u8 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u8).unwrap_or(0) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gen_and_b64() {
        let l = generate_ech_config_list("v.example.com", 64, 0x1301).unwrap();
        assert!(!l.bytes.is_empty());
        assert!(!l.base64.is_empty());
    }
}
