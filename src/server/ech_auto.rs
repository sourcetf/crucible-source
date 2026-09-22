//! ECH 自动配置（RFC 9460 / draft-ietf-tls-esni）。
//!
//! 规格 §16 1.a 的语义：
//!   1. 启动时先找**已经生成的** ECH 配置（`state/ech/ech_keys.pem`）；
//!   2. 若存在且仍满足当前配置（public-name / cipher-suite / max-name-length 一致）→ 直接复用；
//!   3. 否则生成新配置（真实 X25519 keypair）落盘；
//!   4. 无论复用还是新生成，都产出 ECHConfigList 供前端发布 HTTPS(type65) DNS 记录。
//!
//! 编码严格对齐 BoringSSL `bssl generate-ech` 的输出（见 boring 仓库 test/echconfig 向量）：
//! ```text
//! ECHConfig {
//!   uint16 version;                 // 0xfe0d
//!   uint16 length;                  // 其后所有字节长度
//!   uint8  config_id;
//!   uint16 kem_id;                  // 0x0020 = DHKEM(X25519, HKDF-SHA256)
//!   opaque public_key<2^16-1>;      // 2 字节长度前缀 + 32 字节
//!   opaque cipher_suites<4..2^16-4>;// 2 字节长度前缀 + N*(kdf_id, aead_id)
//!   uint8  maximum_name_length;
//!   opaque public_name<1..255>;     // 1 字节长度前缀
//!   opaque extensions<0..2^16-1>;   // 2 字节长度前缀
//! }
//! ECHConfigList { uint16 length; ECHConfig configs<..>; }
//! ```
//! 早期实现把「32 字节伪公钥（(i as u8)+1）」+ 1 字节长度占位拼在一起，
//! 且缺 public_key 长度前缀 / maximum_name_length / public_name——
//! 生成的配置任何客户端都无法用于握手。这里改为真实 X25519 keypair。

use anyhow::{bail, Context, Result};
use boring::pkey::{Id, PKey, Private};
use std::path::{Path, PathBuf};

/// 版本：ECHConfig 的 `version`（RFC 9849 起为 0xfe0d）。
const ECH_VERSION: u16 = 0xfe0d;
/// DHKEM(X25519, HKDF-SHA256)。
const KEM_X25519_HKDF_SHA256: u16 = 0x0020;

// HPKE KDF id
const KDF_HKDF_SHA256: u16 = 0x0001;
const KDF_HKDF_SHA384: u16 = 0x0002;
const KDF_HKDF_SHA512: u16 = 0x0003;
// HPKE AEAD id
const AEAD_AES_128_GCM: u16 = 0x0001;
const AEAD_AES_256_GCM: u16 = 0x0002;
const AEAD_CHACHA20POLY1305: u16 = 0x0003;

/// 默认套件（与 BoringSSL generate-ech 默认一致）。
const DEFAULT_SUITES: &[(u16, u16)] =
    &[(KDF_HKDF_SHA256, AEAD_AES_128_GCM), (KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305)];

/// 默认 maximum_name_length：规格示例给 64。
const DEFAULT_MAX_NAME_LEN: u8 = 64;

/// 一份可用的 ECH 材料。
pub struct EchMaterial {
    /// ECHConfig（单个 config 的 DER，不含 list 长度前缀）。
    pub config: Vec<u8>,
    /// 32 字节 X25519 私钥（HPKE key）。
    pub key: Vec<u8>,
    /// ECHConfigList（2 字节长度前缀 + config）——发布到 HTTPS 记录的就是它。
    pub config_list: Vec<u8>,
    /// 该材料是从磁盘复用的还是新生成的（日志/面板用）。
    pub reused: bool,
}

impl EchMaterial {
    /// ECHConfigList 的 base64——HTTPS(type65) DNS 记录的 ech 参数值。
    pub fn config_list_base64(&self) -> String {
        base64_std(&self.config_list)
    }

    /// Crucible ECH PEM（`ech_pem::load_ech_keys` 可直接加载）。
    pub fn to_pem(&self) -> String {
        format!(
            "-----BEGIN ECH CONFIG-----\n{}\n-----END ECH CONFIG-----\n\
             -----BEGIN ECH PRIVATE KEY-----\n{}\n-----END ECH PRIVATE KEY-----\n",
            wrap64(&base64_std(&self.config)),
            wrap64(&base64_std(&self.key))
        )
    }

    /// 写入 `state/ech/`（ech_keys.pem + ech_config_list.bin）。
    pub fn persist(&self) -> Result<PathBuf> {
        let dir = state_dir();
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let pem = dir.join("ech_keys.pem");
        std::fs::write(&pem, self.to_pem()).with_context(|| format!("write {}", pem.display()))?;
        // 私钥文件：仅所有者可读（OpenBSD 上 0600）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o600));
        }
        let lst = dir.join("ech_config_list.bin");
        std::fs::write(&lst, &self.config_list)
            .with_context(|| format!("write {}", lst.display()))?;
        Ok(pem)
    }
}

/// ECH 状态目录：`state/ech`（相对于进程 cwd，与 `state/dns` 同一约定）。
pub fn state_dir() -> PathBuf {
    let rel = PathBuf::from("state/ech");
    if rel.is_absolute() {
        return rel;
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(rel),
        Err(_) => rel,
    }
}

/// 配置侧期望的 ECH 参数（来自 SslConfig）。
#[derive(Debug, Clone)]
pub struct EchSpec {
    pub public_name: String,
    pub max_name_length: u8,
    pub suites: Vec<(u16, u16)>,
}

impl EchSpec {
    /// 从配置字段构造：`cipher_suite` 形如 `HKDF-SHA384/AES-256-GCM`
    /// （可含多个，逗号或空格分隔；无法识别则回落默认套件）。
    pub fn from_config(
        public_name: Option<&str>,
        cipher_suite: Option<&str>,
        max_name_length: Option<u16>,
    ) -> Result<Self> {
        let public_name = public_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .context("ech_public_name 未配置：无法生成 ECH 配置")?;
        if !valid_public_name(&public_name) {
            bail!("ech_public_name 非法: {public_name:?}");
        }
        let suites = match cipher_suite.map(str::trim).filter(|s| !s.is_empty()) {
            Some(spec) => parse_suites(spec)?,
            None => DEFAULT_SUITES.to_vec(),
        };
        if suites.is_empty() {
            bail!("ech_cipher_suite 解析结果为空");
        }
        let max_name_length = max_name_length
            .map(|v| v.clamp(1, 255) as u8)
            .unwrap_or(DEFAULT_MAX_NAME_LEN);
        Ok(Self { public_name, max_name_length, suites })
    }
}

/// 校验 public-name 是合法域名（避免注入 DNS 记录文本或 named.conf）。
fn valid_public_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && !n.contains("..")
        && !n.starts_with('.')
        && !n.ends_with('.')
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// 解析 `HKDF-SHA384/AES-256-GCM` 形式的套件串。
pub fn parse_suites(spec: &str) -> Result<Vec<(u16, u16)>> {
    let mut out = Vec::new();
    for item in spec.split([',', ' ', ';']).map(str::trim).filter(|s| !s.is_empty()) {
        let (kdf_s, aead_s) = item
            .split_once('/')
            .with_context(|| format!("套件 {item:?} 应为 KDF/AEAD 形式"))?;
        let kdf = match kdf_s.trim().to_ascii_uppercase().as_str() {
            "HKDF-SHA256" | "SHA256" => KDF_HKDF_SHA256,
            "HKDF-SHA384" | "SHA384" => KDF_HKDF_SHA384,
            "HKDF-SHA512" | "SHA512" => KDF_HKDF_SHA512,
            other => bail!("未知 KDF {other:?}"),
        };
        let aead = match aead_s.trim().to_ascii_uppercase().as_str() {
            "AES-128-GCM" | "AES128-GCM" => AEAD_AES_128_GCM,
            "AES-256-GCM" | "AES256-GCM" => AEAD_AES_256_GCM,
            "CHACHA20POLY1305" | "CHACHA20-POLY1305" => AEAD_CHACHA20POLY1305,
            other => bail!("未知 AEAD {other:?}"),
        };
        if !out.contains(&(kdf, aead)) {
            out.push((kdf, aead));
        }
    }
    Ok(out)
}

/// 生成一份新的 ECH 材料（真实 X25519 keypair）。
pub fn generate(spec: &EchSpec) -> Result<EchMaterial> {
    let pkey = PKey::generate(Id::X25519).context("X25519 keygen")?;
    let (key, public) = raw_x25519(&pkey)?;
    let config_id = 1u8; // BoringSSL 测试向量亦用 1；0 留给 retry config 之外的语义
    let config = encode_config(config_id, &public, spec)?;
    let config_list = encode_config_list(&config);
    Ok(EchMaterial { config, key, config_list, reused: false })
}

/// 取 X25519 原始私钥/公钥（各 32 字节）。
fn raw_x25519(pkey: &PKey<Private>) -> Result<(Vec<u8>, Vec<u8>)> {
    let plen = pkey.raw_private_key_len().context("raw_private_key_len")?;
    let mut pbuf = vec![0u8; plen];
    let key = pkey
        .raw_private_key(&mut pbuf)
        .context("raw_private_key")?
        .to_vec();
    let qlen = pkey.raw_public_key_len().context("raw_public_key_len")?;
    let mut qbuf = vec![0u8; qlen];
    let public = pkey
        .raw_public_key(&mut qbuf)
        .context("raw_public_key")?
        .to_vec();
    if key.len() != 32 || public.len() != 32 {
        bail!(
            "X25519 raw sizes unexpected: key={} public={}",
            key.len(),
            public.len()
        );
    }
    Ok((key, public))
}

/// 按 BoringSSL 布局编码单个 ECHConfig。
fn encode_config(config_id: u8, public_key: &[u8], spec: &EchSpec) -> Result<Vec<u8>> {
    if public_key.len() > u16::MAX as usize {
        bail!("public key too large");
    }
    if spec.public_name.len() > 255 {
        bail!("public_name too long (max 255)");
    }
    let mut body = Vec::new();
    body.push(config_id);
    body.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    body.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    body.extend_from_slice(public_key);
    // cipher_suites：2 字节总长 + N*(kdf,aead)
    let suites_len = (spec.suites.len() * 4) as u16;
    if suites_len < 4 {
        bail!("cipher_suites 数量非法: {}", spec.suites.len());
    }
    body.extend_from_slice(&suites_len.to_be_bytes());
    for (kdf, aead) in &spec.suites {
        body.extend_from_slice(&kdf.to_be_bytes());
        body.extend_from_slice(&aead.to_be_bytes());
    }
    body.push(spec.max_name_length);
    let name = spec.public_name.as_bytes();
    body.push(name.len() as u8);
    body.extend_from_slice(name);
    body.extend_from_slice(&0u16.to_be_bytes()); // extensions

    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&ECH_VERSION.to_be_bytes());
    if body.len() > u16::MAX as usize {
        bail!("ECHConfig body too large");
    }
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// ECHConfigList：2 字节长度前缀 + config。
fn encode_config_list(config: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(config.len() + 2);
    out.extend_from_slice(&(config.len() as u16).to_be_bytes());
    out.extend_from_slice(config);
    out
}

/// 解析 ECHConfig，取出 (public_name, max_name_length, suites)，用于「是否仍满足当前配置」的比对。
pub fn parse_config(config: &[u8]) -> Result<(String, u8, Vec<(u16, u16)>)> {
    let mut p = 0usize;
    fn take<'a>(c: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8]> {
        if *p + n > c.len() {
            bail!("ECHConfig 截断");
        }
        let s = &c[*p..*p + n];
        *p += n;
        Ok(s)
    }
    let version = u16::from_be_bytes(take(config, &mut p, 2)?.try_into().unwrap());
    if version != ECH_VERSION {
        bail!("ECHConfig 版本非 0xfe0d: {version:#x}");
    }
    let _len = u16::from_be_bytes(take(config, &mut p, 2)?.try_into().unwrap());
    let _config_id = take(config, &mut p, 1)?[0];
    let kem = u16::from_be_bytes(take(config, &mut p, 2)?.try_into().unwrap());
    if kem != KEM_X25519_HKDF_SHA256 {
        bail!("ECHConfig KEM 非 X25519-HKDF-SHA256: {kem:#x}");
    }
    let pk_len = u16::from_be_bytes(take(config, &mut p, 2)?.try_into().unwrap()) as usize;
    let _pk = take(config, &mut p, pk_len)?;
    let suites_len = u16::from_be_bytes(take(config, &mut p, 2)?.try_into().unwrap()) as usize;
    if suites_len % 4 != 0 {
        bail!("cipher_suites 长度非 4 的倍数");
    }
    let mut suites = Vec::new();
    for _ in 0..(suites_len / 4) {
        let kdf = u16::from_be_bytes(take(config, &mut p, 2)?.try_into().unwrap());
        let aead = u16::from_be_bytes(take(config, &mut p, 2)?.try_into().unwrap());
        suites.push((kdf, aead));
    }
    let max_name_length = take(config, &mut p, 1)?[0];
    let name_len = take(config, &mut p, 1)?[0] as usize;
    let name = String::from_utf8_lossy(take(config, &mut p, name_len)?).into_owned();
    let _ext_len = u16::from_be_bytes(take(config, &mut p, 2)?.try_into().unwrap());
    Ok((name, max_name_length, suites))
}

/// 读取磁盘上已有的 ECH 材料（`state/ech/ech_keys.pem`）。
fn load_persisted() -> Option<(Vec<u8>, Vec<u8>)> {
    let pem_path = state_dir().join("ech_keys.pem");
    let text = std::fs::read_to_string(&pem_path).ok()?;
    let config_b64 = pem_block(&text, "ECH CONFIG")?;
    let key_b64 = pem_block(&text, "ECH PRIVATE KEY")?;
    let config = base64_decode(&config_b64)?;
    let key = base64_decode(&key_b64)?;
    if config.is_empty() || key.len() != 32 {
        return None;
    }
    Some((config, key))
}

fn pem_block(text: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let s = text.find(&begin)? + begin.len();
    let e = text[s..].find(&end)? + s;
    Some(text[s..e].chars().filter(|c| !c.is_whitespace()).collect())
}

/// 规格 §16 1.a 的核心：**先复用，不满足再生成**。
///
/// 复用条件（全部满足才复用）：
///   - 磁盘上存在可解析的 config + 32 字节私钥；
///   - config 的 public_name / maximum_name_length / cipher_suites 与当前配置一致。
/// 任一不满足 → 重新生成并落盘。
pub fn ensure_material(spec: &EchSpec) -> Result<EchMaterial> {
    if let Some((config, key)) = load_persisted() {
        match parse_config(&config) {
            Ok((name, mlen, suites)) => {
                let same_name = name.eq_ignore_ascii_case(&spec.public_name);
                let same_suites = {
                    let mut a = suites.clone();
                    let mut b = spec.suites.clone();
                    a.sort_unstable();
                    b.sort_unstable();
                    a == b
                };
                if same_name && mlen == spec.max_name_length && same_suites {
                    log::info!(
                        "ech: 复用已有配置 (public_name={name} max_name_length={mlen} suites={})",
                        suites.len()
                    );
                    let config_list = encode_config_list(&config);
                    return Ok(EchMaterial { config, key, config_list, reused: true });
                }
                log::info!(
                    "ech: 已有配置不匹配当前设置 (name={name} mlen={mlen} suites={})，重新生成",
                    suites.len()
                );
            }
            Err(e) => log::warn!("ech: 已有配置无法解析（{e:#}），重新生成"),
        }
    }
    let mat = generate(spec)?;
    match mat.persist() {
        Ok(p) => log::info!("ech: 已生成并落盘 {}", p.display()),
        Err(e) => log::warn!("ech: 生成成功但落盘失败: {e:#}"),
    }
    Ok(mat)
}

/// 便捷入口：直接从 SslConfig 三段字段得到 ECH 材料。
pub fn ensure_from_config(
    public_name: Option<&str>,
    cipher_suite: Option<&str>,
    max_name_length: Option<u16>,
) -> Result<EchMaterial> {
    let spec = EchSpec::from_config(public_name, cipher_suite, max_name_length)?;
    ensure_material(&spec)
}

/// 读回已落盘的 ECHConfigList（type65 记录用）。
pub fn persisted_config_list() -> Option<Vec<u8>> {
    let p = state_dir().join("ech_config_list.bin");
    match std::fs::read(&p) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// 读回已落盘的 ECHConfigList 的 base64。
pub fn persisted_config_list_base64() -> Option<String> {
    persisted_config_list().map(|v| base64_std(&v))
}

/// 兼容旧入口：只生成 config list（不做持久化复用）。
/// 保留名字以免破坏既有调用点；新代码应优先用 [`ensure_material`]。
pub fn generate_ech_config_list(
    public_name: &str,
    max_name_length: u16,
    _cipher_suite: u16,
) -> anyhow::Result<EchConfigList> {
    let spec = EchSpec::from_config(Some(public_name), None, Some(max_name_length))?;
    let mat = generate(&spec)?;
    // 先取 base64 再移动 bytes（Vec<u8> 非 Copy，顺序反了会 partial move）。
    let base64 = mat.config_list_base64();
    Ok(EchConfigList { bytes: mat.config_list, base64 })
}

pub struct EchConfigList {
    pub bytes: Vec<u8>,
    pub base64: String,
}

/// 诊断：磁盘上是否存在 ECH 材料。
pub fn has_persisted() -> bool {
    load_persisted().is_some()
}

/// 状态目录路径（供面板展示）。
pub fn pem_path() -> PathBuf {
    Path::new(&state_dir()).join("ech_keys.pem")
}

// ---------- 编解码工具 ----------

fn base64_std(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[((b0 & 0x03) << 4 | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((b1 & 0x0f) << 2 | (b2 >> 6)) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in s.as_bytes() {
        if b == b'=' {
            break;
        }
        let Some(v) = val(b) else { continue };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// PEM 正文按 64 列折行（与 OpenSSL/bssl 输出观感一致）。
fn wrap64(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 64 + 2);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && i % 64 == 0 {
            out.push('\n');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_layout_matches_boringssl() {
        // 用固定公钥验证编码布局与 BoringSSL 向量一致（比的是结构，不是密钥值）。
        let spec = EchSpec {
            public_name: "ech.com".into(),
            max_name_length: 0,
            suites: vec![
                (KDF_HKDF_SHA256, AEAD_AES_128_GCM),
                (KDF_HKDF_SHA256, AEAD_CHACHA20POLY1305),
            ],
        };
        let pk = [0xbbu8; 32];
        let c = encode_config(0, &pk, &spec).unwrap();
        assert_eq!(&c[0..2], &[0xfe, 0x0d]); // version
        assert_eq!(&c[4..5], &[0x00]); // config_id
        assert_eq!(&c[5..7], &[0x00, 0x20]); // kem_id
        assert_eq!(&c[7..9], &[0x00, 0x20]); // public_key len = 32
        assert_eq!(&c[41..43], &[0x00, 0x08]); // cipher_suites len = 8
        assert_eq!(&c[43..45], &[0x00, 0x01]); // kdf
        assert_eq!(&c[45..47], &[0x00, 0x01]); // aead
        assert_eq!(&c[47..49], &[0x00, 0x01]); // kdf
        assert_eq!(&c[49..51], &[0x00, 0x03]); // aead
        assert_eq!(c[51], 0x00); // maximum_name_length
        assert_eq!(c[52], 0x07); // public_name len
        assert_eq!(&c[53..60], b"ech.com");
        assert_eq!(&c[60..62], &[0x00, 0x00]); // extensions
        assert_eq!(c.len(), 62);
        // length 字段 = 其后字节数
        let len = u16::from_be_bytes([c[2], c[3]]) as usize;
        assert_eq!(len, c.len() - 4);
    }

    #[test]
    fn roundtrip_parse() {
        let spec = EchSpec::from_config(
            Some("v.example.com"),
            Some("HKDF-SHA384/AES-256-GCM"),
            Some(64),
        )
        .unwrap();
        let mat = generate(&spec).unwrap();
        let (name, mlen, suites) = parse_config(&mat.config).unwrap();
        assert_eq!(name, "v.example.com");
        assert_eq!(mlen, 64);
        assert_eq!(suites, vec![(KDF_HKDF_SHA384, AEAD_AES_256_GCM)]);
        assert_eq!(mat.key.len(), 32);
        // config_list = 2 字节长度 + config
        assert_eq!(mat.config_list.len(), mat.config.len() + 2);
        assert_eq!(
            u16::from_be_bytes([mat.config_list[0], mat.config_list[1]]) as usize,
            mat.config.len()
        );
        // PEM 往返
        let pem = mat.to_pem();
        assert!(pem.contains("BEGIN ECH CONFIG"));
        assert!(pem.contains("BEGIN ECH PRIVATE KEY"));
        let cfg_b64 = pem_block(&pem, "ECH CONFIG").unwrap();
        assert_eq!(base64_decode(&cfg_b64).unwrap(), mat.config);
    }

    /// 生成的私钥必须与配置里的公钥配对：用 HpkeKey 初始化不报错即格式正确，
    /// 并用 boring 的 ECH API 真正装载一次（最接近真实使用的校验）。
    #[test]
    fn material_loads_into_boringssl() {
        let spec = EchSpec::from_config(Some("crucible.local"), None, Some(64)).unwrap();
        let mat = generate(&spec).unwrap();
        let keys = crate::server::tls::ech_pem::load_ech_keys(mat.to_pem().as_bytes())
            .expect("generated PEM must load into SslEchKeys");
        drop(keys);
    }

    #[test]
    fn suite_parsing() {
        assert_eq!(parse_suites("HKDF-SHA256/AES-128-GCM").unwrap(), vec![(1, 1)]);
        assert_eq!(parse_suites("HKDF-SHA384/AES-256-GCM").unwrap(), vec![(2, 2)]);
        assert_eq!(
            parse_suites("HKDF-SHA256/AES-128-GCM CHACHA20POLY1305/HKDF-SHA256").is_err(),
            true
        );
        assert!(parse_suites("bogus").is_err());
        assert!(parse_suites("HKDF-SHA256/BOGUS-AEAD").is_err());
    }

    #[test]
    fn public_name_validation() {
        assert!(valid_public_name("v.qq.com"));
        assert!(!valid_public_name(""));
        assert!(!valid_public_name("a..b"));
        assert!(!valid_public_name("evil\nzone"));
        assert!(!valid_public_name(".leading"));
    }

    #[test]
    fn base64_roundtrip() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = base64_std(&data);
        assert_eq!(base64_decode(&e).unwrap(), data);
    }
}