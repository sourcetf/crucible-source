//! Bridge: PEM → real BoringSSL quinn crypto::ServerConfig (no rustls transport).

use crate::server::Config as BoringServerConfig;
use crate::QuicSslContext;
use boring::pkey::PKey;
use boring::x509::X509;
use std::sync::Arc;

#[derive(Clone)]
pub struct BoringQuicConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub validated: bool,
    crypto: Option<Arc<BoringServerConfig>>,
}

impl BoringQuicConfig {
    pub fn as_quinn_crypto(&self) -> Option<Arc<dyn quinn_proto::crypto::ServerConfig>> {
        self.crypto
            .clone()
            .map(|c| c as Arc<dyn quinn_proto::crypto::ServerConfig>)
    }

    pub fn status_line(&self) -> String {
        if self.crypto.is_some() {
            "quinn-boring: BoringSSL QUIC ServerConfig ready (no rustls transport)".into()
        } else if self.validated {
            "quinn-boring: PEM validated but ServerConfig build failed".into()
        } else {
            "quinn-boring: not validated".into()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BoringQuicServerCrypto;

impl BoringQuicServerCrypto {
    /// 默认构建：**不开启 0-RTT**（规格：0-RTT 默认关）。
    pub fn try_build(cert_pem: &[u8], key_pem: &[u8]) -> Option<BoringQuicConfig> {
        try_build(cert_pem, key_pem)
    }

    /// 显式指定 0-RTT（QUIC early data）的构建入口。
    ///
    /// 调用方应当只在配置里真的开启了 early data 时传 `true`
    /// （TCP 侧同样语义：`ssl.early_data`，见 boring_path.rs）。
    pub fn try_build_with_opts(
        cert_pem: &[u8],
        key_pem: &[u8],
        early_data: bool,
    ) -> Option<BoringQuicConfig> {
        try_build_with_opts(cert_pem, key_pem, early_data)
    }

    pub fn status_line() -> &'static str {
        "quinn-boring: BoringSSL QUIC provider (vendored quinn-btls adapted to boring)"
    }
}

pub fn try_build(cert_pem: &[u8], key_pem: &[u8]) -> Option<BoringQuicConfig> {
    try_build_with_opts(cert_pem, key_pem, false)
}

pub fn try_build_with_opts(
    cert_pem: &[u8],
    key_pem: &[u8],
    early_data: bool,
) -> Option<BoringQuicConfig> {
    if cert_pem.is_empty() || key_pem.is_empty() {
        return None;
    }
    match build_server_crypto(cert_pem, key_pem, early_data) {
        Ok(crypto) => Some(BoringQuicConfig {
            cert_pem: cert_pem.to_vec(),
            key_pem: key_pem.to_vec(),
            validated: true,
            crypto: Some(Arc::new(crypto)),
        }),
        Err(e) => {
            eprintln!("quinn-boring try_build failed: {e}");
            None
        }
    }
}

fn build_server_crypto(
    cert_pem: &[u8],
    key_pem: &[u8],
    early_data: bool,
) -> Result<BoringServerConfig, String> {
    let certs = X509::stack_from_pem(cert_pem).map_err(|e| format!("cert: {e}"))?;
    if certs.is_empty() {
        return Err("empty cert chain".into());
    }
    let key = PKey::private_key_from_pem(key_pem).map_err(|e| format!("key: {e}"))?;

    let mut cfg = BoringServerConfig::new().map_err(|e| format!("ServerConfig::new: {e}"))?;
    // QuicSslContext APIs take ownership (X509 / PKey), not references.
    cfg.ctx_mut()
        .set_certificate(certs[0].clone())
        .map_err(|e| format!("set_certificate: {e}"))?;
    for c in certs.into_iter().skip(1) {
        let _ = cfg.ctx_mut().add_to_cert_chain(c);
    }
    cfg.ctx_mut()
        .set_private_key(key)
        .map_err(|e| format!("set_private_key: {e}"))?;
    let _ = cfg.ctx_mut().check_private_key();
    // 规格：0-RTT 默认关，只有显式开启时才对客户端开放 early data。
    if early_data {
        cfg.enable_early_data(true);
    }
    let _ = cfg.set_alpn(&[b"h3".to_vec()]);
    Ok(cfg)
}
