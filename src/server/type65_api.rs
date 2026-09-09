//! Type 65 ALPN API for HTTP/3 over QMux (draft-ietf-quic-qmux-01).
//! 供 h3.rs 使用的 ALPN 类型标识。

/// ALPN 标识符：h3-qmux (Type 65)
pub const ALPN_H3_QMUX: &[u8] = b"h3-qmux";

/// 注册 Type 65 ALPN
pub fn alpn_qmux() -> Vec<u8> {
    ALPN_H3_QMUX.to_vec()
}
