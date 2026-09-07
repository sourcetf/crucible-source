//! Peer certificate identity helpers (leaf-first). Never use todo!().

use boring::x509::X509 as BoringX509;

#[derive(Clone, Debug)]
pub struct X509 {
    pub der: Vec<u8>,
}

impl X509 {
    pub fn from_der(der: &[u8]) -> Option<Self> {
        if der.is_empty() {
            return None;
        }
        Some(Self { der: der.to_vec() })
    }
}

pub fn peer_identity(_connection_id: u64, leaf_der: &[u8]) -> Vec<X509> {
    peer_identity_from_der(leaf_der)
}

pub fn peer_identity_from_der(leaf_der: &[u8]) -> Vec<X509> {
    if leaf_der.is_empty() {
        return Vec::new();
    }
    if leaf_der.windows(10).any(|w| w == b"-----BEGIN") {
        if let Ok(certs) = BoringX509::stack_from_pem(leaf_der) {
            let mut out = Vec::with_capacity(certs.len());
            for c in certs {
                if let Ok(der) = c.to_der() {
                    out.push(X509 { der });
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    if let Ok(cert) = BoringX509::from_der(leaf_der) {
        if let Ok(der) = cert.to_der() {
            return vec![X509 { der }];
        }
    }
    vec![X509 {
        der: leaf_der.to_vec(),
    }]
}

pub fn peer_identity_from_ders(ders: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Vec<X509> {
    ders.into_iter()
        .filter_map(|d| {
            let b = d.as_ref();
            (!b.is_empty()).then(|| X509 { der: b.to_vec() })
        })
        .collect()
}
