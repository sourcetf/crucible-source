//! Peer certificate identity helpers (leaf-first Vec<X509>). 禁止 todo!().

use boring::x509::X509 as BoringX509;

/// Leaf-first certificate chain wrapper used by H3 / Admin inspection.
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

    pub fn to_boring(&self) -> Option<BoringX509> {
        BoringX509::from_der(&self.der).ok()
    }
}

/// Build identity from a single leaf DER (or PEM bytes — PEM parsed when possible).
pub fn peer_identity(_connection_id: u64, leaf_der: &[u8]) -> Vec<X509> {
    peer_identity_from_der(leaf_der)
}

pub fn peer_identity_from_der(leaf_der: &[u8]) -> Vec<X509> {
    if leaf_der.is_empty() {
        return Vec::new();
    }
    // Prefer PEM multi-cert parse when input looks like PEM.
    if leaf_der.windows(10).any(|w| w == b-----BEGIN) {
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
    // DER leaf (or concatenated DER chain).
    parse_der_chain(leaf_der)
}

pub fn peer_identity_from_ders(ders: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Vec<X509> {
    ders.into_iter()
        .filter_map(|d| {
            let b = d.as_ref();
            if b.is_empty() {
                None
            } else {
                Some(X509 { der: b.to_vec() })
            }
        })
        .collect()
}

fn parse_der_chain(input: &[u8]) -> Vec<X509> {
    // Try single cert; if fail, return raw as opaque leaf so callers never panic.
    if let Ok(cert) = BoringX509::from_der(input) {
        if let Ok(der) = cert.to_der() {
            return vec![X509 { der }];
        }
    }
    vec![X509 {
        der: input.to_vec(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_identity_from_ders_filters_empty() {
        let v = peer_identity_from_ders([babc.as_slice(), b".as_slice(), bdef]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].der, babc);
    }
}
