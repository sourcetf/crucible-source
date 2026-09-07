//! argon2id / yescrypt password hashing with per-hash salt.
//! UI never accepts pasted hashes — only plaintext passwords.

use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher as ArgonHasher, PasswordVerifier as ArgonVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use yescrypt::{PasswordHasher as YesHasher, PasswordVerifier as YesVerifier, Yescrypt};

/// Preferred algorithm for new hashes.
#[derive(Clone, Copy, Debug)]
pub enum HashAlgo {
    Argon2id,
    Yescrypt,
}

/// New hashes prefer yescrypt (`$y$…`); argon2id remains fully supported for verify.
pub fn hash_password(plain: &str) -> Result<String> {
    hash_password_with(plain, HashAlgo::Yescrypt)
}

pub fn hash_password_with(plain: &str, algo: HashAlgo) -> Result<String> {
    if plain.is_empty() {
        anyhow::bail!("password empty");
    }
    match algo {
        HashAlgo::Argon2id => hash_argon2id(plain),
        HashAlgo::Yescrypt => match hash_yescrypt(plain) {
            Ok(h) => Ok(h),
            Err(e) => {
                log::warn!("yescrypt hash failed ({e:#}); falling back to argon2id");
                hash_argon2id(plain)
            }
        },
    }
}

fn hash_argon2id(plain: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?
        .to_string();
    Ok(hash)
}

fn hash_yescrypt(plain: &str) -> Result<String> {
    let y = Yescrypt::default();
    let ph = y
        .hash_password(plain.as_bytes())
        .map_err(|e| anyhow::anyhow!("yescrypt hash: {e}"))?;
    Ok(ph.to_string())
}

pub fn verify_password(plain: &str, hash: &str) -> Result<bool> {
    if hash.is_empty() {
        return Ok(false);
    }
    if hash.starts_with("$argon2") {
        let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("parse hash: {e}"))?;
        return Ok(Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok());
    }
    if hash.starts_with("$y$") {
        return verify_yescrypt(plain, hash);
    }
    // Unknown prefix: try argon2 then yescrypt.
    if let Ok(parsed) = PasswordHash::new(hash) {
        if Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok()
        {
            return Ok(true);
        }
    }
    verify_yescrypt(plain, hash).or(Ok(false))
}

fn verify_yescrypt(plain: &str, hash: &str) -> Result<bool> {
    let y = Yescrypt::default();
    let parsed = yescrypt::PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("parse yescrypt hash: {e}"))?;
    Ok(y.verify_password(plain.as_bytes(), &parsed).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_roundtrip() {
        let h = hash_password_with("secret", HashAlgo::Argon2id).unwrap();
        assert!(verify_password("secret", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn yescrypt_roundtrip() {
        let h = hash_password_with("secret", HashAlgo::Yescrypt).unwrap();
        assert!(h.starts_with("$y$") || h.starts_with("$argon2"));
        assert!(verify_password("secret", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }
}
