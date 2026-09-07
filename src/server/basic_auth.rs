//! HTTP Basic authentication helpers.

use crate::config::{AdminConfig, BasicAuthConfig};
use crate::server::password;
use http::header::{self, HeaderMap};
use http::Request;

/// True when admin panel must require credentials.
/// Any configured user list enables the gate; empty hashes never authenticate.
pub fn admin_requires_auth(admin: &AdminConfig) -> bool {
    !admin.users.is_empty()
}

/// 泛型化：admin 入口可能收到 Request<Incoming>（h1）或 Request<BoxBody>（h2/h3 复用
/// 完整 admin::handle），鉴权只读 headers，与 body 类型无关。
pub fn check_admin<T>(req: &Request<T>, admin: &AdminConfig) -> bool {
    check_admin_headers(req.headers(), admin)
}

pub fn check_admin_headers(headers: &HeaderMap, admin: &AdminConfig) -> bool {
    if admin.users.is_empty() {
        return true;
    }
    // Only users with a real hash participate; empty-hash entries never grant access.
    let active: Vec<_> = admin
        .users
        .iter()
        .filter(|u| !u.password_hash.is_empty())
        .collect();
    if active.is_empty() {
        // Users listed but none have passwords yet — deny (force set password first).
        return false;
    }
    active
        .iter()
        .any(|u| check_user_pass_headers(headers, &u.username, &u.password_hash))
}

pub fn check_listener<T>(req: &Request<T>, ba: &BasicAuthConfig) -> bool {
    check_listener_headers(req.headers(), ba)
}

/// 供 h2/h3 复用：无 Request 包装，直接对 headers 校验 listener 级 Basic Auth。
pub fn check_listener_headers(headers: &HeaderMap, ba: &BasicAuthConfig) -> bool {
    check_user_pass_headers(headers, &ba.username, &ba.password_hash)
}

fn check_user_pass_headers(headers: &HeaderMap, username: &str, password_hash: &str) -> bool {
    if password_hash.is_empty() {
        return false;
    }
    let Some(val) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = val.to_str() else {
        return false;
    };
    let Some(b64) = s.strip_prefix("Basic ") else {
        return false;
    };
    let decoded = decode_base64(b64.trim()).unwrap_or_default();
    let text = String::from_utf8_lossy(&decoded);
    let Some((user, pass)) = text.split_once(':') else {
        return false;
    };
    if !ct_eq_str(user, username) {
        return false;
    }
    password::verify_password(pass, password_hash).unwrap_or(false)
}

/// 用户名常量时间比较（P2，§16.13）：密码本身已由 argon2id/yescrypt 恒时验证，
/// 这里消除用户名比较的分支时序。长度不等时提前返回——只泄漏长度差，可接受。
fn ct_eq_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = val(bytes[i + 2])?;
        let d = val(bytes[i + 3])?;
        out.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((c << 6) | d);
        }
        i += 4;
    }
    Some(out)
}
