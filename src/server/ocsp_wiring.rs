//! OCSP 响应加载（PEM/DER 自动识别）+ 同步 HTTP GET (RFC 5019).
//! 与 ocsp_fetcher.rs (智能获取) + boring_path.rs::apply_ocsp (BoringSSL 接线) 协作.
use anyhow::{Context, Result};
use std::io::Read as IoRead;
use std::path::Path;
use std::time::Duration;

pub fn load_ocsp_der(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("read {path:?}"))?;
    if bytes.windows(15).any(|w| w == b"-----BEGIN CER") || bytes.starts_with(b"---") {
        // crude PEM strip: 取每行非空非头/尾行, base64 解码.
        let mut out = Vec::new();
        for line in bytes.split(|&b| b == b'\n') {
            let line: &[u8] = if let Some(end) = line.iter().position(|&b| !b.is_ascii_whitespace()) { let start = line.iter().rposition(|&b| !b.is_ascii_whitespace()).unwrap_or(0); &line[end..=start] } else { &[] };
            if line.is_empty() || line.starts_with(b"---") { continue; }
            decode_b64_into(line, &mut out)?;
        }
        return Ok(out);
    }
    Ok(bytes)
}

fn decode_b64_into(input: &[u8], out: &mut Vec<u8>) -> Result<()> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut tab = [0xffu8; 256];
    for (i, &c) in A.iter().enumerate() { tab[c as usize] = i as u8; }
    let mut buf = [0u8; 4]; let mut cur = 0;
    for &b in input {
        let v = tab[b as usize];
        if v == 0xff { continue; }
        buf[cur] = v; cur += 1;
        if cur == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push(((buf[1] & 0x0f) << 4) | (buf[2] >> 2));
            out.push(((buf[2] & 0x03) << 6) | buf[3]);
            cur = 0;
        }
    }
    if cur >= 2 { out.push((buf[0] << 2) | (buf[1] >> 4)); }
    if cur == 3 { out.push(((buf[1] & 0x0f) << 4) | (buf[2] >> 2)); }
    Ok(())
}

pub fn fetch_http_ocsp(url: &str) -> Result<Vec<u8>> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://").map(|s| ("http", s)) {
        r
    } else if let Some(r) = url.strip_prefix("https://").map(|s| ("https", s)) {
        r
    } else { anyhow::bail!("only http/https OCSP URLs supported, got {url}") };
    let (host_port, path) = match rest.find('/') { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "/") };
    let (host, port) = match host_port.rsplit_once(':') { Some((h,p)) => (h.to_string(), p.parse().unwrap_or(80u16)), None => (host_port.to_string(), if scheme == "https" { 443 } else { 80 }) };
    let host_p: std::net::IpAddr = host.parse().with_context(|| format!("bad OCSP host {host}"))?;
    let mut sock = std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(host_p, port), Duration::from_secs(5))?;
    use std::io::Write as IoWrite;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes())?;
    let mut resp = Vec::new();
    sock.read_to_end(&mut resp)?;
    let body_pos = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow::anyhow!("no HTTP separator"))?;
    Ok(resp[body_pos + 4..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn der_passthrough() {
        let tmp = std::env::temp_dir().join("crucible-ocsp-test.der");
        std::fs::write(&tmp, b"\x30\x03\x01\x01\xff").unwrap();
        let d = load_ocsp_der(&tmp).unwrap();
        assert_eq!(d, vec![0x30, 0x03, 0x01, 0x01, 0xff]);
    }
}
