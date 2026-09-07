//! 上传断点续传 — RFC 7233 Range + Content-Range (server side).
//! 内存会话 + 磁盘 spool 目录.
use bytes::Bytes;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct UploadSession {
    pub key: String,
    pub dest_rel: String,
    pub total_size: u64,
    pub written: u64,
    pub last_active: Instant,
    pub done: bool,
}

#[derive(Default)]
pub struct UploadRegistry {
    sessions: RwLock<HashMap<String, UploadSession>>,
    ttl: std::time::Duration,
}


impl UploadRegistry {
    pub async fn create(&self, key: String, dest_rel: String, total_size: u64) -> UploadSession {
        let s = UploadSession { key: key.clone(), dest_rel, total_size, written: 0, last_active: Instant::now(), done: false };
        self.sessions.write().await.insert(key, s.clone());
        s
    }
    pub async fn append(&self, key: &str, body: Bytes, offset: Option<u64>) -> Result<u64, String> {
        let mut s = self.sessions.write().await;
        let session = s.get_mut(key).ok_or("session not found")?;
        if let Some(o) = offset { if o != session.written { return Err(format!("offset mismatch {} vs {}", o, session.written)); } }
        let n = body.len() as u64;
        if session.written + n > session.total_size { return Err("would exceed total_size".into()); }
        let path = self.resolve_dest(&session.dest_rel)?;
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).map_err(|e| e.to_string())?;
        f.write_all(&body).map_err(|e| e.to_string())?;
        session.written += n;
        session.last_active = Instant::now();
        if session.written >= session.total_size { session.done = true; }
        Ok(session.written)
    }
    pub async fn progress(&self, key: &str) -> Option<UploadSession> { self.sessions.read().await.get(key).cloned() }
    pub async fn cancel(&self, key: &str) -> Result<(), String> {
        let dest = { self.sessions.write().await.remove(key).map(|s| s.dest_rel) };
        if let Some(rel) = dest { let _ = std::fs::remove_file(self.resolve_dest(&rel)?); }
        Ok(())
    }
    fn resolve_dest(&self, rel: &str) -> Result<PathBuf, String> {
        if rel.contains("..") { return Err("path traversal".into()); }
        let root = std::path::Path::new("/crucible/uploads");
        std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
        Ok(root.join(rel))
    }
}

pub static UPLOADS: once_cell::sync::Lazy<UploadRegistry> = once_cell::sync::Lazy::new(UploadRegistry::default);

pub fn parse_content_range(v: &http::HeaderValue) -> Result<(u64, u64, u64), String> {
    let s = v.to_str().map_err(|_| "bad CR")?;
    let s = s.strip_prefix("bytes ").ok_or("missing bytes ")?;
    let (range, total) = s.split_once('/').ok_or("missing /")?;
    let total: u64 = total.parse().map_err(|_| "bad total")?;
    let (start, end) = range.split_once('-').ok_or("missing -")?;
    let s: u64 = start.parse().map_err(|_| "bad start")?;
    let e: u64 = end.parse().map_err(|_| "bad end")?;
    if s > e || e >= total { return Err("invalid".into()); }
    Ok((s, e, total))
}
