//! 上传会话与断点续传（规格 §44）。
//!
//! 旧实现是 74 行**零引用死代码**，且自身不安全：`resolve_dest` 把根写死 `/crucible/uploads`、
//! 只查 `contains("..")`、没有 containment、`append()` 既不原子也不并发安全、无临时文件与清理、
//! 也没接鉴权。这里重写成**调用方提供已验证目标路径**的会话层：
//!
//! * 路径安全（`safe_join` + containment + webshell 闸门）由调用方负责 —— 本模块只收 `&Path`；
//! * 落盘 = 同目录临时文件 + 原子 rename：中断/崩溃不会留下半个目标文件；
//! * 续传语义：`append(offset, …)` 要求 `offset == 已收字节数`，否则回
//!   [`UploadErr::OffsetMismatch`]（调用方回 409 + `X-Upload-Offset`）；
//! * 并发：每目标一个会话，片写入在会话锁内串行（支撑浏览器端 4 片并发传同一文件）；
//! * 生命周期：会话带 TTL，维护任务调 [`sweep_expired`] 清理临时文件。

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 会话空闲多久算过期（超时即删临时文件）。
pub const SESSION_TTL: Duration = Duration::from_secs(3600);
/// 单文件上限：超过回 413 并放弃会话（也避免一个请求把盘写满）。
pub const MAX_UPLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// 同时在飞的会话上限（防「只开会话不写完」占满 inode）。
pub const MAX_SESSIONS: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub enum UploadErr {
    /// `Content-Range` 的 start 与已收字节数不符 → 调用方回 409 + 当前偏移。
    OffsetMismatch(u64),
    /// 超过单文件上限 → 413。
    TooLarge,
    /// 会话数超限 → 503。
    TooManySessions,
    /// 同名会话的 total 与本次不一致 → 400（让客户端换名或先 DELETE）。
    TotalMismatch,
    Io(String),
}

pub struct Session {
    /// 目标文件（调用方已做 containment 校验）。
    pub target: PathBuf,
    /// 同目录临时文件：保证 rename 原子（跨目录 rename 不是原子的）。
    pub tmp: PathBuf,
    received: AtomicU64,
    /// 客户端声明的总长度（`Content-Range` 的 `*` → None）。
    pub total: Option<u64>,
    touched: Mutex<Instant>,
    /// 片写入串行化（4 片并发写同一文件时不能交错）。
    lock: Mutex<()>,
}

impl Session {
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// 是否已收齐（客户端没给 total 时无法判定）。
    pub fn complete(&self) -> bool {
        matches!(self.total, Some(t) if t > 0 && self.received() >= t)
    }
}

static SESSIONS: Lazy<Mutex<HashMap<PathBuf, Arc<Session>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 解析 `Content-Range: bytes <start>-<end>/<total|*>` → `(start, end, total)`。
pub fn parse_content_range(v: &str) -> Option<(u64, u64, Option<u64>)> {
    let rest = v.trim().strip_prefix("bytes")?.trim_start();
    let (range, total) = rest.split_once('/')?;
    let (a, b) = range.trim().split_once('-')?;
    let start: u64 = a.trim().parse().ok()?;
    let end: u64 = b.trim().parse().ok()?;
    if end < start {
        return None;
    }
    let total = match total.trim() {
        "*" => None,
        t => Some(t.parse::<u64>().ok()?),
    };
    Some((start, end, total))
}

/// 取（或新建）目标的上传会话。`start` 来自 `Content-Range`（无则 0 = 全量）。
///
/// * `Ok(sess)`：按 `sess.received()` 继续写（`start == 0` 会把临时文件截断重来）；
/// * `Err(OffsetMismatch(cur))`：调用方回 409 + `X-Upload-Offset: cur`。
pub fn session_for(
    target: &Path,
    start: u64,
    total: Option<u64>,
) -> Result<Arc<Session>, UploadErr> {
    if let Some(t) = total {
        if t > MAX_UPLOAD_BYTES {
            return Err(UploadErr::TooLarge);
        }
    }
    let mut map = SESSIONS.lock();
    if let Some(s) = map.get(target).cloned() {
        *s.touched.lock() = Instant::now();
        if let (Some(have), Some(want)) = (s.total, total) {
            if have != want {
                return Err(UploadErr::TotalMismatch);
            }
        }
        if start == 0 {
            // 全量重传：截断临时文件（复用会话，锁不变）。
            let _g = s.lock.lock();
            if let Err(e) = std::fs::File::create(&s.tmp) {
                return Err(UploadErr::Io(e.to_string()));
            }
            s.received.store(0, Ordering::Relaxed);
            return Ok(s);
        }
        if start != s.received() {
            return Err(UploadErr::OffsetMismatch(s.received()));
        }
        return Ok(s);
    }
    if start != 0 {
        // 没有会话却要求从中间续 → 只能从 0 开始（调用方回 409 + X-Upload-Offset: 0）。
        return Err(UploadErr::OffsetMismatch(0));
    }
    if map.len() >= MAX_SESSIONS {
        return Err(UploadErr::TooManySessions);
    }
    let name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "upload".to_string());
    let tmp = target.with_file_name(format!(".{name}.upload.part"));
    if let Err(e) = std::fs::File::create(&tmp) {
        return Err(UploadErr::Io(e.to_string()));
    }
    let sess = Arc::new(Session {
        target: target.to_path_buf(),
        tmp,
        received: AtomicU64::new(0),
        total,
        touched: Mutex::new(Instant::now()),
        lock: Mutex::new(()),
    });
    map.insert(target.to_path_buf(), Arc::clone(&sess));
    Ok(sess)
}

/// 追加一片；返回新的已收字节数。
pub fn append(sess: &Arc<Session>, offset: u64, data: &[u8]) -> Result<u64, UploadErr> {
    let _g = sess.lock.lock();
    let cur = sess.received();
    if offset != cur {
        return Err(UploadErr::OffsetMismatch(cur));
    }
    let next = cur.saturating_add(data.len() as u64);
    if next > MAX_UPLOAD_BYTES {
        return Err(UploadErr::TooLarge);
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&sess.tmp)
        .map_err(|e| UploadErr::Io(e.to_string()))?;
    f.write_all(data).map_err(|e| UploadErr::Io(e.to_string()))?;
    f.flush().map_err(|e| UploadErr::Io(e.to_string()))?;
    sess.received.store(next, Ordering::Relaxed);
    *sess.touched.lock() = Instant::now();
    Ok(next)
}

/// 收齐后原子落盘（临时文件 rename → 目标），并移除会话。
pub fn commit(sess: &Arc<Session>) -> Result<(), UploadErr> {
    let _g = sess.lock.lock();
    std::fs::rename(&sess.tmp, &sess.target).map_err(|e| UploadErr::Io(e.to_string()))?;
    SESSIONS.lock().remove(&sess.target);
    Ok(())
}

/// 放弃会话并删临时文件。
pub fn abort(sess: &Arc<Session>) {
    let _g = sess.lock.lock();
    let _ = std::fs::remove_file(&sess.tmp);
    SESSIONS.lock().remove(&sess.target);
}

/// 清理超时会话（维护任务调用），返回清理数量。
pub fn sweep_expired() -> usize {
    let now = Instant::now();
    let mut map = SESSIONS.lock();
    let dead: Vec<PathBuf> = map
        .iter()
        .filter(|(_, s)| now.duration_since(*s.touched.lock()) > SESSION_TTL)
        .map(|(k, _)| k.clone())
        .collect();
    for k in &dead {
        if let Some(s) = map.remove(k) {
            let _ = std::fs::remove_file(&s.tmp);
        }
    }
    dead.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_range_parses_forms() {
        assert_eq!(parse_content_range("bytes 0-499/1234"), Some((0, 499, Some(1234))));
        assert_eq!(parse_content_range("bytes 500-999/*"), Some((500, 999, None)));
        assert_eq!(parse_content_range("bytes 5-4/10"), None, "end<start 必须拒");
        assert_eq!(parse_content_range("items 0-1/2"), None);
        assert_eq!(parse_content_range("bytes a-b/c"), None);
    }

    #[test]
    fn session_offset_semantics_and_atomic_commit() {
        let dir = std::env::temp_dir().join(format!("crucible-up-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("f1.bin");
        let part = target.with_file_name(".f1.bin.upload.part");
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&part);
        let s = session_for(&target, 0, Some(6)).expect("begin");
        assert_eq!(append(&s, 0, b"abc").unwrap(), 3);
        // 偏移不符必须报错并回当前偏移（调用方据此回 409 + X-Upload-Offset）
        assert_eq!(append(&s, 0, b"x"), Err(UploadErr::OffsetMismatch(3)));
        assert_eq!(append(&s, 1, b"x"), Err(UploadErr::OffsetMismatch(3)));
        // 提交前目标文件不应存在（只该有临时文件）
        assert!(!target.exists(), "未收齐前不能出现目标文件");
        assert_eq!(append(&s, 3, b"def").unwrap(), 6);
        assert!(s.complete());
        commit(&s).expect("commit");
        assert_eq!(std::fs::read(&target).unwrap(), b"abcdef");
        assert!(!part.exists(), "提交后临时文件应消失");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversize_and_missing_session_rejected() {
        let target = std::path::PathBuf::from("/nonexistent/x.bin");
        assert_eq!(
            session_for(&target, 0, Some(MAX_UPLOAD_BYTES + 1)),
            Err(UploadErr::TooLarge)
        );
        assert_eq!(
            session_for(&target, 10, None),
            Err(UploadErr::OffsetMismatch(0)),
            "没有会话却要从中间续 → 应告诉它从 0 开始"
        );
    }
}
