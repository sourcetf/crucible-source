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
/// 「从 0 全量重传」允许截断旧会话前，旧会话必须静默多久。
/// 30s 足以区分「客户端断线后重试」与「另一个客户端在并发上传同名文件」。
pub const RESET_IDLE_GRACE: Duration = Duration::from_secs(30);
/// **进程内**在飞字节上限（所有会话已收字节之和）。
///
/// 为什么要有：单文件上限（2GiB）与会话数上限（256）都是**逐个**计量的，乘起来是 512GiB，
/// 而一台小机器的盘只有几十 GB —— 一个匿名客户端开 256 个会话、每个写几百 MB 就能把盘写满
/// （本项目历史上真的被写满过一次：GeoIP 的 merge 因此死在半路）。这里给一个全局预算，
/// 与下面的「磁盘余量闸门」一起把「用上传打满磁盘」这条路堵死。
/// 与单文件上限取同一个值：既要**支持**文档承诺的单文件上限（否则 2GiB 的上限永远是空话、
/// 1GiB 以上直接 507），又要给并发上传一个全局闸门。真正兜住磁盘的是下面的余量闸门。
pub const MAX_INFLIGHT_BYTES: u64 = MAX_UPLOAD_BYTES;
/// 同一来源 IP 的并发会话上限（防单机占满会话表，把正常用户挤成 503）。
pub const MAX_SESSIONS_PER_IP: usize = 16;
/// 磁盘余量下限：低于它就不再接受新的写入（留出系统/日志/数据库的呼吸空间）。
pub const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;

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
    /// 进程在飞字节预算或磁盘余量不足 → 507（不是客户端的错，也不是请求格式错）。
    NoSpace,
    Io(String),
}

pub struct Session {
    /// 目标文件（调用方已做 containment 校验）。
    pub target: PathBuf,
    /// 创建该会话的来源 IP：释放「每 IP 会话数」配额时要按它回收。
    owner: Option<std::net::IpAddr>,
    /// 同目录临时文件：保证 rename 原子（跨目录 rename 不是原子的）。
    pub tmp: PathBuf,
    received: AtomicU64,
    /// 客户端声明的总长度（`Content-Range` 的 `*` → None）。
    pub total: Option<u64>,
    /// 本次是否用了 `Content-Range: bytes N-M/*`（RFC 合法的「总长未知」写法）。
    ///
    /// 必须与「压根没有 Content-Range」区分开：后者读到 EOF 就是完整文件；
    /// 而 `*/` 形式的第一片**不是**完整文件，当成完成会 ① 201 让客户端以为传完（文件被静默截断）
    /// ② 会话被 commit 掉，后续分片只会收到 409 OffsetMismatch(0)，永远拼不回来。
    pub wildcard_total: std::sync::atomic::AtomicBool,
    touched: Mutex<Instant>,
    /// 片写入串行化（4 片并发写同一文件时不能交错）。
    lock: Mutex<()>,
}

impl Session {
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    pub fn is_wildcard_total(&self) -> bool {
        self.wildcard_total.load(Ordering::Relaxed)
    }

    pub fn mark_wildcard_total(&self) {
        self.wildcard_total.store(true, Ordering::Relaxed);
    }

    /// 客户端给出具体 total 之后就不该再按「未知长度」对待（否则收尾片永远 202）。
    pub fn clear_wildcard_total(&self) {
        self.wildcard_total.store(false, Ordering::Relaxed);
    }

    /// 是否已收齐。`total = Some(0)`（空文件）也算完成 —— 旧实现带 `t > 0` 条件，
    /// 于是 `Content-Length: 0` / `bytes 0-0/0` 永远回 202、目标文件永不生成。
    pub fn complete(&self) -> bool {
        matches!(self.total, Some(t) if self.received() >= t)
    }
}

static SESSIONS: Lazy<Mutex<HashMap<PathBuf, Arc<Session>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 进程级预算：在飞字节数 + 每 IP 会话数（会话增删时同步维护）。
#[derive(Default)]
struct Budget {
    /// 已落盘字节（各会话 `received` 之和）。
    inflight: u64,
    /// **已声明但还没写完**的字节（各会话 `total` 之和）。
    ///
    /// 少了这一项，「先开 256 个声明 2GiB 的会话、再慢慢写」就能绕过在飞预算 ——
    /// 检查时必须 `inflight + reserved` 一起算。它只会**高估**（同一会话两个数都算），
    /// 高估是安全方向。我的第一版只检查不记账，被自己的单测抓出来。
    reserved: u64,
    by_ip: HashMap<std::net::IpAddr, usize>,
}

static BUDGET: Lazy<Mutex<Budget>> = Lazy::new(|| Mutex::new(Budget::default()));

/// 目标所在文件系统的可用字节（拿不到就返回 `None` = 不做这道判断）。
///
/// **必须沿父目录上溯**：上传目标是**还不存在**的新文件，直接 `statvfs(目标)` 会 ENOENT
/// ⇒ 返回 None ⇒ 磁盘闸门永远不会生效（我自己写的单测抓到了这一点）。语义上也该看
/// 「它将被创建在哪块盘上」。
#[cfg(unix)]
fn free_bytes(path: &Path) -> Option<u64> {
    let mut p = path;
    loop {
        if let Some(free) = statvfs_free(p) {
            return Some(free);
        }
        p = p.parent()?;
    }
}

#[cfg(unix)]
fn statvfs_free(p: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs 只写它自己的结构体；c 是合法的 NUL 结尾路径。
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(not(unix))]
fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

/// 磁盘余量下限（字节）。默认 [`MIN_FREE_BYTES`]，可用环境变量 `CRUCIBLE_MIN_FREE_BYTES`
/// 覆盖：
/// * 运维：磁盘很小的机器可以**调高**它（留更多呼吸空间）；
/// * 验证：可以**调到必然触发**的值，确认这道闸门真的接在落盘路径上 —— 这类「检查了但
///   没接上」的闸门是最难发现的（本项目 §21.18 就踩过一个：statvfs 对新文件 ENOENT，
///   闸门从来没生效，全靠单测才发现）。
fn min_free_bytes() -> u64 {
    use std::sync::OnceLock;
    static OVERRIDE: OnceLock<Option<u64>> = OnceLock::new();
    OVERRIDE
        .get_or_init(|| {
            std::env::var("CRUCIBLE_MIN_FREE_BYTES")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        })
        .unwrap_or(MIN_FREE_BYTES)
}

/// 磁盘余量闸门：目标盘可用空间不足 `min_free_bytes() + 本次要写的量` 时拒绝。
fn space_ok(target: &Path, want: u64) -> bool {
    match free_bytes(target) {
        Some(free) => free >= min_free_bytes().saturating_add(want),
        None => true, // 拿不到就只靠字节预算兜着
    }
}

/// 会话结束时回收预算（每 IP 计数 + 在飞字节）。
fn release_budget(sess: &Session) {
    let mut b = BUDGET.lock();
    b.inflight = b.inflight.saturating_sub(sess.received());
    b.reserved = b.reserved.saturating_sub(sess.total.unwrap_or(0));
    if let Some(ip) = sess.owner {
        if let Some(c) = b.by_ip.get_mut(&ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                b.by_ip.remove(&ip);
            }
        }
    }
}

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
    peer: Option<std::net::IpAddr>,
) -> Result<Arc<Session>, UploadErr> {
    if let Some(t) = total {
        if t > MAX_UPLOAD_BYTES {
            return Err(UploadErr::TooLarge);
        }
    }
    // 新建会话前的三道闸门（对**已有**会话的续传不重复计费，见下）。
    // 已知总量时按总量预留，避免「先开 256 个 2GiB 会话、再慢慢写」绕过预算。
    let reserve = total.unwrap_or(0);
    if !space_ok(target, reserve) {
        return Err(UploadErr::NoSpace);
    }
    let mut map = SESSIONS.lock();
    if let Some(s) = map.get(target).cloned() {
        // **先算空闲时长**，再决定放行/拒绝 —— 只有**放行**才刷新 touched。
        // 否则被拒的并发请求会把会话一直"焐热"，`RESET_IDLE_GRACE` 永远走不完，
        // 该目标名的全量重传会被卡到 1h 的 sweep 为止（第一版就踩了这个坑）。
        let idle = s.touched.lock().elapsed();
        if let (Some(have), Some(want)) = (s.total, total) {
            if have != want {
                return Err(UploadErr::TotalMismatch);
            }
        }
        if start == 0 {
            // 全量重传：截断临时文件（复用会话，锁不变）。
            //
            // 但这**只在旧会话已经静默下来**时才允许：否则两个客户端同时上传同名文件时，
            // 后者的「从 0 重传」会截断前者正在写的文件、并把 received 归零，
            // 而前者下一帧用 `sess.received()` 取 offset 继续追加 ⇒
            // 两份数据混在一个文件里、received 是两者之和、**双方都可能收到 201**（损坏文件）。
            // 静默判定给「断线后重试」留了活路，同时把并发写挡在 409（客户端据此续传或稍后重试）。
            if s.received() > 0 && idle < RESET_IDLE_GRACE {
                return Err(UploadErr::OffsetMismatch(s.received()));
            }
            // 守卫必须限定在作用域内：否则 `return Ok(s)` 会在守卫析构前 move `s`（E0505）。
            {
                let _g = s.lock.lock();
                if let Err(e) = std::fs::File::create(&s.tmp) {
                    return Err(UploadErr::Io(e.to_string()));
                }
                // 截断后旧字节不再占盘：同步从在飞预算里扣掉（否则反复「全量重传」会把
                // 预算永久吃满，之后所有人都被 507）。
                let old = s.received.swap(0, Ordering::Relaxed);
                {
                    let mut b = BUDGET.lock();
                    b.inflight = b.inflight.saturating_sub(old);
                }
            }
            *s.touched.lock() = Instant::now();
            return Ok(s);
        }
        if start != s.received() {
            return Err(UploadErr::OffsetMismatch(s.received()));
        }
        *s.touched.lock() = Instant::now();
        return Ok(s);
    }
    if start != 0 {
        // 没有会话却要求从中间续 → 只能从 0 开始（调用方回 409 + X-Upload-Offset: 0）。
        return Err(UploadErr::OffsetMismatch(0));
    }
    if map.len() >= MAX_SESSIONS {
        return Err(UploadErr::TooManySessions);
    }
    // 目标必须是文件（不是目录）：`with_file_name` 在目录上替换的是**路径最后一段**，
    // 于是目标为 docroot 本身（`PUT /`、`PUT /subdir/`）时，临时文件会落到
    // **docroot 的父目录**（`/opt/crucible/www` → `/opt/crucible/.www.upload.part`）——
    // 既逃出了 docroot 的包含关系，又去写另一块文件系统（父目录常在系统盘上，实测顶到
    // 2GiB 上限，而 commit 必然 EISDIR 失败、sweep 一小时后才回收）。
    if target.is_dir() {
        return Err(UploadErr::Io("upload target is a directory".into()));
    }
    let name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "upload".to_string());
    let parent = target
        .parent()
        .ok_or_else(|| UploadErr::Io("upload target has no parent dir".into()))?;
    let tmp = parent.join(format!(".{name}.upload.part"));
    // 预算 / 每-IP 配额闸门必须在**创建临时文件之前**。
    // 反过来（先建文件、再判闸门）时，被拒的请求会在 docroot 里留下一个**没有会话**的
    // `.x.upload.part`：它不在 SESSIONS 里，`sweep_expired` 永远扫不到，于是磁盘/inode
    // 只增不减 —— 攻击者先占满本 IP 的 16 个会话（或声明一个超大 total 把在飞预算顶满），
    // 之后每次带不同文件名的 PUT 都会各留一份这种垃圾文件，可无限制造。
    {
        let mut b = BUDGET.lock();
        if b.inflight
            .saturating_add(b.reserved)
            .saturating_add(reserve)
            > MAX_INFLIGHT_BYTES
        {
            return Err(UploadErr::NoSpace);
        }
        if let Some(ip) = peer {
            if b.by_ip.get(&ip).copied().unwrap_or(0) >= MAX_SESSIONS_PER_IP {
                return Err(UploadErr::TooManySessions);
            }
        }
    }
    if let Err(e) = std::fs::File::create(&tmp) {
        return Err(UploadErr::Io(e.to_string()));
    }
    let sess = Arc::new(Session {
        target: target.to_path_buf(),
        owner: peer,
        tmp,
        received: AtomicU64::new(0),
        total,
        wildcard_total: std::sync::atomic::AtomicBool::new(false),
        touched: Mutex::new(Instant::now()),
        lock: Mutex::new(()),
    });
    map.insert(target.to_path_buf(), Arc::clone(&sess));
    // 计数在**插入成功之后**再加：上面任何一条提前 return 都不会漏计/多计。
    {
        let mut b = BUDGET.lock();
        b.reserved = b.reserved.saturating_add(reserve);
        if let Some(ip) = peer {
            *b.by_ip.entry(ip).or_insert(0) += 1;
        }
    }
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
    // 在飞预算与磁盘余量：两道都过才写。`data.len()` 是本片新增的字节。
    //
    // 这里**故意**只算 `inflight` 不算 `reserved`：会话创建时已经把它的 `total` 预留过
    // 一次，若这里再算一遍，一个合法的大文件会在写到「inflight + 自己的 total 超过上限」
    // 时被自己饿死（传到一半突然 507）。创建闸门管「总量」，这里管「实写」。
    {
        let b = BUDGET.lock();
        if b.inflight.saturating_add(data.len() as u64) > MAX_INFLIGHT_BYTES {
            return Err(UploadErr::NoSpace);
        }
    }
    if !space_ok(&sess.tmp, data.len() as u64) {
        return Err(UploadErr::NoSpace);
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&sess.tmp)
        .map_err(|e| UploadErr::Io(e.to_string()))?;
    f.write_all(data).map_err(|e| UploadErr::Io(e.to_string()))?;
    f.flush().map_err(|e| UploadErr::Io(e.to_string()))?;
    sess.received.store(next, Ordering::Relaxed);
    {
        let mut b = BUDGET.lock();
        b.inflight = b.inflight.saturating_add(data.len() as u64);
    }
    *sess.touched.lock() = Instant::now();
    Ok(next)
}

/// 收齐后原子落盘（临时文件 rename → 目标），并移除会话。
///
/// 锁序固定为 **SESSIONS → 会话锁 → BUDGET**：`session_for` 的「全量重传」分支也是
/// 先拿 SESSIONS 再拿会话锁，两边反过来就会与这里形成经典的 AB/BA 死锁
/// （同目标名「一个在 commit、一个在做 start=0 重传」即可触发）。
pub fn commit(sess: &Arc<Session>) -> Result<(), UploadErr> {
    let mut map = SESSIONS.lock();
    let _g = sess.lock.lock();
    // rename 只保证**目录项**的原子替换，不保证文件内容已经落盘：本项目有强制 exit/OOM
    // 的历史，写盘页还没回刷就被杀时，会在目标名下留下一个**长度正确、内容却是空洞**
    // （或半截）的文件 —— 比「没有文件」更坏（客户端收到 201、校验和却不符）。
    // 先对临时文件 fsync：内容持久化之后才让它以目标名出现。
    // 必须以**可写**句柄打开再 sync —— 只读句柄上的 FlushFileBuffers 在 Windows 上会
    // 直接失败（ERROR_ACCESS_DENIED），那样这份「加固」在开发机上反而把 commit 弄挂。
    std::fs::OpenOptions::new()
        .write(true)
        .open(&sess.tmp)
        .and_then(|f| f.sync_all())
        .map_err(|e| UploadErr::Io(e.to_string()))?;
    std::fs::rename(&sess.tmp, &sess.target).map_err(|e| UploadErr::Io(e.to_string()))?;
    map.remove(&sess.target);
    release_budget(sess);
    Ok(())
}

/// 放弃会话并删临时文件。
pub fn abort(sess: &Arc<Session>) {
    let mut map = SESSIONS.lock();
    let _g = sess.lock.lock();
    let _ = std::fs::remove_file(&sess.tmp);
    map.remove(&sess.target);
    release_budget(sess);
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
    let mut freed = 0usize;
    for k in &dead {
        if let Some(s) = map.remove(k) {
            let _ = std::fs::remove_file(&s.tmp);
            release_budget(&s);
            freed += 1;
        }
    }
    freed
}

#[cfg(test)]
mod tests {
/// 本机磁盘余量是否足够跑这些「真落盘」的用例。
///
/// 不能硬断言「小文件一定放得行」：`session_for`/`append` 有**磁盘余量闸门**
/// （`MIN_FREE_BYTES`），机器盘满时（这台机器就长期紧张，实测一度到 102%）它们会正确地
/// 拒绝 —— 那是被测行为，不是被测对象的 bug。环境不满足就跳过并在输出里说明。
fn test_fs_has_room() -> bool {
    match free_bytes(&std::env::temp_dir()) {
        Some(free) => free >= min_free_bytes().saturating_add(8 * 1024 * 1024),
        None => true,
    }
}


    use super::*;

    #[test]
    fn content_range_parses_forms() {
        assert_eq!(parse_content_range("bytes 0-499/1234"), Some((0, 499, Some(1234))));
        assert_eq!(parse_content_range("bytes 500-999/*"), Some((500, 999, None)));
        assert_eq!(parse_content_range("bytes 5-4/10"), None, "end<start 必须拒");
        assert_eq!(parse_content_range("items 0-1/2"), None);
        assert_eq!(parse_content_range("bytes a-b/c"), None);
    }

    /// `/` 与 `*` 之间的空白必须容忍，且解析结果就是「总长未知」。
    ///
    /// `handle` 现在**直接**用解析结果（`total.is_none()`）判 wildcard，不再拿原始头做
    /// `ends_with("/*")`。这条盯着解析端：万一有人把 `*` 的 trim 去掉，`bytes 0-99/ *`
    /// 就会变成「有总长」→ 首片直接 commit（静默截断）。
    #[test]
    fn content_range_tolerates_space_before_wildcard() {
        assert_eq!(parse_content_range("bytes 0-99/ *"), Some((0, 99, None)));
        assert_eq!(parse_content_range("bytes 0-99/*"), Some((0, 99, None)));
    }

    #[test]
    fn session_offset_semantics_and_atomic_commit() {
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}），落盘用例无从验证");
            return;
        }
        let dir = std::env::temp_dir().join(format!("crucible-up-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("f1.bin");
        let part = target.with_file_name(".f1.bin.upload.part");
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&part);
        let s = session_for(&target, 0, Some(6), None).expect("begin");
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

    /// 每来源 IP 的并发会话上限必须真的生效（否则单机就能把会话表占满、把别人挤成 503）。
    #[test]
    fn per_ip_session_cap_is_enforced() {
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}），落盘用例无从验证");
            return;
        }
        let dir = std::env::temp_dir().join(format!("crucible-up-ip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let mut opened = Vec::new();
        for i in 0..MAX_SESSIONS_PER_IP {
            let t = dir.join(format!("ipv{i}.bin"));
            opened.push(session_for(&t, 0, Some(1), Some(ip)).expect("前 N 个应放行"));
        }
        let over = dir.join("ipv-over.bin");
        match session_for(&over, 0, Some(1), Some(ip)) {
            Err(UploadErr::TooManySessions) => {}
            other => panic!("第 N+1 个应回 TooManySessions，实际 {:?}", other.err()),
        }
        // 换一个 IP 不受影响（不是全局串扰）
        let other_ip: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        assert!(session_for(&dir.join("ipv-other.bin"), 0, Some(1), Some(other_ip)).is_ok());
        // 清理（abort 会回收每 IP 计数与在飞字节）
        for s in &opened {
            abort(s);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 被闸门拒绝的会话**不得**在 docroot 留下临时文件。
    ///
    /// 旧实现的顺序是「先 `File::create(tmp)` 再判预算/每-IP 配额」⇒ 每次被拒都会留下一个
    /// 无会话的 `.x.upload.part`，而 `sweep_expired` 只扫 SESSIONS 里的会话、永远碰不到它。
    /// 攻击者占满每-IP 的 16 个会话后，用不同文件名反复 PUT 就能无限堆积这类文件。
    #[test]
    fn rejected_session_leaves_no_temp_file() {
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}），落盘用例无从验证");
            return;
        }
        let dir = std::env::temp_dir().join(format!("crucible-up-leak-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ip: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let mut opened = Vec::new();
        for i in 0..MAX_SESSIONS_PER_IP {
            let t = dir.join(format!("leak{i}.bin"));
            opened.push(session_for(&t, 0, Some(1), Some(ip)).expect("前 N 个应放行"));
        }
        let over = dir.join("leak-over.bin");
        match session_for(&over, 0, Some(1), Some(ip)) {
            Err(UploadErr::TooManySessions) => {}
            other => panic!("第 N+1 个应回 TooManySessions，实际 {:?}", other.err()),
        }
        assert!(
            !over.with_file_name(".leak-over.bin.upload.part").exists(),
            "被拒的请求不得留下无会话的 .part 文件（永不被 sweep 回收 ⇒ 磁盘/inode 无界增长）"
        );
        for s in &opened {
            abort(s);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 声明总量即**预留**：一堆「声称很大却不发数据」的会话不能无限开。
    ///
    /// 用 64MiB 的声明量把「在飞预算」精确填满（2GiB / 64MiB = 32 个），第 33 个必须被拒。
    /// 不能用「单个 1GiB+」的声明来测：那会先撞上**磁盘余量**闸门（本机盘余量就 1GB 出头），
    /// 测出来的是另一条规则 —— 第一版就是这么写的，被这台机器的真实余量打回来了。
    #[test]
    fn declared_total_reserves_inflight_budget() {
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}），落盘用例无从验证");
            return;
        }
        let dir = std::env::temp_dir().join(format!("crucible-up-budget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chunk = 64 * 1024 * 1024u64;
        let n = (MAX_INFLIGHT_BYTES / chunk) as usize; // 正好填满预算
        let mut open_sessions = Vec::new();
        for i in 0..n {
            let t = dir.join(format!("budget-{i}.bin"));
            // peer=None：这条测的是字节预算，别撞上每 IP 会话数上限
            open_sessions.push(
                session_for(&t, 0, Some(chunk), None)
                    .unwrap_or_else(|e| panic!("第 {i} 个不该被拒：{e:?}")),
            );
        }
        match session_for(&dir.join("budget-over.bin"), 0, Some(chunk), None) {
            Err(UploadErr::NoSpace) => {}
            other => panic!("预算已满，再开应回 NoSpace，实际 {:?}", other.err()),
        }
        // 释放之后应能再开（证明回收路径有效）
        for s in &open_sessions {
            abort(s);
        }
        let after = dir.join("budget-after.bin");
        let s = session_for(&after, 0, Some(chunk), None).expect("释放后应可再开");
        abort(&s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 磁盘余量闸门：用一个**不可能满足**的余量要求反证闸门在（把 MIN_FREE_BYTES 当 want 放大）。
    #[test]
    fn disk_headroom_gate_rejects_when_free_is_tiny() {
        let dir = std::env::temp_dir();
        // 判据函数直测：want 取天文数字时必须为 false（与磁盘余量无关，恒成立）
        assert!(!space_ok(&dir.join("x.bin"), u64::MAX / 2));
        // 小写入是否放行取决于**本机**余量：余量够就必须放行，不够就必须拒绝（两者都要自洽）
        if let Some(free) = free_bytes(&dir) {
            let ok = space_ok(&dir.join("x.bin"), 1024);
            assert_eq!(
                ok,
                free >= MIN_FREE_BYTES + 1024,
                "余量 {free} 与闸门结论不一致（MIN_FREE_BYTES={MIN_FREE_BYTES}）"
            );
        }
    }

    #[test]
    fn oversize_and_missing_session_rejected() {
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}），落盘用例无从验证");
            return;
        }
        let target = std::path::PathBuf::from("/nonexistent/x.bin");
        // 不要在 `Result<Arc<Session>, _>` 上做 == ：Session 含 Mutex/Atomic 字段，
        // 既不可能（也不该）为它实现 PartialEq —— 断言错误**变体**即可
        //（此前这两条 assert_eq! 让整个测试目标编译不过，cargo test 形同虚设）。
        match session_for(&target, 0, Some(MAX_UPLOAD_BYTES + 1), None) {
            Err(UploadErr::TooLarge) => {}
            other => panic!("超限应回 TooLarge，实际 {:?}", other.err()),
        }
        match session_for(&target, 10, None, None) {
            // 没有会话却要从中间续 → 应告诉它从 0 开始
            Err(UploadErr::OffsetMismatch(0)) => {}
            other => panic!("应从 0 重来，实际 {:?}", other.err()),
        }
    }
}
