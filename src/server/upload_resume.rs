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
    /// 目标文件**名**不合法（控制字符 / 超出文件系统的单段长度上限）→ 400。
    /// 与 [`UploadErr::Io`] 分开，是因为这类失败的根因在请求（客户端换名即可），
    /// 报 500 会把「名字太长」说成「服务端故障」。
    BadName(String),
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
    /// 当前**持有**这个会话的请求数（由 `session_for` 原子递增、调用方的
    /// [`Attach`] 守卫递减）。
    ///
    /// 为什么不能只看 `received()`：两个「全量上传」请求可能在**写入任何字节之前**
    /// 都拿到同一个会话（此时 `received() == 0`，旧的并发闸门 `received() > 0 && idle <
    /// RESET_IDLE_GRACE` 判不出来），于是共享同一个 `.part`、各自 append；最后一个
    /// `commit()` 把 `.part` rename 走，另一个 append 撞上 `Io(No such file)` ⇒ **500**，
    /// 且**只有一方**的字节最终落盘（另一方静默丢数据却可能收到 201）。实测复现。
    active: std::sync::atomic::AtomicUsize,
    /// 本会话当前**计入** [`BUDGET`]`.reserved` 的字节量（创建时声明、请求结束时归还）。
    ///
    /// 为什么用 AtomicU64 而不是直接读 `total`：声明预留（`reserved`）必须在
    /// **请求结束时归还**（见 [`Attach::drop`] / [`release_reservation`]），而归还路径
    /// 有多条（请求超时/中断、commit、abort、sweep）。用一个可 swap 到 0 的计数保证
    /// 幂等：谁先归零，后面的人再减就是减 0，不会把全局预算减穿。
    reserved: AtomicU64,
}

/// 会话持有守卫：`session_for` 已经把 `active` 加过 1，这个守卫负责在请求结束
/// （含**所有**提前 return）时把它减回去。
///
/// 必须用 RAII 而不是手工配对：`upload_api` 的请求处理路径上有多个提前 return，
/// 漏减一次就会让该目标名的后续「全量上传」**永久**收到 409（直到 1h 的 sweep 回收会话）。
pub struct Attach {
    sess: Arc<Session>,
}

impl Attach {
    pub fn new(sess: Arc<Session>) -> Self {
        Attach { sess }
    }
}

impl Drop for Attach {
    fn drop(&mut self) {
        self.sess.active.fetch_sub(1, Ordering::Relaxed);
        // 请求结束（无论成功、超时、中断、提前 return）即归还本会话的**声明预留**。
        //
        // 为什么必须在这里归还：`session_for` 建会话时把客户端声明的 `total` 计入了
        // 全局在飞预算（`BUDGET.reserved`，防「先开一堆声明 2GiB 的会话再慢慢写」）。
        // 但那个预留此前**只**在 commit/abort/sweep 时归还 —— 而「声明 2GiB、发 1 字节
        // 就断开/超时」的请求走的是 400/408 分支（按续传语义**故意不 abort**），于是
        // 一份 2GiB 的预留被一个**匿名**请求占住整整 [`SESSION_TTL`]（1h），期间**所有**
        // 新上传（任何 target）都撞 `NoSuch` → 507（实测：单个中断的 2GiB PUT 之后，
        // 后续正常小文件上传恒回 507）。这是「用一条请求把上传功能整体打死一小时」的 DoS。
        //
        // 归还**只动预留、不动 `.part`/会话**：断点续传完全不受影响（客户端稍后仍可按
        // `X-Upload-Offset` 续传，续传会话本身不再预留——真正兜住磁盘的是逐片 `inflight`）。
        release_reservation(&self.sess);
    }
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
            crate::server::apps::env_lock::read_static_env("CRUCIBLE_MIN_FREE_BYTES")
                .and_then(|v: String| v.trim().parse::<u64>().ok())
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

/// 会话结束时回收预算（每 IP 计数 + 在飞字节 + **声明预留**）。
///
/// 预留用 `sess.reserved`（可 swap 到 0 的计数）而不是 `sess.total`：预留可能在
/// 请求结束时就已被 [`release_reservation`] 归还（超时/中断路径），这里再减同一个量会
/// 把**别的**会话的预留减穿。swap 到 0 保证两边只减一次。
fn release_budget(sess: &Session) {
    let mut b = BUDGET.lock();
    b.inflight = b.inflight.saturating_sub(sess.received());
    b.reserved = b.reserved.saturating_sub(sess.reserved.swap(0, Ordering::Relaxed));
    if let Some(ip) = sess.owner {
        if let Some(c) = b.by_ip.get_mut(&ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                b.by_ip.remove(&ip);
            }
        }
    }
}

/// 归还本会话的**声明预留**（`BUDGET.reserved`），幂等。
///
/// 由 [`Attach::drop`] 在**每个**请求结束时调用（成功的 commit 已经归还过 → 这里是减 0）。
/// `.part` 与会话都保留，只归还预留 —— 见 [`Attach::drop`] 里对 DoS 的说明。
pub fn release_reservation(sess: &Arc<Session>) {
    let r = sess.reserved.swap(0, Ordering::Relaxed);
    if r > 0 {
        let mut b = BUDGET.lock();
        b.reserved = b.reserved.saturating_sub(r);
    }
}

/// 纯 ASCII 数字解析（RFC 9110 §14.4 的 `first-pos`/`last-pos`/`complete-length` 只允许
/// DIGIT）。不能直接用 `str::parse::<u64>()`：它**接受前导 `+`** 与前后空白，于是
/// `Content-Range: bytes +0-99/100` 会被当成合法声明 —— 而按 §14.4 这是语法错误，
/// 必须整条拒绝（调用方回 400），绝不能"宽容解析"后照写。
fn digits_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// 解析 `Content-Range: bytes <start>-<end>/<total|*>` → `(start, end, total)`。
pub fn parse_content_range(v: &str) -> Option<(u64, u64, Option<u64>)> {
    let rest = v.trim().strip_prefix("bytes")?.trim_start();
    let (range, total) = rest.split_once('/')?;
    let (a, b) = range.trim().split_once('-')?;
    let start: u64 = digits_u64(a.trim())?;
    let end: u64 = digits_u64(b.trim())?;
    if end < start {
        return None;
    }
    let total = match total.trim() {
        "*" => None,
        t => Some(digits_u64(t)?),
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
            //
            // 再加一条 `active > 0`：**另一个请求正持有这个会话**时，即使它一个字节都还没写
            // （`received() == 0`，上面那条判不出来）也必须拒绝 —— 否则两个全量上传共享同一个
            // `.part`：各自 append、最后一个 commit 把文件 rename 走，另一个 append 撞
            // `Io(No such file)` ⇒ 500，且**只有一方**的字节落盘（另一方静默丢数据）。
            // 记账递增就在本函数返回前（SESSIONS 锁内）完成，因此这里读到的一定是最新值。
            if s.active.load(Ordering::Relaxed) > 0
                || (s.received() > 0 && idle < RESET_IDLE_GRACE)
            {
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
            // 在 SESSIONS 锁内记账（与校验一起原子），调用方用 `Attach` 守卫递减。
            s.active.fetch_add(1, Ordering::Relaxed);
            return Ok(s);
        }
        if start != s.received() {
            return Err(UploadErr::OffsetMismatch(s.received()));
        }
        // 并发闸门必须**同时**覆盖续传分片：另一个请求正持有这个会话（哪怕它一个字节
        // 都还没写）时，后到者必须 409。
        //
        // 漏掉这一条会静默损坏文件（实测复现）：两个请求都带
        // `Content-Range: bytes 4-7/16` 且当前 `received()==4` 时，`start == received`
        // 对二者**同时成立**，于是两个都通过；而 `upload_api` 取写偏移用的是**实时**
        // `sess.received()` —— 后到者读到的是已被前一个推进的偏移（8），把同一片数据
        // **重复追加**（received 4→8→12），随后客户端按 Content-Range 发的收尾片撞
        // `start != received` 回 409，文件永远拼不回来也 commit 不了（实测 race.bin 长度
        // 12、内容重复、GET 404）。断线重试不受影响：旧请求的 `Attach` 已析构、`active` 归零。
        if s.active.load(Ordering::Relaxed) > 0 {
            return Err(UploadErr::OffsetMismatch(s.received()));
        }
        *s.touched.lock() = Instant::now();
        s.active.fetch_add(1, Ordering::Relaxed);
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
    // 文件**名**合法性：控制字符（含 NUL/换行）与超长名必须在建临时文件之前拒。
    //
    // * 控制字符：名字里带 `\n`/`\r` 会写进 access_log 与 autoindex（日志注入 / 列目录
    //   时的显示破坏），NUL 直接让 fs 调用以难读的 OS 错误失败；
    // * 超长名：临时文件名是 `.{name}.upload.part`，比目标名多 13 字节。单段上限
    //   （Linux/OpenBSD 都是 255）附近的名字（240..255）会让**临时文件**创建失败
    //   （ENAMETOOLONG），报出来却是「写入失败」500 —— 客户端无从下手。
    //   这里按 255 的常见上限给出可读的 400。
    if name
        .chars()
        .any(|c| c.is_control() || c == '\u{7f}')
    {
        return Err(UploadErr::BadName("文件名含控制字符".into()));
    }
    if name.len() + ".upload.part".len() + 1 > 255 {
        return Err(UploadErr::BadName(format!(
            "文件名过长（{} 字节，临时名上限 255）",
            name.len()
        )));
    }
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
        // 新会话：下面 `Ok(sess)` 返回前会加 1（与复用分支同一处），
        // 保证「拿到会话」与「记账」在 SESSIONS 锁内是原子的。
        active: std::sync::atomic::AtomicUsize::new(0),
        // 创建时把声明的 total 记进 `reserved`（下面紧接的 BUDGET 块把它计入全局预算），
        // 请求结束时由 `Attach::drop` 归还。
        reserved: AtomicU64::new(reserve),
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
    // 新会话同样是「本请求正持有」：与复用分支一致地记账（调用方 `Attach` 递减）。
    sess.active.fetch_add(1, Ordering::Relaxed);
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
///
/// **跳过正在被请求持有的会话**（`active > 0`）：否则一个 body 被客户端拖过
/// [`SESSION_TTL`]（1 小时）的在途上传，其 `.part` 会被这里删掉，随后该请求的
/// `append` 打开已删除文件失败回 500（不损坏数据，但把合法上传打成 500）。
pub fn sweep_expired() -> usize {
    let now = Instant::now();
    let mut map = SESSIONS.lock();
    let dead: Vec<PathBuf> = map
        .iter()
        .filter(|(_, s)| {
            s.active.load(Ordering::Relaxed) == 0
                && now.duration_since(*s.touched.lock()) > SESSION_TTL
        })
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

/// 会话/预算类用例的**串行化锁**。
///
/// `BUDGET` 是**进程级全局量**（在飞字节 + 每 IP 会话数），而 cargo test 默认**并行**跑
/// 同一个二进制里的所有用例：一个用例把预算填满时，另一个用例随后开新会话就会拿到
/// `NoSpace`，于是断言以「本不该被拒」的形式随机失败（实测：`declared_total_*` 与
/// `oversize_and_missing_*` 两个用例在整包运行时互踩，单独跑就过）。这些用例本来就是
/// 微秒级，串行化没有代价。
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 取串行锁；中毒（前一个用例 panic）也继续，避免二次失败掩盖真因。
fn serial() -> std::sync::MutexGuard<'static, ()> {
    TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// 上传目标的落盘位置必须**真的**有空间：`session_for` 的磁盘闸门走
/// `free_bytes(target)`（沿父目录上溯），所以拿 `/nonexistent/x.bin` 当目标时它看的是
/// **根文件系统**的余量 —— 根盘小到 512MiB 以下（本机 OpenBSD VM 的 `/` 只有 986MiB）
/// 时，用例会以「应从 0 重来，实际 NoSpace」失败，看起来像产品 bug，其实是环境。
/// 这里统一用 temp_dir 下的目标，并显式声明前置条件。
fn upload_target(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("crucible-up-{}-{}", std::process::id(), name));
    let _ = std::fs::create_dir_all(&dir);
    dir.join("target.bin")
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

    /// `first-pos`/`last-pos`/`complete-length` 只允许 DIGIT（RFC 9110 §14.4）：
    /// 前导 `+`（Rust 的 parse 会接受）、前导 0 之外的空格/字母都必须整条拒绝。
    #[test]
    fn content_range_rejects_signs_and_junk() {
        assert_eq!(parse_content_range("bytes +0-99/100"), None, "前导 + 不是 DIGIT");
        assert_eq!(parse_content_range("bytes 0-+99/100"), None);
        assert_eq!(parse_content_range("bytes 0-99/+100"), None);
        assert_eq!(parse_content_range("bytes 0-99/100x"), None);
        assert_eq!(parse_content_range("bytes 0x10-99/100"), None);
        // 合法的零与空白容忍仍成立（`bytes 0-99/ *` 是「总长未知」）
        assert_eq!(parse_content_range("bytes 0-0/1"), Some((0, 0, Some(1))));
        assert_eq!(parse_content_range("bytes 0-99/ *"), Some((0, 99, None)));
    }

    /// 文件名里的控制字符与超长名必须在**建临时文件之前**拒（否则报 500，
    /// 而根因是客户端给的名字）。`BadName` 与 `Io` 分开，调用方能回 400。
    #[test]
    fn bad_target_name_rejected_before_touching_disk() {
        let _g = serial();
        let dir = std::env::temp_dir().join(format!("crucible-up-name-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 换行：会写进 access_log / autoindex HTML
        let bad = dir.join("a\nb.txt");
        match session_for(&bad, 0, Some(1), None) {
            Err(UploadErr::BadName(_)) => {}
            other => panic!("含控制字符的名字应回 BadName，实际 {:?}", other.err()),
        }
        // 超长名（临时名 = `.` + name + `.upload.part`，超过 255 必须提前拒）
        let long = dir.join(format!("{}.txt", "x".repeat(250)));
        match session_for(&long, 0, Some(1), None) {
            Err(UploadErr::BadName(_)) => {}
            other => panic!("超长名应回 BadName，实际 {:?}", other.err()),
        }
        assert!(
            !long.with_file_name(format!(".{}.txt.upload.part", "x".repeat(250))).exists(),
            "被拒的目标不得留下临时文件"
        );
        let _ = std::fs::remove_dir_all(&dir);
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
        let _g = serial();
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

    /// 并发「全量上传」到同一目标必须被挡在 409（`session_for` 的 `active > 0` 判定）。
    ///
    /// 旧实现只在 `received() > 0` 时判并发，于是两个**都还没写任何字节**的全量上传会拿到
    /// **同一个会话**：共享同一个 `.part`，各自 append；最后一个 `commit()` 把 `.part`
    /// rename 走，另一个 append 撞 `Io(No such file)` ⇒ 500，且**只有一方**的字节落盘，
    /// 另一方收到 201 却静默丢数据（第 6 轮并发报告 #5，实测复现）。
    #[test]
    fn concurrent_full_upload_to_same_target_is_rejected() {
        let _g = serial();
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}）");
            return;
        }
        let dir = std::env::temp_dir().join(format!("crucible-up-dup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("dup.bin");
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(target.with_file_name(".dup.bin.upload.part"));

        // 第一个请求持有时：第二个（同样 start=0、也一个字节没写）必须 409 而不是共享会话。
        let a = session_for(&target, 0, Some(4), None).expect("第一个应放行");
        match session_for(&target, 0, Some(4), None) {
            Err(UploadErr::OffsetMismatch(cur)) => assert_eq!(cur, 0, "应报当前偏移 0"),
            Err(other) => panic!("期望 OffsetMismatch(0)，实得 {other:?}"),
            // 不要在 Ok 分支里格式化（Session 没有 Debug）：直接给一句能定位的断言文案。
            Ok(_) => panic!("期望 OffsetMismatch(0)（409），实得 Ok —— 两个并发全量上传共享了会话"),
        }
        // 反向控制：守卫释放（请求结束）后同一目标必须能再次开全量上传，
        // 否则「断线后重试」会被永久卡死 —— 这正是必须用 RAII 守卫的原因。
        {
            let g = Attach::new(Arc::clone(&a));
            drop(g);
        }
        let b = session_for(&target, 0, Some(4), None).expect("释放后应可再开");
        assert!(Arc::ptr_eq(&a, &b), "复用同一个会话对象");
        // 归还预算：`BUDGET` 是进程级全局量，用例留垃圾会破坏其他「正好填满预算」的用例
        //（实测：本用例留 4 字节就让 declared_total_reserves_inflight_budget 假失败）。
        abort(&b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 并发**续传分片**（非 0 start）到同一目标也必须被挡在 409。
    ///
    /// 实测复现的损坏：两个请求都带 `bytes 4-7/16` 且当前 `received()==4` 时，
    /// `start == received` 对二者**同时成立**，旧实现两个都放行；而 `upload_api` 按
    /// **实时** `received()` 取写偏移，后到者把同一片数据重复追加（received 4→8→12），
    /// 客户端按 Content-Range 发的收尾片随后撞 409，文件损坏且永远 commit 不了
    /// （真机 race.bin 实测：len=12、内容重复、GET 404）。
    #[test]
    fn concurrent_resume_chunk_to_same_target_is_rejected() {
        let _g = serial();
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}）");
            return;
        }
        let dir = std::env::temp_dir().join(format!("crucible-up-resume-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("resume.bin");
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(target.with_file_name(".resume.bin.upload.part"));

        let a = session_for(&target, 0, Some(16), None).expect("开始会话");
        assert_eq!(append(&a, 0, b"aaaa").unwrap(), 4);
        // a 仍被本请求持有（active==1）：同偏移（start==received==4）的续传分片必须 409，
        // 而不是拿到同一个会话（否则两片都写、数据重复）。
        match session_for(&target, 4, Some(16), None) {
            Err(UploadErr::OffsetMismatch(cur)) => assert_eq!(cur, 4),
            Err(other) => panic!("期望 OffsetMismatch(4)，实得 {other:?}"),
            Ok(_) => panic!("期望 409，实得 Ok —— 并发续传分片共享了会话（会重复追加数据）"),
        }
        // 释放（请求结束）后，合法的断线续传必须能重新拿到会话。
        {
            let g = Attach::new(Arc::clone(&a));
            drop(g);
        }
        let b = session_for(&target, 4, Some(16), None).expect("释放后应可续传");
        assert!(Arc::ptr_eq(&a, &b), "复用同一个会话对象");
        abort(&b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 每来源 IP 的并发会话上限必须真的生效（否则单机就能把会话表占满、把别人挤成 503）。
    #[test]
    fn per_ip_session_cap_is_enforced() {
        let _g = serial();
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
        let _g = serial();
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
        let _g = serial();
        let dir = std::env::temp_dir().join(format!("crucible-up-budget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chunk = 64 * 1024 * 1024u64;
        // 用**当前剩余**预算算 n，而不是直接 `MAX/chunk`。
        // `BUDGET` 是**进程级**全局量，同一测试进程里先跑过/并行跑的其他用例可能已占掉几个
        // 字节（例如某个并发用例留了 4 字节）：按常数算会把「正好填满预算」变成「超出 4 字节」，
        // 于是最后一个本应放行的会话被拒、断言假失败。实测：另一个用例只留 4 字节就复现了。
        // 按剩余量算既保留「填满即拒」这一被测性质，又不再依赖测试执行的顺序与并行度。
        let head = {
            let b = BUDGET.lock();
            MAX_INFLIGHT_BYTES.saturating_sub(b.inflight.saturating_add(b.reserved))
        };
        let n = (head / chunk) as usize; // 正好填满**剩余**预算
        if n == 0 {
            eprintln!("跳过：在飞预算已被同一进程内其他用例占满（head={head}）");
            return;
        }
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

    /// 请求结束（`Attach` drop）必须归还「声明预留」。
    ///
    /// 复现的 DoS：`PUT` 声明 `Content-Length: 2GiB`、发 1 字节后断开（走 400 分支，
    /// 按续传语义**不 abort**），预留被占住 1h，期间**所有**新上传恒回 507。
    /// 这条盯着 `Attach::drop` 的归还：`before` 与 `after` 必须相等。
    #[test]
    fn attach_drop_releases_declared_reservation() {
        let _g = serial();
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}）");
            return;
        }
        let dir = std::env::temp_dir().join(format!("crucible-up-resv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let before = { BUDGET.lock().reserved };
        let target = dir.join("resv.bin");
        let sess = session_for(&target, 0, Some(64 * 1024 * 1024), None).expect("begin");
        let during = { BUDGET.lock().reserved };
        assert!(
            during >= before + 64 * 1024 * 1024,
            "创建会话时必须把声明的 total 计入 reserved（before={before} during={during}）"
        );
        {
            let g = Attach::new(Arc::clone(&sess));
            drop(g); // 模拟请求结束（未 commit）
        }
        let after = { BUDGET.lock().reserved };
        assert_eq!(
            after, before,
            "请求结束必须归还声明预留（否则一个中断的大声明请求把上传打死 1h）"
        );
        abort(&sess);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 磁盘余量闸门：用一个**不可能满足**的余量要求反证闸门在（把 MIN_FREE_BYTES 当 want 放大）。
    #[test]
    fn disk_headroom_gate_rejects_when_free_is_tiny() {
        let _g = serial();
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
        let _g = serial();
        if !test_fs_has_room() {
            eprintln!("跳过：本机磁盘余量低于闸门阈值（{MIN_FREE_BYTES}），落盘用例无从验证");
            return;
        }
        // 目标放在 temp_dir 下（不是 `/nonexistent/...`）：磁盘闸门沿父目录上溯，
        // 后者会把**根文件系统**的余量当成上传落盘位置的余量，根盘小的机器上必然误判。
        let target = upload_target("oversize");
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
