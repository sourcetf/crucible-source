//! Per-engine temporary environment locks (§7.3 / §22).
//!
//! 进程 env 是**全局**的：临时把一组 `.env` 装进环境的那一段，必须与其他「装不同值」的
//! 调用互斥，否则引擎会读到别的请求的值。但互斥的判据不是引擎名，而是**要装的内容**：
//!
//! * 内容完全相同（同引擎 + 归一化后同样的键值）→ 两组装的是同一份值、恢复的也是同一份
//!   旧值，第二个调用**不必再写环境**（直接复用当前已生效的那一份）→ 天然并发；
//! * 内容不同 → 两组绝不允许同时生效（进程 env 只有一个）→ 全局串行。
//!
//! 旧实现按引擎名取锁并持有整个引擎调用期：同一个引擎的所有请求，哪怕 `.env` 一模一样
//! （甚至来自同一个 app、互不干扰）也被串行化。`vars.is_empty()` 那一档已修（§13.8），
//! 本文件修剩下的非空一档。
//!
//! 不变量（本文件唯一不能错的地方）：`INNER.active` 至多持有一组内容；安装/恢复只发生在
//! 持有 `INNER` 的临界区内；调用方只有在「自己安装了该组」或「在 `INNER` 临界区内确认该组
//! 已生效」之后才运行 `f()`。因此任意时刻进程 env 里的临时值只可能来自同一组内容 ——
//! 两批不同 env 绝不会并发生效。
//!
//! **「无 .env」也是一个组（空组）**，同样走上面这套机制：它不装任何键，但 active 期间
//! 会挡住（并等待）任何非空组。这是修「空值窗口」的关键 —— 旧实现让无 .env 请求完全绕过
//! 互斥，于是在 A（带 .env）在飞时并发的 B（无 .env）会读到 A 的私密值（跨应用秘密泄漏）。
//! 空组跨引擎同身份，所以「无 .env」请求彼此仍并发（§13.8 的 sleep-CGI DoS 不回归）。

use once_cell::sync::Lazy;
use parking_lot::{Condvar, Mutex};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

/// 一组临时覆盖的「内容指纹」。
///
/// 结构化逐项比较，而不是把键值拼成一个字符串：拼接必须挑分隔符，而键或值里恰好带上
/// 同一分隔符时，两组**不同**内容会拼成同一个 key —— 那样两批不同 env 就会并发生效
/// （锁 key 碰撞比性能问题严重得多）。逐项比较原始键值没有这个碰撞面。
struct Group {
    engine: String,
    /// 按 key 升序、同键取最后一次出现（与「逐条 setenv」的结果一致）。
    vars: Vec<(String, String)>,
}

impl Group {
    /// `vars` 必须已归一化（见 [`normalized`]）。
    fn from_normalized(engine: &str, vars: &[(&str, &str)]) -> Group {
        Group {
            // 空组（没有可装的键）与引擎无关：本组不改进程 env，任何「无 .env」请求装出来的
            // 环境都完全一样，故共用一个身份 —— 否则「空 cgi」与「空 php」会被当成两组而
            // 互相串行（把一个 sleep CGI 变成全站应用的排队点，即 §13.8 那个 DoS 换了个壳）。
            engine: if vars.is_empty() { String::new() } else { engine.to_string() },
            vars: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    /// 本组与「引擎 + 键值」是不是同一份内容。`vars` 必须已归一化。
    fn matches(&self, engine: &str, vars: &[(&str, &str)]) -> bool {
        // 空组跨引擎同身份（见 `from_normalized`）。非空组仍按引擎 + 键值逐项比较。
        if self.vars.is_empty() && vars.is_empty() {
            return true;
        }
        self.engine == engine
            && self.vars.len() == vars.len()
            && self
                .vars
                .iter()
                .zip(vars.iter())
                .all(|((mk, mv), (k, v))| mk.as_str() == *k && mv.as_str() == *v)
    }
}

/// 归一化：按 key 排序 + 同键取最后一次出现 + 剔除会让 `set_var`/`remove_var` panic 的项
/// （键为空、含 `=` 或 NUL；值含 NUL）。比较与安装共用本函数，保证「指纹相同」与「装出来
/// 的环境相同」严格等价。
fn normalized<'a>(vars: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut map: BTreeMap<&'a str, &'a str> = BTreeMap::new();
    for (k, v) in vars {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            continue;
        }
        map.insert(*k, *v); // 同键后写覆盖前写
    }
    map.into_iter().collect()
}

/// 当前生效的那一组 + 装它之前的原值。
struct Active {
    group: Group,
    /// 原值：`None` = 调用前该键不存在（恢复语义必须是 remove，不能设成空串）。
    prev: Vec<(OsString, Option<OsString>)>,
}

struct Inner {
    /// 当前生效的临时覆盖。至多一组：内容不同的两组不允许同时生效（见模块注释）。
    active: Option<Active>,
    /// 正在依赖 `active` 运行 `f()` 的调用数（内容与 active 相同的调用可以并发）。
    inflight: usize,
    /// 有人正等着换一组内容。置位后不允许新的同内容调用再「加入」当前组：
    /// 否则只要同内容请求不断，当前组就永远不归零，等换组的调用得等到下一个流量空档
    /// （活锁）。置位者自己会在 active 变空后抢占安装，所以不会自我阻塞。
    drain_requested: bool,
}

static INNER: Lazy<Mutex<Inner>> = Lazy::new(|| {
    Mutex::new(Inner {
        active: None,
        inflight: 0,
        drain_requested: false,
    })
});
static ENV_IDLE: Lazy<Condvar> = Lazy::new(Condvar::new);

/// 启动期进程环境快照（**不含任何请求期临时 `.env`**）。
///
/// # 为什么需要它（这是「慢空请求挡住带 .env 请求」的根治面）
///
/// 进程 env 只有一个：临时把某个请求的 `.env` 装进去的那段时间，任何**继承 `environ`**
/// 的子进程（cgi/cgi_script 的 fork+exec）都会把别人的 `.env` 一起继承走 —— 所以那些引擎
/// 必须参与本模块的「至多一组 active」互斥；而互斥意味着一个慢的**空**请求会挡住随后
/// 带 `.env` 的请求（sec2-wave5 的诚实边界，实测 4.7s）。
///
/// 让 spawn 类引擎改用「**启动期基底 + 本请求 `.env`**」构造子进程环境（`env_clear()` 后
/// 逐条设置），子进程就既拿到运维环境、又**不可能**继承别的请求的临时值 —— 于是它们
/// 完全无需参与互斥，慢请求自然不再挡住别人。C 侧（cgi 引擎）经 `appengine_set_base_env`
/// 拿到同一份基底；Rust 侧（cgi_script）经 [`apply_clean_env`] 使用。
static BASE_ENV: Lazy<Mutex<Option<Vec<(OsString, OsString)>>>> = Lazy::new(|| Mutex::new(None));

/// 在**任何请求期 `.env` 安装之前**调用一次：把运维环境快照为 spawn 类引擎的干净基底。
/// 幂等；未调用时首次访问会惰性快照（此时可能已含某请求的临时值 —— 故服务启动期应显式调用）。
pub fn init_base_env() {
    let mut g = BASE_ENV.lock();
    if g.is_none() {
        *g = Some(std::env::vars_os().collect());
    }
}

/// 启动期基底环境（惰性快照的副本）。
pub fn base_env() -> Vec<(OsString, OsString)> {
    let mut g = BASE_ENV.lock();
    if g.is_none() {
        *g = Some(std::env::vars_os().collect());
        log::debug!("env_lock: 惰性快照启动期基底环境（服务启动期应显式 init_base_env）");
    }
    g.as_ref().cloned().unwrap_or_default()
}

/// 用「启动期基底 + 本请求 `.env`」构造一个**干净**的子进程环境：先 `env_clear()` 再逐条
/// 设置。这样并发请求正在生效的临时 `.env`（进程 env 里的临时值）**绝不会**被继承。
///
/// 语义：本请求 `.env` 覆盖同名基底键（后写胜出）；调用方随后可用 `cmd.env(...)` 追加
/// 引擎专属变量（CGI 变量等），它们同样覆盖同名键。
pub fn apply_clean_env(cmd: &mut std::process::Command, vars: &[(String, String)]) {
    cmd.env_clear();
    for (k, v) in base_env() {
        cmd.env(k, v);
    }
    for (k, v) in vars {
        cmd.env(k, v);
    }
}

/// 把启动期基底环境编码为 C 侧 `appengine_set_base_env` 需要的块：
/// `K=V\0K=V\0…\0`（双 NUL 结尾）。键含 `=`/NUL 或值含 NUL 的项跳过（与 `setenv` 语义一致）。
#[cfg(unix)]
pub fn base_env_block() -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let mut out = Vec::new();
    for (k, v) in base_env() {
        let kb = k.as_bytes();
        let vb = v.as_bytes();
        if kb.is_empty() || kb.contains(&b'=') || kb.contains(&0) || vb.contains(&0) {
            continue;
        }
        out.extend_from_slice(kb);
        out.push(b'=');
        out.extend_from_slice(vb);
        out.push(0);
    }
    out.push(0);
    out
}

/// 「本次调用可以依赖当前生效的临时环境」的凭证。
///
/// 递减读者数，并在**最后一个离开者**那里恢复环境。用 `Drop` 而不是 `f()` 之后顺序恢复，
/// 是为了 `f()` panic 展开时也能恢复：否则那组临时值会永久留在进程 env 里，污染之后所有请求。
struct Slot;

impl Drop for Slot {
    fn drop(&mut self) {
        let mut st = INNER.lock();
        if st.inflight > 0 {
            st.inflight -= 1;
        }
        if st.inflight == 0 {
            if let Some(active) = st.active.take() {
                restore(&active.prev);
            }
            // 唤醒等换组的调用。公平解锁把锁直接交给队首等待者（正在等换组的那一个），
            // 而不是允许刚到的同内容请求再插队（barging）一次——否则等锁者要一次次
            // 错过「归零」的那一瞬。注意 `unlock_fair` 的接收者是 `s: Self`（不是 `self`），
            // 只能按关联函数调用，不能写成 `st.unlock_fair()`。
            ENV_IDLE.notify_all();
        }
        parking_lot::MutexGuard::unlock_fair(st);
    }
}

pub fn with_temp_env_named<T, F>(engine: &str, vars: &[(&str, &str)], f: F) -> T
where
    F: FnOnce() -> T,
{
    // **空变量也必须进 `enter`**（不再直接跑 `f()`）。
    //
    // 旧实现 `vars.is_empty() → return f()` 是为了修 §13.8 的 DoS（一个 sleep CGI 把整条
    // `/cgi/` 堵死）。但它把「无 .env 的请求」完全排除在互斥之外：当 A（带 `.env`）在飞时，
    // 进程 env 里装着 A 的值，而并发到达的 B（无 `.env`）直接跑 `f()` —— 它的引擎读
    // `environ`（cgi 引擎会 `setenv` 后再 fork；FFI 引擎经 `appengine_apply_extra`）就
    // **读到了 A 应用的私密 .env**（DB 口令/API key）—— 跨应用秘密泄漏，规格最忌讳的故障。
    //
    // 正确做法：把「无 .env」也建模成**一个空组**并走同一套「至多一组 active」的机制。
    //   * 空组不装任何键（`install(&[])` 是 no-op），恢复也是 no-op —— 语义不变；
    //   * 空组跨引擎同身份（见 `Group::from_normalized`）→ 所有「无 .env」请求仍并发，
    //     §13.8 的 sleep-CGI DoS **不回归**（下面 `empty_requests_are_concurrent` 用例守着）；
    //   * 代价：空组 active 时非空组要等它退干净（反之亦然）—— 这是「进程 env 只有一个」
    //     的固有约束，无法既保证 B 看不到 A 的值、又让两组真正并发。
    let _slot = enter(engine, vars);
    f()
}

/// 取得「依赖某组临时环境」的资格。
///
/// 恒返回 [`Slot`]：空变量也参与互斥（见 [`with_temp_env_named`] 的说明）。
fn enter(engine: &str, vars: &[(&str, &str)]) -> Slot {
    let g = normalized(vars);
    let mut st = INNER.lock();
    loop {
        // ① 内容相同 + 没人在等换组 + 环境确实还是那组 → 直接加入：不写环境，故与同内容并发。
        let joinable = match &st.active {
            Some(active) => {
                !st.drain_requested && active.group.matches(engine, &g) && env_is(&active.group)
            }
            None => false,
        };
        if joinable {
            st.inflight += 1;
            return Slot;
        }
        // ② 有别的组生效中，或有人等着换组：进程 env 只有一个，只能等这一组连同它的读者
        //    一起退干净（`drain_requested` 让同内容的新调用也不再续命，缩短这个等待）。
        if st.active.is_some() {
            st.drain_requested = true;
            ENV_IDLE.wait(&mut st);
            continue;
        }
        // ③ 环境是干净的：由我装上本组（`drain_requested` 随新组一起复位）。
        let group = Group::from_normalized(engine, &g);
        let prev = install(&group.vars);
        st.active = Some(Active { group, prev });
        st.inflight = 1;
        st.drain_requested = false;
        return Slot;
    }
}

/// 当前进程 env 是不是真的就是这一组的值。
///
/// 为什么需要：进程 env 也会被应用自己的代码改（PHP 的 `putenv`、Python 的
/// `os.environ[k] = v` 都会落到 C 的 `environ`）。旧实现每个请求都重新 `setenv`，这类改动
/// 会在下一个请求被 `.env` 的值覆盖回去；若这里只凭「组相同」就复用已生效的环境，被改过的
/// 值会一直留着，之后所有同内容请求都读到它。校验不过就退回安装路径（等本组退干净后重装）。
fn env_is(group: &Group) -> bool {
    group.vars.iter().all(|(k, v)| {
        if v.is_empty() {
            std::env::var_os(k).is_none()
        } else {
            std::env::var_os(k).as_deref() == Some(OsStr::new(v))
        }
    })
}

/// 把该组写进进程环境，返回每个键的原值（供恢复）。
fn install(vars: &[(String, String)]) -> Vec<(OsString, Option<OsString>)> {
    vars.iter()
        .map(|(k, v)| {
            let old = std::env::var_os(k);
            if v.is_empty() {
                std::env::remove_var(k); // 空值语义 = 确保该键不存在（沿用旧行为）
            } else {
                std::env::set_var(k, v);
            }
            (OsString::from(k.as_str()), old)
        })
        .collect()
}

/// 恢复安装前的环境（原本不存在的键 → remove，而不是设成空串）。
fn restore(prev: &[(OsString, Option<OsString>)]) {
    for (k, old) in prev {
        match old {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
}

/// 读取「启动期只读」环境变量，**结果只取一次并缓存**。
///
/// # 为什么不能直接用 `std::env::var`
///
/// 本模块会在**引擎请求期间**调用 `set_var`/`remove_var`（把 `.env` 里的变量装进进程环境）。
/// 而 glibc 的 `setenv` 可能 **realloc `environ` 数组** —— 此刻任何其它线程的
/// `getenv`/`std::env::var`（**哪怕读的是另一个键**）都可能走到已释放的内存上，
/// 表现是间歇性崩溃或读到垃圾值。Rust 标准库明确把「多线程下修改进程环境」列为不应发生的场景
/// （相关 API 在 2024 edition 下已改为 unsafe），所以「写者之间互斥」并不够，读者也必须避开。
///
/// 这里走的路子最省事也最稳：`CRUCIBLE_*` / `APPENGINE_*_LIB` 这类都是**运维在启动前
/// 设好的只读配置**，缓存一次即可彻底消除竞争 —— 不必让读者也去抢同一把锁
/// （那会把应用层锁塞进热路径，还要改好几个模块）。
///
/// **诚实边界**：缓存后，进程运行期间再改这些环境变量**不会**被读到。对「启动期配置」
/// 这正是期望行为；要支持热改就该用配置文件而不是环境变量。
pub fn read_static_env(key: &str) -> Option<String> {
    static CACHE: Lazy<Mutex<BTreeMap<String, Option<String>>>> =
        Lazy::new(|| Mutex::new(BTreeMap::new()));
    let mut cache = CACHE.lock();
    if let Some(v) = cache.get(key) {
        return v.clone();
    }
    let v = std::env::var(key).ok();
    cache.insert(key.to_string(), v.clone());
    log::debug!("env: 缓存启动期环境变量 {key}（存在={}）", v.is_some());
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{channel, RecvTimeoutError};
    use std::time::Duration;

    /// 进程 env 是全局的：一个用例「生效中的组」会挡住另一个用例的安装（这是被测语义），
    /// 所以本模块的用例必须串行跑（不是被测代码需要的锁）。
    static TEST_GATE: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn gate() -> parking_lot::MutexGuard<'static, ()> {
        TEST_GATE.lock()
    }

    #[test]
    fn normalized_sorts_dedups_and_filters() {
        // 键序不影响指纹
        assert_eq!(
            normalized(&[("b", "2"), ("a", "1")]),
            vec![("a", "1"), ("b", "2")]
        );
        // 同键取最后一次出现（与逐条 setenv 的结果一致）
        assert_eq!(normalized(&[("a", "1"), ("a", "2")]), vec![("a", "2")]);
        // 空值保留：语义是「确保该键不存在」
        assert_eq!(normalized(&[("a", "")]), vec![("a", "")]);
        // 会被 set_var/remove_var panic 的项直接丢掉
        assert!(normalized(&[("", "1"), ("a=b", "1"), ("a", "x\0y")]).is_empty());
    }

    #[test]
    fn group_matches_has_no_separator_collision() {
        let g = Group::from_normalized("php", &[("A", "x"), ("B", "y")]);
        // 键序不同但内容相同 → 同组。`matches` 的契约是「入参已归一化」（生产调用点传的
        // 就是 `normalized(vars)`），所以这里同样先归一化再比 —— 键序无关性由归一化保证。
        assert!(
            g.matches("php", &normalized(&[("B", "y"), ("A", "x")])),
            "键序不同但内容相同 → 同组"
        );
        // 拼字符串实现会把这些误判成同一 key（分隔符/拼接碰撞）——结构化比较不会
        assert!(!g.matches("php", &normalized(&[("A", "x\u{1}B=y")])));
        assert!(!g.matches("php", &normalized(&[("A", "x"), ("B", "y"), ("C", "z")])));
        assert!(
            !g.matches("lua", &normalized(&[("A", "x"), ("B", "y")])),
            "引擎名在指纹里"
        );
    }

    #[test]
    fn same_content_calls_do_not_block_each_other() {
        let _gate = gate();
        const ENGINE: &str = "ut-same";
        const KEY: &str = "CRUCIBLE_UT_SAME_CONTENT";
        std::env::remove_var(KEY);

        let (tx_entered, rx_entered) = channel::<()>();
        let (tx_release, rx_release) = channel::<()>();
        let first = std::thread::spawn(move || {
            with_temp_env_named(ENGINE, &[(KEY, "v1")], || {
                tx_entered.send(()).unwrap();
                rx_release.recv().unwrap();
            });
        });
        rx_entered
            .recv_timeout(Duration::from_secs(5))
            .expect("第一个调用应进入闭包");

        // 内容完全相同：第二个调用必须**不被阻塞**（旧实现按引擎名加锁 → 这里会超时）。
        let (tx_second, rx_second) = channel::<Option<String>>();
        let second = std::thread::spawn(move || {
            with_temp_env_named(ENGINE, &[(KEY, "v1")], || {
                tx_second.send(std::env::var(KEY).ok()).unwrap();
            });
        });
        let seen = rx_second
            .recv_timeout(Duration::from_secs(5))
            .expect("同内容的第二个调用必须与第一个并发（不得被它阻塞）");
        assert_eq!(seen.as_deref(), Some("v1"), "同内容调用应看到同一份值");

        tx_release.send(()).unwrap();
        first.join().unwrap();
        second.join().unwrap();
        assert!(
            std::env::var_os(KEY).is_none(),
            "最后一个调用结束后必须恢复原状"
        );
    }

    #[test]
    fn different_content_is_serialized() {
        let _gate = gate();
        const ENGINE: &str = "ut-diff";
        const KEY: &str = "CRUCIBLE_UT_DIFF_CONTENT";
        std::env::remove_var(KEY);

        let (tx1, rx1) = channel::<()>();
        let (tx_rel, rx_rel) = channel::<()>();
        let first = std::thread::spawn(move || {
            with_temp_env_named(ENGINE, &[(KEY, "a")], || {
                tx1.send(()).unwrap();
                rx_rel.recv().unwrap();
                assert_eq!(std::env::var(KEY).unwrap(), "a", "自己那组期间必须看到自己的值");
            });
        });
        rx1.recv_timeout(Duration::from_secs(5))
            .expect("第一个调用应进入闭包");

        let (tx2, rx2) = channel::<Option<String>>();
        let second = std::thread::spawn(move || {
            with_temp_env_named(ENGINE, &[(KEY, "b")], || {
                tx2.send(std::env::var(KEY).ok()).unwrap();
            });
        });
        // 不同内容绝不能同时生效：第一个还没结束，第二个不许进入闭包。
        match rx2.recv_timeout(Duration::from_millis(300)) {
            Err(RecvTimeoutError::Timeout) => {}
            other => panic!("不同内容必须串行，第二个调用提前进入了：{other:?}"),
        }

        tx_rel.send(()).unwrap();
        let seen = rx2
            .recv_timeout(Duration::from_secs(5))
            .expect("第一个结束后第二个应能进入");
        assert_eq!(
            seen.as_deref(),
            Some("b"),
            "第二个调用必须看到自己那组的值（不能是 'a'）"
        );
        first.join().unwrap();
        second.join().unwrap();
        assert!(std::env::var_os(KEY).is_none());
    }

    #[test]
    fn different_engine_same_vars_is_a_different_group() {
        let _gate = gate();
        const KEY: &str = "CRUCIBLE_UT_ENGINE";
        std::env::remove_var(KEY);

        let (tx, rx) = channel::<()>();
        let (tx_rel, rx_rel) = channel::<()>();
        let holder = std::thread::spawn(move || {
            with_temp_env_named("ut-eng-a", &[(KEY, "same")], || {
                tx.send(()).unwrap();
                rx_rel.recv().unwrap();
            });
        });
        rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let (tx2, rx2) = channel::<Option<String>>();
        let other = std::thread::spawn(move || {
            with_temp_env_named("ut-eng-b", &[(KEY, "same")], || {
                tx2.send(std::env::var(KEY).ok()).unwrap();
            });
        });
        // 引擎名进指纹是**保守**选择：同一批键值跨引擎也按不同组串行。
        // （进程 env 里装的值只由键值决定，去掉引擎名也能成立；保留它是因为 ABI 的
        //   extra JSON 带引擎名，且将来若有引擎自行 setenv 引擎相关变量，跨引擎共享
        //   一组就不再等价。这条只损失跨引擎的并发度，不损失正确性。）
        match rx2.recv_timeout(Duration::from_millis(300)) {
            Err(RecvTimeoutError::Timeout) => {}
            other => panic!("不同引擎 + 同一批键值应串行，实际提前进入了：{other:?}"),
        }
        tx_rel.send(()).unwrap();
        holder.join().unwrap();
        let _ = rx2.recv_timeout(Duration::from_secs(5));
        other.join().unwrap();
        assert!(std::env::var_os(KEY).is_none());
    }

    #[test]
    fn restores_env_on_panic() {
        let _gate = gate();
        const ENGINE: &str = "ut-panic";
        const KEY: &str = "CRUCIBLE_UT_PANIC";
        std::env::remove_var(KEY);

        let (tx, rx) = channel::<Option<String>>();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_temp_env_named(ENGINE, &[(KEY, "boom")], || {
                tx.send(std::env::var(KEY).ok()).unwrap();
                panic!("用例故意 panic（验证临时环境会被 Drop 恢复）");
            })
        }));
        assert!(res.is_err(), "闭包内的 panic 必须原样向外传播");
        assert_eq!(rx.recv().unwrap().as_deref(), Some("boom"), "panic 前应已装上临时值");
        assert!(
            std::env::var_os(KEY).is_none(),
            "panic 展开后也必须恢复：否则临时值会污染之后所有请求"
        );
    }

    #[test]
    fn restores_env_on_return_and_empty_vars_wait_for_active_group() {
        let _gate = gate();
        const ENGINE: &str = "ut-return";
        const KEY: &str = "CRUCIBLE_UT_RETURN";
        const HOLDER: &str = "CRUCIBLE_UT_HOLDER";
        std::env::remove_var(KEY);
        std::env::remove_var(HOLDER);

        // 正常/提前 return：返回后必须恢复
        let out = with_temp_env_named(ENGINE, &[(KEY, "x")], || {
            assert_eq!(std::env::var(KEY).unwrap(), "x");
            7
        });
        assert_eq!(out, 7);
        assert!(std::env::var_os(KEY).is_none(), "f() 返回后必须恢复原状");

        // 原本已存在的变量：恢复要变回原值（不是删掉）
        std::env::set_var(KEY, "orig");
        with_temp_env_named(ENGINE, &[(KEY, "tmp")], || {
            assert_eq!(std::env::var(KEY).unwrap(), "tmp");
        });
        assert_eq!(std::env::var(KEY).unwrap(), "orig");

        // 空值项 = 确保不存在（沿用旧语义），恢复同样要回原值
        with_temp_env_named(ENGINE, &[(KEY, "")], || {
            assert!(std::env::var_os(KEY).is_none());
        });
        assert_eq!(std::env::var(KEY).unwrap(), "orig");
        std::env::remove_var(KEY);

        // **空变量必须等「生效中的非空组」退干净**（这是「空值窗口」的修复点）：
        // 否则空请求的引擎会读到别人装的 .env。用一个「不同内容」的组占住全局状态，
        // 空变量调用此时**不得**进入闭包；释放后才进入，且此时看不到别人的值。
        let (tx, rx) = channel::<()>();
        let (tx_rel, rx_rel) = channel::<()>();
        let holder = std::thread::spawn(move || {
            with_temp_env_named("ut-holder", &[(HOLDER, "h")], || {
                tx.send(()).unwrap();
                rx_rel.recv().unwrap();
            });
        });
        rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let (tx2, rx2) = channel::<Option<String>>();
        let empty = std::thread::spawn(move || {
            with_temp_env_named("ut-empty", &[], || {
                tx2.send(std::env::var(HOLDER).ok()).unwrap();
            });
        });
        match rx2.recv_timeout(Duration::from_millis(300)) {
            Err(RecvTimeoutError::Timeout) => {}
            other => panic!("空变量请求不得与非空组并发生效（会读到别人的 .env）：{other:?}"),
        }
        tx_rel.send(()).unwrap();
        let seen = rx2
            .recv_timeout(Duration::from_secs(5))
            .expect("holder 释放后空请求应能进入");
        assert_eq!(
            seen.as_deref(),
            None,
            "空请求必须看不到 holder 的 .env 值（空值窗口已闭）"
        );
        holder.join().unwrap();
        empty.join().unwrap();
        assert!(std::env::var_os(HOLDER).is_none());
    }

    /// 「无 .env」请求彼此仍并发：空组跨引擎同身份，一个 sleep 的空请求不会把其它空请求
    /// 串行化（§13.8 的 DoS 不回归）。这是空值窗口修复**不能**引入的回归。
    #[test]
    fn empty_requests_are_concurrent() {
        let _gate = gate();
        let (tx_entered, rx_entered) = channel::<()>();
        let (tx_release, rx_release) = channel::<()>();
        // 两个「无 .env」请求、**不同引擎**（模拟 /cgi/ 与 /php/ 的空请求）。
        let first = std::thread::spawn(move || {
            with_temp_env_named("ut-empty-a", &[], || {
                tx_entered.send(()).unwrap();
                rx_release.recv().unwrap();
            });
        });
        rx_entered
            .recv_timeout(Duration::from_secs(5))
            .expect("第一个空请求应进入闭包");

        let (tx2, rx2) = channel::<()>();
        let second = std::thread::spawn(move || {
            with_temp_env_named("ut-empty-b", &[], || {
                tx2.send(()).unwrap();
            });
        });
        rx2.recv_timeout(Duration::from_secs(5))
            .expect("空请求之间必须并发（空组同身份），不得被另一个空请求阻塞");

        tx_release.send(()).unwrap();
        first.join().unwrap();
        second.join().unwrap();
    }
}
