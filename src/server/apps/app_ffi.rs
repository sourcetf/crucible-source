//! dlopen-based app engine FFI (RTLD_GLOBAL).
//!
//! §7.3 最终态：**所有**引擎都走有界线程池（通用 clamp(4..=8)，rack/psgi 串行单线程，
//! cgi 独立窄池）+ 按内容分锁。
//!
//! 这里曾经给 c/go/rust 留了一条「同线程内联、跳过 env 锁」的快路。那条快路的前提是错的：
//! 它以为这些引擎拿 `.env` 变量走的是「extra JSON 下发、不碰进程级 env」，而 C 侧的
//! `appengine_apply_extra` 落地方式就是 **setenv**（libs/app-engines/common/appengine_common.c
//! 与 samples/{c,rust}-plugin 都是）——于是这条快路成了进程 env 唯一不受 [`env_lock`] 保护、
//! 也从不把值恢复回去的写者。现在 c/go/rust 与其它引擎同路（见 [`execute`]）。
//! ABI 的 headers 块与请求 body/content_type 全量透传（旧实现把引擎设置
//! 的响应头整体丢弃，导致 ngx.header / WSGI 自定义头失效、POST 空 body）；
//! 但定界头（Content-Length）不原样透传 —— 见 response_from_outcome 的说明。

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::env_lock;
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::sync::Arc;

#[repr(C)]
struct AppEngineResult {
    status: c_int,
    headers: *mut c_char,
    headers_len: usize,
    body: *mut u8,
    body_len: usize,
    error: *mut c_char,
}

type InitFn = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
type ExecFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const u8,
    usize,
    *const c_char,
    *const c_char,
    c_int,
    *const c_char,
    *mut AppEngineResult,
) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut AppEngineResult);
type ShutdownFn = unsafe extern "C" fn();

struct EngineLib {
    engine: String,
    path: String,
    // libloading::Library 自动 dlclose on Drop (其内部用 NonNull<c_void>)
    _lib: libloading::Library,
    #[allow(dead_code)]
    init: InitFn,
    exec: ExecFn,
    free: FreeFn,
    shutdown: ShutdownFn,
}

unsafe impl Send for EngineLib {}
unsafe impl Sync for EngineLib {}

impl Drop for EngineLib {
    fn drop(&mut self) {
        // Deferred reconcile unload: last Arc drops → shutdown + (libloading 自动 dlclose).
        unsafe { (self.shutdown)() };
    }
}


/// 缓存键 = .so 路径字符串（同引擎多 lib 并存时不串台）。
static LIBS: Lazy<Mutex<HashMap<String, Arc<EngineLib>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 每个 .so 路径一把装载锁。
///
/// 原来的 check-then-insert 不是原子的：两个并发冷请求会各 dlopen 一次、
/// 各跑一次 `appengine_init`，而 map 里只留后者——先到的那个 Arc 被 drop 时
/// 会调用 `appengine_shutdown()`，把仍在被另一个请求执行中的实例状态拆掉。
/// 分路径加锁既消除重复装载，又不让不同引擎互相阻塞。
static LOAD_LOCKS: Lazy<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// §7.2 引擎单次执行的结果（状态码 + 头块 + body）。
pub struct ExecOutcome {
    pub status: i32,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

pub async fn execute(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    // P1-1：.env 变量由 apps::try_handle 注入 extensions。所有引擎（含 c/go/rust）都经
    // env_lock 把它们装进**进程环境**：C 侧的 appengine_apply_extra 就是 setenv，没有
    // 哪条引擎路径是「只下发、不碰进程 env」的。
    let env_vars: Vec<(String, String)> = req
        .extensions()
        .get::<crate::server::apps::deps::DepsEnv>()
        .map(|d| (*d.vars).clone())
        .unwrap_or_default();
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // §7.10 热路径：GET/HEAD 无 body 时不 collect，保持 rust≈static 的延迟。
    // 任务 6（OOM 防护）：引擎请求体上限 32MiB，超限 413。
    let body_bytes = if request_has_body(&parts.method, &parts.headers) {
        match http_body_util::Limited::new(body, crate::server::h1::APP_BODY_CAP).collect().await
        {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(full("request body too large"))
                    .unwrap())
            }
        }
    } else {
        Bytes::new()
    };
    let outcome = exec_dispatch(
        &method, &path, &query, &content_type, &body_bytes, lc, app, peer, &env_vars,
    )
    .await?;
    Ok(response_from_outcome(outcome))
}

/// `Request<Bytes>` 变体（H2/H3 simple 路径）——P1-9：请求体已在协议层收齐，
/// 连同 .env 变量（P1-1）一起交给引擎，不再恒传空 body。
pub async fn execute_simple(
    req: &Request<Bytes>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    deps: &crate::server::apps::deps::DepsEnv,
) -> Result<ExecOutcome> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    exec_dispatch(
        &method,
        &path,
        &query,
        &content_type,
        req.body(),
        lc,
        app,
        peer,
        &deps.vars,
    )
    .await
}

async fn exec_dispatch(
    method: &str,
    path: &str,
    query: &str,
    content_type: &str,
    body: &Bytes,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    env_vars: &[(String, String)],
) -> Result<ExecOutcome> {
    let engine = app.engine.to_ascii_lowercase();
    let lib_path = resolve_lib(app, &engine)?;
    let docroot = app.docroot.clone().unwrap_or_else(|| lc.root.clone());
    // §3.3 语义：docroot 已是应用级根（www-apps/<engine>），script 必须用剥掉
    // app 前缀后的相对路径（/lua/index.lua → index.lua）；目录/根请求回落 app.index。
    // 旧实现整条 request path 直接 join，导致 docroot 双重前缀（lua/wsgi 等真读
    // 文件的引擎 500，而 rust/c/go 样例插件不读文件被掩盖）。
    // §7.1 防穿越：script 必须留在 docroot 下（裸 join 可 /engine/../../ 读任意文件）。
    let rel = rel_script_path(app, path);
    let script = crate::server::admin_files::script_rel(&docroot, rel.trim_start_matches('/'))
        .map_err(|e| anyhow::anyhow!("script path rejected: {e:#}"))?;
    let port = lc.port;
    let server_name = lc.server_name.clone().unwrap_or_else(|| "crucible".into());

    let m = method.to_string();
    let p = path.to_string();
    let q = query.to_string();
    let ct = content_type.to_string();
    let b = body.clone();

    let serial = serial_engine(&engine);
    let engine_for_pool = engine.clone();
    // P1-1：闭包必须持有 owned 环境变量（'static），在闭包内转 &[(&str,&str)]。
    let env_vars_owned: Vec<(String, String)> = env_vars.to_vec();
    let job = move || {
        let vars: Vec<(&str, &str)> = env_vars_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        env_lock::with_temp_env_named(&engine, &vars, || {
            let lib = load_engine(&engine, &lib_path)?;
            call_exec(
                &lib, &engine, &script, &docroot, &m, &p, &q, &ct, &b, peer, port,
                &server_name, &env_vars_owned,
            )
        })
    };
    if serial {
        // rack/psgi：串行单线程池（解释器非线程安全）。
        Ok(serial_pool(&engine_for_pool).run(job).await?)
    } else if let Some(n) = dedicated_pool_threads(&engine_for_pool) {
        // cgi：独立窄池（见 dedicated_pool_threads），不占通用池、也不被通用池拖累。
        Ok(named_pool(&engine_for_pool, n).run(job).await?)
    } else {
        Ok(GENERIC_POOL.run(job).await?)
    }
}

/// POST/PUT/PATCH 或带 Content-Length/Transfer-Encoding 的请求才收 body。
fn request_has_body(m: &http::Method, h: &http::HeaderMap) -> bool {
    if matches!(*m, http::Method::POST | http::Method::PUT | http::Method::PATCH) {
        return true;
    }
    if h.contains_key(http::header::TRANSFER_ENCODING) {
        return true;
    }
    h.get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
        > 0
}


/// §3.3：请求路径 → 引擎脚本相对路径。
/// 剥掉命中的 app 前缀（前缀必须整体匹配，/ 边界对齐，避免 /phplint 命中 /php）；
/// 目录/根请求回落 `app.index`，未配置时按引擎给默认首页。
pub(crate) fn rel_script_path(app: &AppRouteConfig, path: &str) -> String {
    let mut p = path.to_string();
    for prefix in &app.paths {
        if prefix.is_empty() {
            continue;
        }
        // 归一化尾斜杠：配置写 `/php/` 时不能拿 `/php//` 去比前缀，否则应用前缀
        // 永远剥不掉（脚本路径变成 docroot/php/x.php → 404）。与 apps::match_app 同口径。
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() {
            // "/"（或全斜杠）：整段路径原样，无前缀可剥。
            continue;
        }
        if p == prefix || p.starts_with(&format!("{prefix}/")) {
            p = p[prefix.len()..].to_string();
            if !p.starts_with('/') {
                p.insert(0, '/');
            }
            break;
        }
    }
    if p == "/" || p.is_empty() || p.ends_with('/') {
        if let Some(idx) = app.index.as_deref() {
            return format!("/{idx}");
        }
        if let Some(def) = default_index(&app.engine.to_ascii_lowercase()) {
            return format!("/{def}");
        }
    }
    p
}

/// 未配置 `index` 时的引擎默认首页（与 config.toml §3.4 样例一致）。
fn default_index(engine: &str) -> Option<&'static str> {
    match engine {
        "lua" => Some("index.lua"),
        "wsgi" | "asgi" | "python" => Some("index.py"),
        "psgi" => Some("index.psgi"),
        "rack" => Some("index.ru"),
        "cgi" => Some("index.cgi"),
        "ruby" => Some("index.rb"),
        "perl" => Some("index.pl"),
        "php" => Some("index.php"),
        "tsx" => Some("index.tsx"),
        "asp" => Some("index.asp"),
        "aspnet" => Some("index.aspx"),
        "jsp" | "do" => Some("index.jsp"),
        _ => None,
    }
}

pub fn resolve_lib(app: &AppRouteConfig, engine: &str) -> Result<PathBuf> {
    if let Some(p) = &app.lib {
        return Ok(p.clone());
    }
    let env_key = format!("APPENGINE_{}_LIB", engine.to_ascii_uppercase());
    if let Some(p) = env_lock::read_static_env(&env_key) {
        return Ok(PathBuf::from(p));
    }
    Ok(PathBuf::from(format!(
        "target/app-engines/libapp_{engine}.so"
    )))
}

// ---------------------------------------------------------------- 线程池 (§7.3)

type PoolJob = Box<dyn FnOnce() + Send + 'static>;

struct EnginePool {
    tx: std::sync::mpsc::Sender<PoolJob>,
}

static GENERIC_POOL: Lazy<EnginePool> =
    Lazy::new(|| EnginePool::start(generic_pool_threads(), "appffi"));
/// 命名池表：键是 `引擎#线程数`（既是 rack/psgi 的串行池，也是 cgi 那类独立窄池）。
static SERIAL_POOLS: Lazy<Mutex<HashMap<String, Arc<EnginePool>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn generic_pool_threads() -> usize {
    let cpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    // 池宽决定「同时能有多少个引擎请求在飞」。这些线程绝大部分时间阻塞在 I/O 上
    // （等 sidecar 回包、等 fork 出来的 CGI 子进程），不是 CPU 密集，所以与核数脱钩、
    // 给足冗余更划算：实测本机只有 1 核 → 旧下限 2 条线程，两个 `sleep 120` 的 CGI
    // 就把池占满，**其它引擎的请求全部排队**（验收里 lua/asp/python 被饿到客户端超时）。
    // 单个 CGI 最长可占 30s（CGI_TIMEOUT_MS），所以下限提到 4、上限 8。
    cpu.clamp(4, 8)
}

fn serial_engine(engine: &str) -> bool {
    matches!(engine, "rack" | "psgi")
}

impl EnginePool {
    fn start(threads: usize, name: &str) -> EnginePool {
        let (tx, rx) = std::sync::mpsc::channel::<PoolJob>();
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..threads.max(1) {
            let rx = Arc::clone(&rx);
            let _ = std::thread::Builder::new()
                .name(format!("cruc-{name}-{i}"))
                .spawn(move || loop {
                    let job = {
                        let guard = rx.lock();
                        guard.recv()
                    };
                    match job {
                        Ok(j) => j(),
                        Err(_) => break,
                    }
                });
        }
        EnginePool { tx }
    }

    async fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let (otx, orx) = tokio::sync::oneshot::channel();
        self.tx
            .send(Box::new(move || {
                let _ = otx.send(f());
            }))
            .map_err(|_| anyhow::anyhow!("engine thread pool closed"))?;
        orx.await.map_err(|_| anyhow::anyhow!("engine worker dropped"))?
    }
}

/// 按名字取一个固定宽度的引擎池（同名同宽度复用）。
fn named_pool(engine: &str, threads: usize) -> Arc<EnginePool> {
    SERIAL_POOLS
        .lock()
        .entry(format!("{engine}#{threads}"))
        .or_insert_with(|| Arc::new(EnginePool::start(threads, engine)))
        .clone()
}

fn serial_pool(engine: &str) -> Arc<EnginePool> {
    named_pool(engine, 1)
}

/// 需要**独立池**的引擎：`None` = 走通用池。
///
/// 为什么 cgi 要独立：CGI 引擎每个请求 fork 一个子进程、最长可占 30s（CGI_TIMEOUT_MS），
/// 是所有引擎里唯一会长时间占住线程的。它跟通用池混在一起时，几个慢脚本就能把通用池
/// 占满 —— 实测（本机 1 核 → 通用池只有 2 条线程）两个 `sleep 120` 的脚本就让
/// lua/asp/python 的请求全部排队到客户端超时。独立池既隔离了这种阻塞，
/// 也顺手把「同时 fork 多少个子进程」限住（内存可控）。
fn dedicated_pool_threads(engine: &str) -> Option<usize> {
    match engine {
        "cgi" => Some(4),
        _ => None,
    }
}

// ---------------------------------------------------------------- dlopen / exec

fn load_engine(engine: &str, lib_path: &PathBuf) -> Result<Arc<EngineLib>> {
    let key = lib_path.to_string_lossy().into_owned();
    // 快路径：已装载
    {
        let map = LIBS.lock();
        if let Some(l) = map.get(&key) {
            return Ok(Arc::clone(l));
        }
    }
    // 慢路径：按路径串行化，避免并发重复 dlopen + 重复 appengine_init。
    let path_lock = {
        let mut locks = LOAD_LOCKS.lock();
        Arc::clone(locks.entry(key.clone()).or_default())
    };
    let _guard = path_lock.lock();
    // 等到锁之后必须复查：这段时间里另一个线程可能已经装载完成。
    {
        let map = LIBS.lock();
        if let Some(l) = map.get(&key) {
            return Ok(Arc::clone(l));
        }
    }
    if !lib_path.is_file() {
        bail!("missing engine lib {}", lib_path.display());
    }
    // libloading 0.8 type-safe: Symbol<T> 在获取时校验符号类型与 T 签名，
    // 杜绝 std::mem::transmute 的隐藏 UB。
    //
    // 但 `Library::new` 在 unix 上等价于 `open(path, RTLD_LAZY | RTLD_LOCAL)`
    //（libloading 0.8.9 `os/unix/mod.rs:135` 源码核对），与规格 §7.1 铁律 3 / §16.8
    // 要求的 `RTLD_NOW | RTLD_GLOBAL` **相反**：
    //   * LAZY ⇒ 引擎 .so 里缺失/未解析的符号不在装载时报错，而是拖到第一次
    //     `appengine_execute` 跳到未解析 PLT —— 崩的是整个 webserver 进程，而不是
    //     干净地回 502（NOW 正是为了「加载期失败」）；
    //   * LOCAL ⇒ 引擎及其依赖不进全局作用域，多个 `.so` 之间靠
    //     `dlsym(RTLD_DEFAULT)` 共享符号的用法失效。
    // 因此这里显式用 os::unix::Library::open 传 flag，再转回安全包装（From 已实现）。
    #[cfg(unix)]
    let lib: libloading::Library = {
        let raw = unsafe {
            libloading::os::unix::Library::open(
                Some(lib_path),
                libc::RTLD_NOW | libc::RTLD_GLOBAL,
            )
        }
        .map_err(|e| anyhow::anyhow!("dlopen {}: {e}", lib_path.display()))?;
        raw.into()
    };
    // 非 unix 无 dlopen flags 可用（Windows 用 LOAD_WITH_ALTERED_SEARCH_PATH 语义），
    // 保持 libloading 默认。
    #[cfg(not(unix))]
    let lib: libloading::Library = unsafe { libloading::Library::new(lib_path) }
        .map_err(|e| anyhow::anyhow!("dlopen {}: {e}", lib_path.display()))?;
    // type-safe: 编译期校验符号签名 (Symbol<T> 内部实现)
    macro_rules! sym {
        ($ty:ty, $name:literal) => {
            unsafe { lib.get::<$ty>(concat!($name, "\0").as_bytes()) }
                .map_err(|e| anyhow::anyhow!("missing symbol {}: {e}", $name))?
        };
    }
    let init: InitFn = *sym!(InitFn, "appengine_init");
    let exec: ExecFn = *sym!(ExecFn, "appengine_execute");
    let free: FreeFn = *sym!(FreeFn, "appengine_result_free");
    let shutdown: ShutdownFn = *sym!(ShutdownFn, "appengine_shutdown");
    let eng = CString::new(engine).context("engine name nul")?;
    let hint = CString::new(lib_path.to_string_lossy().as_bytes()).context("hint nul")?;
    let rc = unsafe { (init)(eng.as_ptr(), hint.as_ptr()) };
    if rc != 0 {
        bail!("appengine_init failed: {rc}");
    }
    let lib = Arc::new(EngineLib {
        engine: engine.to_string(),
        path: key.clone(),
        // libloading 库句柄 (NonNull<c_void> + Drop dlclose)
        _lib: lib,
        init,
        exec,
        free,
        shutdown,
    });
    LIBS.lock().insert(key, Arc::clone(&lib));
    Ok(lib)
}

#[allow(clippy::too_many_arguments)]
fn call_exec(
    lib: &EngineLib,
    engine: &str,
    script: &PathBuf,
    docroot: &PathBuf,
    method: &str,
    path: &str,
    query: &str,
    content_type: &str,
    body: &Bytes,
    peer: SocketAddr,
    port: u16,
    server_name: &str,
    env_vars: &[(String, String)],
) -> Result<ExecOutcome> {
    let c_script = CString::new(script.to_string_lossy().as_bytes())?;
    let c_doc = CString::new(docroot.to_string_lossy().as_bytes())?;
    let c_method = CString::new(method)?;
    let c_path = CString::new(path)?;
    let c_query = CString::new(query)?;
    let c_ct = CString::new(content_type)?;
    let c_remote = CString::new(peer.ip().to_string())?;
    let c_server = CString::new(server_name)?;
    // P1-1：extra 语义升级——带 .env 变量时传 JSON {"engine":...,"env":{...}}，
    // 由 libs/app-engines/common 解析注入执行环境；无变量时保持 legacy 纯引擎名
    //（现有 C 侧 common 不消费 extra，旧插件不受影响）。
    let extra_s: String = if env_vars.is_empty() {
        engine.to_string()
    } else {
        let mut env_obj = serde_json::Map::new();
        for (k, v) in env_vars {
            env_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        serde_json::json!({"engine": engine, "env": serde_json::Value::Object(env_obj)})
            .to_string()
    };
    let c_extra = CString::new(extra_s)?;
    let mut out = AppEngineResult {
        status: 500,
        headers: std::ptr::null_mut(),
        headers_len: 0,
        body: std::ptr::null_mut(),
        body_len: 0,
        error: std::ptr::null_mut(),
    };
    let (body_ptr, body_len) = if body.is_empty() {
        (std::ptr::null(), 0usize)
    } else {
        (body.as_ptr(), body.len())
    };
    unsafe {
        let rc = (lib.exec)(
            c_script.as_ptr(),
            c_doc.as_ptr(),
            c_method.as_ptr(),
            c_path.as_ptr(),
            c_query.as_ptr(),
            c_ct.as_ptr(),
            body_ptr,
            body_len,
            c_remote.as_ptr(),
            c_server.as_ptr(),
            port as c_int,
            c_extra.as_ptr(),
            &mut out,
        );
        if rc != 0 {
            let msg = if !out.error.is_null() {
                CStr::from_ptr(out.error).to_string_lossy().into_owned()
            } else {
                format!("exec rc={rc}")
            };
            (lib.free)(&mut out);
            bail!("{msg}");
        }
        // rc == 0 表示「引擎服务过这个请求」，但引擎**仍可能**填了 error：典型是
        // WSGI/ASGI/uWSGI 的「应用抛异常 → 500 + 固定文本」，traceback **只在 error 里**
        // （不再回显给客户端 —— 那会泄露绝对路径与源码行）。这类细节必须进本地日志，
        // 否则排障就断了；而它又是**每请求一条**、可被对端驱动（脚本总是抛异常即可）
        // ⇒ 走同一套按引擎的时间节流。
        let engine_reported = if out.error.is_null() {
            None
        } else {
            Some(CStr::from_ptr(out.error).to_string_lossy().into_owned())
        };
        let headers = parse_result_headers(out.headers, out.headers_len);
        // ABI 没有 body 容量字段，宿主无法真正校验 `body_len`（引擎写错长度时
        // `from_raw_parts` 会越界读堆内存并把内容发给客户端）。这里至少加一条
        // 上界：超过上游响应上限的长度一定是 bug，宁可 502 也不能跳进越界读。
        let body_out = if out.body.is_null() || out.body_len == 0 {
            Bytes::new()
        } else if out.body_len > crate::server::h1::UPSTREAM_BODY_CAP {
            let n = out.body_len;
            (lib.free)(&mut out);
            bail!(
                "engine {engine} returned body_len {n} > {} (ABI violation)",
                crate::server::h1::UPSTREAM_BODY_CAP
            );
        } else {
            Bytes::copy_from_slice(std::slice::from_raw_parts(out.body, out.body_len))
        };
        let status = out.status;
        (lib.free)(&mut out);
        if let Some(msg) = engine_reported {
            crate::server::log_throttle::warn_every(
                &format!("engine-app-err::{engine}"),
                std::time::Duration::from_secs(60),
                &format!("{engine}: 应用级错误（客户端只收到固定文本，细节仅本地）: {msg}"),
            );
        }
        Ok(ExecOutcome {
            status,
            headers,
            body: body_out,
        })
    }
}

/// 解析 ABI headers 块（"Name: value\r\n" NUL 结尾），带注入净化。
fn parse_result_headers(ptr: *mut c_char, len: usize) -> Vec<(String, String)> {
    if ptr.is_null() {
        return Vec::new();
    }
    let text: String = unsafe {
        // ABI 契约里这个块是**以 NUL 结尾**的文本块（appengine_result_set_headers 用
        // strlen 填 headers_len）。**不能**直接拿 len 去建 slice —— len 是 C 侧塞进来的：
        // 引擎若直接把 out->headers 指向自己的缓冲却忘了填 headers_len（或填的是上一版
        // 结果残留的长度），`from_raw_parts(ptr, len)` 就会读出一大段分配之外的内存，
        // 而那些字节随后会被当作响应头发出去（堆内容泄露 + 可能 OOM）。
        // 一律先按 NUL 定界取真实长度，len 只当上限用（`len == 0` 时与旧行为等价）。
        let real = CStr::from_ptr(ptr).to_bytes().len();
        let n = if len == 0 || len > real { real } else { len };
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr as *const u8, n)).into_owned()
    };
    // 显式标注：下面的 content-type 去重会先**读** `out`（`iter_mut().find()`）再决定是否
    // push，元素类型无法从 push 反推，省略标注会 E0282。
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if valid_header_kv(k, v) {
                // `Content-Type` 按 RFC 是**单值**头。脚本引擎（`ngx.header`、CGI 打印两行
                // `Content-Type:`、WSGI 里手写 headers）很容易输出两份，而调用方是
                // `builder.header(k, v)` —— hyper 会**追加**而不是替换 ⇒ 响应带两个
                // content-type，缓存/代理与客户端可能各挑一个（实测 CGI 脚本可复现）。
                // 这里统一去重：**后者胜出**（CGI 语义），且对**所有**引擎生效。
                // 只针对 content-type —— `Set-Cookie` 等同名多头是合法的，不能一起合。
                if k.eq_ignore_ascii_case("content-type") {
                    if let Some(slot) = out
                        .iter_mut()
                        .find(|(ek, _)| ek.eq_ignore_ascii_case("content-type"))
                    {
                        *slot = (k.to_string(), v.to_string());
                        continue;
                    }
                }
                out.push((k.to_string(), v.to_string()));
            }
        }
        if out.len() >= 64 {
            break;
        }
    }
    out
}

/// 头注入防护：名 token 字符；值可见 ASCII/tab；长度受限。
pub fn valid_header_kv(k: &str, v: &str) -> bool {
    !k.is_empty()
        && k.len() <= 256
        && k.bytes().all(|b| b.is_ascii_graphic() && b != b':')
        && v.len() <= 8192
        && v.bytes().all(|b| (0x20..=0x7e).contains(&b) || b == b'\t')
}

/// 引擎给的状态码 → hyper 状态码。
///
/// 只接受 **200..=599**：0/1xx 不能作为最终响应 —— hyper 1.x 服务端 encode 对
/// `is_informational()` 的最终响应会改成 500 并返回 `user_unsupported_status_code`，
/// 直接掐掉连接（客户端看到断连/重试，而不是一个干净的 5xx）。`from_u16` 对 3 位以外
/// 的非法值也会失败，统一回 500。
fn status_code(status: i32) -> StatusCode {
    if !(200..=599).contains(&status) {
        log::debug!("app_ffi: engine returned invalid status {status}; using 500");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::from_u16(status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// FFI 结果 → 完整响应；引擎未给 Content-Type 时回退 text/plain。
pub fn response_from_outcome(outcome: ExecOutcome) -> Response<BoxBody> {
    let mut builder = Response::builder().status(status_code(outcome.status));
    let mut has_ct = false;
    for (k, v) in &outcome.headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_ct = true;
        }
        // 引擎声明的 Content-Length 只有**恰好等于真实 body 长度**时才透传。hyper 会
        // 信任这个头的文本、却按 body 的实际长度成帧（hyper 1.x
        // `proto::h1::role::Server::encode`：Known(known_len) 分支只把用户给的值原样写出，
        // encoder 用 known_len）—— 两者不一致时 keep-alive 上就是「声明 N 字节、实发 M 字节」，
        // 客户端把多出来的 M-N 字节当成**下一个响应**（响应走私）。脚本自己拼这个头
        //（`header("Content-Length: " .. n)`、ngx.header）时很容易写错，且值可能来自请求参数。
        // 与 proxy.rs 里「上游 Content-Length 透传导致响应走私」是同一条规则：让服务器按
        // 真实长度自己写。一致时保留（HEAD 场景客户端仍能拿到实体长度）。
        if k.eq_ignore_ascii_case("content-length") {
            let declared = v.trim().parse::<u64>().ok();
            if declared != Some(outcome.body.len() as u64) {
                continue;
            }
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    if !has_ct {
        builder = builder.header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    }
    builder.body(full(outcome.body)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(full("engine response build error"))
            .unwrap()
    })
}

/// `Response<Bytes>` 变体（H2/H3 simple 路径）。
pub fn simple_response_from_outcome(outcome: ExecOutcome) -> Response<Bytes> {
    let mut builder = Response::builder().status(status_code(outcome.status));
    let mut has_ct = false;
    for (k, v) in &outcome.headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_ct = true;
        }
        // 同 `response_from_outcome`：与真实 body 长度不符的 Content-Length 一律丢弃
        //（h1 上是响应走私，h2/h3 上会让对端判 CL 不符并 RST 该流）。
        if k.eq_ignore_ascii_case("content-length") {
            let declared = v.trim().parse::<u64>().ok();
            if declared != Some(outcome.body.len() as u64) {
                continue;
            }
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    if !has_ct {
        builder = builder.header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    }
    builder.body(outcome.body).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Bytes::from_static(b"engine response build error"))
            .unwrap()
    })
}

/// 强制卸载指定引擎的全部 .so（admin / 配置清理入口）。
#[allow(dead_code)]
pub fn shutdown_engine(engine: &str) {
    // 只把条目取出来，**释放 LIBS 锁后再 drop**：drop 会执行 C 侧
    // `appengine_shutdown()` + dlclose，而外部 .so 的 shutdown 可能阻塞
    //（等自己的线程/IO）。持锁执行会把所有 `load_engine` 快路径一起卡死。
    let removed: Vec<Arc<EngineLib>> = {
        let mut map = LIBS.lock();
        let keys: Vec<String> = map
            .iter()
            .filter(|(_, l)| l.engine == engine)
            .map(|(k, _)| k.clone())
            .collect();
        keys.into_iter().filter_map(|k| map.remove(&k)).collect()
    };
    drop(removed); // 锁外 Drop → shutdown + dlclose
}

/// §7.3 热卸载：配置不再引用、且无在途请求（强引用仅剩缓存表）的引擎 →
/// shutdown + dlclose。有在途请求时仅出表，句柄随最后一个引用释放。
pub fn reconcile_unload(active: &[(String, String)]) {
    // 同上：先出表、放锁，再在锁外 drop（shutdown 可能阻塞）。
    let stale: Vec<Arc<EngineLib>> = {
        let mut map = LIBS.lock();
        let keys: Vec<String> = map
            .iter()
            .filter(|(_, l)| !active.iter().any(|(e, p)| e == &l.engine && p == &l.path))
            .map(|(k, _)| k.clone())
            .collect();
        keys.into_iter().filter_map(|k| map.remove(&k)).collect()
    };
    for lib in stale {
        if Arc::strong_count(&lib) == 1 {
            log::info!("app_ffi: unload engine {} ({})", lib.engine, lib.path);
        } else {
            log::debug!(
                "app_ffi: engine {} in-flight; defer dlclose via Drop",
                lib.engine
            );
        }
        // Drop impl performs shutdown+dlclose（无在途请求时；否则最后一个引用 Drop 时执行）。
        drop(lib);
    }
}

#[cfg(test)]
mod status_and_rel_tests {
    use super::*;

    fn app_with_paths(paths: &[&str]) -> AppRouteConfig {
        AppRouteConfig {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            enabled: true,
            engine: "php".into(),
            socket: None,
            extensions: vec!["php".into()],
            index: None,
            php_bin: None,
            workers: 1,
            source_dir: None,
            out_dir: None,
            entry: vec![],
            watch: false,
            docroot: None,
            lib: None,
            deps_dir: None,
            init_timeout_secs: None,
            libc: None,
        }
    }

    /// 0/1xx 不能变成合法最终响应（hyper 会掐连接）；非法/越界值回 500。
    #[test]
    fn invalid_statuses_map_to_500() {
        assert_eq!(status_code(0), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(100), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(199), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(99), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(200), StatusCode::OK);
        assert_eq!(status_code(204), StatusCode::NO_CONTENT);
        assert_eq!(status_code(500), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(599), StatusCode::from_u16(599).unwrap());
        assert_eq!(status_code(600), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_code(-1), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// `paths = ["/php/"]` 与 `"/php"` 必须等价：脚本相对路径都要剥掉前缀。
    #[test]
    fn rel_script_path_normalizes_trailing_slash_prefix() {
        let app = app_with_paths(&["/php/"]);
        assert_eq!(rel_script_path(&app, "/php/index.php"), "/index.php");
        assert_eq!(rel_script_path(&app, "/php/sub/a.php"), "/sub/a.php");
        // 目录请求回落 index（这里只验证前缀已剥掉）
        assert_eq!(rel_script_path(&app, "/php/"), "/index.php");
        // 非前缀不误伤（/phplint 不属于 /php）
        assert_eq!(rel_script_path(&app, "/phplint/x.php"), "/phplint/x.php");
    }

    /// 无尾斜杠写法保持原有行为（回归）。
    #[test]
    fn rel_script_path_plain_prefix() {
        let app = app_with_paths(&["/php"]);
        assert_eq!(rel_script_path(&app, "/php/index.php"), "/index.php");
        let app = app_with_paths(&["/lua/"]);
        assert_eq!(rel_script_path(&app, "/lua/main.lua"), "/main.lua");
    }
}
