//! TypeScript / TSX 一键编译 + watch 部署引擎（规格 §7.7）。
//!
//! 契约（`options_catalog.rs` 里给运维看的说明就是 "One-click compile + watch deploy"）：
//!
//!   1. **内置编译**：首次请求（或 watch 轮询发现变更）时扫描 `source_dir` 下的
//!      `.ts/.tsx`，用宿主上真实存在的转译器（esbuild / tsc / swc，argv 直启、
//!      **绝不经过 shell**）把产物写进 `out_dir`（默认 `<docroot>/dist`）。
//!      编译结果按「源文件集合 + mtime + 大小 + 工具身份」指纹缓存：
//!      指纹不变就不重编译 —— 编译器**不在每请求路径上** spawn。
//!   2. **watch**：`watch = true` 时进程内后台线程每 ≤1.5s 轮询 source_dir 的 mtime，
//!      变更即重编译（单线程、每应用一次，不是每请求）。
//!   3. **静态托管**：请求从 `out_dir` 读产物（拒绝 `..`/反斜杠/NUL，再做 canonical
//!      范围校验防符号链接逃逸）。源码 `.ts/.tsx` 不会被当文件吐出 —— 请求一个
//!      `.tsx` 路径拿到的是它的同名 `.js` 产物（不是源码字节）。
//!   4. **诚实失败**：
//!      * 没有转译器 → 客户端固定 502 文本（含「装什么」的一句话提示），详情进日志；
//!      * 编译失败 → 客户端固定 502 文本，完整 stderr/源路径**只**进服务日志（节流）
//!        与 [`status_json`]（供 admin 面板接线；admin.rs 不是本组文件，见
//!        `.agents/1009/fixes/apps-tsx.md` 的跨文件需求）。
//!
//! 传输层分工：h1 走本文件；h2/h3 的字节路径是 `sidecar_engine` → `app_ffi` 直达
//! `libs/app-engines/tsx/tsx_engine.c` —— 那个 .so 只服务同一套产物约定
//! （`<docroot>/dist/<rel>.js`），不自己编译（编译只在 h1/watch 这条路上发生）。
//!
//! 安全边界：编译命令的每个 argv 都由**配置/文件系统发现的路径**拼出（请求路径从不
//! 进入 argv）；产物只写 `out_dir`；读取只发生在 canonical 校验通过之后。

use crate::config::{AppRouteConfig, ListenerConfig};
#[cfg(unix)]
use crate::server::apps::native_http;
use crate::server::h1::{full, BoxBody};
use anyhow::Result;
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// watch 轮询间隔（规格要求 ≤2s）。
const WATCH_INTERVAL: Duration = Duration::from_millis(1500);
/// 相邻两次「按需」源扫描的最小间隔：突发请求不重复 walk 目录；watch 线程与下一次
/// 检查会兜住窗口内的变更（watch=false 时最坏滞后一个窗口 + 扫描耗时）。
const MIN_CHECK_INTERVAL: Duration = Duration::from_millis(750);
/// 单次编译墙钟上限（npx 首次拉取依赖可能偏慢，给足；超时 kill 子进程）。
const COMPILE_TIMEOUT: Duration = Duration::from_secs(120);
/// 单份产物的读取上限（引擎响应全量进内存）。
const MAX_PRODUCT_BYTES: u64 = 64 * 1024 * 1024;
/// 单次构建扫描的源文件数上限（超过请用 `entry` 明确入口，避免命令行超长）。
const MAX_SOURCES: usize = 2048;
/// 捕获编译器 stdout/stderr 的上限（防呆输出撑爆内存；超出部分照读丢弃）。
const MAX_CAPTURE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// 编译结果缓存 / 状态（内存态，键 = port:app_idx:engine:docroot）
// ---------------------------------------------------------------------------

/// 解析后的应用目录：源码与产物。
#[derive(Clone, Debug)]
struct Paths {
    source: PathBuf,
    out: PathBuf,
}

#[derive(Clone, Debug)]
struct SrcFile {
    /// 相对 source_dir、以 `/` 分隔。
    rel: String,
    mtime: SystemTime,
    len: u64,
}

/// 上次检查的结论。`sig` 是「源集合 + mtime + 大小 + 工具」指纹。
#[derive(Clone)]
enum Cached {
    Ok {
        sig: u64,
        paths: Paths,
    },
    Err {
        sig: u64,
        msg: String,
        /// 缺转译器：要周期性重探（用户可能运行中安装），不能靠指纹一票缓存。
        no_tool: bool,
    },
}

impl Cached {
    fn sig(&self) -> u64 {
        match self {
            Cached::Ok { sig, .. } | Cached::Err { sig, .. } => *sig,
        }
    }

    fn result(&self) -> std::result::Result<Paths, BuildErr> {
        match self {
            Cached::Ok { paths, .. } => Ok(paths.clone()),
            Cached::Err { msg, no_tool, .. } => {
                if *no_tool {
                    Err(BuildErr::NoTool(msg.clone()))
                } else {
                    Err(BuildErr::Failed(msg.clone()))
                }
            }
        }
    }
}

#[derive(Default)]
struct CacheState {
    checked: Option<Instant>,
    entry: Option<Cached>,
}

/// 单个应用（listener.apps 条目）的编译状态。
struct AppBuild {
    key: String,
    /// 构建串行化：并发首请求只允许一个真正编。
    gate: Mutex<()>,
    cache: Mutex<CacheState>,
    status: Mutex<Status>,
}

/// 供日志/面板（[`status_json`]）使用的快照。
#[derive(Clone, Serialize)]
struct Status {
    key: String,
    port: u16,
    engine: String,
    source_dir: String,
    out_dir: String,
    watch: bool,
    tool: String,
    /// "init" | "building" | "ok" | "error"
    state: String,
    files: usize,
    last_build_unix_ms: u64,
    last_error: Option<String>,
}

impl Status {
    fn new(key: &str, port: u16, engine: &str) -> Self {
        Status {
            key: key.to_string(),
            port,
            engine: engine.to_string(),
            source_dir: String::new(),
            out_dir: String::new(),
            watch: false,
            tool: String::new(),
            state: "init".into(),
            files: 0,
            last_build_unix_ms: 0,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone)]
enum BuildErr {
    /// 宿主没有可用的 TS 转译器（附「缺什么、怎么装」）。
    NoTool(String),
    /// 其余编译/IO 失败（详情只进日志与 status）。
    Failed(String),
}

static APPS: Lazy<Mutex<HashMap<String, Arc<AppBuild>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn app_state(key: &str, port: u16, engine: &str) -> Arc<AppBuild> {
    APPS.lock()
        .entry(key.to_string())
        .or_insert_with(|| {
            Arc::new(AppBuild {
                key: key.to_string(),
                gate: Mutex::new(()),
                cache: Mutex::new(CacheState::default()),
                status: Mutex::new(Status::new(key, port, engine)),
            })
        })
        .clone()
}

/// 750ms 内已检查过 → 复用上次结论；否则 None（调用方去扫描/编译）。
fn fresh_cached(state: &AppBuild) -> Option<Cached> {
    let c = state.cache.lock();
    match c.checked {
        Some(t) if t.elapsed() < MIN_CHECK_INTERVAL => c.entry.clone(),
        _ => None,
    }
}

impl AppBuild {
    fn set_cached(&self, entry: Option<Cached>) {
        let mut c = self.cache.lock();
        c.checked = Some(Instant::now());
        c.entry = entry;
    }

    fn set_status<F: FnOnce(&mut Status)>(&self, f: F) {
        f(&mut self.status.lock());
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// watch 注册表（单后台线程，每应用一条 job；配置条数决定上界）
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct WatchJob {
    build: Arc<AppBuild>,
    app: AppRouteConfig,
    docroot: PathBuf,
}

static WATCH: Lazy<Mutex<HashMap<String, WatchJob>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static WATCH_STARTED: AtomicBool = AtomicBool::new(false);

fn register_watch(key: &str, build: Arc<AppBuild>, app: &AppRouteConfig, docroot: &Path) {
    {
        let mut w = WATCH.lock();
        if w.contains_key(key) {
            return;
        }
        w.insert(
            key.to_string(),
            WatchJob {
                build,
                app: app.clone(),
                docroot: docroot.to_path_buf(),
            },
        );
    }
    start_watch_thread();
}

fn start_watch_thread() {
    if WATCH_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("cruc-tsx-watch".into())
        .spawn(|| loop {
            std::thread::sleep(WATCH_INTERVAL);
            let jobs: Vec<WatchJob> = WATCH.lock().values().cloned().collect();
            for job in jobs {
                if !job.app.watch {
                    continue;
                }
                // 失败已在 ensure_built 内落日志/状态；watch 继续等下一次变更。
                let _ = ensure_built(&job.build, &job.app, &job.docroot);
            }
        });
    if spawned.is_err() {
        // 线程起不来不是致命错误：请求路径仍按需编译（只是没有后台热编译）。
        WATCH_STARTED.store(false, Ordering::SeqCst);
        log::warn!("tsx: watch 线程创建失败，退化为按需编译");
    }
}

// ---------------------------------------------------------------------------
// 路径解析与源扫描
// ---------------------------------------------------------------------------

/// `source_dir` / `out_dir`：缺省用调用方给的默认值；相对路径先按进程 CWD 解析
/// （`--config config.toml` 的常规姿势），CWD 下没有再看「默认目录的父目录」
/// （docroot 是绝对的，配置里写 `source_dir = "src"` 常指 docroot/src 或 docroot 的
/// 兄弟目录）。config.rs 只对 docroot/lib/deps_dir 做基准归一化，这两个字段没有，
/// 所以这里必须自己兜住。
fn resolve_dir(opt: Option<&Path>, default: PathBuf) -> PathBuf {
    let Some(p) = opt else {
        return default;
    };
    if p.is_absolute() {
        return p.to_path_buf();
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cand = cwd.join(p);
    if cand.is_dir() {
        return cand;
    }
    if let Some(parent) = default.parent() {
        let alt = parent.join(p);
        if alt.is_dir() {
            return alt;
        }
    }
    cand
}

/// `.ts/.tsx/.mts/.cts`（跳过 `.d.ts` 之类的纯声明）。
fn is_ts_source_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".d.ts") || lower.ends_with(".d.mts") || lower.ends_with(".d.cts") {
        return false;
    }
    matches!(
        Path::new(&lower).extension().and_then(|e| e.to_str()),
        Some("ts") | Some("tsx") | Some("mts") | Some("cts")
    )
}

/// 收集源文件：`entry` 非空时只认显式入口；否则递归遍历（不跟随符号链接，
/// 跳过隐藏目录/node_modules/deps 与 out_dir 自身）。
fn collect_sources(
    source: &Path,
    out: &Path,
    entries: &[String],
) -> std::result::Result<Vec<SrcFile>, String> {
    if !source.is_dir() {
        return Err(format!("source_dir 不存在或不是目录: {}", source.display()));
    }
    let mut files: Vec<SrcFile> = Vec::new();

    if !entries.is_empty() {
        for e in entries {
            let rel = e.trim().trim_start_matches('/').to_string();
            if rel.is_empty() {
                continue;
            }
            if rel.contains('\\') || rel.split('/').any(|s| s.is_empty() || s == "." || s == "..")
            {
                return Err(format!("entry 路径非法: {e}"));
            }
            if !is_ts_source_name(&rel) {
                return Err(format!("entry 不是 TypeScript 源文件（.ts/.tsx）: {rel}"));
            }
            let p = source.join(&rel);
            let md = fs::metadata(&p).map_err(|err| format!("entry {} 不可用: {err}", p.display()))?;
            if !md.is_file() {
                return Err(format!("entry 不是普通文件: {}", p.display()));
            }
            files.push(SrcFile {
                rel,
                mtime: md.modified().unwrap_or(UNIX_EPOCH),
                len: md.len(),
            });
        }
        return Ok(files);
    }

    let out_canon = fs::canonicalize(out).ok();
    // (绝对目录, 相对 source 的路径, 深度)
    let mut stack: Vec<(PathBuf, String, u32)> =
        vec![(source.to_path_buf(), String::new(), 0)];
    while let Some((dir, rel, depth)) = stack.pop() {
        if depth > 32 {
            continue; // 防深目录/环（符号链接已跳过，这里是兜底）
        }
        let rd = fs::read_dir(&dir).map_err(|e| format!("读取目录 {} 失败: {e}", dir.display()))?;
        for ent in rd {
            let Ok(ent) = ent else { continue };
            let Ok(ft) = ent.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let name = ent.file_name().to_string_lossy().to_string();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if ft.is_dir() {
                if name.starts_with('.') || name == "node_modules" || name == "deps" {
                    continue;
                }
                let child_abs = ent.path();
                if let (Some(oc), Ok(cc)) = (&out_canon, fs::canonicalize(&child_abs)) {
                    if &cc == oc {
                        continue; // 产物目录不当源码再喂回编译器
                    }
                }
                stack.push((child_abs, child_rel, depth + 1));
            } else if ft.is_file() && is_ts_source_name(&name) {
                if files.len() >= MAX_SOURCES {
                    return Err(format!(
                        "TypeScript 源文件超过 {MAX_SOURCES} 个；请用 apps[].entry 指定入口"
                    ));
                }
                let md = ent
                    .metadata()
                    .map_err(|e| format!("stat {} 失败: {e}", ent.path().display()))?;
                files.push(SrcFile {
                    rel: child_rel,
                    mtime: md.modified().unwrap_or(UNIX_EPOCH),
                    len: md.len(),
                });
            }
        }
    }
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(files)
}

/// 「源集合 + mtime + 大小 + 工具 + out_dir」指纹。工具身份也进指纹：换成 esbuild
/// 或装上 npx 后同样触发重新编译。
fn signature(files: &[SrcFile], tool_label: &str, out: &Path) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tool_label.hash(&mut h);
    out.hash(&mut h);
    for f in files {
        f.rel.hash(&mut h);
        let nanos = f
            .mtime
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        nanos.hash(&mut h);
        f.len.hash(&mut h);
    }
    h.finish()
}

fn product_rel(rel: &str) -> String {
    let p = Path::new(rel);
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| rel.to_string());
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => {
            format!("{}/{stem}.js", d.to_string_lossy().replace('\\', "/"))
        }
        _ => format!("{stem}.js"),
    }
}

// ---------------------------------------------------------------------------
// 转译器探测（PATH → 应用内 node_modules/.bin → npx）
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ToolKind {
    Esbuild,
    Tsc,
    Swc,
}

#[derive(Clone, Debug)]
struct Tool {
    kind: ToolKind,
    /// 直接执行的文件（esbuild/tsc/swc 或 npx）。
    prog: PathBuf,
    /// 前置参数（npx 时是 `--yes esbuild` 之类）。
    pre: Vec<String>,
    /// 日志/指纹用的身份标签。
    label: String,
}

#[cfg(unix)]
fn is_exec(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.is_file()
        && fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_exec(p: &Path) -> bool {
    p.is_file()
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return is_exec(&p).then_some(p);
    }
    let path = std::path::PathBuf::from(
        crate::server::apps::env_lock::read_static_env("PATH")?,
    );
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let cand = dir.join(name);
        if is_exec(&cand) {
            return Some(cand);
        }
    }
    None
}

/// 探测顺序：PATH 上的 esbuild/tsc/swc → 应用/Docroot 内 `node_modules/.bin/` 的
/// 同名可执行 → npx（esbuild → tsc → swc；会按需下载，需要 node+npx）。
fn detect_tool(source: &Path, docroot: &Path) -> std::result::Result<Tool, String> {
    let bins = [
        ("esbuild", ToolKind::Esbuild),
        ("tsc", ToolKind::Tsc),
        ("swc", ToolKind::Swc),
    ];
    for (name, kind) in bins {
        if let Some(p) = find_in_path(name) {
            return Ok(Tool {
                kind,
                label: format!("{name} ({})", p.display()),
                prog: p,
                pre: Vec::new(),
            });
        }
    }
    let local_dirs = [
        source.join("node_modules").join(".bin"),
        docroot.join("node_modules").join(".bin"),
        // deps/ 是**本项目的标准依赖目录**（init.sh + .env → deps/，见 §7.9）：
        // `npm install --prefix deps esbuild` 会把可执行文件放在这里。
        // 不列它的话「按文档装到 deps」反而探测不到，只能落回 npx（见下）。
        docroot.join("deps").join("node_modules").join(".bin"),
        source.join("deps").join("node_modules").join(".bin"),
    ];
    for (name, kind) in bins {
        for d in &local_dirs {
            let p = d.join(name);
            if is_exec(&p) {
                return Ok(Tool {
                    kind,
                    label: format!("{name} ({})", p.display()),
                    prog: p,
                    pre: Vec::new(),
                });
            }
        }
    }
    // npx 兜底**默认关闭**：`npx --yes esbuild` 在本地没装时会**联网下载**包，
    // 而这条路径在请求路径上 —— 慢网/被墙时一个 /tsx/ 请求会挂到编译超时（实测 120s），
    // 期间客户端只能干等，还会占住并发额度。要允许联网兜底需显式设
    // `CRUCIBLE_TSX_ALLOW_NPX=1`。默认行为：快速失败 + 明确告诉运维怎么装。
    let allow_npx = crate::server::apps::env_lock::read_static_env("CRUCIBLE_TSX_ALLOW_NPX")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false);
    if allow_npx {
        if let Some(npx) = find_in_path("npx") {
            for (name, kind) in bins {
                let (pre, label): (Vec<String>, String) = if name == "swc" {
                    (
                        vec!["--yes".into(), "--package".into(), "@swc/cli".into(), "swc".into()],
                        "npx @swc/cli swc".into(),
                    )
                } else {
                    (vec!["--yes".into(), name.to_string()], format!("npx {name}"))
                };
                // npx 的 shebang 是 `#!/usr/bin/env node`：找不到 node 就没法用这条。
                if find_in_path("node").is_some() {
                    return Ok(Tool {
                        kind,
                        prog: npx.clone(),
                        pre,
                        label,
                    });
                }
            }
        }
    }
    Err(
        "未找到 TypeScript 转译器（已试 esbuild/tsc/swc 的 PATH、应用/deps 的 \
         node_modules/.bin；npx 联网兜底默认关闭）。请任选其一：\
         ① `pkg_add -I node` 后 `npm install -g esbuild`（全局，推荐）；\
         ② `npm install --prefix <docroot>/deps esbuild`（走 deps/ 机制）；\
         ③ 设 CRUCIBLE_TSX_ALLOW_NPX=1 允许 npx 联网下载（不推荐，慢网会挂很久）。"
            .into(),
    )
}

// ---------------------------------------------------------------------------
// 编译执行（argv 直启，无 shell；超时 kill；输出并发读走防管道死锁）
// ---------------------------------------------------------------------------

impl Tool {
    /// 一次构建的 argv（不含 `pre`）。esbuild/tsc 一次吃全部入口；swc 单文件调用
    /// （见 [`run_tool`]）。
    fn args(&self, files: &[SrcFile], source: &Path, out: &Path, bundle: bool) -> Vec<OsString> {
        let mut v: Vec<OsString> = Vec::new();
        match self.kind {
            ToolKind::Esbuild => {
                // ⚠️ esbuild 的 CLI 只接受 `--flag=value`（等号形式）：`--outdir <dir>`
                // 会被判成 `Invalid build flag: "--outdir"` 直接退出 1（实测）。
                // 早期版本容忍空格形式，0.28 起不再容忍 —— 这里一律用等号。
                for f in files {
                    v.push(source.join(&f.rel).into_os_string());
                }
                v.push(OsString::from(format!("--outdir={}", out.display())));
                v.push(OsString::from(format!("--outbase={}", source.display())));
                // classic JSX：产物里是 React.createElement(...)，不引入对
                // react/jsx-runtime 的隐式依赖（`--jsx=automatic` 需要装了 react
                // 才能解析模块）。
                v.push(OsString::from("--jsx=transform"));
                v.push(OsString::from("--format=esm"));
                v.push(OsString::from("--target=es2020"));
                v.push(OsString::from("--log-level=warning"));
                if bundle {
                    v.push(OsString::from("--bundle"));
                }
            }
            ToolKind::Tsc => {
                for f in files {
                    v.push(source.join(&f.rel).into_os_string());
                }
                v.push(OsString::from("--outDir"));
                v.push(out.into());
                v.push(OsString::from("--rootDir"));
                v.push(source.into());
                v.push(OsString::from("--jsx"));
                v.push(OsString::from("react"));
                v.push(OsString::from("--target"));
                v.push(OsString::from("es2020"));
                v.push(OsString::from("--module"));
                v.push(OsString::from("esnext"));
                v.push(OsString::from("--skipLibCheck"));
                v.push(OsString::from("--pretty"));
                v.push(OsString::from("false"));
            }
            ToolKind::Swc => {
                // 单文件调用：`swc <file> -o <out.js> --config-file <cfg>`，
                // 路径映射显式给出，不依赖 @swc/cli 的多入口目录语义。
                debug_assert_eq!(files.len(), 1);
                let f = &files[0];
                v.push(source.join(&f.rel).into_os_string());
                v.push(OsString::from("-o"));
                v.push(out.join(product_rel(&f.rel)).into());
                // 同 esbuild：长选项一律等号形式（@swc/cli 基于 clap，`--k v` 也认，
                // 但统一写法避免再来一次「某个 CLI 版本不认空格」）。
                v.push(OsString::from(format!(
                    "--config-file={}",
                    out.join(SWC_CFG_NAME).display()
                )));
            }
        }
        v
    }
}

const SWC_CFG_NAME: &str = ".tsx-swcrc";
const SWC_CFG_JSON: &str = "{\n  \"jsc\": {\n    \"parser\": { \"syntax\": \"typescript\", \"tsx\": true },\n    \"target\": \"es2020\"\n  },\n  \"module\": { \"type\": \"es6\" },\n  \"sourceMaps\": false\n}\n";

/// 读走子进程的一路输出（stdout/stderr 通用）：读空管道并保留前 `MAX_CAPTURE`
/// 字节；超出部分照读丢弃，避免管道写满把子进程卡死。
fn read_capped<R: Read>(r: &mut Option<R>) -> String {
    let Some(r) = r.as_mut() else {
        return String::new();
    };
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk) {
            // **EOF（read 返回 0）必须 break**：父进程关闭写端后，pipe 上的 read 会
            // 永远立刻返回 0 —— 不退出就是 100% CPU 的忙等（实测 ktrace：4 秒内
            // 189k 次 read(...,0x2000)->0），而 spawn_tool 里的 `t_out.join()`
            // 永远不会返回 ⇒ 一个 /tsx/ 请求挂死到客户端超时、编译结果永远拿不到。
            Ok(0) => break,
            // 超出上限后仍然继续读（排空管道），只是不保留。
            Ok(n) if buf.len() < MAX_CAPTURE => {
                let take = (MAX_CAPTURE - buf.len()).min(n);
                buf.extend_from_slice(&chunk[..take]);
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// 跑一次编译器：argv 直启、stdout/stderr 并发读走、超时 kill。
fn spawn_tool(tool: &Tool, args: &[OsString], cwd: &Path) -> std::result::Result<(), String> {
    let mut cmd = Command::new(&tool.prog);
    // 干净环境：编译器在**请求路径**上被拉起，而进程 env 里可能正装着别的应用的请求期
    // `.env`（env_lock 窗口）。默认继承会把别人的密钥带进构建工具（以及它可能写出的
    // 缓存/产物）。基底（PATH/HOME 等运维环境）照旧。
    crate::server::apps::env_lock::apply_clean_env(&mut cmd, &[]);
    cmd.args(&tool.pre)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("启动 {} 失败: {e}", tool.label))?;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let t_out = std::thread::spawn(move || read_capped(&mut stdout));
    let t_err = std::thread::spawn(move || read_capped(&mut stderr));

    let deadline = Instant::now() + COMPILE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = t_out.join();
                let _ = t_err.join();
                return Err(format!("等待 {} 失败: {e}", tool.label));
            }
        }
    };
    let out_s = t_out.join().unwrap_or_default();
    let err_s = t_err.join().unwrap_or_default();
    let Some(st) = status else {
        return Err(format!(
            "编译超时（{}s），已 kill: {}",
            COMPILE_TIMEOUT.as_secs(),
            tool.label
        ));
    };
    if !st.success() {
        let detail = if !err_s.trim().is_empty() { err_s } else { out_s };
        return Err(format!(
            "{} 退出码 {:?}:\n{}",
            tool.label,
            st.code(),
            detail.trim()
        ));
    }
    if !err_s.trim().is_empty() {
        // 成功但有告警：留痕但不影响部署。
        log::debug!("tsx: {} 告警: {}", tool.label, err_s.trim());
    }
    Ok(())
}

fn run_tool(
    tool: &Tool,
    files: &[SrcFile],
    source: &Path,
    out: &Path,
) -> std::result::Result<(), String> {
    // 有 node_modules 才 bundle：能解析裸包名（react 等）；没有 node_modules 时
    // 保持不打包（相对导入照原样保留，绝不因为缺依赖把整个构建弄失败）。
    let bundle = source.join("node_modules").is_dir();
    match tool.kind {
        ToolKind::Swc => {
            fs::write(out.join(SWC_CFG_NAME), SWC_CFG_JSON)
                .map_err(|e| format!("写 swc 配置失败: {e}"))?;
            for f in files {
                let one = std::slice::from_ref(f);
                let args = tool.args(one, source, out, bundle);
                spawn_tool(tool, &args, source)?;
            }
            Ok(())
        }
        _ => {
            let args = tool.args(files, source, out, bundle);
            spawn_tool(tool, &args, source)
        }
    }
}

// ---------------------------------------------------------------------------
// 编译主流程
// ---------------------------------------------------------------------------

fn truncate_for_status(s: &str) -> String {
    const CAP: usize = 2000;
    if s.chars().count() <= CAP {
        return s.to_string();
    }
    let head: String = s.chars().take(CAP).collect();
    format!("{head}…（截断）")
}

/// 确保产物是最新的：
///   1. 快速路径（750ms 内检查过）→ 复用结论；
///   2. 扫描 source_dir → 算指纹 → 指纹没变 → 复用结论；
///   3. 否则跑一次真实编译，按结果写缓存/状态/日志。
fn ensure_built(
    state: &AppBuild,
    app: &AppRouteConfig,
    docroot: &Path,
) -> std::result::Result<Paths, BuildErr> {
    if let Some(c) = fresh_cached(state) {
        return c.result();
    }
    let _gate = state.gate.lock();
    if let Some(c) = fresh_cached(state) {
        return c.result();
    }

    let source = resolve_dir(app.source_dir.as_deref(), docroot.to_path_buf());
    let out = resolve_dir(app.out_dir.as_deref(), docroot.join("dist"));
    let paths = Paths {
        source: source.clone(),
        out: out.clone(),
    };
    state.set_status(|st| {
        st.source_dir = source.display().to_string();
        st.out_dir = out.display().to_string();
        st.watch = app.watch;
    });

    let files = match collect_sources(&source, &out, &app.entry) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!(
                "源目录不可用: {e}（source_dir={}）",
                source.display()
            );
            state.set_cached(None); // 目录状态可能随时变，不做指纹缓存
            state.set_status(|st| {
                st.state = "error".into();
                st.last_error = Some(truncate_for_status(&msg));
            });
            crate::server::log_throttle::warn_every(
                &format!("tsx-src-{}", state.key),
                Duration::from_secs(60),
                &format!("tsx [{}] {msg}", state.key),
            );
            return Err(BuildErr::Failed(msg));
        }
    };
    if files.is_empty() {
        let msg = format!(
            "没有找到任何 .ts/.tsx 源文件（source_dir={}，可用 apps[].entry 指定入口）",
            source.display()
        );
        state.set_cached(None);
        state.set_status(|st| {
            st.state = "error".into();
            st.last_error = Some(truncate_for_status(&msg));
        });
        crate::server::log_throttle::warn_every(
            &format!("tsx-empty-{}", state.key),
            Duration::from_secs(60),
            &format!("tsx [{}] {msg}", state.key),
        );
        return Err(BuildErr::Failed(msg));
    }

    let tool = match detect_tool(&source, docroot) {
        Ok(t) => t,
        Err(msg) => {
            // 缺工具：指纹仍然记录（重探由 750ms 快速路径过期后发生），日志节流，
            // 客户端拿固定 502 + 安装提示。
            state.set_cached(Some(Cached::Err {
                sig: signature(&files, "none", &out),
                msg: msg.clone(),
                no_tool: true,
            }));
            state.set_status(|st| {
                st.state = "error".into();
                st.tool = "none".into();
                st.last_error = Some(truncate_for_status(&msg));
            });
            crate::server::log_throttle::warn_every(
                &format!("tsx-notool-{}", state.key),
                Duration::from_secs(60),
                &format!("tsx [{}] {msg}", state.key),
            );
            return Err(BuildErr::NoTool(msg));
        }
    };
    state.set_status(|st| st.tool = tool.label.clone());

    let sig = signature(&files, &tool.label, &out);
    // 注意先把 guard 里的结论 clone 出来再放锁：set_cached 会再拿同一把锁
    // （parking_lot 不可重入），在 if let 的临时 guard 里调用会直接死锁。
    let cached_now = state.cache.lock().entry.clone();
    if let Some(c) = cached_now {
        if c.sig() == sig {
            state.set_cached(Some(c.clone())); // 只刷新 checked
            return c.result();
        }
    }

    if let Err(e) = fs::create_dir_all(&out) {
        let msg = format!("创建 out_dir {} 失败: {e}", out.display());
        state.set_status(|st| {
            st.state = "error".into();
            st.last_error = Some(truncate_for_status(&msg));
        });
        crate::server::log_throttle::warn_every(
            &format!("tsx-io-{}", state.key),
            Duration::from_secs(60),
            &format!("tsx [{}] {msg}", state.key),
        );
        return Err(BuildErr::Failed(msg));
    }

    state.set_status(|st| st.state = "building".into());
    let started = Instant::now();
    match run_tool(&tool, &files, &source, &out) {
        Ok(()) => {
            // 产物验证：退出码 0 但文件缺失（e.g. tsc 因 noEmit 配置）也算失败，
            // 免得把「编译成功」的假象带给运维。
            for f in &files {
                let p = out.join(product_rel(&f.rel));
                if !p.is_file() {
                    let msg = format!(
                        "{} 报告成功但产物缺失: {}（源 {}）",
                        tool.label,
                        p.display(),
                        f.rel
                    );
                    state.set_cached(Some(Cached::Err {
                        sig,
                        msg: msg.clone(),
                        no_tool: false,
                    }));
                    state.set_status(|st| {
                        st.state = "error".into();
                        st.last_error = Some(truncate_for_status(&msg));
                    });
                    log::error!("tsx [{}] {msg}", state.key);
                    return Err(BuildErr::Failed(msg));
                }
            }
            let took = started.elapsed();
            state.set_cached(Some(Cached::Ok {
                sig,
                paths: paths.clone(),
            }));
            state.set_status(|st| {
                st.state = "ok".into();
                st.files = files.len();
                st.last_build_unix_ms = unix_ms();
                st.last_error = None;
            });
            log::info!(
                "tsx [{}] 编译成功: {} 个源文件 → {}（{}，{:.0}ms）",
                state.key,
                files.len(),
                out.display(),
                tool.label,
                took.as_secs_f64() * 1000.0
            );
            Ok(paths)
        }
        Err(e) => {
            let msg = format!(
                "编译失败（source_dir={}，out_dir={}，{}）: {e}",
                source.display(),
                out.display(),
                tool.label
            );
            // 同一指纹只编一次、只记一次日志（编辑后指纹变化会自然重试/重记）。
            state.set_cached(Some(Cached::Err {
                sig,
                msg: msg.clone(),
                no_tool: false,
            }));
            state.set_status(|st| {
                st.state = "error".into();
                st.last_error = Some(truncate_for_status(&msg));
            });
            log::error!("tsx [{}] {msg}", state.key);
            Err(BuildErr::Failed(msg))
        }
    }
}

// ---------------------------------------------------------------------------
// 请求 → 产物映射与响应
// ---------------------------------------------------------------------------

/// 剥掉命中的 app 前缀，返回**未做 index 替换**的剩余路径（`""`/以 `/` 结尾 =
/// 目录请求）。与 apps::match_app 的前缀语义一致（整体边界 + 尾斜杠归一化）。
fn app_remainder<'a>(app: &AppRouteConfig, path: &'a str) -> &'a str {
    for prefix in &app.paths {
        let p = prefix.trim_end_matches('/');
        if p.is_empty() {
            continue;
        }
        if path == p {
            return "";
        }
        if let Some(rest) = path.strip_prefix(&format!("{p}/")) {
            return rest;
        }
    }
    path.trim_start_matches('/')
}

/// 请求剩余路径 → 候选产物相对路径（按优先级）。
fn product_candidates(app: &AppRouteConfig, rest: &str) -> Vec<String> {
    let index = app
        .index
        .clone()
        .unwrap_or_else(|| "index.tsx".to_string());
    let dir = rest.is_empty() || rest.ends_with('/');
    let base = if dir {
        format!("{rest}{index}")
    } else {
        rest.to_string()
    };
    let mut v: Vec<String> = Vec::new();
    let ext = Path::new(&base)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        // 源扩展名 → 同名 .js 产物（源码字节绝不外发）。
        Some("ts") | Some("tsx") | Some("mts") | Some("cts") => v.push(product_rel(&base)),
        Some(_) => {
            // 已带产物扩展名（js/css/json/html/svg…）：原样查找。
            v.push(base.clone());
        }
        None => {
            if !base.is_empty() {
                // 无扩展名：先按产物基名（foo → foo.js），再原样（可能是无扩展文件）。
                v.push(format!("{base}.js"));
                if !dir {
                    v.push(base.clone());
                }
            }
        }
    }
    if dir {
        // 目录请求的打包产物兜底（如 dist/index.html）。
        v.push(format!("{rest}index.html"));
    }
    v
}

/// `rel` 安全拼进 `root`：拒绝 `..`/反斜杠/NUL，canonicalize 后再确认仍在 root 内
/// （防符号链接逃逸）。文件不存在（canonicalize 失败）返回 None。
fn join_under(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.contains('\0') {
        return None;
    }
    let mut p = root.to_path_buf();
    for seg in rel.trim_start_matches('/').split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains('\\') {
            return None;
        }
        p.push(seg);
    }
    let canon_root = fs::canonicalize(root).ok()?;
    let canon = fs::canonicalize(&p).ok()?;
    if !canon.starts_with(&canon_root) {
        return None;
    }
    Some(canon)
}

fn content_type_of(p: &Path) -> String {
    let m = mime_guess::from_path(p).first_or_octet_stream();
    let s = m.essence_str().to_string();
    if s.starts_with("text/") && !s.contains("charset") {
        format!("{s}; charset=utf-8")
    } else {
        s
    }
}

fn plain(status: StatusCode, body: &'static str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(body))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full("response build error"))
                .unwrap()
        })
}

/// 字节版固定文本响应（h2/h3 简单路径用；body 是 `Bytes`）。
fn plain_bytes(status: StatusCode, body: &'static str) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Bytes::from_static(body.as_bytes()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Bytes::from_static(b"response build error"))
                .unwrap()
        })
}

fn build_error_response(e: &BuildErr) -> Response<BoxBody> {
    // 固定文本：不含服务器路径/编译器 stderr（那些只进日志与 status_json）。
    match e {
        BuildErr::NoTool(_) => plain(
            StatusCode::BAD_GATEWAY,
            "502 Bad Gateway: tsx: no TypeScript transpiler found (install node + esbuild/tsc; see server log)\n",
        ),
        BuildErr::Failed(_) => plain(
            StatusCode::BAD_GATEWAY,
            "502 Bad Gateway: tsx build failed (see server log)\n",
        ),
    }
}

fn build_error_response_bytes(e: &BuildErr) -> Response<Bytes> {
    match e {
        BuildErr::NoTool(_) => plain_bytes(
            StatusCode::BAD_GATEWAY,
            "502 Bad Gateway: tsx: no TypeScript transpiler found (install node + esbuild/tsc; see server log)\n",
        ),
        BuildErr::Failed(_) => plain_bytes(
            StatusCode::BAD_GATEWAY,
            "502 Bad Gateway: tsx build failed (see server log)\n",
        ),
    }
}

/// 产物托管核心（h1/h2/h3 共用）：只依赖请求的 **path + method**，因此对
/// `Request<Incoming>`（h1）与 `Request<Bytes>`（h2/h3）都能复用。
///
/// 为什么必须共用：此前只有 h1 走这条编译管线，h2/h3 的 `dispatch_simple` 把 tsx 送到
/// `sidecar_engine` → `libapp_tsx.so`；那个 .so 只按产物目录回文件、**忽略请求路径**，
/// 于是 `/tsx/<不存在的源>` 在 h1 是 404、在 h2 却回 `dist/index.js`（内容伪装/软 404）——
/// 同一个 URL 在两个协议版本上给出不同资源。
fn serve_product_bytes(
    path: &str,
    method: &Method,
    app: &AppRouteConfig,
    paths: &Paths,
) -> Response<Bytes> {
    let rest_raw = app_remainder(app, path);
    // URL 里可能是 %20/%E4%B8%AD 这类转义；先解码再按段校验（`%2e%2e` 解出 `..`
    // 会被 join_under 拒绝）。
    let rest = percent_encoding::percent_decode_str(rest_raw)
        .decode_utf8_lossy()
        .into_owned();
    for cand in product_candidates(app, &rest) {
        let Some(p) = join_under(&paths.out, &cand) else {
            continue;
        };
        let Ok(md) = fs::metadata(&p) else { continue };
        if !md.is_file() {
            continue;
        }
        if md.len() > MAX_PRODUCT_BYTES {
            crate::server::log_throttle::warn_every(
                &format!("tsx-big-{}", paths.out.display()),
                Duration::from_secs(60),
                &format!("tsx: 产物过大，拒绝服务: {} ({} 字节)", p.display(), md.len()),
            );
            return plain_bytes(StatusCode::PAYLOAD_TOO_LARGE, "413 Payload Too Large\n");
        }
        let bytes = match fs::read(&p) {
            Ok(b) => b,
            Err(e) => {
                crate::server::log_throttle::warn_every(
                    &format!("tsx-read-{}", paths.out.display()),
                    Duration::from_secs(60),
                    &format!("tsx: 读产物失败 {}: {e}", p.display()),
                );
                return plain_bytes(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "500 Internal Server Error (tsx product read)\n",
                );
            }
        };
        let body = if *method == Method::HEAD {
            Bytes::new()
        } else {
            Bytes::from(bytes)
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type_of(&p))
            // watch 部署期间不要被中间层/浏览器缓存住旧产物。
            .header(header::CACHE_CONTROL, "no-cache")
            .header("x-content-type-options", "nosniff")
            .body(body)
            .unwrap_or_else(|_| {
                plain_bytes(StatusCode::INTERNAL_SERVER_ERROR, "response build error")
            });
    }
    plain_bytes(StatusCode::NOT_FOUND, "404 Not Found\n")
}

async fn serve_product(
    req: &Request<Incoming>,
    app: &AppRouteConfig,
    paths: &Paths,
) -> Result<Response<BoxBody>> {
    let r = serve_product_bytes(req.uri().path(), req.method(), app, paths);
    let (parts, body) = r.into_parts();
    Ok(Response::from_parts(parts, full(body)))
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

pub async fn handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
) -> Result<Response<BoxBody>> {
    // 1) 显式配置且**活着**的 socket：运维明确要把 TSX 交给常驻 node 侧车时，
    //    编译管线不抢占（未存活则落到下面的内置管线，而不是恒 502）。
    #[cfg(unix)]
    {
        let socket_configured = app
            .socket
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if socket_configured && native_http::uds_socket_available(app) {
            return native_http::try_handle_uds(req, app, peer).await;
        }
    }

    // 2) 编译管线产出静态产物：只服务 GET/HEAD。
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full("405 Method Not Allowed\n"))
            .unwrap());
    }

    let docroot = app.docroot.clone().unwrap_or_else(|| lc.root.clone());
    // 键含 docroot：配置热重载换了目录不会被旧状态串台。
    let key = format!(
        "{}:{}:{}:{}",
        lc.port,
        app_idx,
        app.engine.to_ascii_lowercase(),
        docroot.display()
    );
    let state = app_state(&key, lc.port, &app.engine);
    if app.watch {
        register_watch(&key, state.clone(), app, &docroot);
    }

    // 编译/扫描是阻塞工作（含 wait 子进程），放进 blocking 池，别占 tokio worker。
    let built = {
        let st = state.clone();
        let a = app.clone();
        let d = docroot.clone();
        tokio::task::spawn_blocking(move || ensure_built(&st, &a, &d)).await
    };
    match built {
        Ok(Ok(paths)) => serve_product(&req, app, &paths).await,
        Ok(Err(e)) => Ok(build_error_response(&e)),
        Err(join_err) => {
            // spawn_blocking 任务 panic（理论上不该发生）：同样只回固定文本。
            log::error!("tsx [{}] 编译任务异常退出: {join_err}", state.key);
            Ok(plain(
                StatusCode::BAD_GATEWAY,
                "502 Bad Gateway: tsx build task failed (see server log)\n",
            ))
        }
    }
}

/// h2/h3 字节入口：与 [`handle`] 同一编译管线 / 产物托管，只是请求体已在协议层收齐。
///
/// 修复版本间不一致：此前 h2/h3 的 tsx 被 `dispatch_simple` 送到 `libapp_tsx.so`
/// （忽略请求路径的 stub），`/tsx/<不存在的源>` 在 h1 是 404、在 h2 却回 `dist/index.js`
/// （内容伪装）。socket 分支与 h1 同判据（显式配置且存活的 socket 优先，编译管线不抢占）。
pub async fn handle_bytes(
    req: &Request<Bytes>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
) -> Result<Response<Bytes>> {
    // 1) 显式配置且**活着**的 socket：与 h1 `handle` 同判据。
    #[cfg(unix)]
    {
        let socket_configured = app
            .socket
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if socket_configured && native_http::uds_socket_available(app) {
            let sock = native_http::uds_socket_path(app)
                .ok_or_else(|| anyhow::anyhow!("apps[].socket missing"))?;
            let target = crate::server::apps::app_ffi::rel_script_path(app, req.uri().path());
            return crate::server::apps::sidecar_engine::proxy_uds_simple(
                req,
                &sock,
                peer,
                Some(target),
            )
            .await;
        }
    }
    let _ = peer;

    // 2) 编译管线产出静态产物：只服务 GET/HEAD。
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Bytes::from_static(b"405 Method Not Allowed\n"))
            .unwrap());
    }

    let docroot = app.docroot.clone().unwrap_or_else(|| lc.root.clone());
    // 键含 docroot：配置热重载换了目录不会被旧状态串台（与 h1 同一构造）。
    let key = format!(
        "{}:{}:{}:{}",
        lc.port,
        app_idx,
        app.engine.to_ascii_lowercase(),
        docroot.display()
    );
    let state = app_state(&key, lc.port, &app.engine);
    if app.watch {
        register_watch(&key, state.clone(), app, &docroot);
    }

    let built = {
        let st = state.clone();
        let a = app.clone();
        let d = docroot.clone();
        tokio::task::spawn_blocking(move || ensure_built(&st, &a, &d)).await
    };
    match built {
        Ok(Ok(paths)) => Ok(serve_product_bytes(req.uri().path(), req.method(), app, &paths)),
        Ok(Err(e)) => Ok(build_error_response_bytes(&e)),
        Err(join_err) => {
            log::error!("tsx [{}] 编译任务异常退出: {join_err}", state.key);
            Ok(plain_bytes(
                StatusCode::BAD_GATEWAY,
                "502 Bad Gateway: tsx build task failed (see server log)\n",
            ))
        }
    }
}

/// 面板/运维可见的引擎状态快照（JSON 数组）。admin.rs 目前没有 TSX 状态 API
/// （见跨文件需求），这里先提供数据源：admin 只需一行接线
/// `path.ends_with("/api/apps/tsx/status") => json_ok(tsx::status_json())`。
#[allow(dead_code)]
pub fn status_json() -> String {
    let states: Vec<Arc<AppBuild>> = APPS.lock().values().cloned().collect();
    let mut s = String::from("[");
    for (i, a) in states.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let st = a.status.lock().clone();
        match serde_json::to_string(&st) {
            Ok(j) => s.push_str(&j),
            Err(_) => s.push_str("{}"),
        }
    }
    s.push(']');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// esbuild 的 CLI 只认 `--flag=value`：空格形式会被判 `Invalid build flag` 直接
    /// 退出 1（实测 0.28.2）。这条回归测试钉死参数构造。
    #[test]
    fn esbuild_args_use_equals_form() {
        let tool = Tool {
            kind: ToolKind::Esbuild,
            label: "esbuild (test)".into(),
            prog: std::path::PathBuf::from("/usr/local/bin/esbuild"),
            pre: Vec::new(),
        };
        let files = vec![SrcFile {
            rel: "index.tsx".into(),
            mtime: SystemTime::UNIX_EPOCH,
            len: 1,
        }];
        let args = tool.args(
            &files,
            std::path::Path::new("/srv/app"),
            std::path::Path::new("/srv/app/dist"),
            false,
        );
        let strs: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for a in &strs {
            if a.starts_with("--") && a.len() > 2 {
                // 值型长选项必须带 `=`（`--bundle` 这类纯开关例外）
                if ["--outdir", "--outbase", "--jsx", "--format", "--target", "--log-level"]
                    .iter()
                    .any(|k| a == k)
                {
                    panic!("esbuild 长选项必须用等号形式，收到了空格形式: {a}");
                }
            }
        }
        assert!(strs.iter().any(|a| a == "--outdir=/srv/app/dist"));
        assert!(strs.iter().any(|a| a == "--outbase=/srv/app"));
        assert!(strs.iter().any(|a| a == "--jsx=transform"));
        assert!(strs.iter().any(|a| a == "--log-level=warning"));
        // 入口文件排在最前（esbuild 的 positional args）
        assert_eq!(strs[0], "/srv/app/index.tsx");
    }

    fn app(paths: &[&str], index: Option<&str>) -> AppRouteConfig {
        AppRouteConfig {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            enabled: true,
            engine: "tsx".into(),
            socket: None,
            extensions: vec!["tsx".into(), "ts".into(), "".into()],
            index: index.map(|s| s.to_string()),
            php_bin: None,
            workers: 4,
            source_dir: None,
            out_dir: None,
            entry: vec![],
            watch: false,
            docroot: Some(PathBuf::from("www-apps/tsx")),
            lib: None,
            deps_dir: None,
            init_timeout_secs: None,
            libc: None,
        }
    }

    #[test]
    fn remainder_strips_app_prefix() {
        let a = app(&["/tsx"], Some("index.tsx"));
        assert_eq!(app_remainder(&a, "/tsx"), "");
        assert_eq!(app_remainder(&a, "/tsx/"), "");
        assert_eq!(app_remainder(&a, "/tsx/a/b.tsx"), "a/b.tsx");
        // 边界不误伤（/tsxlint 不是 /tsx 的地盘；这里模拟 dispatch 已保证匹配）
        let a2 = app(&["/tsx/"], Some("index.tsx"));
        assert_eq!(app_remainder(&a2, "/tsx/x"), "x", "尾斜杠配置要归一化");
    }

    #[test]
    fn candidates_map_sources_to_js_and_never_serve_source() {
        let a = app(&["/tsx"], Some("index.tsx"));
        // 目录请求 → index.js
        assert_eq!(product_candidates(&a, ""), vec!["index.js", "index.html"]);
        // 源扩展名 → 同名 .js（不是源码本身）
        assert_eq!(product_candidates(&a, "foo.tsx"), vec!["foo.js"]);
        assert_eq!(product_candidates(&a, "sub/foo.ts"), vec!["sub/foo.js"]);
        // 无扩展名 → 先 .js 再原样
        assert_eq!(product_candidates(&a, "foo"), vec!["foo.js", "foo"]);
        // 产物扩展名原样
        assert_eq!(product_candidates(&a, "app.css"), vec!["app.css"]);
        // 子目录目录请求
        assert_eq!(
            product_candidates(&a, "sub/"),
            vec!["sub/index.js", "sub/index.html"]
        );
        // 自定义 index
        let b = app(&["/tsx"], Some("main.tsx"));
        assert_eq!(product_candidates(&b, ""), vec!["main.js", "index.html"]);
    }

    #[test]
    fn product_rel_replaces_extension() {
        assert_eq!(product_rel("index.tsx"), "index.js");
        assert_eq!(product_rel("a/b/c.ts"), "a/b/c.js");
        assert_eq!(product_rel("x.mts"), "x.js");
    }

    #[test]
    fn source_name_filter() {
        assert!(is_ts_source_name("a.ts"));
        assert!(is_ts_source_name("a.TSX"));
        assert!(!is_ts_source_name("a.d.ts"), "纯声明不产 JS");
        assert!(!is_ts_source_name("a.js"));
        assert!(!is_ts_source_name("a.ts.map"));
    }

    #[test]
    fn join_under_rejects_traversal_and_escapes() {
        let root = std::env::temp_dir().join("crucible_tsx_join_test");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/ok.js"), b"ok").unwrap();
        assert!(join_under(&root, "sub/ok.js").is_some());
        // 含 `..` 一律拒绝（fail-closed；不依赖 canonicalize 的归一化来兜）。
        assert!(join_under(&root, "sub/../sub/ok.js").is_none());
        assert!(join_under(&root, "../etc/passwd").is_none());
        assert!(join_under(&root, "sub/../../etc/passwd").is_none());
        assert!(join_under(&root, "sub\\..\\x").is_none());
        assert!(join_under(&root, "sub/\0x").is_none());
        assert!(join_under(&root, "missing.js").is_none(), "不存在的文件不给路径");
        #[cfg(unix)]
        {
            // 符号链接逃逸：root/link → /etc/passwd 必须被 canonical 校验拒绝。
            let _ = std::os::unix::fs::symlink("/etc/passwd", root.join("link"));
            assert!(join_under(&root, "link").is_none());
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn signature_changes_with_content_and_tool() {
        let t0 = UNIX_EPOCH + Duration::from_secs(100);
        let f1 = SrcFile {
            rel: "a.tsx".into(),
            mtime: t0,
            len: 10,
        };
        let f2 = SrcFile {
            rel: "a.tsx".into(),
            mtime: t0,
            len: 11,
        };
        let out = PathBuf::from("/tmp/out");
        let s1 = signature(std::slice::from_ref(&f1), "esbuild", &out);
        let s2 = signature(std::slice::from_ref(&f2), "esbuild", &out);
        let s3 = signature(std::slice::from_ref(&f1), "tsc", &out);
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
    }
}
