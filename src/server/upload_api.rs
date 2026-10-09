//! 上传端点（规格 §44）：`PUT/PATCH/POST` + `Content-Range` 断点续传。
//!
//! 设计要点（与 WORKLOG §18.2 一致）：
//! * **只在**该路径 `autoindex.enabled && enable_upload` 且路径前缀匹配时接管（其余方法仍 405）；
//! * 路径安全：`admin_files::safe_join` 做 containment（拒 `..`/绝对路径/反斜杠），
//!   再加一道**扩展名闸门**——`would_execute` 类扩展名默认拒收（§44「不得有 webshell」）；
//! * 落盘：`upload_resume` 的同目录临时文件 + 原子 rename；未收齐回 **202 + `X-Upload-Offset`**，
//!   偏移不符回 **409 + `X-Upload-Offset`**（客户端据此续传）；
//! * 鉴权/限速/ACL 由调用方（h1/h2/h3 的 dispatcher）在此之前完成 —— 本模块只管落盘语义。

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use std::sync::Arc;
use once_cell::sync::Lazy;
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::h1::{full, BoxBody};
use super::upload_resume::{self, UploadErr, MAX_UPLOAD_BYTES};

/// 两帧请求体之间的**空闲**上限：超过即 408 并放弃本次请求。
///
/// 为什么必须有：`upload_gate` 的 permit 覆盖整段 body 读取（默认 4 个），而 hyper 的
/// `header_read_timeout` 只覆盖请求头。匿名客户端发合法头 + `Content-Length: 100000000`
/// 后每帧只发 1 字节，就能用 4 条连接把该端口的**所有**上传永久打成 503（属 slowloris 的
/// 上传变体）。60s 与 nginx `client_body_timeout` 默认值同量级，不影响正常客户端。
const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// 速率下限的宽限期：刚开始的几十秒不判速率（TCP 慢启动、首帧延迟）。
const UPLOAD_RATE_GRACE: Duration = Duration::from_secs(60);
/// 宽限期之后要求的最低平均速率（**只算本次请求**收到的字节）。
///
/// 空闲超时挡不住「每 59s 发 1 字节」：那种客户端永不过期。1KiB/s（≈8kbps）
/// 是非常宽松的下限（真实的大文件上传远高于它，含慢速移动网络），但足以让
/// 「几乎不发送数据却长期占住 permit」的客户端在宽限期后被 408。
/// 注意：**只释放 permit，不删已收数据** —— 断点续传是产品功能，
/// 被限速的客户端稍后仍可按 `X-Upload-Offset` 接着传。
const UPLOAD_MIN_BYTES_PER_SEC: u64 = 1024;

/// 默认拒收的可执行/可解析扩展名（webshell 面）。想上传这些必须改配置或先改名。
const EXEC_EXTS: &[&str] = &[
    "php", "php3", "php4", "php5", "php7", "phtml", "phar", "jsp", "jspx", "jspf", "asp",
    "aspx", "ashx", "asmx", "cgi", "fcgi", "pl", "pm", "py", "rb", "lua", "sh", "bash", "zsh",
    "ksh", "so", "dll", "exe", "com", "bat", "cmd", "ps1", "jar", "war", "class", "tsx", "js",
    "mjs", "cjs", "html", "htm", "xhtml", "svg", "xml", "xsl", "xslt",
    // 第二组不是「服务端会执行」，而是**浏览器会执行**：static 层用 `mime_guess` 定
    // Content-Type，而这些扩展名被它映射成 `text/html` / `application/xhtml+xml` /
    // `image/svg+xml`（Auto 模式**不带 nosniff**）——上传一个 `.shtml` 就等于在同源上放
    // 了一个 XSS payload，而同一 listener 还挂着 `/__admin`：管理员一点开，脚本就能用
    // 浏览器自带的 Basic 凭据去调管理 API。第一组里的 html/svg/xml 早拒了，这里补齐同类。
    "shtml", "shtm", "stm", "xht", "svgz", "mhtml", "mht", "hta", "htc", "appcache", "vtt",
];

/// 每监听端口的「并发上传」闸门。
///
/// 为什么要有：`autoindex.upload_threads` 以前是**死配置**（面板能改、写进 config、运行时
/// 无人读）—— 而上传会真的落盘，并发数直接决定磁盘写入压力与 fd 占用。这里把它变成真闸门：
/// 尺寸取自该 listener 的 `upload_threads`（clamp 1..=16），`try_acquire` 拿不到就回 503 +
/// `Retry-After`，让客户端稍后重试而不是排队把连接堆起来。
///
/// 配置热重载改了 `upload_threads` 时：尺寸不一致就**换一个新的 Semaphore**（旧的在飞请求
/// 继续持有旧 permit，退出后自然释放）。
static UPLOAD_GATES: Lazy<parking_lot::Mutex<std::collections::HashMap<u16, (std::sync::Arc<tokio::sync::Semaphore>, u16)>>> =
    Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

fn upload_gate(port: u16, threads: u16) -> std::sync::Arc<tokio::sync::Semaphore> {
    let want = threads.clamp(1, 16);
    let mut m = UPLOAD_GATES.lock();
    match m.get(&port) {
        Some((sem, size)) if *size == want => sem.clone(),
        _ => {
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(want as usize));
            m.insert(port, (sem.clone(), want));
            sem
        }
    }
}

/// 扩展名闸门。
///
/// **必须取「最后一个非空、且不是 `.` 的段」**：落盘路径会经过 `safe_join` 的 Path 归一化，
/// 而旧实现只看原始路径的最后一个段 —— 于是
/// `PUT /up/shell.php/`、`/up/shell.php/.`、`/up/shell.php//` 都让 name 变成空串，
/// 扩展名判成「没有」，闸门放行，而文件实际写到 `<root>/up/shell.php` ⇒ **webshell 落盘**
/// （同一条路径随后由引擎执行）。这是审计报的 P0，实测可复现。
///
/// Windows 追加：Win32 **会剥掉**文件名的尾随 `.` 与空格，于是 `shell.php.` / `shell.php `
/// 落盘后就是 `shell.php` —— 闸门必须按剥掉后的名字判（不改判据的话，这两个名字
/// 在 Windows 上直接是 webshell 通道）。Unix 上尾随点是合法且不可执行的独立名字，
/// 故只在 Windows 上收紧，避免误伤运营方的正常上传。
fn has_exec_ext(path: &str) -> bool {
    let name = path
        .rsplit('/')
        .find(|s| !s.is_empty() && *s != ".")
        .unwrap_or("");
    #[cfg(windows)]
    let name = name.trim_end_matches(['.', ' ']);
    match name.rsplit_once('.') {
        Some((_, ext)) => EXEC_EXTS.iter().any(|e| e.eq_ignore_ascii_case(ext)),
        None => false,
    }
}

/// 返回第一个「以 `.` 开头」的路径段（已被 percent-decode、去空段）。`None` = 没有隐藏段。
///
/// `.well-known`（ACME http-01 验证目录）是唯一例外：那里的内容是公开的校验串。
fn hidden_segment(decoded_path: &str) -> Option<String> {
    for seg in decoded_path.split(['/', '\\']) {
        if seg.is_empty() || seg == "." || !seg.starts_with('.') {
            continue;
        }
        // 唯一例外：ACME http-01 的校验目录（其内容是公开串）
        if seg.eq_ignore_ascii_case(".well-known") {
            continue;
        }
        return Some(seg.to_string());
    }
    None
}

/// 取「这条连接对应的**当前**生效配置」。
///
/// 为什么不能只用 `listener_by_port`：同端口不同地址的两个 listener（`127.0.0.1:8080`
/// 与 `10.0.0.1:8080`，§16.1 允许且各自有独立 root）里，`listener_by_port` 返回**第一个**，
/// 于是 B 站上的上传会把文件写进 **A 站的 root**（跨站写入），并沿用 A 站的
/// `enable_upload`/`paths` 策略。连接分发（`listener::listener_matches_local`）是地址感知的，
/// 上传是唯一的写盘面，必须与它一致。
///
/// 判据用连接的 `lc` 的 **bind_key**（address|address_v6|port）在当前配置里找同一条 listener：
/// * 命中 → 用它（地址身份保持一致，跨站写入消失）；
/// * 未命中（热重载刚改过该 listener 的 address）→ 回退 `listener_by_port`（与旧行为一致，
///   不会因为找不到而整个关掉上传）。
fn listener_for_conn(
    live: &Arc<LiveConfig>,
    lc: &ListenerConfig,
) -> Option<crate::config::ListenerConfig> {
    let key = crate::server::bind_key(lc);
    let found = {
        let cur = live.snapshot();
        cur.listeners
            .iter()
            .find(|l| crate::server::bind_key(l) == key)
            .cloned()
    };
    found.or_else(|| crate::server::live_config::listener_by_port(live, lc.port))
}

/// 该请求是否应交给上传处理（调用方在 ACL/限速/鉴权之后、静态分发之前问一次）。
pub fn enabled_for(live: &Arc<LiveConfig>, lc: &ListenerConfig, path: &str) -> bool {
    // 判据用**当前生效**的 listener 配置（连接期快照只作回退）：否则「面板里关掉上传」
    // 之后，已建立的长连接仍会被当成「开了上传」的端口。
    let cur = listener_for_conn(live, lc);
    let lc = cur.as_ref().unwrap_or(lc);
    let a = &lc.autoindex;
    if !a.enabled || !a.enable_upload {
        return false;
    }
    // paths 为空视为整站；否则必须**按路径边界**匹配 —— 与 `AutoindexConfig::allows` 同一套：
    // 旧实现用裸 `starts_with`，配置 `paths = ["/up"]` 会把 `/uploads/...`、`/upfoo/...`
    // 也算成上传目录，上传面比运营方以为的更宽。
    a.paths.is_empty()
        || a.paths.iter().any(|p| {
            let p = p.trim_end_matches('/');
            path == p || path.starts_with(&format!("{p}/"))
        })
}

fn resp(status: StatusCode, msg: &str, offset: Option<u64>) -> Response<BoxBody> {
    let mut b = Response::builder().status(status);
    if let Some(off) = offset {
        b = b.header("x-upload-offset", off.to_string());
    }
    b.header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(msg.to_string()))
        .unwrap_or_else(|_| Response::new(full("upload error".to_string())))
}

/// 取「最深的已存在祖先」canonicalize 后的路径，再把剩余**不存在**的段词法拼回。
///
/// 与 `admin_files::safe_join` 对「尚不存在目标」的处理同一策略：符号链接在 canonicalize
/// 处被解析，故拿到的是**真实**路径；不存在的段没有符号链接语义，词法拼接即真实路径。
fn canon_best_effort(p: &std::path::Path) -> PathBuf {
    let mut base = p.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while !base.exists() {
        match base.file_name() {
            Some(n) => {
                rest.push(n.to_os_string());
                match base.parent() {
                    Some(par) => base = par.to_path_buf(),
                    None => break,
                }
            }
            None => break,
        }
    }
    let mut c = std::fs::canonicalize(&base).unwrap_or(base);
    for seg in rest.iter().rev() {
        c.push(seg);
    }
    c
}

/// 上传目标是否落在**任何应用 docroot**（docroot 本身或其子路径）之内。
///
/// # 为什么必须拦（条件性 P0：上传 → RCE）
///
/// 应用 docroot 是**运行期目录**，里面有一批「非可执行扩展名、GET 也不会走引擎」的文件，
/// 扩展名闸门（`has_exec_ext`）与 `would_execute_on_get`（只看 GET 路由）都拦不住：
///   * `init.sh` —— `deps::ensure_app_deps` 在 mtime 变化时用 `sh` 执行它（**改它即 RCE**）；
///   * `deps/bin/index` —— `sidecar_engine` 把它当可执行 sidecar 二进制拉起（**RCE**）；
///   * `.env` —— `deps::parse_env_file` 把它注入引擎执行环境（**凭据注入/越权**）；
///   * `deps/**` —— 应用依赖产物，覆盖可影响后续执行。
/// 出厂配置默认不开上传故不可达；一旦运维开整站上传（规格要求上传可用），`PUT /rust/init.sh`
/// 就能覆盖它 → 下一次 `deps` 重跑 = 任意命令执行。这是**跨应用**的写面，必须按 docroot 拦。
///
/// 判据用 `canon_best_effort`（与 `safe_join` 落盘用的真实路径对齐）：`www-apps/up/link ->
/// www-apps/rust` 这种符号链接会被解析到真实 docroot 上，从而同样命中。
/// 正常上传目录（如 `/up/`，不在任何 app docroot 内）不受影响。
fn inside_any_app_docroot(lc: &ListenerConfig, target: &std::path::Path) -> Option<PathBuf> {
    for app in &lc.apps {
        // `enabled=false` **且**未显式配 docroot 的应用跳过：它当前不参与分发，且
        // `app_docroot` 会退化成 listener root —— 把 root 算成「应用 docroot」就等于
        // 把开了上传的端口上**所有**上传都回 403（等于关掉上传功能）。
        if !app.enabled && app.docroot.is_none() {
            continue;
        }
        // 显式配了 docroot 的应用**不管 enabled 与否**都算运行期目录：这些文件在应用
        // 被重新启用（或该 docroot 被别的配置指到时）会被执行/注入 —— `init.sh` 被 `sh`、
        // `deps/bin/index` 被 sidecar 拉起、`.env` 注入引擎环境。旧判据跳过 disabled 应用，
        // 实测 `PUT /dapp/deps/bin/index` → **201**（落盘成功）——一条「先上传、后启用」的
        // 定时 RCE。
        let dr = canon_best_effort(&crate::server::apps::deps::app_docroot(lc, app));
        // `Path::starts_with` 按**组件**比较：`/a/rusty` 不以 `/a/rust` 开头（不会误伤兄弟目录）。
        if target == dr || target.starts_with(&dr) {
            return Some(dr);
        }
    }
    None
}

/// 处理上传。body 泛型化以便 h1（Incoming）/h2/h3（Bytes）共用同一条路径。
pub async fn handle<B>(
    req: Request<B>,
    live: &Arc<LiveConfig>,
    lc: &ListenerConfig,
    peer: std::net::SocketAddr,
) -> Response<BoxBody>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::fmt::Display,
{
    // 闸门尺寸与落盘 root 都取**当前生效**的配置：`lc` 是建连快照，长连接下可能已经过期
    //（面板关上传 / 改 upload_threads / 改 root 都应当立刻生效，见文件头说明）。
    // 但**地址身份**必须保持（见 `listener_for_conn`）：否则同端口多地址部署会跨站写入。
    let lc_now = listener_for_conn(live, lc);
    let lc = lc_now.as_ref().unwrap_or(lc);
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    if !matches!(method, Method::PUT | Method::PATCH | Method::POST) {
        // RFC 9110 §15.5.6：405 **必须**带 Allow（静态层已修，这里此前漏了）。
        // 支持的写方法 = PUT/PATCH（POST 仍接受，但见下面的跨站闸门）。
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "PUT, PATCH")
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full("method not allowed"))
            .unwrap_or_else(|_| Response::new(full("method not allowed".to_string())));
    }
    // 跨站写闸门（CSRF）：POST 是浏览器 HTML 表单**唯一**能发出的写方法
    //（PUT/PATCH 需 CORS 预检），而本端点把 POST 直接当上传处理，body 原样落盘。
    // listener 若开了 basic_auth，浏览器会给跨站表单自动附上缓存凭据 ⇒ 攻击者页面
    // 可在站点 origin 下写文件。`Sec-Fetch-Site` 由浏览器写、脚本改不了，
    // 且天然放行 curl/运维脚本（它不带这个头）。与 admin 路径同一套判据。
    if method == Method::POST && crate::server::access::cross_site_blocked(req.headers()) {
        return resp(StatusCode::FORBIDDEN, "跨站写请求被拒绝", None);
    }
    // 并发闸门：拿不到本端口的许可就直接 503（不排队、不占 body 缓冲）。
    // permit 活到函数返回 —— 覆盖整段 body 读取与落盘。
    let _permit = match upload_gate(lc.port, lc.autoindex.upload_threads).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            log::warn!(
                "upload: 并发已满（listener :{}，upload_threads={}）peer={peer}",
                lc.port,
                lc.autoindex.upload_threads
            );
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(header::RETRY_AFTER, "1")
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(full(format!(
                    "上传并发已满（limit={}，可在面板调整 autoindex.upload_threads）",
                    lc.autoindex.upload_threads.clamp(1, 16)
                )))
                .unwrap_or_else(|_| Response::new(full("upload busy".to_string())));
        }
    };
    // 路径安全第一道：拒绝**编码过的分隔符**（`%2f`/`%5c`）与解码后含 `..` 段的路径。
    // 没有这道时 `PUT /..%2f..%2fetc%2fpasswd` 会被当作**一个字面文件名**落在 docroot 里
    //（实测返回 201 ✗）——虽然没逃逸出 root，但客户端意图是穿越、目录里也会留脏名字，
    // 必须拒。判据与 static 层的 normalize_url_path 同一套。
    //
    // 注意顺序：**先**拒编码分隔符，**再**解码 —— 否则 `%2f` 解码出来的 `/` 会让下面
    // 「解码后含 .. 段」的判据失去意义（`%2e%2e%2f` 会被拆成正常的 `..` + `/` 两段而漏判）。
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return resp(StatusCode::BAD_REQUEST, "路径含编码分隔符(%2f/%5c)，拒绝", None);
    }
    let decoded = percent_encoding::percent_decode_str(&path).decode_utf8_lossy();
    // NUL 不能在路径里：fs 层会以难读的 OS 错误冒泡（Windows 上还可能有截断语义）。
    if decoded.contains('\0') {
        return resp(StatusCode::BAD_REQUEST, "路径含 NUL 字节，拒绝", None);
    }
    if decoded.split(['/', '\\']).any(|seg| seg == "..") {
        return resp(StatusCode::BAD_REQUEST, "路径含 .. 段，拒绝", None);
    }
    // 扩展名闸门必须按**解码后**的路径判：落盘用的是解码后的名字，只看原始路径时
    // `PUT /up/shell.ph%70` 会带着 raw 名（`shell.ph%70`，判不出扩展名）通过闸门，
    // 却以 `shell.php` 落盘 ⇒ webshell。`%2e`/`%70` 这类写法现在是免费的绕过通道，
    // 必须与落盘对象对齐判据（此前解码只用于别的闸门，属「闸门看 decoded、落盘用 raw」）。
    if has_exec_ext(&decoded) {
        return resp(
            StatusCode::FORBIDDEN,
            "该扩展名被上传策略拒绝（可执行/可解析内容不允许上传；请改名或调整策略）",
            None,
        );
    }
    // 隐藏路径（任一段以 `.` 开头）不得作为上传目标。
    //
    // 为什么必须拦：`.env` 会被引擎当作环境变量读进进程（`deps.rs` 里的 `KEY=VAL`），
    // `.git/hooks/*` 是提权点，`.htpasswd`/`.part` 同理；而这些**都不是可执行扩展名**，
    // 扩展名闸门与 `would_execute_on_get` 都拦不住。未认证客户端只要
    // `PUT /<root>/.env`（或 `/.git/hooks/pre-commit`）就能改写它们 —— 实测基线里
    // `/rust/.env`、`/c/.env`、`/php/init.sh` 还是可以**匿名 GET 到**的，等于先读后写。
    // 例外只有 `.well-known`：ACME 验证要往那儿放文件（且内容是公开的）。
    if let Some(bad) = hidden_segment(&decoded) {
        return resp(
            StatusCode::FORBIDDEN,
            &format!("隐藏路径（.{bad}…）不允许作为上传目标；只有 /.well-known 例外"),
            None,
        );
    }
    // 「GET 时会被引擎执行」的闸门**必须在这里**，不能靠分发顺序。
    //
    // 分发（h1/h2/h3）拿**原始** URL 路径去问 `apps::would_handle`，而落盘用的是
    // `safe_join` 归一化后的路径；两者对 `/./cgi/pwn`、`//cgi/pwn` 这种写法结论不同 ——
    // 分发把请求交给上传器，文件却写进 CGI 引擎的 docroot，随后 `GET /cgi/pwn` 由引擎
    // 执行（`has_exec_ext` 只看扩展名，`pwn` 没有扩展名，拦不住）⇒ 一条请求换一个 webshell。
    // 这里复用 admin 文件写入同一套归一化判据（`would_execute_on_get` 内部走 `web_path_of`）。
    if crate::server::admin_files::would_execute_on_get(lc, decoded.trim_start_matches('/')) {
        return resp(
            StatusCode::FORBIDDEN,
            "该路径由应用引擎执行（归一化后仍落在引擎路径上），禁止上传",
            None,
        );
    }
    // containment 第二道：safe_join 拒绝 `..`/绝对路径/反斜杠/Windows 盘符。
    //
    // **必须传解码后的路径**：static 层 `resolve_path` 会先 percent-decode 再解析，
    // 上传若按原始 URL（`%20`、`%E6%8A%A5`）落盘，就会在 docroot 里创建**字面文件名**
    // `%20`/`%E6%8A%A5…`，与下载侧、autoindex 链接三处互相不一致；更严重的是
    // 「上传到含编码字符的目录」（autoindex 对目录名做了 encodeURIComponent，
    // 目录名带空格时 URL 就是 `/my%20dir/`）会去找字面名为 `my%20dir` 的目录 ⇒ 不存在
    // ⇒ `File::create` ENOENT ⇒ 上传**恒回 500**（功能完全不可用，见下方错误映射）。
    let rel = decoded.trim_start_matches('/');
    let target: PathBuf = match crate::server::admin_files::safe_join(&lc.root, rel) {
        Ok(p) => p,
        // 不回显文件系统细节（`canon /abs/path: Permission denied` 会把绝对路径交给匿名客户端）
        Err(e) => {
            log::debug!("upload: 路径不合法 path={path:?}: {e:#}");
            return resp(StatusCode::BAD_REQUEST, "路径不合法", None);
        }
    };
    // 应用 docroot 闸门（条件性 P0：上传覆盖 `init.sh`/`deps/bin/index`/`.env` → RCE）。
    // 必须放在 `target` 解析之后、任何落盘动作之前；判据见 `inside_any_app_docroot`。
    // 这条在扩展名闸门/隐藏段闸门/would_execute_on_get 之后，作为**兜底**把整个运行期目录
    // 挡掉（那三道都漏「无扩展名、GET 不路由」的 `deps/bin/index` 之类）。
    if let Some(dr) = inside_any_app_docroot(lc, &target) {
        log::warn!(
            "upload: 目标落在应用 docroot 内，拒绝（docroot={}）peer={peer} path={path:?}",
            dr.display()
        );
        return resp(
            StatusCode::FORBIDDEN,
            "目标位于应用运行期目录（docroot）内，禁止上传（init.sh/deps/.env 等会被执行或注入）",
            None,
        );
    }
    // 目标本身是目录（`PUT /up/`、`PUT /up/subdir/`）→ 409 Conflict。
    //
    // RFC 9110 §9.3.4：PUT 的目标是**资源**，用一个目录当资源语义冲突；且继续走下去
    // 会让 `session_for` 把临时文件写到该目录的**父目录**（`.{dirname}.upload.part`），
    // 既有越出 docroot 的写面、commit 又必然 EISDIR ⇒ 500。这里明确回 409
    //（与 `PUT /up/` 真机实测的 500 相比，至少是「说得清」的应答）。
    if target.is_dir() {
        return resp(StatusCode::CONFLICT, "目标是目录，不能作为上传目标", None);
    }
    // 父目录必须**已经存在**（autoindex/文件管理不负责隐式建目录）→ 409 Conflict。
    //
    // 旧行为：`File::create(tmp)` 在父目录不存在时 ENOENT → `UploadErr::Io` → 500
    //「写入失败」，把「URL 打错了/目录还没建」这种客户端问题报成服务端故障
    //（真机实测 `PUT /up/newdir/x.txt` → 500）。RFC 9110 §9.3.4 允许 409（与 nginx
    // 的 DAV 实现一致：目标层级不存在就是冲突）。
    if let Some(parent) = target.parent() {
        if !parent.is_dir() {
            return resp(StatusCode::CONFLICT, "父目录不存在（请先建目录）", None);
        }
    }

    // Content-Range（可选）：`bytes <start>-<end>/<total|*>`；缺省 = 全量、start=0。
    let mut wildcard_total = false;
    // 本请求声明的区间上界（`Content-Range` 的 last-pos）。用于拒绝「body 比声明的区间长」
    // 的写入：旧实现从不校验，多出来的字节被照单追加，最终文件比声明的 total 还大也能 commit
    //（客户端拿到 201、校验和却对不上）。
    let mut declared_end: Option<u64> = None;
    let (start, total) = match req.headers().get(header::CONTENT_RANGE) {
        Some(v) => match v.to_str().ok().and_then(upload_resume::parse_content_range) {
            Some((s, e, t)) => {
                // `bytes N-M/*` = 总长未知：**不能**把首片当完整文件。
                // 判据必须直接用解析结果（`t` 为 None 就是 `*`），不要再去拿原始头做
                // `ends_with("/*")` —— 那个写法对 `bytes 0-99/ *`（`/` 与 `*` 之间有空白，
                // parse_content_range 用 `trim()` 容忍、这里却不认）会判成「有总长」，
                // 于是唯一的首片直接 commit（**静默截断** + 会话被合并），
                // 正是下面 ③ 要避免的那个 bug。
                // RFC 9110 §14.4：`Content-Range: bytes first-last/complete-length` 要求
                // `last < complete-length`（除非 complete-length 未知用 `*`）——
                // `bytes 0-100/50` 这类声明本身自相矛盾，继续走会把「比声明的 total 多收的
                // 字节」照单收下（文件比 total 大却 commit），故直接 400。
                if let Some(t) = t {
                    if e >= t {
                        return resp(
                            StatusCode::BAD_REQUEST,
                            "Content-Range 与 total 矛盾（last >= total）",
                            None,
                        );
                    }
                }
                declared_end = Some(e);
                wildcard_total = t.is_none();
                (s, t)
            }
            None => {
                return resp(
                    StatusCode::BAD_REQUEST,
                    "Content-Range 无法解析（应形如 bytes 0-1023/4096）",
                    None,
                )
            }
        },
        None => {
            // 没有 Content-Range 时，Content-Length **就是**总量（`curl -T` 的常见形态）。
            // 之前这里给 None → `complete()` 恒假 → 客户端发完全部 body 也只拿到 202、
            // 文件永远留在 .upload.part（build42 端到端实测踩到）。只有分块传输
            // （既无 Content-Range 也无 Content-Length）才按“长度未知”处理，
            // 那种情况在读不到更多帧之后视为完成（见下面的 finished 判断）。
            let cl = req
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            (0, cl)
        }
    };
    let sess = match upload_resume::session_for(&target, start, total, Some(peer.ip())) {
        Ok(s) => s,
        Err(UploadErr::OffsetMismatch(cur)) => {
            return resp(
                StatusCode::CONFLICT,
                "偏移与已收字节数不符（按 X-Upload-Offset 续传，或从 0 全量重传）",
                Some(cur),
            )
        }
        Err(UploadErr::TooLarge) => {
            return resp(StatusCode::PAYLOAD_TOO_LARGE, "超过单文件上限", None)
        }
        Err(UploadErr::TooManySessions) => {
            return resp(
                StatusCode::SERVICE_UNAVAILABLE,
                "上传会话过多（或本来源 IP 的并发上传已达上限），稍后再试",
                None,
            )
        }
        Err(UploadErr::NoSpace) => {
            return resp(
                StatusCode::INSUFFICIENT_STORAGE,
                "服务端存储余量不足（在飞上传总量或磁盘余量触及上限），请稍后重试",
                None,
            )
        }
        Err(UploadErr::TotalMismatch) => {
            return resp(
                StatusCode::BAD_REQUEST,
                "同名上传会话的 total 与本次不一致（请改名或先取消）",
                None,
            )
        }
        Err(UploadErr::BadName(why)) => {
            return resp(StatusCode::BAD_REQUEST, &format!("文件名不可用：{why}"), None)
        }
        Err(UploadErr::Io(e)) => {
            // 其他分支都是 return（类型 `!`），这一支也必须 return，否则 match 各臂类型不一致
            //（build42 实测 E0308）。
            // 不回显 e：Io 错误里带的是**绝对路径**（`canon /opt/.../x: Permission denied`），
            // 给匿名客户端等于免费泄露部署布局；细节只进本地日志。
            log::warn!("upload: session_for({}) 失败: {e}", target.display());
            return resp(StatusCode::INTERNAL_SERVER_ERROR, "写入失败", None);
        }
    };

    // 持有会话记账（`session_for` 已在 SESSIONS 锁内 +1）：守卫必须在**所有**提前 return
    // 之前建立，靠 Drop 递减 —— 漏减会让该目标名的后续全量上传永久 409。
    // 作用：另一个请求正持有同一会话时，`session_for` 会把并发全量上传挡在 409，
    // 不再出现「共享 .part → 一方 500、另一方静默丢数据」。
    let _attach = upload_resume::Attach::new(Arc::clone(&sess));

    // 流式读 body：逐帧 append。offset 用会话当前值 —— 因此并发分片必须带 Content-Range
    // 且服务端按顺序接纳（偏移不符会直接回 409，客户端据此校正重发）。
    //
    // 两层时间预算（slowloris 防线，见 `UPLOAD_IDLE_TIMEOUT` 注释）：
    //   * 帧间**空闲**超时 60s：卡住不发的连接最多占 permit 60s；
    //   * 宽限期（60s）之后的**最低平均速率** 8KiB/s：挡住「每 59s 发 1 字节」这类
    //     刚好绕过空闲超时、却能把 permit 永久占住的客户端。
    // 超时返回 408 并**放弃会话**（`abort` 删掉 `.part` 并归还预算）——半截数据留着
    // 既没用又占盘。速率按「本请求已收到的字节 / 已用时长」算，不受其他会话影响。
    {
        let mut body = req.into_body();
        let started = Instant::now();
        let mut rxed: u64 = 0;
        loop {
            let frame = match tokio::time::timeout(UPLOAD_IDLE_TIMEOUT, body.frame()).await {
                Ok(Some(Ok(f))) => f,
                Ok(Some(Err(e))) => {
                    log::debug!("upload: 读取请求体失败: {e:#}");
                    return resp(StatusCode::BAD_REQUEST, "读取请求体失败", Some(sess.received()));
                }
                Ok(None) => break,
                Err(_) => {
                    log::warn!(
                        "upload: 请求体空闲超时（{}s）peer={peer} path={path:?}",
                        UPLOAD_IDLE_TIMEOUT.as_secs()
                    );
                    // 只释放 permit（靠函数返回），**保留**会话与已收字节：
                    // 断点续传正是为「网络中断/超时」设计的，删掉 `.part` 等于
                    // 让客户端从头再来。弃用会话由 `sweep_expired`（TTL 1h）回收。
                    return resp(
                        StatusCode::REQUEST_TIMEOUT,
                        "请求体读取超时（可按 X-Upload-Offset 续传）",
                        Some(sess.received()),
                    );
                }
            };
            let Some(data) = frame.data_ref() else { continue };
            if data.is_empty() {
                continue;
            }
            rxed += data.len() as u64;
            // 「body 比声明的区间长」必须拒：否则多出来的字节被静默追加进目标文件，
            // 最终长度超过 `Content-Range` 声明的 total 也能 commit（§14.4 语义被破坏）。
            if let Some(end) = declared_end {
                let limit = end - start + 1;
                if rxed > limit {
                    log::warn!(
                        "upload: 请求体超出声明的 Content-Range 区间（{rxed} > {limit}）peer={peer} path={path:?}"
                    );
                    upload_resume::abort(&sess);
                    return resp(
                        StatusCode::BAD_REQUEST,
                        "请求体长度超出 Content-Range 声明的区间",
                        Some(sess.received()),
                    );
                }
            }
            let elapsed = started.elapsed();
            if elapsed > UPLOAD_RATE_GRACE
                && rxed / elapsed.as_secs().max(1) < UPLOAD_MIN_BYTES_PER_SEC
            {
                log::warn!(
                    "upload: 请求体速率过低（{rxed}B/{elapsed:?}）peer={peer} path={path:?}"
                );
                // 同上：只释放 permit，会话与已收字节留下（客户端可续传）。
                return resp(
                    StatusCode::REQUEST_TIMEOUT,
                    "请求体速率过低，已中止（可按 X-Upload-Offset 续传）",
                    Some(sess.received()),
                );
            }
            let off = sess.received();
            // 落盘走 spawn_blocking：`append` 每个 DATA 帧做一次
            // `open(O_APPEND) + write_all + flush`，而 `commit` 还要对最大 2GiB 的临时文件
            // `fsync`。这些都是同步阻塞调用，直接跑在 async worker 上时（bench 形态只有
            // 2 条 worker，三协议共用 runtime）会让整个进程停止调度数秒到数十秒。
            // 这里**只包装调用点**，不改 `upload_resume::append` 的签名（它仍被
            // upload_api 同步调用，模块 API 与单测都不受影响）。`Bytes` 的 clone 是
            // 引用计数，不复制数据。
            let sess2 = Arc::clone(&sess);
            let chunk = data.clone();
            let res = tokio::task::spawn_blocking(move || {
                upload_resume::append(&sess2, off, &chunk)
            })
            .await;
            match res {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return match e {
                        UploadErr::OffsetMismatch(cur) => {
                            resp(StatusCode::CONFLICT, "偏移不符", Some(cur))
                        }
                        UploadErr::TooLarge => {
                            resp(StatusCode::PAYLOAD_TOO_LARGE, "超过单文件上限", None)
                        }
                        UploadErr::NoSpace => resp(
                            StatusCode::INSUFFICIENT_STORAGE,
                            "存储余量不足，请稍后重试",
                            Some(sess.received()),
                        ),
                        other => {
                            log::warn!("upload: append 失败: {other:?}");
                            resp(StatusCode::INTERNAL_SERVER_ERROR, "写入失败", Some(sess.received()))
                        }
                    };
                }
                Err(e) => {
                    // spawn_blocking 任务 panic/取消：会话状态不可信，按服务端错误回。
                    log::warn!("upload: append 任务异常: {e}");
                    return resp(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "写入失败",
                        Some(sess.received()),
                    );
                }
            }
        }
    }

    let received = sess.received();
    if received > MAX_UPLOAD_BYTES {
        return resp(StatusCode::PAYLOAD_TOO_LARGE, "超过单文件上限", None);
    }
    // 完成判定要分三种情况，别把「未知长度」压成一个：
    //  ① `total = Some(n)` → 收够 n 才算完成（分片上传走 202 + X-Upload-Offset）；
    //  ② 完全没有 Content-Range/Length（total=None 且非 `*/`）→ 读到 EOF 就是完整文件
    //     （`curl -T` 的分块传输形态）；
    //  ③ `Content-Range: bytes N-M/*` → 总长**未知**：服务端无法判断何时算完，
    //     因此**永不在本请求里判完成**，一律 202 + X-Upload-Offset，客户端必须用
    //     带具体 total 的请求（`bytes N-M/T` 或 Content-Length）收尾。
    //     旧实现把 ③ 并进 ② → 首片就 201（静默截断 + 会话被 commit，后续分片 409，永远拼不回）。
    // 用**本次请求**声明的 total 判定（不是会话里的那个：会话的 total 是首次创建时定的，
    // 用 `*/` 开的会话 total 恒为 None，于是收尾片即使给了具体 total 也会被判成未完成 → 永久 202）。
    let wildcard = wildcard_total || sess.is_wildcard_total();
    if let Some(t) = total {
        // 客户端一旦给出具体 total，就不再是「未知长度」会话了
        sess.clear_wildcard_total();
        if received >= t {
            return commit_response(&sess).await;
        }
    } else if wildcard {
        sess.mark_wildcard_total();
    } else {
        // 没有 Content-Range/Length：读到 EOF 就是完整文件（`curl -T` 的分块传输形态）
        return commit_response(&sess).await;
    }
    // 未收齐（分片上传）：202 + 当前偏移，客户端据此续传
    resp(StatusCode::ACCEPTED, "partial; continue with X-Upload-Offset", Some(received))
}

/// 收尾落盘（fsync + rename）并映射状态码。
///
/// `commit` 里的 `sync_all()` 是对**最大 2GiB** 的临时文件做 fsync，纯同步阻塞调用；
/// 在 2-worker 的 bench 形态下直接跑在 async worker 上会让整个进程失去响应数秒。
/// 包一层 `spawn_blocking`，签名不改（`upload_resume::commit` 仍可同步调用）。
async fn commit_response(sess: &Arc<upload_resume::Session>) -> Response<BoxBody> {
    let sess2 = Arc::clone(sess);
    match tokio::task::spawn_blocking(move || upload_resume::commit(&sess2)).await {
        Ok(Ok(())) => resp(StatusCode::CREATED, "uploaded", None),
        Ok(Err(e)) => {
            // 不回显 e：Io 错误里带**绝对路径**（`rename /opt/...`）。
            log::warn!("upload: commit 失败: {e:?}");
            resp(StatusCode::INTERNAL_SERVER_ERROR, "落盘失败", None)
        }
        Err(e) => {
            log::warn!("upload: commit 任务异常: {e}");
            resp(StatusCode::INTERNAL_SERVER_ERROR, "落盘失败", None)
        }
    }
}

/// h2/h3 用：这两个协议在协议层已把请求体收齐（`Request<Bytes>`），而返回体是 `Response<Bytes>`。
///
/// 这里不重构 `handle`，只做一层薄适配：把 `Bytes` 包成 `Full` 交给同一条 `handle` 路径
/// （逻辑仍只有一份），再把响应体收集回 `Bytes`（响应都是很小的文案，收集无成本）。
pub async fn handle_bytes(
    req: Request<Bytes>,
    live: &Arc<LiveConfig>,
    lc: &ListenerConfig,
    peer: std::net::SocketAddr,
) -> Response<Bytes> {
    let (parts, body) = req.into_parts();
    let full_req = Request::from_parts(parts, Full::new(body));
    let resp = handle(full_req, live, lc, peer).await;
    let (parts, body) = resp.into_parts();
    let bytes = BodyExt::collect(body)
        .await
        .ok()
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    Response::from_parts(parts, bytes)
}

/// h2/h3 的**流式**入口：body 直接透传给 [`handle`]（不先收齐进内存），响应仍收成 `Bytes`。
///
/// 与 `handle_bytes` 的唯一区别就是不把 body 变成 `Full<Bytes>` —— 这样 h2/h3 上的
/// 大文件上传可以逐帧落盘（上限 `MAX_UPLOAD_BYTES`=2GiB），而不是先撞 `REQUEST_BODY_CAP`(8MiB)。
pub async fn handle_stream<B>(
    req: Request<B>,
    live: &Arc<LiveConfig>,
    lc: &ListenerConfig,
    peer: std::net::SocketAddr,
) -> Response<Bytes>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::fmt::Display,
{
    let resp = handle(req, live, lc, peer).await;
    let (parts, body) = resp.into_parts();
    let bytes = BodyExt::collect(body)
        .await
        .ok()
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    Response::from_parts(parts, bytes)
}

/// 便于测试与静态检查：暴露扩展名闸门。
pub fn exec_ext_rejected(path: &str) -> bool {
    has_exec_ext(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_extensions_rejected() {
        for p in ["/up/x.php", "/up/a.PHP", "/up/shell.jsp", "/up/x.cgi", "/up/x.tsx", "/up/x.html"] {
            assert!(exec_ext_rejected(p), "{p} 应被拒");
        }
        for p in ["/up/x.txt", "/up/data.bin", "/up/photo.png", "/up/noext"] {
            assert!(!exec_ext_rejected(p), "{p} 应放行");
        }
    }

    #[test]
    fn enabled_only_when_configured() {
        // `enabled_for` 现在按 live 里的**当前**配置判（连接期快照只作回退），
        // 所以这里搭一个最小的 LiveConfig：默认 `enable_upload = false` → 必须不接管。
        let toml_text = "[[listeners]]\naddress = \"127.0.0.1\"\nport = 1\nroot = \"/tmp\"\n";
        let cfg: crate::config::Config = ::toml::from_str(toml_text).expect("parse");
        let lc = cfg.listeners[0].clone();
        let live = std::sync::Arc::new(crate::server::live_config::LiveConfig::new(
            cfg,
            std::path::PathBuf::from("/tmp/crucible-upload-test.toml"),
        ));
        assert!(!enabled_for(&live, &lc, "/up/x.txt"), "默认必须不接管");
    }

    /// 上传闸门必须跟**当前**配置走（审计 C-4）。
    ///
    /// 旧实现只看建连时的快照：h1/h2 的长连接能活几小时，期间面板「关上传」不生效。
    /// 这条测试在**同一份 live** 上把 `enable_upload` 打开/关掉，判定要立刻翻转 ——
    /// 没有它，「改回读快照」这种退化不会有测试变红。
    #[test]
    fn enabled_for_follows_live_config() {
        let toml_text = "[[listeners]]\naddress = \"127.0.0.1\"\nport = 1\nroot = \"/tmp\"\nautoindex = { enabled = true, enable_upload = false, paths = [\"/up\"] }\n";
        let cfg: crate::config::Config = ::toml::from_str(toml_text).expect("parse");
        let lc = cfg.listeners[0].clone();
        let live = std::sync::Arc::new(crate::server::live_config::LiveConfig::new(
            cfg,
            std::path::PathBuf::from("/tmp/crucible-upload-live.toml"),
        ));
        assert!(
            !enabled_for(&live, &lc, "/up/x.txt"),
            "enable_upload=false 时必须不接管"
        );

        // 模拟面板保存后的热更新（同一份 live 的当前配置变了）
        let mut cfg2 = (*live.snapshot()).clone();
        cfg2.listeners[0].autoindex.enable_upload = true;
        live.replace(cfg2);
        assert!(
            enabled_for(&live, &lc, "/up/x.txt"),
            "打开后必须立刻生效（否则长连接上关/开上传都无效）"
        );
        // 路径边界仍按当前配置判：不在 paths 里的路径不接管
        assert!(!enabled_for(&live, &lc, "/other/x.txt"));
    }

    #[test]
    fn response_carries_offset_header() {
        let r = resp(StatusCode::ACCEPTED, "partial", Some(1234));
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        assert_eq!(r.headers().get("x-upload-offset").unwrap(), "1234");
    }

    /// 扩展名闸门必须看**percent-decode 之后**的路径：落盘用的是解码后的名字，
    /// 只看 raw 时 `shell.ph%70` 会被当成「没有扩展名」放行，却以 `shell.php` 落盘。
    #[test]
    fn exec_ext_gate_sees_through_percent_encoding() {
        let decoded = |p: &str| {
            percent_encoding::percent_decode_str(p)
                .decode_utf8_lossy()
                .to_string()
        };
        // 这些 raw 形式判不出扩展名（旧实现的闸门会放行）
        for raw in ["/up/shell.ph%70", "/up/shell%2Ephp", "/up/x.HT%4DL"] {
            assert!(
                has_exec_ext(&decoded(raw)),
                "{raw} 解码后（{}）必须被扩展名闸门拒",
                decoded(raw)
            );
        }
        // 正常名字仍放行
        for raw in ["/up/a.txt", "/up/data.bin"] {
            assert!(!has_exec_ext(&decoded(raw)), "{raw} 不应被拒");
        }
    }

    /// 隐藏段闸门也要看解码后的路径（`%2Eenv` → `.env`）。
    #[test]
    fn hidden_segment_sees_through_percent_encoding() {
        let d = |p: &str| {
            percent_encoding::percent_decode_str(p)
                .decode_utf8_lossy()
                .to_string()
        };
        assert_eq!(hidden_segment(&d("/%2Eenv")), Some(".env".into()));
        assert_eq!(hidden_segment(&d("/.git/hooks/x")), Some(".git".into()));
        // .well-known 是唯一例外
        assert_eq!(hidden_segment(&d("/.well-known/acme-challenge/x")), None);
    }

    /// 连接的**地址身份**必须保持（同端口多地址部署不得串站）。
    ///
    /// 这里直接验证判据函数：`bind_key` 命中时取命中的那条 listener，
    /// 而不是「同端口的第一个」。
    #[test]
    fn listener_for_conn_keeps_address_identity() {
        let toml_text = r#"
[[listeners]]
address = "127.0.0.1"
port = 8080
root = "/tmp/site-a"

[[listeners]]
address = "127.0.0.2"
port = 8080
root = "/tmp/site-b"
"#;
        let cfg: crate::config::Config = ::toml::from_str(toml_text).expect("parse");
        let live = std::sync::Arc::new(crate::server::live_config::LiveConfig::new(
            cfg,
            std::path::PathBuf::from("/tmp/crucible-upload-addr.toml"),
        ));
        let site_a = live.snapshot().listeners[0].clone();
        let site_b = live.snapshot().listeners[1].clone();
        let got_a = listener_for_conn(&live, &site_a).expect("a");
        let got_b = listener_for_conn(&live, &site_b).expect("b");
        assert!(
            got_a.root.ends_with("site-a"),
            "A 站必须取到 A 站的 root，实得 {:?}",
            got_a.root
        );
        assert!(
            got_b.root.ends_with("site-b"),
            "B 站必须取到 B 站的 root（旧实现按端口取第一个 ⇒ 跨站写入），实得 {:?}",
            got_b.root
        );
    }

    /// 应用 docroot 闸门：docroot 内一律拒（含 init.sh / deps/bin/index / .env 这类
    /// 「无扩展名、GET 不路由」的运行期文件），docroot 外的正常上传目录放行。
    #[test]
    fn upload_gate_rejects_app_docroot_targets() {
        use crate::config::{AppRouteConfig, AutoindexConfig, FileOpenTable, ListenerConfig};
        let base = std::env::temp_dir().join("crucible-upload-docroot-gate");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("up")).unwrap();
        std::fs::create_dir_all(base.join("rust")).unwrap();
        let app = AppRouteConfig {
            paths: vec!["/rust".into()],
            enabled: true,
            engine: "rust".into(),
            socket: None,
            extensions: vec!["rs".into()],
            index: None,
            php_bin: None,
            workers: 1,
            source_dir: None,
            out_dir: None,
            entry: vec![],
            watch: false,
            docroot: Some(base.join("rust")),
            lib: None,
            deps_dir: None,
            init_timeout_secs: None,
            libc: None,
        };
        let lc = ListenerConfig {
            address: "127.0.0.1".into(),
            address_v6: None,
            port: 1,
            root: base.clone(),
            autoindex: AutoindexConfig::default(),
            http_versions: vec!["h1".into()],
            server_name: None,
            ssl: None,
            file_open: FileOpenTable::default(),
            apps: vec![app.clone()],
            basic_auth: None,
            proxy_rules: vec![],
            page_rules: vec![],
            status_path: None,
            port_reuse: false,
            rate_limit: None,
            ip_access: None,
            l4_forward: None,
            quic_ecn: false,
            qmux: false,
            connect_udp: false,
            access_log: None,
        };
        let t = |rel: &str| canon_best_effort(&base.join(rel));
        // docroot 内（含 init.sh / deps/bin/index 这类非可执行扩展名的运行期文件）→ 命中
        assert!(inside_any_app_docroot(&lc, &t("rust/init.sh")).is_some());
        assert!(inside_any_app_docroot(&lc, &t("rust/deps/bin/index")).is_some());
        assert!(inside_any_app_docroot(&lc, &t("rust/.env")).is_some());
        // docroot 本身 → 命中
        assert!(inside_any_app_docroot(&lc, &t("rust")).is_some());
        // 正常上传目录（不在任何 docroot 内）→ 放行
        assert!(inside_any_app_docroot(&lc, &t("up/x.txt")).is_none());
        // 组件级前缀相同的兄弟目录 → 放行（不得把 /rust 误当成 /rusty 的前缀）
        assert!(inside_any_app_docroot(&lc, &t("rusty/x.txt")).is_none());
        // disabled 但**显式**配了 docroot 的应用同样受保护（先上传、后启用的定时 RCE）→ 命中
        let mut disabled = app.clone();
        disabled.enabled = false;
        let lc_disabled = ListenerConfig {
            apps: vec![disabled.clone()],
            ..lc.clone()
        };
        assert!(inside_any_app_docroot(&lc_disabled, &t("rust/init.sh")).is_some());
        assert!(inside_any_app_docroot(&lc_disabled, &t("rust/deps/bin/index")).is_some());
        // disabled 且**未显式**配 docroot（docroot 会退化成 listener root）→ 跳过：
        // 否则开了上传的端口上**所有**上传都会 403（等于把上传功能关掉）
        let mut no_docroot = disabled;
        no_docroot.docroot = None;
        let lc_no = ListenerConfig {
            apps: vec![no_docroot],
            ..lc.clone()
        };
        assert!(inside_any_app_docroot(&lc_no, &t("up/x.txt")).is_none());
        let _ = std::fs::remove_dir_all(&base);
    }
}
