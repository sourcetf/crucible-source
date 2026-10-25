//! Shared FFI / Unix sidecar dispatch for optional app engines.

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::deps::DepsEnv;
use crate::server::apps::{app_ffi, native_http};
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;

/// h2/h3 字节路径的 sidecar 墙钟上限：整段（发送 + 收集响应体）共用一个 deadline。
/// sidecar 接受连接后不回包（应用卡死/死锁）时，请求任务与 UDS fd 不能永久挂着 ——
/// 此前这条路径完全裸奔（proxy/fastcgi/CGI 都有各自超时）。
const SIDECAR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `.env` → `x-crucible-env-<key>` 转发头（percent-encoded 值）。
///
/// 为什么需要：显式 `apps[].socket` 是**运维自己起的** Jetty 进程，宿主无法再注入
/// 它的进程 env；受管 sidecar（deps/bin/index）则已经由 spawn env 携带本 app 的 `.env`
/// （`native_http::ensure_sidecar`），这里是给「进程 env 够不着」的显式 socket 兜一条
/// 请求级通道。约定：
///   * 头名 `x-crucible-env-<key 的小写>`（.env key 只允许 `[A-Za-z0-9_]`，天然合法 token）；
///   * 值 percent-encode（`A-Za-z0-9-._~` 之外全部 `%XX`），与 URL 编码同义，ASCII 安全；
///   * 空值（`.env` 的 `KEY=` = 「该键不存在」）不转发；
///   * 上限 64 键 / 16KiB，超出截断（防头膨胀）。
///
/// **键仅大小写不同**（`.env` 里合法的 `KEY` 与 `key` 是**两个**环境变量，但 HTTP 头名
/// 大小写不敏感 ⇒ 会生成同名头、sidecar 侧 `getHeader` 只能取到一条）——本函数在此定义
/// 明确语义（P3）：
///   * 值相同 ⇒ 只发**一条**（客户端看到的值与两个键都一致，无信息丢失，不记日志）；
///   * 值不同 ⇒ **保留先出现的那个键**（= `.env` 文件顺序），后来的大小写变体**丢弃**并
///     记一条节流 warn（不静默：运维能看到自己写了两个只差大小写的键，而头通道无法区分）。
///   判定在**头通道**这一层完成（spawn env 通道不受影响：POSIX 环境变量大小写敏感，
///   `KEY`/`key` 都会如实进进程 env）。
///
/// 只对 JSP/do 生效（见调用点）：c/go/rust 样例 sidecar 不读 env，凭空多发头反而可能
/// 改动它们的响应（例如自行打印全部请求头）。
pub(crate) fn env_forward_headers(vars: &[(String, String)]) -> Vec<(String, String)> {
    const MAX_KEYS: usize = 64;
    const MAX_BYTES: usize = 16 * 1024;
    let mut out: Vec<(String, String)> = Vec::new();
    let mut used = 0usize;
    let mut collisions: Vec<(String, String)> = Vec::new();
    for (k, v) in vars {
        if out.len() >= MAX_KEYS {
            break;
        }
        if k.is_empty()
            || k.len() > 128
            || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || v.is_empty()
        {
            continue;
        }
        let enc = percent_encode_env_value(v);
        let name = format!("x-crucible-env-{}", k.to_ascii_lowercase());
        // 大小写不同的同名键（HTTP 头名不区分大小写）：见上面的语义说明。
        // 注意必须比较**编码前的原值**：`percent_encode_env_value` 是单射，比较编码值等价。
        if let Some((_, prev)) = out.iter().find(|(n, _)| n == &name) {
            if prev != &enc {
                collisions.push((k.clone(), name.clone()));
            }
            continue;
        }
        if used + name.len() + enc.len() + 2 > MAX_BYTES {
            break;
        }
        used += name.len() + enc.len() + 2;
        out.push((name, enc));
    }
    if !collisions.is_empty() {
        let detail = collisions
            .iter()
            .map(|(k, n)| format!("{k} → {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        crate::server::log_throttle::warn_every(
            "env-forward-case-collision",
            std::time::Duration::from_secs(60),
            &format!(
                "sidecar env 头通道：.env 里存在仅大小写不同的键，头名大小写不敏感 ⇒ 保留先出现的那个，丢弃：{detail}"
            ),
        );
    }
    out
}

fn percent_encode_env_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// JSP/do 是否需要 `.env` 请求头通道（见 [`env_forward_headers`]）。
fn engine_forwards_env_headers(engine: &str) -> bool {
    matches!(engine, "jsp" | "do")
}

/// `libapp_rack.so` 是否是**可用的嵌入式 MRI 产物**。
///
/// 为什么不能只看 `native_http::lib_available`：Rack 的 MRI 嵌入按平台默认开关
/// （`scripts/build_script_ffi.sh`：Linux 开 / OpenBSD 关）。关闭时构建脚本仍会产出
/// 一个「诚实失败」stub `.so` —— 文件存在、可 dlopen，但每个请求都返回「未嵌入
/// Ruby」。`lib_available` 只判文件是否存在，于是 stub 会把 `deps/bin/index` 常驻
/// sidecar 挡在分发之外，`/rack/` 在 OpenBSD 上恒 502（`/ruby/` 的同类问题是通过
/// 「关嵌入时删掉 .so」解决的；rack 的 stub 被保留下来提供更明确的报错，所以这里
/// 需要一个运行时判据）。
///
/// 判据：可执行映像里是否存在 `libruby<版本>.so` 形态的动态库名。嵌入式构建必定
/// DT_NEEDED 共享 libruby（本仓库的构建用 `LIBRUBYARG_SHARED`），并且编进 .so 的
/// 兼容层还带有 `libruby34.so` / `libruby-3.3.so.3.3` 字符串；stub 的报错文本里只有
/// `libruby（…）`，不匹配这个形态（因此不会把 stub 误判为可用嵌入）。
/// 结果按 (文件长度, mtime) 缓存：重建 .so 后下一次请求即生效。
pub(crate) fn rack_embed_usable(app: &AppRouteConfig) -> bool {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::UNIX_EPOCH;

    static CACHE: OnceLock<parking_lot::Mutex<HashMap<PathBuf, (u64, u64, bool)>>> =
        OnceLock::new();

    let Ok(path) = app_ffi::resolve_lib(app, "rack") else {
        return false;
    };
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let len = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    let cache = CACHE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()));
    {
        let map = cache.lock();
        if let Some((c_len, c_mtime, ok)) = map.get(&path) {
            if *c_len == len && *c_mtime == mtime {
                return *ok;
            }
        }
    }
    let ok = std::fs::read(&path)
        .map(|bytes| image_has_libruby_soname(&bytes))
        .unwrap_or(false);
    let mut map = cache.lock();
    if map.len() >= 64 {
        map.clear();
    }
    map.insert(path, (len, mtime, ok));
    ok
}

/// 字节级判据：`libruby` 后跟可选 `-`/`.`、至少一位版本数字、`[0-9.-]*`，再是 `.so`。
/// 见 [`rack_embed_usable`] 的说明（stub 的 `libruby（…）` 不匹配）。
fn image_has_libruby_soname(bytes: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"libruby";
    let mut i = 0usize;
    while i + NEEDLE.len() <= bytes.len() {
        let Some(off) = bytes[i..]
            .windows(NEEDLE.len())
            .position(|w| w == NEEDLE)
        else {
            break;
        };
        let pos = i + off;
        // 无版本号的 SONAME（`libruby.so`）直接命中。stub 里的 `/libruby`（字符串
        // 到此结束）与 `libruby（…）`（全角括号）都不匹配。
        if bytes[pos + NEEDLE.len()..].starts_with(b".so") {
            return true;
        }
        let mut j = pos + NEEDLE.len();
        if j < bytes.len() && (bytes[j] == b'-' || bytes[j] == b'.') {
            j += 1;
        }
        let version_start = j;
        while j < bytes.len() {
            let c = bytes[j];
            if c.is_ascii_digit() {
                j += 1;
            } else if c == b'.' && j + 1 < bytes.len() && bytes[j + 1] == b's' {
                break; // 版本号结束，紧跟 ".so"
            } else if c == b'.' || c == b'-' {
                j += 1;
            } else {
                break;
            }
        }
        if j > version_start && bytes[j..].starts_with(b".so") {
            return true;
        }
        i = pos + NEEDLE.len();
    }
    false
}

/// Rack 是否该走非 FFI 的 sidecar/UDS 链（嵌入不可用、且确有后端）。
///
/// 调用方据此在「app_ffi 直接执行」与 `sidecar_engine::handle_with_fallback` 之间选；
/// [`handle_with_fallback`] 内部也会用 [`rack_embed_usable`] 复核（防止直接调用方绕过）。
pub(crate) fn rack_sidecar_preferred(app: &AppRouteConfig, lc: &ListenerConfig) -> bool {
    !rack_embed_usable(app)
        && (native_http::uds_socket_available(app) || native_http::sidecar_available(app, lc))
}

/// Rack 的内部路径头：`x-crucible-rack-path`（percent-encoded 应用相对路径）。
///
/// 为什么需要：宿主的 `app_ffi::rel_script_path` 会把**目录请求**改成配置的 index
/// （`/rack/` → `/index.ru`、`/rack/sub/` → `/index.ru`）——对 PHP/CGI 这类「一个
/// 路径必须落到一个脚本」的引擎正确，但 Rack 应用需要真实的 URL 路径（PATH_INFO
/// 是路由输入）。sidecar 侧若只看代理目标，root/目录请求会拿到 `/index.ru`，
/// 应用按 PATH_INFO 路由时必然走错。这个头把**剥掉 app 前缀后的原始路径**带给
/// sidecar（与 `/ruby/` 的 spawn 约定同一层：都是宿主 → 受管 sidecar 的内部通道）。
///
/// 客户端同名头一律在宿主侧删除后重写（见 [`set_rack_path_header`]），不可伪造。
pub(crate) fn rack_path_header_value(app: &AppRouteConfig, path: &str) -> String {
    let mut p = path.to_string();
    for prefix in &app.paths {
        if prefix.is_empty() {
            continue;
        }
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() {
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
    if p.is_empty() {
        p.push('/');
    } else if !p.starts_with('/') {
        p.insert(0, '/');
    }
    // 头里放**已解码的 URL 路径**：sidecar 只需 decode 一次就能得到 Rack 的
    // PATH_INFO。若直接编码原始（仍带 `%2e%2e`）路径，sidecar 解一次后还是
    // percent-encoded，既不符合 Rack 语义，也让穿越判据看不到 `..`。
    percent_encode_env_value(&percent_decode_path(&p))
}

/// `%XX` → 字节（不处理 `+`，路径里 `+` 是字面量）。非法转义原样保留。
fn percent_decode_path(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 在请求上写入内部路径头（先删客户端同名头，防伪造）。
pub(crate) fn set_rack_path_header<B>(req: &mut Request<B>, app: &AppRouteConfig) {
    let value = rack_path_header_value(app, req.uri().path());
    req.headers_mut().remove("x-crucible-rack-path");
    if let Ok(hv) = http::HeaderValue::from_str(&value) {
        req.headers_mut().insert("x-crucible-rack-path", hv);
    }
}

/// 内部路径头（名称、值）：非 Rack 引擎返回 `None`。
fn rack_path_header(app: &AppRouteConfig, engine: &str, path: &str) -> Option<(String, String)> {
    if engine != "rack" {
        return None;
    }
    Some((
        "x-crucible-rack-path".to_string(),
        rack_path_header_value(app, path),
    ))
}


pub async fn handle_with_fallback(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    engine: &str,
    stub_body: &str,
) -> Result<Response<BoxBody>> {
    // 本 app 的 `.env`（deps 解析结果，`try_handle` 注入到 extensions）：
    //   * 受管 sidecar 在 spawn 时装进它的进程 env（本 app 的键在 `System.getenv`/`ENV` 可见）；
    //   * 显式 socket 另发 `x-crucible-env-*` 请求头（进程 env 够不着的兜底通道）。
    // rack：文件存在 ≠ 可用（RACK_EMBED=0 时是「诚实失败」stub，见
    // [`rack_embed_usable`]）——否则 sidecar/UDS 永远轮不到。
    let avail = native_http::lib_available(app, engine)
        && (engine != "rack" || rack_embed_usable(app));
    // FFI 命中时**不需要** .env 克隆 / 转发头（app_ffi::execute 自己从 extensions 取）：
    // 旧实现先深拷贝整份 .env 再判 lib，c/go/rust 每请求白付一次 Vec 分配+拷贝。
    if avail {
        return app_ffi::execute(req, lc, app, peer).await;
    }
    let env_vars: Vec<(String, String)> = req
        .extensions()
        .get::<DepsEnv>()
        .map(|d| (*d.vars).clone())
        .unwrap_or_default();
    let extra_headers: Vec<(String, String)> = if engine_forwards_env_headers(engine) {
        env_forward_headers(&env_vars)
    } else {
        Vec::new()
    };
    // Rack 走 sidecar 时把**原始应用相对路径**通过内部头带给 sidecar（宿主会把
    // 目录请求的代理目标改写成 `/index.ru`，而 Rack 的 PATH_INFO 必须是真实 URL 路径）。
    // 客户端同名头在这里被先删后写，不可伪造。
    let mut req = req;
    if engine == "rack" {
        set_rack_path_header(&mut req, app);
    }
    // **顺序**：显式配置且**活着**的 `socket` 优先于自动探测的 `deps/bin/index`。
    //
    // 为什么：`sidecar_available` 只判「`deps/bin/index` **这个文件存在**」，并不验证它跑得起来；
    // 而 `uds_socket_available` 会真的去 connect（`sock_alive`）。JSP 就是典型：
    // `www-apps/jsp/init.sh` 会生成 `deps/bin/index` 包装脚本，但 `target/jsp-sidecar.jar`
    // 可能压根没构建 ⇒ 走 sidecar 分支必然失败，**永远到不了**配置里那条 `socket = "..."`，
    // 于是 `/jsp/`、`/do/` 恒 502，而且日志还说「sidecar sock not ready」**误导**排查
    // （实测：同一台机上该 socket 直接 `nc -U` 是通的）。
    //
    // 为什么这是**无回归**的改动：`uds_socket_available` 要求 socket **活着** —— 配了但没起
    // 的 socket 会照旧往下落到 sidecar 分支（与今天完全一致）。只有「显式配了、而且真的能连」
    // 的时候才会抢在自动探测之前 —— 那本来就是运维写在配置里的意图。
    if native_http::uds_socket_available(app) {
        return native_http::try_handle_uds(req, app, peer, &extra_headers).await;
    }
    if native_http::sidecar_available(app, lc) {
        return native_http::try_handle(req, lc, app, peer, app_idx, &env_vars).await;
    }
    // No FFI .so and no sidecar/UDS — do not pretend success.
    let _ = (stub_body, extra_headers);
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(format!(
            "502 Bad Gateway: engine `{engine}` unavailable (no libapp_{engine}.so, sidecar, or socket)\n"
        )))
        .unwrap())
}

/// [`handle_with_fallback`] 的**字节版**（h2/h3 simple 路径）：请求体已在协议层收齐为
/// `Bytes`，与 h1 走同一条 fallback 链（FFI .so → 显式且存活的 UDS → `deps/bin/index`
/// 持久 sidecar → 502），只是传输层按 `Bytes` 收发。
///
/// 为什么不直接复用 `handle_with_fallback`：它的入参是 `Request<Incoming>`，而
/// `hyper::body::Incoming` 没有公开构造函数（hyper 1.9 `pub(crate) fn new_channel`），
/// 字节路径无法把已收齐的 body 包回 `Incoming`。
pub async fn handle_with_fallback_simple(
    req: &Request<Bytes>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    engine: &str,
    deps: &DepsEnv,
) -> Result<Response<Bytes>> {
    if native_http::lib_available(app, engine)
        && (engine != "rack" || rack_embed_usable(app))
    {
        let outcome = app_ffi::execute_simple(req, lc, app, peer, deps).await?;
        return Ok(app_ffi::simple_response_from_outcome(outcome));
    }
    // 与 h1 同口径：本 app 的 `.env` 进受管 sidecar 的 spawn env；显式 socket（Jetty，
    // 进程 env 够不着）走 `x-crucible-env-*` 请求头通道（见 `env_forward_headers`）。
    let env_vars: Vec<(String, String)> = (*deps.vars).clone();
    let extra_headers: Vec<(String, String)> = if engine_forwards_env_headers(engine) {
        env_forward_headers(&env_vars)
    } else {
        Vec::new()
    };
    // Rack：原始应用相对路径（见 h1 侧同段说明）——显式 socket 与受管 sidecar 都带。
    let rack_hdr = rack_path_header(app, engine, req.uri().path());
    // 与 h1 同序：显式配置的 socket（活着才算）优先，其次自动探测的 sidecar。
    #[cfg(unix)]
    {
        if native_http::uds_socket_available(app) {
            let sock = native_http::uds_socket_path(app).context("apps[].socket missing")?;
            // 显式 socket 的 sidecar（JSP/do）：**剥掉路由前缀**再转发 —— Jetty 的
            // WebAppContext 是 `/`，原样发 `/jsp/index.jsp` 会让它去 docroot/jsp/ 找文件，
            // 恒 404（与 h1 侧 native_http::try_handle_uds 同一判据）。
            let target = crate::server::apps::app_ffi::rel_script_path(app, req.uri().path());
            let mut hdrs = extra_headers.clone();
            if let Some(h) = &rack_hdr {
                hdrs.push(h.clone());
            }
            return proxy_uds_simple(req, &sock, peer, Some(target), &hdrs).await;
        }
        if native_http::sidecar_available(app, lc) {
            let sock = ensure_sidecar_simple(lc, app, app_idx, &env_vars).await?;
            // 与 h1 侧同语义：自动 sidecar 同样剥掉路由前缀（sidecar 挂在 /ruby、/go
            // 这类前缀下，内部只认应用相对路径）。
            let target = crate::server::apps::app_ffi::rel_script_path(app, req.uri().path());
            // **受管 sidecar 只走 spawn env 通道**（h1 `native_http::try_handle` 传的就是
            // `&[]`）：`.env` 已经在 spawn 时进了进程环境，这里再按请求发一遍
            // `x-crucible-env-*` 有两个害处：
            //   ① 同一 app 在 h1 上读不到 request attribute、在 h2/h3 上读得到 —— 跨协议
            //      行为不一致（T6 真机复现：受管 `/jsp/` 的 `env-attribute` 在 h2c/h3 非空、
            //      在 h1 为空）；
            //   ② 每请求最多 64 头/16KiB 的纯重复开销。
            // 显式 `apps[].socket`（上一分支）仍发头 —— 那条通道是运维进程 env 够不着的兜底。
            // Rack 的内部路径头是另一回事：它承载 PATH_INFO，必须与协议无关地送达。
            let hdrs: &[(String, String)] = match &rack_hdr {
                Some(h) => std::slice::from_ref(h),
                None => &[],
            };
            return proxy_uds_simple(req, &sock, peer, Some(target), hdrs).await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (req, lc, app, peer, app_idx, deps, env_vars, extra_headers, rack_hdr);
    }
    // 「无后端可用」是**引擎不可用**（配置/构建问题），与 h1 `handle_with_fallback` 同口径：
    // 返回一个固定的 502 **响应**（而不是 Err）—— Err 会被 `simple_engine_error` 换成通用
    // 文本「502 Bad Gateway (engine error)」，于是同一个 URL 的 502 错误体在 h1 与 h2/h3
    // 上不同（跨协议不一致）。这里给出与 h1 逐字相同的 502 文本。
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Bytes::from(format!(
            "502 Bad Gateway: engine `{engine}` unavailable (no libapp_{engine}.so, sidecar, or socket)\n"
        )))
        .unwrap())
}

/// 客户端转发头：只能由本代理重写，透传等于让客户端伪造来源。
fn is_client_forward_header(lower: &str) -> bool {
    matches!(
        lower,
        "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" | "x-real-ip"
    )
}

/// hop-by-hop 头（RFC 9110 §7.6.1）：只为当前这条连接服务，不能带进响应/请求的另一端。
fn is_hop_by_hop(lower: &str) -> bool {
    matches!(
        lower,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// 上游响应 → 下游响应（字节版）：过滤 hop-by-hop（含 `Connection` 点名的头）与
/// 和真实 body 长度不符的 `Content-Length`（否则 h1 keep-alive 上是响应走私，
/// h2/h3 上对端判 CL 不符直接 RST 流）。与 proxy.rs 对同一天花板同一口径。
fn upstream_response(rparts: http::response::Parts, body: Bytes) -> Result<Response<Bytes>> {
    let conn_tokens: Vec<String> = rparts
        .headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let mut builder = Response::builder().status(rparts.status);
    for (k, v) in rparts.headers.iter() {
        let lower = k.as_str().to_ascii_lowercase();
        if is_hop_by_hop(&lower) || conn_tokens.iter().any(|t| t == &lower) {
            continue;
        }
        if lower == "content-length" {
            let declared = v.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok());
            if declared != Some(body.len() as u64) {
                continue;
            }
        }
        builder = builder.header(k, v);
    }
    builder
        .body(body)
        .context("build native sidecar response (simple)")
}

#[cfg(unix)]
pub(crate) async fn proxy_uds_simple(
    req: &Request<Bytes>,
    sock: &std::path::Path,
    peer: SocketAddr,
    path_override: Option<String>,
    extra_headers: &[(String, String)],
) -> Result<Response<Bytes>> {
    use hyper::client::conn::http1;
    use http_body_util::BodyExt as _;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect {}", sock.display()))?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .context("h1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("native_http simple conn: {e}");
        }
    });

    // h2/h3 的 URI 带 scheme+authority（:authority），而 UDS sidecar 是 origin server：
    // 目标一律改写为 origin-form（path?query），否则请求行会写成 absolute-form，sidecar
    // 可能解析失败/路由错。h2 也不保证有 Host 头 ⇒ authority 存在而 Host 缺失时补上。
    let target = match path_override {
        Some(p) => match req.uri().query() {
            Some(q) => format!("{p}?{q}"),
            None => p,
        },
        None => req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string()),
    };
    let mut builder = Request::builder().method(req.method().clone()).uri(target);
    let mut has_host = false;
    for (k, v) in req.headers() {
        let lower = k.as_str().to_ascii_lowercase();
        if lower == "host" {
            has_host = true;
        }
        // `x-crucible-env-*` 一律**丢弃客户端值**：它只能由宿主按本 app 的 deps 生成，
        // 透传/追加等于让客户端伪造应用环境（下面 extra_headers 后写生效）。
        if is_client_forward_header(&lower)
            || is_hop_by_hop(&lower)
            || lower.starts_with("x-crucible-env-")
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    if !has_host {
        if let Some(auth) = req.uri().authority() {
            builder = builder.header(http::header::HOST, auth.as_str());
        }
    }
    builder = builder.header("x-forwarded-for", peer.ip().to_string());
    // `.env` 转发头（显式 socket 的 Jetty 进程 env 够不着的兜底通道）。客户端同名头在
    // 上面的复制循环里已被丢弃（`x-crucible-env-*` 前缀），这里写的是宿主按本 app 的
    // deps 生成的值，客户端无法伪造。
    for (k, v) in extra_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let upstream = builder
        .body(http_body_util::Full::new(req.body().clone()))
        .context("build upstream req")?;

    // 整段一个 deadline：发送、响应头、响应体收集都算在内。
    //
    // 超时必须同时**终止受管的 sidecar 进程**（与 native_http 同一判据）：挂死的进程仍占着
    // 监听 socket，`sock_alive` 恒真 ⇒ 该 sidecar 永远留在缓存里，之后每个请求都要等满
    // 30s 才 502，永不自愈。杀掉后下一个请求重新拉起。显式 `apps[].socket`（运维自己起的
    // Jetty）不在受管表里，不会被误杀。
    let (rparts, rbytes) = tokio::time::timeout(SIDECAR_TIMEOUT, async {
        let resp = sender
            .send_request(upstream)
            .await
            .context("sidecar request")?;
        let (rparts, rbody) = resp.into_parts();
        let rbytes = http_body_util::Limited::new(rbody, crate::server::h1::UPSTREAM_BODY_CAP)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("collect upstream body: {e}"))?
            .to_bytes();
        Ok::<_, anyhow::Error>((rparts, rbytes))
    })
    .await
    .map_err(|_| {
        // 跨协议兜底（与 native_http 对称）：还活着但挂死的 sidecar 可能登记在 h1 的
        // `native_http::SIDECARS` 表里（同一个 sock 路径）。只杀自己表里的话，h2/h3 在
        // 「h1 起的进程挂死」时每个请求都要等满 30s 且**永不自愈**（真机实测）。
        if !kill_managed_sidecar_simple_by_sock(sock) {
            crate::server::apps::native_http::kill_managed_sidecar_by_sock(sock);
        }
        anyhow::anyhow!("sidecar timeout after {SIDECAR_TIMEOUT:?}")
    })??;
    upstream_response(rparts, rbytes)
}

/// 代理超时后杀掉**受管**（`SIDECARS_SIMPLE` 表里登记的）sidecar 进程（见调用点说明）。
///
/// `pub(crate)`：h1 的 `native_http::proxy_unix` 也会在超时时回调它 —— 两条协议共用同一个
/// sock 路径，sidecar 可能记在**对方**的表里；只杀自己表里的会让本协议在「对方起的进程
/// 挂死」时永不自愈（实测：h1 起、被 SIGSTOP 的 JSP sidecar，h2c 连续两次都是 30s+502）。
#[cfg(unix)]
pub(crate) fn kill_managed_sidecar_simple_by_sock(sock: &std::path::Path) -> bool {
    let Some(mut dead) = take_managed_sidecar_simple_by_sock(sock) else {
        return false;
    };
    log::warn!(
        "sidecar(simple): {} 代理超时（客户端已 502）→ 终止受管进程，后续请求将重启",
        sock.display()
    );
    crate::server::apps::child_registry::kill_child(&mut dead);
    true
}

/// 从本注册表「摘除」某个 sock 的 sidecar（不杀、不记日志），返回 Child 供调用方按
/// 自己的语义回收（超时 / `.env` 指纹变化）。
#[cfg(unix)]
pub(crate) fn take_managed_sidecar_simple_by_sock(
    sock: &std::path::Path,
) -> Option<std::process::Child> {
    let key = {
        let map = SIDECARS_SIMPLE.lock();
        map.iter().find(|(_, s)| s.sock == sock).map(|(k, _)| k.clone())
    }?;
    SIDECARS_SIMPLE.lock().remove(&key).map(|s| s.child)
}

#[cfg(unix)]
fn sock_alive(sock: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(sock).is_ok()
}

#[cfg(unix)]
struct SimpleSidecar {
    sock: std::path::PathBuf,
    child: std::process::Child,
    /// 与 `native_http::Sidecar` 同判据：`.env` 指纹 / docroot 变了就重启（长驻进程的
    /// env 与 cwd 只在 spawn 时定型）。
    env_fp: u64,
    docroot: std::path::PathBuf,
}

/// h2/h3 字节路径的 sidecar 注册表（键与 native_http 相同：port-app_idx-engine）。
///
/// 与 native_http 的注册表并存：两边用**同一个 sock 路径**（`state/native/{key}/app.sock`），
/// spawn 前先 `sock_alive` 探测，所以一条协议先起的 sidecar 会被另一条复用；**并发首发**
/// 这条窄窗由 [`crate::server::apps::native_http::sidecar_spawn_lock`] 关掉 —— 两条注册表
/// 共用**同一把 per-sock 创建锁**，拿锁后重查（自己表 → `sock_alive`），因此同一时刻只有
/// 一个 spawner 能走到 spawn（见该函数的说明）。
#[cfg(unix)]
static SIDECARS_SIMPLE: once_cell::sync::Lazy<
    parking_lot::Mutex<std::collections::HashMap<String, SimpleSidecar>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

/// 确保 `deps/bin/index` 持久 sidecar 已启动，返回其 UDS 路径。
/// 与 native_http::ensure_sidecar 同一套约定（env、state 目录、5s 就绪等待、
/// 失败 kill 子进程），保证 h1/h2/h3 起出来的是同一种进程。
#[cfg(unix)]
async fn ensure_sidecar_simple(
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    app_idx: usize,
    env_vars: &[(String, String)],
) -> Result<std::path::PathBuf> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let key = format!("{}-{}-{}", lc.port, app_idx, app.engine);
    let state = abs_path(&std::path::PathBuf::from(format!("state/native/{key}")));
    std::fs::create_dir_all(&state).context("mkdir native state")?;
    let sock = abs_canon(&state.join("app.sock"));
    let fp = native_http::env_fingerprint(env_vars);
    let docroot_desired = abs_canon(&app.docroot.clone().unwrap_or_else(|| lc.root.clone()));

    // 别的协议（h1）或本注册表之外的实例已经把这个 socket 起好了：**核验 `.env` 指纹后**
    // 复用。sock 旁有 spawner 写下的 `app.sock.envfp`：
    //   * 指纹一致 → 复用（不重启，反复切协议无抖动）；
    //   * 不一致/缺失 → 旧进程的进程 env 是陈旧的（`.env` 已变），必须重启；
    //   * 不能直接 remove_file 抢走对方的监听 socket（会让对方进程成孤儿）。
    if sock_alive(&sock) {
        let owned_ok = {
            let map = SIDECARS_SIMPLE.lock();
            match map.get(&key) {
                Some(s) => s.env_fp == fp && s.docroot == docroot_desired,
                // 本表没有条目 = 由另一条协议拉起：靠指纹文件核验，**并且**要求
                // `.envfp` 里的 pid 仍是本进程的直系子进程（指纹一致但 pid 已被
                // reparent = 上一代遗留，复用会把它变成永久孤儿）。
                None => native_http::sidecar_reusable(&sock, fp),
            }
        };
        if owned_ok {
            return Ok(sock);
        }
    }
    {
        let map = SIDECARS_SIMPLE.lock();
        if let Some(s) = map.get(&key) {
            if sock_alive(&s.sock) && s.env_fp == fp && s.docroot == docroot_desired {
                return Ok(s.sock.clone());
            }
        }
    }

    let lock = crate::server::apps::native_http::sidecar_spawn_lock(&sock);
    let _guard = lock.lock().await;
    // 等锁期间可能已被别人建好（或已由另一协议拉起）。
    {
        let map = SIDECARS_SIMPLE.lock();
        if let Some(s) = map.get(&key) {
            if sock_alive(&s.sock) && s.env_fp == fp && s.docroot == docroot_desired {
                return Ok(s.sock.clone());
            }
        }
    }
    // 等锁期间**另一条协议**（h1 的 `native_http::SIDECARS`）可能刚拉起同一个 sock：
    // 同一把 per-sock 锁（[`native_http::sidecar_spawn_lock`]）保证对方的 spawn 已经完成、
    // 且**已等到 sock 就绪**才释放锁（对方在锁内做 5s 就绪等待），所以这里 `sock_alive`
    // 为真即代表「有人在服务」⇒ 复用。绝不 `remove_file` + 抢 spawn（那会偷走它的监听
    // socket、把它变成无人回收的孤儿）。
    if sock_alive(&sock) {
        // 本表里仍有条目 ⇒ 它在上面两处检查里都没通过（指纹/docroot 过期），必须重建。
        let own_entry_stale = SIDECARS_SIMPLE.lock().contains_key(&key);
        if !own_entry_stale && native_http::sidecar_reusable(&sock, fp) {
            log::debug!(
                "sidecar(simple): {key} 已由其它注册表拉起（sock 存活、.env 指纹一致且进程属于本进程），复用"
            );
            return Ok(sock);
        }
        native_http::evict_sidecar_for_env_change(&sock, fp);
    }
    // 死条目 / 指纹或 docroot 变化的旧条目：杀进程再摘除（只删表会留下孤儿）。
    if let Some(mut dead) = SIDECARS_SIMPLE.lock().remove(&key) {
        crate::server::apps::child_registry::kill_child(&mut dead.child);
    }

    let deps_bin = native_http::sidecar_binary(app, lc)
        .context("native sidecar binary missing: deps/bin/index (no CGI fallback)")?;
    let docroot = docroot_desired;
    let _ = std::fs::remove_file(&sock);
    let log_path = state.join("sidecar.log");
    let log_file = std::fs::File::create(&log_path).context("sidecar.log")?;

    let mut cmd = Command::new(&deps_bin);
    // 干净环境（与 h1 `native_http::ensure_sidecar` 同一判据）：sidecar 是长驻进程，spawn
    // 时刻可能落在别的应用的请求期 `.env` 窗口内 —— 默认继承 environ 会把别人的密钥永久
    // 烤进 sidecar 环境。启动期基底 + **本 app 的 .env**（本 app 的键对 JSP/Jetty、
    // ruby sidecar 等可见；别人的请求期临时值一律不继承）。
    crate::server::apps::env_lock::apply_clean_env(&mut cmd, env_vars);
    cmd.current_dir(&docroot)
        .env("WEBSERVER_LISTEN_UNIX", sock.display().to_string())
        // 与 h1 `native_http::ensure_sidecar` 同一套 env：sidecar（ruby 等）据此
        // 兜底剥离路由前缀。此前 h2/h3 这条 spawn 路径漏了它，同一 sidecar 由 h1 起
        // 与由 h2 起拿到的环境不同（版本间不一致）。
        .env("WEBSERVER_APP_PREFIXES", app.paths.join(","))
        .env("WEBSERVER_WORKERS", app.workers.max(1).to_string())
        .env("DOCUMENT_ROOT", docroot.display().to_string())
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log_file));
    let mut child = crate::server::apps::child_registry::spawn_tracked(
        &mut cmd,
        &format!("native sidecar {key} (simple)"),
    )
    .with_context(|| format!("spawn sidecar {}", deps_bin.display()))?;

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if sock_alive(&sock) {
            // 先落 `.env` 指纹再进表：h1 侧拿同一把 per-sock 锁后会读它核验。
            native_http::write_sidecar_env_fp(&sock, fp, child.id());
            SIDECARS_SIMPLE.lock().insert(
                key,
                SimpleSidecar {
                    sock: sock.clone(),
                    child,
                    env_fp: fp,
                    docroot: docroot.clone(),
                },
            );
            return Ok(sock);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    // 超时必须收拾刚拉起的子进程（Child 被 drop 不会终止进程）。
    crate::server::apps::child_registry::kill_child(&mut child);
    bail!(
        "native sidecar sock not ready: {} (see {}; spawned child killed)",
        sock.display(),
        log_path.display()
    )
}

#[cfg(unix)]
fn abs_path(p: &std::path::Path) -> std::path::PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(p)
    }
}

#[cfg(unix)]
fn abs_canon(p: &std::path::Path) -> std::path::PathBuf {
    let a = abs_path(p);
    std::fs::canonicalize(&a).unwrap_or(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 上游响应必须过滤 hop-by-hop/Connection 点名的头，并丢弃与实际 body 不符的
    /// Content-Length；其余头（Set-Cookie 等）原样保留。
    #[test]
    fn upstream_response_filters_hop_by_hop_and_bad_cl() {
        let (parts, _) = Response::builder()
            .status(200)
            .header("transfer-encoding", "chunked")
            .header("connection", "keep-alive, x-internal")
            .header("keep-alive", "timeout=5")
            .header("x-internal", "secret")
            .header("content-length", "999")
            .header("set-cookie", "a=1")
            .body(())
            .unwrap()
            .into_parts();
        let r = upstream_response(parts, Bytes::from_static(b"hello")).unwrap();
        assert!(r.headers().get("transfer-encoding").is_none());
        assert!(r.headers().get("connection").is_none());
        assert!(r.headers().get("keep-alive").is_none());
        assert!(r.headers().get("x-internal").is_none(), "Connection 点名的头必须过滤");
        assert!(r.headers().get("content-length").is_none());
        assert_eq!(r.headers().get("set-cookie").unwrap(), "a=1");

        // CL 恰等于真实长度时保留（HEAD 场景仍能给出实体长度）。
        let (parts, _) = Response::builder()
            .status(200)
            .header("content-length", "5")
            .body(())
            .unwrap()
            .into_parts();
        let r = upstream_response(parts, Bytes::from_static(b"hello")).unwrap();
        assert_eq!(r.headers().get("content-length").unwrap(), "5");
    }

    #[test]
    fn hop_by_hop_list_is_complete() {
        for h in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(is_hop_by_hop(h), "{h} 应为 hop-by-hop");
        }
        assert!(!is_hop_by_hop("content-type"));
        assert!(is_client_forward_header("x-forwarded-for"));
        assert!(!is_client_forward_header("x-custom"));
    }

    /// `.env` → 头通道的编码/过滤/上限（与 apps5b 真机实测逐条对齐）。
    #[test]
    fn env_forward_headers_encodes_filters_and_caps() {
        let v = |k: &str, val: &str| (k.to_string(), val.to_string());
        let out = env_forward_headers(&[
            v("A", "hello world"),
            v("B", "a\"b"),
            v("C", "中"),
            v("EMPTY", ""),     // 空值 = 键不存在 ⇒ 不转发
            v("HAS-DASH", "x"), // 非法键（- 不是 env 键字符）⇒ 不转发
        ]);
        assert_eq!(
            out,
            vec![
                ("x-crucible-env-a".to_string(), "hello%20world".to_string()),
                ("x-crucible-env-b".to_string(), "a%22b".to_string()),
                ("x-crucible-env-c".to_string(), "%E4%B8%AD".to_string()),
            ]
        );
        // 头名过滤只要求 `[A-Za-z0-9_]`（数字开头也放行）：`.env` 解析器（deps.rs）已经把
        // `1BAD=x` 这类键拒掉了，这里不必重复一条会在两处漂移的规则。
        assert_eq!(
            env_forward_headers(&[v("1BAD", "x")]),
            vec![("x-crucible-env-1bad".to_string(), "x".to_string())]
        );
        // 76 个键 → 恰好 64 条（上限生效，且无重复头名）
        let many: Vec<(String, String)> = (0..76)
            .map(|i| (format!("K{i}"), format!("v{i}")))
            .collect();
        let out = env_forward_headers(&many);
        assert_eq!(out.len(), 64, "64 键上限");
        let mut names: Vec<&String> = out.iter().map(|(n, _)| n).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 64, "不允许同名头");
    }

    /// `.env` 里仅大小写不同的键：HTTP 头名不区分大小写 ⇒ 必须**去重**，语义为
    /// 「值相同只发一条；值不同保留先出现者」（P3 明确语义，见 `env_forward_headers`）。
    #[test]
    fn env_forward_headers_dedups_case_only_collisions() {
        let v = |k: &str, val: &str| (k.to_string(), val.to_string());
        // 值相同：只一条，无副作用
        let out = env_forward_headers(&[v("KEY", "same"), v("key", "same"), v("Key", "same")]);
        assert_eq!(out, vec![("x-crucible-env-key".to_string(), "same".to_string())]);
        // 值不同：保留先出现的 KEY（.env 顺序），后出现的大小写变体丢弃
        let out = env_forward_headers(&[v("KEY", "first"), v("key", "second")]);
        assert_eq!(out, vec![("x-crucible-env-key".to_string(), "first".to_string())]);
        // 反向顺序同样「先出现者胜」
        let out = env_forward_headers(&[v("key", "lower-first"), v("KEY", "upper-second")]);
        assert_eq!(
            out,
            vec![("x-crucible-env-key".to_string(), "lower-first".to_string())]
        );
        // 编码后再比较也不能漏判（同一原值不同大小写 + 非 ASCII 值）
        let out = env_forward_headers(&[v("M", "a b"), v("m", "a%20b")]);
        assert_eq!(out.len(), 1, "原值不同（一个空格、一个字面 %20）必须判为冲突: {out:?}");
        assert_eq!(out[0].1, "a%20b");
        // 大小写不同但值真的不同 → 仍然是单条（不会出现两条同名头）
        let out = env_forward_headers(&[v("Db_Password", "p1"), v("db_password", "p2")]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], ("x-crucible-env-db_password".to_string(), "p1".to_string()));
    }

    /// 嵌入判据：DT_NEEDED / shim 常量里的 `libruby<版本>.so` 命中；诚实失败 stub
    /// 的报错文本（`libruby（…）`、`/libruby`）不命中。
    #[test]
    fn libruby_soname_detection_separates_embed_from_stub() {
        for s in [
            &b"DT_NEEDED libruby-3.3.so.3.3"[..],
            b"x libruby34.so y",
            b"/usr/local/lib/libruby34.so.0.0",
            b"libruby.so.3.4",
            b"libruby.so",
        ] {
            assert!(image_has_libruby_soname(s), "应判为嵌入: {:?}", String::from_utf8_lossy(s));
        }
        for s in [
            // rack_engine.c 的诚实失败文本（编译进 stub .so）
            &b"need ruby.h and libruby (scripts/build_script_ffi.sh) libapp_rack.so"[..],
            b"libruby\xef\xbc\x88scripts/build_script_ffi.sh\xef\xbc\x89",
            b"/libruby\x00",
            b"libruby",
            b"libapp_rack.so",
        ] {
            assert!(!image_has_libruby_soname(s), "应判为 stub: {:?}", String::from_utf8_lossy(s));
        }
    }

    fn rack_app_with_paths(paths: &[&str]) -> AppRouteConfig {
        AppRouteConfig {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            enabled: true,
            engine: "rack".into(),
            socket: None,
            extensions: vec![],
            index: Some("index.ru".into()),
            php_bin: None,
            workers: 4,
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

    /// Rack 内部路径头：剥前缀、保留目录请求的真实路径（不替换成 index）、
    /// percent-encode（头值里不能出现非 ASCII/空格/换行）。
    #[test]
    fn rack_path_header_keeps_real_path() {
        let app = rack_app_with_paths(&["/rack"]);
        assert_eq!(rack_path_header_value(&app, "/rack/"), "%2F");
        assert_eq!(rack_path_header_value(&app, "/rack/foo"), "%2Ffoo");
        assert_eq!(rack_path_header_value(&app, "/rack/a/b/"), "%2Fa%2Fb%2F");
        assert_eq!(rack_path_header_value(&app, "/rack/a b"), "%2Fa%20b");
        assert_eq!(rack_path_header_value(&app, "/other/x"), "%2Fother%2Fx");
        // URL 编码在宿主侧解一次：`%2e%2e` → `..`（sidecar 的穿越判据必须看得到）
        assert_eq!(rack_path_header_value(&app, "/rack/%2e%2e/x"), "%2F..%2Fx");
        // 双重编码只解一层（`%252e` → `%2e`，不是 `.`）
        assert_eq!(
            rack_path_header_value(&app, "/rack/%252e%252e"),
            "%2F%252e%252e"
        );
        // 尾斜杠写法同义
        let app = rack_app_with_paths(&["/rack/"]);
        assert_eq!(rack_path_header_value(&app, "/rack/foo"), "%2Ffoo");
    }
}
