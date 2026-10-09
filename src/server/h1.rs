//! HTTP/1.1 request handler (hyper 1.x).

use crate::config::ListenerConfig;
use crate::server::apps;
use crate::server::live_config::LiveConfig;
use crate::server::prefixed_stream::PrefixedStream;
use crate::server::static_files;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;


/// HSTS header value (RFC 6797) — applied to all HTTPS responses.
///
/// 只发 `max-age`。**不带** `includeSubDomains` / `preload`：规格 §16 并未要求 HSTS，
/// 更未要求子域覆盖；而 `includeSubDomains` 会把策略强加到本服务**并不托管**的
/// 兄弟子域上（例如本机托管 `www.example.com`，而 `mail.example.com` 在别处且无 TLS），
/// 浏览器据此对这些子域做**不可绕过的**硬失败。多站点正是本项目的核心场景，
/// 默认值不能替运营方扩大作用域。需要子域覆盖的站点可在 page_rules 的响应头里
/// 自行追加（HSTS 的写入已统一为 `entry().or_insert`，不会覆盖显式设置的值）。
pub fn hsts_header() -> &'static str {
    "max-age=31536000"
}

/// Host 头是否「像个主机名」——用于 port_reuse 明文口构造 301 Location。
///
/// 只需挡住明显不像主机名的输入（含空格、斜杠、`@`、`?`、`#`、控制字符），
/// 避免把客户端可控的 Host 原样拼进 Location 造成开放重定向。
/// 允许字母/数字/`.`/`-`/`_`，以及 IPv6 字面量的 `[` `]` `:`。
fn is_plausible_hostname(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let bracketed = h.starts_with('[') && h.ends_with(']');
    h.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'-' | b'_')
            || (bracketed && matches!(b, b'[' | b']' | b':'))
    })
}

/// 从 `Host` 头值里取出主机名部分（去掉可选端口），供 port_reuse 301 拼 Location。
///
/// 此前用 `split(':').next()`：IPv6 字面量 `[::1]:8080` 会被截成 `[`（非法主机名）
/// ⇒ 301 退化成相对路径跳转。这里对 `[...]` 形式取到配对的 `]` 为止。
fn host_without_port(h: &str) -> &str {
    let h = h.trim();
    if let Some(rest) = h.strip_prefix('[') {
        return match rest.find(']') {
            Some(i) => &h[..i + 2], // '[' + inner + ']'
            None => h,
        };
    }
    h.split(':').next().unwrap_or("").trim()
}

/// port_reuse 明文口 301 的 `Location` 路径归一化（RFC 3986 §5.2.4 的简化实现）。
///
/// 为什么必须做：`req.uri().path_and_query()` 是**未规范化**的客户端输入。两个后果：
///   1. **开放重定向**：当本 listener 未配 `server_name`、且请求没有可用的 `Host`
///      （HTTP/1.0、或 absolute-form 缺 Host）时，`host` 退化为 `None`，代码回的是
///      **相对路径** —— 而 `//evil.example/x` 这种「双斜杠开头」的相对引用在浏览器里是
///      **协议相对 URL**，会被解析成 `https://evil.example/x`。301 还是**永久**缓存的。
///   2. 语义可疑路径（`/a/../b`、多重斜杠）被原样写进 Location 并被永久缓存。
///
/// 处理：丢弃空段（折叠 `//`）与 `.` 段，逐段处理 `..`（弹栈，不越过根），
/// 保留尾斜杠与 query；**不做 percent-decode**（Location 里必须是合法 URI，
/// 解码后再拼会把 `%20` 变成裸空格）。归一化后路径必以单个 `/` 开头，不可能再是
/// 协议相对 URL。
fn normalize_redirect_path(path_and_query: &str) -> String {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
    // asterisk-form（`OPTIONS *`）不是可重定向的路径，归到根。
    if path == "*" || path.is_empty() {
        let mut s = "/".to_string();
        if let Some(q) = query {
            s.push('?');
            s.push_str(q);
        }
        return s;
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut s = format!("/{}", out.join("/"));
    if path.ends_with('/') && !s.ends_with('/') {
        s.push('/');
    }
    if let Some(q) = query {
        s.push('?');
        s.push_str(q);
    }
    s
}

/// HTTP/1.1 的 `Host` 头校验（RFC 9112 §3.2）。
///
/// hyper 的 h1 server **不校验** Host：缺 Host / 多个 Host / 非法值都会被正常服务。
/// 而本服务的 Host 是路由与安全输入（DoH 按 Host 白名单分流、port_reuse 301 的 Location、
/// admin 同源判定、反代回源 Host），多 Host 头时 `HeaderMap::get` 取第一行，前置代理/缓存
/// 常取最后一行 ⇒ 前后端路由结论分叉（经典请求走私 / 缓存投毒面），同时也是明确的 RFC 违规。
/// 规则：
///   - 出现 **多于一行** Host ⇒ 拒绝（任何版本）；
///   - HTTP/1.1 且请求目标是 origin-form / asterisk-form（URI 无 authority）时**缺 Host** ⇒ 拒绝；
///     absolute-form（`GET http://host/ …`）允许省略 Host（用 URI 的 authority，RFC 9112 §3.2.2）；
///   - Host 值非法（含空白/控制字符/`@`、`/`、`\`、`?`、`#`、`,` 等，或端口非数字）⇒ 拒绝。
/// HTTP/1.0 及更早不要求 Host（仅「多行」一条仍生效）。
fn host_header_ok(req: &Request<Incoming>) -> bool {
    let n = req
        .headers()
        .get_all(http::header::HOST)
        .iter()
        .count();
    if n > 1 {
        return false;
    }
    // 字段值只要**存在**就必须合法：RFC 9112 §3.2 的「a Host header field with an
    // invalid field value ⇒ 400」不区分 HTTP 版本。此前 HTTP/1.0 在「多行」检查之后
    // 直接 return true，于是 HTTP/1.0 带 `Host: a b` / `Host: host:99999` 一律被服务 ——
    // 而 Host 同时是 DoH 分流、port_reuse 301 与 admin 同源判定的输入，不该有版本差。
    if let Some(v) = req.headers().get(http::header::HOST) {
        match v.to_str() {
            Ok(s) => {
                if !is_valid_host_value(s) {
                    return false;
                }
            }
            // 含不可见字节（to_str 失败）：非法
            Err(_) => return false,
        }
    }
    // RFC 9112 §3.2.2：absolute-form（`GET http://host/…`）时，origin server **必须**
    // 忽略 Host 头、以请求目标的 authority 为准。此前实现两者各自独立判定、从不比对，
    // 于是 `GET http://a.example/ HTTP/1.1` + `Host: b.example` 被原样接受：
    // 前置缓存/代理按 authority（a.example）建键，本服务却按 Host（b.example）做
    // DoH 分流 / admin 同源 / port_reuse 301 —— 前后端路由结论分叉（缓存投毒面）。
    // 保守处置：两者**明确冲突**时回 400（合法代理按 RFC 要么不带 Host、要么与
    // authority 一致；缺省端口 80/443 的差异不视为冲突）。放在 HTTP/1.0 早退之前，
    // 使该判据不区分版本。
    if let Some(auth) = req.uri().authority() {
        if let Some(hv) = req.headers().get(http::header::HOST) {
            if let Ok(h) = hv.to_str() {
                if !authority_matches_host(auth.as_str(), h) {
                    return false;
                }
            }
        }
    }
    // h1 处理链上版本只可能是 HTTP/1.0 或 HTTP/1.1；HTTP/1.0 不要求 Host 存在。
    if req.version() == http::Version::HTTP_10 {
        return true;
    }
    if n == 0 {
        // absolute-form 目标自带 authority，可无 Host；其余形式必须有。
        return req.uri().authority().is_some();
    }
    true
}

/// absolute-form 的 `authority` 与 `Host` 头是否一致（RFC 9112 §3.2.2 的比对）。
///
/// 大小写不敏感、忽略尾点；端口缺省时按 http(80)/https(443) 归一，避免把
/// 「`Host: a.example` vs authority `a.example:80`」这种等价写法误判为冲突。
fn authority_matches_host(authority: &str, host: &str) -> bool {
    /// 拆出 (host, Option<port>)，lowercase、去尾点、IPv6 字面量按 `[...]` 处理。
    fn split(a: &str) -> (String, Option<u16>) {
        let a = a.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(rest) = a.strip_prefix('[') {
            if let Some(i) = rest.find(']') {
                let h = a[..i + 2].to_string(); // '[' + inner + ']'
                let p = a[i + 2..]
                    .strip_prefix(':')
                    .and_then(|x| x.parse::<u16>().ok());
                return (h, p);
            }
        }
        match a.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                (h.to_string(), p.parse::<u16>().ok())
            }
            _ => (a, None),
        }
    }
    let (ah, ap) = split(authority);
    let (hh, hp) = split(host);
    if ah != hh {
        return false;
    }
    match (ap, hp) {
        (None, None) => true,
        // 一方缺省：只有对端是 80/443（默认端口）时才视为同一 authority。
        (Some(p), None) | (None, Some(p)) => p == 80 || p == 443,
        (Some(x), Some(y)) => x == y,
    }
}

/// `port = *DIGIT`（RFC 3986 §3.2.3）：非空、纯数字，且必须落在 u16 范围。
///
/// 此前只查「纯数字」，于是 `Host: example.com:99999` 被判合法 —— 超范围端口没有任何
/// 意义，属 RFC 9112 §3.2 的「invalid field value」（应 400）。解析上限防溢出：
/// 超过 10 位数字时 `parse::<u32>()` 直接失败，同样按非法处理。
fn port_value_ok(p: &str) -> bool {
    !p.is_empty()
        && p.bytes().all(|b| b.is_ascii_digit())
        && p.parse::<u32>().map(|n| n <= 65535).unwrap_or(false)
}

/// `Host` 字段值合法性：`host [":" port]`，host 为域名 / IPv4 / IPv6 字面量。
///
/// 保守校验：挡住空白、控制字符、userinfo（`@`）、路径分隔符等会造成歧义的值；
/// 不追求严格 DNS 语法（保留 `_`，避免误伤带下划线的内部主机名）。
fn is_valid_host_value(v: &str) -> bool {
    if v.is_empty() || v.len() > 255 || v != v.trim() {
        return false;
    }
    let host = if let Some(rest) = v.strip_prefix('[') {
        // IPv6 字面量 `[ ... ]`，其后可选 `:port`。字面量本体交给 std 解析：
        // 此前只查「十六进制数字 + `:` + `.`」，于是 `[....]`、`[:]`、`[:::]` 这类
        // 根本解析不出地址的值也算合法（Host 会被 DoH 白名单/admin 同源判定消费）。
        let Some(end) = rest.find(']') else {
            return false;
        };
        if rest[..end].parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        let after = &rest[end + 1..];
        if after.is_empty() {
            return true;
        }
        let Some(p) = after.strip_prefix(':') else {
            return false;
        };
        return port_value_ok(p);
    } else {
        match v.split_once(':') {
            Some((h, p)) => {
                if !port_value_ok(p) {
                    return false;
                }
                h
            }
            None => v,
        }
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        // 纯标点的「主机名」（`.` / `..` / `-` / `_`）不是主机：RFC 3986 的 reg-name
        // 允许这些字符，但没有任何一个合法主机名不含字母数字。放行它们会让
        // `Host: ..` 之类进入 port_reuse 301 的 Location（`https://../`）与 DoH 分流。
        && host.bytes().any(|b| b.is_ascii_alphanumeric())
}

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

/// admin 请求体缓冲上限：admin::handle 侧本就全量缓冲 body（写文件/读 TOML），
/// 入口统一收齐并设上限，防 DoS；32MiB 足够 config 文本/证书/常规管理上传。
pub const ADMIN_BODY_CAP: usize = 32 * 1024 * 1024;
/// h2/h3 引擎/admin 请求体缓冲上限（P1-9）：不排空 body 会卡住 H2/H3 流量控制。
pub const REQUEST_BODY_CAP: usize = 8 * 1024 * 1024;
/// 应用引擎（php/FFI 等）请求体缓冲上限（任务 6 OOM 防护）：覆盖常见上传配置。
pub const APP_BODY_CAP: usize = 32 * 1024 * 1024;
/// 反代上游请求/响应缓冲上限（任务 6 OOM 防护）。
pub const UPSTREAM_BODY_CAP: usize = 64 * 1024 * 1024;

pub async fn serve(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    serve_io(TokioIo::new(stream), live, lc, peer).await
}

/// 请求头读取超时：客户端连上后「挤牙膏」式发头部会把连接长期占住任务与 socket
/// （slowloris）。hyper 的 header_read_timeout 只覆盖「读完整请求头」这段，
/// 之后的请求体读取与 keep-alive 长连接不受影响（不改 keep-alive 语义）。
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// 请求体读取的**空闲**超时（两次 body 帧之间），与 h2 的 `H2_BODY_IDLE_TIMEOUT`
/// 同语义、同取值 —— 跨协议行为必须一致。
///
/// 为什么必须有：h2 早就用这个上限把「发合法头 + 声明大 Content-Length + 挤牙膏式
/// 送 body」的 slowloris 挡成 408；h1 此前只在收口处做 `Limited::collect()`，
/// **完全没有超时** —— 匿名客户端可以用一个连接（1 个 fd + 1 个任务）无限期占住
/// 内存缓冲（admin 32MiB / proxy 64MiB），并发几百条就是可远程触发的内存与连接耗尽。
/// 这是「头读有 30s 超时、体读无超时」的自身不一致，也是 h1/h2 的跨协议不一致。
const BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// 单个请求的头部条数上限：几十万行头部是廉价的内存/CPU 放大面。
const MAX_HEADERS: usize = 100;

/// 同 [`serve_tls`]，但**允许半关闭**（对端发完请求就 FIN）。
///
/// 为什么需要单独一个入口：hyper 的 `allow_half_close` 默认为 **false**，
/// 此时「消息在途中读到 EOF」会直接报 `IncompleteMessage`（
/// `proto/h1/conn.rs::mid_message_detect_eof`）—— 哪怕请求头已经收全。
/// **QMux 上这是常态**：客户端把 FIN 与请求数据放在同一条记录里一起发出，
/// 于是 hyper 在派发响应之前就看到了 EOF，连接被判失败（表现为「连上了但什么都不发生」）。
/// TCP 侧保持原行为不变（现网客户端不会在同一时刻半关闭），需要时再单独评估。
pub async fn serve_tls_half_close<IO>(
    stream: IO,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_io_opts(TokioIo::new(stream), live, lc, peer, true).await
}

pub async fn serve_with_prefix(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    prefix: &[u8],
) -> Result<()> {
    serve_peek(stream, live, lc, peer, prefix.to_vec()).await
}

async fn serve_peek(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    prefix: Vec<u8>,
) -> Result<()> {
    let io = PrefixedStream::new(stream, prefix);
    serve_io(TokioIo::new(io), live, lc, peer).await
}

#[cfg(feature = "tls")]
pub async fn serve_tls<IO>(
    stream: IO,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_io(TokioIo::new(stream), live, lc, peer).await
}

async fn serve_io<IO>(
    io: TokioIo<IO>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_io_opts(io, live, lc, peer, false).await
}

/// `serve_io` 的真正实现；`half_close` 见 [`serve_tls_half_close`] 的说明。
async fn serve_io_opts<IO>(
    io: TokioIo<IO>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
    half_close: bool,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 建连时的 listener 代数。下面整条连接（keep-alive 上的每个请求）都用**这一份** `lc`
    // —— 也就是说 `root`/`basic_auth`/`page_rules`/`file_open`/限流 这些 per-listener 策略
    // 改了之后，对**已建立**的连接不会生效（只有新连接拿到新配置）。
    // 改 `basic_auth` 的口令却「改了没生效」是安全相关的过期状态，所以这里做一件最小的事：
    // 发现 listener 配置变过，就在响应上写 `Connection: close` —— 本请求仍按旧策略服务
    // （不改变正在处理的语义），之后连接关闭，客户端下一次请求会走新的 accept 路径拿到新配置。
    // 与 nginx reload 关掉 keepalive 同一语义；只在 listener 指纹真的变了时才触发。
    let gen0 = live.listeners_generation();
    // `lc` 为整条连接（keep-alive 上的每个请求）共享且**不可变**：放进 `Arc` 之后
    // service 闭包每请求只做一次引用计数克隆，而不是 `ListenerConfig` 的深拷贝
    // （address/root/http_versions/apps/file_open/page_rules… 一串 String/Vec 的堆分配，
    // 纯静态站点每请求也要 ~4 次 malloc/free）。语义不变：连接存活期内 listener 策略
    // 本就固定（配置变更由下面的 generation 检测触发 Connection: close）。
    let lc = Arc::new(lc);
    let svc = service_fn(move |req: Request<Incoming>| {
        let live = Arc::clone(&live);
        let lc = Arc::clone(&lc);
        async move {
            let mut resp = handle_request(req, live.clone(), lc, peer).await;
            if live.listeners_generation() != gen0 {
                resp.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
            }
            Ok::<_, std::convert::Infallible>(resp)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    // 设了 header_read_timeout 就**必须**给 Timer：否则 hyper 在每个连接上
    // panic（common/time.rs: "timeout set, but no timer set"）—— 实测那样会让
    // 整个 h1 监听口失效（accept 任务被杀，9095/9081 全停）。
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_headers(MAX_HEADERS);
    if half_close {
        builder.half_close(true);
    }
    // **必须用 `.with_upgrades()`**：`serve_connection` 返回的 `Connection` 在遇到
    // `Dispatched::Upgrade` 时只调用 `pending.manual()`（hyper-1.11.1
    // `server/conn/http1.rs`）——给服务端持有的 `OnUpgrade` future 回
    // `Err("upgrade expected but low level API in use")`，**不执行升级**。
    // 于是 `proxy_websocket` 里 `upgrade.await` 拿到 Err、隧道任务什么都不做，
    // hyper 写完 101 就关连接 —— 客户端收到 101 后**立即 EOF、零隧道字节**
    // （WebSocket 反代端到端 100% 失效）。只有 `UpgradeableConnection`
    // （`.with_upgrades()`）才在 101 分支 `pending.fulfill(...)` 把 IO 交给服务端。
    // 注：hyper-1.11.1 的 `Builder` 上**没有** `serve_connection_with_upgrades`。
    builder.serve_connection(io, svc).with_upgrades().await?;
    Ok(())
}

pub async fn handle_request(
    req: Request<Incoming>,
    live: Arc<LiveConfig>,
    lc: Arc<ListenerConfig>,
    peer: SocketAddr,
) -> Response<BoxBody> {
    // P1-11：访问日志在响应完成侧统一记录全字段（时间/method/status/bytes/duration/engine），
    // 请求入口拿不到 status/bytes/duration；engine 标签由各 dispatch 分支经 extensions 注入。
    let t0 = std::time::Instant::now();
    // 只保留**借用得到的最小副本**供收口处的访问日志使用：
    // `http::Method` 对标准方法（GET/POST/…）是廉价枚举拷贝，不分配；`http::Uri` 的
    // path-and-query 存的是 `Bytes`，克隆只增引用计数、不分配。此前两者都
    // `.to_string()`，等于每请求白付两次堆分配（GET/HEAD 静态热路径上最常见）。
    let method = req.method().clone();
    let path0 = req.uri().clone();
    let is_https = lc.ssl.is_some();
    // §16.12：每站访问日志覆盖（`[listeners.access_log]`）必须在 `lc` 被 move 进
    // handle_request_inner 之前取出——收口处的全字段日志在响应完成侧，那时已经没有 lc。
    // `None` = 完全继承全局 `[access_log]`。
    let access_override = lc.access_log.clone();
    // 配置快照**只取一次**：请求判定（handle_request_inner）与收口处的访问日志共用
    // 同一份 `Arc<Config>`。旧实现两处各自 `live.snapshot()`（每次一把 RwLock 读锁 +
    // Arc 克隆），访问日志那一份纯属多余 —— 请求路径上白付一次锁 + 原子操作。
    let snap = live.snapshot();
    let mut resp = handle_request_inner(req, Arc::clone(&live), Arc::clone(&snap), lc, peer).await;
    // 大文件（static 层的 FileSource 标记）在这里换成真正的流式 body：这是所有
    // 分支（acl/admin/apps/proxy/static/upload…）回包的**唯一**收口点。
    // 用 extensions 传来源而不是改 body 类型，是为了不动其它 ~30 处 `Response<BoxBody>`
    // 构造点；代价只是每个协议要在自己的发送路径上认这个标记。
    if let Some(src) = resp
        .extensions_mut()
        .remove::<crate::server::static_files::FileSource>()
    {
        *resp.body_mut() = stream_file(src);
    }
    // P1-7：所有 HTTPS 响应统一补 HSTS。此前只在 dispatch_tail 之后加，telemetry/
    // geoip/DoH/acl 拒绝/限速/basic_auth/admin/status/rule/proxy 等提前返回分支全部漏掉。
    // entry().or_insert 不覆盖分支已显式设置的值。
    if is_https {
        resp.headers_mut()
            .entry(http::header::STRICT_TRANSPORT_SECURITY)
            .or_insert_with(|| http::HeaderValue::from_static(hsts_header()));
    }
    let engine = resp
        .extensions()
        .get::<crate::server::access_log::EngineTag>()
        .map(|t| t.0)
        .unwrap_or("http");
    // 响应体字节数：`size_hint().exact()` 对已知长度的 body（Bytes/Full/文件）返回真实值，
    // 流式/分块 body 返回 None（日志里显示 `-`）。此前这里硬编码 None，导致 h1 访问日志的
    // bytes 字段**恒为 `-`**，而 h2/h3 两条路径都已经在记真实长度 —— 同一字段随协议而异。
    let resp_bytes = hyper::body::Body::size_hint(resp.body()).exact();
    // 复用上面那份快照（不在这里再 snapshot 一次，见 handle_request 顶部说明）。
    // 末尾传本 listener 的 §16.12 访问日志覆盖（None = 继承全局）。
    crate::server::access_log::log_response_with(
        &snap,
        peer,
        "h1",
        method.as_str(),
        path0.path(),
        resp.status().as_u16(),
        resp_bytes,
        t0.elapsed(),
        engine,
        access_override.as_ref(),
    );
    resp
}

async fn handle_request_inner(
    req: Request<Incoming>,
    live: Arc<LiveConfig>,
    snap: Arc<crate::config::Config>,
    lc: Arc<ListenerConfig>,
    peer: SocketAddr,
) -> Response<BoxBody> {
    // RFC 9112 §3.2：HTTP/1.1 缺 Host / 多行 Host / 非法 Host 值一律 400。
    // hyper 不代劳（见 host_header_ok 注释），必须在**任何路由判定之前**挡掉，
    // 否则 Host 会被 DoH 分流 / admin 同源 / port_reuse 301 当成可信输入。
    if !host_header_ok(&req) {
        return tag(
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full("bad request: invalid or missing Host header"))
                .unwrap(),
            "h1",
        );
    }
    // RFC 9112 §6.1/§6.3：同时出现 Transfer-Encoding 与 Content-Length 的请求
    // 「应当」按错误处理（请求走私 / 响应拆分面）。hyper 已在解析层处理：以 TE 为准，
    // **并把 Content-Length 从 HeaderMap 里删掉**（role.rs：`is_cl && con_len.take()` /
    // `if is_te { continue }`），同时强制 `keep_alive=false`。因此服务层看不到 CL，
    // 无法再补一个显式 400；hyper 的「只按 TE 处理 + 关连接」正是 RFC 允许的处置之一。
    // 这里不重复校验（曾试过 contains_key(CONTENT_LENGTH)，实测恒不成立 —— 见报告）。

    let path = req.uri().path().to_string();
    crate::server::telemetry::record_request();

    // GeoIP 公共 API：`try_handle_public` 目前是恒 `None` 的 stub（安全策略：GeoIP API
    // 只在 admin 面板鉴权后暴露）。旧实现每请求都 `.await` 一个必然立即返回 `None` 的
    // future（建状态机 + poll）；这里按它的文档契约（“when `geoip.enabled`”）加一道
    // 廉价闸门。当前语义不变（stub 恒 None）；若将来把它接成真实路由，注意 h2/h3 也从未
    // 调用过它，接线时三协议要同改。
    if snap.geoip.enabled {
        if let Some(resp) = crate::server::admin_geoip::try_handle_public(&req, &live).await {
            return tag(resp, "geoip");
        }
    }

    // 请求路径：IP access → rate limit → metrics → DoH → basic auth → page_rules → admin → apps → proxy → static
    //
    // DoH 必须排在 ACL/限速**之后**：此前它排在前面，等于任何能连上 TLS 口的人
    // 都绕过监听器 IP 白名单与限速，白拿一个公共递归解析器（DoS/滥用放大器）。
    // 同时它排在 basic_auth 之前——DoH 客户端（浏览器/系统解析器）无法交互式
    // 提供 Basic 凭据，要求它会直接让 DoH 不可用。
    // §16.1：per-listener `[listeners.ip_access]` 必须与全局 `[ip_access]` 合并判定
    // （两份都放行才放行）。此前这里只判全局 `snap.ip_access`，于是 listener 档位里
    // 收窄的白名单在 **h1 路径上完全不生效**（h2/h3 已由 agent-h2h3 接线）—— 功能缺陷。
    // `ip_allowed` 内部先判全局、再判 `lc.ip_access`（None 等价于旧行为）。
    if !crate::server::listener::ip_allowed(&snap.ip_access, &lc, peer) {
        let (st, msg) = crate::server::access::deny_response();
        return tag(
            Response::builder().status(st).body(full(msg)).unwrap(),
            "acl",
        );
    }

    if let Some(rl) = &lc.rate_limit {
        if rl.enabled {
            let ok = if rl.per_path {
                crate::server::rate_limit::allow_path(
                    peer.ip(),
                    &path,
                    rl.rate_per_sec,
                    rl.burst,
                )
            } else {
                crate::server::rate_limit::allow(peer.ip(), rl.rate_per_sec, rl.burst)
            };
            if !ok {
                let (st, msg) = crate::server::rate_limit::deny_response();
                return tag(
                    Response::builder().status(st).body(full(msg)).unwrap(),
                    "acl",
                );
            }
        }
    }

    // /__metrics 必须排在 ip_access + 限流**之后**：此前它是本函数的第一个分支，
    // 于是「用 IP 白名单当边界」的部署把指标（请求总数、活跃 H3 流）暴露给任何人。
    // 位置与 DoH 对齐——排在 basic_auth **之前**：listener 口令与「谁能抓指标」是两件事，
    // 指标的门在 telemetry 内部按 [admin].metrics_public 判定（默认要求管理员凭据）。
    if let Some(resp) =
        crate::server::telemetry::maybe_handle(&req, &snap.telemetry, &snap.admin, peer.ip())
    {
        return tag(resp, "telemetry");
    }

    // DoH（RFC8484，需求 9）：按 Host/路径分流；未命中（非 DoH 域名）原样放行，
    // 保证同一 443 上正常 HTTPS 站点不受影响。
    //
    // **RFC 8484 §5：DoH 必须走 https。** 此前无条件调用 `h1_try_handle`（它不看
    // listener 是否 TLS），于是**明文口**上的 `/dns-query` 也被当成 DoH 正常应答
    // （200 + DNS 报文）—— 任何能连上明文口的人都白拿一个递归解析器，也违反 MUST。
    // 现在只在 TLS listener 上放行 DoH；明文口上若确实是 DoH 请求，回 4xx
    // （port_reuse 明文口例外：交由下面的 301 重定向到 https，那是该口的既定语义）。
    let req = if lc.ssl.is_some() {
        match crate::server::dns::dot_doh::h1_try_handle(req, &snap, peer).await {
            Ok(r) => return tag(r, "dns-doh"),
            Err(req) => req,
        }
    } else {
        if !lc.port_reuse {
            let dns_eff = crate::server::dns::effective(&snap);
            if crate::server::dns::dot_doh::is_doh_request(
                &dns_eff,
                req.uri().path(),
                req.headers().get(http::header::HOST),
            ) {
                return tag(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(full("DoH requires HTTPS (RFC 8484 section 5)"))
                        .unwrap(),
                    "dns-doh",
                );
            }
        }
        req
    };

    // P2-21（任务 4）：admin 暴露面——[admin].listeners_allow 非空时仅列出的端口可达
    // （防止 Basic 凭据在明文 listener 上线传输；空 = 兼容旧行为全端口可达）。
    //
    // 位置必须与 h1/h2/h3 保持一致：**早于 listener 级 basic_auth**（h2/h3 的收 body
    // 前置门里就是「ACL → listeners_allow → CSRF → admin 门」这个顺序）。此前 h1 把它
    // 放在 listener basic_auth 之后，于是「端口不在白名单 + 该口又配了 listener 口令」
    // 时会先回 401 —— 浏览器立刻弹出 Basic 口令框，等于把一个本该完全不可见的口
    // 变成凭据输入面；h2/h3 在同一场景回的是 404。白名单的语义是「这个口根本没有
    // 管理面」，所以 404 必须先生效。
    let is_admin = crate::server::access::is_admin_path(&snap.admin.path, &path);
    if is_admin && !snap.admin.listener_allowed(lc.port) {
        return tag(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("not found"))
                .unwrap(),
            "acl",
        );
    }

    // listener 级 Basic Auth 对 **admin 路径跳过**：admin 面板有自己的鉴权 realm
    // （`[admin.users]`）。此前 listener 级校验排在前，于是「同一端口既配了站点
    // `basic_auth` 又开了面板」时，客户端只能带**一个** `Authorization` 头 —— 满足了
    // 站点 realm 就过不了 admin realm，满足了 admin realm 就过不了站点 realm，
    // 结果是**面板在该端口恒 401 不可达**（h1/h2/h3 一致）。admin 路径的安全性由
    // `admin_gate`（fail-closed：无用户/无口令哈希一律拒，见 basic_auth 文末）保证，
    // 跳过 listener 口令不会降低面板的门槛，只是让两个 realm 各自生效。
    // h2/h3 由 agent-h2h3b 同步同一处语义。
    let listener_ba = if is_admin { None } else { lc.basic_auth.as_ref() };
    if let Some(ba) = listener_ba {
        match crate::server::basic_auth::check_listener(&req, ba, peer.ip()) {
            crate::server::basic_auth::BasicCheck::Ok => {}
            crate::server::basic_auth::BasicCheck::Unauthorized => {
                return tag(
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(
                            http::header::WWW_AUTHENTICATE,
                            format!("Basic realm=\"{}\"", ba.realm),
                        )
                        .body(full("unauthorized"))
                        .unwrap(),
                    "acl",
                )
            }
            // 失败退避（见 basic_auth 文末）：回 429 + Retry-After，且这一档**不跑**
            // 口令哈希——否则并发错口令依旧每次烧一次 argon2，退避只是个摆设。
            crate::server::basic_auth::BasicCheck::Throttled(d) => {
                return tag(
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header(
                            http::header::RETRY_AFTER,
                            crate::server::basic_auth::retry_after_secs(d).to_string(),
                        )
                        .body(full("too many failed authentication attempts"))
                        .unwrap(),
                    "acl",
                )
            }
        }
    }

    // P2-8（§16.18）：status_path 接线——此前只解析配置无服务逻辑（status_page.html 孤儿）。
    // 放在 ip_access/rate_limit/basic_auth 之后：状态页尊重访问控制。
    if lc.status_path.as_deref() == Some(path.as_str()) {
        return tag(
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(full(include_str!("status_page.html")))
                .unwrap(),
            "status",
        );
    }

    // 早期规格 5：端口复用口（port_reuse 且非 TLS listener）上的明文 HTTP 请求
    // 统一返回 HSTS 头 + 301 到 https://{host}/，防不支持 HSTS 的客户端钉死明文。
    if lc.port_reuse && lc.ssl.is_none() {
        let raw_host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(host_without_port)
            .unwrap_or("")
            .to_string();
        // 不做开放重定向：Host 是客户端可控的，直接拼进 Location 就等于
        // 把 https://evil.example 回给用户（钓鱼/凭据窃取面）。
        // 优先用本 listener 配置的 server_name；否则仅在 Host 看起来是合法主机名时
        // 才采用，否则退化成纯相对路径跳转。
        let host = match lc.server_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(sn) => Some(sn.to_string()),
            None => {
                if is_plausible_hostname(&raw_host) {
                    Some(raw_host)
                } else {
                    None
                }
            }
        };
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| normalize_redirect_path(p.as_str()))
            .unwrap_or_else(|| "/".to_string());
        let target = match host {
            Some(h) => format!("https://{h}{pq}"),
            None => pq,
        };
        // **不 unwrap**：`target` 里含请求的 `Host`（虽已被 is_plausible_hostname 过滤）。
        // 万一它仍不能作为 header 值，宁可降级成「不带 Location 的 301」，也不要在
        // hyper 的 service future 里 panic —— 那会直接丢掉这条连接。
        let mut resp = match Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(http::header::LOCATION, target.as_str())
            .header(
                http::header::STRICT_TRANSPORT_SECURITY,
                hsts_header(),
            )
            .body(full("moved to https"))
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("port_reuse 301: Location 头非法（{e}），降级为无 Location 的 301");
                Response::builder()
                    .status(StatusCode::MOVED_PERMANENTLY)
                    .body(full("moved to https"))
                    .unwrap()
            }
        };
        resp.extensions_mut()
            .insert(crate::server::access_log::EngineTag("hsts"));
        return resp;
    }

    // admin：在 ip_access / rate limit / basic auth 之后、页面规则改写之前
    //
    // 复用上面（listeners_allow 判定处）已算出的 `is_admin`：`path` 与 `snap.admin.path`
    // 在这两点之间都不变（路径改写发生在本判定**之后**），而 `is_admin_path` 内部每次都要
    // `format!("{}/", …)` 一次堆分配 —— 这里省掉每请求一次多余分配与字符串比较。
    if is_admin {
        // CSRF 补强（详见 access::cross_site_blocked）：admin.rs 的检查缺 `Origin` 时
        // 整段跳过、且 GET 从不带 `Origin`，这里用浏览器自写的 Sec-Fetch-Site 拒跨站。
        // 与 h2/h3 同序：先判跨站（403），再判鉴权（401/429）。
        if crate::server::access::cross_site_blocked(req.headers()) {
            let (st, msg) = crate::server::access::cross_site_response();
            return tag(Response::builder().status(st).body(full(msg)).unwrap(), "acl");
        }
        // 鉴权门必须放在**收 body 之前**：admin::handle 的第一步才是鉴权，而这里
        // 一旦先收满 body（上限 32MiB），一个不带凭据的并发 POST 就能让每个连接各占
        // 32MiB —— 不用通过鉴权（或随便带个垃圾凭据）就能放大内存占用。
        // 门内做的就是完整鉴权（含失败退避），因此未经校验的请求一个字节 body 都不收；
        // admin::handle 里那次同凭据的校验会命中 basic_auth 的成功备忘（见该处说明），
        // 所以合法管理请求**只跑一次** argon2id，换来的是「任意垃圾凭据也能占住
        // 32MiB/请求」这条放大路径被彻底掐掉。
        match crate::server::basic_auth::admin_gate(req.headers(), &snap.admin, peer.ip()) {
            crate::server::basic_auth::AdminGate::Proceed => {}
            crate::server::basic_auth::AdminGate::Unauthorized => {
                return tag(
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(
                            http::header::WWW_AUTHENTICATE,
                            format!("Basic realm=\"{}\"", snap.admin.realm),
                        )
                        .body(full("unauthorized"))
                        .unwrap(),
                    "acl",
                )
            }
            crate::server::basic_auth::AdminGate::Throttled(d) => {
                return tag(
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header(
                            http::header::RETRY_AFTER,
                            crate::server::basic_auth::retry_after_secs(d).to_string(),
                        )
                        .body(full("too many failed authentication attempts"))
                        .unwrap(),
                    "acl",
                )
            }
        }
        // P1-4：admin::handle 统一吃 Request<Full<Bytes>>——admin 侧本就全量缓冲 body，
        // 入口收齐（32MiB 上限）后 h2/h3 才能复用同一处理函数（API 不再只回 UI shell）。
        //
        // 收 body **之前**先按声明的 Content-Length 廉价拒绝：CL 已超上限时直接 413，
        // 既不读 body，也不会回 100 Continue（见 `content_length_too_large`）。
        if content_length_too_large(req.headers(), ADMIN_BODY_CAP) {
            return tag(
                body_read_response(BodyReadErr::TooLarge, "admin request body too large"),
                "acl",
            );
        }
        let (parts, body) = req.into_parts();
        let bytes = match collect_body_capped(body, ADMIN_BODY_CAP).await {
            Ok(b) => b,
            Err(e) => {
                return tag(
                    body_read_response(e, "admin request body too large"),
                    "acl",
                )
            }
        };
        let mut resp = crate::server::admin::handle(
            Request::from_parts(parts, Full::new(bytes)),
            live,
        )
        .await;
        // 兜底记账：失败计数/退避已在 admin_gate 完成，这里只在「过了门却仍回 401」
        // （两次校验之间配置被热重载）时补记一次，不重复清零。
        crate::server::basic_auth::note_admin_result(peer.ip(), resp.status());
        resp.extensions_mut()
            .insert(crate::server::access_log::EngineTag("admin"));
        return resp;
    }

    let mut req = req;
    // 页面规则（rewrite / redirect / block / pass / 响应头）**未配置时整段短路**：
    // 空规则表下这四个入口全部恒为 None/空，但旧实现每请求仍要构造 3 次 `MatchCtx`
    // （每次 `from_request`：method + URI authority/Host 头查找）并各跑一次空扫描 + 空
    // `Vec` 收集。`lc.page_rules` 为空是纯静态/纯反代站点的常态。
    let rules_on = !lc.page_rules.is_empty();
    // 改写之后必须以**新路径**做后续判定与分发。
    // 此前把改写前的 path 传进 dispatch_tail，于是 `would_handle`/`would_proxy` 判断的
    // 是一个路径、真正干活的 handler（apps::try_handle 内部自己重算 req.uri()）
    // 用的是另一个：改写命中时会错发 502「app dispatch returned empty」，
    // 或者把本该交给引擎的请求当静态文件发出去。
    //
    // 无 rewrite 命中时 `path` 不变，直接沿用已有的 owned String —— 省掉每请求一次
    // 多余的 `req.uri().path().to_string()` 堆分配（绝大多数请求都不带 rewrite 规则）。
    // rewrite 需要 method/host/header 判据；改完 URI 后引用失效 → 块内判定、块后重建。
    let mut path = path;
    if rules_on {
        {
            let pr_ctx = crate::server::page_rules::MatchCtx::from_request(&req);
            if let Some(np) = crate::server::page_rules::rewrite_path(&lc, &path, &pr_ctx) {
                let pq = match req.uri().query() {
                    Some(q) => format!("{np}?{q}"),
                    None => np,
                };
                if let Ok(u) = pq.parse() {
                    *req.uri_mut() = u;
                }
                path = req.uri().path().to_string();
            }
        }
        if let Some(resp) = crate::server::page_rules::apply(&lc, &req) {
            return tag(resp, "rule");
        }
        let pr_ctx = crate::server::page_rules::MatchCtx::from_request(&req);
        if let Some((murl, upstream)) = crate::server::page_rules::pass_upstream(&lc, &path, &pr_ctx)
        {
            // 反代本就全量缓冲 body：这里收齐后转 Full 交反代（语义不变，见 proxy.rs）。
            // 上限与 proxy.rs 一致（UPSTREAM_BODY_CAP）：无界 collect 会被超大 body 撑爆内存，
            // 使 proxy.rs 内部的上限形同虚设。
            // 收 body 前先按 Content-Length 廉价拒绝（避免 100 Continue / 白收）。
            if content_length_too_large(req.headers(), UPSTREAM_BODY_CAP) {
                return tag(
                    body_read_response(BodyReadErr::TooLarge, "request body too large"),
                    "proxy",
                );
            }
            let (parts, body) = req.into_parts();
            let bytes = match collect_body_capped(body, UPSTREAM_BODY_CAP).await {
                Ok(b) => b,
                Err(e) => return tag(body_read_response(e, "request body too large"), "proxy"),
            };
            let resp = crate::server::proxy::proxy_page_rule(
                Request::from_parts(parts, Full::new(bytes)),
                &murl,
                &upstream,
                peer.ip(),
                lc.ssl.is_some(),
            )
            .await;
            return tag(resp, "proxy");
        }
    }
    // 未配置页面规则时不再构造 `MatchCtx` / 跑空扫描（见上面 rules_on 的说明）。
    let resp_mods = if rules_on {
        let pr_ctx = crate::server::page_rules::MatchCtx::from_request(&req);
        crate::server::page_rules::response_headers(&lc, &path, &pr_ctx)
    } else {
        Vec::new()
    };
    // `lc` 此后只用于读 `ssl` 标志：先取出该标志，把 lc **移进** dispatch_tail，
    // 省掉每请求一次 `ListenerConfig` 深拷贝（address/root/http_versions/apps/
    // page_rules… 一串 String/Vec/PathBuf 的堆分配）。
    let is_https_local = lc.ssl.is_some();
    let mut resp = dispatch_tail(req, live, lc, peer, path).await;
    crate::server::headers_mod::apply_response(resp.headers_mut(), &resp_mods);
    // HTTPS responses get HSTS header (P1-7)
    if is_https_local {
        // 与 handle_request 收口处的写法**一致**（`entry().or_insert`）：不覆盖
        // page_rules / 分支已显式设置的 Strict-Transport-Security。此前这里用
        // `insert` 强制覆盖，而 apply_response 刚把 page_rules 的头写进去 ——
        // 于是「页面规则里自定义 HSTS」永远被静默丢弃（一旦 HSTS 变成可配置项就是
        // 实打实的 bug）。两处必须是同一套「默认值、可被显式设置覆盖」的语义。
        resp.headers_mut()
            .entry(http::header::STRICT_TRANSPORT_SECURITY)
            .or_insert_with(|| http::HeaderValue::from_static(hsts_header()));
    }
    resp
}

/// dispatch 分支打"响应由谁产出"标签，供访问日志 engine 字段使用。
fn tag(resp: Response<BoxBody>, engine: &'static str) -> Response<BoxBody> {
    let mut resp = resp;
    resp.extensions_mut()
        .insert(crate::server::access_log::EngineTag(engine));
    resp
}

async fn dispatch_tail(
    req: Request<Incoming>,
    live: Arc<LiveConfig>,
    lc: Arc<ListenerConfig>,
    peer: SocketAddr,
    path: String,
) -> Response<BoxBody> {
    // apps 为空时 `would_handle` 必然 false，但它会先做 `Path::extension` + 一次
    // `file_open_mode`（percent-decode + `Vec` + `format!` 的堆分配）。纯静态 listener
    // 每请求白付这次分配 —— 直接短路。
    if !lc.apps.is_empty() && apps::would_handle(&lc, &path) {
        let resp = apps::try_handle(req, &live, &lc, peer)
            .await
            .unwrap_or_else(|| {
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full("app dispatch returned empty"))
                    .unwrap()
            });
        return tag(resp, "app");
    }

    if would_proxy(&lc, &path) {
        // 反代本就全量缓冲 body：收齐后转 Full 交反代（行为不变）。
        // 上限与 proxy.rs 一致（UPSTREAM_BODY_CAP）：无界 collect 会被超大 body 撑爆内存。
        // 收 body 前先按 Content-Length 廉价拒绝（避免 100 Continue / 白收）。
        if content_length_too_large(req.headers(), UPSTREAM_BODY_CAP) {
            return tag(
                body_read_response(BodyReadErr::TooLarge, "request body too large"),
                "proxy",
            );
        }
        let (parts, body) = req.into_parts();
        let bytes = match collect_body_capped(body, UPSTREAM_BODY_CAP).await {
            Ok(b) => b,
            Err(e) => return tag(body_read_response(e, "request body too large"), "proxy"),
        };
        let req = Request::from_parts(parts, Full::new(bytes));
        if let Some((_matched, resp)) = crate::server::proxy::try_proxy(&lc, req, peer.ip()).await {
            return tag(resp, "proxy");
        }
        return tag(
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full("proxy rule matched but produced no response"))
                .unwrap(),
            "proxy",
        );
    }

    // §44 上传：仅当该路径开了 autoindex + enable_upload 时接管写方法。
    // 放在这里 = ACL / 限速 / basic_auth 都已完成，上传与静态下载享受同一套防护。
    if matches!(
        *req.method(),
        http::Method::PUT | http::Method::PATCH | http::Method::POST
    ) && crate::server::upload_api::enabled_for(&live, &lc, &path)
    {
        return tag(
            crate::server::upload_api::handle(req, &live, &lc, peer).await,
            "upload",
        );
    }
    match static_files::serve(&req, &lc).await {
        Ok(r) => tag(r, "static"),
        Err(_) => tag(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("not found"))
                .unwrap(),
            "static",
        ),
    }
}

fn would_proxy(lc: &ListenerConfig, path: &str) -> bool {
    // 必须与 `proxy::try_proxy` 用同一判据（带 `/` 边界）。无边界版本会把 `/apidocs`
    // 判成命中 `path = "/api"` 的规则，而 try_proxy 又拒绝匹配 ⇒ 502「rule matched but
    // produced no response」；`path = ""` 时更是整个 listener 全 502。
    lc.proxy_rules
        .iter()
        .any(|r| crate::server::proxy::path_matches_proxy_prefix(path, &r.path))
}

pub fn full(s: impl Into<Bytes>) -> BoxBody {
    Full::new(s.into()).boxed()
}

/// 按**声明的** `Content-Length` 做请求体上限的廉价前置拒绝。
///
/// 为什么要在收 body 之前单独判一次：`collect_body_capped` 只能等 body 帧陆续到达、
/// 累计超限时才回 413。对带 `Expect: 100-continue` 的客户端，hyper 会在**首次 poll
/// body** 时回 `100 Continue`（`conn.rs`）——于是「声明了超上限 CL」的请求会先收到
/// 100，被诱导把整个大 body 推上来，服务端也得一直接到超限那一刻。RFC 9110 §10.1.1
/// 允许服务端在已决定拒绝时**不发** 100：这里先按 CL 判一次，超限直接 413、不读 body，
/// hyper 也就不会发 100。chunked（无 CL）不受影响，仍走逐帧上限。
///
/// 多个 `Content-Length` 且值不一致的请求，hyper 在解析层已回 400（见 role.rs），
/// 到不了这里；值一致时 `get` 取第一行即代表全体。
fn content_length_too_large(headers: &http::HeaderMap, cap: usize) -> bool {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_some_and(|n| n > cap as u64)
}

/// [`collect_body_capped`] 的失败原因（决定回哪个状态码）。
enum BodyReadErr {
    /// 超过该路径的缓冲上限 ⇒ 413。
    TooLarge,
    /// 帧间空闲超过 [`BODY_IDLE_TIMEOUT`]（slowloris）⇒ 408。
    Timeout,
    /// 底层 body 读取错误（连接中断 / 分块解析失败）⇒ 400。
    Error,
}

/// 收齐请求体（≤ `cap`），带**帧间空闲超时**。
///
/// 与 h2 的 `collect_bytes` 同语义：`Ok` 拿到全部字节，`TooLarge` → 413，
/// `Timeout` → 408，`Error` → 400。超时是「两次 body 帧之间」的空闲上限，
/// **不是**整段 body 的总时长上限 —— 慢链路的大上传只要在持续推进就不会被误杀。
async fn collect_body_capped(mut body: Incoming, cap: usize) -> Result<Bytes, BodyReadErr> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match tokio::time::timeout(BODY_IDLE_TIMEOUT, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    if buf.len() + d.len() > cap {
                        return Err(BodyReadErr::TooLarge);
                    }
                    buf.extend_from_slice(d);
                }
            }
            Ok(Some(Err(_))) => return Err(BodyReadErr::Error),
            Ok(None) => return Ok(Bytes::from(buf)),
            Err(_) => return Err(BodyReadErr::Timeout),
        }
    }
}

/// [`collect_body_capped`] 失败 → 响应（状态码/文案按失败原因）。
fn body_read_response(e: BodyReadErr, too_large_msg: &'static str) -> Response<BoxBody> {
    match e {
        BodyReadErr::TooLarge => Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(full(too_large_msg))
            .unwrap(),
        BodyReadErr::Timeout => Response::builder()
            .status(StatusCode::REQUEST_TIMEOUT)
            .body(full("request body read timeout"))
            .unwrap(),
        BodyReadErr::Error => Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(full("request body read failed"))
            .unwrap(),
    }
}

pub fn empty() -> BoxBody {
    Full::new(Bytes::new()).boxed()
}

/// 大文件流式 body（>16MiB 的静态响应）：按 64KiB 分块从磁盘读，经 mpsc 交给 hyper。
///
/// 为什么用 mpsc：`tokio::fs::File::read` 的 future 借用 `&mut File`，直接塞进
/// `poll_frame` 会变成自引用结构；让后台任务读、body 只 poll 通道最省事，
/// 顺带得到背压（通道容量 2 帧 ⇒ 读盘不会跑到发送前面去）。
///
/// 错误处理：`BoxBody` 的 error 类型是 `Infallible`，而响应头此刻**已经发出**，
/// 读失败只能结束流 + 记日志（Content-Length 与实际不符时 hyper 会关闭连接，
/// 客户端据此判定传输失败 —— 唯一诚实的处理，不能改状态码了）。
pub fn stream_file(src: crate::server::static_files::FileSource) -> BoxBody {
    use crate::server::static_files::STREAM_CHUNK;
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(2);
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut f = match tokio::fs::File::open(&src.path).await {
            Ok(f) => f,
            Err(e) => {
                log::warn!("stream_file open {}: {e}", src.path.display());
                return;
            }
        };
        if src.start > 0 {
            if let Err(e) = f.seek(std::io::SeekFrom::Start(src.start)).await {
                log::warn!("stream_file seek {}: {e}", src.path.display());
                return;
            }
        }
        let mut left = src.len;
        let mut buf = vec![0u8; STREAM_CHUNK];
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            match f.read(&mut buf[..want]).await {
                Ok(0) => {
                    // 文件在传输中被截断：如实记日志并结束（不要死循环）
                    log::warn!("stream_file 提前 EOF（文件被截断？）{}", src.path.display());
                    break;
                }
                Ok(n) => {
                    left -= n as u64;
                    if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        return; // 接收端（body）已丢弃：客户端断开
                    }
                }
                Err(e) => {
                    log::warn!("stream_file read {}: {e}", src.path.display());
                    return;
                }
            }
        }
    });
    BoxBody::new(FileStreamBody {
        rx: parking_lot::Mutex::new(rx),
        len: src.len,
    })
}

/// [`stream_file`] 的 body 适配：把通道里的块当 DATA 帧发出去。
///
/// 接收端放在 `parking_lot::Mutex` 里是必须的：`tokio::sync::mpsc::Receiver` 是
/// `Send` 但**不是** `Sync`，而本 crate 的 [`BoxBody`] 别名是
/// `BoxBody<Bytes, Infallible>`（=`Send + Sync` 的 trait object）。
/// 锁只在 `poll_frame` 里短暂持有，且临界区内不 await，不会引入阻塞。
struct FileStreamBody {
    rx: parking_lot::Mutex<tokio::sync::mpsc::Receiver<Bytes>>,
    len: u64,
}

impl hyper::body::Body for FileStreamBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.rx.lock().poll_recv(cx) {
            std::task::Poll::Ready(Some(b)) => {
                std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b))))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// 精确长度：hyper 需要它来确认与 Content-Length 一致（否则可能改用 chunked）。
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9112 §3.2 Host 值合法性：合法主机名 / IPv4 / 端口 / IPv6 字面量通过；
    /// 空白、控制字符、userinfo、路径、非法端口一律拒绝。
    #[test]
    fn host_value_validation() {
        for ok in [
            "example.com",
            "localhost",
            "127.0.0.1",
            "127.0.0.1:8080",
            "apps-test.crucible.local",
            "host_name.internal",
            "[::1]",
            "[::1]:443",
            "[2001:db8::1]:8443",
        ] {
            assert!(is_valid_host_value(ok), "应接受合法 Host: {ok:?}");
        }
        for bad in [
            "",
            "a b",           // 空格（值被拆分）
            " a",            // 前导空白
            "a ",            // 尾随空白
            "a@b",           // userinfo
            "a/b",           // 路径分隔
            "a\\b",          // 反斜杠
            "a?b",           // query
            "a#b",           // fragment
            "a,b",           // 逗号（多值混淆）
            "host:",         // 空端口
            "host:abc",      // 非数字端口
            "host:80x",
            "[::1",           // 未闭合的 IPv6 字面量（缺 `]`）
            "[]",            // 空 IPv6 字面量
            "[::1]x",        // `]` 后非法字符
            // 端口必须是 u16（RFC 3986 §3.2.3）：超范围值没有任何意义，属非法字段值。
            "host:99999",
            "host:65536",
            "[::1]:99999",
            "[::1]:65536",
            // IPv6 字面量本体必须真能解析成地址（此前只查字符集）。
            "[....]",
            "[:]",
            "[:::]",
            "[1:2:3:4:5:6:7:8:9]",
            "[v1.abc]",
            // 纯标点不是主机名（没有任何字母数字）：`Host: ..` 此前被放行，会进入
            // port_reuse 301 的 Location（`https://../`）与 DoH 分流判定。
            "..",
            ".",
            "-",
            "_",
            "..:8080",
        ] {
            assert!(!is_valid_host_value(bad), "应拒绝非法 Host: {bad:?}");
        }
        // 端口边界：65535 合法、65536 非法。
        assert!(is_valid_host_value("host:65535"));
        assert!(!is_valid_host_value("host:65536"));
        for ok in ["[::ffff:1.2.3.4]", "[fe80::1]", "host:0", "host:00080"] {
            assert!(is_valid_host_value(ok), "应接受合法 Host: {ok:?}");
        }
    }

    /// port_reuse 301 的主机名提取：IPv6 字面量不能被 `split(':')` 截断。
    #[test]
    fn host_without_port_ipv6() {
        assert_eq!(host_without_port("example.com:8080"), "example.com");
        assert_eq!(host_without_port("example.com"), "example.com");
        assert_eq!(host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(host_without_port("[::1]"), "[::1]");
        assert_eq!(host_without_port(" [2001:db8::1]:443 "), "[2001:db8::1]");
        // 提取结果必须能通过「像主机名」判据（否则 301 会退化成相对路径）。
        assert!(is_plausible_hostname(host_without_port("[::1]:8080")));
    }

    /// port_reuse 301 的 Location 路径归一化：点段/多重斜杠被规范化，且**绝不能**
    /// 产生「双斜杠开头」的相对引用（浏览器会当成协议相对 URL → 开放重定向）。
    #[test]
    fn redirect_path_is_normalized_and_never_protocol_relative() {
        assert_eq!(normalize_redirect_path("/a/b"), "/a/b");
        assert_eq!(normalize_redirect_path("/a/../b"), "/b");
        assert_eq!(normalize_redirect_path("/a/./b"), "/a/b");
        assert_eq!(normalize_redirect_path("/../x"), "/x");
        assert_eq!(normalize_redirect_path("//evil.example/x"), "/evil.example/x");
        assert_eq!(normalize_redirect_path("/a//b///c"), "/a/b/c");
        assert_eq!(normalize_redirect_path("/dir/"), "/dir/");
        assert_eq!(normalize_redirect_path("/a?x=1&y=2"), "/a?x=1&y=2");
        assert_eq!(normalize_redirect_path("/a/../b?q=1"), "/b?q=1");
        assert_eq!(normalize_redirect_path("/"), "/");
        assert_eq!(normalize_redirect_path(""), "/");
        assert_eq!(normalize_redirect_path("*"), "/");
        // 归一化结果必须始终以单个 `/` 开头（相对引用不能是协议相对 URL）。
        for p in ["//x", "///x", "/../..//x", "/a/..", "*", ""] {
            let n = normalize_redirect_path(p);
            assert!(n.starts_with('/'), "{p:?} → {n:?} 必须以 / 开头");
            assert!(!n.starts_with("//"), "{p:?} → {n:?} 不能是协议相对 URL");
        }
    }

    /// RFC 9112 §3.2.2：absolute-form 的 authority 与 Host 头的一致性比对。
    #[test]
    fn absolute_form_authority_matches_host() {
        // 一致（大小写、尾点、默认端口归一）。
        assert!(authority_matches_host("a.example", "a.example"));
        assert!(authority_matches_host("A.Example", "a.example"));
        assert!(authority_matches_host("a.example.", "a.example"));
        assert!(authority_matches_host("a.example:8080", "a.example:8080"));
        assert!(authority_matches_host("a.example", "a.example:80"));
        assert!(authority_matches_host("a.example:443", "a.example"));
        assert!(authority_matches_host("[::1]:8443", "[::1]:8443"));
        assert!(authority_matches_host("[::1]", "[::1]"));
        // 冲突（host 不同 / 端口不同 / 非默认端口缺省）。
        assert!(!authority_matches_host("a.example", "b.example"));
        assert!(!authority_matches_host("a.example:8080", "a.example:9090"));
        assert!(!authority_matches_host("a.example:8080", "a.example"));
        assert!(!authority_matches_host("a.example", "a.example:8080"));
        assert!(!authority_matches_host("[::1]", "[::2]"));
        assert!(!authority_matches_host("[::1]:80", "[::2]:80"));
    }

    /// 收 body 前的廉价上限判据：CL 超 cap 才算超限；chunked/无 CL/非法 CL 不误判。
    #[test]
    fn content_length_precheck() {
        let mk = |v: &str| {
            let mut h = http::HeaderMap::new();
            h.insert(http::header::CONTENT_LENGTH, v.parse().unwrap());
            h
        };
        assert!(!content_length_too_large(&mk("0"), 100));
        assert!(!content_length_too_large(&mk("100"), 100));
        assert!(content_length_too_large(&mk("101"), 100));
        // chunked（无 CL）：不判超限（交给逐帧上限）。
        assert!(!content_length_too_large(&http::HeaderMap::new(), 100));
        // 非数字 CL：不在这里误判（hyper 解析层已处理非法 CL）。
        assert!(!content_length_too_large(&mk("abc"), 100));
    }
}
