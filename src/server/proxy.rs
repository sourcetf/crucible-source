//! Reverse proxy with Hyper client.
//!
//! Tor/.onion connect order:
//! 1. `CRUCIBLE_TOR_FFI_LIB` — optional dlopen stub (see [`try_tor_ffi_connect`]);
//!    if the library is missing or exports nothing usable, fall through.
//! 2. `CRUCIBLE_TOR_SOCKS_UNIX` — Unix-domain SOCKS5
//! 3. `CRUCIBLE_TOR_SOCKS` or `127.0.0.1:9050` — TCP SOCKS5
//!
//! The FFI path is a documented stub: Crucible does not ship a Tor client .so;
//! operators may point at an experimental helper that will later expose
//! `crucible_tor_connect`. Until then, SOCKS remains the supported path.
//!
//! §3：连接池默认禁用；connection_pool=true 时按
//! (host,port,scheme,h2,use_tor,ssl_mode,upstream_tls_version,tor_socks) 维度复用
//! 已建立的 SendRequest，各维度全量入键（不哈希截断，见 [`PoolKey`]），
//! 空闲上限 16，坏连接自动重建。
//!
//! # Onion TLS (`ssl_mode`)
//! For `.onion` hosts, [`onion_ca::validate_onion_upstream`] always runs.
//! Modes `verify` / `no_verify` / `trust_self_signed` wrap the SOCKS/TCP stream
//! in TLS (BoringSSL when `tls_boring`, else rustls). In `verify` mode the leaf
//! DER is checked with [`onion_ca::onion_cert_matches_host`]; if no peer cert
//! path is available the connection is rejected.

use crate::config::{ListenerConfig, ProxyRuleConfig};
use crate::server::apps::env_lock;
use crate::server::h1::{empty, full, BoxBody};

use once_cell::sync::Lazy;
use parking_lot::Mutex as PLMutex;
use std::collections::HashMap;

/// §3 连接池（每 upstream 目的地+scheme+h2+出口+TLS/HTTP 策略 维度，上限 16）。
const POOL_CAP: usize = 16;

/// 回源分阶段超时。此前整条链路一个 deadline 都没有：一个「接受连接但永不回包」
/// 的上游会永久占住请求、任务与缓冲（body 缓冲上限 64MiB/请求）。取值理由：
///
/// - connect 10s：TCP + SOCKS5 握手 + TLS 握手全在这一段。公网 RTT 在数十 ms 量级，
///   10s 对直连上游足够宽，又能在连不上时及时失败。
/// - **Tor 上游另给一份预算**（见 `UPSTREAM_CONNECT_TIMEOUT_TOR`）：tor 的 SOCKS 应答
///   会一直等到**电路建好**才返回，冷 tor 的第一条电路不属于「数秒量级」。
/// - head 30s：请求已发出、等响应头。上游可能要现做一次 RDAP/DB 查询，Tor 冷启动
///   首包常达 3–10s；30s 覆盖这类慢启动，又能把僵死上游在 30s 内踢掉。
/// - body 300s：响应体本身是合法的长时间传输（64MiB 上限对 300s 相当于
///   ≥218KB/s），所以这里只兜「一个字节都不再发」的上游，把总时长框住。
const UPSTREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// 走 Tor 的连接预算。
///
/// 为什么必须单独放宽：`do_socks5` 里的应答**不是**「握手完成」就回来 —— tor 会等到电路
/// 建好（甚至先取一次新的网络共识）才回 SOCKS5 应答，冷电路实测可超过 10s。本轮真机复现：
/// 一台刚启动的 tor 上，经我们反代取 `icanhazip.com` 直接吃满 10s 预算报
/// `upstream connect timed out after 10s`；同一个目标在电路热了之后 0.6~1.2s 就返回（curl
/// 走 tor 的 TCP SocksPort 对照也是 0.9~2.3s）。也就是说通用 10s 会把「tor 还在建电路」
/// 误判成上游故障，给 Tor 规则带来周期性 502 —— 而 tor 自身的 SOCKS 等待上限是三分钟量级。
const UPSTREAM_CONNECT_TIMEOUT_TOR: std::time::Duration = std::time::Duration::from_secs(45);
const UPSTREAM_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const UPSTREAM_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// 连接池键：把每个决定「这条请求能复用到哪条连接」的维度**原样**放进结构体，
/// 由字段比较/字段哈希定相等，**不做 64 位哈希截断**。
///
/// 此前是 `PoolKey(u64)`（DefaultHasher 各维度压成一个 u64）：池键决定复用到哪条
/// 上游连接，哈希一旦碰撞，取出的就是发往**另一个上游**（或另一套 TLS 策略）的连接
/// —— 与「复用」的语义完全不符，属安全问题而不只是命中率问题。字段集合没有变化，
/// 所以相等性语义与原来一致（同规则 → 同键 → 可复用，不会退化成每条请求都新建连接）。
#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    /// 目的地（host + port）：同 host 不同端口是不同上游。
    host: String,
    port: u16,
    /// `http` 与 `https` 决定是否起 TLS 握手，而同一 host:port 完全可能同时被
    /// `http://` 与 `https://` 两条规则指向；共用连接会把「要求 TLS」的请求
    /// 写进明文连接。
    scheme: String,
    /// 回源 HTTP 版本（显式配置或 ALPN 协商结果）：h2/h1 的 SendRequest 不可互换。
    h2: bool,
    /// 出口是否经 Tor。use_tor 必须进来：同一 host:port 经 Tor 与直连建立的是语义
    /// 完全不同的两条连接（此前这里传的是 `scheme == "https"`，参数名却是 use_tor
    /// —— 于是「经 Tor 的规则」会复用「直连规则」留下的连接，本该经 Tor 的请求从本机
    /// 直连发了出去，出口反了）。
    use_tor: bool,
    /// TLS 策略：两条规则可以指向同一 host:port 却要求不同校验档
    /// （verify / no_verify），共用连接会让 no_verify 建立的连接被 verify 规则复用，
    /// 把「要求校验」降级成「不校验」。存原始字符串：同义写法（大小写/空格）
    /// 只会少复用、不会错复用。
    ssl_mode: String,
    /// 回源 TLS 版本（None = 自动协商）：同 host:port 上 tls1.2 与 tls1.3
    /// 是两次不同的握手结果。
    tls_version: Option<String>,
    /// Tor SOCKS 端点：不同端点 = 不同电路/出口节点，出口 IP 不同，同样不能互相复用。
    tor_socks: Option<String>,
}

impl PoolKey {
    /// 池键维度：目的地 + scheme + HTTP 版本 + 出口（是否经 Tor、哪个 SOCKS）
    /// + TLS 策略/版本。少任何一个维度都可能把请求复用到语义不同的连接上（见各字段）。
    fn new(
        host: &str,
        port: u16,
        scheme: &str,
        h2: bool,
        use_tor: bool,
        ssl_mode: &str,
        tls_version: Option<&str>,
        tor_socks: Option<&str>,
    ) -> Self {
        Self {
            host: host.to_string(),
            port,
            scheme: scheme.to_string(),
            h2,
            use_tor,
            ssl_mode: ssl_mode.to_string(),
            tls_version: tls_version.map(str::to_string),
            tor_socks: tor_socks.map(str::to_string),
        }
    }
}

static POOL: Lazy<PLMutex<HashMap<PoolKey, Vec<UpSender>>>> =
    Lazy::new(|| PLMutex::new(HashMap::new()));

fn pool_give(key: PoolKey, sender: UpSender) {
    let mut p = POOL.lock();
    let q = p.entry(key).or_insert_with(Vec::new);
    if q.len() < POOL_CAP { q.push(sender); }
}

async fn pool_take(key: PoolKey) -> Option<UpSender> {
    POOL.lock().get_mut(&key).and_then(Vec::pop)
}
use crate::server::onion_ca::{
    is_onion_host, onion_cert_matches_host, validate_onion_upstream, OnionSslMode,
};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use bytes::Bytes;
use http::header::{CONNECTION, HOST, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::FromRawFd;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixStream};

/// Object-safe read+write stream for upstream TLS/plain TCP.
trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// Type-erased upstream byte stream (plain TCP or TLS).
struct UpstreamIo {
    inner: Pin<Box<dyn AsyncReadWrite>>,
    /// 上游 TLS 协商出的 ALPN 是否为 h2（规格 11：`upstream_http_version`
    /// 不配置时按 ALPN 自动选择回源 HTTP 版本）。
    negotiated_h2: bool,
    /// 「已经读进来但还没被消费」的字节 —— poll_read 时优先吐出。
    ///
    /// 为什么必须留着：读响应头（[`read_http_head`]）按 `\r\n\r\n` 切分，而一次 `read`
    /// 往往**同时带回响应头与正文起始字节**；升级 WebSocket（101）时那些字节就是上游的
    /// 首批 WS 帧。旧实现只解析 `..pos+4`、剩下的直接丢：隧道开头缺数据、WS 帧错位
    /// （客户端与上游都会解析失败），现象是「WS 连上但立刻报协议错」。
    leftover: Vec<u8>,
}

impl UpstreamIo {
    fn plain(tcp: TcpStream) -> Self {
        Self {
            inner: Box::pin(tcp),
            negotiated_h2: false,
            leftover: Vec::new(),
        }
    }

    fn from_tls<S>(s: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            inner: Box::pin(s),
            negotiated_h2: false,
            leftover: Vec::new(),
        }
    }
}

impl AsyncRead for UpstreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 先把上次多读出来的字节交出去，再读 socket。
        //
        // `remaining() == 0` 时必须直接返回：`ReadBuf::put_slice` 在容量不足时**panic**，
        // 而 hyper 的 h1 读循环会算出 `next = min(strategy.next(), max - len)`，某些缓冲
        // 状态下这一轮就是 0 —— 那时这里会带着 leftover 走进 put_slice，把任务打死。
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.remaining());
            let rest = self.leftover.split_off(n);
            buf.put_slice(&self.leftover);
            self.leftover = rest;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for UpstreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// RFC7230 §6.1：hop-by-hop 头不得转发（proxy_once 非 WS 路径剥除；响应侧同样）。
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// `Connection:` 里点名的头也是逐跳头（RFC 9110 §7.6.1）。固定名单盖不住对端自定义的
/// 逐跳头，所以剥除时要连这些 token 一起用。
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()).collect())
        .unwrap_or_default()
}

/// 规则（`modify_response_headers`）注入响应头时的禁用名单：HOP_BY_HOP 之外再加两个。
///
/// - `content-length`：报文定界头。规则写一个与真实 body 长度不符的值，客户端就会按
///   错误长度截断/粘连后续报文 —— 与请求方向的 TE/CL 走私同源，不能让配置侧凭空造。
/// - `host`：属请求方向，响应里出现只会误导客户端与中间缓存。
///
/// `Connection:` 点名的名字同样禁用（同一条逐跳语义）。其余 `set-cookie` /
/// `cache-control` / `content-type` / CSP 等是正常业务头，必须照常注入。
fn response_header_injectable(name: &HeaderName, conn_tokens: &[String]) -> bool {
    let l = name.as_str();
    !(HOP_BY_HOP.contains(&l)
        || l == "content-length"
        || l == "host"
        || conn_tokens.iter().any(|t| t.as_str() == l))
}

/// 应用规则里的 `modify_response_headers`：**替换**语义（同名只留一份、规则值胜出）
/// 且丢弃禁用头（见 [`response_header_injectable`]）。
///
/// 配置项名就是 “modify”（config.rs 亦写明 Inject/replace），语义应为覆盖：此前经由
/// response builder 的 `header()` 落下去是**追加**，客户端会同时收到上游旧值与规则新值
/// 两份同名头，而浏览器普遍取第一个 —— 管理员「改」了头却没生效。
fn apply_response_header_rules(
    headers: &mut HeaderMap,
    rule: &ProxyRuleConfig,
    conn_tokens: &[String],
) {
    for (k, v) in &rule.modify_response_headers {
        // 名字/值先按 HTTP 规范校验：含 CR/LF 的值会把「注入一个头」变成「注入任意个头
        // 或提前结束响应头」。非法项丢弃而不是让整条响应失败（响应体已经拿到了）。
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) else {
            continue;
        };
        if !response_header_injectable(&name, conn_tokens) {
            continue;
        }
        headers.insert(name, value);
    }
}

/// WebSocket 直写路径要跳过的头。与 HOP_BY_HOP 的区别：**保留** `upgrade`/`connection`
/// （缺了握手不成立），但报文定界相关的头一律不转发 —— 否则客户端可以同时带上
/// `Transfer-Encoding: chunked`，而我们会自己追加 `Content-Length`，
/// 上游就会同时看到 TE 与 CL，这正是 TE.CL 请求走私的形态。
/// 另外客户端自带的 X-Forwarded-* 也不转发，避免来源被伪造。
const WS_SKIP: &[&str] = &[
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
    "x-forwarded-for",
    "x-forwarded-proto",
];

pub async fn try_proxy(
    lc: &ListenerConfig,
    req: Request<Full<Bytes>>,
    peer_ip: IpAddr,
) -> Option<(bool, Response<BoxBody>)> {
    let path = req.uri().path().to_string();
    let client_https = lc.ssl.is_some();
    for rule in &lc.proxy_rules {
        if path_matches_proxy_prefix(&path, &rule.path) {
            match proxy_once(req, rule, peer_ip, client_https).await {
                Ok(r) => return Some((true, r)),
                Err(e) => {
                    // 不回显 `{e:#}`：那是**完整错误链**，里面有上游地址与端口、tor 的
                    // unix socket 路径、TLS 后端与库错误文本、超时预算等内网布局信息，
                    // 而拿到它的人只是任意一个能命中该规则的客户端。细节进本地日志。
                    log::warn!("proxy: 规则 {} 处理 {path} 失败: {e:#}", rule.path);
                    return Some((
                        true,
                        Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(full("502 Bad Gateway"))
                            .unwrap(),
                    ));
                }
            }
        }
    }
    None
}


/// Path prefix match that requires a boundary (end or `/`) to avoid `/api@evil` SSRF.
///
/// `pub(crate)`：h1/h2/h3 的 `would_proxy` 必须用**同一判据**。此前三个 dispatcher
/// 各自写了 `path.starts_with(&r.path)`（无边界），于是规则 `path = "/api"` 会把
/// `/apidocs/x` 也判成「归代理」，而 `try_proxy` 内部用的是带边界的版本 → 请求拿到
/// 502「proxy rule matched but produced no response」，而不是落到 static/apps/404。
/// 更糟的是手写配置里 `path = ""`（面板校验拒、`Config::validate` 不拒）在无边界时
/// **任何路径都 starts_with("")** ⇒ 整个 listener 全部 502。
pub(crate) fn path_matches_proxy_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    if prefix == "/" {
        return path.starts_with('/');
    }
    if path == prefix {
        return true;
    }
    let p = prefix.trim_end_matches('/');
    path.starts_with(p) && path[p.len()..].starts_with('/')
}

/// Join upstream base + rest（rest 里的 `@` 不能再造出 authority —— 见下面补 `/` 的说明）。
fn join_upstream(upstream: &str, rest: &str) -> Result<String> {
    let rest = if rest.is_empty() { "/" } else { rest };
    // **不再**因为 rest 含 `@` 就拒绝：`rest` 是「路径 + 查询串」，`@` 在两者里都很常见
    //（`/api/users/@me`、`?u=user@host`、`?next=mailto:a@b`），旧版把这些正常请求全打成
    // 502。它当年要防的是「用 `@` 再造一个 authority」，而下面「必须补 `/` 分隔符」那句
    // 已经把门关死：rest 一定以 `/` 开头，拼出的 URL 的 authority 就是 upstream 自己的。
    if rest.starts_with("//") {
        bail!("proxy refused protocol-relative suffix");
    }
    // Reject `http:` / `https:` absolute URLs sneaked into the path suffix.
    let lower = rest.to_ascii_lowercase();
    if lower.starts_with("http:") || lower.starts_with("https:") {
        bail!("proxy refused absolute URL suffix");
    }
    let upstream = upstream.trim_end_matches('/');
    // 必须补分隔符：`rest` 不一定以 '/' 开头 —— rule.path 以 '/' 结尾时
    // strip_prefix 会留下 `v1/x` 这样的尾巴，直接拼接会把尾巴并进 authority：
    // `http://backend` + `.evil.tld/x` 就是发给**攻击者指定的** `backend.evil.tld`
    // （只要他控制一个首标签匹配的域名）；上游带端口时拼出来是非法 URI，全部 502。
    let rest = if rest.starts_with('/') {
        rest.to_string()
    } else {
        format!("/{rest}")
    };
    Ok(format!("{upstream}{rest}"))
}

/// §11 回源 HTTP 版本枚举：统一 h1/h2 SendRequest 的 send_request 调用。
///
/// 只保留这一份定义。此前 proxy_once 里还有一份同名的局部 enum，于是模块级的
/// POOL/pool_give/pool_take（按它来声明类型）与真正创建连接的代码类型不同，
/// 池化永远接不上——这正是那三个符号一直没有调用者的原因。
enum UpSender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}
impl UpSender {
    async fn send_request(
        &mut self,
        req: Request<Full<Bytes>>,
    ) -> anyhow::Result<Response<hyper::body::Incoming>> {
        match self {
            UpSender::H1(s) => Ok(s.send_request(req).await?),
            UpSender::H2(s) => Ok(s.send_request(req).await?),
        }
    }

    /// 连接是否仍可复用（从池中取出前后各查一次）。
    fn is_ready(&self) -> bool {
        match self {
            UpSender::H1(s) => s.is_ready(),
            UpSender::H2(s) => s.is_ready(),
        }
    }
}

async fn proxy_once(
    req: Request<Full<Bytes>>,
    rule: &ProxyRuleConfig,
    peer_ip: IpAddr,
    client_https: bool,
) -> Result<Response<BoxBody>> {
    if is_websocket_upgrade(&req) {
        return proxy_websocket(req, rule).await;
    }

    let upstream = rule.upstream.trim_end_matches('/');
    let suffix = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let rest = suffix
        .strip_prefix(&rule.path)
        .or_else(|| suffix.strip_prefix(rule.path.trim_end_matches('/')))
        .unwrap_or(suffix.as_str());
    let target = join_upstream(upstream, rest)?;
    let uri = Uri::from_str(&target).context("upstream uri")?;

    let (host, scheme, port) = upstream_parts(&uri)?;

    let stream = connect_upstream(&host, port, &scheme, rule).await?;
    // 规格 11：未配置 upstream_http_version 时按上游 ALPN 协商结果自动选 h2/h1。
    let alpn_h2 = stream.negotiated_h2;
    let io = TokioIo::new(stream);

    // 规格 11：回源 HTTP 版本可配（h2 显式启用；不配置时按 ALPN 协商结果自动选）。
    // UpSender 定义在模块级（连接池 POOL 按它声明类型，两处必须同一个类型）。

    // 大小写/空白归一：面板与手写 TOML 里 `"H2"`、`" h2 "` 都是合法写法，
    // 而精确比较会让它们**静默**按 h1 处理（保存成功、行为不变 —— 最难查的一类）。
    let want_h2 = rule
        .upstream_http_version
        .as_deref()
        .map(|v| v.trim().eq_ignore_ascii_case("h2"))
        .unwrap_or(false)
        || (rule.upstream_http_version.is_none() && alpn_h2);
    let pool_key = PoolKey::new(
        &host,
        port,
        &scheme,
        want_h2,
        needs_tor(&host, rule),
        &rule.ssl_mode,
        rule.upstream_tls_version.as_deref(),
        rule.tor_socks.as_deref(),
    );
    // §3 连接池：仅当规则显式 `connection_pool = true` 时复用上游连接（默认关闭）。
    // 此前 POOL / pool_give / pool_take 三个都是死代码（无任何调用者），
    // 配置项开了也没有任何效果。
    let pooled = if rule.connection_pool {
        pool_take(pool_key.clone()).await
    } else {
        None
    };
    let mut sender = match pooled {
        Some(s) if s.is_ready() => s,
        _ => {
            if want_h2 {
                use hyper_util::rt::TokioExecutor;
                let (sender, conn) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                        .await
                        .context("upstream h2 handshake")?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                UpSender::H2(sender)
            } else {
                let (sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .context("upstream handshake")?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                UpSender::H1(sender)
            }
        }
    };

    let (parts, body) = req.into_parts();
    // 任务 6（OOM 防护）：上游请求体上限 64MiB；超限 → Err → 调用方 502。
    let bytes = http_body_util::Limited::new(body, crate::server::h1::UPSTREAM_BODY_CAP)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("read upstream request body: {e}"))?
        .to_bytes();
    // 先把「是不是 HEAD」记下来：`parts.method` 马上会被 move 进 builder，
    // 而响应侧判断上游 Content-Length 能不能透传时还要用它（HEAD 的 CL 描述 GET 体大小）。
    let req_is_head = parts.method == http::Method::HEAD;
    let mut builder = Request::builder().method(parts.method).uri(&uri);
    // hop-by-hop 头与 Connection 列名的头一律不上游（host 单独重写）。
    let conn_tokens: Vec<String> = parts
        .headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()).collect())
        .unwrap_or_default();
    for (k, v) in parts.headers.iter() {
        let kl = k.as_str().to_ascii_lowercase();
        if k == HOST || HOP_BY_HOP.contains(&kl.as_str()) || conn_tokens.iter().any(|t| *t == kl) {
            continue;
        }
        // XFF/XFP 由下面自行计算后注入。这里若把客户端那份也转发，
        // builder.header 是**追加**语义，上游会同时收到两份且客户端的排在前面 ——
        // 后端按「取第一个」解析时就被伪造了（例如明文口上谎称 X-Forwarded-Proto: https）。
        if kl == "x-forwarded-for" || kl == "x-forwarded-proto" {
            continue;
        }
        // 规则里 modify_request_headers 指定的头同理：交给下面统一注入，
        // 否则「注入/替换」语义退化成「客户端值在前 + 规则值在后」。
        if rule
            .modify_request_headers
            .keys()
            .any(|mk| mk.eq_ignore_ascii_case(&kl))
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder = builder.header(HOST, upstream_host_header(&host, port, &scheme));
    // 标准代理头注入：**只写我们自己看到的对端地址**。
    //
    // 旧实现是「客户端那份 + `, ` + peer_ip」（= nginx 的 $proxy_add_x_forwarded_for），
    // 也就是把**未认证客户端**提供的值当成信任链的第一跳；后端按惯例「取第一个」记日志/
    // 做 ACL 时，任何客户端都能用一行 `X-Forwarded-For: 1.2.3.4` 冒充来源 IP（本项目的
    // ip_access / GeoIP 就是按 IP 决策）。要接续上游代理链，应当显式配「受信代理白名单」，
    // 而不是无条件信任客户端。现在链上只有我们这一跳，语义明确。
    builder = builder.header("x-forwarded-for", peer_ip.to_string());
    builder = builder.header(
        "x-forwarded-proto",
        if client_https { "https" } else { "http" },
    );
    for (k, v) in &rule.modify_request_headers {
        // 与响应方向（response_header_injectable）对称：报文定界头与 authority 头不得由规则
        // 注入。`builder.header` 是**追加**语义，于是 `{"Host": "evil.tld"}` 会发出**两个**
        // Host；`{"Content-Length": N}` 会成为 hyper 的定界长度（与真实 body 不符时静默截断）；
        // `Connection: x` 让规则指定额外逐跳头，绕过我们在两个方向上的剥离。
        let Ok(name) = http::header::HeaderName::from_bytes(k.as_bytes()) else {
            log::warn!("proxy: 忽略规则里非法的请求头名 {k:?}");
            continue;
        };
        let l = name.as_str();
        if HOP_BY_HOP.contains(&l) || l == "content-length" || l == "host" {
            log::warn!("proxy: 忽略规则注入的请求头 {k:?}（定界头/authority/逐跳头不得注入）");
            continue;
        }
        builder = builder.header(k, v);
    }
    let upstream_req = builder
        .body(Full::new(bytes))
        .context("build upstream req")?;

    // 「发出请求 + 读到响应头」共用一段 deadline：hyper 的 send_request 在响应头
    // 到达（h1 解析完状态行与头，h2 收到 HEADERS 帧）时才 resolve，body 另行流式读。
    // 上游「收下连接但不回包」就卡在这里，没有这个 timeout 请求会永远挂着。
    let resp = tokio::time::timeout(UPSTREAM_HEAD_TIMEOUT, sender.send_request(upstream_req))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "upstream response head timed out after {}s",
                UPSTREAM_HEAD_TIMEOUT.as_secs()
            )
        })?
        .context("upstream send")?;
    let (rparts, rbody) = resp.into_parts();
    // 任务 6（OOM 防护）：上游响应体上限 64MiB。
    // 超时与上限互补：上限管「发太多」，超时管「一个字节都不发」（僵死上游）。
    // 已超时/出错的连接不还池（提前 return，sender 随作用域析构）。
    let rbytes = tokio::time::timeout(
        UPSTREAM_BODY_TIMEOUT,
        http_body_util::Limited::new(rbody, crate::server::h1::UPSTREAM_BODY_CAP).collect(),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "upstream response body timed out after {}s",
            UPSTREAM_BODY_TIMEOUT.as_secs()
        )
    })?
    .map_err(|e| anyhow::anyhow!("read upstream response body: {e}"))?
    .to_bytes();
    // 重建后的 body 长度：`rbytes` 马上会被 move 进 body，而响应头过滤要用这个值
    // 判断上游声明的 Content-Length 是否可信（见下面的说明）。
    let body_len = rbytes.len();
    let mut out = Response::builder()
        .status(rparts.status)
        .body(full(rbytes))
        .context("build upstream response")?;
    {
        // 响应侧同样剥 hop-by-hop（上游的 Connection/TE/Upgrade 透传会污染客户端）。
        // 除固定名单外，`Connection:` 点名的头同样是逐跳头：只看名单的话，上游用一行
        // Connection 就能让任意头（定界头也在内）原样透传到客户端。
        let conn_tokens = connection_tokens(&rparts.headers);
        let out_headers = out.headers_mut();
        for (k, v) in rparts.headers.iter() {
            let kl = k.as_str().to_ascii_lowercase();
            if HOP_BY_HOP.contains(&kl.as_str()) || conn_tokens.iter().any(|t| *t == kl) {
                continue;
            }
            // 上游声明的长度必须与**重建后**的 body 一致，否则不能透传。
            //
            // 这里的 body 是我们重新序列化出来的（`body(full(rbytes))`），而 hyper 的
            // 服务端按 **body 的长度**定界、却把用户给的头值**原样**写出去（一致性检查只在
            // debug_assertions 下）。于是上游只要回一个 `Transfer-Encoding: chunked` +
            // 谎报的 `Content-Length: N`（tor 规则下就是恶意线路端），客户端/中间缓存就会
            // 按 N 去读、把**多出来的字节当成下一条响应**——响应走私。配置方向的同类头
            //（response_header_injectable）早就拒了，漏的正是「上游那一份」。
            // HEAD 例外：它的 CL 描述的是 GET 体的大小，body 本就为空。
            if k == http::header::CONTENT_LENGTH
                && !req_is_head
                && v.to_str()
                    .ok()
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    != Some(body_len)
            {
                log::debug!(
                    "proxy: 丢弃上游 Content-Length（声明 {:?}，实际 {} 字节）",
                    v.to_str().unwrap_or("?"),
                    body_len
                );
                continue;
            }
            out_headers.append(k.clone(), v.clone());
        }
        apply_response_header_rules(out_headers, rule, &conn_tokens);
    }
    // 连接池：响应体已完整读完（H1 复用的前提），连接仍可用就放回池中。
    if rule.connection_pool && sender.is_ready() {
        pool_give(pool_key, sender);
    }
    Ok(out)
}

async fn proxy_websocket(
    req: Request<Full<Bytes>>,
    rule: &ProxyRuleConfig,
) -> Result<Response<BoxBody>> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let upgrade = hyper::upgrade::on(Request::from_parts(parts.clone(), Full::new(body_bytes.clone())));

    let (target, host, port, scheme) = resolve_upstream_target(&parts.uri, rule)?;
    let target_uri = Uri::from_str(&target).context("websocket upstream uri")?;
    let host_hdr = upstream_host_header(&host, port, &scheme);
    let mut upstream = connect_upstream(&host, port, &scheme, rule).await?;
    // 写握手请求 + 读 101 响应头共用一段 deadline：read_http_head 自身没有超时，
    // 上游若收下升级请求后不回包，这个任务会一直挂在这里（连接与两端口都被占住）。
    let (status, headers) =
        tokio::time::timeout(UPSTREAM_HEAD_TIMEOUT, async {
            write_raw_request(&mut upstream, &parts, &body_bytes, &host_hdr, &target_uri, rule).await?;
            read_http_head(&mut upstream).await
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "websocket upstream handshake timed out after {}s",
                UPSTREAM_HEAD_TIMEOUT.as_secs()
            )
        })??;
    if status != StatusCode::SWITCHING_PROTOCOLS {
        // Do not upgrade client unless upstream accepted the handshake.
        let mut out = Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(full(format!(
                "websocket upstream returned {status}, expected 101"
            )))
            .context("build websocket error response")?;
        // 与正常回源路径同一套注入语义（替换 + 丢弃定界/逐跳头）。
        apply_response_header_rules(out.headers_mut(), rule, &[]);
        return Ok(out);
    }

    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            let mut client = TokioIo::new(upgraded);
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
    });

    let mut out = Response::builder()
        .status(status)
        .body(empty())
        .context("build websocket 101 response")?;
    {
        // 101 的 Connection/Upgrade 必须由上游那份原样透传（缺了握手不成立），
        // 所以这里不做逐跳剥除；但规则注入的那一份仍按禁用名单过滤。
        let conn_tokens = connection_tokens(&headers);
        let out_headers = out.headers_mut();
        for (k, v) in headers.iter() {
            out_headers.append(k.clone(), v.clone());
        }
        apply_response_header_rules(out_headers, rule, &conn_tokens);
    }
    Ok(out)
}

fn is_websocket_upgrade(req: &Request<Full<Bytes>>) -> bool {
    let upgrade_ok = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let conn_ok = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    let key_ok = req.headers().get("sec-websocket-key").is_some();
    upgrade_ok && conn_ok && key_ok
}

fn resolve_upstream_target(
    uri: &Uri,
    rule: &ProxyRuleConfig,
) -> Result<(String, String, u16, String)> {
    let upstream = rule.upstream.trim_end_matches('/');
    let suffix = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let rest = suffix
        .strip_prefix(&rule.path)
        .or_else(|| suffix.strip_prefix(rule.path.trim_end_matches('/')))
        .unwrap_or(suffix.as_str());
    let target = join_upstream(upstream, rest)?;
    let parsed = Uri::from_str(&target).context("upstream uri")?;
    let (host, scheme, port) = upstream_parts(&parsed)?;
    Ok((target, host, port, scheme))
}

/// 从上游 URI 取 (host, scheme, port)。
///
/// 旧写法是 `uri.host().unwrap_or("127.0.0.1")`：相对形式（`/foo`、漏写 scheme 的
/// `backend:8080`）解析不出 host，于是被**静默**改成对本机 80 端口的请求 ——
/// 配置写错一个字符就从「转发到上游」退化成「打本机」。这里改成显式报错。
fn upstream_parts(uri: &Uri) -> Result<(String, String, u16)> {
    let host = uri
        .host()
        .with_context(|| format!("proxy upstream `{uri}` has no host (need http://host[:port] form)"))?
        .to_string();
    let scheme = uri
        .scheme_str()
        .with_context(|| format!("proxy upstream `{uri}` has no scheme (need http:// or https://)"))?
        .to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        bail!("proxy upstream scheme `{scheme}` is not supported (http/https only)");
    }
    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    Ok((host, scheme, port))
}

/// 是否必须经 Tor 出站（早期规格 A.1）。连接与连接池判定必须用同一份逻辑，
/// 否则会出现「建连接时走 Tor、复用时走直连」这种出口不一致。
fn needs_tor(host: &str, rule: &ProxyRuleConfig) -> bool {
    rule.via_tor || is_onion_host(host) || rule.ssl_mode.eq_ignore_ascii_case("tor")
}

/// 回源 Host 头的值（RFC 9110 §7.2：非默认端口必须写进 Host）。
///
/// `Uri::host()` 只给主机名，直接用它当 Host 会把 `http://backend:8080/` 写成
/// `Host: backend` —— 按 vhost + 端口挑站点的后端会挑不到（或落到默认站点），
/// h2 上游还会与我们自己填的 `:authority`（hyper 由 URI 生成，带端口）不一致。
fn upstream_host_header(host: &str, port: u16, scheme: &str) -> String {
    let default_port = if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 };
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// 连接阶段的预算选择：Tor 单独放宽（原因见 `UPSTREAM_CONNECT_TIMEOUT_TOR` 的说明）。
fn connect_budget(via_tor: bool) -> std::time::Duration {
    if via_tor {
        UPSTREAM_CONNECT_TIMEOUT_TOR
    } else {
        UPSTREAM_CONNECT_TIMEOUT
    }
}

async fn connect_upstream(
    host: &str,
    port: u16,
    scheme: &str,
    rule: &ProxyRuleConfig,
) -> Result<UpstreamIo> {
    let via_tor = needs_tor(host, rule);
    let budget = connect_budget(via_tor);
    // 连接阶段统一 deadline：TCP connect、SOCKS5 握手、TLS 握手都在这一段里，
    // 上游或 SOCKS 端「接受连接后不推进握手」会被这里掐断（future 一并取消）。
    tokio::time::timeout(budget, connect_upstream_inner(host, port, scheme, rule))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "upstream connect timed out after {}s ({host}:{port}{})",
                budget.as_secs(),
                if via_tor {
                    "，经 Tor：冷电路建路可能较慢，若持续超时请查 tor 的 notice.log"
                } else {
                    ""
                }
            )
        })?
}

async fn connect_upstream_inner(
    host: &str,
    port: u16,
    scheme: &str,
    rule: &ProxyRuleConfig,
) -> Result<UpstreamIo> {
    let mode = OnionSslMode::parse(&rule.ssl_mode);
    // 早期规格 A.1：走 Tor 的三种情形——显式 via_tor、.onion 目标、ssl_mode=tor。
    let is_onion = is_onion_host(host);
    if rule.ssl_mode.eq_ignore_ascii_case("tor") && !is_onion {
        bail!("ssl_mode=tor requires a .onion upstream host");
    }
    let via_tor = needs_tor(host, rule);

    // 校验 .onion 主机（verify 档要求 v3 pubkey）。
    if is_onion && !validate_onion_upstream(host, &rule.ssl_mode) {
        bail!(
            "invalid onion upstream host={host} ssl_mode={} (verify requires v3 .onion)",
            rule.ssl_mode
        );
    }

    // 走 Tor：FFI → unix SOCKS → TCP SOCKS（优先 rule.tor_socks，其次环境变量）。
    //
    // 此前这里是无条件 bail!("tor upstream not supported")，而「是否走 Tor」对任何
    // .onion 目标都为真——于是下面的 SOCKS 实现、以及 via_tor / ssl_mode=tor /
    // rule.tor_socks 三个配置项全部成了死代码，Tor 反代从未真正可用过。
    let tcp = if via_tor {
        connect_tor_socks(host, port, rule.tor_socks.as_deref()).await?
    } else {
        TcpStream::connect((host, port))
            .await
            .with_context(|| format!("connect {host}:{port}"))?
    };

    let want_tls = scheme.eq_ignore_ascii_case("https")
        || (is_onion && mode != OnionSslMode::Off);

    if !want_tls {
        if mode == OnionSslMode::Verify && is_onion {
            bail!("onion ssl_mode=verify requires TLS; cannot verify without a cert path");
        }
        return Ok(UpstreamIo::plain(tcp));
    }

    // 回源 ALPN 三态（此前只有「显式指定就完全不发 ALPN」两态，于是 `h2` 这个**文档化的
    // 配置项永远不可能工作**）：普通 TLS h2 上游（nginx/Caddy/Envoy）靠 ALPN 协商协议，
    // 不发 ALPN 时它按 HTTP/1.1 回话，而我们按 h2 起始帧（prior-knowledge 前奏）讲话 ⇒
    // 握手后立刻协议错、请求 502。
    //   * 显式 h2  → 只给 h2（不给上游挑 h1 的机会，我们只会说 h2）
    //   * 显式 h1  → 不发 ALPN
    //   * 未指定   → h2 + http/1.1（现状：按协商结果选 client conn）
    let alpn = match rule
        .upstream_http_version
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("h2") => UpstreamAlpn::H2Only,
        Some(_) => UpstreamAlpn::Off,
        None => UpstreamAlpn::Auto,
    };
    wrap_upstream_tls(
        tcp,
        host,
        mode,
        rule.upstream_tls_version.as_deref(),
        alpn,
    )
    .await
}

/// TLS wrap for HTTPS / onion upstreams. Onion `verify` checks leaf DER via
/// [`onion_cert_matches_host`]; missing peer-cert APIs reject the connection.
/// 回源 ALPN 策略（见调用点的说明）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UpstreamAlpn {
    /// 未指定回源 HTTP 版本：h2 + http/1.1，按协商结果选 client conn。
    Auto,
    /// 显式 `h2`：只提供 h2。
    H2Only,
    /// 显式 `h1`：不发 ALPN。
    Off,
}

async fn wrap_upstream_tls(
    tcp: TcpStream,
    host: &str,
    mode: OnionSslMode,
    tls_version: Option<&str>,
    alpn: UpstreamAlpn,
) -> Result<UpstreamIo> {
    #[cfg(feature = "tls_boring")]
    {
        return wrap_upstream_tls_boring(tcp, host, mode, tls_version, alpn).await;
    }
    #[cfg(all(feature = "tls_rustls", not(feature = "tls_boring")))]
    {
        let _ = alpn;
        return wrap_upstream_tls_rustls(tcp, host, mode, tls_version).await;
    }
    #[cfg(not(any(feature = "tls_boring", feature = "tls_rustls")))]
    {
        let _ = tcp;
        if mode == OnionSslMode::Verify && is_onion_host(host) {
            bail!(
                "onion ssl_mode=verify: no TLS client stack (need tls_boring or tls_rustls); \
                 cannot obtain peer certificate for onion_cert_matches_host"
            );
        }
        bail!(
            "HTTPS/.onion TLS upstream requires feature tls_boring or tls_rustls (host={host})"
        );
    }
}

#[cfg(feature = "tls_boring")]
async fn wrap_upstream_tls_boring(
    tcp: TcpStream,
    host: &str,
    mode: OnionSslMode,
    tls_version: Option<&str>,
    alpn: UpstreamAlpn,
) -> Result<UpstreamIo> {
    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

    let mut builder = SslConnector::builder(SslMethod::tls()).context("SslConnector builder")?;
    // 规格 11：回源 TLS 版本可配（tls1.2/tls1.3；不配=自动协商）。
    match tls_version.map(|v| v.to_ascii_lowercase().replace(['.', '_'], "")) {
        Some(ref v) if v == "tls12" || v == "tlsv12" => {
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        }
        Some(ref v) if v == "tls13" || v == "tlsv13" => {
            builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        }
        _ => {}
    }
    // Non-onion Verify: system CA verification. Onion + NoVerify/TrustSelfSigned: NONE
    // (onion still checks cert-as-pubkey after handshake).
    match mode {
        OnionSslMode::Verify if !is_onion_host(host) => {
            builder.set_verify(SslVerifyMode::PEER);
        }
        OnionSslMode::Verify | OnionSslMode::NoVerify | OnionSslMode::TrustSelfSigned => {
            builder.set_verify(SslVerifyMode::NONE);
        }
        OnionSslMode::Off => {}
    }
    let connector = builder.build();
    let mut config = connector.configure().context("ssl configure")?;
    // 规格 11「不配置时自动处理」：未显式指定回源 HTTP 版本时，用 ALPN 让上游
    // 自己选。ALPN 线格式是「1 字节长度 + 名字」序列。协商结果在握手后读回，
    // 据此决定用 h2 还是 h1 的 client conn。
    match alpn {
        UpstreamAlpn::Auto => {
            config
                .set_alpn_protos(&[2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'])
                .context("upstream set_alpn_protos")?;
        }
        UpstreamAlpn::H2Only => {
            config
                .set_alpn_protos(&[2, b'h', b'2'])
                .context("upstream set_alpn_protos")?;
        }
        UpstreamAlpn::Off => {}
    }
    // SNI: use host; for .onion Boring still accepts the name string.
    let mut tls = tokio_boring::connect(config, host, tcp)
        .await
        .with_context(|| format!("boring TLS connect to {host}"))?;

    if mode == OnionSslMode::Verify && is_onion_host(host) {
        let leaf_der = tls
            .ssl()
            .peer_certificate()
            .map(|c| c.to_der())
            .transpose()
            .context("peer cert to_der")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "onion ssl_mode=verify: no peer certificate available after TLS handshake"
                )
            })?;
        if !onion_cert_matches_host(&leaf_der, host) {
            bail!("onion ssl_mode=verify: peer certificate does not match .onion pubkey");
        }
        log::debug!("onion cert-as-pubkey verified for {host}");
    }

    let negotiated_h2 = tls
        .ssl()
        .selected_alpn_protocol()
        .map(|p| p == b"h2")
        .unwrap_or(false);
    if alpn != UpstreamAlpn::Off {
        log::debug!(
            "upstream {host}: ALPN {alpn:?} → {}",
            if negotiated_h2 { "h2" } else { "http/1.1" }
        );
    }
    let mut io = UpstreamIo::from_tls(tls);
    io.negotiated_h2 = negotiated_h2;
    Ok(io)
}

/// rustls client path (feature `tls_rustls`, when Boring is not the primary stack).
#[cfg(all(feature = "tls_rustls", not(feature = "tls_boring")))]
async fn wrap_upstream_tls_rustls(
    tcp: TcpStream,
    host: &str,
    mode: OnionSslMode,
    _tls_version: Option<&str>,
) -> Result<UpstreamIo> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    /// 支持的握手签名算法集合：取**已安装的** crypto provider（`main.rs` 里
    /// `rustls::crypto::ring::default_provider()`），拿不到再退回 ring 的默认值。
    ///
    /// 注意 rustls 0.23 的 `verify_tls1{2,3}_signature` 收的是 `&WebPkiSupportedAlgorithms`
    /// （0.22 那种传切片的形式已改），所以这里缓存的是整个结构体。
    fn verify_algs() -> &'static rustls::crypto::WebPkiSupportedAlgorithms {
        use std::sync::OnceLock;
        static ALGS: OnceLock<rustls::crypto::WebPkiSupportedAlgorithms> = OnceLock::new();
        ALGS.get_or_init(|| match rustls::crypto::CryptoProvider::get_default() {
            // WebPkiSupportedAlgorithms 是 Clone 而非 Copy（rustls 0.23）
            Some(p) => p.signature_verification_algorithms.clone(),
            None => rustls::crypto::ring::default_provider().signature_verification_algorithms,
        })
    }

    /// 校验 CertificateVerify 的签名（TLS1.2 / TLS1.3 各一个入口）。
    ///
    /// **为什么必须有**：这两个回调此前是 `HandshakeSignatureValid::assertion()` 的桩
    /// —— 即「握手签名一律不验」。在 `.onion` 的 `verify` 档下，攻击者只要拿到目标隐藏
    /// 服务的**公开**证书（`cert-as-pubkey` 的 SPKI 本来就是 .onion 地址里那 32 字节），
    /// 就能原样重放，**无需任何私钥** ⇒「证书即公钥」校验形同虚设。
    fn verify_handshake_signature(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
        tls13: bool,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let algs = verify_algs();
        if tls13 {
            rustls::crypto::verify_tls13_signature(message, cert, dss, algs)
        } else {
            rustls::crypto::verify_tls12_signature(message, cert, dss, algs)
        }
    }

    #[derive(Debug)]
    struct AcceptAll;
    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            verify_handshake_signature(message, cert, dss, false)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            verify_handshake_signature(message, cert, dss, true)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    #[derive(Debug)]
    struct OnionVerifier {
        host: String,
    }
    impl ServerCertVerifier for OnionVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            if onion_cert_matches_host(end_entity.as_ref(), &self.host) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(TlsError::General("onion cert-as-pubkey mismatch".into()))
            }
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            verify_handshake_signature(message, cert, dss, false)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            verify_handshake_signature(message, cert, dss, true)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    let verifier: Arc<dyn ServerCertVerifier> =
        if mode == OnionSslMode::Verify && is_onion_host(host) {
            Arc::new(OnionVerifier {
                host: host.to_string(),
            })
        } else if mode == OnionSslMode::Verify {
            bail!(
                "ssl_mode=verify on non-onion host via rustls fallback: \
                 no CA roots wired; reject (use tls_boring or onion)"
            );
        } else {
            Arc::new(AcceptAll)
        };

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).context("TLS server name")?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("rustls TLS connect to {host}"))?;
    Ok(UpstreamIo::from_tls(tls))
}

async fn write_raw_request(
    stream: &mut UpstreamIo,
    parts: &http::request::Parts,
    body: &[u8],
    host_hdr: &str,
    upstream_uri: &Uri,
    rule: &ProxyRuleConfig,
) -> Result<()> {
    let path_q = upstream_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let method = parts.method.as_str();
    let mut lines = format!("{method} {path_q} HTTP/1.1\r\nHost: {host_hdr}\r\n");
    for (k, v) in parts.headers.iter() {
        if k == HOST {
            continue;
        }
        let kl = k.as_str().to_ascii_lowercase();
        if WS_SKIP.contains(&kl.as_str()) {
            continue;
        }
        if rule
            .modify_request_headers
            .keys()
            .any(|mk| mk.eq_ignore_ascii_case(&kl))
        {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            lines.push_str(&format!("{k}: {vs}\r\n"));
        }
    }
    for (k, v) in &rule.modify_request_headers {
        // 这一路是**直接拼报文**（非 WS 的 h1/h2 路径会先经 HeaderName/HeaderValue 校验，
        // 非法值让 builder 报错、整条请求 502）。不校验就等于让规则的名字/值里塞 CR/LF
        // 而往上游请求注入任意个头、甚至提前结束请求头，所以这里照同样的失败语义拦下。
        if HeaderName::from_bytes(k.as_bytes()).is_err() {
            bail!("modify_request_headers has an invalid header name `{k}`");
        }
        if HeaderValue::from_bytes(v.as_bytes()).is_err() {
            bail!("modify_request_headers value for `{k}` has invalid bytes (CR/LF?)");
        }
        lines.push_str(&format!("{k}: {v}\r\n"));
    }
    lines.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    stream.write_all(lines.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    Ok(())
}

/// 读取上游响应头（上限 64KiB，读到 `\r\n\r\n` 即返回）。
///
/// **自身没有 deadline**：上游可以「收下连接后一个字节都不发」，那时这里永远不返回。
/// 调用方必须把它套在 [`UPSTREAM_HEAD_TIMEOUT`] 里（见 [`proxy_websocket`]）。
///
/// 头部之后**多读进来的字节会写回 `stream.leftover`**（不是丢掉）：一次 read 常常
/// 同时带回头部与正文起始，升级场景下那些就是上游的首批 WS 帧。
async fn read_http_head(stream: &mut UpstreamIo) -> Result<(StatusCode, HeaderMap)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        // 先把 leftover（上次多读的）纳入本次解析，避免「上一轮剩的字节被跳过」
        if !stream.leftover.is_empty() && buf.is_empty() {
            buf.extend_from_slice(&stream.leftover);
            stream.leftover.clear();
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = buf[..pos + 4].to_vec();
            // 头部之后剩下的字节**回注**，交给后续隧道/正文读取
            stream.leftover = buf[pos + 4..].to_vec();
            // 1xx 是**中间响应**（`HTTP/1.1 100 Continue` 最常见：客户端带
            // `Expect: 100-continue` 时 nginx/Caddy 会先回 100 再回 101），不是最终状态行。
            // 旧实现在第一个空行处就返回，于是 WS 升级被判成「上游返回 100 Continue」→ 硬 502。
            // hyper 自己的客户端会跳过 1xx，这里补上同一语义（丢弃该段头，继续读真正的头）。
            if let Ok((code, _)) = parse_http_head(&head) {
                if code.as_u16() < 200 {
                    log::debug!("ws upstream 中间响应 {}：继续读最终头", code.as_u16());
                    buf = std::mem::take(&mut stream.leftover);
                    continue;
                }
            }
            return parse_http_head(&head);
        }
        if buf.len() > 65536 {
            bail!("upstream headers too large");
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("upstream closed before headers");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn parse_http_head(raw: &[u8]) -> Result<(StatusCode, HeaderMap)> {
    let text = std::str::from_utf8(raw).context("invalid utf8 headers")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().context("missing status")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.trim().as_bytes()),
                HeaderValue::from_str(v.trim()),
            ) {
                headers.insert(name, val);
            }
        }
    }
    Ok((status, headers))
}

/// Tor connect: optional FFI stub → unix SOCKS → TCP SOCKS.
///
/// `socks_override` 来自 `ProxyRuleConfig::tor_socks`（每条规则可指定不同 SOCKS），
/// 支持 `unix:/path` / 绝对路径（UDS）与 `host:port`（TCP）。为空时回落到
/// 环境变量 CRUCIBLE_TOR_SOCKS_UNIX / CRUCIBLE_TOR_SOCKS，最后是 127.0.0.1:9050。
async fn connect_tor_socks(
    host: &str,
    port: u16,
    socks_override: Option<&str>,
) -> Result<TcpStream> {
    // 走 SOCKS5 的名字必须与路由判定用**同一规范形态**：`is_onion_host`/`needs_tor` 会把
    // 尾点规范化掉（`x.onion.` 也走 Tor），但 SOCKS 请求里若原样带上尾点，tor 的 v3 校验
    // 要求恰好 62 字符，会把 `xxx.onion.` 当成**普通域名**（既不认成隐藏服务，还等于把
    // 名字交给出口去解析）。这里统一成小写、去尾点后再发。
    let host_owned = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let host: &str = &host_owned;
    if let Some(stream) = try_tor_ffi_connect(host, port).await {
        return stream;
    }
    // 1) 规则级覆盖（面板可配）
    if let Some(spec) = socks_override.map(str::trim).filter(|s| !s.is_empty()) {
        if spec.starts_with("unix:") || spec.starts_with('/') {
            let path = spec.strip_prefix("unix:").unwrap_or(spec);
            let unix = UnixStream::connect(path)
                .await
                .with_context(|| format!("tor unix socks {path}"))?;
            return socks5_unix_bridge(unix, host, port).await;
        }
        let addr: SocketAddr = spec.parse().with_context(|| format!("tor_socks {spec}"))?;
        ensure_loopback_socks(addr, "tor_socks")?;
        let tcp = TcpStream::connect(addr)
            .await
            .with_context(|| format!("tor socks connect {addr}"))?;
        return socks5_connect(tcp, host, port).await;
    }
    // 用缓存的读取器：env_lock 会在引擎请求期间写进程环境，直接 var() 有数据竞争（见其说明）
    if let Some(unix_path) = crate::server::apps::env_lock::read_static_env("CRUCIBLE_TOR_SOCKS_UNIX") {
        if !unix_path.is_empty() {
            let unix = UnixStream::connect(&unix_path)
                .await
                .with_context(|| format!("tor unix socks {unix_path}"))?;
            return socks5_unix_bridge(unix, host, port).await;
        }
    }
    // 2) 未显式配置时的默认 UDS 探测链。
    //
    // 早先只有「环境变量 → 直落 TCP 9050」，而 config.rs 的文档写着
    // 「空 = 内置优先链（arti → UDS → loopback）」—— 那条链**当时并不存在**。
    // 这里补齐其中真正有用的一段：系统 tor 的 SOCKS 口在多数发行版/OpenBSD 上都以
    // unix socket 形式落在下面这些路径（一次性 stat，成本可忽略），找到就用它，
    // 走 UDS 不经过 TCP 栈、也不需要监听回环端口。
    //
    // （arti 是**有意不做**的：引入 arti-client 会带进一整套 rustls/sqlite 依赖，
    //   与本项目「BoringSSL 为主、不引入第二套 TLS 栈」的取向相冲。config 的文档已同步改成
    //   与实现一致，不再留下不存在的承诺。）
    for cand in default_tor_uds_candidates() {
        if cand.is_socket() {
            match UnixStream::connect(&cand).await {
                Ok(unix) => {
                    log::debug!(
                        "tor: 使用默认 UDS {}（未配置 CRUCIBLE_TOR_SOCKS[_UNIX]）",
                        cand.display()
                    );
                    return socks5_unix_bridge(unix, host, port).await;
                }
                Err(e) => log::debug!("tor: UDS {} 打不开（{e}），继续下一个候选", cand.display()),
            }
        }
    }

    // 3) 最后兜底：系统 tor 的默认 TCP SOCKS 口（仅 loopback）。
    let socks = crate::server::apps::env_lock::read_static_env("CRUCIBLE_TOR_SOCKS")
        .unwrap_or_else(|| "127.0.0.1:9050".to_string());
    let addr: SocketAddr = socks.parse().context("CRUCIBLE_TOR_SOCKS parse")?;
    ensure_loopback_socks(addr, "CRUCIBLE_TOR_SOCKS")?;
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("tor socks connect {addr}"))?;
    socks5_connect(tcp, host, port).await
}


/// `Path::is_socket()` 需要 `std::os::unix::fs::FileTypeExt`（仅 unix）。
trait SocketPath {
    fn is_socket(&self) -> bool;
}
impl SocketPath for PathBuf {
    fn is_socket(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            return std::fs::metadata(self)
                .map(|m| m.file_type().is_socket())
                .unwrap_or(false);
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// 默认 UDS 探测候选（按优先级）。顺序与 orig 规格 A 一致，另加本项目 `state/tor-client`。
pub(crate) fn default_tor_uds_candidates() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        v.push(cwd.join("state/tor-client/socks.sock"));
    }
    v.push(PathBuf::from("/run/tor/socks"));
    v.push(PathBuf::from("/var/run/tor/socks"));
    v.push(PathBuf::from("/run/tor/socks.sock"));
    v
}

/// SOCKS5 端点若走 TCP，必须是 loopback。
///
/// SOCKS5 请求是**明文**的：目标主机名与端口都写在里面（.onion 尤其敏感——它同时
/// 暴露「谁在访问哪个隐藏服务」）。把 `tor_socks` / `CRUCIBLE_TOR_SOCKS` 指到远端
/// 等于把每条 Tor 规则的访问目标交给那台机器，而它并不受本机信任约束（面板占位符
/// 也只承诺 `unix:/path` 与 `127.0.0.1:9050` 两种形态）。UDS 不在此限：它没有网络
/// 暴露面。原先这条约束只写在已死的 tor_client.rs 里，实际在跑的这条路径没有。
fn ensure_loopback_socks(addr: SocketAddr, source: &str) -> Result<()> {
    if !addr.ip().is_loopback() {
        bail!(
            "{source}={addr} refused: TCP SOCKS must be loopback \
             (127.0.0.0/8 or ::1); use unix:/path for a proxy on another host"
        );
    }
    Ok(())
}

/// Optional `CRUCIBLE_TOR_FFI_LIB` dlopen path.
///
/// Expected future ABI (not required today):
/// `int crucible_tor_connect(const char *host, uint16_t port, int *out_fd);`
///
/// Returns `Some(Ok(stream))` only if a real helper handed us a connected socket.
/// On missing lib / missing symbol / probe failure, returns `None` so callers
/// fall back to unix/TCP SOCKS (documented supported path).
async fn try_tor_ffi_connect(host: &str, port: u16) -> Option<Result<TcpStream>> {
    let path = crate::server::apps::env_lock::read_static_env("CRUCIBLE_TOR_FFI_LIB")?;
    if path.is_empty() {
        return None;
    }
    match tor_ffi_probe_and_connect(&path, host, port) {
        Ok(Some(stream)) => Some(Ok(stream)),
        Ok(None) => {
            log::debug!(
                "CRUCIBLE_TOR_FFI_LIB={path} loaded but no usable crucible_tor_connect; falling back to SOCKS"
            );
            None
        }
        Err(e) => {
            log::debug!("CRUCIBLE_TOR_FFI_LIB={path} probe failed ({e:#}); falling back to SOCKS");
            None
        }
    }
}

/// Sync dlopen probe. Does not call into Tor yet — symbol presence only —
/// then falls through (`Ok(None)`). Keeps link surface zero when env unset.
fn tor_ffi_probe_and_connect(lib_path: &str, host: &str, port: u16) -> Result<Option<TcpStream>> {
    #[cfg(unix)]
    {
        // Safety: dlopen of operator-supplied path; we only dlsym-check and dlclose.
        unsafe {
            let c_path = std::ffi::CString::new(lib_path)
                .map_err(|_| anyhow::anyhow!("CRUCIBLE_TOR_FFI_LIB path contains NUL"))?;
            let handle = libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW);
            if handle.is_null() {
                let err = std::ffi::CStr::from_ptr(libc::dlerror());
                bail!("dlopen failed: {}", err.to_string_lossy());
            }
            let sym_name = std::ffi::CString::new("crucible_tor_connect").unwrap();
            let sym = libc::dlsym(handle, sym_name.as_ptr());
            if sym.is_null() {
                libc::dlclose(handle);
                log::info!(
                    "tor FFI stub: {lib_path} has no crucible_tor_connect (host={host} port={port}); use SOCKS"
                );
                return Ok(None);
            }
            type TorConnectFn = unsafe extern "C" fn(*const libc::c_char, u16, *mut libc::c_int) -> libc::c_int;
            let connect_fn: TorConnectFn = std::mem::transmute(sym);
            let host_c = std::ffi::CString::new(host)
                .map_err(|_| anyhow::anyhow!("tor host contains NUL"))?;
            let mut out_fd: libc::c_int = -1;
            let rc = connect_fn(host_c.as_ptr(), port, &mut out_fd);
            libc::dlclose(handle);
            if rc != 0 || out_fd < 0 {
                log::debug!(
                    "tor FFI: crucible_tor_connect rc={rc} fd={out_fd} host={host} port={port}; SOCKS fallback"
                );
                return Ok(None);
            }
            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(out_fd) };
            std_stream.set_nonblocking(true)?;
            let stream = TcpStream::from_std(std_stream)?;
            log::info!("tor FFI: connected via crucible_tor_connect fd={out_fd} → {host}:{port}");
            return Ok(Some(stream));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (lib_path, host, port);
        log::debug!("CRUCIBLE_TOR_FFI_LIB ignored on non-unix; SOCKS fallback");
        Ok(None)
    }
}

async fn socks5_connect(mut tcp: TcpStream, host: &str, port: u16) -> Result<TcpStream> {
    do_socks5(&mut tcp, host, port).await?;
    Ok(tcp)
}

/// After SOCKS5 on a Unix socket, bridge bytes to a local TcpStream for Hyper.
/// 把一条 **Unix socket**（tor 的 SOCKS 口）桥接成 `TcpStream`：上游连接的类型在
/// `connect_upstream` 里固定是 `TcpStream`，而 `TcpStream::from_std` 无法从 `UnixStream`
/// 造出来，所以在本机回环上开一个临时端口做中转。
///
/// **必须校验 accept 到的对端就是自己**：临时端口虽是内核分配的，但同机进程可以先连上
/// 抢到隧道（于是它经我们这条已验证的 `.onion` 隧道出网）。这里比对「我们 client 侧的
/// 本地端口」与「accept 到的 peer 端口」，不一致就丢弃该连接再等下一个 —— 抢占者拿不到
/// 隧道，我们自己在同一循环里继续 accept。
async fn socks5_unix_bridge(mut unix: UnixStream, host: &str, port: u16) -> Result<TcpStream> {
    do_socks5(&mut unix, host, port).await?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("tor bridge bind")?;
    let addr = listener.local_addr()?;
    let client = TcpStream::connect(addr)
        .await
        .context("tor bridge client")?;
    let mine = client
        .local_addr()
        .context("tor bridge client local_addr")?
        .port();
    // 只接受端口号等于本连接的那个；别的（同机抢占/扫描）一律立刻关闭
    let mut server = loop {
        let (sock, peer) = listener.accept().await.context("tor bridge accept")?;
        if peer.port() == mine {
            break sock;
        }
        log::warn!(
            "tor bridge: 丢弃非预期连接 peer={peer}（期望端口 {mine}）—— 疑似同机抢占"
        );
        drop(sock);
    };
    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut unix, &mut server).await;
    });
    Ok(client)
}

async fn do_socks5<S>(stream: &mut S, host: &str, port: u16) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        bail!("socks5 handshake rejected: {:02x} {:02x}", resp[0], resp[1]);
    }

    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        bail!("socks5 host too long");
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    // 版本字节也必须校验：只查 REP 会让「非 SOCKS5 的服务端」被当成握手成功，
    // 后续把它的响应体当隧道数据读出（诊断时会表现为莫名其妙的协议错）。
    if head[0] != 0x05 {
        bail!("socks5 bad reply version {:#04x} (expected 0x05)", head[0]);
    }
    if head[1] != 0x00 {
        bail!("socks5 connect failed code {}", head[1]);
    }
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut dom = vec![0u8; len[0] as usize];
            stream.read_exact(&mut dom).await?;
            let mut port_b = [0u8; 2];
            stream.read_exact(&mut port_b).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        _ => bail!("socks5 unknown atyp {}", head[3]),
    }
    Ok(())
}

/// page_rules `pass` 动作入口:复用反代机制,把 match_url 前缀流量转发到 target。
/// 上游 TLS 校验按 URL scheme 决定(http:// → off,https:// → verify)。
pub async fn proxy_page_rule(
    req: Request<Full<Bytes>>,
    match_url: &str,
    upstream: &str,
    peer_ip: IpAddr,
    client_https: bool,
) -> Response<BoxBody> {
    let ssl_mode = if upstream.starts_with("https://") {
        "verify"
    } else {
        "off"
    };
    let rule = ProxyRuleConfig {
        path: match_url.trim_end_matches('*').to_string(),
        upstream: upstream.to_string(),
        ssl_mode: ssl_mode.into(),
        modify_request_headers: Default::default(),
        modify_response_headers: Default::default(),
        upstream_tls_version: None,
        upstream_http_version: None,
        connection_pool: false,
        via_tor: false,
        tor_socks: None,
    };
    match proxy_once(req, &rule, peer_ip, client_https).await {
        Ok(r) => r,
        Err(e) => {
            // 与 `try_proxy` 同口径：**不回显** `{e:#}` —— 那是完整错误链，里面有上游地址
            // 与端口、tor 的 unix socket 路径、TLS 后端错误文本、超时预算等内网布局信息，
            // 而能拿到它的人只是任意一个命中该 page rule 的客户端。细节只进本地日志。
            log::warn!("proxy: page rule pass 处理失败: {e:#}");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full("502 Bad Gateway"))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod tor_socks_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 假 SOCKS5 服务端：按脚本应答，并记录客户端发来的请求字节。
    /// 返回 (服务端任务句柄, 收到的请求字节)。
    fn fake_socks5(
        reply: Vec<u8>,
    ) -> (tokio::task::JoinHandle<Vec<u8>>, tokio::io::DuplexStream) {
        let (client, mut server) = tokio::io::duplex(4096);
        let h = tokio::spawn(async move {
            // 握手：+05 +01 +00 → 回 +05 +00
            let mut hs = [0u8; 3];
            let _ = server.read_exact(&mut hs).await;
            let _ = server.write_all(&[0x05, 0x00]).await;
            // 请求：ver cmd rsv atyp len host port
            let mut head = [0u8; 5];
            let _ = server.read_exact(&mut head).await;
            let mut host = vec![0u8; head[4] as usize];
            let _ = server.read_exact(&mut host).await;
            let mut port = [0u8; 2];
            let _ = server.read_exact(&mut port).await;
            let mut req = Vec::from(head.as_slice());
            req.extend_from_slice(&host);
            req.extend_from_slice(&port);
            let _ = server.write_all(&reply).await;
            req
        });
        (h, client)
    }

    /// 正常路径：握手 + CONNECT(域名) + 各种 ATYP 应答都要能收干净。
    #[tokio::test]
    async fn socks5_success_all_atyps() {
        for (name, reply) in [
            ("ipv4", vec![0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 80]),
            // 域名应答：len=3 "abc" port
            ("domain", vec![0x05, 0x00, 0x00, 0x03, 3, b'a', b'b', b'c', 0, 80]),
            (
                "ipv6",
                {
                    let mut v = vec![0x05, 0x00, 0x00, 0x04];
                    v.extend_from_slice(&[0u8; 16]);
                    v.extend_from_slice(&[0, 80]);
                    v
                },
            ),
        ] {
            let (srv, mut c) = fake_socks5(reply);
            do_socks5(&mut c, "example.onion", 443)
                .await
                .unwrap_or_else(|e| panic!("{name}: {e:#}"));
            let req = srv.await.unwrap();
            // 请求必须是 CONNECT + ATYP=domain + 主机名原样（**不做本地 DNS**）
            assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x03], "{name}");
            assert_eq!(req[4] as usize, "example.onion".len(), "{name}");
            assert_eq!(&req[5..5 + "example.onion".len()], b"example.onion", "{name}");
            assert_eq!(&req[5 + "example.onion".len()..], &[0x01, 0xBB], "{name}"); // 443
        }
    }

    /// REP != 0 → 必须报错（不能把失败当成功）。
    #[tokio::test]
    async fn socks5_reject_code_is_error() {
        // 0x04 = host unreachable
        let (srv, mut c) = fake_socks5(vec![0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let e = do_socks5(&mut c, "x.onion", 80).await.unwrap_err();
        assert!(format!("{e:#}").contains("code 4"), "实际: {e:#}");
        let _ = srv.await;
    }

    /// 应答版本字节不是 0x05 → 必须报错（非 SOCKS5 服务端不能当成功）。
    #[tokio::test]
    async fn socks5_bad_reply_version_is_error() {
        let (srv, mut c) = fake_socks5(vec![0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let e = do_socks5(&mut c, "x.onion", 80).await.unwrap_err();
        assert!(format!("{e:#}").contains("bad reply version"), "实际: {e:#}");
        let _ = srv.await;
    }

    /// 握手被拒（服务端要求认证）→ 报错。
    #[tokio::test]
    async fn socks5_handshake_reject_is_error() {
        let (client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut hs = [0u8; 3];
            let _ = server.read_exact(&mut hs).await;
            let _ = server.write_all(&[0x05, 0x02]).await; // 需要用户名口令
        });
        let mut c = client;
        let e = do_socks5(&mut c, "x.onion", 80).await.unwrap_err();
        assert!(format!("{e:#}").contains("handshake rejected"), "实际: {e:#}");
    }

    /// 未知 ATYP → 报错（而不是把剩余字节当作隧道数据）。
    #[tokio::test]
    async fn socks5_unknown_atyp_is_error() {
        let (srv, mut c) = fake_socks5(vec![0x05, 0x00, 0x00, 0x07, 0, 0]);
        let e = do_socks5(&mut c, "x.onion", 80).await.unwrap_err();
        assert!(format!("{e:#}").contains("unknown atyp"), "实际: {e:#}");
        let _ = srv.await;
    }

    /// 主机名超过 255 字节 → 拒绝（SOCKS5 的 len 是单字节，否则会截断成错误主机）。
    #[tokio::test]
    async fn socks5_host_too_long_rejected() {
        let (srv, mut c) = fake_socks5(vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let long = "a".repeat(256);
        let e = do_socks5(&mut c, &long, 80).await.unwrap_err();
        assert!(format!("{e:#}").contains("too long"), "实际: {e:#}");
        // 客户端在发请求**之前**就拒绝了，假服务端会永远等在 read_exact 上 ⇒ 必须 abort
        // （否则 `srv.await` 挂死整个测试二进制，本轮就踩到了）。
        srv.abort();
    }

    /// TCP SOCKS 只允许 loopback —— 非回环必须拒绝（否则等于把 tor 出口暴露成开放代理）。
    #[test]
    fn tcp_socks_must_be_loopback() {
        let ok: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        assert!(ensure_loopback_socks(ok, "test").is_ok());
        let ok6: SocketAddr = "[::1]:9050".parse().unwrap();
        assert!(ensure_loopback_socks(ok6, "test").is_ok());
        let bad: SocketAddr = "10.0.0.5:9050".parse().unwrap();
        let e = ensure_loopback_socks(bad, "CRUCIBLE_TOR_SOCKS").unwrap_err();
        assert!(format!("{e:#}").contains("must be loopback"), "实际: {e:#}");
        let bad_pub: SocketAddr = "8.8.8.8:9050".parse().unwrap();
        assert!(ensure_loopback_socks(bad_pub, "test").is_err());
    }

    /// `.onion.`（尾点）也必须走 Tor：否则会直连并把 onion 名交给 DNS。
    #[test]
    fn needs_tor_for_trailing_dot_onion() {
        use crate::server::onion_ca::is_onion_host;
        let rule = ProxyRuleConfig {
            path: "/".into(),
            upstream: "http://x.onion/".into(),
            ssl_mode: "no_verify".into(),
            ..Default::default()
        };
        let v3 = "w6sxlmzmz2mgzkg5r5fcvycu3lx2i5mkc4z3ycpuj5l22ewpplr2q70.onion";
        assert!(needs_tor(v3, &rule));
        assert!(needs_tor(&format!("{v3}."), &rule), "带尾点也必须走 Tor");
        assert!(is_onion_host(&format!("{v3}.")));
    }

    /// Tor 的连接预算必须**明显大于**直连预算：tor 的 SOCKS5 应答要等电路建好才回，
    /// 冷电路实测超过 10s（本轮真机复现的 502 就是它）。这条断言防的是「有人把预算改回 10s」。
    #[test]
    fn tor_gets_a_larger_connect_budget() {
        assert_eq!(connect_budget(false), UPSTREAM_CONNECT_TIMEOUT);
        assert_eq!(connect_budget(true), UPSTREAM_CONNECT_TIMEOUT_TOR);
        assert!(
            connect_budget(true) > connect_budget(false),
            "tor 预算必须大于直连预算"
        );
        assert!(
            connect_budget(true).as_secs() >= 30,
            "冷电路实测可超 10s，预算不该压回十几秒"
        );
    }

    /// 默认 UDS 候选链里必须包含 orig 规格 A 列出的那几个路径。
    #[test]
    fn default_uds_candidates_cover_spec_paths() {
        let v = default_tor_uds_candidates();
        let joined: Vec<String> = v.iter().map(|p| p.display().to_string()).collect();
        for want in ["/run/tor/socks", "/var/run/tor/socks", "/run/tor/socks.sock"] {
            assert!(joined.iter().any(|j| j == want), "缺少候选 {want}: {joined:?}");
        }
        assert!(joined.iter().any(|j| j.ends_with("state/tor-client/socks.sock")));
    }
}
