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
/// WebSocket 隧道的**每方向空闲上限**：101 升级后 h1/h2 的空闲/头读超时都不再适用，
/// 客户端（或只回 101 后静默的恶意上游）只要保持安静就能永久占住两个 socket、任务
/// 与转发缓冲。取 10min：WS 正常 ping/pong 远小于此，长时间无业务数据也不会被误杀。
const WS_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// WebSocket 隧道全局并发上限：项目没有 per-IP/全局连接上限，反代隧道必须自带一个，
/// 否则批量 101 即可耗尽 fd/内存（隧道结束/失败即释放 permit）。
const WS_MAX_TUNNELS: usize = 256;
static WS_TUNNELS: Lazy<tokio::sync::Semaphore> =
    Lazy::new(|| tokio::sync::Semaphore::new(WS_MAX_TUNNELS));
/// 反代**响应全量缓冲**的全局预算（单请求上限 64MiB，此前没有全局上限 ⇒ N 个并发请求
/// 就是 N×64MiB 常驻）。按每请求上限从预算里预留，超限快速失败（503），把 OOM 向量从
/// 「随并发线性增长」变成有界。彻底修法是响应流式转发（见总结的跨文件需求：BoxBody 的
/// 错误类型是 Infallible，流式需要改 h1/h2/h3 的公共类型）。
const PROXY_BUFFER_BUDGET: usize = 1024 * 1024 * 1024; // 1 GiB
static PROXY_BUFFER_RESERVED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// `trust_self_signed` 当前没有自定义根证书可配、实际等价 `no_verify`，只警告一次。
static TRUST_SELF_SIGNED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 响应缓冲预算的 RAII 预留（drop 即归还；随 [`Response`] extensions 一起活到响应被
/// hyper 消费完，覆盖「已缓冲但还没写给客户端」的那段内存）。
struct BufferReservation {
    bytes: usize,
}

impl BufferReservation {
    fn try_acquire(bytes: usize) -> Option<Self> {
        use std::sync::atomic::Ordering;
        let mut cur = PROXY_BUFFER_RESERVED.load(Ordering::Relaxed);
        loop {
            let next = cur.checked_add(bytes)?;
            if next > PROXY_BUFFER_BUDGET {
                return None;
            }
            match PROXY_BUFFER_RESERVED.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self { bytes }),
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Drop for BufferReservation {
    fn drop(&mut self) {
        PROXY_BUFFER_RESERVED.fetch_sub(self.bytes, std::sync::atomic::Ordering::AcqRel);
    }
}

/// 缓冲预算耗尽（与上游故障区分开：调用方回 503 而不是 502）。
#[derive(Debug)]
struct BufferBudgetExhausted;

impl std::fmt::Display for BufferBudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "proxy response buffering budget exhausted ({} MiB global)",
            PROXY_BUFFER_BUDGET / (1024 * 1024)
        )
    }
}

impl std::error::Error for BufferBudgetExhausted {}

/// 上游**超时**（连接 / 读响应头 / 读响应体 / WS 握手）：与「上游拒绝连接、返回非法
/// 响应、提前关闭」等故障区分开，映射为 **504 Gateway Timeout** 而不是 502。
///
/// 为什么必须区分：网关语义里 502 = 上游给出了非法/无法处理的响应，504 = 上游在预算内
/// 没有及时响应（客户端可安全重试）。此前全部超时都落成 502，与「连不上/坏响应」混为
/// 一谈，调用方无法据此决定重试；真机复现：上游 sleep 45s，我方 30s 头超时后回 502。
#[derive(Debug)]
struct UpstreamTimeout(String);

impl std::fmt::Display for UpstreamTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream {} timed out", self.0)
    }
}

impl std::error::Error for UpstreamTimeout {}

/// 上游处理失败 → 客户端状态码的统一映射（`try_proxy` 与 page-rule `pass` 共用，
/// 避免两处再次分叉）。顺序：预算耗尽 503 → 超时 504 → 其余 502。
fn upstream_error_response(e: &anyhow::Error) -> Response<BoxBody> {
    let (status, msg) = if e.downcast_ref::<BufferBudgetExhausted>().is_some() {
        (StatusCode::SERVICE_UNAVAILABLE, "503 Service Unavailable")
    } else if e.downcast_ref::<UpstreamTimeout>().is_some() {
        (StatusCode::GATEWAY_TIMEOUT, "504 Gateway Timeout")
    } else {
        (StatusCode::BAD_GATEWAY, "502 Bad Gateway")
    };
    Response::builder()
        .status(status)
        .body(full(msg))
        .unwrap()
}

/// 连接池键：把每个决定「这条请求能复用到哪条连接」的维度**原样**放进结构体，
/// 由字段比较/字段哈希定相等，**不做 64 位哈希截断**。
///
/// 此前是 `PoolKey(u64)`（DefaultHasher 各维度压成一个 u64）：池键决定复用到哪条
/// 上游连接，哈希一旦碰撞，取出的就是发往**另一个上游**（或另一套 TLS 策略）的连接
/// —— 与「复用」的语义完全不符，属安全问题而不只是命中率问题。字段集合没有变化，
/// 所以相等性语义与原来一致（同规则 → 同键 → 可复用，不会退化成每条请求都新建连接）。
#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    /// 目的地：TCP 上游是 host（+ 下面的 port），**UDS 上游是 socket 路径**。
    ///
    /// 为什么 UDS 不能用占位 `localhost`：两条规则分别指向 `unix:/run/a.sock` 与
    /// `unix:/run/b.sock` 时，键会完全一样，池里取出的就是**发往另一个上游**的连接
    /// （真机复现：/u1 → /run/u1.sock、/u2 → /run/u2.sock 两条 pool=true 规则，
    /// 两条路径都得到 u1 的响应，取决于哪个先入池）。这是把请求发给错误后端的
    /// 功能/安全问题，不只是命中率问题。
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
use std::path::{Path, PathBuf};
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
    /// 这条上游连接**是否真的做了 TLS 握手**（`http://` 直连为 false；`https://` /
    /// `.onion` TLS 档为 true）。显式 `upstream_http_version = "h2"` 的降级判定要用它：
    /// 明文上游的 h2 是 h2c prior-knowledge（直接按 h2 讲话），TLS 上游必须以 ALPN
    /// 协商结果为准（见 `proxy_once` 的 ALPN 校验）。
    tls: bool,
    /// TLS 握手协商出的 ALPN 协议名（`Some("h2")` / `Some("http/1.1")`）；未协商出
    /// ALPN 或明文连接为 `None`。显式配置 `upstream_http_version = "h2"` 时用来在**发请求
    /// 之前**发现「上游不会说 h2」，而不是等 30s 头超时后回一个误导性的 504。
    tls_alpn: Option<String>,
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
            tls: false,
            tls_alpn: None,
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
            tls: true,
            tls_alpn: None,
            leftover: Vec::new(),
        }
    }

    /// 任意字节流上游（UDS 等）：与 [`Self::from_tls`] 同一包装，只是命名上区分来源。
    fn from_stream<S>(s: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            inner: Box::pin(s),
            negotiated_h2: false,
            tls: false,
            tls_alpn: None,
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
///
/// **必须遍历所有 `Connection` 行**：`HeaderMap::get` 只看第一个值，
/// 而 RFC 允许 `Connection: keep-alive` 与 `Connection: X-Secret` 分两行写
/// （等价于 `Connection: keep-alive, X-Secret`）。只读第一行时，第二行点名的
/// `X-Secret` 会被当成**端到端头**原样转发（请求方向送进上游、响应方向送还客户端），
/// 逐跳剥离被一行头绕过。真机复现（本地 29095 → python 上游）：多行 Connection 的第二个
/// token 在两种方向都残留在报文里。
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    // `get_all` 取**全部**同名的行；每行再按逗号拆 token。
    for v in headers.get_all(CONNECTION).iter() {
        if let Ok(s) = v.to_str() {
            for t in s.split(',') {
                let t = t.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    out.push(t);
                }
            }
        }
    }
    out
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
/// 客户端自带的转发头族不在本名单里：`write_raw_request` 另用
/// [`is_client_forwarded_header`] 按「`forwarded` / `x-forwarded-*` / `x-real-ip`」
/// 整族剥离并注入权威值。
const WS_SKIP: &[&str] = &[
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
];

/// 客户端提供的**转发头族**是否要剥离：`Forwarded`（RFC 7239）、整族 `X-Forwarded-*`、
/// `X-Real-IP`。这些头描述的是「客户端自认为的来源链」，未认证客户端可以随意伪造
/// （来源 IP/Host/协议）；此前只剥了 XFF/XFP 两个名字，`Forwarded`/`X-Forwarded-Host`/
/// `X-Real-IP` 等仍原样进上游 —— 依赖它们的后端（Django USE_X_FORWARDED_HOST、按
/// X-Real-IP 做 ACL/限流的网关）就会被伪造。权威值由代理自己注入。
fn is_client_forwarded_header(name_lower: &str) -> bool {
    name_lower == "forwarded" || name_lower == "x-real-ip" || name_lower.starts_with("x-forwarded-")
}

/// 代理注入的 `Forwarded`（RFC 7239）值：只写我们自己看到的对端地址。
/// IPv6 按 §6 要求用引号包裹的方括号形式。
fn forwarded_value(peer: IpAddr, client_https: bool) -> String {
    let proto = if client_https { "https" } else { "http" };
    match peer {
        IpAddr::V4(v4) => format!("for={v4};proto={proto}"),
        IpAddr::V6(v6) => format!("for=\"[{v6}]\";proto={proto}"),
    }
}

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
                    // 缓冲预算耗尽不是上游故障：503（可重试）而不是 502。
                    // 超时（连接/读头/读体）是 504；其余上游故障 502。
                    return Some((true, upstream_error_response(&e)));
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
    //
    // 曾经还有一条 `rest.starts_with("//") → bail!`（「protocol-relative suffix」），
    // **同样过严**：`//` 在路径里是合法字节（RFC 3986 §3.3 的 path 段允许空段），
    // 客户端 `GET /api//x` 会被这条打成 502 —— 真机复现：/api//x → 502，
    // 而上游根本没收到请求。安全性不靠这条 bail：下面把 rest 补成以 `/` 开头后
    // 拼出的 `http://base//x` 里 authority 仍是 base（http::Uri 已在本地核对：
    // `http://127.0.0.1:29096//evil/x` 解析出 host=127.0.0.1、path=//evil/x），
    // 攻击者无法借 `//` 换掉 authority。UI/配置里的 path 也收到 `path_matches` 的边界约束。
    // Reject `http:` / `https:` absolute URLs sneaked into the path suffix.
    // （rest 由请求路径切出，正常必然以 `/` 开头；这条只兜住 UDS 形态下
    //  `join_upstream("", rest)` 的绝对 URL 注入面。）
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

    /// 这条 sender 说的是 h2 还是 h1（决定回源请求行/伪头的 URI 形态）。
    ///
    /// 用 sender 的**实际**变体而不是配置推断：池里取出的 sender 就是接下来真正发请求的
    /// 那条连接，URI 形态必须与它一致（h2 需要带 scheme+authority 的 URI 生成
    /// `:scheme`/`:authority`；h1 需要 origin-form，见 `send_uri` 的说明）。
    fn is_h2(&self) -> bool {
        matches!(self, UpSender::H2(_))
    }
}

/// 上游是否为 UDS 形态（`unix:/abs/path`，或裸绝对路径 `/abs/path`）。
///
/// 规格 §16.10：上游可写 `ip:port` 或 `unix:/path` 两种形态。此前只支持 http(s)://
/// authority，写 `unix:/…` 会在 `upstream_parts` 直接报「no host」→ 该规则恒 502。
/// 与 `fastcgi.rs`/`native_http.rs` 的 UDS 写法保持一致（`unix:` 前缀或裸绝对路径）。
fn upstream_uds_path(upstream: &str) -> Option<&str> {
    let s = upstream.trim();
    let p = s.strip_prefix("unix:").unwrap_or(s);
    if p.starts_with('/') && !p.starts_with("//") {
        Some(p)
    } else {
        None
    }
}

async fn proxy_once(
    req: Request<Full<Bytes>>,
    rule: &ProxyRuleConfig,
    peer_ip: IpAddr,
    client_https: bool,
) -> Result<Response<BoxBody>> {
    if is_websocket_upgrade(&req) {
        return proxy_websocket(req, rule, peer_ip, client_https).await;
    }

    let suffix = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let rest = suffix
        .strip_prefix(&rule.path)
        .or_else(|| suffix.strip_prefix(rule.path.trim_end_matches('/')))
        .unwrap_or(suffix.as_str());
    // UDS 上游：没有 authority，请求目标用 origin-form（`/rest`），Host 用占位值；
    // 连接是 UnixStream，不做 TLS/Tor。`pool_dest` 是**池键里的目的地**：
    // UDS 用 socket 路径，TCP 用 host —— 见下面的说明。
    let (uri, host, scheme, port, pool_dest) = if let Some(sock) = upstream_uds_path(&rule.upstream)
    {
        let path = join_upstream("", rest)?;
        let uri = Uri::from_str(&path).context("uds upstream uri")?;
        log::debug!("proxy: UDS 上游 {sock}（请求目标 {path}）");
        (
            uri,
            "localhost".to_string(),
            "unix".to_string(),
            80u16,
            sock.to_string(),
        )
    } else {
        let upstream = rule.upstream.trim_end_matches('/');
        let target = join_upstream(upstream, rest)?;
        let uri = Uri::from_str(&target).context("upstream uri")?;
        let (host, scheme, port) = upstream_parts(&uri)?;
        let pool_dest = host.clone();
        (uri, host, scheme, port, pool_dest)
    };

    // 规格 11：回源 HTTP 版本可配（h2 显式启用；不配置时按 ALPN 协商结果自动选）。
    // UpSender 定义在模块级（连接池 POOL 按它声明类型，两处必须同一个类型）。

    // 大小写/空白归一：面板与手写 TOML 里 `"H2"`、`" h2 "` 都是合法写法，
    // 而精确比较会让它们**静默**按 h1 处理（保存成功、行为不变 —— 最难查的一类）。
    // `Some(true)` = 显式 h2、`Some(false)` = 显式 h1、`None` = 未配置（按 ALPN 自动）。
    let explicit_version: Option<bool> = rule
        .upstream_http_version
        .as_deref()
        .map(|v| v.trim().eq_ignore_ascii_case("h2"));
    let explicit_h2 = explicit_version == Some(true);
    // 池键构造函数：`pool_dest`（TCP=host、UDS=socket 路径）+ 全部 TLS/出口维度。
    let mk_pool_key = |want_h2: bool| {
        PoolKey::new(
            &pool_dest,
            port,
            &scheme,
            want_h2,
            needs_tor(&host, rule),
            &rule.ssl_mode,
            rule.upstream_tls_version.as_deref(),
            rule.tor_socks.as_deref(),
        )
    };
    // §3 连接池：仅当规则显式 `connection_pool = true` 时复用上游连接（默认关闭）。
    //
    // **先查池、命中就不建连**：旧顺序是「无条件 connect（含 TCP/SOCKS/TLS 握手）→
    // 再 pool_take → 命中就把刚建好的连接丢掉」，于是开了池反而比不开更贵（每条请求
    // 多一次建连再丢弃）。真机复现（本地 4 条 pool=true 请求）：上游侧看到 4 条独立
    // TCP 连接，其中两条只承载 1 个请求就被丢弃 —— 池的收益全被这笔浪费抵消。
    // 只有**显式指定了回源 HTTP 版本**时才能在拨号前定池键（ALPN 自动档的结果
    // 必须等握手后才知道，见下）。
    let mut sender: Option<UpSender> = None;
    let mut pool_key = mk_pool_key(explicit_version.unwrap_or(false));
    if rule.connection_pool {
        if let Some(want_h2) = explicit_version {
            pool_key = mk_pool_key(want_h2);
            if let Some(s) = pool_take(pool_key.clone()).await {
                if s.is_ready() {
                    sender = Some(s);
                }
            }
        }
    }

    if sender.is_none() {
        let stream = connect_upstream(&host, port, &scheme, rule, false).await?;
        // 规格 11：未配置 upstream_http_version 时按上游 ALPN 协商结果自动选 h2/h1。
        let alpn_h2 = stream.negotiated_h2;
        let upstream_alpn: Option<String> = stream.tls_alpn.clone();
        let upstream_is_tls = stream.tls;
        let io = TokioIo::new(stream);

        // 显式 `upstream_http_version = "h2"` + TLS 上游：**必须**以 ALPN 协商结果为准。
        //
        // 显式 h2 只在握手时提供 `h2`；若上游要么不支持 ALPN、要么回话里没有 h2，
        // 我们仍按 h2 prior-knowledge 前奏讲话 —— 上游把二进制前奏当非法请求行丢掉，
        // 于是这条规则**每个请求**都要等满 30s 头超时才失败（真机复现：本地 /stall 规则
        // 显式 h2 + 一个只 accept 不回话的 TCP 上游 = 30s 后 504，而超时消息把
        // 「上游不会说 h2」这个真因完全遮住了）。
        // ALPN 是 TLS 才有的协商机制：协商不到 h2 就等于「上游不会说 h2」，此时
        // ALPN 是权威证据 —— 不回落到 h1（那是另一条连接上的另一种协议，不能凭空假设），
        // 而是**立刻**按上游故障处理，日志给出准确的 ALPN 值。
        // 明文（无 TLS）上游没有 ALPN 可用：显式 h2 就是 h2c prior-knowledge，照发。
        if explicit_h2 && upstream_is_tls && !alpn_h2 {
            let got = upstream_alpn.as_deref().unwrap_or("（无 ALPN）");
            log::warn!(
                "proxy: 规则指向 {host}:{port} 且 upstream_http_version=h2，但 TLS ALPN 协商结果是 {got} \
                 —— 上游不会说 h2，拒绝按 h2 讲话（避免每请求等满头超时）"
            );
            anyhow::bail!(
                "upstream {host}:{port} did not negotiate ALPN h2 (got {got}); \
                 set upstream_http_version to h1/omit it, or point at an h2-capable upstream"
            );
        }
        let want_h2 = explicit_h2 || (explicit_version.is_none() && alpn_h2);
        pool_key = mk_pool_key(want_h2);
        // 自动档：刚做完 ALPN 握手才知道池键，这里补一次查找（命中则丢弃刚建的连接，
        // 与旧行为一致；显式档已在上面查过且不会走到这里）。
        if rule.connection_pool && sender.is_none() {
            if let Some(s) = pool_take(pool_key.clone()).await {
                if s.is_ready() {
                    sender = Some(s);
                }
            }
        }
        if sender.is_none() {
            sender = Some(if want_h2 {
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
            });
        }
    }
    let mut sender = sender.expect("sender established above");

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
    // 回源请求行里的 request-target 形态（RFC 9112 §3.2.1）：
    //
    // * h1 上游：直接对**源服务器**讲话，请求目标必须是 **origin-form**（`/path?q`）。
    //   `Request::builder().uri(<绝对 URL>)` 经 hyper h1 客户端会**原样**写进请求行
    //   （`role.rs::Client::encode` 只做 `write!("{}")`），于是一台严格的源服务器会按
    //   「绝对 URL 不是本机资源」处理 —— 真机复现：python `http.server` 对
    //   `GET http://127.0.0.1:29095/index.html` 回 **404**，而同一个请求走本代理
    //   （绝对形态）也回 404；改成 origin-form 后 200。nginx/大多数源服务器接受两种形态，
    //   但这属于「不该依赖上游宽容」的协议正确性。
    // * h2 上游：URI 必须带 scheme+authority —— hyper 的 h2 客户端从 URI 生成
    //   `:scheme`/`:authority` 伪头，剥掉 authority 会让部分 h2 上游收不到 vhost 信息。
    // * UDS 上游：`uri` 本来就是 origin-form（没有 authority），原样用。
    let send_uri: Uri = if sender.is_h2() {
        uri.clone()
    } else if upstream_uds_path(&rule.upstream).is_some() {
        uri.clone()
    } else {
        uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .parse()
            .context("upstream origin-form uri")?
    };
    let mut builder = Request::builder().method(parts.method).uri(&send_uri);
    // hop-by-hop 头与 Connection 列名的头一律不上游（host 单独重写）。
    let conn_tokens: Vec<String> = connection_tokens(&parts.headers);
    for (k, v) in parts.headers.iter() {
        let kl = k.as_str().to_ascii_lowercase();
        if k == HOST || HOP_BY_HOP.contains(&kl.as_str()) || conn_tokens.iter().any(|t| *t == kl) {
            continue;
        }
        // 整个转发头族（Forwarded / X-Forwarded-* / X-Real-IP）由下面自行计算后注入。
        // 这里若把客户端那份也转发，builder.header 是**追加**语义，上游会同时收到两份
        // 且客户端的排在前面 —— 后端按「取第一个」解析时就被伪造了（例如明文口上谎称
        // X-Forwarded-Proto: https、X-Forwarded-Host 投毒密码重置链接、X-Real-IP 骗 ACL）。
        if is_client_forwarded_header(&kl) {
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
    // RFC 7239 的 Forwarded 同样只写权威值（客户端那份已在上面剥离）。
    builder = builder.header("forwarded", forwarded_value(peer_ip, client_https));
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
            anyhow::Error::new(UpstreamTimeout(format!(
                "response head (budget {}s)",
                UPSTREAM_HEAD_TIMEOUT.as_secs()
            )))
        })?
        .context("upstream send")?;
    let (rparts, rbody) = resp.into_parts();
    // P2：全量缓冲的全局预算。单请求 64MiB、没有全局上限时，并发请求会把常驻内存拉到
    // N×64MiB；这里在开始缓冲前按上限预留，超限快速失败（走 BufferBudgetExhausted →
    // 调用方 503），而不是让内存随并发线性增长。
    let buffer_guard = BufferReservation::try_acquire(crate::server::h1::UPSTREAM_BODY_CAP)
        .ok_or_else(|| anyhow::Error::new(BufferBudgetExhausted))?;
    // 任务 6（OOM 防护）：上游响应体上限 64MiB。
    // 超时与上限互补：上限管「发太多」，超时管「一个字节都不发」（僵死上游）。
    // 已超时/出错的连接不还池（提前 return，sender 随作用域析构）。
    let rbytes = tokio::time::timeout(
        UPSTREAM_BODY_TIMEOUT,
        http_body_util::Limited::new(rbody, crate::server::h1::UPSTREAM_BODY_CAP).collect(),
    )
    .await
    .map_err(|_| {
        anyhow::Error::new(UpstreamTimeout(format!(
            "response body (budget {}s)",
            UPSTREAM_BODY_TIMEOUT.as_secs()
        )))
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
    // 预算随响应一起活到被 hyper 消费完（extensions 在 Response drop 时才释放），
    // 覆盖「body 已缓冲、还没写完给客户端」的那段内存。
    //
    // `http::Extensions::insert` 要求 `T: Clone`（http 1.5），而这是 RAII 预算守卫 ——
    // 直接 Clone 会让同一笔预留被归还两次（计数器下溢/提前放行）。用 `Arc` 包一层：
    // Arc 的 Clone 只加引用计数，Drop 在最后一个引用消失时归还预算，语义与
    // 「预算跟着响应走」完全一致。
    out.extensions_mut()
        .insert(std::sync::Arc::new(buffer_guard));
    // 连接池：响应体已完整读完（H1 复用的前提），连接仍可用就放回池中。
    if rule.connection_pool && sender.is_ready() {
        pool_give(pool_key, sender);
    }
    Ok(out)
}

async fn proxy_websocket(
    req: Request<Full<Bytes>>,
    rule: &ProxyRuleConfig,
    peer_ip: IpAddr,
    client_https: bool,
) -> Result<Response<BoxBody>> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();
    let upgrade = hyper::upgrade::on(Request::from_parts(parts.clone(), Full::new(body_bytes.clone())));

    let (target, host, port, scheme) = resolve_upstream_target(&parts.uri, rule)?;
    let target_uri = Uri::from_str(&target).context("websocket upstream uri")?;
    let host_hdr = upstream_host_header(&host, port, &scheme);
    let mut upstream = connect_upstream(&host, port, &scheme, rule, true).await?;
    // 写握手请求 + 读 101 响应头共用一段 deadline：read_http_head 自身没有超时，
    // 上游若收下升级请求后不回包，这个任务会一直挂在这里（连接与两端口都被占住）。
    let (status, headers) =
        tokio::time::timeout(UPSTREAM_HEAD_TIMEOUT, async {
            write_raw_request(
                &mut upstream,
                &parts,
                &body_bytes,
                &host_hdr,
                &target_uri,
                rule,
                peer_ip,
                client_https,
            )
            .await?;
            read_http_head(&mut upstream).await
        })
        .await
        .map_err(|_| {
            anyhow::Error::new(UpstreamTimeout(format!(
                "websocket handshake (budget {}s)",
                UPSTREAM_HEAD_TIMEOUT.as_secs()
            )))
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

    // 隧道并发上限：101 之前就取 permit，取不到直接 503（不进入升级），
    // permit 随隧道任务结束释放（static 上的借用是 'static，可直接 move 进任务）。
    let permit = match WS_TUNNELS.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            log::warn!("proxy: WebSocket 隧道并发已达上限 {WS_MAX_TUNNELS}，拒绝升级");
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(full("websocket tunnels exhausted"))
                .context("build websocket limit response");
        }
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Ok(upgraded) = upgrade.await {
            let client = TokioIo::new(upgraded);
            // 每方向独立空闲超时（复用 l4::copy_idle）：没有它时，客户端或只回 101 的
            // 恶意上游保持静默即可永久占住两个 socket + 任务 + 缓冲。
            let (mut client_read, mut client_write) = tokio::io::split(client);
            let (mut up_read, mut up_write) = tokio::io::split(upstream);
            let _ = tokio::try_join!(
                crate::server::l4::copy_idle(&mut client_read, &mut up_write, WS_IDLE_TIMEOUT),
                crate::server::l4::copy_idle(&mut up_read, &mut client_write, WS_IDLE_TIMEOUT),
            );
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
    // `Upgrade` 与 `Connection` 都可能**跨多行**（RFC 9110 §7.6.1 允许把 token 拆到多行，
    // 等价于逗号连接的一行）。此前用 `get(UPGRADE)` / `get(CONNECTION)` 只看**第一行**：
    //   * `Connection: keep-alive` + `Connection: Upgrade` 两行 → 只看 "keep-alive"，
    //     `contains("upgrade")` 为假 ⇒ 明明带了升级意图却被当成普通请求转发，
    //     101 升级静默退化成一次普通回源（真机复现：多行 Connection 的 /ws 请求
    //     得到上游的普通 200，而不是升级）。
    //   * `Upgrade: h2c` + `Upgrade: websocket` 两行 → 只看第一行同理。
    // 这里改用 `connection_tokens`（本文件已按「遍历全部行 + 拆逗号」实现，与逐跳头剥离
    // 同一判据）与 `get_all`，把多行/多值都覆盖到；token 用**精确匹配**而不是
    // `contains("upgrade")`，避免 `Connection: x-upgrade-y` 这类子串误判。
    let upgrade_ok = req
        .headers()
        .get_all(UPGRADE)
        .iter()
        .any(|v| v.to_str().map(|s| s.eq_ignore_ascii_case("websocket")).unwrap_or(false));
    let conn_ok = connection_tokens(req.headers())
        .iter()
        .any(|t| t == "upgrade");
    let key_ok = req.headers().get("sec-websocket-key").is_some();
    upgrade_ok && conn_ok && key_ok
}

fn resolve_upstream_target(
    uri: &Uri,
    rule: &ProxyRuleConfig,
) -> Result<(String, String, u16, String)> {
    let suffix = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let rest = suffix
        .strip_prefix(&rule.path)
        .or_else(|| suffix.strip_prefix(rule.path.trim_end_matches('/')))
        .unwrap_or(suffix.as_str());
    // UDS 上游：请求目标 origin-form，无 authority（host 占位、scheme=unix）。
    if upstream_uds_path(&rule.upstream).is_some() {
        let target = join_upstream("", rest)?;
        return Ok((target, "localhost".to_string(), 80u16, "unix".to_string()));
    }
    let upstream = rule.upstream.trim_end_matches('/');
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
///
/// 返回的 host 保留 `[ ]`（IPv6 字面量的 Host 头/authority 写法，RFC 9110 §7.2）；
/// 需要**拨号 / SNI** 的调用点必须先过 [`host_for_connect`]。
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

/// 把 URI host 变成可直接用于**拨号 / TLS SNI** 的形态：去掉 IPv6 字面量的方括号。
///
/// `Uri::host()` 对 `http://[::1]:9000/` 返回 `[::1]`（带括号，Host 头要的就是这个），
/// 但：
///   * `TcpStream::connect(("[::1]", p))` 的 `ToSocketAddrs` 解析**失败**
///     （`failed to lookup address information`）—— 真机复现：IPv6 上游规则
///     100% 502，日志 `connect [::1]:29096: failed to lookup address information`；
///   * TLS SNI / 证书名也不允许括号（`[` `]` 不是合法 DNS 字符，也不是 IP 字面量语法）。
///
/// 所以拨号与 SNI 一律用去括号后的 `::1`；Host 头仍用带括号的原值。
fn host_for_connect(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
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

/// UDS 上游连接：`unix:/abs/path`（或裸绝对路径）。
async fn connect_unix(path: &str) -> Result<UpstreamIo> {
    let unix = UnixStream::connect(path)
        .await
        .with_context(|| format!("connect unix upstream {path}"))?;
    Ok(UpstreamIo::from_stream(unix))
}

async fn connect_upstream(
    host: &str,
    port: u16,
    scheme: &str,
    rule: &ProxyRuleConfig,
    force_h1: bool,
) -> Result<UpstreamIo> {
    // UDS 上游：直接连 UnixStream（无 TLS/Tor），仍套连接超时（防止目标 socket 存在
    // 但 accept 队列满/不推进时把任务挂死）。
    if let Some(sock) = upstream_uds_path(&rule.upstream) {
        return tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, connect_unix(sock))
            .await
            .map_err(|_| {
                anyhow::Error::new(UpstreamTimeout(format!(
                    "connect unix after {}s ({sock})",
                    UPSTREAM_CONNECT_TIMEOUT.as_secs()
                )))
            })?;
    }
    let via_tor = needs_tor(host, rule);
    let budget = connect_budget(via_tor);
    // 拨号/SNI 用去括号的 host（见 [`host_for_connect`]）：`[::1]` 这种 Host 头写法
    // 交给 `TcpStream::connect` 会解析失败（真机复现的 100% 502），也不能当 SNI。
    let dial_host = host_for_connect(host).to_string();
    // 连接阶段统一 deadline：TCP connect、SOCKS5 握手、TLS 握手都在这一段里，
    // 上游或 SOCKS 端「接受连接后不推进握手」会被这里掐断（future 一并取消）。
    tokio::time::timeout(
        budget,
        connect_upstream_inner(&dial_host, port, scheme, rule, force_h1),
    )
    .await
        .map_err(|_| {
            anyhow::Error::new(UpstreamTimeout(format!(
                "connect after {}s ({host}:{port}{})",
                budget.as_secs(),
                if via_tor {
                    "，经 Tor：冷电路建路可能较慢，若持续超时请查 tor 的 notice.log"
                } else {
                    ""
                }
            )))
        })?
}

async fn connect_upstream_inner(
    host: &str,
    port: u16,
    scheme: &str,
    rule: &ProxyRuleConfig,
    force_h1: bool,
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
    // 回源方向同样关掉 Nagle：否则每个上游请求的首包都要等延迟 ACK。
    let _ = tcp.set_nodelay(true);

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
    //
    // **WebSocket 升级例外（`force_h1`）**：WS 握手是 `proxy_websocket` 里**手写的
    // HTTP/1.1 报文**（`write_raw_request`），它不会说 h2。若这里仍发 `h2 + http/1.1`
    // 的 ALPN，任何支持 h2 的 TLS 上游（nginx/Caddy/Envoy/本 webserver 自身）都会**挑 h2**，
    // 于是我们把 h1 报文写进一条 h2 连接 —— 上游按 h2 前奏解析失败后直接关连接，
    // 表现为 `upstream closed before headers` → 502（真机复现：/ws2 → https 上游
    // ALPN=h2，502）。所以 WS 路径**一律不发 h2**：显式配了 h2 也强制按 h1 协商
    // （WS over h2 需要 Extended CONNECT，本项目未实现）。
    let alpn = if force_h1 {
        if rule
            .upstream_http_version
            .as_deref()
            .map(|v| v.trim().eq_ignore_ascii_case("h2"))
            .unwrap_or(false)
        {
            log::warn!(
                "proxy: WebSocket 规则指向 {host}:{port} 且配了 upstream_http_version=h2，\
                 但 WS 握手是 HTTP/1.1（h2 需 Extended CONNECT，未实现）—— 该连接强制按 h1 协商"
            );
        }
        UpstreamAlpn::Off
    } else {
        match rule
            .upstream_http_version
            .as_deref()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("h2") => UpstreamAlpn::H2Only,
            Some(_) => UpstreamAlpn::Off,
            None => UpstreamAlpn::Auto,
        }
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
    // P2：`trust_self_signed` 目前没有自定义根证书可配，实现上与 `no_verify` 一样落到
    // 「接受任意证书」—— 与面板/规格给人的印象（只多信任自签）不符，警告一次。
    // 语义修正需要 `upstream_ca_file`（已写 config-requests/proxy-subsys.md）。
    if mode == OnionSslMode::TrustSelfSigned
        && !TRUST_SELF_SIGNED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        log::warn!(
            "proxy: ssl_mode=trust_self_signed 当前等价于 no_verify（接受任意证书，无证书绑定）——\
             自定义根证书（upstream_ca_file）尚未实现；需要真正校验的上游请用 verify"
        );
    }
    #[cfg(feature = "tls_boring")]
    {
        return wrap_upstream_tls_boring(tcp, host, mode, tls_version, alpn).await;
    }
    #[cfg(all(feature = "tls_rustls", not(feature = "tls_boring")))]
    {
        return wrap_upstream_tls_rustls(tcp, host, mode, tls_version, alpn).await;
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

    let negotiated_alpn = tls
        .ssl()
        .selected_alpn_protocol()
        .map(|p| p.to_vec());
    let negotiated_h2 = negotiated_alpn.as_deref() == Some(b"h2".as_slice());
    if alpn != UpstreamAlpn::Off {
        log::debug!(
            "upstream {host}: ALPN {alpn:?} → {}",
            if negotiated_h2 { "h2" } else { "http/1.1" }
        );
    }
    let mut io = UpstreamIo::from_tls(tls);
    io.negotiated_h2 = negotiated_h2;
    io.tls_alpn = negotiated_alpn.map(|p| String::from_utf8_lossy(&p).into_owned());
    Ok(io)
}

/// rustls client path (feature `tls_rustls`, when Boring is not the primary stack).
#[cfg(all(feature = "tls_rustls", not(feature = "tls_boring")))]
async fn wrap_upstream_tls_rustls(
    tcp: TcpStream,
    host: &str,
    mode: OnionSslMode,
    tls_version: Option<&str>,
    alpn: UpstreamAlpn,
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

    // 回源 TLS 版本：此前参数被整个忽略（`_tls_version`）⇒ 配置静默无效。
    // 归一化与 boring 分支一致（tls1.2 / tls12 / tlsv1.3 …）。
    let versions: &[&'static rustls::SupportedProtocolVersion] =
        match tls_version.map(|v| v.to_ascii_lowercase().replace(['.', '_'], "")) {
            Some(ref v) if v == "tls12" || v == "tlsv12" => &[&rustls::version::TLS12],
            Some(ref v) if v == "tls13" || v == "tlsv13" => &[&rustls::version::TLS13],
            _ => rustls::DEFAULT_VERSIONS,
        };
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // ALPN：与 boring 分支同一策略。此前 rustls 构建完全不发 ALPN，
    // `upstream_http_version = "h2"` 必然 502（上游按 h1 回话、我们按 h2 前奏讲话）。
    match alpn {
        UpstreamAlpn::Auto => {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        UpstreamAlpn::H2Only => {
            config.alpn_protocols = vec![b"h2".to_vec()];
        }
        UpstreamAlpn::Off => {}
    }
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).context("TLS server name")?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("rustls TLS connect to {host}"))?;
    // 与 boring 路径一致：把 ALPN 协商结果带回去，未显式配 upstream_http_version 时
    // 据此选 h2/h1 的 client conn。
    let negotiated_alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    let negotiated_h2 = negotiated_alpn.as_deref() == Some(b"h2".as_slice());
    let mut io = UpstreamIo::from_tls(tls);
    io.negotiated_h2 = negotiated_h2;
    io.tls_alpn = negotiated_alpn.map(|p| String::from_utf8_lossy(&p).into_owned());
    Ok(io)
}

async fn write_raw_request(
    stream: &mut UpstreamIo,
    parts: &http::request::Parts,
    body: &[u8],
    host_hdr: &str,
    upstream_uri: &Uri,
    rule: &ProxyRuleConfig,
    peer_ip: IpAddr,
    client_https: bool,
) -> Result<()> {
    let path_q = upstream_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let method = parts.method.as_str();
    let mut lines = format!("{method} {path_q} HTTP/1.1\r\nHost: {host_hdr}\r\n");
    // `Connection:` 点名的头同样是逐跳头（RFC 9110 §7.6.1），WS 直写路径也必须剥掉，
    // 否则客户端一行 `Connection: X-Secret` + `X-Secret: v` 就能把自定义头送进上游
    // （与 proxy_once 的 h1/h2 路径同一判据、同一多行处理）。
    let conn_tokens = connection_tokens(&parts.headers);
    for (k, v) in parts.headers.iter() {
        if k == HOST {
            continue;
        }
        let kl = k.as_str().to_ascii_lowercase();
        // WS 路径同样剥掉客户端转发头族（此前只剥了 XFF/XFP 两个名字），
        // 权威值在下面注入。
        if WS_SKIP.contains(&kl.as_str())
            || is_client_forwarded_header(&kl)
            || conn_tokens.iter().any(|t| *t == kl)
        {
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
    // 标准代理头注入：只写我们自己看到的对端地址（与 proxy_once 同一口径）。
    lines.push_str(&format!("X-Forwarded-For: {peer_ip}\r\n"));
    lines.push_str(&format!(
        "X-Forwarded-Proto: {}\r\n",
        if client_https { "https" } else { "http" }
    ));
    lines.push_str(&format!(
        "Forwarded: {}\r\n",
        forwarded_value(peer_ip, client_https)
    ));
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
            //
            // 但 **101 是最终响应**：hyper 自己的客户端正是这么分类的
            //（`hyper::proto::h1::role::Client::decoder`：`101 => Some((ZERO, true))`，
            //  `100 | 102..=199 => None`（跳过））。升级握手把 101 也当中间响应跳过，
            // 就会一直等「真正的头」直到 UPSTREAM_HEAD_TIMEOUT —— 上游明明已经回了 101，
            // 客户端却一个字节都收不到，30s 后拿到 504。真机复现（本地 29095 → python
            // 上游 /ws）：客户端 101 永远等不到；日志一行
            // `ws upstream 中间响应 101：继续读最终头` 之后就是 head 超时。
            if let Ok((code, _)) = parse_http_head(&head) {
                let c = code.as_u16();
                if c < 200 && c != 101 {
                    log::debug!("ws upstream 中间响应 {c}：继续读最终头");
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
        let _ = tcp.set_nodelay(true);
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
        if uds_socket_trusted(&cand) {
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
    let _ = tcp.set_nodelay(true);
    socks5_connect(tcp, host, port).await
}


/// 默认候选 UDS 是否可信：候选本身必须是 socket（**不是符号链接**），且它到根之间的
/// 每一级目录都必须是真实目录、**不可被 group/other 写**。
///
/// 为什么需要：未配置 SOCKS 时第一条候选是 cwd 下的 `state/tor-client/socks.sock`。
/// 进程若从可写目录（/tmp、可写部署目录）启动，同机其他账号可以预先放一个同名 socket，
/// 所有 `.onion` 出站都会连到它（窥知访问目标、DoS；no_verify/off 下可中间人）。
/// 原实现只 `is_socket()`（还跟随符号链接）。逐级目录不可被他人改写时，攻击者无法在
/// 这条路径上放置自己的 socket —— 此时才信任；否则跳过、继续下一个候选（系统路径）。
fn uds_socket_trusted(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        // symlink_metadata：符号链接拿到的是链接本身（file_type 不是 socket）⇒ 拒绝。
        let Ok(md) = std::fs::symlink_metadata(p) else {
            return false;
        };
        if !md.file_type().is_socket() {
            return false;
        }
        let mut cur = p.parent();
        while let Some(d) = cur {
            let Ok(dm) = std::fs::symlink_metadata(d) else {
                return false;
            };
            if !dm.is_dir() || dm.mode() & 0o022 != 0 {
                return false;
            }
            cur = d.parent();
        }
        true
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        false
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
    // 比**完整 SocketAddr**（地址 + 端口）：只比端口时，同机攻击者可以从另一个回环地址
    // （如 127.0.0.2）绑定相同源端口抢在 accept 窗口里连上，接管这条已建立的 Tor 隧道。
    let mine = client
        .local_addr()
        .context("tor bridge client local_addr")?;
    // 只接受与本连接本地地址完全相同的那个；别的（同机抢占/扫描）一律立刻关闭
    let mut server = loop {
        let (sock, peer) = listener.accept().await.context("tor bridge accept")?;
        if peer == mine {
            break sock;
        }
        log::warn!(
            "tor bridge: 丢弃非预期连接 peer={peer}（期望 {mine}）—— 疑似同机抢占"
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
/// page rule `pass` 的上游 TLS 档位：按**解析后的 scheme** 判定（大小写不敏感）。
///
/// 此前是 `upstream.starts_with("https://")` 的字面前缀比较，而 `http::Uri` 会把
/// scheme 归一化：页面规则 target 写 `HTTPS://backend/` 能通过配置校验并存盘，
/// 运行期却被判成 `off`（boring 下不设置 verify，rustls 下直接 AcceptAll）——
/// 同一份配置因大小写得到不同的 TLS 安全档。
fn page_rule_pass_ssl_mode(upstream: &str) -> &'static str {
    match Uri::from_str(upstream.trim())
        .ok()
        .and_then(|u| u.scheme_str().map(str::to_ascii_lowercase))
    {
        Some(s) if s == "https" => "verify",
        _ => "off",
    }
}

pub async fn proxy_page_rule(
    req: Request<Full<Bytes>>,
    match_url: &str,
    upstream: &str,
    peer_ip: IpAddr,
    client_https: bool,
) -> Response<BoxBody> {
    let ssl_mode = page_rule_pass_ssl_mode(upstream);
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
            upstream_error_response(&e)
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

    /// P2：转发头族必须整体剥离（不只是 XFF/XFP 两个名字）。
    #[test]
    fn forwarded_header_family_is_stripped() {
        for h in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-forwarded-ssl",
            "x-real-ip",
        ] {
            assert!(is_client_forwarded_header(h), "{h} 必须剥离");
        }
        for h in ["x-custom", "forwarded-by", "x-real", "host", "x-forwardeds"] {
            assert!(!is_client_forwarded_header(h), "{h} 不应被误剥");
        }
    }

    /// Forwarded 注入值：IPv4 裸值、IPv6 加引号方括号（RFC 7239 §6）。
    #[test]
    fn forwarded_value_formats_ipv6_quoted() {
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(forwarded_value(v4, false), "for=203.0.113.7;proto=http");
        assert_eq!(forwarded_value(v4, true), "for=203.0.113.7;proto=https");
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(forwarded_value(v6, false), "for=\"[2001:db8::1]\";proto=http");
    }

    /// P3：page rule `pass` 的 https 判定必须大小写不敏感
    /// （此前 `HTTPS://` 被判成 off，同一配置因大小写落到不同 TLS 安全档）。
    #[test]
    fn page_rule_pass_ssl_mode_is_case_insensitive() {
        assert_eq!(page_rule_pass_ssl_mode("https://backend/"), "verify");
        assert_eq!(page_rule_pass_ssl_mode("HTTPS://backend/"), "verify");
        assert_eq!(page_rule_pass_ssl_mode("HtTpS://backend"), "verify");
        assert_eq!(page_rule_pass_ssl_mode("http://backend/"), "off");
        assert_eq!(page_rule_pass_ssl_mode("backend:8080"), "off");
    }

    /// P2：全局缓冲预算——整份预算只能被预留一次，drop 后归还（OOM 向量的硬上限）。
    #[test]
    fn buffer_budget_is_global_and_released_on_drop() {
        let all =
            BufferReservation::try_acquire(PROXY_BUFFER_BUDGET).expect("整份预算可预留一次");
        assert!(
            BufferReservation::try_acquire(1).is_none(),
            "已耗尽时不得再预留"
        );
        drop(all);
        assert!(
            BufferReservation::try_acquire(PROXY_BUFFER_BUDGET).is_some(),
            "drop 后应归还"
        );
    }

    /// P3：默认候选 UDS 只信任「真实 socket + 路径全程不可被他人改写」；
    /// 符号链接一律拒绝（此前用 `metadata()` 跟随链接 + 只查 is_socket）。
    #[cfg(unix)]
    #[test]
    fn uds_trust_rejects_symlinks_and_non_sockets() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("crucible-uds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let sock = base.join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(!uds_socket_trusted(std::path::Path::new(
            "/nonexistent-crucible.sock"
        )));
        symlink(&sock, base.join("link.sock")).unwrap();
        assert!(
            !uds_socket_trusted(&base.join("link.sock")),
            "符号链接必须拒绝"
        );
        std::fs::write(base.join("plain"), b"x").unwrap();
        assert!(
            !uds_socket_trusted(&base.join("plain")),
            "非 socket 必须拒绝"
        );
        drop(listener);
        let _ = std::fs::remove_dir_all(&base);
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

    /// 规格 §16.10：上游 UDS 形态识别（`unix:/path` 与裸绝对路径）。
    #[test]
    fn uds_upstream_forms_are_recognized() {
        assert_eq!(
            upstream_uds_path("unix:/run/backend.sock"),
            Some("/run/backend.sock")
        );
        assert_eq!(upstream_uds_path("unix:/tmp/x.sock"), Some("/tmp/x.sock"));
        assert_eq!(upstream_uds_path("/run/backend.sock"), Some("/run/backend.sock"));
        assert_eq!(upstream_uds_path("http://127.0.0.1:8080"), None);
        assert_eq!(upstream_uds_path("https://backend/"), None);
        assert_eq!(upstream_uds_path("backend:8080"), None);
        assert_eq!(upstream_uds_path("//evil/x"), None);
    }

    /// `is_websocket_upgrade` 必须看**全部** `Connection`/`Upgrade` 行（不只是第一行）：
    /// RFC 9110 允许把 token 拆成多行，只看第一行会把升级静默降级成普通回源。
    fn ws_req(upgrade_lines: &[&str], conn_lines: &[&str], key: bool) -> Request<Full<Bytes>> {
        let mut b = Request::builder().method("GET").uri("/ws");
        for u in upgrade_lines {
            b = b.header(UPGRADE, *u);
        }
        for c in conn_lines {
            b = b.header(CONNECTION, *c);
        }
        if key {
            b = b.header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
        }
        b.body(Full::new(Bytes::new())).unwrap()
    }

    #[test]
    fn websocket_upgrade_detects_multiline_connection_and_upgrade() {
        // 单行标准写法
        assert!(is_websocket_upgrade(&ws_req(
            &["websocket"],
            &["Upgrade"],
            true
        )));
        // Connection 跨两行：keep-alive + Upgrade（等价 `keep-alive, Upgrade`）
        assert!(is_websocket_upgrade(&ws_req(
            &["websocket"],
            &["keep-alive", "Upgrade"],
            true
        )));
        // Upgrade 跨两行
        assert!(is_websocket_upgrade(&ws_req(
            &["h2c", "websocket"],
            &["Upgrade"],
            true
        )));
        // 逗号连接的 token
        assert!(is_websocket_upgrade(&ws_req(
            &["websocket"],
            &["keep-alive, Upgrade"],
            true
        )));
        // 只有 keep-alive：不是升级
        assert!(!is_websocket_upgrade(&ws_req(
            &["websocket"],
            &["keep-alive"],
            true
        )));
        // 子串误判防护：`x-upgrade-y` 不是 `upgrade` token
        assert!(!is_websocket_upgrade(&ws_req(
            &["websocket"],
            &["x-upgrade-y"],
            true
        )));
        // 缺 key / Upgrade 不是 websocket
        assert!(!is_websocket_upgrade(&ws_req(
            &["websocket"],
            &["Upgrade"],
            false
        )));
        assert!(!is_websocket_upgrade(&ws_req(&["h2c"], &["Upgrade"], true)));
    }

    /// P2：上游超时映射 504、预算耗尽 503、其余上游故障 502（此前超时也落 502）。
    #[test]
    fn upstream_error_status_mapping() {
        let t = anyhow::Error::new(UpstreamTimeout("connect".into()));
        assert_eq!(
            upstream_error_response(&t).status(),
            StatusCode::GATEWAY_TIMEOUT
        );
        let b = anyhow::Error::new(BufferBudgetExhausted);
        assert_eq!(
            upstream_error_response(&b).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let o = anyhow::anyhow!("upstream send: connection reset by peer");
        assert_eq!(upstream_error_response(&o).status(), StatusCode::BAD_GATEWAY);
    }
}
