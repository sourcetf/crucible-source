//! C/Go/Rust 无 .so 时的持久 Unix HTTP sidecar（Hyper 代理 + 简易连接池）。
//! 禁止 CGI fallback —— spawn 失败直接返回错误。

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::h1::{full, BoxBody};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

static SIDECARS: Lazy<Mutex<HashMap<String, Sidecar>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// 每个 key 一把「创建中」锁：并发首次请求只允许一个真正 spawn。
///
/// 没有它时，N 个并发的首次请求会各自走完 entire ensure 流程：每个都
/// `remove_file(sock)` + spawn + 等到自己的 sock 就绪 —— 最后只有最后一个被登记进
/// SIDECARS，前面几个进程直接变成没人管、也不再被复用的孤儿（且共用同一个 sock 路径，
/// 后 spawn 的会把先 spawn 的 socket 覆盖掉）。
/// key 的集合由配置决定（port-app_idx-engine），数量有界，无需淘汰。
#[cfg(unix)]
static SPAWN_LOCKS: Lazy<Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(unix)]
fn spawn_lock(key: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    SPAWN_LOCKS
        .lock()
        .entry(key.to_string())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

struct Sidecar {
    sock: PathBuf,
    #[allow(dead_code)]
    child: Child,
    /// 启动该 sidecar 时应用的 `.env`（指纹）与 docroot。
    ///
    /// 长驻 sidecar 的进程 env 只在 spawn 时定型：`.env` 改动或配置重载换了 app
    /// （app_idx 相同但 docroot 不同）后，旧进程必须重启，否则「新配置 + 旧环境/旧 docroot」
    /// 会一直服务下去（跨应用错配 + .env 陈旧）。指纹不同即杀旧拉新。
    env_fp: u64,
    docroot: PathBuf,
}

/// `.env` 变量集的内容指纹（与键序无关；进程内比较用）。
///
/// 为什么不用「配置里的 .env 路径 mtime」：deps 的 `.env` 解析结果才是真正装进环境的
/// 东西（含引号剥离/空值语义），指纹直接对**最终键值**做，和 `apply_clean_env` 的实际
/// 输入严格等价。
pub(crate) fn env_fingerprint(vars: &[(String, String)]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut sorted: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    sorted.sort_unstable();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for (k, v) in sorted {
        k.hash(&mut h);
        // 分隔符参与哈希：防止 ("A","BC") 与 ("AB","C") 拼出同一指纹。
        0xffu8.hash(&mut h);
        v.hash(&mut h);
    }
    h.finish()
}

/// Try FFI-less native sidecar for c/go/rust when `.so` is missing.
///
/// `env_vars` = 本请求 app 的 `.env`（deps 解析结果）。长驻 sidecar 在 spawn 时把它装进
/// 进程 env（**启动期基底 + 本 app 的 .env**，见 `apply_clean_env`），JSP/Jetty 这类
/// 读 `System.getenv` 的应用由此看到自己的 `.env`（此前一律拿空集：应用环境里没有
/// 自己的键）。`.env` 变化（内容指纹不同）或 docroot 变化 → 杀旧拉新。
pub async fn try_handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    env_vars: &[(String, String)],
) -> Result<Response<BoxBody>> {
    #[cfg(not(unix))]
    {
        let _ = (req, lc, app, peer, app_idx, env_vars);
        bail!("native_http sidecar requires Unix (OpenBSD/Linux)");
    }

    #[cfg(unix)]
    {
        let key = format!("{}-{}-{}", lc.port, app_idx, app.engine);
        let sock = ensure_sidecar(&key, lc, app, env_vars).await?;
        // 两条分支必须同语义：显式 socket 与自动探测的 `deps/bin/index` 都剥掉应用
        // 路由前缀（sidecar 挂在 `/jsp`、`/go` 这类前缀下，内部只认应用相对路径）。
        // 样例应用（c/go/rust）不回读请求路径做路由，剥前缀同样安全。
        let target = uds_target_uri(app, req.uri());
        proxy_unix(req, &sock, peer, Some(target), &[]).await
    }
}

#[cfg(unix)]
async fn ensure_sidecar(
    key: &str,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    env_vars: &[(String, String)],
) -> Result<PathBuf> {
    let fp = env_fingerprint(env_vars);
    let docroot_current = abs_canon(&app.docroot.clone().unwrap_or_else(|| lc.root.clone()));
    {
        let map = SIDECARS.lock();
        if let Some(s) = map.get(key) {
            if sock_alive(&s.sock) && s.env_fp == fp && s.docroot == docroot_current {
                return Ok(s.sock.clone());
            }
        }
    }
    // 快路径未命中：串行化创建（拿锁后必须重查 SIDECARS —— 等锁期间可能已经有人建好了）。
    // 这是并发首请求只 spawn 一个进程的关键。
    let lock = spawn_lock(key);
    let _guard = lock.lock().await;
    {
        let map = SIDECARS.lock();
        if let Some(s) = map.get(key) {
            if sock_alive(&s.sock) && s.env_fp == fp && s.docroot == docroot_current {
                return Ok(s.sock.clone());
            }
        }
    }
    // Remove dead entry（顺带收掉它的子进程：只从表里删掉等于把它变成没人管的孤儿，
    // sock 死了不代表进程已经退出）。**指纹/docroot 变化**也走这里：旧进程带着旧 `.env`
    // 或旧 docroot，必须回收重建（否则跨应用错配会一直服务下去）。
    if let Some(mut dead) = SIDECARS.lock().remove(key) {
        log::info!(
            "native_http: sidecar {key} 需要重启（.env 指纹或 docroot 变化 / sock 不可用），回收旧进程"
        );
        crate::server::apps::child_registry::kill_child(&mut dead.child);
    }

    let docroot = docroot_current;
    let state = abs_path(&PathBuf::from(format!("state/native/{key}")));
    fs::create_dir_all(&state).context("mkdir native state")?;
    let sock = abs_canon(&state.join("app.sock"));
    // **别的协议/别的注册表**（h2/h3 的 `sidecar_engine::SIDECARS_SIMPLE`）已经在同一个
    // sock 路径上服务：直接复用它，**绝不** `remove_file` + 重新 spawn —— 那会偷走对方的
    // 监听 socket，把对方刚 spawn 的进程变成谁也不管的孤儿（实测：h2c 首请求起 sidecar 后
    // 首个 h1 请求会再 spawn 一个，旧进程泄漏到 webserver 退出；反复交替可无界堆积）。
    //
    // 诚实边界（与 `sidecar_engine::ensure_sidecar_simple` 同一取舍）：复用别人管的进程时
    // 无法核验它的 `.env` 指纹（env 在对方 spawn 时定型），因此「改了 `.env` 但只有对方
    // 协议先请求」的窗口里可能短暂沿用旧环境；下一次**自己表里**的指纹检查或超时回收会
    // 纠正。宁可短暂陈旧，也不制造无人回收的孤儿进程。
    if sock_alive(&sock) {
        log::debug!("native_http: sidecar {key} 已由其它注册表拉起（sock 存活），复用");
        return Ok(sock);
    }

    let deps_bin = app
        .deps_dir
        .clone()
        .unwrap_or_else(|| docroot.join("deps"))
        .join("bin")
        .join("index");
    if !deps_bin.is_file() {
        bail!(
            "native sidecar binary missing: {} (no CGI fallback)",
            deps_bin.display()
        );
    }

    let _ = fs::remove_file(&sock);
    let log_path = state.join("sidecar.log");
    let log_file = fs::File::create(&log_path).context("sidecar.log")?;

    let mut cmd = Command::new(&deps_bin);
    // **干净环境**：sidecar 是**长驻**进程，spawn 只发生在「缓存里没有 / 上一个死了」时，
    // 而这个时刻完全可能落在**另一个应用**的请求期 `.env` 窗口内（进程 env 里装着别人的
    // 密钥）。默认继承 environ 会把这些密钥永久烤进 sidecar 的环境（真机实测：wsgi 应用
    // 的 .env 窗口里拉起 JSP sidecar，wrapper 里 `env` 能看到 WINDOWMARK/SECRET_A）。
    // 用「启动期基底 + **本 app 的 .env**」构造 envp：运维环境照旧、别人的请求期临时值
    // 一律不继承，而本 app 自己的键（JSP 的 `System.getenv`、ruby sidecar 的 `ENV`）
    // 可见 —— 这正是 §7.9 要求的「.env 注入引擎执行环境」。
    crate::server::apps::env_lock::apply_clean_env(&mut cmd, env_vars);
    cmd.current_dir(&docroot)
        .env("WEBSERVER_LISTEN_UNIX", sock.display().to_string())
        // 路由前缀：sidecar 自行决定是否剥离（JSP/Jetty 据此把 /jsp/x.jsp 映射到 docroot/x.jsp）。
        .env("WEBSERVER_APP_PREFIXES", app.paths.join(","))
        .env("WEBSERVER_WORKERS", app.workers.max(1).to_string())
        .env("DOCUMENT_ROOT", docroot.display().to_string())
        .env("GATEWAY_INTERFACE", "CGI/1.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log_file));
    let mut child = crate::server::apps::child_registry::spawn_tracked(
        &mut cmd,
        &format!("native sidecar {key}"),
    )
    .with_context(|| format!("spawn sidecar {}", deps_bin.display()))?;

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if sock_alive(&sock) {
            SIDECARS.lock().insert(
                key.to_string(),
                Sidecar {
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
    // 超时失败路径必须**收拾掉刚拉起的子进程**：只 `bail!` 的话 child 被 drop 但不
    // 终止（child_registry 的注释也点明了 Drop 不会杀进程），于是每次「sock 未就绪」
    // 都会留下一个活着却永远不被复用的 sidecar —— 反复请求就能把进程数堆起来。
    // kill_child = SIGTERM → 短暂等待 → SIGKILL → wait 回收 → 注销注册表。
    crate::server::apps::child_registry::kill_child(&mut child);
    bail!(
        "native sidecar sock not ready: {} (see {}; spawned child killed)",
        sock.display(),
        log_path.display()
    );
}

#[cfg(unix)]
fn sock_alive(sock: &Path) -> bool {
    use std::os::unix::net::UnixStream;
    UnixStream::connect(sock).is_ok()
}

/// 代理超时后杀掉**受管**（`SIDECARS` 表里登记的）sidecar 进程，返回是否真的杀了。
///
/// 为什么必须杀（实测）：挂死的 sidecar（死锁 / SIGSTOP）仍在 listen，`sock_alive()`
/// 的 connect 被内核 backlog 接住并成功 ⇒ 缓存判定「活着」，之后的每个请求都要再等满
/// `SIDECAR_TIMEOUT` 才 502，**不会自愈**。杀掉后下一个请求会重新 spawn。
///
/// 只按 **sock 路径** 在受管表里找：显式 `apps[].socket`（运维的 Jetty）不在表里，
/// 不会被误杀（那是别人管理的进程，宿主没有终止权）。SIGTERM → 短等 → SIGKILL → 回收
/// 由 `child_registry::kill_child` 完成。
#[cfg(unix)]
pub(crate) fn kill_managed_sidecar_by_sock(sock: &Path) -> bool {
    let key = {
        let map = SIDECARS.lock();
        map.iter().find(|(_, s)| s.sock == sock).map(|(k, _)| k.clone())
    };
    let Some(key) = key else {
        return false;
    };
    let removed = SIDECARS.lock().remove(&key);
    if let Some(mut dead) = removed {
        log::warn!(
            "native_http: sidecar {} 代理超时（客户端已 502）→ 终止受管进程，后续请求将重启",
            dead.sock.display()
        );
        crate::server::apps::child_registry::kill_child(&mut dead.child);
        return true;
    }
    false
}

#[cfg(unix)]
/// P2-5：每 sidecar 常驻 h1 连接池——避免每请求新建 UDS 连接 + 握手；
/// 坏连接在 send 失败路径回收重连。键 = sock 路径。
static UDS_POOL: Lazy<
    Mutex<HashMap<PathBuf, Vec<hyper::client::conn::http1::SendRequest<Full<Bytes>>>>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));
#[cfg(unix)]
const UDS_POOL_CAP: usize = 16;

/// h1 引擎 sidecar 代理的墙钟上限：整段（发送 + 响应头 + 收集响应体）共用一个 deadline。
///
/// 这是 h1 引擎代理**唯一**没有超时的路径：proxy.rs 有 UPSTREAM_*_TIMEOUT，fastcgi.rs 有
/// FCGI_TIMEOUT，sidecar_engine 的 h2/h3 字节路径有 SIDECAR_TIMEOUT，CGI/deps 各有
/// init_timeout —— 只有这里裸奔。一个「接受连接但永不回包」的 sidecar 会让请求任务、UDS
/// 池槽位与 fd 永久挂着；重复请求可无界堆积任务（fd/task 泄漏级联）。与
/// `sidecar_engine::SIDECAR_TIMEOUT` 同值同语义。
#[cfg(unix)]
const SIDECAR_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(unix)]
async fn checkout_unix(sock: &Path) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    if let Some(sender) = UDS_POOL.lock().get_mut(sock).and_then(Vec::pop) {
        if sender.is_ready() {
            return Ok(sender);
        }
        // 池里取出的连接已坏：丢弃走新建。
    }
    let stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect {}", sock.display()))?;
    let (sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .context("h1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("native_http conn: {e}");
        }
    });
    Ok(sender)
}

#[cfg(unix)]
fn checkin_unix(sock: &Path, sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>) {
    if sender.is_ready() {
        let mut map = UDS_POOL.lock();
        let v = map.entry(sock.to_path_buf()).or_default();
        if v.len() < UDS_POOL_CAP {
            v.push(sender);
        }
    }
}

#[cfg(unix)]
/// 显式 `apps[].socket`（UDS sidecar）的目标路径：**剥掉应用路由前缀**。
///
/// 为什么必须剥：sidecar 是「挂在某个路径前缀下的应用」（JSP 挂在 `/jsp`、ActionBridge
/// 挂在 `/do`），Jetty 侧的 WebAppContext 是 `/`，它期望的是**应用内相对路径**。
/// 原样转发 `/jsp/index.jsp` 会让 Jetty 去 `<docroot>/jsp/index.jsp` 找文件 —— 不存在，
/// 于是恒 404（实测：`curl /jsp/` 拿到的是 Jetty 自己的 404 页，`/do/` 同样）。
/// 目录请求回落到 `index`（`/jsp/` → `/index.jsp`），与 FFI/cgi_script 同一套判据。
///
/// 只对**显式配置的 socket** 生效；自动探测的 `deps/bin/index` sidecar（c/go/rust 的
/// 无 .so 回退）保持原路径语义不变（那些样例应用自己打印 `r.URL.Path`）。
fn uds_target_uri(app: &AppRouteConfig, uri: &http::Uri) -> http::Uri {
    let rel = crate::server::apps::app_ffi::rel_script_path(app, uri.path());
    let s = match uri.query() {
        Some(q) => format!("{rel}?{q}"),
        None => rel,
    };
    s.parse::<http::Uri>().unwrap_or_else(|_| uri.clone())
}

async fn proxy_unix(
    req: Request<Incoming>,
    sock: &Path,
    peer: SocketAddr,
    target: Option<http::Uri>,
    extra_headers: &[(String, String)],
) -> Result<Response<BoxBody>> {
    use hyper::client::conn::http1;

    let (parts, body) = req.into_parts();
    let is_head = parts.method == http::Method::HEAD;
    // 任务 6（OOM 防护）：sidecar 请求体上限 32MiB；Limited 错误已装箱 → map_err。
    let collected = http_body_util::Limited::new(body, crate::server::h1::APP_BODY_CAP)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("collect body: {e}"))?;
    let bytes = collected.to_bytes();
    let peer_ip = peer.ip().to_string();

    let target = target.unwrap_or_else(|| parts.uri.clone());
    let build = || -> Result<http::Request<Full<Bytes>>> {
        let mut builder = Request::builder()
            .method(parts.method.clone())
            .uri(target.clone());
        for (k, v) in parts.headers.iter() {
            let lower = k.as_str().to_ascii_lowercase();
            // **丢弃客户端自带的转发头**，否则客户端可以把任意 IP 放在最左边，
            // 后端拿它做日志/ACL 就是伪造点（proxy.rs 的 WS 路径早就是「跳过再写」，
            // 这里此前是「追加语义」，把客户端值原样传下去了）。
            // `x-crucible-env-*` 同理：只能由宿主按本 app 的 deps 生成（见 extra_headers）。
            if matches!(
                lower.as_str(),
                "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" | "x-real-ip"
            ) || lower.starts_with("x-crucible-env-")
            {
                continue;
            }
            builder = builder.header(k, v);
        }
        // 只写真实 peer（sidecar 是本地应用后端，它要的就是「谁连到了 webserver」）。
        builder = builder.header("x-forwarded-for", peer_ip.clone());
        // `.env` 转发头（只由宿主根据本 app 的 deps 生成；见 sidecar_engine 的
        // `env_forward_headers`）。对这些头同样先写覆盖：客户端伪造无效。
        for (k, v) in extra_headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder.body(Full::new(bytes.clone()))
            .context("build upstream req")
    };

    // P2-5：池化 checkout；坏连接重建后重试一次。
    // 池化 checkout；**只**在发送前检查连接可用性，不对已发出的请求重试。
    //
    // hyper 在「请求已写入、上游随即关闭」时同样返回 Err——旧代码对任何 Err 都
    // 无条件重建连接再发一次，非幂等请求（POST 等）会在上游被执行两次。
    // 真需要上游重试应由调用方按方法幂等性显式决定，传输层不该擅自复制请求。
    let mut sender = checkout_unix(sock).await?;
    if !sender.is_ready() {
        sender = checkout_unix(sock).await?;
    }
    // 整段一个 deadline（见 SIDECAR_TIMEOUT 说明）。超时后这条连接已不可复用，直接丢弃、
    // 不 checkin —— 否则一个卡死的 sidecar 连接会被放回池里毒化后续请求。
    //
    // 超时还必须**杀掉受管的 sidecar 进程**：挂死的进程（死锁/被 SIGSTOP）仍然占着监听
    // socket，`sock_alive()` 的 connect 会落进 backlog 而成功 ⇒ 该 sidecar 在缓存里永远
    // 「活着」，之后每个请求都要再等满 30s 才 502，**永不恢复**（真机实测：SIGSTOP 后两次
    // 连续请求都是 30s+502，进程一直挂着）。杀掉之后下一个请求走 ensure_sidecar 重新拉起。
    // 只动 SIDECARS 里登记的（宿主自己 spawn 的）进程；显式 `apps[].socket`
    //（运维自己起的 Jetty）不在表里，绝不会被误杀。
    let (rparts, rbytes) = tokio::time::timeout(SIDECAR_TIMEOUT, async {
        let resp = sender.send_request(build()?).await.context("sidecar request")?;
        let (rparts, rbody) = resp.into_parts();
        // 任务 6（OOM 防护）：sidecar 响应体上限 64MiB。
        let rbytes = http_body_util::Limited::new(rbody, crate::server::h1::UPSTREAM_BODY_CAP)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("collect upstream body: {e}"))?
            .to_bytes();
        Ok::<_, anyhow::Error>((rparts, rbytes))
    })
    .await
    .map_err(|_| {
        // 跨协议兜底：sidecar 也可能是 h2/h3 字节路径（sidecar_engine 注册表）拉起的，
        // 它挂在同一个 sock 路径上。只杀自己表里的话，这条协议在「对方起的进程挂死」时
        // 永远不自愈（反向同理，见 sidecar_engine::proxy_uds_simple）。任一侧杀成功后，
        // 下一个请求（任一协议）都会重新拉起。
        if !kill_managed_sidecar_by_sock(sock) {
            crate::server::apps::sidecar_engine::kill_managed_sidecar_simple_by_sock(sock);
        }
        anyhow::anyhow!("sidecar timeout after {SIDECAR_TIMEOUT:?}")
    })??;
    checkin_unix(sock, sender);
    // 上游响应头必须净化后再透传：sidecar 是「挂在某个路径前缀下的应用」，它回的
    // `Content-Length`/`Transfer-Encoding` 与我们重建的 body 不符时会造成响应走私
    // （与 proxy.rs / sidecar_engine.rs 同一套净化；本路径此前漏了）。
    let headers = super::fastcgi::sanitize_response_headers(
        rparts.headers,
        rbytes.len(),
        is_head,
    );
    let mut out = Response::builder().status(rparts.status);
    for (k, v) in headers.iter() {
        out = out.header(k, v);
    }
    Ok(out.body(full(rbytes)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(full("native_http response build error"))
            .unwrap()
    }))
}

fn abs_path(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

fn abs_canon(p: &Path) -> PathBuf {
    let a = abs_path(p);
    fs::canonicalize(&a).unwrap_or(a)
}

/// Whether a default/configured `.so` exists for in-process FFI.
pub fn lib_available(app: &AppRouteConfig, engine: &str) -> bool {
    if let Some(p) = &app.lib {
        return p.is_file();
    }
    project_path(&format!("target/app-engines/libapp_{engine}.so")).is_file()
}

/// Sidecar binary from init.sh (`deps/bin/index`) for c/go/rust when FFI .so is unavailable.
pub fn sidecar_available(app: &AppRouteConfig, lc: &ListenerConfig) -> bool {
    sidecar_binary(app, lc).is_some()
}

pub fn sidecar_binary(app: &AppRouteConfig, lc: &ListenerConfig) -> Option<PathBuf> {
    let docroot = app
        .docroot
        .clone()
        .unwrap_or_else(|| lc.root.clone());
    let deps_bin = app
        .deps_dir
        .clone()
        .unwrap_or_else(|| docroot.join("deps"))
        .join("bin")
        .join("index");
    let p = abs_path(&deps_bin);
    p.is_file().then_some(p)
}

/// Configured Unix domain socket for HTTP sidecar (e.g. JSP Jetty/Python shim).
pub fn uds_socket_available(app: &AppRouteConfig) -> bool {
    uds_socket_path(app).is_some_and(|p| {
        #[cfg(unix)]
        {
            sock_alive(&p)
        }
        #[cfg(not(unix))]
        {
            let _ = p;
            false
        }
    })
}

pub fn uds_socket_path(app: &AppRouteConfig) -> Option<PathBuf> {
    let raw = app.socket.as_ref()?;
    let p = raw.strip_prefix("unix:").unwrap_or(raw.as_str());
    let path = abs_path(Path::new(p));
    path.exists().then_some(path)
}

/// Proxy one request to a pre-started UDS HTTP sidecar (`apps[].socket`).
///
/// 显式 socket 是**运维自己起的**进程（如 Jetty）：宿主无法再注入它的进程 env，因此
/// 本 app 的 `.env` 以 `x-crucible-env-<key>` 请求头（percent-encoded 值）转发，
/// 由 sidecar 侧自行读取（约定见 `sidecar_engine::env_forward_headers`）。
pub async fn try_handle_uds(
    req: Request<Incoming>,
    app: &AppRouteConfig,
    peer: SocketAddr,
    extra_headers: &[(String, String)],
) -> Result<Response<BoxBody>> {
    #[cfg(not(unix))]
    {
        let _ = (req, app, peer, extra_headers);
        bail!("UDS sidecar requires Unix (OpenBSD/Linux)");
    }
    #[cfg(unix)]
    {
        let sock = uds_socket_path(app).context("apps[].socket missing")?;
        let target = uds_target_uri(app, req.uri());
        proxy_unix(req, &sock, peer, Some(target), extra_headers).await
    }
}

fn project_path(rel: &str) -> PathBuf {
    abs_path(Path::new(rel))
}
