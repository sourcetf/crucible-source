//! 把**生产源码**直接编进 fuzz harness。
//!
//! 设计：`src/server/h1_fast.rs` / `src/server/upload_api.rs` 由 `build.rs` 去掉整行
//! `//!` 文档注释后生成副本（逻辑逐字不变），再 `include!` 到一个**同名模块**里 ——
//! 这样 harness 与生产代码在同一个模块作用域，能调用私有函数
//! （`scan_head`/`parse_request`/`hidden_segment`/`real_path_gate` …），
//! 而不是复制一份实现（复制会漂移，测的就不是线上代码了）。
//!
//! 其余模块（`qmux/proto.rs`、`dns/ecs.rs`、`admin_files.rs`、`upload_resume.rs`）的
//! 被测函数都是 `pub`，用 `#[path]` 直接编进来即可。
//!
//! 生产模块里对 `crate::config` / `crate::server::{live_config,listener,static_files,…}`
//! 的引用由本文件顶部的**桩**满足；桩只被编译、不会在被 fuzz 的纯函数路径上执行
//! （`parse_request` 例外：它调用 `h1::is_valid_host_value`，桩固定返回 `true` ——
//! Host 值的真实判据由 `src/server/fuzz_tests.rs` 在真实 crate 里用 proptest 覆盖）。
#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut,
    clippy::all
)]

// ── 直接编进来的生产模块（pub API） ──────────────────────────────────────────
#[path = "../../src/server/qmux/proto.rs"]
pub mod qmux_proto;

#[path = "../../src/server/geoip_panel/iputil.rs"]
pub mod iputil_impl;

#[path = "../../src/server/dns/ecs.rs"]
pub mod dns_ecs;

#[path = "../../src/server/admin_files.rs"]
pub mod admin_files_impl;

#[path = "../../src/server/upload_resume.rs"]
pub mod upload_resume_impl;

// ── 生产模块依赖的桩 ────────────────────────────────────────────────────────
pub mod config {
    use std::path::PathBuf;

    #[derive(Clone, Default)]
    pub struct RateLimitConfig {
        pub enabled: bool,
    }

    #[derive(Clone, Default)]
    pub struct AutoindexConfig {
        pub enabled: bool,
        pub enable_upload: bool,
        pub paths: Vec<String>,
        pub upload_threads: u16,
    }

    #[derive(Clone, Default)]
    pub struct AppRouteConfig {
        pub enabled: bool,
        pub docroot: Option<PathBuf>,
    }

    #[derive(Clone, Default)]
    pub struct ListenerConfig {
        pub port: u16,
        pub root: PathBuf,
        pub ssl: Option<()>,
        pub status_path: Option<String>,
        pub access_log: Option<()>,
        pub apps: Vec<AppRouteConfig>,
        pub proxy_rules: Vec<()>,
        pub file_open: Vec<()>,
        pub basic_auth: Option<()>,
        pub port_reuse: bool,
        pub rate_limit: Option<RateLimitConfig>,
        pub autoindex: AutoindexConfig,
    }

    #[derive(Default)]
    pub struct TelemetryConfig {
        pub enabled: bool,
        pub path: String,
    }

    #[derive(Default)]
    pub struct DohConfig {
        pub enabled: bool,
        pub path: String,
        pub hostnames: Vec<String>,
    }

    #[derive(Default)]
    pub struct DnsConfig {
        pub enabled: bool,
        pub doh: DohConfig,
    }

    #[derive(Default)]
    pub struct AdminConfig {
        pub path: String,
    }

    #[derive(Default)]
    pub struct Config {
        pub listeners: Vec<ListenerConfig>,
        pub ip_access: (),
        pub telemetry: TelemetryConfig,
        pub dns: DnsConfig,
        pub admin: AdminConfig,
    }
}

pub mod server {
    pub mod apps {
        pub mod env_lock {
            /// 生产版是启动期缓存；桩直接读进程环境（fuzz 路径上不可达）。
            pub fn read_static_env(key: &str) -> Option<String> {
                std::env::var(key).ok()
            }
        }
        pub mod deps {
            use std::path::PathBuf;
            pub fn app_docroot(
                lc: &crate::config::ListenerConfig,
                app: &crate::config::AppRouteConfig,
            ) -> PathBuf {
                app.docroot.clone().unwrap_or_else(|| lc.root.clone())
            }
        }
        pub fn would_handle(_lc: &crate::config::ListenerConfig, _path: &str) -> bool {
            false
        }
    }

    pub mod page_rules {
        pub fn has_rules(_lc: &crate::config::ListenerConfig) -> bool {
            false
        }
    }

    pub mod geoip_panel {
        pub use crate::iputil_impl as iputil;
    }

    pub mod live_config {
        use std::sync::Arc;

        pub struct LiveConfig {
            cfg: Arc<crate::config::Config>,
            gen: u64,
        }

        impl LiveConfig {
            pub fn new(cfg: crate::config::Config, _path: std::path::PathBuf) -> Self {
                Self {
                    cfg: Arc::new(cfg),
                    gen: 0,
                }
            }
            pub fn snapshot(&self) -> Arc<crate::config::Config> {
                Arc::clone(&self.cfg)
            }
            pub fn listeners_generation(&self) -> u64 {
                self.gen
            }
        }

        pub fn listener_by_port(
            live: &Arc<LiveConfig>,
            port: u16,
        ) -> Option<crate::config::ListenerConfig> {
            live.snapshot()
                .listeners
                .iter()
                .find(|l| l.port == port)
                .cloned()
        }
    }

    pub fn bind_key(lc: &crate::config::ListenerConfig) -> String {
        format!("0.0.0.0|0|{}", lc.port)
    }

    pub mod h1 {
        use bytes::Bytes;

        pub type BoxBody =
            http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

        pub fn full<T: Into<Bytes>>(b: T) -> BoxBody {
            use http_body_util::BodyExt;
            http_body_util::Full::new(b.into()).map_err(|e| match e {}).boxed()
        }

        /// 桩：真实判据在 `src/server/h1.rs`，由真实 crate 的 proptest 覆盖。
        pub fn is_valid_host_value(_h: &str) -> bool {
            true
        }

        pub fn hsts_header() -> String {
            String::new()
        }
    }

    pub mod static_files {
        use bytes::Bytes;
        use http::{Request, Response};

        pub struct FileSource;

        pub async fn serve_simple<T>(
            _req: &Request<T>,
            _lc: &crate::config::ListenerConfig,
        ) -> anyhow::Result<Response<Bytes>> {
            Err(anyhow::anyhow!("fuzz stub"))
        }
    }

    pub mod access_log {
        use std::net::SocketAddr;
        use std::time::Duration;

        pub struct ConnPrefix<'a> {
            _p: std::marker::PhantomData<&'a ()>,
        }

        impl<'a> ConnPrefix<'a> {
            pub fn new(_engine: &'a str, _peer: SocketAddr) -> Self {
                Self {
                    _p: std::marker::PhantomData,
                }
            }
        }

        #[allow(clippy::too_many_arguments)]
        pub fn log_response_prefixed_with(
            _cfg: &crate::config::Config,
            _prefix: &ConnPrefix<'_>,
            _method: &str,
            _path: &str,
            _status: u16,
            _len: Option<u64>,
            _dur: Duration,
            _engine: &str,
            _override: Option<&()>,
        ) {
        }
    }

    pub mod listener {
        use std::net::SocketAddr;

        pub fn ip_allowed(
            _acl: &(),
            _lc: &crate::config::ListenerConfig,
            _peer: SocketAddr,
        ) -> bool {
            true
        }
    }

    pub mod telemetry {
        pub fn record_request() {}
    }

    pub mod dns {
        pub struct DohEff {
            pub enabled: bool,
            pub path: String,
            pub hostnames: Vec<String>,
        }

        pub struct DnsEff {
            pub doh: DohEff,
        }

        pub fn effective(cfg: &crate::config::Config) -> DnsEff {
            DnsEff {
                doh: DohEff {
                    enabled: cfg.dns.doh.enabled,
                    path: cfg.dns.doh.path.clone(),
                    hostnames: cfg.dns.doh.hostnames.clone(),
                },
            }
        }

        pub mod dot_doh {
            pub fn is_doh_request(
                _eff: &super::DnsEff,
                _path: &str,
                _host: Option<&http::HeaderValue>,
            ) -> bool {
                false
            }
        }
    }

    pub mod access {
        pub fn is_admin_path(_admin: &str, _path: &str) -> bool {
            false
        }
        pub fn cross_site_blocked(_h: &http::HeaderMap) -> bool {
            false
        }
    }

    // 真实 `safe_join` / `would_execute_on_get`（admin_files.rs 几乎自足）。
    pub use crate::admin_files_impl as admin_files;
    // 真实上传会话层（upload_api.rs 的 `super::upload_resume`）。
    pub use crate::upload_resume_impl as upload_resume;

    // ── 被测模块：生产源码 include! 进来，harness 与它同作用域 ──────────────
    pub mod h1_fast {
        include!(concat!(env!("OUT_DIR"), "/h1_fast.rs"));

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct FuzzReq {
            pub is_head: bool,
            pub http_10: bool,
            pub target: String,
            pub path: String,
            pub keep_alive: bool,
            pub host: Option<String>,
        }

        /// `scan_head` 的可判定结果（`0` = NeedMore，`1` = Complete(n)，`2` = NotUnderstood）。
        pub fn fuzz_scan(buf: &[u8], from: usize) -> (u8, usize) {
            match scan_head(buf, from) {
                HeadScan::NeedMore => (0, 0),
                HeadScan::Complete(n) => (1, n),
                HeadScan::NotUnderstood => (2, 0),
            }
        }

        pub fn fuzz_parse(head: &[u8]) -> Option<FuzzReq> {
            parse_request(head).map(|r| FuzzReq {
                is_head: r.is_head,
                http_10: r.http_10,
                target: r.target.to_string(),
                path: r.path.to_string(),
                keep_alive: r.keep_alive,
                host: r.host.map(str::to_string),
            })
        }

        pub fn fuzz_connection_has(value: &[u8], needle: &[u8]) -> bool {
            connection_has(value, needle)
        }

        /// 回退路径的字节保真：`ReplayIo` 读出来的必须是 `prefix ++ inner`。
        pub fn fuzz_replay(prefix: &[u8], inner: &[u8]) -> Vec<u8> {
            use std::pin::Pin;
            use std::sync::Arc;
            use std::task::{Context, Poll, Wake, Waker};
            use tokio::io::AsyncRead;

            struct NoopWake;
            impl Wake for NoopWake {
                fn wake(self: Arc<Self>) {}
            }

            let cursor = std::io::Cursor::new(inner.to_vec());
            let mut io = ReplayIo::new(cursor, prefix.to_vec());
            let waker = Waker::from(Arc::new(NoopWake));
            let mut cx = Context::from_waker(&waker);
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let mut rb = tokio::io::ReadBuf::new(&mut buf);
                match Pin::new(&mut io).poll_read(&mut cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            break;
                        }
                        out.extend_from_slice(rb.filled());
                    }
                    Poll::Ready(Err(_)) | Poll::Pending => break,
                }
            }
            out
        }
    }

    pub mod upload_api {
        include!(concat!(env!("OUT_DIR"), "/upload_api.rs"));

        /// 与 `handle` 内联顺序一致的纯判据镜像（只用于 fuzz 断言）：
        /// 返回 `Some(拒绝原因类别)`；`None` = 前四道闸门放行。
        ///
        /// 注意：这里**不重写**任何判据，只是依次调用生产函数：
        /// `is_double_encoded` / `hidden_segment` / `has_exec_ext`，
        /// 以及 `safe_join` 的 containment。
        pub fn fuzz_gate(decoded: &str, root: &std::path::Path) -> Option<&'static str> {
            if decoded.contains('\0') {
                return Some("nul");
            }
            if is_double_encoded(decoded) {
                return Some("double-encoded");
            }
            if decoded.split(['/', '\\']).any(|seg| seg == "..") {
                return Some("dotdot");
            }
            if has_exec_ext(decoded) {
                return Some("exec-ext");
            }
            if hidden_segment(decoded).is_some() {
                return Some("hidden");
            }
            match crate::server::admin_files::safe_join(root, decoded.trim_start_matches('/')) {
                Ok(p) => {
                    // containment：safe_join 成功时目标必须仍在 root 内。
                    let root_canon = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
                    if p == root_canon || p.starts_with(&root_canon) {
                        None
                    } else {
                        Some("escape")
                    }
                }
                Err(_) => Some("safe-join-err"),
            }
        }

        pub fn fuzz_real_path_gate(
            lc: &crate::config::ListenerConfig,
            target: &std::path::Path,
            rel: &str,
        ) -> Option<String> {
            real_path_gate(lc, target, rel)
        }

        pub fn fuzz_hidden_segment(p: &str) -> Option<String> {
            hidden_segment(p)
        }

        pub fn fuzz_double_encoded(p: &str) -> bool {
            is_double_encoded(p)
        }

        pub fn fuzz_has_exec_ext(p: &str) -> bool {
            has_exec_ext(p)
        }
    }
}
