//! Script FFI：Python/Ruby/Perl 静态嵌入（scriptffi）。
//!
//! §7.8 设计：
//! - 生产路径**禁止 spawn**（per-request CGI 已 §7.1 禁；解释器嵌入由外部 libscriptffi.so
//!   静态链 python + perl + mruby，webserver 进程 dlopen 一次，多次 exec）。
//! - 走通用 app-engine ABI（§7.2）；engine 名 = `python`/`ruby`/`perl`/`mruby`。
//! - 与 `app_ffi` 共享 LIBS 缓存与线程池：解释器非线程安全 → 串行单线程池（rack/psgi 同策略）。
//! - 缺失 libscriptffi.so 时返回 502，**不回退 CGI**（避免热路径 spawn）。

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::app_ffi;
use crate::server::h1::{full, BoxBody};
use anyhow::bail;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;

/// Script FFI 引擎的 .so 默认路径（可由 `apps[].lib` 覆盖）。
/// 命名遵循 §7.2：libapp_<engine>.so（python/ruby/perl/mruby 各一，
/// 或单一 libapp_scriptffi.so 内含多解释器——由构建脚本 `build_script_ffi.sh` 决定）。
fn default_lib_for(engine: &str) -> String {
    format!("target/app-engines/libapp_{engine}.so")
}

/// 执行脚本引擎请求。走 app_ffi ABI（dlopen + 串行线程池 + env 分锁），
/// 不再返回 "not implemented"。缺失 .so 时明确报错引导用户构建 script-ffi。
pub async fn handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
) -> anyhow::Result<Response<BoxBody>> {
    let engine = app.engine.to_ascii_lowercase();
    if !handles(&engine) {
        bail!("script_ffi: unsupported engine `{engine}`");
    }
    // apps[].lib 缺省时按命名规范推算；保证未显式配置也能尝试加载。
    let mut app_for_ffi = app.clone();
    if app_for_ffi.lib.is_none() {
        let candidate = default_lib_for(if engine == "scriptffi" { "python" } else { &engine });
        app_for_ffi.lib = Some(std::path::PathBuf::from(candidate));
    }
    // app_ffi::execute 接收 Request<Incoming>；这里直接委托。
    match app_ffi::execute(req, lc, &app_for_ffi, peer).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            let msg = format!(
                "script FFI `{engine}` unavailable: {e:#} \
                 (build libs/script-ffi via scripts/build_script_ffi.sh — no CGI fallback per spec §7.1)"
            );
            log::warn!("{msg}");
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(msg))
                .unwrap())
        }
    }
}

/// 是否是 script_ffi 负责的引擎。
pub fn handles(engine: &str) -> bool {
    matches!(engine, "python" | "ruby" | "perl" | "mruby" | "scriptffi")
}

// 让 dispatch 处 `use crate::server::apps::script_ffi;` 不再需要额外 impl。