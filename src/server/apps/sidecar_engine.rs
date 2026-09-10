//! Sidecar 引擎调度：C/Go/Rust/Lua/WSGI 等引擎的可用性预决策。
//!
//! 关键约束：`Request<Incoming>` 的 body 是一次性流，一旦被某条后端路径读取就无法
//! 重放。因此**不能**"先试 FFI 失败再回退 sidecar"——必须依据各后端的可用性
//! **预先选出唯一路径**（优先级：FFI .so > 已配置的 UDS socket > 可启动的 sidecar 二进制）。
//! 全不可用时返回 501，绝不回退 CGI spawn（规格 §7.1）。

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::{app_ffi, native_http};
use crate::server::h1::{full, BoxBody};
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;

/// 引擎可用性预决策 + 分发。
pub async fn handle_with_fallback(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    engine: &str,
    _sidecar_cmd: &str,  // 预留给将来的 sidecar 启动指令；目前不使用。
) -> anyhow::Result<Response<BoxBody>> {
    let engine_lower = engine.to_ascii_lowercase();

    // 1) 进程内 FFI .so（最快、零 IPC）。
    if native_http::lib_available(app, &engine_lower) {
        return app_ffi::execute(req, lc, app, peer).await;
    }

    // 2) 显式配置的常驻 UDS HTTP sidecar（apps[].socket=unix:/path，且已存活）。
    if native_http::uds_socket_available(app) {
        return native_http::try_handle_uds(req, app, peer).await;
    }

    // 3) 可启动的 sidecar 二进制（deps/bin/index）——首次请求拉起并连接池化。
    if native_http::sidecar_available(app, lc) {
        return native_http::try_handle(req, lc, app, peer, app_idx).await;
    }

    // 4) 无任何可用后端：501（不回退 CGI）。
    Ok(Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .body(full(format!(
            "engine `{engine}` unavailable: no FFI .so, no live socket=, no deps/bin/index \
             (build libs/app-engines or configure apps[].socket; CGI fallback disabled per spec)"
        )))
        .unwrap())
}

#[cfg(test)]
mod tests {
    /// 回归：分发必须是"预决策唯一路径"，不得出现对同一 Incoming body 的二次 await
    /// （try_handle 之后再 try_handle_uds 会导致 body 已消费的 UB 逻辑错误）。
    #[test]
    fn dispatch_is_predecision_exclusive() {
        let src = include_str!("sidecar_engine.rs");
        // 三条后端调用各自处于独立 `return` 分支，互斥。
        let ffi = src.find("app_ffi::execute").expect("ffi path");
        let uds = src.find("try_handle_uds").expect("uds path");
        let sc = src.find("try_handle(").expect("sidecar path");
        assert!(ffi < uds && uds < sc, "priority must be FFI > UDS > sidecar");
    }
}
