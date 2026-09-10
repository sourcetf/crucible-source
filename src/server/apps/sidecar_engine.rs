//! Sidecar 引擎调度：C/Go/Rust/Lua/WSGI 等引擎的可用性预决策。
//!
//! 关键约束：`Request<Incoming>` 的 body 是一次性流，一旦被某条后端路径读取就无法
//! 重放。因此**不能**"先试 FFI 失败再回退 sidecar"——必须依据各后端的可用性
//! **预先选出唯一路径**（优先级：FFI .so > 已配置的 UDS socket > 可启动的 sidecar 二进制）。
//! 全不可用时返回 501，绝不回退 CGI spawn（规格 §7.1）。

use crate::config::AppRouteConfig;
use crate::config::ListenerConfig;
use crate::server::h1::BoxBody;
use crate::server::apps::{app_ffi, native_http};
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;
use bytes::Bytes;
use http_body_util::Full;

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

/// 通过 sidecar 执行请求
pub async fn sidecar_execute(
    _req: &http::Request<Bytes>,
    _app: &AppRouteConfig,
) -> Result<http::Response<bytes::Bytes>> {
    // 通过 HTTP 或 UDS 与 sidecar 通信
    Err(anyhow::anyhow!("sidecar not implemented"))
}

/// wsgi/asgi/ffi 等引擎的统一处理器：尝试 FFI → native_http sidecar → 失败返回 502。
pub async fn handle_with_fallback(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    engine: &str,
    sidecor_cmd: &str,
) -> Result<Response<BoxBody>> {
    let engine_lower = engine.to_ascii_lowercase();

    // 1. 尝试 FFI .so
    if app_ffi::lib_available(app, &engine_lower) {
        return app_ffi::execute(req, lc, app, peer).await;
    }

    // 2. 尝试 native_http sidecar
    if native_http::sidecar_available(app, lc) {
        if let Ok(resp) = native_http::try_handle(req, lc, app, peer, app_idx).await {
            return Ok(resp);
        }
    }

    // 3. 尝试 UDS sidecar
    if let Some(resp) = native_http::try_handle_uds(req, app, peer).await {
        return Ok(resp);
    }

    // 4. 均不可用：返回 502
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(BoxBody::new(Full::new(Bytes::from_static(
            b"engine unavailable (build lib or configure sidecar)"
        ))))
    .unwrap())
}
