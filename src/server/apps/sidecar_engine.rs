//! Shared FFI / Unix sidecar dispatch for optional app engines.

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::{app_ffi, native_http};
use crate::server::h1::{full, BoxBody};
use anyhow::Result;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;

pub async fn handle_with_fallback(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
    engine: &str,
    stub_body: &str,
) -> Result<Response<BoxBody>> {
    if native_http::lib_available(app, engine) {
        return app_ffi::execute(req, lc, app, peer).await;
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
        return native_http::try_handle_uds(req, app, peer).await;
    }
    if native_http::sidecar_available(app, lc) {
        return native_http::try_handle(req, lc, app, peer, app_idx).await;
    }
    // No FFI .so and no sidecar/UDS — do not pretend success.
    let _ = stub_body;
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(format!(
            "502 Bad Gateway: engine `{engine}` unavailable (no libapp_{engine}.so, sidecar, or socket)\n"
        )))
        .unwrap())
}
