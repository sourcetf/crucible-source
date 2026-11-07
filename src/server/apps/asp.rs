//! Classic ASP application engine — FFI / sidecar / 502 fallback.
//!
//! **实现现状 vs 规格（P2-10）**：规格 §16.6/§7.6 写「AxonASP FFI（Go c-shared）」。实际
//! 加载的是 `target/app-engines/libapp_asp.so`，由 `libs/axonasp-ffi/axonasp_engine.c`
//! （AxonASP 兼容的 **C** 实现）编出；`libaxonasp.so`（`go build -buildmode=c-shared`）
//! 在本机**不存在**，且即便构建出来也只导出 `axonasp_handle`/`axonasp_free`，**不符合**
//! appengine ABI（`appengine_init`/`execute`/`shutdown`），`app_ffi` 不会加载它。
//! 详情与证据见 `axonasp_engine.c` 文件头与 `OPERATOR-TODO.md §3.3`。此处的 FFI/sidecar/
//! 502 链与其它引擎一致（`handle_with_fallback`），响应头 `X-Crucible-Engine: asp`
//! 由 C 引擎在 200 与 404 路径统一给出。

use crate::config::{AppRouteConfig, ListenerConfig};
use crate::server::apps::sidecar_engine;
use crate::server::h1::BoxBody;
use anyhow::Result;
use http::{Request, Response};
use hyper::body::Incoming;
use std::net::SocketAddr;

pub async fn handle(
    req: Request<Incoming>,
    lc: &ListenerConfig,
    app: &AppRouteConfig,
    peer: SocketAddr,
    app_idx: usize,
) -> Result<Response<BoxBody>> {
    sidecar_engine::handle_with_fallback(req, lc, app, peer, app_idx, "asp", "asp").await
}
