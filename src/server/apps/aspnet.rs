//! ASP.NET Core application engine — hostfxr FFI / mini / 502 fallback.
//!
//! **降级标注（P2-10）**：加载的是 `target/app-engines/libapp_aspnet.so`
//! （`libs/aspnet-ffi/aspnet_engine.c`）。按 §16.6 优先 hostfxr **进程内**加载
//! `docroot/bin/CrucibleAspNetSample.dll` 渲染；**本机没有 .NET 运行时/hostfxr**
//! （`command -v dotnet` 空、`~/.dotnet` 只有 sentinel、无 `libhostfxr.so`，见
//! `OPERATOR-TODO.md §3.3`），于是走 C「mini」渲染器（仍回 **200**）。
//!
//! 为让运维**从响应头就能区分**真 hostfxr 与 mini，C 引擎在**所有**降级路径都带
//! `X-Crucible-Engine: aspnet-mini`（真路径为 `aspnet-hostfxr`）：
//!   * 托管渲染成功 → `aspnet-hostfxr`；
//!   * 无 hostfxr / 无托管程序集 / 托管渲染失败 → `aspnet-mini`（200）；
//!   * 脚本不存在 → `aspnet-mini`（404）。
//! 本 Rust 层经 `handle_with_fallback` 走 FFI，`sanitize_engine_headers` 保留该头；
//! 引擎不可用时的 502 是**错误**（不是 mini），不带 200 语义。
//!
//! 不伪造 hostfxr：缺 .NET 运行时就走 mini 并如实标注，未声称「已过 CoreCLR」。

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
    sidecar_engine::handle_with_fallback(req, lc, app, peer, app_idx, "aspnet", "aspnet").await
}
