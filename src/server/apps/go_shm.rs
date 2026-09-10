//! Go shared memory IPC（OpenBSD 上的 go-shm-server fallback）。
//! 仅在 `go_shm_ipc` feature + unix 平台编译为完整实现；
//! 在其它平台，available() 永为 false，execute 返回 501。

use crate::config::{AppRouteConfig, ListenerConfig};
use anyhow::Result;
use http::Request;
use hyper::body::Incoming;
use http_body_util::BodyExt;
use crate::server::h1::BoxBody;
use http_body_util::Full;
use http::Response;
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const GO_SHM_MAGIC: u32 = 0x4352_474f;
const GO_SHM_VERSION: u32 = 1;
const GO_SHM_SLOTS: u32 = 64;
const GO_SHM_BODY_MAX: u32 = 65536;
const GO_SHM_PATH_MAX: usize = 512;
const GO_SHM_METHOD_MAX: usize = 16;

const STATE_IDLE: u32 = 0;
const STATE_REQ_READY: u32 = 1;
const STATE_RESP_READY: u32 = 2;

#[repr(C)]
struct GoShmHeader {
    magic: u32,
    version: u32,
    slot_count: u32,
    slot_stride: u32,
    body_cap: u32,
}

#[repr(C)]
struct GoShmSlotMeta {
    state: u32,
    http_status: u32,
    req_body_len: u32,
    resp_body_len: u32,
    method: [u8; GO_SHM_METHOD_MAX],
    path: [u8; GO_SHM_PATH_MAX],
}

struct Runtime {
    shm_path: PathBuf,
    notify_path: PathBuf,
    child: Child,
    mmap: memmap2::MmapMut,
    header: GoShmHeaderLayout,
}

struct GoShmHeaderLayout {
    slot_stride: usize,
    body_cap: usize,
    slot_count: u32,
    data_offset: usize,
}

static RUNTIMES: Lazy<Mutex<HashMap<String, Runtime>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static RT_LOCKS: Lazy<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(all(feature = "go_shm_ipc", unix))]
pub fn available() -> bool {
    // 检查 go-shm-server 是否运行
    // TODO: 实现 socket 检查
    false
}

#[cfg(all(feature = "go_shm_ipc", unix))]
pub async fn execute(
    req: Request<Incoming>,
    _lc: &ListenerConfig,
    _app: &AppRouteConfig,
    app_idx: usize,
    peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    let body = req.body().collect().await.map(|c| c.to_bytes())?;
    Err(anyhow::anyhow!("go shm IPC not configured"))
}

#[cfg(not(all(feature = "go_shm_ipc", unix)))]
pub fn available() -> bool {
    false
}

#[cfg(not(all(feature = "go_shm_ipc", unix)))]
pub async fn execute(
    req: Request<Incoming>,
    _lc: &ListenerConfig,
    _app: &AppRouteConfig,
    _app_idx: usize,
    _peer: SocketAddr,
) -> Result<Response<BoxBody>> {
    Err(anyhow::anyhow!("go shm IPC requires go_shm_ipc feature and unix"))
}