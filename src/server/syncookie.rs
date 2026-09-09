//! Linux `/proc/sys/net/ipv4/tcp_syncookies` read/write + evaluate loop (feature-gated).

use crate::server::live_config::LiveConfig;
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(all(target_os = "linux", feature = "linux_syncookie"))]
const PROC_PATH: &str = "/proc/sys/net/ipv4/tcp_syncookies";

/// P2-7：accept 路径的连接计数信号（server::mod accept_loop 每次 accept 调 note_syn）。
/// 评估器按 tick 差值估算速率，在 value_on / value_off 之间动态切换——
/// 旧实现只会周期性写 value_on，value_off 是死配置、也没有任何负载评估。
static SYN_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn note_syn() {
    SYN_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// SYN 速率阈值（次/秒）：超过视为疑似 SYN 洪水 → value_on；回落 → value_off。
/// 简化评估信号（syncookie 配置无独立阈值字段），后续可把阈值提升为可配置项。
const SYN_RATE_THRESHOLD: u64 = 2000;

/// Read current tcp_syncookies sysctl value (0 or 1 on Linux).
pub fn read_enabled() -> Result<u8> {
    read_enabled_impl()
}

/// Write tcp_syncookies sysctl value (0 or 1 on Linux).
pub fn write_enabled(value: u8) -> Result<()> {
    write_enabled_impl(value)
}

/// Background evaluator: re-reads live config each tick so reload applies.
pub fn spawn_evaluator(live: Arc<LiveConfig>) {
    tokio::spawn(async move {
        // P2-7：动态评估——tick 间 accept 速率决定写 value_on 还是 value_off。
        let mut prev: u64 = SYN_COUNT.load(Ordering::Relaxed);
        loop {
            let cfg = live.snapshot().syncookie.clone();
            let interval = Duration::from_millis(cfg.evaluate_interval_ms.max(500));
            tokio::time::sleep(interval).await;
            if !cfg.enabled {
                continue;
            }
            #[cfg(all(target_os = "linux", feature = "linux_syncookie"))]
            {
                let now = SYN_COUNT.load(Ordering::Relaxed);
                let delta = now.saturating_sub(prev);
                prev = now;
                let secs = interval.as_secs_f64().max(0.001);
                let rate = (delta as f64 / secs) as u64;
                let target: u8 = if rate >= SYN_RATE_THRESHOLD {
                    cfg.value_on.parse().unwrap_or(1)
                } else {
                    cfg.value_off.parse().unwrap_or(0)
                };
                if let Err(e) = write_enabled(target) {
                    log::debug!("syncookie evaluate: {e:#}");
                }
                log::debug!("syncookie evaluate: rate={rate}/s target={target}");
            }
            #[cfg(not(all(target_os = "linux", feature = "linux_syncookie")))]
            {
                // OpenBSD 等平台：内核自行管理 syncookies，评估循环保持 no-op。
                let _ = (&cfg, &mut prev);
                log::trace!("syncookie evaluate no-op on this platform");
            }
        }
    });
}

#[cfg(all(target_os = "linux", feature = "linux_syncookie"))]
fn read_enabled_impl() -> Result<u8> {
    let raw = std::fs::read_to_string(PROC_PATH).context("read tcp_syncookies")?;
    raw.trim()
        .parse::<u8>()
        .context("parse tcp_syncookies")
}

#[cfg(all(target_os = "linux", feature = "linux_syncookie"))]
fn write_enabled_impl(value: u8) -> Result<()> {
    std::fs::write(PROC_PATH, format!("{value}\n")).context("write tcp_syncookies")
}

#[cfg(not(all(target_os = "linux", feature = "linux_syncookie")))]
fn read_enabled_impl() -> Result<u8> {
    Ok(0)
}

#[cfg(not(all(target_os = "linux", feature = "linux_syncookie")))]
fn write_enabled_impl(_value: u8) -> Result<()> {
    Ok(())
}
