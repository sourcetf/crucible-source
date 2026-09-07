//! Crucible webserver entry point.

mod config;
mod server;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;

use config::Config;
use server::live_config::LiveConfig;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 启动即清理上一代崩溃残留的引擎子进程（php-fpm / sidecar / go-shm-server）。
    server::apps::child_registry::cleanup_orphans_at_startup();

    // QUIC/H3 (quinn) uses rustls even when TCP TLS is BoringSSL-primary.
    #[cfg(feature = "tls")]
    {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    }

    let config_path = parse_config_path();
    let cfg = Config::load(&config_path)
        .with_context(|| format!("load config {}", config_path.display()))?;

    log::info!(
        "Crucible starting; config={} listeners={}",
        config_path.display(),
        cfg.listeners.len()
    );

    let dns_cfg_path = config_path.clone();
    let live = Arc::new(LiveConfig::new(cfg, config_path));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    let result = rt.block_on(async move {
        // DNS(bind9) 控制面：启用 [dns] 时 reconcile named、启动 DoT 监听与维护循环
        server::dns::startup(&live, &dns_cfg_path).await;
        tokio::select! {
            r = server::run(live) => r,
            _ = shutdown_signal() => Ok(()),
        }
    });
    // 退出路径：终止注册的引擎子进程，防止孤儿 fpm / sidecar 堆积。
    server::apps::child_registry::kill_all();
    result
}

/// SIGTERM（scripts 重启用）或 Ctrl-C。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn parse_config_path() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" || a == "-c" {
            if let Some(p) = args.next() {
                return PathBuf::from(p);
            }
        } else if let Some(p) = a.strip_prefix("--config=") {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("config.toml")
}
