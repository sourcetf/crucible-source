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
    // 关停必须有**截止时间**。
    //
    // `Runtime` 被 drop 时会等所有 `spawn_blocking` 任务收尾，而那些任务里是同步 IO
    // （引擎 sidecar 的阻塞 UnixStream、CGI 子进程、各种 fs/DB 调用）——对端不响应就永久
    // 卡住。实测：一个实例收到 SIGTERM 后**关掉了监听端口却带着一个连接残留 6 小时**没退出，
    // 表现是 `pgrep` 里总有多余的 webserver 进程（它不监听、不服务任何请求），
    // 部署后旧实例就这样赖着不走。所以：先是 shutdown_timeout 限时收尾，再留一个看门狗
    // 兜底（万一连析构路径也在做同步 IO），保证进程一定会退出。
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let exit_code = if result.is_ok() { 0 } else { 1 };
    std::thread::spawn(move || {
        if done_rx
            .recv_timeout(std::time::Duration::from_secs(8))
            .is_err()
        {
            log::warn!(
                "shutdown: 8s 内未能正常退出 → 强制 exit({exit_code})（有阻塞任务未收尾）"
            );
            std::process::exit(exit_code);
        }
    });
    rt.shutdown_timeout(std::time::Duration::from_secs(3));
    // 正常路径：main 返回即进程退出，看门狗线程随之消失。
    drop(done_tx);
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
