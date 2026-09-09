//! 环境变量锁：为不同引擎分离的 env 锁，防止全局互斥把并发打成串行。
//! P1-1：按引擎分锁（禁止全进程一把锁）。

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

static ENV_LOCKS: once_cell::sync::Lazy<Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>> =
    once_cell::sync::Lazy::new(Default::default);

/// 获取指定引擎的环境锁
pub async fn with_temp_env_named<T, E, F, Fut>(engine: &str, f: F) -> Result<T, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let sem = {
        let mut locks = ENV_LOCKS.lock().await;
        locks
            .entry(engine.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)))
            .clone()
    };
    let _permit = sem.acquire().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    f().await
}
