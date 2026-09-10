//! Per-engine temporary environment locks (§7.3 / §22).

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Arc;
use parking_lot::Mutex;

static ENV_LOCKS: once_cell::sync::Lazy<Mutex<HashMap<String, Arc<std::sync::Semaphore>>>> =
    once_cell::sync::Lazy::new(Default::default);

/// 同步版本：获取指定引擎的环境锁，在闭包内设置临时环境变量。
/// 用于线程池中的同步执行（app_ffi.rs 的 PoolJob）。
pub fn with_temp_env_named<T, F>(engine: &str, vars: &[(&str, &str)], f: F) -> T
where
    F: FnOnce() -> T,
{
    let sem = {
        let mut locks = ENV_LOCKS.lock();
        locks
            .entry(engine.to_string())
            .or_insert_with(|| Arc::new(std::sync::Semaphore::new(1)))
            .clone()
    };
    let _permit = sem.acquire().expect("semaphore closed");
    
    // 设置临时环境变量
    let mut saved = Vec::new();
    for (k, v) in vars {
        if let Ok(old) = std::env::var(k) {
            saved.push((k.to_string(), Some(old)));
        } else {
            saved.push((k.to_string(), None));
        }
        std::env::set_var(k, v);
    }
    
    let result = f();
    
    // 恢复环境变量
    for (k, old) in saved {
        if let Some(v) = old {
            std::env::set_var(&k, v);
        } else {
            std::env::remove_var(&k);
        }
    }
    
    result
}

/// 异步版本：用于 tokio::spawn 中的异步执行。
pub async fn with_temp_env_named_async<T, F, Fut>(engine: &str, vars: Vec<(String, String)>, f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let sem = {
        let mut locks = ENV_LOCKS.lock();
        locks
            .entry(engine.to_string())
            .or_insert_with(|| Arc::new(std::sync::Semaphore::new(1)))
            .clone()
    };
    let _permit = sem.acquire().expect("semaphore closed");
    
    // 设置临时环境变量
    let mut saved = Vec::new();
    for (k, v) in &vars {
        if let Ok(old) = std::env::var(k) {
            saved.push((k.clone(), Some(old)));
        } else {
            saved.push((k.clone(), None));
        }
        std::env::set_var(k, v);
    }
    
    let result = f().await;
    
    // 恢复环境变量
    for (k, old) in saved {
        if let Some(v) = old {
            std::env::set_var(&k, v);
        } else {
            std::env::remove_var(&k);
        }
    }
    
    result
}
