//! Per-engine temporary environment locks (§7.3 / §22).

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Arc;

/// P2-18：锁表改为动态注册——已知引擎预置，未知引擎首次使用时按名建锁。
/// 旧实现把未知名落到单把全局 FALLBACK 锁，新增引擎名会悄悄把并发打成全局串行。
static ENV_LOCKS: Lazy<Mutex<HashMap<String, Arc<Mutex<()>>>>> = Lazy::new(|| {
    let engines = [
        "php", "lua", "wsgi", "asgi", "psgi", "rack", "cgi", "uwsgi", "python", "ruby", "perl",
    ];
    Mutex::new(
        engines
            .iter()
            .map(|e| (e.to_string(), Arc::new(Mutex::new(()))))
            .collect(),
    )
});

pub fn with_temp_env_named<T, F>(engine: &str, vars: &[(&str, &str)], f: F) -> T
where
    F: FnOnce() -> T,
{
    let lock = ENV_LOCKS
        .lock()
        .entry(engine.to_string())
        .or_default()
        .clone();
    let _guard = lock.lock();
    let prev: Vec<(OsString, Option<OsString>)> = vars
        .iter()
        .map(|(k, v)| {
            let key = OsString::from(*k);
            let old = std::env::var_os(*k);
            if v.is_empty() {
                std::env::remove_var(*k);
            } else {
                std::env::set_var(*k, v);
            }
            (key, old)
        })
        .collect();
    let out = f();
    for (k, old) in prev {
        match old {
            Some(v) => std::env::set_var(&k, v),
            None => std::env::remove_var(&k),
        }
    }
    out
}
