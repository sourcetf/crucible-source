#![no_main]

//! `upload_api` percent-decode + 路径闸门的属性 fuzz。
//!
//! 断言（全部调用**生产函数**，不复制判据）：
//! 1. 任意字节 → `is_double_encoded` / `hidden_segment` / `has_exec_ext` /
//!    `real_path_gate` / `safe_join` 不 panic；
//! 2. **containment**：`safe_join(root, decoded)` 成功时目标必须仍在 root 内
//!    （符号链接别名同样按 canonicalize 判）；失败则一律拒绝；
//! 3. 解码后含 `..` 段 / NUL / 双重编码 / 可执行扩展名 / 隐藏段 ⇒ 闸门必须拒绝；
//! 4. `allows_path` 的路径边界：paths=["/up"] 时只有 `/up` 与 `/up/...` 属于上传面
//!    （`/uploads`、`/upfoo` 不得命中）；
//! 5. `real_path_gate` 对符号链接别名（`up/alias -> ../.env`）必须拒绝。

use crucible_fuzz::config::{AutoindexConfig, ListenerConfig};
use crucible_fuzz::server::upload_api as up;
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;
use std::sync::OnceLock;

struct Env {
    root: PathBuf,
    lc: ListenerConfig,
}

fn env() -> &'static Env {
    static ENV: OnceLock<Env> = OnceLock::new();
    ENV.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "crucible-fuzz-upload-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(root.join("up")).expect("mkdir up");
        std::fs::write(root.join("up/plain.txt"), b"plain").expect("write plain");
        std::fs::write(root.join(".env"), b"SECRET=1").expect("write .env");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("../.env", root.join("up/alias"));
        }
        let lc = ListenerConfig {
            port: 1,
            root: root.clone(),
            autoindex: AutoindexConfig {
                enabled: true,
                enable_upload: true,
                paths: vec!["/up".to_string()],
                upload_threads: 4,
            },
            ..Default::default()
        };
        Env { root, lc }
    })
}

fuzz_target!(|data: &[u8]| {
    let e = env();
    let raw = String::from_utf8_lossy(data);
    // 与 upload_api::handle 完全同一条解码表达式（percent_encoding）。
    let decoded = percent_encoding::percent_decode_str(&raw).decode_utf8_lossy();

    // (1) 纯判据不 panic。
    let _ = up::fuzz_double_encoded(&decoded);
    let _ = up::fuzz_hidden_segment(&decoded);
    let _ = up::fuzz_has_exec_ext(&decoded);
    let _ = up::fuzz_has_exec_ext(&raw);

    // (2)(3) 闸门 + containment。`handle` 的判据是**有顺序**的（NUL → 双重编码 →
    // `..` 段 → 可执行扩展名 → 隐藏段），所以同时命中多类时只应报第一类。
    let verdict = up::fuzz_gate(&decoded, &e.root);
    let dotdot = decoded.split(['/', '\\']).any(|seg| seg == "..");
    let class = if decoded.contains('\0') {
        Some("nul")
    } else if up::fuzz_double_encoded(&decoded) {
        Some("double-encoded")
    } else if dotdot {
        Some("dotdot")
    } else if up::fuzz_has_exec_ext(&decoded) {
        Some("exec-ext")
    } else if up::fuzz_hidden_segment(&decoded).is_some() {
        Some("hidden")
    } else {
        None
    };
    match class {
        Some(c) => assert_eq!(
            verdict,
            Some(c),
            "闸门判定的类别/顺序与 handle 不一致: decoded={decoded:?}"
        ),
        None => assert!(
            !matches!(
                verdict,
                Some("nul" | "double-encoded" | "dotdot" | "exec-ext" | "hidden")
            ),
            "四道闸门都不命中却被拒绝: decoded={decoded:?} verdict={verdict:?}"
        ),
    }
    if verdict.is_none() {
        // 放行 ⇒ 必须是 root 内的真实路径。
        let target = crucible_fuzz::server::admin_files::safe_join(
            &e.root,
            decoded.trim_start_matches('/'),
        )
        .expect("放行路径必须 safe_join 成功");
        let root_canon =
            std::fs::canonicalize(&e.root).unwrap_or_else(|_| e.root.clone());
        assert!(
            target == root_canon || target.starts_with(&root_canon),
            "路径穿越: decoded={decoded:?} target={}",
            target.display()
        );
    }

    // (5) 符号链接别名必须被真实路径闸门拒绝（仅当 decoded 恰好落在该别名上）。
    #[cfg(unix)]
    if decoded.trim_start_matches('/') == "up/alias" {
        let target = crucible_fuzz::server::admin_files::safe_join(&e.root, "up/alias").unwrap();
        let why = up::fuzz_real_path_gate(&e.lc, &target, "up/alias");
        assert!(why.is_some(), "符号链接别名 up/alias -> ../.env 未被拒绝");
    }

    // (4) allows_path 的路径边界。
    let p = decoded.as_ref();
    let expected = p == "/up" || p.starts_with("/up/");
    assert_eq!(
        up::allows_path(&e.lc, p),
        expected,
        "allows_path 边界错误: {p:?}"
    );
});
