//! 生成「去掉内层文档注释」的源码副本，供 `include!` 到本地模块里。
//!
//! 为什么需要：`include!` 不允许被包含文件以 `//!` 开头（E0753: inner doc comment
//! not permitted）。而我们要在**同一个模块作用域**里访问生产代码的私有函数
//! （`h1_fast::scan_head/parse_request`、`upload_api::hidden_segment/...`）——
//! 只有把它们包含进同名模块才行。这里只删除**整行**的 `//!` 文档注释，
//! 其余字节逐字保留（逻辑/断言/常量都不动），并在运行时由 harness 校验：
//! 生成副本的文件长度只差被删除的注释行。

use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo = manifest.parent().expect("fuzz/ 的父目录是仓库根").to_path_buf();
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));

    let sources = [
        "src/server/h1_fast.rs",
        "src/server/upload_api.rs",
    ];
    for rel in sources {
        let src_path = repo.join(rel);
        println!("cargo:rerun-if-changed={}", src_path.display());
        let src = fs::read_to_string(&src_path)
            .unwrap_or_else(|e| panic!("读取 {} 失败: {e}", src_path.display()));
        let mut stripped = String::with_capacity(src.len());
        for line in src.lines() {
            if line.trim_start().starts_with("//!") {
                continue;
            }
            stripped.push_str(line);
            stripped.push('\n');
        }
        let name = Path::new(rel).file_name().expect("file name");
        fs::write(out.join(name), stripped).expect("写出预处理副本");
    }
}
