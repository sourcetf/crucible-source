//! Reads `build/crucible-build.toml` (from `./configure`) and sets `cfg` flags.
//! Also builds TLS C shims: BoringSSL is linked via the `boring` crate; NSS /
//! TomCrypt legacy stacks compile here when features are enabled.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tls_nss_enabled)");
    println!("cargo::rustc-check-cfg=cfg(tls_tomcrypt_enabled)");
    println!("cargo::rustc-check-cfg=cfg(go_engine_shm)");
    println!("cargo::rustc-check-cfg=cfg(crucible_linux)");
    println!("cargo::rustc-check-cfg=cfg(linux_busy_poll)");
    println!("cargo::rustc-check-cfg=cfg(linux_syncookie)");
    let path = Path::new("build/crucible-build.toml");
    if !path.exists() {
        let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        if os == "linux" {
            println!("cargo:rustc-cfg=crucible_linux");
            println!("cargo:rustc-cfg=linux_busy_poll");
            println!("cargo:rustc-cfg=linux_syncookie");
        }
        if os == "openbsd" {
            println!("cargo:rustc-cfg=go_engine_shm");
        }
        maybe_build_tls_shims();
        return;
    }

    let content = fs::read_to_string(path).expect("read build/crucible-build.toml");
    let map = parse_simple_toml(&content);

    if map.get("target_os").map(|s| s.as_str()) == Some("linux") {
        println!("cargo:rustc-cfg=crucible_linux");
        println!("cargo:rustc-cfg=linux_busy_poll");
        println!("cargo:rustc-cfg=linux_syncookie");
    }
    if map.get("go_engine_mode").map(|s| s.as_str()) == Some("shm") {
        println!("cargo:rustc-cfg=go_engine_shm");
    }
    if map.get("enable_nss").map(|s| s.as_str()) == Some("yes") {
        println!("cargo:rustc-cfg=tls_nss_enabled");
    }
    if map.get("enable_tomcrypt").map(|s| s.as_str()) == Some("yes") {
        println!("cargo:rustc-cfg=tls_tomcrypt_enabled");
    }

    if let Some(wt) = map.get("worker_threads") {
        println!("cargo:rustc-cfg=worker_threads=\"{wt}\"");
    }

    maybe_build_tls_shims();

    println!("cargo:rerun-if-changed=build/crucible-build.toml");
    println!("cargo:rerun-if-changed=libs/tls-common/peek_io.c");
    println!("cargo:rerun-if-changed=libs/tls-common/pem_util.c");
    println!("cargo:rerun-if-changed=libs/tls-nss/nss_shim.c");
    println!("cargo:rerun-if-changed=libs/tls-tomcrypt/tc_shim.c");
}

fn maybe_build_tls_shims() {
    let features = env::var("CARGO_CFG_FEATURE").unwrap_or_default();
    let want_nss = features.split(',').any(|f| f == "tls_nss");
    let want_tc = features.split(',').any(|f| f == "tls_tomcrypt");
    if !want_nss && !want_tc {
        return;
    }
    // Shared PEM/peek helpers — single static lib to avoid duplicate symbols.
    build_tls_common();
    if want_nss {
        build_nss_shim();
        println!("cargo:rustc-cfg=tls_nss_enabled");
    }
    if want_tc {
        build_tomcrypt_shim();
        println!("cargo:rustc-cfg=tls_tomcrypt_enabled");
    }
}

fn add_openbsd_tls_paths(builder: &mut cc::Build) {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "openbsd" {
        // OpenBSD ports: headers under include/nss and include/nspr (not nss3/).
        builder.include("/usr/local/include/nss");
        builder.include("/usr/local/include/nspr");
        builder.include("/usr/local/include/nspr/private");
        builder.include("/usr/local/include");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    } else {
        builder.include("/usr/include/nss");
        builder.include("/usr/include/nss3");
        builder.include("/usr/include/nspr");
        builder.include("/usr/include/nspr4");
        builder.include("/usr/include/nspr/private");
    }
}

fn build_tls_common() {
    let mut build = cc::Build::new();
    build.file("libs/tls-common/peek_io.c");
    build.file("libs/tls-common/pem_util.c");
    build.include("libs/tls-common");
    build.warnings(false);
    build.compile("crucible_tls_common");
    println!("cargo:rustc-link-lib=static=crucible_tls_common");
}

fn build_nss_shim() {
    let mut build = cc::Build::new();
    build.file("libs/tls-nss/nss_shim.c");
    build.include("libs/tls-common");
    add_openbsd_tls_paths(&mut build);
    // private/pprio.h for PR_ImportTCPSocket
    build.warnings(false);
    build.compile("crucible_tls_nss");
    println!("cargo:rustc-link-lib=static=crucible_tls_nss");
    println!("cargo:rustc-link-lib=nss3");
    println!("cargo:rustc-link-lib=ssl3");
    println!("cargo:rustc-link-lib=smime3");
    println!("cargo:rustc-link-lib=nssutil3");
    println!("cargo:rustc-link-lib=plds4");
    println!("cargo:rustc-link-lib=plc4");
    println!("cargo:rustc-link-lib=nspr4");
}

fn build_tomcrypt_shim() {
    let mut build = cc::Build::new();
    build.file("libs/tls-tomcrypt/tc_shim.c");
    build.include("libs/tls-common");
    build.define("CRUCIBLE_HAVE_TOMCRYPT", None);
    // LTC_ARGCHK → return error codes (never abort). Must match vendored libtomcrypt.a.
    build.define("ARGTYPE", Some("2"));
    add_openbsd_tls_paths(&mut build);
    let vendored_inc = Path::new("target/tls-libs/include");
    if vendored_inc.exists() {
        build.include(vendored_inc);
    }
    let src_inc = Path::new("target/tls-libs/libtomcrypt-src/libtomcrypt/src/headers");
    if src_inc.exists() {
        build.include(src_inc);
    }
    build.warnings(false);
    build.compile("crucible_tls_tomcrypt");
    println!("cargo:rustc-link-lib=static=crucible_tls_tomcrypt");
    let vendored = Path::new("target/tls-libs/libtomcrypt.a");
    if !vendored.exists() {
        panic!(
            "tls_tomcrypt requires vendored target/tls-libs/libtomcrypt.a \
             (run scripts/build_libtomcrypt.sh with ARGTYPE=2). \
             System libtomcrypt often uses LTC_ARGCHK→abort() and will kill the process."
        );
    }
    println!("cargo:rustc-link-search=native=target/tls-libs");
    println!("cargo:rustc-link-lib=static=tomcrypt");
    // ltm_desc requires LibTomMath at final link.
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-lib=tommath");
}

fn parse_simple_toml(content: &str) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim().to_string();
            let v = v.trim().trim_matches('"').to_string();
            m.insert(k, v);
        }
    }
    m
}
