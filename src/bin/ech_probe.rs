//! ECH 现场探针：用我们自己依赖的 `boring` 作客户端，对**正在运行的** listener 做一次
//! 真实 ECHClientHello，并报告服务端是否接受了 ECH。
//!
//! 为什么需要它：`curl --ech` 在本机不可用（OpenBSD 自带 curl 是 LibreSSL 后端，
//! `--ech: the installed libcurl version does not support this`），而 ECHConfigList
//! 只有我们自己 `ech_auto` 生成的那份。于是「生产上 ECH 到底生不生效」这件事，
//! 只能由我们自己的客户端来回答 —— 思路与 `ech_handshake_test.rs` 相同，
//! 区别是本工具打的是**线上端口**，而不是测试里自建的 acceptor。
//!
//! 用法：
//! ```text
//! ech_probe <host:port> <ech_config_list.bin> <inner_name> [--no-ech]
//! ```
//! * `--no-ech`：故意**不带** ECHConfigList，只把内层真实名当 SNI 发出去
//!   （探测场景：确认「猜域名」拿不到真实证书）。
//!
//! 判据（对齐 RFC 9849 与本项目的验收标准）：
//! 1. `ECH_ACCEPTED=true` 才算服务端成功解开了 ClientHelloInner；
//! 2. 同时打印对端证书 CN/SAN 与 SHA-256 —— ECH 被接受时应当是**真实证书**，
//!    未被接受时只能是外层（cover）证书。只看第 1 条会被「标称成功但证书是外层」骗过。

use boring::ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode};
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: ech_probe <host:port> <ech_config_list.bin> <inner_name> [--no-ech]");
        std::process::exit(2);
    }
    let addr = &args[1];
    let list_path = &args[2];
    let inner = &args[3];
    let no_ech = args.iter().any(|a| a == "--no-ech");

    match probe(addr, list_path, inner, no_ech) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("PROBE_ERROR: {e}");
            std::process::exit(1);
        }
    }
}

fn probe(addr: &str, list_path: &str, inner: &str, no_ech: bool) -> Result<(), String> {
    let mut b = SslContext::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    // 只验 ECH 行为，不做链校验（真实/外层证书由我们比对 CN/SAN 自行判定）
    b.set_verify(SslVerifyMode::NONE);
    let ctx = b.build();

    let mut ssl = Ssl::new(&ctx).map_err(|e| e.to_string())?;
    // 内层（真实）名：ECH 被接受时服务端才能看到它
    ssl.set_hostname(inner).map_err(|e| e.to_string())?;
    if !no_ech {
        let list = std::fs::read(list_path).map_err(|e| format!("read {list_path}: {e}"))?;
        // ECHConfigList 是**连接级**配置（SSL_set1_ech_config_list）
        ssl.set_ech_config_list(&list)
            .map_err(|e| format!("set_ech_config_list: {e}"))?;
    }

    let tcp = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    let mut tls = SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
    tls.connect().map_err(|e| format!("TLS connect: {e}"))?;

    println!("ECH_ACCEPTED={}", tls.ssl().ech_accepted());
    println!("ALPN={:?}", tls.ssl().selected_alpn_protocol());
    if let Some(name) = tls.ssl().servername(boring::ssl::NameType::HOST_NAME) {
        // 客户端侧看到的是自己设进去的名字（服务端看到了什么，由服务端日志回答）
        println!("CLIENT_SNI={name}");
    }
    if let Some(cert) = tls.ssl().peer_certificate() {
        let cn = cert
            .subject_name()
            .entries_by_nid(boring::nid::Nid::COMMONNAME)
            .next()
            .map(|e| String::from_utf8_lossy(e.data().as_slice()).to_string())
            .unwrap_or_else(|| "?".into());
        println!("PEER_CN={cn}");
        if let Some(ext) = cert.subject_alt_names() {
            let names: Vec<String> = ext
                .iter()
                .filter_map(|n| n.dnsname().map(|s| s.to_string()))
                .collect();
            println!("PEER_SAN={}", names.join(","));
        }
        let sha = cert
            .digest(boring::hash::MessageDigest::sha256())
            .map(|d| d.to_vec())
            .unwrap_or_default();
        println!("PEER_SHA256={}", sha.iter().map(|x| format!("{x:02x}")).collect::<String>());
    }

    // 握手之后必须真的能收发：ECH 只影响握手，但「握手成功却传不了数据」同样是坏的。
    tls.write_all(b"GET / HTTP/1.0\r\nHost: ").map_err(|e| e.to_string())?;
    tls.write_all(inner.as_bytes()).map_err(|e| e.to_string())?;
    tls.write_all(b"\r\n\r\n").map_err(|e| e.to_string())?;
    let mut buf = [0u8; 64];
    let n = tls.read(&mut buf).map_err(|e| e.to_string())?;
    println!(
        "HTTP_FIRST_LINE={:?}",
        String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("")
    );
    Ok(())
}
