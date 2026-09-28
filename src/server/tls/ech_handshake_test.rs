//! ECH **真机握手**测试：用我们自己的 `boring` 依赖当客户端，对本地 TLS 服务端做一次
//! 真实 ECH 握手。
//!
//! # 为什么要有这个文件
//!
//! 之前讨论「ECH 需要外层（cover）证书」时，我一度以「现场没有 ECH 客户端、无法验证」为由
//! 想把实现留成「写了但标注未验证」—— 那是自欺欺人：**我们自己依赖的 `boring` 就能当
//! ECH 客户端**（`SslRef::set_ech_config_list` / `ech_accepted()` / `get_ech_name_override()`），
//! 而 ECHConfigList 还是我们 `ech_auto` 自己生成的。于是握手能不能验，取决于我们**有没有写
//! 这个测试**，而不是现场有没有现成工具。
//!
//! 这个测试回答两个问题（两者都必须为真才叫「ECH 生效」）：
//! 1. 客户端 `ech_accepted() == true` —— 服务端用我们的密钥成功解开了 ClientHelloInner；
//! 2. **服务端看到的 SNI 是内层真实名**（外层名由 ECHConfig 的 public_name 决定，明文可见）
//!    —— 这条才证明「加密的才是真名字」，只看第 1 条会被「协商标称成功但名字没换」骗过。
//!
//! 有了它，(b) 类「ECH 未被接受时用外层证书」的实现才有验收手段：
//! 同一套 harness 里，非 ECH 客户端 / ECH 被拒客户端必须拿到 **cover** 证书。

#![cfg(all(test, feature = "tls_boring"))]

use boring::pkey::PKey;
use boring::ssl::{
    NameType, Ssl, SslContext, SslContextBuilder, SslContextRef, SslMethod, SslStream,
    SslVerifyMode,
};
use boring::x509::X509;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// 仓库自带的测试证书（tests 的 cwd 是 crate 根）。
const CERT: &str = "cert.pem";
const KEY: &str = "key.pem";

fn load_cert_key() -> (X509, PKey<boring::pkey::Private>) {
    let cert = X509::from_pem(&std::fs::read(CERT).expect("cert.pem（仓库自带）")).expect("cert PEM");
    let key = PKey::private_key_from_pem(&std::fs::read(KEY).expect("key.pem（仓库自带）"))
        .expect("key PEM");
    (cert, key)
}

/// 服务端 ctx：默认证书 + 我们的 ECH 密钥。
fn server_ctx(ech_keys: &boring::ssl::SslEchKeys) -> SslContext {
    let (cert, key) = load_cert_key();
    let mut b = SslContextBuilder::new(SslMethod::tls()).expect("server ctx");
    b.set_certificate(&cert).expect("set_certificate");
    b.set_private_key(&key).expect("set_private_key");
    b.set_ech_keys(ech_keys).expect("set_ech_keys");
    b.build()
}

fn client_ctx() -> SslContext {
    let mut b = SslContextBuilder::new(SslMethod::tls()).expect("client ctx");
    // 只验 ECH 行为，证书链校验关掉（否则还要构造 CA 与 SAN）
    b.set_verify(SslVerifyMode::NONE);
    b.build()
}

/// 一次完整握手。返回 `(客户端是否 ECH 成功, 服务端看到的 SNI, 客户端看到的对端证书 CN)`。
fn handshake(
    server: &boring::ssl::SslContextRef,
    client: &SslContextRef,
    inner_name: &str,
    ech_config_list: Option<&[u8]>,
) -> (bool, Option<String>, Option<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    // SslContextRef 不能 clone；服务端线程持有 Arc<SslContext>（用 ToOwned）
    let server_ctx: SslContext = server.to_owned();

    let srv = std::thread::spawn(move || -> (Option<String>, Option<String>) {
        let (sock, _) = listener.accept().expect("accept");
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
        let ssl = Ssl::new(&server_ctx).expect("server ssl");
        let mut stream = match SslStream::new(ssl, sock) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ech-test] 服务端 SslStream::new 失败: {e}");
                return (None, None);
            }
        };
        if let Err(e) = stream.accept() {
            eprintln!("[ech-test] 服务端 accept 失败: {e}");
            return (None, None);
        }
        // 服务端看到的 SNI：ECH 成功时应当是**内层真实名**
        let sni = stream.ssl().servername(NameType::HOST_NAME).map(|s| s.to_string());
        // 读一个字节再回一个字节，证明握手后数据可用
        let mut b = [0u8; 1];
        let _ = stream.read(&mut b);
        let _ = stream.write_all(b"k");
        // 服务端本次呈现的证书 CN（用于 (b) 类的外层证书断言）
        let cn = stream
            .ssl()
            .peer_certificate()
            .and_then(|c| c.subject_name().entries_by_nid(boring::nid::Nid::COMMONNAME).next().map(|e| {
                String::from_utf8_lossy(e.data().as_slice()).to_string()
            }));
        (sni, cn)
    });

    let sock = TcpStream::connect(addr).expect("connect");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    let mut ssl = Ssl::new(client).expect("client ssl");
    // 关键：客户端设的是**内层真实名**；外层（明文 SNI）由 ECHConfig 的 public_name 决定
    ssl.set_hostname(inner_name).expect("set_hostname");
    if let Some(list) = ech_config_list {
        // ECHConfigList 是**连接级**配置（SSL_set1_ech_config_list）
        ssl.set_ech_config_list(list).expect("set_ech_config_list");
    }
    let mut stream = SslStream::new(ssl, sock).expect("client stream");
    let accepted = match stream.connect() {
        Ok(()) => stream.ssl().ech_accepted(),
        Err(e) => {
            eprintln!("[ech-test] 客户端 connect 失败: {e}");
            false
        }
    };
    // 客户端看到的对端证书 CN
    let peer_cn = stream.ssl().peer_certificate().and_then(|c| {
        c.subject_name()
            .entries_by_nid(boring::nid::Nid::COMMONNAME)
            .next()
            .map(|e| String::from_utf8_lossy(e.data().as_slice()).to_string())
    });
    let _ = stream.write_all(b"q");
    let mut b = [0u8; 1];
    let _ = stream.read(&mut b);
    let (srv_sni, _srv_cn) = srv.join().expect("server thread");
    (accepted, srv_sni, peer_cn)
}

/// **核心测试**：ECH 握手成功，且服务端看到的是**内层真实名**。
#[test]
fn ech_handshake_accepted_and_inner_name_visible_to_server() {
    use crate::server::ech_auto::{generate, EchSpec};

    // public_name = 外层名（明文可见）；inner = 内层真实名
    let spec = EchSpec::from_config(Some("cover.example.com"), None, None).expect("spec");
    let mat = generate(&spec).expect("generate ECH material");
    let keys = crate::server::tls::ech_pem::load_ech_keys(mat.to_pem().as_bytes())
        .expect("load ECH keys");

    let server = server_ctx(&keys);
    let client = client_ctx();
    let (accepted, srv_sni, peer_cn) =
        handshake(&server, &client, "inner.real.test", Some(&mat.config_list));

    eprintln!(
        "[ech-test] ech_accepted={accepted} 服务端 SNI={srv_sni:?} 对端证书 CN={peer_cn:?}"
    );
    assert!(
        accepted,
        "客户端未达成 ECH（ech_accepted=false）—— 服务端 ECH 密钥/参数有问题"
    );
    assert_eq!(
        srv_sni.as_deref(),
        Some("inner.real.test"),
        "服务端应看到**内层真实名**（说明 ClientHelloInner 被成功解密）；\
         若看到 cover.example.com 说明只做了「标称成功」"
    );
}

/// 对照组：客户端**不使用** ECH 时，服务端看到的就是它自己发的 SNI（明文路径），
/// 且握手正常。这条用来证明「测试里的差异只来自 ECH」。
#[test]
fn without_ech_server_sees_plain_sni() {
    use crate::server::ech_auto::{generate, EchSpec};

    let spec = EchSpec::from_config(Some("cover.example.com"), None, None).expect("spec");
    let mat = generate(&spec).expect("generate");
    let keys = crate::server::tls::ech_pem::load_ech_keys(mat.to_pem().as_bytes()).expect("keys");

    let server = server_ctx(&keys);
    let client = client_ctx(); // 不提供 ECHConfig ⇒ 普通 TLS
    let (accepted, srv_sni, peer_cn) = handshake(&server, &client, "plain.example.com", None);
    eprintln!("[ech-test] 无 ECH: accepted={accepted} SNI={srv_sni:?} CN={peer_cn:?}");
    assert!(!accepted, "未提供 ECHConfig 不应达成 ECH");
    assert_eq!(srv_sni.as_deref(), Some("plain.example.com"));
}

// ---------------------------------------------------------------- ECH cover 证书 (b)

/// 用 boring 现场签一张自签证书（CN = name）—— 不依赖 openssl。
fn self_signed(cn: &str) -> (X509, PKey<boring::pkey::Private>) {
    use boring::asn1::Asn1Time;
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::x509::{X509Builder, X509NameBuilder};

    let rsa = boring::rsa::Rsa::generate(2048).expect("gen rsa");
    let pkey = PKey::from_rsa(rsa).expect("pkey from rsa");
    let mut nb = X509NameBuilder::new().expect("name builder");
    nb.append_entry_by_nid(Nid::COMMONNAME, cn).expect("append CN");
    let name = nb.build();
    let mut b = X509Builder::new().expect("x509 builder");
    b.set_version(2).expect("version");
    b.set_subject_name(&name).expect("subject");
    b.set_issuer_name(&name).expect("issuer");
    b.set_pubkey(&pkey).expect("pubkey");
    b.set_not_before(&Asn1Time::days_from_now(0).expect("nb")).expect("set nb");
    b.set_not_after(&Asn1Time::days_from_now(30).expect("na")).expect("set na");
    // SAN：现代 CA 一律走 SAN，`cert_covers` 也优先看它（只给 CN 的证书现实中已罕见）
    {
        use boring::x509::extension::SubjectAlternativeName;
        let san = SubjectAlternativeName::new()
            .dns(cn)
            .build(&b.x509v3_context(None, None))
            .expect("build san");
        b.append_extension(&san).expect("append san");
    }
    b.sign(&pkey, MessageDigest::sha256()).expect("sign");
    (b.build(), pkey)
}

fn write_pair(
    dir: &std::path::Path,
    stem: &str,
    cert: &X509,
    key: &PKey<boring::pkey::Private>,
) -> (String, String) {
    let cp = dir.join(format!("{stem}.crt.pem"));
    let kp = dir.join(format!("{stem}.key.pem"));
    std::fs::write(&cp, cert.to_pem().expect("cert pem")).expect("write cert");
    std::fs::write(&kp, key.private_key_to_pem_pkcs8().expect("key pem")).expect("write key");
    (cp.to_string_lossy().to_string(), kp.to_string_lossy().to_string())
}

/// **ECH cover 证书的验收**（走真实装配路径 `build_acceptor`）：
/// * ECH 客户端（外层 cover、内层 real）→ 必须拿到**真实证书**，且 ech_accepted = true；
/// * 非 ECH 客户端（SNI = public_name）→ 必须拿到 **cover 证书**。
///
/// 只断言 ech_accepted 会被「标称成功」骗过，所以这里断言的是**客户端实际看到哪张证书**。
#[test]
fn ech_cover_certificate_selection() {
    use crate::config::{ListenerConfig, SslConfig};
    use crate::server::ech_auto::{generate, EchSpec};

    let dir = std::env::temp_dir().join(format!("crucible-ech-cover-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (real_cert, real_key) = self_signed("real.example.com");
    let (cover_cert, cover_key) = self_signed("cover.example.com");
    let (rc, rk) = write_pair(&dir, "real", &real_cert, &real_key);
    let (cc, ck) = write_pair(&dir, "cover", &cover_cert, &cover_key);

    let spec = EchSpec::from_config(Some("cover.example.com"), None, None).expect("spec");
    let mat = generate(&spec).expect("generate ECH material");
    let ek = dir.join("ech.pem");
    std::fs::write(&ek, mat.to_pem()).expect("write ech pem");

    let ssl_cfg = SslConfig {
        cert: Some(rc),
        key: Some(rk),
        ech: true,
        ech_keys: Some(ek.to_string_lossy().to_string()),
        ech_public_name: Some("cover.example.com".into()),
        ech_cover_cert: Some(cc),
        ech_cover_key: Some(ck),
        ..Default::default()
    };
    let lc = ListenerConfig::default();
    let acceptor = crate::server::tls::boring_path::build_acceptor(&ssl_cfg, &lc).expect("acceptor");
    let server_ctx = acceptor.context();

    let client = client_ctx();
    let (accepted, srv_sni, peer_cn) =
        handshake(&server_ctx, &client, "real.example.com", Some(&mat.config_list));
    eprintln!(
        "[ech-cover] ECH 客户端: accepted={accepted} 服务端 SNI={srv_sni:?} 证书 CN={peer_cn:?}"
    );
    assert!(accepted, "ECH 客户端未达成 ECH");
    assert_eq!(
        peer_cn.as_deref(),
        Some("real.example.com"),
        "ECH 客户端必须拿到**真实证书**，而不是 cover"
    );

    let client2 = client_ctx();
    let (acc2, sni2, cn2) = handshake(&server_ctx, &client2, "cover.example.com", None);
    eprintln!("[ech-cover] 非 ECH: accepted={acc2} SNI={sni2:?} 证书 CN={cn2:?}");
    assert!(!acc2);
    assert_eq!(
        cn2.as_deref(),
        Some("cover.example.com"),
        "非 ECH 客户端必须拿到 **cover 证书**"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// **探测防护**（关键安全验收）：客户端**不带 ECH**、却把 SNI 写成**内层真实名**时，
/// 必须只拿到 **cover 证书** —— 否则任何主动探测者都能用「猜 SNI」确认本机持有该域名的
/// 证书，cover 也就形同虚设。判据必须是 `ech_accepted()`，不能按域名。
#[test]
fn probe_with_real_name_without_ech_gets_cover() {
    use crate::config::{ListenerConfig, SslConfig};
    use crate::server::ech_auto::{generate, EchSpec};

    let dir = std::env::temp_dir().join(format!("crucible-ech-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (real_cert, real_key) = self_signed("real.example.com");
    let (cover_cert, cover_key) = self_signed("cover.example.com");
    let (rc, rk) = write_pair(&dir, "real", &real_cert, &real_key);
    let (cc, ck) = write_pair(&dir, "cover", &cover_cert, &cover_key);

    let spec = EchSpec::from_config(Some("cover.example.com"), None, None).expect("spec");
    let mat = generate(&spec).expect("generate");
    let ek = dir.join("ech.pem");
    std::fs::write(&ek, mat.to_pem()).expect("write ech pem");

    let ssl_cfg = SslConfig {
        cert: Some(rc),
        key: Some(rk),
        ech: true,
        ech_keys: Some(ek.to_string_lossy().to_string()),
        ech_public_name: Some("cover.example.com".into()),
        ech_cover_cert: Some(cc),
        ech_cover_key: Some(ck),
        ..Default::default()
    };
    let acceptor = crate::server::tls::boring_path::build_acceptor(&ssl_cfg, &ListenerConfig::default())
        .expect("acceptor");

    // 探测：SNI=真实名，**不发 ECH**
    let client = client_ctx();
    let (accepted, sni, cn) = handshake(acceptor.context(), &client, "real.example.com", None);
    eprintln!("[ech-probe] 探测(SNI=真实名,无 ECH): accepted={accepted} SNI={sni:?} 证书 CN={cn:?}");
    assert!(!accepted, "不该达成 ECH");
    assert_eq!(
        cn.as_deref(),
        Some("cover.example.com"),
        "不带 ECH 的探测连接**必须**只拿到 cover 证书（否则 ECH 失去意义）"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// **ECH 被拒**路径（RFC 9849：客户端持过期/不匹配的 ECHConfig）：服务端解不开 ⇒
/// 退回外层参数 ⇒ 必须发 **cover 证书**（客户端按 public_name 校验），且 `ech_accepted=false`。
#[test]
fn rejected_ech_falls_back_to_cover() {
    use crate::config::{ListenerConfig, SslConfig};
    use crate::server::ech_auto::{generate, EchSpec};

    let dir = std::env::temp_dir().join(format!("crucible-ech-rej-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (real_cert, real_key) = self_signed("real.example.com");
    let (cover_cert, cover_key) = self_signed("cover.example.com");
    let (rc, rk) = write_pair(&dir, "real", &real_cert, &real_key);
    let (cc, ck) = write_pair(&dir, "cover", &cover_cert, &cover_key);

    // 服务端装 B 的密钥；客户端拿 A 的 ECHConfig（密钥不匹配 ⇒ 服务端解不开）
    let spec_a = EchSpec::from_config(Some("cover.example.com"), None, None).expect("spec a");
    let spec_b = EchSpec::from_config(Some("cover.example.com"), None, None).expect("spec b");
    let mat_a = generate(&spec_a).expect("gen a");
    let mat_b = generate(&spec_b).expect("gen b");
    let ek = dir.join("ech-b.pem");
    std::fs::write(&ek, mat_b.to_pem()).expect("write b");

    let ssl_cfg = SslConfig {
        cert: Some(rc),
        key: Some(rk),
        ech: true,
        ech_keys: Some(ek.to_string_lossy().to_string()),
        ech_public_name: Some("cover.example.com".into()),
        ech_cover_cert: Some(cc),
        ech_cover_key: Some(ck),
        ..Default::default()
    };
    let acceptor = crate::server::tls::boring_path::build_acceptor(&ssl_cfg, &ListenerConfig::default())
        .expect("acceptor");

    // 客户端用 A 的 config_list（服务端没有对应私钥）
    let client = client_ctx();
    let (accepted, sni, cn) =
        handshake(acceptor.context(), &client, "real.example.com", Some(&mat_a.config_list));
    eprintln!("[ech-rej] ECH 被拒: accepted={accepted} 服务端 SNI={sni:?} 证书 CN={cn:?}");
    assert!(!accepted, "密钥不匹配时不应达成 ECH");
    assert_eq!(
        cn.as_deref(),
        Some("cover.example.com"),
        "ECH 被拒后必须回退到 cover 证书"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// **证书不得混用**（RFC 9849 的部署要求）：把同一张证书同时配成真实与 cover
/// 必须在**配置期**被拒 —— 否则任何连接看到的证书都一样，ECH 失去意义。
#[test]
fn same_cert_for_inner_and_outer_is_rejected() {
    use crate::config::{ListenerConfig, SslConfig};
    use crate::server::ech_auto::{generate, EchSpec};

    let dir = std::env::temp_dir().join(format!("crucible-ech-same-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (only_cert, only_key) = self_signed("cover.example.com");
    let (pc, pk) = write_pair(&dir, "only", &only_cert, &only_key);

    let spec = EchSpec::from_config(Some("cover.example.com"), None, None).expect("spec");
    let mat = generate(&spec).expect("generate");
    let ek = dir.join("ech.pem");
    std::fs::write(&ek, mat.to_pem()).expect("write ech pem");

    let ssl_cfg = SslConfig {
        cert: Some(pc.clone()),
        key: Some(pk.clone()),
        ech: true,
        ech_keys: Some(ek.to_string_lossy().to_string()),
        ech_public_name: Some("cover.example.com".into()),
        // 同一张证书充当 cover ⇒ 必须被拒
        ech_cover_cert: Some(pc),
        ech_cover_key: Some(pk),
        ..Default::default()
    };
    let err = match crate::server::tls::boring_path::build_acceptor(&ssl_cfg, &ListenerConfig::default()) {
        Ok(_) => panic!("同一张证书必须被拒绝，但构建成功了"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    eprintln!("[ech-same] 预期报错: {msg}");
    assert!(
        msg.contains("同一张"),
        "报错信息应明确说明内外层不能用同一张证书，实际: {msg}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// cover 证书不覆盖 `ech_public_name` ⇒ 配置期报错（否则回退路径客户端校验必然失败）。
#[test]
fn cover_not_covering_public_name_is_rejected() {
    use crate::config::{ListenerConfig, SslConfig};
    use crate::server::ech_auto::{generate, EchSpec};

    let dir = std::env::temp_dir().join(format!("crucible-ech-cov-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (real_cert, real_key) = self_signed("real.example.com");
    let (wrong_cert, wrong_key) = self_signed("other.example.net"); // 不覆盖 public_name
    let (rc, rk) = write_pair(&dir, "real", &real_cert, &real_key);
    let (wc, wk) = write_pair(&dir, "wrong", &wrong_cert, &wrong_key);

    let spec = EchSpec::from_config(Some("cover.example.com"), None, None).expect("spec");
    let mat = generate(&spec).expect("generate");
    let ek = dir.join("ech.pem");
    std::fs::write(&ek, mat.to_pem()).expect("write ech pem");

    let ssl_cfg = SslConfig {
        cert: Some(rc),
        key: Some(rk),
        ech: true,
        ech_keys: Some(ek.to_string_lossy().to_string()),
        ech_public_name: Some("cover.example.com".into()),
        ech_cover_cert: Some(wc),
        ech_cover_key: Some(wk),
        ..Default::default()
    };
    let err = match crate::server::tls::boring_path::build_acceptor(&ssl_cfg, &ListenerConfig::default()) {
        Ok(_) => panic!("cover 未覆盖 public_name 必须被拒绝，但构建成功了"),
        Err(e) => e,
    };
    eprintln!("[ech-cov] 预期报错: {err:#}");
    assert!(format!("{err:#}").contains("不覆盖"));
    let _ = std::fs::remove_dir_all(&dir);
}
