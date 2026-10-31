//! Primary TLS path — BoringSSL (TCP + QUIC foundation).
//!
//! Handles modern TLS 1.2/1.3, ECH, post-quantum hybrid groups (X25519MLKEM768),
//! session tickets, and optional TLS-PSK hooks for H3.

use crate::config::{ListenerConfig, SslConfig};
use crate::server::live_config::LiveConfig;
use crate::server::prefixed_stream::PrefixedStream;
use crate::server::ssl_material;
use crate::server::{h1, h2};
use anyhow::{Context, Result};
use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVersion, NameType};
use boring::x509::{X509, X509Ref};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_boring::SslStream;

/// G-12：`ssl.prefer_tls13 = true` 时按 **ClientHello** 选择的两套 SSL_CTX 版本档位。
///
/// BoringSSL 没有「协议版本偏好」开关（版本偏好库内固定），所以「prefer」做成可观测的
/// 两套上下文：
/// * 客户端在 `supported_versions` 里声明了 TLS1.3 (0x0304) ⇒ 用 **1.3-only** 上下文
///   （客户端即使同时给 1.2 也只会协商到 1.3）；
/// * 不支持 1.3 的客户端 ⇒ 用 **max=TLS1.2** 上下文，正常回落到 1.2（**不拒绝** 1.2 客户端）。
///
/// 只有 `ssl.versions` 为空（即没有显式版本钉死）时才启用；显式 `versions` /
/// `min_version` / `max_version` 的优先级更高，此时按库默认范围（`Default`）。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) enum VersionProfile {
    /// 库默认范围（不因 prefer_tls13 做任何覆盖）。
    Default,
    /// 客户端支持 TLS1.3：只协商 TLS1.3。
    Tls13Only,
    /// 客户端不支持 TLS1.3：上限钉在 TLS1.2（min 仍为 1.2）。
    Tls12Max,
}

/// 按 ClientHello 的 wire 探测选择版本档位（与 legacy 分流同一套探测：
/// [`crate::server::tls::client_hello::has_tls13_supported_versions`]）。
pub(crate) fn pick_version_profile(ssl: &SslConfig, peek: &[u8]) -> VersionProfile {
    if !ssl.prefer_tls13 || !ssl.versions.is_empty() {
        return VersionProfile::Default;
    }
    // peek 没读全（超长 ClientHello 被 PEEK_CAP 截断 / 对端只发了一半）时**不要**
    // 猜成「不支持 1.3」：那会把一个支持 1.3 的客户端硬压到 1.2。无法判定就回库默认
    // （它会按客户端能力正常协商），只有确定不含 0x0304 时才用 max=1.2 上下文。
    //
    // 完整性判据必须按**握手消息长度**（允许跨 record 分片），不能只看首个 record 的
    // 声明长度 —— 旧写法 `peek.len() < need` 在「ClientHello 被拆成两条 record」时
    // 会误判为完整，随后 `has_tls13` 在错位的字节上扫描（本波单测抓到的真实 bug）。
    if !crate::server::tls::client_hello::client_hello_is_complete(peek) {
        return VersionProfile::Default;
    }
    if crate::server::tls::client_hello::has_tls13_supported_versions(peek) {
        VersionProfile::Tls13Only
    } else {
        VersionProfile::Tls12Max
    }
}

/// 把版本档位落到 builder 上（在 [`apply_versions`] 之后调用；显式 versions 时
/// 调用方传 `Default`，不会被覆盖）。
fn apply_version_profile(
    builder: &mut SslAcceptorBuilder,
    profile: VersionProfile,
) -> Result<()> {
    match profile {
        VersionProfile::Default => {}
        VersionProfile::Tls13Only => {
            builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        }
        VersionProfile::Tls12Max => {
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        }
    }
    Ok(())
}

pub fn build_acceptor(ssl: &SslConfig, lc: &ListenerConfig) -> Result<SslAcceptor> {
    // strict=true：这是 `--check-config`（以及启动预检/单测）走的入口。非法配置在这里
    // **必须报错**，把「端口能监听但握手全失败」提前到运维的预检阶段。
    build_acceptor_full(ssl, lc, VersionProfile::Default, false, true)
}

/// [`build_acceptor`] 的带版本档位版本（accept 热路径按 ClientHello 选档位）。
///
/// `allow_dot_alpn`：G-08 端口复用 DoT。true 时 accept 的 ALPN 列表额外提供
/// `dot`（RFC 7858）并**优先于** h2/http1.1 —— 只有调用方已确认这条 ClientHello
/// 声明了 dot 才会传 true，因此站点流量永远不会命中这个分支。
///
/// 运行时（热路径）一律 strict=false：配置即使有瑕疵也**只降级**（剔除坏名字/禁用
/// 可选特性并大声告警），绝不让 build_acceptor 失败 —— 那等于整个监听口 soft-fail
/// （热重载/面板保存不跑 `--check-config`，tls-core P1-21 的教训）。
pub(crate) fn build_acceptor_profile(
    ssl: &SslConfig,
    lc: &ListenerConfig,
    profile: VersionProfile,
    allow_dot_alpn: bool,
) -> Result<SslAcceptor> {
    build_acceptor_full(ssl, lc, profile, allow_dot_alpn, false)
}

fn build_acceptor_full(
    ssl: &SslConfig,
    lc: &ListenerConfig,
    profile: VersionProfile,
    allow_dot_alpn: bool,
    strict: bool,
) -> Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
    // boring 的 mozilla_modern 预设带 SSL_OP_NO_TLSV1_3,不清掉 TLS1.3 永远握手失败(
    // set_min/max_proto_version 不会复位该 option 位)。§6 主路径要求 1.2/1.3 全开。
    builder.clear_options(boring::ssl::SslOptions::NO_TLSV1_3);
    apply_versions(&mut builder, ssl)?;
    // G-12：prefer_tls13 的两套上下文（显式 versions 时 profile=Default）。
    apply_version_profile(&mut builder, profile)?;
    // OCSP 是**逐证书**一份：先规划（真实/cover 各一份），再让 load_identity 在
    // 「ECH 接受与否」的决策点装对应那份（见 OcspPlan 的说明）。
    let ocsp = plan_ocsp(ssl);
    load_identity(&mut builder, ssl, &ocsp)?;
    // 早期规格 3：0-RTT 默认关闭；early_data=true 才显式开启（boring 无安全封装，
    // 直调 BoringSSL C API SSL_CTX_set_early_data_enabled）。
    if ssl.early_data {
        unsafe {
            boring_sys::SSL_CTX_set_early_data_enabled(builder.as_ptr(), 1);
        }
        // 重放防护语义（U-05）：BoringSSL **不做** 0-RTT 反重放 —— `SSL_CTX_set_early_data_enabled`
        // 只是允许客户端在恢复会话里发 early data（服务端用 `SSL_in_early_data` /
        // `SSL_early_data_accepted` 区分）。RFC 8446 §8 要求应用层自行反重放（单次票据、
        // 时间窗、幂等判定等），本项目未实现任何反重放 ⇒ 开启后**同一份 early data 可以被
        // 重放**。因此只应在幂等请求（GET/HEAD）上启用，或由前置层做单次票据校验。
        log::warn!(
            "tls: early data (0-RTT) enabled —— 注意 BoringSSL 不提供反重放，\
同一份 early data 可被重放；仅建议用于幂等请求（GET/HEAD），state-changing 请求务必等 1-RTT"
        );
    }
    apply_ciphers(&mut builder, ssl, strict)?;
    apply_groups(&mut builder, ssl, strict)?;
    apply_ech(&mut builder, ssl)?;
    apply_ocsp(&mut builder, ssl, &ocsp)?;
    apply_psk(&mut builder, ssl, strict)?;
    apply_alpn(&mut builder, lc, allow_dot_alpn)?;
    Ok(builder.build())
}

fn apply_versions(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    if ssl.versions.is_empty() {
        // `prefer_tls13` **不在这里**生效：它需要按 ClientHello 在两套 SSL_CTX 之间
        // 选择（1.3-only / max=1.2），见 [`VersionProfile`] 与 [`apply_version_profile`]。
        // 这里保持库默认范围（mozilla_modern + 清除 NO_TLSV1_3 ⇒ 1.2–1.3）。
        return Ok(());
    }
    let (min, max, legacy) = plan_versions(&ssl.versions)?;
    let (Some(min), Some(max)) = (min, max) else {
        // 只配了 legacy 版本（tls1.0/tls1.1/tlsv1/...）：BoringSSL 一个都做不了。
        // **绝不能**让构建失败 —— 旧实现遇到 legacy 条目直接 `?` bail ⇒ acceptor
        // 构建失败 ⇒ 该监听口包括 TLS1.2/1.3 在内的**每条**连接都被 soft-fail 丢弃
        //（热重载不构建 acceptor，所以配置能成功加载，端口却完全不再服务）。
        // 这里回落到 BoringSSL 能给的最接近集合（1.2–1.3）并**大声告知降级**：
        // 要真正服务 legacy 客户端请启用 NSS/TomCrypt（client_hello::resolve 分流）。
        crate::server::log_throttle::warn_every(
            "tls-versions-legacy-only",
            std::time::Duration::from_secs(60),
            &format!(
                "ssl.versions 只含 BoringSSL 不支持的 legacy 版本 {:?} —— 为避免整个监听口失效，\
BoringSSL 侧回落到 TLS1.2–1.3（这是一次降级，不是配置生效）；要服务 legacy 客户端请启用 \
NSS/TomCrypt（enable_nss / enable_tomcrypt），它们按 ClientHello 分流",
                legacy
            ),
        );
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        return Ok(());
    };
    builder.set_min_proto_version(Some(min))?;
    builder.set_max_proto_version(Some(max))?;
    if !legacy.is_empty() {
        // 同时配了现代版本与 legacy 版本：legacy 条目对 BoringSSL 无意义（它是
        // ClientHello 分流策略），忽略而不是报错；但要如实说明哪些被忽略了。
        crate::server::log_throttle::warn_every(
            "tls-versions-legacy-ignored",
            std::time::Duration::from_secs(60),
            &format!(
                "ssl.versions 含 BoringSSL 不支持的 legacy 版本 {:?}（已忽略：仅由 NSS/TomCrypt \
分流处理）；BoringSSL 实际协商范围 {:?}–{:?}",
                legacy, min, max
            ),
        );
    }
    Ok(())
}

/// 把 `ssl.versions` 拆成 (BoringSSL min, BoringSSL max, 被忽略的 legacy 条目)。
///
/// 规则：现代条目取 rank 最小/最大作为范围；legacy 条目只影响遗留栈分流，不参与
/// BoringSSL 范围计算（旧实现为它 bail，直接毒死整个监听口）。只含 legacy 时返回
/// `(None, None, legacy)`，由调用方决定回落策略。
fn plan_versions(
    versions: &[String],
) -> Result<(Option<SslVersion>, Option<SslVersion>, Vec<String>)> {
    let mut min: Option<SslVersion> = None;
    let mut max: Option<SslVersion> = None;
    let mut legacy: Vec<String> = Vec::new();
    for v in versions {
        match parse_version(v)? {
            Some(ver) => {
                if min.is_none_or(|m| version_rank(ver) < version_rank(m)) {
                    min = Some(ver);
                }
                if max.is_none_or(|m| version_rank(ver) > version_rank(m)) {
                    max = Some(ver);
                }
            }
            None => legacy.push(v.clone()),
        }
    }
    Ok((min, max, legacy))
}

fn version_rank(v: SslVersion) -> u8 {
    match v {
        SslVersion::TLS1_2 => 2,
        SslVersion::TLS1_3 => 3,
        _ => 2,
    }
}

/// `Ok(Some(v))` = BoringSSL 支持的版本；`Ok(None)` = legacy 版本（BoringSSL 不做，
/// 交给 NSS/TomCrypt 分流，不参与 min/max 计算）；`Err` = 无法识别的字符串。
fn parse_version(s: &str) -> Result<Option<SslVersion>> {
    match s.to_ascii_uppercase().replace(['.', '_'], "").as_str() {
        "TLSV13" | "TLS13" => Ok(Some(SslVersion::TLS1_3)),
        "TLSV12" | "TLS12" => Ok(Some(SslVersion::TLS1_2)),
        "TLSV11" | "TLS11" | "TLSV10" | "TLS10" | "TLSV1" | "TLS1" | "SSLV3" | "SSL3" => Ok(None),
        other => anyhow::bail!("unsupported TLS version: {other}"),
    }
}

/// 把一份 PEM 拆成 (叶证书, 中间链)。
///
/// 用 `X509::stack_from_pem` 而不是 `X509::from_pem`：后者**只解析第一张**，
/// 而 `ssl.cert` 的典型形态就是 `fullchain.pem`（ACME/certbot 产物，叶+中间 CA）。
/// 旧实现把整份 fullchain 丢给 `from_pem`、从不调用任何 `*_chain_cert` API ⇒
/// 服务端**只发叶证书**。实测（本地 127.0.0.1:21443，三级链 leaf←int←root）：
/// `openssl s_client -showcerts` 只拿到 1 张证书，客户端若未预置中间 CA 则链校验失败
/// （`verify error: unable to get local issuer certificate`）。
///
/// **链顺序**：按 RFC 8555/常规约定叶证书必须在**第一张**，但运维手工 `cat` 出
/// `fullchain.pem` 时很常见把根/中间写在前面。旧实现直接 `remove(0)` 当叶 ⇒
/// `check_private_key` 失败 ⇒ `build_acceptor` 失败 ⇒ **整个监听口每条连接
/// soft-fail**（实测 `chain-root-first.pem` 端口 `unexpected eof`）。这里用私钥
/// 反查真正的叶证书并**自动重排**（只重排，不改变证书集合），同时保留一条明确 warn。
fn split_chain(pem: &[u8], key: &PKey<boring::pkey::Private>) -> Result<(X509, Vec<X509>)> {
    let mut certs = X509::stack_from_pem(pem)?;
    if certs.is_empty() {
        anyhow::bail!("证书 PEM 里没有任何 CERTIFICATE 块");
    }
    let key_pub = key.public_key_to_der().ok();
    if let Some(key_pub) = key_pub.as_deref() {
        let matches = |c: &X509| -> bool {
            c.public_key()
                .and_then(|p| p.public_key_to_der())
                .map(|d| d.as_slice() == key_pub)
                .unwrap_or(false)
        };
        if !matches(&certs[0]) {
            match certs.iter().position(matches) {
                Some(i) => {
                    let leaf = certs.remove(i);
                    log::warn!(
                        "ssl.cert 的链顺序不是 leaf-first（第 {i} 张证书才与私钥匹配），已自动重排为 \
叶证书在前；建议修正 fullchain.pem（叶 || 中间…）以避免其它工具误用"
                    );
                    certs.insert(0, leaf);
                }
                None => {
                    anyhow::bail!(
                        "ssl.cert 的证书链里没有任何一张证书与私钥匹配 —— 请检查 ssl.cert/ssl.key \
是否来自同一对（链顺序会自动重排，但证书本身必须匹配）"
                    );
                }
            }
        }
    }
    let leaf = certs.remove(0);
    Ok((leaf, certs))
}

/// 证书有效期检查（只告警，不阻断 TLS）。
///
/// 过期/尚未生效的证书仍会被 BoringSSL 正常发送（库不做时间校验），客户端随后拒绝 ——
/// 运维视角是「站点突然不可用」，而日志里通常只有客户端侧的 verify error。这里在
/// acceptor 构建（低温路径，每个配置版本一次）时把 notBefore/notAfter 与当前时间比较，
/// 直接点名哪张证书、哪个时间，便于在续期失败时第一时间定位。
fn warn_cert_validity(label: &str, cert: &X509Ref) {
    let Ok(now) = boring::asn1::Asn1Time::days_from_now(0) else {
        return;
    };
    if let Ok(std::cmp::Ordering::Less) = cert.not_after().compare(&now) {
        log::error!(
            "TLS 证书 {label} 已过期（notAfter={}）—— 握手会成功但客户端校验必失败，请立即续期",
            cert.not_after()
        );
    }
    if let Ok(std::cmp::Ordering::Greater) = cert.not_before().compare(&now) {
        log::error!(
            "TLS 证书 {label} 尚未生效（notBefore={}）—— 握手会成功但客户端校验必失败",
            cert.not_before()
        );
    }
}

/// 清空 builder 上 legacy credential 的中间链（`SSL_CTX_clear_chain_certs`）。
///
/// 用于「同一层内切换证书」的场景（cover EC 覆盖 cover RSA）：`set_certificate` 只换
/// 叶，之前 `add_extra_chain_cert` 追加的中间链仍留在 credential 上，不清理会发出一条
/// 与当前叶不匹配的链（客户端报 `unable to verify the first certificate`）。
fn clear_chain(builder: &mut SslAcceptorBuilder) {
    unsafe {
        boring_sys::SSL_CTX_clear_chain_certs(builder.as_ptr());
    }
}

/// 把中间链追加到（刚设置的）容器证书上。`add_extra_chain_cert` = `SSL_CTX_add0_chain_cert`
/// ⇒ 给 legacy credential 追加**非叶**证书（叶由 `set_certificate` 放链首）。
fn attach_intermediates(builder: &mut SslAcceptorBuilder, chain: &[X509]) -> Result<()> {
    for c in chain {
        builder
            .add_extra_chain_cert(c.clone())
            .context("添加中间证书链失败（链过长或证书非法）")?;
    }
    Ok(())
}

/// 用**多 credential**（`SSL_CREDENTIAL_new_x509` + `SSL_CTX_add1_credential`）装配一张
/// 证书，让 BoringSSL 按客户端 `signature_algorithms` 自动在 RSA / ECDSA 之间选。
///
/// 为什么必须这样：本 BoringSSL 的 `SSL_CTX_use_certificate` 只配置**单个**「legacy
/// credential」，同一层里再 set 一次是**覆盖**（不是按类型各存一张）。所以旧实现
/// 「先 set cert/key 再 set cert_ec/key_ec」的最终容器里**只剩 EC 那张**：
/// 实测（本地 21444）`cert=rsa.pem, cert_ec=ec.pem` 时，只用 RSA sigalgs 的客户端
/// 握手直接 `handshake failure (alert 40)` —— 配了 ECC 副证书反而**弄丢 RSA 主证书**。
///
/// `SSL_CREDENTIAL_set1_cert_chain` 接收 CRYPTO_BUFFER 数组、`set1_private_key` 接收
/// `EVP_PKEY*`；boring 高层 API 未导出 credential 结构，故这条路径直接用 `boring_sys`
/// （crate 已依赖）。传入的都是**已有对象的 DER/`*mut`**：key 指针由调用方从
/// `PKey` 取（本项目 `libs/quinn-boring` 的 `bffi_ext.rs` 里同一个 crate 有现成写法）。
/// 所有 CRYPTO_BUFFER 都是新建的，`set1_cert_chain` 内部会 `UpRef`，装配完由 guard 释放。
#[cfg(feature = "tls_boring")]
fn add_x509_credential_der(
    builder: &mut SslAcceptorBuilder,
    cert_der: &[u8],
    intermediates_der: &[Vec<u8>],
    key_ptr: *mut boring_sys::EVP_PKEY,
) -> Result<()> {
    use boring_sys as bsys;

    unsafe {
        let cred = bsys::SSL_CREDENTIAL_new_x509();
        if cred.is_null() {
            anyhow::bail!("SSL_CREDENTIAL_new_x509 失败");
        }
        /// RAII：中途任何一步失败都不泄漏。
        struct CredGuard(*mut bsys::SSL_CREDENTIAL);
        impl Drop for CredGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { bsys::SSL_CREDENTIAL_free(self.0) };
                }
            }
        }
        struct BufGuard(Vec<*mut bsys::CRYPTO_BUFFER>);
        impl Drop for BufGuard {
            fn drop(&mut self) {
                for b in &self.0 {
                    if !b.is_null() {
                        unsafe { bsys::CRYPTO_BUFFER_free(*b) };
                    }
                }
            }
        }
        let cred_guard = CredGuard(cred);

        let mut ders: Vec<&[u8]> = Vec::with_capacity(1 + intermediates_der.len());
        ders.push(cert_der);
        for c in intermediates_der {
            ders.push(c.as_slice());
        }
        let mut bufs: Vec<*mut bsys::CRYPTO_BUFFER> = Vec::with_capacity(ders.len());
        for d in &ders {
            let b = bsys::CRYPTO_BUFFER_new(d.as_ptr(), d.len(), std::ptr::null_mut());
            if b.is_null() {
                anyhow::bail!("CRYPTO_BUFFER_new 失败");
            }
            bufs.push(b);
        }
        let bufs_guard = BufGuard(bufs);
        let buf_ptrs: Vec<*mut bsys::CRYPTO_BUFFER> = bufs_guard.0.clone();

        if bsys::SSL_CREDENTIAL_set1_cert_chain(cred_guard.0, buf_ptrs.as_ptr(), buf_ptrs.len())
            != 1
        {
            anyhow::bail!("SSL_CREDENTIAL_set1_cert_chain 失败");
        }
        if bsys::SSL_CREDENTIAL_set1_private_key(cred_guard.0, key_ptr) != 1 {
            anyhow::bail!("SSL_CREDENTIAL_set1_private_key 失败（证书与私钥不匹配？）");
        }
        if bsys::SSL_CTX_add1_credential(builder.as_ptr(), cred_guard.0) != 1 {
            anyhow::bail!("SSL_CTX_add1_credential 失败");
        }
        drop(bufs_guard);
        drop(cred_guard);
    }
    Ok(())
}

fn load_identity(builder: &mut SslAcceptorBuilder, ssl: &SslConfig, ocsp: &OcspPlan) -> Result<()> {
    let cert_pem = ssl_material::load_bytes(ssl.cert.as_deref().context("ssl.cert")?)?;
    let key_pem = ssl_material::load_bytes(ssl.key.as_deref().context("ssl.key")?)?;
    let key = PKey::private_key_from_pem(&key_pem)?;
    // split_chain 用私钥反查真正的叶证书并自动重排（root-first 的 fullchain 不再
    // 让整个监听口构建失败）。
    let (cert, real_chain) = split_chain(&cert_pem, &key)?;
    warn_cert_validity("ssl.cert", &cert);

    // ⚠️ 本 BoringSSL 只有**一个** legacy credential 槽：
    // `SSL_CTX_use_certificate` 的文档原文是 "Each of these functions configures the single
    // "legacy credential"... To select between multiple certificates, use
    // SSL_CREDENTIAL_new_x509"，而本 build 并未导出那套 API。所以**同一层里重复
    // set_certificate 是覆盖、不是「按密钥类型各存一张」**（原注释写的「备用链」是错的）。
    //
    // 由此推出两条硬约束（配置期已 fail-fast，见 config.rs）：
    //   * 内层与外层必须**配成同一组密钥类型**：每层实际生效的是最后设置的那张，两层类型
    //     不一致时 ECH 接受前后会把证书类型换掉，只支持一种类型的客户端两条路径各失败一边。
    //   * 因此下面「容器用 cover、回调换 real」在类型上天然一致（都被最后那张 EC 或都 RSA）。
    //
    // 备用 EC 证书（`ssl.cert_ec`）：与 `cert` 同层，后设置的生效。它同样可以是
    // fullchain（叶+中间）：旧实现只 `X509::from_pem` 取第一张、把中间链**整段丢弃**，
    // 于是 EC credential 只发叶证书，客户端若未预置中间 CA 就校验失败。
    let ec_pair = match (&ssl.cert_ec, &ssl.key_ec) {
        (Some(c), Some(k)) => {
            let ec_pkey = PKey::private_key_from_pem(&ssl_material::load_bytes(k)?)?;
            let (ec_x509, ec_chain) = split_chain(&ssl_material::load_bytes(c)?, &ec_pkey)?;
            warn_cert_validity("ssl.cert_ec", &ec_x509);
            Some((ec_x509, ec_pkey, ec_chain))
        }
        _ => None,
    };

    // ECH 外层（cover）证书：容器默认证书设为 cover —— **不带 ECH 的客户端**（以及
    // ECH 被拒后回退的客户端）按 `ech_public_name` 校验证书，走的就是这一张。
    let (cover, cover_chain) = match (&ssl.ech_cover_cert, &ssl.ech_cover_key) {
        (Some(c), Some(k)) => {
            let ck = PKey::private_key_from_pem(&ssl_material::load_bytes(k)?)?;
            let (cc, chain) = split_chain(&ssl_material::load_bytes(c)?, &ck)?;
            warn_cert_validity("ssl.ech_cover_cert", &cc);
            (Some((cc, ck)), chain)
        }
        _ => (None, Vec::new()),
    };

    // 外层 cover 的**备用 EC 证书**。见上：本 BoringSSL 单 credential 槽，同层后设置的生效；
    // 外层配 EC 是为了让「外层生效的那张」与「内层生效的那张」是同一种密钥类型
    // —— 否则 ECH 接受前后证书类型会变，只支持一种类型的客户端必有一边失败。
    let cover_ec = match (&ssl.ech_cover_cert_ec, &ssl.ech_cover_key_ec) {
        (Some(c), Some(k)) => {
            let p = PKey::private_key_from_pem(&ssl_material::load_bytes(k)?)?;
            let (x, chain) = split_chain(&ssl_material::load_bytes(c)?, &p)?;
            warn_cert_validity("ssl.ech_cover_cert_ec", &x);
            Some((x, p, chain))
        }
        _ => None,
    };

    // ECH（RFC 9849）部署约束 —— 全部**配置期 fail-fast**，不做静默降级：
    //
    // ① 外层（cover）与内层（真实）必须是**两张不同的证书**。若用同一张，任何连接
    //    （含不做 ECH 的探测者）看到的证书都一样，ECH 就失去意义 —— 中间人凭证书即可
    //    关联出「这台主机在服务哪个真实域名」。
    // ② cover 证书必须**覆盖 `ech_public_name`**：客户端未用 ECH、或 ECH 被拒时看到的是
    //    外层名，它按 public_name 校验证书；cover 不覆盖它 ⇒ 回退路径直接校验失败。
    // ③ cover 与 OCSP 装订**同时开启**时直接报错：staple 是**逐证书的单份 DER**
    //    （`set_ocsp_status` 只装一份），而我们会在两套证书之间切换 ⇒ 必然有一边拿到
    //    不匹配的 staple：严格客户端校验失败、宽松客户端**撤回检查静默失效**（比不装订更糟）。
    //    与其错配，不如明确要求二选一。
    if let Some((cc, _ck)) = &cover {
        let public_name = ssl
            .ech_public_name
            .as_deref()
            .context("ECH cover 需要 ssl.ech_public_name（RFC 9849 的 public_name）")?
            .trim()
            .to_string();
        if cert.to_der()? == cc.to_der()? {
            anyhow::bail!(
                "ECH: cover 证书与真实证书是**同一张**（DER 完全相同）—— RFC 9849 要求内外层分离；\
同一张证书会让 ECH 失去意义（中间人凭证书即可关联真实域名）"
            );
        }
        if !cert_covers(cc, &public_name) {
            anyhow::bail!(
                "ECH: cover 证书不覆盖 ech_public_name={public_name} —— 未使用 ECH / ECH 被拒的\
客户端会按 public_name 校验证书，必然失败"
            );
        }
        if ssl.ocsp_der_path.is_some() {
            anyhow::bail!(
                "ECH cover 证书与 ssl.ocsp_der_path 不能同时配置：OCSP staple 是逐证书的单份 DER，\
两套证书间切换必然有一边错配（严格客户端校验失败、宽松客户端撤回检查静默失效）。请二选一"
            );
        }
        // ④ 内外层必须**配成同一组密钥类型**。理由见文件上方关于「单 credential 槽」的说明：
        //    每层实际生效的是**最后设置的那张**，若内层有 EC 而外层没有（或反之），ECH 接受
        //    前后证书类型会变（cover=RSA → real=EC），只提供单一类型的客户端会在两条路径里
        //    各失败一边；更糟的是**内层可能因此被逼出来**（外层只有 RSA 时，容器里唯一的 EC
        //    证书是内层那张 —— §21.34 在 127.0.0.1:18443 上实测复现过：ECH/非 ECH+RSA/
        //    非 ECH+仅 ECDSA 三条探针拿到**完全相同**的内层指纹）。
        if ec_pair.is_some() != cover_ec.is_some() {
            anyhow::bail!(
                "ECH: ssl.cert_ec 与 ssl.ech_cover_cert_ec 必须**同时配或同时不配** —— 本 BoringSSL\
 的 SSL_CTX_use_certificate 只有单个 credential 槽（是覆盖、不是按类型各存一张），每层生效的\
是最后设置的那张。内外层密钥类型不一致时，ECH 接受前后证书类型会变：只支持一种类型的客户端在\
「ECH / 非 ECH」两条路径里必有一边失败，且外层缺 EC 时容器里偏巧就是**内层**那张 EC 证书（\
主动探测者换一组 sigalgs 即可确认真实域名）"
            );
        }
        if let Some((cec, _, _)) = &cover_ec {
            // 外层 EC 也必须覆盖 public_name（它是外层生效的那张）
            if !cert_covers(cec, &public_name) {
                anyhow::bail!(
                    "ECH: ech_cover_cert_ec 不覆盖 ech_public_name={public_name} —— 外层按 \
public_name 校验证书，必然失败"
                );
            }
            // 与内层 EC 不能是同一张（同 ① 的理由，只是换成 EC 那一对）
            if let Some((inner_ec, _, _)) = &ec_pair {
                if inner_ec.to_der()? == cec.to_der()? {
                    anyhow::bail!(
                        "ECH: ech_cover_cert_ec 与 ssl.cert_ec 是**同一张** —— 内外层必须分离"
                    );
                }
            }
        }
    }

    match &cover {
        Some((cc, ck)) => {
            builder.set_certificate(cc)?;
            builder.set_private_key(ck)?;
            builder.check_private_key()?;
            // 外层 cover 自己的中间链（容器上生效的就是这一层）。
            attach_intermediates(builder, &cover_chain)?;
        }
        None => {
            builder.set_certificate(&cert)?;
            builder.set_private_key(&key)?;
            builder.check_private_key()?;
            // 中间链（`ssl.cert` 是 fullchain.pem 时就在同一个文件里）。
            // **必须在 set_certificate 之后**：`add_extra_chain_cert` 追加的是
            // legacy credential 的**中间**证书（叶由 set_certificate 放在链首）。
            attach_intermediates(builder, &real_chain)?;
        }
    }
    // 容器上的证书（非 ECH 路径生效的那张）：配了 cover 时是**外层**，否则是内层。
    //
    // **非 ECH 的双证（RSA + ECDSA）**：不能再「同层再 set 一次」——那是覆盖，
    // 结果是容器里只剩最后一张（EC），只提供 RSA sigalgs 的客户端直接
    // `handshake failure`（实测本地 21444）。这里改为把 EC 作为**第二个 credential**
    // 追加进列表（`SSL_CTX_add1_credential`），BoringSSL 按客户端 sigalgs 自动选：
    //   * 列表顺序 = 优先级 ⇒ EC 在前（现代客户端默认拿 ECDSA）；
    //   * legacy credential（RSA + 中间链 + OCSP staple）永远在列表**末尾**兜底，
    //     所以「只支持 RSA 的客户端」「只支持 ECDSA 的客户端」都能成功。
    //
    // 为什么配了 cover 时**不**走这条路：ECH 的证书切换发生在 servername 回调里，
    // 而回调只能改 legacy credential（`ssl.set_certificate`）；显式 credential 列表
    // 在 `SSL_CTX_add1_credential` 之后即冻结（文档明言不得再改），ECH 接受时无法
    // 把 cover 的 EC credential 换成真实那份 ⇒ 会向非 ECH 客户端泄漏内层 EC 证书
    // （比现状更糟）。cover 场景维持原行为并把限制留在日志/报告里。
    if cover.is_none() {
        if let Some((ec_x509, ec_pkey, ec_chain)) = ec_pair.as_ref() {
            // 取 EC 私钥的 `EVP_PKEY*`：**先把容器换成 EC**（证书+私钥必须同类型，
            // 否则 `SSL_CREDENTIAL_set1_private_key` 会以 `KEY_TYPE_MISMATCH` 拒绝），
            // 取回指针、注册成独立 credential，再换回主（RSA）证书。
            // 这样不必新增依赖（`PKey` 的 `as_ptr` 来自 `foreign_types`，本 crate
            // 没有直接依赖它），也不必手写 PEM/DER 解析。
            //
            // 指针生命周期：`set1_private_key` 内部 `UpRef`，所以第 4 步把容器换回
            // 主证书（legacy 槽上类型不匹配的 EC 私钥被静默丢弃）之后指针仍有效。
            builder.set_certificate(ec_x509)?;
            builder.set_private_key(ec_pkey)?;
            let key_ptr = unsafe { boring_sys::SSL_CTX_get0_privatekey(builder.as_ptr()) };
            if key_ptr.is_null() {
                anyhow::bail!("SSL_CTX_get0_privatekey 取 EC 私钥指针失败");
            }
            let ec_der = ec_x509.to_der()?;
            // EC 自己的中间链必须一起进 credential（否则 ECDSA 客户端只拿到叶证书）。
            let mut ec_chain_der: Vec<Vec<u8>> = Vec::with_capacity(ec_chain.len());
            for c in ec_chain {
                ec_chain_der.push(c.to_der()?);
            }
            add_x509_credential_der(builder, &ec_der, &ec_chain_der, key_ptr).with_context(|| {
                "把 ssl.cert_ec 注册为独立 credential 失败（RSA 主证书仍可用）"
            })?;
            // 换回主证书 + 主密钥 + 主链。
            builder.set_certificate(&cert)?;
            builder.set_private_key(&key)?;
            builder.check_private_key()?;
            clear_chain(builder);
            attach_intermediates(builder, &real_chain)?;
            return Ok(());
        }
    } else if let Some((ec_x509, ec_pkey, ec_chain)) = cover_ec.as_ref().or(ec_pair.as_ref()) {
        // ECH 路径：维持「单 credential 槽、后设置者生效」的历史行为。
        // 切换后必须**清掉上一层留下的中间链**再挂这一张自己的链，否则客户端会收到
        // 「叶=EC、中间链=RSA 那条」的错配链。
        builder.set_certificate(ec_x509)?;
        builder.set_private_key(ec_pkey)?;
        builder.check_private_key()?;
        clear_chain(builder);
        attach_intermediates(builder, ec_chain)?;
    }

    if cover.is_some() {
        // RFC 9849：证书选择判据是 **ECH 是否被接受**（`SSL_ech_accepted`），
        // **不能用域名比较** —— 按名字判等于「谁把 SNI 写成真实名，谁就拿到真实证书」，
        // 那既让 cover 形同虚设，又向主动探测者确认了「本机持有该域名的证书」。
        //
        // * `ech_accepted() == true`：客户端用了 ECH 且解密成功，服务端看到的是**内层真实名**
        //   ⇒ 用真实证书（TLS1.3 下证书对被动观察者加密，MITM 看不到）。
        // * `false`（客户端没发 ECH，或发了但被拒后回退）：一律用 **cover**。
        //   —— 包括「SNI 恰好是真实名」的探测连接：它们只配看到外层证书。
        // 注：本回调在 **ECH 处理之后**运行（实测：ECH 客户端在此处已能看到内层名）。
        let real_cert = cert.clone();
        let real_key = key.clone();
        let real_ec = ec_pair
            .as_ref()
            .map(|(c, k, chain)| (c.clone(), k.clone(), chain.clone()));
        // OCSP 是逐证书一份：把两份材料搬进回调 —— 但**不能在这里取快照**。
        // `StapleSource::bytes()` 对 Auto 是「读一次当前值」，而自动续期线程在构建之后
        // 才把新响应写进槽 ⇒ 构建期为空的部署会**永远不装订**（即便续期早就成功），
        // 有值的则冻结到下次 reload。改成搬「来源」，每次握手现读。
        let ocsp_real = LiveStaple::from(&ocsp.real);
        let ocsp_cover = LiveStaple::from(&ocsp.cover);
        builder.set_servername_callback(move |s, _alert| {
            if !s.ech_accepted() {
                // 未接受 ECH：保持容器默认（cover）证书 —— 但 **staple 必须换成 cover 的**：
                // 容器上装的是真实证书那份（apply_ocsp 的默认动作），装在 cover 上就是错配。
                //
                // 「未接受」既包括普通非 ECH 客户端，也包括发了 ECH 但服务端解密失败
                //（配置轮换/攻击者构造）后的回退。后者在排障时最容易与「ECH 未生效」
                // 混淆，所以留一条 debug（只对排障有意义，info 会被匿名连接刷）。
                log::debug!(
                    "ech: not accepted ⇒ 使用 cover 证书（SNI={:?}；非 ECH 客户端或 ECH 被拒）",
                    s.servername(NameType::HOST_NAME)
                );
                match ocsp_cover.as_ref().and_then(|l| l.bytes()) {
                    Some(der) => {
                        let _ = s.set_ocsp_status(&der);
                    }
                    // cover 没有自己的 staple ⇒ **清空**：不装订是安全的（客户端自行查询），
                    // 留着真实证书那份才是错的。
                    None => {
                        let _ = s.set_ocsp_status(&[]);
                    }
                }
                return Ok(());
            }
            // ECH 被接受：换成真实证书，并把 staple 换成真实证书那份（**现读**，
            // 这样续期线程一成功，后续握手立刻用上新响应）。
            // 读不到就**什么都不做**：容器上装的正是 apply_ocsp 给真实证书装的那份
            //（同一个来源），清空反而会把一份有效 staple 抹掉。
            if let Some(der) = ocsp_real.as_ref().and_then(|l| l.bytes()) {
                let _ = s.set_ocsp_status(&der);
            }
            if s.set_certificate(&real_cert).is_err() || s.set_private_key(&real_key).is_err() {
                log::warn!("ech: ECH 已接受但切换真实证书失败（保持 cover）");
                return Err(boring::ssl::SniError::ALERT_FATAL);
            }
            if let Some((ec_c, ec_k, ec_chain)) = &real_ec {
                // 备用 EC 链同样切成真实的，否则 ECDSA 客户端拿到不匹配的链。
                //
                // 这里**只追加、不清空**：`SslRef::as_ptr` 需要 `foreign_types` 的 trait
                //（本 crate 不是它的直接依赖），而追加在语义上是安全的 —— 客户端按叶证书
                // 的 issuer 只挑真正需要的那张中间证书；多出来的 cover 中间证书本来就是
                // 公开信息。ctx 级别的切换（load_identity 的 cover_ec 分支）才做 clear。
                let _ = s.set_certificate(ec_c);
                let _ = s.set_private_key(ec_k);
                for c in ec_chain {
                    let _ = s.add_chain_cert(c);
                }
            }
            // 日志不脱敏（本地存储安全，用户明确要求）：内层名便于排障。
            log::debug!(
                "ech: accepted ⇒ 真实证书（服务端看到内层名 {:?}）",
                s.servername(NameType::HOST_NAME)
            );
            Ok(())
        });
    }
    Ok(())
}

/// 名字匹配（通配符感知，RFC 6125 §6.4.3 的简化：只支持最左 `*.`）。
fn dns_name_matches(pattern: &str, name: &str) -> bool {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if p == n {
        return true;
    }
    if let Some(rest) = p.strip_prefix("*.") {
        // 通配符只匹配**一个**标签：`*.example.com` 匹配 `a.example.com`，不匹配
        // `a.b.example.com`、也不匹配 `example.com` 本身。
        return match n.split_once('.') {
            Some((_, tail)) => tail == rest,
            None => false,
        };
    }
    false
}

/// 证书是否覆盖该名字：**SAN 优先**，CN 仅作兼容回退（现代 CA 一律走 SAN）。
fn cert_covers(cert: &X509Ref, name: &str) -> bool {
    if let Some(sans) = cert.subject_alt_names() {
        for gn in sans.iter() {
            if let Some(dns) = gn.dnsname() {
                if dns_name_matches(dns, name) {
                    return true;
                }
            }
        }
    }
    if let Some(cn) = cert
        .subject_name()
        .entries_by_nid(boring::nid::Nid::COMMONNAME)
        .next()
    {
        if let Ok(s) = std::str::from_utf8(cn.data().as_slice()) {
            if dns_name_matches(s, name) {
                return true;
            }
        }
    }
    false
}

/// BoringSSL 内置的 TLS1.3 套件名 —— **唯一真相源**是
/// [`cipher_catalog::TLS13_SUITES`]，这里只做个别名，**不要再抄一份**。
///
/// 原来本文件自己抄了一份（3 条），而 `cipher_catalog` 那份是 5 条（多出 RFC 8446 有、
/// 但 BoringSSL `kCiphers` 里没有的两条 CCM）：两份名单漂移的直接后果是**配置校验放行、
/// 剔除逻辑不认**，那个名字落进 `set_cipher_list` 之后 `SSL_R_NO_CIPHER_MATCH` ⇒ 该监听口
/// 无法构建 acceptor（已实测：`--check-config` 直接报 `[NO_CIPHER_MATCH]`）。
/// 面板把这份名单当可选项列出，所以运维**点一下**就能造出这个故障。
const TLS13_SUITES: &[&str] = crate::server::tls::cipher_catalog::TLS13_SUITES;


/// psk=true 时追加的 PSK/ECDHE-PSK 套件族（早期规格 13）。
///
/// 从 [`cipher_catalog`] 里筛出来 —— 不再手工维护名字：以前那份常量里 6 个名字有 5 个
/// 是 OpenSSL 的、BoringSSL 没有，而解析失败是静默忽略的，于是"显式配套件列表"时 psk 一个都没生效。
fn psk_tail() -> String {
    let mut s = String::new();
    for n in crate::server::tls::cipher_catalog::psk_suites() {
        s.push(':');
        s.push_str(&n);
    }
    s
}

fn apply_ciphers(builder: &mut SslAcceptorBuilder, ssl: &SslConfig, strict: bool) -> Result<()> {
    // 配置里写了 BoringSSL 不认的套件名：**运行时绝不能 bail**。这条错误发生在
    // `build_acceptor` 里，而 acceptor 是**每条连接**在握手热路径上构建的
    //（`accept_and_serve` → `build_acceptor_cached`）⇒ 一个拼错的套件名会让该
    // listener 的**每条**连接（包括配置正确的 TLS1.2/1.3 客户端）都被 soft-fail
    // 丢弃，运维只能看到「端口在监听、握手全失败」。热重载/面板保存不跑
    // `--check-config`，`config.validate` 也不校验套件名 —— 这正是 tls-core P1-21
    // （legacy 版本条目毒死监听口）的同类回归。
    //
    // 两档语义：
    // * strict=true（`--check-config`/启动预检/单测）：非法名字**直接报错**，让配置
    //   问题在预检阶段暴露；
    // * strict=false（握手热路径）：剔除坏名字并指名列报（= 显式禁用），剩余名字正常
    //   生效；若全部被剔除，回落库默认列表并大声告警 —— 端口继续服务。
    let (kept, bad) = filter_acceptable_ciphers(&ssl.ciphers);
    if !bad.is_empty() {
        if strict {
            anyhow::bail!(
                "ssl.ciphers 里含 BoringSSL 不支持的套件名 {:?}（可用目录见 /api/tls/ciphers 或面板）。\
严格模式下拒绝启动；若这是热重载，运行时会剔除坏名字并继续服务",
                bad
            );
        }
        crate::server::log_throttle::warn_every(
            "tls-ciphers-invalid",
            std::time::Duration::from_secs(60),
            &format!(
                "ssl.ciphers 里含 BoringSSL 不支持的套件名 {:?}（已剔除，否则整个监听口构建不出 \
acceptor、所有连接被丢弃）；实际生效 {:?}。可用目录见 /api/tls/ciphers",
                bad, kept
            ),
        );
    }
    let mut list = if ssl.ciphers.is_empty() {
        "ALL:!eNULL:!SSLv3".to_string()
    } else if kept.is_empty() {
        log::error!(
            "ssl.ciphers 全部被剔除（无 BoringSSL 可配置的 TLS≤1.2 套件），回落默认列表 \
ALL:!eNULL:!SSLv3 —— 这是降级，不是配置生效"
        );
        "ALL:!eNULL:!SSLv3".to_string()
    } else {
        kept.join(":")
    };
    // TLS1.3 套件名**不能**经 SSL_CTX_set_cipher_list 生效：BoringSSL 的可配置套件表
    // （ssl_cipher.cc 的 co_list）只含 TLS≤1.2 套件，TLS1.3 名字匹配不到条目 → 被
    // 静默忽略；若列表里**只有** TLS1.3 名字，结果为空 → SSL_R_NO_CIPHER_MATCH →
    // set_cipher_list 报错 → build_acceptor 失败 → 这个监听口的**每个**连接都软失败
    //（客户端只看到连接被关闭）。boring 明确写着 BoringSSL 没有 set_ciphersuites，
    // 所以 TLS1.3 套件集合在库内固定：要限制 TLS1.3 只能用 ssl.versions。
    // 这里如实告警 + 剔除；剔除后没有 1.2 套件可配时回落默认列表，不把监听口配死。
    let (list_without13, dropped) = split_tls13_suites(&list);
    if !dropped.is_empty() {
        log::error!(
            "ssl.ciphers 中的 TLS1.3 套件 {:?} 无法配置（BoringSSL 未实现 set_ciphersuites，\
             TLS1.3 固定为 AES-128-GCM/AES-256-GCM/CHACHA20-POLY1305）；限制 TLS1.3 请用 \
             ssl.versions。已从 TLS≤1.2 套件列表中剔除",
            dropped
        );
    }
    if list_without13.trim_matches(':').is_empty() {
        log::error!("ssl.ciphers 剔除 TLS1.3 套件后无剩余套件，回落默认列表 ALL:!eNULL:!SSLv3");
        list = "ALL:!eNULL:!SSLv3".to_string();
    } else {
        list = list_without13;
    }
    if ssl.psk {
        list.push_str(&psk_tail());
    }
    // 即便逐个名字都过了 `is_acceptable`，整条 cipher string 仍可能因组合语义
    // （`!`/`+`/`-` 修饰符、别名交互）被库拒绝。这时也**不能**让 acceptor 构建失败：
    // 回落默认列表并明确告警（该 listener 继续服务，只是套件策略降级）。
    if let Err(e) = builder.set_cipher_list(&list) {
        log::error!(
            "ssl.ciphers 整条列表被 BoringSSL 拒绝（{e:?}），回落默认 ALL:!eNULL:!SSLv3 —— \
该监听口继续服务，但套件策略是降级后的默认值"
        );
        let mut fallback = "ALL:!eNULL:!SSLv3".to_string();
        if ssl.psk {
            fallback.push_str(&psk_tail());
        }
        builder
            .set_cipher_list(&fallback)
            .context("回落默认套件列表仍失败（BoringSSL 内部异常）")?;
    }
    Ok(())
}

/// 逐名过滤 `ssl.ciphers`，返回 (可用条目, 被剔除的条目)。纯函数，便于单测。
///
/// 注意 cipher string 的条目可以带 `!`/`-`/`+`/`@` 修饰符（排除/降低/提升/固定）。
/// 校验时要把修饰符剥掉再问 BoringSSL —— 否则 `!AES128-SHA` 这类**合法排除项**会被
/// 误判为坏名字剔除，等于静默取消管理员的排除策略。返回的 `kept` 保留原始写法。
fn filter_acceptable_ciphers(ciphers: &[String]) -> (Vec<String>, Vec<String>) {
    let mut kept = Vec::new();
    let mut bad = Vec::new();
    for raw in ciphers {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        let bare = name.trim_start_matches(['!', '-', '+', '@']);
        if bare.is_empty() {
            bad.push(name.to_string());
        } else if crate::server::tls::cipher_catalog::is_acceptable(bare)
            || crate::server::tls::cipher_catalog::is_acceptable(name)
        {
            kept.push(name.to_string());
        } else {
            bad.push(name.to_string());
        }
    }
    (kept, bad)
}

/// 把配置里的套件串拆开，返回 (TLS≤1.2 套件串, 被剔除的 TLS1.3 套件名)。
///
/// 分隔符按 BoringSSL 非严格模式接受的形式（`:`/`,`/空白/`;`）切开再统一用 `:` 拼回；
/// 条目上的 `!`/`-`/`+`/`@` 修饰符不参与名字匹配（剔除整条：对固定套件做排除同样无效）。
fn split_tls13_suites(spec: &str) -> (String, Vec<String>) {
    let mut kept: Vec<&str> = Vec::new();
    let mut dropped: Vec<String> = Vec::new();
    for item in spec.split([':', ',', ';', ' ', '\t', '\n']).filter(|s| !s.is_empty()) {
        let name = item.trim_start_matches(['!', '-', '+', '@']);
        if TLS13_SUITES.iter().any(|s| s.eq_ignore_ascii_case(name)) {
            dropped.push(item.to_string());
        } else {
            kept.push(item);
        }
    }
    (kept.join(":"), dropped)
}

#[cfg(test)]
mod ciphers_tests {
    use super::{filter_acceptable_ciphers, split_tls13_suites};

    /// TLS1.3 套件名不能进 set_cipher_list（BoringSSL 会忽略；只剩它们时整条列表报错
    /// → 监听口每个连接都失败）。
    #[test]
    fn tls13_suite_names_are_stripped() {
        let (kept, dropped) =
            split_tls13_suites("TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256");
        assert_eq!(kept, "ECDHE-RSA-AES128-GCM-SHA256");
        assert_eq!(dropped, vec!["TLS_AES_128_GCM_SHA256".to_string()]);

        // 只有 TLS1.3 名字 → 剔除后为空（调用方回落默认列表，而不是把口配死）。
        let (kept, dropped) =
            split_tls13_suites("TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256");
        assert!(kept.is_empty());
        assert_eq!(dropped.len(), 2);

        // 修饰符 + 大小写。
        let (kept, dropped) = split_tls13_suites("!tls_aes_128_gcm_sha256");
        assert!(kept.is_empty());
        assert_eq!(dropped.len(), 1);

        // 前缀相近的 TLS1.2 名字不受影响。
        let (kept, dropped) = split_tls13_suites("TLS_RSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(kept, "TLS_RSA_WITH_AES_128_GCM_SHA256");
        assert!(dropped.is_empty());
    }

    /// 回归（P1-21 同类）：拼错一个套件名必须**只剔除该名字**，不能 bail 掉整个
    /// acceptor —— 否则热重载/面板保存后该 listener 的每条连接都 soft-fail。
    #[test]
    fn invalid_cipher_names_are_filtered_not_fatal() {
        let input = vec![
            "ECDHE-RSA-AES128-GCM-SHA256".to_string(),
            "NOT-A-REAL-CIPHER".to_string(),
            "  ".to_string(),
        ];
        let (kept, bad) = filter_acceptable_ciphers(&input);
        assert_eq!(kept, vec!["ECDHE-RSA-AES128-GCM-SHA256".to_string()]);
        assert_eq!(bad, vec!["NOT-A-REAL-CIPHER".to_string()]);

        // 全部无效：kept 为空，由调用方回落默认列表（端口继续服务）。
        let (kept, bad) = filter_acceptable_ciphers(&["NOT-A-REAL-CIPHER".to_string()]);
        assert!(kept.is_empty());
        assert_eq!(bad.len(), 1);

        // 合法排除项（`!name`）必须保留原始写法 —— 剥掉修饰符校验，不能把管理员的
        // 排除策略当坏名字静默剔除。
        let (kept, bad) = filter_acceptable_ciphers(&["!ECDHE-RSA-AES128-GCM-SHA256".to_string()]);
        assert_eq!(kept, vec!["!ECDHE-RSA-AES128-GCM-SHA256".to_string()]);
        assert!(bad.is_empty());
    }
}

#[cfg(test)]
mod versions_tests {
    use super::*;

    fn v(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// 回归（P1）：`versions` 里包含 tls1.0/tls1.1 时，旧实现对 legacy 条目直接 bail
    /// ⇒ build_acceptor 失败 ⇒ 整个监听口（包括 TLS1.2 客户端）全部 soft-fail。
    /// 现在 legacy 条目被忽略并单独返回，现代范围仍正确计算。
    #[test]
    fn legacy_entries_do_not_poison_boring_range() {
        let (min, max, legacy) = plan_versions(&v(&["tls1.0", "tls1.2"])).unwrap();
        assert_eq!(min.map(version_rank), Some(2));
        assert_eq!(max.map(version_rank), Some(2));
        assert_eq!(legacy, vec!["tls1.0".to_string()]);

        let (min, max, legacy) = plan_versions(&v(&["tls1.1", "tls1.3"])).unwrap();
        assert_eq!(min.map(version_rank), Some(3));
        assert_eq!(max.map(version_rank), Some(3));
        assert_eq!(legacy.len(), 1);

        let (min, max, legacy) = plan_versions(&v(&["TLSv1.2", "tlsv1.3"])).unwrap();
        assert_eq!(min.map(version_rank), Some(2));
        assert_eq!(max.map(version_rank), Some(3));
        assert!(legacy.is_empty());
    }

    /// 只含 legacy 版本时返回空范围（调用方回落 1.2–1.3，而不是把端口配死）。
    #[test]
    fn legacy_only_yields_empty_modern_range() {
        let (min, max, legacy) = plan_versions(&v(&["tls1.0", "tlsv1.1"])).unwrap();
        assert!(min.is_none() && max.is_none());
        assert_eq!(legacy, vec!["tls1.0".to_string(), "tlsv1.1".to_string()]);
    }

    /// 无法识别的版本串仍要报错（热重载路径不跑 config 校验，必须在这里拦）。
    #[test]
    fn unknown_version_string_errors() {
        assert!(plan_versions(&v(&["tls9.9"])).is_err());
    }
}

/// G-12：`prefer_tls13` 按 ClientHello 选两套上下文的判定。
#[cfg(test)]
mod prefer_profile_tests {
    use super::*;

    /// 真实布局的最小 ClientHello；`versions` 为空表示不带 supported_versions 扩展。
    fn client_hello(versions: &[u16]) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0x00); // session_id_len
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        hs.push(0x01); // compression_methods_len
        hs.push(0x00);
        let mut ext = Vec::new();
        if !versions.is_empty() {
            let mut ed = vec![(versions.len() * 2) as u8];
            for v in versions {
                ed.extend_from_slice(&v.to_be_bytes());
            }
            ext.extend_from_slice(&0x002bu16.to_be_bytes());
            ext.extend_from_slice(&(ed.len() as u16).to_be_bytes());
            ext.extend_from_slice(&ed);
        }
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((4 + hs.len()) as u16).to_be_bytes());
        rec.push(0x01);
        let hl = hs.len();
        rec.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn prefer_true_splits_by_clienthello() {
        let ssl = SslConfig {
            prefer_tls13: true,
            ..Default::default()
        };
        // 声明 1.3 ⇒ 1.3-only；只声明 1.2 ⇒ 上限 1.2（不是拒绝）。
        assert_eq!(
            pick_version_profile(&ssl, &client_hello(&[0x0304, 0x0303])),
            VersionProfile::Tls13Only
        );
        assert_eq!(
            pick_version_profile(&ssl, &client_hello(&[0x0303])),
            VersionProfile::Tls12Max
        );
        // 完全没有 supported_versions（老客户端）⇒ 回落 1.2。
        assert_eq!(
            pick_version_profile(&ssl, &client_hello(&[])),
            VersionProfile::Tls12Max
        );
    }

    /// peek 被截断（超长 ClientHello / 只读到一半）时不能猜成「不支持 1.3」：
    /// 回库默认，由客户端能力正常协商（避免把 1.3 客户端硬压到 1.2）。
    #[test]
    fn truncated_peek_falls_back_to_library_default() {
        let ssl = SslConfig {
            prefer_tls13: true,
            ..Default::default()
        };
        let full = client_hello(&[0x0304, 0x0303]);
        assert_eq!(
            pick_version_profile(&ssl, &full[..full.len() - 3]),
            VersionProfile::Default
        );
    }

    #[test]
    fn prefer_false_is_library_default() {
        let ssl = SslConfig::default();
        assert_eq!(
            pick_version_profile(&ssl, &client_hello(&[0x0304, 0x0303])),
            VersionProfile::Default
        );
        assert_eq!(
            pick_version_profile(&ssl, &client_hello(&[0x0303])),
            VersionProfile::Default
        );
    }

    #[test]
    fn explicit_versions_win_over_prefer() {
        let ssl = SslConfig {
            prefer_tls13: true,
            versions: vec!["tls1.2".into(), "tls1.3".into()],
            ..Default::default()
        };
        assert_eq!(
            pick_version_profile(&ssl, &client_hello(&[0x0304, 0x0303])),
            VersionProfile::Default,
            "显式 versions 优先，prefer_tls13 不得再覆盖范围"
        );
    }

    /// 把单 record 的 ClientHello 拆成两条握手 record。
    fn split_records(full: &[u8], at: usize) -> Vec<u8> {
        let hs = &full[5..];
        let at = at.min(hs.len());
        let (a, b) = hs.split_at(at);
        let mut out = Vec::new();
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&(a.len() as u16).to_be_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(b);
        out
    }

    /// 回归：supported_versions 在第二个 record 时，**只有第一个 record** 的 peek
    /// 不能把 1.3 客户端判成 Tls12Max（必须回 Default，让库按客户端能力协商）。
    /// 两个 record 都在 peek 里时则应正确判定 Tls13Only。
    #[test]
    fn fragmented_client_hello_does_not_force_tls12() {
        let ssl = SslConfig {
            prefer_tls13: true,
            ..Default::default()
        };
        let full = client_hello(&[0x0304, 0x0303]);
        let frag = split_records(&full, 20);
        // 只给第一个 record：无法看到完整 ClientHello ⇒ 不猜。
        let first = &frag[..25 + 20];
        assert_eq!(pick_version_profile(&ssl, first), VersionProfile::Default);
        // 完整的两段：必须识别出 1.3。
        assert_eq!(
            pick_version_profile(&ssl, &frag),
            VersionProfile::Tls13Only
        );
    }
}

/// 证书链顺序 / 私钥反查回归。
#[cfg(test)]
mod chain_tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_file(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name)
    }

    /// 回归：`fullchain.pem` 被写成 root-first（或任意顺序）时，按私钥反查出真正的
    /// 叶证书并重排 —— 旧实现 `remove(0)` 把根当叶，`check_private_key` 失败 ⇒
    /// build_acceptor 失败 ⇒ 整个监听口每条连接 soft-fail。
    #[test]
    fn chain_reorders_leaf_when_not_first() {
        let cert_pem = std::fs::read(repo_file("cert.pem")).expect("cert.pem");
        let ec_pem = std::fs::read(repo_file("cert_ec.pem")).expect("cert_ec.pem");
        let key_pem = std::fs::read(repo_file("key.pem")).expect("key.pem");
        let key = PKey::private_key_from_pem(&key_pem).expect("key parse");
        let rsa = X509::from_pem(&cert_pem).expect("rsa parse");
        let ec = X509::from_pem(&ec_pem).expect("ec parse");

        // 错误顺序：EC（不匹配）在前，真正的叶（RSA）在后。
        let mut chain = ec_pem.clone();
        chain.extend_from_slice(&cert_pem);
        let (leaf, rest) = split_chain(&chain, &key).expect("split_chain");
        assert_eq!(leaf.to_der().unwrap(), rsa.to_der().unwrap(), "叶证书必须是被重排到首位的那张");
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].to_der().unwrap(), ec.to_der().unwrap());
    }

    /// 私钥与链里任何证书都不匹配时必须明确报错（而不是把第一张当叶继续）。
    #[test]
    fn chain_without_matching_key_errors_clearly() {
        let ec_pem = std::fs::read(repo_file("cert_ec.pem")).expect("cert_ec.pem");
        let key_pem = std::fs::read(repo_file("key.pem")).expect("key.pem");
        let key = PKey::private_key_from_pem(&key_pem).expect("key parse");
        let err = split_chain(&ec_pem, &key).unwrap_err();
        assert!(
            format!("{err:#}").contains("没有任何一张证书与私钥匹配"),
            "{err:#}"
        );
    }
}

/// Post-quantum hybrid + explicit group list (BoringSSL `SSL_CTX_set1_groups_list`).
fn apply_groups(builder: &mut SslAcceptorBuilder, ssl: &SslConfig, strict: bool) -> Result<()> {
    let list = if !ssl.groups.is_empty() {
        ssl.groups.join(":")
    } else if ssl.pqc {
        "X25519MLKEM768:X25519:P-256:P-384".to_string()
    } else {
        return Ok(());
    };
    // 一个拼错的组名会让 `set_curves_list` 报错 ⇒ build_acceptor 失败 ⇒ 该监听口
    // **每条**连接都在构建 acceptor 处 soft-fail（热重载/面板保存不跑校验，只有
    // `--check-config` 能提前拦，tls-core P3）。
    //
    // 这里改为**逐名探测**：对每个名字单独调一次 `set_curves_list`（同名会整体失败、
    // boring 的 ErrorStack 又不指名是哪个），把坏的剔除并指名列报，最后用过滤后的列表
    // 定稿。这样拼错一个名字只降级为「该组被忽略」，而不是把整个监听口配死。
    // 不做硬编码白名单（BoringSSL 组名别名多，白名单会误拒合法名字）。
    let mut kept: Vec<String> = Vec::new();
    let mut bad: Vec<String> = Vec::new();
    for name in list.split(':').filter(|s| !s.is_empty()) {
        match builder.set_curves_list(name) {
            Ok(()) => kept.push(name.to_string()),
            Err(_) => bad.push(name.to_string()),
        }
    }
    if !bad.is_empty() {
        if strict {
            anyhow::bail!(
                "ssl.groups 含 BoringSSL 不认识的组名 {:?}（预检严格模式拒绝；常用组名如 \
X25519MLKEM768/X25519/P-256/P-384）",
                bad
            );
        }
        crate::server::log_throttle::warn_every(
            "tls-groups-invalid",
            std::time::Duration::from_secs(60),
            &format!(
                "ssl.groups 含 BoringSSL 不认识的组名 {:?}（已剔除，否则整个监听口构建不出 acceptor、\
所有连接被丢弃）；实际启用 {:?}。常用组名如 X25519MLKEM768/X25519/P-256/P-384",
                bad, kept
            ),
        );
    }
    if kept.is_empty() {
        // 全被剔除：不能调 `set_curves_list("")`（会报错把口配死），保持库内默认。
        return Ok(());
    }
    // 逐名探测通过后整条列表理论上不会失败；但真失败了也**不能**让 acceptor 构建失败
    // （那会把整个监听口变成「每连接 soft-fail」）。回落库默认 + 明确告警。
    if let Err(e) = builder.set_curves_list(&kept.join(":")) {
        log::error!(
            "ssl.groups 定稿失败（{e:?}），保持 BoringSSL 默认组列表 —— 该监听口继续服务，\
但组策略是降级后的默认值"
        );
    }
    Ok(())
}

/// 应用 ECH 密钥（**仅当 `ssl.ech = true`**；关掉就是一点 ECH 材料都不装）。
///
/// 三条路径，优先级从高到低：
///   1. `ssl.ech_keys` 显式配置 → 用管理员材料（原行为不变）；
///   2. 未配置 → **自动配置**（规格 §16 1.a）：先复用 `state/ech/ech_keys.pem`
///      里已生成且仍匹配当前 public-name/suite/max-name-length 的配置，
///      不匹配则用真实 X25519 keypair 重新生成并落盘；
///   3. 自动配置失败（如未填 `ech_public_name`）→ 仅 warn，不阻断 TLS。
///
/// 早期实现只走路径 1：`ech_keys` 没配就直接放弃，于是「ECH 自动配置」实际不存在。
/// `ech_advertise` 不参与这里的开关判断，它只决定「配置要不要发到 HTTPS(type65) 记录」，
/// 见 `SslConfig::ech_advertise_enabled`。
fn apply_ech(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    // 判据只能是 `ssl.ech`。旧写法 `!ssl.ech && !ssl.ech_advertise` 有真实后果：
    // `ech_advertise` 的 serde 默认值是 **true**，于是只要 `ech_public_name` 配了
    // （它同时是 `SslConfig::ocsp_host()` 的身份来源），**显式关掉** ECH 的 listener
    // 也会继续走到下面的自动配置 —— 生成密钥、装进 acceptor，ECH 被实际打开。
    // 开关必须名副其实。反向情形（`ech = true` 但材料不全）仍要走到下面的 warn：
    // 那是「开了却没生效」，必须吵（见回归测试 ech_false_disables_ech_even_with_public_name）。
    if !ssl.ech {
        return Ok(());
    }
    if let Some(keys_path) = ssl.ech_keys.as_deref() {
        match ssl_material::load_bytes(keys_path) {
            Ok(pem) => {
                if let Err(e) = apply_ech_keys(builder, &pem) {
                    log::warn!("ECH keys invalid ({keys_path}): {e:#}; continuing without ECH");
                } else {
                    // 显式 ech_keys 场景：把这份 PEM 里的 ECHConfig 派生出的 ECHConfigList
                    // 落盘到 DNS/面板读取的固定路径，保证「发布的 = 服务端实际在用的」。
                    // 旧实现只把 PEM 装进 BoringSSL，DNS 读固定路径 → 发布缺失或另一把钥匙
                    // 的配置（tls-core P2）。
                    match crate::server::tls::ech_pem::first_config(&pem) {
                        Some(cfg) => {
                            crate::server::ech_auto::ensure_config_list_file(&cfg);
                        }
                        None => log::warn!(
                            "ECH: ech_keys={keys_path} 解析不出 ECH CONFIG 块，DNS 无法发布对应配置"
                        ),
                    }
                }
            }
            Err(e) => {
                log::warn!("ECH keys unavailable ({keys_path}): {e:#}; continuing without ECH");
            }
        }
        return Ok(());
    }

    // 自动配置路径（规格 §16 1.a）
    match crate::server::ech_auto::ensure_from_config(
        ssl.ech_public_name.as_deref(),
        ssl.ech_cipher_suite.as_deref(),
        ssl.ech_max_name_length,
    ) {
        Ok(mat) => {
            let pem = mat.to_pem();
            match apply_ech_keys(builder, pem.as_bytes()) {
                Ok(()) => log::info!(
                    "ECH 自动配置就绪 (reused={} public_name={} config_list_b64_len={})",
                    mat.reused,
                    ssl.ech_public_name.as_deref().unwrap_or("?"),
                    mat.config_list_base64().len()
                ),
                Err(e) => log::warn!("ECH 自动配置装载失败: {e:#}; continuing without ECH"),
            }
        }
        Err(e) => {
            log::warn!(
                "ECH 自动配置不可用（配置 ssl.ech_public_name 后可用）: {e:#}; continuing without ECH"
            );
        }
    }
    Ok(())
}

fn apply_ech_keys(builder: &mut SslAcceptorBuilder, pem: &[u8]) -> Result<()> {
    let keys = crate::server::tls::ech_pem::load_ech_keys(pem).context("ECH keys PEM")?;
    builder.set_ech_keys(&keys).context("set_ech_keys")?;
    Ok(())
}

/// P1-8（§16.16/§22.7）+ 早期规格 1b：server 端 OCSP stapling。
///
/// 两种来源，**静态路径优先**：
/// 1. `ssl.ocsp_der_path` 已配置 → 原行为不变（读文件 → 剥 PEM → 回调装订）。
/// 2. 未配置 → 自动获取：从 `ssl.cert` 全链 + 叶子 AIA 解析出 OCSP 目标，
///    经 `ocsp_fetcher::prepare_stapling` 建槽（只读本地 `state/ocsp` 缓存，**不触网**），
///    真正的网络抓取由 `ocsp_fetcher` 的后台续期线程完成，取回后回调自动装订。
///
/// 两条路径都失败时仅 warn，绝不阻断 TLS。
/// 一份 OCSP staple 的来源：静态文件内容，或后台自动续期的槽。
enum StapleSource {
    Static(Vec<u8>),
    Auto(std::sync::Arc<crate::server::ocsp_fetcher::StapleSlot>),
}

/// 可搬进握手回调的 staple 来源：`Static` 是配置里给的那份（内容不变），
/// `Auto` 指向续期线程会持续更新的槽 —— 每次握手 `bytes()` 现读，所以续期一旦成功
/// 后续握手立刻用上。
#[derive(Clone)]
enum LiveStaple {
    Static(std::sync::Arc<Vec<u8>>),
    Auto(std::sync::Arc<crate::server::ocsp_fetcher::StapleSlot>),
}

impl LiveStaple {
    fn from(src: &Option<StapleSource>) -> Option<Self> {
        match src {
            Some(StapleSource::Static(b)) => Some(LiveStaple::Static(std::sync::Arc::new(b.clone()))),
            Some(StapleSource::Auto(s)) => Some(LiveStaple::Auto(std::sync::Arc::clone(s))),
            None => None,
        }
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            LiveStaple::Static(b) => Some((**b).clone()),
            LiveStaple::Auto(s) => s.current(),
        }
    }
}

impl StapleSource {
    fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            StapleSource::Static(b) => Some(b.clone()),
            StapleSource::Auto(s) => s.current(),
        }
    }
}

/// **逐证书**的 OCSP 装订规划。
///
/// ECH 会在 **cover** 与 **真实** 证书之间切换，而 OCSP 响应是与证书**一一对应**的
/// （`SSL_set_ocsp_status` 装的是单份 DER）⇒ 必须各准备一份：
/// * `real`  —— 配给 `ssl.cert`（ECH 被接受、使用内层真实证书时用）；
/// * `cover` —— 配给 `ssl.ech_cover_cert`（未用 ECH / ECH 被拒时用）。
///
/// 某一侧没有材料时**不装订那一侧**：**不装订是安全的**（客户端会自行查询 OCSP），
/// 而装了**不匹配**的那份才是有害的（严格客户端校验失败；宽松客户端撤回检查静默失效）。
struct OcspPlan {
    real: Option<StapleSource>,
    cover: Option<StapleSource>,
}

fn ocsp_static_from(path: &str) -> Option<StapleSource> {
    match ssl_material::load_bytes(path) {
        Ok(d) if !d.is_empty() => {
            let der = pem_to_der(&d).unwrap_or(d);
            // 静态路径过去只「读文件 → 装订」，完全不看内容：过期/unknown/超大 DER 会被
            // 原样发给客户端（unknown 让 must-staple 失败；>65535 让 BoringSSL 编码
            // ServerHello 时 overflow，该口**每条** TLS1.3 握手失败）。这里用与自动抓取
            // 相同的判据显式禁用并说清原因。
            if let Err(why) = crate::server::ocsp_fetcher::validate_staple_der(&der) {
                log::warn!("ssl.ocsp_der_path={path} 不可装订（{why}）；该证书不装订 OCSP");
                return None;
            }
            log::info!("ocsp stapling: {} bytes from {path}", der.len());
            Some(StapleSource::Static(der))
        }
        Ok(_) => {
            log::warn!("ssl.ocsp 材料 {path} 为空；该证书不装订");
            None
        }
        Err(e) => {
            log::warn!("ssl.ocsp 材料 {path} 不可读: {e:#}；该证书不装订");
            None
        }
    }
}

/// 从 `ssl.cert` + `ssl.key` 取**真正的叶证书**（链顺序错误时也能找对）。
///
/// 旧实现一律 `X509::from_pem(&cert_pem)`（= 第一张）。chain-root-first 的部署会
/// 把根当作叶：SAN/AIA/序列号全错，自动 OCSP 直接静默失效（找不到 AIA）。
fn load_leaf_for_ssl(ssl: &SslConfig) -> Option<X509> {
    let cert_pem = ssl_material::load_bytes(ssl.cert.as_deref()?).ok()?;
    match ssl.key.as_deref() {
        Some(k) => {
            let key_pem = ssl_material::load_bytes(k).ok()?;
            let key = PKey::private_key_from_pem(&key_pem).ok()?;
            split_chain(&cert_pem, &key).ok().map(|(leaf, _)| leaf)
        }
        None => X509::from_pem(&cert_pem).ok(),
    }
}

/// 自动获取路径：`(host, 叶证书, 全链 PEM)` → 后台续期槽。
fn ocsp_auto_slot(host: &str, leaf: &X509, chain_pem: &[u8]) -> Option<StapleSource> {
    crate::server::ocsp_fetcher::prepare_stapling(host, leaf, chain_pem)
        .map(StapleSource::Auto)
}

/// OCSP 自动获取用的站点身份。
///
/// 优先配置的 `sni_name` / `ech_public_name`；两者都缺时回退叶子证书的**第一个 DNS SAN**
/// —— 站点身份本可从证书推导，而缓存键另有证书指纹隔离，host 只是文件名/日志标签。
/// 旧实现只认配置字段，于是「只配了 cert/key 的最典型 listener」永远静默跳过自动 OCSP
/// （tls-core P2）。都没有才返回 None。
fn ocsp_identity(ssl: &SslConfig) -> Option<String> {
    if let Some(h) = ssl.ocsp_host() {
        return Some(h);
    }
    let leaf = load_leaf_for_ssl(ssl)?;
    if let Some(sans) = leaf.subject_alt_names() {
        for gn in sans.iter() {
            if let Some(dns) = gn.dnsname() {
                let d = dns.trim();
                if !d.is_empty() {
                    return Some(d.to_string());
                }
            }
        }
    }
    None
}

/// 为真实证书与 cover 证书各规划一份 staple（见 [`OcspPlan`] 的说明）。
fn plan_ocsp(ssl: &SslConfig) -> OcspPlan {
    // 真实证书：显式路径优先，否则自动获取（身份取 ocsp_identity，含 SAN 回退）。
    // 叶证书按**私钥**反查（链顺序错误也能找对）；全链 PEM 传给 issuer 查找。
    let real = if let Some(p) = ssl.ocsp_der_path.as_deref() {
        ocsp_static_from(p)
    } else {
        match (ssl.cert.as_deref(), ocsp_identity(ssl), load_leaf_for_ssl(ssl)) {
            (Some(c), Some(h), Some(leaf)) => match ssl_material::load_bytes(c) {
                Ok(pem) => ocsp_auto_slot(&h, &leaf, &pem),
                Err(_) => None,
            },
            _ => None,
        }
    };

    // cover 证书：只在配了 cover 时规划。
    let cover = if let (Some(cover_cert), Some(public_name)) = (
        ssl.ech_cover_cert.as_deref(),
        ssl.ech_public_name.as_deref(),
    ) {
        if let Some(p) = ssl.ech_cover_ocsp_der_path.as_deref() {
            ocsp_static_from(p)
        } else {
            // 自动探测用 **public_name**（cover 证书服务的就是这个名字）。
            // cover 也可以是 fullchain（旧实现只取第一张，链顺序错时叶就找错了）。
            let cover_leaf = ssl.ech_cover_key.as_deref().and_then(|k| {
                let key_pem = ssl_material::load_bytes(k).ok()?;
                let key = PKey::private_key_from_pem(&key_pem).ok()?;
                let chain_pem = ssl_material::load_bytes(cover_cert).ok()?;
                let (leaf, _) = split_chain(&chain_pem, &key).ok()?;
                Some((leaf, chain_pem))
            });
            let slot = cover_leaf.and_then(|(leaf, pem)| {
                ocsp_auto_slot(public_name.trim(), &leaf, &pem)
            });
            if slot.is_none() {
                log::info!(
                    "ocsp: cover 证书未配置且无法自动获取 staple ⇒ cover 路径不装订（不装订是安全的：客户端会自行查询 OCSP）"
                );
            }
            slot
        }
    } else {
        None
    };

    OcspPlan { real, cover }
}

fn apply_ocsp(builder: &mut SslAcceptorBuilder, ssl: &SslConfig, ocsp: &OcspPlan) -> Result<()> {
    // 配了 cover 时：装订在 **servername 回调**里按 ech_accepted 分派（见 load_identity）；
    // 这里只开启装订能力，**不**注册 select_certificate 装订（否则会先装上真实证书那份，
    // 而 cover 路径无从纠正 —— select_certificate 早于 servername 且只能注册一次）。
    if ssl.ech_cover_cert.is_some() {
        if ocsp.real.is_none() && ocsp.cover.is_none() {
            return Ok(());
        }
        builder.enable_ocsp_stapling();
        log::info!(
            "ocsp stapling: 按证书分派（real={} cover={}）",
            ocsp.real.is_some(),
            ocsp.cover.is_some()
        );
        return Ok(());
    }
    if let Some(path) = ssl.ocsp_der_path.as_deref() {
        return apply_ocsp_static(builder, path);
    }
    apply_ocsp_auto(builder, ssl)
}

/// 静态路径（`ssl.ocsp_der_path`）——历史行为，逐字节保持不变。
fn apply_ocsp_static(builder: &mut SslAcceptorBuilder, path: &str) -> Result<()> {
    let raw = match ssl_material::load_bytes(path) {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => {
            log::warn!("ssl.ocsp_der_path={path} 为空；OCSP stapling 关闭");
            return Ok(());
        }
        Err(e) => {
            log::warn!("ssl.ocsp_der_path={path} 不可读: {e:#}；OCSP stapling 关闭");
            return Ok(());
        }
    };
    let der = pem_to_der(&raw).unwrap_or(raw);
    // 与 `ocsp_static_from`（ECH 规划路径）同一判据：静态文件也必须过校验。
    // 这条路径是「未配 cover + ocsp_der_path」时真正安装 staple 的地方 —— 旧实现
    // 在这里不做任何内容校验，未知/撤销/过期/超大的 DER 会被原样装订（超大响应
    // 还会让 BoringSSL 编码 ServerHello 时 overflow，整条 TLS1.3 握手失败）。
    if let Err(why) = crate::server::ocsp_fetcher::validate_staple_der(&der) {
        log::warn!("ssl.ocsp_der_path={path} 不可装订（{why}）；OCSP stapling 关闭");
        return Ok(());
    }
    let der_len = der.len();
    builder.enable_ocsp_stapling();
    builder.set_select_certificate_callback(move |mut ch| {
        let _ = ch.ssl_mut().set_ocsp_status(&der);
        Ok(())
    });
    log::info!("ocsp stapling enabled ({} bytes from {path})", der_len);
    Ok(())
}

/// 自动获取路径（早期规格 1b）：`ocsp_der_path` 未配置时启用。
/// 叶子无 AIA / 链不完整 → 保持无装订，但**留日志**说明原因（旧实现全程静默，
/// 运维无法判断「为什么没装订」，tls-core P2）。
fn apply_ocsp_auto(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    let Some(cert_path) = ssl.cert.as_deref() else {
        log::info!("ocsp auto: 未配置 ssl.cert，跳过自动装订");
        return Ok(());
    };
    let Some(host) = ocsp_identity(ssl) else {
        log::info!(
            "ocsp auto: 未配置 ssl.sni_name / ssl.ech_public_name 且叶子证书无 DNS SAN，\
无法确定稳定身份 ⇒ 跳过自动装订（配任一即可启用，或显式设置 ssl.ocsp_der_path）"
        );
        return Ok(());
    };
    let cert_pem = match ssl_material::load_bytes(cert_path) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("ocsp auto: ssl.cert 不可读: {e:#}；OCSP stapling 关闭");
            return Ok(());
        }
    };
    let leaf = match load_leaf_for_ssl(ssl) {
        Some(x) => x,
        None => {
            log::warn!("ocsp auto: leaf 解析失败（证书/私钥不可读或链里没有匹配私钥的那张）；OCSP stapling 关闭");
            return Ok(());
        }
    };
    // 全链材料（叶 + 中间链）——issuer 查找与 caIssuers 兜底都用它。
    let Some(slot) = crate::server::ocsp_fetcher::prepare_stapling(&host, &leaf, &cert_pem) else {
        return Ok(());
    };
    builder.enable_ocsp_stapling();
    // 回调内只读槽内快照（纯内存）；网络刷新在后台线程，握手永不阻塞。
    builder.set_select_certificate_callback(move |mut ch| {
        if let Some(der) = slot.current() {
            let _ = ch.ssl_mut().set_ocsp_status(&der);
        }
        Ok(())
    });
    log::info!("ocsp stapling enabled (auto-fetch, host={host})");
    Ok(())
}

/// 极简 PEM→DER：剥 BEGIN/END 之间的 base64；非 PEM 原样返回（None）。
fn pem_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok()?;
    if !text.contains("-----BEGIN") {
        return None;
    }
    let start = text.find("-----BEGIN")?;
    let nl = text[start..].find('\n')? + start + 1;
    let end = text[nl..].find("-----END")? + nl;
    let body: String = text[nl..end].chars().filter(|c| !c.is_whitespace()).collect();
    b64_decode(&body)
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = val(bytes[i + 2])?;
        let d = val(bytes[i + 3])?;
        out.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((c << 6) | d);
        }
        i += 4;
    }
    Some(out)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        out.push((nib(b[i])? << 4) | nib(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// TLS-PSK server hook（§16.16）。
/// P1-10：材料来源优先级 ssl.psk_key（配置：hex / base64 / 文件路径）> env
/// CRUCIBLE_TLS_PSK（保留兼容）；配置 psk_identity 后严格匹配 identity。
/// H3/QUIC 侧 PSK 涉及 quinn-boring 内部，另行移交（见 REVIEW-MASTER 移交清单）。
fn apply_psk(builder: &mut SslAcceptorBuilder, ssl: &SslConfig, strict: bool) -> Result<()> {
    if !ssl.psk {
        return Ok(());
    }
    // BoringSSL 的 `SSL_CTX_set_psk_server_callback` **只**在 TLS 1.2 协商时被调用
    // （boringssl ssl.h：「called when TLS 1.2 PSK is negotiated on the server」），
    // 本库没有 TLS1.3 外部 PSK 的服务端 API。因此 psk=true 对 TLS1.3 连接**不生效**：
    // 如实告警，避免「配了 PSK 却在 1.3 上静默无用」（tls-core 移交的运行时验证项）。
    log::warn!(
        "ssl.psk=true：BoringSSL 的 PSK 服务端回调仅在 TLS1.2 协商时生效（本库不支持 TLS1.3 \
外部 PSK）；TLS1.3 客户端将走证书而非 PSK。要强制 PSK 请把 ssl.versions 钉到 TLSv1.2"
    );
    // 拒绝确定性占位 PSK（audit High）——材料必须真实配置。
    //
    // 材料错误（路径写错/hex 不合法/文件不可读）**不能** `?`：那会让 build_acceptor
    // 失败 ⇒ 整个监听口每条连接 soft-fail（PSK 只是可选特性，不该把证书 TLS 一起
    // 拖下水）。这里明确告警并**禁用 PSK**（端口继续按证书服务），语义是「显式关闭」
    // 而不是静默忽略。
    let secret: Vec<u8> = if let Some(k) = ssl.psk_key.as_deref() {
        match psk_material(k) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => {
                if strict {
                    anyhow::bail!("ssl.psk=true 但 ssl.psk_key 解析为空");
                }
                log::error!("ssl.psk=true 但 ssl.psk_key 解析为空；PSK 已禁用，端口继续按证书服务");
                return Ok(());
            }
            Err(e) => {
                if strict {
                    return Err(e.context("ssl.psk_key 不可用"));
                }
                log::error!("ssl.psk=true 但 ssl.psk_key 不可用（{e:#}）；PSK 已禁用，端口继续按证书服务");
                return Ok(());
            }
        }
    } else {
        match crate::server::apps::env_lock::read_static_env("CRUCIBLE_TLS_PSK") {
            Some(s) if !s.is_empty() => s.into_bytes(),
            _ => {
                log::warn!("ssl.psk=true 但未配置 ssl.psk_key / CRUCIBLE_TLS_PSK；不装 PSK 回调（PSK 禁用）");
                return Ok(());
            }
        }
    };
    let identity = ssl.psk_identity.clone();
    builder.set_psk_server_callback(move |_ssl, ident, psk| {
        // 配置了 identity 时严格匹配：任意 identity 都能换出同一 PSK 是弱语义。
        if let Some(want) = &identity {
            match ident {
                Some(got) if got.eq_ignore_ascii_case(want.as_bytes()) => {}
                _ => return Ok(0),
            }
        }
        if psk.is_empty() {
            return Ok(0);
        }
        let n = secret.len().min(psk.len());
        psk[..n].copy_from_slice(&secret[..n]);
        Ok(n)
    });
    Ok(())
}

/// P1-10：PSK 材料解析——含路径特征（/ 或 .）先按文件处理；否则偶长 hex >
/// base64 > 文件路径兜底。
fn psk_material(spec: &str) -> Result<Vec<u8>> {
    let s = spec.trim();
    if s.contains('/') || s.contains('.') {
        if let Ok(v) = ssl_material::load_bytes(s) {
            return Ok(v);
        }
    }
    if s.len() >= 2 && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Some(v) = hex_decode(s) {
            return Ok(v);
        }
    }
    if let Some(v) = b64_decode(s) {
        if !v.is_empty() {
            return Ok(v);
        }
    }
    ssl_material::load_bytes(s).map_err(|e| anyhow::anyhow!("ssl.psk_key: {e:#}"))
}

fn apply_alpn(builder: &mut SslAcceptorBuilder, lc: &ListenerConfig, allow_dot: bool) -> Result<()> {
    // 任务 2 实测发现（P1）：set_alpn_protos 是【客户端】API——服务端用它永远不会
    // 回应 ALPN，浏览器在 TLS 上全部回落 HTTP/1.1（h2 形同虚设）。服务端必须装
    // select 回调，并从客户端列表内回显所选协议（RFC 7301 要求回显原字节）。
    let offer_h2 = lc.allows_h2();
    let offer_h1 = lc.allows_h1();
    // QMux（`qmux = true`）走 h1-over-QMux，所以必须 h1 开着（配置校验已拦）。
    let offer_qmux = lc.qmux && offer_h1;
    builder.set_alpn_select_callback(move |_ssl, client_protos: &[u8]| {
        // wire 格式：u8 len + name，逐段扫描；记录 h2 / http/1.1 / qmux 的命中区间。
        let mut h2_span: Option<&[u8]> = None;
        let mut h1_span: Option<&[u8]> = None;
        let mut qmux_span: Option<&[u8]> = None;
        let mut dot_span: Option<&[u8]> = None;
        let mut i = 0usize;
        while i < client_protos.len() {
            let l = client_protos[i] as usize;
            let end = match i.checked_add(1 + l) {
                Some(e) if e <= client_protos.len() => e,
                _ => break,
            };
            let name = &client_protos[i + 1..end];
            match name {
                b"h2" if offer_h2 => h2_span = Some(name),
                b"http/1.1" if offer_h1 => h1_span = Some(name),
                // G-08：只有本 acceptor 明确为「DoT 端口复用」构建时才提供 dot；
                // 站点 acceptor（allow_dot=false）的 ALPN 行为逐字节不变。
                b"dot" if allow_dot => dot_span = Some(name),
                n if offer_qmux && n == crate::server::qmux::conn::QMUX_ALPN => {
                    qmux_span = Some(name)
                }
                _ => {}
            }
            i = end;
        }
        // 服务端偏好：DoT 连接必须拿到 dot（它接下来只说长度前缀的 DNS wire）；
        // 站点连接保持 h2 > http/1.1 > QMux 的历史偏好不变。
        dot_span
            .or(h2_span)
            .or(h1_span)
            .or(qmux_span)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    Ok(())
}

// P2-4：按（listener + SslConfig 全字段指纹）缓存 SslAcceptor——旧实现每连接重新
// load PEM/解析双证/装 ECH keys，session ticket 复用全部失效。缓存上限 64，超限清空。
// 注意：PSK 若经环境变量注入，env 变化不会反映到指纹（配置 ssl.psk_key 即可热生效）。
static ACCEPTOR_CACHE: Lazy<Mutex<HashMap<u64, Arc<SslAcceptor>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// acceptor 缓存条目上限。
///
/// 必须**大于等于**允许的 listener 数（`admin_config_edit::MAX_LISTENERS = 128`）：
/// 指纹里含 `lc.port`，每个 listener 至少占一项；以前是 64 < 128，一旦配置里的
/// ssl listener 超过 64 个（或 ssl 参数组合多），满上限就**整表清空** ⇒ 命中率跌到 0，
/// 每次握手都重新读 PEM/解析链/装 ECH 密钥（纯性能悬崖，不是正确性问题）。
/// 取 256 = 128 listener × 2（同一 listener 在 h1/h2 两种 ALPN 组合下各一项）+ 余量。
pub const ACCEPTOR_CACHE_CAP: usize = 256;

/// 清空 acceptor 缓存。
///
/// 指纹只覆盖配置字符串，缓存又永不失效，因此「同一路径上换证书」这类
/// 内容变化（certbot 续期、面板覆盖 ssl.cert / ssl.ech_keys）不会命中新指纹，
/// 进程会继续用旧证书直到重启。热路径（accept_and_serve 每连接查一次）不适合
/// 加 stat，所以在配置重载这个低频点显式清空——由 `LiveConfig::reload` 调用。
pub fn clear_acceptor_cache() {
    let mut map = ACCEPTOR_CACHE.lock();
    let n = map.len();
    map.clear();
    if n > 0 {
        log::info!("tls: acceptor cache cleared ({n} entries) — certificates/config re-read on next handshake");
    }
}

fn acceptor_fingerprint(
    ssl: &SslConfig,
    lc: &ListenerConfig,
    profile: VersionProfile,
    allow_dot: bool,
) -> u64 {
    let mut h = DefaultHasher::new();
    // G-12：同一个 listener 会同时存在 1.3-only 与 max=1.2 两套 acceptor，档位必须
    // 进指纹，否则其中一套会命中另一套（把「prefer」语义抹掉）。
    profile.hash(&mut h);
    // G-08：同一个 listener 的站点 acceptor（不提供 dot）与复用 acceptor（提供 dot）
    // 必须分开缓存，否则 ALPN 行为会串。
    allow_dot.hash(&mut h);
    ssl.cert.hash(&mut h);
    ssl.key.hash(&mut h);
    ssl.cert_ec.hash(&mut h);
    ssl.key_ec.hash(&mut h);
    ssl.versions.hash(&mut h);
    ssl.ciphers.hash(&mut h);
    ssl.prefer_tls13.hash(&mut h);
    ssl.ech.hash(&mut h);
    ssl.ech_keys.hash(&mut h);
    // cover-EC（外层备用 EC 证书）**必须进指纹**：路径不变、内容原地轮换时，
    // 只哈希其它字段会让指纹不变 ⇒ 命中旧 acceptor ⇒ 继续出示**旧的外层 EC 证书**
    // 直到 reload/重启。这是「材料 mtime/size 进指纹」那次修复漏掉的一个字段。
    ssl.ech_cover_cert.hash(&mut h);
    ssl.ech_cover_key.hash(&mut h);
    ssl.ech_cover_cert_ec.hash(&mut h);
    ssl.ech_cover_key_ec.hash(&mut h);
    ssl.psk.hash(&mut h);
    ssl.psk_identity.hash(&mut h);
    ssl.psk_key.hash(&mut h);
    ssl.ocsp_der_path.hash(&mut h);
    // 下面这些字段同样影响 acceptor 的**行为**（不只是材料文件）：
    // * early_data 决定是否 `SSL_CTX_set_early_data_enabled`；
    // * ECH 的 public_name / suite / max_name_length 决定自动生成的 ECHConfig；
    // * ech_advertise 决定是否把 ech_keys 派生出的 config 落盘发布；
    // * ech_cover_ocsp_der_path 决定 cover 路径装不装订。
    // 漏进指纹时，`LiveConfig::replace`（局部热更）若只在内存改这些字段而不清缓存，
    // 会让进程继续用旧语义服务到重启。全部编进指纹是最省心的正确做法。
    ssl.early_data.hash(&mut h);
    ssl.ech_public_name.hash(&mut h);
    ssl.ech_cipher_suite.hash(&mut h);
    ssl.ech_max_name_length.hash(&mut h);
    ssl.ech_advertise.hash(&mut h);
    ssl.ech_cover_ocsp_der_path.hash(&mut h);
    ssl.sni_name.hash(&mut h);
    ssl.pqc.hash(&mut h);
    ssl.groups.hash(&mut h);
    lc.port.hash(&mut h);
    lc.allows_h1().hash(&mut h);
    lc.allows_h2().hash(&mut h);
    // **材料指纹（mtime + size）**：证书/密钥路径不变、内容被原地替换（certbot/acme.sh/
    // `dns.acme` 续期、运维手工覆盖）时，只哈希**路径字符串**会让指纹不变 ⇒ 命中旧
    // acceptor ⇒ 对继续出示**旧证书**（甚至已过期的）直到 config.toml 被 reload 或重启。
    // 哈希 mtime+size 让「文件被换掉」这件事本身进指纹：mtime 由内核在写入/替换时更新，
    // 精确到纳秒（OpenBSD: st_mtim），两次续期落在同一纳秒的可能性可以忽略。
    //
    // 热路径不额外 stat：`build_acceptor_cached` 只在**握手路径**上（每连接一次），
    // 这里 stat 的是 4~8 个小文件（内核 denty 缓存），代价远小于一次 TLS 握手。
    for p in [
        &ssl.cert,
        &ssl.key,
        &ssl.cert_ec,
        &ssl.key_ec,
        &ssl.ech_keys,
        &ssl.ech_cover_cert,
        &ssl.ech_cover_key,
        &ssl.ech_cover_cert_ec,
        &ssl.ech_cover_key_ec,
        &ssl.ocsp_der_path,
    ] {
        if let Some(path) = p.as_deref() {
            if path.contains("-----BEGIN") {
                // 内联 PEM：内容本身就是配置的一部分，上面已经哈希过字段值。
                continue;
            }
            match std::fs::metadata(path) {
                Ok(m) => {
                    m.len().hash(&mut h);
                    if let Ok(t) = m.modified() {
                        if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                            d.as_nanos().hash(&mut h);
                        }
                    }
                }
                // 打不开的文件：把「打不开」也编进指纹，避免「文件先消失后出现」
                // 一直命中旧 acceptor（真正读不到时 build_acceptor 会自己报错）。
                Err(_) => 0u8.hash(&mut h),
            }
        }
    }
    h.finish()
}

/// 缓存版 acceptor 构建（accept 热路径用；build_acceptor 供首建/测试直连）。
pub(crate) fn build_acceptor_cached(
    ssl: &SslConfig,
    lc: &ListenerConfig,
    profile: VersionProfile,
    allow_dot: bool,
) -> Result<Arc<SslAcceptor>> {
    let fp = acceptor_fingerprint(ssl, lc, profile, allow_dot);
    if let Some(a) = ACCEPTOR_CACHE.lock().get(&fp) {
        return Ok(Arc::clone(a));
    }
    let a = Arc::new(build_acceptor_profile(ssl, lc, profile, allow_dot)?);
    let mut map = ACCEPTOR_CACHE.lock();
    if map.len() >= ACCEPTOR_CACHE_CAP {
        map.clear();
    }
    map.insert(fp, Arc::clone(&a));
    Ok(a)
}

pub async fn accept_and_serve(
    stream: TcpStream,
    peek: Vec<u8>,
    ssl: &SslConfig,
    lc: ListenerConfig,
    peer: SocketAddr,
    live: Arc<LiveConfig>,
) -> Result<()> {
    // Incomplete SSLv2 probes are routed here to avoid TomCrypt abort — soft-close.
    if !peek.is_empty() && peek[0] & 0x80 != 0 {
        // debug 而非 info：这是**匿名可触发**的廉价路径（发几个字节就命中），
        // info 级别等于给磁盘开一个「按连接数计费」的写入口（本机磁盘长期紧张）。
        log::debug!(
            "boringssl soft-drop non-TLS/incomplete SSLv2-framed peek peer={peer} len={}",
            peek.len()
        );
        drop(stream);
        return Ok(());
    }
    // G-12：prefer_tls13 的两套上下文按**这条连接的 ClientHello** 选择（与 legacy
    // 分流同一套 wire 探测）。prefer_tls13=false / 显式 versions 时恒为 Default，
    // 行为与修改前逐字节一致。
    let profile = pick_version_profile(ssl, &peek);
    if ssl.prefer_tls13 {
        // debug 而非 info：匿名客户端可按连接速率触发；这里只用于验证/排障
        // 「prefer_tls13 到底选了哪套 SSL_CTX」。
        log::debug!("tls prefer_tls13: peer={peer} profile={profile:?} peek={}", peek.len());
    }
    // G-08：这条 ClientHello 是否声明了 ALPN `dot`（且 SNI 通过 `[dns.dot].sni`
    // 白名单）。命中后仍在**同一个 TLS listener** 上完成握手，只是按 DoT 证书
    // （若配置）建立 acceptor，握手后交给 DNS handler —— HTTP 站点流量完全不走这里。
    if let Some(dc) = crate::server::tls::accept::dot_reuse_config(&live, &peek) {
        return accept_dot_reuse(stream, peek, ssl, lc, peer, live, dc, profile).await;
    }
    let acceptor = build_acceptor_cached(ssl, &lc, profile, false)?;
    let io = PrefixedStream::new(stream, peek);
    // 握手必须有**截止时间**。`tokio_boring::accept` 自己没有任何超时：一个匿名客户端
    // 只要发一个**完整合法**的 ClientHello、然后在握手中途停下（不回 Finished），
    // 这条连接的任务、fd 与缓冲就永久挂住 —— 前面 `peek_first_record` 的预算只覆盖
    // 「读第一个 record」，覆盖不到这里。这类「发一半就不动」是扫描器/慢速攻击的常规手法，
    // 所以握手阶段必须自己掐表。超时后直接丢弃连接（不握手、不占用后续资源）。
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio_boring::accept(&acceptor, io)).await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Err(anyhow::anyhow!("boringssl accept failed: {e:?}")),
        Err(_) => {
            log::debug!("tls 握手超时（{HANDSHAKE_TIMEOUT:?}）peer={peer}，丢弃连接");
            return Ok(());
        }
    };
    dispatch_alpn(tls, live, lc, peer).await
}

/// G-08：在站点 TLS listener 上服务一条 DoT 连接（ALPN `dot` / SNI 白名单已由
/// [`crate::server::tls::accept::dot_reuse_config`] 判定）。
///
/// 证书策略：
/// * `[dns.dot] cert/key` **已配置** ⇒ 用 DoT 专用 acceptor（站点证书与 DoT 证书可
///   完全不同，DoT 客户端按自己的 SNI 校验）；构建失败（cert 缺失/ACME 未签发）
///   时 fail-closed 丢弃并节流告警，绝不拿站点证书冒充。
/// * 未配置 ⇒ 复用站点 acceptor（只把 `dot` 加进 ALPN 列表），证书仍是站点证书。
///
/// 握手完成后仍以**协商出的 ALPN** 为准：只有真的选中 `dot` 才进入 DNS 帧循环；
/// 站点 acceptor 分支里客户端若把 h2/http1.1 也给了且 dot 未被选中，则落回 HTTP。
#[cfg(feature = "tls_boring")]
// 参数由调用面决定，拆结构体会改变调用签名（本波只清 warning，不重构）。
#[allow(clippy::too_many_arguments)]
async fn accept_dot_reuse(
    stream: TcpStream,
    peek: Vec<u8>,
    ssl: &SslConfig,
    lc: ListenerConfig,
    peer: SocketAddr,
    live: Arc<LiveConfig>,
    dc: Arc<crate::server::dns::DnsConfig>,
    profile: VersionProfile,
) -> Result<()> {
    let io = PrefixedStream::new(stream, peek);
    let has_dot_cert = dc.dot.cert.is_some() && dc.dot.key.is_some();
    let (tls, dot_only_acceptor) = if has_dot_cert {
        let acceptor = match crate::server::dns::dot_doh::reuse_acceptor(&dc.dot) {
            Ok(a) => a,
            Err(e) => {
                // 匿名客户端可触发（每个 dot 连接一次）⇒ 按类别节流；证书就绪后自动恢复。
                crate::server::log_throttle::warn_every(
                    "dot-reuse-cert",
                    std::time::Duration::from_secs(60),
                    &format!(
                        "dot reuse: [dns.dot] 证书不可用，DoT 连接被拒（站点 TLS 不受影响）：{e:#}"
                    ),
                );
                return Ok(());
            }
        };
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio_boring::accept(&acceptor, io)).await {
            Ok(Ok(t)) => (t, true),
            Ok(Err(e)) => {
                log::debug!("dot reuse: DoT acceptor 握手失败 peer={peer}: {e:?}");
                return Ok(());
            }
            Err(_) => {
                log::debug!("dot reuse: 握手超时（{HANDSHAKE_TIMEOUT:?}）peer={peer}");
                return Ok(());
            }
        }
    } else {
        let acceptor = build_acceptor_cached(ssl, &lc, profile, true)?;
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio_boring::accept(&acceptor, io)).await {
            Ok(Ok(t)) => (t, false),
            Ok(Err(e)) => return Err(anyhow::anyhow!("boringssl accept failed: {e:?}")),
            Err(_) => {
                log::debug!("dot reuse: 握手超时（{HANDSHAKE_TIMEOUT:?}）peer={peer}");
                return Ok(());
            }
        }
    };
    let alpn = tls.ssl().selected_alpn_protocol().map(|p| p.to_vec());
    if alpn.as_deref() == Some(b"dot") {
        log::info!("dot: reuse handshake ok from {peer} (TLS listener :{})", lc.port);
        return crate::server::dns::dot_doh::serve_reused_tls(tls, peer, live).await;
    }
    if dot_only_acceptor {
        // DoT acceptor 的 ALPN 列表只有 dot：没选中说明客户端其实没给（或给了畸形值），
        // 不能把 DNS 帧循环套在一条 HTTP 意图的连接上。
        log::debug!("dot reuse: 未协商出 dot，丢弃 peer={peer}");
        drop(tls);
        return Ok(());
    }
    // 站点 acceptor 分支：dot 优先级最高，走到这里说明这条连接没有可用的 dot；
    // 按正常 HTTP 分发（与未开启 reuse 时一致）。
    log::debug!("dot reuse: ALPN={alpn:?} 非 dot，按站点 HTTP 处理 peer={peer}");
    dispatch_alpn(tls, live, lc, peer).await
}

/// TLS 握手的总预算。
///
/// 取值依据：真实客户端（含最慢的移动网络 + 后量子混合组）握手都在 1s 内完成；
/// 30s 与 h1 的 header_read_timeout 同量级，足以覆盖极端情况而不会让「发一半就不动」
/// 的连接长期占用资源。**只**约束握手，不约束握手之后的请求（那是各自的读超时管）。
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn dispatch_alpn(
    tls: SslStream<PrefixedStream>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    let alpn = tls.ssl().selected_alpn_protocol().map(|p| p.to_vec());
    if alpn.as_deref() == Some(crate::server::qmux::conn::QMUX_ALPN) && lc.qmux {
        // QMux v1：在其逻辑流上跑 HTTP/1.1（每条流一个 h1 会话）
        crate::server::qmux::serve_h1(tls, live, lc, peer).await
    } else if alpn.as_deref() == Some(b"h2") && lc.allows_h2() {
        h2::serve_tls(tls, live, lc, peer).await
    } else if lc.allows_h1() {
        h1::serve_tls(tls, live, lc, peer).await
    } else {
        // 规格 §16：「未启用版本不监听对应 ALPN」。旧实现这里**无条件**回落 h1，
        // 于是 `http_versions=["h2"]` 的口上，客户端只给 http/1.1（或不发 ALPN）时
        // 仍会被服务 HTTP/1.1 —— 未启用版本被实际监听。协商不出已启用协议即丢弃。
        log::debug!(
            "ALPN 未协商出已启用协议（http_versions 未含 h1，且客户端未选 h2/qmux），丢弃连接 peer={peer}"
        );
        drop(tls);
        Ok(())
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    /// 证书文件被**原地替换**（路径不变）时，指纹必须变化。
    ///
    /// 旧实现只哈希**路径字符串**：certbot/acme.sh/`dns.acme` 续期、运维手工覆盖
    /// `ssl.cert` 之后指纹不变 ⇒ 命中旧 acceptor ⇒ 端口继续出示旧（甚至已过期的）
    /// 证书，直到 config.toml 被 reload 或进程重启。
    #[test]
    fn fingerprint_follows_material_changes() {
        let dir = std::env::temp_dir().join(format!("crucible-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, b"first").expect("write");
        std::fs::write(&key, b"key").expect("write");
        let ssl = crate::config::SslConfig {
            cert: Some(cert.display().to_string()),
            key: Some(key.display().to_string()),
            ..Default::default()
        };
        let lc = crate::config::ListenerConfig::default();

        let fp1 = acceptor_fingerprint(&ssl, &lc, VersionProfile::Default, false);
        assert_eq!(
            fp1,
            acceptor_fingerprint(&ssl, &lc, VersionProfile::Default, false),
            "同样的材料必须得到同样的指纹（否则缓存永不命中）"
        );

        // ① 长度不同的替换
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&cert, b"second-cert-content").expect("rewrite");
        let fp2 = acceptor_fingerprint(&ssl, &lc, VersionProfile::Default, false);
        assert_ne!(fp1, fp2, "证书被替换后指纹必须变化（否则继续用旧证书）");

        // ② **同样长度**、不同内容（只把 size 编进指纹的实现会在这条上漏掉）
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&cert, b"THIRD-cert-content!").expect("rewrite2");
        let fp3 = acceptor_fingerprint(&ssl, &lc, VersionProfile::Default, false);
        assert_ne!(fp2, fp3, "等长替换也必须改变指纹（要靠 mtime）");

        // ③ 与内容无关的字段变化同样要影响指纹
        let mut ssl2 = ssl.clone();
        ssl2.prefer_tls13 = true;
        assert_ne!(fp3, acceptor_fingerprint(&ssl2, &lc, VersionProfile::Default, false), "配置字段变化必须影响指纹");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
