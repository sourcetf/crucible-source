//! ECN（RFC 3168 / RFC 9000 §13.4）——UDP socket 级的 ECN 码点读写与解码。
//!
//! 提供三件事：
//! - 入向 ECN 可观测：`IP_RECVTOS`（IPv4）/ `IPV6_RECVTCLASS`（IPv6）——[`enable_recv_ecn`]；
//! - 出向 ECN 码点读写：`IP_TOS` / `IPV6_TCLASS`——[`set_outgoing_ecn`]、[`outgoing_ecn`]；
//! - TOS/tclass 字节 → [`EcnCodepoint`] 解码（走 [`parse_ecn`]）。
//!
//! # 能力边界（先读这段，结论和直觉相反）
//!
//! 已逐个核对 `Cargo.lock` 钉住的版本和 registry 里的源码。事实是：
//! **ECN 在本仓库根本不是「没实现」——quinn 已经完整跑着了，缺的只是公开 API。**
//!
//! 1. 传输层 ECN 是**开着**的：`quinn-proto-0.11.17/src/connection/paths.rs`
//!    把 `sending_ecn` 初始化成 `true`（第 73/122 行），`connection/mod.rs` 据此
//!    把每个出向包标成 `Ect0`（`ecn: if self.path.sending_ecn { ... }`，第 999 行），
//!    并实现了 ACK_ECN 校验与黑洞退避（`detect_ecn` / `process_ecn`，
//!    失败时置 `sending_ecn = false`，第 1530-1566 行）。
//! 2. socket 级选项 quinn-udp **自己就设了**：`quinn-udp-0.5.15/src/unix.rs`
//!    设 `IP_RECVTOS`（~119 行）与 `IPV6_RECVTCLASS`（~177 行）；
//!    出向用 `IP_TOS` / `IPV6_TCLASS` 的 per-packet cmsg（~608/612 行）；
//!    收向再把 cmsg 解回 `RecvMeta.ecn`（~713-721 行）。
//! 3. 真正缺的是**公开入口**：`quinn::TransportConfig` 没有 `enable_ecn`，
//!    `ConnectionStats` / `PathStats` 也没有 ECN 计数
//!    （`quinn-proto-0.11.17/src/connection/stats.rs` 全列过），
//!    所以「查这条连接的 ECN 状态/计数」和「关掉 ECN」都做不到。
//!
//! 所以本模块的定位是：**给不走 quinn 的 UDP socket 用，以及给 QUIC socket 做启动校验**
//! （见 `h3.rs::apply_quic_ecn`）。它不是「ECN 的实现」——实现（标记 + 校验）
//! 在 quinn 内部已经生效，本模块既不能增强它，也不该假装重新实现了它。
//!
//! ⚠️ **不要在 QUIC socket 上调用 [`set_outgoing_ecn`]**：quinn 决定发 Not-ECT 时
//! 的做法是「不加 cmsg」，此时 socket 级的 `IP_TOS` 就会生效——等于把 quinn 刚刚
//! 判定「这条路不能标 ECT」的黑洞退避又覆盖回去。这也是 [`enable_recv_ecn`] /
//! [`outgoing_ecn`] 在 h3 侧只读（或只重设入向选项）不写出向码点的原因。

use std::net::UdpSocket;

/// ECN 码点（RFC 3168 §5）。QUIC 只用到 ECT(0) / ECT(1) / CE。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    /// 0b00：非 ECN 能力端点。
    NotEct,
    /// 0b10：ECT(0)，QUIC 的推荐标记。
    Ect0,
    /// 0b01：ECT(1)，用于 L4S 等实验。
    Ect1,
    /// 0b11：CE，拥塞已发生。
    Ce,
}

impl EcnCodepoint {
    /// 从 TOS/tclass 字节解码。
    ///
    /// 解码本身交给 [`parse_ecn`]（返回 `(是否 ECT/CE, 是否 CE)`），
    /// ECT(0) 与 ECT(1) 用最低位区分——`parse_ecn` 把这两者归成同一类，
    /// 这正是它需要与位判断配合使用的原因。
    pub fn from_tos_byte(byte: u8) -> Self {
        match parse_ecn(byte) {
            (false, _) => Self::NotEct,
            (true, true) => Self::Ce,
            (true, false) => {
                if byte & 0x01 == 0 {
                    Self::Ect0
                } else {
                    Self::Ect1
                }
            }
        }
    }

    /// 编码为 TOS/tclass 字节：只保留 ECN 两位，DSCP 归零。
    pub fn tos_byte(self) -> u8 {
        match self {
            Self::NotEct => 0b00,
            Self::Ect1 => 0b01,
            Self::Ect0 => 0b10,
            Self::Ce => 0b11,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotEct => "not-ect",
            Self::Ect0 => "ect(0)",
            Self::Ect1 => "ect(1)",
            Self::Ce => "ce",
        }
    }
}

/// 解码 TOS/tclass 字节的低两位，返回 `(ect, ce)`。
///
/// - `(false, false)` → Not-ECT（0b00）
/// - `(true,  false)` → ECT(0) 或 ECT(1)（0b10 / 0b01）
/// - `(true,  true )` → CE（0b11）
///
/// 需要区分 ECT(0)/ECT(1) 时配合最低位使用，见 [`EcnCodepoint::from_tos_byte`]。
pub fn parse_ecn(tos_tclass: u8) -> (bool, bool) {
    let v = tos_tclass & 0x03;
    (v != 0, v == 0x03)
}

/// 支持 ECN socket 选项的平台实现。
///
/// 白名单而不是 `#[cfg(unix)]`：`IP_RECVTOS` / `IPV6_RECVTCLASS` 在 libc 里
/// 并非所有 unix 都有 —— 已逐个核对 `libc 0.2.189` 的常量定义位置：
///
/// - `netbsdlike`（OpenBSD / NetBSD）没有 `IP_RECVTOS`；
/// - DragonFly 与 FreeBSD 共用 `freebsdlike`，但 `IP_RECVTOS` 只定义在
///   `freebsdlike/freebsd/mod.rs` 里，DragonFly 拿不到。
///
/// 所以这里只列出已确认两个常量都存在的目标，其余走下面的 fallback。
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
))]
mod sys {
    use super::EcnCodepoint;
    use std::io;
    use std::net::UdpSocket;
    use std::os::fd::{AsRawFd, RawFd};

    /// 本平台有真实的 ECN socket 选项。
    pub const SUPPORTED: bool = true;

    fn setsockopt_int(
        fd: RawFd,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn getsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int) -> io::Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                &mut value as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(value)
        }
    }

    /// 让入向包的 ECN 码点可被读到。
    ///
    /// v4/v6 两个选项各自尽力而为：单栈 socket 上另一个族的选项会返回
    /// ENOPROTOOPT/EINVAL，那是正常的，不算失败；两个都失败才回报错误。
    pub fn enable_recv_ecn(socket: &UdpSocket) -> io::Result<()> {
        let fd = socket.as_raw_fd();
        let v4 = setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, 1);
        let v6 = setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, 1);
        match (v4, v6) {
            (Ok(()), _) => Ok(()),
            (Err(_), Ok(())) => Ok(()),
            (Err(e), Err(_)) => Err(e),
        }
    }

    /// 设置出向 ECN 码点（`IP_TOS` / `IPV6_TCLASS`）。同样两个族各自尽力而为。
    ///
    /// 当前树内**没有调用方**，这是刻意的：QUIC socket 上的出向标记由 quinn 逐包
    /// 用 cmsg 决定（`quinn-udp/src/unix.rs` ~608/612 行），在 socket 级再写一遍
    /// 会覆盖它的黑洞退避（见文件头的说明）。这个函数留给「自己拥有 UDP socket、
    /// 且没有 quinn 在管」的场景。
    #[allow(dead_code)]
    pub fn set_outgoing_ecn(socket: &UdpSocket, cp: EcnCodepoint) -> io::Result<()> {
        let fd = socket.as_raw_fd();
        let v = cp.tos_byte() as libc::c_int;
        let v4 = setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TOS, v);
        let v6 = setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, v);
        match (v4, v6) {
            (Ok(()), _) => Ok(()),
            (Err(_), Ok(())) => Ok(()),
            (Err(e), Err(_)) => Err(e),
        }
    }

    /// 回读当前出向 ECN 码点（先试 IPv4，再试 IPv6）。
    pub fn outgoing_ecn(socket: &UdpSocket) -> io::Result<EcnCodepoint> {
        let fd = socket.as_raw_fd();
        let v = match getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TOS) {
            Ok(v) => v,
            Err(_) => getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS)?,
        };
        Ok(EcnCodepoint::from_tos_byte(v as u8))
    }
}

/// 其余平台（Windows、OpenBSD/NetBSD、DragonFly 等）：
/// 这些选项不可用，全部 no-op / 明确报不支持。
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
)))]
mod sys {
    use super::EcnCodepoint;
    use std::io;
    use std::net::UdpSocket;

    /// 本平台没有可用的 ECN socket 选项。
    pub const SUPPORTED: bool = false;

    /// 无操作：没有可设的选项，也不该因此让监听起不来。
    pub fn enable_recv_ecn(_socket: &UdpSocket) -> io::Result<()> {
        Ok(())
    }

    /// 本平台没有可设的选项，如实报不支持（与上面 `sys` 的语义一致，
    /// 同样当前只在未来「自己拥有 UDP socket」的场景被调用）。
    #[allow(dead_code)]
    pub fn set_outgoing_ecn(_socket: &UdpSocket, _cp: EcnCodepoint) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ECN socket options (IP_TOS/IPV6_TCLASS) not available on this platform",
        ))
    }

    pub fn outgoing_ecn(_socket: &UdpSocket) -> io::Result<EcnCodepoint> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ECN socket options (IP_TOS/IPV6_TCLASS) not available on this platform",
        ))
    }
}

pub use sys::{enable_recv_ecn, outgoing_ecn, set_outgoing_ecn};

/// 本平台是否有真实的 ECN socket 支持（Windows 上为 false）。
pub fn platform_supported() -> bool {
    sys::SUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecn_codepoint_bits() {
        // 低两位 → 码点，四位组合一个不漏。
        assert_eq!(EcnCodepoint::from_tos_byte(0b0000_0000), EcnCodepoint::NotEct);
        assert_eq!(EcnCodepoint::from_tos_byte(0b0000_0001), EcnCodepoint::Ect1);
        assert_eq!(EcnCodepoint::from_tos_byte(0b0000_0010), EcnCodepoint::Ect0);
        assert_eq!(EcnCodepoint::from_tos_byte(0b0000_0011), EcnCodepoint::Ce);
        // DSCP 位不该影响判定。
        assert_eq!(EcnCodepoint::from_tos_byte(0b1011_1000), EcnCodepoint::NotEct);
        assert_eq!(EcnCodepoint::from_tos_byte(0b1011_1011), EcnCodepoint::Ce);
        for cp in [
            EcnCodepoint::NotEct,
            EcnCodepoint::Ect0,
            EcnCodepoint::Ect1,
            EcnCodepoint::Ce,
        ] {
            assert_eq!(EcnCodepoint::from_tos_byte(cp.tos_byte()), cp);
        }
        // parse_ecn 的三种输出形态。
        assert_eq!(parse_ecn(0b00), (false, false));
        assert_eq!(parse_ecn(0b10), (true, false));
        assert_eq!(parse_ecn(0b01), (true, false));
        assert_eq!(parse_ecn(0b11), (true, true));
    }
}
