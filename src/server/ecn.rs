//! ECN (RFC 3168/9000) — Linux-only setsockopt helpers.
#[cfg(target_os = "linux")]
pub mod linux {
    use std::os::fd::RawFd;
    pub unsafe fn enable_tcp_ecn(fd: RawFd) -> std::io::Result<()> {
        const TCP_ECN: libc::c_int = 18;
        let on: libc::c_int = 1;
        let rc = libc::setsockopt(
            fd, libc::IPPROTO_TCP, TCP_ECN,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        );
        if rc != 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }
}
#[cfg(not(target_os = "linux"))]
pub mod linux {
    use std::os::fd::RawFd;
    pub unsafe fn enable_tcp_ecn(_fd: RawFd) -> std::io::Result<()> { Ok(()) }
}

pub fn parse_ecn(tos_tclass: u8) -> (bool, bool) {
    let v = tos_tclass & 0x03;
    (v != 0, v == 0x03)
}
