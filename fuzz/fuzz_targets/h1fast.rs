#![no_main]

//! `h1_fast` 请求解析 / 回退的属性 fuzz。
//!
//! 断言：
//! 1. 任意字节 → `scan_head` / `parse_request` / `connection_has` 不 panic、不越界；
//! 2. `scan_head` 的可判定不变量：`Complete(n)` ⇒ 以 `\r\n\r\n` 结尾且前 n 字节无裸 LF；
//!    `NotUnderstood` ⇒ 确实存在裸 LF；`NeedMore` ⇒ 既无结束符也无裸 LF；
//! 3. **回退不丢字节**：`ReplayIo` 读出 `prefix ++ inner` 逐字节相等；
//! 4. **对拍子集**：凡本模块接受（`Some`）的请求头，httparse（hyper 使用的解析器）
//!    必须也能解析，且 method / target / version 三个字段完全一致 —— 这条防的是
//!    「快车道放行了 hyper 会拒的形状」（走私/语义分叉）；
//! 5. 由输入合成的合法 GET/HEAD 请求必须被接受，且字段与构造值一致（覆盖接受路径）。

use crucible_fuzz::server::h1_fast as hf;
use libfuzzer_sys::fuzz_target;

fn bare_lf(buf: &[u8], end: usize) -> bool {
    (0..end).any(|i| buf[i] == b'\n' && (i == 0 || buf[i - 1] != b'\r'))
}

fn head_end(buf: &[u8]) -> Option<usize> {
    (0..buf.len().saturating_sub(3))
        .find(|&i| &buf[i..i + 4] == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn synth(data: &[u8]) -> (Vec<u8>, bool, bool, String) {
    let is_head = data.first().map_or(false, |b| b & 1 == 0);
    let http_10 = data.get(1).map_or(false, |b| b & 1 == 1);
    let mut target = String::from("/");
    for &b in data.iter().skip(2).take(40) {
        // 可见 ASCII（0x21..=0x7d），排除 `#`（fragment 不允许出现在 request-target）。
        let mut c = char::from(0x21 + (b % 0x5d));
        if c == '#' {
            c = 'x';
        }
        target.push(c);
    }
    let method = if is_head { "HEAD" } else { "GET" };
    let version = if http_10 { "HTTP/1.0" } else { "HTTP/1.1" };
    let conn = match data.get(42).copied().unwrap_or(0) % 4 {
        0 => "",
        1 => "Connection: keep-alive\r\n",
        2 => "Connection: close\r\n",
        _ => "Connection: CLOSE\r\n",
    };
    let raw = format!("{method} {target} {version}\r\nHost: h\r\n{conn}\r\n");
    (raw.into_bytes(), is_head, http_10, target)
}

fuzz_target!(|data: &[u8]| {
    // ── 1/2：任意字节下的不变量 ──
    let (kind, n) = hf::fuzz_scan(data, 0);
    match kind {
        1 => {
            assert!(n >= 4 && n <= data.len(), "Complete(n) 越界: n={n} len={}", data.len());
            assert_eq!(&data[n - 4..n], b"\r\n\r\n", "Complete(n) 未以 CRLFCRLF 结尾");
            assert!(!bare_lf(data, n), "Complete(n) 区段内出现裸 LF");
        }
        2 => {
            assert!(bare_lf(data, data.len()), "NotUnderstood 但没有裸 LF");
        }
        _ => {
            assert!(head_end(data).is_none(), "NeedMore 但存在 CRLFCRLF");
            assert!(!bare_lf(data, data.len()), "NeedMore 但存在裸 LF");
        }
    }

    // ── 1/4：任意字节解析 + httparse 对拍 ──
    if let Some(r) = hf::fuzz_parse(data) {
        assert!(r.target.starts_with('/'), "target 不是 origin-form: {:?}", r.target);
        assert!(r.target.starts_with(&r.path), "path 不是 target 的前缀");
        assert!(!r.target.contains('#'), "target 含 #");
        assert!(
            r.target.bytes().all(|b| b >= 0x21 && b != 0x7f),
            "target 含不可见字节"
        );
        if !r.http_10 {
            assert!(r.host.is_some(), "HTTP/1.1 无 Host 却接受");
        }
        if let Some(end) = head_end(data) {
            let mut headers = [httparse::EMPTY_HEADER; 100];
            let mut hr = httparse::Request::new(&mut headers);
            match hr.parse(&data[..end]) {
                Ok(httparse::Status::Complete(_)) => {
                    assert_eq!(
                        hr.method.unwrap(),
                        if r.is_head { "HEAD" } else { "GET" },
                        "method 与 httparse 不一致"
                    );
                    assert_eq!(hr.path.unwrap(), r.target, "target 与 httparse 不一致");
                    assert_eq!(
                        hr.version.unwrap(),
                        if r.http_10 { 0 } else { 1 },
                        "version 与 httparse 不一致"
                    );
                }
                _ => panic!(
                    "快车道接受了 httparse 拒绝的请求头（形状分叉/走私风险）: {:?}",
                    String::from_utf8_lossy(data)
                ),
            }
        }
    }

    // ── 3：回退字节保真 ──
    let mid = data.len() / 2;
    assert_eq!(
        hf::fuzz_replay(&data[..mid], &data[mid..]),
        data,
        "ReplayIo 丢/重排字节"
    );

    // ── 5：合成合法请求必须被接受 ──
    let (raw, is_head, http_10, target) = synth(data);
    let r = hf::fuzz_parse(&raw).expect("合成合法请求必须被接受");
    assert_eq!(r.is_head, is_head);
    assert_eq!(r.http_10, http_10);
    assert_eq!(r.target, target);
    assert_eq!(r.host.as_deref(), Some("h"));
    // Connection 语义（复刻 hyper 的逐行赋值，见 `parse_request`）：
    // 1.1 默认保持，仅显式 `Connection: close` 关闭；1.0 默认关闭，仅显式
    // `Connection: keep-alive` 保持（实测 hyper 对 1.0+KA 复用连接）。
    let close = raw
        .windows(17)
        .any(|w| w.eq_ignore_ascii_case(b"connection: close"));
    let ka = raw
        .windows(22)
        .any(|w| w.eq_ignore_ascii_case(b"connection: keep-alive"));
    let expected_keep_alive = if http_10 { ka } else { !close };
    assert_eq!(r.keep_alive, expected_keep_alive);

    // 任意值上的 connection_has 不 panic（且与大小写无关）。
    let _ = hf::fuzz_connection_has(data, b"close");
    let _ = hf::fuzz_connection_has(data, b"keep-alive");
});
