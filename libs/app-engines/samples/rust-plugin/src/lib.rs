use std::os::raw::{c_char, c_int};
use std::ptr;

#[repr(C)]
pub struct AppEngineResult {
    pub status: c_int,
    pub headers: *mut c_char,
    pub headers_len: usize,
    pub body: *mut u8,
    pub body_len: usize,
    pub error: *mut c_char,
}

#[no_mangle]
pub unsafe extern "C" fn appengine_init(
    _engine: *const c_char,
    _lib_hint: *const c_char,
) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn appengine_execute(
    _script: *const c_char,
    _docroot: *const c_char,
    _method: *const c_char,
    _path: *const c_char,
    _query: *const c_char,
    _content_type: *const c_char,
    _body: *const u8,
    _body_len: usize,
    _remote: *const c_char,
    _server_name: *const c_char,
    _server_port: c_int,
    extra: *const c_char,
    out: *mut AppEngineResult,
) -> c_int {
    // P1-1：extra JSON {"engine":...,"env":{...}} → 注入进程环境（APP_HELLO 等）；
    // legacy 非 JSON 输入（纯引擎名）解析失败即忽略。样例用手写极简解析，
    // 生产插件建议 serde_json。edition 2021 下 set_var 是安全 API。
    if !extra.is_null() {
        let raw = std::ffi::CStr::from_ptr(extra).to_string_lossy().into_owned();
        if let Some(pos) = raw.find("\"env\"") {
            if let Some(open) = raw[pos..].find('{') {
                for pair in raw[pos + open + 1..].split(',') {
                    let pair = pair.trim().trim_end_matches('}');
                    let mut it = pair.splitn(2, ':');
                    let (Some(k), Some(v)) = (it.next(), it.next()) else {
                        continue;
                    };
                    let clean = |s: &str| {
                        s.trim()
                            .trim_matches('"')
                            .replace("\\\"", "\"")
                            .replace("\\\\", "\\")
                    };
                    let k = clean(k);
                    let v = clean(v);
                    if !k.is_empty() {
                        std::env::set_var(&k, &v);
                    }
                }
            }
        }
    }
    let msg: Vec<u8> = match std::env::var("APP_HELLO") {
        Ok(v) if !v.is_empty() => {
            let path = std::ffi::CStr::from_ptr(_path).to_string_lossy();
            format!("{v} path={path}\n").into_bytes()
        }
        _ => b"hello from rust-plugin\n".to_vec(),
    };
    let buf = libc_malloc(msg.len());
    if buf.is_null() {
        return -1;
    }
    ptr::copy_nonoverlapping(msg.as_ptr(), buf, msg.len());
    (*out).status = 200;
    (*out).headers = ptr::null_mut();
    (*out).headers_len = 0;
    (*out).body = buf;
    (*out).body_len = msg.len();
    (*out).error = ptr::null_mut();
    0
}

#[no_mangle]
pub unsafe extern "C" fn appengine_result_free(out: *mut AppEngineResult) {
    if out.is_null() {
        return;
    }
    if !(*out).body.is_null() {
        libc_free((*out).body as *mut _);
    }
    if !(*out).headers.is_null() {
        libc_free((*out).headers as *mut _);
    }
    if !(*out).error.is_null() {
        libc_free((*out).error as *mut _);
    }
    ptr::write_bytes(out, 0, 1);
}

#[no_mangle]
pub unsafe extern "C" fn appengine_shutdown() {}

extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(p: *mut u8);
}

unsafe fn libc_malloc(n: usize) -> *mut u8 {
    malloc(n)
}
unsafe fn libc_free(p: *mut u8) {
    free(p)
}
