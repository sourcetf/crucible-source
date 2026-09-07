//! Native Rust sidecar / docroot entry for www-apps/rust.
//! When libapp_rust.so is unavailable, init.sh builds this as deps/bin/index
//! listening on WEBSERVER_LISTEN_UNIX.

use std::env;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

fn handle(mut stream: UnixStream) {
    let mut buf = [0u8; 4096];
    let _ = stream.read(&mut buf);
    let body = b"hello from rust www-app\n";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(body);
}

fn main() {
    let sock = env::var("WEBSERVER_LISTEN_UNIX").unwrap_or_else(|_| "/tmp/rust-app.sock".into());
    if Path::new(&sock).exists() {
        let _ = std::fs::remove_file(&sock);
    }
    let listener = UnixListener::bind(&sock).expect("bind unix");
    eprintln!("rust www-app listening on {}", sock);
    for conn in listener.incoming() {
        if let Ok(stream) = conn {
            handle(stream);
        }
    }
}
