//! The real `kavach-api` process on SIGTERM: it stops accepting, drains,
//! says so, and exits 0. (The drain itself, with a call in flight, is
//! `gateway.rs`; this is the binary's wiring: the signal, every listener,
//! the exit status.)

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One raw `GET /health`: whether it answered 200.
fn healthy(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    reply.starts_with("HTTP/1.1 200")
}

#[test]
fn the_binary_drains_and_exits_zero_on_sigterm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (http, grpc) = (free_port(), free_port());
    let mut child = Command::new(env!("CARGO_BIN_EXE_kavach-api"))
        .args([
            "--insecure-dev",
            "--access-control",
            "none",
            "--pack",
            root.join("packs/finance/v0.yaml").to_str().unwrap(),
            "--model",
            root.join("models/finance/credit-underwriting-v1.yaml")
                .to_str()
                .unwrap(),
            "--listen",
            &format!("127.0.0.1:{http}"),
            "--grpc-listen",
            &format!("127.0.0.1:{grpc}"),
            "--shutdown-grace-seconds",
            "10",
        ])
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kavach-api starts");
    let addr: SocketAddr = format!("127.0.0.1:{http}").parse().unwrap();

    let up = Instant::now();
    while !healthy(addr) {
        assert!(
            child.try_wait().unwrap().is_none(),
            "kavach-api exited before it was ready"
        );
        assert!(up.elapsed() < Duration::from_secs(30), "never became ready");
        std::thread::sleep(Duration::from_millis(100));
    }

    let term = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(term.success());
    let stopping = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if stopping.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            panic!("kavach-api did not stop within 20 s of SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(0), "a clean stop exits 0: {status:?}");

    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(
        output.contains("shutting down: no new connections"),
        "{output}"
    );
    assert!(output.contains("shutdown complete"), "{output}");
    assert!(!healthy(addr), "nothing is listening after the stop");
}
