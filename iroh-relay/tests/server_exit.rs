//! Bounded executable lifecycle checks using only native configuration and loopback.
#![cfg(feature = "server")]

use std::{
    fs::{self, File},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
#[cfg(unix)]
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "iroh-relay-exit-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct OwnedChild(Child);
impl OwnedChild {
    fn spawn(command: &mut Command) -> Self {
        let guard = Self(command.spawn().expect("spawn owned child"));
        eprintln!("owned child PID {}", guard.0.id());
        guard
    }

    fn wait(&mut self, deadline: Instant) -> ExitStatus {
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "owned child deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // Kill only the child this guard spawned, including assertion/timeout paths.
            let _ = self.0.kill();
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.0.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn spawn_relay(scratch: &Scratch, config: &str) -> OwnedChild {
    let path = scratch.0.join("relay.toml");
    fs::write(&path, config).unwrap();
    let log = File::create(scratch.0.join("output.log")).unwrap();
    OwnedChild::spawn(
        Command::new(env!("CARGO_BIN_EXE_iroh-relay"))
            .arg("--config-path")
            .arg(path)
            .env_clear()
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log)),
    )
}

#[test]
fn no_services_exits_with_native_failure() {
    let deadline = Instant::now() + Duration::from_secs(15);
    let scratch = Scratch::new();
    let mut child = spawn_relay(
        &scratch,
        "enable_relay=false\nenable_quic_addr_discovery=false\nenable_metrics=false\n",
    );
    let status = child.wait(deadline);
    let output = fs::read_to_string(scratch.0.join("output.log")).unwrap();
    eprintln!("native no-services status={status}; output:\n{output}");
    assert!(
        output.contains("No relay services are enabled"),
        "native failure not reached: {output}"
    );
    assert!(!output.contains("JoinHandle polled after completion"));
    assert!(
        !status.success(),
        "supervisor failure must not become exit success"
    );
    assert!(Instant::now() < deadline, "whole process/output deadline");
}

#[cfg(unix)]
#[test]
fn healthy_loopback_sigint_exits_successfully() {
    let deadline = Instant::now() + Duration::from_secs(15);
    let scratch = Scratch::new();
    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr: SocketAddr = reserved.local_addr().unwrap();
    drop(reserved);
    let mut child = spawn_relay(
        &scratch,
        &format!(
            "enable_relay=true\nenable_quic_addr_discovery=false\nenable_metrics=false\nhttp_bind_addr=\"{addr}\"\n"
        ),
    );
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "relay exited before serving"
        );
        assert!(Instant::now() < deadline, "loopback startup deadline");
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            stream
                .set_read_timeout(Some(remaining.min(Duration::from_secs(1))))
                .unwrap();
            stream
                .set_write_timeout(Some(remaining.min(Duration::from_secs(1))))
                .unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.1 200"));
            assert!(response.contains("iroh.computer"));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let mut signal = OwnedChild::spawn(
        Command::new("/bin/kill")
            .arg("-INT")
            .arg(child.0.id().to_string()),
    );
    assert!(signal.wait(deadline).success());
    let status = child.wait(deadline);
    let output = fs::read_to_string(scratch.0.join("output.log")).unwrap();
    assert!(status.success(), "Ctrl-C exit={status}: {output}");
    drop(TcpListener::bind(addr).expect("owned process listener released"));
    assert!(
        Instant::now() < deadline,
        "whole process/probe/output deadline"
    );
}
