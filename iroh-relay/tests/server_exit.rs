//! Bounded executable lifecycle checks using only native configuration and loopback.
#![cfg(feature = "server")]

use std::{
    fs::{self, File},
    io,
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
impl OwnedChild {
    fn terminate_and_reap(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.0.try_wait()? {
            return Ok(status);
        }
        // A successful native kill is followed by a native wait, never a polling
        // timeout that could silently relinquish an unreaped child.
        match self.0.kill() {
            Ok(()) => self.0.wait(),
            Err(kill_error) => match self.0.try_wait()? {
                // The child may have exited between try_wait and kill.
                Some(status) => Ok(status),
                None => Err(kill_error),
            },
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Err(error) = self.terminate_and_reap() {
            eprintln!("owned child PID {} kill/reap failed: {error}", self.0.id());
            // Preserve an existing assertion panic while making cleanup failure
            // explicit. Outside unwinding, cleanup failure itself fails the test.
            assert!(thread::panicking(), "owned child kill/reap failed: {error}");
        }
    }
}

#[cfg(unix)]
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "absolute probe deadline"))
}

#[cfg(unix)]
fn read_response(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(response),
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn write_request(stream: &mut TcpStream, deadline: Instant) -> io::Result<()> {
    let mut request = &b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"[..];
    while !request.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(request) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => request = &request[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
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
fn serving_relay(scratch: &Scratch, deadline: Instant) -> (OwnedChild, SocketAddr) {
    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr: SocketAddr = reserved.local_addr().unwrap();
    drop(reserved);
    let mut child = spawn_relay(
        scratch,
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
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &addr,
            remaining(deadline).unwrap().min(Duration::from_millis(100)),
        ) {
            write_request(&mut stream, deadline).unwrap();
            let response = read_response(&mut stream, deadline).unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"));
            assert!(String::from_utf8_lossy(&response).contains("iroh.computer"));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    (child, addr)
}

#[cfg(unix)]
#[test]
fn healthy_loopback_sigint_exits_successfully() {
    let deadline = Instant::now() + Duration::from_secs(15);
    let scratch = Scratch::new();
    let (mut child, addr) = serving_relay(&scratch, deadline);
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

#[cfg(unix)]
#[test]
fn progressing_response_cannot_extend_absolute_deadline() {
    let scenario_deadline = Instant::now() + Duration::from_secs(3);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut client =
        TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(1))
            .unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let read_deadline = Instant::now() + Duration::from_millis(75);
    let writer = thread::spawn(move || {
        let until = Instant::now() + Duration::from_millis(250);
        let mut count = 0;
        let mut last = Instant::now();
        while Instant::now() < until {
            server
                .set_write_timeout(Some(
                    until
                        .saturating_duration_since(Instant::now())
                        .max(Duration::from_millis(1)),
                ))
                .unwrap();
            if server.write_all(b"x").is_err() {
                break;
            }
            count += 1;
            last = Instant::now();
            thread::sleep(Duration::from_millis(10));
        }
        (count, last)
    });
    let result = read_response(&mut client, read_deadline);
    let returned = Instant::now();
    // Keep the client open until the bounded writer exits, proving it continued
    // supplying bytes after the read deadline rather than failing/disconnecting.
    let (count, last) = writer.join().expect("local writer joined");
    let error = result.expect_err("progress must not extend the absolute deadline");
    assert!(matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ));
    assert!(
        count > 1 && last > read_deadline,
        "response genuinely progressed past deadline"
    );
    assert!(
        returned < read_deadline + Duration::from_millis(100),
        "reader returned before writer completion"
    );
    assert!(
        Instant::now() < scenario_deadline,
        "whole progressing-response scenario deadline"
    );
}

#[cfg(unix)]
fn cleanup_failure_path(timeout: bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let scratch = Scratch::new();
    let (mut child, addr) = serving_relay(&scratch, deadline);
    let pid = child.0.id();
    let result = std::panic::catch_unwind(move || {
        if timeout {
            child.wait(Instant::now());
        } else {
            panic!("controlled assertion unwind after local serving");
        }
    });
    assert!(result.is_err(), "failure path was reached");
    drop(TcpListener::bind(addr).expect("failure cleanup released child listener"));
    // Signal zero checks only this owned PID; it neither kills nor selects by name.
    let mut absent = OwnedChild::spawn(Command::new("/bin/kill").arg("-0").arg(pid.to_string()));
    assert!(
        !absent.wait(deadline).success(),
        "owned child must be terminated and reaped"
    );
    assert!(
        Instant::now() < deadline,
        "whole cleanup failure scenario deadline"
    );
}

#[cfg(unix)]
#[test]
fn assertion_unwind_kills_and_reaps_owned_child() {
    cleanup_failure_path(false);
}

#[cfg(unix)]
#[test]
fn timeout_kills_and_reaps_owned_child() {
    cleanup_failure_path(true);
}
