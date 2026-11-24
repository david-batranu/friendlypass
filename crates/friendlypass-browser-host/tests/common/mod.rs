//! Test harness: spawn the real host binary with piped stdio and run a mock
//! app socket server. Shared by the WP1 fault tests.
//!
//! The mock socket path is derived by the host from `browser_server_path()`
//! (`$TMPDIR/org.keepassxc.KeePassXC.BrowserServer` on macOS,
//! `std::env::temp_dir()` elsewhere), so every test gets its own `TMPDIR`.
//! That directory is deliberately short and lives under the platform's short
//! temp root: macOS caps `sun_path` at 104 bytes and the default per-user
//! temp directory alone is ~52.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

pub const SOCKET_NAME: &str = "org.keepassxc.KeePassXC.BrowserServer";

/// The database hash the mock app reports for probes.
const PROBE_DB_HASH: &str = "4265c37dbe9ad073ac19837734d54fdd7d7c30bd87322ba886da62b147d66fbb";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A short, unique directory used as the host's `TMPDIR`.
pub struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    pub fn new() -> Self {
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            PathBuf::from("/tmp")
        };
        loop {
            let id = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = base.join(format!("fpwp1-{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("cannot create test temp dir {}: {e}", path.display()),
            }
        }
    }

    pub fn socket_path(&self) -> PathBuf {
        self.path.join(SOCKET_NAME)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A running host process with framed stdio.
pub struct Host {
    pub root: TempRoot,
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    frames: Receiver<Vec<u8>>,
    logs: Arc<Mutex<String>>,
}

impl Host {
    pub fn spawn(root: TempRoot) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_friendlypass-browser-host"))
            .env("TMPDIR", root.path())
            .env("TMP", root.path())
            .env("TEMP", root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn friendlypass-browser-host");

        let stdin = child.stdin.take().expect("host stdin");
        let stdout = child.stdout.take().expect("host stdout");
        let stderr = child.stderr.take().expect("host stderr");

        let (tx, frames) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = stdout;
            loop {
                let mut prefix = [0u8; 4];
                if stdout.read_exact(&mut prefix).is_err() {
                    break;
                }
                let len = u32::from_le_bytes(prefix) as usize;
                let mut payload = vec![0u8; len];
                if stdout.read_exact(&mut payload).is_err() {
                    break;
                }
                if tx.send(payload).is_err() {
                    break;
                }
            }
        });

        let logs = Arc::new(Mutex::new(String::new()));
        let logs_for_thread = Arc::clone(&logs);
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut guard = logs_for_thread.lock().unwrap_or_else(|e| e.into_inner());
                guard.push_str(&line);
                guard.push('\n');
            }
        });

        Self {
            root,
            child,
            stdin: Some(stdin),
            frames,
            logs,
        }
    }

    pub fn logs(&self) -> String {
        self.logs.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Write one native-messaging frame.
    pub fn send_payload(&mut self, payload: &[u8]) {
        self.send_bytes(&frame_bytes(payload));
    }

    /// Write raw bytes (used to exercise split frames).
    pub fn send_bytes(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("host stdin still open");
        stdin.write_all(bytes).expect("write to host stdin");
        stdin.flush().expect("flush host stdin");
    }

    pub fn send(&mut self, value: &Value) {
        self.send_payload(&serde_json::to_vec(value).expect("serialise test frame"));
    }

    /// Receive one frame payload.
    pub fn recv_payload(&self, timeout: Duration) -> Vec<u8> {
        match self.frames.recv_timeout(timeout) {
            Ok(payload) => payload,
            Err(_) => panic!(
                "host wrote no frame within {timeout:?}; stderr:\n{}",
                self.logs()
            ),
        }
    }

    pub fn recv(&self, timeout: Duration) -> Value {
        let payload = self.recv_payload(timeout);
        serde_json::from_slice(&payload).unwrap_or_else(|e| {
            panic!(
                "host frame is not JSON ({e}): {:?}; stderr:\n{}",
                String::from_utf8_lossy(&payload),
                self.logs()
            )
        })
    }

    pub fn recv_default(&self) -> Value {
        self.recv(Duration::from_secs(10))
    }

    pub fn ping(&mut self, nonce: &str) -> Value {
        self.send(&serde_json::json!({"action": "ping", "nonce": nonce}));
        self.recv(Duration::from_secs(5))
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Drop stdin (browser closed the port) and return the exit status.
    pub fn close_stdin_and_wait(&mut self, timeout: Duration) -> std::process::ExitStatus {
        self.stdin.take();
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait().expect("wait for host") {
                Some(status) => return status,
                None if Instant::now() >= deadline => {
                    panic!("host did not exit within {timeout:?}")
                }
                None => thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn frame_bytes(payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// A mock app server on the host's socket path.
///
/// The handler receives each raw request object and returns the raw response
/// objects to write. It runs on the connection thread, so a stateful `FnMut`
/// can batch requests. Requests are recorded for assertions.
pub struct MockApp {
    path: PathBuf,
    running: Arc<AtomicBool>,
    active: Arc<Mutex<Option<UnixStream>>>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MockApp {
    pub fn start<F>(path: &Path, mut handler: F) -> Self
    where
        F: FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).expect("bind mock app socket");
        listener
            .set_nonblocking(true)
            .expect("non-blocking mock listener");

        let running = Arc::new(AtomicBool::new(true));
        let active: Arc<Mutex<Option<UnixStream>>> = Arc::new(Mutex::new(None));
        let requests = Arc::new(Mutex::new(Vec::new()));

        let thread_running = Arc::clone(&running);
        let thread_active = Arc::clone(&active);
        let thread_requests = Arc::clone(&requests);
        let thread = thread::spawn(move || {
            while thread_running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                        *thread_active.lock().unwrap_or_else(|e| e.into_inner()) =
                            stream.try_clone().ok();
                        serve(&stream, &thread_running, &thread_requests, &mut handler);
                        *thread_active.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            path: path.to_path_buf(),
            running,
            active,
            requests,
            thread: Some(thread),
        }
    }

    /// Connect-and-reply helper that mirrors every request.
    pub fn start_echo(path: &Path) -> Self {
        Self::start(path, echo_handler())
    }

    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Send an unsolicited frame, as the app's push broadcast would.
    pub fn push(&self, value: &Value) {
        let payload = serde_json::to_vec(value).expect("serialise push");
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(stream) = guard.as_mut() {
            stream.write_all(&payload).expect("write push to host");
            stream.flush().expect("flush push to host");
        } else {
            panic!("no host connection to push to");
        }
    }
}

impl Drop for MockApp {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(stream) = self.active.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        // Wake the non-blocking accept loop, then let it observe `running`.
        let _ = UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn serve<F>(
    mut stream: &UnixStream,
    running: &AtomicBool,
    requests: &Mutex<Vec<Vec<u8>>>,
    handler: &mut F,
) where
    F: FnMut(&[u8]) -> Vec<Vec<u8>>,
{
    let mut framer = TestFramer::default();
    let mut buffer = [0u8; 8192];
    while running.load(Ordering::SeqCst) {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                framer.push(&buffer[..n]);
                while let Some(request) = framer.next() {
                    // The host's liveness probe is answered by the harness so
                    // tests only deal with their own requests.
                    let parsed: Value = serde_json::from_slice(&request).unwrap_or(Value::Null);
                    if parsed.get("action").and_then(Value::as_str) == Some("ping") {
                        let reply = serde_json::to_vec(&serde_json::json!({
                            "action": "ping",
                            "success": "true",
                            "appVersion": "0.1.0",
                            "locked": false,
                            "databaseHash": PROBE_DB_HASH,
                        }))
                        .expect("serialise mock probe reply");
                        if stream.write_all(&reply).is_err() {
                            return;
                        }
                        let _ = stream.flush();
                        continue;
                    }

                    requests
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(request.clone());
                    for reply in handler(&request) {
                        if stream.write_all(&reply).is_err() {
                            return;
                        }
                    }
                    let _ = stream.flush();
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Mirror each request's action and nonce, like a minimal app server. Host
/// probes are answered by [`serve`] itself.
pub fn echo_handler() -> impl FnMut(&[u8]) -> Vec<Vec<u8>> + Send + 'static {
    |raw: &[u8]| {
        let value: Value = serde_json::from_slice(raw).unwrap_or(Value::Null);
        let reply = serde_json::json!({
            "action": value.get("action").cloned().unwrap_or(Value::from("")),
            "message": "ciphertext",
            "nonce": value.get("nonce").cloned().unwrap_or(Value::Null),
        });
        vec![serde_json::to_vec(&reply).expect("serialise mock reply")]
    }
}

#[derive(Default)]
struct TestFramer {
    buffer: Vec<u8>,
}

impl TestFramer {
    fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    fn next(&mut self) -> Option<Vec<u8>> {
        let start = self.buffer.iter().position(|&b| b == b'{')?;
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escape = false;
        for (i, &b) in self.buffer.iter().enumerate().skip(start) {
            if escape {
                escape = false;
                continue;
            }
            match b {
                b'\\' if in_string => escape = true,
                b'"' => in_string = !in_string,
                b'{' if !in_string => depth += 1,
                b'}' if !in_string => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(self.buffer.drain(..=i).collect());
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// Poll `check` until it returns true or the deadline passes.
pub fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut check: F) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if check() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
}
