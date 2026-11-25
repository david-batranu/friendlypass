//! The BrowserServer socket: listens where KeePassXC's `BrowserHost` does
//! (`<user temp dir>/org.keepassxc.KeePassXC.BrowserServer` on macOS), so the
//! shipped `keepassxc-proxy` — and through it the real browser extension —
//! can talk to this server. The socket carries raw compact JSON (one object
//! per message, coalesced objects handled like the C++ parser).
//!
//! Each connection has one reader loop and one worker thread that share a
//! single writer, so frames never interleave. The reader answers host-level
//! `ping` immediately — liveness must never wait for an action the worker is
//! still processing (pairing contract §1). Every other request is handed to
//! the worker in arrival order; it owns the connection's [`ClientSession`].
//! Unsolicited pushes from the GUI arrive through a bounded channel and are
//! written by the reader, so a slow browser can never stall the application.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::protocol::{
    get_str, host_error_reply, ACTION_PING, HOST_ERROR_FRAME_TOO_LARGE,
    HOST_ERROR_MALFORMED_FRAME, PROTOCOL_VERSION,
};
use crate::push::PushHub;
use crate::service::{lock_state, ClientSession, SharedState};

/// Maximum frame size in both directions (`BrowserShared::SOCKET_BUFFER_SIZE`,
/// also the friendlypass 1 MiB contract).
pub const MAX_FRAME: usize = 1024 * 1024;

/// How often a connection checks for queued push messages.
const PUSH_POLL: Duration = Duration::from_millis(200);

/// The KeePassXC BrowserServer socket path (macOS form, like BrowserShared).
///
/// `FP_APP_SOCKET` overrides the path for tests and for a relocated app. The
/// native host derives its app link from this same function, so setting the
/// variable is sufficient to keep both ends of the app socket in sync and
/// guarantees tests never touch the user's real socket.
pub fn browser_server_path() -> PathBuf {
    if let Some(path) = std::env::var_os("FP_APP_SOCKET") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    let temp = user_temp_dir();
    temp.join("org.keepassxc.KeePassXC.BrowserServer")
}

/// The per-user temporary directory, matching the C++ `getUserTemporaryDirectory`
/// (confstr(_CS_DARWIN_USER_TEMP_DIR) on macOS).
pub fn user_temp_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // confstr(_CS_DARWIN_USER_TEMP_DIR) == $TMPDIR on macOS.
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let mut p = PathBuf::from(tmpdir);
            if p.ends_with("/") && p.as_os_str().len() > 1 {
                p.pop();
            }
            return p;
        }
    }
    std::env::temp_dir()
}

/// A running browser-protocol server.
pub struct ServerHandle {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    push: Arc<PushHub>,
}

impl ServerHandle {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Broadcast one unencrypted push frame to every connected client.
    pub fn broadcast(&self, frame: &Value) {
        self.push.broadcast(frame);
    }

    /// The push hub, for the GUI's lock/unlock/changed notifications.
    pub fn push_hub(&self) -> Arc<PushHub> {
        Arc::clone(&self.push)
    }

    pub fn client_count(&self) -> usize {
        self.push.client_count()
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking `accept` so the listener thread can observe stop.
        if let Ok(stream) = UnixStream::connect(&self.path) {
            drop(stream);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Start serving the browser protocol on `path`.
///
/// A live server at `path` is never stolen: if another process answers the
/// socket the call fails. A stale socket file is replaced.
pub fn start(path: &std::path::Path, state: SharedState) -> Result<ServerHandle> {
    if UnixStream::connect(path).is_ok() {
        bail!(
            "a browser protocol server is already listening on {}",
            path.display()
        );
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("cannot bind browser server socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    let push = {
        let guard = lock_state(&state);
        Arc::clone(&guard.push)
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let path_owned = path.to_path_buf();
    let push_thread = Arc::clone(&push);

    let thread = std::thread::Builder::new()
        .name("friendlypass-browser".into())
        .spawn(move || {
            for stream in listener.incoming() {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { break };
                let state = Arc::clone(&state);
                let hub = Arc::clone(&push_thread);
                let conn_stop = Arc::clone(&stop_thread);
                let _ = std::thread::Builder::new()
                    .name("friendlypass-browser-conn".into())
                    .spawn(move || handle_connection(stream, &state, &hub, &conn_stop));
            }
            let _ = std::fs::remove_file(&path_owned);
        })
        .context("cannot start browser server thread")?;

    Ok(ServerHandle {
        path: path.to_path_buf(),
        stop,
        thread: Some(thread),
        push,
    })
}

fn handle_connection(
    mut stream: UnixStream,
    state: &SharedState,
    hub: &Arc<PushHub>,
    stop: &Arc<AtomicBool>,
) {
    let Ok(write_stream) = stream.try_clone() else {
        return;
    };
    let _ = stream.set_read_timeout(Some(PUSH_POLL));
    // A peer that stops reading must not wedge a connection thread forever.
    let _ = write_stream.set_write_timeout(Some(Duration::from_secs(5)));
    // Reader, worker and pushes all write through this one handle. Holding the
    // mutex for a whole frame keeps objects from interleaving on the wire.
    let writer = Arc::new(Mutex::new(write_stream));
    let (client_id, pushes) = hub.register();

    // Requests other than `ping` are processed in order by one worker so the
    // reader stays free to answer liveness probes and deliver pushes.
    let (requests, incoming) = mpsc::channel::<Value>();
    let worker_state = Arc::clone(state);
    let worker_writer = Arc::clone(&writer);
    let worker_stop = Arc::clone(stop);
    let worker = std::thread::Builder::new()
        .name("friendlypass-browser-worker".into())
        .spawn(move || {
            // The per-connection protocol state belongs to the worker: only it
            // touches `ClientSession`, so reader-side pings cannot race it.
            let mut session = ClientSession::new();
            while let Ok(request) = incoming.recv() {
                if worker_stop.load(Ordering::SeqCst) {
                    break;
                }
                let response = session.handle(&worker_state, &request);
                if write_frame(&worker_writer, &response).is_err() {
                    break;
                }
            }
        });
    if worker.is_err() {
        hub.unregister(client_id);
        return;
    }
    // The handle is deliberately dropped (detached): a worker blocked in an
    // approval must not keep a closing connection or the process alive. It
    // exits on the closed channel or the next failed write.

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        // Deliver queued unsolicited frames between reads. A write failure
        // means the peer is gone; drop the registration and exit.
        while let Some(frame) = pushes.try_recv() {
            if write_frame(&writer, &frame).is_err() {
                hub.unregister(client_id);
                return;
            }
        }

        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if !drain_frames(&writer, state, &requests, &mut buffer) {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(_) => break,
        }
    }
    hub.unregister(client_id);
    // Dropping `requests` closes the worker's channel; it exits as soon as
    // any in-flight request returns.
}

/// Handle every complete frame in `buffer`. Returns false when the connection
/// should close.
fn drain_frames(
    writer: &Arc<Mutex<UnixStream>>,
    state: &SharedState,
    requests: &Sender<Value>,
    buffer: &mut Vec<u8>,
) -> bool {
    while let Some(end) = find_json_end(buffer) {
        let raw: Vec<u8> = buffer.drain(..end).collect();
        if raw.len() > MAX_FRAME {
            let reply = host_error_reply("", HOST_ERROR_FRAME_TOO_LARGE, "Message exceeds the 1 MiB frame limit");
            if write_frame(writer, &reply).is_err() {
                return false;
            }
            continue;
        }
        let Some(request) = parse_one(&raw) else {
            let reply = host_error_reply("", HOST_ERROR_MALFORMED_FRAME, "Malformed frame");
            if write_frame(writer, &reply).is_err() {
                return false;
            }
            continue;
        };
        // `ping` is answered here, on the reader, so it never queues behind a
        // slow action. It carries no session state, only the app's status.
        if get_str(&request, "action").as_deref() == Some(ACTION_PING) {
            let reply = ping_reply(state, &request);
            if write_frame(writer, &reply).is_err() {
                return false;
            }
            continue;
        }
        if requests.send(request).is_err() {
            return false;
        }
    }

    if buffer.len() > MAX_FRAME {
        // A frame larger than the cap that never closes: answer once and
        // discard what we have rather than growing without bound.
        let reply = host_error_reply("", HOST_ERROR_FRAME_TOO_LARGE, "Message exceeds the 1 MiB frame limit");
        if write_frame(writer, &reply).is_err() {
            return false;
        }
        buffer.clear();
    }
    true
}

/// The §5.2 shape for a host-level `ping`, built without a [`ClientSession`]
/// so the reader can answer it while the worker is busy. Mirrors
/// `ClientSession::handle_status`; `ping` needs no per-session fields.
fn ping_reply(state: &SharedState, request: &Value) -> Value {
    let (locked, hash, app_version) = {
        let guard = lock_state(state);
        (guard.locked, guard.db_hash.clone(), guard.app_version.clone())
    };
    let app_version = if app_version.is_empty() {
        env!("CARGO_PKG_VERSION").to_owned()
    } else {
        app_version
    };
    let mut response = serde_json::Map::new();
    response.insert("action".into(), json!(ACTION_PING));
    response.insert("success".into(), json!("true"));
    response.insert("protocolVersion".into(), json!(PROTOCOL_VERSION));
    response.insert("hostVersion".into(), json!(env!("CARGO_PKG_VERSION")));
    response.insert("appRunning".into(), json!(true));
    response.insert("appVersion".into(), json!(app_version));
    response.insert("locked".into(), json!(locked));
    response.insert(
        "databaseHash".into(),
        if locked || hash.is_empty() {
            Value::Null
        } else {
            json!(hash)
        },
    );
    if let Some(nonce) = get_str(request, "nonce") {
        // Host-level ping echoes the nonce verbatim (not incremented).
        response.insert("nonce".into(), json!(nonce));
    }
    Value::Object(response)
}

fn write_frame(writer: &Arc<Mutex<UnixStream>>, value: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    let mut stream = writer
        .lock()
        .map_err(|_| std::io::Error::other("browser connection writer poisoned"))?;
    stream.write_all(&body)?;
    stream.flush()
}

/// Find the end index (exclusive) of the first complete top-level JSON
/// object in the buffer, if any.
fn find_json_end(buffer: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    let mut started = false;
    for (i, &b) in buffer.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        match b {
            b'\\' if in_string => escape = true,
            b'"' if started => in_string = !in_string,
            b'{' if !in_string => {
                depth += 1;
                started = true;
            }
            b'}' if !in_string && started => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_one(raw: &[u8]) -> Option<Value> {
    // Ignore leading garbage, like the C++ parser.
    let start = raw.iter().position(|&b| b == b'{')?;
    serde_json::from_slice(&raw[start..]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_end_finder() {
        assert_eq!(find_json_end(br#"{"a":1}"#), Some(7));
        assert_eq!(find_json_end(br#"{ "a": "}" }"#), Some(12));
        assert_eq!(find_json_end(br#"{"a":1"#), None);
        assert_eq!(find_json_end(br#"garbage{"a":1}"#), Some(14));
        assert_eq!(find_json_end(br#"{} {}"#), Some(2));
    }

    #[test]
    fn state_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<crate::service::ServiceState>();
    }
}
