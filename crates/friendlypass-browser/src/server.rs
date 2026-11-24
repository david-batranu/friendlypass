//! The BrowserServer socket: listens where KeePassXC's `BrowserHost` does
//! (`<user temp dir>/org.keepassxc.KeePassXC.BrowserServer` on macOS), so the
//! shipped `keepassxc-proxy` — and through it the real browser extension —
//! can talk to this server. The socket carries raw compact JSON (one object
//! per message, coalesced objects handled like the C++ parser).
//!
//! Each connection thread owns its socket for writes; unsolicited pushes from
//! the GUI are delivered through a bounded channel so a slow browser can never
//! stall the application.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::protocol::{host_error_reply, HOST_ERROR_FRAME_TOO_LARGE, HOST_ERROR_MALFORMED_FRAME};
use crate::push::PushHub;
use crate::service::{lock_state, ClientSession, SharedState};

/// Maximum frame size in both directions (`BrowserShared::SOCKET_BUFFER_SIZE`,
/// also the friendlypass 1 MiB contract).
pub const MAX_FRAME: usize = 1024 * 1024;

/// How often a connection checks for queued push messages.
const PUSH_POLL: Duration = Duration::from_millis(200);

/// The KeePassXC BrowserServer socket path (macOS form, like BrowserShared).
pub fn browser_server_path() -> PathBuf {
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
    let _ = stream.set_read_timeout(Some(PUSH_POLL));
    // A peer that stops reading must not wedge a connection thread forever.
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let (client_id, pushes) = hub.register();
    let mut session = ClientSession::new();
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        // Deliver queued unsolicited frames between reads. A write failure
        // means the peer is gone; drop the registration and exit.
        while let Some(frame) = pushes.try_recv() {
            if write_frame(&mut stream, &frame).is_err() {
                hub.unregister(client_id);
                return;
            }
        }

        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if !drain_frames(&mut stream, state, &mut session, &mut buffer) {
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
}

/// Handle every complete frame in `buffer`. Returns false when the connection
/// should close.
fn drain_frames(
    stream: &mut UnixStream,
    state: &SharedState,
    session: &mut ClientSession,
    buffer: &mut Vec<u8>,
) -> bool {
    while let Some(end) = find_json_end(buffer) {
        let raw: Vec<u8> = buffer.drain(..end).collect();
        if raw.len() > MAX_FRAME {
            let reply = host_error_reply("", HOST_ERROR_FRAME_TOO_LARGE, "Message exceeds the 1 MiB frame limit");
            if write_frame(stream, &reply).is_err() {
                return false;
            }
            continue;
        }
        let Some(request) = parse_one(&raw) else {
            let reply = host_error_reply("", HOST_ERROR_MALFORMED_FRAME, "Malformed frame");
            if write_frame(stream, &reply).is_err() {
                return false;
            }
            continue;
        };
        let response = session.handle(state, &request);
        if write_frame(stream, &response).is_err() {
            return false;
        }
    }

    if buffer.len() > MAX_FRAME {
        // A frame larger than the cap that never closes: answer once and
        // discard what we have rather than growing without bound.
        let reply = host_error_reply("", HOST_ERROR_FRAME_TOO_LARGE, "Message exceeds the 1 MiB frame limit");
        if write_frame(stream, &reply).is_err() {
            return false;
        }
        buffer.clear();
    }
    true
}

fn write_frame(stream: &mut UnixStream, value: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
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
