//! The BrowserServer socket: listens where KeePassXC's `BrowserHost` does
//! (`<user temp dir>/org.keepassxc.KeePassXC.BrowserServer` on macOS), so the
//! shipped `keepassxc-proxy` — and through it the real browser extension —
//! can talk to this server. The socket carries raw compact JSON (one object
//! per message, coalesced objects handled like the C++ parser).

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::service::{ClientSession, ServiceState};

/// Shared state, refreshed by the GUI side.
pub type SharedState = Arc<Mutex<ServiceState>>;

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
}

impl ServerHandle {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
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
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = UnixStream::connect(&self.path) {
            drop(stream);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Start serving the browser protocol on `path`.
pub fn start(path: &std::path::Path, state: SharedState) -> Result<ServerHandle> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("cannot bind browser server socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let path_owned = path.to_path_buf();

    let thread = std::thread::Builder::new()
        .name("friendlypass-browser".into())
        .spawn(move || {
            let listener = listener;
            for stream in listener.incoming() {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { break };
                let state = Arc::clone(&state);
                let _ = std::thread::Builder::new()
                    .name("friendlypass-browser-conn".into())
                    .spawn(move || handle_connection(stream, &state));
            }
            let _ = std::fs::remove_file(&path_owned);
        })
        .context("cannot start browser server thread")?;

    Ok(ServerHandle {
        path: path.to_path_buf(),
        stop,
        thread: Some(thread),
    })
}

fn handle_connection(mut stream: UnixStream, state: &SharedState) {
    let mut session = ClientSession::new();
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buffer.extend_from_slice(&chunk[..n]);

        // Parse complete JSON objects out of the buffer, coalesced or not.
        while let Some(end) = find_json_end(&buffer) {
            let raw: Vec<u8> = buffer.drain(..end).collect();
            let Some(request) = parse_one(&raw) else { continue };
            let response = {
                let mut guard = match state.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                session.handle(&mut guard, &request)
            };
            let Ok(body) = serde_json::to_vec(&response) else { return };
            if stream.write_all(&body).is_err() {
                return;
            }
        }

        if buffer.len() > 1024 * 1024 {
            return; // protocol cap, like SOCKET_BUFFER_SIZE
        }
    }
}

/// Find the end index (exclusive) of the first complete top-level JSON
/// object in the buffer, if any.
fn find_json_end(buffer: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in buffer.iter().enumerate() {
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
    }
}
