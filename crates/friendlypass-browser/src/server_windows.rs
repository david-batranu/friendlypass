//! Windows browser-protocol server: a per-user named pipe.
//!
//! The protocol, framing, reader/worker split, immediate `ping` answers and
//! pushes are identical to the Unix socket and live in
//! [`crate::server_core`]. This module only owns the Windows transport:
//!
//! * a pipe name `\\.\pipe\org.friendlypass.BrowserServer_<USERNAME>` (the
//!   same `<name>_<USERNAME>` pattern KeePassXC uses);
//! * a DACL granting the object owner only, plus `PIPE_REJECT_REMOTE_CLIENTS`;
//! * `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance, which turns a
//!   second app's start attempt into the Unix "already listening" error;
//! * peer verification through `GetNamedPipeClientProcessId` +
//!   `QueryFullProcessImageNameW`.
//!
//! `FP_APP_SOCKET` overrides the pipe path for tests and relocated apps, just
//! like it overrides the Unix socket path.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::Value;
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

use crate::peer::verify_peer;
use crate::pipe::PipeStream;
use crate::push::PushHub;
use crate::server_core::handle_connection;
use crate::service::{lock_state, SharedState};

pub use crate::server_core::MAX_FRAME;

/// Base name of the friendlypass browser-integration pipe.
pub const SOCKET_FILE_NAME: &str = "org.friendlypass.BrowserServer";

/// How the server decides which pipe clients to trust (contract §3).
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// Path of the native host binary that may be auto-approved, normally the
    /// GUI's `native_host_path` (a `friendlypass-browser-host.exe` next to the
    /// running GUI). `None` never trusts a peer.
    pub trusted_host_path: Option<PathBuf>,
}

/// The per-user friendlypass browser-integration pipe name.
///
/// `FP_APP_SOCKET` overrides the path for tests and for a relocated app. The
/// native host derives its app link from this same function, so setting the
/// variable is sufficient to keep both ends of the app link in sync and
/// guarantees tests never touch the user's real pipe.
pub fn browser_server_path() -> PathBuf {
    if let Some(path) = std::env::var_os("FP_APP_SOCKET") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    default_browser_server_path()
}

/// The default pipe name, ignoring `FP_APP_SOCKET`.
fn default_browser_server_path() -> PathBuf {
    crate::pipe::pipe_name(SOCKET_FILE_NAME, &crate::pipe::current_user_name())
}

/// The per-user temporary directory. Kept for API parity with Unix; the
/// Windows transport uses a named pipe instead of a file in it.
pub fn user_temp_dir() -> PathBuf {
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
    pub fn path(&self) -> &Path {
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
        // Wake a blocking `ConnectNamedPipe` so the accept thread can observe
        // stop. The connected dummy is closed immediately.
        if let Ok(stream) = PipeStream::connect(&self.path) {
            drop(stream);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Start serving the browser protocol on `path`.
///
/// A live server at `path` is never stolen: the first pipe instance is created
/// with `FILE_FLAG_FIRST_PIPE_INSTANCE`, and an existing server makes that fail
/// with `ERROR_ACCESS_DENIED`. Without a [`ServerConfig`] no peer is ever
/// trusted (the manual approval path only).
pub fn start(path: &Path, state: SharedState) -> Result<ServerHandle> {
    start_with_config(path, ServerConfig::default(), state)
}

/// Start serving with peer verification (contract §3).
pub fn start_with_config(
    path: &Path,
    config: ServerConfig,
    state: SharedState,
) -> Result<ServerHandle> {
    // Create the first instance synchronously so "already running" and other
    // setup failures are reported to the caller, not from a background thread.
    let first = PipeStream::create_server(path, true).map_err(|error| {
        if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            anyhow::anyhow!(
                "a browser protocol server is already listening on {}",
                path.display()
            )
        } else {
            anyhow::anyhow!(
                "cannot create browser server pipe {}: {error}",
                path.display()
            )
        }
    })?;

    let push = {
        let guard = lock_state(&state);
        Arc::clone(&guard.push)
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let accept_path = path.to_path_buf();
    let push_thread = Arc::clone(&push);
    let trusted_host_path = config.trusted_host_path;

    let thread = std::thread::Builder::new()
        .name("friendlypass-browser".into())
        .spawn(move || {
            let mut next = Some(first);
            loop {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let stream = match next.take() {
                    Some(stream) => stream,
                    None => match PipeStream::create_server(&accept_path, false) {
                        Ok(stream) => stream,
                        Err(error) => {
                            // A transient failure (for example the stop wake-up
                            // client) must not kill the listener permanently.
                            if stop_thread.load(Ordering::SeqCst) {
                                break;
                            }
                            eprintln!(
                                "friendlypass-browser: cannot create pipe instance for {}: {error}",
                                accept_path.display()
                            );
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            continue;
                        }
                    },
                };
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                match stream.accept() {
                    Ok(()) => {}
                    Err(_) => continue,
                }
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                // Identify the peer before the connection thread starts: the
                // process query is cheap and the result must be fixed for the
                // connection's lifetime (§3).
                let peer = verify_peer(&stream, trusted_host_path.as_deref());
                let state = Arc::clone(&state);
                let hub = Arc::clone(&push_thread);
                let conn_stop = Arc::clone(&stop_thread);
                let _ = std::thread::Builder::new()
                    .name("friendlypass-browser-conn".into())
                    .spawn(move || handle_connection(stream, &state, &hub, &conn_stop, peer));
            }
        })
        .context("cannot start browser server thread")?;

    Ok(ServerHandle {
        path: path.to_path_buf(),
        stop,
        thread: Some(thread),
        push,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `browser_server_path()` is process-global because it reads env vars, so
    /// the two tests that touch `FP_APP_SOCKET` must not run concurrently.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn default_path_is_a_per_user_named_pipe() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("FP_APP_SOCKET");
        let path = browser_server_path();
        let text = path.to_string_lossy();
        let user = crate::pipe::current_user_name();
        assert!(text.starts_with(r"\\.\pipe\"), "{text}");
        assert_eq!(text, format!(r"\\.\pipe\{SOCKET_FILE_NAME}_{user}"));
        assert!(!text.to_lowercase().contains("keepassxc"), "{text}");
    }

    #[test]
    fn fp_app_socket_overrides_the_pipe_name() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let override_name = r"\\.\pipe\friendlypass-test-override";
        std::env::set_var("FP_APP_SOCKET", override_name);
        assert_eq!(browser_server_path(), PathBuf::from(override_name));
        std::env::remove_var("FP_APP_SOCKET");
    }
}
