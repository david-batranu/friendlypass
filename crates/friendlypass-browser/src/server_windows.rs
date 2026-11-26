//! Windows stub for the browser-protocol socket server.
//!
//! The real server (`server.rs`) listens on the friendlypass browser socket
//! and verifies the peer process through Unix credentials (`peer.rs`). Windows
//! has neither, so this build exposes the
//! same public surface with a [`start`] that always fails; the GUI disables the
//! Browser Integration settings and never calls it.
//!
//! Porting the protocol to named pipes (with an equivalent peer check) is a
//! known follow-up, not part of this change.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Result};
use serde_json::Value;

use crate::push::PushHub;
use crate::service::SharedState;

/// Maximum frame size in both directions (`BrowserShared::SOCKET_BUFFER_SIZE`,
/// also the friendlypass 1 MiB contract).
pub const MAX_FRAME: usize = 1024 * 1024;

/// How the server decides which socket peers to trust (contract §3). Kept for
/// API compatibility; Windows never reaches a peer check.
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    pub trusted_host_path: Option<PathBuf>,
}

/// File name of the friendlypass browser-integration socket in the user's
/// temporary directory (kept identical to the Unix form).
pub const SOCKET_FILE_NAME: &str = "org.friendlypass.BrowserServer";

/// The friendlypass browser-integration socket path, kept identical to the
/// Unix form so diagnostics and the native host agree. `FP_APP_SOCKET` still
/// overrides it.
pub fn browser_server_path() -> PathBuf {
    if let Some(path) = std::env::var_os("FP_APP_SOCKET") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    user_temp_dir().join(SOCKET_FILE_NAME)
}

/// The per-user temporary directory (the Unix implementation uses the macOS
/// user temp dir; on Windows the standard temp dir is the closest match).
pub fn user_temp_dir() -> PathBuf {
    std::env::temp_dir()
}

/// A running browser-protocol server (never constructed on Windows).
pub struct ServerHandle {
    path: PathBuf,
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

    pub fn stop(self) {}
}

/// Start serving the browser protocol on `path` (always fails on Windows).
pub fn start(path: &Path, state: SharedState) -> Result<ServerHandle> {
    start_with_config(path, ServerConfig::default(), state)
}

/// Start serving with peer verification (always fails on Windows).
pub fn start_with_config(
    path: &Path,
    _config: ServerConfig,
    _state: SharedState,
) -> Result<ServerHandle> {
    bail!(
        "browser integration is not available on Windows yet \
         (it needs Unix domain sockets and Unix peer credentials); socket {}",
        path.display()
    )
}
