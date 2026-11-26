//! Windows stub for the SSH agent socket server.
//!
//! The real server (`server.rs`) listens on a Unix domain socket, which
//! Windows does not provide here. Keeping the same public surface lets the GUI
//! build on Windows; [`spawn`] reports the feature as unavailable and the GUI
//! disables the SSH Agent settings.
//!
//! Porting the agent to Windows named pipes is a known follow-up, not part of
//! this change.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};

use crate::openssh::SshIdentity;

/// The shared identity pool: refreshed by the GUI side, read by the agent
/// thread per request (so new keys are served without restarting).
pub type IdentityPool = Arc<Mutex<Vec<SshIdentity>>>;

/// The placeholder for a running agent server. It never exists on Windows.
pub struct AgentHandle {
    path: PathBuf,
}

impl AgentHandle {
    /// Socket path (for `SSH_AUTH_SOCK`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop the server (a no-op: there is nothing to stop).
    pub fn stop(self) {}
}

/// Always fails: the agent needs a Unix domain socket.
pub fn spawn(path: &Path, _pool: IdentityPool) -> Result<AgentHandle> {
    bail!(
        "the friendlypass SSH agent is not available on Windows yet \
         (it needs Unix domain sockets); requested socket {}",
        path.display()
    )
}
