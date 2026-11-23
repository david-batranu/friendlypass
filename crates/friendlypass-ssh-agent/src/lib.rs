//! `friendlypass-ssh-agent` — friendlypass SSH agent: serves SSH keys that
//! live in database entries over the standard agent protocol.
//!
//! Serves SSH identities found in database entry attachments over the
//! standard ssh-agent protocol, like KeePassXC's SSH agent integration:
//! set `SSH_AUTH_SOCK` to the socket and `ssh-add -l` lists the keys;
//! signature requests are fulfilled with the matching private key.
//!
//! Supported subset: unencrypted `ssh-ed25519` keys. RSA/ECDSA and
//! passphrase-encrypted keys are detected and skipped with a notice.

pub mod openssh;
pub mod protocol;
pub mod server;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use keepass::DatabaseKey;
use server::{AgentHandle, IdentityPool};

/// Collect identities from a database and wrap them in a shared pool
/// (the caller can refresh the pool in place later).
pub fn pool_from_database(db: &keepass::db::Database) -> (IdentityPool, Vec<String>) {
    let (identities, skipped) = openssh::collect_identities(db);
    (Arc::new(Mutex::new(identities)), skipped)
}

/// Start serving on `path`.
pub fn start(path: &std::path::Path, pool: IdentityPool) -> Result<AgentHandle> {
    server::spawn(path, pool)
}

/// CLI helper: unlock a database with a password (prompt on a TTY, one line
/// from stdin when piped) — shared by the bin and tests.
pub fn unlock_database(path: &std::path::Path, password: &str) -> Result<keepass::db::Database> {
    let mut file = std::fs::File::open(path).context("cannot open database")?;
    let key = DatabaseKey::new().with_password(password);
    keepass::Database::open(&mut file, key).context("cannot unlock database (wrong password?)")
}

/// Default socket path.
pub fn default_socket_path() -> std::path::PathBuf {
    let runtime: std::path::PathBuf = std::env::var_os("TMPDIR")
        .unwrap_or_else(|| "/tmp".into())
        .into();
    runtime.join("friendlypass-ssh-agent.sock")
}

// Re-exported for the GUI integration.
pub use openssh::collect_identities;
