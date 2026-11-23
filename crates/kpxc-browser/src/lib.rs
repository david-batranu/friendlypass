//! `kpxc-browser` — the KeepassXC-Browser protocol server for the Rust
//! KeePassXC migration.
//!
//! Implements the socket side of the protocol that KeePassXC's `BrowserHost`
//! serves and the shipped `keepassxc-proxy` relays: the X25519
//! `change-public-keys` handshake, encrypted actions (`get-databasehash`,
//! `associate`, `test-associate`, `get-logins`, `generate-password`,
//! `lock-database`) with libsodium-compatible `crypto_box_easy` sealing and
//! nonce-increment responses — all matching KeePassXC 2.8.0's message shapes.
//!
//! Verified end-to-end against the REAL `keepassxc-proxy` binary from the
//! KeePassXC.app bundle: the proxy relays our handshake and encrypted
//! request/response frames unchanged (see tests/e2e_proxy.rs).

pub mod crypto;
pub mod protocol;
pub mod server;
pub mod service;

pub use server::{browser_server_path, start, user_temp_dir, ServerHandle, SharedState};
pub use service::{CredentialEntry, ServiceState};

use sha2::{Digest, Sha256};

/// The database hash reported to browser clients: hex SHA-256 of the root
/// group UUID string — the same formula KeePassXC uses
/// (`BrowserService::getDatabaseHash`).
pub fn database_hash(root_uuid: &str) -> String {
    hex_lower(&Sha256::digest(root_uuid.as_bytes()))
}

fn hex_lower(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a credential snapshot from a keepass database.
pub fn snapshot_from_database(db: &keepass::db::Database) -> ServiceState {
    let root_uuid = db
        .root()
        .id()
        .uuid()
        .hyphenated()
        .to_string();
    let mut state = ServiceState {
        db_hash: database_hash(&root_uuid),
        ..Default::default()
    };
    for entry in db.iter_all_entries() {
        state.entries.push(CredentialEntry {
            title: entry.get("Title").unwrap_or_default().to_owned(),
            username: entry.get("UserName").unwrap_or_default().to_owned(),
            password: entry.get("Password").unwrap_or_default().to_owned(),
            url: entry.get("URL").unwrap_or_default().to_owned(),
            uuid: entry.id().uuid().hyphenated().to_string(),
        });
    }
    state
}
