//! Headless [`BrowserBridge`] that writes `set-login` straight to a KDBX file.
//!
//! Used by `examples/test_server.rs` (and its integration test) so the
//! Phase-1 protocol server persists logins exactly like the GUI: the same
//! [`crate::entry_write::apply_set_login`] mutation, the same group/title rules,
//! and an atomic temp-file + rename save. It exists so tests never need a
//! second, subtly different implementation of "create the entry".
//!
//! The GUI does **not** use this bridge: it keeps the database in memory, marks
//! it dirty and saves through the app's normal path (see
//! `friendlypass-gui/src/browser_bridge.rs`).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use keepass::config::DatabaseVersion;
use keepass::{Database, DatabaseKey};

use crate::bridge::{AssociationRequest, BrowserBridge, SetLoginRequest};
use crate::entry_write::apply_set_login;

/// A bridge that auto-approves one fixed association id and saves every
/// `set-login` to `path`.
pub struct FileBridge {
    id: String,
    database: Arc<Mutex<Database>>,
    key: DatabaseKey,
    path: PathBuf,
    changed: AtomicBool,
    last_error: Mutex<Option<String>>,
}

impl FileBridge {
    pub fn new(
        id: impl Into<String>,
        database: Arc<Mutex<Database>>,
        key: DatabaseKey,
        path: impl Into<PathBuf>,
    ) -> FileBridge {
        FileBridge {
            id: id.into(),
            database,
            key,
            path: path.into(),
            changed: AtomicBool::new(false),
            last_error: Mutex::new(None),
        }
    }

    /// The live database the server serves. Callers take the lock, build a
    /// snapshot and release it again; the bridge holds it only while writing.
    pub fn database(&self) -> Arc<Mutex<Database>> {
        Arc::clone(&self.database)
    }

    /// `true` once if the database changed since the last call. The headless
    /// server uses this to refresh its served snapshot after a save.
    pub fn take_changed(&self) -> bool {
        self.changed.swap(false, Ordering::SeqCst)
    }

    /// Last save error (never a credential), for diagnostics.
    pub fn last_error(&self) -> Option<String> {
        self.lock_errors().clone()
    }

    fn lock_database(&self) -> MutexGuard<'_, Database> {
        self.database
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_errors(&self) -> MutexGuard<'_, Option<String>> {
        self.last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn record_error(&self, message: Option<String>) {
        *self.lock_errors() = message;
    }

    /// Write the database atomically: a partially written file never replaces
    /// the previous good copy.
    fn save(&self, db: &Database) -> Result<(), String> {
        if !matches!(db.config.version, DatabaseVersion::KDB4(_)) {
            return Err(format!(
                "cannot save database version {:?} (only KDBX4 is writable)",
                db.config.version
            ));
        }

        let tmp = temp_path(&self.path);
        let result = (|| -> Result<(), String> {
            let file = fs::File::create(&tmp).map_err(|error| {
                format!("unable to create temporary database {}: {error}", tmp.display())
            })?;
            let mut writer = std::io::BufWriter::new(file);
            db.save(&mut writer, self.key.clone())
                .map_err(|error| error.to_string())?;
            writer
                .flush()
                .map_err(|error| format!("unable to flush database: {error}"))?;
            fs::rename(&tmp, &self.path).map_err(|error| {
                format!(
                    "unable to move {} to {}: {error}",
                    tmp.display(),
                    self.path.display()
                )
            })
        })();

        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

impl BrowserBridge for FileBridge {
    fn approve_association(&self, _request: &AssociationRequest) -> Option<String> {
        Some(self.id.clone())
    }

    fn request_unlock(&self) {}

    fn lock_database(&self) {}

    fn apply_set_login(&self, request: &SetLoginRequest) -> bool {
        let mut db = self.lock_database();
        if !apply_set_login(&mut db, request) {
            self.record_error(None);
            return false;
        }
        match self.save(&db) {
            Ok(()) => {
                self.record_error(None);
                self.changed.store(true, Ordering::SeqCst);
                true
            }
            Err(message) => {
                self.record_error(Some(message));
                false
            }
        }
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "database.kdbx".to_owned());
    path.with_file_name(format!("{name}.friendlypass.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::BrowserIdentity;

    #[test]
    fn temp_path_keeps_the_file_in_the_same_directory() {
        let path = temp_path(Path::new("/tmp/example.kdbx"));
        assert_eq!(path, Path::new("/tmp/example.kdbx.friendlypass.tmp"));
    }

    /// Contract §5: existing bridges keep their behaviour; FileBridge still
    /// approves under its one configured id even when the request could have
    /// been auto-approved by the GUI.
    #[test]
    fn fixed_association_name_is_unchanged() {
        let bridge = FileBridge::new(
            "chrome-work-laptop",
            Arc::new(Mutex::new(Database::new())),
            DatabaseKey::new().with_password("test"),
            "/tmp/does-not-need-to-exist.kdbx",
        );
        let request = AssociationRequest {
            client_id: "client".into(),
            suggested_id: "chrome-browser".into(),
            browser: Some(BrowserIdentity {
                kind: "chrome".into(),
                verified: true,
                ..Default::default()
            }),
            auto_approvable: true,
        };
        assert_eq!(
            bridge.approve_association(&request).as_deref(),
            Some("chrome-work-laptop")
        );
    }
}
