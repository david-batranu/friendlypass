//! Helpers for opening and (atomically) saving databases.

use anyhow::{bail, Context, Result};
use keepass::config::DatabaseVersion;
use keepass::{Database, DatabaseKey};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

/// Retry delays for transient rename locks (e.g. Google Drive Desktop or
/// antivirus briefly holding the destination file on Windows).
const RENAME_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
];

/// Open a database file with the given key.
pub fn open(path: &Path, key: DatabaseKey) -> Result<Database> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("unable to open database file {}", path.display()))?;
    match Database::open(&mut file, key) {
        Ok(db) => Ok(db),
        // Wrong credentials produce either an explicit key error or, on
        // KDBX3, a low-level padding/decryption error before the stream
        // start check; report both as invalid credentials.
        Err(
            e @ (keepass::db::DatabaseOpenError::Key(_)
            | keepass::db::DatabaseOpenError::Cryptography(_)),
        ) => bail!("invalid credentials (wrong password or key file?) for {}: {e}", path.display()),
        Err(e) => bail!("unable to open database {}: {e}", path.display()),
    }
}

/// Save a database back to `path` (via a temp file + rename so the original
/// survives a failed write).
///
/// KDBX 3 files are upgraded to KDBX 4.1 on save, since the writer only
/// supports KDBX 4 — this mirrors KeePassXC's modernization path.
pub fn save(path: &Path, db: &Database, key: DatabaseKey) -> Result<()> {
    if !matches!(db.config.version, DatabaseVersion::KDB4(_)) {
        bail!(
            "cannot save database version {:?} (only KDBX4 is writable)",
            db.config.version
        );
    }

    let tmp = tempfile_path(path);
    let write_result = (|| -> Result<()> {
        let out = std::fs::File::create(&tmp)
            .with_context(|| format!("unable to create temporary file {}", tmp.display()))?;
        let mut writer = std::io::BufWriter::new(out);
        db.save(&mut writer, key)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("failed to save database")?;
        writer.flush().context("failed to flush database")?;
        writer
            .into_inner()
            .map_err(|e| anyhow::anyhow!(e.into_error()))
            .context("failed to finalize database buffer")?
            .sync_all()
            .with_context(|| format!("failed to sync temporary file {}", tmp.display()))?;
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }

    if let Err(err) = rename_with_retry(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| {
            format!("unable to move {} to {}", tmp.display(), path.display())
        });
    }
    Ok(())
}

fn is_transient_lock_error(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return true;
    }
    // Windows ERROR_ACCESS_DENIED (5), ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33)
    matches!(err.raw_os_error(), Some(5 | 32 | 33))
}

fn rename_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(mut last_err) => {
            if !is_transient_lock_error(&last_err) {
                return Err(last_err);
            }
            for delay in RENAME_RETRY_DELAYS {
                std::thread::sleep(delay);
                match std::fs::rename(from, to) {
                    Ok(()) => return Ok(()),
                    Err(err) if is_transient_lock_error(&err) => last_err = err,
                    Err(err) => return Err(err),
                }
            }
            Err(last_err)
        }
    }
}

fn tempfile_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "database.kdbx".to_string());
    name.push_str(&format!(".{}.friendlypass.tmp", std::process::id()));
    path.with_file_name(name)
}
