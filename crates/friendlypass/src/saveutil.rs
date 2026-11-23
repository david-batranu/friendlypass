//! Helpers for opening and (atomically) saving databases.

use anyhow::{bail, Context, Result};
use keepass::config::DatabaseVersion;
use keepass::{Database, DatabaseKey};
use std::io::Write;
use std::path::Path;

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
    let out = std::fs::File::create(&tmp)
        .with_context(|| format!("unable to create temporary file {}", tmp.display()))?;
    let mut writer = std::io::BufWriter::new(out);
    db.save(&mut writer, key)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .context("failed to save database")?;
    writer.flush().context("failed to flush database")?;

    std::fs::rename(&tmp, path).with_context(|| {
        format!("unable to move {} to {}", tmp.display(), path.display())
    })?;
    Ok(())
}

fn tempfile_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "database.kdbx".to_string());
    name.push_str(".friendlypass.tmp");
    path.with_file_name(name)
}
