//! Cloud-sync safety: file fingerprinting, full KDBX database merging, and
//! merge-on-save so concurrent edits across synced folders (Google Drive,
//! Dropbox, Nextcloud, iCloud Drive) do not silently overwrite one another.
//!
//! Built on [`keepass::Database::merge`] (UUID + timestamp + `deleted_objects`
//! tombstones + group moves + history + custom icons), extended with:
//! * first-conflict history preservation when an entry had no prior history;
//! * attachment synchronization for entries created or updated from disk;
//! * `meta.custom_data` merge (preserving browser associations `KPXC_BROWSER_*`
//!   across machines);
//! * root-UUID validation so an unrelated database on disk is never scrambled
//!   into the open vault.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::ops::Deref;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use keepass::db::merge::{MergeEventTarget, MergeEventType};
use keepass::db::{EntryId, History, Value};
use keepass::{Database, DatabaseKey};
use sha2::{Digest, Sha256};

use crate::saveutil;

/// Retry delays when opening a file that a cloud syncer may be mid-writing.
const OPEN_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(250),
    Duration::from_millis(500),
];

/// Content + metadata fingerprint of a `.kdbx` file on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFingerprint {
    pub len: u64,
    pub modified: Option<SystemTime>,
    pub sha256: [u8; 32],
}

impl FileFingerprint {
    /// Read `path` and compute its metadata + SHA-256 fingerprint.
    pub fn from_path(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        let len = meta.len();
        let modified = meta.modified().ok();
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(Self {
            len,
            modified,
            sha256: hasher.finalize().into(),
        })
    }

    /// Cheap `stat()`-only pre-check for background polling. Returns `true`
    /// when file length or mtime changed (or mtime is unavailable), signaling
    /// the caller to verify with [`Self::from_path`].
    pub fn stat_changed(&self, path: &Path) -> bool {
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        if meta.len() != self.len {
            return true;
        }
        match (self.modified, meta.modified().ok()) {
            (Some(prev), Some(curr)) => prev != curr,
            _ => true,
        }
    }
}

/// Summary of what [`merge_databases`] brought in from the remote/on-disk copy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeSummary {
    pub created_entries: usize,
    pub updated_entries: usize,
    pub deleted_entries: usize,
    pub moved_entries: usize,
    pub created_groups: usize,
    pub updated_groups: usize,
    pub deleted_groups: usize,
    pub moved_groups: usize,
    pub custom_data_updated: usize,
    pub warnings: Vec<String>,
}

impl MergeSummary {
    pub fn total_changes(&self) -> usize {
        self.created_entries
            + self.updated_entries
            + self.deleted_entries
            + self.moved_entries
            + self.created_groups
            + self.updated_groups
            + self.deleted_groups
            + self.moved_groups
            + self.custom_data_updated
    }

    /// Short human-readable summary for the GUI status bar / toast.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.created_entries > 0 {
            parts.push(format!("{} added", self.created_entries));
        }
        if self.updated_entries > 0 {
            parts.push(format!("{} updated", self.updated_entries));
        }
        if self.deleted_entries > 0 {
            parts.push(format!("{} deleted", self.deleted_entries));
        }
        if self.moved_entries > 0 {
            parts.push(format!("{} moved", self.moved_entries));
        }
        let group_changes =
            self.created_groups + self.updated_groups + self.deleted_groups + self.moved_groups;
        if group_changes > 0 {
            parts.push(format!(
                "{group_changes} {}",
                if group_changes == 1 { "group" } else { "groups" }
            ));
        }
        if parts.is_empty() {
            "in sync with disk".to_owned()
        } else {
            parts.join(", ")
        }
    }
}

/// Outcome of [`save_with_merge`].
#[derive(Clone, Debug)]
pub struct SaveOutcome {
    /// Fresh fingerprint of the file written to disk.
    pub fingerprint: FileFingerprint,
    /// `Some(summary)` when the on-disk file had changed and was merged before saving.
    pub merged: Option<MergeSummary>,
}

/// Merge `source` (typically the newer on-disk copy synced by Google Drive)
/// into `dest` (the in-memory database), preserving both sides' edits.
pub fn merge_databases(dest: &mut Database, source: &Database) -> Result<MergeSummary> {
    let dest_root = dest.root().id().uuid();
    let source_root = source.root().id().uuid();
    if dest_root != source_root {
        bail!(
            "cannot merge: the file on disk is a different database (root UUID mismatch)"
        );
    }

    // 1. Identify entries where `source` is strictly newer than `dest` (so
    //    `dest` will take `source`'s fields & attachments) and preserve `dest`'s
    //    prior version in history even if `dest` had no prior history yet.
    let mut source_newer_entries: HashSet<EntryId> = HashSet::new();
    let dest_entry_ids: Vec<EntryId> = dest.iter_all_entries().map(|e| e.id()).collect();
    for id in dest_entry_ids {
        let Some(src) = source.entry(id) else {
            continue;
        };
        let Some(mut dst) = dest.entry_mut(id) else {
            continue;
        };
        let src_mod = src.times.last_modification;
        let dst_mod = dst.times.last_modification;
        if let (Some(sm), Some(dm)) = (src_mod, dst_mod) {
            if sm > dm {
                source_newer_entries.insert(id);
                if entry_contents_differ(dst.as_ref(), src) {
                    let mut snapshot = dst.as_ref().deref().clone();
                    snapshot.history = None;
                    let history = dst.history.get_or_insert_with(History::default);
                    let already_present = history.get_entries().iter().any(|h| {
                        h.times.last_modification == snapshot.times.last_modification
                            && h.fields == snapshot.fields
                            && h.tags == snapshot.tags
                    });
                    if !already_present {
                        history.add_entry(snapshot);
                    }
                }
            }
        }
    }

    // 2. Run keepass's core UUID/timestamp/tombstone/history/icon merge.
    let log = dest
        .merge(source)
        .map_err(|e| anyhow::anyhow!("database merge failed: {e}"))?;

    let mut summary = MergeSummary {
        warnings: log.warnings,
        ..Default::default()
    };

    let mut sync_attachment_ids: HashSet<EntryId> = HashSet::new();
    for event in &log.events {
        match (&event.target, &event.event_type) {
            (MergeEventTarget::Entry(id), MergeEventType::Created) => {
                summary.created_entries += 1;
                sync_attachment_ids.insert(*id);
            }
            (MergeEventTarget::Entry(id), MergeEventType::Updated) => {
                summary.updated_entries += 1;
                if source_newer_entries.contains(id) {
                    sync_attachment_ids.insert(*id);
                }
            }
            (MergeEventTarget::Entry(_), MergeEventType::Deleted) => {
                summary.deleted_entries += 1;
            }
            (MergeEventTarget::Entry(_), MergeEventType::LocationUpdated) => {
                summary.moved_entries += 1;
            }
            (MergeEventTarget::Group(_), MergeEventType::Created) => {
                summary.created_groups += 1;
            }
            (MergeEventTarget::Group(_), MergeEventType::Updated) => {
                summary.updated_groups += 1;
            }
            (MergeEventTarget::Group(_), MergeEventType::Deleted) => {
                summary.deleted_groups += 1;
            }
            (MergeEventTarget::Group(_), MergeEventType::LocationUpdated) => {
                summary.moved_groups += 1;
            }
            (MergeEventTarget::Icon(_), _) => {}
            _ => {}
        }
    }

    // 3. Synchronize attachments for entries created or overwritten from `source`
    //    (keepass 0.17's Database::merge leaves attachments as a TODO).
    for id in sync_attachment_ids {
        let Some(src_entry) = source.entry(id) else {
            continue;
        };
        let src_attachments: HashMap<String, Value<Vec<u8>>> = src_entry
            .attachments_named()
            .map(|(name, att)| (name.to_owned(), att.data.clone()))
            .collect();
        if let Some(mut dst_entry) = dest.entry_mut(id) {
            let existing_names: Vec<String> = dst_entry
                .as_ref()
                .attachments_named()
                .map(|(name, _)| name.to_owned())
                .collect();
            for name in existing_names {
                if !src_attachments.contains_key(&name) {
                    dst_entry.remove_attachment_by_name(&name);
                }
            }
            for (name, data) in src_attachments {
                dst_entry.add_attachment(name, data);
            }
        }
    }

    // 4. Merge database-level `meta.custom_data` (e.g. `KPXC_BROWSER_*` associations).
    for (key, src_item) in &source.meta.custom_data {
        match dest.meta.custom_data.get(key) {
            None => {
                dest.meta.custom_data.insert(key.clone(), src_item.clone());
                summary.custom_data_updated += 1;
            }
            Some(dst_item) => {
                let src_newer = match (
                    src_item.last_modification_time,
                    dst_item.last_modification_time,
                ) {
                    (Some(s), Some(d)) => s > d,
                    (Some(_), None) => true,
                    _ => false,
                };
                if src_newer && src_item.value != dst_item.value {
                    dest.meta.custom_data.insert(key.clone(), src_item.clone());
                    summary.custom_data_updated += 1;
                }
            }
        }
    }

    // 5. Preserve recycle bin metadata if the other side created the Recycle Bin first.
    if dest.meta.recyclebin_uuid.is_none() {
        if let Some(rb_uuid) = source.meta.recyclebin_uuid {
            if dest.iter_all_groups().any(|g| g.id().uuid() == rb_uuid) {
                dest.meta.recyclebin_uuid = Some(rb_uuid);
                dest.meta.recyclebin_enabled = source.meta.recyclebin_enabled;
            }
        }
    }

    Ok(summary)
}

fn entry_contents_differ(a: keepass::db::EntryRef<'_>, b: keepass::db::EntryRef<'_>) -> bool {
    if a.fields != b.fields || a.tags != b.tags || a.autotype != b.autotype || a.icon() != b.icon() {
        return true;
    }
    let a_att: HashMap<&str, Vec<u8>> = a
        .attachments_named()
        .map(|(n, att)| (n, att.data.get().clone()))
        .collect();
    let b_att: HashMap<&str, Vec<u8>> = b
        .attachments_named()
        .map(|(n, att)| (n, att.data.get().clone()))
        .collect();
    a_att != b_att
}

/// Open `path` with brief retries in case a cloud syncer is mid-write.
pub fn open_with_retry(path: &Path, key: DatabaseKey) -> Result<Database> {
    match saveutil::open(path, key.clone()) {
        Ok(db) => Ok(db),
        Err(mut last_err) => {
            for delay in OPEN_RETRY_DELAYS {
                std::thread::sleep(delay);
                match saveutil::open(path, key.clone()) {
                    Ok(db) => return Ok(db),
                    Err(err) => last_err = err,
                }
            }
            Err(last_err)
        }
    }
}

/// Save `db` to `path`, merging with the on-disk file first if its content
/// fingerprint changed since `expected_fingerprint` was recorded.
///
/// Pass `expected_fingerprint = None` for "Save As" to a new file.
pub fn save_with_merge(
    path: &Path,
    db: &mut Database,
    key: DatabaseKey,
    expected_fingerprint: Option<&FileFingerprint>,
) -> Result<SaveOutcome> {
    let mut merged = None;

    if let Some(expected) = expected_fingerprint {
        if path.exists() {
            let disk_fp = FileFingerprint::from_path(path).with_context(|| {
                format!("unable to inspect {} before saving", path.display())
            })?;
            if disk_fp.sha256 != expected.sha256 {
                let on_disk = open_with_retry(path, key.clone()).with_context(|| {
                    format!(
                        "{} changed on disk and could not be opened for merging (was its master key changed?)",
                        path.display()
                    )
                })?;
                let summary = merge_databases(db, &on_disk)?;
                merged = Some(summary);
            }
        }
    }

    saveutil::save(path, db, key)?;
    let fingerprint = FileFingerprint::from_path(path).with_context(|| {
        format!("unable to read fingerprint after saving {}", path.display())
    })?;

    Ok(SaveOutcome {
        fingerprint,
        merged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use keepass::config::DatabaseVersion;
    use keepass::db::{fields, CustomDataItem, CustomDataValue};

    fn ts(secs: u32) -> chrono::NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 6, 1)
            .unwrap()
            .and_hms_opt(12, 0, secs)
            .unwrap()
    }

    fn base_db() -> (Database, DatabaseKey) {
        let mut db = Database::new();
        db.config.version = DatabaseVersion::KDB4(1);
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "GitHub");
            e.set_unprotected(fields::USERNAME, "alice");
            e.set_protected(fields::PASSWORD, "v1-pass");
            e.times.creation = Some(ts(0));
            e.times.last_modification = Some(ts(0));
            e.times.location_changed = Some(ts(0));
        }
        let key = DatabaseKey::new().with_password("syncpw");
        (db, key)
    }

    #[test]
    fn concurrent_additions_on_two_computers_both_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let (base, key) = base_db();
        saveutil::save(&path, &base, key.clone()).unwrap();

        // Both Computer A and Computer B open the same synced file.
        let fp_a = FileFingerprint::from_path(&path).unwrap();
        let fp_b = FileFingerprint::from_path(&path).unwrap();
        let mut db_a = saveutil::open(&path, key.clone()).unwrap();
        let mut db_b = saveutil::open(&path, key.clone()).unwrap();

        // Computer A adds Entry A and saves.
        {
            let mut root = db_a.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "From A");
            e.set_protected(fields::PASSWORD, "pass-a");
            e.times.creation = Some(ts(10));
            e.times.last_modification = Some(ts(10));
            e.times.location_changed = Some(ts(10));
        }
        let out_a = save_with_merge(&path, &mut db_a, key.clone(), Some(&fp_a)).unwrap();
        assert!(out_a.merged.is_none());

        // Computer B (still holding the older snapshot!) adds Entry B and saves.
        {
            let mut root = db_b.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "From B");
            e.set_protected(fields::PASSWORD, "pass-b");
            e.times.creation = Some(ts(20));
            e.times.last_modification = Some(ts(20));
            e.times.location_changed = Some(ts(20));
        }
        let out_b = save_with_merge(&path, &mut db_b, key.clone(), Some(&fp_b)).unwrap();
        let summary = out_b.merged.expect("must detect external save and merge");
        assert_eq!(summary.created_entries, 1);

        // Re-open from disk: GitHub, From A, AND From B are all present!
        let final_db = saveutil::open(&path, key).unwrap();
        let titles: HashSet<String> = final_db
            .iter_all_entries()
            .filter_map(|e| e.get(fields::TITLE).map(str::to_owned))
            .collect();
        assert!(titles.contains("GitHub"));
        assert!(titles.contains("From A"));
        assert!(titles.contains("From B"));
    }

    #[test]
    fn conflicting_edits_keep_newer_and_preserve_older_in_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let (base, key) = base_db();
        saveutil::save(&path, &base, key.clone()).unwrap();

        let fp_b = FileFingerprint::from_path(&path).unwrap();
        let mut db_a = saveutil::open(&path, key.clone()).unwrap();
        let mut db_b = saveutil::open(&path, key.clone()).unwrap();

        let entry_id = db_a.iter_all_entries().next().unwrap().id();

        // Computer A edits GitHub at t=30 (newer) with an attachment, and saves.
        {
            let mut e = db_a.entry_mut(entry_id).unwrap();
            e.set_protected(fields::PASSWORD, "pass-from-A-t30");
            e.add_attachment("recovery.txt", Value::Unprotected(b"codes-from-A".to_vec()));
            e.times.last_modification = Some(ts(30));
        }
        saveutil::save(&path, &db_a, key.clone()).unwrap();

        // Computer B edits the SAME entry at t=20 (older) with no prior history, then saves.
        {
            let mut e = db_b.entry_mut(entry_id).unwrap();
            e.set_protected(fields::PASSWORD, "pass-from-B-t20");
            e.times.last_modification = Some(ts(20));
        }
        let out_b = save_with_merge(&path, &mut db_b, key.clone(), Some(&fp_b)).unwrap();
        assert!(out_b.merged.is_some());

        let final_db = saveutil::open(&path, key).unwrap();
        let e = final_db.entry(entry_id).unwrap();
        // Newer version (A at t=30) wins, including its attachment!
        assert_eq!(e.get(fields::PASSWORD), Some("pass-from-A-t30"));
        assert_eq!(
            e.attachment_by_name("recovery.txt").map(|a| a.data.get().clone()),
            Some(b"codes-from-A".to_vec())
        );
        // Older version (B at t=20) is preserved in entry history, not lost!
        let history = e.history.as_ref().expect("history must preserve B's edit");
        assert!(
            history
                .get_entries()
                .iter()
                .any(|h| h.get(fields::PASSWORD) == Some("pass-from-B-t20")),
            "B's conflicting password edit must be preserved in entry history"
        );
    }

    #[test]
    fn deletion_tombstones_and_custom_data_merge_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let (base, key) = base_db();
        saveutil::save(&path, &base, key.clone()).unwrap();

        let fp_b = FileFingerprint::from_path(&path).unwrap();
        let mut db_a = saveutil::open(&path, key.clone()).unwrap();
        let mut db_b = saveutil::open(&path, key.clone()).unwrap();

        let entry_id = db_a.iter_all_entries().next().unwrap().id();

        // Computer A permanently deletes GitHub (recording a deleted_objects tombstone)
        // and adds a browser association.
        db_a.entry_mut(entry_id).unwrap().track_changes().remove();
        db_a.meta.custom_data.insert(
            "KPXC_BROWSER_chrome-a".to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String("key-a".to_owned())),
                last_modification_time: Some(ts(15)),
            },
        );
        saveutil::save(&path, &db_a, key.clone()).unwrap();

        // Computer B adds a new entry + its own browser association, then saves.
        {
            let mut root = db_b.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "Kept Entry");
            e.times.creation = Some(ts(25));
            e.times.last_modification = Some(ts(25));
        }
        db_b.meta.custom_data.insert(
            "KPXC_BROWSER_chrome-b".to_owned(),
            CustomDataItem {
                value: Some(CustomDataValue::String("key-b".to_owned())),
                last_modification_time: Some(ts(25)),
            },
        );

        let out_b = save_with_merge(&path, &mut db_b, key.clone(), Some(&fp_b)).unwrap();
        let summary = out_b.merged.unwrap();
        assert_eq!(summary.deleted_entries, 1);

        let final_db = saveutil::open(&path, key).unwrap();
        assert!(final_db.entry(entry_id).is_none(), "deleted entry stays deleted");
        assert!(final_db
            .iter_all_entries()
            .any(|e| e.get(fields::TITLE) == Some("Kept Entry")));
        assert!(final_db.meta.custom_data.contains_key("KPXC_BROWSER_chrome-a"));
        assert!(final_db.meta.custom_data.contains_key("KPXC_BROWSER_chrome-b"));
    }

    #[test]
    fn refuses_to_merge_unrelated_database_root_uuid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let (base, key) = base_db();
        saveutil::save(&path, &base, key.clone()).unwrap();
        let fp = FileFingerprint::from_path(&path).unwrap();

        let mut db_local = saveutil::open(&path, key.clone()).unwrap();
        // Someone replaces the file on disk with a brand-new unrelated database.
        let (unrelated, _) = base_db();
        saveutil::save(&path, &unrelated, key.clone()).unwrap();

        let err = save_with_merge(&path, &mut db_local, key, Some(&fp)).unwrap_err();
        assert!(err.to_string().contains("different database"));
    }
}
