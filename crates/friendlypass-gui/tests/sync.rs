//! End-to-end GUI tests for cloud-sync safety (auto-reload when clean and
//! automatic KDBX merge-on-save when two friendlypass instances edit the same
//! synced database file).

use chrono::NaiveDate;
use friendlypass_gui::App;
use keepass::config::DatabaseVersion;
use keepass::db::{fields, Database};
use keepass::DatabaseKey;

fn ts(secs: u32) -> chrono::NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 6, 1)
        .unwrap()
        .and_hms_opt(12, 0, secs)
        .unwrap()
}

fn seed_vault(path: &std::path::Path) -> DatabaseKey {
    let mut db = Database::new();
    db.config.version = DatabaseVersion::KDB4(1);
    db.meta.recyclebin_enabled = Some(false);
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "Shared Account");
        e.set_unprotected(fields::USERNAME, "user@example.com");
        e.set_protected(fields::PASSWORD, "initial-pw");
        e.times.creation = Some(ts(0));
        e.times.last_modification = Some(ts(0));
        e.times.location_changed = Some(ts(0));
    }
    let key = DatabaseKey::new().with_password("drive-sync-pw");
    friendlypass::saveutil::save(path, &db, key.clone()).unwrap();
    key
}

#[test]
fn clean_app_auto_reloads_external_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synced.kdbx");
    let key = seed_vault(&path);
    let path_str = path.display().to_string();

    let mut app_a = App::with_open_database(&path_str, key.clone());
    let mut app_b = App::with_open_database(&path_str, key);

    // Computer A adds an entry and saves.
    {
        let db = app_a.db.as_mut().unwrap();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "Created on Mac");
        e.set_protected(fields::PASSWORD, "mac-secret");
        e.times.creation = Some(ts(10));
        e.times.last_modification = Some(ts(10));
        e.times.location_changed = Some(ts(10));
    }
    app_a.dirty = true;
    app_a.perform_save(None);
    assert!(!app_a.dirty);

    // Computer B has no unsaved edits: auto-reload picks up Computer A's change.
    assert!(app_b.check_external_changes_now());
    assert!(app_b.status.contains("Reloaded external changes"));
    assert!(
        app_b
            .db
            .as_ref()
            .unwrap()
            .iter_all_entries()
            .any(|e| e.get(fields::TITLE) == Some("Created on Mac")),
        "Computer B must see Computer A's newly synced entry"
    );

    // Checking again immediately is a no-op once fingerprint is updated.
    assert!(!app_b.check_external_changes_now());
}

#[test]
fn dirty_app_does_not_discard_local_edits_and_merges_on_save() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synced.kdbx");
    let key = seed_vault(&path);
    let path_str = path.display().to_string();

    let mut app_a = App::with_open_database(&path_str, key.clone());
    let mut app_b = App::with_open_database(&path_str, key.clone());

    // Computer A adds "Added on Mac" and saves.
    {
        let db = app_a.db.as_mut().unwrap();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "Added on Mac");
        e.set_protected(fields::PASSWORD, "mac-pw");
        e.times.creation = Some(ts(10));
        e.times.last_modification = Some(ts(10));
        e.times.location_changed = Some(ts(10));
    }
    app_a.dirty = true;
    app_a.perform_save(None);

    // Computer B adds "Added on Windows" without reloading first.
    {
        let db = app_b.db.as_mut().unwrap();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "Added on Windows");
        e.set_protected(fields::PASSWORD, "win-pw");
        e.times.creation = Some(ts(20));
        e.times.last_modification = Some(ts(20));
        e.times.location_changed = Some(ts(20));
    }
    app_b.dirty = true;

    // Auto-reload MUST NOT discard Computer B's unsaved edits.
    assert!(!app_b.check_external_changes_now());
    assert!(app_b.dirty);

    // Saving on Computer B merges Computer A's synced edits instead of overwriting them!
    app_b.perform_save(None);
    assert!(!app_b.dirty);
    assert!(
        app_b.status.contains("Merged external changes"),
        "unexpected status: {}",
        app_b.status
    );

    // Both entries exist in memory and on disk.
    let reopened = friendlypass::saveutil::open(&path, key).unwrap();
    let titles: Vec<String> = reopened
        .iter_all_entries()
        .filter_map(|e| e.get(fields::TITLE).map(str::to_owned))
        .collect();
    assert!(titles.contains(&"Shared Account".to_owned()));
    assert!(titles.contains(&"Added on Mac".to_owned()));
    assert!(titles.contains(&"Added on Windows".to_owned()));
}

#[test]
fn permanent_delete_on_one_computer_propagates_across_merge() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synced.kdbx");
    let key = seed_vault(&path);
    let path_str = path.display().to_string();

    let mut app_a = App::with_open_database(&path_str, key.clone());
    let mut app_b = App::with_open_database(&path_str, key.clone());

    let shared_id = app_a
        .db
        .as_ref()
        .unwrap()
        .iter_all_entries()
        .next()
        .unwrap()
        .id();

    // Computer A permanently deletes "Shared Account" via GUI method and saves.
    app_a.delete_entry(shared_id);
    app_a.perform_save(None);

    // Computer B adds a new entry and saves.
    {
        let db = app_b.db.as_mut().unwrap();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "Fresh Entry");
        e.times.creation = Some(ts(30));
        e.times.last_modification = Some(ts(30));
        e.times.location_changed = Some(ts(30));
    }
    app_b.dirty = true;
    app_b.perform_save(None);

    let reopened = friendlypass::saveutil::open(&path, key).unwrap();
    assert!(
        reopened.entry(shared_id).is_none(),
        "permanent deletion must be preserved via deleted_objects tombstone"
    );
    assert!(reopened
        .iter_all_entries()
        .any(|e| e.get(fields::TITLE) == Some("Fresh Entry")));
}
