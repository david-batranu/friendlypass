//! KeeShare classic-share tests: reference persistence (KeePassXC format),
//! export to a readable KDBX container, and UUID-based import/merge.

use keepass::db::{fields, Database, Value};
use keepass::DatabaseKey;
use kpxc::keeshare::{self, ShareReference};

fn build_source_db() -> (Database, keepass::db::GroupId) {
    let mut db = Database::new();
    db.meta.database_name = Some("Source".into());
    let mut root = db.root_mut();
    let mut group = root.add_group();
    group.name = "Shared".into();
    let group_id = group.id();
    {
        let mut e = group.add_entry();
        e.set_unprotected(fields::TITLE, "Shared Entry");
        e.set_unprotected(fields::USERNAME, "shared-user");
        e.set_protected(fields::PASSWORD, "shared-pw");
        e.add_attachment("note.txt", Value::unprotected(b"shared attachment".to_vec()));
    }
    let mut sub = group.add_group();
    sub.name = "Sub".into();
    let mut e2 = sub.add_entry();
    e2.set_unprotected(fields::TITLE, "Nested Entry");
    e2.set_unprotected(fields::USERNAME, "nested-user");
    drop(e2);
    drop(sub);
    drop(group);
    drop(root);
    (db, group_id)
}

#[test]
fn share_reference_persists_in_group_custom_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("share.kdbx");

    let (mut db, group_id) = build_source_db();
    let reference = ShareReference {
        import: true,
        export: true,
        group_uuid: Some(db.group(group_id).unwrap().id().uuid()),
        path: path.display().to_string(),
        password: "share-pw".into(),
        keep_groups: false,
    };
    keeshare::set_reference(&mut db, group_id, &reference);
    assert_eq!(keeshare::reference_of(&db, group_id), Some(reference.clone()));

    // Save + reopen: the reference survives in the group custom data.
    let db_path = dir.path().join("source.kdbx");
    let key = DatabaseKey::new().with_password("db-pw");
    let mut out = std::io::BufWriter::new(std::fs::File::create(&db_path).unwrap());
    db.save(&mut out, key.clone()).unwrap();
    drop(out);
    let mut file = std::fs::File::open(&db_path).unwrap();
    let reopened = Database::open(&mut file, key).unwrap();
    let parsed = keeshare::reference_of(&reopened, group_id).expect("reference persisted");
    assert_eq!(parsed, reference);
    // And the raw custom-data value is KeePassXC's XML (stored base64 on the
    // wire, round-tripped as bytes by the keepass crate).
    let group = reopened.group(group_id).unwrap();
    let raw = match group.custom_data.get(keeshare::REFERENCE_KEY).unwrap().value.as_ref().unwrap() {
        keepass::db::CustomDataValue::String(s) => {
            use base64::Engine;
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
        }
        keepass::db::CustomDataValue::Binary(b) => String::from_utf8(b.clone()).unwrap(),
    };
    assert!(raw.contains("<KeeShare>"), "KeePassXC XML reference: {raw}");
}

#[test]
fn export_and_import_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let share_path = dir.path().join("share.kdbx");

    let (mut source, group_id) = build_source_db();
    let info = keeshare::export_share(&source, group_id, &share_path, "share-pw").unwrap();
    assert_eq!(info.entries, 2);
    assert!(share_path.exists());

    // The exported container is a normal KDBX readable with the share password.
    let mut file = std::fs::File::open(&share_path).unwrap();
    let share = Database::open(&mut file, DatabaseKey::new().with_password("share-pw")).unwrap();
    assert_eq!(share.num_entries(), 2);
    let entry = share
        .iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Shared Entry"))
        .unwrap();
    assert_eq!(entry.get(fields::USERNAME), Some("shared-user"));
    assert_eq!(entry.get(fields::PASSWORD), Some("shared-pw"));
    assert!(entry.attachment_by_name("note.txt").is_some(), "attachments shared");

    // Import into another database: entries added.
    let mut consumer = Database::new();
    let target = consumer.root().id();
    let info = keeshare::import_share(&mut consumer, target, &share_path, "share-pw").unwrap();
    assert_eq!(info.added, 2);
    assert_eq!(info.updated, 0);
    assert_eq!(consumer.num_entries(), 2);

    // Modify the shared entry in the source, re-export, re-import: updated.
    let shared_id = source
        .iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Shared Entry"))
        .map(|e| e.id());
    if let Some(mut entry) = shared_id.and_then(|id| source.entry_mut(id)) {
        entry.set_unprotected(fields::USERNAME, "updated-user");
    }
    keeshare::export_share(&source, group_id, &share_path, "share-pw").unwrap();
    let info = keeshare::import_share(&mut consumer, target, &share_path, "share-pw").unwrap();
    assert_eq!(info.added, 0, "same UUIDs are matched");
    assert_eq!(info.updated, 2);
    let entry = consumer
        .iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Shared Entry"))
        .unwrap();
    assert_eq!(entry.get(fields::USERNAME), Some("updated-user"));
}

/// Writes a share container to a fixed path for the external keepassxc-cli
/// cross-check in verify.sh (ignored during normal test runs).
#[test]
#[ignore]
fn export_for_external_verification() {
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/keeshare-share.kdbx");
    let _ = std::fs::remove_file(&out);
    let (db, group_id) = build_source_db();
    let info = keeshare::export_share(&db, group_id, &out, "share-pw").unwrap();
    assert_eq!(info.entries, 2);
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/keeshare-path.txt"),
        out.display().to_string(),
    )
    .unwrap();
}
