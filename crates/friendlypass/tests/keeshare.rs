//! KeeShare classic-share tests: reference persistence (KeePassXC format),
//! export to a readable KDBX container, and UUID-based import/merge.

use keepass::db::{fields, Database, Value};
use keepass::DatabaseKey;
use friendlypass::keeshare::{self, ShareReference};

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

#[test]
fn signed_export_and_import_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let share_path = dir.path().join("signed.kdbx.share");

    let (source, group_id) = build_source_db();
    let identity = friendlypass::keeshare_signed::Identity::generate("Alice").unwrap();
    let info = friendlypass::keeshare_signed::export_signed(&source, group_id, &share_path, "share-pw", &identity)
        .unwrap();
    assert_eq!(info.entries, 2);

    // ZIP container with KeePassXC's layout.
    let bytes = std::fs::read(&share_path).unwrap();
    assert!(friendlypass::keeshare_signed::is_signed_container(&bytes));

    // A consumer imports: signature verified, entries merged, signer reported.
    let mut consumer = Database::new();
    let target = consumer.root().id();
    let result = friendlypass::keeshare_signed::import_signed(&mut consumer, target, &share_path, "share-pw")
        .unwrap();
    assert_eq!(result.signer, "Alice");
    assert_eq!(result.import.added, 2);
    assert_eq!(consumer.num_entries(), 2);

    // Tampering with the database portion breaks verification.
    let tampered_path = dir.path().join("tampered.kdbx.share");
    {
        let file = std::fs::File::open(&share_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut db_bytes = Vec::new();
        {
            let mut entry = archive
                .by_name(friendlypass::keeshare_signed::CONTAINER_FILE)
                .unwrap();
            use std::io::Read;
            entry.read_to_end(&mut db_bytes).unwrap();
        }
        let mut sig = String::new();
        {
            let mut entry = archive
                .by_name(friendlypass::keeshare_signed::SIGNATURE_FILE)
                .unwrap();
            use std::io::Read;
            entry.read_to_string(&mut sig).unwrap();
        }
        drop(archive);

        // Flip one byte in the middle of the database.
        let mid = db_bytes.len() / 2;
        db_bytes[mid] ^= 0xFF;

        let out = std::fs::File::create(&tampered_path).unwrap();
        let mut zipw = zip::ZipWriter::new(out);
        let opts = zip::write::SimpleFileOptions::default();
        use std::io::Write;
        zipw.start_file(friendlypass::keeshare_signed::SIGNATURE_FILE, opts).unwrap();
        zipw.write_all(sig.as_bytes()).unwrap();
        zipw.start_file(friendlypass::keeshare_signed::CONTAINER_FILE, opts).unwrap();
        zipw.write_all(&db_bytes).unwrap();
        zipw.finish().unwrap();
    }
    let mut consumer2 = Database::new();
    let target2 = consumer2.root().id();
    let err = friendlypass::keeshare_signed::import_signed(&mut consumer2, target2, &tampered_path, "share-pw");
    assert!(err.is_err(), "tampered container must be rejected");
    let msg = format!("{:#}", err.unwrap_err());
    assert!(
        msg.contains("signature") || msg.contains("padding") || msg.contains("decrypt"),
        "unexpected error: {msg}"
    );
}

/// Writes a signed container + the signer's RSA public key (PEM) for the
/// real-tool cross-checks in verify.sh (openssl dgst -verify, unzip -l).
#[test]
#[ignore]
fn signed_export_for_external_verification() {
    use rsa::pkcs8::EncodePublicKey;
    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let share = out_dir.join("keeshare-signed.kdbx.share");
    let db_file = out_dir.join("keeshare-signed-container.kdbx");
    let pub_file = out_dir.join("keeshare-signer.pub.pem");
    let _ = std::fs::remove_file(&share);

    let (db, group_id) = build_source_db();
    let identity = friendlypass::keeshare_signed::Identity::generate("Verify Signer").unwrap();
    friendlypass::keeshare_signed::export_signed(&db, group_id, &share, "signed-pw", &identity).unwrap();

    // Extract the DB bytes for the cross-check.
    let file = std::fs::File::open(&share).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut db_bytes = Vec::new();
    {
        let mut entry = archive
            .by_name(friendlypass::keeshare_signed::CONTAINER_FILE)
            .unwrap();
        use std::io::Read;
        entry.read_to_end(&mut db_bytes).unwrap();
    }
    std::fs::write(&db_file, &db_bytes).unwrap();

    // Write the RSA public key (PEM/SPKI) and the raw signature for openssl.
    let pem = identity
        .public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    std::fs::write(&pub_file, pem).unwrap();
    let sig = identity.sign(&db_bytes);
    let hex_sig = sig.strip_prefix("rsa|").unwrap();
    std::fs::write(out_dir.join("keeshare-signature.bin"), hex::decode(hex_sig).unwrap()).unwrap();
}

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
