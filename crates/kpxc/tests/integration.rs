//! Integration tests: open real KeePassXC-created databases and round-trip
//! our own writes.
//!
//! Fixtures (passwords in comments):
//! * sample4.kdbx          — KDBX 3.1, AES256-CBC, AES-KDF 14285714 rounds, GZip,
//!                           2 groups, 2 entries, 1 attachment   (pw: testpassword)
//! * sample4_keyfile.kdbx  — same era, password + XML v2 keyfile
//! * sample4_argon2.kdbx   — KDBX 3.1, AES-KDF 1000000 rounds    (pw: testpassword)
//! * Format400.kdbx        — KDBX 4.0, ChaCha20                  (pw: t)
//! * Compressed.kdbx       — KDBX 3.x, GZip                      (pw: empty)
//! * NonAscii.kdbx         — KDBX 3.1, no compression            (pw: Δöص)
//! * ProtectedStrings.kdbx — KDBX 3.x, protected fields          (pw: masterpw)
//!
//! sample4* were created by keepassxc-cli 2.8.0; the others come from the
//! KeePassXC repository's own test data (tests/data).

use keepass::config::{CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};
use keepass::db::{fields, Database, Value};
use keepass::DatabaseKey;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name)
}

fn open_fixture(name: &str, key: DatabaseKey) -> Database {
    let path = fixture(name);
    let mut file = std::fs::File::open(&path).unwrap();
    Database::open(&mut file, key).unwrap()
}

// ---------------------------------------------------------------------------
// Reading real KeePassXC databases
// ---------------------------------------------------------------------------

#[test]
fn open_keepassxc_2_8_kdbx31_with_attachment() {
    let db = open_fixture("sample4.kdbx", DatabaseKey::new().with_password("testpassword"));

    assert_eq!(DatabaseVersion::KDB3(1), db.config.version);
    assert_eq!(OuterCipherConfig::AES256, db.config.outer_cipher_config);
    assert_eq!(CompressionConfig::GZip, db.config.compression_config);
    assert_eq!(InnerCipherConfig::Salsa20, db.config.inner_cipher_config);
    assert!(matches!(db.config.kdf_config, KdfConfig::Aes { rounds: 14_285_714 }));

    // 2 entries + 2 child groups (Web, Bank).
    assert_eq!(db.num_entries(), 2);
    assert_eq!(db.num_groups(), 3);

    let entry = db
        .iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Sample Entry"))
        .expect("Sample Entry exists");
    assert_eq!(entry.get(fields::USERNAME), Some("user@example.com"));
    assert_eq!(entry.get(fields::URL), Some("https://example.com"));
    assert_eq!(entry.get(fields::NOTES), Some("some notes"));

    // Protected password (Salsa20 inner stream) decodes to a 20-char value.
    let password = entry.get(fields::PASSWORD).unwrap();
    assert_eq!(password.len(), 20);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));

    // Attachment round-trips byte-identically.
    // (Attachment.txt in the KeePassXC repo's test data is exactly "Content\n".)
    let attachment = entry.attachment_by_name("attach.txt").expect("attachment");
    assert_eq!(attachment.data.get().as_slice(), b"Content\n");
}

#[test]
fn open_keepassxc_database_with_keyfile() {
    let mut keyfile = std::fs::File::open(fixture("sample4.keyx")).unwrap();
    let key = DatabaseKey::new()
        .with_password("testpassword")
        .with_keyfile(&mut keyfile)
        .unwrap();
    let db = open_fixture("sample4_keyfile.kdbx", key);

    assert_eq!(db.num_entries(), 1);
    let entry = db.iter_all_entries().next().unwrap();
    assert_eq!(entry.get(fields::TITLE), Some("Keyfile Entry"));
    assert_eq!(entry.get(fields::USERNAME), Some("kfuser"));
}

#[test]
fn open_keepassxc_kdbx31_one_million_rounds() {
    let db = open_fixture("sample4_argon2.kdbx", DatabaseKey::new().with_password("testpassword"));
    assert!(matches!(db.config.kdf_config, KdfConfig::Aes { rounds: 1_000_000 }));
    assert_eq!(db.num_entries(), 1);
    assert_eq!(db.iter_all_entries().next().unwrap().get(fields::TITLE), Some("Argon Entry"));
}

#[test]
fn open_kdbx4_chacha20_from_keepassxc_repo_tests() {
    let db = open_fixture("Format400.kdbx", DatabaseKey::new().with_password("t"));
    assert_eq!(DatabaseVersion::KDB4(0), db.config.version);
    assert_eq!(OuterCipherConfig::ChaCha20, db.config.outer_cipher_config);
    assert_eq!(db.num_entries(), 1);
}

#[test]
fn open_kdbx3_empty_password_gzip() {
    let db = open_fixture("Compressed.kdbx", DatabaseKey::new().with_password(""));
    assert_eq!(CompressionConfig::GZip, db.config.compression_config);
    assert!(db.num_entries() > 0);
}

#[test]
fn open_kdbx3_nonascii_password_no_compression() {
    // Password "Δöص" (U+0394, U+00F6, U+0636) — the exact UTF-8 bytes from
    // KeePassXC's TestKdbx3::testNonAscii.
    let pw = "\u{394}\u{f6}\u{636}";
    let db = open_fixture("NonAscii.kdbx", DatabaseKey::new().with_password(pw));
    assert_eq!(CompressionConfig::None, db.config.compression_config);
    assert_eq!(db.meta.database_name.as_deref(), Some("NonAsciiTest"));
}

#[test]
fn open_kdbx3_protected_strings() {
    let db = open_fixture("ProtectedStrings.kdbx", DatabaseKey::new().with_password("masterpw"));
    let entry = db
        .iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Sample Entry"))
        .expect("entry");
    assert_eq!(entry.get(fields::USERNAME), Some("Protected User Name"));
    assert_eq!(entry.get(fields::PASSWORD), Some("ProtectedPassword"));
    assert_eq!(entry.get("TestProtected"), Some("ABC"));
    assert_eq!(entry.get("TestUnprotected"), Some("DEF"));
}

#[test]
fn wrong_password_is_rejected() {
    let path = fixture("sample4.kdbx");
    let mut file = std::fs::File::open(&path).unwrap();
    let result = Database::open(&mut file, DatabaseKey::new().with_password("definitely-wrong"));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Writing databases that KeePassXC can open
// ---------------------------------------------------------------------------

fn test_db() -> Database {
    let mut db = Database::new();
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.outer_cipher_config = OuterCipherConfig::AES256;
    db.config.compression_config = CompressionConfig::GZip;
    db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    db.config.kdf_config = KdfConfig::Argon2id {
        iterations: 10,
        memory: 8 * 1024 * 1024,
        parallelism: 2,
        version: argon2::Version::Version13,
    };
    db
}

fn populate(db: &mut Database) {
    db.meta.database_name = Some("Round Trip".into());

    let mut root = db.root_mut();
    let mut group = root.add_group();
    group.name = "Web".into();

    let mut entry = group.add_entry();
    entry.set_unprotected(fields::TITLE, "Round Trip Entry");
    entry.set_unprotected(fields::USERNAME, "rtuser");
    entry.set_unprotected(fields::URL, "https://example.net");
    entry.set_protected(fields::PASSWORD, "s3cret-pw");
    entry.tags.push("rust".into());
    entry.add_attachment("hello.txt", Value::unprotected(b"hello world\n".to_vec()));
}

#[test]
fn write_roundtrip_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("roundtrip.kdbx");

    let key = DatabaseKey::new().with_password("round-trip-pw");
    let mut db = test_db();
    populate(&mut db);
    kpxc::saveutil::save(&path, &db, key.clone()).unwrap();

    // Reopen and verify everything survived.
    let mut file = std::fs::File::open(&path).unwrap();
    let db2 = Database::open(&mut file, key).unwrap();
    assert_eq!(db2.meta.database_name.as_deref(), Some("Round Trip"));
    assert_eq!(db2.num_entries(), 1);

    let entry = db2.iter_all_entries().next().unwrap();
    assert_eq!(entry.get(fields::TITLE), Some("Round Trip Entry"));
    assert_eq!(entry.get(fields::USERNAME), Some("rtuser"));
    assert_eq!(entry.get(fields::PASSWORD), Some("s3cret-pw"));
    assert_eq!(entry.get("hello.txt"), None); // attachments are not string fields
    assert_eq!(entry.tags, vec!["rust".to_string()]);

    let attachment = entry.attachment_by_name("hello.txt").expect("attachment survived");
    assert_eq!(attachment.data.get().as_slice(), b"hello world\n");
}

#[test]
fn write_all_cipher_and_kdf_variants_roundtrip() {
    for (cipher, kdf) in [
        (OuterCipherConfig::AES256, KdfConfig::Argon2id {
            iterations: 10,
            memory: 8 * 1024 * 1024,
            parallelism: 2,
            version: argon2::Version::Version13,
        }),
        (OuterCipherConfig::ChaCha20, KdfConfig::Argon2 {
            iterations: 10,
            memory: 8 * 1024 * 1024,
            parallelism: 2,
            version: argon2::Version::Version13,
        }),
        (OuterCipherConfig::Twofish, KdfConfig::Aes { rounds: 10_000 }),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("variant.kdbx");

        let key = DatabaseKey::new().with_password("variant-pw");
        let mut db = test_db();
        db.config.outer_cipher_config = cipher.clone();
        db.config.kdf_config = kdf.clone();
        populate(&mut db);
        kpxc::saveutil::save(&path, &db, key.clone()).unwrap();

        let mut file = std::fs::File::open(&path).unwrap();
        let db2 = Database::open(&mut file, key).unwrap();
        assert_eq!(db2.config.outer_cipher_config, cipher);
        assert_eq!(db2.num_entries(), 1);
        assert_eq!(db2.iter_all_entries().next().unwrap().get(fields::PASSWORD), Some("s3cret-pw"));
    }
}

#[test]
fn upgrade_kdbx31_to_kdbx41_preserves_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("upgraded.kdbx");

    let key = DatabaseKey::new().with_password("testpassword");
    let mut db = open_fixture("sample4.kdbx", DatabaseKey::new().with_password("testpassword"));
    assert_eq!(DatabaseVersion::KDB3(1), db.config.version);

    // The same upgrade kpxc applies when saving a modified KDBX3 database.
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    kpxc::saveutil::save(&path, &db, key).unwrap();

    let db2 = open_fixtureless(&path, DatabaseKey::new().with_password("testpassword"));
    assert_eq!(DatabaseVersion::KDB4(1), db2.config.version);
    assert_eq!(db2.num_entries(), 2);
    let entry = db2
        .iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Sample Entry"))
        .expect("entry survived upgrade");
    assert_eq!(entry.get(fields::USERNAME), Some("user@example.com"));
    // The attachment even survives the version upgrade.
    assert!(entry.attachment_by_name("attach.txt").is_some());
}

fn open_fixtureless(path: &Path, key: DatabaseKey) -> Database {
    let mut file = std::fs::File::open(path).unwrap();
    Database::open(&mut file, key).unwrap()
}

// ---------------------------------------------------------------------------
// kpxc-specific helpers
// ---------------------------------------------------------------------------

#[test]
fn generated_passwords_are_printable_and_random() {
    let a = kpxc::commands::generate_password(32);
    let b = kpxc::commands::generate_password(32);
    assert_eq!(a.len(), 32);
    assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
    assert_ne!(a, b);
}

#[test]
fn generated_keyfiles_match_keepassxc_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let kf = dir.path().join("test.keyx");
    kpxc::key::ensure_key_file(&kf).unwrap();

    let content = std::fs::read_to_string(&kf).unwrap();
    assert!(content.contains("<Version>2.0</Version>"), "v2 XML keyfile");

    // The key data must be exactly 32 bytes (64 hex chars) so that
    // KeePassXC (first 32 bytes) and keepass-rs (whole array) agree.
    let mut reader = DatabaseKey::new();
    let mut file = std::fs::File::open(&kf).unwrap();
    reader = reader.with_keyfile(&mut file).unwrap();
    // (We can't inspect the parsed key element directly; the cross-check is
    // that keepassxc-cli opens databases locked with this keyfile — see
    // verify.sh.)
    let _ = reader;
}
