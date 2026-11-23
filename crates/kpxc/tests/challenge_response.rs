//! Challenge-response (YubiKey-equivalent) composite-key tests.
//!
//! KeePassXC supports challenge-response keys (YubiKey HMAC-SHA1) as a key
//! component: the response is HMAC-SHA1(challenge = KDF seed, key = secret).
//! The keepass crate's `challenge_response` feature provides the same
//! construction via `ChallengeResponseKey::LocalChallenge(hex secret)`; live
//! USB YubiKey transport needs physical hardware and is out of scope.

use keepass::db::{fields, Database};
use keepass::DatabaseKey;
use kpxc::saveutil;

const SECRET: &str = "0102030405060708090a0b0c0d0e0f1011121314";

fn key_with_cr(password: &str, secret: &str) -> DatabaseKey {
    kpxc::key::with_challenge_response(DatabaseKey::new().with_password(password), secret).unwrap()
}

#[test]
fn challenge_response_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cr.kdbx");

    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "CR Entry");
        e.set_unprotected(fields::USERNAME, "cruser");
        e.set_protected(fields::PASSWORD, "cr-pw");
    }
    saveutil::save(&path, &db, key_with_cr("db-pw", SECRET)).unwrap();

    // Opens with the correct challenge-response secret.
    let reopened = saveutil::open(&path, key_with_cr("db-pw", SECRET)).unwrap();
    assert_eq!(reopened.num_entries(), 1);
    assert!(reopened
        .iter_all_entries()
        .any(|e| e.get(fields::TITLE) == Some("CR Entry")));

    // Fails without the challenge-response component.
    let without = saveutil::open(&path, DatabaseKey::new().with_password("db-pw"));
    assert!(without.is_err(), "password alone must not open a CR database");

    // Fails with a wrong secret.
    let wrong = saveutil::open(
        &path,
        key_with_cr("db-pw", "ffffffffffffffffffffffffffffffffffffffff"),
    );
    assert!(wrong.is_err(), "wrong CR secret must not open the database");
}

#[test]
fn challenge_response_combines_with_keyfile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cr-kf.kdbx");
    let keyfile = dir.path().join("id.keyx");

    // Generate a keyfile with the CLI helper and load it.
    kpxc::key::ensure_key_file(&keyfile).unwrap();
    let mut f = std::fs::File::open(&keyfile).unwrap();

    let mut key = DatabaseKey::new()
        .with_password("db-pw")
        .with_keyfile(&mut f)
        .unwrap();
    key = kpxc::key::with_challenge_response(key, SECRET).unwrap();

    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "Combined");
    }
    saveutil::save(&path, &db, key.clone()).unwrap();

    let reopened = saveutil::open(&path, key).unwrap();
    assert_eq!(reopened.num_entries(), 1);

    // Password + keyfile without the CR component must fail.
    let mut f = std::fs::File::open(&keyfile).unwrap();
    let partial = DatabaseKey::new()
        .with_password("db-pw")
        .with_keyfile(&mut f)
        .unwrap();
    assert!(saveutil::open(&path, partial).is_err());
}
