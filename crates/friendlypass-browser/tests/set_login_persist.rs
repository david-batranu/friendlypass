//! `set-login` persistence through the real protocol action path.
//!
//! Drives the real `ClientSession` with the golden `set-login` frame while the
//! server state uses [`friendlypass_browser::FileBridge`] — the same bridge
//! `examples/test_server.rs` serves with. The assertion that matters for the
//! e2e suite is that the KDBX file on disk contains the new entry after the
//! action returns, so a fresh process (the `friendlypass` CLI) can read it.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keepass::db::fields;
use keepass::{Database, DatabaseKey};
use serde_json::Value;

use friendlypass_browser::crypto::{open, KeyPair};
use friendlypass_browser::service::ClientSession;
use friendlypass_browser::{snapshot_from_database, FileBridge};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/fixtures")
}

fn load(name: &str) -> Value {
    let path = fixtures_dir().join(name);
    serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn decode(document: &Value, pointer: &str) -> Vec<u8> {
    let text = document
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {pointer}"));
    B64.decode(text).unwrap_or_else(|error| panic!("{pointer}: {error}"))
}

#[test]
fn set_login_writes_the_entry_to_the_database_file() {
    let fixture = load("set-login.json");
    let create = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "set-login/create")
        .expect("set-login/create vector");
    let expected = &create["request"]["plaintext"];

    // A throwaway KDBX so no fixture is modified.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("set-login.kdbx");
    let key = DatabaseKey::new().with_password("testpassword");
    let database = Database::new();
    friendlypass::saveutil::save(&path, &database, key.clone()).expect("initial save");

    let database = Arc::new(Mutex::new(database));
    let mut state = {
        let guard = database.lock().expect("database");
        snapshot_from_database(&guard)
    };
    let bridge = Arc::new(FileBridge::new(
        "chrome-work-laptop",
        Arc::clone(&database),
        key.clone(),
        path.clone(),
    ));
    state.set_bridge(bridge.clone());
    state.associations.insert(
        "chrome-work-laptop".to_owned(),
        B64.encode(decode(&fixture, "/keys/identity/publicKey")),
    );
    let state = Arc::new(Mutex::new(state));

    // The canonical handshake + association, then the golden set-login frame.
    let mut session = ClientSession::with_keypair(
        KeyPair::from_secret(&decode(&fixture, "/keys/host/secretKey")).expect("host keypair"),
    );
    session.accept_client_key(decode(&fixture, "/keys/client/publicKey"));

    let test_associate = load("test-associate.json");
    let response = session.handle(&state, &test_associate["vectors"][0]["request"]["frame"]);
    assert_eq!(response["errorCode"], Value::Null, "test-associate: {response}");

    let response = session.handle(&state, &create["request"]["frame"]);
    assert_eq!(response["errorCode"], Value::Null, "set-login: {response}");

    let response_nonce = B64
        .decode(response["nonce"].as_str().expect("response nonce"))
        .expect("nonce base64");
    let plaintext = open(
        &decode(&fixture, "/keys/host/publicKey"),
        &decode(&fixture, "/keys/client/secretKey"),
        &response_nonce,
        response["message"].as_str().expect("encrypted reply"),
    )
    .expect("decrypt set-login reply");
    let reply: Value = serde_json::from_slice(&plaintext).expect("reply JSON");
    assert_eq!(reply["success"], "true");
    assert_eq!(reply["error"], "success");

    // The bridge saved synchronously before replying.
    assert!(bridge.take_changed(), "bridge must report a database change");
    {
        let snapshot = {
            let guard = database.lock().expect("database");
            snapshot_from_database(&guard)
        };
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].username, "alice@example.com");
    }
    drop(bridge);
    drop(state);

    // Reopen the file as a fresh process would (this is what the e2e CLI
    // assertion does) and check every field the protocol carried.
    let reopened = friendlypass::saveutil::open(&path, key).expect("reopen database");
    let entry = reopened
        .iter_all_entries()
        .find(|entry| entry.get(fields::URL) == expected["url"].as_str())
        .expect("entry with the submitted URL");
    assert_eq!(entry.get(fields::TITLE), Some("accounts.example.com"));
    assert_eq!(
        entry.get(fields::USERNAME),
        expected["login"].as_str()
    );
    assert_eq!(
        entry.get(fields::PASSWORD),
        expected["password"].as_str()
    );
}
