//! `passkeys-register` / `passkeys-get` integration tests (ACTIONS.md §4.12).
//!
//! The tests drive the real `ClientSession` and the real `FileBridge`:
//!
//! * a passkey entry written in KeePassXC's `KPEX_PASSKEY_*` format (the exact
//!   field names and protected flags from upstream) is usable for
//!   `passkeys-get`;
//! * a credential registered by the new code parses back as a KeePassXC
//!   passkey and its assertion signature verifies with the public key from the
//!   registration response;
//! * `excludeCredentials`, RP-id mismatches, cancelled prompts and invalid
//!   origins produce the KeePassXC error codes, in the same inner/outer shape.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use keepass::{Database, DatabaseKey};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use pkcs8::DecodePublicKey as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use friendlypass_browser::crypto::{increment_nonce, open, random_nonce, seal, KeyPair};
use friendlypass_browser::service::ClientSession;
use friendlypass_browser::{snapshot_from_database, DenyAllBridge, FileBridge, SharedState};
use friendlypass_passkey::{StoredPasskey, ES256};

const ORIGIN: &str = "https://example.com";
const ASSOCIATION_ID: &str = "test-association";

struct Client {
    host: KeyPair,
    client: KeyPair,
    id_key: Vec<u8>,
    session: ClientSession,
    state: SharedState,
}

impl Client {
    fn new(db: &Database, bridge: Option<Arc<dyn friendlypass_browser::BrowserBridge>>) -> Client {
        let host = KeyPair::generate().unwrap();
        let client = KeyPair::generate().unwrap();
        let id_key = KeyPair::generate().unwrap().public.to_vec();
        let mut state = snapshot_from_database(db);
        state.allow_localhost_passkeys = true;
        state
            .associations
            .insert(ASSOCIATION_ID.to_owned(), B64.encode(&id_key));
        if let Some(bridge) = bridge {
            state.set_bridge(bridge);
        }
        let mut session = ClientSession::with_keypair(host.clone());
        session.accept_client_key(client.public.to_vec());
        let mut client = Client {
            host,
            client,
            id_key,
            session,
            state: Arc::new(Mutex::new(state)),
        };
        client.associate();
        client
    }

    /// Send one encrypted action and return the decrypted inner response. An
    /// outer error frame is returned unchanged (it has `errorCode` at top
    /// level and no `response`).
    fn call(&mut self, action: &str, inner: Value) -> Value {
        let nonce = random_nonce();
        let plaintext = serde_json::to_vec(&inner).unwrap();
        let message = seal(
            &self.host.public,
            &self.client.secret,
            &nonce,
            &plaintext,
        )
        .unwrap();
        let request = json!({
            "action": action,
            "message": message,
            "nonce": B64.encode(nonce),
            "clientID": B64.encode([9u8; 24]),
        });
        let response = self.session.handle(&self.state, &request);
        if let Some(ciphertext) = response.get("message").and_then(Value::as_str) {
            let plaintext = open(
                &self.host.public,
                &self.client.secret,
                &increment_nonce(&nonce),
                ciphertext,
            )
            .expect("decrypt passkey reply");
            serde_json::from_slice(&plaintext).expect("inner reply JSON")
        } else {
            response
        }
    }

    fn associate(&mut self) {
        let reply = self.call(
            "test-associate",
            json!({
                "action": "test-associate",
                "id": ASSOCIATION_ID,
                "key": B64.encode(&self.id_key),
            }),
        );
        assert!(reply.get("errorCode").is_none(), "association failed: {reply}");
    }

    fn register(&mut self, options: Value) -> Value {
        self.call(
            "passkeys-register",
            json!({
                "action": "passkeys-register",
                "publicKey": options,
                "origin": ORIGIN,
                "groupName": "Passkeys",
            }),
        )
    }

    fn get(&mut self, options: Value) -> Value {
        self.call(
            "passkeys-get",
            json!({
                "action": "passkeys-get",
                "publicKey": options,
                "origin": ORIGIN,
            }),
        )
    }
}

fn challenge() -> String {
    B64.encode([7u8; 32])
}

fn registration_options(user: &[u8], username: &str) -> Value {
    json!({
        "challenge": challenge(),
        "pubKeyCredParams": [{"type": "public-key", "alg": ES256}],
        "rp": {"id": "example.com", "name": "Example"},
        "user": {
            "id": friendlypass_passkey::b64url_encode(user),
            "name": username,
            "displayName": username,
        },
        "timeout": 60000,
    })
}

fn assertion_options(credential_id: &str) -> Value {
    json!({
        "challenge": challenge(),
        "rpId": "example.com",
        "allowCredentials": [{
            "type": "public-key",
            "id": credential_id,
            "transports": ["internal"],
        }],
    })
}

/// Build a database entry in KeePassXC's on-disk format (field names, protected
/// flags and the default BE/BS `1` flags), as `BrowserService::addPasskeyToEntry`
/// writes it.
fn database_with_kpxc_passkey() -> (Database, StoredPasskey, Vec<u8>) {
    let registration =
        friendlypass_passkey::register("example.com", "alice@example.com", b"kpxc-user", &[ES256])
            .unwrap();
    let public_key = registration.public_key_spki_der.clone();
    let passkey = registration.passkey;
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Example (Passkey)");
        entry.set_unprotected("UserName", "alice@example.com");
        entry.set_unprotected("URL", ORIGIN);
        for field in passkey.to_fields() {
            if field.protected {
                entry.set_protected(field.name, field.value);
            } else {
                entry.set_unprotected(field.name, field.value);
            }
        }
    }
    (db, passkey, public_key)
}

fn verify_assertion(credential: &Value, public_key_der_b64: &str) {
    let response = &credential["response"];
    let auth_data = B64
        .decode(response["authenticatorData"].as_str().unwrap())
        .unwrap();
    let client_data = B64
        .decode(response["clientDataJSON"].as_str().unwrap())
        .unwrap();
    let signature = B64.decode(response["signature"].as_str().unwrap()).unwrap();

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));

    let spki = B64.decode(public_key_der_b64).unwrap();
    let key = VerifyingKey::from_public_key_der(&spki).expect("ES256 SPKI");
    let signature = Signature::from_der(&signature).expect("DER ECDSA signature");
    key.verify(&signed, &signature)
        .expect("assertion signature verifies with the registration public key");

    // The RP-id hash in authData must be SHA-256("example.com").
    assert_eq!(&auth_data[..32], Sha256::digest(b"example.com").as_slice());
}

#[test]
fn a_kpxc_formatted_passkey_is_usable_for_passkeys_get() {
    let (db, passkey, public_key) = database_with_kpxc_passkey();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.kdbx");
    let database = Arc::new(Mutex::new(db));
    let bridge = Arc::new(FileBridge::new(
        "test",
        Arc::clone(&database),
        DatabaseKey::new().with_password("test"),
        path,
    ));
    let mut client = {
        let db = database.lock().unwrap();
        Client::new(
            &db,
            Some(bridge as Arc<dyn friendlypass_browser::BrowserBridge>),
        )
    };

    let credential_id = friendlypass_passkey::b64url_encode(&passkey.credential_id);
    let reply = client.get(assertion_options(&credential_id));
    let credential = &reply["response"];
    assert_eq!(credential["id"], credential_id, "{reply}");
    assert_eq!(
        credential["response"]["userHandle"],
        friendlypass_passkey::b64url_encode(b"kpxc-user")
    );
    // The assertion came from the KeePassXC-format entry; verify it with the
    // public key that belongs to that entry's stored private key.
    verify_assertion(credential, &B64.encode(public_key));
}

#[test]
fn register_then_get_round_trips_and_verifies_the_signature() {
    let (db, _kpxc, _key) = database_with_kpxc_passkey();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.kdbx");
    let database = Arc::new(Mutex::new(db));
    let bridge = Arc::new(FileBridge::new(
        "test",
        Arc::clone(&database),
        DatabaseKey::new().with_password("test"),
        path.clone(),
    ));
    let mut client = {
        let db = database.lock().unwrap();
        Client::new(
            &db,
            Some(bridge as Arc<dyn friendlypass_browser::BrowserBridge>),
        )
    };

    let reply = client.register(registration_options(b"new-user", "bob@example.com"));
    let credential = &reply["response"];
    assert!(credential["id"].as_str().is_some(), "registration failed: {reply}");
    let credential_id = credential["id"].as_str().unwrap();
    let public_key = credential["response"]["publicKey"].as_str().unwrap();
    assert_eq!(credential["response"]["publicKeyAlgorithm"], ES256);

    // The saved entry is parsed by friendlypass-passkey as a KeePassXC passkey.
    {
        let db = database.lock().unwrap();
        let entry = db
            .iter_all_entries()
            .find(|entry| {
                friendlypass_passkey::StoredPasskey::from_fields(|key: &str| {
                    entry.get(key).map(str::to_owned)
                })
                .is_some_and(|passkey| {
                    friendlypass_passkey::b64url_encode(&passkey.credential_id) == credential_id
                })
            })
            .expect("registered entry saved");
        let stored = StoredPasskey::from_fields(|key: &str| entry.get(key).map(str::to_owned)).unwrap();
        assert_eq!(stored.rp_id, "example.com");
        assert_eq!(stored.username, "bob@example.com");
        assert_eq!(stored.user_handle, b"new-user");
        assert_eq!(entry.get("KPEX_PASSKEY_FLAG_BE"), Some("1"));
        assert_eq!(entry.get("KPEX_PASSKEY_FLAG_BS"), Some("1"));
        assert_eq!(entry.get("KPEX_PASSKEY_RELYING_PARTY"), Some("example.com"));
        assert_eq!(entry.get("URL"), Some(ORIGIN));
        assert_eq!(entry.parent().name, "Passkeys");
        assert!(entry.tags.iter().any(|tag| tag == "Passkey"));
    }

    // The test_server snapshot is refreshed from the database before the next
    // action (the headless loop does the same); emulate that for `get`.
    {
        let db = database.lock().unwrap();
        let snapshot = snapshot_from_database(&db);
        let mut state = client.state.lock().unwrap();
        state.passkeys = snapshot.passkeys;
        state.entries = snapshot.entries;
    }

    let reply = client.get(assertion_options(credential_id));
    let assertion = &reply["response"];
    assert_eq!(assertion["id"], credential_id);
    assert_eq!(
        assertion["response"]["userHandle"],
        friendlypass_passkey::b64url_encode(b"new-user")
    );
    verify_assertion(assertion, public_key);
}

#[test]
fn excluded_credentials_rp_mismatch_and_cancel_return_keepassxc_codes() {
    let (db, kpxc, _key) = database_with_kpxc_passkey();
    let dir = tempfile::tempdir().unwrap();
    let database = Arc::new(Mutex::new(db));
    let bridge = Arc::new(FileBridge::new(
        "test",
        Arc::clone(&database),
        DatabaseKey::new().with_password("test"),
        dir.path().join("db.kdbx"),
    ));
    let mut client = {
        let db = database.lock().unwrap();
        Client::new(
            &db,
            Some(bridge as Arc<dyn friendlypass_browser::BrowserBridge>),
        )
    };

    let mut options = registration_options(b"new-user", "bob@example.com");
    options["excludeCredentials"] = json!([{
        "type": "public-key",
        "id": friendlypass_passkey::b64url_encode(&kpxc.credential_id),
    }]);
    let reply = client.register(options);
    assert_eq!(reply["response"]["errorCode"], 21, "{reply}");

    let mut options = registration_options(b"new-user", "bob@example.com");
    options["rp"]["id"] = json!("evil.example.net");
    let reply = client.register(options);
    assert_eq!(reply["response"]["errorCode"], 28, "{reply}");

    // A bridge that refuses everything (no GUI) cancels with error 22.
    let mut cancelling = {
        let db = database.lock().unwrap();
        Client::new(
            &db,
            Some(Arc::new(DenyAllBridge) as Arc<dyn friendlypass_browser::BrowserBridge>),
        )
    };
    let credential_id = friendlypass_passkey::b64url_encode(&kpxc.credential_id);
    let reply = cancelling.get(assertion_options(&credential_id));
    assert_eq!(reply["response"]["errorCode"], 22, "{reply}");

    // Outer errors, exactly like BrowserAction.
    let reply = client.call(
        "passkeys-get",
        json!({"action": "passkeys-get", "publicKey": {}, "origin": ORIGIN}),
    );
    assert_eq!(reply["errorCode"], "24", "{reply}");
    let reply = client.call(
        "passkeys-get",
        json!({
            "action": "passkeys-get",
            "publicKey": assertion_options(&credential_id),
            "origin": "http://example.com",
        }),
    );
    assert_eq!(reply["errorCode"], "25", "{reply}");
}

#[test]
fn allow_credentials_without_a_match_returns_no_logins() {
    let (db, _kpxc, _key) = database_with_kpxc_passkey();
    let mut client = Client::new(&db, None);
    let unknown = friendlypass_passkey::b64url_encode(&[3u8; 32]);
    let reply = client.get(assertion_options(&unknown));
    assert_eq!(reply["response"]["errorCode"], 15, "{reply}");
}

