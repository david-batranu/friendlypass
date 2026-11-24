//! Golden-vector action tests (WP7a).
//!
//! Drives the *real* `ClientSession`/`ServiceState` with the exact outer
//! frames from `protocol/fixtures/*.json` and checks the responses against
//! `protocol/ACTIONS.md`:
//!
//! * `errorCode` is a string and error replies have no nonce/message;
//! * encrypted responses use the request nonce incremented by one;
//! * `get-databasehash` returns the server's own 64-hex hash;
//! * `get-logins` credentials are plaintext (never Base64);
//! * `get-database-groups` is nested `{groups:{groups:[…]}}`;
//! * `set-login` reports the operation in the inner `error` field;
//! * pushes (`database-locked`) are emitted to connected clients.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use friendlypass_browser::bridge::{AssociationRequest, BrowserBridge, SetLoginRequest};
use friendlypass_browser::crypto::{increment_nonce, open, KeyPair};
use friendlypass_browser::service::{ClientSession, CredentialEntry, GroupNode, ServiceState};
use friendlypass_browser::{database_hash, SharedState};

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

fn b64(value: &Value, pointer: &str) -> Vec<u8> {
    let text = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {pointer}"));
    B64.decode(text).unwrap_or_else(|error| panic!("{pointer}: {error}"))
}

struct Fixture {
    document: Value,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        Fixture { document: load(name) }
    }

    fn host_keypair(&self) -> KeyPair {
        KeyPair::from_secret(&b64(&self.document, "/keys/host/secretKey")).unwrap()
    }

    fn client_public(&self) -> Vec<u8> {
        b64(&self.document, "/keys/client/publicKey")
    }

    fn session(&self) -> ClientSession {
        let mut session = ClientSession::with_keypair(self.host_keypair());
        session.accept_client_key(self.client_public());
        session
    }

    fn state(&self) -> SharedState {
        let root = self.document["database"]["rootGroupUuid"]
            .as_str()
            .unwrap_or_default();
        let state = ServiceState {
            db_hash: database_hash(root),
            ..Default::default()
        };
        Arc::new(Mutex::new(state))
    }

    fn vector(&self, name: &str) -> &Value {
        self.document["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap_or_else(|| panic!("vector {name} missing"))
    }

    /// Decrypt an encrypted outer response with the fixture client key.
    fn decrypt(&self, response: &Value) -> Value {
        let nonce = B64
            .decode(response["nonce"].as_str().expect("response nonce"))
            .unwrap();
        let message = response["message"].as_str().expect("response message");
        let plaintext = open(
            &b64(&self.document, "/keys/host/publicKey"),
            &b64(&self.document, "/keys/client/secretKey"),
            &nonce,
            message,
        )
        .expect("decrypt response");
        serde_json::from_slice(&plaintext).expect("response JSON")
    }

    fn assert_common(&self, request: &Value, response: &Value, plaintext: &Value) {
        let request_nonce = B64.decode(request["nonce"].as_str().unwrap()).unwrap();
        let response_nonce = B64.decode(response["nonce"].as_str().unwrap()).unwrap();
        assert_eq!(
            response_nonce,
            increment_nonce(&request_nonce),
            "response nonce must be request nonce + 1"
        );
        assert_eq!(plaintext["version"], "2.8.0");
        assert_eq!(plaintext["success"], "true");
        assert_eq!(
            plaintext["nonce"].as_str().unwrap(),
            response["nonce"].as_str().unwrap()
        );
    }
}

#[derive(Default)]
struct RecordingBridge {
    approval_id: Mutex<Option<String>>,
    logins: Mutex<Vec<SetLoginRequest>>,
    locked: AtomicBool,
    unlock_requested: AtomicBool,
}

impl RecordingBridge {
    fn approving(id: &str) -> Self {
        RecordingBridge {
            approval_id: Mutex::new(Some(id.to_owned())),
            ..Default::default()
        }
    }

    fn last_login(&self) -> Option<SetLoginRequest> {
        self.logins.lock().unwrap().last().cloned()
    }
}

impl BrowserBridge for RecordingBridge {
    fn approve_association(&self, _request: &AssociationRequest) -> Option<String> {
        self.approval_id.lock().unwrap().clone()
    }

    fn request_unlock(&self) {
        self.unlock_requested.store(true, Ordering::SeqCst);
    }

    fn lock_database(&self) {
        self.locked.store(true, Ordering::SeqCst);
    }

    fn apply_set_login(&self, request: &SetLoginRequest) -> bool {
        self.logins.lock().unwrap().push(request.clone());
        true
    }
}

fn seed_association(state: &SharedState, id: &str, key: &str) {
    state
        .lock()
        .unwrap()
        .associations
        .insert(id.to_owned(), key.to_owned());
}

/// Run the canonical `test-associate` golden frame so the connection is
/// associated. All fixtures share the same fixed keys.
fn associate(_fixture: &Fixture, session: &mut ClientSession, state: &SharedState) {
    let canonical = Fixture::new("test-associate.json");
    let vector = canonical.vector("test-associate/known-key");
    let response = session.handle(state, &vector["request"]["frame"]);
    assert_eq!(
        response["errorCode"],
        Value::Null,
        "test-associate failed: {response}"
    );
}

#[test]
fn fixture_database_hash_matches_keepassxc_formula() {
    let fixture = Fixture::new("get-databasehash.json");
    let root = fixture.document["database"]["rootGroupUuid"].as_str().unwrap();
    let expected = fixture.document["database"]["databaseHash"].as_str().unwrap();
    assert_eq!(database_hash(root), expected);
    assert_eq!(expected.len(), 64);
}

#[test]
fn get_databasehash_uses_server_hash_not_client_hash() {
    let fixture = Fixture::new("get-databasehash.json");
    for (index, vector) in fixture.document["vectors"].as_array().unwrap().iter().enumerate() {
        let state = fixture.state();
        let mut session = fixture.session();
        let request = &vector["request"]["frame"];
        let response = session.handle(&state, request);
        let plaintext = fixture.decrypt(&response);
        fixture.assert_common(request, &response, &plaintext);
        let expected = fixture.document["database"]["databaseHash"].as_str().unwrap();
        assert_eq!(plaintext["hash"], expected);
        if index == 0 {
            assert!(
                request["message"].as_str().is_some(),
                "the client sends no `hash`; the server injects its own"
            );
            assert!(request["hash"].is_null());
        }
    }
}

#[test]
fn associate_uses_user_approval_and_returns_chosen_id() {
    let fixture = Fixture::new("associate.json");
    for vector in fixture.document["vectors"].as_array().unwrap() {
        let expected_id = vector["response"]["plaintext"]["id"].as_str().unwrap();
        let state = fixture.state();
        state
            .lock()
            .unwrap()
            .set_bridge(Arc::new(RecordingBridge::approving(expected_id)));
        let mut session = fixture.session();
        let request = &vector["request"]["frame"];
        let response = session.handle(&state, request);
        assert_eq!(response["errorCode"], Value::Null, "associate failed: {response}");
        let plaintext = fixture.decrypt(&response);
        assert_eq!(plaintext["id"], expected_id);
        assert_eq!(
            plaintext["hash"],
            fixture.document["database"]["databaseHash"].as_str().unwrap()
        );
        // The association is stored for later `test-associate` / `get-logins`.
        assert!(state.lock().unwrap().associations.contains_key(expected_id));
    }
}

#[test]
fn associate_denied_returns_error_6() {
    let fixture = Fixture::new("associate.json");
    let vector = fixture.vector("associate/new-association");
    let state = fixture.state();
    state
        .lock()
        .unwrap()
        .set_bridge(Arc::new(RecordingBridge::default()));
    let mut session = fixture.session();
    let response = session.handle(&state, &vector["request"]["frame"]);
    assert_eq!(response["errorCode"], "6");
    assert!(response.get("nonce").is_none());
}

#[test]
fn get_logins_returns_plaintext_credentials() {
    let fixture = Fixture::new("get-logins.json");
    let state = fixture.state();
    let mut session = fixture.session();
    let identity = B64.encode(b64(&fixture.document, "/keys/identity/publicKey"));
    seed_association(&state, "chrome-work-laptop", &identity);
    associate(&fixture, &mut session, &state);

    for vector in fixture.document["vectors"].as_array().unwrap() {
        let request = &vector["request"]["frame"];
        let request_plain = &vector["request"]["plaintext"];
        let url = request_plain["url"].as_str().unwrap();
        {
            let mut state = state.lock().unwrap();
            state.entries.clear();
            // Seed from the fixture's expected entries so the assertion can
            // compare every documented field deterministically.
            for entry in vector["response"]["plaintext"]["entries"]
                .as_array()
                .unwrap()
            {
                state.entries.push(CredentialEntry {
                    title: entry["name"].as_str().unwrap_or_default().to_owned(),
                    username: entry["login"].as_str().unwrap_or_default().to_owned(),
                    password: entry["password"].as_str().unwrap_or_default().to_owned(),
                    url: url.to_owned(),
                    uuid: entry["uuid"].as_str().unwrap_or_default().to_owned(),
                    group: entry["group"].as_str().unwrap_or_default().to_owned(),
                    group_uuid: "17a19761914f9005f195c781475d37be".into(),
                    expired: entry.get("expired").is_some(),
                    skip_auto_submit: entry
                        .get("skipAutoSubmit")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    string_fields: entry
                        .get("stringFields")
                        .and_then(Value::as_array)
                        .map(|fields| {
                            fields
                                .iter()
                                .flat_map(|field| {
                                    field.as_object().map(|object| {
                                        object
                                            .iter()
                                            .map(|(key, value)| {
                                                (key.clone(), value.as_str().unwrap_or_default().to_owned())
                                            })
                                            .collect::<Vec<_>>()
                                    })
                                })
                                .flatten()
                                .collect()
                        })
                        .unwrap_or_default(),
                    ..Default::default()
                });
            }
        }

        let response = session.handle(&state, request);
        assert_eq!(
            response["errorCode"],
            Value::Null,
            "get-logins failed for {}: {response}",
            vector["name"]
        );
        let plaintext = fixture.decrypt(&response);
        fixture.assert_common(request, &response, &plaintext);
        let expected = &vector["response"]["plaintext"];
        assert_eq!(plaintext["count"], expected["count"]);
        assert_eq!(plaintext["hash"], expected["hash"]);
        assert_eq!(plaintext["id"], expected["id"]);
        let actual_entries = plaintext["entries"].as_array().unwrap();
        let expected_entries = expected["entries"].as_array().unwrap();
        assert_eq!(actual_entries.len(), expected_entries.len());
        for (actual, expected) in actual_entries.iter().zip(expected_entries) {
            for field in ["login", "password", "name", "uuid", "group"] {
                assert_eq!(actual[field], expected[field], "field {field} must be plaintext");
            }
            if expected.get("expired").is_some() {
                assert_eq!(actual["expired"], "true");
            }
            if let Some(skip) = expected.get("skipAutoSubmit") {
                assert_eq!(actual["skipAutoSubmit"], *skip);
            }
            if let Some(fields) = expected.get("stringFields") {
                assert_eq!(actual["stringFields"], *fields);
            }
            // Credentials must never be Base64 of themselves.
            if let Some(login) = actual["login"].as_str() {
                assert_ne!(
                    login,
                    B64.encode(login.as_bytes()),
                    "login must not be Base64"
                );
            }
        }
    }
}

#[test]
fn get_database_groups_is_nested_and_recycle_free() {
    let fixture = Fixture::new("get-database-groups.json");
    let vector = &fixture.document["vectors"][0];
    let expected = &vector["response"]["plaintext"]["groups"]["groups"];
    let state = fixture.state();
    let mut session = fixture.session();
    let identity = B64.encode(b64(&fixture.document, "/keys/identity/publicKey"));
    seed_association(&state, "chrome-work-laptop", &identity);
    associate(&fixture, &mut session, &state);
    {
        let mut state = state.lock().unwrap();
        state.groups = expected
            .as_array()
            .unwrap()
            .iter()
            .map(node_from_json)
            .collect();
    }

    let request = &vector["request"]["frame"];
    let response = session.handle(&state, request);
    let plaintext = fixture.decrypt(&response);
    fixture.assert_common(request, &response, &plaintext);
    assert_eq!(plaintext["groups"]["groups"], *expected);
}

fn node_from_json(value: &Value) -> GroupNode {
    GroupNode {
        name: value["name"].as_str().unwrap_or_default().to_owned(),
        uuid: value["uuid"].as_str().unwrap_or_default().to_owned(),
        children: value["children"]
            .as_array()
            .map(|children| children.iter().map(node_from_json).collect())
            .unwrap_or_default(),
    }
}

#[test]
fn set_login_passes_plaintext_to_the_gui_and_reports_inner_error() {
    let fixture = Fixture::new("set-login.json");
    for vector in fixture.document["vectors"].as_array().unwrap() {
        let state = fixture.state();
        let bridge = Arc::new(RecordingBridge::approving("chrome-work-laptop"));
        state.lock().unwrap().set_bridge(bridge.clone());
        let mut session = fixture.session();
        let identity = B64.encode(b64(&fixture.document, "/keys/identity/publicKey"));
        seed_association(&state, "chrome-work-laptop", &identity);
        associate(&fixture, &mut session, &state);

        let request = &vector["request"]["frame"];
        let expected = &vector["request"]["plaintext"];
        let response = session.handle(&state, request);
        assert_eq!(response["errorCode"], Value::Null, "set-login failed: {response}");
        let plaintext = fixture.decrypt(&response);
        fixture.assert_common(request, &response, &plaintext);
        assert_eq!(plaintext["count"], Value::Null);
        assert_eq!(plaintext["entries"], Value::Null);
        assert_eq!(plaintext["error"], "success");
        assert_eq!(
            plaintext["hash"],
            fixture.document["database"]["databaseHash"].as_str().unwrap()
        );

        let written = bridge.last_login().expect("bridge received set-login");
        assert_eq!(written.login, expected["login"].as_str().unwrap());
        assert_eq!(written.password, expected["password"].as_str().unwrap());
        assert_eq!(written.url, expected["url"].as_str().unwrap());
    }
}

#[test]
fn set_login_rejects_references_with_error_34() {
    let fixture = Fixture::new("errors.json");
    let vector = fixture
        .document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "error/cannot-use-references")
        .unwrap();
    let state = fixture.state();
    state
        .lock()
        .unwrap()
        .set_bridge(Arc::new(RecordingBridge::approving("chrome-work-laptop")));
    let mut session = fixture.session();
    let identity = B64.encode(b64(&fixture.document, "/keys/identity/publicKey"));
    seed_association(&state, "chrome-work-laptop", &identity);
    associate(&fixture, &mut session, &state);
    let response = session.handle(&state, &vector["request"]["frame"]);
    assert_eq!(response["errorCode"], "34");
    assert!(response.get("nonce").is_none());
}

#[test]
fn get_totp_returns_a_code_and_rejects_bad_uuid() {
    let fixture = Fixture::new("get-totp.json");
    let vector = &fixture.document["vectors"][0];
    let state = fixture.state();
    let mut session = fixture.session();
    let identity = B64.encode(b64(&fixture.document, "/keys/identity/publicKey"));
    seed_association(&state, "chrome-work-laptop", &identity);
    associate(&fixture, &mut session, &state);
    {
        let mut state = state.lock().unwrap();
        state.entries.push(CredentialEntry {
            title: "TOTP".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://accounts.example.com/".into(),
            uuid: "d5ec68c35705b72fde380bd469aa149f".into(),
            group: "KeePassXC-Browser Passwords".into(),
            group_uuid: "17a19761914f9005f195c781475d37be".into(),
            totp_url: Some(
                "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30"
                    .into(),
            ),
            ..Default::default()
        });
    }
    let request = &vector["request"]["frame"];
    let response = session.handle(&state, request);
    let plaintext = fixture.decrypt(&response);
    fixture.assert_common(request, &response, &plaintext);
    let code = plaintext["totp"].as_str().unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|ch| ch.is_ascii_digit()));

    // Bad UUID -> error 18, from the error fixture.
    let errors = Fixture::new("errors.json");
    let bad = errors
        .document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "error/no-valid-uuid")
        .unwrap();
    let response = session.handle(&state, &bad["request"]["frame"]);
    assert_eq!(response["errorCode"], "18");
}

#[test]
fn lock_database_locks_and_broadcasts_a_push() {
    let fixture = Fixture::new("lock-database.json");
    let vector = &fixture.document["vectors"][0];
    let state = fixture.state();
    let bridge = Arc::new(RecordingBridge::approving("chrome-work-laptop"));
    state.lock().unwrap().set_bridge(bridge.clone());
    let mut session = fixture.session();
    let identity = B64.encode(b64(&fixture.document, "/keys/identity/publicKey"));
    seed_association(&state, "chrome-work-laptop", &identity);
    associate(&fixture, &mut session, &state);

    let (client_id, pushes) = state.lock().unwrap().push.register();
    let request = &vector["request"]["frame"];
    let response = session.handle(&state, request);
    let plaintext = fixture.decrypt(&response);
    fixture.assert_common(request, &response, &plaintext);
    assert_eq!(plaintext.as_object().unwrap().len(), 3, "common prefix only");
    assert!(bridge.locked.load(Ordering::SeqCst), "GUI asked to lock");
    assert!(state.lock().unwrap().locked);
    let push = pushes.try_recv().expect("database-locked push");
    assert_eq!(push["action"], "database-locked");
    state.lock().unwrap().push.unregister(client_id);
}

#[test]
fn generate_password_returns_a_password() {
    let fixture = Fixture::new("generate-password.json");
    let vector = &fixture.document["vectors"][0];
    let state = fixture.state();
    let mut session = fixture.session();
    let identity = B64.encode(b64(&fixture.document, "/keys/identity/publicKey"));
    seed_association(&state, "chrome-work-laptop", &identity);
    associate(&fixture, &mut session, &state);
    let request = &vector["request"]["frame"];
    let response = session.handle(&state, request);
    let plaintext = fixture.decrypt(&response);
    fixture.assert_common(request, &response, &plaintext);
    let password = plaintext["password"].as_str().unwrap();
    assert_eq!(password.chars().count(), 24);
}

#[test]
fn fixture_error_frames_match_error_shapes() {
    let fixture = Fixture::new("errors.json");
    for vector in fixture.document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let expected = &vector["response"]["frame"];
        if expected.get("hostError").is_some() || vector["request"].is_null() {
            // Host-level errors are WP1's; app errors are below.
            continue;
        }
        let state = fixture.state();
        let mut session = fixture.session();
        match name {
            "error/database-not-opened" => {
                state.lock().unwrap().locked = true;
            }
            "error/database-hash-not-received" => {
                state.lock().unwrap().db_hash.clear();
                seed_association_for_errors(&fixture, &state);
                associate(&fixture, &mut session, &state);
            }
            "error/client-public-key-not-received" => {
                let mut bare = ClientSession::with_keypair(fixture.host_keypair());
                let response = bare.handle(&state, &vector["request"]["frame"]);
                assert_error_shape(&response, expected);
                continue;
            }
            "error/cannot-decrypt-message" => {
                // Wrong host key: decryption must fail closed.
                let mut wrong = ClientSession::with_keypair(KeyPair::generate().unwrap());
                wrong.accept_client_key(fixture.client_public());
                let response = wrong.handle(&state, &vector["request"]["frame"]);
                assert_error_shape(&response, expected);
                continue;
            }
            "error/association-failed" => {
                // No association stored.
            }
            "error/no-url-provided" | "error/no-logins-found" => {
                seed_association_for_errors(&fixture, &state);
                associate(&fixture, &mut session, &state);
            }
            "error/no-valid-uuid" => {
                seed_association_for_errors(&fixture, &state);
                associate(&fixture, &mut session, &state);
            }
            "error/cannot-use-references" => {
                seed_association_for_errors(&fixture, &state);
                state
                    .lock()
                    .unwrap()
                    .set_bridge(Arc::new(RecordingBridge::approving("chrome-work-laptop")));
                associate(&fixture, &mut session, &state);
            }
            other => panic!("unhandled error fixture {other}"),
        }
        let response = session.handle(&state, &vector["request"]["frame"]);
        assert_error_shape(&response, expected);
    }
}

fn seed_association_for_errors(fixture: &Fixture, state: &SharedState) {
    let identity = B64.encode(b64(&fixture.document, "/keys/identity/publicKey"));
    seed_association(state, "chrome-work-laptop", &identity);
}

fn assert_error_shape(response: &Value, expected: &Value) {
    assert_eq!(response["action"], expected["action"]);
    assert_eq!(response["errorCode"], expected["errorCode"]);
    assert_eq!(response["error"], expected["error"]);
    assert!(response.get("nonce").is_none(), "errors carry no nonce");
    assert!(response.get("message").is_none(), "errors are unencrypted");
    assert!(response.get("hostError").is_none(), "app errors are not host errors");
}

#[test]
fn ping_and_hello_are_answered_by_the_app() {
    let state: SharedState = Arc::new(Mutex::new(ServiceState {
        locked: true,
        ..Default::default()
    }));
    let mut session = ClientSession::new();
    let ping = session.handle(&state, &json!({"action": "ping", "nonce": "abc"}));
    assert_eq!(ping["action"], "ping");
    assert_eq!(ping["success"], "true");
    assert_eq!(ping["protocolVersion"], 1);
    assert_eq!(ping["nonce"], "abc");
    assert_eq!(ping["appRunning"], true);
    assert_eq!(ping["locked"], true);
    let hello = session.handle(&state, &json!({"action": "hello"}));
    assert_eq!(hello["action"], "hello");
    assert_eq!(hello["protocolVersion"], 1);
    assert!(hello["sessionId"].as_str().is_some());
    assert!(hello["hostPid"].as_i64().unwrap() > 0);
    assert!(hello.get("nonce").is_none());
}

#[test]
fn entry_matching_is_ordered_and_honours_http_auth_flags() {
    let mut state = ServiceState::default();
    let entry = |title: &str, url: &str, http_only: bool, not_http: bool| CredentialEntry {
        title: title.into(),
        username: "u".into(),
        password: "p".into(),
        url: url.into(),
        uuid: "d5ec68c35705b72fde380bd469aa149f".into(),
        group: "Group".into(),
        http_only,
        not_http_auth: not_http,
        ..Default::default()
    };
    state.entries = vec![
        entry("subdomain", "https://accounts.example.com/login", false, false),
        entry("root", "https://example.com/", false, false),
        entry("http-only", "https://example.com/login", true, false),
        entry("not-http", "https://example.com/login", false, true),
    ];

    let form = state.find_entries("https://example.com/login", None, false);
    let titles: Vec<&str> = form.iter().map(|entry| entry.title.as_str()).collect();
    assert_eq!(titles, ["not-http", "root", "subdomain"]);
    assert!(!titles.contains(&"http-only"));

    let auth = state.find_entries("https://example.com/login", None, true);
    let titles: Vec<&str> = auth.iter().map(|entry| entry.title.as_str()).collect();
    assert!(!titles.contains(&"not-http"));
}
