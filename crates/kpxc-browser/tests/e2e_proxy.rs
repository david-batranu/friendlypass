//! End-to-end verification against the REAL `keepassxc-proxy` binary from
//! the KeePassXC.app bundle — the same proxy the actual browser extension
//! launches.
//!
//! The proxy relays native-messaging frames (4-byte LE length + JSON) between
//! the browser and the BrowserServer socket. We start our protocol server at
//! the exact socket path KeePassXC uses, drive the REAL proxy over stdin,
//! and verify the complete protocol flow on stdout:
//!
//! 1. `change-public-keys` handshake (unencrypted, nonce-increment reply)
//! 2. `associate` (encrypted) — a new association id is issued
//! 3. `test-associate` (encrypted) — the association verifies
//! 4. `get-logins` (encrypted) — credentials for the URL are returned
//!    with base64-encoded login/password, exactly like KeePassXC

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use kpxc_browser::crypto::{increment_nonce, open, random_nonce, seal, KeyPair};
use kpxc_browser::service::{ClientSession, CredentialEntry, ServiceState};
use kpxc_browser::{database_hash, protocol as proto};

fn keepassxc_proxy() -> Option<PathBuf> {
    let path = PathBuf::from("/Applications/KeePassXC.app/Contents/MacOS/keepassxc-proxy");
    path.exists().then_some(path)
}

/// Native-messaging framed write (4-byte LE length + JSON).
fn write_native(child: &mut Child, value: &Value) {
    let body = serde_json::to_vec(value).unwrap();
    let stdin = child.stdin.as_mut().unwrap();
    stdin.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
    stdin.write_all(&body).unwrap();
    stdin.flush().unwrap();
}

/// Native-messaging framed read with a timeout.
fn read_native(child: &mut Child) -> Option<Value> {
    let stdout = child.stdout.take()?;
    let mut reader = std::io::BufReader::new(stdout);
    // (Re-insert for future reads.)
    let mut len = [0u8; 4];
    reader.read_exact(&mut len).ok()?;
    let len = u32::from_le_bytes(len) as usize;
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).ok()?;
    child.stdout = Some(reader.into_inner());
    serde_json::from_slice(&body).ok()
}

fn test_service_state() -> ServiceState {
    let mut state = ServiceState {
        db_hash: database_hash("2c91d8d5-456a-4f9c-9b76-62947c5b31d4"),
        ..Default::default()
    };
    state.entries.push(CredentialEntry {
        title: "Example Login".into(),
        username: "user@example.com".into(),
        password: "hunter2!".into(),
        url: "https://example.com/login".into(),
        uuid: "8e2b1a3f-1111-2222-3333-444455556666".into(),
    });
    state
}

#[test]
fn full_protocol_flow_through_the_real_keepassxc_proxy() {
    let Some(proxy_path) = keepassxc_proxy() else {
        // The proxy is shipped with KeePassXC.app; skip where absent.
        eprintln!("keepassxc-proxy not found; skipping");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    // The exact socket path the shipped proxy connects to.
    let socket = kpxc_browser::user_temp_dir().join("org.keepassxc.KeePassXC.BrowserServer");
    let _ = std::fs::remove_file(&socket);

    let state: Arc<Mutex<ServiceState>> = Arc::new(Mutex::new(test_service_state()));
    let server = kpxc_browser::start(&socket, Arc::clone(&state)).unwrap();

    // The REAL proxy: native messaging on stdin/stdout, socket upstream.
    let mut proxy = Command::new(&proxy_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn keepassxc-proxy");

    // --- 1. change-public-keys handshake (unencrypted) --------------------
    let client = KeyPair::generate().unwrap();
    let client_nonce = random_nonce();
    let handshake = json!({
        "action": "change-public-keys",
        "publicKey": B64.encode(client.public),
        "nonce": B64.encode(client_nonce),
        "triggerUnlock": "false",
    });
    write_native(&mut proxy, &handshake);

    let response = loop {
        match read_native(&mut proxy) {
            Some(v) => break v,
            None => panic!("no handshake response from the proxy"),
        }
    };
    assert_eq!(response["action"], "change-public-keys");
    assert_eq!(response["success"], "true", "proxy relayed our server's success");
    assert_eq!(response["publicKey"].as_str().unwrap().len(), 44, "server public key");
    // The nonce must be the request nonce incremented by one.
    let response_nonce = B64
        .decode(response["nonce"].as_str().unwrap())
        .unwrap();
    assert_eq!(response_nonce, increment_nonce(&client_nonce));
    let server_public: Vec<u8> = B64
        .decode(response["publicKey"].as_str().unwrap())
        .unwrap();

    // --- helper: encrypted request/response through the real proxy -------
    let db_hash = state.lock().unwrap().db_hash.clone();
    let mut request_nonce = increment_nonce(&client_nonce);

    let mut roundtrip = |inner: &Value| -> (Value, Option<Value>) {
        let nonce_b64 = B64.encode(request_nonce);
        let plaintext = serde_json::to_vec(inner).unwrap();
        let sealed = seal(&server_public, &client.secret, &request_nonce, &plaintext).unwrap();
        let frame = json!({
            "action": inner["action"],
            "message": sealed,
            "nonce": nonce_b64,
        });
        write_native(&mut proxy, &frame);
        let response = loop {
            match read_native(&mut proxy) {
                Some(v) => break v,
                None => panic!("no response from the proxy for {}", inner["action"]),
            }
        };
        // Advance the nonce for the next request (error replies carry none).
        if let Some(nonce) = response["nonce"].as_str() {
            let resp_nonce = B64.decode(nonce).unwrap();
            request_nonce = increment_nonce(&resp_nonce);
            if let Some(msg) = response["message"].as_str() {
                let decrypted = open(&server_public, &client.secret, &resp_nonce, msg).unwrap();
                return (response, Some(serde_json::from_slice(&decrypted).unwrap()));
            }
        }
        (response, None)
    };

    // --- 2. associate (encrypted) -----------------------------------------
    let associate_inner = json!({
        "action": "associate",
        "hash": db_hash,
        "key": B64.encode(client.public),
        "idKey": B64.encode(client.public),
    });
    let (raw, reply) = roundtrip(&associate_inner);
    let reply = reply.expect(&format!("encrypted reply: {raw}"));
    assert_eq!(reply["success"], "true", "association succeeded");
    let association_id = reply["id"].as_str().unwrap().to_owned();
    assert!(
        association_id.starts_with("KeePassXC-Browser_Identifier_"),
        "association id issued: {association_id}"
    );
    assert!(state
        .lock()
        .unwrap()
        .associations
        .contains_key(&association_id));

    // --- 3. test-associate (encrypted) ------------------------------------
    let test_inner = json!({
        "action": "test-associate",
        "hash": db_hash,
        "id": association_id,
        "key": B64.encode(client.public),
    });
    let (_raw, reply) = roundtrip(&test_inner);
    let reply = reply.unwrap();
    assert_eq!(reply["success"], "true", "test-associate verified");

    // --- 4. get-logins (encrypted) ----------------------------------------
    let get_logins_inner = json!({
        "action": "get-logins",
        "hash": db_hash,
        "id": association_id,
        "url": "https://example.com/login",
        "submitUrl": "https://example.com/login",
    });
    let (_raw2, reply) = roundtrip(&get_logins_inner);
    let reply = reply.unwrap();
    assert_eq!(reply["success"], "true");
    assert_eq!(reply["count"], 1, "one matching entry");
    let entries = reply["entries"].as_array().unwrap();
    assert_eq!(
        B64.decode(entries[0]["login"].as_str().unwrap()).unwrap(),
        b"user@example.com"
    );
    assert_eq!(
        B64.decode(entries[0]["password"].as_str().unwrap()).unwrap(),
        b"hunter2!"
    );
    assert_eq!(entries[0]["name"], "Example Login");

    // --- unknown action gets KeePassXC's error shape -----------------------
    let bogus = json!({"action": "not-a-real-action"});
    let (response, decrypted) = roundtrip(&bogus);
    assert!(decrypted.is_none(), "error replies are unencrypted");
    assert_eq!(response["errorCode"], proto::ERROR_INCORRECT_ACTION.to_string());
    assert_eq!(response["error"], "Incorrect action");

    let _ = proxy.kill();
    let _ = proxy.wait();
    server.stop();
    assert!(!socket.exists());
}

/// The service state machine itself (no proxy): direct JSON-level tests of
/// the action handling, mirroring the C++ behavior for edge cases.
#[test]
fn service_action_edge_cases() {
    let mut state = test_service_state();
    let mut session = ClientSession::new();

    // Encrypted action without a handshake -> client public key error.
    let err = session.handle(
        &mut state,
        &json!({"action": "get-logins", "message": "AAAA", "nonce": "AAAA"}),
    );
    assert_eq!(err["errorCode"], proto::ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED.to_string());

    // Handshake with a bad nonce -> error.
    let err = session.handle(
        &mut state,
        &json!({"action": "change-public-keys", "publicKey": "AAAA", "nonce": "AAAA"}),
    );
    assert_eq!(err["errorCode"], proto::ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED.to_string());

    // get-logins for an unrelated URL -> NO_LOGINS_FOUND (associated first).
    let client = KeyPair::generate().unwrap();
    let nonce = random_nonce();
    let handshake = json!({
        "action": "change-public-keys",
        "publicKey": B64.encode(client.public),
        "nonce": B64.encode(nonce),
    });
    let response = session.handle(&mut state, &handshake);
    assert_eq!(response["success"], "true");

    let server_public: Vec<u8> = B64
        .decode(response["publicKey"].as_str().unwrap())
        .unwrap();
    let inner = json!({
        "action": "associate",
        "hash": state.db_hash.clone(),
        "key": B64.encode(client.public),
        "idKey": B64.encode(client.public),
    });
    let sealed = seal(&server_public, &client.secret, &nonce, serde_json::to_vec(&inner).unwrap().as_slice()).unwrap();
    let response = session.handle(
        &mut state,
        &json!({"action": "associate", "message": sealed, "nonce": B64.encode(nonce)}),
    );
    eprintln!("DBG associate response: {response}");
    let resp_nonce = B64.decode(response["nonce"].as_str().unwrap()).unwrap();
    let decrypted = open(
        &server_public,
        &client.secret,
        &resp_nonce,
        response["message"].as_str().unwrap(),
    )
    .unwrap();
    let reply: Value = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(reply["success"], "true");
    assert!(reply["id"].as_str().unwrap().starts_with("KeePassXC-Browser_Identifier_"));

    // Now an unrelated URL.
    let inner = json!({
        "action": "get-logins",
        "hash": state.db_hash.clone(),
        "id": reply["id"].clone(),
        "url": "https://nowhere.example.org/",
    });
    let sealed = seal(&server_public, &client.secret, &resp_nonce, serde_json::to_vec(&inner).unwrap().as_slice()).unwrap();
    let response = session.handle(
        &mut state,
        &json!({"action": "get-logins", "message": sealed, "nonce": B64.encode(resp_nonce)}),
    );
    assert_eq!(response["errorCode"], proto::ERROR_NO_LOGINS_FOUND.to_string());
}
