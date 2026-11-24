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
//! 2. `associate` (encrypted) — an approved association id is issued
//! 3. `test-associate` (encrypted) — the association verifies
//! 4. `get-databasehash` (encrypted) — the server's own hash, never a client hash
//! 5. `get-logins` (encrypted) — **plaintext** credentials per ACTIONS.md
//!
//! Skipped (passes trivially) where KeePassXC.app is not installed.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use friendlypass_browser::crypto::{increment_nonce, open, random_nonce, seal, KeyPair};
use friendlypass_browser::service::{ClientSession, CredentialEntry, ServiceState};
use friendlypass_browser::{database_hash, protocol as proto, AutoApproveBridge};

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

/// Native-messaging framed read.
fn read_native(child: &mut Child) -> Option<Value> {
    let stdout = child.stdout.take()?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut len = [0u8; 4];
    let parsed = reader.read_exact(&mut len).ok().and_then(|()| {
        let len = u32::from_le_bytes(len) as usize;
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).ok()?;
        serde_json::from_slice(&body).ok()
    });
    child.stdout = Some(reader.into_inner());
    parsed
}

fn read_response(child: &mut Child, action: &str) -> Value {
    match read_native(child) {
        Some(value) => value,
        None => panic!("no response from the proxy for {action}"),
    }
}

fn test_service_state() -> ServiceState {
    let mut state = ServiceState {
        db_hash: database_hash("bb710c2f876761bb90748cc271ff8fae"),
        ..Default::default()
    };
    state.set_bridge(Arc::new(AutoApproveBridge::new("test-browser")));
    state.entries.push(CredentialEntry {
        title: "Example Login".into(),
        username: "user@example.com".into(),
        password: "hunter2!".into(),
        url: "https://example.com/login".into(),
        uuid: "d5ec68c35705b72fde380bd469aa149f".into(),
        group: "KeePassXC-Browser Passwords".into(),
        group_uuid: "17a19761914f9005f195c781475d37be".into(),
        ..Default::default()
    });
    state
}

#[test]
fn full_protocol_flow_through_the_real_keepassxc_proxy() {
    let Some(proxy_path) = keepassxc_proxy() else {
        eprintln!("keepassxc-proxy not found; skipping");
        return;
    };

    let socket = friendlypass_browser::user_temp_dir().join("org.keepassxc.KeePassXC.BrowserServer");
    let _ = std::fs::remove_file(&socket);

    let state: friendlypass_browser::SharedState =
        Arc::new(Mutex::new(test_service_state()));
    let server = friendlypass_browser::start(&socket, Arc::clone(&state)).unwrap();

    let mut proxy = Command::new(&proxy_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn keepassxc-proxy");

    // --- 1. change-public-keys handshake (unencrypted) --------------------
    let client = KeyPair::generate().unwrap();
    let client_nonce = random_nonce();
    write_native(
        &mut proxy,
        &json!({
            "action": "change-public-keys",
            "publicKey": B64.encode(client.public),
            "nonce": B64.encode(client_nonce),
            "clientID": "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0",
        }),
    );

    let response = read_response(&mut proxy, "change-public-keys");
    assert_eq!(response["action"], "change-public-keys");
    assert_eq!(response["success"], "true");
    assert_eq!(response["version"], "2.8.0");
    assert_eq!(
        response["publicKey"].as_str().unwrap().len(),
        44,
        "server public key"
    );
    let response_nonce = B64.decode(response["nonce"].as_str().unwrap()).unwrap();
    assert_eq!(response_nonce, increment_nonce(&client_nonce));
    let server_public: Vec<u8> = B64.decode(response["publicKey"].as_str().unwrap()).unwrap();

    // --- encrypted request/response through the real proxy ---------------
    let mut request_nonce = increment_nonce(&response_nonce);

    let mut roundtrip = |inner: &Value| -> (Value, Option<Value>) {
        let nonce_b64 = B64.encode(request_nonce);
        let plaintext = serde_json::to_vec(inner).unwrap();
        let sealed = seal(&server_public, &client.secret, &request_nonce, &plaintext).unwrap();
        write_native(
            &mut proxy,
            &json!({
                "action": inner["action"],
                "message": sealed,
                "nonce": nonce_b64,
                "clientID": "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0",
            }),
        );
        let response = read_response(&mut proxy, inner["action"].as_str().unwrap_or("?"));
        if let Some(nonce) = response["nonce"].as_str() {
            let resp_nonce = B64.decode(nonce).unwrap();
            request_nonce = increment_nonce(&resp_nonce);
            if let Some(message) = response["message"].as_str() {
                let decrypted = open(&server_public, &client.secret, &resp_nonce, message).unwrap();
                return (response, Some(serde_json::from_slice(&decrypted).unwrap()));
            }
        }
        (response, None)
    };

    // --- 2. associate (encrypted) -----------------------------------------
    let id_key = B64.encode(KeyPair::generate().unwrap().public);
    let (raw, reply) = roundtrip(&json!({
        "action": "associate",
        "key": B64.encode(client.public),
        "idKey": id_key,
    }));
    let reply = reply.unwrap_or_else(|| panic!("encrypted associate reply, got {raw}"));
    assert_eq!(reply["success"], "true");
    assert_eq!(reply["id"], "test-browser");
    assert_eq!(reply["hash"], state.lock().unwrap().db_hash);

    // --- 3. test-associate (encrypted) ------------------------------------
    let (_raw, reply) = roundtrip(&json!({
        "action": "test-associate",
        "id": "test-browser",
        "key": id_key,
    }));
    let reply = reply.expect("encrypted test-associate reply");
    assert_eq!(reply["success"], "true");
    assert_eq!(reply["hash"], state.lock().unwrap().db_hash);

    // --- 4. get-databasehash: the server's own hash, no client `hash` -----
    let (_raw, reply) = roundtrip(&json!({
        "action": "get-databasehash",
        "connectedKeys": [],
    }));
    let reply = reply.expect("encrypted get-databasehash reply");
    assert_eq!(reply["success"], "true");
    assert_eq!(reply["hash"], state.lock().unwrap().db_hash);
    assert_eq!(reply["hash"].as_str().unwrap().len(), 64, "64 lowercase hex");

    // --- 5. get-logins: PLAINTEXT credentials -----------------------------
    let (_raw, reply) = roundtrip(&json!({
        "action": "get-logins",
        "id": "test-browser",
        "url": "https://example.com/login",
        "submitUrl": "https://example.com/login",
        "keys": [{ "id": "test-browser", "key": id_key }],
    }));
    let reply = reply.expect("encrypted get-logins reply");
    assert_eq!(reply["success"], "true");
    assert_eq!(reply["count"], 1);
    let entries = reply["entries"].as_array().unwrap();
    assert_eq!(entries[0]["login"], "user@example.com");
    assert_eq!(entries[0]["password"], "hunter2!");
    assert_eq!(entries[0]["name"], "Example Login");
    assert_eq!(entries[0]["uuid"], "d5ec68c35705b72fde380bd469aa149f");
    assert_eq!(entries[0]["group"], "KeePassXC-Browser Passwords");

    // --- unknown action gets KeePassXC's error shape ----------------------
    let (response, decrypted) = roundtrip(&json!({"action": "not-a-real-action"}));
    assert!(decrypted.is_none(), "error replies are unencrypted");
    assert_eq!(response["errorCode"], proto::ERROR_INCORRECT_ACTION.to_string());
    assert_eq!(response["error"], "Incorrect action");
    assert!(response.get("nonce").is_none());

    let _ = proxy.kill();
    let _ = proxy.wait();
    server.stop();
    assert!(!socket.exists());
}

/// The service state machine itself (no proxy): JSON-level tests of the
/// handshake, locked state and error shapes.
#[test]
fn service_action_edge_cases() {
    let state: friendlypass_browser::SharedState = Arc::new(Mutex::new(test_service_state()));
    let mut session = ClientSession::new();

    // Encrypted action without a handshake -> client public key error.
    let err = session.handle(
        &state,
        &json!({"action": "get-logins", "message": "AAAA", "nonce": "AAAA"}),
    );
    assert_eq!(
        err["errorCode"],
        proto::ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED.to_string()
    );

    // Handshake with a bad nonce -> error 3, never a panic.
    let err = session.handle(
        &state,
        &json!({"action": "change-public-keys", "publicKey": "AAAA", "nonce": "AAAA"}),
    );
    assert_eq!(
        err["errorCode"],
        proto::ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED.to_string()
    );

    // A valid handshake resets the association flag.
    let client = KeyPair::generate().unwrap();
    let nonce = random_nonce();
    let response = session.handle(
        &state,
        &json!({
            "action": "change-public-keys",
            "publicKey": B64.encode(client.public),
            "nonce": B64.encode(nonce),
        }),
    );
    assert_eq!(response["success"], "true");
    assert_eq!(response["version"], "2.8.0");
    assert!(!session.is_associated());

    // A locked database answers every credential action with error 1.
    state.lock().unwrap().locked = true;
    let err = session.handle(
        &state,
        &json!({"action": "get-logins", "message": "AAAA", "nonce": "AAAA"}),
    );
    assert_eq!(
        err["errorCode"],
        proto::ERROR_DATABASE_NOT_OPENED.to_string()
    );

    // ping/hello stay available while locked and echo status.
    let ping = session.handle(&state, &json!({"action": "ping", "nonce": "abc"}));
    assert_eq!(ping["success"], "true");
    assert_eq!(ping["locked"], true);
    assert_eq!(ping["nonce"], "abc");
    assert!(ping["databaseHash"].is_null());
    let hello = session.handle(&state, &json!({"action": "hello"}));
    assert_eq!(hello["appRunning"], true);
    assert!(hello["sessionId"].as_str().unwrap().contains('-'));
}
