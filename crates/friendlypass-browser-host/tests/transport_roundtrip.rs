//! End-to-end: the real `friendlypass-browser-host` over the real platform
//! transport (Unix domain socket on Unix, named pipe on Windows) and the real
//! protocol server.
//!
//! This is the cross-platform proof for the app link. It round-trips:
//!
//! 1. host-level `ping` (answered by the host, no app involvement);
//! 2. `change-public-keys` over the app link;
//! 3. an encrypted `test-associate`;
//! 4. an encrypted `get-logins`, checking plaintext credentials come back.
//!
//! `FP_APP_SOCKET` points both ends at a private test endpoint, so the real
//! user socket/pipe is never touched.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

use friendlypass_browser::crypto::{increment_nonce, open, random_nonce, seal, KeyPair};
use friendlypass_browser::service::{CredentialEntry, ServiceState};
use friendlypass_browser::{database_hash, SharedState};

const CLIENT_ID: &str = "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0";
const ASSOCIATION_ID: &str = "transport-test";
const DB_HASH: &str = "bb710c2f876761bb90748cc271ff8fae";
const LOGIN: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery staple";
const URL: &str = "https://accounts.example.com/login";

#[cfg(windows)]
static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A private app endpoint for this test: a socket file on Unix, a pipe name
/// on Windows.
struct Endpoint {
    _dir: Option<tempfile::TempDir>,
    path: PathBuf,
}

impl Endpoint {
    fn new() -> Self {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("browser.sock");
            Endpoint {
                _dir: Some(dir),
                path,
            }
        }
        #[cfg(windows)]
        {
            use std::sync::atomic::Ordering;
            let id = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = PathBuf::from(format!(
                r"\\.\pipe\friendlypass-transport-test-{}-{id}",
                std::process::id()
            ));
            Endpoint { _dir: None, path }
        }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

/// A running host binary with framed stdio.
struct HostProcess {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    frames: Receiver<Vec<u8>>,
}

impl HostProcess {
    fn spawn(endpoint: &Endpoint) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_friendlypass-browser-host"))
            .env("FP_APP_SOCKET", endpoint.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn friendlypass-browser-host");

        let stdin = child.stdin.take().expect("host stdin");
        let stdout = child.stdout.take().expect("host stdout");
        let (tx, frames) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = stdout;
            loop {
                let mut prefix = [0u8; 4];
                if stdout.read_exact(&mut prefix).is_err() {
                    break;
                }
                let length = u32::from_le_bytes(prefix) as usize;
                let mut payload = vec![0u8; length];
                if stdout.read_exact(&mut payload).is_err() {
                    break;
                }
                if tx.send(payload).is_err() {
                    break;
                }
            }
        });

        Self {
            child,
            stdin: Some(stdin),
            frames,
        }
    }

    fn send(&mut self, value: &Value) {
        let payload = serde_json::to_vec(value).expect("serialise frame");
        let stdin = self.stdin.as_mut().expect("host stdin open");
        stdin
            .write_all(&(payload.len() as u32).to_le_bytes())
            .expect("write frame length");
        stdin.write_all(&payload).expect("write frame");
        stdin.flush().expect("flush frame");
    }

    fn recv(&self, timeout: Duration) -> Value {
        let payload = self
            .frames
            .recv_timeout(timeout)
            .unwrap_or_else(|_| panic!("host produced no frame within {timeout:?}"));
        serde_json::from_slice(&payload).expect("host frame is JSON")
    }
}

impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn service_state(identification_key: &[u8]) -> SharedState {
    let mut state = ServiceState {
        db_hash: database_hash(DB_HASH),
        entries: vec![CredentialEntry {
            title: "Example account".into(),
            username: LOGIN.into(),
            password: PASSWORD.into(),
            url: URL.into(),
            uuid: "d5ec68c35705b72fde380bd469aa149f".into(),
            group: "Passwords".into(),
            group_uuid: "17a19761914f9005f195c781475d37be".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    state
        .associations
        .insert(ASSOCIATION_ID.to_owned(), B64.encode(identification_key));
    Arc::new(Mutex::new(state))
}

/// Run one encrypted request through the host and return the decrypted inner
/// response.
fn encrypted(
    host: &mut HostProcess,
    server_public: &[u8],
    client: &KeyPair,
    action: &str,
    inner: &Value,
) -> Value {
    let nonce = random_nonce();
    let plaintext = serde_json::to_vec(inner).expect("serialise inner request");
    let message = seal(server_public, &client.secret, &nonce, &plaintext).expect("seal");
    host.send(&json!({
        "action": action,
        "message": message,
        "nonce": B64.encode(nonce),
        "clientID": CLIENT_ID,
        "triggerUnlock": "true",
    }));
    let response = host.recv(Duration::from_secs(10));
    assert_eq!(response["action"], action, "{response}");
    let message = response["message"]
        .as_str()
        .unwrap_or_else(|| panic!("{action} returned an error frame: {response}"));
    let plaintext = open(
        server_public,
        &client.secret,
        &increment_nonce(&nonce),
        message,
    )
    .expect("decrypt response");
    serde_json::from_slice(&plaintext).expect("inner response JSON")
}

#[test]
fn host_and_server_round_trip_over_the_platform_transport() {
    let endpoint = Endpoint::new();
    let identification = KeyPair::generate().expect("identification key");
    let state = service_state(&identification.public);
    let server =
        friendlypass_browser::start(endpoint.path(), Arc::clone(&state)).expect("start app server");
    let mut host = HostProcess::spawn(&endpoint);

    // 1. Host-level ping is answered locally, even before the app is ready.
    host.send(&json!({"action": "ping", "nonce": "transport-ping"}));
    let ping = host.recv(Duration::from_secs(5));
    assert_eq!(ping["action"], "ping", "{ping}");
    assert_eq!(ping["success"], "true");
    assert_eq!(ping["protocolVersion"], 1);
    assert_eq!(ping["nonce"], "transport-ping");

    // 2. The unencrypted handshake crosses the host to the real server.
    let client = KeyPair::generate().expect("client keypair");
    let client_nonce = random_nonce();
    host.send(&json!({
        "action": "change-public-keys",
        "publicKey": B64.encode(client.public),
        "nonce": B64.encode(client_nonce),
        "clientID": CLIENT_ID,
    }));
    let handshake = host.recv(Duration::from_secs(10));
    assert_eq!(handshake["action"], "change-public-keys", "{handshake}");
    assert_eq!(handshake["success"], "true");
    assert_eq!(
        handshake["nonce"],
        B64.encode(increment_nonce(&client_nonce))
    );
    let server_public = B64
        .decode(handshake["publicKey"].as_str().expect("server public key"))
        .expect("server public key base64");
    assert_eq!(server_public.len(), 32);

    // 3. Encrypted association check.
    let associated = encrypted(
        &mut host,
        &server_public,
        &client,
        "test-associate",
        &json!({
            "action": "test-associate",
            "id": ASSOCIATION_ID,
            "key": B64.encode(identification.public),
        }),
    );
    assert_eq!(associated["success"], "true", "{associated}");
    assert_eq!(associated["hash"], database_hash(DB_HASH));

    // 4. Encrypted credentials come back in plaintext.
    let logins = encrypted(
        &mut host,
        &server_public,
        &client,
        "get-logins",
        &json!({
            "action": "get-logins",
            "id": ASSOCIATION_ID,
            "url": URL,
            "keys": [{"id": ASSOCIATION_ID, "key": B64.encode(identification.public)}],
        }),
    );
    assert_eq!(logins["success"], "true", "{logins}");
    assert_eq!(logins["count"], 1, "{logins}");
    assert_eq!(logins["entries"][0]["login"], LOGIN);
    assert_eq!(logins["entries"][0]["password"], PASSWORD);
    assert_eq!(logins["hash"], database_hash(DB_HASH));

    drop(host);
    server.stop();
}
