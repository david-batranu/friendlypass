//! Pairing contract §1: the app must answer host-level `ping` immediately even
//! while another request on the same connection is still waiting (association
//! approval, `set-login`). Before the reader/worker split both ran on one
//! thread, so a blocked `associate` starved the host's 1 s probes, the host
//! dropped the socket after two misses and the reply was lost.
//!
//! Each test drives the real server over a real Unix socket with a bridge that
//! blocks, and asserts every ping is answered in well under the host's 1 s
//! probe timeout while the action is still in flight.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use friendlypass_browser::bridge::{AssociationRequest, BrowserBridge, SetLoginRequest};
use friendlypass_browser::crypto::{increment_nonce, open, random_nonce, seal, KeyPair};
use friendlypass_browser::service::ServiceState;
use friendlypass_browser::{database_hash, start, SharedState};

const CLIENT_ID: &str = "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0";
const ASSOCIATION_ID: &str = "test-browser";
const DB_HASH: &str = "bb710c2f876761bb90748cc271ff8fae";
/// The host's probe budget is 1 s (`PROBE_TIMEOUT`); anything close to that
/// would risk a dropped connection.
const PING_BUDGET: Duration = Duration::from_millis(200);

/// A bridge whose interactive calls block for a configurable time, like the
/// GUI's approval dialog or a save dialog.
struct SlowBridge {
    /// How long `approve_association` waits before approving.
    approval: Duration,
    /// How long `apply_set_login` waits before reporting success.
    set_login: Duration,
}

impl BrowserBridge for SlowBridge {
    fn approve_association(&self, _request: &AssociationRequest) -> Option<String> {
        std::thread::sleep(self.approval);
        Some(ASSOCIATION_ID.to_owned())
    }

    fn request_unlock(&self) {}

    fn lock_database(&self) {}

    fn apply_set_login(&self, _request: &SetLoginRequest) -> bool {
        std::thread::sleep(self.set_login);
        true
    }
}

fn shared_state(bridge: SlowBridge) -> SharedState {
    let mut state = ServiceState {
        db_hash: database_hash(DB_HASH),
        ..Default::default()
    };
    state.set_bridge(Arc::new(bridge));
    Arc::new(Mutex::new(state))
}

/// A minimal app-socket client: raw concatenated JSON objects, like the host.
struct Client {
    stream: UnixStream,
    buffer: Vec<u8>,
}

impl Client {
    fn connect(path: &Path) -> Client {
        let stream = UnixStream::connect(path).expect("connect to browser server");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        Client {
            stream,
            buffer: Vec::new(),
        }
    }

    fn send(&mut self, value: &Value) {
        let body = serde_json::to_vec(value).expect("serialise request");
        self.stream.write_all(&body).expect("write request");
        self.stream.flush().expect("flush request");
    }

    /// Read one complete JSON object, or `None` on timeout/EOF.
    fn read_frame(&mut self, timeout: Duration) -> Option<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(frame) = self.take_frame() {
                return Some(frame);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let _ = self.stream.set_read_timeout(Some(deadline - now));
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => return None,
                Ok(n) => self.buffer.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return None;
                }
                Err(_) => return None,
            }
        }
    }

    fn take_frame(&mut self) -> Option<Value> {
        let start = self.buffer.iter().position(|&byte| byte == b'{')?;
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escape = false;
        for (index, &byte) in self.buffer.iter().enumerate().skip(start) {
            if escape {
                escape = false;
                continue;
            }
            match byte {
                b'\\' if in_string => escape = true,
                b'"' => in_string = !in_string,
                b'{' if !in_string => depth += 1,
                b'}' if !in_string => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        let raw: Vec<u8> = self.buffer.drain(..=index).collect();
                        return serde_json::from_slice(&raw).ok();
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// An established handshake: client keypair plus the app's session public key.
struct Session {
    client: Client,
    keypair: KeyPair,
    server_public: Vec<u8>,
    nonce: [u8; 24],
}

impl Session {
    fn open(path: &Path) -> Session {
        let mut client = Client::connect(path);
        let keypair = KeyPair::generate().expect("client keypair");
        let nonce = random_nonce();
        client.send(&json!({
            "action": "change-public-keys",
            "publicKey": B64.encode(keypair.public),
            "nonce": B64.encode(nonce),
            "clientID": CLIENT_ID,
        }));
        let reply = client
            .read_frame(Duration::from_secs(5))
            .expect("change-public-keys reply");
        assert_eq!(reply["action"], "change-public-keys");
        assert_eq!(reply["success"], "true");
        let server_public = B64
            .decode(reply["publicKey"].as_str().expect("server public key"))
            .expect("server public key base64");
        assert_eq!(server_public.len(), 32);
        Session {
            client,
            keypair,
            server_public,
            nonce: increment_nonce(&nonce),
        }
    }

    fn client_public_b64(&self) -> String {
        B64.encode(self.keypair.public)
    }

    /// Seal and send one encrypted request, advancing the request nonce.
    fn send_encrypted(&mut self, inner: &Value) {
        let plaintext = serde_json::to_vec(inner).expect("serialise inner request");
        let sealed = seal(
            &self.server_public,
            &self.keypair.secret,
            &self.nonce,
            &plaintext,
        )
        .expect("seal request");
        self.client.send(&json!({
            "action": inner["action"],
            "message": sealed,
            "nonce": B64.encode(self.nonce),
            "clientID": CLIENT_ID,
            "triggerUnlock": "true",
        }));
        self.nonce = increment_nonce(&self.nonce);
    }

    fn decrypt(&self, response: &Value) -> Value {
        let nonce = B64
            .decode(response["nonce"].as_str().expect("response nonce"))
            .expect("response nonce base64");
        let message = response["message"].as_str().expect("response message");
        let plaintext = open(&self.server_public, &self.keypair.secret, &nonce, message)
            .expect("decrypt response");
        serde_json::from_slice(&plaintext).expect("inner response JSON")
    }

    /// Send a `ping` and assert it is answered inside [`PING_BUDGET`].
    fn ping_quickly(&mut self, label: &str) {
        let nonce = format!("ping-{label}");
        let started = Instant::now();
        self.client.send(&json!({"action": "ping", "nonce": nonce}));
        let reply = self
            .client
            .read_frame(Duration::from_secs(2))
            .unwrap_or_else(|| panic!("{label}: no ping reply"));
        let elapsed = started.elapsed();
        assert_eq!(reply["action"], "ping", "{label}: unexpected frame {reply}");
        assert_eq!(reply["nonce"], nonce, "{label}: nonce not echoed");
        assert_eq!(reply["success"], "true");
        assert_eq!(reply["appRunning"], true);
        assert_eq!(reply["databaseHash"], database_hash(DB_HASH));
        assert!(
            elapsed < PING_BUDGET,
            "{label}: ping took {elapsed:?}, budget is {PING_BUDGET:?}"
        );
    }
}

fn temp_socket() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let path = dir.path().join("browser.sock");
    (dir, path)
}

#[test]
fn ping_is_answered_while_associate_waits() {
    let (_dir, socket) = temp_socket();
    let state = shared_state(SlowBridge {
        approval: Duration::from_secs(3),
        set_login: Duration::from_secs(0),
    });
    let server = start(&socket, Arc::clone(&state)).expect("start server");

    let mut session = Session::open(&socket);
    session.send_encrypted(&json!({
        "action": "associate",
        "key": session.client_public_b64(),
        "idKey": session.client_public_b64(),
    }));
    let sent = Instant::now();

    // The approval is still blocking: keep probing like the host does.
    for round in 0..15 {
        session.ping_quickly(&format!("associate-{round}"));
        std::thread::sleep(Duration::from_millis(120));
    }
    assert!(
        sent.elapsed() < Duration::from_secs(3),
        "the approval did not actually block"
    );

    let response = session
        .client
        .read_frame(Duration::from_secs(5))
        .expect("associate reply after the delay");
    assert_eq!(
        response["action"], "associate",
        "unexpected frame {response}"
    );
    assert!(
        sent.elapsed() >= Duration::from_secs(3),
        "associate replied before the approval delay elapsed"
    );
    let inner = session.decrypt(&response);
    assert_eq!(inner["success"], "true");
    assert_eq!(inner["id"], ASSOCIATION_ID);
    assert_eq!(inner["hash"], database_hash(DB_HASH));

    // The association really was stored, and the server is still responsive.
    assert!(state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .associations
        .contains_key(ASSOCIATION_ID));
    session.ping_quickly("after-associate");

    server.stop();
}

#[test]
fn ping_is_answered_while_set_login_waits() {
    let (_dir, socket) = temp_socket();
    let state = shared_state(SlowBridge {
        approval: Duration::from_secs(0),
        set_login: Duration::from_secs(2),
    });
    let server = start(&socket, Arc::clone(&state)).expect("start server");

    let mut session = Session::open(&socket);
    // Pre-associated, so `set-login` goes straight to the blocking bridge.
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .associations
        .insert(ASSOCIATION_ID.to_owned(), session.client_public_b64());

    session.send_encrypted(&json!({
        "action": "test-associate",
        "id": ASSOCIATION_ID,
        "key": session.client_public_b64(),
    }));
    let reply = session
        .client
        .read_frame(Duration::from_secs(5))
        .expect("test-associate reply");
    assert_eq!(session.decrypt(&reply)["success"], "true");

    session.send_encrypted(&json!({
        "action": "set-login",
        "id": ASSOCIATION_ID,
        "login": "alice@example.com",
        "password": "correct horse battery staple",
        "url": "https://accounts.example.com/login",
        "submitUrl": "https://accounts.example.com/login",
    }));
    let sent = Instant::now();

    for round in 0..10 {
        session.ping_quickly(&format!("set-login-{round}"));
        std::thread::sleep(Duration::from_millis(120));
    }
    assert!(
        sent.elapsed() < Duration::from_secs(2),
        "the save did not actually block"
    );

    let response = session
        .client
        .read_frame(Duration::from_secs(5))
        .expect("set-login reply after the delay");
    assert_eq!(
        response["action"], "set-login",
        "unexpected frame {response}"
    );
    assert!(
        sent.elapsed() >= Duration::from_secs(2),
        "set-login replied before the bridge delay elapsed"
    );
    let inner = session.decrypt(&response);
    assert_eq!(inner["success"], "true");
    assert_eq!(inner["error"], "success");

    server.stop();
}
