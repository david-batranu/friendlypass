//! The BrowserServer socket: listens where KeePassXC's `BrowserHost` does
//! (`<user temp dir>/org.keepassxc.KeePassXC.BrowserServer` on macOS), so the
//! shipped `keepassxc-proxy` — and through it the real browser extension —
//! can talk to this server. The socket carries raw compact JSON (one object
//! per message, coalesced objects handled like the C++ parser).
//!
//! Each connection thread owns its socket for writes; unsolicited pushes from
//! the GUI are delivered through a bounded channel so a slow browser can never
//! stall the application.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::peer::{verify_peer, PeerInfo};
use crate::protocol::{host_error_reply, HOST_ERROR_FRAME_TOO_LARGE, HOST_ERROR_MALFORMED_FRAME};
use crate::push::PushHub;
use crate::service::{lock_state, ClientSession, SharedState};

/// Maximum frame size in both directions (`BrowserShared::SOCKET_BUFFER_SIZE`,
/// also the friendlypass 1 MiB contract).
pub const MAX_FRAME: usize = 1024 * 1024;

/// How the server decides which socket peers to trust (contract §3).
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// Path of the native host binary that may be auto-approved, normally the
    /// GUI's `native_host_path` (running inside `friendlypass.app`, or the
    /// resolved development binary). `None` never trusts a peer.
    pub trusted_host_path: Option<PathBuf>,
}

/// How often a connection checks for queued push messages.
const PUSH_POLL: Duration = Duration::from_millis(200);

/// The KeePassXC BrowserServer socket path (macOS form, like BrowserShared).
///
/// `FP_APP_SOCKET` overrides the path for tests and for a relocated app. The
/// native host derives its app link from this same function, so setting the
/// variable is sufficient to keep both ends of the app socket in sync and
/// guarantees tests never touch the user's real socket.
pub fn browser_server_path() -> PathBuf {
    if let Some(path) = std::env::var_os("FP_APP_SOCKET") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    let temp = user_temp_dir();
    temp.join("org.keepassxc.KeePassXC.BrowserServer")
}

/// The per-user temporary directory, matching the C++ `getUserTemporaryDirectory`
/// (confstr(_CS_DARWIN_USER_TEMP_DIR) on macOS).
pub fn user_temp_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // confstr(_CS_DARWIN_USER_TEMP_DIR) == $TMPDIR on macOS.
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let mut p = PathBuf::from(tmpdir);
            if p.ends_with("/") && p.as_os_str().len() > 1 {
                p.pop();
            }
            return p;
        }
    }
    std::env::temp_dir()
}

/// A running browser-protocol server.
pub struct ServerHandle {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    push: Arc<PushHub>,
}

impl ServerHandle {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Broadcast one unencrypted push frame to every connected client.
    pub fn broadcast(&self, frame: &Value) {
        self.push.broadcast(frame);
    }

    /// The push hub, for the GUI's lock/unlock/changed notifications.
    pub fn push_hub(&self) -> Arc<PushHub> {
        Arc::clone(&self.push)
    }

    pub fn client_count(&self) -> usize {
        self.push.client_count()
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking `accept` so the listener thread can observe stop.
        if let Ok(stream) = UnixStream::connect(&self.path) {
            drop(stream);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Start serving the browser protocol on `path`.
///
/// A live server at `path` is never stolen: if another process answers the
/// socket the call fails. A stale socket file is replaced. Without a
/// [`ServerConfig`] no peer is ever trusted (the manual approval path only).
pub fn start(path: &std::path::Path, state: SharedState) -> Result<ServerHandle> {
    start_with_config(path, ServerConfig::default(), state)
}

/// Start serving with peer verification (§3).
pub fn start_with_config(
    path: &std::path::Path,
    config: ServerConfig,
    state: SharedState,
) -> Result<ServerHandle> {
    if UnixStream::connect(path).is_ok() {
        bail!(
            "a browser protocol server is already listening on {}",
            path.display()
        );
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("cannot bind browser server socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    let push = {
        let guard = lock_state(&state);
        Arc::clone(&guard.push)
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let path_owned = path.to_path_buf();
    let push_thread = Arc::clone(&push);
    let trusted_host_path = config.trusted_host_path;

    let thread = std::thread::Builder::new()
        .name("friendlypass-browser".into())
        .spawn(move || {
            for stream in listener.incoming() {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { break };
                // Identify the peer before the connection thread starts: the
                // Kernel/Security queries are cheap and the result must be
                // fixed for the connection's lifetime (§3).
                let peer = verify_peer(&stream, trusted_host_path.as_deref());
                let state = Arc::clone(&state);
                let hub = Arc::clone(&push_thread);
                let conn_stop = Arc::clone(&stop_thread);
                let _ = std::thread::Builder::new()
                    .name("friendlypass-browser-conn".into())
                    .spawn(move || handle_connection(stream, &state, &hub, &conn_stop, peer));
            }
            let _ = std::fs::remove_file(&path_owned);
        })
        .context("cannot start browser server thread")?;

    Ok(ServerHandle {
        path: path.to_path_buf(),
        stop,
        thread: Some(thread),
        push,
    })
}

fn handle_connection(
    mut stream: UnixStream,
    state: &SharedState,
    hub: &Arc<PushHub>,
    stop: &Arc<AtomicBool>,
    peer: PeerInfo,
) {
    let _ = stream.set_read_timeout(Some(PUSH_POLL));
    // A peer that stops reading must not wedge a connection thread forever.
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let (client_id, pushes) = hub.register();
    let mut session = ClientSession::new().with_peer(peer);
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        // Deliver queued unsolicited frames between reads. A write failure
        // means the peer is gone; drop the registration and exit.
        while let Some(frame) = pushes.try_recv() {
            if write_frame(&mut stream, &frame).is_err() {
                hub.unregister(client_id);
                return;
            }
        }

        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if !drain_frames(&mut stream, state, &mut session, &mut buffer) {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(_) => break,
        }
    }
    hub.unregister(client_id);
}

/// Handle every complete frame in `buffer`. Returns false when the connection
/// should close.
fn drain_frames(
    stream: &mut UnixStream,
    state: &SharedState,
    session: &mut ClientSession,
    buffer: &mut Vec<u8>,
) -> bool {
    while let Some(end) = find_json_end(buffer) {
        let raw: Vec<u8> = buffer.drain(..end).collect();
        if raw.len() > MAX_FRAME {
            let reply = host_error_reply("", HOST_ERROR_FRAME_TOO_LARGE, "Message exceeds the 1 MiB frame limit");
            if write_frame(stream, &reply).is_err() {
                return false;
            }
            continue;
        }
        let Some(request) = parse_one(&raw) else {
            let reply = host_error_reply("", HOST_ERROR_MALFORMED_FRAME, "Malformed frame");
            if write_frame(stream, &reply).is_err() {
                return false;
            }
            continue;
        };
        let response = session.handle(state, &request);
        if write_frame(stream, &response).is_err() {
            return false;
        }
    }

    if buffer.len() > MAX_FRAME {
        // A frame larger than the cap that never closes: answer once and
        // discard what we have rather than growing without bound.
        let reply = host_error_reply("", HOST_ERROR_FRAME_TOO_LARGE, "Message exceeds the 1 MiB frame limit");
        if write_frame(stream, &reply).is_err() {
            return false;
        }
        buffer.clear();
    }
    true
}

fn write_frame(stream: &mut UnixStream, value: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    stream.write_all(&body)?;
    stream.flush()
}

/// Find the end index (exclusive) of the first complete top-level JSON
/// object in the buffer, if any.
fn find_json_end(buffer: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    let mut started = false;
    for (i, &b) in buffer.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        match b {
            b'\\' if in_string => escape = true,
            b'"' if started => in_string = !in_string,
            b'{' if !in_string => {
                depth += 1;
                started = true;
            }
            b'}' if !in_string && started => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_one(raw: &[u8]) -> Option<Value> {
    // Ignore leading garbage, like the C++ parser.
    let start = raw.iter().position(|&b| b == b'{')?;
    serde_json::from_slice(&raw[start..]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_end_finder() {
        assert_eq!(find_json_end(br#"{"a":1}"#), Some(7));
        assert_eq!(find_json_end(br#"{ "a": "}" }"#), Some(12));
        assert_eq!(find_json_end(br#"{"a":1"#), None);
        assert_eq!(find_json_end(br#"garbage{"a":1}"#), Some(14));
        assert_eq!(find_json_end(br#"{} {}"#), Some(2));
    }

    #[test]
    fn state_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<crate::service::ServiceState>();
    }

    mod auto_approve {
        use super::*;
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use serde_json::{json, Value};

        use crate::bridge::{AssociationRequest, BrowserBridge, SetLoginRequest};
        use crate::crypto::{increment_nonce, open, random_nonce, seal, KeyPair};
        use crate::peer::verify_peer;
        use crate::server::{start_with_config, write_frame, ServerConfig, ServerHandle};
        use crate::service::lock_state;

        /// A bridge that records every approval request and applies the
        /// contract §5 policy: with the setting off, trusted+verified
        /// associations are approved without a dialog.
        #[derive(Default)]
        struct RecordingBridge {
            /// `true` = the "Require approval for new browsers" setting is on.
            require_approval: bool,
            requests: Mutex<Vec<AssociationRequest>>,
        }

        impl BrowserBridge for RecordingBridge {
            fn approve_association(&self, request: &AssociationRequest) -> Option<String> {
                self.requests
                    .lock()
                    .unwrap()
                    .push(request.clone());
                Some(
                    crate::bridge::auto_approve_name(request, self.require_approval)
                        .unwrap_or_else(|| "manual-approval".to_owned()),
                )
            }

            fn request_unlock(&self) {}

            fn lock_database(&self) {}

            fn apply_set_login(&self, _request: &SetLoginRequest) -> bool {
                false
            }
        }

        struct TestClient {
            stream: UnixStream,
            keypair: KeyPair,
            host_public: Vec<u8>,
            client_id: String,
        }

        impl TestClient {
            fn connect(path: &std::path::Path) -> TestClient {
                let mut stream = UnixStream::connect(path).expect("connect to test server");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                let keypair = KeyPair::generate().expect("client keypair");
                let nonce = random_nonce();
                let client_id = B64.encode([7u8; 24]);
                write_frame(
                    &mut stream,
                    &json!({
                        "action": "change-public-keys",
                        "publicKey": B64.encode(keypair.public),
                        "nonce": B64.encode(nonce),
                        "clientID": client_id,
                    }),
                )
                .expect("handshake frame");
                let reply = read_frame(&mut stream);
                assert_eq!(reply["success"], "true", "{reply}");
                assert_eq!(reply["nonce"], B64.encode(increment_nonce(&nonce)));
                let host_public = B64
                    .decode(reply["publicKey"].as_str().expect("publicKey"))
                    .expect("host key");
                TestClient {
                    stream,
                    keypair,
                    host_public,
                    client_id,
                }
            }

            fn host_identify(&mut self, verified: bool) -> Value {
                write_frame(
                    &mut self.stream,
                    &json!({
                        "action": "host-identify",
                        "hostVersion": "0.1.0",
                        "browser": {
                            "kind": "chrome",
                            "verified": verified,
                            "executable": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                            "teamId": "EQHXZ8M8AV",
                        },
                    }),
                )
                .expect("host-identify frame");
                read_frame(&mut self.stream)
            }

            /// Run `associate` and return the decrypted inner response.
            fn associate(&mut self) -> Value {
                let nonce = random_nonce();
                let identification = KeyPair::generate().expect("identification key");
                let inner = json!({
                    "action": "associate",
                    "key": B64.encode(self.keypair.public),
                    "idKey": B64.encode(identification.public),
                });
                let sealed = seal(
                    &self.host_public,
                    &self.keypair.secret,
                    &nonce,
                    &serde_json::to_vec(&inner).expect("inner json"),
                )
                .expect("seal");
                write_frame(
                    &mut self.stream,
                    &json!({
                        "action": "associate",
                        "message": sealed,
                        "nonce": B64.encode(nonce),
                        "clientID": self.client_id,
                    }),
                )
                .expect("associate frame");
                let reply = read_frame(&mut self.stream);
                assert_eq!(reply["action"], "associate", "{reply}");
                let message = reply["message"].as_str().unwrap_or_else(|| {
                    panic!("associate returned an error frame: {reply}")
                });
                let plaintext = open(
                    &self.host_public,
                    &self.keypair.secret,
                    &increment_nonce(&nonce),
                    message,
                )
                .expect("decrypt associate reply");
                serde_json::from_slice(&plaintext).expect("inner associate reply")
            }
        }

        fn read_frame(stream: &mut UnixStream) -> Value {
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let read = stream.read(&mut chunk).expect("read from test server");
                assert!(read > 0, "server closed the connection");
                buffer.extend_from_slice(&chunk[..read]);
                if let Ok(value) = serde_json::from_slice(&buffer) {
                    return value;
                }
            }
        }

        fn server_state(bridge: Arc<dyn BrowserBridge>) -> SharedState {
            let mut state = crate::service::ServiceState {
                db_hash: "bb710c2f876761bb90748cc271ff8fae".into(),
                ..Default::default()
            };
            state.set_bridge(bridge);
            Arc::new(Mutex::new(state))
        }

        fn start_test_server(
            dir: &tempfile::TempDir,
            config: ServerConfig,
            bridge: Arc<dyn BrowserBridge>,
        ) -> (std::path::PathBuf, ServerHandle, SharedState) {
            let path = dir.path().join("browser.sock");
            let state = server_state(bridge);
            let handle = start_with_config(&path, config, Arc::clone(&state)).expect("start server");
            (path, handle, state)
        }

        /// Whether this machine can verify code identities for the running
        /// test binary (macOS ad-hoc signing). Unsigned builds cannot be
        /// trusted by design, so the trusted-path tests are skipped there.
        fn environment_supports_code_identity() -> bool {
            let (ours, _peer) = UnixStream::pair().expect("socketpair");
            let exe = std::env::current_exe().expect("current_exe");
            verify_peer(&ours, Some(&exe)).trusted
        }

        #[test]
        fn untrusted_peer_is_not_trusted_and_is_not_auto_approved() {
            let dir = tempfile::tempdir().expect("tempdir");
            let bridge = Arc::new(RecordingBridge::default());
            let (path, handle, state) =
                start_test_server(&dir, ServerConfig::default(), bridge.clone());

            let mut client = TestClient::connect(&path);
            let identify = client.host_identify(true);
            assert_eq!(identify["action"], "host-identify");
            assert_eq!(identify["success"], "true");
            assert_eq!(
                identify["trusted"], false,
                "no trusted host path is configured"
            );

            let reply = client.associate();
            assert_eq!(reply["success"], "true");
            assert_eq!(
                reply["id"], "manual-approval",
                "an untrusted peer always takes the approval path"
            );
            let requests = bridge.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert!(!requests[0].auto_approvable, "untrusted peers are never auto-approvable");
            assert_eq!(
                requests[0].browser, None,
                "browser claims from an untrusted peer are ignored"
            );
            drop(requests);
            assert_eq!(lock_state(&state).associations.len(), 1);
            drop(handle);
        }

        #[test]
        fn trusted_verified_browser_is_auto_approved_with_the_setting_off() {
            if !environment_supports_code_identity() {
                eprintln!("test binary has no verifiable code signature; skipping");
                return;
            }
            let dir = tempfile::tempdir().expect("tempdir");
            let exe = std::env::current_exe().expect("current_exe");
            let bridge = Arc::new(RecordingBridge::default());
            let (path, handle, _state) = start_test_server(
                &dir,
                ServerConfig {
                    trusted_host_path: Some(exe),
                },
                bridge.clone(),
            );

            let mut client = TestClient::connect(&path);
            let identify = client.host_identify(true);
            assert_eq!(identify["trusted"], true, "{identify}");

            let reply = client.associate();
            assert_eq!(reply["success"], "true");
            let id = reply["id"].as_str().expect("association id");
            assert!(id.starts_with("Chrome · "), "{id}");
            let suffix = id.trim_start_matches("Chrome · ");
            assert_eq!(suffix.len(), 4);
            assert!(suffix.chars().all(|ch| ch.is_ascii_hexdigit()));

            let requests = bridge.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].auto_approvable);
            assert_eq!(
                requests[0].browser.as_ref().map(|browser| browser.kind.as_str()),
                Some("chrome")
            );
            assert_eq!(Some(id), crate::bridge::auto_approve_name(&requests[0], false).as_deref());
            drop(requests);
            drop(handle);
        }

        #[test]
        fn require_approval_setting_forces_the_dialog_path() {
            if !environment_supports_code_identity() {
                eprintln!("test binary has no verifiable code signature; skipping");
                return;
            }
            let dir = tempfile::tempdir().expect("tempdir");
            let exe = std::env::current_exe().expect("current_exe");
            let bridge = Arc::new(RecordingBridge {
                require_approval: true,
                ..Default::default()
            });
            let (path, handle, _state) = start_test_server(
                &dir,
                ServerConfig {
                    trusted_host_path: Some(exe),
                },
                bridge.clone(),
            );

            let mut client = TestClient::connect(&path);
            assert_eq!(client.host_identify(true)["trusted"], true);
            let reply = client.associate();
            assert_eq!(reply["id"], "manual-approval");
            let requests = bridge.requests.lock().unwrap();
            assert!(requests[0].auto_approvable, "trust itself still holds");
            assert_eq!(
                crate::bridge::auto_approve_name(&requests[0], true),
                None,
                "the setting routes the decision to the dialog"
            );
            drop(requests);
            drop(handle);
        }

        #[test]
        fn unverified_browser_on_a_trusted_peer_is_not_auto_approved() {
            if !environment_supports_code_identity() {
                eprintln!("test binary has no verifiable code signature; skipping");
                return;
            }
            let dir = tempfile::tempdir().expect("tempdir");
            let exe = std::env::current_exe().expect("current_exe");
            let bridge = Arc::new(RecordingBridge::default());
            let (path, handle, _state) = start_test_server(
                &dir,
                ServerConfig {
                    trusted_host_path: Some(exe),
                },
                bridge.clone(),
            );

            let mut client = TestClient::connect(&path);
            assert_eq!(client.host_identify(false)["trusted"], true);
            let reply = client.associate();
            assert_eq!(reply["id"], "manual-approval");
            let requests = bridge.requests.lock().unwrap();
            assert!(!requests[0].auto_approvable);
            drop(requests);
            drop(handle);
        }
    }
}
