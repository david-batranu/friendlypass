//! The friendlypass browser-integration socket
//! (`<user temp dir>/org.friendlypass.BrowserServer` on macOS). It speaks the
//! same raw compact-JSON framing the KeePassXC protocol uses (one object per
//! message, coalesced objects handled like the C++ parser) so the friendlypass
//! extension and host can talk to this server.
//!
//! Each connection has one reader loop and one worker thread that share a
//! single writer, so frames never interleave. The reader answers host-level
//! `ping` immediately — liveness must never wait for an action the worker is
//! still processing (pairing contract §1). Every other request is handed to
//! the worker in arrival order; it owns the connection's [`ClientSession`].
//! Unsolicited pushes from the GUI arrive through a bounded channel and are
//! written by the reader, so a slow browser can never stall the application.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::peer::verify_peer;
use crate::push::PushHub;
use crate::server_core::handle_connection;
use crate::service::{lock_state, SharedState};

pub use crate::server_core::MAX_FRAME;

/// How the server decides which socket peers to trust (contract §3).
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// Path of the native host binary that may be auto-approved, normally the
    /// GUI's `native_host_path` (running inside `friendlypass.app`, or the
    /// resolved development binary). `None` never trusts a peer.
    pub trusted_host_path: Option<PathBuf>,
}

/// File name of the friendlypass browser-integration socket in the user's
/// temporary directory.
pub const SOCKET_FILE_NAME: &str = "org.friendlypass.BrowserServer";

/// The friendlypass browser-integration socket path.
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
    default_browser_server_path()
}

/// The default path, ignoring `FP_APP_SOCKET`.
fn default_browser_server_path() -> PathBuf {
    user_temp_dir().join(SOCKET_FILE_NAME)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<crate::service::ServiceState>();
    }

    #[test]
    fn default_socket_path_is_friendlypass_branded() {
        assert_eq!(SOCKET_FILE_NAME, "org.friendlypass.BrowserServer");
        let path = default_browser_server_path();
        assert_eq!(path.parent(), Some(user_temp_dir().as_path()));
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(SOCKET_FILE_NAME)
        );
        let rendered = path.to_string_lossy().to_lowercase();
        assert!(rendered.contains("friendlypass"), "{rendered}");
        assert!(!rendered.contains("keepassxc"), "{rendered}");
    }

    mod auto_approve {
        use super::*;
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use serde_json::{json, Value};

        use crate::bridge::{AssociationRequest, BrowserBridge, SetLoginRequest};
        use crate::crypto::{increment_nonce, open, random_nonce, seal, KeyPair};
        use crate::peer::verify_peer;
        use crate::server::{start_with_config, ServerConfig, ServerHandle};
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
                self.requests.lock().unwrap().push(request.clone());
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

        fn write_test_frame(stream: &mut UnixStream, value: &Value) -> std::io::Result<()> {
            stream.write_all(&serde_json::to_vec(value).map_err(std::io::Error::other)?)?;
            stream.flush()
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
                write_test_frame(
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
                write_test_frame(
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
                write_test_frame(
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
                let message = reply["message"]
                    .as_str()
                    .unwrap_or_else(|| panic!("associate returned an error frame: {reply}"));
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
            let handle =
                start_with_config(&path, config, Arc::clone(&state)).expect("start server");
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
            assert!(
                !requests[0].auto_approvable,
                "untrusted peers are never auto-approvable"
            );
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
                requests[0]
                    .browser
                    .as_ref()
                    .map(|browser| browser.kind.as_str()),
                Some("chrome")
            );
            assert_eq!(
                Some(id),
                crate::bridge::auto_approve_name(&requests[0], false).as_deref()
            );
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
