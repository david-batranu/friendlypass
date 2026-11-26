#![cfg(unix)]
//! Pairing contract §1 end-to-end: the REAL host binary against the headless
//! `test_server` app, with `FP_TEST_APPROVAL_DELAY_MS=5000`.
//!
//! While `associate` waits for approval the host keeps probing the app socket
//! once per second. If the app answered only after the worker finished, two
//! probes would time out, the host would drop the socket, settle the request
//! with error 5 and reconnect — the association would be stored but the reply
//! lost. This test proves the reply arrives and that neither happened:
//!
//! * browser `ping`s issued during the wait all report `appRunning: true`;
//! * `test_server`'s JSONL log shows exactly one client registration and no
//!   count going back to zero (i.e. no reconnect).

mod common;

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use friendlypass_browser::crypto::{open, random_nonce, seal, KeyPair};

use common::{wait_until, Host, TempRoot};

const CLIENT_ID: &str = "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0";
const APPROVAL_DELAY_MS: u64 = 5000;
const ASSOCIATION_ID: &str = "chrome-work-laptop";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// The `test_server` example binary, built on demand (it is not a target of
/// this package, so `cargo test -p friendlypass-browser-host` alone would
/// otherwise not have one).
fn test_server_binary() -> PathBuf {
    let root = workspace_root();
    let status = Command::new(option_env!("CARGO").unwrap_or("cargo"))
        .args([
            "build",
            "-p",
            "friendlypass-browser",
            "--example",
            "test_server",
        ])
        .current_dir(&root)
        .stdout(Stdio::null())
        .status()
        .expect("run cargo to build the test_server example");
    assert!(status.success(), "building test_server failed: {status:?}");

    let target = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => root.join("target"),
    };
    let binary = target.join("debug").join("examples").join("test_server");
    assert!(
        binary.exists(),
        "test_server not found at {}",
        binary.display()
    );
    binary
}

struct TestServer {
    child: Child,
}

impl TestServer {
    /// Start `test_server` on `socket` with the approval delay, logging to
    /// `log`.
    fn start(socket: &Path, log: &Path) -> TestServer {
        let child = Command::new(test_server_binary())
            .env("FP_APP_SOCKET", socket)
            .env("FP_TEST_APPROVAL_DELAY_MS", APPROVAL_DELAY_MS.to_string())
            .arg("--log")
            .arg(log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn test_server");
        let started = wait_until(Duration::from_secs(10), || socket.exists());
        assert!(started, "test_server never bound {}", socket.display());
        TestServer { child }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Every `client-count` value `test_server` logged, in order.
fn logged_client_counts(log: &Path) -> Vec<u64> {
    let file = std::fs::File::open(log)
        .unwrap_or_else(|error| panic!("open test_server log {}: {error}", log.display()));
    std::io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(&line).ok())
        .filter(|entry| entry["event"] == "client-count")
        .map(|entry| entry["count"].as_u64().unwrap_or_default())
        .collect()
}

#[test]
fn associate_reply_survives_the_approval_delay_without_reconnect() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let log = root.path().join("test_server.jsonl");
    let _server = TestServer::start(&socket, &log);

    let mut host = Host::spawn(root);

    // Wait until the host's status probe sees the app.
    let up = wait_until(Duration::from_secs(10), || {
        host.ping("startup")["appRunning"] == true
    });
    assert!(up, "host never reported the app as running");

    // --- handshake through the host (host-level ping never interferes) ---
    let client = KeyPair::generate().expect("client keypair");
    let handshake_nonce = random_nonce();
    host.send(&json!({
        "action": "change-public-keys",
        "publicKey": B64.encode(client.public),
        "nonce": B64.encode(handshake_nonce),
        "clientID": CLIENT_ID,
    }));
    let handshake = host.recv(Duration::from_secs(10));
    assert_eq!(handshake["action"], "change-public-keys", "{handshake}");
    assert_eq!(handshake["success"], "true", "{handshake}");
    let server_public = B64
        .decode(handshake["publicKey"].as_str().expect("server public key"))
        .expect("server public key base64");

    // --- associate: the app blocks for APPROVAL_DELAY_MS ------------------
    let nonce = random_nonce();
    let client_public = B64.encode(client.public);
    let inner = json!({
        "action": "associate",
        "key": client_public,
        "idKey": client_public,
    });
    let sealed = seal(
        &server_public,
        &client.secret,
        &nonce,
        &serde_json::to_vec(&inner).expect("serialise inner associate"),
    )
    .expect("seal associate");
    host.send(&json!({
        "action": "associate",
        "message": sealed,
        "nonce": B64.encode(nonce),
        "clientID": CLIENT_ID,
        "triggerUnlock": "true",
    }));
    let started = Instant::now();

    // Probe like the browser does while the approval waits. Any reconnection
    // or probe miss would show up as `appRunning: false` or terminate the
    // pending associate with a host error.
    let mut probes = 0u32;
    let response = loop {
        host.send(&json!({"action": "ping", "nonce": format!("during-{probes}")}));
        let frame = host.recv(Duration::from_secs(10));
        if frame["action"] == "associate" {
            break frame;
        }
        assert_eq!(frame["action"], "ping", "unexpected frame: {frame}");
        assert_eq!(
            frame["appRunning"], true,
            "host reported the app down while associate was pending: {frame}"
        );
        assert!(
            frame.get("errorCode").is_none(),
            "associate was settled early: {frame}"
        );
        probes += 1;
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "associate never returned"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    let elapsed = started.elapsed();

    assert_eq!(response["action"], "associate", "{response}");
    assert!(
        response.get("errorCode").is_none(),
        "associate failed after a reconnect: {response}"
    );
    assert!(
        elapsed >= Duration::from_millis(APPROVAL_DELAY_MS - 500),
        "associate returned after {elapsed:?}, before the {APPROVAL_DELAY_MS} ms delay"
    );
    assert!(
        probes >= 8,
        "only {probes} probes fit into the approval wait"
    );

    let response_nonce = B64
        .decode(
            response["nonce"]
                .as_str()
                .expect("associate response nonce"),
        )
        .expect("nonce base64");
    let plaintext = open(
        &server_public,
        &client.secret,
        &response_nonce,
        response["message"]
            .as_str()
            .expect("associate response message"),
    )
    .expect("decrypt associate response");
    let inner: Value = serde_json::from_slice(&plaintext).expect("associate inner JSON");
    assert_eq!(inner["success"], "true", "{inner}");
    assert_eq!(inner["id"], ASSOCIATION_ID, "{inner}");
    assert!(
        inner["hash"].as_str().is_some_and(|hash| hash.len() == 64),
        "associate reply has no database hash: {inner}"
    );

    // The app socket was registered exactly once and never went away.
    let counts = logged_client_counts(&log);
    assert!(
        !counts.is_empty(),
        "test_server never logged a client registration"
    );
    assert_eq!(
        counts,
        vec![1],
        "the app socket was dropped/reconnected during the approval wait: {counts:?}"
    );

    assert!(host.is_running(), "host died during the approval wait");
    assert_eq!(host.ping("after-associate")["appRunning"], true);
}
