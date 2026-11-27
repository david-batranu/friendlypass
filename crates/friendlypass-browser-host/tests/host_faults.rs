#![cfg(unix)]
//! WP1 fault tests: spawn the real binary with piped stdio against a mock app
//! socket. Every scenario from the brief is covered here:
//!
//! - app absent at start (`ping` says `appRunning:false`, host stays alive);
//! - app appears later (first forwarded request succeeds < 1 s);
//! - the app restarts 20x in a loop;
//! - split and coalesced native-messaging frames;
//! - a 2 MiB frame is rejected with a typed error and the host survives;
//! - a non-ASCII password round-trips byte-exactly in both directions;
//! - 100 concurrent forwarded requests are all answered (out of order).

mod common;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use common::{frame_bytes, wait_until, Host, MockApp, TempRoot};

const DB_HASH: &str = "4265c37dbe9ad073ac19837734d54fdd7d7c30bd87322ba886da62b147d66fbb";

fn forwarded(action: &str, nonce: &str, request_id: Option<u32>) -> Value {
    let mut frame = json!({
        "action": action,
        "message": "Y2lwaGVydGV4dA==",
        "nonce": nonce,
        "clientID": "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0",
    });
    if let Some(id) = request_id {
        frame["requestID"] = json!(id);
    }
    frame
}

#[test]
fn app_absent_ping_and_hello_keep_host_alive() {
    let mut host = Host::spawn(TempRoot::new());

    let ping = host.ping("nonce-absent");
    assert_eq!(ping["action"], "ping");
    assert_eq!(ping["success"], "true");
    assert_eq!(ping["protocolVersion"], 1);
    assert_eq!(ping["hostVersion"], env!("CARGO_PKG_VERSION"));
    assert_eq!(ping["appRunning"], false);
    assert!(ping["appVersion"].is_null());
    assert!(ping["locked"].is_null());
    assert!(ping["databaseHash"].is_null());
    assert_eq!(ping["nonce"], "nonce-absent");

    let hello_frame = json!({
        "action": "hello",
        "clientID": "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0",
        "extensionVersion": "0.1.0",
    });
    host.send(&hello_frame);
    let hello = host.recv(Duration::from_secs(5));
    assert_eq!(hello["action"], "hello");
    assert_eq!(hello["success"], "true");
    assert_eq!(hello["protocolVersion"], 1);
    assert_eq!(hello["appRunning"], false);
    assert!(hello["appVersion"].is_null());
    assert_eq!(
        hello["sessionId"].as_str().map(str::len),
        Some(36),
        "sessionId must be UUID-shaped"
    );
    assert!(hello["hostPid"].as_u64().unwrap_or(0) > 0);

    // The session id is stable for the lifetime of this stdio connection.
    host.send(&hello_frame);
    let hello_again = host.recv(Duration::from_secs(5));
    assert_eq!(hello_again["sessionId"], hello["sessionId"]);

    // Still alive and still answering after a while.
    thread::sleep(Duration::from_millis(300));
    assert!(host.is_running());
    let again = host.ping("nonce-absent-2");
    assert_eq!(again["action"], "ping");
    assert_eq!(again["nonce"], "nonce-absent-2");
    assert_eq!(again["appRunning"], false);

    // A forwarded encrypted action is settled with host error 5 (the
    // KeePassXC-compatible "not connected" code) instead of hanging.
    host.send(&forwarded("get-logins", "nonce-nc", None));
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["action"], "get-logins");
    assert_eq!(error["errorCode"], "5");
    assert_eq!(error["hostError"], true);

    // change-public-keys has no `message` but is still forwarded, so it is
    // settled the same way (not rejected as an unknown host action).
    host.send(&json!({
        "action": "change-public-keys",
        "publicKey": "Z0wuYBn1AC+vA6rEOeUJEzG7Dtp07a5ZLRzgqlxAbyY=",
        "nonce": "CA8WHSQrMjlAR05VXGNqcXh/ho2Um6Kp",
        "clientID": "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0",
    }));
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["action"], "change-public-keys");
    assert_eq!(error["errorCode"], "5");
}

#[test]
fn app_appears_later_and_first_request_is_fast() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);

    assert_eq!(host.ping("n0")["appRunning"], false);

    let _app = MockApp::start_echo(&socket);

    let started = Instant::now();
    host.send(&forwarded("get-databasehash", "nonce-later", None));
    let reply = host.recv(Duration::from_secs(5));
    let elapsed = started.elapsed();
    assert_eq!(reply["action"], "get-databasehash");
    assert_eq!(reply["nonce"], "nonce-later");
    assert!(
        reply.get("errorCode").is_none(),
        "first forwarded request failed: {reply}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "first forwarded request took {elapsed:?}"
    );

    // The status probe catches up within a couple of seconds.
    let up = wait_until(Duration::from_secs(5), || {
        host.ping("probe")["appRunning"] == true
    });
    assert!(up, "ping never reported appRunning:true");
    let ping = host.ping("probe-2");
    assert_eq!(ping["appVersion"], "0.1.0");
    assert_eq!(ping["locked"], false);
    assert_eq!(ping["databaseHash"], DB_HASH);
}

#[test]
fn app_restarts_twenty_times() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);

    for round in 0..20u32 {
        let app = MockApp::start_echo(&socket);

        // Retry a couple of times: the first write can hit the previous
        // (already dead) connection before its EOF is observed.
        let nonce = format!("round-{round}");
        let mut reply = Value::Null;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            host.send(&forwarded("test-associate", &nonce, None));
            reply = host.recv(Duration::from_secs(3));
            if reply.get("errorCode").is_none() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(reply["action"], "test-associate", "round {round}: {reply}");
        assert_eq!(reply["nonce"], nonce, "round {round}: {reply}");
        assert!(host.is_running(), "host died in round {round}");

        drop(app);

        let down = wait_until(Duration::from_secs(5), || {
            host.ping(&format!("down-{round}"))["appRunning"] == false
        });
        assert!(down, "round {round}: ping kept reporting appRunning:true");
    }

    assert!(host.is_running(), "host died after 20 restarts");
    assert_eq!(host.ping("final")["appRunning"], false);
}

#[test]
fn split_and_coalesced_frames() {
    let mut host = Host::spawn(TempRoot::new());

    // One frame delivered in three chunks.
    let payload = serde_json::to_vec(&json!({"action": "ping", "nonce": "split"})).unwrap();
    let framed = frame_bytes(&payload);
    host.send_bytes(&framed[..2]);
    thread::sleep(Duration::from_millis(60));
    host.send_bytes(&framed[2..5]);
    thread::sleep(Duration::from_millis(60));
    host.send_bytes(&framed[5..]);
    assert_eq!(host.recv(Duration::from_secs(5))["nonce"], "split");

    // Two frames in a single write.
    let first = frame_bytes(
        &serde_json::to_vec(&json!({"action": "ping", "nonce": "coalesced-a"})).unwrap(),
    );
    let second = frame_bytes(
        &serde_json::to_vec(&json!({"action": "ping", "nonce": "coalesced-b"})).unwrap(),
    );
    let mut both = first.clone();
    both.extend(second);
    host.send_bytes(&both);
    assert_eq!(host.recv(Duration::from_secs(5))["nonce"], "coalesced-a");
    assert_eq!(host.recv(Duration::from_secs(5))["nonce"], "coalesced-b");
}

#[test]
fn oversize_frame_is_rejected_and_host_survives() {
    let mut host = Host::spawn(TempRoot::new());

    let size = 2 * 1024 * 1024usize;
    let mut bytes = (size as u32).to_le_bytes().to_vec();
    bytes.resize(4 + size, b'x');
    host.send_bytes(&bytes);

    let error = host.recv(Duration::from_secs(10));
    assert_eq!(error["errorCode"], "1001");
    assert_eq!(error["hostError"], true);
    assert_eq!(error["action"], "");

    // The stream stays aligned and the host stays alive.
    assert_eq!(host.ping("after-oversize")["nonce"], "after-oversize");
    assert!(host.is_running());
}

#[test]
fn malformed_and_unknown_frames_are_typed_errors() {
    let mut host = Host::spawn(TempRoot::new());

    // Invalid UTF-8.
    host.send_payload(&[0xff, 0xfe, 0xfd]);
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["errorCode"], "1002");
    assert_eq!(error["hostError"], true);

    // Invalid JSON.
    host.send_payload(b"{\"action\":");
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["errorCode"], "1002");

    // Valid JSON, but not an object.
    host.send_payload(b"[1,2,3]");
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["errorCode"], "1002");

    // No action.
    host.send_payload(br#"{"nonce":"x"}"#);
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["errorCode"], "1002");

    // An unencrypted action the host does not implement.
    host.send_payload(br#"{"action":"launch-app"}"#);
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["errorCode"], "1003");
    assert_eq!(error["hostError"], true);
    assert_eq!(error["action"], "launch-app");

    // A push action is app -> extension, never a request.
    host.send_payload(br#"{"action":"database-locked"}"#);
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["errorCode"], "1003");

    assert_eq!(host.ping("alive")["action"], "ping");
}

#[test]
fn non_ascii_password_is_byte_exact_both_ways() {
    let root = TempRoot::new();
    let socket = root.socket_path();

    let password = "pässwörd 🔑 密码 Ω≈ç√∫˜µ≤≥÷";
    let request = json!({
        "action": "get-logins",
        "message": "Y2lwaGVydGV4dA==",
        "nonce": "bm9uY2Utbm9uLWFzY2lp",
        "clientID": "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0",
        "password": password,
        "login": "üser@exämple.com",
    });
    let request_bytes = serde_json::to_vec(&request).unwrap();

    let response = json!({
        "action": "get-logins",
        "message": "cmVzcG9uc2U=",
        "nonce": "bm9uY2Utbm9uLWFzY2lp",
        "password": password,
        "login": "üser@exämple.com",
    });
    let response_bytes = serde_json::to_vec(&response).unwrap();
    let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

    let reply = response_bytes.clone();
    let captured_for_app = Arc::clone(&captured);
    let app = MockApp::start(&socket, move |raw: &[u8]| {
        captured_for_app
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(raw.to_vec());
        vec![reply.clone()]
    });

    let mut host = Host::spawn(root);
    host.send_payload(&request_bytes);
    let forwarded = host.recv_payload(Duration::from_secs(5));

    // App -> browser: byte-for-byte, no re-encoding or escaping changes.
    assert_eq!(forwarded, response_bytes);

    // Browser -> app: also byte-for-byte.
    let received = wait_until(Duration::from_secs(5), || {
        !captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    });
    assert!(received, "app never received the request");
    let recorded = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(recorded[0], request_bytes);

    // And the text really is the same after a JSON round-trip.
    let decoded: Value = serde_json::from_slice(&recorded[0]).unwrap();
    assert_eq!(decoded["password"], password);
    let _app = app;
}

#[test]
fn hundred_concurrent_requests_all_answered_out_of_order() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);
    let _app = MockApp::start(&socket, {
        let mut batch: Vec<Value> = Vec::new();
        move |raw: &[u8]| {
            let request: Value = serde_json::from_slice(raw).unwrap();
            batch.push(request);
            if batch.len() < 100 {
                return Vec::new();
            }
            // Answer everything in reverse order to prove the host is a
            // transparent relay and does not depend on arrival order.
            batch
                .drain(..)
                .rev()
                .map(|request| {
                    let reply = json!({
                        "action": request.get("action").cloned().unwrap_or(Value::Null),
                        "nonce": request.get("nonce").cloned().unwrap_or(Value::Null),
                        "requestID": request.get("requestID").cloned().unwrap_or(Value::Null),
                    });
                    serde_json::to_vec(&reply).unwrap()
                })
                .collect()
        }
    });

    for id in 0..100u32 {
        host.send(&forwarded("get-logins", &format!("nonce-{id}"), Some(id)));
    }

    let mut seen = vec![0u32; 100];
    for _ in 0..100 {
        let reply = host.recv(Duration::from_secs(15));
        assert_eq!(reply["action"], "get-logins", "unexpected frame: {reply}");
        let id = reply["requestID"].as_u64().expect("requestID") as usize;
        assert_eq!(reply["nonce"], format!("nonce-{id}"));
        seen[id] += 1;
    }
    assert!(
        seen.iter().all(|&count| count == 1),
        "some requests were answered zero or multiple times: {seen:?}"
    );
    assert_eq!(host.ping("after-100")["action"], "ping");
}

#[test]
fn socket_drop_settles_requests_in_flight_then_reconnects() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);
    let app = MockApp::start(&socket, |_raw: &[u8]| Vec::new());

    host.send(&forwarded("get-logins", "in-flight-1", None));
    host.send(&forwarded("get-totp", "in-flight-2", None));
    host.send(&forwarded("set-login", "in-flight-3", None));
    let arrived = wait_until(Duration::from_secs(5), || app.requests().len() == 3);
    assert!(arrived, "app never saw all three requests");

    // Kill the app without answering: every pending request must settle.
    drop(app);

    let mut settled = Vec::new();
    for _ in 0..3 {
        settled.push(host.recv(Duration::from_secs(5)));
    }
    for frame in &settled {
        assert_eq!(frame["errorCode"], "5", "unexpected frame: {frame}");
        assert_eq!(frame["hostError"], true);
    }
    let mut actions: Vec<&str> = settled
        .iter()
        .map(|frame| frame["action"].as_str().unwrap_or_default())
        .collect();
    actions.sort_unstable();
    assert_eq!(actions, ["get-logins", "get-totp", "set-login"]);

    // Transparent recovery: a new app instance serves the next request.
    let _app = MockApp::start_echo(&socket);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut reply = Value::Null;
    while Instant::now() < deadline {
        host.send(&forwarded("get-databasehash", "after-reconnect", None));
        reply = host.recv(Duration::from_secs(3));
        if reply.get("errorCode").is_none() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(reply["action"], "get-databasehash");
    assert_eq!(reply["nonce"], "after-reconnect");
}

#[test]
fn push_messages_are_relayed() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);
    let app = MockApp::start_echo(&socket);

    // Wait for the host to connect (a forwarded request is the surest signal).
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        host.send(&forwarded("get-databasehash", "connect", None));
        let reply = host.recv(Duration::from_secs(3));
        connected = reply.get("errorCode").is_none();
    }
    assert!(connected, "host never connected to the mock app");

    app.push(&json!({"action": "database-locked"}));
    assert_eq!(
        host.recv(Duration::from_secs(5))["action"],
        "database-locked"
    );

    app.push(&json!({"action": "database-unlocked"}));
    assert_eq!(
        host.recv(Duration::from_secs(5))["action"],
        "database-unlocked"
    );

    app.push(&json!({"action": "database-changed", "hash": DB_HASH}));
    let changed = host.recv(Duration::from_secs(5));
    assert_eq!(changed["action"], "database-changed");
    assert_eq!(changed["hash"], DB_HASH);

    // Status cache reflects the pushes.
    let up = wait_until(Duration::from_secs(5), || {
        host.ping("after-pushes")["locked"] == false
    });
    assert!(up, "locked status did not follow database-unlocked");
}

#[test]
fn stdin_eof_exits_cleanly() {
    let mut host = Host::spawn(TempRoot::new());
    assert_eq!(host.ping("bye")["action"], "ping");
    let status = host.close_stdin_and_wait(Duration::from_secs(5));
    assert!(status.success(), "host exited with {status:?}");
}

#[test]
fn malformed_app_json_is_a_typed_host_error() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    // The mock's `serve` answers the host's status probes itself; every other
    // request gets a brace-balanced but invalid JSON object, exactly what a
    // buggy/desynchronised app could write on the raw-JSON app socket.
    let _app = MockApp::start(&socket, |_raw| vec![b"{\"action\":}".to_vec()]);
    let mut host = Host::spawn(root);

    host.send(&forwarded("get-logins", "corrupt-app-json", None));
    let error = host.recv(Duration::from_secs(5));
    assert_eq!(error["hostError"], true, "expected a host error: {error}");
    assert_eq!(
        error["errorCode"], "1002",
        "expected malformed frame: {error}"
    );
    assert!(host.is_running(), "host died on malformed app JSON");
    assert_eq!(host.ping("still-alive")["action"], "ping");
}

#[test]
fn status_push_is_opt_in_and_reports_app_down() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);

    // Opt in through `hello`; without statusPush the host stays silent.
    host.send(&json!({
        "action": "hello",
        "clientVersion": "0.1.0",
        "statusPush": true
    }));
    let hello = host.recv(Duration::from_secs(5));
    assert_eq!(hello["action"], "hello");
    assert_eq!(hello["appRunning"], false);

    let app = MockApp::start_echo(&socket);

    // The first successful probe is announced without the browser asking.
    let up = host.recv(Duration::from_secs(5));
    assert_eq!(up["action"], "ping", "expected a status push: {up}");
    assert_eq!(up["appRunning"], true);
    assert_eq!(up["databaseHash"], DB_HASH);

    // The socket going away is announced immediately too.
    drop(app);
    let down = host.recv(Duration::from_secs(5));
    assert_eq!(down["action"], "ping", "expected a status push: {down}");
    assert_eq!(down["appRunning"], false);

    // And a normal ping agrees.
    assert_eq!(host.ping("after-down")["appRunning"], false);
    assert!(host.is_running());
}
