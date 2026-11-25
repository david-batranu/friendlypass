//! Contract §2 / §4: the host identifies its launching browser and sends
//! `host-identify` as the first frame on every app-socket connection.
//!
//! Covered here:
//!
//! - `host-identify` is the first frame after the initial connect *and* after
//!   a reconnect, even when a forwarded request triggered the connect;
//! - an app that answers with a host error frame (unknown action) does not
//!   break forwarding;
//! - the reply is consumed by the host and never forwarded to stdout;
//! - `hello`/`ping` carry the additive `appTrusted` + `browser` fields, and a
//!   reconnect does not inherit the previous peer's trust;
//! - a host launched by a non-browser parent reports `verified:false`.

mod common;

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use common::{echo_handler, wait_until, Host, IdentifyReply, MockApp, TempRoot};

fn forwarded(action: &str, nonce: &str) -> Value {
    json!({
        "action": action,
        "message": "Y2lwaGVydGV4dA==",
        "nonce": nonce,
        "clientID": "TJwIfytHTekEUQHdQVIZ1XZEanwCbYl0",
    })
}

/// Send a forwarded request, retrying while the app is not reachable yet.
fn forward_with_retry(host: &mut Host, action: &str, nonce: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        host.send(&forwarded(action, nonce));
        let reply = host.recv(Duration::from_secs(3));
        if reply.get("errorCode").is_none() {
            return reply;
        }
        assert!(
            Instant::now() < deadline,
            "forwarded request never succeeded: {reply}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_identify(app: &MockApp) {
    assert!(
        wait_until(Duration::from_secs(5), || !app.identify_frames().is_empty()),
        "host never sent host-identify to the mock app"
    );
}

/// Every connection must open with `host-identify`, before probes or
/// forwarded frames.
fn assert_first_frames_are_identify(app: &MockApp) -> Value {
    let frames = app.first_frames();
    assert!(
        !frames.is_empty(),
        "mock app saw no frame at all on its connections"
    );
    let mut first_identify = None;
    for frame in &frames {
        let value: Value = serde_json::from_slice(frame).expect("first frame is JSON");
        assert_eq!(
            value["action"], "host-identify",
            "the first frame on a connection was not host-identify: {value}"
        );
        assert_eq!(value["hostVersion"], env!("CARGO_PKG_VERSION"));
        assert!(
            value["browser"].is_object(),
            "browser object missing: {value}"
        );
        let kind = value["browser"]["kind"]
            .as_str()
            .expect("browser.kind is a string");
        assert!(
            ["chrome", "chromium", "brave", "edge", "firefox", "unknown"].contains(&kind),
            "unexpected browser kind {kind}"
        );
        assert!(
            value["browser"]["verified"].is_boolean(),
            "browser.verified must be a boolean: {value}"
        );
        // The contract requires the keys; a null value is valid (Linux has no
        // team ID, unknown parents have no executable).
        assert!(value["browser"].get("executable").is_some());
        assert!(value["browser"].get("teamId").is_some());
        first_identify.get_or_insert(value);
    }
    first_identify.expect("at least one identify frame")
}

#[test]
fn identify_is_the_first_frame_on_connect_and_after_reconnect() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    // The host starts first, so it may need a retry before the mock binds.
    let mut host = Host::spawn(root);
    let app1 = MockApp::start(&socket, echo_handler());

    // A forwarded request that races the connect must still land *after* the
    // identify frame: the host writes it inside the connect path.
    let reply = forward_with_retry(&mut host, "change-public-keys", "first-connect");
    assert_eq!(reply["nonce"], "first-connect");
    wait_for_identify(&app1);
    assert_first_frames_are_identify(&app1);

    // The app goes away and comes back: the new connection must be identified
    // before anything else as well.
    drop(app1);
    let app2 = MockApp::start(&socket, echo_handler());
    wait_for_identify(&app2);
    assert_first_frames_are_identify(&app2);

    // And forwarding still works on the reconnected socket.
    let reply = forward_with_retry(&mut host, "get-databasehash", "after-reconnect");
    assert_eq!(reply["nonce"], "after-reconnect");
    assert_first_frames_are_identify(&app2);
    assert!(host.is_running(), "host died across the reconnect");
}

#[test]
fn identify_reply_is_never_forwarded() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);
    let _app = MockApp::start_with_identify(&socket, IdentifyReply::Trusted(true), echo_handler());
    wait_for_identify(&_app);

    // The app's `{"action":"host-identify",...}` answer must be consumed by the
    // host; nothing unsolicited reaches the browser.
    assert!(
        host.try_recv_payload(Duration::from_millis(400)).is_none(),
        "the host forwarded the host-identify reply to stdout"
    );

    // The next frame the browser sees is its own reply, not the identify one.
    host.send(&json!({"action": "ping", "nonce": "after-identify"}));
    let ping = host.recv(Duration::from_secs(5));
    assert_eq!(ping["action"], "ping");
    assert_eq!(ping["nonce"], "after-identify");
    assert!(ping.get("trusted").is_none(), "leaked identify field: {ping}");
}

#[test]
fn unknown_action_error_reply_does_not_break_forwarding() {
    for reply in [
        IdentifyReply::HostError,
        IdentifyReply::HostErrorWithAction,
    ] {
        let root = TempRoot::new();
        let socket = root.socket_path();
        let mut host = Host::spawn(root);
        let app =
            MockApp::start_with_identify(&socket, reply, echo_handler());
        wait_for_identify(&app);

        // An older app answers with a host error frame for the unknown action.
        // The host must ignore it and keep the relay working.
        let response =
            forward_with_retry(&mut host, "get-databasehash", "after-host-error");
        assert_eq!(response["action"], "get-databasehash");
        assert_eq!(response["nonce"], "after-host-error");
        assert!(
            response.get("errorCode").is_none(),
            "forwarding broke after an identify error reply: {response}"
        );
        assert!(host.is_running(), "host died on an identify error reply");

        // No identify error leaked to the browser either.
        let ping = host.ping("still-alive");
        assert_eq!(ping["action"], "ping");
        assert_eq!(ping["appRunning"], true);
    }
}

#[test]
fn hello_reports_app_trust_and_browser_kind() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);
    let _app = MockApp::start_with_identify(&socket, IdentifyReply::Trusted(true), echo_handler());
    wait_for_identify(&_app);

    let hello = wait_until(Duration::from_secs(5), || {
        host.send(&json!({"action": "hello", "statusPush": false}));
        host.recv(Duration::from_secs(5))["appTrusted"] == true
    });
    assert!(hello, "hello never reported appTrusted:true");

    host.send(&json!({"action": "hello"}));
    let hello = host.recv(Duration::from_secs(5));
    assert_eq!(hello["action"], "hello");
    assert_eq!(hello["appTrusted"], true);
    let kind = hello["browser"]["kind"]
        .as_str()
        .expect("hello.browser.kind is a string");
    assert!(["chrome", "chromium", "brave", "edge", "firefox", "unknown"].contains(&kind));
    assert!(hello["browser"]["verified"].is_boolean());
    // The additive summary stays minimal: no executable path or team ID.
    assert!(hello["browser"].get("executable").is_none());
    assert!(hello["browser"].get("teamId").is_none());
    assert!(
        hello.get("message").is_none(),
        "hello must stay host-level: {hello}"
    );

    // `ping` carries the same fields.
    let ping = host.ping("trust");
    assert_eq!(ping["appTrusted"], true);
    assert_eq!(ping["browser"], hello["browser"]);
}

#[test]
fn reconnect_clears_app_trust() {
    let root = TempRoot::new();
    let socket = root.socket_path();
    let mut host = Host::spawn(root);
    let app1 = MockApp::start_with_identify(&socket, IdentifyReply::Trusted(true), echo_handler());
    wait_for_identify(&app1);
    assert!(
        wait_until(Duration::from_secs(5), || host.ping("trusted")["appTrusted"] == true),
        "first connection was never reported as trusted"
    );

    // A new app instance that does not vouch for the host must not inherit the
    // old verdict.
    drop(app1);
    let app2 = MockApp::start_with_identify(&socket, IdentifyReply::Trusted(false), echo_handler());
    wait_for_identify(&app2);
    assert!(
        wait_until(Duration::from_secs(5), || {
            host.ping("untrusted")["appTrusted"] == false
        }),
        "appTrusted stayed true after the reconnect"
    );
    assert!(host.is_running());
}

/// A host launched by a shell instead of a browser must report
/// `verified:false` and still run normally. This is the manual "unsigned
/// parent" check, automated.
#[test]
fn non_browser_parent_is_reported_unverified() {
    let root = TempRoot::new();
    let binary = env!("CARGO_BIN_EXE_friendlypass-browser-host");

    // `sh` runs the host as a child (the extra `exit` prevents sh from
    // exec-optimising itself away), so `getppid()` is the shell.
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#""$0"; exit $?"#)
        .arg(binary)
        .env("TMPDIR", root.path())
        .env("TMP", root.path())
        .env("TEMP", root.path())
        .env("FP_HOST_DEBUG", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn host under a shell parent");

    // Closing stdin is the normal "browser closed the port" shutdown.
    drop(child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("wait for host") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                panic!("host did not exit after stdin EOF");
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("host stderr")
        .read_to_string(&mut stderr)
        .expect("read host stderr");
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("host stdout")
        .read_to_end(&mut stdout)
        .expect("read host stdout");

    assert!(
        stdout.is_empty(),
        "stdout must carry protocol frames only, got {:?}",
        String::from_utf8_lossy(&stdout)
    );
    assert!(
        stderr.contains("browser identity"),
        "debug identity log missing:\n{stderr}"
    );
    assert!(
        stderr.contains("verified=false"),
        "a non-browser parent must not be verified:\n{stderr}"
    );
}
