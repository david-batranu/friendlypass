//! The stdin dispatcher: framing, host-level actions, and forwarding.
//!
//! `ping` and `hello` never leave the host (§1.1). Everything the host does not
//! implement as a host action is forwarded byte-for-byte over the app socket.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufReader, Read};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::app::AppLink;
use crate::errors;
use crate::framing::{self, FrameRead};
use crate::status::StatusCell;
use crate::writer::Writer;

/// Frozen protocol version (`protocol/version`).
pub const PROTOCOL_VERSION: u32 = 1;
/// The host's own version, reported in `ping`/`hello`.
pub const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The host name browsers register for this binary.
pub const HOST_NAME: &str = "org.friendlypass.browser";

/// KeePassXC actions that are always relayed even when they carry no
/// `message` field (`change-public-keys` is the unencrypted handshake).
const FORWARDED_ACTIONS: &[&str] = &[
    "change-public-keys",
    "get-databasehash",
    "associate",
    "test-associate",
    "get-logins",
    "set-login",
    "get-totp",
    "get-database-groups",
    "create-new-group",
    "get-database-entries",
    "delete-entry",
    "request-autotype",
    "lock-database",
    "generate-password",
    "passkeys-get",
    "passkeys-register",
];

/// Actions that are push messages (app -> extension) and make no sense as a
/// request; answer 1003 rather than relaying them.
const PUSH_ACTIONS: &[&str] = &["database-locked", "database-unlocked", "database-changed"];

pub struct Runtime {
    out: Arc<Writer>,
    app: Arc<AppLink>,
    status: Arc<StatusCell>,
    session_id: String,
}

impl Runtime {
    pub fn new(out: Arc<Writer>, app: Arc<AppLink>, status: Arc<StatusCell>) -> Self {
        Self {
            out,
            app,
            status,
            session_id: new_session_id(),
        }
    }

    /// Handle one decoded native-messaging payload. Output errors are fatal for
    /// the connection (the browser is gone); framing errors are not.
    pub fn handle(&self, payload: &[u8]) -> io::Result<()> {
        let value: Value = match serde_json::from_slice(payload) {
            Ok(value) => value,
            Err(_) => {
                return self.out.value(&errors::host_error(
                    "",
                    errors::MALFORMED_FRAME,
                    "Invalid JSON payload",
                ))
            }
        };

        let Some(object) = value.as_object() else {
            return self.out.value(&errors::host_error(
                "",
                errors::MALFORMED_FRAME,
                "Frame payload must be a JSON object",
            ));
        };

        let Some(action) = object.get("action").and_then(Value::as_str) else {
            return self.out.value(&errors::host_error(
                "",
                errors::MALFORMED_FRAME,
                "Frame has no string action",
            ));
        };

        match action {
            "ping" => self.answer_ping(object.get("nonce").and_then(Value::as_str)),
            "hello" => self.answer_hello(object),
            _ if PUSH_ACTIONS.contains(&action) => self.out.value(&errors::host_error(
                action,
                errors::UNKNOWN_HOST_ACTION,
                "Push messages are sent by the app, not received by the host",
            )),
            // Known encrypted actions are relayed even if the client forgot
            // `message`, so the app produces the authoritative error. Unknown
            // actions are relayed only when they look encrypted (forward
            // compatibility), otherwise they are host errors.
            _ if FORWARDED_ACTIONS.contains(&action) || object.contains_key("message") => {
                self.forward(action, payload)
            }
            _ => self.out.value(&errors::host_error(
                action,
                errors::UNKNOWN_HOST_ACTION,
                "Unknown host action",
            )),
        }
    }

    fn forward(&self, action: &str, payload: &[u8]) -> io::Result<()> {
        if self.app.submit(action.to_owned(), payload.to_vec()) {
            return Ok(());
        }
        self.out.value(&errors::host_error(
            action,
            errors::APP_UNAVAILABLE_COMPAT,
            "friendlypass is not running",
        ))
    }

    fn answer_ping(&self, nonce: Option<&str>) -> io::Result<()> {
        let snapshot = self.status.snapshot();
        let mut frame = Map::new();
        frame.insert("action".into(), Value::from("ping"));
        frame.insert("success".into(), Value::from("true"));
        frame.insert("protocolVersion".into(), Value::from(PROTOCOL_VERSION));
        frame.insert("hostVersion".into(), Value::from(HOST_VERSION));
        frame.insert("appRunning".into(), Value::from(snapshot.app_running));
        frame.insert("appVersion".into(), option_string(snapshot.app_version));
        frame.insert("locked".into(), option_bool(snapshot.locked));
        frame.insert("databaseHash".into(), option_string(snapshot.database_hash));
        insert_trust_fields(&mut frame, snapshot.app_trusted);
        if let Some(nonce) = nonce {
            // Echoed verbatim, never incremented (§2.3, §5.2).
            frame.insert("nonce".into(), Value::from(nonce));
        }
        self.out.value(&Value::Object(frame))
    }

    fn answer_hello(&self, request: &Map<String, Value>) -> io::Result<()> {
        // Opt-in: the new extension asks for appRunning pushes; nobody else
        // (in particular stock KeePassXC clients) gets unsolicited frames.
        if request
            .get("statusPush")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            self.app.set_status_push(true);
        }
        let snapshot = self.status.snapshot();
        let mut frame = Map::new();
        frame.insert("action".into(), Value::from("hello"));
        frame.insert("success".into(), Value::from("true"));
        frame.insert("protocolVersion".into(), Value::from(PROTOCOL_VERSION));
        frame.insert("hostVersion".into(), Value::from(HOST_VERSION));
        frame.insert("appRunning".into(), Value::from(snapshot.app_running));
        frame.insert("appVersion".into(), option_string(snapshot.app_version));
        frame.insert("locked".into(), option_bool(snapshot.locked));
        frame.insert("databaseHash".into(), option_string(snapshot.database_hash));
        insert_trust_fields(&mut frame, snapshot.app_trusted);
        frame.insert("sessionId".into(), Value::from(self.session_id.clone()));
        frame.insert("hostPid".into(), Value::from(std::process::id()));
        self.out.value(&Value::Object(frame))
    }
}

/// Main stdio loop. Returns when the browser closes stdin (clean exit).
pub fn run<R: Read>(input: R, runtime: &Runtime) -> io::Result<()> {
    let mut reader = BufReader::new(input);
    loop {
        match framing::read_frame(&mut reader) {
            Ok(FrameRead::Eof) => return Ok(()),
            Ok(FrameRead::TooLarge(len)) => {
                eprintln!("friendlypass-browser-host: discarded {len}-byte frame (1 MiB cap)");
                if runtime
                    .out
                    .value(&errors::host_error(
                        "",
                        errors::FRAME_TOO_LARGE,
                        "Message exceeds the 1 MiB frame limit",
                    ))
                    .is_err()
                {
                    return Ok(());
                }
            }
            Ok(FrameRead::Frame(payload)) => {
                if runtime.handle(&payload).is_err() {
                    // stdout is gone; the browser closed the port.
                    return Ok(());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // A truncated frame at shutdown; nothing to answer.
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }
}

fn option_string(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

fn option_bool(value: Option<bool>) -> Value {
    value.map(Value::Bool).unwrap_or(Value::Null)
}

/// Additive **[friendlypass]** fields shared by `ping` and `hello`:
/// `appTrusted` (the app's answer to `host-identify`) and `browser`
/// (`{kind, verified}` of the browser that launched this host). Both are
/// documented in `protocol/ACTIONS.md` §5.2/§5.3; older clients ignore them.
fn insert_trust_fields(frame: &mut Map<String, Value>, app_trusted: Option<bool>) {
    frame.insert(
        "appTrusted".into(),
        app_trusted.map(Value::Bool).unwrap_or(Value::Null),
    );
    frame.insert("browser".into(), crate::browser_identity::summary_json());
}

/// A random UUID-shaped id for diagnostics only (not authentication). Uses the
/// std hasher's randomised keys, so no extra dependency is needed.
fn new_session_id() -> String {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut parts = [0u64; 2];
    for (index, part) in parts.iter_mut().enumerate() {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(seed);
        hasher.write_u32(std::process::id());
        hasher.write_usize(index);
        *part = hasher.finish();
    }
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        parts[0] >> 32,
        (parts[0] >> 16) & 0xffff,
        parts[0] & 0x0fff,
        ((parts[1] >> 48) & 0x3fff) | 0x8000,
        parts[1] & 0xffff_ffff_ffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_uuid_shaped_and_unique() {
        let a = new_session_id();
        let b = new_session_id();
        assert_ne!(a, b);
        let parts: Vec<&str> = a.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
    }

    #[test]
    fn forwarded_action_list_matches_the_contract() {
        // `change-public-keys` is the only unencrypted forwarded action, and it
        // must be present even without a `message` field.
        assert!(FORWARDED_ACTIONS.contains(&"change-public-keys"));
        for action in PUSH_ACTIONS {
            assert!(!FORWARDED_ACTIONS.contains(action));
        }
    }
}
