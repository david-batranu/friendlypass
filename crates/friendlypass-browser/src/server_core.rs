//! Platform-independent connection loop for the app socket.
//!
//! Both [`crate::server`] (Unix domain socket) and [`crate::server_windows`]
//! (named pipe) accept connections in their own way, verify the peer with the
//! platform mechanism, and then hand the connected stream to
//! [`handle_connection`] here. Framing, the reader/worker split, immediate
//! `ping` answers and push delivery are therefore implemented exactly once.

use std::io::{ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::peer::PeerInfo;
use crate::protocol::{
    get_str, host_error_reply, ACTION_PING, HOST_ERROR_FRAME_TOO_LARGE, HOST_ERROR_MALFORMED_FRAME,
    PROTOCOL_VERSION,
};
use crate::push::PushHub;
use crate::service::{lock_state, ClientSession, SharedState};
use crate::transport::AppStream;

/// Maximum frame size in both directions (`BrowserShared::SOCKET_BUFFER_SIZE`,
/// also the friendlypass 1 MiB contract).
pub const MAX_FRAME: usize = 1024 * 1024;

/// How often a connection checks for queued push messages and shutdown.
pub(crate) const PUSH_POLL: Duration = Duration::from_millis(200);

/// Run one accepted connection: one reader thread (this function), one worker
/// for everything except `ping`, and a shared writer protected by a mutex.
pub fn handle_connection<S: AppStream>(
    mut stream: S,
    state: &SharedState,
    hub: &Arc<PushHub>,
    stop: &Arc<AtomicBool>,
    peer: PeerInfo,
) {
    let Ok(write_stream) = stream.try_clone() else {
        return;
    };
    let _ = stream.set_read_timeout(Some(PUSH_POLL));
    // A peer that stops reading must not wedge a connection thread forever.
    let _ = write_stream.set_write_timeout(Some(Duration::from_secs(5)));
    // Reader, worker and pushes all write through this one handle. Holding the
    // mutex for a whole frame keeps objects from interleaving on the wire.
    let writer = Arc::new(Mutex::new(write_stream));
    let (client_id, pushes) = hub.register();

    // Requests other than `ping` are processed in order by one worker so the
    // reader stays free to answer liveness probes and deliver pushes.
    let (requests, incoming) = mpsc::channel::<Value>();
    let worker_state = Arc::clone(state);
    let worker_writer = Arc::clone(&writer);
    let worker_stop = Arc::clone(stop);
    let worker = std::thread::Builder::new()
        .name("friendlypass-browser-worker".into())
        .spawn(move || {
            // The per-connection protocol state belongs to the worker: only it
            // touches `ClientSession`, so reader-side pings cannot race it.
            let mut session = ClientSession::new().with_peer(peer);
            while let Ok(request) = incoming.recv() {
                if worker_stop.load(Ordering::SeqCst) {
                    break;
                }
                let response = session.handle(&worker_state, &request);
                if write_frame(&worker_writer, &response).is_err() {
                    break;
                }
            }
        });
    if worker.is_err() {
        hub.unregister(client_id);
        return;
    }
    // The handle is deliberately dropped (detached): a worker blocked in an
    // approval must not keep a closing connection or the process alive. It
    // exits on the closed channel or the next failed write.

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        // Deliver queued unsolicited frames between reads. A write failure
        // means the peer is gone; drop the registration and exit.
        while let Some(frame) = pushes.try_recv() {
            if write_frame(&writer, &frame).is_err() {
                hub.unregister(client_id);
                return;
            }
        }

        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if !drain_frames(&writer, state, &requests, &mut buffer) {
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
    // Dropping `requests` closes the worker's channel; it exits as soon as
    // any in-flight request returns.
}

/// Handle every complete frame in `buffer`. Returns false when the connection
/// should close.
fn drain_frames<S: AppStream>(
    writer: &Arc<Mutex<S>>,
    state: &SharedState,
    requests: &Sender<Value>,
    buffer: &mut Vec<u8>,
) -> bool {
    while let Some(end) = find_json_end(buffer) {
        let raw: Vec<u8> = buffer.drain(..end).collect();
        if raw.len() > MAX_FRAME {
            let reply = host_error_reply(
                "",
                HOST_ERROR_FRAME_TOO_LARGE,
                "Message exceeds the 1 MiB frame limit",
            );
            if write_frame(writer, &reply).is_err() {
                return false;
            }
            continue;
        }
        let Some(request) = parse_one(&raw) else {
            let reply = host_error_reply("", HOST_ERROR_MALFORMED_FRAME, "Malformed frame");
            if write_frame(writer, &reply).is_err() {
                return false;
            }
            continue;
        };
        // `ping` is answered here, on the reader, so it never queues behind a
        // slow action. It carries no session state, only the app's status.
        if get_str(&request, "action").as_deref() == Some(ACTION_PING) {
            let reply = ping_reply(state, &request);
            if write_frame(writer, &reply).is_err() {
                return false;
            }
            continue;
        }
        if requests.send(request).is_err() {
            return false;
        }
    }

    if buffer.len() > MAX_FRAME {
        // A frame larger than the cap that never closes: answer once and
        // discard what we have rather than growing without bound.
        let reply = host_error_reply(
            "",
            HOST_ERROR_FRAME_TOO_LARGE,
            "Message exceeds the 1 MiB frame limit",
        );
        if write_frame(writer, &reply).is_err() {
            return false;
        }
        buffer.clear();
    }
    true
}

/// The §5.2 shape for a host-level `ping`, built without a [`ClientSession`]
/// so the reader can answer it while the worker is busy. Mirrors
/// `ClientSession::handle_status`; `ping` needs no per-session fields.
fn ping_reply(state: &SharedState, request: &Value) -> Value {
    let (locked, hash, app_version) = {
        let guard = lock_state(state);
        (
            guard.locked,
            guard.db_hash.clone(),
            guard.app_version.clone(),
        )
    };
    let app_version = if app_version.is_empty() {
        env!("CARGO_PKG_VERSION").to_owned()
    } else {
        app_version
    };
    let mut response = serde_json::Map::new();
    response.insert("action".into(), json!(ACTION_PING));
    response.insert("success".into(), json!("true"));
    response.insert("protocolVersion".into(), json!(PROTOCOL_VERSION));
    response.insert("hostVersion".into(), json!(env!("CARGO_PKG_VERSION")));
    response.insert("appRunning".into(), json!(true));
    response.insert("appVersion".into(), json!(app_version));
    response.insert("locked".into(), json!(locked));
    response.insert(
        "databaseHash".into(),
        if locked || hash.is_empty() {
            Value::Null
        } else {
            json!(hash)
        },
    );
    if let Some(nonce) = get_str(request, "nonce") {
        // Host-level ping echoes the nonce verbatim (not incremented).
        response.insert("nonce".into(), json!(nonce));
    }
    Value::Object(response)
}

fn write_frame<S: Write>(writer: &Arc<Mutex<S>>, value: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    let mut stream = writer
        .lock()
        .map_err(|_| std::io::Error::other("browser connection writer poisoned"))?;
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
}
