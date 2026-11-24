//! The app socket link: connect with backoff, status probes, forwarding, and
//! transparent reconnects.
//!
//! Guiding rules from the contract and the brief:
//!
//! - never lose a forwarded request silently: every request either reaches the
//!   app or is settled with a typed host error;
//! - the stdin loop never blocks on the app socket, so `ping` keeps its 100 ms
//!   budget even when the app is hung (writes happen on a dedicated thread,
//!   fed through a bounded queue);
//! - a dropped socket does not kill the host: the manager reconnects with a
//!   capped backoff, and an arriving request triggers an immediate connect
//!   attempt so recovery is well under one second;
//! - frames are forwarded byte-for-byte (no re-serialisation, so no field
//!   reordering and no Unicode accidents).

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::errors;
use crate::framing::ObjectFramer;
use crate::status::StatusCell;
use crate::writer::Writer;

/// The probe the host sends to learn liveness + status. The app answers it like
/// any other host-level frame; a plain error answer still counts as alive.
pub const PROBE_FRAME: &[u8] = br#"{"action":"ping"}"#;

/// How often the manager probes a connected app.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// How long a probe may stay unanswered before it counts as a miss. Kept at
/// one interval so a hung app is reported down within ~3 s, well inside the
/// extension's 5 s status budget.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// Consecutive misses that make the host drop and reconnect the socket.
const PROBE_MISSES: u8 = 2;
/// Reconnect backoff: 100 ms doubling to a 1 s cap (recovery < 1 s).
const CONNECT_BACKOFF_INITIAL: Duration = Duration::from_millis(100);
const CONNECT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// Absolute bound on a forwarded request that never gets any answer. The
/// extension has its own (shorter) timeouts; this only prevents leaks.
const PENDING_TIMEOUT: Duration = Duration::from_secs(300);
/// Bounded outbound queue; `try_send` keeps the stdin loop non-blocking.
const OUTBOUND_QUEUE: usize = 1024;

struct Pending {
    action: String,
    generation: u64,
    since: Instant,
}

struct Outbound {
    action: String,
    payload: Vec<u8>,
}

#[derive(Default)]
struct Conn {
    stream: Option<UnixStream>,
    /// A clone used only to shut the reader down from the manager thread.
    shutdown: Option<UnixStream>,
    generation: u64,
    pending_probe: bool,
    probe_sent: Option<Instant>,
    misses: u8,
}

pub struct AppLink {
    path: PathBuf,
    out: Arc<Writer>,
    status: Arc<StatusCell>,
    conn: Mutex<Conn>,
    pending: Mutex<Vec<Pending>>,
    outbound: SyncSender<Outbound>,
    /// Last `appRunning` value announced to the browser. Lets the host push a
    /// status frame the moment the app goes away or comes back, so the
    /// extension never has to wait for its 20 s heartbeat.
    announced_running: Mutex<Option<bool>>,
    /// Only clients that asked for status pushes (via `hello.statusPush`) see
    /// unsolicited frames; KeePassXC clients and order-sensitive tests keep a
    /// strict request/reply stream.
    status_push: AtomicBool,
}

impl AppLink {
    /// Create the link and start its writer + manager threads.
    pub fn start(path: PathBuf, out: Arc<Writer>, status: Arc<StatusCell>) -> Arc<Self> {
        let (outbound, receiver) = mpsc::sync_channel(OUTBOUND_QUEUE);
        let link = Arc::new(Self {
            path,
            out,
            status,
            conn: Mutex::new(Conn::default()),
            pending: Mutex::new(Vec::new()),
            outbound,
            announced_running: Mutex::new(None),
            status_push: AtomicBool::new(false),
        });

        let writer_link = Arc::clone(&link);
        spawn_thread("friendlypass-host-app-writer", move || {
            writer_link.write_loop(receiver);
        });

        let manager_link = Arc::clone(&link);
        spawn_thread("friendlypass-host-app-manager", move || {
            manager_link.manage_loop();
        });

        link
    }

    /// Queue a frame for the app. Returns `false` when the queue is closed or
    /// full; the caller then settles the request with a typed host error.
    pub fn submit(&self, action: String, payload: Vec<u8>) -> bool {
        match self.outbound.try_send(Outbound { action, payload }) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Enable unsolicited `appRunning` status frames (opt-in via `hello`).
    pub fn set_status_push(&self, enabled: bool) {
        self.status_push.store(enabled, Ordering::SeqCst);
        if enabled {
            // Announce the current value even if no transition happens next.
            *self
                .announced_running
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Conn> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_pending(&self) -> std::sync::MutexGuard<'_, Vec<Pending>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The outbound writer thread: connect on demand and write frames.
    fn write_loop(self: Arc<Self>, receiver: Receiver<Outbound>) {
        while let Ok(message) = receiver.recv() {
            self.deliver(message);
        }
    }

    fn deliver(self: &Arc<Self>, message: Outbound) {
        let mut lost_generation = None;
        let mut unavailable = false;
        {
            let mut conn = self.lock_conn();
            if conn.stream.is_none() && !self.connect_locked(&mut conn) {
                unavailable = true;
            } else {
                let generation = conn.generation;
                {
                    let mut pending = self.lock_pending();
                    pending.push(Pending {
                        action: message.action.clone(),
                        generation,
                        since: Instant::now(),
                    });
                }
                let written = match conn.stream.as_mut() {
                    Some(stream) => stream.write_all(&message.payload).is_ok(),
                    None => false,
                };
                if !written {
                    lost_generation = Some(disconnect(&mut conn));
                }
            }
        }

        if let Some(generation) = lost_generation {
            self.on_generation_lost(generation);
        } else if unavailable {
            self.settle(
                &message.action,
                errors::APP_UNAVAILABLE_COMPAT,
                "friendlypass is not running",
            );
        }
    }

    /// Connect if needed. Must be called with the connection lock held.
    fn connect_locked(self: &Arc<Self>, conn: &mut Conn) -> bool {
        let Ok(stream) = UnixStream::connect(&self.path) else {
            return false;
        };
        // Bounded writes: a wedged app cannot block the writer thread forever.
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let Ok(reader_stream) = stream.try_clone() else {
            return false;
        };
        let shutdown = stream.try_clone().ok();

        conn.generation = conn.generation.wrapping_add(1);
        conn.stream = Some(stream);
        conn.shutdown = shutdown;
        conn.pending_probe = false;
        conn.probe_sent = None;
        conn.misses = 0;

        let generation = conn.generation;
        self.status.set_connected();

        let reader_link = Arc::clone(self);
        spawn_thread("friendlypass-host-app-reader", move || {
            reader_link.read_loop(reader_stream, generation);
        });
        true
    }

    /// Read app frames until EOF/error, then settle that generation.
    fn read_loop(self: Arc<Self>, mut stream: UnixStream, generation: u64) {
        let mut framer = ObjectFramer::new();
        let mut buffer = [0u8; 8192];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    framer.push(&buffer[..n]);
                    while let Some(object) = framer.next_object() {
                        self.on_app_frame(generation, &object);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        self.reader_closed(generation);
    }

    /// Handle one frame from the app: probe answers feed the status cache,
    /// everything else is relayed verbatim to the browser.
    fn on_app_frame(&self, generation: u64, payload: &[u8]) {
        let parsed = serde_json::from_slice::<Value>(payload).ok();
        // The app socket carries raw concatenated JSON objects (see the
        // app-socket section of ACTIONS.md). Anything that is not a single
        // JSON object is a protocol violation: answer 1002 instead of writing
        // an unparseable frame to the browser, and keep both links alive.
        let Some(parsed) = parsed else {
            self.settle(
                "",
                errors::MALFORMED_FRAME,
                "Invalid JSON from the app socket",
            );
            return;
        };
        if !parsed.is_object() {
            self.settle(
                "",
                errors::MALFORMED_FRAME,
                "App frame is not a JSON object",
            );
            return;
        }
        let action = parsed.get("action").and_then(Value::as_str);

        if action == Some("ping") {
            self.probe_answered(generation, Some(&parsed));
            return;
        }

        // A frame from a superseded connection must not reach the browser.
        {
            let conn = self.lock_conn();
            if conn.generation != generation {
                return;
            }
        }

        if payload.len() > crate::framing::MAX_PAYLOAD {
            // The app must obey the 1 MiB cap; dropping is safer than writing
            // an unparseable frame to the browser, and the host stays alive.
            eprintln!(
                "friendlypass-browser-host: dropped {}-byte app frame (1 MiB cap)",
                payload.len()
            );
            return;
        }

        if self.out.frame(payload).is_err() {
            // The browser closed the port; nothing left to talk to.
            std::process::exit(0);
        }

        if let Some(action) = action {
            self.pop_pending(action);
            if matches!(
                action,
                "database-locked" | "database-unlocked" | "database-changed"
            ) {
                let hash = parsed
                    .get("hash")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                self.status.observe_push(action, hash);
            }
        }
    }

    fn probe_answered(&self, generation: u64, value: Option<&Value>) {
        {
            let mut conn = self.lock_conn();
            if conn.generation != generation {
                return;
            }
            conn.pending_probe = false;
            conn.probe_sent = None;
            conn.misses = 0;
        }

        let field = |name: &str| value.and_then(|v| v.get(name));
        let app_version = field("appVersion")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let locked = field("locked").and_then(Value::as_bool);
        let database_hash = field("databaseHash")
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.status.probe_ok(app_version, locked, database_hash);
        self.publish_status();
    }

    /// Announce an `appRunning` change to the browser as an unsolicited
    /// host-level `ping` frame. The extension's state machine already treats
    /// such a frame exactly like a probe answer (it updates `appRunning` and
    /// rebuilds the session on a false→true transition), so this needs no new
    /// wire action and is ignored by clients that do not expect it.
    ///
    /// Only transitions are written: a steady app produces no traffic.
    fn publish_status(&self) {
        if !self.status_push.load(Ordering::SeqCst) {
            return;
        }
        let snapshot = self.status.snapshot();
        {
            let mut announced = self
                .announced_running
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if *announced == Some(snapshot.app_running) {
                return;
            }
            *announced = Some(snapshot.app_running);
        }
        let mut frame = serde_json::Map::new();
        frame.insert("action".into(), Value::from("ping"));
        frame.insert("success".into(), Value::from("true"));
        frame.insert(
            "protocolVersion".into(),
            Value::from(crate::dispatch::PROTOCOL_VERSION),
        );
        frame.insert(
            "hostVersion".into(),
            Value::from(crate::dispatch::HOST_VERSION),
        );
        frame.insert("appRunning".into(), Value::from(snapshot.app_running));
        frame.insert(
            "appVersion".into(),
            snapshot.app_version.map(Value::from).unwrap_or(Value::Null),
        );
        frame.insert(
            "locked".into(),
            snapshot.locked.map(Value::from).unwrap_or(Value::Null),
        );
        frame.insert(
            "databaseHash".into(),
            snapshot
                .database_hash
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
        if self.out.value(&Value::Object(frame)).is_err() {
            // The browser closed the port; the stdin loop will notice EOF and
            // exit. Nothing else to do from this thread.
        }
    }

    fn pop_pending(&self, action: &str) {
        let mut pending = self.lock_pending();
        if let Some(index) = pending.iter().position(|p| p.action == action) {
            pending.remove(index);
        }
    }

    fn reader_closed(&self, generation: u64) {
        let was_current = {
            let mut conn = self.lock_conn();
            if conn.generation == generation && conn.stream.is_some() {
                disconnect(&mut conn);
                true
            } else {
                false
            }
        };
        if was_current {
            self.status.set_disconnected();
            self.publish_status();
        }
        self.settle_generation(generation);
    }

    /// Clear status for a lost connection and settle everything in flight on
    /// it. Safe to call more than once for the same generation.
    fn on_generation_lost(&self, generation: u64) {
        let is_current = {
            let conn = self.lock_conn();
            conn.generation == generation && conn.stream.is_none()
        };
        if is_current {
            self.status.set_disconnected();
            self.publish_status();
        }
        self.settle_generation(generation);
    }

    fn settle_generation(&self, generation: u64) {
        let settled = {
            let mut pending = self.lock_pending();
            let mut keep = Vec::with_capacity(pending.len());
            let mut settled = Vec::new();
            for entry in pending.drain(..) {
                if entry.generation == generation {
                    settled.push(entry);
                } else {
                    keep.push(entry);
                }
            }
            *pending = keep;
            settled
        };
        for entry in settled {
            self.settle(
                &entry.action,
                errors::APP_UNAVAILABLE_COMPAT,
                "friendlypass is not running or the connection was lost",
            );
        }
    }

    /// Emit an unencrypted host error for a forwarded request.
    fn settle(&self, action: &str, code: u32, message: &str) {
        if self
            .out
            .value(&errors::host_error(action, code, message))
            .is_err()
        {
            std::process::exit(0);
        }
    }

    /// Manager loop: keep a live socket and probe it; reconnect with backoff.
    fn manage_loop(self: Arc<Self>) {
        let mut backoff = CONNECT_BACKOFF_INITIAL;
        loop {
            let connected = {
                let mut conn = self.lock_conn();
                conn.stream.is_some() || self.connect_locked(&mut conn)
            };
            if !connected {
                thread::sleep(backoff);
                backoff = std::cmp::min(backoff.saturating_mul(2), CONNECT_BACKOFF_MAX);
                continue;
            }
            backoff = CONNECT_BACKOFF_INITIAL;
            self.probe_tick();
            thread::sleep(PROBE_INTERVAL);
        }
    }

    fn probe_tick(&self) {
        let mut lost_generation = None;
        {
            let mut conn = self.lock_conn();
            if conn.stream.is_none() {
                return;
            }

            if conn.pending_probe
                && conn
                    .probe_sent
                    .is_some_and(|sent| sent.elapsed() > PROBE_TIMEOUT)
            {
                conn.misses += 1;
                conn.pending_probe = false;
            }

            if conn.misses >= PROBE_MISSES {
                lost_generation = Some(disconnect(&mut conn));
            } else if !conn.pending_probe {
                let written = match conn.stream.as_mut() {
                    Some(stream) => stream.write_all(PROBE_FRAME).is_ok(),
                    None => false,
                };
                if written {
                    conn.pending_probe = true;
                    conn.probe_sent = Some(Instant::now());
                } else {
                    lost_generation = Some(disconnect(&mut conn));
                }
            }
        }

        if let Some(generation) = lost_generation {
            self.on_generation_lost(generation);
        }
        self.sweep_expired();
    }

    /// Requests the app never answered are settled after [`PENDING_TIMEOUT`].
    fn sweep_expired(&self) {
        let expired = {
            let mut pending = self.lock_pending();
            let now = Instant::now();
            let mut keep = Vec::with_capacity(pending.len());
            let mut expired = Vec::new();
            for entry in pending.drain(..) {
                if now.duration_since(entry.since) >= PENDING_TIMEOUT {
                    expired.push(entry);
                } else {
                    keep.push(entry);
                }
            }
            *pending = keep;
            expired
        };
        for entry in expired {
            self.settle(
                &entry.action,
                errors::APP_UNAVAILABLE_COMPAT,
                "friendlypass did not answer in time",
            );
        }
    }
}

/// Tear down a connection in place and return its generation.
fn disconnect(conn: &mut Conn) -> u64 {
    let generation = conn.generation;
    if let Some(stream) = conn.stream.take() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    if let Some(shutdown) = conn.shutdown.take() {
        let _ = shutdown.shutdown(std::net::Shutdown::Both);
    }
    conn.pending_probe = false;
    conn.probe_sent = None;
    conn.misses = 0;
    generation
}

fn spawn_thread<F>(name: &str, body: F)
where
    F: FnOnce() + Send + 'static,
{
    // A failed thread spawn is not fatal: the manager simply tries again on
    // the next loop, and the writer queue stays drained by its owner.
    let _ = thread::Builder::new().name(name.to_owned()).spawn(body);
}
