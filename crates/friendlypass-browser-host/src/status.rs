//! Cached app status for `ping` / `hello`.
//!
//! The contract (§5.2) is specific: `appRunning` is true only when the host has
//! a live app socket **and** the app answered its most recent status probe
//! within the last 5 s. `locked` / `databaseHash` are cached and may lag; null
//! means unknown. Nothing here blocks on I/O, so `ping` can always answer
//! within its 100 ms budget.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Probe answers older than this make `appRunning` false.
const APP_RUNNING_FRESHNESS: Duration = Duration::from_secs(5);

/// A point-in-time view handed to `ping` / `hello`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub app_running: bool,
    pub app_version: Option<String>,
    pub locked: Option<bool>,
    pub database_hash: Option<String>,
    /// The app's verdict on the `host-identify` frame (contract §2): `true`
    /// only when the app verified that its socket peer is our host binary.
    /// `None` means the app has not answered the identify frame yet.
    pub app_trusted: Option<bool>,
}

#[derive(Default)]
struct State {
    connected: bool,
    last_probe_ok: Option<Instant>,
    app_version: Option<String>,
    locked: Option<bool>,
    database_hash: Option<String>,
    app_trusted: Option<bool>,
}

/// Mutex-protected status cache shared by the reader, manager, and dispatcher.
pub struct StatusCell {
    state: Mutex<State>,
}

impl StatusCell {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let app_running = state.connected
            && state
                .last_probe_ok
                .is_some_and(|at| at.elapsed() <= APP_RUNNING_FRESHNESS);
        Snapshot {
            app_running,
            app_version: state.app_version.clone(),
            locked: state.locked,
            database_hash: state.database_hash.clone(),
            app_trusted: state.app_trusted,
        }
    }

    /// A socket was established. Status fields stay unknown until the first
    /// probe answer; `appTrusted` is also reset because a new peer has not
    /// answered `host-identify` yet.
    pub fn set_connected(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.connected = true;
        state.last_probe_ok = None;
        state.app_trusted = None;
    }

    /// The socket is gone: everything becomes unknown again.
    pub fn set_disconnected(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.connected = false;
        state.last_probe_ok = None;
        state.app_version = None;
        state.locked = None;
        state.database_hash = None;
        state.app_trusted = None;
    }

    /// Record the app's answer to `host-identify` (contract §2). The verdict
    /// belongs to one connection: it is cleared on disconnect.
    pub fn set_app_trusted(&self, trusted: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.app_trusted = Some(trusted);
    }

    /// The app answered a status probe. `None` fields keep their cached value,
    /// which matters for apps that answer `ping` with a plain error frame.
    pub fn probe_ok(
        &self,
        app_version: Option<String>,
        locked: Option<bool>,
        database_hash: Option<String>,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.connected = true;
        state.last_probe_ok = Some(Instant::now());
        if app_version.is_some() {
            state.app_version = app_version;
        }
        if locked.is_some() {
            state.locked = locked;
        }
        if database_hash.is_some() {
            state.database_hash = database_hash;
        }
    }

    /// Reflect a push message in the cached status.
    pub fn observe_push(&self, action: &str, hash: Option<String>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match action {
            "database-locked" => state.locked = Some(true),
            "database-unlocked" => state.locked = Some(false),
            "database-changed" => {
                if let Some(hash) = hash {
                    state.database_hash = Some(hash);
                }
            }
            _ => {}
        }
    }
}

impl Default for StatusCell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_probe_means_running() {
        let cell = StatusCell::new();
        assert!(!cell.snapshot().app_running);
        cell.set_connected();
        // Connected but not probed yet: deliberately not "running".
        assert!(!cell.snapshot().app_running);
        cell.probe_ok(Some("0.1.0".into()), Some(true), Some("abc".into()));
        let snapshot = cell.snapshot();
        assert!(snapshot.app_running);
        assert_eq!(snapshot.app_version.as_deref(), Some("0.1.0"));
        assert_eq!(snapshot.locked, Some(true));
        assert_eq!(snapshot.database_hash.as_deref(), Some("abc"));
    }

    #[test]
    fn disconnect_clears_unknown_fields() {
        let cell = StatusCell::new();
        cell.probe_ok(Some("1".into()), Some(false), None);
        cell.set_disconnected();
        let snapshot = cell.snapshot();
        assert!(!snapshot.app_running);
        assert_eq!(snapshot.app_version, None);
        assert_eq!(snapshot.locked, None);
    }

    #[test]
    fn trust_starts_unknown_and_is_cleared_by_reconnect() {
        let cell = StatusCell::new();
        assert_eq!(cell.snapshot().app_trusted, None);
        cell.set_connected();
        assert_eq!(cell.snapshot().app_trusted, None);
        cell.set_app_trusted(true);
        assert_eq!(cell.snapshot().app_trusted, Some(true));
        cell.set_app_trusted(false);
        assert_eq!(cell.snapshot().app_trusted, Some(false));
        // A reconnect must not inherit the previous peer's verdict.
        cell.set_disconnected();
        assert_eq!(cell.snapshot().app_trusted, None);
        cell.set_connected();
        assert_eq!(cell.snapshot().app_trusted, None);
    }
}
