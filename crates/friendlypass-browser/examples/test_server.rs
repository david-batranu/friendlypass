//! Headless friendlypass protocol server for the Phase-1 exit test.
//!
//! Opens a real database from `fixtures/` with the `friendlypass` crate,
//! installs an auto-approving association bridge (so `associate` needs no
//! GUI), and serves the KeePassXC-Browser protocol on
//! `friendlypass_browser::browser_server_path()` — i.e. on `FP_APP_SOCKET`
//! when the e2e harness sets it. `set-login` writes the entry with the same
//! code path as the GUI bridge (`entry_write::apply_set_login`) and saves the
//! KDBX file, so a test can reopen it with the CLI. Nothing ever touches the
//! user's real socket or database: the harness passes a copied fixture path and
//! a temp socket.
//!
//! Usage:
//!   test_server [--db PATH] [--associations PATH] [--log PATH]
//!
//! `--associations` is a JSON sidecar (`{"<id>":"<Base64 key>"}`) updated
//! whenever the server stores a new association. It mirrors the real app's
//! persistence in KDBX metadata, so an app restart keeps existing browsers
//! associated without re-approval.
//!
//! Diagnostics (never credentials) go to stderr and the optional JSONL log.
//!
//! `FP_TEST_APPROVAL_DELAY_MS` (default 0) makes `associate` wait that long
//! before the auto-approval returns, so integration tests can verify the host
//! keeps its connection (and the app keeps answering `ping`) while an approval
//! is pending. It is a test hook only; production bridges never read it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friendlypass_browser::service::lock_state;
use friendlypass_browser::{snapshot_from_database, FileBridge};
use keepass::{Database, DatabaseKey};

const DEFAULT_DB: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/sample4.kdbx");
const DEFAULT_PASSWORD: &str = "testpassword";
const ASSOCIATION_ID: &str = "chrome-work-laptop";

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let index = args
        .iter()
        .position(|value| value == &format!("--{name}"))?;
    args.get(index + 1).cloned()
}

fn main() -> anyhow::Result<()> {
    let db_path = PathBuf::from(arg("db").unwrap_or_else(|| DEFAULT_DB.to_owned()));
    let association_path = arg("associations").map(PathBuf::from);
    let log_path = arg("log").map(PathBuf::from);
    let password = std::env::var("FP_TEST_DB_PASSWORD")
        .ok()
        .unwrap_or_else(|| DEFAULT_PASSWORD.to_owned());

    let log = |event: &str, detail: &str| {
        let Some(path) = log_path.as_ref() else {
            return;
        };
        let line = format!(
            "{{\"ts\":{},\"event\":\"{event}\"{}{}}}\n",
            now_ms(),
            if detail.is_empty() { "" } else { "," },
            detail
        );
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            let _ = file.write_all(line.as_bytes());
        }
    };

    let key = DatabaseKey::new().with_password(&password);
    let database = friendlypass::saveutil::open(&db_path, key.clone())?;
    let database: Arc<Mutex<Database>> = Arc::new(Mutex::new(database));
    let mut state = {
        let guard = database.lock().expect("test database");
        snapshot_from_database(&guard)
    };
    // Auto-approve associations and persist every `set-login` with the same
    // entry-writing code path the GUI uses, then save the KDBX file.
    let bridge = Arc::new(FileBridge::new(
        ASSOCIATION_ID,
        Arc::clone(&database),
        key,
        db_path.clone(),
    ));
    state.set_bridge(bridge.clone());
    if let Some(path) = association_path.as_ref() {
        for (id, key) in load_associations(path) {
            state.associations.insert(id, key);
        }
    }
    let state = Arc::new(Mutex::new(state));

    let socket = friendlypass_browser::browser_server_path();
    // Contract §3: the harness may point the server at the native host binary
    // whose socket peer may be auto-approved. Unset = never trust a peer.
    let trusted_host_path = std::env::var_os("FP_TRUSTED_HOST_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let handle = friendlypass_browser::start_with_config(
        &socket,
        friendlypass_browser::ServerConfig { trusted_host_path },
        Arc::clone(&state),
    )?;
    log(
        "listening",
        &format!("\"socket\":{}", json_string(&socket.display().to_string())),
    );
    eprintln!(
        "test_server: serving {} on {}",
        db_path.display(),
        socket.display()
    );

    // Persist new associations, refresh the served snapshot after a browser
    // save, and report connection counts for the harness.
    let mut last_clients = 0usize;
    let mut last_written: Option<HashMap<String, String>> = None;
    let mut last_save_error: Option<String> = None;
    loop {
        std::thread::sleep(Duration::from_millis(10));
        let (associations, changed) = {
            let mut guard = lock_state(&state);
            let changed = guard.associations_changed;
            guard.associations_changed = false;
            (guard.associations.clone(), changed)
        };
        if changed {
            if let Some(path) = association_path.as_ref() {
                if last_written.as_ref() != Some(&associations) {
                    save_associations(path, &associations)?;
                    last_written = Some(associations.clone());
                    log("associations-saved", "");
                }
            }
        }

        // A `set-login` mutated and saved the file on the bridge; make the
        // in-memory snapshot match so later get-logins calls see the entry.
        if bridge.take_changed() {
            let snapshot = {
                let guard = database.lock().expect("test database");
                snapshot_from_database(&guard)
            };
            {
                let mut guard = lock_state(&state);
                guard.entries = snapshot.entries;
                guard.groups = snapshot.groups;
                guard.db_hash = snapshot.db_hash;
                guard.snapshot_signature = snapshot.snapshot_signature;
                guard.push.send_changed(None);
            }
            log("database-saved", "");
        }

        let save_error = bridge.last_error();
        if save_error != last_save_error {
            if let Some(message) = save_error.as_deref() {
                log("save-error", &format!("\"error\":{}", json_string(message)));
            }
            last_save_error = save_error;
        }

        let clients = handle.client_count();
        if clients != last_clients {
            log("client-count", &format!("\"count\":{clients}"));
            last_clients = clients;
        }
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| value.as_millis())
}

fn json_string(value: &str) -> String {
    // Only paths/ids are ever passed here; escaping the few JSON metacharacters
    // is enough and avoids adding a logging dependency.
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn load_associations(path: &Path) -> HashMap<String, String> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<HashMap<String, String>>(&bytes).ok())
        .unwrap_or_default()
}

fn save_associations(path: &Path, associations: &HashMap<String, String>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(associations)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
