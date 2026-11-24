//! Headless friendlypass protocol server for the Phase-1 exit test.
//!
//! Opens a real database from `fixtures/` with the `friendlypass` crate,
//! installs an auto-approving association bridge (so `associate` needs no
//! GUI), and serves the KeePassXC-Browser protocol on
//! `friendlypass_browser::browser_server_path()` — i.e. on `FP_APP_SOCKET`
//! when the e2e harness sets it. Nothing ever touches the user's real socket
//! or database: the harness passes a copied fixture path and a temp socket.
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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friendlypass_browser::service::lock_state;
use friendlypass_browser::{snapshot_from_database, start, AutoApproveBridge};
use keepass::DatabaseKey;

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

    let database =
        friendlypass::saveutil::open(&db_path, DatabaseKey::new().with_password(&password))?;
    let mut state = snapshot_from_database(&database);
    state.set_bridge(Arc::new(AutoApproveBridge::new(ASSOCIATION_ID)));
    if let Some(path) = association_path.as_ref() {
        for (id, key) in load_associations(path) {
            state.associations.insert(id, key);
        }
    }
    let state = Arc::new(Mutex::new(state));

    let socket = friendlypass_browser::browser_server_path();
    let handle = start(&socket, Arc::clone(&state))?;
    log(
        "listening",
        &format!("\"socket\":{}", json_string(&socket.display().to_string())),
    );
    eprintln!(
        "test_server: serving {} on {}",
        db_path.display(),
        socket.display()
    );

    // Persist new associations and report connection counts for the harness.
    let mut last_clients = 0usize;
    let mut last_written: Option<HashMap<String, String>> = None;
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
