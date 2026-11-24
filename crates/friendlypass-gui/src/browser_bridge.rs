//! The GUI side of the browser protocol bridge.
//!
//! `friendlypass-browser` runs the socket and protocol state machine on
//! background threads. Anything that needs the database, the user or the
//! eframe paint loop goes through this module:
//!
//! * association approval is a real modal prompt in the Browser Integration
//!   dialog (the connection thread waits with a bounded deadline);
//! * `set-login` writes entries on the GUI thread and marks the database
//!   dirty;
//! * lock/unlock/changed pushes are broadcast to every connected browser;
//! * associations are persisted in database metadata under
//!   `KPXC_BROWSER_<id>`, exactly like KeePassXC.
//!
//! The server is started automatically once a database is unlocked. It keeps
//! answering `ping`/`hello` and returns error 1 while the database is locked.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use eframe::egui;
use keepass::db::{fields, CustomDataItem, CustomDataValue, Database, GroupId};

use friendlypass_browser::bridge::{AssociationRequest, BrowserBridge, SetLoginRequest};
use friendlypass_browser::service::lock_state;
use friendlypass_browser::{
    associations_from_database, browser_server_path, database_hash, snapshot_from_database,
    snapshot_signature, ServiceState, SharedState,
};

use crate::app::App;
use crate::dialogs::Dialog;

/// How long a connection thread waits for the user to approve an association.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a `set-login` request waits for the GUI to write the entry.
const SET_LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// Repaint interval while a browser request is waiting for the GUI.
const PENDING_REPAINT: Duration = Duration::from_millis(100);

struct ApprovalRequest {
    request: AssociationRequest,
    name: String,
    answer: Option<Option<String>>,
}

struct LoginJob {
    request: SetLoginRequest,
    result: Option<bool>,
}

#[derive(Default)]
struct BridgeState {
    approval: Option<ApprovalRequest>,
    login: Option<LoginJob>,
    unlock_requested: bool,
    lock_requested: bool,
}

/// The concrete [`BrowserBridge`] used by the GUI.
pub struct GuiBrowserBridge {
    state: Mutex<BridgeState>,
    cv: Condvar,
}

impl GuiBrowserBridge {
    fn new() -> GuiBrowserBridge {
        GuiBrowserBridge {
            state: Mutex::new(BridgeState::default()),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BridgeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn has_work(&self) -> bool {
        let state = self.lock();
        state.approval.is_some() || state.login.is_some() || state.unlock_requested || state.lock_requested
    }

    /// The association currently waiting for the user, if any.
    pub fn pending_approval(&self) -> Option<(String, String)> {
        self.lock()
            .approval
            .as_ref()
            .map(|approval| (approval.name.clone(), approval.request.client_id.clone()))
    }

    pub fn set_approval_name(&self, name: String) {
        if let Some(approval) = self.lock().approval.as_mut() {
            approval.name = name;
        }
    }

    /// Approve under `name` (`None` denies; the server then returns error 6).
    pub fn answer_approval(&self, name: Option<String>) {
        if let Some(approval) = self.lock().approval.as_mut() {
            approval.answer = Some(name);
            self.cv.notify_all();
        }
    }

    fn take_login(&self) -> Option<SetLoginRequest> {
        self.lock().login.as_ref().map(|job| job.request.clone())
    }

    fn finish_login(&self, result: bool) {
        if let Some(job) = self.lock().login.as_mut() {
            job.result = Some(result);
            self.cv.notify_all();
        }
    }

    fn take_unlock_request(&self) -> bool {
        let mut state = self.lock();
        std::mem::take(&mut state.unlock_requested)
    }

    fn take_lock_request(&self) -> bool {
        let mut state = self.lock();
        std::mem::take(&mut state.lock_requested)
    }
}

impl BrowserBridge for GuiBrowserBridge {
    fn approve_association(&self, request: &AssociationRequest) -> Option<String> {
        {
            let mut state = self.lock();
            if state.approval.is_some() {
                // One prompt at a time; a second concurrent association is
                // denied rather than queued behind a dialog.
                return None;
            }
            state.approval = Some(ApprovalRequest {
                request: request.clone(),
                name: sanitise_association_id(&request.suggested_id),
                answer: None,
            });
        }
        self.cv.notify_all();

        let deadline = Instant::now() + APPROVAL_TIMEOUT;
        let mut state = self.lock();
        loop {
            if state
                .approval
                .as_ref()
                .is_some_and(|approval| approval.answer.is_some())
            {
                break;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                state.approval = None;
                return None;
            };
            let (next, _) = self
                .cv
                .wait_timeout(state, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
        }
        state
            .approval
            .take()
            .and_then(|approval| approval.answer)
            .flatten()
            .map(|name| sanitise_association_id(&name))
    }

    fn request_unlock(&self) {
        self.lock().unlock_requested = true;
        self.cv.notify_all();
    }

    fn lock_database(&self) {
        self.lock().lock_requested = true;
        self.cv.notify_all();
    }

    fn apply_set_login(&self, request: &SetLoginRequest) -> bool {
        {
            let mut state = self.lock();
            if state.login.is_some() {
                return false;
            }
            state.login = Some(LoginJob {
                request: request.clone(),
                result: None,
            });
        }
        self.cv.notify_all();

        let deadline = Instant::now() + SET_LOGIN_TIMEOUT;
        let mut state = self.lock();
        loop {
            if state.login.as_ref().is_some_and(|job| job.result.is_some()) {
                break;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                state.login = None;
                return false;
            };
            let (next, _) = self
                .cv
                .wait_timeout(state, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
        }
        state
            .login
            .take()
            .and_then(|job| job.result)
            .unwrap_or(false)
    }
}

/// Start serving the browser protocol for the currently open database. Safe to
/// call on every unlock: it is a no-op when a server is already running.
pub fn start(app: &mut App) {
    start_inner(app, true);
}

/// Auto-start on unlock without replacing the unlock status message.
pub fn start_background(app: &mut App) {
    start_inner(app, false);
}

fn start_inner(app: &mut App, announce: bool) {
    if app.browser_handle.is_some() {
        return;
    }
    let bridge = app
        .browser_bridge
        .get_or_insert_with(|| Arc::new(GuiBrowserBridge::new()))
        .clone();
    let mut state = match app.db.as_ref() {
        Some(db) => snapshot_from_database(db),
        None => ServiceState {
            locked: true,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            ..Default::default()
        },
    };
    state.set_bridge(bridge);
    let state: SharedState = Arc::new(Mutex::new(state));
    let path = browser_server_path();
    match friendlypass_browser::start(&path, state.clone()) {
        Ok(handle) => {
            app.browser_handle = Some(handle);
            app.browser_state = Some(state);
            if announce {
                app.status = format!("Browser protocol serving on {}", path.display());
            }
        }
        Err(error) => {
            // Auto-start must not clobber an unlock message; the Browser
            // dialog's explicit Start still reports the failure.
            if announce || app.status.is_empty() {
                app.status = format!("cannot start browser server: {error:#}");
            }
        }
    }
}

/// Stop serving and forget the GUI bridge.
pub fn stop(app: &mut App) {
    // Settle anything a connection thread is waiting on before dropping the
    // bridge, so no request is left hanging until its deadline.
    if let Some(bridge) = app.browser_bridge.as_ref() {
        if bridge.pending_approval().is_some() {
            bridge.answer_approval(None);
        }
        bridge.finish_login(false);
    }
    if let Some(handle) = app.browser_handle.take() {
        handle.stop();
    }
    app.browser_state = None;
    app.browser_bridge = None;
    app.status = "Browser integration stopped".into();
}

/// Run once per frame, before drawing. Processes bridge requests, keeps the
/// served snapshot in sync and emits lock/unlock/changed pushes.
pub fn pump(app: &mut App, ctx: &egui::Context) {
    let Some(push) = app.browser_handle.as_ref().map(|handle| handle.push_hub()) else {
        return;
    };
    let Some(bridge) = app.browser_bridge.clone() else {
        return;
    };

    // Interactive requests first: the server thread is waiting for them.
    if bridge.pending_approval().is_some() {
        if matches!(app.dialog, Dialog::None) {
            app.dialog = Dialog::Browser;
        }
        ctx.request_repaint_after(PENDING_REPAINT);
    }

    if let Some(request) = bridge.take_login() {
        let accepted = apply_set_login(app, &request);
        bridge.finish_login(accepted);
        ctx.request_repaint();
    }

    if bridge.take_unlock_request() {
        if app.db.is_none() {
            app.focus_password = true;
            app.unlock_error.clear();
            app.status = "Unlock friendlypass to use the browser extension".into();
        }
        ctx.request_repaint();
    }

    if bridge.take_lock_request() && app.db.is_some() {
        app.lock();
        ctx.request_repaint();
    }

    let associations_changed = sync(app, &push);

    if bridge.has_work() {
        ctx.request_repaint_after(PENDING_REPAINT);
    } else if associations_changed {
        ctx.request_repaint();
    } else {
        // Poll for server-side requests (association approval, lock/unlock)
        // even while the app is otherwise idle.
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

/// Copy the live database into the served snapshot and emit transition pushes.
fn sync(app: &mut App, push: &friendlypass_browser::PushHub) -> bool {
    let Some(shared) = app.browser_state.clone() else {
        return false;
    };

    let Some(db) = app.db.as_mut() else {
        let was_locked = {
            let mut state = lock_state(&shared);
            let was = state.locked;
            state.locked = true;
            state.entries.clear();
            state.groups.clear();
            state.db_hash.clear();
            was
        };
        if !was_locked {
            push.send_locked();
        }
        return false;
    };

    let new_hash = database_hash(&db.root().id().uuid().simple().to_string());
    let signature = snapshot_signature(db);
    let (was_locked, old_hash, old_signature) = {
        let state = lock_state(&shared);
        (state.locked, state.db_hash.clone(), state.snapshot_signature)
    };
    let switched = !old_hash.is_empty() && old_hash != new_hash;

    let mut associations_changed = false;
    if switched {
        // A different database: its metadata owns the association list.
        let mut state = lock_state(&shared);
        state.associations = associations_from_database(db);
        state.associations_changed = false;
    } else {
        associations_changed = persist_associations(app, &shared);
    }

    let snapshot = match app.db.as_ref() {
        Some(db) => snapshot_from_database(db),
        None => return associations_changed,
    };
    {
        let mut state = lock_state(&shared);
        let had_pending = state.associations_changed;
        state.locked = false;
        if was_locked || switched || old_signature != signature || state.entries.len() != snapshot.entries.len()
        {
            state.entries = snapshot.entries;
            state.groups = snapshot.groups;
        }
        state.snapshot_signature = signature;
        state.db_hash = snapshot.db_hash.clone();
        if !switched {
            // Preserve a just-approved association that may have landed after
            // the snapshot was read; revocations were already removed.
            for (id, key) in snapshot.associations {
                state.associations.entry(id).or_insert(key);
            }
        } else {
            state.associations = snapshot.associations;
        }
        state.associations_changed = had_pending && state.associations_changed;
    }

    let hash_changed = old_hash != snapshot.db_hash;
    let entries_changed = !was_locked && (switched || old_signature != signature);
    if was_locked {
        push.send_unlocked();
        push.send_changed(Some(&snapshot.db_hash));
    } else if hash_changed {
        push.send_changed(Some(&snapshot.db_hash));
    } else if associations_changed || entries_changed {
        // Metadata or entries changed: tell clients without claiming a new hash.
        push.send_changed(None);
    }
    associations_changed || entries_changed
}

/// Write in-memory associations into database metadata (`KPXC_BROWSER_<id>`)
/// and remove metadata entries the user revoked.
fn persist_associations(app: &mut App, shared: &SharedState) -> bool {
    let desired = lock_state(shared).associations.clone();
    let Some(db) = app.db.as_mut() else {
        return false;
    };
    let mut changed = false;
    let prefix = friendlypass_browser::BROWSER_CUSTOM_DATA_PREFIX;
    for (id, key) in &desired {
        let metadata_key = format!("{prefix}{id}");
        let existing = db
            .meta
            .custom_data
            .get(&metadata_key)
            .and_then(friendlypass_browser::custom_string);
        if existing.as_deref() != Some(key.as_str()) {
            db.meta.custom_data.insert(
                metadata_key,
                CustomDataItem {
                    value: Some(CustomDataValue::String(key.clone())),
                    last_modification_time: Some(chrono::Utc::now().naive_utc()),
                },
            );
            changed = true;
        }
    }
    let stale: Vec<String> = db
        .meta
        .custom_data
        .keys()
        .filter(|key| key.starts_with(prefix))
        .filter(|key| !desired.contains_key(&key[prefix.len()..]))
        .cloned()
        .collect();
    for key in stale {
        db.meta.custom_data.remove(&key);
        changed = true;
    }
    if changed {
        let was_dirty = app.dirty;
        app.dirty = true;
        lock_state(shared).associations_changed = false;
        if !was_dirty {
            save_associations_now(app);
        }
    }
    changed
}

/// Persist the metadata immediately when it is the only unsaved change, so an
/// approved association survives an app restart without a manual save.
fn save_associations_now(app: &mut App) {
    let path = std::path::PathBuf::from(&app.db_path);
    if path.as_os_str().is_empty() {
        return;
    }
    let result = {
        let Some(db) = app.db.as_ref() else {
            return;
        };
        if !matches!(
            db.config.version,
            keepass::config::DatabaseVersion::KDB4(_)
        ) {
            None
        } else {
            app.db_key
                .clone()
                .map(|key| friendlypass::saveutil::save(&path, db, key))
        }
    };
    match result {
        None => {
            app.status = "Browser association added; save the database to keep it".into();
        }
        Some(Ok(())) => {
            app.dirty = false;
            app.status = "Browser association saved".into();
        }
        Some(Err(error)) => {
            app.status = format!("cannot save browser association: {error:#}");
        }
    }
}

/// Apply a `set-login` request on the GUI thread.
fn apply_set_login(app: &mut App, request: &SetLoginRequest) -> bool {
    let Some(db) = app.db.as_mut() else {
        return false;
    };
    let now = chrono::Utc::now().naive_utc();
    let mut accepted = false;

    if let Some(uuid) = &request.uuid {
        let target = db
            .iter_all_entries()
            .find(|entry| entry.id().uuid().simple().to_string() == *uuid)
            .map(|entry| entry.id());
        if let Some(id) = target {
            if let Some(mut entry) = db.entry_mut(id) {
                entry.set_unprotected(fields::USERNAME, &request.login);
                entry.set_protected(fields::PASSWORD, &request.password);
                entry.set_unprotected(fields::URL, &request.url);
                if let Some(submit) = &request.submit_url {
                    if submit != &request.url {
                        entry.set_unprotected("KP2A_URL", submit);
                    }
                }
                entry.times.last_modification = Some(now);
                accepted = true;
            }
        }
    } else {
        let group_id = target_group(db, request.group_uuid.as_deref(), request.group.as_deref());
        if let Some(mut group) = db.group_mut(group_id) {
            let mut entry = group.add_entry();
            entry.set_unprotected(fields::TITLE, title_for_url(&request.url));
            entry.set_unprotected(fields::USERNAME, &request.login);
            entry.set_protected(fields::PASSWORD, &request.password);
            entry.set_unprotected(fields::URL, &request.url);
            if let Some(submit) = &request.submit_url {
                if submit != &request.url {
                    entry.set_unprotected("KP2A_URL", submit);
                }
            }
            entry.times.creation = Some(now);
            entry.times.last_modification = Some(now);
            accepted = true;
        }
    }

    if accepted {
        app.dirty = true;
        app.status = "Saved a login from the browser".into();
    }
    accepted
}

fn target_group(db: &Database, uuid: Option<&str>, name: Option<&str>) -> GroupId {
    if let Some(uuid) = uuid.and_then(friendlypass_browser::protocol::normalize_uuid) {
        if let Some(group) = db
            .iter_all_groups()
            .find(|group| group.id().uuid().simple().to_string() == uuid)
        {
            return group.id();
        }
    }
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        if let Some(group) = db.iter_all_groups().find(|group| group.name == name) {
            return group.id();
        }
    }
    db.root().id()
}

fn title_for_url(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_start_matches("www.");
    if host.is_empty() {
        "Browser login".to_owned()
    } else {
        host.to_owned()
    }
}

fn sanitise_association_id(id: &str) -> String {
    let cleaned: String = id
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "chrome-browser".to_owned()
    } else {
        cleaned
    }
}

// -- helpers used by the Browser Integration dialog ------------------------

/// Current association names, sorted for display.
pub fn association_names(app: &App) -> Vec<String> {
    let Some(state) = app.browser_state.as_ref() else {
        return Vec::new();
    };
    let mut names: Vec<String> = lock_state(state).associations.keys().cloned().collect();
    names.sort();
    names
}

/// Revoke one association; the change is persisted on the next pump.
pub fn revoke_association(app: &App, id: &str) {
    let Some(state) = app.browser_state.as_ref() else {
        return;
    };
    let mut state = lock_state(state);
    if state.associations.remove(id).is_some() {
        state.associations_changed = true;
    }
}

/// The pending approval, if the Browser dialog should render the prompt.
pub fn pending_approval(app: &App) -> Option<(String, String)> {
    app.browser_bridge.as_ref()?.pending_approval()
}

pub fn approval_name(app: &App) -> String {
    pending_approval(app)
        .map(|(name, _)| name)
        .unwrap_or_default()
}

pub fn set_approval_name(app: &App, name: String) {
    if let Some(bridge) = app.browser_bridge.as_ref() {
        bridge.set_approval_name(name);
    }
}

pub fn answer_approval(app: &App, name: Option<String>) {
    if let Some(bridge) = app.browser_bridge.as_ref() {
        bridge.answer_approval(name);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn association_approval_round_trip() {
        let bridge = Arc::new(GuiBrowserBridge::new());
        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || {
                bridge.approve_association(&AssociationRequest {
                    client_id: "client".into(),
                    suggested_id: "chrome-browser".into(),
                })
            })
        };
        // Wait until the GUI would see the prompt.
        for _ in 0..100 {
            if bridge.pending_approval().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let (name, client) = bridge.pending_approval().expect("approval prompt");
        assert_eq!(client, "client");
        bridge.set_approval_name(format!("{name}-work"));
        bridge.answer_approval(Some("chrome-work-laptop".into()));
        assert_eq!(worker.join().unwrap().as_deref(), Some("chrome-work-laptop"));
    }

    #[test]
    fn association_denial_returns_none() {
        let bridge = Arc::new(GuiBrowserBridge::new());
        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || {
                bridge.approve_association(&AssociationRequest {
                    client_id: "client".into(),
                    suggested_id: "chrome-browser".into(),
                })
            })
        };
        for _ in 0..100 {
            if bridge.pending_approval().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        bridge.answer_approval(None);
        assert_eq!(worker.join().unwrap(), None);
    }

    #[test]
    fn association_names_are_sanitised() {
        assert_eq!(sanitise_association_id("  work\nlaptop  "), "worklaptop");
        assert_eq!(sanitise_association_id(""), "chrome-browser");
    }

    #[test]
    fn set_login_bridge_round_trip() {
        let bridge = Arc::new(GuiBrowserBridge::new());
        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || {
                bridge.apply_set_login(&SetLoginRequest {
                    acting_id: "id".into(),
                    login: "alice".into(),
                    password: "secret".into(),
                    url: "https://example.com".into(),
                    submit_url: None,
                    group: None,
                    group_uuid: None,
                    uuid: None,
                    download_favicon: false,
                })
            })
        };
        for _ in 0..100 {
            if bridge.take_login().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        bridge.finish_login(true);
        assert!(worker.join().unwrap());
    }

    #[test]
    fn title_comes_from_the_url_host() {
        assert_eq!(title_for_url("https://www.example.com/login"), "example.com");
        assert_eq!(title_for_url("not a url"), "not a url");
    }
}
