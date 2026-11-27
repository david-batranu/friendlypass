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

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use eframe::egui;
use keepass::db::{CustomDataItem, CustomDataValue};
use serde_json::Value;

use friendlypass_browser::bridge::{
    AssociationRequest, BrowserBridge, PasskeyCandidate, PasskeyGetRequest, PasskeyRegisterRequest,
    SetLoginRequest,
};
use friendlypass_browser::protocol::{BrowserIdentity, ERROR_PASSKEYS_REQUEST_CANCELED};
use friendlypass_browser::service::lock_state;
use friendlypass_browser::{
    associations_from_database, browser_server_path, database_hash, snapshot_from_database,
    snapshot_signature, ServerConfig, ServiceState, SharedState,
};

use crate::app::App;
use crate::dialogs::Dialog;
use crate::window_focus::{ActivePrompt, NoopWindowFocus, WindowFocusDriver};

/// How long a connection thread waits for the user to approve an association.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a `set-login` request waits for the GUI to write the entry.
const SET_LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a passkey confirmation waits for the user. The page may ask for up
/// to 120 s (`PASSKEYS_WAIT_FOR_LIFETIMER`); the bridge deadline is the same.
const PASSKEY_TIMEOUT: Duration = Duration::from_secs(120);
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

/// One queued passkey request. The server thread waits on `reply`; the GUI
/// drains the queue one dialog at a time.
#[derive(Clone)]
pub enum PasskeyRequest {
    Register(PasskeyRegisterRequest),
    Get(PasskeyGetRequest),
}

struct PasskeyJob {
    id: u64,
    request: PasskeyRequest,
    reply: Arc<(Mutex<Option<Result<Value, i32>>>, Condvar)>,
}

#[derive(Default)]
struct BridgeState {
    approval: Option<ApprovalRequest>,
    login: Option<LoginJob>,
    passkeys: VecDeque<PasskeyJob>,
    /// Entry UUID selected in the current prompt (`None` = create new).
    passkey_selection: Option<String>,
    next_passkey_id: u64,
    unlock_requested: bool,
    lock_requested: bool,
}

/// A non-blocking "Chrome connected to friendlypass" notice with a Revoke
/// action (contract §5). Shown by the main window, not by a dialog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserNotice {
    /// Display name of the browser, e.g. `"Chrome"`.
    pub browser: String,
    /// The association the automatic approval created.
    pub association_id: String,
}

/// What the passkey dialog is asking. Contains no private key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasskeyPromptKind {
    Register {
        rp_id: String,
        rp_name: String,
        username: String,
        origin: String,
        /// Same-RP/same-user-handle passkeys the user may update instead.
        existing: Vec<PasskeyCandidate>,
    },
    Get {
        rp_id: String,
        candidates: Vec<PasskeyCandidate>,
    },
}

/// A snapshot of the request the passkey dialog must render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyPrompt {
    pub id: u64,
    pub kind: PasskeyPromptKind,
}

/// The concrete [`BrowserBridge`] used by the GUI.
pub struct GuiBrowserBridge {
    state: Mutex<BridgeState>,
    cv: Condvar,
    /// "Require approval for new browsers"; mirrors the preference so the
    /// connection thread can decide without touching the GUI.
    require_approval: AtomicBool,
    notices: Mutex<Vec<BrowserNotice>>,
    egui_ctx: Mutex<Option<egui::Context>>,
    window_focus: Mutex<Arc<dyn WindowFocusDriver>>,
}

impl GuiBrowserBridge {
    fn new(require_approval: bool) -> GuiBrowserBridge {
        GuiBrowserBridge {
            state: Mutex::new(BridgeState::default()),
            cv: Condvar::new(),
            require_approval: AtomicBool::new(require_approval),
            notices: Mutex::new(Vec::new()),
            egui_ctx: Mutex::new(None),
            window_focus: Mutex::new(Arc::new(NoopWindowFocus)),
        }
    }

    pub fn set_egui_ctx(&self, ctx: &egui::Context) {
        let mut slot = self
            .egui_ctx
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(ctx.clone());
        }
    }

    pub fn set_window_focus(&self, driver: Arc<dyn WindowFocusDriver>) {
        *self
            .window_focus
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = driver;
    }

    fn wake_gui(&self) {
        if let Some(ctx) = self
            .egui_ctx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            ctx.request_repaint();
        }
    }

    /// Wake a potentially minimized/backgrounded desktop window right when an
    /// interactive confirmation (passkey, browser approval, unlock) arrives.
    fn wake_gui_for_prompt(&self) {
        let driver = Arc::clone(
            &self
                .window_focus
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        driver.wake_from_background();
        self.wake_gui();
    }

    fn lock(&self) -> MutexGuard<'_, BridgeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn has_work(&self) -> bool {
        let state = self.lock();
        state.approval.is_some()
            || state.login.is_some()
            || !state.passkeys.is_empty()
            || state.unlock_requested
            || state.lock_requested
    }

    /// Follow the "Require approval for new browsers" preference.
    pub fn set_require_approval(&self, require: bool) {
        self.require_approval.store(require, Ordering::Relaxed);
    }

    /// Completed automatic approvals the main window has not shown yet.
    pub fn take_notices(&self) -> Vec<BrowserNotice> {
        std::mem::take(
            &mut *self
                .notices
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
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

    /// Queue one passkey request and block the connection thread until the GUI
    /// answers (or the deadline passes). One request is in front at a time.
    fn enqueue_passkey(&self, request: PasskeyRequest) -> Result<Value, i32> {
        let reply = Arc::new((Mutex::new(None), Condvar::new()));
        let id = {
            let mut state = self.lock();
            state.next_passkey_id += 1;
            let id = state.next_passkey_id;
            state.passkey_selection = match &request {
                PasskeyRequest::Get(request) => {
                    request.candidates.first().map(|candidate| candidate.uuid.clone())
                }
                PasskeyRequest::Register(_) => None,
            };
            state.passkeys.push_back(PasskeyJob {
                id,
                request,
                reply: Arc::clone(&reply),
            });
            id
        };
        self.cv.notify_all();
        self.wake_gui_for_prompt();

        let deadline = Instant::now() + PASSKEY_TIMEOUT;
        let (lock, cv) = &*reply;
        let mut answer = lock.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(result) = answer.take() {
                return result;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                // The GUI never answered: remove the job so a later pump does
                // not open a stale dialog, and report a cancellation.
                let mut state = self.lock();
                state.passkeys.retain(|job| job.id != id);
                return Err(ERROR_PASSKEYS_REQUEST_CANCELED);
            };
            let (next, _) = cv
                .wait_timeout(answer, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            answer = next;
        }
    }

    /// The prompt the dialog should render, if any.
    pub fn pending_passkey(&self) -> Option<PasskeyPrompt> {
        let state = self.lock();
        state.passkeys.front().map(|job| PasskeyPrompt {
            id: job.id,
            kind: match &job.request {
                PasskeyRequest::Register(request) => PasskeyPromptKind::Register {
                    rp_id: request.prepared.rp_id.clone(),
                    rp_name: request.prepared.rp_name.clone(),
                    username: request.prepared.username.clone(),
                    origin: request.origin.clone(),
                    existing: request.existing.clone(),
                },
                PasskeyRequest::Get(request) => PasskeyPromptKind::Get {
                    rp_id: request.prepared.rp_id.clone(),
                    candidates: request.candidates.clone(),
                },
            },
        })
    }

    /// The request behind [`GuiBrowserBridge::pending_passkey`].
    pub fn pending_passkey_request(&self) -> Option<(u64, PasskeyRequest)> {
        let state = self.lock();
        state
            .passkeys
            .front()
            .map(|job| (job.id, job.request.clone()))
    }

    pub fn passkey_selection(&self) -> Option<String> {
        self.lock().passkey_selection.clone()
    }

    pub fn select_passkey(&self, selection: Option<String>) {
        self.lock().passkey_selection = selection;
    }

    /// Answer the request at the front of the queue.
    fn finish_passkey(&self, id: u64, result: Result<Value, i32>) {
        let job = {
            let mut state = self.lock();
            match state.passkeys.front() {
                Some(job) if job.id == id => state.passkeys.pop_front(),
                _ => None,
            }
        };
        if let Some(job) = job {
            let (lock, cv) = &*job.reply;
            *lock.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
            cv.notify_all();
            self.cv.notify_all();
        }
    }

    fn cancel_all_passkeys(&self) {
        let jobs: Vec<PasskeyJob> = {
            let mut state = self.lock();
            state.passkeys.drain(..).collect()
        };
        for job in jobs {
            let (lock, cv) = &*job.reply;
            *lock.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Err(ERROR_PASSKEYS_REQUEST_CANCELED));
            cv.notify_all();
        }
        self.cv.notify_all();
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
        // Contract §5: a trusted peer with a host-verified browser is approved
        // immediately unless the user asked for a prompt.
        if let Some(name) = friendlypass_browser::bridge::auto_approve_name(
            request,
            self.require_approval.load(Ordering::Relaxed),
        ) {
            let browser = request
                .browser
                .as_ref()
                .map(BrowserIdentity::display_name)
                .unwrap_or("Browser")
                .to_owned();
            self.notices
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(BrowserNotice {
                    browser,
                    association_id: name.clone(),
                });
            self.cv.notify_all();
            self.wake_gui();
            return Some(name);
        }

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
        self.wake_gui_for_prompt();

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
        self.wake_gui_for_prompt();
    }

    fn lock_database(&self) {
        self.lock().lock_requested = true;
        self.cv.notify_all();
        self.wake_gui();
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
        self.wake_gui();

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

    fn passkeys_register(&self, request: &PasskeyRegisterRequest) -> Result<Value, i32> {
        self.enqueue_passkey(PasskeyRequest::Register(request.clone()))
    }

    fn passkeys_get(&self, request: &PasskeyGetRequest) -> Result<Value, i32> {
        self.enqueue_passkey(PasskeyRequest::Get(request.clone()))
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
    let require_approval = app.prefs.require_approval_for_new_browsers;
    let bridge = app
        .browser_bridge
        .get_or_insert_with(|| Arc::new(GuiBrowserBridge::new(require_approval)))
        .clone();
    bridge.set_window_focus(app.window_focus.driver());
    // Contract §3: the only socket peer that may be auto-approved is our own
    // native host binary.
    let trusted_host_path = native_host_path(app);
    let mut state = match app.db.as_ref() {
        Some(db) => snapshot_from_database(db),
        None => ServiceState {
            locked: true,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            ..Default::default()
        },
    };
    state.allow_localhost_passkeys = app.prefs.allow_localhost_passkeys;
    state.set_bridge(bridge);
    let state: SharedState = Arc::new(Mutex::new(state));
    let path = browser_server_path();
    let config = ServerConfig { trusted_host_path };
    match friendlypass_browser::start_with_config(&path, config, state.clone()) {
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
        bridge.cancel_all_passkeys();
    }
    if let Some(handle) = app.browser_handle.take() {
        handle.stop();
    }
    app.browser_state = None;
    app.browser_bridge = None;
    app.status = "Browser integration stopped".into();
}

// -- native-messaging manifests ------------------------------------------

/// What one settings change did, for the status bar.
struct NativeMessagingOutcome {
    enabled: bool,
    installed: usize,
    removed: usize,
    /// Selected browsers whose per-user config root does not exist.
    skipped: usize,
    /// Integration is on but every per-browser box is off.
    no_browsers: bool,
}

/// Browsers with a per-user configuration root under the install home.
///
/// The settings UI uses this to disable browsers that are not installed.
pub fn installed_browsers(app: &App) -> Vec<friendlypass_browser::native_messaging::Browser> {
    let Ok(platform) = manifest_platform(app) else {
        return Vec::new();
    };
    platform.installed_browsers(&app.browser_install_home)
}

/// Where the host binary that registrations point at lives.
pub fn native_host_path(app: &App) -> Option<std::path::PathBuf> {
    app.browser_install_host
        .clone()
        .or_else(friendlypass_browser::native_messaging::resolve_host_path)
}

fn manifest_platform(
    app: &App,
) -> anyhow::Result<friendlypass_browser::native_messaging::Platform> {
    app.browser_install_platform
        .or_else(friendlypass_browser::native_messaging::Platform::current)
        .ok_or_else(|| anyhow::anyhow!("browser integration is not supported on this platform"))
}

/// Options for removing manifests: no host binary is needed.
fn remove_options(
    app: &App,
    browsers: Vec<friendlypass_browser::native_messaging::Browser>,
) -> anyhow::Result<friendlypass_browser::native_messaging::InstallOptions> {
    let mut options = friendlypass_browser::native_messaging::InstallOptions::new(
        app.browser_install_home.clone(),
        manifest_platform(app)?,
        std::path::PathBuf::new(),
    );
    options.browsers = browsers;
    Ok(options)
}

/// Options for writing manifests, resolving the bundled host next to the app
/// when the caller did not supply one.
fn install_options(
    app: &App,
    browsers: Vec<friendlypass_browser::native_messaging::Browser>,
) -> anyhow::Result<friendlypass_browser::native_messaging::InstallOptions> {
    let mut options = remove_options(app, browsers)?;
    options.host_path = native_host_path(app).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot find {} next to the app; reinstall the app or build the host",
            friendlypass_browser::native_messaging::host_binary_file_name()
        )
    })?;
    Ok(options)
}

fn apply_native_messaging(app: &App) -> anyhow::Result<NativeMessagingOutcome> {
    use friendlypass_browser::native_messaging::{self, Browser};

    let selected = app.prefs.selected_browsers();
    if !app.prefs.browser_integration {
        let options = remove_options(app, Browser::ALL.to_vec())?;
        let report = native_messaging::uninstall(&options)?;
        return Ok(NativeMessagingOutcome {
            enabled: false,
            installed: 0,
            removed: report.removed.len(),
            skipped: 0,
            no_browsers: false,
        });
    }
    if selected.is_empty() {
        // Enabled with no browser ticked: clean up anything left behind and
        // tell the user to pick at least one.
        let options = remove_options(app, Browser::ALL.to_vec())?;
        let report = native_messaging::uninstall(&options)?;
        return Ok(NativeMessagingOutcome {
            enabled: true,
            installed: 0,
            removed: report.removed.len(),
            skipped: 0,
            no_browsers: true,
        });
    }

    let install = install_options(app, selected.clone())?;
    let report = native_messaging::install(&install)?;

    // Unchecked browsers lose their manifest, so per-browser toggles take
    // effect immediately. Only our own file is removed.
    let unselected: Vec<Browser> = Browser::ALL
        .into_iter()
        .filter(|browser| !selected.contains(browser))
        .collect();
    let removed = if unselected.is_empty() {
        0
    } else {
        let options = remove_options(app, unselected)?;
        native_messaging::uninstall(&options)?.removed.len()
    };

    Ok(NativeMessagingOutcome {
        enabled: true,
        installed: report.changed.len(),
        removed,
        skipped: report.skipped.len(),
        no_browsers: false,
    })
}

/// Apply the Browser Integration settings: write the manifests for the
/// selected browsers and remove the rest. Called when a toggle changes.
pub fn sync_native_messaging(app: &mut App) {
    match apply_native_messaging(app) {
        Ok(outcome) if outcome.no_browsers => {
            app.status = "Browser integration is on but no browser is selected; manifests removed"
                .into();
        }
        Ok(outcome) if outcome.enabled => {
            app.status = if outcome.installed > 0 {
                format!(
                    "Browser integration enabled: {} manifest(s) written",
                    outcome.installed
                )
            } else if outcome.skipped > 0 {
                "Browser integration is on, but no selected browser is installed; no manifests were written".into()
            } else {
                "Browser integration manifests are up to date".into()
            };
        }
        Ok(outcome) => {
            app.status = if outcome.removed == 0 {
                "Browser integration disabled".into()
            } else {
                format!(
                    "Browser integration disabled: {} manifest(s) removed",
                    outcome.removed
                )
            };
        }
        Err(error) => {
            app.status = format!("cannot update browser integration manifests: {error:#}");
        }
    }
}

/// Startup refresh: rewrite manifests when the host path changed (the app was
/// moved or updated) without replacing an unrelated startup status message.
pub fn refresh_native_messaging(app: &mut App) {
    if !app.prefs.browser_integration {
        return;
    }
    let previous = app.status.clone();
    match apply_native_messaging(app) {
        Ok(_) => app.status = previous,
        Err(error) => {
            if previous.is_empty() {
                app.status = format!("cannot update browser integration manifests: {error:#}");
            }
        }
    }
}

/// Run once per frame, before drawing. Processes bridge requests, keeps the
/// served snapshot in sync and emits lock/unlock/changed pushes.
pub fn pump(app: &mut App, ctx: &egui::Context) {
    let Some(push) = app.browser_handle.as_ref().map(|handle| handle.push_hub()) else {
        app.window_focus.sync_prompt(ctx, None);
        return;
    };
    let Some(bridge) = app.browser_bridge.clone() else {
        app.window_focus.sync_prompt(ctx, None);
        return;
    };
    bridge.set_egui_ctx(ctx);
    bridge.set_window_focus(app.window_focus.driver());
    bridge.set_require_approval(app.prefs.require_approval_for_new_browsers);
    // Automatic approvals completed on a connection thread become notices.
    for notice in bridge.take_notices() {
        app.browser_notice = Some(notice);
    }

    // Interactive requests first: the server thread is waiting for them.
    let approval_pending = bridge.pending_approval();
    if approval_pending.is_some() {
        if matches!(app.dialog, Dialog::None) {
            app.dialog = Dialog::Browser;
        }
        ctx.request_repaint_after(PENDING_REPAINT);
    }

    // One passkey dialog at a time; an unrelated open dialog is not replaced.
    let passkey_pending = bridge.pending_passkey();
    if passkey_pending.is_some() {
        if matches!(app.dialog, Dialog::None | Dialog::Passkey) {
            app.dialog = Dialog::Passkey;
        }
        ctx.request_repaint_after(PENDING_REPAINT);
    } else if matches!(app.dialog, Dialog::Passkey) {
        app.dialog = Dialog::None;
    }

    // Raise & float the window while a passkey or association confirmation is
    // awaiting user input, then drop AlwaysOnTop and return focus to the
    // previous app (e.g. the browser) once the prompt settles.
    let active_prompt = passkey_pending
        .as_ref()
        .map(|prompt| ActivePrompt::Passkey(prompt.id))
        .or_else(|| {
            approval_pending
                .as_ref()
                .map(|(_, client_id)| ActivePrompt::Approval(client_id.clone()))
        });
    app.window_focus.sync_prompt(ctx, active_prompt);

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
            app.window_focus.raise_for_unlock(ctx);
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
            state.passkeys = snapshot.passkeys;
        }
        state.snapshot_signature = signature;
        state.db_hash = snapshot.db_hash.clone();
        state.allow_localhost_passkeys = app.prefs.allow_localhost_passkeys;
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

/// The passkey dialog's current request, if one is waiting.
pub fn passkey_prompt(app: &App) -> Option<PasskeyPrompt> {
    app.browser_bridge.as_ref()?.pending_passkey()
}

pub fn passkey_selection(app: &App) -> Option<String> {
    app.browser_bridge.as_ref()?.passkey_selection()
}

pub fn select_passkey(app: &App, selection: Option<String>) {
    if let Some(bridge) = app.browser_bridge.as_ref() {
        bridge.select_passkey(selection);
    }
}

/// Confirm the pending passkey request on the GUI thread and answer the
/// waiting connection. The dialog's selection is read from the bridge.
pub fn confirm_passkey(app: &mut App) {
    let Some(bridge) = app.browser_bridge.clone() else {
        return;
    };
    let Some((id, request)) = bridge.pending_passkey_request() else {
        return;
    };
    let selection = bridge.passkey_selection();
    let result = apply_passkey_request(app, &request, selection);
    bridge.finish_passkey(id, result);
    app.dialog = Dialog::None;
}

/// Deny/cancel the pending passkey request (error 22).
pub fn deny_passkey(app: &mut App) {
    let Some(bridge) = app.browser_bridge.clone() else {
        return;
    };
    if let Some((id, _)) = bridge.pending_passkey_request() {
        bridge.finish_passkey(id, Err(ERROR_PASSKEYS_REQUEST_CANCELED));
    }
    app.dialog = Dialog::None;
}

/// Build the credential/assertion and, for registration, write the entry.
fn apply_passkey_request(
    app: &mut App,
    request: &PasskeyRequest,
    selection: Option<String>,
) -> Result<Value, i32> {
    match request {
        PasskeyRequest::Register(request) => {
            let completed = request
                .prepared
                .complete()
                .map_err(|_| friendlypass_browser::protocol::ERROR_PASSKEYS_UNKNOWN_ERROR)?;
            let group = if request.group_name.trim().is_empty() {
                app.prefs.passkey_default_group.trim().to_owned()
            } else {
                request.group_name.trim().to_owned()
            };
            let selected = selection.filter(|uuid| {
                request.existing.iter().any(|candidate| &candidate.uuid == uuid)
            });
            let db = app.db.as_mut().ok_or(friendlypass_browser::protocol::ERROR_PASSKEYS_REQUEST_CANCELED)?;
            let uuid = match selected {
                Some(uuid) => {
                    if !friendlypass_browser::passkey_write::update_passkey_entry(
                        db,
                        &uuid,
                        &completed.passkey,
                    ) {
                        return Err(friendlypass_browser::protocol::ERROR_PASSKEYS_UNKNOWN_ERROR);
                    }
                    uuid
                }
                None => friendlypass_browser::passkey_write::create_passkey_entry(
                    db,
                    &completed.passkey,
                    &request.prepared.rp_name,
                    &request.origin,
                    &group,
                )
                .ok_or(friendlypass_browser::protocol::ERROR_PASSKEYS_UNKNOWN_ERROR)?,
            };
            app.dirty = true;
            app.status = format!("Saved a passkey for {}", request.prepared.rp_id);
            let _ = uuid;
            // A page may call `get` immediately after `create`; make the new
            // passkey visible to the shared server state before answering, so
            // the next request does not race the next pump.
            refresh_served_snapshot(app);
            Ok(completed.credential)
        }
        PasskeyRequest::Get(request) => {
            let candidate = selection
                .as_deref()
                .and_then(|uuid| {
                    request
                        .candidates
                        .iter()
                        .find(|candidate| candidate.uuid == uuid)
                })
                .or_else(|| request.candidates.first())
                .ok_or(friendlypass_browser::protocol::ERROR_NO_LOGINS_FOUND)?;
            let db = app
                .db
                .as_ref()
                .ok_or(friendlypass_browser::protocol::ERROR_DATABASE_NOT_OPENED)?;
            let passkey = friendlypass_browser::passkey_write::entry_passkey(db, &candidate.uuid)
                .ok_or(friendlypass_browser::protocol::ERROR_PASSKEYS_UNKNOWN_ERROR)?;
            request
                .prepared
                .complete(&passkey)
                .map_err(|_| friendlypass_browser::protocol::ERROR_PASSKEYS_UNKNOWN_ERROR)
        }
    }
}

/// Copy the current database into the served snapshot immediately. Used after
/// an interactive write so a follow-up browser action never sees stale state.
fn refresh_served_snapshot(app: &App) {
    let (Some(db), Some(shared)) = (app.db.as_ref(), app.browser_state.as_ref()) else {
        return;
    };
    let snapshot = friendlypass_browser::snapshot_from_database(db);
    let mut state = lock_state(shared);
    state.entries = snapshot.entries;
    state.groups = snapshot.groups;
    state.passkeys = snapshot.passkeys;
    state.db_hash = snapshot.db_hash;
    state.snapshot_signature = snapshot.snapshot_signature;
}

/// Apply a `set-login` request on the GUI thread.
fn apply_set_login(app: &mut App, request: &SetLoginRequest) -> bool {
    let Some(db) = app.db.as_mut() else {
        return false;
    };
    if !friendlypass_browser::entry_write::apply_set_login(db, request) {
        return false;
    }
    app.dirty = true;
    app.status = "Saved a login from the browser".into();
    true
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
    association_rows(app).into_iter().map(|row| row.id).collect()
}

/// One line of the Browser Integration dialog's association list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssociationRow {
    pub id: String,
    /// Browser kind ("Chrome", "Firefox", …) or "Unknown browser".
    pub browser: String,
    /// `"verified"` for automatic/verified approvals, otherwise
    /// `"approved manually"` (contract §5).
    pub how: &'static str,
}

/// The association list with its browser kind and approval provenance.
pub fn association_rows(app: &App) -> Vec<AssociationRow> {
    let Some(state) = app.browser_state.as_ref() else {
        return Vec::new();
    };
    let state = lock_state(state);
    let mut rows: Vec<AssociationRow> = state
        .associations
        .keys()
        .map(|id| match state.associations_info.get(id) {
            Some(info) => AssociationRow {
                id: id.clone(),
                browser: info.browser.clone(),
                how: if info.verified && info.auto_approved {
                    "verified"
                } else {
                    "approved manually"
                },
            },
            None => {
                // Associations loaded from database metadata only carry their
                // name; the automatic `"<Browser> · <4 hex>"` shape still
                // tells us the browser and that it was verified.
                let browser = friendlypass_browser::bridge::automatic_association_browser(id);
                AssociationRow {
                    id: id.clone(),
                    browser: browser.unwrap_or("Unknown browser").to_owned(),
                    how: if browser.is_some() {
                        "verified"
                    } else {
                        "approved manually"
                    },
                }
            }
        })
        .collect();
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    rows
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
    state.associations_info.remove(id);
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
    use friendlypass_browser::entry_write::title_for_url;
    use friendlypass_browser::passkeys::{prepare_assertion, prepare_registration};
    use friendlypass_passkey::ES256;
    use keepass::Database;
    use serde_json::json;
    use std::time::Duration;

    fn wait_for_passkey(bridge: &GuiBrowserBridge) {
        for _ in 0..200 {
            if bridge.pending_passkey().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the passkey prompt never appeared");
    }

    fn registration_request() -> PasskeyRegisterRequest {
        let options = json!({
            "challenge": friendlypass_browser::b64(&[7u8; 32]),
            "pubKeyCredParams": [{"type": "public-key", "alg": ES256}],
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": friendlypass_passkey::b64url_encode(b"user-1"),
                "name": "alice@example.com",
                "displayName": "Alice",
            },
            "timeout": 60000,
        });
        let prepared =
            prepare_registration(&options, "https://example.com").expect("valid options");
        PasskeyRegisterRequest {
            acting_id: "client".into(),
            prepared,
            origin: "https://example.com".into(),
            group_name: "Passkeys".into(),
            existing: Vec::new(),
        }
    }

    fn app_with_database() -> App {
        let mut app = App::default();
        app.db = Some(Database::new());
        app
    }

    #[test]
    fn passkey_registration_prompt_writes_a_keepassxc_entry() {
        let bridge = Arc::new(GuiBrowserBridge::new(false));
        let mut app = app_with_database();
        app.browser_bridge = Some(Arc::clone(&bridge));
        app.browser_state = Some(Arc::new(Mutex::new(
            friendlypass_browser::ServiceState::default(),
        )));
        let request = registration_request();

        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || bridge.passkeys_register(&request))
        };
        wait_for_passkey(&bridge);
        let prompt = bridge.pending_passkey().expect("prompt");
        assert!(matches!(
            prompt.kind,
            PasskeyPromptKind::Register { .. }
        ));
        confirm_passkey(&mut app);

        let credential = worker.join().unwrap().expect("credential");
        assert!(credential["response"]["attestationObject"].is_string());
        let db = app.db.as_ref().unwrap();
        let entry = db
            .iter_all_entries()
            .find(|entry| entry.get("KPEX_PASSKEY_CREDENTIAL_ID").is_some())
            .expect("passkey entry written");
        assert_eq!(entry.get("KPEX_PASSKEY_RELYING_PARTY"), Some("example.com"));
        assert_eq!(entry.get("UserName"), Some("alice@example.com"));
        assert_eq!(entry.get("URL"), Some("https://example.com"));
        assert_eq!(entry.parent().name, "Passkeys");
        assert!(app.dirty);
        // The shared server snapshot sees the passkey without waiting a frame.
        let state = app.browser_state.as_ref().unwrap().lock().unwrap();
        assert_eq!(state.passkeys.len(), 1);
        assert_eq!(state.passkeys[0].uuid.len(), 32);
    }

    #[test]
    fn passkey_registration_can_replace_an_existing_entry() {
        let bridge = Arc::new(GuiBrowserBridge::new(false));
        let mut app = app_with_database();
        app.browser_bridge = Some(Arc::clone(&bridge));
        let existing = friendlypass_passkey::register(
            "example.com",
            "alice@example.com",
            b"user-1",
            &[ES256],
        )
        .unwrap();
        let uuid = friendlypass_browser::passkey_write::create_passkey_entry(
            app.db.as_mut().unwrap(),
            &existing.passkey,
            "Example",
            "https://example.com",
            "",
        )
        .unwrap();

        let mut request = registration_request();
        request.existing = vec![PasskeyCandidate {
            uuid: uuid.clone(),
            title: "Example (Passkey)".into(),
            username: "alice@example.com".into(),
            credential_id: friendlypass_passkey::b64url_encode(&existing.credential_id),
        }];
        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || bridge.passkeys_register(&request))
        };
        wait_for_passkey(&bridge);
        bridge.select_passkey(Some(uuid.clone()));
        confirm_passkey(&mut app);

        let credential = worker.join().unwrap().expect("credential");
        assert_eq!(app.db.as_ref().unwrap().iter_all_entries().count(), 1);
        let stored = friendlypass_browser::passkey_write::entry_passkey(
            app.db.as_ref().unwrap(),
            &uuid,
        )
        .expect("passkey updated");
        assert_eq!(
            friendlypass_passkey::b64url_encode(&stored.credential_id),
            credential["id"].as_str().unwrap()
        );
    }

    #[test]
    fn passkey_get_prompt_signs_with_the_selected_entry() {
        let registration = friendlypass_passkey::register(
            "example.com",
            "alice@example.com",
            b"user-1",
            &[ES256],
        )
        .unwrap();
        let mut app = app_with_database();
        let credential_id = friendlypass_passkey::b64url_encode(&registration.credential_id);
        let uuid = friendlypass_browser::passkey_write::create_passkey_entry(
            app.db.as_mut().unwrap(),
            &registration.passkey,
            "Example",
            "https://example.com",
            "",
        )
        .unwrap();
        let options = json!({
            "challenge": friendlypass_browser::b64(&[5u8; 32]),
            "rpId": "example.com",
            "allowCredentials": [{
                "type": "public-key",
                "id": credential_id,
                "transports": ["internal"],
            }],
        });
        let prepared =
            prepare_assertion(&options, "https://example.com").expect("valid options");
        let request = PasskeyGetRequest {
            acting_id: "client".into(),
            prepared,
            candidates: vec![PasskeyCandidate {
                uuid: uuid.clone(),
                title: "Example (Passkey)".into(),
                username: "alice@example.com".into(),
                credential_id,
            }],
        };
        let bridge = Arc::new(GuiBrowserBridge::new(false));
        app.browser_bridge = Some(Arc::clone(&bridge));

        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || bridge.passkeys_get(&request))
        };
        wait_for_passkey(&bridge);
        assert_eq!(bridge.passkey_selection(), Some(uuid));
        confirm_passkey(&mut app);

        let assertion = worker.join().unwrap().expect("assertion");
        assert!(assertion["response"]["signature"].is_string());
        assert_eq!(
            assertion["response"]["userHandle"],
            friendlypass_passkey::b64url_encode(b"user-1")
        );
    }

    #[test]
    fn cancelling_a_passkey_prompt_returns_error_22() {
        let bridge = Arc::new(GuiBrowserBridge::new(false));
        let mut app = app_with_database();
        app.browser_bridge = Some(Arc::clone(&bridge));
        let request = registration_request();

        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || bridge.passkeys_register(&request))
        };
        wait_for_passkey(&bridge);
        deny_passkey(&mut app);
        assert_eq!(worker.join().unwrap(), Err(ERROR_PASSKEYS_REQUEST_CANCELED));
        assert!(app.db.as_ref().unwrap().iter_all_entries().next().is_none());
    }

    #[test]
    fn association_approval_round_trip() {
        let bridge = Arc::new(GuiBrowserBridge::new(false));
        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || {
                bridge.approve_association(&AssociationRequest {
                    client_id: "client".into(),
                    suggested_id: "chrome-browser".into(),
                    ..Default::default()
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
        let bridge = Arc::new(GuiBrowserBridge::new(false));
        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || {
                bridge.approve_association(&AssociationRequest {
                    client_id: "client".into(),
                    suggested_id: "chrome-browser".into(),
                    ..Default::default()
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

    fn trusted_chrome_request() -> AssociationRequest {
        AssociationRequest {
            client_id: "Y2xpZW50".into(),
            suggested_id: "chrome-browser".into(),
            browser: Some(BrowserIdentity {
                kind: "chrome".into(),
                verified: true,
                ..Default::default()
            }),
            auto_approvable: true,
        }
    }

    #[test]
    fn auto_approve_skips_the_dialog_and_queues_a_notice() {
        let bridge = GuiBrowserBridge::new(false);
        let name = bridge
            .approve_association(&trusted_chrome_request())
            .expect("approved");
        assert!(name.starts_with("Chrome · "), "{name}");
        assert_eq!(name.split(" · ").nth(1).map(str::len), Some(4));
        assert!(
            bridge.pending_approval().is_none(),
            "no dialog is opened for an automatic approval"
        );
        let notices = bridge.take_notices();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].browser, "Chrome");
        assert_eq!(notices[0].association_id, name);
        assert!(bridge.take_notices().is_empty(), "notices are delivered once");
    }

    #[test]
    fn require_approval_setting_opens_the_dialog() {
        let bridge = Arc::new(GuiBrowserBridge::new(true));
        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || bridge.approve_association(&trusted_chrome_request()))
        };
        for _ in 0..100 {
            if bridge.pending_approval().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            bridge.pending_approval().is_some(),
            "the setting forces the existing approval dialog"
        );
        assert!(bridge.take_notices().is_empty());
        bridge.answer_approval(Some("chrome-work".into()));
        assert_eq!(worker.join().unwrap().as_deref(), Some("chrome-work"));
    }

    #[test]
    fn untrusted_requests_always_take_the_dialog() {
        let bridge = Arc::new(GuiBrowserBridge::new(false));
        let mut request = trusted_chrome_request();
        request.auto_approvable = false;
        let worker = {
            let bridge = Arc::clone(&bridge);
            std::thread::spawn(move || bridge.approve_association(&request))
        };
        for _ in 0..100 {
            if bridge.pending_approval().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(bridge.pending_approval().is_some());
        bridge.answer_approval(None);
        assert_eq!(worker.join().unwrap(), None);
    }

    #[test]
    fn association_rows_label_browser_and_provenance() {
        let mut state = ServiceState {
            associations: [
                ("Chrome · 3f9a".to_owned(), "key-a".to_owned()),
                ("chrome-work-laptop".to_owned(), "key-b".to_owned()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        state.associations_info.insert(
            "chrome-work-laptop".to_owned(),
            friendlypass_browser::AssociationInfo {
                browser: "Chrome".into(),
                verified: true,
                auto_approved: false,
            },
        );
        let mut app = App::default();
        app.browser_state = Some(Arc::new(Mutex::new(state)));
        let rows = association_rows(&app);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "Chrome · 3f9a");
        assert_eq!(rows[0].browser, "Chrome");
        assert_eq!(rows[0].how, "verified", "automatic names are recognised");
        assert_eq!(rows[1].browser, "Chrome");
        assert_eq!(rows[1].how, "approved manually");
        assert_eq!(
            friendlypass_browser::bridge::automatic_association_browser("Brave · 0a1B"),
            Some("Brave")
        );
        assert_eq!(
            friendlypass_browser::bridge::automatic_association_browser("chrome-work"),
            None
        );
    }

    #[test]
    fn association_names_are_sanitised() {
        assert_eq!(sanitise_association_id("  work\nlaptop  "), "worklaptop");
        assert_eq!(sanitise_association_id(""), "chrome-browser");
    }

    #[test]
    fn set_login_bridge_round_trip() {
        let bridge = Arc::new(GuiBrowserBridge::new(false));
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
                    title: None,
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
