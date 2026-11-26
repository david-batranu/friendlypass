//! Application state, the eframe `App` implementation, the unlock screen
//! and the main window chrome (toolbar / status bar / save logic).

use eframe::egui;
use eframe::egui::Ui;
use keepass::db::{Database, GroupId};
use keepass::DatabaseKey;
use std::path::PathBuf;
use std::sync::Arc;

use crate::browser;
use crate::config::{self, ColumnId, Preferences};
use crate::dialogs::{self, Dialog};
use crate::startup::{self, SecretStore, StoredSecret};
use crate::icons::IconCache;
use keepass::db::EntryId;

/// Which entry field a keyboard shortcut copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyField {
    Password,
    Username,
    Url,
    Totp,
}

/// Window width (points) below which the library sidebar hides itself: under
/// this, three columns cannot coexist without squeezing the details pane.
pub const SIDEBAR_AUTO_HIDE_WIDTH: f32 = 1000.0;

/// How long a copy button shows its "Copied" confirmation state.
pub const COPIED_TTL: std::time::Duration = std::time::Duration::from_millis(1200);
/// How long a toast notification stays on screen.
pub const TOAST_TTL: std::time::Duration = std::time::Duration::from_millis(2600);

/// What the idle auto-lock decided this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleLock {
    /// Not idle long enough (or auto-lock is off / nothing is open).
    Wait,
    /// Idle and nothing would be lost: lock.
    Lock,
    /// Idle, but there are unsaved changes or an open editor: do not lock.
    Postpone,
}

/// A transient toast notification (bottom-right corner of the window).
pub struct Toast {
    pub text: String,
    pub created: std::time::Instant,
}

/// Column to sort the entry list by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Tags,
    /// Last modification time (falls back to the creation time).
    Modified,
}

impl SortColumn {
    /// Every sortable column, in Sort-menu order.
    pub const ALL: [SortColumn; 7] = [
        SortColumn::Title,
        SortColumn::Username,
        SortColumn::Url,
        SortColumn::Modified,
        SortColumn::Tags,
        SortColumn::Notes,
        SortColumn::Password,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            SortColumn::Title => "Title",
            SortColumn::Username => "Username",
            SortColumn::Password => "Password",
            SortColumn::Url => "URL",
            SortColumn::Notes => "Notes",
            SortColumn::Tags => "Tags",
            SortColumn::Modified => "Modified",
        }
    }

    /// The direction a fresh sort on this column starts with: newest first
    /// for dates, A to Z for text.
    pub fn default_desc(&self) -> bool {
        matches!(self, SortColumn::Modified)
    }
}

/// The main GUI application.
pub struct App {
    // -- unlock screen state --------------------------------------------
    pub db_path: String,
    pub password: String,
    pub key_file: String,
    /// Optional local challenge-response secret (hex) — the software
    /// equivalent of a YubiKey HMAC-SHA1 response.
    pub challenge_response: String,
    /// Short, human message shown under the password field after a failed
    /// unlock ("Wrong password or key file.").
    pub unlock_error: String,
    /// The full technical error behind `unlock_error` (hover text).
    pub unlock_error_detail: String,
    /// Focus (and select) the unlock password field on the next frame: set on
    /// startup with a database path, after locking, and after a failed unlock.
    pub focus_password: bool,
    /// The unlock screen's "More options" (key file, challenge-response) are
    /// expanded.
    pub unlock_more_options: bool,
    /// Store the unlock key in the OS keychain and auto-unlock this database
    /// on startup.
    pub remember_unlock: bool,
    /// A saved secret for the current database exists and was used on startup.
    pub auto_unlock: bool,
    /// Inline entry editor shown in the right column (replaces details).
    pub inline_edit: Option<Box<dialogs::EntryEdit>>,
    /// The OS login item is installed (read by the Settings dialog).
    pub launch_at_login: bool,
    /// Where auto-unlock secrets live (the OS keychain in production).
    pub secret_store: Arc<dyn SecretStore>,

    // -- open database state --------------------------------------------
    pub db: Option<Database>,
    pub db_key: Option<DatabaseKey>,
    pub dirty: bool,
    /// Set once the KDBX3→4.1 upgrade has been confirmed, so we don't ask
    /// again on every save.
    pub upgrade_confirmed: bool,

    // -- browsing state --------------------------------------------------
    pub search: String,
    /// Set to focus the search box on the next frame (Cmd/Ctrl+F).
    pub focus_search: bool,
    pub selected_group: Option<GroupId>, // None = root
    /// Active tag filter from the sidebar TAGS section.
    pub selected_tag: Option<String>,
    /// Show only favorite (starred) entries.
    pub filter_favorites: bool,
    /// Show only entries that have attachments.
    pub filter_attachments: bool,
    /// Entry-selection history behind the toolbar's Back arrow (oldest last).
    pub nav_back: Vec<EntryId>,
    /// Entries the Forward arrow can return to (nearest last).
    pub nav_forward: Vec<EntryId>,
    /// The entry the navigation recorder last saw.
    nav_last: Option<EntryId>,
    /// Set while the app itself moves the selection (Back/Forward), so that
    /// move is not recorded as a new history step.
    nav_internal: bool,
    /// Sidebar GROUPS / TAGS sections are collapsible (useful in short
    /// windows); collapsed state is remembered for the session.
    pub groups_collapsed: bool,
    pub tags_collapsed: bool,
    /// Sidebar visibility override: `None` follows the window width (shown
    /// when there is room for three columns), `Some` pins it either way so the
    /// toolbar toggle wins even in a narrow window.
    pub sidebar_override: Option<bool>,
    pub selected_entry: Option<keepass::db::EntryId>,
    /// Multi-selection (Ctrl/Cmd-click) for batch operations.
    pub selected_entries: std::collections::HashSet<EntryId>,
    /// Where a Shift-click range selection starts (the last plain or
    /// Cmd-click).
    pub selection_anchor: Option<EntryId>,
    /// Scroll the list/table so the selected entry is visible (set by arrow
    /// key navigation).
    pub scroll_to_selected: bool,
    pub sort_column: SortColumn,
    pub sort_desc: bool,
    pub show_passwords: bool,
    pub status: String,
    /// Field key -> when its value was last copied; drives the "Copied"
    /// confirmation on the details panel's copy buttons and value cells.
    pub copied_fields: std::collections::HashMap<String, std::time::Instant>,
    /// Transient toast notifications shown bottom-right.
    pub toasts: Vec<Toast>,
    /// Non-blocking browser connection notice ("Chrome connected to
    /// friendlypass") with a Revoke action, shown until dismissed.
    pub browser_notice: Option<crate::browser_bridge::BrowserNotice>,
    pub dialog: Dialog,
    /// Lazily-uploaded icon textures (standard + custom icons).
    pub icon_cache: IconCache,
    /// The running SSH agent server (KeePassXC's SSH agent integration).
    pub ssh_handle: Option<friendlypass_ssh_agent::server::AgentHandle>,
    pub ssh_pool: Option<friendlypass_ssh_agent::server::IdentityPool>,
    /// Socket path for the SSH agent (editable before starting).
    pub ssh_socket: String,
    /// The running browser-protocol server (friendlypass browser integration).
    pub browser_handle: Option<friendlypass_browser::ServerHandle>,
    pub browser_state: Option<friendlypass_browser::SharedState>,
    /// The GUI bridge the browser server calls back into (approval, writes).
    pub browser_bridge: Option<Arc<crate::browser_bridge::GuiBrowserBridge>>,
    /// `$HOME` used when writing native-messaging manifests (tests point this
    /// at a temporary directory).
    pub browser_install_home: PathBuf,
    /// Platform override for manifest paths; `None` detects at write time.
    pub browser_install_platform: Option<friendlypass_browser::native_messaging::Platform>,
    /// Host binary registered with the browsers; `None` resolves the sibling
    /// of the running executable (the app bundle in a packaged build).
    pub browser_install_host: Option<PathBuf>,

    // -- persisted preferences ------------------------------------------
    /// Column layout and the recent-databases list.
    pub prefs: Preferences,
    /// Where `prefs` are stored; `None` keeps them in memory only
    /// (constructed with `App::default()`, e.g. in tests).
    pub config_path: Option<PathBuf>,
    /// Reset the table's persisted column widths on the next frame (set when
    /// the Columns dialog changes the layout, so the new widths apply).
    pub reset_columns: bool,

    // -- security ---------------------------------------------------------
    /// Where copies go (the system clipboard; tests use a memory clipboard).
    pub clipboard: Arc<dyn crate::clipboard::ClipboardBackend>,
    /// The scheduled clipboard clear for the last copied value.
    pub clipboard_pending: Option<crate::clipboard::PendingClear>,
    /// Last time the user did anything (drives the idle auto-lock).
    pub last_activity: std::time::Instant,
    /// The idle auto-lock came due while there were unsaved changes and was
    /// postponed (shown in the status bar until the user acts or saves).
    pub auto_lock_postponed: bool,
}

impl Default for App {
    fn default() -> Self {
        App {
            db_path: String::new(),
            password: String::new(),
            key_file: String::new(),
            challenge_response: String::new(),
            unlock_error: String::new(),
            unlock_error_detail: String::new(),
            // Startup: focus the password when a database is preselected.
            focus_password: true,
            unlock_more_options: false,
            remember_unlock: false,
            auto_unlock: false,
            inline_edit: None,
            launch_at_login: false,
            secret_store: Arc::new(startup::KeychainStore),
            db: None,
            db_key: None,
            dirty: false,
            upgrade_confirmed: false,
            search: String::new(),
            focus_search: false,
            selected_group: None,
            selected_tag: None,
            filter_favorites: false,
            filter_attachments: false,
            nav_back: Vec::new(),
            nav_forward: Vec::new(),
            nav_last: None,
            nav_internal: false,
            groups_collapsed: false,
            tags_collapsed: false,
            sidebar_override: None,
            selected_entry: None,
            selected_entries: std::collections::HashSet::new(),
            selection_anchor: None,
            scroll_to_selected: false,
            sort_column: SortColumn::Title,
            sort_desc: false,
            show_passwords: false,
            status: String::new(),
            copied_fields: std::collections::HashMap::new(),
            toasts: Vec::new(),
            browser_notice: None,
            dialog: Dialog::None,
            icon_cache: IconCache::default(),
            ssh_handle: None,
            ssh_pool: None,
            ssh_socket: friendlypass_ssh_agent::default_socket_path().display().to_string(),
            browser_handle: None,
            browser_state: None,
            browser_bridge: None,
            browser_install_home: friendlypass_browser::native_messaging::user_home()
                .unwrap_or_default(),
            browser_install_platform: None,
            browser_install_host: None,
            prefs: Preferences::default(),
            config_path: None,
            reset_columns: false,
            clipboard: Arc::new(crate::clipboard::SystemClipboard),
            clipboard_pending: None,
            last_activity: std::time::Instant::now(),
            auto_lock_postponed: false,
        }
    }
}

impl App {
    /// Application entry point: loads persisted preferences (column layout,
    /// recent databases) and prefills the last database when no path was
    /// given on the command line.
    pub fn new(initial_db: Option<String>) -> Self {
        let mut app = match config::config_path() {
            Some(path) => App::with_config_path(path),
            None => App::default(),
        };
        if let Some(path) = initial_db {
            app.db_path = path;
        }
        // If the last database has an enrolled key, unlock it before the
        // first frame. Failures fall back to the normal unlock screen.
        if !app.db_path.is_empty() && app.has_saved_secret(&app.db_path) {
            app.auto_unlock = true;
            app.remember_unlock = true;
            app.try_auto_unlock();
        }
        // Always listen for the browser extension, even on the unlock screen:
        // a locked app answers error 1 (rather than looking "not running").
        // Re-register the native host first: if the app moved or was updated,
        // the manifests still point at the previous location.
        crate::browser_bridge::refresh_native_messaging(&mut app);
        crate::browser_bridge::start_background(&mut app);
        app
    }

    /// Replace the secret store (tests use an in-memory store).
    pub fn with_secret_store(mut self, store: Arc<dyn SecretStore>) -> Self {
        self.secret_store = store;
        self
    }

    /// Load preferences from an explicit config file (used by tests and by
    /// `FRIENDLYPASS_GUI_CONFIG`-style portable setups).
    pub fn with_config_path(path: PathBuf) -> Self {
        let mut app = App::default();
        app.prefs = Preferences::load(&path);
        app.secret_store = startup::platform_store(app.prefs.windows_dpapi_fallback);
        app.config_path = Some(path);
        if app.db_path.is_empty() {
            if let Some(last) = &app.prefs.last_db {
                app.db_path = last.clone();
            }
        }
        app
    }

    /// Whether an auto-unlock secret is enrolled for `path`.
    pub fn has_saved_secret(&self, path: &str) -> bool {
        let account = startup::account_key(path);
        self.secret_store
            .get(&account)
            .ok()
            .flatten()
            .is_some()
    }

    /// Rebuild the database key from the stored secret and open the
    /// database. Returns false (and leaves the unlock screen usable) on
    /// failure.
    pub fn try_auto_unlock(&mut self) -> bool {
        let path = self.db_path.trim().to_owned();
        if path.is_empty() {
            return false;
        }
        let account = startup::account_key(&path);
        let secret = match self.secret_store.get(&account) {
            Ok(Some(secret)) => secret,
            Ok(None) => return false,
            Err(e) => {
                self.unlock_error = format!("Auto-unlock unavailable: {e:#}");
                return false;
            }
        };

        let mut key = DatabaseKey::new();
        if !secret.password.is_empty() {
            key = key.with_password(&secret.password);
        }
        if let Some(bytes) = &secret.keyfile {
            match key.with_keyfile(&mut std::io::Cursor::new(bytes)) {
                Ok(k) => key = k,
                Err(e) => {
                    self.unlock_error = format!("Auto-unlock key file invalid: {e}");
                    return false;
                }
            }
        }
        if !secret.challenge_response.is_empty() {
            match friendlypass::key::with_challenge_response(key, &secret.challenge_response) {
                Ok(k) => key = k,
                Err(e) => {
                    self.unlock_error = format!("Auto-unlock challenge-response invalid: {e:#}");
                    return false;
                }
            }
        }

        match open_database_checked(&path, &key) {
            Ok(db) => {
                self.db = Some(db);
                self.db_key = Some(key);
                self.dirty = false;
                self.upgrade_confirmed = false;
                self.search.clear();
                self.selected_group = None;
                self.selected_entry = None;
                self.auto_unlock = true;
                self.remember_unlock = true;
                self.last_activity = std::time::Instant::now();
                self.status = format!("Unlocked {path} automatically");
                crate::browser_bridge::start_background(self);
                true
            }
            Err(e) => {
                self.unlock_error = format!("Auto-unlock failed: {}", e.message());
                self.unlock_error_detail = e.detail;
                self.focus_password = true;
                false
            }
        }
    }

    /// Persist the current preferences (no-op when no config path is set).
    pub fn save_preferences(&mut self) {
        if let Some(path) = &self.config_path {
            let _ = self.prefs.save(path);
        }
    }

    /// Remember a successfully opened database in the recent list.
    pub fn record_recent_database(&mut self, path: &str) {
        self.prefs.record_recent(path);
        self.save_preferences();
    }

    /// The saved/merged column layout (visible columns in display order).
    pub fn column_layout(&self) -> Vec<config::ColumnConfig> {
        let mut prefs = self.prefs.clone();
        prefs.normalize();
        prefs.columns.iter().filter(|c| c.visible).cloned().collect()
    }

    /// Toggle/column width edits from the Columns dialog.
    pub fn set_column_visible(&mut self, id: ColumnId, visible: bool) {
        if self.prefs.set_visible(id, visible) {
            self.reset_columns = true;
            self.save_preferences();
        } else {
            self.status = "At least one column must stay visible".into();
        }
    }

    /// Open a database directly (used by tests and scripting entry points).
    pub fn with_open_database(path: &str, key: DatabaseKey) -> Self {
        let mut app = App::default();
        app.db_path = path.to_string();
        match open_database(path, &key) {
            Ok(db) => {
                app.db = Some(db);
                app.db_key = Some(key);
                app.status = format!("Opened {}", path);
            }
            Err(e) => app.unlock_error = format!("{e:#}"),
        }
        app
    }

    /// Attempt to unlock using the fields on the welcome screen.
    pub fn try_unlock(&mut self) {
        self.unlock_error.clear();
        self.unlock_error_detail.clear();
        self.try_unlock_inner();
        if !self.unlock_error.is_empty() {
            // Put the cursor back in the password field with the text
            // selected, so the user can simply retype it.
            self.focus_password = true;
        }
    }

    fn try_unlock_inner(&mut self) {

        if self.db_path.trim().is_empty() {
            self.unlock_error = "Select a database file first.".into();
            return;
        }
        if self.password.is_empty() && self.key_file.trim().is_empty() {
            self.unlock_error = "Enter a password and/or select a key file.".into();
            return;
        }

        let mut key = DatabaseKey::new();
        if !self.password.is_empty() {
            key = key.with_password(&self.password);
        }
        if !self.key_file.trim().is_empty() {
            match std::fs::File::open(&self.key_file) {
                Ok(mut f) => match key.with_keyfile(&mut f) {
                    Ok(k) => key = k,
                    Err(e) => {
                        self.unlock_error = "The key file can't be used.".into();
                        self.unlock_error_detail = format!("unable to read key file: {e}");
                        return;
                    }
                },
                Err(e) => {
                    self.unlock_error = if e.kind() == std::io::ErrorKind::NotFound {
                        "Key file not found.".into()
                    } else {
                        "The key file can't be read.".into()
                    };
                    self.unlock_error_detail = format!("unable to open key file {}: {e}", self.key_file);
                    return;
                }
            }
        }

        if !self.challenge_response.trim().is_empty() {
            match friendlypass::key::with_challenge_response(key, &self.challenge_response) {
                Ok(k) => key = k,
                Err(e) => {
                    self.unlock_error = "The challenge-response secret is not valid hex.".into();
                    self.unlock_error_detail = format!("{e:#}");
                    return;
                }
            }
        }

        match open_database_checked(&self.db_path, &key) {
            Ok(db) => {
                self.db = Some(db);
                self.db_key = Some(key);
                self.dirty = false;
                self.upgrade_confirmed = false;
                self.search.clear();
                self.selected_group = None;
                self.selected_entry = None;
                self.status = format!("Opened {}", self.db_path);
                self.last_activity = std::time::Instant::now();
                self.auto_lock_postponed = false;
                let opened = self.db_path.clone();
                self.record_recent_database(&opened);
                self.update_saved_secret(&opened);
                self.password.clear();
                crate::browser_bridge::start_background(self);
            }
            Err(e) => {
                self.unlock_error = e.message().to_owned();
                self.unlock_error_detail = e.detail;
            }
        }
    }

    /// Enroll or remove the auto-unlock secret after a successful unlock.
    fn update_saved_secret(&mut self, path: &str) {
        let account = startup::account_key(path);
        if self.remember_unlock {
            let keyfile = if self.key_file.trim().is_empty() {
                None
            } else {
                std::fs::read(self.key_file.trim()).ok()
            };
            let secret = StoredSecret {
                password: self.password.clone(),
                keyfile,
                keyfile_name: std::path::Path::new(self.key_file.trim())
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned()),
                challenge_response: self.challenge_response.clone(),
            };
            match self.secret_store.set(&account, &secret) {
                Ok(()) => {
                    self.auto_unlock = true;
                    self.status = format!("{} (auto-unlock enabled)", self.status);
                }
                Err(e) => {
                    self.auto_unlock = false;
                    self.status = format!("{} (auto-unlock not saved: {e:#})", self.status);
                }
            }
        } else if self.auto_unlock {
            if let Err(e) = self.secret_store.delete(&account) {
                self.status = format!("{} (auto-unlock key not removed: {e:#})", self.status);
            }
            self.auto_unlock = false;
        }
    }

    /// Remove the stored auto-unlock secret for the current database.
    pub fn forget_saved_secret(&mut self) -> bool {
        let path = self.db_path.clone();
        let account = startup::account_key(&path);
        match self.secret_store.delete(&account) {
            Ok(()) => {
                self.auto_unlock = false;
                self.remember_unlock = false;
                self.status = "Saved auto-unlock key removed".into();
                true
            }
            Err(e) => {
                self.status = format!("Unable to remove the saved key: {e:#}");
                false
            }
        }
    }

    /// Lock the database and return to the unlock screen.
    ///
    /// Unsaved changes are discarded (the explicit Lock action and Cmd+L
    /// always behaved this way); the idle auto-lock never calls this while
    /// there are unsaved changes, see [`App::tick_idle_lock`].
    pub fn lock(&mut self) {
        // A copied password must not outlive the unlocked session.
        self.clear_clipboard_now();
        self.focus_password = true;
        self.auto_lock_postponed = false;
        self.selection_anchor = None;
        self.selected_entries.clear();
        self.db = None;
        self.db_key = None;
        self.dirty = false;
        self.upgrade_confirmed = false;
        self.selected_entry = None;
        self.selected_group = None;
        self.selected_tag = None;
        self.filter_favorites = false;
        self.filter_attachments = false;
        self.nav_back.clear();
        self.nav_forward.clear();
        self.sidebar_override = None;
        self.nav_last = None;
        self.search.clear();
        self.dialog = Dialog::None;
        self.inline_edit = None;
        self.status = "Database locked".into();
        self.password.clear();
    }

    /// Save button: checks whether an upgrade confirmation is needed first.
    pub fn request_save(&mut self) {
        let needs_upgrade = self
            .db
            .as_ref()
            .map(|db| !matches!(db.config.version, keepass::config::DatabaseVersion::KDB4(_)))
            .unwrap_or(false);
        if needs_upgrade && !self.upgrade_confirmed {
            self.dialog = Dialog::ConfirmUpgrade;
            return;
        }
        self.perform_save(None);
    }

    /// Perform the actual save (optionally to a new path).
    pub fn perform_save(&mut self, new_path: Option<String>) {
        let Some(path) = new_path.clone().or_else(|| Some(self.db_path.clone())) else {
            return;
        };
        let Some(db) = self.db.as_mut() else { return };
        let Some(key) = self.db_key.clone() else { return };

        // KDBX 3.x can only be saved after upgrading to KDBX 4.1.
        friendlypass::commands::ensure_writable_version(db);

        let path = PathBuf::from(&path);
        match friendlypass::saveutil::save(&path, db, key) {
            Ok(()) => {
                if let Some(p) = new_path {
                    self.db_path = p;
                    let saved = self.db_path.clone();
                    self.record_recent_database(&saved);
                }
                self.dirty = false;
                self.upgrade_confirmed = true;
                self.dialog = Dialog::None;
                self.status = format!("Saved {}", self.db_path);
            }
            Err(e) => {
                self.status = format!("{e:#}");
            }
        }
    }

    /// Copy text to the clipboard; reports failures in the status bar. With
    /// auto-clear on (the default), the value is removed again after the
    /// configured delay if the clipboard still holds it.
    pub fn copy_to_clipboard(&mut self, text: String) {
        match self.clipboard.set_text(&text) {
            Ok(()) => {
                self.status = "Copied to clipboard".into();
                self.clipboard_pending = self.prefs.clipboard_clear.then(|| {
                    crate::clipboard::PendingClear::new(
                        &text,
                        std::time::Instant::now(),
                        self.clipboard_clear_after(),
                    )
                });
            }
            Err(e) => self.status = format!("clipboard unavailable: {e}"),
        }
    }

    /// How long a copied value stays on the clipboard.
    pub fn clipboard_clear_after(&self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.prefs.clipboard_clear_secs.max(1)))
    }

    /// Clear the clipboard once the pending deadline passes (called every
    /// frame, on the unlock screen too, so it also happens after locking).
    /// Returns the outcome when a pending clear was resolved.
    pub fn tick_clipboard(
        &mut self,
        now: std::time::Instant,
    ) -> Option<crate::clipboard::ClearOutcome> {
        use crate::clipboard::{clear_if_due, ClearOutcome};
        let pending = self.clipboard_pending.as_ref()?;
        let outcome = clear_if_due(self.clipboard.as_ref(), pending, now, false);
        match outcome {
            ClearOutcome::NotDue => return None,
            ClearOutcome::Cleared => self.status = "Clipboard cleared".into(),
            ClearOutcome::Replaced | ClearOutcome::Failed => {}
        }
        self.clipboard_pending = None;
        Some(outcome)
    }

    /// Clear our value from the clipboard right away (on lock).
    fn clear_clipboard_now(&mut self) {
        if let Some(pending) = self.clipboard_pending.take() {
            let _ = crate::clipboard::clear_if_due(
                self.clipboard.as_ref(),
                &pending,
                std::time::Instant::now(),
                true,
            );
        }
    }

    /// What the idle auto-lock should do at `now`.
    pub fn idle_lock_action(&self, now: std::time::Instant) -> IdleLock {
        if self.db.is_none() || !self.prefs.auto_lock {
            return IdleLock::Wait;
        }
        let limit = std::time::Duration::from_secs(u64::from(self.prefs.auto_lock_minutes) * 60);
        if now.saturating_duration_since(self.last_activity) < limit {
            return IdleLock::Wait;
        }
        if self.dirty || self.inline_edit.is_some() {
            IdleLock::Postpone
        } else {
            IdleLock::Lock
        }
    }

    /// Lock after the configured inactivity, unless that would throw away
    /// work: with unsaved changes (or an open editor) the lock is postponed
    /// and the status bar says so; it happens on the next idle period after
    /// the changes are saved.
    pub fn tick_idle_lock(&mut self, now: std::time::Instant) -> IdleLock {
        let action = self.idle_lock_action(now);
        match action {
            IdleLock::Wait => {}
            IdleLock::Lock => {
                self.lock();
                self.status = "Locked after inactivity".into();
            }
            IdleLock::Postpone => {
                if !self.auto_lock_postponed {
                    self.auto_lock_postponed = true;
                    self.status =
                        "Auto-lock postponed: save or discard your changes to allow it".into();
                }
            }
        }
        action
    }

    /// Record user activity (resets the idle timer).
    pub fn note_activity(&mut self, now: std::time::Instant) {
        self.last_activity = now;
    }

    /// True while `field_key` is showing its "Copied" confirmation.
    pub fn is_field_copied(&self, field_key: &str) -> bool {
        self.copied_fields
            .get(field_key)
            .is_some_and(|t| t.elapsed() < COPIED_TTL)
    }

    /// Copy `text` to the clipboard for `field_key` (e.g. "username",
    /// "attr:KP2A_URL"): records the "Copied" confirmation state for the
    /// details panel and queues a toast notification.
    pub fn note_copied(&mut self, field_key: &str, label: &str, text: String) {
        self.copy_to_clipboard(text);
        if self.status.starts_with("clipboard unavailable") {
            return;
        }
        self.status = format!("Copied {label} to clipboard");
        self.copied_fields
            .insert(field_key.to_string(), std::time::Instant::now());
        self.toasts.push(Toast {
            text: self.copy_toast_text(label),
            created: std::time::Instant::now(),
        });
        if self.toasts.len() > 3 {
            self.toasts.remove(0);
        }
    }

    /// "Password copied — clears in 30 s" (or without the countdown when
    /// auto-clear is off).
    pub fn copy_toast_text(&self, label: &str) -> String {
        match &self.clipboard_pending {
            Some(_) => format!(
                "{label} copied \u{2014} clears in {} s",
                self.prefs.clipboard_clear_secs
            ),
            None => format!("{label} copied to clipboard"),
        }
    }

    /// Draw the transient toast notifications (bottom-right, fading out) and
    /// prune expired copy-confirmation state.
    fn render_toasts(&mut self, ctx: &egui::Context) {
        let now = std::time::Instant::now();
        self.toasts.retain(|t| now.duration_since(t.created) < TOAST_TTL);
        self.copied_fields
            .retain(|_, t| now.duration_since(*t) < COPIED_TTL);
        if self.toasts.is_empty() {
            return;
        }
        let toasts = std::mem::take(&mut self.toasts);
        egui::Area::new(egui::Id::new("friendlypass-toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-18.0, -44.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Max), |ui| {
                    for toast in toasts.iter().rev() {
                        let frac = 1.0
                            - now.duration_since(toast.created).as_secs_f32()
                                / TOAST_TTL.as_secs_f32();
                        let a = frac.clamp(0.0, 1.0);
                        egui::Frame::new()
                            .fill(crate::theme::p().panel.gamma_multiply(a))
                            .stroke(egui::Stroke::new(
                                1.0,
                                crate::theme::p().border.gamma_multiply(a),
                            ))
                            .corner_radius(10)
                            .inner_margin(egui::Margin::symmetric(12, 8))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let (r, _) = ui.allocate_exact_size(
                                        egui::vec2(14.0, 14.0),
                                        egui::Sense::hover(),
                                    );
                                    crate::theme::draw_check_icon(
                                        ui.painter(),
                                        r.center(),
                                        crate::theme::p().good.gamma_multiply(a),
                                    );
                                    ui.add_space(4.0);
                                    ui.label(
                                        egui::RichText::new(&toast.text)
                                            .size(13.0)
                                            .color(crate::theme::p().text.gamma_multiply(a)),
                                    );
                                });
                            });
                        ui.add_space(6.0);
                    }
                });
            });
        self.toasts = toasts;
        ctx.request_repaint_after(std::time::Duration::from_millis(80));
    }

    /// Draw the non-blocking browser-connection notice (top center) and apply
    /// its Revoke action. Unlike toasts it stays until the user acts: it is
    /// the only place that undoes an automatic approval.
    fn render_browser_notice(&mut self, ctx: &egui::Context) {
        let Some(notice) = self.browser_notice.clone() else {
            return;
        };
        let mut revoke = false;
        let mut dismiss = false;
        egui::Area::new(egui::Id::new("friendlypass-browser-notice"))
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 64.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(crate::theme::p().panel)
                    .stroke(egui::Stroke::new(1.0, crate::theme::p().border))
                    .corner_radius(10)
                    .inner_margin(egui::Margin::symmetric(14, 8))
                    .shadow(egui::epaint::Shadow {
                        offset: [0, 2],
                        blur: 12,
                        spread: 0,
                        color: egui::Color32::from_black_alpha(60),
                    })
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} connected to friendlypass",
                                    notice.browser
                                ))
                                .size(13.5)
                                .color(crate::theme::p().text),
                            );
                            if ui.small_button("Revoke").clicked() {
                                revoke = true;
                            }
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("\u{00d7}")
                                            .size(14.0)
                                            .color(crate::theme::p().muted),
                                    )
                                    .frame(false),
                                )
                                .on_hover_text("Dismiss")
                                .clicked()
                            {
                                dismiss = true;
                            }
                        });
                    });
            });
        if revoke {
            crate::browser_bridge::revoke_association(self, &notice.association_id);
            self.status = format!("{} disconnected", notice.browser);
            self.browser_notice = None;
        } else if dismiss {
            self.browser_notice = None;
        }
    }

    /// Copy a field of the selected entry (keyboard shortcuts).
    pub fn copy_selected(&mut self, field: CopyField) {
        let Some(id) = self.selected_entry else {
            self.status = "No entry selected".into();
            return;
        };
        let Some(db) = self.db.as_ref() else { return };
        let Some(entry) = db.entry(id) else { return };
        let (label, value) = match field {
            CopyField::Password => ("password", entry.get("Password").unwrap_or_default().to_owned()),
            CopyField::Username => ("username", entry.get("UserName").unwrap_or_default().to_owned()),
            CopyField::Url => ("URL", entry.get("URL").unwrap_or_default().to_owned()),
            CopyField::Totp => ("TOTP", match crate::totp::current_code(&entry) {
                Some((code, _)) => code,
                None => {
                    self.status = "This entry has no TOTP".into();
                    return;
                }
            }),
        };
        if value.is_empty() {
            self.status = format!("This entry has no {label}");
            return;
        }
        let key = match field {
            CopyField::Password => "password",
            CopyField::Username => "username",
            CopyField::Url => "url",
            CopyField::Totp => "totp",
        };
        let pretty = match field {
            CopyField::Password => "Password",
            CopyField::Username => "Username",
            CopyField::Url => "URL",
            CopyField::Totp => "TOTP",
        };
        self.note_copied(key, pretty, value);
        if !self.status.starts_with("clipboard unavailable") {
            self.status = format!("Copied {label} to clipboard");
        }
    }

    /// Whether entry `id` is a favorite (the `FRIENDLYPASS_FAVORITE` field,
    /// or a "favorite"-style tag from other apps).
    pub fn is_favorite(&self, id: EntryId) -> bool {
        self.db
            .as_ref()
            .and_then(|db| db.entry(id))
            .is_some_and(|e| crate::browser::entry_is_favorite(&e))
    }

    /// Star or unstar an entry. Stored as the `FRIENDLYPASS_FAVORITE` custom
    /// field; unstarring also drops "favorite"-style tags, which would
    /// otherwise keep the entry starred. Recorded in the entry history like
    /// every other edit.
    pub fn toggle_favorite(&mut self, id: EntryId) {
        let now_favorite = !self.is_favorite(id);
        let Some(db) = self.db.as_mut() else { return };
        let Some(mut entry) = db.entry_mut(id) else { return };
        let title = entry.as_ref().get(keepass::db::fields::TITLE).unwrap_or_default().to_owned();
        entry.track_changes().as_mut().edit(|e| {
            if now_favorite {
                e.fields.insert(
                    crate::browser::FAVORITE_FIELD.to_owned(),
                    keepass::db::Value::unprotected("1".to_owned()),
                );
            } else {
                e.fields.remove(crate::browser::FAVORITE_FIELD);
                e.tags.retain(|t| !crate::browser::is_favorite_tag(t));
            }
        });
        self.dirty = true;
        self.status = if now_favorite {
            format!("Added '{title}' to Favorites")
        } else {
            format!("Removed '{title}' from Favorites")
        };
    }

    /// Handle global keyboard shortcuts on the database screen.
    /// Returns true if a shortcut consumed a key this frame.
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        use egui::{Key, Modifiers};
        // Shortcuts are ignored while a dialog is open (dialogs handle their
        // own keys, see `dialogs::show`).
        if !matches!(self.dialog, Dialog::None) {
            return;
        }
        let cmd = Modifiers::COMMAND;
        let shift = Modifiers::COMMAND | Modifiers::SHIFT;
        // True while a text field (e.g. the search box) has focus. Typing
        // keys then belong to the field; global commands still work.
        let typing = ctx.egui_wants_keyboard_input();

        // Global commands: available even while typing.
        if ctx.input_mut(|i| i.consume_key(cmd, Key::S)) {
            self.request_save();
        }
        if ctx.input_mut(|i| i.consume_key(shift, Key::S)) {
            self.dialog = Dialog::SaveAs(self.db_path.clone());
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::L)) {
            self.lock();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::F)) {
            self.focus_search = true;
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::G)) {
            self.dialog = Dialog::Generator(Box::new(dialogs::Generator::default()));
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::N)) {
            self.new_entry_dialog(self.selected_group);
        }
        if ctx.input_mut(|i| i.consume_key(shift, Key::N)) {
            self.open_new_group_dialog();
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F1)) {
            self.dialog = Dialog::Shortcuts;
        }
        if typing {
            return;
        }
        // While the inline editor is open, Escape / Cmd+Enter belong to it
        // and plain keys must not act on the list behind it.
        if self.inline_edit.is_some() {
            return;
        }
        // Entry commands: only when no text field is focused, so Cmd+C in
        // the search box still copies text and Delete edits the query.
        if ctx.input_mut(|i| i.consume_key(cmd, Key::C)) {
            self.copy_selected(CopyField::Password);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::B)) {
            self.copy_selected(CopyField::Username);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::U)) {
            self.copy_selected(CopyField::Url);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::T)) {
            self.copy_selected(CopyField::Totp);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::E)) {
            if let Some(id) = self.selected_entry {
                self.edit_entry_dialog(id);
            }
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::H)) {
            if let Some(id) = self.selected_entry {
                self.dialog = Dialog::History(id);
            }
        }
        // Up/Down walk through the entries the list currently shows.
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::ArrowDown)) {
            self.select_adjacent_entry(1);
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::ArrowUp)) {
            self.select_adjacent_entry(-1);
        }
        // Delete key (macOS Backspace) recycles the selected entry.
        let delete = ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Delete))
            || ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Backspace));
        if delete {
            if let Some(id) = self.selected_entry {
                self.dialog = Dialog::ConfirmDeleteEntry(id);
            }
        }
        // Enter opens the selected entry for editing.
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Enter)) {
            if let Some(id) = self.selected_entry {
                self.edit_entry_dialog(id);
            }
        }
        // Escape clears an active search.
        if !self.search.is_empty() && ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
            self.search.clear();
        }
    }

    /// Move the selection `step` rows through the visible entries (arrow
    /// keys). With nothing selected, Down picks the first entry and Up the
    /// last. The list scrolls to keep the selection visible.
    pub fn select_adjacent_entry(&mut self, step: isize) {
        let ids = crate::browser::visible_entry_ids(self);
        if ids.is_empty() {
            return;
        }
        let current = self
            .selected_entry
            .and_then(|id| ids.iter().position(|e| *e == id));
        let next = match current {
            Some(i) => (i as isize + step).clamp(0, ids.len() as isize - 1) as usize,
            None if step >= 0 => 0,
            None => ids.len() - 1,
        };
        let id = ids[next];
        self.selected_entry = Some(id);
        self.selected_entries.clear();
        self.selected_entries.insert(id);
        self.selection_anchor = Some(id);
        self.scroll_to_selected = true;
    }

    /// Apply a click on entry `id` in the list or table: plain click selects
    /// it alone, Cmd/Ctrl toggles it in the multi-selection, Shift selects the
    /// range from the anchor (the last plain/Cmd click) in list order.
    pub fn click_entry(&mut self, id: EntryId, modifiers: egui::Modifiers) {
        if modifiers.shift {
            let ids = crate::browser::visible_entry_ids(self);
            let anchor = self.selection_anchor.or(self.selected_entry).unwrap_or(id);
            let a = ids.iter().position(|e| *e == anchor);
            let b = ids.iter().position(|e| *e == id);
            if let (Some(a), Some(b)) = (a, b) {
                let (lo, hi) = (a.min(b), a.max(b));
                self.selected_entries = ids[lo..=hi].iter().copied().collect();
                self.selected_entry = Some(id);
                // The anchor stays put so the range can be adjusted.
                self.selection_anchor = Some(anchor);
                return;
            }
        }
        if modifiers.command {
            if !self.selected_entries.remove(&id) {
                self.selected_entries.insert(id);
            }
        } else {
            self.selected_entries.clear();
            self.selected_entries.insert(id);
        }
        self.selected_entry = Some(id);
        self.selection_anchor = Some(id);
    }

    /// Open the entry editor for a new entry in the given group.
    pub fn new_entry_dialog(&mut self, group: Option<GroupId>) {
        let parent = group
            .or(self.selected_group)
            .unwrap_or_else(|| self.db.as_ref().map(|db| db.root().id()).expect("db open"));
        let targets = self
            .db
            .as_ref()
            .map(|db| crate::refs::ref_targets(db, None))
            .unwrap_or_default();
        let custom_icons = self.custom_icon_snapshot();
        // New entries use the same inline editor as edits (right column, or
        // under the list in the stacked layout).
        self.inline_edit = Some(Box::new(dialogs::EntryEdit::new(parent, targets, custom_icons)));
        if !self.prefs.list_view {
            self.prefs.list_view = true;
            self.save_preferences();
        }
        self.dialog = Dialog::None;
    }

    /// Open the entry editor for an existing entry (loads its fields).
    pub fn edit_entry_dialog(&mut self, id: keepass::db::EntryId) {
        let Some(db) = self.db.as_ref() else { return };
        let Some(entry) = db.entry(id) else { return };
        let targets = crate::refs::ref_targets(db, Some(id));
        let custom_icons = self.custom_icon_snapshot();
        self.inline_edit = Some(Box::new(dialogs::EntryEdit::from_entry(
            id,
            &entry,
            targets,
            custom_icons,
        )));
        // Inline editing lives in the right-hand details column.
        if !self.prefs.list_view {
            self.prefs.list_view = true;
            self.save_preferences();
        }
        self.dialog = Dialog::None;
    }

    /// Snapshot of the database custom icon pool (for editor pickers).
    fn custom_icon_snapshot(&self) -> Vec<(keepass::db::CustomIconId, Vec<u8>)> {
        self.db
            .as_ref()
            .map(|db| {
                db.iter_all_custom_icons()
                    .map(|ci| (ci.id(), ci.data.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Delete an entry (after confirmation), mirroring KeePassXC's behavior:
    /// if the recycle bin is enabled and the entry is not already inside it,
    /// the entry is *moved* to the recycle bin group (created on demand);
    /// otherwise it is deleted permanently.
    pub fn delete_entry(&mut self, id: keepass::db::EntryId) {
        let to_recycle = self.deletes_to_recycle_bin_entry(id);
        let bin_id = to_recycle.then(|| self.ensure_recycle_bin());
        let Some(db) = self.db.as_mut() else { return };

        if let Some(bin_id) = bin_id {
            if let Some(mut entry) = db.entry_mut(id) {
                match entry.track_changes().move_to(bin_id) {
                    Ok(()) => {
                        self.dirty = true;
                        self.selected_entry = None;
                        self.status = "Entry moved to the Recycle Bin".into();
                    }
                    Err(e) => self.status = format!("cannot move entry to recycle bin: {e}"),
                }
            }
        } else if let Some(entry) = db.entry_mut(id) {
            entry.remove();
            self.dirty = true;
            if self.selected_entry == Some(id) {
                self.selected_entry = None;
            }
            self.status = "Entry deleted permanently".into();
        }
    }

    /// Delete a group (after confirmation) with the same recycle-bin
    /// semantics as [`App::delete_entry`]. The root group cannot be deleted.
    pub fn delete_group(&mut self, id: GroupId) {
        // Decide first (immutable), then mutate.
        let bin_id_current = self.db.as_ref().and_then(|db| db.recycle_bin()).map(|b| b.id());
        let in_bin = self
            .db
            .as_ref()
            .and_then(|db| db.group(id))
            .and_then(|g| g.parent().map(|p| p.id()))
            .map(|pid| Some(pid) == bin_id_current)
            .unwrap_or(false);
        let is_bin_itself = bin_id_current == Some(id);
        let to_recycle = self.recycle_bin_enabled() && !in_bin && !is_bin_itself;

        let bin_id = to_recycle.then(|| self.ensure_recycle_bin());
        let Some(db) = self.db.as_mut() else { return };

        if let Some(bin_id) = bin_id {
            if let Some(mut group) = db.group_mut(id) {
                match group.track_changes().move_to(bin_id) {
                    Ok(()) => {
                        self.dirty = true;
                        if self.selected_group == Some(id) {
                            self.selected_group = None;
                        }
                        self.status = "Group moved to the Recycle Bin".into();
                    }
                    Err(e) => self.status = format!("cannot move group to recycle bin: {e}"),
                }
            }
        } else if let Some(mut group) = db.group_mut(id) {
            match group.track_changes().remove() {
                Ok(()) => {
                    self.dirty = true;
                    if self.selected_group == Some(id) {
                        self.selected_group = None;
                    }
                    self.status = "Group deleted permanently".into();
                }
                Err(e) => self.status = format!("cannot delete group: {e}"),
            }
        }
    }

    /// Perform auto-type for an entry: resolves the entry's auto-type
    /// sequence (or the KeePass default) and injects the keystrokes on a
    /// background thread after a short countdown, so the user can focus the
    /// target window — the same UX as KeePassXC.
    ///
    /// On macOS this requires the Accessibility permission; failures are
    /// logged (the GUI cannot inject without the user granting it).
    pub fn perform_auto_type(&mut self, id: keepass::db::EntryId) {
        let Some(db) = self.db.as_ref() else { return };
        let Some(entry) = db.entry(id) else { return };
        let sequence = entry
            .autotype
            .as_ref()
            .and_then(|a| a.default_sequence.clone())
            .unwrap_or_else(|| crate::autotype::DEFAULT_SEQUENCE.to_owned());
        let actions = crate::autotype::resolve_sequence(db, id, &sequence);

        std::thread::spawn(move || {
            // Countdown so the user can focus the target window.
            std::thread::sleep(std::time::Duration::from_millis(1500));
            let result = crate::autotype::EnigoInjector::new()
                .and_then(|mut injector| crate::autotype::execute(&mut injector, &actions));
            if let Err(e) = result {
                eprintln!("auto-type failed: {e:#} (on macOS, grant the app the Accessibility permission)");
            }
        });
        self.status =
            "Auto-Type starts in 1.5 seconds - focus the target window".into();
    }

    /// Move a group to another group (drag & drop), with the same
    /// cycle-prevention as KeePassXC: a group cannot be dropped into itself
    /// or into one of its own descendants.
    pub fn move_group_to(&mut self, group: GroupId, target: Option<GroupId>) {
        let Some(db) = self.db.as_ref() else { return };
        let root_id = db.root().id();
        let target_id = target.unwrap_or(root_id);

        if target_id == group {
            self.status = "Cannot move a group into itself".into();
            return;
        }
        // Reject dropping a group into its own subtree.
        let mut cur = Some(target_id);
        while let Some(c) = cur {
            if c == group {
                self.status = "Cannot move a group into one of its own groups".into();
                return;
            }
            cur = self
                .db
                .as_ref()
                .and_then(|db| db.group(c))
                .and_then(|g| g.parent().map(|p| p.id()));
        }

        let group_name = self
            .db
            .as_ref()
            .and_then(|db| db.group(group))
            .map(|g| g.name.clone())
            .unwrap_or_default();
        let target_name = target
            .and_then(|t| self.db.as_ref().and_then(|db| db.group(t)).map(|g| g.name.clone()))
            .unwrap_or_else(|| {
                self.db
                    .as_ref()
                    .map(|db| db.root().name.clone())
                    .unwrap_or_default()
            });

        let Some(db) = self.db.as_mut() else { return };
        if let Some(mut g) = db.group_mut(group) {
            match g.track_changes().move_to(target_id) {
                Ok(()) => {
                    self.dirty = true;
                    self.selected_group = Some(group);
                    self.status = format!("Moved group {group_name} to {target_name}");
                }
                Err(e) => self.status = format!("cannot move group: {e}"),
            }
        }
    }

    /// Move a batch of entries to a group (batch operation on the
    /// multi-selection).
    pub fn move_entries_to(&mut self, ids: &[EntryId], target: GroupId) {
        let mut moved = 0;
        if let Some(db) = self.db.as_mut() {
            for id in ids {
                if let Some(mut entry) = db.entry_mut(*id) {
                    if entry.track_changes().move_to(target).is_ok() {
                        moved += 1;
                    }
                }
            }
        }
        if moved > 0 {
            self.dirty = true;
            let target_name = self
                .db
                .as_ref()
                .and_then(|db| db.group(target))
                .map(|g| g.name.clone())
                .unwrap_or_default();
            let plural = if moved == 1 { "entry" } else { "entries" };
            self.status = format!("Moved {moved} {plural} to {target_name}");
        }
        self.selected_entries.clear();
        self.selected_entry = None;
    }

    /// Recycle a batch of entries (multi-selection delete).
    pub fn recycle_entries(&mut self, ids: Vec<EntryId>) {
        let n = ids.len();
        for id in ids {
            self.delete_entry(id);
        }
        self.status = format!("Moved {n} entries to the Recycle Bin");
        self.selected_entries.clear();
        self.selected_entry = None;
    }

    /// Snapshot of all groups (for the batch-move dialog), with paths.
    pub fn group_snapshot(&self) -> Vec<(GroupId, String)> {
        let Some(db) = self.db.as_ref() else { return Vec::new() };
        let mut out = vec![(db.root().id(), "(root)".into())];
        fn walk(db: &keepass::db::Database, id: GroupId, prefix: &str, out: &mut Vec<(GroupId, String)>) {
            if let Some(g) = db.group(id) {
                let mut children: Vec<(GroupId, String)> = g
                    .groups()
                    .map(|c| (c.id(), c.name.clone()))
                    .collect();
                children.sort_by(|a, b| a.1.cmp(&b.1));
                for (cid, name) in children {
                    let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
                    out.push((cid, path.clone()));
                    walk(db, cid, &path, out);
                }
            }
        }
        let root = db.root().id();
        walk(db, root, "", &mut out);
        out
    }

    /// Permanently remove everything inside the recycle bin.
    pub fn empty_recycle_bin(&mut self) {
        let Some(db) = self.db.as_mut() else { return };
        let Some(bin) = db.recycle_bin() else {
            self.status = "No recycle bin in this database".into();
            return;
        };
        let entry_ids: Vec<_> = bin.entries().map(|e| e.id()).collect();
        let group_ids: Vec<_> = bin.groups().map(|g| g.id()).collect();
        let n = entry_ids.len() + group_ids.len();

        for id in entry_ids {
            if let Some(entry) = db.entry_mut(id) {
                entry.remove();
            }
        }
        for id in group_ids {
            if let Some(mut group) = db.group_mut(id) {
                let _ = group.track_changes().remove();
            }
        }
        self.dirty = true;
        self.selected_entry = None;
        self.status = format!("Emptied the Recycle Bin ({n} objects removed)");
    }

    /// Whether the recycle bin is enabled in this database's metadata.
    pub fn recycle_bin_enabled(&self) -> bool {
        self.db
            .as_ref()
            .map(|db| db.meta.recyclebin_enabled.unwrap_or(true))
            .unwrap_or(true)
    }

    /// Whether deleting this entry would move it to the recycle bin
    /// (used to word the confirmation dialog like KeePassXC does).
    pub fn deletes_to_recycle_bin_entry(&self, id: keepass::db::EntryId) -> bool {
        let Some(db) = self.db.as_ref() else { return false };
        if !self.recycle_bin_enabled() {
            return false;
        }
        let bin_id = db.recycle_bin().map(|b| b.id());
        // Already inside the bin (or inside a group within the bin)?
        let mut parent = db.entry(id).map(|e| e.parent().id());
        while let Some(pid) = parent {
            if Some(pid) == bin_id {
                return false;
            }
            parent = db.group(pid).and_then(|g| g.parent().map(|p| p.id()));
        }
        true
    }

    /// Get the recycle bin group id, creating the group (and registering it
    /// in the metadata) on first use, exactly like KeePassXC.
    fn ensure_recycle_bin(&mut self) -> GroupId {
        if let Some(bin) = self.db.as_ref().and_then(|db| db.recycle_bin()) {
            return bin.id();
        }
        let Some(db) = self.db.as_mut() else { unreachable!("db is open") };
        let mut root = db.root_mut();
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".into();
        let id = bin.id();
        drop(bin);
        drop(root);
        db.meta.recyclebin_uuid = Some(id.uuid());
        db.meta.recyclebin_changed = Some(chrono::Utc::now().naive_utc());
        self.dirty = true;
        id
    }

    /// Restore a historical revision of an entry: copies all fields of the
    /// revision into the current entry. Like KeePassXC, the restore itself
    /// is recorded in the entry's history.
    pub fn restore_history_entry(&mut self, id: keepass::db::EntryId, index: usize) {
        let Some(db) = self.db.as_mut() else { return };

        // Snapshot the historical fields.
        let historical_fields = db
            .entry(id)
            .and_then(|e| e.historical(index).map(|h| h.fields.clone()));

        let Some(fields) = historical_fields else {
            self.status = "History revision not found".into();
            return;
        };

        if let Some(mut entry) = db.entry_mut(id) {
            entry.track_changes().edit(|e| {
                e.fields = fields;
            });
            self.dirty = true;
            self.dialog = Dialog::None;
            self.status = "Restored entry from history".into();
        }
    }

    /// Whether the library sidebar is shown for a window of `window_w` points:
    /// the explicit toggle wins, otherwise it appears when three columns fit.
    pub fn sidebar_visible(&self, window_w: f32) -> bool {
        self.sidebar_override.unwrap_or(window_w >= SIDEBAR_AUTO_HIDE_WIDTH)
    }

    /// The toolbar's action buttons (right to left): New Entry, the "+" menu
    /// (other things to add), Lock, Save, and the gear menu (settings and
    /// tools).
    fn toolbar_actions(&mut self, ui: &mut Ui) {
        if ui
            .add(crate::theme::primary_button("New Entry"))
            .on_hover_text("New entry (Cmd/Ctrl+N)")
            .clicked()
        {
            self.new_entry_dialog(self.selected_group);
        }
        crate::theme::icon_menu(ui, "add-menu", "Add", crate::theme::draw_plus_icon, |ui| {
            if ui.button("New Group…").clicked() {
                self.open_new_group_dialog();
                ui.close();
            }
            if ui.button("Import…").clicked() {
                self.dialog = Dialog::Import(Box::default());
                ui.close();
            }
        });
        if ui
            .button("Lock")
            .on_hover_text("Lock the database (Cmd/Ctrl+L)")
            .clicked()
        {
            self.lock();
        }
        if save_button(ui, self.dirty).clicked() {
            self.request_save();
        }
        crate::theme::icon_menu(
            ui,
            "settings-menu",
            "Settings and tools",
            crate::theme::draw_gear_icon,
            |ui| {
                if ui.button("Settings…").clicked() {
                    self.launch_at_login = startup::launch_at_login_enabled();
                    self.dialog = Dialog::Settings;
                    ui.close();
                }
                if ui.button("Columns…").clicked() {
                    self.dialog = Dialog::Columns;
                    ui.close();
                }
                if ui.button("Database Info…").clicked() {
                    self.dialog = Dialog::DbInfo;
                    ui.close();
                }
                if ui.button("SSH Agent…").clicked() {
                    self.dialog = Dialog::SshAgent;
                    ui.close();
                }
                if ui.button("Browser…").clicked() {
                    self.dialog = Dialog::Browser;
                    ui.close();
                }
                if ui.button("Shortcuts…").clicked() {
                    self.dialog = Dialog::Shortcuts;
                    ui.close();
                }
                ui.separator();
                if ui.button("Export…").clicked() {
                    self.dialog = Dialog::Export(Box::new(dialogs::ExportDialog::new(
                        &self.db_path,
                        "XML",
                    )));
                    ui.close();
                }
                if ui.button("Save As…").clicked() {
                    self.dialog = Dialog::SaveAs(self.db_path.clone());
                    ui.close();
                }
                if ui.button("Password Generator…").clicked() {
                    self.dialog = Dialog::Generator(Box::new(dialogs::Generator::default()));
                    ui.close();
                }
                ui.separator();
                ui.checkbox(&mut self.show_passwords, "Show passwords");
            },
        );
    }

    /// Open the New Group dialog under the selected group (or the root).
    pub fn open_new_group_dialog(&mut self) {
        let Some(db) = self.db.as_ref() else { return };
        let parent = self.selected_group.unwrap_or_else(|| db.root().id());
        self.dialog = Dialog::GroupNew(Box::new(dialogs::GroupEdit::new(parent)));
    }

    /// Record a user navigation step whenever the selected entry changes, so
    /// the toolbar arrows can walk back and forth between entries.
    fn record_navigation(&mut self) {
        if self.nav_internal {
            self.nav_internal = false;
            self.nav_last = self.selected_entry;
            return;
        }
        if self.selected_entry != self.nav_last {
            if let (Some(previous), Some(_)) = (self.nav_last, self.selected_entry) {
                self.nav_back.push(previous);
                self.nav_forward.clear();
            }
            self.nav_last = self.selected_entry;
        }
    }

    /// Show `id`, revealing the group it lives in and clearing filters that
    /// would hide it. Used by Back/Forward.
    fn reveal_entry(&mut self, id: EntryId) {
        let parent = self.db.as_ref().and_then(|db| db.entry(id)).map(|e| e.parent().id());
        if let Some(parent) = parent {
            let is_root = self
                .db
                .as_ref()
                .is_some_and(|db| db.root().id() == parent);
            self.selected_group = if is_root { None } else { Some(parent) };
        }
        self.selected_tag = None;
        self.filter_favorites = false;
        self.filter_attachments = false;
        self.search.clear();
        self.selected_entries.clear();
        self.selected_entries.insert(id);
        self.selected_entry = Some(id);
        self.nav_internal = true;
    }

    /// Go back to the previously selected entry (toolbar Back arrow).
    pub fn navigate_back(&mut self) {
        let Some(target) = self.nav_back.pop() else { return };
        if let Some(current) = self.selected_entry {
            self.nav_forward.push(current);
        }
        self.reveal_entry(target);
        self.nav_last = self.selected_entry;
        self.status = "Went back".into();
    }

    /// Go forward again after going back (toolbar Forward arrow).
    pub fn navigate_forward(&mut self) {
        let Some(target) = self.nav_forward.pop() else { return };
        if let Some(current) = self.selected_entry {
            self.nav_back.push(current);
        }
        self.reveal_entry(target);
        self.nav_last = self.selected_entry;
        self.status = "Went forward".into();
    }

    /// Attach `data` to entry `id` under `name`, overwriting an attachment of
    /// the same name (KeePassXC replaces rather than rejects duplicates).
    /// Like every other mutation this records an entry history revision, so
    /// the change can be undone from the history browser.
    pub fn add_entry_attachment(
        &mut self,
        id: keepass::db::EntryId,
        name: &str,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let name = attachment_name(name);
        if name.is_empty() {
            anyhow::bail!("the file name cannot be empty");
        }
        let Some(db) = self.db.as_mut() else {
            anyhow::bail!("no database is open");
        };
        let Some(mut entry) = db.entry_mut(id) else {
            anyhow::bail!("entry not found");
        };
        let bytes = data.len();
        let replaced = entry.as_ref().attachment_by_name(&name).is_some();
        entry.track_changes().as_mut().edit(|e| {
            e.add_attachment(name.clone(), keepass::db::Value::unprotected(data));
        });
        self.dirty = true;
        self.status = format!(
            "{} attachment '{name}' ({bytes} bytes)",
            if replaced { "Replaced" } else { "Added" }
        );
        Ok(())
    }

    /// Remove attachment `name` from entry `id`, recording a history revision.
    /// Data shared with other entries is only detached here — the file is
    /// deleted from the database once nothing references it.
    pub fn remove_entry_attachment(
        &mut self,
        id: keepass::db::EntryId,
        name: &str,
    ) -> anyhow::Result<()> {
        let Some(db) = self.db.as_mut() else {
            anyhow::bail!("no database is open");
        };
        let Some(mut entry) = db.entry_mut(id) else {
            anyhow::bail!("entry not found");
        };
        if entry.as_ref().attachment_by_name(name).is_none() {
            anyhow::bail!("no attachment named {name:?}");
        }
        entry.track_changes().as_mut().edit(|e| {
            e.remove_attachment_by_name(name);
        });
        self.dirty = true;
        self.status = format!("Removed attachment '{name}'");
        Ok(())
    }
}

/// Tidy a user- or OS-supplied file name into something that is safe as a
/// KeePass attachment name: directories are stripped (the attachment name is
/// not a path, so "/" in it breaks export on Unix and Windows alike).
pub fn attachment_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches(['/', '\\']);
    if trimmed.is_empty() {
        return String::new();
    }
    // Split on both separators regardless of the host OS: a name coming from
    // a Windows path on macOS must still lose its directories.
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| trimmed.to_owned())
}

/// Human-readable byte size ("512 bytes", "1.4 KB", "3.2 MB").
pub fn format_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    match bytes as f64 {
        b if b < KB => format!("{bytes} bytes"),
        b if b < KB * KB => format!("{:.1} KB", b / KB),
        b => format!("{:.1} MB", b / (KB * KB)),
    }
}

/// Why a database could not be opened, in terms a person can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFailure {
    /// No file at that path.
    Missing,
    /// The file exists but cannot be read (permissions, I/O error).
    Unreadable,
    /// The password, key file or challenge-response secret is wrong.
    Credentials,
    /// Not a KeePass database (or a damaged / unsupported one).
    NotADatabase,
}

/// A failed open: the category plus the full technical error.
#[derive(Debug, Clone)]
pub struct OpenError {
    pub kind: OpenFailure,
    pub detail: String,
}

impl OpenError {
    /// The short message shown on the unlock screen.
    pub fn message(&self) -> &'static str {
        match self.kind {
            OpenFailure::Missing => "Database file not found.",
            OpenFailure::Unreadable => "The database file can't be read.",
            OpenFailure::Credentials => "Wrong password or key file.",
            OpenFailure::NotADatabase => "This file isn't a KeePass database, or it is damaged.",
        }
    }
}

/// Sort a `keepass` open error into an [`OpenFailure`]. KDBX 4 reports a wrong
/// key as `IncorrectKey`; KDBX 3 only notices when decryption produces bad
/// padding, so both mean "wrong credentials".
fn classify_open_error(e: &keepass::db::DatabaseOpenError) -> OpenFailure {
    use keepass::db::DatabaseOpenError as E;
    let debug = format!("{e:?}").to_ascii_lowercase();
    if debug.contains("incorrectkey") || debug.contains("padding") {
        return OpenFailure::Credentials;
    }
    match e {
        E::Key(_) | E::Cryptography(_) => OpenFailure::Credentials,
        E::Io(_) => OpenFailure::Unreadable,
        _ => OpenFailure::NotADatabase,
    }
}

/// Open a database, classifying failures for the unlock screen.
pub fn open_database_checked(path: &str, key: &DatabaseKey) -> Result<Database, OpenError> {
    let mut file = std::fs::File::open(path).map_err(|e| OpenError {
        kind: if e.kind() == std::io::ErrorKind::NotFound {
            OpenFailure::Missing
        } else {
            OpenFailure::Unreadable
        },
        detail: format!("unable to open database file {path}: {e}"),
    })?;
    Database::open(&mut file, key.clone()).map_err(|e| OpenError {
        kind: classify_open_error(&e),
        detail: format!("unable to open database {path}: {e}"),
    })
}

/// Open a database with friendly error mapping (shared with the CLI layer).
pub fn open_database(path: &str, key: &DatabaseKey) -> anyhow::Result<Database> {
    open_database_checked(path, key).map_err(|e| anyhow::anyhow!("{} ({})", e.message(), e.detail))
}

// ---------------------------------------------------------------------------
// eframe integration
// ---------------------------------------------------------------------------

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        crate::theme::setup(&ctx, self.prefs.theme);
        let now = std::time::Instant::now();

        // Browser-integration bridge: approvals, set-login writes, pushes and
        // the served snapshot all run on the GUI thread.
        crate::browser_bridge::pump(self, &ctx);

        // Clipboard auto-clear runs on every screen, so a copied password is
        // removed even after the database was locked.
        self.tick_clipboard(now);
        if let Some(pending) = &self.clipboard_pending {
            ctx.request_repaint_after(pending.deadline.saturating_duration_since(now));
        }

        if self.db.is_some() {
            // Any input counts as activity for the idle auto-lock.
            if ctx.input(|i| !i.events.is_empty() || i.pointer.any_down()) {
                self.note_activity(now);
                self.auto_lock_postponed = false;
            }
            self.tick_idle_lock(now);
            if self.db.is_some() && self.prefs.auto_lock {
                let limit = std::time::Duration::from_secs(
                    u64::from(self.prefs.auto_lock_minutes) * 60,
                );
                let due = (self.last_activity + limit).saturating_duration_since(now);
                ctx.request_repaint_after(due.max(std::time::Duration::from_secs(1)));
            }
        }

        if self.db.is_none() {
            self.unlock_screen(ui);
        } else {
            self.database_screen(ui);
        }
    }
}

/// Width of the label column on the unlock card.
const UNLOCK_LABEL_W: f32 = 130.0;

/// A form row on the unlock screen: fixed-width label + field content.
/// (egui 0.37's Grid clamps TextEdit widths to the previous column width,
/// leaving the fields tiny; manual rows honor `desired_width`.)
fn unlock_row(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui, egui::Id)) {
    ui.horizontal(|ui| {
        let label_resp = ui.add_sized(
            [UNLOCK_LABEL_W, ui.spacing().interact_size.y],
            egui::Label::new(
                egui::RichText::new(label)
                    .size(13.5)
                    .color(crate::theme::p().muted),
            ),
        );
        add(ui, label_resp.id);
    });
}

/// The toolbar Save button. With unsaved changes it is tinted with the
/// accent colour and carries a dot; without, it is disabled. Its accessible
/// name is "Save database" (the entry editor has its own "Save").
fn save_button(ui: &mut egui::Ui, dirty: bool) -> egui::Response {
    let pal = crate::theme::p();
    let text = if dirty {
        egui::RichText::new("     Save").color(pal.accent).strong()
    } else {
        egui::RichText::new("Save")
    };
    let mut button = egui::Button::new(text);
    if dirty {
        button = button
            .fill(pal.accent_soft)
            .stroke(egui::Stroke::new(1.0, pal.list_selected_stroke));
    }
    let resp = ui.add_enabled(dirty, button);
    if dirty {
        let dot = egui::pos2(resp.rect.left() + 14.0, resp.rect.center().y);
        ui.painter().circle_filled(dot, 3.5, pal.accent);
    }
    resp.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, dirty, "Save database")
    });
    if dirty {
        resp.on_hover_text("Unsaved changes \u{2014} save the database (Cmd/Ctrl+S)")
    } else {
        resp.on_disabled_hover_text("No unsaved changes")
    }
}

/// One recent-database row on the unlock screen: file name over the muted
/// full path, the whole row clickable. Missing files are shown dimmed and
/// cannot be picked.
fn recent_database_row(ui: &mut egui::Ui, path: &str, selected: bool) -> bool {
    let pal = crate::theme::p();
    let p = std::path::Path::new(path);
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_owned());
    let exists = p.exists();
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 46.0),
        egui::Sense::hover(),
    );
    let hovered = exists && ui.rect_contains_pointer(rect);
    let fill = if selected {
        pal.list_selected
    } else if hovered {
        pal.list_hover
    } else {
        egui::Color32::TRANSPARENT
    };
    if fill != egui::Color32::TRANSPARENT {
        ui.painter().rect_filled(rect, egui::CornerRadius::same(8), fill);
    }
    let mut content = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect.shrink2(egui::vec2(12.0, 5.0)))
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    content.spacing_mut().item_spacing.y = 1.0;
    let name_color = if exists { pal.text } else { pal.muted };
    content.add(
        egui::Label::new(egui::RichText::new(&name).size(14.0).strong().color(name_color))
            .truncate(),
    );
    let sub = if exists {
        path.to_owned()
    } else {
        format!("Missing \u{2014} {path}")
    };
    content.add(
        egui::Label::new(egui::RichText::new(sub).size(11.5).color(pal.muted)).truncate(),
    );
    let resp = ui.interact(
        rect,
        ui.scope_id().with(("recent-db", path)),
        if exists { egui::Sense::click() } else { egui::Sense::hover() },
    );
    let resp = if exists {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        resp.on_hover_text("This file no longer exists")
    };
    exists && resp.clicked()
}

impl App {
    /// The unlock / welcome screen.
    fn unlock_screen(&mut self, root: &mut Ui) {
        let ctx = root.ctx().clone();
        let pal = crate::theme::p();
        egui::CentralPanel::default().show(root, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("unlock-scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(44.0);
                // Brand mark: the same squircle as the app/window icon.
                if let Some(icon) =
                    self.icon_cache
                        .texture(&ctx, "brand-icon", crate::brand::ICON_PNG)
                {
                    ui.add(
                        egui::Image::from_texture(&icon)
                            .fit_to_exact_size(egui::vec2(64.0, 64.0)),
                    );
                }
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new(crate::brand::NAME)
                        .size(28.0)
                        .strong()
                        .color(pal.text),
                );
                ui.label(
                    egui::RichText::new(crate::brand::TAGLINE)
                        .size(13.0)
                        .color(pal.muted),
                );
                ui.add_space(22.0);
            });

            // Key file / challenge-response stay out of the way unless used.
            if !self.key_file.trim().is_empty() || !self.challenge_response.trim().is_empty() {
                self.unlock_more_options = true;
            }

            let mut chosen: Option<String> = None;
            let mut clear_recent = false;
            ui.vertical_centered(|ui| {
                let card_w = (ui.available_width() - 32.0).clamp(420.0, 620.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(card_w, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                egui::Frame::new()
                    .fill(pal.panel)
                    .corner_radius(16)
                    .inner_margin(egui::Margin::symmetric(24, 22))
                    .stroke(egui::Stroke::new(1.0, pal.border))
                    .show(ui, |ui| {
                        let inner_w = (card_w - 48.0).max(360.0);
                        ui.set_width(inner_w);
                        let field_w = (inner_w - UNLOCK_LABEL_W - 92.0).max(180.0);
            // Manual rows (egui 0.37 Grid clamps TextEdit widths to the tiny
            // previous column width; see `form_row` in dialogs.rs).
            unlock_row(ui, "Database file:", |ui, id| {
                let path_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.db_path)
                        .hint_text("/path/to/database.kdbx")
                        .desired_width(field_w),
                );
                path_resp.labelled_by(id);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("KeePass database", &["kdbx", "kdb"])
                        .pick_file()
                    {
                        self.db_path = p.display().to_string();
                        self.focus_password = true;
                    }
                }
            });

            let mut unlock_on_enter = false;
            let mut password_changed = false;
            unlock_row(ui, "Password:", |ui, id| {
                let output = egui::TextEdit::singleline(&mut self.password)
                    .password(true)
                    .hint_text("password")
                    .desired_width(field_w)
                    .show(ui);
                let pw_resp: egui::Response = output.response.response.clone();
                // Autofocus when a database is already chosen (startup with a
                // remembered database, after locking, after a failed unlock),
                // with the old text selected so typing replaces it.
                if self.focus_password {
                    self.focus_password = false;
                    if !self.db_path.trim().is_empty() {
                        pw_resp.request_focus();
                        let mut state = output.state;
                        state.cursor.set_char_range(Some(
                            egui::text::CCursorRange::select_all_str(&self.password),
                        ));
                        state.store(ui.ctx(), pw_resp.id);
                    }
                }
                // Enter in the password field unlocks.
                unlock_on_enter =
                    pw_resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                password_changed = pw_resp.changed();
                pw_resp.labelled_by(id);
            });
            if password_changed {
                // Typing again dismisses the previous error.
                self.unlock_error.clear();
                self.unlock_error_detail.clear();
            }
            // The error sits right under the field it is about.
            if !self.unlock_error.is_empty() {
                ui.horizontal(|ui| {
                    ui.add_space(UNLOCK_LABEL_W + ui.spacing().item_spacing.x);
                    let resp = ui.label(
                        egui::RichText::new(&self.unlock_error)
                            .size(13.0)
                            .color(pal.danger),
                    );
                    if !self.unlock_error_detail.is_empty() {
                        resp.on_hover_text(&self.unlock_error_detail);
                    }
                });
            }
            if unlock_on_enter {
                self.try_unlock();
            }

            ui.add_space(4.0);
            let mut more = self.unlock_more_options;
            crate::theme::disclosure(ui, "unlock-more", "More options", &mut more);
            self.unlock_more_options = more;
            if more {
                unlock_row(ui, "Key file:", |ui, id| {
                    let kf_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.key_file)
                            .hint_text("/path/to/keyfile.keyx (optional)")
                            .desired_width(field_w),
                    );
                    kf_resp.labelled_by(id);
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("Key file", &["keyx", "key"])
                            .pick_file()
                        {
                            self.key_file = p.display().to_string();
                        }
                    }
                });

                unlock_row(ui, "Challenge-response:", |ui, id| {
                    let cr_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.challenge_response)
                            .hint_text("HMAC-SHA1 secret in hex (optional)")
                            .desired_width(field_w),
                    );
                    cr_resp
                        .on_hover_text(
                            "The YubiKey-equivalent HMAC-SHA1 secret, as hex. Leave empty \
                             unless the database was protected with challenge-response.",
                        )
                        .labelled_by(id);
                });
            }

            ui.add_space(8.0);
            let mut remember = self.remember_unlock;
            if ui
                .checkbox(
                    &mut remember,
                    "Remember unlock key and auto-unlock at startup",
                )
                .on_hover_text(
                    "The password/key file/challenge-response secret is stored in the operating \
                     system's keychain (macOS Keychain, Windows Credential Manager or the Linux \
                     Secret Service). Anyone who can use your logged-in account can then open \
                     the database.",
                )
                .changed()
            {
                self.remember_unlock = remember;
            }
            if self.auto_unlock {
                ui.label(
                    egui::RichText::new("An auto-unlock key is saved for this database.")
                        .weak(),
                );
            }

            ui.add_space(16.0);
            if ui
                .add_sized(
                    [ui.available_width(), 36.0],
                    crate::theme::primary_button("Unlock"),
                )
                .clicked()
            {
                self.try_unlock();
            }
            ui.add_space(6.0);
            if ui
                .add_sized(
                    [ui.available_width(), 28.0],
                    egui::Button::new(
                        egui::RichText::new("Create new database…")
                            .size(13.0)
                            .color(pal.muted),
                    )
                    .frame(false),
                )
                .clicked()
            {
                self.dialog = Dialog::NewDb(Box::new(dialogs::NewDb::default()));
            }
                    });

                // Recently opened databases (persisted between launches).
                if !self.prefs.recent.is_empty() {
                    ui.add_space(18.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Recent databases")
                                .size(12.0)
                                .strong()
                                .color(pal.muted),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(crate::theme::subtle_button("Clear recent list")).clicked() {
                                clear_recent = true;
                            }
                        });
                    });
                    ui.add_space(2.0);
                    egui::Frame::new()
                        .fill(pal.panel)
                        .corner_radius(12)
                        .inner_margin(egui::Margin::same(6))
                        .stroke(egui::Stroke::new(1.0, pal.border))
                        .show(ui, |ui| {
                            ui.set_width(card_w - 14.0);
                            ui.spacing_mut().item_spacing.y = 2.0;
                            for path in self.prefs.recent.clone() {
                                let selected = path == self.db_path;
                                if recent_database_row(ui, &path, selected) {
                                    chosen = Some(path.clone());
                                }
                            }
                        });
                }
                    },
                );
            });
            if let Some(path) = chosen {
                self.db_path = path;
                self.password.clear();
                self.unlock_error.clear();
                self.unlock_error_detail.clear();
                self.focus_password = true;
            }
            if clear_recent {
                self.prefs.recent.clear();
                self.prefs.last_db = None;
                self.save_preferences();
            }
                });
            dialogs::show(self, &ctx);
        });
    }

    /// The search field (shared by the wide one-row and the narrow two-row
    /// toolbar). It has no visible caption; the magnifier icon carries the
    /// accessible name "Search" and labels the field.
    fn search_field(&mut self, ui: &mut Ui, width: f32) {
        let pal = crate::theme::p();
        let (icon_rect, icon_resp) =
            ui.allocate_exact_size(egui::vec2(15.0, 15.0), egui::Sense::hover());
        let c = icon_rect.center() + egui::vec2(-1.0, -1.0);
        ui.painter().circle_stroke(c, 4.3, egui::Stroke::new(1.5, pal.muted));
        ui.painter().line_segment(
            [c + egui::vec2(3.1, 3.1), c + egui::vec2(6.2, 6.2)],
            egui::Stroke::new(1.6, pal.muted),
        );
        icon_resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, "Search"));
        let search_resp = ui.add(
            egui::TextEdit::singleline(&mut self.search)
                .hint_text("Search all entries (Cmd/Ctrl+F)")
                .desired_width(width),
        );
        if self.focus_search {
            search_resp.request_focus();
            self.focus_search = false;
        }
        search_resp.labelled_by(icon_resp.id);
        if !self.search.is_empty() && ui.add(crate::theme::subtle_button("Clear")).clicked() {
            self.search.clear();
        }
    }

    /// The entry editor (new or existing entry) with its pinned header:
    /// returns after applying or cancelling, which clears `inline_edit`.
    fn inline_editor(&mut self, ui: &mut Ui, max_width: f32) {
        let Some(mut d) = self.inline_edit.take() else { return };
        let (mut apply, mut cancel) = dialogs::entry_edit_inline_header(ui, d.entry_id.is_none());
        apply |= ui.ctx().input_mut(|i| {
            i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter)
        });
        cancel |= ui.ctx().input_mut(|i| {
            i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)
        });
        if apply {
            d.apply(self);
            self.inline_edit = None;
        } else if cancel {
            self.inline_edit = None;
            self.status = "Cancelled".into();
        } else {
            egui::ScrollArea::vertical()
                .id_salt("inline-edit-scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_max_width((max_width - 14.0).max(220.0));
                    dialogs::entry_edit_body(ui, self, &mut d);
                });
            self.inline_edit = Some(d);
        }
    }

    /// The main database screen: toolbar, group tree, entry list, details.
    fn database_screen(&mut self, root: &mut Ui) {
        let ctx = root.ctx().clone();
        let pal = crate::theme::p();

        // Global keyboard shortcuts (skipped while dialogs or text fields
        // have focus).
        self.handle_shortcuts(&ctx);
        if self.db.is_none() {
            return; // e.g. Cmd+L locked the database this frame
        }

        // Full window width, read before any panel takes space: the one input
        // for every responsive decision below (toolbar wrapping, sidebar,
        // list/details stacking).
        let window_w = root.available_width();

        // Toolbar ---------------------------------------------------------
        egui::Panel::top("toolbar")
            .resizable(false)
            .default_size(60.0)
            .show_separator_line(false)
            .frame(
                egui::Frame::new()
                    .fill(pal.panel)
                    .inner_margin(egui::Margin::symmetric(18, 10))
                    .stroke(egui::Stroke::new(1.0, pal.border)),
            )
            .show(root, |ui| {
                // The toolbar has two arrangements: everything on one row when
                // there is room, and a search row of its own when the window is
                // narrow (otherwise the fixed-width search box was drawn over
                // the action buttons).
                let narrow = ui.available_width() < 860.0;

                ui.horizontal(|ui| {
                    let sidebar_visible = self.sidebar_visible(window_w);
                    let resp = crate::theme::icon_button(
                        ui,
                        "sidebar-toggle",
                        if sidebar_visible {
                            "Hide the library sidebar"
                        } else {
                            "Show the library sidebar"
                        },
                        sidebar_visible,
                        crate::theme::draw_sidebar_icon,
                    );
                    if resp.clicked() {
                        self.sidebar_override = Some(!sidebar_visible);
                    }
                    ui.add_space(6.0);
                    // The app name only: the database name lives in the
                    // sidebar header.
                    ui.label(
                        egui::RichText::new(crate::brand::NAME)
                            .size(16.0)
                            .strong()
                            .color(pal.text),
                    );
                    ui.add_space(16.0);
                    let can_back = !self.nav_back.is_empty();
                    let can_forward = !self.nav_forward.is_empty();
                    if crate::theme::nav_arrow_button(ui, true, can_back).clicked() && can_back {
                        self.navigate_back();
                    }
                    if crate::theme::nav_arrow_button(ui, false, can_forward).clicked()
                        && can_forward
                    {
                        self.navigate_forward();
                    }
                    if !narrow {
                        ui.add_space(6.0);
                        self.search_field(ui, 260.0);
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        self.toolbar_actions(ui);
                    });
                });

                // Second row on narrow windows: the search field gets the
                // full width so it never collides with the actions.
                if narrow {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let width = (ui.available_width() - 40.0).max(120.0);
                        self.search_field(ui, width);
                    });
                }

                // Batch operations on the multi-selection get their own row
                // so the toolbar never overflows.
                let n = self.selected_entries.len();
                if n >= 2 {
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.label(format!("{n} entries selected:"));
                        if ui.button(format!("Move {n} to group…")).clicked() {
                            let ids: Vec<EntryId> = self.selected_entries.iter().copied().collect();
                            let groups = self.group_snapshot();
                            self.dialog = Dialog::BatchMove(Box::new(dialogs::BatchMove {
                                entries: ids,
                                groups,
                                target: None,
                            }));
                        }
                        if ui.button(format!("Recycle {n} entries…")).clicked() {
                            let ids: Vec<EntryId> = self.selected_entries.iter().copied().collect();
                            self.recycle_entries(ids);
                        }
                    });
                }
            });

        // Status bar ------------------------------------------------------
        // Left: the last status message. Right: how many entries the list
        // shows and whether there are unsaved changes, so the strip always
        // says something useful.
        let visible_count = browser::visible_entry_count(self);
        egui::Panel::bottom("statusbar")
            .resizable(false)
            .exact_size(30.0)
            .frame(
                egui::Frame::new()
                    .fill(pal.sidebar)
                    .inner_margin(egui::Margin::symmetric(14, 5))
                    .stroke(egui::Stroke::new(1.0, pal.border)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    let right_w = 260.0;
                    let left_w = (ui.available_width() - right_w).max(60.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(left_w, ui.available_height()),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&self.status)
                                        .size(12.0)
                                        .color(pal.muted),
                                )
                                .truncate(),
                            );
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.dirty {
                            ui.label(
                                egui::RichText::new("Unsaved changes")
                                    .size(12.0)
                                    .strong()
                                    .color(pal.warn_fg),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new("All changes saved")
                                    .size(12.0)
                                    .color(pal.muted),
                            );
                        }
                        ui.label(egui::RichText::new("·").size(12.0).color(pal.muted));
                        ui.label(
                            egui::RichText::new(browser::pluralize(visible_count, "entry", "entries"))
                                .size(12.0)
                                .color(pal.muted),
                        );
                    });
                });
            });

        // Responsive layout ------------------------------------------------
        // Three columns need roughly 1000 px. Below that the sidebar is
        // dropped, and below ~820 px the list and the details are stacked in
        // one column instead of being squeezed side by side (which used to
        // clip the details pane entirely).
        let show_sidebar = self.sidebar_visible(window_w);
        let stacked = !self.prefs.list_view || window_w < 820.0;

        // Sidebar: groups ---------------------------------------------------
        if show_sidebar {
            egui::Panel::left("sidebar")
                .resizable(true)
                .default_size(225.0)
                .size_range(170.0..=320.0)
                .frame(
                    egui::Frame::new()
                        .fill(pal.sidebar)
                        .inner_margin(egui::Margin::symmetric(14, 14))
                        .stroke(egui::Stroke::new(1.0, pal.border)),
                )
                .show(root, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("groups-scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            browser::group_tree(ui, self);
                        });
                });
        }

        // Middle column and details --------------------------------------
        if !stacked {
            egui::Panel::left("entry-list")
                .resizable(true)
                .default_size(340.0)
                .size_range(240.0..=520.0)
                .frame(
                    egui::Frame::new()
                        .fill(pal.panel)
                        .inner_margin(egui::Margin::symmetric(16, 12))
                        .stroke(egui::Stroke::new(1.0, pal.border)),
                )
                .show(root, |ui| {
                    browser::entry_view(ui, self);
                });

            egui::CentralPanel::default()
                .frame(
                    egui::Frame::new()
                        .fill(pal.panel)
                        .inner_margin(egui::Margin::symmetric(24, 18)),
                )
                .show(root, |ui| {
                    let width = ui.available_width().min(820.0);
                    if self.inline_edit.is_some() {
                        self.inline_editor(ui, width);
                    } else {
                        egui::ScrollArea::vertical()
                            .id_salt("details-scroll")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.set_max_width((width - 14.0).max(220.0));
                                browser::entry_details(ui, self, self.selected_entry);
                            });
                    }
                });
        } else {
            // The table needs the whole width (six configurable columns).
            // Details (or the entry editor) then sit under the table, still
            // inside the central column, with the table clipped above them.
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::new()
                        .fill(pal.panel)
                        .inner_margin(egui::Margin::symmetric(16, 12)),
                )
                .show(root, |ui| {
                    let editing = self.inline_edit.is_some();
                    if editing || self.selected_entry.is_some() {
                        let selected = self.selected_entry;
                        egui::Panel::bottom("details-table")
                            .resizable(true)
                            .default_size(if editing { 420.0 } else { 300.0 })
                            .show_inside(ui, |ui| {
                                // Cap the reading width but never exceed the
                                // pane: a hard 900 px used to overflow (and get
                                // clipped) in narrow windows.
                                let pane_w = (ui.available_width() - 16.0).max(240.0);
                                if editing {
                                    ui.add_space(8.0);
                                    self.inline_editor(ui, pane_w.min(900.0));
                                } else {
                                    egui::ScrollArea::vertical()
                                        .id_salt("details-table-scroll")
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            ui.set_max_width(pane_w.min(900.0));
                                            ui.set_width(pane_w.min(900.0));
                                            browser::entry_details(ui, self, selected);
                                        });
                                }
                            });
                    }
                    browser::entry_view(ui, self);
                });
        }

        dialogs::show(self, &ctx);

        // Track entry-to-entry moves for the back/forward arrows.
        self.record_navigation();

        // Transient copy-confirmation toasts (bottom-right overlay).
        self.render_toasts(&ctx);
        // Automatic browser approvals are announced without blocking.
        self.render_browser_notice(&ctx);
    }
}
