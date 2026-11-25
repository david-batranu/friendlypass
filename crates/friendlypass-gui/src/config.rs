//! Persisted GUI preferences: entry-table column layout and the list of
//! recently opened databases.
//!
//! Stored as JSON in the platform configuration directory, e.g.
//! `~/Library/Application Support/friendlypass-gui/config.json` on macOS,
//! `%APPDATA%\friendlypass-gui\config.json` on Windows and
//! `$XDG_CONFIG_HOME/friendlypass-gui/config.json` on Linux. Set
//! `FRIENDLYPASS_GUI_CONFIG` to override the location (portable use and tests).
//!
//! The file contains no secrets — only display settings and database paths.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Identifier of an entry-table column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ColumnId {
    Title,
    UserName,
    Password,
    Url,
    Notes,
    Tags,
}

impl ColumnId {
    /// All columns in their default order.
    pub const ALL: [ColumnId; 6] = [
        ColumnId::Title,
        ColumnId::UserName,
        ColumnId::Password,
        ColumnId::Url,
        ColumnId::Notes,
        ColumnId::Tags,
    ];

    /// The column heading (matches KeePassXC's naming).
    pub fn label(self) -> &'static str {
        match self {
            ColumnId::Title => "Title",
            ColumnId::UserName => "Username",
            ColumnId::Password => "Password",
            ColumnId::Url => "URL",
            ColumnId::Notes => "Notes",
            ColumnId::Tags => "Tags",
        }
    }

    /// Default width in points.
    pub fn default_width(self) -> f32 {
        match self {
            ColumnId::Title => 180.0,
            ColumnId::UserName => 150.0,
            ColumnId::Password => 130.0,
            ColumnId::Url => 180.0,
            ColumnId::Notes => 180.0,
            ColumnId::Tags => 100.0,
        }
    }
}

/// One column's saved settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ColumnConfig {
    pub id: ColumnId,
    pub visible: bool,
    /// Initial width; the user can still drag column borders at runtime.
    pub width: f32,
}

impl ColumnConfig {
    fn new(id: ColumnId) -> Self {
        ColumnConfig {
            id,
            visible: true,
            width: id.default_width(),
        }
    }
}

/// How many recently opened databases are remembered.
pub const MAX_RECENT: usize = 10;

/// All persisted GUI settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    /// Columns in display order.
    pub columns: Vec<ColumnConfig>,
    /// Recently opened databases, most recent first.
    pub recent: Vec<String>,
    /// Last successfully opened database (used to prefill the unlock form).
    pub last_db: Option<String>,
    /// Entry list style: true = 1Password-style cards, false = the
    /// configurable-column table.
    pub list_view: bool,
    /// Windows only: store the auto-unlock secret in a DPAPI-protected file
    /// instead of Credential Manager (for accounts without a login password).
    pub windows_dpapi_fallback: bool,
    /// Light, dark, or follow the operating system.
    pub theme: crate::theme::ThemeChoice,
    /// Clear the clipboard a while after copying a value into it (only if it
    /// still holds what we put there).
    pub clipboard_clear: bool,
    /// Seconds before a copied value is cleared from the clipboard.
    pub clipboard_clear_secs: u32,
    /// Lock the database after a period without user input.
    pub auto_lock: bool,
    /// Minutes of inactivity before the database locks.
    pub auto_lock_minutes: u32,
    /// Register the native-messaging host with the browsers below.
    pub browser_integration: bool,
    /// Always show the approval dialog for a new browser association, even
    /// when the peer/host/browser trust chain verified (§5). Off by default.
    pub require_approval_for_new_browsers: bool,
    /// Per-browser native-messaging manifests (Chrome-family + Firefox).
    pub browser_chrome: bool,
    pub browser_chromium: bool,
    pub browser_brave: bool,
    pub browser_edge: bool,
    pub browser_firefox: bool,
}

/// Default seconds before a copied value is cleared from the clipboard.
pub const DEFAULT_CLIPBOARD_CLEAR_SECS: u32 = 30;
/// Default idle minutes before auto-lock (when the user turns it on).
pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 10;
/// The idle timeouts offered in Settings, in minutes.
pub const AUTO_LOCK_CHOICES: [u32; 7] = [1, 2, 5, 10, 15, 30, 60];

impl Default for Preferences {
    fn default() -> Self {
        Preferences {
            columns: ColumnId::ALL.iter().map(|&id| ColumnConfig::new(id)).collect(),
            recent: Vec::new(),
            last_db: None,
            list_view: true,
            windows_dpapi_fallback: false,
            theme: crate::theme::ThemeChoice::System,
            clipboard_clear: true,
            clipboard_clear_secs: DEFAULT_CLIPBOARD_CLEAR_SECS,
            auto_lock: false,
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            // Off by default, like KeePassXC: nothing is written into the
            // browser configuration until the user opts in.
            browser_integration: false,
            require_approval_for_new_browsers: false,
            browser_chrome: true,
            browser_chromium: true,
            browser_brave: true,
            browser_edge: true,
            browser_firefox: true,
        }
    }
}

impl Preferences {
    /// Fix up a loaded configuration: append columns added in newer
    /// versions, drop duplicates/invalid widths, clamp the recent list and
    /// guarantee at least one visible column.
    pub fn normalize(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.columns.retain(|c| {
            seen.insert(c.id) && c.width.is_finite() && c.width >= 40.0
        });
        if !self.columns.iter().any(|c| c.visible) {
            if let Some(first) = self.columns.first_mut() {
                first.visible = true;
            }
        }
        for id in ColumnId::ALL {
            if !seen.contains(&id) {
                self.columns.push(ColumnConfig::new(id));
            }
        }
        self.recent.truncate(MAX_RECENT);
        self.clipboard_clear_secs = self.clipboard_clear_secs.clamp(5, 600);
        self.auto_lock_minutes = self.auto_lock_minutes.clamp(1, 24 * 60);
    }

    /// Canonical display path (resolves symlinks when possible).
    fn canonical(path: &str) -> String {
        std::fs::canonicalize(path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.to_string())
    }

    /// Record a successfully opened database at the top of the recent list.
    pub fn record_recent(&mut self, path: &str) {
        let path = Self::canonical(path);
        self.recent.retain(|p| p != &path);
        self.recent.insert(0, path.clone());
        self.recent.truncate(MAX_RECENT);
        self.last_db = Some(path);
    }

    /// Load preferences from `path`; missing or malformed files yield the
    /// defaults (the GUI must always start).
    pub fn load(path: &Path) -> Preferences {
        let mut prefs = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<Preferences>(&text).ok())
            .unwrap_or_default();
        prefs.normalize();
        prefs
    }

    /// Save preferences atomically (write a temp file, then rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)
    }

    /// Visible columns in display order.
    pub fn visible_columns(&self) -> impl Iterator<Item = &ColumnConfig> {
        self.columns.iter().filter(|c| c.visible)
    }

    /// Toggle a column; the last visible column cannot be hidden.
    pub fn set_visible(&mut self, id: ColumnId, visible: bool) -> bool {
        if !visible && self.columns.iter().filter(|c| c.visible).count() <= 1 {
            return false;
        }
        if let Some(c) = self.columns.iter_mut().find(|c| c.id == id) {
            c.visible = visible;
        }
        true
    }

    /// Whether the native-messaging manifest for `browser` is selected.
    pub fn browser_enabled(&self, browser: friendlypass_browser::native_messaging::Browser) -> bool {
        use friendlypass_browser::native_messaging::Browser;
        match browser {
            Browser::Chrome => self.browser_chrome,
            Browser::Chromium => self.browser_chromium,
            Browser::Brave => self.browser_brave,
            Browser::Edge => self.browser_edge,
            Browser::Firefox => self.browser_firefox,
        }
    }

    /// Select or deselect the native-messaging manifest for `browser`.
    pub fn set_browser_enabled(
        &mut self,
        browser: friendlypass_browser::native_messaging::Browser,
        enabled: bool,
    ) {
        use friendlypass_browser::native_messaging::Browser;
        match browser {
            Browser::Chrome => self.browser_chrome = enabled,
            Browser::Chromium => self.browser_chromium = enabled,
            Browser::Brave => self.browser_brave = enabled,
            Browser::Edge => self.browser_edge = enabled,
            Browser::Firefox => self.browser_firefox = enabled,
        }
    }

    /// The browsers selected for native-messaging registration.
    pub fn selected_browsers(&self) -> Vec<friendlypass_browser::native_messaging::Browser> {
        use friendlypass_browser::native_messaging::Browser;
        Browser::ALL
            .into_iter()
            .filter(|&browser| self.browser_enabled(browser))
            .collect()
    }
}

/// Platform configuration file location, or `None` when no home directory
/// is known (preferences are then kept in memory only).
pub fn config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("FRIENDLYPASS_GUI_CONFIG") {
        return Some(PathBuf::from(p));
    }
    let dir = if cfg!(target_os = "macos") {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    dir.map(|d| d.join("friendlypass-gui").join("config.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_all_columns_visible_in_order() {
        let prefs = Preferences::default();
        let ids: Vec<_> = prefs.columns.iter().map(|c| c.id).collect();
        assert_eq!(ids, ColumnId::ALL);
        assert!(prefs.columns.iter().all(|c| c.visible));
        assert!(prefs.columns.iter().all(|c| c.width >= 40.0));
        assert!(prefs.recent.is_empty());
        assert_eq!(prefs.last_db, None);
    }

    #[test]
    fn roundtrips_columns_and_recent_databases() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("nested").join("config.json");
        let db = dir.path().join("vault.kdbx");
        std::fs::write(&db, b"x").unwrap();

        let mut prefs = Preferences::default();
        prefs.set_visible(ColumnId::Url, false);
        prefs.columns.swap(0, 2); // Password, UserName, Title, ...
        prefs.columns[0].width = 321.0;
        prefs.record_recent(db.to_str().unwrap());
        prefs.save(&file).unwrap();

        let loaded = Preferences::load(&file);
        assert_eq!(loaded, prefs);
        assert_eq!(loaded.visible_columns().count(), 5);
        assert!(loaded.visible_columns().all(|c| c.id != ColumnId::Url));
        assert_eq!(loaded.columns[0].id, ColumnId::Password);
        assert_eq!(loaded.columns[0].width, 321.0);
        assert_eq!(loaded.recent.len(), 1);
        assert_eq!(loaded.last_db.as_deref(), Some(loaded.recent[0].as_str()));
    }

    #[test]
    fn recent_list_dedupes_and_caps() {
        let mut prefs = Preferences::default();
        for i in 0..(MAX_RECENT + 3) {
            prefs.record_recent(&format!("/tmp/does-not-exist-{i}.kdbx"));
        }
        assert_eq!(prefs.recent.len(), MAX_RECENT);
        assert_eq!(
            prefs.recent[0],
            format!("/tmp/does-not-exist-{}.kdbx", MAX_RECENT + 2)
        );
        // Re-opening an older database moves it to the front.
        let older = prefs.recent[5].clone();
        prefs.record_recent(&older);
        assert_eq!(prefs.recent[0], older);
        assert_eq!(prefs.recent.len(), MAX_RECENT);
        assert_eq!(prefs.last_db.as_deref(), Some(older.as_str()));
    }

    #[test]
    fn malformed_or_partial_files_fall_back_safely() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.json");
        std::fs::write(&file, b"{ not json").unwrap();
        assert_eq!(Preferences::load(&file), Preferences::default());

        // A config from an older version that only knows two columns.
        std::fs::write(
            &file,
            br#"{"columns":[{"id":"Title","visible":false,"width":250.0},{"id":"UserName","visible":true,"width":100.0}],"recent":["/a.kdbx"]}"#,
        )
        .unwrap();
        let loaded = Preferences::load(&file);
        assert_eq!(loaded.columns.len(), ColumnId::ALL.len());
        // Newer columns are appended with their defaults.
        assert!(loaded.columns.iter().any(|c| c.id == ColumnId::Tags && c.visible));
        // The file's own visibility choice is kept.
        let username = loaded
            .columns
            .iter()
            .find(|c| c.id == ColumnId::UserName)
            .unwrap();
        assert!(username.visible);

        // A complete config with every column hidden keeps the first one.
        let all_hidden: Vec<_> = ColumnId::ALL
            .iter()
            .map(|&id| format!(r#"{{"id":"{id:?}","visible":false,"width":100.0}}"#))
            .collect();
        std::fs::write(
            &file,
            format!(r#"{{"columns":[{}],"recent":[]}}"#, all_hidden.join(",")),
        )
        .unwrap();
        let loaded = Preferences::load(&file);
        assert_eq!(loaded.visible_columns().count(), 1);
        assert_eq!(loaded.visible_columns().next().unwrap().id, ColumnId::Title);
    }

    #[test]
    fn security_and_theme_preferences_default_and_roundtrip() {
        let prefs = Preferences::default();
        assert!(prefs.clipboard_clear, "clipboard auto-clear is on by default");
        assert_eq!(prefs.clipboard_clear_secs, 30);
        assert!(!prefs.auto_lock, "idle auto-lock is off by default");
        assert_eq!(prefs.theme, crate::theme::ThemeChoice::System);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.json");
        let mut prefs = Preferences::default();
        prefs.clipboard_clear = false;
        prefs.clipboard_clear_secs = 45;
        prefs.auto_lock = true;
        prefs.auto_lock_minutes = 5;
        prefs.theme = crate::theme::ThemeChoice::Dark;
        prefs.save(&file).unwrap();
        assert_eq!(Preferences::load(&file), prefs);

        // Files written before these settings existed get the defaults.
        std::fs::write(&file, br#"{"recent":[]}"#).unwrap();
        let old = Preferences::load(&file);
        assert!(old.clipboard_clear && old.clipboard_clear_secs == 30 && !old.auto_lock);
    }

    #[test]
    fn last_visible_column_cannot_be_hidden() {
        let mut prefs = Preferences::default();
        for id in ColumnId::ALL.into_iter().skip(1) {
            assert!(prefs.set_visible(id, false));
        }
        assert!(!prefs.set_visible(ColumnId::Title, false));
        assert_eq!(prefs.visible_columns().count(), 1);
    }

    #[test]
    fn browser_integration_defaults_off_with_every_browser_selected() {
        use friendlypass_browser::native_messaging::Browser;
        let prefs = Preferences::default();
        assert!(!prefs.browser_integration, "nothing is written until the user opts in");
        assert_eq!(prefs.selected_browsers(), Browser::ALL.to_vec());

        let mut prefs = Preferences::default();
        prefs.set_browser_enabled(Browser::Brave, false);
        assert!(!prefs.browser_enabled(Browser::Brave));
        assert_eq!(
            prefs.selected_browsers(),
            vec![Browser::Chrome, Browser::Chromium, Browser::Edge, Browser::Firefox]
        );
    }

    #[test]
    fn browser_integration_roundtrips_and_old_configs_get_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.json");
        let mut prefs = Preferences::default();
        prefs.browser_integration = true;
        prefs.browser_chrome = false;
        prefs.browser_firefox = false;
        prefs.save(&file).unwrap();
        assert_eq!(Preferences::load(&file), prefs);

        std::fs::write(&file, br#"{"recent":[]}"#).unwrap();
        let old = Preferences::load(&file);
        assert!(!old.browser_integration);
        assert!(old.browser_chrome && old.browser_firefox);
    }

    #[test]
    fn config_path_honors_the_environment_override() {
        // SAFETY: single-threaded test process for this variable.
        let key = "FRIENDLYPASS_GUI_CONFIG";
        let old = std::env::var_os(key);
        // Tests in one binary may run in parallel; only assert the override
        // when we are the only writer.
        if old.is_none() {
            unsafe { std::env::set_var(key, "/tmp/friendlypass-gui-test/config.json") };
            assert_eq!(
                config_path(),
                Some(PathBuf::from("/tmp/friendlypass-gui-test/config.json"))
            );
            unsafe { std::env::remove_var(key) };
        }
    }
}
