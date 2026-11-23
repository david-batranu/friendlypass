//! Persisted GUI preferences: entry-table column layout and the list of
//! recently opened databases.
//!
//! Stored as JSON in the platform configuration directory, e.g.
//! `~/Library/Application Support/kpxc-gui/config.json` on macOS,
//! `%APPDATA%\kpxc-gui\config.json` on Windows and
//! `$XDG_CONFIG_HOME/kpxc-gui/config.json` on Linux. Set
//! `KPXC_GUI_CONFIG` to override the location (portable use and tests).
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
            ColumnId::UserName => "UserName",
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
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences {
            columns: ColumnId::ALL.iter().map(|&id| ColumnConfig::new(id)).collect(),
            recent: Vec::new(),
            last_db: None,
            list_view: true,
            windows_dpapi_fallback: false,
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
}

/// Platform configuration file location, or `None` when no home directory
/// is known (preferences are then kept in memory only).
pub fn config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KPXC_GUI_CONFIG") {
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
    dir.map(|d| d.join("kpxc-gui").join("config.json"))
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
    fn last_visible_column_cannot_be_hidden() {
        let mut prefs = Preferences::default();
        for id in ColumnId::ALL.into_iter().skip(1) {
            assert!(prefs.set_visible(id, false));
        }
        assert!(!prefs.set_visible(ColumnId::Title, false));
        assert_eq!(prefs.visible_columns().count(), 1);
    }

    #[test]
    fn config_path_honors_the_environment_override() {
        // SAFETY: single-threaded test process for this variable.
        let key = "KPXC_GUI_CONFIG";
        let old = std::env::var_os(key);
        // Tests in one binary may run in parallel; only assert the override
        // when we are the only writer.
        if old.is_none() {
            unsafe { std::env::set_var(key, "/tmp/kpxc-gui-test/config.json") };
            assert_eq!(
                config_path(),
                Some(PathBuf::from("/tmp/kpxc-gui-test/config.json"))
            );
            unsafe { std::env::remove_var(key) };
        }
    }
}
