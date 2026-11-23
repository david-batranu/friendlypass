//! Application state and domain actions for the BUI front-end.
//!
//! The UI is drawn by BUI (Blender's UI kit); this module owns the database,
//! the unlock form, browsing state, persisted preferences and the edit
//! drafts. It is deliberately independent from any particular rendering
//! pass so the headless tests can drive the same code.

use std::path::{Path, PathBuf};

use keepass::db::{fields, Database, EntryId, EntryRef, GroupId};
use keepass::DatabaseKey;
use kpxc_gui_config::{ColumnId, Preferences};

/// A row in the entry list, with everything already owned so rendering and
/// listeners do not borrow the database.
#[derive(Debug, Clone)]
pub struct EntryRow {
    pub id: EntryId,
    pub group: GroupId,
    pub group_path: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
}

/// One group in the sidebar tree.
#[derive(Debug, Clone)]
pub struct GroupNode {
    pub id: GroupId,
    pub depth: usize,
    pub name: String,
    pub entries: usize,
    pub groups: usize,
}

/// The selected entry's details, rendered into the right-hand panel.
#[derive(Debug, Clone)]
pub struct Details {
    pub id: EntryId,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub attributes: Vec<(String, String, bool)>,
    pub totp: Option<(String, u64)>,
}

/// Draft state of the entry editor.
#[derive(Debug, Clone)]
pub struct EntryDraft {
    pub id: Option<EntryId>,
    pub group: GroupId,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub show_password: bool,
}

impl EntryDraft {
    pub fn new(group: GroupId) -> Self {
        EntryDraft {
            id: None,
            group,
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            tags: String::new(),
            show_password: false,
        }
    }

    pub fn from_entry(db: &Database, id: EntryId) -> Option<Self> {
        let entry = db.entry(id)?;
        Some(EntryDraft {
            id: Some(id),
            group: entry.parent().id(),
            title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
            username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
            password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
            url: entry.get(fields::URL).unwrap_or_default().to_owned(),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
            tags: entry.tags.join(", "),
            show_password: false,
        })
    }

    /// Complete field map for the entry (password protected, like
    /// KeePassXC's editor).
    fn build_fields(&self) -> std::collections::HashMap<String, keepass::db::Value<String>> {
        use keepass::db::Value;
        let mut out = std::collections::HashMap::new();
        out.insert(fields::TITLE.to_owned(), Value::unprotected(self.title.clone()));
        out.insert(fields::USERNAME.to_owned(), Value::unprotected(self.username.clone()));
        out.insert(fields::PASSWORD.to_owned(), Value::protected(self.password.clone()));
        out.insert(fields::URL.to_owned(), Value::unprotected(self.url.clone()));
        out.insert(fields::NOTES.to_owned(), Value::unprotected(self.notes.clone()));
        out
    }

    /// Apply the edit. Existing entries record a history item, exactly like
    /// the egui front-end.
    pub fn apply(&self, db: &mut Database) -> String {
        let new_fields = self.build_fields();
        let tags: Vec<String> = self
            .tags
            .split(',')
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();
        match self.id {
            Some(id) => {
                if let Some(mut entry) = db.entry_mut(id) {
                    entry.track_changes().edit(|e| {
                        e.fields = new_fields;
                        e.tags = tags;
                    });
                }
                format!("Updated entry '{}'", self.title)
            }
            None => {
                if let Some(mut group) = db.group_mut(self.group) {
                    let mut entry = group.add_entry();
                    let id = {
                        let e: &mut keepass::db::Entry = &mut entry;
                        e.fields = new_fields;
                        e.tags = tags;
                        e.id()
                    };
                    format!("Added entry '{}' ({id})", self.title)
                } else {
                    "Cannot add entry: group not found".into()
                }
            }
        }
    }
}

/// Draft state of the new-database dialog.
#[derive(Debug, Clone)]
pub struct NewDbDraft {
    pub path: String,
    pub name: String,
    pub password: String,
    pub password_repeat: String,
    pub error: String,
}

impl Default for NewDbDraft {
    fn default() -> Self {
        NewDbDraft {
            path: "new-database.kdbx".into(),
            name: "New database".into(),
            password: String::new(),
            password_repeat: String::new(),
            error: String::new(),
        }
    }
}

impl NewDbDraft {
    /// Validate the fields; the modal renders `error`.
    pub fn validate(&self) -> Result<(), String> {
        if self.path.trim().is_empty() {
            return Err("Choose a file path".into());
        }
        if self.password != self.password_repeat {
            return Err("Passwords do not match".into());
        }
        if self.password.is_empty() {
            return Err("Set a password".into());
        }
        Ok(())
    }

    /// Create the database and its key (KeePassXC defaults: KDBX 4.1,
    /// AES-256, ChaCha20 inner stream, Argon2id, GZip).
    pub fn create(&self) -> Result<(Database, DatabaseKey), String> {
        use keepass::config::{
            CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig,
        };

        let mut db = Database::new();
        db.config.version = DatabaseVersion::KDB4(1);
        db.config.outer_cipher_config = OuterCipherConfig::AES256;
        db.config.compression_config = CompressionConfig::GZip;
        db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        db.config.kdf_config = KdfConfig::Argon2id {
            iterations: 50,
            memory: 64 * 1024 * 1024,
            parallelism: 4,
            version: argon2::Version::Version13,
        };
        db.meta.database_name = Some(self.name.clone());

        let key = DatabaseKey::new().with_password(&self.password);
        let path = PathBuf::from(self.path.trim());
        kpxc::saveutil::save(&path, &db, key.clone()).map_err(|e| format!("{e:#}"))?;
        Ok((db, key))
    }
}

/// A password-generator draft.
#[derive(Debug, Clone)]
pub struct GeneratorDraft {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub value: String,
}

impl Default for GeneratorDraft {
    fn default() -> Self {
        GeneratorDraft {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            value: String::new(),
        }
    }
}

impl GeneratorDraft {
    pub fn generate(&mut self) {
        self.value = kpxc::commands::generate_password_opts(
            self.length,
            self.uppercase,
            self.lowercase,
            self.digits,
            self.symbols,
        );
    }
}

/// Which modal dialog is open.
#[derive(Debug, Clone)]
pub enum Modal {
    Entry(EntryDraft),
    GroupNew { parent: GroupId, name: String },
    NewDb(NewDbDraft),
    Generator(GeneratorDraft),
    Columns,
    DbInfo,
    ConfirmDeleteEntry(EntryId),
    Message(String),
}

/// The BUI application state.
pub struct BuiApp {
    // persisted preferences
    pub prefs: Preferences,
    pub config_path: Option<PathBuf>,

    // unlock form
    pub db_path: String,
    pub password: String,
    pub key_file: String,
    pub challenge_response: String,
    pub unlock_error: String,

    // open database
    pub db: Option<Database>,
    pub db_key: Option<DatabaseKey>,
    pub dirty: bool,

    // browsing
    pub selected_group: Option<GroupId>,
    pub selected_entry: Option<EntryId>,
    pub search: String,
    pub sort_column: ColumnId,
    pub sort_desc: bool,
    pub show_passwords: bool,
    pub status: String,

    // dialogs
    pub modal: Option<Modal>,
}

impl Default for BuiApp {
    fn default() -> Self {
        BuiApp {
            prefs: Preferences::default(),
            config_path: None,
            db_path: String::new(),
            password: String::new(),
            key_file: String::new(),
            challenge_response: String::new(),
            unlock_error: String::new(),
            db: None,
            db_key: None,
            dirty: false,
            selected_group: None,
            selected_entry: None,
            search: String::new(),
            sort_column: ColumnId::Title,
            sort_desc: false,
            show_passwords: false,
            status: String::new(),
            modal: None,
        }
    }
}

impl BuiApp {
    /// Load persisted preferences and prefill the last database.
    pub fn with_config_path(path: PathBuf) -> Self {
        let mut app = BuiApp::default();
        app.prefs = Preferences::load(&path);
        app.config_path = Some(path);
        if let Some(last) = &app.prefs.last_db {
            app.db_path = last.clone();
        }
        app
    }

    /// Application entry point: uses the platform config path, or an
    /// explicit database path from the command line.
    pub fn new(initial_db: Option<String>) -> Self {
        let mut app = match kpxc_gui_config::config_path() {
            Some(path) => BuiApp::with_config_path(path),
            None => BuiApp::default(),
        };
        if let Some(path) = initial_db {
            app.db_path = path;
        }
        app
    }

    /// Persist preferences (no-op without a config path).
    pub fn save_preferences(&mut self) {
        if let Some(path) = &self.config_path {
            let _ = self.prefs.save(path);
        }
    }

    /// Remember a successfully opened database.
    pub fn record_recent(&mut self, path: &str) {
        self.prefs.record_recent(path);
        self.save_preferences();
    }

    /// Open the database in `self.db_path` with the current form values.
    pub fn try_unlock(&mut self) {
        self.unlock_error.clear();
        let path = self.db_path.trim().to_owned();
        if path.is_empty() {
            self.unlock_error = "Select a database file first.".into();
            return;
        }
        if self.password.is_empty()
            && self.key_file.trim().is_empty()
            && self.challenge_response.trim().is_empty()
        {
            self.unlock_error = "Enter a password and/or select a key file.".into();
            return;
        }

        let mut key = DatabaseKey::new();
        if !self.password.is_empty() {
            key = key.with_password(&self.password);
        }
        if !self.key_file.trim().is_empty() {
            match std::fs::File::open(self.key_file.trim()) {
                Ok(mut f) => match key.with_keyfile(&mut f) {
                    Ok(k) => key = k,
                    Err(e) => {
                        self.unlock_error = format!("unable to read key file: {e}");
                        return;
                    }
                },
                Err(e) => {
                    self.unlock_error = format!("unable to open key file: {e}");
                    return;
                }
            }
        }
        if !self.challenge_response.trim().is_empty() {
            match kpxc::key::with_challenge_response(key, &self.challenge_response) {
                Ok(k) => key = k,
                Err(e) => {
                    self.unlock_error = format!("{e:#}");
                    return;
                }
            }
        }

        match open_database(&path, &key) {
            Ok(db) => {
                self.selected_group = None;
                self.selected_entry = None;
                self.search.clear();
                self.db = Some(db);
                self.db_key = Some(key);
                self.password.clear();
                self.dirty = false;
                self.modal = None;
                self.status = format!("Opened {path}");
                let opened = self.db_path.clone();
                self.record_recent(&opened);
            }
            Err(e) => self.unlock_error = e,
        }
    }

    /// Lock the database and return to the welcome screen.
    pub fn lock(&mut self) {
        self.db = None;
        self.db_key = None;
        self.dirty = false;
        self.selected_group = None;
        self.selected_entry = None;
        self.search.clear();
        self.modal = None;
        self.password.clear();
        self.status = "Database locked".into();
    }

    /// Save the open database to its current path.
    pub fn save(&mut self) {
        let (Some(db), Some(key)) = (self.db.as_mut(), self.db_key.clone()) else {
            return;
        };
        // KDBX 3.x can only be written after upgrading to KDBX 4.1.
        kpxc::commands::ensure_writable_version(db);
        match kpxc::saveutil::save(Path::new(&self.db_path), db, key) {
            Ok(()) => {
                self.dirty = false;
                self.status = format!("Saved {}", self.db_path);
                let path = self.db_path.clone();
                self.record_recent(&path);
            }
            Err(e) => self.status = format!("{e:#}"),
        }
    }

    /// Visible columns in display order.
    pub fn columns(&self) -> Vec<kpxc_gui_config::ColumnConfig> {
        let mut prefs = self.prefs.clone();
        prefs.normalize();
        prefs
            .columns
            .iter()
            .filter(|c| c.visible)
            .cloned()
            .collect()
    }

    /// Toggle a column; at least one stays visible.
    pub fn set_column_visible(&mut self, id: ColumnId, visible: bool) {
        if self.prefs.set_visible(id, visible) {
            self.save_preferences();
        } else {
            self.status = "At least one column must stay visible".into();
        }
    }

    pub fn move_column(&mut self, id: ColumnId, up: bool) {
        let Some(pos) = self.prefs.columns.iter().position(|c| c.id == id) else {
            return;
        };
        let target = if up {
            pos.checked_sub(1)
        } else if pos + 1 < self.prefs.columns.len() {
            Some(pos + 1)
        } else {
            None
        };
        if let Some(target) = target {
            self.prefs.columns.swap(pos, target);
            self.save_preferences();
        }
    }

    /// The group tree (root's children, recursively).
    pub fn group_tree(&self) -> Vec<GroupNode> {
        let Some(db) = &self.db else { return Vec::new() };
        let mut out = Vec::new();
        for g in db.root().groups() {
            push_group(&g, 0, &mut out);
        }
        out
    }

    /// Group id → path (for the search results and details).
    pub fn group_path(&self, id: GroupId) -> String {
        let Some(db) = &self.db else { return String::new() };
        let mut map = std::collections::HashMap::new();
        collect_paths(&db.root(), "", &mut map);
        map.get(&id).cloned().unwrap_or_default()
    }

    /// The visible entry rows (filtered by search and sorted).
    pub fn rows(&self) -> Vec<EntryRow> {
        let Some(db) = &self.db else { return Vec::new() };
        let mut paths = std::collections::HashMap::new();
        collect_paths(&db.root(), "", &mut paths);
        let searching = !self.search.trim().is_empty();
        let query = self.search.trim().to_lowercase();

        let mut rows: Vec<EntryRow> = Vec::new();
        if searching {
            for e in db.iter_all_entries() {
                rows.push(row_from_entry(&e, &paths));
            }
        } else if let Some(gid) = self.selected_group {
            if let Some(g) = db.group(gid) {
                for e in g.entries() {
                    rows.push(row_from_entry(&e, &paths));
                }
            }
        } else {
            for e in db.iter_all_entries() {
                rows.push(row_from_entry(&e, &paths));
            }
        }

        if !query.is_empty() {
            rows.retain(|r| {
                [&r.title, &r.username, &r.url, &r.notes, &r.tags, &r.group_path]
                    .iter()
                    .any(|s| s.to_lowercase().contains(&query))
            });
        }

        let col = self.sort_column;
        rows.sort_by(|a, b| {
            let key = |r: &EntryRow| match col {
                ColumnId::Title => r.title.to_lowercase(),
                ColumnId::UserName => r.username.to_lowercase(),
                ColumnId::Password => r.password.clone(),
                ColumnId::Url => r.url.to_lowercase(),
                ColumnId::Notes => r.notes.to_lowercase(),
                ColumnId::Tags => r.tags.to_lowercase(),
            };
            let ord = key(a).cmp(&key(b));
            if self.sort_desc {
                ord.reverse()
            } else {
                ord
            }
        });
        rows
    }

    /// The selected entry's details.
    pub fn details(&self) -> Option<Details> {
        let db = self.db.as_ref()?;
        let id = self.selected_entry?;
        let entry = db.entry(id)?;
        let mut attributes: Vec<(String, String, bool)> = entry
            .fields
            .iter()
            .filter(|(k, _)| !fields::KNOWN_FIELDS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.get().clone(), v.is_protected()))
            .collect();
        attributes.sort_by(|a, b| a.0.cmp(&b.0));
        Some(Details {
            id,
            title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
            username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
            password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
            url: entry.get(fields::URL).unwrap_or_default().to_owned(),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
            tags: entry.tags.join(", "),
            attributes,
            totp: totp_of(&entry),
        })
    }

    /// Start editing the selected entry.
    pub fn edit_selected(&mut self) {
        let (Some(db), Some(id)) = (self.db.as_ref(), self.selected_entry) else {
            return;
        };
        if let Some(draft) = EntryDraft::from_entry(db, id) {
            self.modal = Some(Modal::Entry(draft));
        }
    }

    /// Open the editor for a new entry in the selected (or root) group.
    pub fn new_entry(&mut self) {
        let Some(db) = self.db.as_ref() else { return };
        let group = self
            .selected_group
            .unwrap_or_else(|| db.root().id());
        self.modal = Some(Modal::Entry(EntryDraft::new(group)));
    }

    /// Apply the entry editor draft.
    pub fn apply_entry(&mut self, draft: EntryDraft) {
        let Some(db) = self.db.as_mut() else { return };
        let message = draft.apply(db);
        self.dirty = true;
        self.status = message;
        if draft.id.is_none() {
            // Select the entry that was just added (last in the group).
            let group = draft.group;
            if let Some(g) = db.group(group) {
                self.selected_entry = g.entries().last().map(|e| e.id());
            }
        }
        self.modal = None;
    }

    /// Add a group under `parent`.
    pub fn add_group(&mut self, parent: GroupId, name: &str) {
        if name.trim().is_empty() {
            self.status = "Group name must not be empty".into();
            return;
        }
        let Some(db) = self.db.as_mut() else { return };
        if let Some(mut group) = db.group_mut(parent) {
            let mut g = group.add_group();
            g.name = name.trim().to_owned();
            let id = g.id();
            self.dirty = true;
            self.selected_group = Some(id);
            self.status = format!("Added group '{}'", name.trim());
        }
        self.modal = None;
    }

    /// Delete the selected entry (recycle bin when enabled).
    pub fn delete_entry(&mut self, id: EntryId) {
        let to_recycle = self.deletes_to_recycle_bin_entry(id);
        let bin_id = to_recycle.then(|| self.ensure_recycle_bin());
        let Some(db) = self.db.as_mut() else { return };
        if let Some(bin) = bin_id {
            if let Some(mut entry) = db.entry_mut(id) {
                match entry.track_changes().move_to(bin) {
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
        self.modal = None;
    }

    fn recycle_bin_enabled(&self) -> bool {
        self.db
            .as_ref()
            .map(|db| db.meta.recyclebin_enabled.unwrap_or(true))
            .unwrap_or(true)
    }

    fn ensure_recycle_bin(&mut self) -> GroupId {
        if let Some(bin) = self.db.as_ref().and_then(|db| db.recycle_bin()) {
            return bin.id();
        }
        let db = self.db.as_mut().expect("db is open");
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

    fn deletes_to_recycle_bin_entry(&self, id: EntryId) -> bool {
        let Some(db) = self.db.as_ref() else { return false };
        if !self.recycle_bin_enabled() {
            return false;
        }
        let bin_id = db.recycle_bin().map(|b| b.id());
        let mut parent = db.entry(id).map(|e| e.parent().id());
        while let Some(pid) = parent {
            if Some(pid) == bin_id {
                return false;
            }
            parent = db.group(pid).and_then(|g| g.parent().map(|p| p.id()));
        }
        true
    }
}

/// Open a database with friendly credential errors.
pub fn open_database(path: &str, key: &DatabaseKey) -> Result<Database, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("unable to open database file {path}: {e}"))?;
    match Database::open(&mut file, key.clone()) {
        Ok(db) => Ok(db),
        Err(e) => Err(format!(
            "unable to open database {path} (wrong password or key file?): {e}"
        )),
    }
}

fn push_group(group: &keepass::db::GroupRef<'_>, depth: usize, out: &mut Vec<GroupNode>) {
    out.push(GroupNode {
        id: group.id(),
        depth,
        name: group.name.clone(),
        entries: group.entries().count(),
        groups: group.groups().count(),
    });
    for g in group.groups() {
        push_group(&g, depth + 1, out);
    }
}

fn collect_paths(
    group: &keepass::db::GroupRef<'_>,
    prefix: &str,
    out: &mut std::collections::HashMap<GroupId, String>,
) {
    let path = if prefix.is_empty() {
        group.name.clone()
    } else {
        format!("{prefix}/{}", group.name)
    };
    out.insert(group.id(), path.clone());
    for g in group.groups() {
        collect_paths(&g, &path, out);
    }
}

fn row_from_entry(
    entry: &EntryRef<'_>,
    paths: &std::collections::HashMap<GroupId, String>,
) -> EntryRow {
    let group = entry.parent().id();
    EntryRow {
        id: entry.id(),
        group,
        group_path: paths.get(&group).cloned().unwrap_or_default(),
        title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
        username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
        password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
        url: entry.get(fields::URL).unwrap_or_default().to_owned(),
        notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
        tags: entry.tags.join(", "),
    }
}

fn totp_of(entry: &EntryRef<'_>) -> Option<(String, u64)> {
    let totp = entry.get_otp().ok()?;
    let code = totp.value_now().ok()?;
    Some((code.code, code.valid_for.as_secs()))
}
