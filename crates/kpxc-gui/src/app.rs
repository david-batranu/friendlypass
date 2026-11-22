//! Application state, the eframe `App` implementation, the unlock screen
//! and the main window chrome (toolbar / status bar / save logic).

use eframe::egui;
use eframe::egui::Ui;
use keepass::db::{Database, GroupId};
use keepass::DatabaseKey;
use std::path::PathBuf;

use crate::browser;
use crate::dialogs::{self, Dialog};

/// Column to sort the entry list by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Tags,
}

impl SortColumn {
    pub fn label(&self) -> &'static str {
        match self {
            SortColumn::Title => "Title",
            SortColumn::Username => "UserName",
            SortColumn::Password => "Password",
            SortColumn::Url => "URL",
            SortColumn::Notes => "Notes",
            SortColumn::Tags => "Tags",
        }
    }
}

/// The main GUI application.
pub struct App {
    // -- unlock screen state --------------------------------------------
    pub db_path: String,
    pub password: String,
    pub key_file: String,
    pub unlock_error: String,

    // -- open database state --------------------------------------------
    pub db: Option<Database>,
    pub db_key: Option<DatabaseKey>,
    pub dirty: bool,
    /// Set once the KDBX3→4.1 upgrade has been confirmed, so we don't ask
    /// again on every save.
    pub upgrade_confirmed: bool,

    // -- browsing state --------------------------------------------------
    pub search: String,
    pub selected_group: Option<GroupId>, // None = root
    pub selected_entry: Option<keepass::db::EntryId>,
    pub sort_column: SortColumn,
    pub sort_desc: bool,
    pub show_passwords: bool,
    pub status: String,
    pub dialog: Dialog,
}

impl Default for App {
    fn default() -> Self {
        App {
            db_path: String::new(),
            password: String::new(),
            key_file: String::new(),
            unlock_error: String::new(),
            db: None,
            db_key: None,
            dirty: false,
            upgrade_confirmed: false,
            search: String::new(),
            selected_group: None,
            selected_entry: None,
            sort_column: SortColumn::Title,
            sort_desc: false,
            show_passwords: false,
            status: String::new(),
            dialog: Dialog::None,
        }
    }
}

impl App {
    pub fn new(initial_db: Option<String>) -> Self {
        let mut app = App::default();
        if let Some(path) = initial_db {
            app.db_path = path;
        }
        app
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

        match open_database(&self.db_path, &key) {
            Ok(db) => {
                self.db = Some(db);
                self.db_key = Some(key);
                self.password.clear();
                self.dirty = false;
                self.upgrade_confirmed = false;
                self.search.clear();
                self.selected_group = None;
                self.selected_entry = None;
                self.status = format!("Opened {}", self.db_path);
            }
            Err(e) => {
                self.unlock_error = format!("{e:#}");
            }
        }
    }

    /// Lock the database and return to the unlock screen.
    pub fn lock(&mut self) {
        self.db = None;
        self.db_key = None;
        self.dirty = false;
        self.upgrade_confirmed = false;
        self.selected_entry = None;
        self.selected_group = None;
        self.search.clear();
        self.dialog = Dialog::None;
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
        kpxc::commands::ensure_writable_version(db);

        let path = PathBuf::from(&path);
        match kpxc::saveutil::save(&path, db, key) {
            Ok(()) => {
                if let Some(p) = new_path {
                    self.db_path = p;
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

    /// Copy text to the system clipboard; reports failures in the status bar.
    pub fn copy_to_clipboard(&mut self, text: String) {
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
            Ok(()) => self.status = "Copied to clipboard".into(),
            Err(e) => self.status = format!("clipboard unavailable: {e}"),
        }
    }

    /// Open the entry editor for a new entry in the given group.
    pub fn new_entry_dialog(&mut self, group: Option<GroupId>) {
        let parent = group
            .or(self.selected_group)
            .unwrap_or_else(|| self.db.as_ref().map(|db| db.root().id()).expect("db open"));
        self.dialog = Dialog::EntryEdit(Box::new(dialogs::EntryEdit::new(parent)));
    }

    /// Open the entry editor for an existing entry (loads its fields).
    pub fn edit_entry_dialog(&mut self, id: keepass::db::EntryId) {
        let Some(db) = self.db.as_ref() else { return };
        let Some(entry) = db.entry(id) else { return };
        self.dialog = Dialog::EntryEdit(Box::new(dialogs::EntryEdit::from_entry(id, &entry)));
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

}

/// Open a database with friendly error mapping (shared with the CLI layer).
pub fn open_database(path: &str, key: &DatabaseKey) -> anyhow::Result<Database> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("unable to open database file {path}: {e}"))?;
    match Database::open(&mut file, key.clone()) {
        Ok(db) => Ok(db),
        Err(e) => anyhow::bail!("unable to open database {path} (wrong password or key file?): {e}"),
    }
}

// ---------------------------------------------------------------------------
// eframe integration
// ---------------------------------------------------------------------------

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        if self.db.is_none() {
            self.unlock_screen(ui);
        } else {
            self.database_screen(ui);
        }
    }
}

impl App {
    /// The unlock / welcome screen.
    fn unlock_screen(&mut self, root: &mut Ui) {
        let ctx = root.ctx().clone();
        egui::CentralPanel::default().show(root, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.heading("KeePassXC-RS");
                ui.label("KeePassXC core, migrated to Rust");
                ui.add_space(24.0);
            });

            egui::Grid::new("unlock-grid")
                .num_columns(3)
                .spacing([8.0, 8.0])
                .show(ui, |ui| {
                    let db_label = ui.label("Database file:");
                    let path_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.db_path).hint_text("/path/to/database.kdbx"),
                    );
                    path_resp.labelled_by(db_label.id);
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("KeePass database", &["kdbx", "kdb"])
                            .pick_file()
                        {
                            self.db_path = p.display().to_string();
                        }
                    }
                    ui.end_row();

                    let pw_label = ui.label("Password:");
                    let pw_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .hint_text("password"),
                    );
                    // Enter in the password field unlocks.
                    let enter_unlock = pw_resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                    pw_resp.labelled_by(pw_label.id);
                    if enter_unlock {
                        self.try_unlock();
                    }
                    ui.label("");
                    ui.end_row();

                    let kf_label = ui.label("Key file (optional):");
                    let kf_resp = ui
                        .add(egui::TextEdit::singleline(&mut self.key_file).hint_text("/path/to/keyfile.keyx"));
                    kf_resp.labelled_by(kf_label.id);
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("Key file", &["keyx", "key"])
                            .pick_file()
                        {
                            self.key_file = p.display().to_string();
                        }
                    }
                    ui.end_row();
                });

            ui.add_space(16.0);
            ui.vertical_centered(|ui| {
                if ui.button("Unlock").clicked() {
                    self.try_unlock();
                }
                ui.add_space(8.0);
                if ui.button("Create new database…").clicked() {
                    self.dialog = Dialog::NewDb(Box::new(dialogs::NewDb::default()));
                }
            });

            if !self.unlock_error.is_empty() {
                ui.add_space(12.0);
                ui.colored_label(egui::Color32::RED, &self.unlock_error);
            }

            dialogs::show(self, &ctx);
        });
    }

    /// The main database screen: toolbar, group tree, entry list, details.
    fn database_screen(&mut self, root: &mut Ui) {
        let ctx = root.ctx().clone();

        // Cmd/Ctrl+S saves.
        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::S)) {
            self.request_save();
        }

        // Toolbar ---------------------------------------------------------
        egui::Panel::top("toolbar")
            .resizable(false)
            .exact_size(42.0)
            .show(root, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let name = std::path::Path::new(&self.db_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "database".into());
                    ui.strong(format!("{name}{}", if self.dirty { "  *" } else { "" }));
                    ui.separator();

                    let search_label = ui.label("Search:");
                    let search_resp =
                        ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("search all entries…"));
                    search_resp.labelled_by(search_label.id);
                    if !self.search.is_empty() && ui.button("Clear search").clicked() {
                        self.search.clear();
                    }
                    ui.separator();

                    if ui.button("New Entry").clicked() {
                        self.new_entry_dialog(self.selected_group);
                    }
                    if ui.button("New Group").clicked() {
                        let parent = self
                            .selected_group
                            .unwrap_or_else(|| self.db.as_ref().unwrap().root().id());
                        self.dialog = Dialog::GroupNew(Box::new(dialogs::GroupEdit::new(parent)));
                    }
                    if ui.button("Password Generator…").clicked() {
                        self.dialog = Dialog::Generator(Box::new(dialogs::Generator::default()));
                    }
                    if ui.button("Database Info…").clicked() {
                        self.dialog = Dialog::DbInfo;
                    }
                    ui.separator();
                    let save = ui.add_enabled(self.dirty, egui::Button::new("Save"));
                    if save.clicked() {
                        self.request_save();
                    }
                    if ui.button("Save As…").clicked() {
                        self.dialog = Dialog::SaveAs(self.db_path.clone());
                    }
                    ui.separator();
                    ui.checkbox(&mut self.show_passwords, "Show passwords");
                    if ui.button("Lock").clicked() {
                        self.lock();
                    }
                });
                ui.add_space(4.0);
            });

        // Status bar ------------------------------------------------------
        egui::Panel::bottom("statusbar")
            .resizable(false)
            .exact_size(24.0)
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(&self.status);
                });
            });

        // Details panel ----------------------------------------------------
        let selected_entry = self.selected_entry;
        if selected_entry.is_some() {
            egui::Panel::bottom("details")
                .resizable(true)
                .default_size(170.0)
                .show(root, |ui| {
                    browser::entry_details(ui, self, selected_entry);
                });
        }

        // Group tree --------------------------------------------------------
        egui::Panel::left("groups")
            .resizable(true)
            .default_size(230.0)
            .show(root, |ui| {
                browser::group_tree(ui, self);
            });

        // Entry list ---------------------------------------------------------
        egui::CentralPanel::default().show(root, |ui| {
            browser::entry_table(ui, self);
        });

        dialogs::show(self, &ctx);
    }
}
