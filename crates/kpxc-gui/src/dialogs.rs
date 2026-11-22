//! Modal windows: entry editor, group editor, password generator,
//! database info, new database, save-as, and confirmation dialogs.

use eframe::egui;
use keepass::config::{CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};
use keepass::db::{fields, EntryId, GroupId};

use crate::app::App;

/// Which modal window (if any) is currently open.
pub enum Dialog {
    None,
    /// `entry_id == None` creates a new entry in `group`.
    EntryEdit(Box<EntryEdit>),
    GroupNew(Box<GroupEdit>),
    GroupRename(Box<GroupEdit>),
    Generator(Box<Generator>),
    DbInfo,
    /// Path (editable) for saving a copy of the database.
    SaveAs(String),
    NewDb(Box<NewDb>),
    /// Pending save that requires upgrading KDBX 3 → 4.1.
    ConfirmUpgrade,
    ConfirmDeleteEntry(EntryId),
    ConfirmDeleteGroup(GroupId),
}

// ---------------------------------------------------------------------------
// entry editor
// ---------------------------------------------------------------------------

pub struct EntryEdit {
    pub entry_id: Option<EntryId>,
    pub group: GroupId,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub show_password: bool,
}

impl EntryEdit {
    pub fn new(group: GroupId) -> Self {
        EntryEdit {
            entry_id: None,
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

    pub fn from_entry(id: EntryId, entry: &keepass::db::EntryRef<'_>) -> Self {
        EntryEdit {
            entry_id: Some(id),
            group: entry.parent().id(),
            title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
            username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
            password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
            url: entry.get(fields::URL).unwrap_or_default().to_owned(),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
            tags: entry.tags.join(", "),
            show_password: false,
        }
    }

    /// Apply the edit: create a new entry or update the existing one
    /// (recording an entry history item, like KeePassXC does).
    pub fn apply(&self, app: &mut App) {
        let Some(db) = app.db.as_mut() else { return };

        let fill = |entry: &mut keepass::db::Entry| {
            entry.set_unprotected(fields::TITLE, &self.title);
            entry.set_unprotected(fields::USERNAME, &self.username);
            entry.set_protected(fields::PASSWORD, &self.password);
            entry.set_unprotected(fields::URL, &self.url);
            entry.set_unprotected(fields::NOTES, &self.notes);
            entry.tags = self
                .tags
                .split(',')
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect();
        };

        match self.entry_id {
            Some(id) => {
                if let Some(mut entry) = db.entry_mut(id) {
                    // track_changes() records a history item on drop.
                    entry.track_changes().edit(|e| {
                        fill(e);
                    });
                    app.dirty = true;
                    app.status = format!("Updated entry '{}'", self.title);
                }
            }
            None => {
                if let Some(mut group) = db.group_mut(self.group) {
                    let mut entry = group.add_entry();
                    fill(&mut entry);
                    let id = entry.id();
                    app.dirty = true;
                    app.status = format!("Added entry '{}'", self.title);
                    app.selected_entry = Some(id);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// group editor
// ---------------------------------------------------------------------------

pub struct GroupEdit {
    pub id: Option<GroupId>,
    pub parent: GroupId,
    pub name: String,
}

impl GroupEdit {
    pub fn new(parent: GroupId) -> Self {
        GroupEdit {
            id: None,
            parent,
            name: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// password generator
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Generator {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub preview: String,
}

impl Default for Generator {
    fn default() -> Self {
        Generator {
            length: 24,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            preview: kpxc::commands::generate_password_opts(24, true, true, true, true),
        }
    }
}

impl Generator {
    pub fn regenerate(&mut self) {
        self.preview = kpxc::commands::generate_password_opts(
            self.length,
            self.upper,
            self.lower,
            self.digits,
            self.symbols,
        );
    }
}

// ---------------------------------------------------------------------------
// new database
// ---------------------------------------------------------------------------

pub struct NewDb {
    pub path: String,
    pub name: String,
    pub password: String,
    pub password_repeat: String,
    pub key_file: String,
    pub iterations: u64,
    pub memory_mib: u64,
    pub parallelism: u32,
    pub error: String,
}

impl Default for NewDb {
    fn default() -> Self {
        NewDb {
            path: "new-database.kdbx".into(),
            name: "New database".into(),
            password: String::new(),
            password_repeat: String::new(),
            key_file: String::new(),
            iterations: 50,
            memory_mib: 64,
            parallelism: 4,
            error: String::new(),
        }
    }
}

impl NewDb {
    /// Validate the dialog fields; the window renders the error message.
    pub fn validate(&self) -> Result<(), String> {
        if self.path.trim().is_empty() {
            return Err("Choose a file path".into());
        }
        if self.password != self.password_repeat {
            return Err("Passwords do not match".into());
        }
        if self.password.is_empty() && self.key_file.trim().is_empty() {
            return Err("Set a password and/or key file".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

/// Render whatever dialog is currently open.
pub fn show(app: &mut App, ctx: &egui::Context) {
    // Swap the dialog out so the rest of `app` can be mutated freely while
    // the dialog state is being rendered.
    let dialog = std::mem::replace(&mut app.dialog, Dialog::None);
    match dialog {
        Dialog::None => {}
        Dialog::EntryEdit(mut d) => {
            let mut open = true;
            let mut apply = false;
            let mut cancelled = false;
            egui::Window::new(if d.entry_id.is_some() { "Edit Entry" } else { "New Entry" })
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    egui::Grid::new("entry-edit").num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
                        let l = ui.label("Title:");
                        let r = ui.text_edit_singleline(&mut d.title);
                        r.labelled_by(l.id);
                        ui.end_row();

                        let l = ui.label("UserName:");
                        let r = ui.text_edit_singleline(&mut d.username);
                        r.labelled_by(l.id);
                        ui.end_row();

                        let l = ui.label("Password:");
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.password)
                                .password(!d.show_password)
                                .hint_text("password"),
                        );
                        r.labelled_by(l.id);
                        if ui.button("Generate").clicked() {
                            d.password = kpxc::commands::generate_password_opts(24, true, true, true, true);
                        }
                        if ui
                            .button(if d.show_password { "Hide" } else { "Show" })
                            .on_hover_text("Show or hide the password")
                            .clicked()
                        {
                            d.show_password = !d.show_password;
                        }
                        ui.end_row();

                        let l = ui.label("URL:");
                        let r = ui.text_edit_singleline(&mut d.url);
                        r.labelled_by(l.id);
                        ui.end_row();

                        let l = ui.label("Tags:");
                        let r = ui.add(egui::TextEdit::singleline(&mut d.tags).hint_text("comma,separated"));
                        r.labelled_by(l.id);
                        ui.end_row();

                        let l = ui.label("Notes:");
                        let r = ui.add(egui::TextEdit::multiline(&mut d.notes).desired_rows(3).desired_width(320.0));
                        r.labelled_by(l.id);
                        ui.end_row();
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("OK").clicked() {
                            apply = true;
                        }
                    });
                });
            if apply {
                d.apply(app);
            } else if !cancelled && open {
                app.dialog = Dialog::EntryEdit(d);
            }
        }
        Dialog::GroupNew(mut d) => {
            let mut open = true;
            let mut apply = false;
            let mut cancelled = false;
            egui::Window::new("New Group")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    let l = ui.label("Group name:");
                    let r = ui.text_edit_singleline(&mut d.name);
                    r.labelled_by(l.id);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Create").clicked() {
                            apply = true;
                        }
                    });
                });
            if apply && !d.name.trim().is_empty() {
                if let Some(db) = app.db.as_mut() {
                    if let Some(mut parent) = db.group_mut(d.parent) {
                        let mut group = parent.add_group();
                        group.name = d.name.trim().to_owned();
                        let id = group.id();
                        app.dirty = true;
                        app.status = format!("Added group '{}'", d.name.trim());
                        app.selected_group = Some(id);
                    }
                }
            }
            if !apply && !cancelled && open {
                app.dialog = Dialog::GroupNew(d);
            }
        }
        Dialog::GroupRename(mut d) => {            let mut open = true;
            let mut apply = false;
            let mut cancelled = false;
            egui::Window::new("Rename Group")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    let l = ui.label("Group name:");
                    let r = ui.text_edit_singleline(&mut d.name);
                    r.labelled_by(l.id);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Rename").clicked() {
                            apply = true;
                        }
                    });
                });
            if apply && !d.name.trim().is_empty() {
                if let Some(db) = app.db.as_mut() {
                    if let Some(mut group) = db.group_mut(d.id.unwrap()) {
                        group.name = d.name.trim().to_owned();
                        app.dirty = true;
                        app.status = format!("Renamed group to '{}'", d.name.trim());
                    }
                }
            }
            if !cancelled && open {
                app.dialog = Dialog::GroupRename(d);
            }
        }
        Dialog::Generator(mut g) => {
            let mut open = true;
            let mut copy = false;
            egui::Window::new("Password Generator")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    let l = ui.label("Length:");
                    let r = ui.add(egui::Slider::new(&mut g.length, 8..=64).text("characters"));
                    r.labelled_by(l.id);
                    let dirty = ui.checkbox(&mut g.upper, "Upper case (A-Z)")
                        | ui.checkbox(&mut g.lower, "Lower case (a-z)")
                        | ui.checkbox(&mut g.digits, "Digits (0-9)")
                        | ui.checkbox(&mut g.symbols, "Symbols (!@#…)");
                    if dirty.changed() || ui.button("Regenerate").clicked() {
                        g.regenerate();
                    }
                    ui.add_space(6.0);
                    let l = ui.label("Preview:");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut g.preview)
                            .font(egui::TextStyle::Monospace)
                            .interactive(false),
                    );
                    r.labelled_by(l.id);
                    ui.add_space(6.0);
                    if ui.button("Copy to clipboard").clicked() {
                        copy = true;
                    }
                });
            if copy {
                app.copy_to_clipboard(g.preview.clone());
            }
            if open {
                app.dialog = Dialog::Generator(g);
            }
        }
        Dialog::DbInfo => {
            let mut open = true;
            let mut close_clicked = false;
            egui::Window::new("Database Information")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    if let Some(db) = app.db.as_ref() {
                        egui::Grid::new("db-info").num_columns(2).show(ui, |ui| {
                            for (k, v) in [
                                ("Version", kpxc::commands::version_string(&db.config.version)),
                                ("Cipher", kpxc::commands::outer_cipher_name(&db.config.outer_cipher_config).to_owned()),
                                (
                                    "Compression",
                                    kpxc::commands::compression_name(&db.config.compression_config).to_owned(),
                                ),
                                (
                                    "Inner cipher",
                                    kpxc::commands::inner_cipher_name(&db.config.inner_cipher_config).to_owned(),
                                ),
                                ("KDF", kpxc::commands::kdf_name(&db.config.kdf_config)),
                                (
                                    "Name",
                                    db.meta.database_name.clone().unwrap_or_else(|| "(none)".into()),
                                ),
                                (
                                    "Generator",
                                    db.meta.generator.clone().unwrap_or_else(|| "(none)".into()),
                                ),
                                ("Groups", db.num_groups().to_string()),
                                ("Entries", db.num_entries().to_string()),
                            ] {
                                ui.strong(k);
                                ui.label(v);
                                ui.end_row();
                            }
                        });
                    }
                    ui.add_space(6.0);
                    if ui.button("Close").clicked() {
                        close_clicked = true;
                    }
                });
            if !close_clicked && open {
                app.dialog = Dialog::DbInfo;
            }
        }
        Dialog::SaveAs(mut path) => {
            let mut open = true;
            let mut save = false;
            let mut cancelled = false;
            egui::Window::new("Save Database As")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    let l = ui.label("File path:");
                    let r = ui.add(egui::TextEdit::singleline(&mut path).hint_text("/path/to/database.kdbx"));
                    r.labelled_by(l.id);
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("KeePass database", &["kdbx"])
                            .set_file_name("database.kdbx")
                            .save_file()
                        {
                            path = p.display().to_string();
                        }
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Save").clicked() {
                            save = true;
                        }
                    });
                });
            if save {
                app.perform_save(Some(path.clone()));
            }
            if !save && !cancelled && open {
                app.dialog = Dialog::SaveAs(path);
            }
        }
        Dialog::NewDb(mut d) => {
            let mut open = true;
            let mut create = false;
            let mut cancelled = false;
            egui::Window::new("Create New Database")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    let mut validation_error = d.error.clone();
                    egui::Grid::new("new-db").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                        let l = ui.label("File path:");
                        let r = ui.add(egui::TextEdit::singleline(&mut d.path).hint_text("/path/to/new-database.kdbx"));
                        r.labelled_by(l.id);
                        ui.end_row();
                        let l = ui.label("Database name:");
                        let r = ui.text_edit_singleline(&mut d.name);
                        r.labelled_by(l.id);
                        ui.end_row();
                        let l = ui.label("Password:");
                        let r = ui.add(egui::TextEdit::singleline(&mut d.password).password(true));
                        r.labelled_by(l.id);
                        ui.end_row();
                        let l = ui.label("Repeat password:");
                        let r = ui.add(egui::TextEdit::singleline(&mut d.password_repeat).password(true));
                        r.labelled_by(l.id);
                        ui.end_row();
                        let l = ui.label("Key file (optional):");
                        let r = ui
                            .add(egui::TextEdit::singleline(&mut d.key_file).hint_text("generated if missing"));
                        r.labelled_by(l.id);
                        ui.end_row();
                        let l = ui.label("Argon2 iterations:");
                        let r = ui.add(egui::DragValue::new(&mut d.iterations).range(1..=1_000_000));
                        r.labelled_by(l.id);
                        ui.end_row();
                        let l = ui.label("Argon2 memory (MiB):");
                        let r = ui.add(egui::DragValue::new(&mut d.memory_mib).range(8..=1024));
                        r.labelled_by(l.id);
                        ui.end_row();
                        let l = ui.label("Argon2 parallelism:");
                        let r = ui.add(egui::DragValue::new(&mut d.parallelism).range(1..=8));
                        r.labelled_by(l.id);
                        ui.end_row();
                    });
                    if let Err(e) = d.validate() {
                        validation_error = e;
                    }
                    if !validation_error.is_empty() {
                        ui.colored_label(egui::Color32::RED, &validation_error);
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Create").clicked() {
                            match d.validate() {
                                Ok(()) => {
                                    create = true;
                                }
                                Err(e) => d.error = e,
                            }
                        }
                    });
                });
            if create {
                create_new_database(app, &d);
            }
            if !create && !cancelled && open {
                app.dialog = Dialog::NewDb(d);
            }
        }
        Dialog::ConfirmUpgrade => {
            let mut open = true;
            let mut confirmed = false;
            let mut cancelled = false;
            egui::Window::new("Upgrade Database Format")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label("This database uses the older KDBX 3.1 format.");
                    ui.label("Saving requires upgrading it to KDBX 4.1 (KeePassXC's current format).");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Upgrade and Save").clicked() {
                            confirmed = true;
                        }
                    });
                });
            if confirmed {
                app.upgrade_confirmed = true;
                app.perform_save(None);
            } else if !cancelled && open {
                app.dialog = Dialog::ConfirmUpgrade;
            }
        }
        Dialog::ConfirmDeleteEntry(id) => {
            let mut open = true;
            let mut confirmed = false;
            let mut cancelled = false;
            egui::Window::new("Delete Entry")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label("Delete this entry? This cannot be undone.");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Delete").clicked() {
                            confirmed = true;
                        }
                    });
                });
            if confirmed {
                app.delete_entry(id);
            } else if !cancelled && open {
                app.dialog = Dialog::ConfirmDeleteEntry(id);
            }
        }
        Dialog::ConfirmDeleteGroup(id) => {
            let mut open = true;
            let mut confirmed = false;
            let mut cancelled = false;
            egui::Window::new("Delete Group")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label("Delete this group and all its contents? This cannot be undone.");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Delete").clicked() {
                            confirmed = true;
                        }
                    });
                });
            if confirmed {
                app.delete_group(id);
            } else if !cancelled && open {
                app.dialog = Dialog::ConfirmDeleteGroup(id);
            }
        }
    }
}

/// Create (and open) a new database from the dialog state.
fn create_new_database(app: &mut App, d: &NewDb) {
    let mut db = keepass::Database::new();
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.outer_cipher_config = OuterCipherConfig::AES256;
    db.config.compression_config = CompressionConfig::GZip;
    db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    db.config.kdf_config = KdfConfig::Argon2id {
        iterations: d.iterations,
        memory: d.memory_mib * 1024 * 1024,
        parallelism: d.parallelism,
        version: argon2::Version::Version13,
    };
    db.meta.database_name = Some(d.name.clone());

    let mut key = keepass::DatabaseKey::new();
    if !d.password.is_empty() {
        key = key.with_password(&d.password);
    }
    if !d.key_file.trim().is_empty() {
        // Generate a KeePassXC-compatible keyfile if it does not exist yet.
        let kf_path = std::path::PathBuf::from(&d.key_file);
        if let Err(e) = kpxc::key::ensure_key_file(&kf_path) {
            app.status = format!("{e:#}");
            return;
        }
        match std::fs::File::open(&kf_path) {
            Ok(mut f) => match key.with_keyfile(&mut f) {
                Ok(k) => key = k,
                Err(e) => {
                    app.status = format!("unable to read key file: {e}");
                    return;
                }
            },
            Err(e) => {
                app.status = format!("unable to open key file: {e}");
                return;
            }
        }
    }

    let path = std::path::PathBuf::from(&d.path);
    if let Err(e) = kpxc::saveutil::save(&path, &db, key.clone()) {
        app.status = format!("{e:#}");
        return;
    }

    app.db = Some(db);
    app.db_key = Some(key);
    app.db_path = d.path.clone();
    app.dirty = false;
    app.upgrade_confirmed = true;
    app.selected_group = None;
    app.selected_entry = None;
    app.status = format!("Created {}", app.db_path);
}
