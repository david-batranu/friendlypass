//! Modal windows: entry editor, group editor, password generator,
//! database info, new database, save-as, and confirmation dialogs.

use eframe::egui;
use keepass::config::{CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};
use keepass::db::{fields, EntryId, GroupId};
use keepass::db::CustomIconId;

use crate::app::App;
use crate::refs::{self, RefTarget};

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
    /// Browse / restore an entry's history revisions.
    History(EntryId),
    /// Permanently remove everything inside the recycle bin.
    ConfirmEmptyRecycleBin,
    /// Move a multi-selection of entries to a group.
    BatchMove(Box<BatchMove>),
}

/// State of the batch-move dialog.
pub struct BatchMove {
    pub entries: Vec<EntryId>,
    pub groups: Vec<(GroupId, String)>,
    /// Selected destination (persisted across frames, unlike a render local).
    pub target: Option<GroupId>,
}

/// The icon selection of the entry/group editor.
#[derive(Clone)]
pub enum IconChoice {
    None,
    Standard(usize),
    Custom(CustomIconId),
    /// A new image file to store as a database custom icon on apply.
    NewCustom(Vec<u8>),
}

impl std::fmt::Display for IconChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IconChoice::None => write!(f, "no icon"),
            IconChoice::Standard(n) => write!(f, "standard icon {n}"),
            IconChoice::Custom(id) => write!(f, "custom icon {id}"),
            IconChoice::NewCustom(_) => write!(f, "new custom icon from file"),
        }
    }
}

/// Reusable icon picker: the 69 KeePass standard icons, the database's custom
/// icon pool, and loading a new custom image from a file path.
fn icon_picker(
    ui: &mut egui::Ui,
    app: &mut App,
    choice: &mut IconChoice,
    custom_pool: &[(CustomIconId, Vec<u8>)],
    icon_path: &mut String,
) {
    let ctx = ui.ctx().clone();
    ui.label(format!("Current icon: {choice}"));
    ui.horizontal_wrapped(|ui| {
        for (n, _) in crate::icons::STANDARD_ICONS {
            if let Some(tex) = app.icon_cache.standard(&ctx, *n) {
                let selected = matches!(choice, IconChoice::Standard(k) if *k == *n);
                let btn = egui::Button::image((tex.id(), egui::Vec2::splat(18.0))).selected(selected);
                if ui.add(btn).on_hover_text(format!("Icon {n}")).clicked() {
                    *choice = IconChoice::Standard(*n);
                }
            }
        }
    });
    if ui.button("No icon").clicked() {
        *choice = IconChoice::None;
    }
    if !custom_pool.is_empty() {
        ui.separator();
        ui.label("Database custom icons:");
        ui.horizontal_wrapped(|ui| {
            for (id, bytes) in custom_pool {
                if let Some(tex) = app.icon_cache.texture(&ctx, &format!("custom-{id}"), bytes) {
                    let selected = matches!(choice, IconChoice::Custom(c) if *c == *id);
                    let btn =
                        egui::Button::image((tex.id(), egui::Vec2::splat(18.0))).selected(selected);
                    if ui.add(btn).on_hover_text(format!("Custom icon {id}")).clicked() {
                        *choice = IconChoice::Custom(*id);
                    }
                }
            }
        });
    }
    ui.separator();
    let l = ui.label("Custom icon image path:");
    let r = ui.add(egui::TextEdit::singleline(icon_path).hint_text("/path/to/icon.png"));
    r.labelled_by(l.id);
    if ui.button("Use image…").clicked() {
        match std::fs::read(icon_path.trim()) {
            Ok(bytes) => *choice = IconChoice::NewCustom(bytes),
            Err(e) => app.status = format!("unable to read icon file: {e}"),
        }
    }
    if ui.button("Browse…").clicked() {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("Image", &["png", "jpg", "jpeg"])
            .pick_file()
        {
            *icon_path = p.display().to_string();
        }
    }
}

/// Apply an icon choice to an entry (works for both new and existing entries).
fn apply_entry_icon(entry: &mut keepass::db::EntryMut<'_>, choice: &IconChoice) {
    match choice {
        IconChoice::None => entry.set_icon_none(),
        IconChoice::Standard(n) => entry.set_icon_builtin(*n),
        IconChoice::Custom(id) => {
            let _ = entry.set_icon_custom(*id);
        }
        IconChoice::NewCustom(bytes) => {
            entry.set_icon_custom_new(bytes.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// entry editor
// ---------------------------------------------------------------------------

/// One editable custom attribute in the entry editor.
#[derive(Clone)]
pub struct AttributeRow {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

/// One editable auto-type window association.
#[derive(Clone)]
pub struct AssociationRow {
    pub window: String,
    pub sequence: String,
}

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
    /// Custom (non-standard) attributes.
    pub attributes: Vec<AttributeRow>,
    /// Auto-Type settings.
    pub at_enabled: bool,
    pub at_default_sequence: String,
    pub at_obfuscate: bool,
    pub at_associations: Vec<AssociationRow>,
    /// Icon selection.
    pub icon: IconChoice,
    pub icon_path: String,
    /// Custom icon pool snapshot (for the picker strip).
    pub custom_icons: Vec<(CustomIconId, Vec<u8>)>,
    /// Entry-reference insertion state.
    pub ref_targets: Vec<RefTarget>,
    pub ref_target: Option<usize>,
    pub ref_field: char,
    pub ref_into: char,
}

impl EntryEdit {
    pub fn new(
        group: GroupId,
        ref_targets: Vec<RefTarget>,
        custom_icons: Vec<(CustomIconId, Vec<u8>)>,
    ) -> Self {
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
            attributes: Vec::new(),
            at_enabled: true,
            at_default_sequence: String::new(),
            at_obfuscate: false,
            at_associations: Vec::new(),
            icon: IconChoice::Standard(crate::icons::DEFAULT_ENTRY_ICON),
            icon_path: String::new(),
            custom_icons,
            ref_targets,
            ref_target: None,
            ref_field: refs::CODE_PASSWORD,
            ref_into: refs::CODE_NOTES,
        }
    }

    pub fn from_entry(
        id: EntryId,
        entry: &keepass::db::EntryRef<'_>,
        ref_targets: Vec<RefTarget>,
        custom_icons: Vec<(CustomIconId, Vec<u8>)>,
    ) -> Self {
        let mut attributes: Vec<AttributeRow> = entry
            .fields
            .iter()
            .filter(|(k, _)| !fields::KNOWN_FIELDS.contains(&k.as_str()))
            .map(|(k, v)| AttributeRow {
                key: k.clone(),
                value: v.get().clone(),
                protected: v.is_protected(),
            })
            .collect();
        attributes.sort_by(|a, b| a.key.cmp(&b.key));

        let icon = match entry.icon() {
            Some(keepass::db::Icon::BuiltIn(n)) => IconChoice::Standard(*n),
            Some(keepass::db::Icon::Custom(id)) => IconChoice::Custom(*id),
            None => IconChoice::None,
        };

        let autotype = entry.autotype.as_ref();
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
            attributes,
            at_enabled: autotype.map(|a| a.enabled).unwrap_or(true),
            at_default_sequence: autotype
                .and_then(|a| a.default_sequence.clone())
                .unwrap_or_default(),
            at_obfuscate: autotype
                .map(|a| {
                    matches!(a.data_transfer_obfuscation, keepass::db::DataTransferObfuscation::UseClipboard)
                })
                .unwrap_or(false),
            at_associations: autotype
                .map(|a| {
                    a.associations
                        .iter()
                        .map(|assoc| AssociationRow {
                            window: assoc.window.clone(),
                            sequence: assoc.sequence.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            icon,
            icon_path: String::new(),
            custom_icons,
            ref_targets,
            ref_target: None,
            ref_field: refs::CODE_PASSWORD,
            ref_into: refs::CODE_NOTES,
        }
    }

    /// Build the complete field map for the entry after editing.
    fn build_fields(&self) -> std::collections::HashMap<String, keepass::db::Value<String>> {
        use keepass::db::Value;
        let mut out = std::collections::HashMap::new();
        out.insert(fields::TITLE.to_owned(), Value::unprotected(self.title.clone()));
        out.insert(fields::USERNAME.to_owned(), Value::unprotected(self.username.clone()));
        out.insert(fields::PASSWORD.to_owned(), Value::protected(self.password.clone()));
        out.insert(fields::URL.to_owned(), Value::unprotected(self.url.clone()));
        out.insert(fields::NOTES.to_owned(), Value::unprotected(self.notes.clone()));
        for a in &self.attributes {
            let key = a.key.trim();
            if key.is_empty() || fields::KNOWN_FIELDS.contains(&key) {
                continue;
            }
            let value = if a.protected {
                Value::protected(a.value.clone())
            } else {
                Value::unprotected(a.value.clone())
            };
            out.insert(key.to_owned(), value);
        }
        out
    }

    /// Apply the edit: create a new entry or update the existing one
    /// (recording an entry history item, like KeePassXC does).
    pub fn apply(&self, app: &mut App) {
        let Some(db) = app.db.as_mut() else { return };

        let new_fields = self.build_fields();
        let autotype = keepass::db::AutoType {
            enabled: self.at_enabled,
            default_sequence: (!self.at_default_sequence.is_empty()).then(|| self.at_default_sequence.clone()),
            data_transfer_obfuscation: if self.at_obfuscate {
                keepass::db::DataTransferObfuscation::UseClipboard
            } else {
                keepass::db::DataTransferObfuscation::None
            },
            associations: self
                .at_associations
                .iter()
                .filter(|a| !a.window.trim().is_empty())
                .map(|a| keepass::db::AutoTypeAssociation {
                    window: a.window.clone(),
                    sequence: a.sequence.clone(),
                })
                .collect(),
        };
        let tags: Vec<String> = self
            .tags
            .split(',')
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();

        match self.entry_id {
            Some(id) => {
                // Tracked edit of fields (records a history item on drop)…
                if let Some(mut entry) = db.entry_mut(id) {
                    entry.track_changes().edit(|e| {
                        e.fields = new_fields;
                        e.autotype = Some(autotype);
                        e.tags = tags;
                    });
                }
                // …then the icon (history already captured the old icon).
                if let Some(mut entry) = db.entry_mut(id) {
                    apply_entry_icon(&mut entry, &self.icon);
                }
                app.dirty = true;
                app.status = format!("Updated entry '{}'", self.title);
            }
            None => {
                if let Some(mut group) = db.group_mut(self.group) {
                    let mut entry = group.add_entry();
                    {
                        let e: &mut keepass::db::Entry = &mut entry;
                        e.fields = new_fields;
                        e.autotype = Some(autotype);
                        e.tags = tags;
                    }
                    apply_entry_icon(&mut entry, &self.icon);
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

                    // --- custom attributes -----------------------------------
                    ui.separator();
                    ui.strong("Custom attributes");
                    let mut remove_attr: Option<usize> = None;
                    for (i, a) in d.attributes.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            let l = ui.label(format!("Attribute {i} key:"));
                            let r = ui.text_edit_singleline(&mut a.key);
                            r.labelled_by(l.id);
                            let l = ui.label(format!("Attribute {i} value:"));
                            let r = ui.add(
                                egui::TextEdit::singleline(&mut a.value).password(a.protected),
                            );
                            r.labelled_by(l.id);
                            ui.checkbox(&mut a.protected, format!("Protected {i}"));
                            if ui.button(format!("Remove attribute {i}")).clicked() {
                                remove_attr = Some(i);
                            }
                        });
                    }
                    if let Some(i) = remove_attr {
                        d.attributes.remove(i);
                    }
                    if ui.button("Add attribute").clicked() {
                        d.attributes.push(AttributeRow {
                            key: String::new(),
                            value: String::new(),
                            protected: false,
                        });
                    }

                    // --- auto-type --------------------------------------------
                    ui.separator();
                    ui.strong("Auto-Type");
                    ui.checkbox(&mut d.at_enabled, "Auto-Type enabled");
                    ui.horizontal(|ui| {
                        let l = ui.label("Default sequence:");
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.at_default_sequence)
                                .hint_text("{USERNAME}{TAB}{PASSWORD}{ENTER}"),
                        );
                        r.labelled_by(l.id);
                    });
                    ui.checkbox(&mut d.at_obfuscate, "Obfuscate using the clipboard");
                    let mut remove_assoc: Option<usize> = None;
                    for (i, a) in d.at_associations.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            let l = ui.label(format!("Window {i}:"));
                            let r = ui.add(
                                egui::TextEdit::singleline(&mut a.window).hint_text("* - Notepad"),
                            );
                            r.labelled_by(l.id);
                            let l = ui.label(format!("Sequence {i}:"));
                            let r = ui.text_edit_singleline(&mut a.sequence);
                            r.labelled_by(l.id);
                            if ui.button(format!("Remove association {i}")).clicked() {
                                remove_assoc = Some(i);
                            }
                        });
                    }
                    if let Some(i) = remove_assoc {
                        d.at_associations.remove(i);
                    }
                    if ui.button("Add window association").clicked() {
                        d.at_associations.push(AssociationRow {
                            window: String::new(),
                            sequence: String::new(),
                        });
                    }

                    // Auto-type sequence preview (placeholder resolution).
                    if !d.at_default_sequence.is_empty() {
                        let preview = d
                            .entry_id
                            .and_then(|id| app.db.as_ref().map(|db| (db, id)))
                            .map(|(db, id)| {
                                refs::resolve_auto_type_sequence(db, id, &d.at_default_sequence)
                            });
                        if let Some(mut preview) = preview {
                            ui.add_space(4.0);
                            let l = ui.label("Sequence preview:");
                            let r = ui.add(egui::TextEdit::singleline(&mut preview).interactive(false));
                            r.labelled_by(l.id);
                        }
                    }

                    // --- entry references -------------------------------------
                    ui.separator();
                    ui.strong("References");
                    ui.label("Insert a field reference to another entry ({REF:…}) into one of this entry's fields.");
                    ui.horizontal(|ui| {
                        let selected_text = d
                            .ref_target
                            .and_then(|i| d.ref_targets.get(i))
                            .map(|t| t.title.clone())
                            .unwrap_or_else(|| "(select entry)".into());
                        egui::ComboBox::new("ref-target", "Referenced entry")
                            .selected_text(selected_text)
                            .show_ui(ui, |ui| {
                                for (i, t) in d.ref_targets.iter().enumerate() {
                                    ui.selectable_value(&mut d.ref_target, Some(i), &t.title);
                                }
                            });
                    });
                    ui.horizontal(|ui| {
                        let selected_text = refs::REFERENCEABLE
                            .iter()
                            .find(|(code, _, _)| *code == d.ref_field)
                            .map(|(_, name, _)| *name)
                            .unwrap_or("Password");
                        egui::ComboBox::new("ref-field", "Referenced field")
                            .selected_text(selected_text)
                            .show_ui(ui, |ui| {
                                for (code, name, _) in refs::REFERENCEABLE {
                                    ui.selectable_value(&mut d.ref_field, code, name);
                                }
                            });
                        let selected_text = refs::REFERENCEABLE
                            .iter()
                            .find(|(code, _, _)| *code == d.ref_into)
                            .map(|(_, name, _)| *name)
                            .unwrap_or("Notes");
                        egui::ComboBox::new("ref-into", "Insert into")
                            .selected_text(selected_text)
                            .show_ui(ui, |ui| {
                                for (code, name, _) in refs::REFERENCEABLE {
                                    ui.selectable_value(&mut d.ref_into, code, name);
                                }
                            });
                    });
                    if ui.button("Insert reference").clicked() {
                        if let Some(target) = d.ref_target.and_then(|i| d.ref_targets.get(i)) {
                            let reference = refs::make_reference(d.ref_field, &target.uuid);
                            match d.ref_into {
                                refs::CODE_TITLE => d.title.push_str(&reference),
                                refs::CODE_USERNAME => d.username.push_str(&reference),
                                refs::CODE_PASSWORD => d.password.push_str(&reference),
                                refs::CODE_URL => d.url.push_str(&reference),
                                refs::CODE_NOTES => d.notes.push_str(&reference),
                                _ => {}
                            }
                        }
                    }

                    // --- icon picker ---------------------------------------------
                    ui.separator();
                    ui.strong("Icon");
                    icon_picker(ui, app, &mut d.icon, &d.custom_icons, &mut d.icon_path);

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
            // Word the confirmation like KeePassXC does.
            let to_recycle = app.deletes_to_recycle_bin_entry(id);
            egui::Window::new("Delete Entry")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    if to_recycle {
                        ui.label("Move this entry to the Recycle Bin?");
                        ui.weak("Entries in the Recycle Bin can be restored or deleted permanently later.");
                    } else {
                        ui.label("Permanently delete this entry? This cannot be undone.");
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button(if to_recycle { "Move to Recycle Bin" } else { "Delete" }).clicked() {
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
        Dialog::History(id) => {
            // Immutable snapshot of the history list for rendering.
            let history: Vec<(usize, String, String, String)> = app
                .db
                .as_ref()
                .and_then(|db| db.entry(id))
                .map(|e| {
                    let mut out = Vec::new();
                    if let Some(h) = &e.history {
                        for (i, item) in h.get_entries().iter().enumerate() {
                            let modified = item
                                .times
                                .last_modification
                                .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                                .unwrap_or_else(|| "(unknown date)".into());
                            let get = |k: &str| {
                                item.fields
                                    .get(k)
                                    .map(|v| v.get().clone())
                                    .unwrap_or_default()
                            };
                            out.push((i, modified, get("Title"), get("UserName")));
                        }
                    }
                    out
                })
                .unwrap_or_default();

            let mut open = true;
            let mut cancelled = false;
            let mut restore: Option<usize> = None;
            egui::Window::new("Entry History")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    if history.is_empty() {
                        ui.label("This entry has no recorded history.");
                    } else {
                        egui::Grid::new("history-grid")
                            .num_columns(5)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("#");
                                ui.strong("Modified");
                                ui.strong("Title");
                                ui.strong("UserName");
                                ui.strong("");
                                ui.end_row();
                                for (i, modified, title, username) in &history {
                                    ui.label(i.to_string());
                                    ui.label(modified);
                                    ui.label(title);
                                    ui.label(username);
                                    if ui.button(format!("Restore revision {i}")).clicked() {
                                        restore = Some(*i);
                                    }
                                    ui.end_row();
                                }
                            });
                        ui.add_space(4.0);
                        ui.weak("Restoring copies all fields of the revision into the current entry; the change is itself recorded in the history.");
                    }
                    ui.add_space(6.0);
                    if ui.button("Close").clicked() {
                        cancelled = true;
                    }
                });
            if let Some(index) = restore {
                app.restore_history_entry(id, index);
            } else if !cancelled && open {
                app.dialog = Dialog::History(id);
            }
        }
        Dialog::ConfirmEmptyRecycleBin => {
            let count = app
                .db
                .as_ref()
                .and_then(|db| db.recycle_bin())
                .map(|bin| bin.entries().count() + bin.groups().count())
                .unwrap_or(0);

            let mut open = true;
            let mut confirmed = false;
            let mut cancelled = false;
            egui::Window::new("Empty the Recycle Bin?")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(format!("Permanently remove all {count} objects from the Recycle Bin?"));
                    ui.weak("This cannot be undone.");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Empty Recycle Bin").clicked() {
                            confirmed = true;
                        }
                    });
                });
            if confirmed {
                app.empty_recycle_bin();
            } else if !cancelled && open {
                app.dialog = Dialog::ConfirmEmptyRecycleBin;
            }
        }
        Dialog::BatchMove(mut bm) => {
            let mut open = true;
            let mut cancelled = false;
            let mut move_clicked = false;
            egui::Window::new(format!("Move {} Entries to Group", bm.entries.len()))
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label("Choose the destination group:");
                    egui::ScrollArea::vertical()
                        .max_height(220.0)
                        .show(ui, |ui| {
                            for (gid, path) in &bm.groups {
                                ui.radio_value(&mut bm.target, Some(*gid), format!("Group: {path}"));
                            }
                        });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        let ok = ui.add_enabled(bm.target.is_some(), egui::Button::new("Move entries"));
                        if ok.clicked() {
                            move_clicked = true;
                        }
                    });
                });
            if move_clicked {
                if let Some(gid) = bm.target {
                    app.move_entries_to(&bm.entries, gid);
                }
            } else if !cancelled && open {
                app.dialog = Dialog::BatchMove(bm);
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
