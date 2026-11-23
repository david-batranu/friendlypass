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
    /// SSH agent integration: serve the database's SSH keys.
    SshAgent,
    /// KeePassXC-Browser protocol integration.
    Browser,
    /// KeeShare: share a group via a container file.
    ShareGroup(Box<ShareDialog>),
    /// Keyboard shortcut reference.
    Shortcuts,
}

/// State of the KeeShare dialog.
pub struct ShareDialog {
    pub group: keepass::db::GroupId,
    pub group_name: String,
    pub path: String,
    pub password: String,
    pub import: bool,
    pub export: bool,
    pub show_password: bool,
    pub message: String,
}

impl ShareDialog {
    /// Build the dialog for a group, prefilled from its existing reference.
    pub fn for_group(db: &keepass::db::Database, group: keepass::db::GroupId) -> Self {
        let group_name = db
            .group(group)
            .map(|g| g.name.clone())
            .unwrap_or_default();
        let mut dialog = ShareDialog {
            group,
            group_name,
            path: String::new(),
            password: String::new(),
            import: true,
            export: true,
            show_password: false,
            message: String::new(),
        };
        if let Some(reference) = kpxc::keeshare::reference_of(db, group) {
            dialog.path = reference.path;
            dialog.password = reference.password;
            dialog.import = reference.import;
            dialog.export = reference.export;
        }
        dialog
    }

    fn reference(&self, db: &keepass::db::Database) -> kpxc::keeshare::ShareReference {
        kpxc::keeshare::ShareReference {
            import: self.import,
            export: self.export,
            group_uuid: db.group(self.group).map(|g| g.id().uuid()),
            path: self.path.clone(),
            password: self.password.clone(),
            keep_groups: false,
        }
    }
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

/// A form row: a fixed-width label followed by the field content.
///
/// egui 0.37's `Grid` clamps a widget's available width to the *previous
/// frame's* column width, so a `TextEdit` inside a `Grid` stays at the tiny
/// initial cell width and `desired_width` can never grow it. Forms therefore
/// use manual horizontal rows with a fixed label column.
fn form_row(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui, egui::Id)) {
    ui.horizontal(|ui| {
        let label_resp = ui.add_sized(
            [190.0, ui.spacing().interact_size.y],
            egui::Label::new(label),
        );
        add(ui, label_resp.id);
    });
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
    // Universal dialog keys: Escape cancels, Enter confirms single-line
    // dialogs (the entry editor uses Cmd+Enter because of its multiline
    // notes field).
    let dialog_open = !matches!(app.dialog, Dialog::None);
    let escape_key = dialog_open && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
    // Enter confirms these dialogs. It is deliberately not consumed in
    // dialogs that don't use it (the entry editor needs Enter in its
    // multiline notes field; it uses Cmd+Enter to apply instead).
    let enter_applies = matches!(
        app.dialog,
        Dialog::ConfirmUpgrade
            | Dialog::ConfirmDeleteEntry(_)
            | Dialog::ConfirmDeleteGroup(_)
            | Dialog::ConfirmEmptyRecycleBin
            | Dialog::DbInfo
            | Dialog::Shortcuts
            | Dialog::SshAgent
            | Dialog::Browser
            | Dialog::GroupNew(_)
            | Dialog::GroupRename(_)
            | Dialog::NewDb(_)
            | Dialog::SaveAs(_)
            | Dialog::BatchMove(_)
            | Dialog::ShareGroup(_)
    );
    let enter_key = dialog_open && enter_applies && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter));
    let cmd_enter_key = matches!(app.dialog, Dialog::EntryEdit(_))
        && ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter));

    if dialog_open && escape_key {
        app.dialog = Dialog::None;
        app.status = "Cancelled".into();
        return;
    }

    // Confirmation dialogs: Enter confirms immediately.
    if dialog_open && enter_key {
        match &app.dialog {
            Dialog::ConfirmUpgrade => {
                app.dialog = Dialog::None;
                app.upgrade_confirmed = true;
                app.perform_save(None);
                return;
            }
            Dialog::ConfirmDeleteEntry(id) => {
                let id = *id;
                app.dialog = Dialog::None;
                app.delete_entry(id);
                return;
            }
            Dialog::ConfirmDeleteGroup(id) => {
                let id = *id;
                app.dialog = Dialog::None;
                app.delete_group(id);
                return;
            }
            Dialog::ConfirmEmptyRecycleBin => {
                app.dialog = Dialog::None;
                app.empty_recycle_bin();
                return;
            }
            Dialog::DbInfo | Dialog::Shortcuts | Dialog::SshAgent | Dialog::Browser => {
                app.dialog = Dialog::None;
                return;
            }
            _ => {}
        }
    }

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
                .default_width(880.0)
                .show(ctx, |ui| {
                    form_row(ui, "Title:", |ui, id| {
                        let r = ui.add(egui::TextEdit::singleline(&mut d.title).desired_width(600.0));
                        r.labelled_by(id);
                    });
                    form_row(ui, "UserName:", |ui, id| {
                        let r = ui.add(egui::TextEdit::singleline(&mut d.username).desired_width(600.0));
                        r.labelled_by(id);
                    });
                    form_row(ui, "Password:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.password)
                                .password(!d.show_password)
                                .hint_text("password")
                                .desired_width(600.0),
                        );
                        r.labelled_by(id);
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
                    });
                    form_row(ui, "URL:", |ui, id| {
                        let r = ui.add(egui::TextEdit::singleline(&mut d.url).desired_width(600.0));
                        r.labelled_by(id);
                    });
                    form_row(ui, "Tags:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.tags)
                                .hint_text("comma,separated")
                                .desired_width(600.0),
                        );
                        r.labelled_by(id);
                    });
                    form_row(ui, "Notes:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::multiline(&mut d.notes)
                                .desired_rows(5)
                                .desired_width(600.0),
                        );
                        r.labelled_by(id);
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
                                egui::TextEdit::singleline(&mut a.value).password(a.protected).desired_width(300.0),
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
            if cmd_enter_key {
                apply = true;
            }
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
            if enter_key {
                apply = true;
            }
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
            if enter_key {
                apply = true;
            }
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
            if enter_key && !path.trim().is_empty() {
                save = true;
            }
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
                    form_row(ui, "File path:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.path)
                                .hint_text("/path/to/new-database.kdbx")
                                .desired_width(600.0),
                        );
                        r.labelled_by(id);
                    });
                    form_row(ui, "Database name:", |ui, id| {
                        let r = ui.add(egui::TextEdit::singleline(&mut d.name).desired_width(600.0));
                        r.labelled_by(id);
                    });
                    form_row(ui, "Password:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.password)
                                .password(true)
                                .desired_width(600.0),
                        );
                        r.labelled_by(id);
                    });
                    form_row(ui, "Repeat password:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.password_repeat)
                                .password(true)
                                .desired_width(600.0),
                        );
                        r.labelled_by(id);
                    });
                    form_row(ui, "Key file (optional):", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.key_file)
                                .hint_text("generated if missing")
                                .desired_width(600.0),
                        );
                        r.labelled_by(id);
                    });
                    form_row(ui, "Argon2 iterations:", |ui, id| {
                        let r = ui.add(egui::DragValue::new(&mut d.iterations).range(1..=1_000_000));
                        r.labelled_by(id);
                    });
                    form_row(ui, "Argon2 memory (MiB):", |ui, id| {
                        let r = ui.add(egui::DragValue::new(&mut d.memory_mib).range(8..=1024));
                        r.labelled_by(id);
                    });
                    form_row(ui, "Argon2 parallelism:", |ui, id| {
                        let r = ui.add(egui::DragValue::new(&mut d.parallelism).range(1..=8));
                        r.labelled_by(id);
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
                    if enter_key {
                        match d.validate() {
                            Ok(()) => create = true,
                            Err(e) => d.error = e,
                        }
                    }
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
            if enter_key && bm.target.is_some() {
                move_clicked = true;
            }
            if move_clicked {
                if let Some(gid) = bm.target {
                    app.move_entries_to(&bm.entries, gid);
                }
            } else if !cancelled && open {
                app.dialog = Dialog::BatchMove(bm);
            }
        }
        Dialog::SshAgent => {
            let mut open = true;
            let mut close_clicked = false;
            let mut start_clicked = false;
            let mut stop_clicked = false;
            egui::Window::new("SSH Agent")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    // Detect SSH keys in entry attachments (live, so new
                    // attachments appear without reopening the window).
                    let (identities, skipped) = app
                        .db
                        .as_ref()
                        .map(kpxc_ssh_agent::openssh::collect_identities)
                        .unwrap_or_default();

                    ui.label(
                        "SSH keys attached to entries are served over the ssh-agent protocol, \
                         like KeePassXC's SSH agent integration.",
                    );
                    ui.separator();

                    if identities.is_empty() {
                        ui.label("No SSH keys found in entry attachments.");
                        ui.weak(
                            "Attach an OpenSSH private key (e.g. id_ed25519) to an entry to serve it. \
                             Supported: unencrypted ssh-ed25519.",
                        );
                    } else {
                        ui.label(format!("{} SSH key(s) available:", identities.len()));
                        egui::Grid::new("ssh-keys").num_columns(2).striped(true).show(ui, |ui| {
                            for identity in &identities {
                                ui.strong(&identity.comment);
                                ui.weak(format!(
                                    "ssh-ed25519 SHA256:{}",
                                    identity.fingerprint_sha256()
                                ));
                                ui.end_row();
                            }
                        });
                    }
                    for note in &skipped {
                        ui.colored_label(egui::Color32::RED, format!("skipped: {note}"));
                    }

                    ui.separator();
                    if app.ssh_handle.is_some() {
                        ui.label(format!("Serving on: {}", app.ssh_socket));
                        ui.weak(format!("Use: export SSH_AUTH_SOCK={}", app.ssh_socket));
                        // Refresh the served identities from the live database.
                        if let Some(pool) = app.ssh_pool.clone() {
                            let _ = pool.lock().map(|mut p| *p = identities);
                        }
                        if ui.button("Stop serving").clicked() {
                            stop_clicked = true;
                        }
                    } else {
                        let l = ui.label("Socket path:");
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut app.ssh_socket)
                                .hint_text("/tmp/kpxc-ssh-agent.sock"),
                        );
                        r.labelled_by(l.id);
                        let start = ui.add_enabled(!identities.is_empty(), egui::Button::new("Start serving"));
                        if start.clicked() {
                            start_clicked = true;
                        }
                    }
                    ui.add_space(6.0);
                    if ui.button("Close").clicked() {
                        close_clicked = true;
                    }
                });

            if start_clicked {
                let (pool, _skipped) = app
                    .db
                    .as_ref()
                    .map(kpxc_ssh_agent::pool_from_database)
                    .unwrap();
                let path = std::path::PathBuf::from(&app.ssh_socket);
                match kpxc_ssh_agent::start(&path, pool.clone()) {
                    Ok(handle) => {
                        app.ssh_handle = Some(handle);
                        app.ssh_pool = Some(pool);
                        app.status = format!("SSH agent serving on {}", app.ssh_socket);
                    }
                    Err(e) => app.status = format!("cannot start SSH agent: {e:#}"),
                }
            }
            if stop_clicked {
                if let Some(handle) = app.ssh_handle.take() {
                    handle.stop();
                    app.ssh_pool = None;
                    app.status = "SSH agent stopped".into();
                }
            }
            if !close_clicked && open {
                app.dialog = Dialog::SshAgent;
            }
        }
        Dialog::Browser => {
            let mut open = true;
            let mut close_clicked = false;
            let mut start_clicked = false;
            let mut stop_clicked = false;
            egui::Window::new("Browser Integration")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(
                        "Serve the KeepassXC-Browser protocol on the same socket the shipped \
                         keepassxc-proxy connects to, so the real browser extension can fill \
                         credentials from this database.",
                    );
                    ui.separator();
                    let associations = app
                        .browser_state
                        .as_ref()
                        .and_then(|s| s.lock().ok().map(|s| s.associations.len()))
                        .unwrap_or(0);
                    if app.browser_handle.is_some() {
                        ui.label(format!(
                            "Serving on: {}",
                            kpxc_browser::browser_server_path().display()
                        ));
                        ui.weak(format!("{associations} associated browser client(s)"));
                        // Refresh the served snapshot from the live database.
                        if let Some(state) = app.browser_state.clone() {
                            if let Some(db) = app.db.as_ref() {
                                let snapshot = kpxc_browser::snapshot_from_database(db);
                                let _ = state.lock().map(|mut s| {
                                    s.entries = snapshot.entries;
                                    if !snapshot.db_hash.is_empty() {
                                        s.db_hash = snapshot.db_hash;
                                    }
                                });
                            }
                        }
                        if ui.button("Stop serving").clicked() {
                            stop_clicked = true;
                        }
                    } else {
                        ui.label("Browser integration is not running.");
                        if ui.button("Start serving").clicked() {
                            start_clicked = true;
                        }
                    }
                    ui.add_space(6.0);
                    if ui.button("Close").clicked() {
                        close_clicked = true;
                    }
                });

            if start_clicked {
                let state: kpxc_browser::SharedState = std::sync::Arc::new(std::sync::Mutex::new(
                    app.db
                        .as_ref()
                        .map(kpxc_browser::snapshot_from_database)
                        .unwrap_or_default(),
                ));
                let path = kpxc_browser::browser_server_path();
                match kpxc_browser::start(&path, state.clone()) {
                    Ok(handle) => {
                        app.browser_handle = Some(handle);
                        app.browser_state = Some(state);
                        app.status =
                            format!("Browser protocol serving on {}", path.display());
                    }
                    Err(e) => app.status = format!("cannot start browser server: {e:#}"),
                }
            }
            if stop_clicked {
                if let Some(handle) = app.browser_handle.take() {
                    handle.stop();
                    app.browser_state = None;
                    app.status = "Browser integration stopped".into();
                }
            }
            if !close_clicked && open {
                app.dialog = Dialog::Browser;
            }
        }
        Dialog::ShareGroup(mut d) => {
            let mut open = true;
            let mut cancelled = false;
            let mut saved = false;
            let mut export_clicked = false;
            let mut import_clicked = false;
            egui::Window::new(format!("Share Group “{}”", d.group_name))
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(
                        "KeeShare (classic shares): the group subtree is exported to a KDBX \
                         container protected by the share password, and can be imported back \
                         (entries are matched by UUID).",
                    );
                    ui.weak(
                        "Paths ending in .kdbx.share produce a SIGNED ZIP container \
                         (container.share.kdbx + container.share.signature, RSA PKCS#1 v1.5 \
                         SHA-256) signed with the local X.509 identity; signed containers are \
                         verified on import.",
                    );
                    ui.separator();
                    let l = ui.label("Share container path:");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut d.path).hint_text("/path/to/share.kdbx"),
                    );
                    r.labelled_by(l.id);
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("KeePass database", &["kdbx"])
                            .set_file_name("share.kdbx")
                            .save_file()
                        {
                            d.path = p.display().to_string();
                        }
                    }
                    let l = ui.label("Share password:");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut d.password).password(!d.show_password),
                    );
                    r.labelled_by(l.id);
                    if ui.button(if d.show_password { "Hide" } else { "Show" }).clicked() {
                        d.show_password = !d.show_password;
                    }
                    ui.checkbox(&mut d.import, "Import from the container");
                    ui.checkbox(&mut d.export, "Export to the container");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let can_run = !d.path.trim().is_empty() && !d.password.is_empty();
                        if ui
                            .add_enabled(can_run, egui::Button::new("Export now"))
                            .clicked()
                        {
                            export_clicked = true;
                        }
                        if ui
                            .add_enabled(can_run, egui::Button::new("Import now"))
                            .clicked()
                        {
                            import_clicked = true;
                        }
                    });
                    if !d.message.is_empty() {
                        ui.add_space(4.0);
                        ui.label(&d.message);
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui
                            .add_enabled(
                                !d.path.trim().is_empty() && !d.password.is_empty(),
                                egui::Button::new("Save settings"),
                            )
                            .clicked()
                        {
                            saved = true;
                        }
                    });
                });

            if export_clicked {
                if let Some(db) = app.db.as_ref() {
                    let path = std::path::Path::new(&d.path);
                    let signed = d.path.ends_with(".kdbx.share");
                    let result = if signed {
                        kpxc::keeshare_signed::load_or_create_identity("KeePassXC-RS").and_then(
                            |identity| {
                                let info = kpxc::keeshare_signed::export_signed(
                                    db, d.group, path, &d.password, &identity,
                                )?;
                                Ok((info, Some(identity.signer)))
                            },
                        )
                    } else {
                        kpxc::keeshare::export_share(db, d.group, path, &d.password)
                            .map(|info| (info, None))
                    };
                    match result {
                        Ok((info, signer)) => {
                            d.message = match signer {
                                Some(signer) => format!(
                                    "Exported {} entries to a SIGNED container as {signer} ({})",
                                    info.entries,
                                    info.path.display()
                                ),
                                None => format!(
                                    "Exported {} entries ({} groups) to {}",
                                    info.entries,
                                    info.groups,
                                    info.path.display()
                                ),
                            };
                            app.status = d.message.clone();
                            // Persist the reference with the export settings.
                            if let Some(db) = app.db.as_mut() {
                                let reference = kpxc::keeshare::ShareReference {
                                    import: d.import,
                                    export: d.export,
                                    group_uuid: db.group(d.group).map(|g| g.id().uuid()),
                                    path: d.path.clone(),
                                    password: d.password.clone(),
                                    keep_groups: false,
                                };
                                kpxc::keeshare::set_reference(db, d.group, &reference);
                                app.dirty = true;
                            }
                        }
                        Err(e) => d.message = format!("export failed: {e:#}"),
                    }
                }
            }
            if import_clicked {
                if let Some(db) = app.db.as_mut() {
                    let path = std::path::Path::new(&d.path);
                    let is_zip = std::fs::read(path)
                        .map(|b| kpxc::keeshare_signed::is_signed_container(&b))
                        .unwrap_or(false);
                    let result = if is_zip {
                        kpxc::keeshare_signed::import_signed(db, d.group, path, &d.password).map(
                            |info| {
                                format!(
                                    "Verified signed container from '{}'; imported: {} added, {} updated",
                                    info.signer, info.import.added, info.import.updated
                                )
                            },
                        )
                    } else {
                        kpxc::keeshare::import_share(db, d.group, path, &d.password).map(|info| {
                            format!("Imported: {} added, {} updated", info.added, info.updated)
                        })
                    };
                    match result {
                        Ok(message) => {
                            d.message = message;
                            app.status = d.message.clone();
                            app.dirty = true;
                        }
                        Err(e) => d.message = format!("import failed: {e:#}"),
                    }
                }
            }
            if enter_key && !d.path.trim().is_empty() && !d.password.is_empty() {
                saved = true;
            }
            if saved {
                if let Some(db) = app.db.as_mut() {
                    let reference = {
                        let r = d.reference(db);
                        r
                    };
                    kpxc::keeshare::set_reference(db, d.group, &reference);
                    app.dirty = true;
                    app.status = format!("Share settings saved for group '{}'", d.group_name);
                }
            }
            if !cancelled && !saved && open {
                app.dialog = Dialog::ShareGroup(d);
            }
        }
        Dialog::Shortcuts => {
            let mut open = true;
            let mut close_clicked = false;
            egui::Window::new("Keyboard Shortcuts")
                .open(&mut open)
                .collapsible(false)
                .default_width(560.0)
                .show(ctx, |ui| {
                    egui::Grid::new("shortcuts-grid")
                        .num_columns(2)
                        .striped(true)
                        .spacing([24.0, 4.0])
                        .show(ui, |ui| {
                            for (keys, action) in SHORTCUTS {
                                ui.strong(*keys);
                                ui.label(*action);
                                ui.end_row();
                            }
                        });
                    ui.add_space(6.0);
                    ui.weak("Shortcuts are ignored while a text field has focus. Cmd is Ctrl on Windows/Linux.");
                    ui.add_space(6.0);
                    if ui.button("Close").clicked() {
                        close_clicked = true;
                    }
                });
            if !close_clicked && open {
                app.dialog = Dialog::Shortcuts;
            }
        }
    }
}

/// The keyboard shortcut reference shown in the GUI.
pub const SHORTCUTS: &[(&str, &str)] = &[
    ("Cmd/Ctrl+C", "Copy password of the selected entry"),
    ("Cmd/Ctrl+B", "Copy username"),
    ("Cmd/Ctrl+U", "Copy URL"),
    ("Cmd/Ctrl+T", "Copy TOTP code"),
    ("Cmd/Ctrl+F", "Focus the search box"),
    ("Cmd/Ctrl+N", "New entry"),
    ("Cmd/Ctrl+Shift+N", "New group"),
    ("Cmd/Ctrl+E or Enter", "Edit the selected entry"),
    ("Cmd/Ctrl+H", "Entry history"),
    ("Cmd/Ctrl+G", "Password generator"),
    ("Delete / Backspace", "Recycle the selected entry"),
    ("Cmd/Ctrl+S", "Save the database"),
    ("Cmd/Ctrl+Shift+S", "Save as…"),
    ("Cmd/Ctrl+L", "Lock the database"),
    ("F1", "Show this shortcut reference"),
    ("Escape", "Close a dialog / clear the search"),
    ("Enter", "Confirm a dialog (Cmd+Enter in the entry editor)"),
];

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
