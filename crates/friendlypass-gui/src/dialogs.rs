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
    /// Remove one attachment from an entry (undoable via entry history).
    ConfirmDeleteAttachment(EntryId, String),
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
    /// Browser passkey registration / sign-in confirmation.
    Passkey,
    /// KeeShare: share a group via a container file.
    ShareGroup(Box<ShareDialog>),
    /// Keyboard shortcut reference.
    Shortcuts,
    /// Entry-table column configuration (visibility, order, width).
    Columns,
    /// Import XML/CSV/Bitwarden/1PUX/KDB/KDBX into the open database.
    Import(Box<ImportDialog>),
    /// Export the open database to XML/CSV/HTML.
    Export(Box<ExportDialog>),
    /// Startup settings: launch at login and auto-unlock.
    Settings,
}

/// State of the import dialog.
pub struct ImportDialog {
    pub path: String,
    pub format: String,
    pub password: String,
    pub error: String,
}

impl Default for ImportDialog {
    fn default() -> Self {
        ImportDialog {
            path: String::new(),
            format: "Auto-detect".into(),
            password: String::new(),
            error: String::new(),
        }
    }
}

impl ImportDialog {
    fn format(&self) -> Option<friendlypass::import::ImportFormat> {
        match self.format.as_str() {
            "Auto-detect" => friendlypass::import::ImportFormat::from_path(std::path::Path::new(self.path.trim())),
            "KeePass 2 XML" => Some(friendlypass::import::ImportFormat::Xml),
            "CSV" => Some(friendlypass::import::ImportFormat::Csv),
            "Bitwarden JSON" => Some(friendlypass::import::ImportFormat::Bitwarden),
            "Proton Pass JSON" => Some(friendlypass::import::ImportFormat::ProtonPass),
            "1Password 1PUX" => Some(friendlypass::import::ImportFormat::OnePux),
            "KeePass 1 (KDB)" => Some(friendlypass::import::ImportFormat::Kdb),
            "KeePass 2 (KDBX)" => Some(friendlypass::import::ImportFormat::Kdbx),
            _ => None,
        }
    }

    fn is_encrypted(&self) -> bool {
        matches!(
            self.format(),
            Some(friendlypass::import::ImportFormat::Kdb | friendlypass::import::ImportFormat::Kdbx)
        )
    }
}

/// State of the export dialog.
pub struct ExportDialog {
    pub path: String,
    pub format: String,
    pub error: String,
    /// Export only this group (and its subtree); `None` exports the database.
    pub group: Option<GroupId>,
    pub group_name: String,
}

impl ExportDialog {
    pub fn new(database_path: &str, format: &str) -> Self {
        let mut dialog = ExportDialog {
            path: String::new(),
            format: format.to_owned(),
            error: String::new(),
            group: None,
            group_name: String::new(),
        };
        dialog.update_default_path(database_path);
        dialog
    }

    /// Export a single group (or the whole database when `group` is None).
    pub fn for_group(
        database_path: &str,
        group: Option<GroupId>,
        group_name: &str,
        format: &str,
    ) -> Self {
        let mut dialog = ExportDialog {
            path: String::new(),
            format: format.to_owned(),
            error: String::new(),
            group,
            group_name: group_name.to_owned(),
        };
        dialog.update_default_path(database_path);
        dialog
    }

    fn update_default_path(&mut self, database_path: &str) {
        let ext = match self.format.as_str() {
            "CSV" => "csv",
            "HTML" => "html",
            _ => "xml",
        };
        let stem = if self.group_name.is_empty() {
            std::path::Path::new(database_path)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "database".into())
        } else {
            self.group_name
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || matches!(c, ' ' | '-' | '_') {
                        c
                    } else {
                        '_'
                    }
                })
                .collect()
        };
        let dir = std::path::Path::new(database_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        self.path = dir.join(format!("{stem}.{ext}")).display().to_string();
    }
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
        if let Some(reference) = friendlypass::keeshare::reference_of(db, group) {
            dialog.path = reference.path;
            dialog.password = reference.password;
            dialog.import = reference.import;
            dialog.export = reference.export;
        }
        dialog
    }

    fn reference(&self, db: &keepass::db::Database) -> friendlypass::keeshare::ShareReference {
        friendlypass::keeshare::ShareReference {
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

/// How the entry being edited will look in the list and details panel.
fn preview_icon_spec(d: &EntryEdit) -> crate::icons::IconSpec {
    let avatar = crate::icons::avatar_for(&d.title, &d.username, d.symbol.as_deref());
    match &d.icon {
        IconChoice::Custom(id) => {
            if let Some((_, bytes)) = d.custom_icons.iter().find(|(i, _)| i == id) {
                return crate::icons::custom_icon_spec(format!("custom-{id}"), bytes.clone(), avatar);
            }
        }
        IconChoice::NewCustom(bytes) => {
            return crate::icons::custom_icon_spec(
                "preview-custom".into(),
                bytes.clone(),
                avatar,
            );
        }
        IconChoice::None | IconChoice::Standard(_) => {}
    }
    if let Some(origin) = crate::icons::normalize_site_origin(&d.url) {
        crate::icons::IconSpec::Website { origin, avatar }
    } else {
        crate::icons::IconSpec::Avatar(avatar)
    }
}

/// Icon editor: a live preview, the optional symbol picker, and the database's
/// custom icon pool (including loading a new image from a file).
fn icon_picker(ui: &mut egui::Ui, app: &mut App, d: &mut EntryEdit) {
    let ctx = ui.ctx().clone();
    let spec = preview_icon_spec(d);
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(crate::theme::p().bg)
            .corner_radius(12)
            .inner_margin(egui::Margin::same(6))
            .show(ui, |ui| {
                crate::icons::draw_icon_sized(ui, &mut app.icon_cache, Some(&spec), 52.0);
            });
        let (label, hint) = match &spec {
            crate::icons::IconSpec::Custom { .. } => (
                "Custom icon",
                "A database custom icon takes precedence over favicons and avatars.",
            ),
            crate::icons::IconSpec::Website { .. } => (
                "Website favicon",
                "Fetched from the URL; the letter avatar shows while it loads or when the site has no favicon.",
            ),
            crate::icons::IconSpec::Avatar(_) if d.symbol.is_some() => (
                "Symbol avatar",
                "The chosen symbol replaces the title's first letter.",
            ),
            _ => (
                "Letter avatar",
                "The title's first letter (or your username) on a colour derived from the title.",
            ),
        };
        ui.vertical(|ui| {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(label).strong());
            ui.add(
                egui::Label::new(
                    egui::RichText::new(hint).size(12.0).color(crate::theme::p().muted),
                )
                .wrap(),
            );
        });
    });

    ui.horizontal(|ui| {
        ui.menu_button("Choose symbol", |ui| {
            ui.set_min_width(260.0);
            egui::Grid::new("entry-symbol-grid")
                .spacing(egui::vec2(2.0, 2.0))
                .show(ui, |ui| {
                    for (i, symbol) in crate::icons::SYMBOLS.iter().enumerate() {
                        let selected = d.symbol.as_deref() == Some(*symbol);
                        let button = egui::Button::new(
                            egui::RichText::new(*symbol).size(18.0),
                        )
                        .selected(selected)
                        .min_size(egui::vec2(28.0, 28.0));
                        if ui
                            .add(button)
                            .on_hover_text(format!("Symbol {symbol}"))
                            .clicked()
                        {
                            d.symbol = Some((*symbol).to_owned());
                            ui.close();
                        }
                        if (i + 1) % 8 == 0 {
                            ui.end_row();
                        }
                    }
                });
        });
        if ui
            .button("Use letter")
            .on_hover_text("Clear the symbol and show the first letter again")
            .clicked()
        {
            d.symbol = None;
        }
    });

    if !d.custom_icons.is_empty() {
        ui.separator();
        ui.label("Database custom icons:");
        ui.horizontal_wrapped(|ui| {
            for (id, bytes) in &d.custom_icons {
                if let Some(tex) = app.icon_cache.texture(&ctx, &format!("custom-{id}"), bytes) {
                    let selected = matches!(d.icon, IconChoice::Custom(c) if c == *id);
                    let btn =
                        egui::Button::image((tex.id(), egui::Vec2::splat(18.0))).selected(selected);
                    if ui.add(btn).on_hover_text(format!("Custom icon {id}")).clicked() {
                        d.icon = IconChoice::Custom(*id);
                    }
                }
            }
        });
    }
    ui.separator();
    let l = ui.label("Custom icon image path:");
    let r = ui.add(egui::TextEdit::singleline(&mut d.icon_path).hint_text("/path/to/icon.png"));
    r.labelled_by(l.id);
    if ui.button("Use image…").clicked() {
        match std::fs::read(d.icon_path.trim()) {
            Ok(bytes) => d.icon = IconChoice::NewCustom(bytes),
            Err(e) => app.status = format!("unable to read icon file: {e}"),
        }
    }
    if ui.button("Browse…").clicked() {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("Image", &["png", "jpg", "jpeg"])
            .pick_file()
        {
            d.icon_path = p.display().to_string();
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
            [110.0, ui.spacing().interact_size.y],
            egui::Label::new(
                egui::RichText::new(label)
                    .size(13.5)
                    .color(crate::theme::p().muted),
            ),
        );
        add(ui, label_resp.id);
    });
}

/// Apply an icon choice to an entry (works for both new and existing entries).
///
/// The KDBX `IconID` is left exactly as it was unless the user actually chose
/// a different icon: editing a title must never rewrite or reset the icon.
fn apply_entry_icon(entry: &mut keepass::db::EntryMut<'_>, choice: &IconChoice) {
    let unchanged = match (entry.icon(), choice) {
        (Some(keepass::db::Icon::BuiltIn(current)), IconChoice::Standard(chosen)) => {
            *current == *chosen
        }
        (Some(keepass::db::Icon::Custom(current)), IconChoice::Custom(chosen)) => {
            *current == *chosen
        }
        (None, IconChoice::None) => true,
        _ => false,
    };
    if unchanged {
        return;
    }
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

/// Store (or clear) the optional `friendlypass.symbol` on an entry.
fn apply_entry_symbol(
    custom_data: &mut std::collections::HashMap<String, keepass::db::CustomDataItem>,
    symbol: Option<&str>,
) {
    use keepass::db::{CustomDataItem, CustomDataValue};
    let key = crate::icons::SYMBOL_CUSTOM_DATA_KEY;
    match symbol.map(str::trim).filter(|s| !s.is_empty()) {
        Some(symbol) => {
            let unchanged = matches!(
                custom_data.get(key).and_then(|item| item.value.as_ref()),
                Some(CustomDataValue::String(current)) if current == symbol
            );
            if !unchanged {
                custom_data.insert(
                    key.to_owned(),
                    CustomDataItem {
                        value: Some(CustomDataValue::String(symbol.to_owned())),
                        last_modification_time: Some(chrono::Utc::now().naive_utc()),
                    },
                );
            }
        }
        None => {
            custom_data.remove(key);
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
    /// Icon selection (custom icons); standard icon IDs are preserved as-is.
    pub icon: IconChoice,
    /// Optional single-glyph avatar symbol (`friendlypass.symbol`).
    pub symbol: Option<String>,
    pub icon_path: String,
    /// Custom icon pool snapshot (for the picker strip).
    pub custom_icons: Vec<(CustomIconId, Vec<u8>)>,
    /// Entry-reference insertion state.
    pub ref_targets: Vec<RefTarget>,
    pub ref_target: Option<usize>,
    pub ref_field: char,
    pub ref_into: char,
    /// Collapsible editor sections (collapsed by default).
    pub show_autotype: bool,
    pub show_references: bool,
    pub show_icon: bool,
    /// Focus the Title field on the next frame (new entries).
    pub focus_title: bool,
    /// The favorite marker, kept out of the attribute list (it is toggled
    /// with the star) but preserved when the edit is applied.
    pub favorite_marker: Option<keepass::db::Value<String>>,
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
            icon: IconChoice::Standard(0),
            symbol: None,
            icon_path: String::new(),
            custom_icons,
            ref_targets,
            ref_target: None,
            ref_field: refs::CODE_PASSWORD,
            ref_into: refs::CODE_NOTES,
            show_autotype: false,
            show_references: false,
            show_icon: false,
            focus_title: true,
            favorite_marker: None,
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
            .filter(|(k, _)| {
                !fields::KNOWN_FIELDS.contains(&k.as_str())
                    && k.as_str() != crate::browser::FAVORITE_FIELD
            })
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
            symbol: crate::icons::entry_symbol(entry),
            icon_path: String::new(),
            custom_icons,
            ref_targets,
            ref_target: None,
            ref_field: refs::CODE_PASSWORD,
            ref_into: refs::CODE_NOTES,
            show_autotype: false,
            show_references: false,
            show_icon: false,
            focus_title: false,
            favorite_marker: entry.fields.get(crate::browser::FAVORITE_FIELD).cloned(),
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
        if let Some(marker) = &self.favorite_marker {
            out.insert(crate::browser::FAVORITE_FIELD.to_owned(), marker.clone());
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
                    let symbol = self.symbol.clone();
                    entry.track_changes().edit(|e| {
                        e.fields = new_fields;
                        e.autotype = Some(autotype);
                        e.tags = tags;
                        apply_entry_symbol(&mut e.custom_data, symbol.as_deref());
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
                    apply_entry_symbol(&mut entry.custom_data, self.symbol.as_deref());
                    let id = entry.id();
                    app.dirty = true;
                    app.status = format!("Added entry '{}'", self.title);
                    app.selected_entry = Some(id);
                }
            }
        }
    }
}

/// The entry editor form, shared by the New Entry modal and the inline
/// right-column editor. Buttons are supplied by the caller.
pub fn entry_edit_body(ui: &mut egui::Ui, app: &mut App, d: &mut EntryEdit) {
                    let field_width = (ui.available_width() - 125.0).max(160.0);
                    form_row(ui, "Title:", |ui, id| {
                        let r = ui.add(egui::TextEdit::singleline(&mut d.title).desired_width(field_width));
                        // A new entry starts with the cursor in the title.
                        if std::mem::take(&mut d.focus_title) {
                            r.request_focus();
                        }
                        r.labelled_by(id);
                    });
                    form_row(ui, "Username:", |ui, id| {
                        let r = ui.add(egui::TextEdit::singleline(&mut d.username).desired_width(field_width));
                        r.labelled_by(id);
                    });
                    form_row(ui, "Password:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.password)
                                .password(!d.show_password)
                                .hint_text("password")
                                .desired_width((field_width - 170.0).max(100.0)),
                        );
                        r.labelled_by(id);
                        if ui.button("Generate").clicked() {
                            d.password = friendlypass::commands::generate_password_opts(24, true, true, true, true);
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
                        let r = ui.add(egui::TextEdit::singleline(&mut d.url).desired_width(field_width));
                        r.labelled_by(id);
                    });
                    form_row(ui, "Tags:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.tags)
                                .hint_text("comma,separated")
                                .desired_width(field_width),
                        );
                        r.labelled_by(id);
                    });
                    form_row(ui, "Notes:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::multiline(&mut d.notes)
                                .desired_rows(5)
                                .desired_width(field_width),
                        );
                        r.labelled_by(id);
                    });

                    // --- custom attributes -----------------------------------
                    ui.separator();
                    ui.strong("Custom attributes");
                    let mut remove_attr: Option<usize> = None;
                    for (i, a) in d.attributes.iter_mut().enumerate() {
                        egui::Frame::new()
                            .fill(crate::theme::p().bg)
                            .corner_radius(8)
                            .inner_margin(egui::Margin::symmetric(8, 6))
                            .show(ui, |ui| {
                                let l = ui.label(format!("Attribute {i} key:"));
                                let width = ui.available_width();
                                let r = ui.add(
                                    egui::TextEdit::singleline(&mut a.key)
                                        .desired_width(width),
                                );
                                r.labelled_by(l.id);
                                let l = ui.label(format!("Attribute {i} value:"));
                                let width = ui.available_width();
                                let r = ui.add(
                                    egui::TextEdit::singleline(&mut a.value)
                                        .password(a.protected)
                                        .desired_width(width),
                                );
                                r.labelled_by(l.id);
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut a.protected, format!("Protected {i}"));
                                    if ui.button(format!("Remove attribute {i}")).clicked() {
                                        remove_attr = Some(i);
                                    }
                                });
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
                    // Auto-Type, References and Icon are rarely needed, so
                    // they sit behind collapsed disclosures.
                    ui.separator();
                    crate::theme::disclosure(ui, "edit-autotype", "Auto-Type settings", &mut d.show_autotype);
                    if d.show_autotype {
                    ui.checkbox(&mut d.at_enabled, "Auto-Type enabled");
                    ui.horizontal(|ui| {
                        let l = ui.label("Default sequence:");
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.at_default_sequence)
                                .hint_text("{USERNAME}{TAB}{PASSWORD}{ENTER}")
                                .desired_width(field_width),
                        );
                        r.labelled_by(l.id);
                    });
                    ui.checkbox(&mut d.at_obfuscate, "Obfuscate using the clipboard");
                    let mut remove_assoc: Option<usize> = None;
                    for (i, a) in d.at_associations.iter_mut().enumerate() {
                        egui::Frame::new()
                            .fill(crate::theme::p().bg)
                            .corner_radius(8)
                            .inner_margin(egui::Margin::symmetric(8, 6))
                            .show(ui, |ui| {
                                let l = ui.label(format!("Window {i}:"));
                                let width = ui.available_width();
                                let r = ui.add(
                                    egui::TextEdit::singleline(&mut a.window)
                                        .hint_text("* - Notepad")
                                        .desired_width(width),
                                );
                                r.labelled_by(l.id);
                                let l = ui.label(format!("Sequence {i}:"));
                                let width = ui.available_width();
                                let r = ui.add(
                                    egui::TextEdit::singleline(&mut a.sequence)
                                        .desired_width(width),
                                );
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

                    }

                    // --- entry references -------------------------------------
                    crate::theme::disclosure(ui, "edit-references", "References", &mut d.show_references);
                    if d.show_references {
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

                    }

                    // --- icon picker ---------------------------------------------
                    crate::theme::disclosure(ui, "edit-icon", "Icon", &mut d.show_icon);
                    if d.show_icon {
                        icon_picker(ui, app, d);
                    }

}

/// The pinned header of the inline entry editor: the title on the left,
/// Cancel and the primary button ("Create" for a new entry, "Save" for an
/// edit) on the right. It stays put while the form below scrolls.
/// Returns `(apply, cancel)`.
pub fn entry_edit_inline_header(ui: &mut egui::Ui, is_new: bool) -> (bool, bool) {
    let mut apply = false;
    let mut cancelled = false;
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(if is_new { "New Item" } else { "Edit Item" })
                .size(24.0)
                .strong()
                .color(crate::theme::p().text),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(crate::theme::primary_button(if is_new { "Create" } else { "Save" }))
                .on_hover_text("Cmd/Ctrl+Enter")
                .clicked()
            {
                apply = true;
            }
            if ui
                .button("Cancel")
                .on_hover_text("Discard the changes (Escape)")
                .clicked()
            {
                cancelled = true;
            }
        });
    });
    ui.add(egui::Separator::default().spacing(8.0));
    (apply, cancelled)
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
            preview: friendlypass::commands::generate_password_opts(24, true, true, true, true),
        }
    }
}

impl Generator {
    pub fn regenerate(&mut self) {
        self.preview = friendlypass::commands::generate_password_opts(
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

/// Show a dialog: centred over a dimmed backdrop that blocks the rest of the
/// window (egui's [`egui::Modal`]), with a title row and a close button.
/// Tall content scrolls inside the dialog. Returns `false` once the close
/// button was clicked. (Escape and Enter are handled by [`show`].)
fn modal_window(
    ctx: &egui::Context,
    id_salt: &str,
    title: &str,
    width: f32,
    add: impl FnOnce(&mut egui::Ui),
) -> bool {
    let pal = crate::theme::p();
    let screen = ctx.content_rect();
    let width = width.min(screen.width() - 48.0).max(240.0);
    let max_h = (screen.height() - 140.0).max(160.0);
    let mut open = true;
    let frame = egui::Frame::window(&ctx.global_style())
        .fill(pal.panel)
        .inner_margin(egui::Margin::symmetric(20, 16));
    egui::Modal::new(egui::Id::new(("friendlypass-dialog", id_salt)))
        .backdrop_color(pal.backdrop)
        .frame(frame)
        .show(ctx, |ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(title).size(17.0).strong().color(pal.text));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if crate::theme::icon_button(
                        ui,
                        "dialog-close",
                        "Close dialog",
                        false,
                        crate::theme::draw_close_icon,
                    )
                    .clicked()
                    {
                        open = false;
                    }
                });
            });
            ui.add_space(6.0);
            // The modal is centred using last frame's size, so the space
            // below its top edge can be smaller than its content. Asking for
            // at least the content height (capped at `max_h`) lets it grow
            // and re-centre instead of staying clipped.
            let key = egui::Id::new(("dialog-content-h", id_salt));
            let prev = ui.ctx().data(|d| d.get_temp::<f32>(key));
            let out = egui::ScrollArea::vertical()
                .id_salt(("dialog-scroll", id_salt))
                .max_height(max_h)
                .min_scrolled_height(prev.unwrap_or(0.0).min(max_h))
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.set_width(width - 4.0);
                    add(ui);
                });
            // The scroll area sizes itself from the previous frame's content;
            // when the content grows or shrinks (e.g. "Start serving" adds
            // rows), ask for one more frame so the dialog never stays clipped.
            let h = out.content_size.y;
            if prev.is_none_or(|p| (p - h).abs() > 0.5) {
                ui.ctx().data_mut(|d| d.insert_temp(key, h));
                ui.ctx().request_repaint();
            }
        });
    open
}

/// Placeholder for a settings dialog whose feature needs Unix domain sockets.
/// The menu entries stay visible so the limitation is discoverable; the dialog
/// itself is replaced by this short note.
#[cfg(windows)]
fn unavailable_dialog(
    ctx: &egui::Context,
    app: &mut App,
    dialog: Dialog,
    title: &str,
    message: &str,
) {
    let mut close_clicked = false;
    let open = modal_window(ctx, "unavailable-feature", title, 460.0, |ui| {
        ui.label(egui::RichText::new("Not available on Windows yet").strong());
        ui.add_space(4.0);
        ui.label(message);
        ui.add_space(6.0);
        if ui.button("Close").clicked() {
            close_clicked = true;
        }
    });
    if !close_clicked && open {
        app.dialog = dialog;
    }
}

/// Render whatever dialog is currently open.
pub fn show(app: &mut App, ctx: &egui::Context) {
    // Universal dialog keys: Escape cancels, Enter confirms single-line
    // dialogs. (The entry editor is not a dialog: it lives inline in the
    // details pane and handles Cmd+Enter / Escape itself.)
    let dialog_open = !matches!(app.dialog, Dialog::None);
    let escape_key = dialog_open && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
    // Enter confirms these dialogs. It is deliberately not consumed in
    // dialogs that don't use it.
    let enter_applies = matches!(
        app.dialog,
        Dialog::ConfirmUpgrade
            | Dialog::ConfirmDeleteEntry(_)
            | Dialog::ConfirmDeleteAttachment(..)
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
            | Dialog::Columns
            | Dialog::Import(_)
            | Dialog::Export(_)
            | Dialog::Settings
    );
    let enter_key = dialog_open && enter_applies && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter));

    if dialog_open && escape_key {
        if matches!(app.dialog, Dialog::Passkey) {
            crate::browser_bridge::deny_passkey(app);
            return;
        }
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
            Dialog::ConfirmDeleteAttachment(id, name) => {
                let (id, name) = (*id, name.clone());
                app.dialog = Dialog::None;
                if let Err(e) = app.remove_entry_attachment(id, &name) {
                    app.status = format!("unable to remove attachment: {e:#}");
                }
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
            Dialog::DbInfo | Dialog::Shortcuts | Dialog::SshAgent | Dialog::Browser | Dialog::Columns | Dialog::Settings => {
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
        Dialog::GroupNew(mut d) => {
            let open: bool;
            let mut apply = false;
            let mut cancelled = false;
            open = modal_window(ctx, "new-group", "New Group", 460.0, |ui| {
                    let l = ui.label("Group name:");
                    let r = ui.text_edit_singleline(&mut d.name);
                    r.labelled_by(l.id);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.add(crate::theme::primary_button("Create")).clicked() {
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
        Dialog::GroupRename(mut d) => {            let open: bool;
            let mut apply = false;
            let mut cancelled = false;
            open = modal_window(ctx, "rename-group", "Rename Group", 460.0, |ui| {
                    let l = ui.label("Group name:");
                    let r = ui.text_edit_singleline(&mut d.name);
                    r.labelled_by(l.id);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.add(crate::theme::primary_button("Rename")).clicked() {
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
            if !apply && !cancelled && open {
                app.dialog = Dialog::GroupRename(d);
            }
        }
        Dialog::Generator(mut g) => {
            let open: bool;
            let mut copy = false;
            open = modal_window(ctx, "password-generator", "Password Generator", 460.0, |ui| {
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
            let open: bool;
            let mut close_clicked = false;
            open = modal_window(ctx, "database-information", "Database Information", 460.0, |ui| {
                    if let Some(db) = app.db.as_ref() {
                        egui::Grid::new("db-info").num_columns(2).show(ui, |ui| {
                            for (k, v) in [
                                ("Version", friendlypass::commands::version_string(&db.config.version)),
                                ("Cipher", friendlypass::commands::outer_cipher_name(&db.config.outer_cipher_config).to_owned()),
                                (
                                    "Compression",
                                    friendlypass::commands::compression_name(&db.config.compression_config).to_owned(),
                                ),
                                (
                                    "Inner cipher",
                                    friendlypass::commands::inner_cipher_name(&db.config.inner_cipher_config).to_owned(),
                                ),
                                ("KDF", friendlypass::commands::kdf_name(&db.config.kdf_config)),
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
            let open: bool;
            let mut save = false;
            let mut cancelled = false;
            open = modal_window(ctx, "save-database-as", "Save Database As", 460.0, |ui| {
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
                        if ui.add(crate::theme::primary_button("Save")).clicked() {
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
            let open: bool;
            let mut create = false;
            let mut cancelled = false;
            open = modal_window(ctx, "create-new-database", "Create New Database", 760.0, |ui| {
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
                        ui.colored_label(crate::theme::p().danger, &validation_error);
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.add(crate::theme::primary_button("Create")).clicked() {
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
            let open: bool;
            let mut confirmed = false;
            let mut cancelled = false;
            open = modal_window(ctx, "upgrade-database-format", "Upgrade Database Format", 460.0, |ui| {
                    ui.label("This database uses the older KDBX 3.1 format.");
                    ui.label("Saving requires upgrading it to KDBX 4.1 (KeePassXC's current format).");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.add(crate::theme::primary_button("Upgrade and Save")).clicked() {
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
            let open: bool;
            let mut confirmed = false;
            let mut cancelled = false;
            // Word the confirmation like KeePassXC does.
            let to_recycle = app.deletes_to_recycle_bin_entry(id);
            open = modal_window(ctx, "delete-entry", "Delete Entry", 460.0, |ui| {
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
                        if ui
                            .add(crate::theme::danger_button(if to_recycle { "Move to Recycle Bin" } else { "Delete" }))
                            .clicked()
                        {
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
        Dialog::ConfirmDeleteAttachment(id, name) => {
            let open: bool;
            let mut confirmed = false;
            let mut cancelled = false;
            let size = app
                .db
                .as_ref()
                .and_then(|db| db.entry(id))
                .and_then(|e| e.attachment_by_name(&name).map(|a| a.data.get().len()));
            open = modal_window(ctx, "delete-attachment", "Delete Attachment", 460.0, |ui| {
                    ui.label(format!("Remove the attachment \"{name}\" from this entry?"));
                    if let Some(size) = size {
                        ui.weak(format!("{} of data.", crate::app::format_size(size)));
                    }
                    ui.weak(
                        "The entry's history keeps the previous version, so this can be \
                         restored from Entry History.",
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.add(crate::theme::danger_button("Delete")).clicked() {
                            confirmed = true;
                        }
                    });
                });
            if confirmed {
                if let Err(e) = app.remove_entry_attachment(id, &name) {
                    app.status = format!("unable to remove attachment: {e:#}");
                }
            } else if !cancelled && open {
                app.dialog = Dialog::ConfirmDeleteAttachment(id, name);
            }
        }
        Dialog::ConfirmDeleteGroup(id) => {
            let open: bool;
            let mut confirmed = false;
            let mut cancelled = false;
            open = modal_window(ctx, "delete-group", "Delete Group", 460.0, |ui| {
                    ui.label("Delete this group and all its contents? This cannot be undone.");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.add(crate::theme::danger_button("Delete")).clicked() {
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

            let open: bool;
            let mut cancelled = false;
            let mut restore: Option<usize> = None;
            open = modal_window(ctx, "entry-history", "Entry History", 600.0, |ui| {
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
                                ui.strong("Username");
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

            let open: bool;
            let mut confirmed = false;
            let mut cancelled = false;
            open = modal_window(ctx, "empty-the-recycle-bin", "Empty the Recycle Bin?", 460.0, |ui| {
                    ui.label(format!("Permanently remove all {count} objects from the Recycle Bin?"));
                    ui.weak("This cannot be undone.");
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.add(crate::theme::danger_button("Empty Recycle Bin")).clicked() {
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
            let open: bool;
            let mut cancelled = false;
            let mut move_clicked = false;
            let batch_title = if bm.entries.len() == 1 {
                "Move Entry to Group".to_owned()
            } else {
                format!("Move {} Entries to Group", bm.entries.len())
            };
            open = modal_window(ctx, "batch-move", &batch_title, 460.0, |ui| {
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
            #[cfg(windows)]
            {
                unavailable_dialog(
                    ctx,
                    app,
                    Dialog::SshAgent,
                    "SSH Agent",
                    "The SSH agent serves keys over a Unix domain socket. A Windows \
                     named-pipe transport is planned; this build does not provide the \
                     agent yet.",
                );
            }
            #[cfg(not(windows))]
            {
            // Unix: the real agent UI (keys, socket path, start/stop).
            let open: bool;
            let mut close_clicked = false;
            let mut start_clicked = false;
            let mut stop_clicked = false;
            open = modal_window(ctx, "ssh-agent", "SSH Agent", 560.0, |ui| {
                    // Detect SSH keys in entry attachments (live, so new
                    // attachments appear without reopening the window).
                    let (identities, skipped) = app
                        .db
                        .as_ref()
                        .map(friendlypass_ssh_agent::openssh::collect_identities)
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
                        ui.colored_label(crate::theme::p().danger, format!("skipped: {note}"));
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
                                .hint_text("/tmp/friendlypass-ssh-agent.sock"),
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
                    .map(friendlypass_ssh_agent::pool_from_database)
                    .unwrap();
                let path = std::path::PathBuf::from(&app.ssh_socket);
                match friendlypass_ssh_agent::start(&path, pool.clone()) {
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
        }
        Dialog::Browser => {
            #[cfg(windows)]
            {
                unavailable_dialog(
                    ctx,
                    app,
                    Dialog::Browser,
                    "Browser Integration",
                    "Browser integration needs the KeePassXC-Browser app socket and \
                     Unix peer verification. Both are macOS/Linux only today; a Windows \
                     named-pipe transport is planned, so this build cannot serve the \
                     extension or passkeys.",
                );
            }
            #[cfg(not(windows))]
            {
            // Unix: the real browser-integration UI (manifests, approvals).
            let mut close_clicked = false;
            let mut start_clicked = false;
            let mut stop_clicked = false;
            let mut prefs_changed = false;
            let mut answer: Option<Option<String>> = None;
            let mut revoke: Option<String> = None;
            // Browsers whose per-user config root does not exist are shown
            // disabled and never default to ticked; no manifest (and no junk
            // directory) is written for them.
            let installed_browsers = crate::browser_bridge::installed_browsers(app);
            let open = modal_window(ctx, "browser-integration", "Browser Integration", 560.0, |ui| {
                    ui.label(egui::RichText::new("Native messaging").strong());
                    if ui
                        .checkbox(
                            &mut app.prefs.browser_integration,
                            "Enable browser integration",
                        )
                        .on_hover_text(
                            "Registers this app as the org.friendlypass.browser native \
                             host, so the friendlypass extension can reach it. The \
                             extension itself still has to be installed in each browser.",
                        )
                        .changed()
                    {
                        prefs_changed = true;
                    }
                    ui.weak(
                        "Writes a small manifest in each selected browser's own \
                         native-messaging folder. Other hosts' manifests are never touched.",
                    );
                    if ui
                        .checkbox(
                            &mut app.prefs.require_approval_for_new_browsers,
                            "Require approval for new browsers",
                        )
                        .on_hover_text(
                            "Ask before a browser connects. Off (the default), a browser \
                             launched through the friendlypass host is approved automatically \
                             and a non-blocking notice offers to revoke it.",
                        )
                        .changed()
                    {
                        prefs_changed = true;
                    }
                    ui.add_space(4.0);
                    ui.label("Browser passkeys");
                    ui.horizontal(|ui| {
                        ui.label("Default group:");
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut app.prefs.passkey_default_group)
                                .hint_text("KeePassXC-Browser Passkeys")
                                .desired_width(240.0),
                        );
                        if response.changed() {
                            prefs_changed = true;
                        }
                    });
                    if ui
                        .checkbox(
                            &mut app.prefs.allow_localhost_passkeys,
                            "Allow passkeys on localhost",
                        )
                        .on_hover_text(
                            "Permit http://localhost development sites to use this app's \
                             passkeys. WebAuthn normally requires HTTPS.",
                        )
                        .changed()
                    {
                        prefs_changed = true;
                    }
                    let browsers_enabled = app.prefs.browser_integration;
                    ui.horizontal_wrapped(|ui| {
                        for browser in friendlypass_browser::native_messaging::Browser::ALL {
                            let installed = installed_browsers.contains(&browser);
                            let mut on = installed && app.prefs.browser_enabled(browser);
                            let label = if installed {
                                browser.label().to_owned()
                            } else {
                                format!("{} (not installed)", browser.label())
                            };
                            let response = ui.add_enabled(
                                browsers_enabled && installed,
                                egui::Checkbox::new(&mut on, label),
                            );
                            let response = if installed {
                                response
                            } else {
                                response.on_hover_text(
                                    "This browser has no per-user configuration directory yet. \
                                     Start it once, then reopen this dialog.",
                                )
                            };
                            if response.changed() {
                                app.prefs.set_browser_enabled(browser, on);
                                prefs_changed = true;
                            }
                        }
                    });
                    if browsers_enabled {
                        match crate::browser_bridge::native_host_path(app) {
                            Some(path) => {
                                ui.weak(format!("Native host: {}", path.display()));
                            }
                            None => {
                                ui.weak("Native host binary not found; reinstall the app.");
                            }
                        }
                    }
                    ui.separator();
                    ui.label(
                        "Serve the KeePassXC-Browser protocol on the same socket the shipped \
                         keepassxc-proxy connects to, so the official extension and the \
                         friendlypass extension can fill credentials from this database.",
                    );
                    ui.separator();

                    if let Some((name, client_id)) = crate::browser_bridge::pending_approval(app) {
                        ui.label(
                            egui::RichText::new("A browser wants to connect")
                                .strong()
                                .size(15.0),
                        );
                        ui.label(
                            "Approve this browser once: it will be remembered in the database \
                             until you remove the association below.",
                        );
                        ui.weak(format!("Client id: {client_id}"));
                        let mut chosen = name;
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut chosen)
                                    .hint_text("Association name"),
                            )
                            .changed()
                        {
                            crate::browser_bridge::set_approval_name(app, chosen);
                        }
                        ui.horizontal(|ui| {
                            if ui.button("Approve").clicked() {
                                answer = Some(Some(
                                    crate::browser_bridge::approval_name(app),
                                ));
                            }
                            if ui.button("Deny").clicked() {
                                answer = Some(None);
                            }
                        });
                        ui.separator();
                    }

                    let associations = crate::browser_bridge::association_rows(app);
                    if app.browser_handle.is_some() {
                        ui.label(format!(
                            "Serving on: {}",
                            friendlypass_browser::browser_server_path().display()
                        ));
                    }
                    if app.browser_state.is_some() {
                        ui.weak(format!(
                            "{} associated browser client(s)",
                            associations.len()
                        ));
                        if !associations.is_empty() {
                            ui.add_space(4.0);
                            for row in &associations {
                                ui.horizontal(|ui| {
                                    ui.label(&row.id);
                                    ui.weak(format!("{} \u{00b7} {}", row.browser, row.how));
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("Remove").clicked() {
                                                revoke = Some(row.id.clone());
                                            }
                                        },
                                    );
                                });
                            }
                        }
                        ui.add_space(6.0);
                        if app.browser_handle.is_some() {
                            if ui.button("Stop serving").clicked() {
                                stop_clicked = true;
                            }
                        } else if ui.button("Start serving").clicked() {
                            start_clicked = true;
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

            if prefs_changed {
                app.save_preferences();
                crate::browser_bridge::sync_native_messaging(app);
            }
            if let Some(revoke) = revoke {
                crate::browser_bridge::revoke_association(app, &revoke);
            }
            if let Some(decision) = answer {
                crate::browser_bridge::answer_approval(app, decision);
            }
            if start_clicked {
                crate::browser_bridge::start(app);
            }
            if stop_clicked {
                crate::browser_bridge::stop(app);
            }
            if close_clicked && app.browser_bridge.is_some()
                && crate::browser_bridge::pending_approval(app).is_some()
            {
                // Closing the dialog denies the waiting connection instead of
                // leaving it until the bridge deadline.
                crate::browser_bridge::answer_approval(app, None);
            }
            if !close_clicked && open {
                app.dialog = Dialog::Browser;
            }
            }
        }
        Dialog::Passkey => {
            let Some(prompt) = crate::browser_bridge::passkey_prompt(app) else {
                app.dialog = Dialog::None;
                return;
            };
            let mut selection = crate::browser_bridge::passkey_selection(app);
            let mut confirm = false;
            let mut cancel = false;
            let (title, width) = match &prompt.kind {
                crate::browser_bridge::PasskeyPromptKind::Register { .. } => {
                    ("Save a passkey", 480.0)
                }
                crate::browser_bridge::PasskeyPromptKind::Get { .. } => {
                    ("Sign in with a passkey", 460.0)
                }
            };
            let open = modal_window(ctx, "browser-passkey", title, width, |ui| match &prompt.kind {
                crate::browser_bridge::PasskeyPromptKind::Register {
                    rp_id,
                    rp_name,
                    username,
                    origin,
                    existing,
                } => {
                    let name = if rp_name.is_empty() { rp_id } else { rp_name };
                    ui.label(
                        egui::RichText::new(format!("{name} wants to create a passkey"))
                            .strong()
                            .size(15.0),
                    );
                    ui.add_space(4.0);
                    ui.label(format!("Website: {origin}"));
                    ui.label(format!("Relying party: {rp_id}"));
                    ui.label(format!("Account: {username}"));
                    ui.add_space(6.0);
                    if ui
                        .radio(selection.is_none(), "Create a new entry")
                        .clicked()
                    {
                        selection = None;
                    }
                    for candidate in existing {
                        let label = if candidate.username.is_empty() {
                            candidate.title.clone()
                        } else {
                            format!("{} ({})", candidate.title, candidate.username)
                        };
                        if ui
                            .radio(
                                selection.as_deref() == Some(candidate.uuid.as_str()),
                                format!("Replace the passkey in \u{201c}{label}\u{201d}"),
                            )
                            .clicked()
                        {
                            selection = Some(candidate.uuid.clone());
                        }
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save passkey").clicked() {
                            confirm = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                }
                crate::browser_bridge::PasskeyPromptKind::Get { rp_id, candidates } => {
                    if selection.is_none() {
                        selection = candidates.first().map(|candidate| candidate.uuid.clone());
                    }
                    ui.label(
                        egui::RichText::new(format!("Sign in to {rp_id}"))
                            .strong()
                            .size(15.0),
                    );
                    ui.add_space(4.0);
                    if candidates.len() > 1 {
                        ui.label("Choose a passkey:");
                    }
                    for candidate in candidates {
                        let label = if candidate.username.is_empty() {
                            candidate.title.clone()
                        } else {
                            format!("{} ({})", candidate.title, candidate.username)
                        };
                        if ui
                            .radio(
                                selection.as_deref() == Some(candidate.uuid.as_str()),
                                label,
                            )
                            .clicked()
                        {
                            selection = Some(candidate.uuid.clone());
                        }
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Sign in").clicked() {
                            confirm = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                }
            });

            if selection != crate::browser_bridge::passkey_selection(app) {
                crate::browser_bridge::select_passkey(app, selection);
            }
            if confirm {
                crate::browser_bridge::confirm_passkey(app);
            } else if cancel || !open {
                crate::browser_bridge::deny_passkey(app);
            } else if open {
                app.dialog = Dialog::Passkey;
            }
        }
        Dialog::ShareGroup(mut d) => {
            let open: bool;
            let mut cancelled = false;
            let mut saved = false;
            let mut export_clicked = false;
            let mut import_clicked = false;
            let share_title = format!("Share Group \u{201c}{}\u{201d}", d.group_name);
            open = modal_window(ctx, "share-group", &share_title, 560.0, |ui| {
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
                        friendlypass::keeshare_signed::load_or_create_identity(crate::brand::NAME).and_then(
                            |identity| {
                                let info = friendlypass::keeshare_signed::export_signed(
                                    db, d.group, path, &d.password, &identity,
                                )?;
                                Ok((info, Some(identity.signer)))
                            },
                        )
                    } else {
                        friendlypass::keeshare::export_share(db, d.group, path, &d.password)
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
                                let reference = friendlypass::keeshare::ShareReference {
                                    import: d.import,
                                    export: d.export,
                                    group_uuid: db.group(d.group).map(|g| g.id().uuid()),
                                    path: d.path.clone(),
                                    password: d.password.clone(),
                                    keep_groups: false,
                                };
                                friendlypass::keeshare::set_reference(db, d.group, &reference);
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
                        .map(|b| friendlypass::keeshare_signed::is_signed_container(&b))
                        .unwrap_or(false);
                    let result = if is_zip {
                        friendlypass::keeshare_signed::import_signed(db, d.group, path, &d.password).map(
                            |info| {
                                format!(
                                    "Verified signed container from '{}'; imported: {} added, {} updated",
                                    info.signer, info.import.added, info.import.updated
                                )
                            },
                        )
                    } else {
                        friendlypass::keeshare::import_share(db, d.group, path, &d.password).map(|info| {
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
                    friendlypass::keeshare::set_reference(db, d.group, &reference);
                    app.dirty = true;
                    app.status = format!("Share settings saved for group '{}'", d.group_name);
                }
            }
            if !cancelled && !saved && open {
                app.dialog = Dialog::ShareGroup(d);
            }
        }
        Dialog::Shortcuts => {
            let open: bool;
            let mut close_clicked = false;
            open = modal_window(ctx, "keyboard-shortcuts", "Keyboard Shortcuts", 560.0, |ui| {
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
        Dialog::Columns => {
            let open: bool;
            let mut close_clicked = false;
            let mut changed = false;
            let mut cols = app.prefs.columns.clone();
            open = modal_window(ctx, "columns", "Columns", 600.0, |ui| {
                    ui.label(
                        "Choose which columns are visible, reorder them, and set their width. \
                         The width is the starting width; column borders can also be dragged.",
                    );
                    ui.add_space(6.0);
                    let count = cols.len();
                    for i in 0..count {
                        ui.horizontal(|ui| {
                            let label = format!("{} column", cols[i].id.label());
                            let mut visible = cols[i].visible;
                            if ui.checkbox(&mut visible, label).changed() {
                                cols[i].visible = visible;
                                changed = true;
                            }
                            ui.add_space(8.0);
                            ui.label("Width:");
                            let mut width = cols[i].width;
                            if ui
                                .add(
                                    egui::DragValue::new(&mut width)
                                        .range(60.0..=600.0)
                                        .speed(5.0)
                                        .suffix(" px"),
                                )
                                .changed()
                            {
                                cols[i].width = width;
                                changed = true;
                            }
                            ui.add_space(8.0);
                            if ui
                                .add_enabled(i > 0, egui::Button::new("Up"))
                                .on_hover_text("Move this column left")
                                .clicked()
                            {
                                cols.swap(i - 1, i);
                                changed = true;
                            }
                            if ui
                                .add_enabled(i + 1 < count, egui::Button::new("Down"))
                                .on_hover_text("Move this column right")
                                .clicked()
                            {
                                cols.swap(i, i + 1);
                                changed = true;
                            }
                        });
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Reset to defaults").clicked() {
                            cols = crate::config::Preferences::default().columns;
                            changed = true;
                        }
                        if ui.button("Close").clicked() {
                            close_clicked = true;
                        }
                    });
                });
            if changed {
                if !cols.iter().any(|c| c.visible) {
                    if let Some(first) = cols.first_mut() {
                        first.visible = true;
                    }
                    app.status = "At least one column must stay visible".into();
                }
                app.prefs.columns = cols;
                app.reset_columns = true;
                app.save_preferences();
            }
            if !close_clicked && open {
                app.dialog = Dialog::Columns;
            }
        }
        Dialog::Import(mut d) => {
            let open: bool;
            let mut import_clicked = false;
            let mut cancelled = false;
            open = modal_window(ctx, "import", "Import", 720.0, |ui| {
                    form_row(ui, "File to import:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.path)
                                .hint_text("/path/to/export.xml")
                                .desired_width(520.0),
                        );
                        r.labelled_by(id);
                    });
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("KeePass XML", &["xml"])
                            .add_filter("CSV", &["csv"])
                            .add_filter("JSON", &["json"])
                            .add_filter("1Password 1PUX", &["1pux"])
                            .add_filter("KeePass databases", &["kdb", "kdbx"])
                            .pick_file()
                        {
                            d.path = p.display().to_string();
                        }
                    }
                    form_row(ui, "Format:", |ui, id| {
                        let resp = egui::ComboBox::from_id_salt("import-format")
                            .selected_text(d.format.clone())
                            .show_ui(ui, |ui| {
                                for option in [
                                    "Auto-detect",
                                    "KeePass 2 XML",
                                    "CSV",
                                    "Bitwarden JSON",
                                    "Proton Pass JSON",
                                    "1Password 1PUX",
                                    "KeePass 1 (KDB)",
                                    "KeePass 2 (KDBX)",
                                ] {
                                    ui.selectable_value(&mut d.format, option.into(), option);
                                }
                            });
                        resp.response.labelled_by(id);
                    });
                    if d.is_encrypted() {
                        form_row(ui, "Database password:", |ui, id| {
                            let r = ui.add(
                                egui::TextEdit::singleline(&mut d.password)
                                    .password(true)
                                    .desired_width(520.0),
                            );
                            r.labelled_by(id);
                        });
                    }
                    ui.label(
                        "The imported entries are merged into the current database (root group). \
                         XML, CSV, Bitwarden JSON and 1PUX are unencrypted; KDB/KDBX need their password.",
                    );
                    if !d.error.is_empty() {
                        ui.colored_label(crate::theme::p().danger, &d.error);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Import now").clicked() {
                            import_clicked = true;
                        }
                    });
                });
            if import_clicked {
                let path = std::path::PathBuf::from(d.path.trim());
                let password = (!d.password.is_empty()).then_some(d.password.as_str());
                match friendlypass::import::import_file(&path, password, None) {
                    Ok(source) => {
                        if let Some(db) = app.db.as_mut() {
                            let root = db.root().id();
                            let count = friendlypass::import::merge_into(db, &source, root);
                            app.dirty = true;
                            app.status = format!("Imported {count} entries from {}", path.display());
                            app.dialog = Dialog::None;
                        } else {
                            d.error = "No database is open".into();
                            app.dialog = Dialog::Import(d);
                        }
                    }
                    Err(e) => {
                        d.error = format!("{e:#}");
                        app.dialog = Dialog::Import(d);
                    }
                }
            } else if !cancelled && open {
                app.dialog = Dialog::Import(d);
            }
        }
        Dialog::Export(mut d) => {
            let open: bool;
            let mut export_clicked = false;
            let mut cancelled = false;
            let title = if d.group.is_some() {
                "Export group (unencrypted)"
            } else {
                "Export (unencrypted)"
            };
            open = modal_window(ctx, "export", title, 720.0, |ui| {
                    if d.group.is_some() {
                        ui.label(format!("Group: {}", d.group_name));
                    }
                    form_row(ui, "Format:", |ui, id| {
                        let resp = egui::ComboBox::from_id_salt("export-format")
                            .selected_text(d.format.clone())
                            .show_ui(ui, |ui| {
                                for option in ["XML", "CSV", "HTML"] {
                                    ui.selectable_value(&mut d.format, option.into(), option);
                                }
                            });
                        resp.response.labelled_by(id);
                    });
                    form_row(ui, "Export to:", |ui, id| {
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut d.path).desired_width(520.0),
                        );
                        r.labelled_by(id);
                    });
                    if ui.button("Browse…").clicked() {
                        let ext = match d.format.as_str() {
                            "CSV" => "csv",
                            "HTML" => "html",
                            _ => "xml",
                        };
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("Export", &[ext])
                            .set_file_name(
                                std::path::Path::new(&d.path)
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| format!("database.{ext}")),
                            )
                            .save_file()
                        {
                            d.path = p.display().to_string();
                        }
                    }
                    ui.colored_label(
                        crate::theme::p().warn_fg,
                        "You are about to export your database to an unencrypted file. \
                         This leaves passwords and sensitive information readable by anyone.",
                    );
                    if !d.error.is_empty() {
                        ui.colored_label(crate::theme::p().danger, &d.error);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        if ui.button("Export now").clicked() {
                            export_clicked = true;
                        }
                    });
                });
            if export_clicked {
                let Some(db) = app.db.as_ref() else {
                    d.error = "No database is open".into();
                    app.dialog = Dialog::Export(d);
                    return;
                };
                let group = d.group;
                let rendered = match d.format.as_str() {
                    "CSV" => Ok(match group {
                        Some(g) => friendlypass::export::export_csv_group(db, g),
                        None => friendlypass::export::export_csv(db),
                    }),
                    "HTML" => {
                        let name = std::path::Path::new(&app.db_path)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| app.db_path.clone());
                        Ok(match group {
                            Some(g) => friendlypass::export::export_html_group(db, &name, g),
                            None => friendlypass::export::export_html(db, &name),
                        })
                    }
                    _ => match group {
                        Some(g) => friendlypass::export::export_xml_group(db, g)
                            .map_err(|e| format!("{e:#}")),
                        None => friendlypass::export::export_xml(db).map_err(|e| format!("{e:#}")),
                    },
                };
                match rendered {
                    Ok(out) => match std::fs::write(std::path::Path::new(d.path.trim()), out) {
                        Ok(()) => {
                            app.status = format!("Exported {} to {}", d.format, d.path);
                            app.dialog = Dialog::None;
                        }
                        Err(e) => {
                            d.error = format!("unable to write {}: {e}", d.path);
                            app.dialog = Dialog::Export(d);
                        }
                    },
                    Err(e) => {
                        d.error = e;
                        app.dialog = Dialog::Export(d);
                    }
                }
            } else if !cancelled && open {
                app.dialog = Dialog::Export(d);
            }
        }
        Dialog::Settings => {
            let open: bool;
            let mut close_clicked = false;
            open = modal_window(ctx, "settings", "Settings", 660.0, |ui| {
                    ui.heading("Startup");
                    let supported = crate::startup::launch_at_login_supported();
                    let mut launch = app.launch_at_login;
                    if ui
                        .add_enabled(
                            supported,
                            egui::Checkbox::new(&mut launch, "Launch at login"),
                        )
                        .on_disabled_hover_text("Launch at login is currently implemented on macOS, Windows and Linux")
                        .changed()
                    {
                        match crate::startup::set_launch_at_login(launch) {
                            Ok(_) => {
                                app.launch_at_login = launch;
                                app.status = if launch {
                                    "Launch at login enabled".into()
                                } else {
                                    "Launch at login disabled".into()
                                };
                            }
                            Err(e) => {
                                app.status = format!("Unable to change launch at login: {e:#}");
                            }
                        }
                    }
                    #[cfg(windows)]
                    {
                        ui.add_space(6.0);
                        let mut dpapi = app.prefs.windows_dpapi_fallback;
                        if ui
                            .checkbox(
                                &mut dpapi,
                                "Use a DPAPI-protected file instead of Credential Manager",
                            )
                            .on_hover_text(
                                "For Windows accounts without a login password, Credential Manager \
                                 may be unavailable. The unlock key is then encrypted with Windows \
                                 DPAPI in the app's config folder. This is weaker: any program \
                                 running as this user can decrypt it.",
                            )
                            .changed()
                        {
                            app.prefs.windows_dpapi_fallback = dpapi;
                            app.save_preferences();
                            app.secret_store = crate::startup::platform_store(dpapi);
                            app.auto_unlock = false;
                            app.remember_unlock = false;
                            app.status = "Auto-unlock backend changed; unlock once with                                           “Remember unlock key” to enroll again"
                                .into();
                        }
                    }
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label("Automatic unlock");
                    let saved = !app.db_path.is_empty()
                        && app.has_saved_secret(&app.db_path);
                    if saved {
                        ui.label(format!(
                            "An unlock key for {} is stored in the operating system's keychain.",
                            std::path::Path::new(&app.db_path)
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| app.db_path.clone())
                        ));
                        ui.label(
                            egui::RichText::new(
                                "Auto-unlock is only as strong as your OS login. Disable it if \
                                 other people can use your unlocked session.",
                            )
                            .weak(),
                        );
                        if ui.button("Forget saved unlock key").clicked() {
                            app.forget_saved_secret();
                        }
                    } else {
                        ui.label(
                            "No key is saved. On the unlock screen, tick “Remember unlock key \
                             and auto-unlock at startup” and unlock once.",
                        );
                    }

                    ui.add_space(10.0);
                    ui.heading("Security");
                    let mut prefs_changed = false;
                    ui.horizontal(|ui| {
                        prefs_changed |= ui
                            .checkbox(&mut app.prefs.clipboard_clear, "Clear the clipboard after")
                            .on_hover_text(
                                "Copied passwords and other values are removed from the \
                                 clipboard after this delay, unless you copied something else \
                                 in the meantime.",
                            )
                            .changed();
                        let r = ui.add_enabled(
                            app.prefs.clipboard_clear,
                            egui::DragValue::new(&mut app.prefs.clipboard_clear_secs)
                                .range(5..=600)
                                .suffix(" s"),
                        );
                        prefs_changed |= r.changed();
                    });
                    ui.horizontal(|ui| {
                        prefs_changed |= ui
                            .checkbox(&mut app.prefs.auto_lock, "Lock after inactivity of")
                            .on_hover_text(
                                "Locks the database when there was no keyboard or mouse input \
                                 for this long. With unsaved changes (or an open editor) the \
                                 lock is postponed rather than discarding your work.",
                            )
                            .changed();
                        ui.add_enabled_ui(app.prefs.auto_lock, |ui| {
                            egui::ComboBox::new("auto-lock-minutes", "minutes")
                                .selected_text(app.prefs.auto_lock_minutes.to_string())
                                .show_ui(ui, |ui| {
                                    for m in crate::config::AUTO_LOCK_CHOICES {
                                        prefs_changed |= ui
                                            .selectable_value(
                                                &mut app.prefs.auto_lock_minutes,
                                                m,
                                                m.to_string(),
                                            )
                                            .changed();
                                    }
                                });
                        });
                    });

                    ui.add_space(10.0);
                    ui.heading("Appearance");
                    ui.horizontal(|ui| {
                        ui.label("Theme:");
                        for choice in crate::theme::ThemeChoice::ALL {
                            prefs_changed |= ui
                                .radio_value(&mut app.prefs.theme, choice, choice.label())
                                .changed();
                        }
                    });
                    if prefs_changed {
                        app.save_preferences();
                    }
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        close_clicked = true;
                    }
                });
            if !close_clicked && open {
                app.dialog = Dialog::Settings;
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
    ("Up / Down", "Select the previous / next entry"),
    ("Shift+click", "Select a range of entries"),
    ("Cmd/Ctrl+click", "Add or remove an entry from the selection"),
    ("Cmd/Ctrl+H", "Entry history"),
    ("Cmd/Ctrl+G", "Password generator"),
    ("Delete / Backspace", "Recycle the selected entry"),
    ("Cmd/Ctrl+S", "Save the database"),
    ("Cmd/Ctrl+Shift+S", "Save as…"),
    ("Cmd/Ctrl+L", "Lock the database"),
    ("F1", "Show this shortcut reference"),
    ("Escape", "Close a dialog, cancel the entry editor, clear the search"),
    ("Enter", "Confirm a dialog"),
    ("Cmd/Ctrl+Enter", "Create / save in the entry editor"),
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
        if let Err(e) = friendlypass::key::ensure_key_file(&kf_path) {
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
    if let Err(e) = friendlypass::saveutil::save(&path, &db, key.clone()) {
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
    let created = app.db_path.clone();
    app.record_recent_database(&created);
}
