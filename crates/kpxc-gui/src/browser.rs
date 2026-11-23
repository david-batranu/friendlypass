//! The main browsing UI: group tree, entry table, entry details panel.

use eframe::egui;
use eframe::egui::{Align, Layout};
use egui_extras::{Column, TableBuilder};
use keepass::db::{fields, Database, EntryId, GroupId};

use crate::app::{App, SortColumn};

/// A dimmed label (the old `ui.weak_label` helper, removed in egui 0.37).
fn weak_label(ui: &mut egui::Ui, text: impl Into<String>) -> egui::Response {
    ui.add(egui::Label::new(egui::RichText::new(text.into()).weak()))
}

/// One row in the group tree.
pub struct GroupRow {
    /// `None` is the root group.
    pub id: Option<GroupId>,
    pub depth: usize,
    pub name: String,
    pub entries: usize,
    pub icon: crate::icons::IconSpec,
}

fn flatten_groups(db: &Database) -> Vec<GroupRow> {
    let mut rows = Vec::new();
    fn walk(db: &Database, id: GroupId, depth: usize, rows: &mut Vec<GroupRow>) {
        if let Some(g) = db.group(id) {
            let mut children: Vec<GroupRow> = g
                .groups()
                .map(|c| GroupRow {
                    id: Some(c.id()),
                    depth,
                    name: c.name.clone(),
                    entries: c.entries().count(),
                    icon: crate::icons::icon_spec(db, c.icon(), crate::icons::DEFAULT_GROUP_ICON),
                })
                .collect();
            children.sort_by(|a, b| a.name.cmp(&b.name));
            for child in children {
                let cid = child.id.unwrap();
                rows.push(child);
                walk(db, cid, depth + 1, rows);
            }
        }
    }
    walk(db, db.root().id(), 1, &mut rows);
    rows
}

/// One row in the entry table.
#[derive(Clone)]
pub struct EntryRow {
    pub id: EntryId,
    /// Set when showing search results across groups.
    pub group: Option<String>,
    pub icon: crate::icons::IconSpec,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
}

fn entry_row(db: &Database, id: EntryId, with_group: bool) -> EntryRow {
    let entry = db.entry(id).expect("entry exists");
    let group = if with_group { Some(group_path(db, entry.parent().id())) } else { None };
    EntryRow {
        id,
        group,
        icon: crate::icons::icon_spec(db, entry.icon(), crate::icons::DEFAULT_ENTRY_ICON),
        title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
        username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
        password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
        url: entry.get(fields::URL).unwrap_or_default().to_owned(),
        notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
        tags: entry.tags.join(", "),
    }
}

/// Path of a group ("Web/Sub"), excluding the root group.
fn group_path(db: &Database, group: GroupId) -> String {
    let mut parts = Vec::new();
    let mut current = group;
    while let Some(g) = db.group(current) {
        match g.parent() {
            Some(p) => {
                if p.parent().is_some() {
                    parts.push(g.name.clone());
                }
                current = p.id();
            }
            None => break,
        }
    }
    parts.reverse();
    parts.join("/")
}

/// The entries to display: search results across the database, or the
/// entries of the selected group.
fn visible_entries(app: &App) -> Vec<EntryRow> {
    let Some(db) = app.db.as_ref() else { return Vec::new() };

    if app.search.trim().is_empty() {
        let group = app
            .selected_group
            .unwrap_or_else(|| db.root().id());
        let Some(g) = db.group(group) else { return Vec::new() };
        let mut rows: Vec<EntryRow> = g
            .entries()
            .map(|e| entry_row(db, e.id(), false))
            .collect();
        sort_rows(&mut rows, app);
        rows
    } else {
        let needle = app.search.to_lowercase();
        let mut rows: Vec<EntryRow> = db
            .iter_all_entries()
            .filter(|e| {
                let hay = [
                    e.get(fields::TITLE).unwrap_or_default(),
                    e.get(fields::USERNAME).unwrap_or_default(),
                    e.get(fields::URL).unwrap_or_default(),
                    e.get(fields::NOTES).unwrap_or_default(),
                    e.tags.join(", ").as_str(),
                ]
                .concat()
                .to_lowercase();
                hay.contains(&needle)
            })
            .map(|e| entry_row(db, e.id(), true))
            .collect();
        sort_rows(&mut rows, app);
        rows
    }
}

fn sort_rows(rows: &mut [EntryRow], app: &App) {
    let key = |r: &EntryRow| match app.sort_column {
        SortColumn::Title => r.title.clone(),
        SortColumn::Username => r.username.clone(),
        SortColumn::Password => r.password.clone(),
        SortColumn::Url => r.url.clone(),
        SortColumn::Notes => r.notes.clone(),
        SortColumn::Tags => r.tags.clone(),
    };
    rows.sort_by_key(key);
    if app.sort_desc {
        rows.reverse();
    }
}

// ---------------------------------------------------------------------------
// group tree
// ---------------------------------------------------------------------------

pub fn group_tree(ui: &mut egui::Ui, app: &mut App) {
    use keepass::db::GroupRef;

    // Split borrows: render from an immutable snapshot of the tree, mutate
    // selection/dialog fields freely.
    let rows: Vec<GroupRow> = app
        .db
        .as_ref()
        .map(flatten_groups)
        .unwrap_or_default();

    let root_name = std::path::Path::new(&app.db_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "database".into());

    ui.heading("Groups");
    ui.separator();

    // Precompute everything the row renderer needs from the immutable db.
    let root_entries = app.db.as_ref().map(|db| db.num_entries()).unwrap_or(0);
    let root_id = app.db.as_ref().map(|db| db.root().id());
    let root_icon = app
        .db
        .as_ref()
        .map(|db| {
            crate::icons::icon_spec(db, db.root().icon(), crate::icons::DEFAULT_GROUP_ICON)
        })
        .unwrap_or(crate::icons::IconSpec::Standard(crate::icons::DEFAULT_GROUP_ICON));

    let mut selected_group: Option<GroupId> = app.selected_group;
    let new_dialog: Option<crate::dialogs::Dialog> = None;
    let mut rename_dialog: Option<crate::dialogs::Dialog> = None;
    let mut delete_target: Option<GroupId> = None;
    let mut share_target: Option<GroupId> = None;
    let mut empty_bin_clicked = false;
    // Entry dropped from the entry table onto a group row: (entry, target).
    let mut dropped: Option<(EntryId, Option<GroupId>)> = None;
    // Group dropped onto another group row: (group, target).
    let mut dropped_group: Option<(GroupId, Option<GroupId>)> = None;

    // Split borrows: the icon cache is mutated while rendering rows.
    let cache = &mut app.icon_cache;

    let mut row_ui = |ui: &mut egui::Ui, row: &GroupRow, is_root: bool| {
        let selected = if is_root {
            selected_group.is_none()
        } else {
            selected_group == row.id
        };
        ui.horizontal(|ui| {
            for _ in 0..row.depth.saturating_sub(1) {
                ui.label("  ");
            }
            crate::icons::draw_icon(ui, cache, Some(&row.icon));
            let label = if is_root {
                format!("{root_name} ({root_entries})")
            } else {
                format!("{} ({})", row.name, row.entries)
            };
            // The row is clickable (select), draggable (move groups), and a
            // drop zone for both entries and other groups.
            let resp = ui.add(
                egui::Button::selectable(selected, label)
                    .frame(false)
                    .sense(egui::Sense::click_and_drag()),
            );
            if resp.clicked() {
                selected_group = if is_root { None } else { row.id };
            }
            // Drag source: non-root groups can be dragged.
            if let Some(gid) = row.id {
                resp.dnd_set_drag_payload(gid);
            }
            // Drop zone: entries dropped onto this group move into it.
            // IMPORTANT: check the payload type non-destructively first —
            // `dnd_release_payload` consumes ANY payload on a hovered row
            // even when the type doesn't match.
            if resp.dnd_hover_payload::<GroupId>().is_some() {
                // A group is being dropped here (cycle-checked at apply time).
                if let Some(group_id) = resp.dnd_release_payload::<GroupId>() {
                    if row.id != Some(*group_id) {
                        dropped_group = Some((*group_id, row.id));
                    }
                }
            } else if let Some(entry_id) = resp.dnd_release_payload::<EntryId>() {
                // `None` target means the root row was the drop target.
                dropped = Some((*entry_id, row.id));
            }
            // Drop highlight while a drag hovers this row.
            if egui::DragAndDrop::has_any_payload(ui.ctx()) && resp.contains_pointer() {
                let rect = resp.rect;
                ui.painter().rect_stroke(
                    rect.expand(2.0),
                    4.0,
                    ui.visuals().selection.stroke,
                    egui::StrokeKind::Middle,
                );
            }
        });
    };

    row_ui(
        ui,
        &GroupRow {
            id: None,
            depth: 0,
            name: root_name.clone(),
            entries: 0,
            icon: root_icon,
        },
        true,
    );
    for row in &rows {
        row_ui(ui, row, false);
    }

    ui.separator();
    ui.horizontal(|ui| {
        let has_selection = selected_group.is_some();
        if ui
            .add_enabled(has_selection, egui::Button::new("Rename group…"))
            .on_disabled_hover_text("Select a group first")
            .clicked()
        {
            if let Some(id) = selected_group {
                let name = app
                    .db
                    .as_ref()
                    .and_then(|db| db.group(id))
                    .map(|g: GroupRef<'_>| g.name.clone())
                    .unwrap_or_default();
                rename_dialog = Some(crate::dialogs::Dialog::GroupRename(Box::new(
                    crate::dialogs::GroupEdit { id: Some(id), parent: id, name },
                )));
            }
        }
        if ui
            .add_enabled(has_selection, egui::Button::new("Delete group…"))
            .on_disabled_hover_text("Select a group first (the root group cannot be deleted)")
            .clicked()
        {
            if let Some(id) = selected_group {
                delete_target = Some(id);
            }
        }
        if ui
            .add_enabled(has_selection, egui::Button::new("Share group…"))
            .on_disabled_hover_text("Select a group first")
            .clicked()
        {
            if let Some(id) = selected_group {
                share_target = Some(id);
            }
        }
    });

    // Recycle bin management: shown when the database has a recycle bin.
    let bin_id = app
        .db
        .as_ref()
        .and_then(|db| db.recycle_bin())
        .map(|b| b.id());
    if bin_id.is_some() {
        let bin_selected = selected_group == bin_id;
        if ui
            .add_enabled(bin_selected, egui::Button::new("Empty Recycle Bin…"))
            .on_disabled_hover_text("Select the Recycle Bin group first")
            .clicked()
        {
            empty_bin_clicked = true;
        }
        if bin_selected {
            weak_label(
                ui,
                "This group is the Recycle Bin: deleting from here is permanent.",
            );
        }
    }

    // Apply pending mutations now that the immutable borrows are over.
    app.selected_group = selected_group;
    if let Some((entry_id, target)) = dropped {
        // Dropping onto the root row moves the entry to the root group.
        let gid = target.or(root_id);
        if let Some(gid) = gid {
            app.move_entries_to(&[entry_id], gid);
        }
    }
    if let Some((group_id, target)) = dropped_group {
        app.move_group_to(group_id, target);
    }
    if let Some(d) = new_dialog {
        app.dialog = d;
    }
    if let Some(d) = rename_dialog {
        app.dialog = d;
    }
    if let Some(id) = delete_target {
        app.dialog = crate::dialogs::Dialog::ConfirmDeleteGroup(id);
    }
    if let Some(id) = share_target {
        if let Some(db) = app.db.as_ref() {
            app.dialog = crate::dialogs::Dialog::ShareGroup(Box::new(
                crate::dialogs::ShareDialog::for_group(db, id),
            ));
        }
    }
    if empty_bin_clicked {
        app.dialog = crate::dialogs::Dialog::ConfirmEmptyRecycleBin;
    }
}

// ---------------------------------------------------------------------------
// entry table
// ---------------------------------------------------------------------------

pub fn entry_table(ui: &mut egui::Ui, app: &mut App) {
    let rows = visible_entries(app);
    if rows.is_empty() {
        ui.centered_and_justified(|ui| {
            weak_label(
                ui,
                if app.search.is_empty() {
                    "No entries in this group. Use “New Entry” to add one."
                } else {
                    "No entries match the search."
                },
            );
        });
        return;
    }

    let searching = !app.search.trim().is_empty();
    let mut sort_column = app.sort_column;
    let mut sort_desc = app.sort_desc;
    let mut select: Option<EntryId> = None;
    let mut edit: Option<EntryId> = None;

    let mut builder = TableBuilder::new(ui)
        .striped(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .min_scrolled_height(0.0);

    if searching {
        builder = builder.column(Column::auto().resizable(true).clip(true));
    }
    builder = builder
        .column(Column::initial(160.0).resizable(true).clip(true))
        .column(Column::initial(140.0).resizable(true).clip(true))
        .column(Column::initial(110.0).resizable(true).clip(true))
        .column(Column::initial(180.0).resizable(true).clip(true))
        .column(Column::remainder().clip(true))
        .column(Column::auto().clip(true));

    let mut sort_headers: Vec<(SortColumn, bool)> = Vec::new();
    builder
        .header(24.0, |mut header| {
            if searching {
                header.col(|ui| {
                    ui.strong("Group");
                });
            }
            for col in [
                SortColumn::Title,
                SortColumn::Username,
                SortColumn::Password,
                SortColumn::Url,
                SortColumn::Notes,
                SortColumn::Tags,
            ] {
                header.col(|ui| {
                    let mark = if sort_column == col {
                        if sort_desc { " v" } else { " ^" }
                    } else {
                        ""
                    };
                    if ui.button(format!("{}{mark}", col.label())).clicked() {
                        if sort_column == col {
                            sort_desc = !sort_desc;
                        } else {
                            sort_column = col;
                            sort_desc = false;
                        }
                    }
                    sort_headers.push((col, false));
                });
            }
        })
        .body(|mut body| {
            for row_data in &rows {
                body.row(24.0, |mut row| {
                    if searching {
                        row.col(|ui| {
                            weak_label(ui, row_data.group.clone().unwrap_or_default());
                        });
                    }
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            crate::icons::draw_icon(ui, &mut app.icon_cache, Some(&row_data.icon));
                            // Draggable source: drag an entry onto a group in
                            // the tree to move it (KeePassXC parity). The
                            // title is both clickable and draggable.
                            let in_set = app.selected_entries.contains(&row_data.id);
                            let is_selected = app.selected_entry == Some(row_data.id);
                            let title_resp = ui
                                .add(
                                    egui::Button::new(&row_data.title)
                                        .frame(false)
                                        .selected(in_set || is_selected)
                                        .sense(egui::Sense::click_and_drag()),
                                )
                                .on_hover_text("click to select, double-click to edit, drag onto a group to move; Cmd/Ctrl-click for multi-selection");
                            if title_resp.dragged() {
                                egui::DragAndDrop::set_payload(ui.ctx(), row_data.id);
                            }
                            let multi = ui.ctx().input(|i| i.modifiers.command);
                            if title_resp.clicked() {
                                if multi {
                                    if !app.selected_entries.remove(&row_data.id) {
                                        app.selected_entries.insert(row_data.id);
                                    }
                                } else {
                                    app.selected_entries.clear();
                                    app.selected_entries.insert(row_data.id);
                                }
                                select = Some(row_data.id);
                            }
                            if title_resp.double_clicked() {
                                select = Some(row_data.id);
                                edit = Some(row_data.id);
                            }
                        });
                    });
                    row.col(|ui| {
                        weak_label(ui, &row_data.username);
                    });
                    row.col(|ui| {
                        if app.show_passwords {
                            weak_label(ui, &row_data.password);
                        } else if !row_data.password.is_empty() {
                            weak_label(ui, "••••••••");
                        }
                    });
                    row.col(|ui| {
                        weak_label(ui, &row_data.url);
                    });
                    row.col(|ui| {
                        weak_label(ui, &row_data.notes);
                    });
                    row.col(|ui| {
                        weak_label(ui, &row_data.tags);
                    });

                    let response = row.response();
                    if response.clicked() {
                        select = Some(row_data.id);
                    }
                    if response.double_clicked() {
                        select = Some(row_data.id);
                        edit = Some(row_data.id);
                    }
                });
            }
        });

    // Apply pending mutations.
    app.sort_column = sort_column;
    app.sort_desc = sort_desc;
    if let Some(id) = select {
        app.selected_entry = Some(id);
    }
    if let Some(id) = edit {
        app.edit_entry_dialog(id);
    }
    let _ = sort_headers;
}

// ---------------------------------------------------------------------------
// entry details
// ---------------------------------------------------------------------------

pub fn entry_details(ui: &mut egui::Ui, app: &mut App, selected: Option<EntryId>) {
    let Some(id) = selected else { return };

    // Immutable snapshot for rendering (resolving {REF:…} field references
    // like KeePassXC does when displaying an entry).
    let data: Option<EntryDetailsData> = app.db.as_ref().and_then(|db| {
        db.entry(id).map(|e| EntryDetailsData {
            title: crate::refs::resolve_references(db, e.get(fields::TITLE).unwrap_or_default()),
            username: crate::refs::resolve_references(db, e.get(fields::USERNAME).unwrap_or_default()),
            password: crate::refs::resolve_references(db, e.get(fields::PASSWORD).unwrap_or_default()),
            url: crate::refs::resolve_references(db, e.get(fields::URL).unwrap_or_default()),
            notes: crate::refs::resolve_references(db, e.get(fields::NOTES).unwrap_or_default()),
            tags: e.tags.join(", "),
            attributes: e
                .fields
                .iter()
                .filter(|(k, _)| !fields::KNOWN_FIELDS.contains(&k.as_str()))
                .map(|(k, v)| {
                    (
                        k.clone(),
                        crate::refs::resolve_references(db, v.get()),
                        v.is_protected(),
                    )
                })
                .collect(),
            autotype: e.autotype.as_ref().map(|a| AutoTypeSummary {
                enabled: a.enabled,
                default_sequence: a.default_sequence.clone().unwrap_or_default(),
                associations: a
                    .associations
                    .iter()
                    .map(|assoc| (assoc.window.clone(), assoc.sequence.clone()))
                    .collect(),
            }),
            history_count: e.history.as_ref().map(|h| h.get_entries().len()).unwrap_or(0),
            attachments: e
                .attachments_named()
                .map(|(name, a)| (name.to_owned(), a.data.get().len()))
                .collect(),
        })
    });
    let Some(d) = data else { return };

    let mut copy: Option<String> = None;
    let mut edit_clicked = false;
    let mut delete_clicked = false;
    let mut history_clicked = false;
    let mut autotype_clicked = false;
    let mut export: Option<(String, Vec<u8>)> = None;

    ui.horizontal(|ui| {
        ui.strong(&d.title);
        ui.separator();
        if ui.button("Edit…").clicked() {
            edit_clicked = true;
        }
        if ui
            .add_enabled(d.history_count > 0, egui::Button::new("History…"))
            .on_disabled_hover_text("This entry has no recorded history")
            .clicked()
        {
            history_clicked = true;
        }
        if ui
            .button("Auto-Type")
            .on_hover_text("Type the entry's sequence into the focused window (needs the OS Accessibility permission on macOS)")
            .clicked()
        {
            autotype_clicked = true;
        }
        if ui.button("Delete…").clicked() {
            delete_clicked = true;
        }
    });
    ui.separator();

    egui::Grid::new("details-grid")
        .num_columns(3)
        .spacing([8.0, 4.0])
        .show(ui, |ui| {
            for (label, value) in [
                ("UserName", &d.username),
                ("Password", &d.password),
                ("URL", &d.url),
                ("Tags", &d.tags),
            ] {
                ui.label(label);
                if label == "Password" && !app.show_passwords && !d.password.is_empty() {
                    weak_label(ui, "••••••••");
                } else {
                    weak_label(ui, value);
                }
                if ui.button(format!("Copy {label}")).clicked() {
                    copy = Some(value.clone());
                }
                ui.end_row();
            }
            ui.label("Notes");
            weak_label(ui, &d.notes);
            ui.end_row();
        });

    // Custom attributes (like KeePassXC's details view).
    if !d.attributes.is_empty() {
        ui.separator();
        ui.label("Attributes:");
        egui::Grid::new("details-attributes")
            .num_columns(2)
            .show(ui, |ui| {
                for (key, value, protected) in &d.attributes {
                    ui.label(format!("{key}{}", if *protected { " (protected)" } else { "" }));
                    if *protected && !app.show_passwords {
                        weak_label(ui, "••••••••");
                    } else {
                        weak_label(ui, value);
                    }
                    ui.end_row();
                }
            });
    }

    // Auto-Type summary.
    if let Some(at) = &d.autotype {
        ui.separator();
        ui.label(format!(
            "Auto-Type: {}{}",
            if at.enabled { "enabled" } else { "disabled" },
            if !at.default_sequence.is_empty() {
                format!(" — default sequence: {}", at.default_sequence)
            } else {
                String::new()
            }
        ));
        for (window, sequence) in &at.associations {
            weak_label(ui, format!("  {window} -> {}", if sequence.is_empty() { "(default)" } else { sequence }));
        }
    }

    if !d.attachments.is_empty() {
        ui.separator();
        ui.label("Attachments:");
        egui::Grid::new("attachments-grid")
            .num_columns(2)
            .show(ui, |ui| {
                for (name, size) in &d.attachments {
                    ui.label(format!("{name} ({size} bytes)"));
                    if ui.button("Export…").clicked() {
                        if let Some(data) = app
                            .db
                            .as_ref()
                            .and_then(|db| db.entry(id))
                            .and_then(|e| e.attachment_by_name(name).map(|a| a.data.get().clone()))
                        {
                            export = Some((name.clone(), data));
                        }
                    }
                    ui.end_row();
                }
            });
    }

    // Apply pending mutations.
    if let Some(text) = copy {
        app.copy_to_clipboard(text);
    }
    if edit_clicked {
        app.edit_entry_dialog(id);
    }
    if history_clicked {
        app.dialog = crate::dialogs::Dialog::History(id);
    }
    if autotype_clicked {
        app.perform_auto_type(id);
    }
    if delete_clicked {
        app.dialog = crate::dialogs::Dialog::ConfirmDeleteEntry(id);
    }
    if let Some((name, data)) = export {
        if let Some(path) = rfd::FileDialog::new().set_file_name(&name).save_file() {
            match std::fs::write(&path, &data) {
                Ok(()) => app.status = format!("Exported attachment to {}", path.display()),
                Err(e) => app.status = format!("export failed: {e}"),
            }
        }
    }
}

struct EntryDetailsData {
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    tags: String,
    attributes: Vec<(String, String, bool)>,
    autotype: Option<AutoTypeSummary>,
    history_count: usize,
    attachments: Vec<(String, usize)>,
}

struct AutoTypeSummary {
    enabled: bool,
    default_sequence: String,
    associations: Vec<(String, String)>,
}
