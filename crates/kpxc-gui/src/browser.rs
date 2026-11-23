//! The main browsing UI: group tree, entry table, entry details panel.

use eframe::egui;
use eframe::egui::{Align, Layout};
use egui_extras::{Column, TableBuilder};
use crate::config::ColumnId;
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

    // Library header: icon + database name.
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(crate::theme::ACCENT_SOFT)
            .corner_radius(10)
            .inner_margin(egui::Margin::same(4))
            .show(ui, |ui| {
                crate::icons::draw_icon_sized(
                    ui,
                    &mut app.icon_cache,
                    Some(&root_icon),
                    28.0,
                );
            });
        ui.vertical(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&root_name)
                        .size(16.0)
                        .strong()
                        .color(crate::theme::TEXT),
                )
                .truncate(),
            );
            ui.label(
                egui::RichText::new("KeePassXC-RS")
                    .size(11.0)
                    .color(crate::theme::MUTED),
            );
        });
    });
    ui.add_space(18.0);
    ui.label(
        egui::RichText::new("LIBRARY")
            .size(11.0)
            .strong()
            .color(crate::theme::MUTED),
    );
    ui.add_space(4.0);

    let mut selected_group: Option<GroupId> = app.selected_group;
    let new_dialog: Option<crate::dialogs::Dialog> = None;
    let mut rename_dialog: Option<crate::dialogs::Dialog> = None;
    let mut delete_target: Option<GroupId> = None;
    let mut share_target: Option<GroupId> = None;
    // Group-scoped export chosen from a row's context menu.
    let mut export_request: Option<(Option<GroupId>, &'static str)> = None;
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
                format!("All Items ({root_entries})")
            } else {
                format!("{} ({})", row.name, row.entries)
            };
            let label = egui::RichText::new(label)
                .size(14.0)
                .color(if selected {
                    crate::theme::ACCENT
                } else {
                    crate::theme::TEXT
                });
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
            resp.context_menu(|ui| {
                ui.label(if is_root { "Database export" } else { "Group export" });
                for (label, format) in [
                    ("Export as KeePass 2 XML…", "XML"),
                    ("Export as CSV…", "CSV"),
                    ("Export as HTML…", "HTML"),
                ] {
                    if ui.button(label).clicked() {
                        export_request = Some((row.id, format));
                        ui.close();
                    }
                }
            });
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
    ui.add_space(14.0);
    ui.label(
        egui::RichText::new("GROUPS")
            .size(11.0)
            .strong()
            .color(crate::theme::MUTED),
    );
    ui.add_space(2.0);
    for row in &rows {
        row_ui(ui, row, false);
    }

    if let Some((group, format)) = export_request {
        let group_name = match group {
            Some(id) => app
                .db
                .as_ref()
                .and_then(|db| db.group(id))
                .map(|g| g.name.clone())
                .unwrap_or_default(),
            None => std::path::Path::new(&app.db_path)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "database".into()),
        };
        app.dialog = crate::dialogs::Dialog::Export(Box::new(crate::dialogs::ExportDialog::for_group(
            &app.db_path,
            group,
            &group_name,
            format,
        )));
    }

    ui.separator();
    ui.horizontal_wrapped(|ui| {
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

/// The middle column: a 1Password-style card list or the configurable
/// spreadsheet-style table.
pub fn entry_view(ui: &mut egui::Ui, app: &mut App) {
    let rows = visible_entries(app);
    let title = if !app.search.trim().is_empty() {
        "Search Results".to_owned()
    } else {
        app.selected_group
            .and_then(|id| app.db.as_ref().and_then(|db| db.group(id)).map(|g| g.name.clone()))
            .unwrap_or_else(|| "All Items".into())
    };
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(title).size(21.0).strong());
            ui.label(
                egui::RichText::new(format!(
                    "{} item{}",
                    rows.len(),
                    if rows.len() == 1 { "" } else { "s" }
                ))
                .size(12.0)
                .color(crate::theme::MUTED),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let table = !app.prefs.list_view;
            if ui.selectable_label(table, "Table").clicked() {
                app.prefs.list_view = false;
                app.save_preferences();
            }
            if ui.selectable_label(!table, "List").clicked() {
                app.prefs.list_view = true;
                app.save_preferences();
            }
            ui.menu_button("Sort", |ui| {
                for col in [
                    SortColumn::Title,
                    SortColumn::Username,
                    SortColumn::Password,
                    SortColumn::Url,
                    SortColumn::Notes,
                    SortColumn::Tags,
                ] {
                    if ui
                        .selectable_label(app.sort_column == col, col.label())
                        .clicked()
                    {
                        app.sort_column = col;
                        app.sort_desc = false;
                        ui.close();
                    }
                }
                ui.separator();
                if ui.selectable_label(!app.sort_desc, "Ascending").clicked() {
                    app.sort_desc = false;
                    ui.close();
                }
                if ui.selectable_label(app.sort_desc, "Descending").clicked() {
                    app.sort_desc = true;
                    ui.close();
                }
            });
        });
    });
    ui.add_space(8.0);

    if app.prefs.list_view {
        entry_list(ui, app, &rows);
    } else {
        let table_rect = ui.available_rect_before_wrap();
        let mut table_ui = ui.new_child(egui::UiBuilder::new().max_rect(table_rect));
        table_ui.set_clip_rect(table_rect.intersect(ui.clip_rect()));
        table_ui.expand_to_include_rect(table_rect);
        entry_table(&mut table_ui, app);
    }
}

fn entry_list(ui: &mut egui::Ui, app: &mut App, rows: &[EntryRow]) {
    if rows.is_empty() {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
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
    egui::ScrollArea::vertical()
        .id_salt("entry-list-scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for row in rows {
                let selected = app.selected_entry == Some(row.id)
                    || app.selected_entries.contains(&row.id);
                let (rect, _alloc) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 56.0),
                    egui::Sense::hover(),
                );
                let hovered = ui.rect_contains_pointer(rect);
                let fill = if selected {
                    crate::theme::ACCENT_SOFT
                } else if hovered {
                    crate::theme::HOVER
                } else {
                    egui::Color32::TRANSPARENT
                };
                if fill != egui::Color32::TRANSPARENT {
                    ui.painter()
                        .rect_filled(rect, egui::CornerRadius::same(10), fill);
                }
                if selected {
                    // A thin accent bar on the left, like a browser tab.
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(rect.left_top() + egui::vec2(0.0, 10.0), egui::vec2(3.0, rect.height() - 20.0)),
                        egui::CornerRadius::same(2),
                        crate::theme::ACCENT,
                    );
                }
                let mut content = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(rect.shrink2(egui::vec2(12.0, 6.0)))
                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                );
                egui::Frame::new()
                    .fill(crate::theme::BG)
                    .corner_radius(8)
                    .inner_margin(egui::Margin::same(3))
                    .show(&mut content, |ui| {
                        crate::icons::draw_icon_sized(
                            ui,
                            &mut app.icon_cache,
                            Some(&row.icon),
                            24.0,
                        );
                    });
                content.add_space(8.0);
                let secondary = if !row.username.is_empty() {
                    row.username.clone()
                } else if !row.url.is_empty() {
                    row.url.clone()
                } else {
                    row.tags.clone()
                };
                content.vertical(|ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&row.title)
                                .size(15.0)
                                .strong()
                                .color(crate::theme::TEXT),
                        )
                        .truncate(),
                    );
                    if !secondary.is_empty() {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(secondary)
                                    .size(13.0)
                                    .color(crate::theme::MUTED),
                            )
                            .truncate(),
                        );
                    }
                });

                // Interact after the labels have been painted: otherwise a
                // click aimed at the title label is swallowed by the label
                // instead of reaching the row.
                let resp = ui.interact(
                    rect,
                    ui.id().with(("entry-row", row.id)),
                    egui::Sense::click_and_drag(),
                );
                if resp.clicked() {
                    let multi = ui.ctx().input(|i| i.modifiers.command);
                    if multi {
                        if !app.selected_entries.remove(&row.id) {
                            app.selected_entries.insert(row.id);
                        }
                    } else {
                        app.selected_entries.clear();
                        app.selected_entries.insert(row.id);
                    }
                    app.selected_entry = Some(row.id);
                }
                if resp.double_clicked() {
                    app.selected_entry = Some(row.id);
                    app.edit_entry_dialog(row.id);
                }
                if resp.dragged() {
                    egui::DragAndDrop::set_payload(ui.ctx(), row.id);
                }
                resp.on_hover_cursor(egui::CursorIcon::PointingHand);
            }
        });
}

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

    // User-configurable columns (visibility, order, width), persisted in
    // the GUI preferences.
    let mut columns = app.column_layout();
    if columns.is_empty() {
        columns.push(crate::config::ColumnConfig {
            id: ColumnId::Title,
            visible: true,
            width: ColumnId::Title.default_width(),
        });
    }

    let mut builder = TableBuilder::new(ui)
        .striped(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .min_scrolled_height(0.0);
    if app.reset_columns {
        // The Columns dialog changed visibility/order/width: drop the
        // table's remembered widths so the new configuration applies.
        builder.reset();
        app.reset_columns = false;
    }

    if searching {
        builder = builder.column(Column::initial(140.0).resizable(true).clip(true));
    }
    for (i, c) in columns.iter().enumerate() {
        let col = if i + 1 == columns.len() {
            // The last column fills the remaining width.
            Column::remainder().clip(true)
        } else {
            Column::initial(c.width).resizable(true).clip(true)
        };
        builder = builder.column(col);
    }

    builder
        .header(24.0, |mut header| {
            if searching {
                header.col(|ui| {
                    ui.strong("Group");
                });
            }
            for c in &columns {
                header.col(|ui| {
                    let col = sort_column_of(c.id);
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
                    for c in &columns {
                        row.col(|ui| {
                            entry_cell(ui, app, c.id, row_data, &mut select, &mut edit);
                        });
                    }

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
}

/// Map a configured column to the sortable field it represents.
fn sort_column_of(id: ColumnId) -> SortColumn {
    match id {
        ColumnId::Title => SortColumn::Title,
        ColumnId::UserName => SortColumn::Username,
        ColumnId::Password => SortColumn::Password,
        ColumnId::Url => SortColumn::Url,
        ColumnId::Notes => SortColumn::Notes,
        ColumnId::Tags => SortColumn::Tags,
    }
}

/// Draw one entry-table cell for the given configured column.
fn entry_cell(
    ui: &mut egui::Ui,
    app: &mut App,
    column: ColumnId,
    row_data: &EntryRow,
    select: &mut Option<EntryId>,
    edit: &mut Option<EntryId>,
) {
    match column {
        ColumnId::Title => {
            ui.horizontal(|ui| {
                crate::icons::draw_icon(ui, &mut app.icon_cache, Some(&row_data.icon));
                // Draggable source: drag an entry onto a group in the tree to
                // move it. The title is both clickable and draggable.
                let in_set = app.selected_entries.contains(&row_data.id);
                let is_selected = app.selected_entry == Some(row_data.id);
                let title_resp = ui
                    .add(
                        egui::Button::new(&row_data.title)
                            .frame(false)
                            .selected(in_set || is_selected)
                            .sense(egui::Sense::click_and_drag()),
                    )
                    .on_hover_text(
                        "click to select, double-click to edit, drag onto a group to move; Cmd/Ctrl-click for multi-selection",
                    );
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
                    *select = Some(row_data.id);
                }
                if title_resp.double_clicked() {
                    *select = Some(row_data.id);
                    *edit = Some(row_data.id);
                }
            });
        }
        ColumnId::UserName => {
            weak_label(ui, &row_data.username);
        }
        ColumnId::Password => {
            if app.show_passwords {
                weak_label(ui, &row_data.password);
            } else if !row_data.password.is_empty() {
                weak_label(ui, "••••••••");
            }
        }
        ColumnId::Url => {
            weak_label(ui, &row_data.url);
        }
        ColumnId::Notes => {
            weak_label(ui, &row_data.notes);
        }
        ColumnId::Tags => {
            weak_label(ui, &row_data.tags);
        }
    }
}

// ---------------------------------------------------------------------------
// entry details
// ---------------------------------------------------------------------------

pub fn entry_details(ui: &mut egui::Ui, app: &mut App, selected: Option<EntryId>) {
    let Some(id) = selected else {
        ui.add_space(80.0);
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new("Select an item")
                    .size(20.0)
                    .strong()
                    .color(crate::theme::TEXT),
            );
            ui.label(
                egui::RichText::new("Choose an entry to see its details.")
                    .size(13.0)
                    .color(crate::theme::MUTED),
            );
        });
        return;
    };

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
            otp: crate::totp::current_code(&e),
            has_passkey: e.fields.keys().any(|k| is_passkey_field(k)),
            group: {
                let path = group_path(db, e.parent().id());
                if path.is_empty() { "All Items".into() } else { path }
            },
            icon: crate::icons::icon_spec(db, e.icon(), crate::icons::DEFAULT_ENTRY_ICON),
            last_modified: e.times.last_modification,
            attributes: e
                .fields
                .iter()
                .filter(|(k, _)| {
                    !fields::KNOWN_FIELDS.contains(&k.as_str()) && !is_passkey_field(k)
                })
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
    let mut show_password = app.show_passwords;
    let mut export: Option<(String, Vec<u8>)> = None;

    // Header ------------------------------------------------------------
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(crate::theme::BG)
            .corner_radius(16)
            .inner_margin(egui::Margin::same(9))
            .show(ui, |ui| {
                crate::icons::draw_icon_sized(
                    ui,
                    &mut app.icon_cache,
                    Some(&d.icon),
                    54.0,
                );
            });
        ui.add_space(12.0);
        let title_width = (ui.available_width() - 96.0).max(110.0);
        ui.allocate_ui_with_layout(
            egui::vec2(title_width, 60.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&d.title)
                        .size(24.0)
                        .strong()
                        .color(crate::theme::TEXT),
                )
                .wrap(),
            );
            ui.label(
                egui::RichText::new(&d.group)
                    .size(13.0)
                    .color(crate::theme::MUTED),
            );
            if d.has_passkey {
                ui.add_space(4.0);
                egui::Frame::new()
                    .fill(crate::theme::BG)
                    .corner_radius(6)
                    .inner_margin(egui::Margin::symmetric(8, 3))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new("Passkey")
                                .size(12.0)
                                .color(crate::theme::MUTED),
                        );
                    });
            }
            if !d.tags.is_empty() {
                ui.add_space(3.0);
                ui.horizontal_wrapped(|ui| {
                    for tag in d.tags.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                        egui::Frame::new()
                            .fill(crate::theme::BG)
                            .corner_radius(6)
                            .inner_margin(egui::Margin::symmetric(7, 2))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(tag)
                                        .size(11.0)
                                        .color(crate::theme::MUTED),
                                );
                            });
                    }
                });
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
            if ui.add(crate::theme::primary_button("Edit…")).clicked() {
                edit_clicked = true;
            }
        });
    });
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui
            .add(crate::theme::subtle_button("History…"))
            .on_hover_text("Browse and restore previous versions")
            .clicked()
        {
            history_clicked = true;
        }
        if ui
            .add(crate::theme::subtle_button("Auto-Type"))
            .on_hover_text("Type the entry's sequence (macOS needs Accessibility permission)")
            .clicked()
        {
            autotype_clicked = true;
        }
        if ui
            .add(
                egui::Button::new(
                    egui::RichText::new("Delete…").color(crate::theme::DANGER),
                )
                .frame(false),
            )
            .clicked()
        {
            delete_clicked = true;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if !d.tags.is_empty() {
                ui.label(
                    egui::RichText::new(format!("{} history", d.history_count))
                        .size(11.0)
                        .color(crate::theme::MUTED),
                );
            }
        });
    });
    ui.add_space(16.0);

    // The main field card ------------------------------------------------
    detail_card(ui, |ui| {
        field_block(
            ui,
            "username",
            &d.username,
            &d.username,
            "Copy UserName",
            &mut copy,
        );
        ui.add(egui::Separator::default().spacing(6.0));
        let masked = if show_password || d.password.is_empty() {
            d.password.clone()
        } else {
            "••••••••".to_owned()
        };
        let row_width = ui.available_width();
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2((row_width - 170.0).max(80.0), 42.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.label(
                        egui::RichText::new("password")
                            .size(12.0)
                            .color(crate::theme::ACCENT),
                    );
                    ui.label(
                        egui::RichText::new(masked)
                            .size(16.0)
                            .monospace()
                            .color(crate::theme::TEXT),
                    );
                },
            );
            if ui
                .add(crate::theme::subtle_button(if show_password { "Hide" } else { "Show" }))
                .clicked()
            {
                show_password = !show_password;
            }
            if ui
                .add(crate::theme::subtle_button("Copy Password"))
                .clicked()
            {
                copy = Some(d.password.clone());
            }
        });
        if let Some((code, valid_for)) = &d.otp {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_secs(1));
            ui.add(egui::Separator::default().spacing(6.0));
            let row_width = ui.available_width();
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2((row_width - 100.0).max(100.0), 48.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.label(
                            egui::RichText::new("one-time password (TOTP)")
                                .size(12.0)
                                .color(crate::theme::ACCENT),
                        );
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(spaced_code(code))
                                    .size(18.0)
                                    .monospace()
                                    .strong()
                                    .color(crate::theme::TEXT),
                            );
                            ui.label(
                                egui::RichText::new(format!("{valid_for}s"))
                                    .size(11.0)
                                    .color(crate::theme::MUTED),
                            );
                        });
                    },
                );
                if ui
                    .add(crate::theme::subtle_button("Copy TOTP"))
                    .clicked()
                {
                    copy = Some(code.clone());
                }
            });
        }
    });

    // Website ------------------------------------------------------------
    if !d.url.is_empty() {
        ui.add_space(16.0);
        ui.label(
            egui::RichText::new("website")
                .size(12.0)
                .color(crate::theme::ACCENT),
        );
        ui.add(
            egui::Label::new(
                egui::RichText::new(&d.url)
                    .size(15.0)
                    .color(crate::theme::ACCENT),
            )
            .truncate(),
        )
        .on_hover_text(&d.url);
        if ui
            .add(crate::theme::subtle_button("Copy URL"))
            .clicked()
        {
            copy = Some(d.url.clone());
        }
    }

    // Custom fields / security ------------------------------------------
    if !d.attributes.is_empty() {
        ui.add_space(22.0);
        ui.label(
            egui::RichText::new("SECURITY")
                .size(11.0)
                .strong()
                .color(crate::theme::MUTED),
        );
        ui.add_space(4.0);
        detail_card(ui, |ui| {
            for (i, (key, value, protected)) in d.attributes.iter().enumerate() {
                if i > 0 {
                    ui.add(egui::Separator::default().spacing(4.0));
                }
                let shown = if *protected && !show_password {
                    "••••••••".to_owned()
                } else {
                    value.clone()
                };
                let label = if *protected {
                    format!("{key} (protected)")
                } else {
                    key.clone()
                };
                field_block(ui, &label, &shown, value, "Copy", &mut copy);
            }
        });
        if ui.add(crate::theme::subtle_button("Copy Tags")).clicked() {
            copy = Some(d.tags.clone());
        }
    }

    // Notes --------------------------------------------------------------
    if !d.notes.is_empty() {
        ui.add_space(22.0);
        ui.label(
            egui::RichText::new("NOTES")
                .size(11.0)
                .strong()
                .color(crate::theme::MUTED),
        );
        ui.add_space(4.0);
        detail_card(ui, |ui| {
            ui.label(
                egui::RichText::new(&d.notes)
                    .size(14.0)
                    .color(crate::theme::TEXT),
            );
        });
    }

    // Auto-Type summary --------------------------------------------------
    if let Some(at) = &d.autotype {
        ui.add_space(22.0);
        ui.label(
            egui::RichText::new("AUTO-TYPE")
                .size(11.0)
                .strong()
                .color(crate::theme::MUTED),
        );
        ui.add_space(4.0);
        detail_card(ui, |ui| {
            ui.label(
                egui::RichText::new(if at.enabled { "Enabled" } else { "Disabled" })
                    .size(14.0)
                    .strong(),
            );
            if !at.default_sequence.is_empty() {
                ui.label(
                    egui::RichText::new(format!("Sequence: {}", at.default_sequence))
                        .size(13.0)
                        .color(crate::theme::MUTED),
                );
            }
            for (window, sequence) in &at.associations {
                ui.label(
                    egui::RichText::new(format!(
                        "{window} -> {}",
                        if sequence.is_empty() { "(default)" } else { sequence }
                    ))
                    .size(13.0)
                    .color(crate::theme::MUTED),
                );
            }
        });
    }

    // Attachments --------------------------------------------------------
    if !d.attachments.is_empty() {
        ui.add_space(22.0);
        ui.label(
            egui::RichText::new("ATTACHMENTS")
                .size(11.0)
                .strong()
                .color(crate::theme::MUTED),
        );
        ui.add_space(4.0);
        detail_card(ui, |ui| {
            for (i, (name, size)) in d.attachments.iter().enumerate() {
                if i > 0 {
                    ui.add(egui::Separator::default().spacing(4.0));
                }
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(name).size(14.0));
                        ui.label(
                            egui::RichText::new(format!("{size} bytes"))
                                .size(11.0)
                                .color(crate::theme::MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(crate::theme::subtle_button("Export…")).clicked() {
                            if let Some(data) = app
                                .db
                                .as_ref()
                                .and_then(|db| db.entry(id))
                                .and_then(|e| e.attachment_by_name(name).map(|a| a.data.get().clone()))
                            {
                                export = Some((name.clone(), data));
                            }
                        }
                    });
                });
            }
        });
    }

    // Footer -------------------------------------------------------------
    if let Some(t) = d.last_modified {
        ui.add_space(24.0);
        ui.label(
            egui::RichText::new(format!(
                "Last edited {}",
                t.format("%A, %B %-d, %Y at %-I:%M:%S %p")
            ))
            .size(12.0)
            .color(crate::theme::MUTED),
        );
    }

    // Apply pending mutations.
    app.show_passwords = show_password;
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

fn detail_card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(crate::theme::CARD)
        .stroke(egui::Stroke::new(1.0, crate::theme::BORDER))
        .corner_radius(12)
        .inner_margin(egui::Margin::symmetric(16, 10))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            add(ui);
        });
}

fn field_block(
    ui: &mut egui::Ui,
    label: &str,
    shown: &str,
    copy_value: &str,
    copy_label: &str,
    copy: &mut Option<String>,
) {
    let width = ui.available_width();
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2((width - 90.0).max(80.0), 42.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.label(
                    egui::RichText::new(label)
                        .size(12.0)
                        .color(crate::theme::ACCENT),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(shown)
                            .size(16.0)
                            .color(crate::theme::TEXT),
                    )
                    .truncate(),
                );
            },
        );
        if ui.add(crate::theme::subtle_button(copy_label)).clicked() {
            *copy = Some(copy_value.to_owned());
        }
    });
}

fn spaced_code(code: &str) -> String {
    let mut out = String::with_capacity(code.len() + code.len() / 3);
    for (i, c) in code.chars().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// KeePassXC stores passkeys in KPEX_PASSKEY*/KPXC_PASSKEY* attributes.
fn is_passkey_field(key: &str) -> bool {
    key.starts_with("KPEX_PASSKEY") || key.starts_with("KPXC_PASSKEY")
}

struct EntryDetailsData {
    has_passkey: bool,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    tags: String,
    group: String,
    icon: crate::icons::IconSpec,
    last_modified: Option<chrono::NaiveDateTime>,
    otp: Option<(String, u64)>,
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
