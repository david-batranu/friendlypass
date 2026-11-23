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

/// Allocate a full-width sidebar row and paint its hover/selection
/// background. Callers draw the row content and then call `ui.interact` with
/// the returned rect — registering the interaction *after* the content, so
/// the labels do not swallow clicks (same pattern as the entry list).
fn sidebar_row_background(ui: &mut egui::Ui, selected: bool, height: f32) -> egui::Rect {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let hovered = ui.rect_contains_pointer(rect);
    let fill = if selected {
        crate::theme::SIDEBAR_SELECTED
    } else if hovered {
        crate::theme::HOVER
    } else {
        egui::Color32::TRANSPARENT
    };
    if fill != egui::Color32::TRANSPARENT {
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(8), fill);
    }
    rect
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
    pub is_favorite: bool,
    pub month_header: Option<String>,
}

fn entry_is_favorite(entry: &keepass::db::EntryRef<'_>) -> bool {
    entry.tags.iter().any(|t| {
        let lower = t.trim().to_ascii_lowercase();
        lower == "favorite" || lower == "favorites" || lower == "fav" || lower == "star"
    }) || entry
        .fields
        .get("KPXC_FAVORITE")
        .map(|v| v.get() == "1" || v.get().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn entry_row(db: &Database, id: EntryId, with_group: bool) -> EntryRow {
    let entry = db.entry(id).expect("entry exists");
    let group = if with_group { Some(group_path(db, entry.parent().id())) } else { None };
    let month_header = entry
        .times
        .last_modification
        .or(entry.times.creation)
        .map(|t| t.format("%B %Y").to_string().to_uppercase());
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
        is_favorite: entry_is_favorite(&entry),
        month_header,
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
/// entries of the selected group / tag / favorites filter.
fn visible_entries(app: &App) -> Vec<EntryRow> {
    let Some(db) = app.db.as_ref() else { return Vec::new() };

    if !app.search.trim().is_empty() {
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
    } else if app.filter_favorites {
        let mut rows: Vec<EntryRow> = db
            .iter_all_entries()
            .filter(|e| entry_is_favorite(e))
            .map(|e| entry_row(db, e.id(), true))
            .collect();
        sort_rows(&mut rows, app);
        rows
    } else if let Some(tag) = &app.selected_tag {
        let mut rows: Vec<EntryRow> = db
            .iter_all_entries()
            .filter(|e| e.tags.iter().any(|t| t.trim() == tag))
            .map(|e| entry_row(db, e.id(), true))
            .collect();
        sort_rows(&mut rows, app);
        rows
    } else {
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
    let mut selected_tag: Option<String> = app.selected_tag.clone();
    let mut filter_favorites: bool = app.filter_favorites;
    let mut new_dialog: Option<crate::dialogs::Dialog> = None;
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

    let all_tags: Vec<String> = app
        .db
        .as_ref()
        .map(|db| {
            let mut tags = std::collections::BTreeSet::new();
            for e in db.iter_all_entries() {
                for t in &e.tags {
                    let trimmed = t.trim();
                    if !trimmed.is_empty() {
                        tags.insert(trimmed.to_owned());
                    }
                }
            }
            tags.into_iter().collect()
        })
        .unwrap_or_default();

    // If the selected tag disappeared (for example its last entry was deleted
    // or retagged), drop the filter instead of showing an empty list.
    if let Some(tag) = &selected_tag {
        if !all_tags.iter().any(|t| t == tag) {
            selected_tag = None;
        }
    }

    // Split borrows: the icon cache is mutated while rendering rows.
    let mut row_clicked: Option<Option<GroupId>> = None;
    let mut fav_toggled = false;
    let mut add_group_clicked = false;
    let cache = &mut app.icon_cache;

    let mut row_ui = |ui: &mut egui::Ui, row: &GroupRow, is_root: bool| {
        let selected = !filter_favorites
            && selected_tag.is_none()
            && if is_root {
                selected_group.is_none()
            } else {
                selected_group == row.id
            };
        // A full-width row: clicking anywhere on it selects the group, which
        // also makes dragging and the context menu reliable.
        let rect = sidebar_row_background(ui, selected, 28.0);
        let mut content = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(rect.shrink2(egui::vec2(8.0, 3.0)))
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        content.add_space(row.depth.saturating_sub(1) as f32 * 14.0);
        crate::icons::draw_icon(&mut content, cache, Some(&row.icon));
        let label = if is_root {
            format!("All Items ({root_entries})")
        } else {
            format!("{} ({})", row.name, row.entries)
        };
        let mut text = egui::RichText::new(label)
            .size(14.0)
            .color(crate::theme::TEXT);
        if selected {
            text = text.strong();
        }
        content.label(text);
        let resp = ui
            .interact(
                rect,
                ui.id().with(("group-row", row.id)),
                egui::Sense::click_and_drag(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);

        if resp.clicked() {
            row_clicked = Some(if is_root { None } else { row.id });
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
        if resp.dnd_hover_payload::<GroupId>().is_some() {
            if let Some(group_id) = resp.dnd_release_payload::<GroupId>() {
                if row.id != Some(*group_id) {
                    dropped_group = Some((*group_id, row.id));
                }
            }
        } else if let Some(entry_id) = resp.dnd_release_payload::<EntryId>() {
            dropped = Some((*entry_id, row.id));
        }
        if egui::DragAndDrop::has_any_payload(ui.ctx()) && resp.contains_pointer() {
            ui.painter().rect_stroke(
                rect.expand(1.0),
                8.0,
                ui.visuals().selection.stroke,
                egui::StrokeKind::Middle,
            );
        }
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

    // Favorites shortcut row (like 1Password).
    {
        let fav_selected = filter_favorites;
        let rect = sidebar_row_background(ui, fav_selected, 28.0);
        let mut content = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(rect.shrink2(egui::vec2(8.0, 3.0)))
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        let (star_rect, _) =
            content.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
        crate::theme::draw_star_badge(content.painter(), star_rect.center(), 7.5);
        let mut text = egui::RichText::new("Favorites")
            .size(14.0)
            .color(crate::theme::TEXT);
        if fav_selected {
            text = text.strong();
        }
        content.label(text);
        let resp = ui
            .interact(
                rect,
                ui.id().with("favorites-row"),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if resp.clicked() {
            fav_toggled = true;
        }
    }

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        crate::theme::draw_chevron_down(ui, crate::theme::MUTED);
        ui.label(
            egui::RichText::new("GROUPS")
                .size(11.0)
                .strong()
                .color(crate::theme::MUTED),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("+")
                            .size(15.0)
                            .strong()
                            .color(crate::theme::MUTED),
                    )
                    .frame(false),
                )
                .on_hover_text("New Group")
                .clicked()
            {
                add_group_clicked = true;
            }
        });
    });
    ui.add_space(2.0);
    for row in &rows {
        row_ui(ui, row, false);
    }

    if let Some(group) = row_clicked {
        selected_group = group;
        selected_tag = None;
        filter_favorites = false;
    }
    if fav_toggled {
        filter_favorites = !filter_favorites;
        if filter_favorites {
            selected_tag = None;
        }
    }
    if add_group_clicked {
        if let Some(parent) = selected_group.or(root_id) {
            new_dialog = Some(crate::dialogs::Dialog::GroupNew(Box::new(
                crate::dialogs::GroupEdit::new(parent),
            )));
        }
    }

    if !all_tags.is_empty() {
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            crate::theme::draw_chevron_down(ui, crate::theme::MUTED);
            ui.label(
                egui::RichText::new("TAGS")
                    .size(11.0)
                    .strong()
                    .color(crate::theme::MUTED),
            );
        });
        ui.add_space(2.0);
        for tag in &all_tags {
            let is_sel = selected_tag.as_deref() == Some(tag.as_str());
            let rect = sidebar_row_background(ui, is_sel, 26.0);
            let mut content = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(rect.shrink2(egui::vec2(8.0, 3.0)))
                    .layout(egui::Layout::left_to_right(egui::Align::Center)),
            );
            crate::theme::draw_tag_pill(&mut content, crate::theme::TAG_GREEN);
            let mut text = egui::RichText::new(tag)
                .size(13.5)
                .color(crate::theme::TEXT);
            if is_sel {
                text = text.strong();
            }
            content.label(text);
            let resp = ui
                .interact(
                    rect,
                    ui.id().with(("tag-row", tag)),
                    egui::Sense::click(),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            if resp.clicked() {
                if is_sel {
                    selected_tag = None;
                } else {
                    selected_tag = Some(tag.clone());
                    filter_favorites = false;
                }
            }
        }
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
    app.selected_tag = selected_tag;
    app.filter_favorites = filter_favorites;
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
    } else if app.filter_favorites {
        "Favorites".to_owned()
    } else if let Some(tag) = &app.selected_tag {
        format!("Tag: {tag}")
    } else {
        app.selected_group
            .and_then(|id| app.db.as_ref().and_then(|db| db.group(id)).map(|g| g.name.clone()))
            .unwrap_or_else(|| "All Categories".into())
    };
    ui.horizontal(|ui| {
        crate::theme::draw_categories_grid_icon(ui);
        ui.label(
            egui::RichText::new(&title)
                .size(14.5)
                .color(crate::theme::TEXT),
        );
        crate::theme::draw_chevron_down(ui, crate::theme::MUTED);
        if app.selected_tag.is_some() || app.filter_favorites {
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("×")
                            .size(15.0)
                            .color(crate::theme::MUTED),
                    )
                    .frame(false),
                )
                .on_hover_text("Clear the filter")
                .clicked()
            {
                app.selected_tag = None;
                app.filter_favorites = false;
            }
        }
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
    ui.add_space(10.0);

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
            ui.spacing_mut().item_spacing.y = 3.0;
            let mut last_month: Option<String> = None;
            for row in rows {
                let month = row
                    .month_header
                    .clone()
                    .unwrap_or_else(|| "MARCH 2025".to_owned());
                if last_month.as_deref() != Some(month.as_str()) {
                    if last_month.is_some() {
                        ui.add_space(10.0);
                    }
                    ui.label(
                        egui::RichText::new(&month)
                            .size(11.0)
                            .strong()
                            .color(crate::theme::MUTED),
                    );
                    ui.add_space(4.0);
                    last_month = Some(month);
                }

                let selected = app.selected_entry == Some(row.id)
                    || app.selected_entries.contains(&row.id);
                let (rect, _alloc) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 56.0),
                    egui::Sense::hover(),
                );
                let hovered = ui.rect_contains_pointer(rect);
                let fill = if selected {
                    crate::theme::LIST_SELECTED
                } else if hovered {
                    crate::theme::HOVER
                } else {
                    egui::Color32::TRANSPARENT
                };
                if fill != egui::Color32::TRANSPARENT {
                    ui.painter()
                        .rect_filled(rect, egui::CornerRadius::same(8), fill);
                }
                let mut content = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(rect.shrink2(egui::vec2(10.0, 6.0)))
                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                );
                let icon_resp = egui::Frame::new()
                    .fill(crate::theme::BG)
                    .corner_radius(8)
                    .inner_margin(egui::Margin::same(4))
                    .show(&mut content, |ui| {
                        crate::icons::draw_icon_sized(
                            ui,
                            &mut app.icon_cache,
                            Some(&row.icon),
                            26.0,
                        );
                    });
                if row.is_favorite {
                    crate::theme::draw_star_badge(
                        content.painter(),
                        icon_resp.response.rect.right_bottom() + egui::vec2(-2.0, -2.0),
                        5.5,
                    );
                }
                content.add_space(10.0);
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
                                .size(15.5)
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
            parent_group_id: e.parent().id(),
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
                    !fields::KNOWN_FIELDS.contains(&k.as_str())
                        && !is_passkey_field(k)
                        && *k != "KPXC_FAVORITE"
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
            attachments: e
                .attachments_named()
                .map(|(name, a)| (name.to_owned(), a.data.get().len()))
                .collect(),
        })
    });
    let Some(d) = data else { return };

    let db_name = std::path::Path::new(&app.db_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "database".into());

    let mut copy: Option<String> = None;
    let mut edit_clicked = false;
    let mut delete_clicked = false;
    let mut history_clicked = false;
    let mut autotype_clicked = false;
    let mut share_clicked = false;
    let mut show_password = app.show_passwords;
    let mut export: Option<(String, Vec<u8>)> = None;

    // 1Password-style top breadcrumb & action bar -----------------------
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(&db_name)
                .size(13.5)
                .color(crate::theme::TEXT),
        );
        ui.label(egui::RichText::new("|").size(13.0).color(crate::theme::BORDER));
        ui.label(
            egui::RichText::new(&d.group)
                .size(13.5)
                .color(crate::theme::TEXT),
        );
        crate::theme::draw_chevron_down(ui, crate::theme::MUTED);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            crate::theme::draw_kebab_icon(ui, crate::theme::MUTED);
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("Edit…")
                            .size(14.0)
                            .color(crate::theme::TEXT),
                    )
                    .frame(false),
                )
                .clicked()
            {
                edit_clicked = true;
            }
            let (p_rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
            crate::theme::draw_pencil_icon(ui.painter(), p_rect.center(), crate::theme::MUTED);
            ui.add_space(6.0);
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("Share")
                            .size(14.0)
                            .color(crate::theme::TEXT),
                    )
                    .frame(false),
                )
                .on_hover_text("Share group via KeeShare")
                .clicked()
            {
                share_clicked = true;
            }
            let (s_rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
            crate::theme::draw_share_icon(ui.painter(), s_rect.center(), crate::theme::MUTED);
        });
    });
    ui.add_space(18.0);

    // Header: Large icon + Favorite star + Title ------------------------
    ui.horizontal(|ui| {
        let icon_resp = egui::Frame::new()
            .fill(crate::theme::BG)
            .corner_radius(14)
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                crate::icons::draw_icon_sized(
                    ui,
                    &mut app.icon_cache,
                    Some(&d.icon),
                    52.0,
                );
            });
        crate::theme::draw_star_badge(
            ui.painter(),
            icon_resp.response.rect.right_bottom() + egui::vec2(-3.0, -3.0),
            9.0,
        );
        ui.add_space(14.0);
        ui.vertical(|ui| {
            ui.add_space(10.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&d.title)
                        .size(24.0)
                        .strong()
                        .color(crate::theme::TEXT),
                )
                .wrap(),
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
                ui.add_space(4.0);
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
    });
    ui.add_space(18.0);

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
            "••••••••••".to_owned()
        };
        let (strength_label, strength_frac, strength_color) = password_strength(&d.password);
        let row_width = ui.available_width();
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2((row_width - 255.0).max(80.0), 42.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.label(
                        egui::RichText::new("password")
                            .size(12.5)
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
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(crate::theme::subtle_button("Copy Password"))
                    .clicked()
                {
                    copy = Some(d.password.clone());
                }
                if ui
                    .add(crate::theme::subtle_button(if show_password { "Hide" } else { "Show" }))
                    .clicked()
                {
                    show_password = !show_password;
                }
                if !d.password.is_empty() {
                    crate::theme::draw_progress_ring(ui, 7.0, strength_frac, strength_color);
                    ui.label(
                        egui::RichText::new(strength_label)
                            .size(13.0)
                            .color(crate::theme::MUTED),
                    );
                }
            });
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
                                .size(12.5)
                                .color(crate::theme::ACCENT),
                        );
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(spaced_code(code))
                                    .size(17.0)
                                    .monospace()
                                    .color(crate::theme::TEXT),
                            );
                            let frac = (*valid_for as f32 / 30.0).clamp(0.05, 1.0);
                            crate::theme::draw_progress_ring(
                                ui,
                                6.5,
                                frac,
                                crate::theme::GOOD,
                            );
                            ui.label(
                                egui::RichText::new(format!("{valid_for}"))
                                    .size(13.0)
                                    .color(crate::theme::MUTED),
                            );
                        });
                    },
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add(crate::theme::subtle_button("Copy TOTP"))
                        .clicked()
                    {
                        copy = Some(code.clone());
                    }
                });
            });
        }
    });

    // Website ------------------------------------------------------------
    if !d.url.is_empty() {
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new("website")
                        .size(12.5)
                        .color(crate::theme::ACCENT),
                );
                let (head, tail) = split_url_domain(&d.url);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    if !head.is_empty() {
                        ui.label(
                            egui::RichText::new(head)
                                .size(15.5)
                                .color(crate::theme::MUTED),
                        );
                    }
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(tail)
                                .size(15.5)
                                .color(crate::theme::TEXT),
                        )
                        .truncate(),
                    )
                    .on_hover_text(&d.url);
                });
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(crate::theme::subtle_button("Copy URL"))
                    .clicked()
                {
                    copy = Some(d.url.clone());
                }
            });
        });
    }

    // Custom fields / security ------------------------------------------
    if !d.attributes.is_empty() {
        ui.add_space(26.0);
        ui.label(
            egui::RichText::new("SECURITY")
                .size(12.5)
                .strong()
                .color(crate::theme::TEXT),
        );
        ui.add_space(8.0);
        for (i, (key, value, protected)) in d.attributes.iter().enumerate() {
            if i > 0 {
                ui.add_space(10.0);
            }
            let shown = if *protected && !show_password {
                "••••••••••".to_owned()
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
    ui.add_space(26.0);
    if let Some(t) = d.last_modified {
        ui.horizontal(|ui| {
            crate::theme::draw_chevron_right(ui, crate::theme::MUTED);
            ui.label(
                egui::RichText::new(format!(
                    "Last edited {}",
                    t.format("%A, %B %-d, %Y at %-I:%M:%S %p")
                ))
                .size(13.0)
                .color(crate::theme::TEXT),
            );
        });
        ui.add_space(8.0);
    }
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
                    egui::RichText::new("Delete…")
                        .size(12.5)
                        .color(crate::theme::DANGER),
                )
                .frame(false),
            )
            .clicked()
        {
            delete_clicked = true;
        }
    });

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
    if share_clicked {
        if let Some(db) = app.db.as_ref() {
            app.dialog = crate::dialogs::Dialog::ShareGroup(Box::new(
                crate::dialogs::ShareDialog::for_group(db, d.parent_group_id),
            ));
        }
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
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(16, 12))
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
            egui::vec2((width - 110.0).max(80.0), 42.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.label(
                    egui::RichText::new(label)
                        .size(12.5)
                        .color(crate::theme::ACCENT),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(shown)
                            .size(15.5)
                            .color(crate::theme::TEXT),
                    )
                    .truncate(),
                );
            },
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(crate::theme::subtle_button(copy_label)).clicked() {
                *copy = Some(copy_value.to_owned());
            }
        });
    });
}

fn password_strength(pw: &str) -> (&'static str, f32, egui::Color32) {
    let len = pw.chars().count();
    let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_sym = pw.chars().any(|c| !c.is_ascii_alphanumeric());
    let classes =
        has_upper as usize + has_lower as usize + has_digit as usize + has_sym as usize;
    let score = len.saturating_mul(2) + classes * 4;
    if score >= 36 {
        ("Fantastic", 0.96, crate::theme::GOOD)
    } else if score >= 20 {
        ("Very Good", 0.80, crate::theme::GOOD)
    } else if score >= 12 {
        ("Good", 0.55, crate::theme::WARN)
    } else {
        ("Weak", 0.25, crate::theme::DANGER)
    }
}

/// Split a URL into `(scheme_prefix, domain_and_path)` so we can dim `https://`
/// and highlight the domain like 1Password.
fn split_url_domain(url: &str) -> (&str, &str) {
    for prefix in ["https://www.", "http://www.", "https://", "http://"] {
        if let Some(rest) = url.strip_prefix(prefix) {
            return (&url[..prefix.len()], rest);
        }
    }
    ("", url)
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
    parent_group_id: GroupId,
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
    attachments: Vec<(String, usize)>,
}

struct AutoTypeSummary {
    enabled: bool,
    default_sequence: String,
    associations: Vec<(String, String)>,
}
