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
        crate::theme::p().sidebar_selected
    } else if hovered {
        crate::theme::p().sidebar_hover
    } else {
        egui::Color32::TRANSPARENT
    };
    if fill != egui::Color32::TRANSPARENT {
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(8), fill);
    }
    if selected {
        ui.painter().rect_stroke(
            rect,
            egui::CornerRadius::same(8),
            egui::Stroke::new(1.0, crate::theme::p().list_selected_stroke),
            egui::StrokeKind::Inside,
        );
        let bar = egui::Rect::from_min_max(
            egui::pos2(rect.left() + 2.5, rect.top() + 5.0),
            egui::pos2(rect.left() + 5.5, rect.bottom() - 5.0),
        );
        ui.painter()
            .rect_filled(bar, egui::CornerRadius::same(2), crate::theme::p().accent);
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
                    icon: crate::icons::group_icon_spec(db, c.id()),
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

/// Width kept free at the right of a list row for the attachment marker
/// (paperclip plus a one-digit count and its padding).
pub const ATTACHMENT_BADGE_RESERVE: f32 = 26.0;

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
    /// How many files are attached to the entry (drives the paperclip badge
    /// and the "Attachments" filter).
    pub attachments: usize,
    /// Last modification (or creation) time; drives the Modified sort.
    pub modified: Option<chrono::NaiveDateTime>,
}

impl EntryRow {
    /// The month heading this row falls under when sorting by date
    /// ("MARCH 2025"), or "NO DATE" for entries without timestamps.
    pub fn month_header(&self) -> String {
        month_header(self.modified)
    }
}

/// The list's month heading for a timestamp.
pub fn month_header(t: Option<chrono::NaiveDateTime>) -> String {
    match t {
        Some(t) => t.format("%B %Y").to_string().to_uppercase(),
        None => "NO DATE".to_owned(),
    }
}

/// The custom field that marks an entry as a favorite ("1" or "true").
pub const FAVORITE_FIELD: &str = "FRIENDLYPASS_FAVORITE";

/// Tags other apps use to star entries; treated as favorites too.
pub fn is_favorite_tag(tag: &str) -> bool {
    let lower = tag.trim().to_ascii_lowercase();
    lower == "favorite" || lower == "favorites" || lower == "fav" || lower == "star"
}

pub fn entry_is_favorite(entry: &keepass::db::EntryRef<'_>) -> bool {
    entry.tags.iter().any(|t| is_favorite_tag(t))
        || entry
            .fields
            .get(FAVORITE_FIELD)
            .map(|v| v.get() == "1" || v.get().eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

fn entry_row(db: &Database, id: EntryId, with_group: bool) -> EntryRow {
    let entry = db.entry(id).expect("entry exists");
    let group = if with_group { Some(group_path(db, entry.parent().id())) } else { None };
    let modified = entry.times.last_modification.or(entry.times.creation);
    let url = entry.get(fields::URL).unwrap_or_default().to_owned();
    let resolved_url = crate::refs::resolve_references(db, &url);
    EntryRow {
        id,
        group,
        icon: crate::icons::entry_icon_spec(
            db,
            &entry,
            entry.get(fields::TITLE).unwrap_or_default(),
            entry.get(fields::USERNAME).unwrap_or_default(),
            &resolved_url,
        ),
        title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
        username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
        password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
        url,
        notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
        tags: entry.tags.join(", "),
        is_favorite: entry_is_favorite(&entry),
        attachments: entry.attachments_named().count(),
        modified,
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

/// The ids of the entries matching the current search / filter / group,
/// unsorted, plus whether they come from several groups (search and the
/// filters span the whole database, so rows then show their group).
fn matching_ids(app: &App) -> (Vec<EntryId>, bool) {
    let Some(db) = app.db.as_ref() else { return (Vec::new(), false) };

    if !app.search.trim().is_empty() {
        let needle = app.search.to_lowercase();
        let ids = db
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
            .map(|e| e.id())
            .collect();
        (ids, true)
    } else if app.filter_attachments {
        let ids = db
            .iter_all_entries()
            .filter(|e| e.attachments_named().next().is_some())
            .map(|e| e.id())
            .collect();
        (ids, true)
    } else if app.filter_favorites {
        let ids = db
            .iter_all_entries()
            .filter(|e| entry_is_favorite(e))
            .map(|e| e.id())
            .collect();
        (ids, true)
    } else if let Some(tag) = &app.selected_tag {
        let ids = db
            .iter_all_entries()
            .filter(|e| e.tags.iter().any(|t| t.trim() == tag))
            .map(|e| e.id())
            .collect();
        (ids, true)
    } else {
        let group = app
            .selected_group
            .unwrap_or_else(|| db.root().id());
        let Some(g) = db.group(group) else { return (Vec::new(), false) };
        (g.entries().map(|e| e.id()).collect(), false)
    }
}

/// The entries to display: search results across the database, or the
/// entries of the selected group / tag / favorites / attachments filter.
fn visible_entries(app: &App) -> Vec<EntryRow> {
    let Some(db) = app.db.as_ref() else { return Vec::new() };
    let (ids, with_group) = matching_ids(app);
    let mut rows: Vec<EntryRow> = ids
        .into_iter()
        .map(|id| entry_row(db, id, with_group))
        .collect();
    sort_rows(&mut rows, app);
    rows
}

/// The ids of the entries the list currently shows, in list order. Handy for
/// tests and for anything that needs the filtered set without the rows.
pub fn visible_entry_ids(app: &App) -> Vec<EntryId> {
    visible_entries(app).into_iter().map(|r| r.id).collect()
}

/// How many entries the list shows (cheap: no sorting or row building).
pub fn visible_entry_count(app: &App) -> usize {
    matching_ids(app).0.len()
}

fn sort_rows(rows: &mut [EntryRow], app: &App) {
    match app.sort_column {
        SortColumn::Modified => rows.sort_by(|a, b| {
            a.modified
                .cmp(&b.modified)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        }),
        col => {
            let key = |r: &EntryRow| match col {
                SortColumn::Title => r.title.clone(),
                SortColumn::Username => r.username.clone(),
                SortColumn::Password => r.password.clone(),
                SortColumn::Url => r.url.clone(),
                SortColumn::Notes => r.notes.clone(),
                SortColumn::Tags => r.tags.clone(),
                SortColumn::Modified => unreachable!(),
            };
            rows.sort_by_key(key);
        }
    }
    if app.sort_desc {
        rows.reverse();
    }
}

/// "1 entry" / "3 entries".
pub fn pluralize(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {plural}")
    }
}

// ---------------------------------------------------------------------------
// group tree
// ---------------------------------------------------------------------------

pub fn group_tree(ui: &mut egui::Ui, app: &mut App) {

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
        .map(|db| crate::icons::group_icon_spec(db, db.root().id()))
        .unwrap_or(crate::icons::IconSpec::Folder);

    // Library header: icon + database name.
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(crate::theme::p().accent_soft)
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
                        .color(crate::theme::p().text),
                )
                .truncate(),
            );
            ui.label(
                egui::RichText::new(crate::brand::NAME)
                    .size(11.0)
                    .color(crate::theme::p().muted),
            );
        });
    });
    ui.add_space(18.0);
    ui.label(
        egui::RichText::new("LIBRARY")
            .size(11.0)
            .strong()
            .color(crate::theme::p().muted),
    );
    ui.add_space(4.0);

    let mut selected_group: Option<GroupId> = app.selected_group;
    let mut selected_tag: Option<String> = app.selected_tag.clone();
    let mut filter_favorites: bool = app.filter_favorites;
    let mut filter_attachments: bool = app.filter_attachments;
    let mut new_dialog: Option<crate::dialogs::Dialog> = None;
    // What a group row's context menu asked for.
    let mut group_action: Option<GroupAction> = None;
    // Group-scoped export chosen from a row's context menu.
    let mut export_request: Option<(Option<GroupId>, &'static str)> = None;
    let bin_id = app
        .db
        .as_ref()
        .and_then(|db| db.recycle_bin())
        .map(|b| b.id());
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
    let mut attachments_toggled = false;
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
        let rect = sidebar_row_background(ui, selected, 30.0);
        let mut content = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(rect.shrink2(egui::vec2(10.0, 4.0)))
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
            .size(13.5)
            .color(if selected {
                crate::theme::p().accent
            } else {
                crate::theme::p().text
            });
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
            ui.set_min_width(210.0);
            let target = if is_root { root_id } else { row.id };
            if let Some(target) = target {
                if ui.button("New subgroup…").clicked() {
                    group_action = Some(GroupAction::NewSubgroup(target));
                    ui.close();
                }
            }
            // The root group cannot be renamed, shared or deleted.
            if let (false, Some(id)) = (is_root, row.id) {
                if ui.button("Rename group…").clicked() {
                    group_action = Some(GroupAction::Rename(id));
                    ui.close();
                }
                if ui.button("Share group…").clicked() {
                    group_action = Some(GroupAction::Share(id));
                    ui.close();
                }
                if Some(id) == bin_id {
                    if ui
                        .button(egui::RichText::new("Empty Recycle Bin…").color(crate::theme::p().danger))
                        .clicked()
                    {
                        group_action = Some(GroupAction::EmptyBin);
                        ui.close();
                    }
                }
                if ui
                    .button(egui::RichText::new("Delete group…").color(crate::theme::p().danger))
                    .clicked()
                {
                    group_action = Some(GroupAction::Delete(id));
                    ui.close();
                }
            }
            ui.separator();
            ui.label(
                egui::RichText::new(if is_root { "Database export" } else { "Group export" })
                    .size(12.0)
                    .color(crate::theme::p().muted),
            );
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
        let rect = sidebar_row_background(ui, fav_selected, 30.0);
        let mut content = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(rect.shrink2(egui::vec2(10.0, 4.0)))
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        let (star_rect, _) =
            content.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
        crate::theme::draw_star_badge(content.painter(), star_rect.center(), 7.5);
        let mut text = egui::RichText::new("Favorites")
            .size(13.5)
            .color(if fav_selected {
                crate::theme::p().accent
            } else {
                crate::theme::p().text
            });
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

    // Attachments shortcut row: the same idea as Favorites.
    {
        let with_attachments = app
            .db
            .as_ref()
            .map(|db| {
                db.iter_all_entries()
                    .filter(|e| e.attachments_named().next().is_some())
                    .count()
            })
            .unwrap_or(0);
        let sel = filter_attachments;
        let rect = sidebar_row_background(ui, sel, 30.0);
        let mut content = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(rect.shrink2(egui::vec2(10.0, 4.0)))
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        let (clip_rect, _) =
            content.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
        crate::theme::draw_paperclip_icon(
            content.painter(),
            clip_rect.center(),
            15.0,
            if sel {
                crate::theme::p().accent
            } else {
                crate::theme::p().muted
            },
        );
        let mut text = egui::RichText::new(format!("Attachments ({with_attachments})"))
            .size(13.5)
            .color(if sel {
                crate::theme::p().accent
            } else {
                crate::theme::p().text
            });
        if sel {
            text = text.strong();
        }
        content.label(text);
        let resp = ui
            .interact(
                rect,
                ui.id().with("attachments-row"),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text("Show only entries that have files attached");
        if resp.clicked() {
            attachments_toggled = true;
        }
    }

    ui.add_space(12.0);
    let mut groups_collapsed = app.groups_collapsed;
    ui.horizontal(|ui| {
        if crate::theme::chevron_toggle(ui, "groups-section", !groups_collapsed, crate::theme::p().muted)
            .on_hover_text(if groups_collapsed { "Expand groups" } else { "Collapse groups" })
            .clicked()
        {
            groups_collapsed = !groups_collapsed;
        }
        ui.label(
            egui::RichText::new("GROUPS")
                .size(11.0)
                .strong()
                .color(crate::theme::p().muted),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("+")
                            .size(15.0)
                            .strong()
                            .color(crate::theme::p().muted),
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
    if !groups_collapsed {
        for row in &rows {
            row_ui(ui, row, false);
        }
    }

    if let Some(group) = row_clicked {
        selected_group = group;
        selected_tag = None;
        filter_favorites = false;
        filter_attachments = false;
    }
    if fav_toggled {
        filter_favorites = !filter_favorites;
        if filter_favorites {
            selected_tag = None;
            filter_attachments = false;
        }
    }
    if attachments_toggled {
        filter_attachments = !filter_attachments;
        if filter_attachments {
            selected_tag = None;
            filter_favorites = false;
        }
    }
    if add_group_clicked {
        if let Some(parent) = selected_group.or(root_id) {
            new_dialog = Some(crate::dialogs::Dialog::GroupNew(Box::new(
                crate::dialogs::GroupEdit::new(parent),
            )));
        }
    }

    let mut tags_collapsed = app.tags_collapsed;
    if !all_tags.is_empty() {
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if crate::theme::chevron_toggle(ui, "tags-section", !tags_collapsed, crate::theme::p().muted)
                .on_hover_text(if tags_collapsed { "Expand tags" } else { "Collapse tags" })
                .clicked()
            {
                tags_collapsed = !tags_collapsed;
            }
            ui.label(
                egui::RichText::new("TAGS")
                    .size(11.0)
                    .strong()
                    .color(crate::theme::p().muted),
            );
        });
        ui.add_space(2.0);
    }
    if !all_tags.is_empty() && !tags_collapsed {
        for tag in &all_tags {
            let is_sel = selected_tag.as_deref() == Some(tag.as_str());
            let rect = sidebar_row_background(ui, is_sel, 28.0);
            let mut content = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(rect.shrink2(egui::vec2(10.0, 4.0)))
                    .layout(egui::Layout::left_to_right(egui::Align::Center)),
            );
            crate::theme::draw_tag_pill(&mut content, crate::theme::p().tag_green);
            let mut text = egui::RichText::new(tag)
                .size(13.5)
                .color(if is_sel {
                    crate::theme::p().accent
                } else {
                    crate::theme::p().text
                });
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
                    filter_attachments = false;
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

    // A hint while the Recycle Bin is open (its actions live in the row's
    // context menu).
    if bin_id.is_some() && selected_group == bin_id {
        ui.add_space(8.0);
        weak_label(
            ui,
            "Recycle Bin: deleting from here is permanent. Right-click it to empty it.",
        );
    }

    // Apply pending mutations now that the immutable borrows are over.
    app.selected_group = selected_group;
    app.selected_tag = selected_tag;
    app.filter_favorites = filter_favorites;
    app.filter_attachments = filter_attachments;
    app.groups_collapsed = groups_collapsed;
    app.tags_collapsed = tags_collapsed;
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
    match group_action {
        Some(GroupAction::NewSubgroup(parent)) => {
            app.dialog = crate::dialogs::Dialog::GroupNew(Box::new(
                crate::dialogs::GroupEdit::new(parent),
            ));
        }
        Some(GroupAction::Rename(id)) => {
            let name = app
                .db
                .as_ref()
                .and_then(|db| db.group(id))
                .map(|g| g.name.clone())
                .unwrap_or_default();
            app.dialog = crate::dialogs::Dialog::GroupRename(Box::new(
                crate::dialogs::GroupEdit { id: Some(id), parent: id, name },
            ));
        }
        Some(GroupAction::Delete(id)) => {
            app.dialog = crate::dialogs::Dialog::ConfirmDeleteGroup(id);
        }
        Some(GroupAction::Share(id)) => {
            if let Some(db) = app.db.as_ref() {
                app.dialog = crate::dialogs::Dialog::ShareGroup(Box::new(
                    crate::dialogs::ShareDialog::for_group(db, id),
                ));
            }
        }
        Some(GroupAction::EmptyBin) => {
            app.dialog = crate::dialogs::Dialog::ConfirmEmptyRecycleBin;
        }
        None => {}
    }
}

/// A group row context-menu action.
enum GroupAction {
    NewSubgroup(GroupId),
    Rename(GroupId),
    Delete(GroupId),
    Share(GroupId),
    EmptyBin,
}

/// The sort direction in words, for the Sort button ("A–Z", "newest
/// first"). The bundled UI font has no arrow glyphs, so no "↑".
pub fn sort_direction_label(col: SortColumn, desc: bool) -> &'static str {
    match (col, desc) {
        (SortColumn::Modified, true) => "newest first",
        (SortColumn::Modified, false) => "oldest first",
        (_, false) => "A\u{2013}Z",
        (_, true) => "Z\u{2013}A",
    }
}

/// The table header's sort marker (ASCII: the UI font has no arrows).
fn sort_marker(desc: bool) -> &'static str {
    if desc {
        "v"
    } else {
        "^"
    }
}

/// A group name that opens a picker: picking another group switches the
/// sidebar/list to it. Returns the chosen group (`Some(None)` = the root
/// "All Items") when the user picks one.
fn group_picker(
    ui: &mut egui::Ui,
    app: &App,
    current: Option<GroupId>,
    id_salt: &str,
) -> Option<Option<GroupId>> {
    let db = app.db.as_ref()?;
    let current_name = current
        .and_then(|id| db.group(id))
        .map(|g| g.name.clone())
        .unwrap_or_else(|| "All Items".to_owned());
    let rows = flatten_groups(db);
    let mut picked = None;
    let menu = ui.menu_button(
        egui::RichText::new(current_name).size(13.5),
        |ui| {
            ui.set_min_width(220.0);
            if ui
                .selectable_label(current.is_none(), "All Items")
                .clicked()
            {
                picked = Some(None);
                ui.close();
            }
            ui.separator();
            for row in &rows {
                let Some(id) = row.id else { continue };
                ui.horizontal(|ui| {
                    ui.add_space((row.depth.saturating_sub(1)) as f32 * 12.0);
                    if ui
                        .selectable_label(Some(id) == current, &row.name)
                        .on_hover_text(format!("{} entr{}", row.entries, if row.entries == 1 { "y" } else { "ies" }))
                        .clicked()
                    {
                        picked = Some(Some(id));
                        ui.close();
                    }
                });
            }
        },
    );
    menu.response
        .on_hover_text("Switch group (this entry's group is shown here)");
    let _ = id_salt;
    picked
}

/// The flattened group list, for pickers outside the sidebar.

// ---------------------------------------------------------------------------
// entry table
// ---------------------------------------------------------------------------

/// The middle column: a 1Password-style card list or the configurable
/// spreadsheet-style table.
/// What the list's title menu picked.
enum ListPick {
    All,
    Favorites,
    Attachments,
    Group(GroupId),
}

pub fn entry_view(ui: &mut egui::Ui, app: &mut App) {
    let rows = visible_entries(app);
    let title = if !app.search.trim().is_empty() {
        "Search Results".to_owned()
    } else if app.filter_favorites {
        "Favorites".to_owned()
    } else if app.filter_attachments {
        "With Attachments".to_owned()
    } else if let Some(tag) = &app.selected_tag {
        format!("Tag: {tag}")
    } else {
        app.selected_group
            .and_then(|id| app.db.as_ref().and_then(|db| db.group(id)).map(|g| g.name.clone()))
            .unwrap_or_else(|| "All Items".into())
    };
    // Snapshot the picker entries before the closure borrows `app`.
    let picker_groups: Vec<(GroupId, String, usize, usize)> = app
        .db
        .as_ref()
        .map(|db| {
            flatten_groups(db)
                .into_iter()
                .filter_map(|r| r.id.map(|id| (id, r.name, r.depth, r.entries)))
                .collect()
        })
        .unwrap_or_default();
    let mut pick: Option<ListPick> = None;
    ui.horizontal(|ui| {
        crate::theme::draw_categories_grid_icon(ui);
        ui.menu_button(
            egui::RichText::new(&title).size(14.5),
            |ui| {
                ui.set_min_width(220.0);
                if ui.selectable_label(false, "All Items").clicked() {
                    pick = Some(ListPick::All);
                    ui.close();
                }
                if ui.selectable_label(false, "Favorites").clicked() {
                    pick = Some(ListPick::Favorites);
                    ui.close();
                }
                if ui
                    .selectable_label(false, "With Attachments")
                    .clicked()
                {
                    pick = Some(ListPick::Attachments);
                    ui.close();
                }
                if !picker_groups.is_empty() {
                    ui.separator();
                }
                for (id, name, depth, entries) in &picker_groups {
                    ui.horizontal(|ui| {
                        ui.add_space((depth.saturating_sub(1)) as f32 * 12.0);
                        if ui
                            .selectable_label(false, name)
                            .on_hover_text(format!(
                                "{entries} entr{}",
                                if *entries == 1 { "y" } else { "ies" }
                            ))
                            .clicked()
                        {
                            pick = Some(ListPick::Group(*id));
                            ui.close();
                        }
                    });
                }
            },
        )
        .response
        .on_hover_text("Choose what the list shows");
        if app.selected_tag.is_some() || app.filter_favorites || app.filter_attachments {
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("×")
                            .size(15.0)
                            .color(crate::theme::p().muted),
                    )
                    .frame(false),
                )
                .on_hover_text("Clear the filter")
                .clicked()
            {
                app.selected_tag = None;
                app.filter_favorites = false;
                app.filter_attachments = false;
            }
        }
    });
    // Second row: the current sort (a menu) on the left, list/table on the
    // right. On one row with the title they collided in the narrow column.
    ui.horizontal(|ui| {
        let sort_label = format!(
            "Sort: {} ({})",
            app.sort_column.label(),
            sort_direction_label(app.sort_column, app.sort_desc)
        );
        ui.menu_button(sort_label, |ui| {
            for col in SortColumn::ALL {
                if ui
                    .selectable_label(app.sort_column == col, col.label())
                    .clicked()
                {
                    app.sort_column = col;
                    app.sort_desc = col.default_desc();
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
        });
    });
    if let Some(pick) = pick {
        app.search.clear();
        app.selected_tag = None;
        match pick {
            ListPick::All => {
                app.selected_group = None;
                app.filter_favorites = false;
                app.filter_attachments = false;
            }
            ListPick::Favorites => {
                app.filter_favorites = true;
                app.filter_attachments = false;
            }
            ListPick::Attachments => {
                app.filter_attachments = true;
                app.filter_favorites = false;
            }
            ListPick::Group(id) => {
                app.selected_group = Some(id);
                app.filter_favorites = false;
                app.filter_attachments = false;
            }
        }
    }
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
            ui.spacing_mut().item_spacing.y = 4.0;
            // Month headings only make sense when the list is in date order;
            // in any other order they would repeat and fragment the list.
            let by_date = app.sort_column == SortColumn::Modified;
            let mut last_month: Option<String> = None;
            let mut action: Option<(EntryId, RowAction)> = None;
            let scroll_to = std::mem::take(&mut app.scroll_to_selected)
                .then_some(app.selected_entry)
                .flatten();
            for row in rows {
                if by_date {
                    let month = row.month_header();
                    if last_month.as_deref() != Some(month.as_str()) {
                        if last_month.is_some() {
                            ui.add_space(12.0);
                        }
                        ui.label(
                            egui::RichText::new(&month)
                                .size(11.0)
                                .strong()
                                .color(crate::theme::p().muted),
                        );
                        ui.add_space(4.0);
                        last_month = Some(month);
                    }
                }

                let selected = app.selected_entry == Some(row.id)
                    || app.selected_entries.contains(&row.id);
                let (rect, _alloc) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), 58.0),
                    egui::Sense::hover(),
                );
                let hovered = ui.rect_contains_pointer(rect);
                let fill = if selected {
                    crate::theme::p().list_selected
                } else if hovered {
                    crate::theme::p().list_hover
                } else {
                    egui::Color32::TRANSPARENT
                };
                if fill != egui::Color32::TRANSPARENT {
                    ui.painter()
                        .rect_filled(rect, egui::CornerRadius::same(10), fill);
                }
                if selected {
                    ui.painter().rect_stroke(
                        rect,
                        egui::CornerRadius::same(10),
                        egui::Stroke::new(1.0, crate::theme::p().list_selected_stroke),
                        egui::StrokeKind::Inside,
                    );
                    let bar = egui::Rect::from_min_max(
                        egui::pos2(rect.left() + 3.0, rect.top() + 10.0),
                        egui::pos2(rect.left() + 6.5, rect.bottom() - 10.0),
                    );
                    ui.painter()
                        .rect_filled(bar, egui::CornerRadius::same(2), crate::theme::p().accent);
                }
                let mut content = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(rect.shrink2(egui::vec2(12.0, 7.0)))
                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                );
                let icon_fill = if selected {
                    crate::theme::p().panel
                } else {
                    crate::theme::p().bg
                };
                let icon_resp = egui::Frame::new()
                    .fill(icon_fill)
                    .stroke(egui::Stroke::new(1.0, crate::theme::p().border))
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
                // Space the attachment marker will need, reserved before the
                // truncating title is laid out — otherwise a long title takes
                // the whole row and the marker is pushed off the edge.
                let badge_reserve = if row.attachments > 0 {
                    ATTACHMENT_BADGE_RESERVE
                } else {
                    0.0
                };
                content.vertical(|ui| {
                    ui.set_max_width((ui.available_width() - badge_reserve).max(60.0));
                    ui.spacing_mut().item_spacing.y = 2.0;
                    let mut title_text = egui::RichText::new(&row.title)
                        .size(15.0)
                        .color(if selected {
                            crate::theme::p().accent
                        } else {
                            crate::theme::p().text
                        });
                    if selected {
                        title_text = title_text.strong();
                    }
                    ui.add(egui::Label::new(title_text).truncate());
                    if !secondary.is_empty() {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(secondary)
                                    .size(12.5)
                                    .color(crate::theme::p().muted),
                            )
                            .truncate(),
                        );
                    }
                });

                if row.attachments > 0 {
                    content.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            let _ = ui.allocate_space(egui::vec2(2.0, 0.0));
                            crate::theme::draw_attachment_badge(
                                ui,
                                row.attachments,
                                if selected {
                                    crate::theme::p().accent
                                } else {
                                    crate::theme::p().muted
                                },
                            );
                        },
                    );
                }

                // Interact after the labels have been painted: otherwise a
                // click aimed at the title label is swallowed by the label
                // instead of reaching the row.
                let resp = ui.interact(
                    rect,
                    ui.id().with(("entry-row", row.id)),
                    egui::Sense::click_and_drag(),
                );
                if scroll_to == Some(row.id) {
                    ui.scroll_to_rect(rect, None);
                }
                if resp.clicked() {
                    let modifiers = ui.ctx().input(|i| i.modifiers);
                    app.click_entry(row.id, modifiers);
                }
                if resp.double_clicked() {
                    app.selected_entry = Some(row.id);
                    app.edit_entry_dialog(row.id);
                }
                if resp.dragged() {
                    egui::DragAndDrop::set_payload(ui.ctx(), row.id);
                }
                entry_context_menu(&resp, row, &mut action);
                resp.on_hover_cursor(egui::CursorIcon::PointingHand);
            }
            if let Some((id, act)) = action {
                apply_row_action(app, id, act);
            }
        });
}

/// What an entry row's context menu asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowAction {
    /// Right-click: select the row the menu belongs to.
    Select,
    CopyUsername,
    CopyPassword,
    CopyUrl,
    Edit,
    Move,
    Delete,
}

/// Attach the entry context menu (right-click) to a list row or table row.
fn entry_context_menu(
    resp: &egui::Response,
    row: &EntryRow,
    action: &mut Option<(EntryId, RowAction)>,
) {
    if resp.secondary_clicked() {
        *action = Some((row.id, RowAction::Select));
    }
    resp.context_menu(|ui| {
        ui.set_min_width(190.0);
        let mut pick = |ui: &mut egui::Ui, label: &str, enabled: bool, act: RowAction| {
            if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                *action = Some((row.id, act));
                ui.close();
            }
        };
        pick(ui, "Copy username", !row.username.is_empty(), RowAction::CopyUsername);
        pick(ui, "Copy password", !row.password.is_empty(), RowAction::CopyPassword);
        pick(ui, "Copy URL", !row.url.is_empty(), RowAction::CopyUrl);
        ui.separator();
        pick(ui, "Edit…", true, RowAction::Edit);
        pick(ui, "Move to group…", true, RowAction::Move);
        ui.separator();
        if ui
            .button(egui::RichText::new("Delete…").color(crate::theme::p().danger))
            .clicked()
        {
            *action = Some((row.id, RowAction::Delete));
            ui.close();
        }
    });
}

/// Carry out an entry context-menu action (after the list is drawn).
fn apply_row_action(app: &mut App, id: EntryId, action: RowAction) {
    // Every action is about the row that was right-clicked: make it the
    // selection (unless it is already part of it).
    if !app.selected_entries.contains(&id) || app.selected_entry != Some(id) {
        app.click_entry(id, egui::Modifiers::NONE);
    }
    let field = |app: &App, key: &str| -> String {
        let Some(db) = app.db.as_ref() else { return String::new() };
        db.entry(id)
            .map(|e| crate::refs::resolve_references(db, e.get(key).unwrap_or_default()))
            .unwrap_or_default()
    };
    match action {
        RowAction::Select => {}
        RowAction::CopyUsername => {
            let v = field(app, fields::USERNAME);
            app.note_copied("username", "Username", v);
        }
        RowAction::CopyPassword => {
            let v = field(app, fields::PASSWORD);
            app.note_copied("password", "Password", v);
        }
        RowAction::CopyUrl => {
            let v = field(app, fields::URL);
            app.note_copied("url", "URL", v);
        }
        RowAction::Edit => app.edit_entry_dialog(id),
        RowAction::Move => {
            let groups = app.group_snapshot();
            app.dialog = crate::dialogs::Dialog::BatchMove(Box::new(crate::dialogs::BatchMove {
                entries: vec![id],
                groups,
                target: None,
            }));
        }
        RowAction::Delete => app.dialog = crate::dialogs::Dialog::ConfirmDeleteEntry(id),
    }
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
    let ui_modifiers = ui.ctx().input(|i| i.modifiers);
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
        .sense(egui::Sense::click())
        .cell_layout(Layout::left_to_right(Align::Center))
        .min_scrolled_height(0.0);
    if std::mem::take(&mut app.scroll_to_selected) {
        if let Some(index) = app
            .selected_entry
            .and_then(|id| rows.iter().position(|r| r.id == id))
        {
            builder = builder.scroll_to_row(index, None);
        }
    }
    let mut action: Option<(EntryId, RowAction)> = None;
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
                        format!(" {}", sort_marker(sort_desc))
                    } else {
                        String::new()
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
                            entry_cell(ui, app, c.id, row_data, &mut action, &mut edit);
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
                    entry_context_menu(&response, row_data, &mut action);
                });
            }
        });

    // Apply pending mutations.
    app.sort_column = sort_column;
    app.sort_desc = sort_desc;
    if let Some(id) = select {
        if app.selected_entry != Some(id) {
            let modifiers = ui_modifiers;
            app.click_entry(id, modifiers);
        }
    }
    if let Some(id) = edit {
        app.edit_entry_dialog(id);
    }
    if let Some((id, act)) = action {
        apply_row_action(app, id, act);
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
    action: &mut Option<(EntryId, RowAction)>,
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
                        "Click to select, double-click to edit, drag onto a group to move; Cmd/Ctrl-click or Shift-click to select several; right-click for actions",
                    );
                if title_resp.dragged() {
                    egui::DragAndDrop::set_payload(ui.ctx(), row_data.id);
                }
                if title_resp.clicked() {
                    let modifiers = ui.ctx().input(|i| i.modifiers);
                    app.click_entry(row_data.id, modifiers);
                }
                if title_resp.double_clicked() {
                    *edit = Some(row_data.id);
                }
                entry_context_menu(&title_resp, row_data, action);
                if row_data.attachments > 0 {
                    crate::theme::draw_attachment_badge(
                        ui,
                        row_data.attachments,
                        crate::theme::p().muted,
                    );
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
                    .color(crate::theme::p().text),
            );
            ui.label(
                egui::RichText::new("Choose an entry to see its details.")
                    .size(13.0)
                    .color(crate::theme::p().muted),
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
            is_favorite: entry_is_favorite(&e),
            parent_group_id: e.parent().id(),
            icon: {
                let resolved_url =
                    crate::refs::resolve_references(db, e.get(fields::URL).unwrap_or_default());
                crate::icons::entry_icon_spec(
                    db,
                    &e,
                    &crate::refs::resolve_references(db, e.get(fields::TITLE).unwrap_or_default()),
                    &crate::refs::resolve_references(db, e.get(fields::USERNAME).unwrap_or_default()),
                    &resolved_url,
                )
            },
            last_modified: e.times.last_modification,
            attributes: sorted_attributes(e
                .fields
                .iter()
                .filter(|(k, _)| {
                    !fields::KNOWN_FIELDS.contains(&k.as_str())
                        && !is_passkey_field(k)
                        && *k != FAVORITE_FIELD
                })
                .map(|(k, v)| {
                    (
                        k.clone(),
                        crate::refs::resolve_references(db, v.get()),
                        v.is_protected(),
                    )
                })
                .collect()),
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

    let mut edit_clicked = false;
    let mut delete_clicked = false;
    let mut history_clicked = false;
    let mut autotype_clicked = false;
    let mut favorite_clicked = false;
    let mut show_password = app.show_passwords;
    let mut attach: Option<AttachmentAction> = None;

    // 1Password-style top breadcrumb & action bar -----------------------
    // Every control here actually does something: the group name is a
    // picker, and Edit / the ⋮ overflow menu carry their own icons. (The
    // database name lives in the sidebar header only.)
    let mut group_pick: Option<Option<GroupId>> = None;
    ui.horizontal(|ui| {
        if let Some(picked) = group_picker(ui, app, Some(d.parent_group_id), "details-group") {
            group_pick = Some(picked);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Overflow menu: everything that is not a primary action.
            crate::theme::overflow_menu(ui, "entry-actions", "More actions", |ui| {
                if ui.button("Edit…").clicked() {
                    edit_clicked = true;
                    ui.close();
                }
                if ui.button("History…").clicked() {
                    history_clicked = true;
                    ui.close();
                }
                if ui.button("Auto-Type").clicked() {
                    autotype_clicked = true;
                    ui.close();
                }
                if ui
                    .button(if d.is_favorite { "Unstar" } else { "Star" })
                    .on_hover_text("Add to or remove from Favorites")
                    .clicked()
                {
                    favorite_clicked = true;
                    ui.close();
                }
                ui.separator();
                if ui
                    .add(egui::Button::new(
                        egui::RichText::new("Delete…").color(crate::theme::p().danger),
                    ))
                    .clicked()
                {
                    delete_clicked = true;
                    ui.close();
                }
            });
            if crate::theme::action_button(
                ui,
                "top-edit",
                "Edit…",
                crate::theme::ActionIcon::Pencil,
                "Edit this entry (Cmd/Ctrl+E)",
            )
            .clicked()
            {
                edit_clicked = true;
            }
        });
    });
    ui.add_space(18.0);

    // Header: Large icon + Favorite star + Title ------------------------
    ui.horizontal(|ui| {
        let icon_resp = egui::Frame::new()
            .fill(crate::theme::p().bg)
            .stroke(egui::Stroke::new(1.0, crate::theme::p().border))
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
        if d.is_favorite {
            crate::theme::draw_star_badge(
                ui.painter(),
                icon_resp.response.rect.right_bottom() + egui::vec2(-3.0, -3.0),
                9.0,
            );
        }
        ui.add_space(14.0);
        ui.vertical(|ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                // Keep room for the star so a long title wraps before it.
                ui.allocate_ui_with_layout(
                    egui::vec2((ui.available_width() - 40.0).max(80.0), 0.0),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&d.title)
                                    .size(23.0)
                                    .strong()
                                    .color(crate::theme::p().text),
                            )
                            .wrap(),
                        );
                    },
                );
                if crate::theme::favorite_toggle(ui, "details-favorite", d.is_favorite).clicked() {
                    favorite_clicked = true;
                }
            });
            // Collect badges on a single row, deduplicating any user tag named
            // "Passkey" / "Passkeys" when the entry already shows the Passkey
            // indicator chip from KPEX_PASSKEY* / FRIENDLYPASS_PASSKEY* fields.
            let non_passkey_tags: Vec<&str> = d
                .tags
                .split(',')
                .map(str::trim)
                .filter(|t| {
                    !t.is_empty()
                        && !(d.has_passkey
                            && (t.eq_ignore_ascii_case("passkey")
                                || t.eq_ignore_ascii_case("passkeys")))
                })
                .collect();
            if d.has_passkey || !non_passkey_tags.is_empty() {
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
                    if d.has_passkey {
                        egui::Frame::new()
                            .fill(crate::theme::p().accent_soft)
                            .stroke(egui::Stroke::new(1.0, crate::theme::p().list_selected_stroke))
                            .corner_radius(6)
                            .inner_margin(egui::Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new("Passkey")
                                        .size(12.0)
                                        .strong()
                                        .color(crate::theme::p().accent),
                                );
                            });
                    }
                    for tag in non_passkey_tags {
                        egui::Frame::new()
                            .fill(crate::theme::p().bg)
                            .stroke(egui::Stroke::new(1.0, crate::theme::p().border))
                            .corner_radius(6)
                            .inner_margin(egui::Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(tag)
                                        .size(11.5)
                                        .color(crate::theme::p().muted),
                                );
                            });
                    }
                });
            }
        });
    });
    ui.add_space(16.0);

    // The main field card ------------------------------------------------
    // Only the fields the entry actually has: an empty username or password
    // gets no row (and no copy button for nothing).
    let has_main = !d.username.is_empty() || !d.password.is_empty() || d.otp.is_some();
    if has_main {
    detail_card(ui, |ui| {
        let mut first = true;
        if !d.username.is_empty() {
            field_block(
                ui,
                app,
                "username",
                "username",
                &d.username,
                &d.username,
                "Username",
                "Copy Username",
                "Copy username (Cmd/Ctrl+B) — or click the field",
            );
            first = false;
        }
        if !d.password.is_empty() {
        if !first {
            ui.add(egui::Separator::default().spacing(6.0));
        }
        first = false;
        let masked = if show_password {
            d.password.clone()
        } else {
            "••••••••••".to_owned()
        };
        let (strength_label, strength_frac, strength_color) =
            password_strength(&d.password, &[&d.title, &d.username, &d.url]);
        let row_width = ui.available_width();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let avail = (row_width - 300.0).max(80.0);
            value_cell(
                ui,
                app,
                "password",
                avail,
                "password",
                &masked,
                true,
                crate::theme::p().text,
                "Click to copy the password (Cmd/Ctrl+C)",
                |app| app.note_copied("password", "Password", d.password.clone()),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                copy_action(
                    ui,
                    app,
                    "password",
                    "Password",
                    &d.password,
                    "Copy Password",
                    "Copy password (Cmd/Ctrl+C)",
                );
                if crate::theme::action_button(
                    ui,
                    "toggle-password",
                    if show_password { "Hide" } else { "Show" },
                    crate::theme::ActionIcon::Eye { shown: show_password },
                    "Show / hide the password",
                )
                .clicked()
                {
                    show_password = !show_password;
                }
                crate::theme::draw_progress_ring(ui, 7.0, strength_frac, strength_color);
                ui.label(
                    egui::RichText::new(strength_label)
                        .size(13.0)
                        .color(crate::theme::p().muted),
                )
                .on_hover_text("Estimated strength (zxcvbn)");
            });
        });
        }
        if let Some((code, valid_for)) = &d.otp {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_secs(1));
            if !first {
                ui.add(egui::Separator::default().spacing(6.0));
            }
            let row_width = ui.available_width();
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let avail = (row_width - 130.0).max(100.0);
                value_cell(
                    ui,
                    app,
                    "totp",
                    avail,
                    "one-time password (TOTP)",
                    &spaced_code(code),
                    true,
                    crate::theme::p().text,
                    "Click to copy the TOTP code (Cmd/Ctrl+T)",
                    |app| app.note_copied("totp", "TOTP", code.clone()),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    copy_action(
                        ui,
                        app,
                        "totp",
                        "TOTP",
                        code,
                        "Copy TOTP",
                        "Copy TOTP (Cmd/Ctrl+T)",
                    );
                    let frac = (*valid_for as f32 / 30.0).clamp(0.05, 1.0);
                    crate::theme::draw_progress_ring(ui, 6.5, frac, crate::theme::p().good);
                    ui.label(
                        egui::RichText::new(format!("{valid_for}"))
                            .size(13.0)
                            .color(crate::theme::p().muted),
                    );
                });
            });
        }
    });
    }

    // Website ------------------------------------------------------------
    if !d.url.is_empty() {
        if has_main {
            ui.add_space(16.0);
        }
        detail_card(ui, |ui| {
            let width = ui.available_width();
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let avail = (width - 120.0).max(80.0);
                // Clickable URL: hover pill, accent-colored text, click opens
                // the system browser.
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(avail, 44.0), egui::Sense::hover());
                let hovered = ui.rect_contains_pointer(rect);
                let inner = rect.shrink2(egui::vec2(10.0, 5.0));
                let lg = ui.painter().layout_no_wrap(
                    "website".to_owned(),
                    egui::FontId::new(12.5, egui::FontFamily::Proportional),
                    crate::theme::p().accent,
                );
                let lg_size = lg.size();
                let cap = ui.interact(
                    egui::Rect::from_min_size(inner.min, lg_size),
                    ui.id().with("value-cap-url"),
                    egui::Sense::hover(),
                );
                cap.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::Role::Label, ui.is_enabled(), "website")
                });
                if ui.is_rect_visible(rect) {
                    let painter = ui.painter();
                    if hovered {
                        painter.rect_filled(rect, egui::CornerRadius::same(8), crate::theme::p().hover);
                    }
                    painter.galley(egui::pos2(inner.left(), inner.top()), lg, crate::theme::p().accent);
                    let (head, tail) = split_url_domain(&d.url);
                    let vfont = egui::FontId::new(15.5, egui::FontFamily::Proportional);
                    let vcolor = if hovered {
                        crate::theme::p().accent
                    } else {
                        crate::theme::p().text
                    };
                    let y = inner.top() + 17.0;
                    let mut x = inner.left();
                    if !head.is_empty() {
                        let hg = layout_truncated(
                            painter,
                            head,
                            vfont.clone(),
                            crate::theme::p().muted,
                            inner.width(),
                        );
                        let hw = hg.size().x;
                        painter.galley(egui::pos2(x, y), hg, crate::theme::p().muted);
                        x += hw;
                    }
                    let tg = layout_truncated(painter, tail, vfont, vcolor, inner.right() - x);
                    painter.galley(egui::pos2(x, y), tg, vcolor);
                }
                let mut resp = ui.interact(
                    rect,
                    ui.id().with("value-cell-url"),
                    egui::Sense::click(),
                );
                resp = resp.on_hover_text(format!("Open {} in the browser", d.url));
                if resp.clicked() {
                    open_url(&d.url);
                    app.status = format!("Opening {} in the browser…", d.url);
                }
                resp.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), &d.url)
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    copy_action(
                        ui,
                        app,
                        "url",
                        "URL",
                        &d.url,
                        "Copy URL",
                        "Copy URL (Cmd/Ctrl+U) — or click the field",
                    );
                });
            });
        });
    }

    // Custom fields / security ------------------------------------------
    if !d.attributes.is_empty() {
        ui.add_space(18.0);
        ui.label(
            egui::RichText::new("SECURITY")
                .size(11.0)
                .strong()
                .color(crate::theme::p().muted),
        );
        ui.add_space(4.0);
        detail_card(ui, |ui| {
            for (i, (key, value, protected)) in d.attributes.iter().enumerate() {
                if i > 0 {
                    ui.add(egui::Separator::default().spacing(6.0));
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
                field_block(
                    ui,
                    app,
                    &format!("attr:{key}"),
                    &label,
                    &shown,
                    value,
                    key,
                    "Copy",
                    &format!("Copy {key} — or click the field"),
                );
            }
            if !d.tags.is_empty() {
                ui.add(egui::Separator::default().spacing(6.0));
                copy_action(ui, app, "tags", "tags", &d.tags, "Copy Tags", "Copy all tags");
            }
        });
    }

    // Notes --------------------------------------------------------------
    if !d.notes.is_empty() {
        ui.add_space(18.0);
        ui.label(
            egui::RichText::new("NOTES")
                .size(11.0)
                .strong()
                .color(crate::theme::p().muted),
        );
        ui.add_space(4.0);
        detail_card(ui, |ui| {
            ui.label(
                egui::RichText::new(&d.notes)
                    .size(14.0)
                    .color(crate::theme::p().text),
            );
        });
    }

    // Auto-Type summary --------------------------------------------------
    // The common case (enabled, default sequence, no window associations) is
    // one muted line; a card only when there is something specific to show.
    if let Some(at) = &d.autotype {
        let custom = !at.default_sequence.is_empty() || !at.associations.is_empty();
        ui.add_space(18.0);
        if !custom {
            ui.label(
                egui::RichText::new(if at.enabled {
                    "Auto-Type: enabled, default sequence"
                } else {
                    "Auto-Type: disabled"
                })
                .size(12.5)
                .color(crate::theme::p().muted),
            );
        } else {
            ui.label(
                egui::RichText::new("AUTO-TYPE")
                    .size(11.0)
                    .strong()
                    .color(crate::theme::p().muted),
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
                            .color(crate::theme::p().muted),
                    );
                }
                for (window, sequence) in &at.associations {
                    ui.label(
                        egui::RichText::new(format!(
                            "{window} -> {}",
                            if sequence.is_empty() { "(default)" } else { sequence }
                        ))
                        .size(13.0)
                        .color(crate::theme::p().muted),
                    );
                }
            });
        }
    }

    // Attachments --------------------------------------------------------
    // Always shown (with an "Add file…" button) so the section is
    // discoverable on entries that have no attachments yet.
    ui.add_space(18.0);
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("ATTACHMENTS")
                .size(11.0)
                .strong()
                .color(crate::theme::p().muted),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if crate::theme::action_button(
                ui,
                &format!("attach-add:{id:?}"),
                "Add file…",
                crate::theme::ActionIcon::None,
                "Attach a file to this entry",
            )
            .clicked()
            {
                attach = Some(AttachmentAction::Add);
            }
        });
    });
    ui.add_space(4.0);
    detail_card(ui, |ui| {
        if d.attachments.is_empty() {
            ui.label(
                egui::RichText::new("No attachments")
                    .size(13.0)
                    .color(crate::theme::p().muted),
            );
            return;
        }
        let total: usize = d.attachments.iter().map(|(_, size)| *size).sum();
        for (i, (name, size)) in d.attachments.iter().enumerate() {
            if i > 0 {
                ui.add(egui::Separator::default().spacing(4.0));
            }
            attachment_row(ui, name, *size, &mut attach);
        }
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new(format!(
                "{} · {} in total",
                pluralize(d.attachments.len(), "attachment", "attachments"),
                crate::app::format_size(total)
            ))
            .size(11.0)
            .color(crate::theme::p().muted),
        );
    });

    // Footer -------------------------------------------------------------
    ui.add_space(20.0);
    if let Some(t) = d.last_modified {
        ui.horizontal(|ui| {
            crate::theme::draw_chevron_right(ui, crate::theme::p().muted);
            ui.label(
                egui::RichText::new(format!(
                    "Last edited {}",
                    t.format("%A, %B %-d, %Y at %-I:%M:%S %p")
                ))
                .size(13.0)
                .color(crate::theme::p().text),
            );
        });
        ui.add_space(8.0);
    }
    // Keep repainting while a "Copied" confirmation is visible.
    if app
        .copied_fields
        .values()
        .any(|t| t.elapsed() < crate::app::COPIED_TTL)
    {
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(120));
    }

    // Apply pending mutations.
    app.show_passwords = show_password;
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
    if favorite_clicked {
        app.toggle_favorite(id);
    }
    if let Some(group) = group_pick {
        app.selected_group = group;
        app.selected_tag = None;
        app.filter_favorites = false;
        app.filter_attachments = false;
    }
    match attach {
        Some(AttachmentAction::Export(name)) => {
            let data = app
                .db
                .as_ref()
                .and_then(|db| db.entry(id))
                .and_then(|e| e.attachment_by_name(&name).map(|a| a.data.get().clone()));
            match data {
                Some(data) => {
                    if let Some(path) = rfd::FileDialog::new().set_file_name(&name).save_file() {
                        match std::fs::write(&path, &data) {
                            Ok(()) => {
                                app.status = format!("Exported attachment to {}", path.display())
                            }
                            Err(e) => app.status = format!("export failed: {e}"),
                        }
                    }
                }
                None => app.status = format!("attachment \"{name}\" is gone"),
            }
        }
        Some(AttachmentAction::Add) => {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                match std::fs::read(&path) {
                    Ok(data) => {
                        if let Err(e) = app.add_entry_attachment(id, &name, data) {
                            app.status = format!("unable to attach '{name}': {e:#}");
                        }
                    }
                    Err(e) => app.status = format!("unable to read {}: {e}", path.display()),
                }
            }
        }
        Some(AttachmentAction::Delete(name)) => {
            app.dialog = crate::dialogs::Dialog::ConfirmDeleteAttachment(id, name);
        }
        None => {}
    }
}

/// What the attachments card asked for; applied after painting so `app` is
/// not borrowed while rendering.
pub enum AttachmentAction {
    Add,
    Export(String),
    Delete(String),
}

/// The least room a file name gets before the row stacks its buttons below.
pub const ATTACHMENT_MIN_NAME_WIDTH: f32 = 150.0;

/// Whether an attachment row can put Export/Delete beside the name. Split out
/// so the responsive rule is unit-testable without rendering.
pub fn attachment_row_inline(card_width: f32, buttons_width: f32) -> bool {
    card_width >= buttons_width + ATTACHMENT_MIN_NAME_WIDTH
}

/// One attachment row: name + size, with Export/Delete buttons.
///
/// The layout adapts to the available width. While there is room the buttons
/// sit on the right of the row and the name is shortened in the middle to fit
/// the remaining space; in a narrow panel (or a short window) the buttons move
/// to their own right-aligned line under the name. Without this the name used
/// to wrap underneath the buttons and overlap them.
fn attachment_row(
    ui: &mut egui::Ui,
    name: &str,
    size: usize,
    attach: &mut Option<AttachmentAction>,
) {
    use crate::theme::ActionIcon;
    let export_w = crate::theme::action_button_width(ui, "Export…", ActionIcon::Download);
    let delete_w = crate::theme::action_button_width(ui, "Delete", ActionIcon::Trash);
    let gap = 4.0;
    let buttons_w = export_w + delete_w + gap;
    let card_w = ui.available_width();
    let inline = attachment_row_inline(card_w, buttons_w);
    let name_font = egui::FontId::proportional(14.0);

    let name_and_size = |ui: &mut egui::Ui, max_w: f32| {
        let shown = crate::theme::truncate_middle(ui, name, name_font.clone(), max_w);
        ui.add(egui::Label::new(egui::RichText::new(shown).size(14.0)).truncate())
            .on_hover_text(name);
        ui.add(
            egui::Label::new(
                egui::RichText::new(crate::app::format_size(size))
                    .size(11.0)
                    .color(crate::theme::p().muted),
            )
            .truncate(),
        );
    };

    let buttons = |ui: &mut egui::Ui,
                   name: &str,
                   attach: &mut Option<AttachmentAction>| {
        // Right-to-left: Delete is added first, so it appears on the right.
        if crate::theme::action_button_danger(
            ui,
            &format!("attach-delete:{name}"),
            "Delete",
            ActionIcon::Trash,
            "Remove this attachment from the entry",
        )
        .clicked()
        {
            *attach = Some(AttachmentAction::Delete(name.to_owned()));
        }
        if crate::theme::action_button(
            ui,
            &format!("attach-export:{name}"),
            "Export…",
            ActionIcon::Download,
            "Export this attachment to a file",
        )
        .clicked()
        {
            *attach = Some(AttachmentAction::Export(name.to_owned()));
        }
    };

    if inline {
        ui.horizontal(|ui| {
            let name_w = (card_w - buttons_w - 10.0).max(ATTACHMENT_MIN_NAME_WIDTH);
            ui.allocate_ui_with_layout(
                egui::vec2(name_w, ui.spacing().interact_size.y),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    name_and_size(ui, name_w - 6.0);
                },
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                buttons(ui, name, attach);
            });
        });
    } else {
        name_and_size(ui, card_w - 4.0);
        ui.add_space(2.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            buttons(ui, name, attach);
        });
    }
}

fn detail_card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(crate::theme::p().card)
        .stroke(egui::Stroke::new(1.0, crate::theme::p().border))
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            add(ui);
        });
}

/// Lay out `text` without wrapping, truncating with an ellipsis to `max_w`.
fn layout_truncated(
    painter: &egui::Painter,
    text: &str,
    font: egui::FontId,
    color: egui::Color32,
    max_w: f32,
) -> std::sync::Arc<egui::Galley> {
    let full = painter.layout_no_wrap(text.to_owned(), font.clone(), color);
    if full.size().x <= max_w {
        return full;
    }
    let mut s = text.to_string();
    while !s.is_empty() {
        s.pop();
        let g = painter.layout_no_wrap(format!("{s}…"), font.clone(), color);
        if g.size().x <= max_w {
            return g;
        }
    }
    painter.layout_no_wrap("…".to_owned(), font, color)
}

/// A clickable field value in the details panel: soft pill on hover, accent
/// flash while the "Copied" confirmation is active; clicking runs `on_click`.
/// The accessible label is the shown value itself (role: button).
#[allow(clippy::too_many_arguments)]
fn value_cell(
    ui: &mut egui::Ui,
    app: &mut App,
    key: &str,
    width: f32,
    label: &str,
    shown: &str,
    mono: bool,
    value_color: egui::Color32,
    click_tooltip: &str,
    on_click: impl FnOnce(&mut App),
) -> egui::Response {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 44.0), egui::Sense::hover());
    let hovered = ui.rect_contains_pointer(rect);
    let copied = app.is_field_copied(key);
    let inner = rect.shrink2(egui::vec2(10.0, 5.0));
    // Lay out the caption even when off-screen so its accessibility node
    // still exists (tests and screen readers query it, e.g. "attr_49").
    let lg = ui.painter().layout_no_wrap(
        label.to_owned(),
        egui::FontId::new(12.5, egui::FontFamily::Proportional),
        crate::theme::p().accent,
    );
    let lg_size = lg.size();
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if copied {
            painter.rect_filled(rect, egui::CornerRadius::same(8), crate::theme::p().accent_soft);
        } else if hovered {
            painter.rect_filled(rect, egui::CornerRadius::same(8), crate::theme::p().hover);
        }
        painter.galley(egui::pos2(inner.left(), inner.top()), lg, crate::theme::p().accent);
        let family = if mono {
            egui::FontFamily::Monospace
        } else {
            egui::FontFamily::Proportional
        };
        let vg = layout_truncated(
            painter,
            shown,
            egui::FontId::new(15.5, family),
            value_color,
            inner.width(),
        );
        painter.galley(egui::pos2(inner.left(), inner.top() + 17.0), vg, value_color);
    }
    let cap = ui.interact(
        egui::Rect::from_min_size(inner.min, lg_size),
        ui.id().with(("value-cap", key)),
        egui::Sense::hover(),
    );
    cap.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Label, ui.is_enabled(), label)
    });
    let mut resp = ui.interact(rect, ui.id().with(("value-cell", key)), egui::Sense::click());
    if !click_tooltip.is_empty() {
        resp = resp.on_hover_text(click_tooltip);
    }
    if resp.clicked() {
        on_click(app);
    }
    resp.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), shown)
    });
    resp
}

/// The copy button for a details field: clipboard icon at rest, morphs into a
/// green "✓ Copied" while the confirmation is active.
fn copy_action(
    ui: &mut egui::Ui,
    app: &mut App,
    key: &str,
    label: &str,
    value: &str,
    btn_label: &str,
    btn_tooltip: &str,
) {
    let id = format!("copy-{key}");
    let resp = if app.is_field_copied(key) {
        crate::theme::action_button_ex(
            ui,
            &id,
            "Copied",
            crate::theme::ActionIcon::Check,
            "Copied to clipboard",
            Some(crate::theme::p().good),
        )
    } else {
        crate::theme::action_button(
            ui,
            &id,
            btn_label,
            crate::theme::ActionIcon::Copy,
            btn_tooltip,
        )
    };
    if resp.clicked() {
        app.note_copied(key, label, value.to_owned());
    }
}

/// One details row: a clickable value cell (click = copy) plus a copy action
/// button on the right.
#[allow(clippy::too_many_arguments)]
fn field_block(
    ui: &mut egui::Ui,
    app: &mut App,
    key: &str,
    label: &str,
    shown: &str,
    copy_value: &str,
    copy_label: &str,
    btn_label: &str,
    btn_tooltip: &str,
) {
    let width = ui.available_width();
    let btn_w = 120.0;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        let avail = (width - btn_w).max(80.0);
        value_cell(
            ui,
            app,
            key,
            avail,
            label,
            shown,
            false,
            crate::theme::p().text,
            &format!("Click to copy {copy_label}"),
            |app| app.note_copied(key, copy_label, copy_value.to_owned()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            copy_action(ui, app, key, copy_label, copy_value, btn_label, btn_tooltip);
        });
    });
}

/// Open a URL in the system browser (best effort, cross-platform).
fn open_url(url: &str) {
    let url = url.to_owned();
    std::thread::spawn(move || {
        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("open").arg(&url).spawn();
        #[cfg(target_os = "windows")]
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn();
        #[cfg(all(unix, not(target_os = "macos")))]
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
        #[cfg(not(any(unix, windows)))]
        let _ = &url;
    });
}

/// A password strength estimate for display: label, ring fraction and colour.
///
/// Uses zxcvbn (dictionary words, keyboard patterns, dates, repeats and
/// l33t substitutions), so "Password1!" rates as weak instead of the old
/// length-plus-character-classes score's "Very Good". `user_inputs` (title,
/// username, URL) count as guessable words too. Results are cached because
/// the details pane is redrawn every frame and zxcvbn is not free.
pub fn password_strength(pw: &str, user_inputs: &[&str]) -> (&'static str, f32, egui::Color32) {
    let score = password_score(pw, user_inputs);
    let pal = crate::theme::p();
    match score {
        0 => ("Very weak", 0.12, pal.danger),
        1 => ("Weak", 0.3, pal.danger),
        2 => ("Fair", 0.55, pal.warn),
        3 => ("Good", 0.8, pal.good),
        _ => ("Strong", 1.0, pal.good),
    }
}

/// The zxcvbn score (0 = trivially guessable … 4 = very strong), cached.
pub fn password_score(pw: &str, user_inputs: &[&str]) -> u8 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::HashMap<u64, u8>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }
    if pw.is_empty() {
        return 0;
    }
    let mut h = DefaultHasher::new();
    pw.hash(&mut h);
    user_inputs.hash(&mut h);
    let key = h.finish();
    if let Some(score) = CACHE.with(|c| c.borrow().get(&key).copied()) {
        return score;
    }
    // zxcvbn's work grows with length; past 100 characters nothing is weak.
    let score = if pw.chars().count() > 100 {
        4
    } else {
        let inputs: Vec<&str> = user_inputs.iter().copied().filter(|s| !s.is_empty()).collect();
        u8::from(zxcvbn::zxcvbn(pw, &inputs).score())
    };
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.len() > 512 {
            c.clear();
        }
        c.insert(key, score);
    });
    score
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

/// KeePassXC stores passkeys in KPEX_PASSKEY*/FRIENDLYPASS_PASSKEY* attributes.
fn is_passkey_field(key: &str) -> bool {
    key.starts_with("KPEX_PASSKEY") || key.starts_with("FRIENDLYPASS_PASSKEY")
}

struct EntryDetailsData {
    has_passkey: bool,
    is_favorite: bool,
    parent_group_id: GroupId,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    tags: String,
    icon: crate::icons::IconSpec,
    last_modified: Option<chrono::NaiveDateTime>,
    otp: Option<(String, u64)>,
    attributes: Vec<(String, String, bool)>,
    autotype: Option<AutoTypeSummary>,
    attachments: Vec<(String, usize)>,
}

/// Sort custom attributes by name: the entry's fields live in a `HashMap`,
/// so without this the order changed from one launch to the next.
fn sorted_attributes(mut attrs: Vec<(String, String, bool)>) -> Vec<(String, String, bool)> {
    attrs.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()).then(a.0.cmp(&b.0)));
    attrs
}

struct AutoTypeSummary {
    enabled: bool,
    default_sequence: String,
    associations: Vec<(String, String)>,
}
