//! Tests for the UI review follow-ups: favorites, date sorting with month
//! headings, group actions in the sidebar context menu, keyboard and
//! Shift-click selection, the entry context menu, clipboard auto-clear, idle
//! auto-lock, the status bar, unlock errors and the dark theme.

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use friendlypass_gui::app::IdleLock;
use friendlypass_gui::clipboard::MemoryClipboard;
use friendlypass_gui::dialogs::Dialog;
use keepass::DatabaseKey;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

/// Open a writable copy of the sample database (Sample Entry in the root
/// group with username user@example.com, Web Login with webuser; groups Web
/// and Bank). The app copies into a memory clipboard.
fn open_sample(
    size: egui::Vec2,
) -> (tempfile::TempDir, Harness<'static, friendlypass_gui::App>, MemoryClipboard) {
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &dst).unwrap();
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = dst.display().to_string();
    let clip = MemoryClipboard::default();
    let clip_app = clip.clone();
    let mut harness = Harness::new_eframe(move |_cc| {
        let mut app = friendlypass_gui::App::with_open_database(&path_str, key);
        app.clipboard = Arc::new(clip_app);
        app
    });
    harness.set_size(size);
    harness.run();
    (dir, harness, clip)
}

fn entry_id(h: &Harness<'_, friendlypass_gui::App>, title: &str) -> keepass::db::EntryId {
    h.state()
        .db
        .as_ref()
        .unwrap()
        .iter_all_entries()
        .find(|e| e.get("Title") == Some(title))
        .unwrap_or_else(|| panic!("entry {title}"))
        .id()
}

fn history_len(h: &Harness<'_, friendlypass_gui::App>, id: keepass::db::EntryId) -> usize {
    h.state()
        .db
        .as_ref()
        .unwrap()
        .entry(id)
        .unwrap()
        .history
        .as_ref()
        .map(|x| x.get_entries().len())
        .unwrap_or(0)
}

fn group_named(h: &Harness<'_, friendlypass_gui::App>, name: &str) -> Option<keepass::db::GroupId> {
    h.state()
        .db
        .as_ref()
        .unwrap()
        .iter_all_groups()
        .find(|g| g.name == name)
        .map(|g| g.id())
}

/// The list row for `title` (the details pane repeats the selected entry's
/// title further right, so pick the leftmost node).
fn row<'h>(h: &'h Harness<'_, friendlypass_gui::App>, title: &'h str) -> egui_kittest::Node<'h> {
    h.query_all_by_label(title)
        .min_by(|a, b| a.rect().left().total_cmp(&b.rect().left()))
        .unwrap_or_else(|| panic!("row {title}"))
}

/// Pin every timestamp so date-based rendering is deterministic.
fn pin_times(h: &mut Harness<'_, friendlypass_gui::App>) {
    let fixed = chrono::NaiveDate::from_ymd_opt(2025, 3, 12)
        .unwrap()
        .and_hms_opt(16, 41, 3)
        .unwrap();
    let db = h.state_mut().db.as_mut().unwrap();
    let ids: Vec<_> = db.iter_all_entries().map(|e| e.id()).collect();
    for id in ids {
        if let Some(mut entry) = db.entry_mut(id) {
            entry.times.creation = Some(fixed);
            entry.times.last_modification = Some(fixed);
            entry.times.last_access = Some(fixed);
        }
    }
    h.state_mut().status.clear();
    h.run();
}

// ---------------------------------------------------------------------------
// favorites
// ---------------------------------------------------------------------------

#[test]
fn the_details_star_toggles_favorite_with_history() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    let id = entry_id(&h, "Sample Entry");
    let before = history_len(&h, id);
    h.get_by_label("Sample Entry").click();
    h.run();

    assert!(!h.state().is_favorite(id));
    h.get_by_label("Add to Favorites").click();
    h.run();
    assert!(h.state().is_favorite(id), "the star marks the entry as a favorite");
    assert!(h.state().dirty, "favoriting marks the database dirty");
    assert_eq!(history_len(&h, id), before + 1, "recorded in the entry history");
    {
        let state = h.state();
        let entry = state.db.as_ref().unwrap().entry(id).unwrap();
        assert_eq!(
            entry.fields.get("FRIENDLYPASS_FAVORITE").map(|v| v.get().as_str()),
            Some("1")
        );
    }
    // The Favorites filter lists it.
    h.state_mut().filter_favorites = true;
    h.run();
    assert_eq!(friendlypass_gui::browser::visible_entry_ids(h.state()), vec![id]);
    h.state_mut().filter_favorites = false;
    h.run();

    // Editing keeps the marker (it is not an editable attribute) and the
    // star stays on.
    h.get_by_label("Edit…").click();
    h.run();
    assert_eq!(h.query_all_by_label_contains("FRIENDLYPASS_FAVORITE").count(), 0);
    h.get_by_label("Save").click();
    h.run();
    assert!(h.state().is_favorite(id), "an edit does not drop the favorite");

    // Unstar again.
    h.get_by_label("Remove from Favorites").click();
    h.run();
    assert!(!h.state().is_favorite(id));
    let state = h.state();
    assert!(state.db.as_ref().unwrap().entry(id).unwrap().fields.get("FRIENDLYPASS_FAVORITE").is_none());
}

#[test]
fn unstarring_also_clears_favorite_tags() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    let id = entry_id(&h, "Web Login");
    {
        let db = h.state_mut().db.as_mut().unwrap();
        db.entry_mut(id).unwrap().tags = vec!["favorite".into(), "work".into()];
    }
    h.run();
    assert!(h.state().is_favorite(id), "a 'favorite' tag counts as starred");
    h.state_mut().toggle_favorite(id);
    assert!(!h.state().is_favorite(id));
    let state = h.state();
    let tags = &state.db.as_ref().unwrap().entry(id).unwrap().tags;
    assert_eq!(tags, &vec!["work".to_owned()], "other tags are kept");
}

// ---------------------------------------------------------------------------
// password strength
// ---------------------------------------------------------------------------

#[test]
fn common_passwords_are_not_rated_good() {
    use friendlypass_gui::browser::{password_score, password_strength};
    for weak in ["Password1!", "password", "Qwerty123!", "letmein2024"] {
        let (label, _, _) = password_strength(weak, &[]);
        assert!(
            !matches!(label, "Good" | "Strong"),
            "{weak:?} must not be rated good, got {label:?} (score {})",
            password_score(weak, &[])
        );
    }
    // The entry's own username makes a password built from it weak.
    assert!(password_score("jdoe-jdoe-jdoe", &["jdoe"]) <= 2);
    // A long random password is.
    let (label, _, _) = password_strength("q7#Vt9!xL2@pRm$4zW8&", &[]);
    assert!(matches!(label, "Good" | "Strong"), "random password rated {label:?}");
}

// ---------------------------------------------------------------------------
// date sort and month headings
// ---------------------------------------------------------------------------

#[test]
fn month_headings_only_appear_when_sorting_by_date() {
    use friendlypass_gui::app::SortColumn;
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    pin_times(&mut h);
    assert_eq!(
        h.query_all_by_label("MARCH 2025").count(),
        0,
        "no headings in title order"
    );

    // Pick "Modified" from the Sort menu.
    h.get_by_label_contains("Sort: Title").click();
    h.run();
    h.get_by_label("Modified").click();
    h.run();
    assert_eq!(h.state().sort_column, SortColumn::Modified);
    assert!(h.state().sort_desc, "dates sort newest first");
    h.get_by_label("Sort: Modified (newest first)");
    assert_eq!(h.query_all_by_label("MARCH 2025").count(), 1, "one heading for the month");

    // An entry without timestamps is grouped honestly.
    {
        let db = h.state_mut().db.as_mut().unwrap();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "Undated");
        e.times.creation = None;
        e.times.last_modification = None;
    }
    h.run();
    h.get_by_label("NO DATE");
    assert_eq!(
        friendlypass_gui::browser::month_header(None),
        "NO DATE"
    );
}

// ---------------------------------------------------------------------------
// sidebar group actions
// ---------------------------------------------------------------------------

#[test]
fn group_context_menu_renames_creates_and_deletes() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    // The old always-disabled button row is gone.
    assert!(h.query_by_label("Rename group…").is_none());

    // Rename.
    h.get_by_label("Web (0)").click_secondary();
    h.run();
    h.get_by_label("Rename group…").click();
    h.run();
    h.get_by_label("Rename Group");
    h.get_by_label("Group name:").click();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.event(egui::Event::Text("Websites".into()));
    h.run();
    h.get_by_label("Rename").click();
    h.run();
    assert!(group_named(&h, "Websites").is_some(), "renamed");
    assert!(matches!(h.state().dialog, Dialog::None), "the rename dialog closes");

    // New subgroup.
    h.get_by_label("Websites (0)").click_secondary();
    h.run();
    h.get_by_label("New subgroup…").click();
    h.run();
    h.get_by_label("Group name:").click();
    h.run();
    h.event(egui::Event::Text("Shops".into()));
    h.run();
    h.get_by_label("Create").click();
    h.run();
    let shops = group_named(&h, "Shops").expect("subgroup created");
    let websites = group_named(&h, "Websites").unwrap();
    let parent = h
        .state()
        .db
        .as_ref()
        .unwrap()
        .group(shops)
        .unwrap()
        .parent()
        .map(|p| p.id());
    assert_eq!(parent, Some(websites), "created inside the right-clicked group");

    // Delete (moves to the recycle bin).
    h.get_by_label("Bank (0)").click_secondary();
    h.run();
    h.get_by_label("Delete group…").click();
    h.run();
    assert!(matches!(h.state().dialog, Dialog::ConfirmDeleteGroup(_)));
    h.get_by_label("Delete").click();
    h.run();
    let bank = group_named(&h, "Bank").unwrap();
    let bin = h.state().db.as_ref().unwrap().recycle_bin().map(|b| b.id());
    let bank_parent = h.state().db.as_ref().unwrap().group(bank).unwrap().parent().map(|p| p.id());
    assert_eq!(bank_parent, bin, "group moved to the recycle bin");

    // The recycle bin row offers "Empty Recycle Bin…".
    h.get_by_label("Recycle Bin (0)").click_secondary();
    h.run();
    h.get_by_label("Empty Recycle Bin…").click();
    h.run();
    assert!(matches!(h.state().dialog, Dialog::ConfirmEmptyRecycleBin));
}

#[test]
fn the_root_row_cannot_be_renamed_or_deleted() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    h.get_by_label("All Items (2)").click_secondary();
    h.run();
    h.get_by_label("New subgroup…");
    assert!(h.query_by_label("Rename group…").is_none());
    assert!(h.query_by_label("Delete group…").is_none());
    assert!(h.query_by_label("Share group…").is_none());
}

// ---------------------------------------------------------------------------
// keyboard and mouse selection
// ---------------------------------------------------------------------------

#[test]
fn arrow_keys_walk_the_visible_entries() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    let sample = entry_id(&h, "Sample Entry");
    let web = entry_id(&h, "Web Login");

    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().selected_entry, Some(sample), "Down selects the first entry");
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().selected_entry, Some(web));
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().selected_entry, Some(web), "stops at the last entry");
    h.key_press(egui::Key::ArrowUp);
    h.run();
    assert_eq!(h.state().selected_entry, Some(sample));

    // Not while typing in the search field…
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::F);
    h.run();
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().selected_entry, Some(sample), "arrows belong to the text field");
    h.key_press(egui::Key::Escape);
    h.run();

    // …nor while a dialog is open.
    h.state_mut().dialog = Dialog::Shortcuts;
    h.run();
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().selected_entry, Some(sample), "dialogs block arrow navigation");
    h.state_mut().dialog = Dialog::None;
    h.run();

    // The table follows the same order.
    h.state_mut().prefs.list_view = false;
    h.run();
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().selected_entry, Some(web), "Down works in table mode too");
}

#[test]
fn shift_click_selects_a_range() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    {
        let db = h.state_mut().db.as_mut().unwrap();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "Third Entry");
    }
    h.run();
    // Title order: Sample Entry, Third Entry, Web Login.
    h.get_by_label("Sample Entry").click();
    h.run();
    h.get_by_label("Web Login").click_modifiers(egui::Modifiers::SHIFT);
    h.run();
    let ids: std::collections::HashSet<_> = ["Sample Entry", "Third Entry", "Web Login"]
        .iter()
        .map(|t| entry_id(&h, t))
        .collect();
    assert_eq!(h.state().selected_entries, ids, "the whole range is selected");
    assert_eq!(h.state().selected_entry, Some(entry_id(&h, "Web Login")));
    // A plain click collapses it again.
    row(&h, "Web Login").click();
    h.run();
    assert_eq!(h.state().selected_entries.len(), 1);
}

#[test]
fn entry_rows_have_a_context_menu() {
    let (_dir, mut h, clip) = open_sample(egui::vec2(1200.0, 900.0));
    let web = entry_id(&h, "Web Login");

    h.get_by_label("Web Login").click_secondary();
    h.run();
    assert_eq!(h.state().selected_entry, Some(web), "right-click selects the row");
    h.get_by_label("Copy username").click();
    h.run();
    assert_eq!(clip.contents().as_deref(), Some("webuser"));

    row(&h, "Web Login").click_secondary();
    h.run();
    h.get_by_label("Move to group…").click();
    h.run();
    match &h.state().dialog {
        Dialog::BatchMove(bm) => assert_eq!(bm.entries, vec![web]),
        _ => panic!("expected the move dialog"),
    }
    h.get_by_label("Move Entry to Group");
    h.key_press(egui::Key::Escape);
    h.run();

    row(&h, "Web Login").click_secondary();
    h.run();
    assert!(h.query_all_by_label("Edit…").count() >= 2, "menu Edit… next to the details one");
    h.query_all_by_label("Delete…").next().unwrap().click();
    h.run();
    assert!(matches!(h.state().dialog, Dialog::ConfirmDeleteEntry(id) if id == web));
}

// ---------------------------------------------------------------------------
// clipboard auto-clear and idle auto-lock
// ---------------------------------------------------------------------------

#[test]
fn copied_values_are_cleared_from_the_clipboard() {
    let (_dir, mut h, clip) = open_sample(egui::vec2(1200.0, 900.0));
    h.get_by_label("Sample Entry").click();
    h.run();
    h.get_by_label("Copy Password").click();
    h.run();
    let password = clip.contents().expect("password copied");
    assert!(!password.is_empty());
    let toast = h.state().toasts.last().unwrap().text.clone();
    assert!(toast.contains("clears in 30 s"), "toast announces the clear: {toast:?}");

    // Nothing happens before the deadline…
    let now = Instant::now();
    assert_eq!(h.state_mut().tick_clipboard(now), None);
    assert_eq!(clip.contents().as_deref(), Some(password.as_str()));
    // …then our value is removed.
    let later = now + Duration::from_secs(31);
    assert_eq!(
        h.state_mut().tick_clipboard(later),
        Some(friendlypass_gui::clipboard::ClearOutcome::Cleared)
    );
    assert_eq!(clip.contents(), None);

    // Something the user copied afterwards is left alone.
    h.state_mut().copy_selected(friendlypass_gui::app::CopyField::Username);
    use friendlypass_gui::clipboard::ClipboardBackend;
    clip.set_text("my own text").unwrap();
    assert_eq!(
        h.state_mut().tick_clipboard(Instant::now() + Duration::from_secs(31)),
        Some(friendlypass_gui::clipboard::ClearOutcome::Replaced)
    );
    assert_eq!(clip.contents().as_deref(), Some("my own text"));

    // Turned off: no clear is scheduled and the toast says nothing about it.
    h.state_mut().prefs.clipboard_clear = false;
    h.state_mut().copy_selected(friendlypass_gui::app::CopyField::Password);
    assert!(h.state().clipboard_pending.is_none());
    let toast = h.state().toasts.last().unwrap().text.clone();
    assert!(!toast.contains("clears"), "no countdown when off: {toast:?}");

    // Locking clears a pending copy right away.
    h.state_mut().prefs.clipboard_clear = true;
    h.state_mut().copy_selected(friendlypass_gui::app::CopyField::Password);
    assert!(clip.contents().is_some());
    h.state_mut().lock();
    assert_eq!(clip.contents(), None, "lock clears our clipboard value");
}

#[test]
fn idle_auto_lock_never_discards_unsaved_changes() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    let now = Instant::now();
    let idle = |h: &mut Harness<'_, friendlypass_gui::App>| {
        h.state_mut().last_activity = now - Duration::from_secs(3 * 60);
    };

    // Off by default: nothing happens however long the user is away.
    idle(&mut h);
    assert_eq!(h.state_mut().tick_idle_lock(now), IdleLock::Wait);
    assert!(h.state().db.is_some());

    h.state_mut().prefs.auto_lock = true;
    h.state_mut().prefs.auto_lock_minutes = 2;

    // Not idle long enough yet.
    h.state_mut().last_activity = now - Duration::from_secs(60);
    assert_eq!(h.state_mut().tick_idle_lock(now), IdleLock::Wait);

    // Unsaved changes: postponed, the database stays open, and the status
    // bar says why.
    h.state_mut().dirty = true;
    idle(&mut h);
    assert_eq!(h.state_mut().tick_idle_lock(now), IdleLock::Postpone);
    assert!(h.state().db.is_some(), "unsaved changes are not thrown away");
    assert!(h.state().status.contains("Auto-lock postponed"));

    // An open editor counts as unsaved work too.
    h.state_mut().dirty = false;
    h.get_by_label("Sample Entry").click();
    h.run();
    h.get_by_label("Edit…").click();
    h.run();
    idle(&mut h);
    assert_eq!(h.state_mut().tick_idle_lock(now), IdleLock::Postpone);
    h.state_mut().inline_edit = None;

    // Nothing to lose: it locks.
    idle(&mut h);
    assert_eq!(h.state_mut().tick_idle_lock(now), IdleLock::Lock);
    assert!(h.state().db.is_none(), "locked after inactivity");
    assert_eq!(h.state().status, "Locked after inactivity");
}

// ---------------------------------------------------------------------------
// chrome: status bar, toolbar save state, unlock errors, dark mode
// ---------------------------------------------------------------------------

#[test]
fn status_bar_shows_count_and_unsaved_state() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    h.get_by_label("2 entries");
    h.get_by_label("All changes saved");
    assert!({ use egui_kittest::kittest::NodeT; h.get_by_label("Save database").accesskit_node().is_disabled() }, "Save is disabled when clean");

    let id = entry_id(&h, "Web Login");
    h.state_mut().toggle_favorite(id);
    h.run();
    h.get_by_label("Unsaved changes");
    assert!(!{ use egui_kittest::kittest::NodeT; h.get_by_label("Save database").accesskit_node().is_disabled() }, "Save is enabled when dirty");

    h.state_mut().search = "web".into();
    h.run();
    h.get_by_label("1 entry");
}

#[test]
fn unlock_errors_are_short_and_specific() {
    // A missing file.
    let mut app = friendlypass_gui::App::default();
    app.db_path = "/definitely/not/here.kdbx".into();
    app.password = "x".into();
    app.try_unlock();
    assert_eq!(app.unlock_error, "Database file not found.");
    assert!(app.unlock_error_detail.contains("/definitely/not/here.kdbx"));
    assert!(app.focus_password, "the password field gets focus back");

    // Not a database.
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.kdbx");
    std::fs::write(&junk, b"this is not a keepass file").unwrap();
    let mut app = friendlypass_gui::App::default();
    app.db_path = junk.display().to_string();
    app.password = "x".into();
    app.try_unlock();
    assert_eq!(
        app.unlock_error,
        "This file isn't a KeePass database, or it is damaged."
    );

    // Wrong password on a KDBX 4 database (the 3.1 case is covered in gui.rs).
    let mut app = friendlypass_gui::App::default();
    app.db_path = fixture("sample4_keyfile.kdbx").display().to_string();
    app.password = "testpassword".into();
    app.try_unlock();
    assert_eq!(app.unlock_error, "Wrong password or key file.");
}

#[test]
fn dark_theme_is_selectable_and_tests_default_to_light() {
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1150.0, 800.0));
    assert!(
        !friendlypass_gui::theme::p().dark,
        "following the system in the headless harness resolves to light"
    );
    h.state_mut().prefs.theme = friendlypass_gui::theme::ThemeChoice::Dark;
    h.run();
    assert!(friendlypass_gui::theme::p().dark, "the dark palette is active");
    h.get_by_label("Sample Entry").click();
    h.run();
    pin_times(&mut h);
    h.hover_at(egui::pos2(1140.0, 790.0));
    h.run();
    h.snapshot("gui_dark_entry_details");

    h.state_mut().prefs.theme = friendlypass_gui::theme::ThemeChoice::Light;
    h.run();
    assert!(!friendlypass_gui::theme::p().dark);
}

#[test]
fn new_entries_use_the_inline_editor_in_narrow_and_table_layouts() {
    // Narrow window: list and details are stacked; the editor sits under
    // the list.
    let (_dir, mut h, _clip) = open_sample(egui::vec2(700.0, 900.0));
    h.get_by_label("New Entry").click();
    h.run();
    assert!(matches!(h.state().dialog, Dialog::None), "no floating window");
    h.get_by_label("New Item");
    h.get_by_label("Title:").click();
    h.run();
    h.event(egui::Event::Text("Narrow Entry".into()));
    h.run();
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::Enter);
    h.run();
    assert!(h.state().inline_edit.is_none());
    let id = entry_id(&h, "Narrow Entry");
    assert_eq!(h.state().selected_entry, Some(id), "the new entry is selected");

    // Table mode switches to the list layout for editing, as for edits.
    let (_dir, mut h, _clip) = open_sample(egui::vec2(1200.0, 900.0));
    h.state_mut().prefs.list_view = false;
    h.run();
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::N);
    h.run();
    assert!(h.state().prefs.list_view, "editing uses the list + details layout");
    h.get_by_label("New Item");
    h.get_by_label("Cancel").click();
    h.run();
    assert!(h.state().inline_edit.is_none());
    assert_eq!(h.state().status, "Cancelled");
}

#[test]
fn settings_expose_security_and_theme_and_persist_them() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.json");
    let db = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &db).unwrap();
    let (config_c, db_c) = (config.clone(), db.display().to_string());
    let mut h = Harness::new_eframe(move |_cc| {
        let mut app = friendlypass_gui::App::with_open_database(
            &db_c,
            DatabaseKey::new().with_password("testpassword"),
        );
        app.config_path = Some(config_c);
        app
    });
    h.set_size(egui::vec2(1200.0, 1000.0));
    h.run();

    h.get_by_label("Settings and tools").click();
    h.run();
    h.get_by_label("Settings…").click();
    h.run();
    h.get_by_label("Security");

    // Idle auto-lock: off by default; turn it on and pick 5 minutes from the
    // drop-down (a popup inside the modal dialog).
    h.get_by_label("Lock after inactivity of").click();
    h.run();
    assert!(h.state().prefs.auto_lock);
    h.get_by_label("minutes").click();
    h.run();
    h.get_by_label("5").click();
    h.run();
    assert_eq!(h.state().prefs.auto_lock_minutes, 5);

    // Clipboard auto-clear can be turned off.
    h.get_by_label("Clear the clipboard after").click();
    h.run();
    assert!(!h.state().prefs.clipboard_clear);

    // Theme choice.
    h.get_by_label("Dark").click();
    h.run();
    assert_eq!(h.state().prefs.theme, friendlypass_gui::theme::ThemeChoice::Dark);

    let saved = friendlypass_gui::config::Preferences::load(&config);
    assert!(saved.auto_lock && saved.auto_lock_minutes == 5);
    assert!(!saved.clipboard_clear);
    assert_eq!(saved.theme, friendlypass_gui::theme::ThemeChoice::Dark);
}
