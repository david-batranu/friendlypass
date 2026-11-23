//! UI polish regression tests for the changes driven by the layout/UX goal:
//!
//! * long attachment names no longer run underneath the Export/Delete
//!   buttons — at any window width, including the narrow stacked layout;
//! * entries with attachments are marked in both list and table mode and can
//!   be filtered from the sidebar;
//! * the toolbar Back/Forward arrows actually navigate between entries;
//! * the GROUPS / TAGS section chevrons really collapse their sections.

use eframe::egui;
use egui_kittest::kittest::{NodeT, Queryable};
use egui_kittest::Harness;
use keepass::DatabaseKey;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn open_sample() -> (tempfile::TempDir, Harness<'static, friendlypass_gui::App>) {
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &dst).unwrap();
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = dst.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| friendlypass_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 900.0));
    harness.run();
    (dir, harness)
}

fn entry_id(harness: &Harness<'_, friendlypass_gui::App>, title: &str) -> keepass::db::EntryId {
    harness
        .state()
        .db
        .as_ref()
        .unwrap()
        .iter_all_entries()
        .find(|e| e.get("Title") == Some(title))
        .expect("entry exists")
        .id()
}

/// Every accessible node that carries a label, with where it was drawn.
fn labelled_nodes(harness: &Harness<'_, friendlypass_gui::App>) -> Vec<(String, egui::Rect)> {
    let root = harness.root();
    root.children_recursive()
        .filter_map(|n| {
            let node = n.accesskit_node();
            // kittest exposes Role::Label text through `value`, other widgets
            // through `label`.
            let text = if node.role() == accesskit::Role::Label {
                node.value()
            } else {
                node.label()
            }?;
            node.bounding_box()?;
            Some((text, n.rect()))
        })
        .collect()
}

fn find_node(harness: &Harness<'_, friendlypass_gui::App>, pred: impl Fn(&str) -> bool) -> Option<egui::Rect> {
    labelled_nodes(harness)
        .into_iter()
        .find(|(label, _)| pred(label))
        .map(|(_, rect)| rect)
}

const LONG_NAME: &str =
    "1PasswordExport-J6ZX2N25FBGMLAAQX5EDJZ2Z44-20261120-151905.1pux";

#[test]
fn long_attachment_names_never_overlap_the_buttons() {
    let (_dir, mut harness) = open_sample();
    let id = entry_id(&harness, "Sample Entry");
    harness
        .state_mut()
        .add_entry_attachment(id, LONG_NAME, vec![0u8; 2048])
        .unwrap();
    harness.run();
    harness.get_by_label("Sample Entry").click();
    harness.run();

    for (w, h) in [(1150.0, 900.0), (900.0, 800.0), (700.0, 800.0)] {
        harness.set_size(egui::Vec2::new(w, h));
        harness.run();

        let name_rect = find_node(&harness, |l| l.starts_with("1PasswordExp"))
            .unwrap_or_else(|| panic!("file name is shown at {w}x{h}"));
        let buttons: Vec<egui::Rect> = labelled_nodes(&harness)
            .into_iter()
            .filter(|(l, _)| l == "Export…" || l == "Delete")
            .map(|(_, r)| r)
            .collect();
        assert!(!buttons.is_empty(), "buttons are visible at {w}x{h}");
        for btn in &buttons {
            assert!(
                !name_rect.intersects(*btn),
                "at {w}x{h} the name {name_rect:?} overlaps a button {btn:?}"
            );
        }
    }
}

#[test]
fn the_attachment_row_stacks_when_the_name_would_be_squeezed() {
    use friendlypass_gui::browser::{attachment_row_inline, ATTACHMENT_MIN_NAME_WIDTH};
    let buttons = 180.0;
    // Wide panel: buttons beside the name.
    assert!(attachment_row_inline(600.0, buttons));
    // Just enough for the minimum name width: still inline.
    assert!(attachment_row_inline(buttons + ATTACHMENT_MIN_NAME_WIDTH, buttons));
    // Narrow panel: stacked, so the name always keeps its minimum width.
    assert!(!attachment_row_inline(buttons + ATTACHMENT_MIN_NAME_WIDTH - 1.0, buttons));
    assert!(!attachment_row_inline(300.0, buttons));
}

#[test]
fn middle_truncation_keeps_the_file_extension() {
    use friendlypass_gui::theme::truncate_middle_with;
    // Pretend every character is 7 px wide.
    let measure = |s: &str| s.chars().count() as f32 * 7.0;

    // Fits: untouched.
    assert_eq!(
        truncate_middle_with("short.txt", 500.0, measure),
        "short.txt"
    );

    // Too long: shortened in the middle, both ends kept.
    let shortened = truncate_middle_with(LONG_NAME, 30.0 * 7.0, measure);
    assert!(shortened.contains('…'), "an ellipsis marks the elision: {shortened:?}");
    assert!(shortened.starts_with("1PasswordEx"), "prefix kept: {shortened:?}");
    assert!(shortened.ends_with(".1pux"), "extension kept: {shortened:?}");
    assert!(
        measure(&shortened) <= 30.0 * 7.0,
        "result fits the width: {shortened:?}"
    );

    // A tiny (but positive) budget still fits within the width.
    let tiny = truncate_middle_with(LONG_NAME, 21.0, measure);
    assert!(tiny.contains('…'), "tiny budget keeps an ellipsis: {tiny:?}");
    assert!(measure(&tiny) <= 21.0, "tiny result fits: {tiny:?}");
    // A caller that passes no constraint gets the text back untouched.
    assert_eq!(truncate_middle_with(LONG_NAME, 0.0, measure), LONG_NAME);
}

#[test]
fn attachment_buttons_have_icons_and_a_destructive_style() {
    let (_dir, mut harness) = open_sample();
    harness.get_by_label("Sample Entry").click();
    harness.run();
    // The quiet buttons expose their labels to assistive tech, which also
    // proves the icons are inside the button rather than floating beside it.
    assert!(find_node(&harness, |l| l == "Export…").is_some());
    assert!(find_node(&harness, |l| l == "Delete").is_some());
    assert!(find_node(&harness, |l| l == "Add file…").is_some());
}

#[test]
fn entries_with_attachments_are_marked_and_filterable() {
    let (_dir, mut harness) = open_sample();

    // The fixture's "Sample Entry" has one attachment; the other does not.
    harness.get_by_label("Sample Entry").click();
    harness.run();
    assert!(
        find_node(&harness, |l| l == "1 attachment").is_some(),
        "the attachment badge is announced with its count"
    );
    harness.get_by_label("Web Login").click();
    harness.run();

    // Sidebar shortcut reports how many entries have attachments.
    let row = harness
        .query_all_by_label_contains("Attachments (")
        .next()
        .expect("sidebar Attachments row");
    row.click();
    harness.run();

    let state = harness.state();
    assert!(state.filter_attachments, "filter is on");
    assert!(!state.filter_favorites, "filters are exclusive");
    assert_eq!(state.selected_group, None, "group selection cleared");

    // Only the entry with an attachment is listed.
    let sample = entry_id(&harness, "Sample Entry");
    let visible = friendlypass_gui::browser::visible_entry_ids(harness.state());
    assert_eq!(visible, vec![sample], "only entries with attachments are listed");
    assert!(
        harness.query_by_label("Sample Entry").is_some(),
        "the entry with an attachment stays"
    );

    // Clicking again clears the filter.
    harness
        .query_all_by_label_contains("Attachments (")
        .next()
        .unwrap()
        .click();
    harness.run();
    assert!(!harness.state().filter_attachments);
    let visible = friendlypass_gui::browser::visible_entry_ids(harness.state());
    assert_eq!(visible.len(), 2, "the group's entries come back: {visible:?}");
}

#[test]
fn attachment_marking_also_shows_in_table_mode() {
    let (_dir, mut harness) = open_sample();
    harness
        .state_mut()
        .prefs
        .list_view = false;
    harness.run();
    harness.get_by_label("Sample Entry").click();
    harness.run();
    assert!(
        find_node(&harness, |l| l == "1 attachment").is_some(),
        "the table's title cell carries the badge too"
    );
}

#[test]
fn back_and_forward_arrows_navigate_between_entries() {
    let (_dir, mut harness) = open_sample();
    let sample = entry_id(&harness, "Sample Entry");
    let web = entry_id(&harness, "Web Login");

    harness.get_by_label("Sample Entry").click();
    harness.run();
    harness.get_by_label("Web Login").click();
    harness.run();
    assert_eq!(harness.state().selected_entry, Some(web));

    // Back returns to the first entry.
    harness.get_by_label("Back").click();
    harness.run();
    assert_eq!(harness.state().selected_entry, Some(sample));

    // Forward returns to the second.
    harness.get_by_label("Forward").click();
    harness.run();
    assert_eq!(harness.state().selected_entry, Some(web));

    // Going back then selecting a new entry drops the redo trail.
    harness.get_by_label("Back").click();
    harness.run();
    harness.get_by_label("Web Login").click();
    harness.run();
    assert!(
        harness.state().nav_forward.is_empty(),
        "a fresh selection clears Forward"
    );
}

#[test]
fn sidebar_sections_collapse_and_expand() {
    let (_dir, mut harness) = open_sample();

    // GROUPS: the "Bank" group row is visible, collapses, comes back.
    assert!(harness.query_by_label_contains("Bank").is_some());
    harness.get_by_label("Collapse groups").click();
    harness.run();
    assert!(harness.state().groups_collapsed);
    assert!(
        harness.query_by_label_contains("Bank").is_none(),
        "collapsed GROUPS hides its rows"
    );
    harness.get_by_label("Expand groups").click();
    harness.run();
    assert!(!harness.state().groups_collapsed);
    assert!(harness.query_by_label_contains("Bank").is_some());
}

#[test]
fn details_have_a_working_overflow_menu() {
    let (_dir, mut harness) = open_sample();
    harness.get_by_label("Sample Entry").click();
    harness.run();

    let kebab = harness
        .query_all_by_label("More actions")
        .next()
        .expect("overflow button");
    kebab.click();
    harness.run();

    // The menu opens with its actions (Edit… duplicates the action bar's
    // label, so the popup is identified by position near the top).
    let popup_item = |harness: &Harness<'_, friendlypass_gui::App>, label: &str| {
        labelled_nodes(harness)
            .into_iter()
            .find(|(l, r)| l == label && r.top() < 400.0)
            .unwrap_or_else(|| panic!("{label:?} in the popup"))
            .1
    };
    popup_item(&harness, "Edit…");
    popup_item(&harness, "Auto-Type");
    let history = popup_item(&harness, "History…");

    // Click it through its widget: find the Button node at that position.
    let history_node = harness
        .root()
        .children_recursive()
        .find(|n| {
            n.accesskit_node().label().as_deref() == Some("History…")
                && n.accesskit_node().bounding_box().is_some()
                && n.rect().top() < 400.0
        })
        .expect("History… menu item");
    history_node.click();
    harness.run();
    assert!(history.top() > 0.0);
    assert!(matches!(
        harness.state().dialog,
        friendlypass_gui::dialogs::Dialog::History(_)
    ));
}

#[test]
fn list_title_menu_switches_what_the_list_shows() {
    let (_dir, mut harness) = open_sample();
    // The title is a menu button ("All Items" by default).
    harness.get_by_label("All Items").click();
    harness.run();
    assert!(
        harness.query_by_label("With Attachments").is_some(),
        "the picker lists the attachment filter"
    );
    harness
        .get_by_role_and_label(accesskit::Role::Button, "Favorites")
        .click();
    harness.run();
    assert!(harness.state().filter_favorites);
}

#[test]
fn narrow_windows_drop_the_sidebar_and_stack_the_panes() {
    let (_dir, mut harness) = open_sample();
    harness.get_by_label("Sample Entry").click();
    harness.run();

    // Wide: all three columns, sidebar visible.
    harness.set_size(egui::Vec2::new(1150.0, 900.0));
    harness.run();
    assert!(
        harness.query_all_by_label_contains("Attachments (").count() > 0,
        "sidebar (with its Attachments filter row) is shown when wide"
    );

    // Medium: sidebar gives up its space, list + details stay side by side.
    harness.set_size(egui::Vec2::new(840.0, 900.0));
    harness.run();
    assert!(
        harness.query_all_by_label_contains("Attachments (").count() == 0,
        "sidebar is dropped below the three-column threshold"
    );
    // The toggle now reflects what is on screen (it used to say "Hide" while
    // the sidebar was already hidden).
    assert!(
        harness.query_by_label("Show the library sidebar").is_some(),
        "the toolbar toggle offers to bring the library back"
    );

    // Narrow: the details move under the list instead of being clipped away.
    harness.set_size(egui::Vec2::new(620.0, 900.0));
    harness.run();
    let name = find_node(&harness, |l| l == "Sample Entry").expect("list still shows entries");
    let details = find_node(&harness, |l| l == "ATTACHMENTS").expect("details are still rendered");
    assert!(
        details.top() > name.top(),
        "narrow layout stacks the details below the list (list {name:?}, details {details:?})"
    );
}

#[test]
fn toolbar_actions_never_overlap_the_search_box() {
    let (_dir, mut harness) = open_sample();
    for w in [620.0_f32, 780.0, 1150.0] {
        harness.set_size(egui::Vec2::new(w, 800.0));
        harness.run();

        let search = harness
            .query_all_by_role(accesskit::Role::TextInput)
            .map(|n| n.rect())
            .find(|r| r.width() > 80.0)
            .unwrap_or_else(|| panic!("search field at {w}"));
        for label in ["Settings and tools", "Add", "Save database", "Lock", "New Entry"] {
            let btn = find_node(&harness, |l| l == label);
            if let Some(btn) = btn {
                assert!(
                    !search.intersects(btn),
                    "at {w}px the search box {search:?} overlaps {label:?} {btn:?}"
                );
            }
        }
    }
}

#[test]
fn the_sidebar_toggle_hides_and_restores_the_library() {
    let (_dir, mut harness) = open_sample();
    harness.set_size(egui::Vec2::new(1150.0, 900.0));
    harness.run();
    assert!(harness.query_all_by_label_contains("Attachments (").count() > 0);

    harness.get_by_label("Hide the library sidebar").click();
    harness.run();
    assert_eq!(harness.state().sidebar_override, Some(false), "toggle records the choice");
    assert!(
        harness.query_all_by_label_contains("Attachments (").count() == 0,
        "the library is hidden"
    );

    harness.get_by_label("Show the library sidebar").click();
    harness.run();
    assert_eq!(harness.state().sidebar_override, Some(true));
    assert!(harness.query_all_by_label_contains("Attachments (").count() > 0);

    // A pinned-open sidebar also works in a narrow window (it then stacks).
    harness.set_size(egui::Vec2::new(700.0, 900.0));
    harness.run();
    assert!(
        harness.query_all_by_label_contains("Attachments (").count() > 0,
        "an explicit show overrides the automatic hide"
    );
}
