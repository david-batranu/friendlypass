//! Tests for the friendlier copy affordances in the entry details panel:
//! icon action buttons with hover chrome, click-to-copy on the value cell
//! itself, the transient "Copied" confirmation state and the toast.

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use keepass::db::fields;
use keepass::DatabaseKey;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

/// Open the sample database (keepassxc-cli 2.8.0, KDBX 3.1) and select
/// "Sample Entry" so the details panel is showing.
fn open_sample_with_details() -> (tempfile::TempDir, Harness<'static, friendlypass_gui::App>) {
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &dst).unwrap();
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = dst.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| friendlypass_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 1500.0));
    harness.run();
    harness.get_by_label("Sample Entry").click();
    harness.run();
    (dir, harness)
}

fn username_of_sample_entry(harness: &Harness<'_, friendlypass_gui::App>) -> String {
    let state = harness.state();
    let db = state.db.as_ref().unwrap();
    db.iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some("Sample Entry"))
        .unwrap()
        .get(fields::USERNAME)
        .unwrap()
        .to_owned()
}

#[test]
fn copy_button_enters_copied_state_and_queues_toast() {
    let (_dir, mut harness) = open_sample_with_details();

    // The copy affordances are real buttons with icons and tooltips.
    harness.get_by_label("Copy Username");
    harness.get_by_label("Copy Password");

    harness.get_by_label("Copy Username").click();
    harness.run();

    let state = harness.state();
    assert!(
        state.is_field_copied("username"),
        "username field should be in the Copied state"
    );
    assert!(!state.toasts.is_empty(), "a toast should be queued");
    assert!(
        state.status.contains("Copied"),
        "status bar should confirm the copy, got: {}",
        state.status
    );
    // The button itself morphed into the confirmation.
    harness.get_by_label("Copied");
}

#[test]
fn clicking_the_field_value_copies_it() {
    let (_dir, mut harness) = open_sample_with_details();
    let username = username_of_sample_entry(&harness);
    assert!(!username.is_empty());

    // The value cell is a button labelled with the value itself (the list
    // card also shows the username as plain text, so query by role+label).
    harness
        .get_by_role_and_label(accesskit::Role::Button, &username)
        .click();
    harness.run();

    assert!(
        harness.state().is_field_copied("username"),
        "clicking the value cell should copy it"
    );
    assert!(!harness.state().toasts.is_empty());
}

#[test]
fn show_hide_password_toggles_and_keeps_copy_state_independent() {
    let (_dir, mut harness) = open_sample_with_details();

    // Toggle visibility via the eye button.
    assert!(!harness.state().show_passwords);
    harness.get_by_label("Show").click();
    harness.run();
    assert!(harness.state().show_passwords);
    harness.get_by_label("Hide").click();
    harness.run();
    assert!(!harness.state().show_passwords);

    // Copying the password marks only the password field as copied.
    harness.get_by_label("Copy Password").click();
    harness.run();
    let state = harness.state();
    assert!(state.is_field_copied("password"));
    assert!(!state.is_field_copied("username"));
}
