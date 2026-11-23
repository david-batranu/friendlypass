//! UI layout regression tests: form fields must be wide (egui 0.37's Grid
//! clamps TextEdit widths to the previous frame's column width, which left
//! the fields tiny — forms use manual rows instead).

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use keepass::DatabaseKey;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name)
}

#[test]
fn form_fields_are_wide() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &db_path).unwrap();
    let key = DatabaseKey::new().with_password("testpassword");
    let path = db_path.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| kpxc_gui::App::with_open_database(&path, key));
    harness.set_size(egui::Vec2::new(1400.0, 1000.0));
    harness.run();

    // Open the entry editor and measure the fields.
    harness.get_by_label("New Entry").click();
    harness.run();
    for label in ["Title:", "UserName:", "URL:"] {
        let width = harness.get_by_label(label).rect().width();
        assert!(
            width >= 400.0,
            "{label} field is too narrow: {width}px (expected >= 400)"
        );
    }
    let password_width = harness.get_by_label("Password:").rect().width();
    assert!(
        password_width >= 400.0,
        "Password field is too narrow: {password_width}px"
    );

    // The unlock screen fields are wide too (fresh app, no database).
    let mut welcome = Harness::new_eframe(|_cc| kpxc_gui::App::default());
    welcome.set_size(egui::Vec2::new(1400.0, 900.0));
    welcome.run();
    let path_width = welcome.get_by_label("Database file:").rect().width();
    assert!(
        path_width >= 300.0,
        "unlock database-file field is too narrow: {path_width}px"
    );
    let pw_width = welcome.get_by_label("Password:").rect().width();
    assert!(
        pw_width >= 300.0,
        "unlock password field is too narrow: {pw_width}px"
    );
}
