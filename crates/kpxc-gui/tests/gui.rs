//! Headless GUI tests using `egui_kittest`: drive the real `eframe` app the
//! way a user would (clicks, typing), and assert on both the rendered UI and
//! the resulting app state.
//!
//! These tests double as compatibility evidence: the final test creates a
//! database copy, adds an entry through the GUI, upgrades it from KDBX 3.1
//! to 4.1 via the save dialog, and saves — producing a file that
//! `keepassxc-cli` (the original C++ app) can then open (see verify.sh).
//!
//! Snapshots (PNG renders of the actual UI) are stored in
//! `crates/kpxc-gui/tests/snapshots/`.

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use keepass::DatabaseKey;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name)
}

/// Copy the sample database (keepassxc-cli 2.8.0 created, KDBX 3.1) to a
/// writable location, because the GUI tests modify and save it.
fn fresh_sample(dir: &tempfile::TempDir) -> PathBuf {
    let dst = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &dst).unwrap();
    dst
}

/// Make snapshots deterministic: the status bar shows the (random) tempdir
/// path, which would otherwise make image comparisons unstable.
fn stabilize(harness: &mut Harness<kpxc_gui::App>) {
    harness.state_mut().status.clear();
    harness.run();
}

#[test]
fn unlock_screen_renders() {
    let mut harness = Harness::new_eframe(|_cc| kpxc_gui::App::default());
    harness.run();

    // All the unlock controls are present and accessible.
    harness.get_by_label("Database file:");
    harness.get_by_label("Password:");
    harness.get_by_label("Key file (optional):");
    harness.get_by_label("Unlock");
    harness.get_by_label("Create new database…");

    harness.snapshot("gui_unlock_screen");
}

#[test]
fn wrong_password_shows_error() {
    let mut harness = Harness::new_eframe(|_cc| {
        let mut app = kpxc_gui::App::default();
        app.db_path = fixture("sample4.kdbx").display().to_string();
        app.password = "wrong-password".into();
        app
    });
    harness.run();

    harness.get_by_label("Unlock").click();
    harness.run();

    // Still on the unlock screen, with an error message.
    let state = harness.state();
    assert!(state.db.is_none(), "database must not open with a wrong password");
    assert!(
        state.unlock_error.contains("unable to open"),
        "expected an error, got: {:?}",
        state.unlock_error
    );
    harness.snapshot("gui_unlock_error");
}

#[test]
fn browse_groups_entries_and_details() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_sample(&dir);
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = path.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| kpxc_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 720.0));
    harness.run();

    // Group tree: root + the two groups created by keepassxc-cli.
    let state = harness.state();
    assert!(state.db.is_some());
    let db = state.db.as_ref().unwrap();
    assert_eq!(db.num_groups(), 3, "root + Web + Bank");
    assert_eq!(db.num_entries(), 2);

    // Entry table lists both entries.
    harness.get_by_label("Sample Entry");
    harness.get_by_label("Web Login");
    stabilize(&mut harness);
    harness.snapshot("gui_main_window");

    // Select an entry -> the details panel with copy buttons appears.
    harness.get_by_label("Sample Entry").click();
    harness.run();
    harness.get_by_label("Edit…");
    harness.get_by_label("Copy UserName");
    harness.get_by_label("Copy Password");
    stabilize(&mut harness);
    harness.snapshot("gui_entry_details");

    // Wrong search term -> empty result message.
    harness.state_mut().search = "does-not-exist".into();
    harness.run();
    harness.get_by_label_contains("No entries match");

    // Search matches across groups.
    harness.state_mut().search = "web login".into();
    harness.run();
    harness.get_by_label("Web Login");
    stabilize(&mut harness);
    harness.snapshot("gui_search");
}

#[test]
fn add_entry_via_ui_save_with_upgrade_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_sample(&dir);

    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = path.display().to_string();
    let mut harness = Harness::new_eframe(move |_cc| {
        kpxc_gui::App::with_open_database(&path_str, key)
    });
    harness.set_size(egui::Vec2::new(1150.0, 720.0));
    harness.run();

    // --- open the "New Entry" dialog ---------------------------------
    harness.get_by_label("New Entry").click();
    harness.run();
    harness.get_by_label("Title:");
    harness.get_by_label("Password:");
    stabilize(&mut harness);
    harness.snapshot("gui_new_entry_dialog");

    // --- type a title, generate a password ----------------------------
    harness.get_by_label("Title:").click();
    harness.run();
    harness.event(egui::Event::Text("GUI Created Entry".into()));
    harness.run();
    harness.get_by_label("Generate").click();
    harness.run();

    // --- confirm the dialog -------------------------------------------
    harness.get_by_label("OK").click();
    harness.run();

    let state = harness.state();
    let db = state.db.as_ref().unwrap();
    assert_eq!(db.num_entries(), 3, "entry added through the GUI");
    assert!(state.dirty, "modification marks the database dirty");
    let entry = db
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("GUI Created Entry"))
        .expect("new entry present");
    assert!(!entry.get("Password").unwrap().is_empty(), "generated password set");

    // --- saving a KDBX 3.1 database asks for the 4.1 upgrade ----------
    harness.get_by_label("Save").click();
    harness.run();
    harness.get_by_label("Upgrade Database Format");
    stabilize(&mut harness);
    harness.snapshot("gui_upgrade_dialog");

    harness.get_by_label("Upgrade and Save").click();
    harness.run();

    let state = harness.state();
    assert!(!state.dirty, "saved");
    assert!(
        state.status.contains("Saved"),
        "status: {:?}",
        state.status
    );
    assert!(matches!(
        state.db.as_ref().unwrap().config.version,
        keepass::config::DatabaseVersion::KDB4(1)
    ));

    // --- the saved file opens again, with everything intact -----------
    let mut file = std::fs::File::open(&path).unwrap();
    let db2 = keepass::Database::open(
        &mut file,
        DatabaseKey::new().with_password("testpassword"),
    )
    .unwrap();
    assert_eq!(db2.num_entries(), 3);
    assert!(db2
        .iter_all_entries()
        .any(|e| e.get("Title") == Some("GUI Created Entry")));
    // The pre-existing attachment survived the upgrade.
    let sample = db2
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("Sample Entry"))
        .unwrap();
    assert!(sample.attachment_by_name("attach.txt").is_some());

    stabilize(&mut harness);
    harness.snapshot("gui_after_save");
}

// ---------------------------------------------------------------------------
// recycle bin
// ---------------------------------------------------------------------------

#[test]
fn delete_entry_moves_to_recycle_bin_then_permanent() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_sample(&dir);
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = path.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| kpxc_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 720.0));
    harness.run();

    // Deleting an entry outside the bin asks to move it to the Recycle Bin.
    harness.get_by_label("Web Login").click();
    harness.run();
    harness.get_by_label("Delete…").click();
    harness.run();
    harness.get_by_label("Move to Recycle Bin").click();
    harness.run();

    let state = harness.state();
    let db = state.db.as_ref().unwrap();
    assert_eq!(db.num_entries(), 2, "entry was moved, not removed");
    let bin = db.recycle_bin().expect("recycle bin created lazily");
    assert_eq!(bin.name, "Recycle Bin");
    assert!(db.meta.recyclebin_uuid.is_some(), "bin registered in metadata");
    assert_eq!(bin.entries().count(), 1);
    assert!(
        state.status.contains("Recycle Bin"),
        "status: {:?}",
        state.status
    );
    harness.snapshot("gui_recycle_bin_created");

    // The bin appears in the group tree; selecting it enables "Empty Recycle Bin…".
    harness.get_by_label("Recycle Bin (1)").click();
    harness.run();
    harness.get_by_label("Web Login").click();
    harness.run();

    // Deleting from inside the bin is permanent.
    harness.get_by_label("Delete…").click();
    harness.run();
    // The confirm button now says "Delete" (permanent).
    harness.get_by_label("Delete").click();
    harness.run();
    let state = harness.state();
    assert_eq!(state.db.as_ref().unwrap().num_entries(), 1);
    assert!(
        state.status.contains("permanently"),
        "status: {:?}",
        state.status
    );

    // Empty the bin via the tree action (empty now, but must not fail).
    harness.state_mut().dialog = kpxc_gui::dialogs::Dialog::ConfirmEmptyRecycleBin;
    harness.run();
    harness.get_by_label("Empty Recycle Bin").click();
    harness.run();
    let state = harness.state();
    assert!(
        state.status.contains("Emptied the Recycle Bin"),
        "status: {:?}",
        state.status
    );

    // Save (with upgrade) and verify the bin + metadata survive on disk.
    harness.get_by_label("Save").click();
    harness.run();
    harness.get_by_label("Upgrade and Save").click();
    harness.run();

    let mut file = std::fs::File::open(&path).unwrap();
    let db2 = keepass::Database::open(
        &mut file,
        DatabaseKey::new().with_password("testpassword"),
    )
    .unwrap();
    assert_eq!(db2.num_entries(), 1);
    assert!(db2.recycle_bin().is_some(), "recycle bin persisted");
    assert!(db2.meta.recyclebin_uuid.is_some());
}

// ---------------------------------------------------------------------------
// entry history
// ---------------------------------------------------------------------------

/// Focus the widget, select all, and replace its text.
fn replace_text(harness: &mut Harness<kpxc_gui::App>, label: &str, text: &str) {
    harness.get_by_label(label).click();
    harness.run();
    harness.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    harness.run();
    harness.event(egui::Event::Text(text.into()));
    harness.run();
}

#[test]
fn entry_history_browser_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_sample(&dir);
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = path.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| kpxc_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 720.0));
    harness.run();

    let history_len = |h: &Harness<kpxc_gui::App>| {
        h.state()
            .db
            .as_ref()
            .unwrap()
            .iter_all_entries()
            .find(|e| e.get("Title") == Some("Sample Entry"))
            .unwrap()
            .history
            .as_ref()
            .map(|hist| hist.get_entries().len())
            .unwrap_or(0)
    };
    let baseline = history_len(&harness);

    // Edit the username through the entry editor -> history is recorded.
    harness.get_by_label("Sample Entry").click();
    harness.run();
    harness.get_by_label("Edit…").click();
    harness.run();
    replace_text(&mut harness, "UserName:", "changed-user@example.org");
    harness.get_by_label("OK").click();
    harness.run();

    assert_eq!(history_len(&harness), baseline + 1, "edit recorded a history item");
    let current_user = harness
        .state()
        .db
        .as_ref()
        .unwrap()
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("Sample Entry"))
        .unwrap()
        .get("UserName")
        .unwrap()
        .to_string();
    assert_eq!(current_user, "changed-user@example.org");

    // Open the history browser: the old revision is listed with its old username.
    harness.get_by_label("History…").click();
    harness.run();
    // (The fixture may carry several revisions — at least one must match.)
    let old_revisions = harness.query_all_by_label_contains("user@example.com");
    assert!(old_revisions.count() > 0, "history lists the old username");
    stabilize(&mut harness);
    harness.snapshot("gui_history_dialog");

    // Restore revision 0: all fields revert, and the restore itself is history.
    harness.get_by_label("Restore revision 0").click();
    harness.run();
    assert!(history_len(&harness) >= baseline + 2, "restore recorded in history");
    let restored_user = harness
        .state()
        .db
        .as_ref()
        .unwrap()
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("Sample Entry"))
        .unwrap()
        .get("UserName")
        .unwrap()
        .to_string();
    assert_eq!(restored_user, "user@example.com", "fields restored");
    assert!(
        harness.state().status.contains("Restored"),
        "status: {:?}",
        harness.state().status
    );
}

// ---------------------------------------------------------------------------
// custom attributes (with protection) and auto-type editing
// ---------------------------------------------------------------------------

#[test]
fn custom_attributes_and_autotype_edit_and_persist() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_sample(&dir);
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = path.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| kpxc_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 720.0));
    harness.run();

    // Open the entry editor for "Sample Entry".
    harness.get_by_label("Sample Entry").click();
    harness.run();
    harness.get_by_label("Edit…").click();
    harness.run();

    // Add a protected custom attribute.
    harness.get_by_label("Add attribute").click();
    harness.run();
    replace_text(&mut harness, "Attribute 0 key:", "API Key");
    replace_text(&mut harness, "Attribute 0 value:", "sk-secret-12345");
    harness.get_by_label("Protected 0").click();
    harness.run();

    // Configure auto-type: default sequence + a window association.
    replace_text(&mut harness, "Default sequence:", "{USERNAME}{TAB}{PASSWORD}{ENTER}");
    harness.get_by_label("Add window association").click();
    harness.run();
    replace_text(&mut harness, "Window 0:", "* - Notepad");
    replace_text(&mut harness, "Sequence 0:", "{USERNAME}{ENTER}");

    harness.get_by_label("OK").click();
    harness.run();

    // Assert on the in-memory database.
    let entry = harness
        .state()
        .db
        .as_ref()
        .unwrap()
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("Sample Entry"))
        .unwrap();
    let attr = entry.fields.get("API Key").expect("attribute stored");
    assert_eq!(attr.get(), "sk-secret-12345");
    assert!(attr.is_protected(), "attribute is protected");
    let at = entry.autotype.as_ref().expect("autotype stored");
    assert!(at.enabled);
    assert_eq!(at.default_sequence.as_deref(), Some("{USERNAME}{TAB}{PASSWORD}{ENTER}"));
    assert_eq!(at.associations.len(), 1);
    assert_eq!(at.associations[0].window, "* - Notepad");
    assert_eq!(at.associations[0].sequence, "{USERNAME}{ENTER}");

    // The details panel lists the protected attribute (panics if missing).
    harness.get_by_label("API Key (protected)");
    stabilize(&mut harness);
    harness.snapshot("gui_attributes_details");

    // Save (upgrade dialog) and verify persistence on disk.
    harness.get_by_label("Save").click();
    harness.run();
    harness.get_by_label("Upgrade and Save").click();
    harness.run();

    let mut file = std::fs::File::open(&path).unwrap();
    let db2 = keepass::Database::open(
        &mut file,
        DatabaseKey::new().with_password("testpassword"),
    )
    .unwrap();
    let entry = db2
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("Sample Entry"))
        .unwrap();
    let attr = entry.fields.get("API Key").expect("attribute persisted");
    assert!(attr.is_protected(), "protection flag persisted");
    assert_eq!(attr.get(), "sk-secret-12345");
    let at = entry.autotype.as_ref().unwrap();
    assert_eq!(at.associations.len(), 1, "auto-type association persisted");
    assert_eq!(at.associations[0].window, "* - Notepad");
}


#[test]
#[ignore]
fn write_database_for_external_verification() {
    let out = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/gui-roundtrip.kdbx");
    let _ = std::fs::remove_file(&out);

    let mut harness = Harness::new_eframe(|_cc| {
        let mut app = kpxc_gui::App::default();
        app.dialog = kpxc_gui::dialogs::Dialog::NewDb(Box::new(kpxc_gui::dialogs::NewDb {
            path: out.display().to_string(),
            name: "GUI Roundtrip".into(),
            password: "gui-pass-123".into(),
            password_repeat: "gui-pass-123".into(),
            key_file: String::new(),
            iterations: 10,
            memory_mib: 8,
            parallelism: 2,
            error: String::new(),
        }));
        app
    });
    harness.set_size(egui::Vec2::new(1150.0, 720.0));
    harness.run();

    // Create the database through the dialog.
    harness.get_by_label("Create").click();
    harness.run();

    let state = harness.state();
    assert!(state.db.is_some(), "database created");
    assert!(state.db.as_ref().unwrap().num_entries() == 0);

    // Add an entry through the GUI — with a protected custom attribute and
    // an auto-type configuration.
    harness.get_by_label("New Entry").click();
    harness.run();
    harness.get_by_label("Title:").click();
    harness.run();
    harness.event(egui::Event::Text("GUI Only Entry".into()));
    harness.run();
    harness.get_by_label("Add attribute").click();
    harness.run();
    replace_text(&mut harness, "Attribute 0 key:", "API Key");
    replace_text(&mut harness, "Attribute 0 value:", "sk-12345");
    harness.get_by_label("Protected 0").click();
    harness.run();
    replace_text(&mut harness, "Default sequence:", "{USERNAME}{TAB}{PASSWORD}{ENTER}");
    harness.get_by_label("Generate").click();
    harness.run();
    harness.get_by_label("OK").click();
    harness.run();

    // Add a second entry and delete it -> lands in the Recycle Bin.
    harness.get_by_label("New Entry").click();
    harness.run();
    harness.get_by_label("Title:").click();
    harness.run();
    harness.event(egui::Event::Text("Temp Entry".into()));
    harness.run();
    harness.get_by_label("OK").click();
    harness.run();
    // The newly added entry is selected automatically -> the details panel
    // shows "Temp Entry"; delete via the details panel.
    harness.get_by_label("Delete…").click();
    harness.run();
    harness.get_by_label("Move to Recycle Bin").click();
    harness.run();

    // Save.
    harness.get_by_label("Save").click();
    harness.run();

    let state = harness.state();
    assert!(
        state.status.contains("Saved"),
        "status: {:?}",
        state.status
    );

    // The file must open with the keepass engine and contain the entry,
    // the protected attribute, the auto-type settings, and the recycle bin.
    let mut file = std::fs::File::open(&out).unwrap();
    let db = keepass::Database::open(
        &mut file,
        DatabaseKey::new().with_password("gui-pass-123"),
    )
    .unwrap();
    assert_eq!(db.num_entries(), 2, "one live + one recycled");
    let entry = db
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("GUI Only Entry"))
        .unwrap();
    assert_eq!(entry.fields.get("API Key").unwrap().get(), "sk-12345");
    assert!(entry.fields.get("API Key").unwrap().is_protected());
    assert!(entry.autotype.as_ref().unwrap().default_sequence.is_some());
    assert!(db.recycle_bin().is_some(), "recycle bin group persisted");
    assert_eq!(db.recycle_bin().unwrap().entries().count(), 1);
}

// ---------------------------------------------------------------------------
// unit tests for the pure logic helpers
// ---------------------------------------------------------------------------

#[test]
fn generator_options_produce_expected_classes() {
    let pw = kpxc::commands::generate_password_opts(200, false, true, false, false);
    assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    let pw = kpxc::commands::generate_password_opts(200, true, false, false, true);
    assert!(pw.chars().all(|c| c.is_ascii_uppercase() || "!@#$%^&*()-_=+[]{};:,.<>?/".contains(c)));
    assert_eq!(kpxc::commands::generate_password_opts(17, true, true, true, true).len(), 17);
}
