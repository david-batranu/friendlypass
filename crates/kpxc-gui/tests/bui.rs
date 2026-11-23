//! Headless BUI tests: open real BUI windows off-screen, click/type into
//! the actual widget tree, assert on the state, and render PNG screenshots
//! with BUI's rasterizer.
//!
//! `cargo test -p kpxc-gui` runs these; they need no display server.

use blenderui::prelude::*;
use kpxc_gui::state::{BuiApp, EntryDraft, Modal};
use kpxc_gui_config::{ColumnId, Preferences};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn fresh_sample(dir: &tempfile::TempDir) -> PathBuf {
    let dst = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &dst).unwrap();
    dst
}

/// Copy the fixture to a fixed path: the screenshots then show the same path
/// on every run instead of a random tempdir.
fn stable_fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kpxc-bui-screens-{name}"));
    std::fs::create_dir_all(&dir).unwrap();
    let dst = dir.join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &dst).unwrap();
    dst
}

fn open_app(cx: &mut App, app: BuiApp) -> WindowHandle<BuiApp> {
    let opts = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds {
            origin: point(px(0.0), px(0.0)),
            size: size(px(1200.0), px(760.0)),
        })),
        ..Default::default()
    };
    cx.open_window(opts, move |_, cx| cx.new(|_| app))
        .expect("open headless BUI window")
}

/// The centre of an element, for clicking.
fn center(cx: &mut App, win: WindowId, id: &str) -> (f32, f32) {
    let b = cx
        .element_bounds(win, id)
        .unwrap_or_else(|| panic!("element {id:?} not found"));
    (b.origin.x + b.size.width / 2.0, b.origin.y + b.size.height / 2.0)
}

fn click(cx: &mut App, win: WindowId, id: &str) {
    let (x, y) = center(cx, win, id);
    cx.simulate_click(win, x, y);
}

fn type_into(cx: &mut App, win: WindowId, id: &str, text: &str) {
    click(cx, win, id);
    for ch in text.chars() {
        let s = ch.to_string();
        cx.simulate_key(win, &s, &s);
    }
    // BUI form fields commit their value on Enter (or when focus leaves).
    cx.simulate_key(win, "", "Return");
}

/// Focus a field, erase its contents with Backspace and type a new value.
fn replace_field(cx: &mut App, win: WindowId, id: &str, text: &str) {
    click(cx, win, id);
    for _ in 0..120 {
        cx.simulate_key(win, "", "BackSpace");
    }
    cx.simulate_key(win, "", "Return");
    type_into(cx, win, id, text);
}

fn save_png(cx: &mut App, win: WindowId, name: &str) {
    let (w, h, px) = cx.draw(win);
    let rgba: Vec<u8> = px
        .iter()
        .flat_map(|p| [(p >> 16) as u8, (p >> 8) as u8, *p as u8, 255])
        .collect();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/screenshots");
    std::fs::create_dir_all(&dir).unwrap();
    let file = std::fs::File::create(dir.join(name)).unwrap();
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()
        .unwrap()
        .write_image_data(&rgba)
        .unwrap();
}

#[test]
fn unlock_browse_search_and_save() {
    let db_path = stable_fixture("unlock");
    let db_str = db_path.display().to_string();
    let config = std::env::temp_dir().join("kpxc-bui-screens-unlock.json");

    Application::headless().run(|cx| {
        let mut app = BuiApp::with_config_path(config.clone());
        app.db_path = db_str.clone();
        app.password = "testpassword".into();
        let win = open_app(cx, app);
        cx.draw(win.id);
        cx.draw(win.id);

        // The unlock screen is real BUI: the button and fields have bounds.
        assert!(cx.element_bounds(win.id, "unlock").is_some());
        assert!(cx.element_bounds(win.id, "db-path").is_some());
        assert!(cx.element_bounds(win.id, "password").is_some());
        assert!(cx.element_bounds(win.id, "cr-secret").is_some());

        // Move focus off the first field: BUI blinks the caret, which would
        // make the screenshot depend on the clock.
        cx.simulate_click(win.id, 4.0, 4.0);
        cx.draw(win.id);
        save_png(cx, win.id, "bui_unlock.png");

        click(cx, win.id, "unlock");
        cx.draw(win.id);
        assert!(
            win.root().read(cx).db.is_some(),
            "unlock opened the database: {:?}",
            win.root().read(cx).unlock_error
        );

        // The sample entry is in the table, with a row element id.
        let entry_id = win
            .root()
            .read(cx)
            .db
            .as_ref()
            .unwrap()
            .iter_all_entries()
            .find(|e| e.get("Title") == Some("Sample Entry"))
            .map(|e| e.id())
            .expect("sample entry");
        let row_id = format!("entry-{entry_id}");
        assert!(cx.element_bounds(win.id, &row_id).is_some());

        // Click selects it and the details panel appears.
        click(cx, win.id, &row_id);
        cx.draw(win.id);
        assert_eq!(win.root().read(cx).selected_entry, Some(entry_id));
        assert!(cx.element_bounds(win.id, "details-title").is_some());
        assert!(cx.element_bounds(win.id, "copy-password").is_some());
        save_png(cx, win.id, "bui_details.png");

        // Search filters through the real input widget.
        type_into(cx, win.id, "search", "Sample");
        cx.draw(win.id);
        assert_eq!(win.root().read(cx).search, "Sample");
        assert_eq!(win.root().read(cx).rows().len(), 1, "search filtered to one row");

        // Save writes the database back; reopening proves it is valid.
        click(cx, win.id, "save");
        cx.draw(win.id);
        assert!(win.root().read(cx).status.starts_with("Saved"));
        let key = keepass::DatabaseKey::new().with_password("testpassword");
        let reopened = kpxc::saveutil::open(&db_path, key).expect("saved database reopens");
        assert!(reopened
            .iter_all_entries()
            .any(|e| e.get("Title") == Some("Sample Entry")));

        // Lock returns to the welcome screen.
        click(cx, win.id, "lock");
        cx.draw(win.id);
        assert!(win.root().read(cx).db.is_none());
        assert!(cx.element_bounds(win.id, "unlock").is_some());
    });
}

#[test]
fn edit_entry_through_bui_and_persist() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = fresh_sample(&dir);
    let config = dir.path().join("config.json");

    Application::headless().run(|cx| {
        let mut app = BuiApp::with_config_path(config.clone());
        app.db_path = db_path.display().to_string();
        app.password = "testpassword".into();
        let win = open_app(cx, app);
        cx.draw(win.id);
        click(cx, win.id, "unlock");
        cx.draw(win.id);

        let entry_id = win
            .root()
            .read(cx)
            .db
            .as_ref()
            .unwrap()
            .iter_all_entries()
            .next()
            .map(|e| e.id())
            .unwrap();
        click(cx, win.id, &format!("entry-{entry_id}"));
        cx.draw(win.id);
        click(cx, win.id, "edit-entry");
        cx.draw(win.id);
        assert!(matches!(
            win.root().read(cx).modal,
            Some(Modal::Entry(_))
        ));

        // Replace the title: focus, select all, type.
        replace_field(cx, win.id, "entry-title", "Renamed in BUI");
        click(cx, win.id, "entry-save");
        cx.draw(win.id);

        let app = win.root().read(cx);
        assert!(app.modal.is_none(), "editor closed");
        assert_eq!(app.details().unwrap().title, "Renamed in BUI");
        assert!(app.dirty);
        drop(app);

        // Save and reopen outside the GUI.
        click(cx, win.id, "save");
        cx.draw(win.id);
        let key = keepass::DatabaseKey::new().with_password("testpassword");
        let reopened = kpxc::saveutil::open(&db_path, key).unwrap();
        let entry = reopened.entry(entry_id).expect("entry still exists");
        assert_eq!(entry.get("Title"), Some("Renamed in BUI"));
        assert!(reopened.entry(entry_id).unwrap().historical(0).is_some());
    });
}

#[test]
fn columns_dialog_hides_and_reorders() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = fresh_sample(&dir);
    let config = dir.path().join("config.json");

    Application::headless().run(|cx| {
        let mut app = BuiApp::with_config_path(config.clone());
        app.db_path = db_path.display().to_string();
        app.password = "testpassword".into();
        let win = open_app(cx, app);
        cx.draw(win.id);
        click(cx, win.id, "unlock");
        cx.draw(win.id);

        // All headers exist initially.
        for label in ["Title", "UserName", "Password", "URL", "Notes", "Tags"] {
            assert!(
                cx.element_bounds(win.id, &format!("hdr-{label}")).is_some(),
                "header {label}"
            );
        }

        // Hide URL through the BUI Columns dialog.
        click(cx, win.id, "columns");
        cx.draw(win.id);
        click(cx, win.id, "col-URL");
        cx.draw(win.id);
        click(cx, win.id, "columns-close");
        cx.draw(win.id);
        assert!(
            cx.element_bounds(win.id, "hdr-URL").is_none(),
            "URL header hidden"
        );
        let prefs = Preferences::load(&config);
        assert!(!prefs
            .columns
            .iter()
            .find(|c| c.id == ColumnId::Url)
            .unwrap()
            .visible);

        // Reorder UserName before Title.
        click(cx, win.id, "columns");
        cx.draw(win.id);
        click(cx, win.id, "col-up-UserName");
        cx.draw(win.id);
        click(cx, win.id, "columns-close");
        cx.draw(win.id);
        let user = cx.element_bounds(win.id, "hdr-UserName").unwrap();
        let title = cx.element_bounds(win.id, "hdr-Title").unwrap();
        assert!(
            user.origin.x < title.origin.x,
            "UserName before Title: {} < {}",
            user.origin.x,
            title.origin.x
        );
        let prefs = Preferences::load(&config);
        let user_pos = prefs
            .columns
            .iter()
            .position(|c| c.id == ColumnId::UserName)
            .unwrap();
        let title_pos = prefs
            .columns
            .iter()
            .position(|c| c.id == ColumnId::Title)
            .unwrap();
        assert!(user_pos < title_pos, "order persisted");
    });
}

#[test]
fn recent_databases_are_remembered_by_bui() {
    let db_path = stable_fixture("recent");
    let config = std::env::temp_dir().join("kpxc-bui-screens-recent.json");
    let _ = std::fs::remove_file(&config);

    Application::headless().run(|cx| {
        // First launch: unlock the database.
        let mut app = BuiApp::with_config_path(config.clone());
        app.db_path = db_path.display().to_string();
        app.password = "testpassword".into();
        let win = open_app(cx, app);
        cx.draw(win.id);
        click(cx, win.id, "unlock");
        cx.draw(win.id);
        assert!(win.root().read(cx).db.is_some());
        cx.close_window(win.id);

        // Second launch: the last database is prefilled and listed.
        let app = BuiApp::with_config_path(config.clone());
        let expected = std::fs::canonicalize(&db_path)
            .unwrap()
            .display()
            .to_string();
        assert_eq!(app.db_path, expected, "prefilled across launches");
        let win = open_app(cx, app);
        cx.draw(win.id);
        assert!(cx.element_bounds(win.id, "recent-0").is_some());
        let prefs = Preferences::load(&config);
        assert_eq!(prefs.last_db.as_deref(), Some(expected.as_str()));
        assert_eq!(prefs.recent, vec![expected]);
        save_png(cx, win.id, "bui_recent.png");
    });
}

#[test]
fn generator_and_new_database_dialogs() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("created-by-bui.kdbx");
    let config = dir.path().join("config.json");

    Application::headless().run(|cx| {
        let mut app = BuiApp::with_config_path(config);
        app.password = "new-password".into();
        app.db_path = db_path.display().to_string();
        let win = open_app(cx, app);
        cx.draw(win.id);

        // Generator modal produces a password.
        click(cx, win.id, "new-database");
        cx.draw(win.id);
        click(cx, win.id, "newdb-cancel");
        cx.draw(win.id);
        click(cx, win.id, "new-database");
        cx.draw(win.id);
        // Fill the create form through real BUI inputs.
        replace_field(cx, win.id, "newdb-path", &db_path.display().to_string());
        replace_field(cx, win.id, "newdb-name", "BUI Database");
        type_into(cx, win.id, "newdb-password", "pw");
        type_into(cx, win.id, "newdb-repeat", "pw");
        click(cx, win.id, "newdb-create");
        cx.draw(win.id);
        assert!(
            win.root().read(cx).db.is_some(),
            "new database created: {:?}",
            win.root().read(cx).status
        );
        let key = keepass::DatabaseKey::new().with_password("pw");
        let reopened = kpxc::saveutil::open(&db_path, key).expect("created DB reopens");
        assert_eq!(
            reopened.meta.database_name.as_deref(),
            Some("BUI Database")
        );

        // The generator modal opens and regenerates.
        click(cx, win.id, "generator");
        cx.draw(win.id);
        let first = match win.root().read(cx).modal {
            Some(Modal::Generator(ref d)) => d.value.clone(),
            _ => panic!("generator modal"),
        };
        assert_eq!(first.len(), 24);
        click(cx, win.id, "gen-regenerate");
        cx.draw(win.id);
        let second = match win.root().read(cx).modal {
            Some(Modal::Generator(ref d)) => d.value.clone(),
            _ => panic!("generator modal"),
        };
        assert_ne!(first, second);
        click(cx, win.id, "gen-close");
        cx.draw(win.id);
    });
}

#[test]
fn new_entry_and_delete_through_bui() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = fresh_sample(&dir);
    let config = dir.path().join("config.json");

    Application::headless().run(|cx| {
        let mut app = BuiApp::with_config_path(config);
        app.db_path = db_path.display().to_string();
        app.password = "testpassword".into();
        let win = open_app(cx, app);
        cx.draw(win.id);
        click(cx, win.id, "unlock");
        cx.draw(win.id);

        let before = win.root().read(cx).db.as_ref().unwrap().num_entries();

        // Create an entry with the real modal.
        click(cx, win.id, "new-entry");
        cx.draw(win.id);
        type_into(cx, win.id, "entry-title", "Created in BUI");
        type_into(cx, win.id, "entry-username", "bui-user");
        type_into(cx, win.id, "entry-password", "bui-secret");
        click(cx, win.id, "entry-save");
        cx.draw(win.id);
        let app = win.root().read(cx);
        assert_eq!(app.db.as_ref().unwrap().num_entries(), before + 1);
        assert_eq!(app.selected_entry.is_some(), true);
        let created = app.details().unwrap();
        assert_eq!(created.title, "Created in BUI");
        assert_eq!(created.username, "bui-user");
        assert_eq!(created.password, "bui-secret");
        drop(app);

        // Delete it (moves to the recycle bin).
        click(cx, win.id, "delete-entry");
        cx.draw(win.id);
        assert!(matches!(
            win.root().read(cx).modal,
            Some(Modal::ConfirmDeleteEntry(_))
        ));
        click(cx, win.id, "confirm-delete");
        cx.draw(win.id);
        let app = win.root().read(cx);
        // The entry still exists — in the recycle bin (KeePassXC semantics).
        assert_eq!(app.db.as_ref().unwrap().num_entries(), before + 1);
        assert!(app
            .db
            .as_ref()
            .unwrap()
            .recycle_bin()
            .unwrap()
            .entries()
            .any(|e| e.get("Title") == Some("Created in BUI")));
    });
}

#[test]
fn draft_apply_unit() {
    // The pure state layer works without a window.
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_sample(&dir);
    let key = keepass::DatabaseKey::new().with_password("testpassword");
    let mut db = kpxc::saveutil::open(&path, key).unwrap();
    let group = db.root().id();
    let mut draft = EntryDraft::new(group);
    draft.title = "Unit Entry".into();
    draft.password = "secret".into();
    let message = draft.apply(&mut db);
    assert!(message.starts_with("Added entry"));
    assert!(db
        .iter_all_entries()
        .any(|e| e.get("Title") == Some("Unit Entry")));
}

