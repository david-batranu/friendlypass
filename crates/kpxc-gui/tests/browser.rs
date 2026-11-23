//! Browser-integration GUI test: start/stop serving from the window, and
//! the served socket answers the protocol (deep protocol verification with
//! the REAL keepassxc-proxy lives in kpxc-browser/tests/e2e_proxy.rs).

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use keepass::DatabaseKey;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name)
}

#[test]
fn browser_window_serves_the_protocol() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &db_path).unwrap();

    let socket = kpxc_browser::browser_server_path();
    let _ = std::fs::remove_file(&socket);

    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = db_path.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| kpxc_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 720.0));
    harness.run();

    // Open the Browser Integration window and start serving.
    harness.get_by_label("More…").click();
    harness.run();
    harness.get_by_label("Browser…").click();
    harness.run();
    harness.get_by_label("Start serving").click();
    harness.run();

    assert!(socket.exists(), "browser protocol socket created");
    let state = harness.state();
    assert!(state.browser_handle.is_some());
    assert!(state.status.contains("Browser protocol serving on"));

    // The served snapshot contains the database entries.
    {
        let served = state.browser_state.as_ref().unwrap().lock().unwrap();
        assert_eq!(served.entries.len(), 2, "both entries served");
        assert!(
            served.entries.iter().any(|e| e.title == "Sample Entry"),
            "Sample Entry is servable"
        );
        assert!(!served.db_hash.is_empty(), "database hash computed");
    }

    // Stop serving: the socket is cleaned up.
    harness.get_by_label("Stop serving").click();
    harness.run();
    assert!(!socket.exists(), "socket removed on stop");
    assert_eq!(harness.state().status, "Browser integration stopped");
}
