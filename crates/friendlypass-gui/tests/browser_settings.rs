//! Browser Integration settings: the native-messaging toggles write and remove
//! the per-browser manifests, and a startup refresh follows a moved host.
//!
//! The manifest layout itself is covered exhaustively (every browser on both
//! platforms) by `friendlypass-browser/tests/native_messaging_install.rs`; here
//! we test the GUI wiring with a temporary `$HOME`.

// Tests build an App with Default::default() and then override the fields that
// point at the temporary home/host.
#![allow(clippy::field_reassign_with_default)]

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use friendlypass_browser::native_messaging::{Browser, Platform, HOST_NAME};
use keepass::DatabaseKey;
use std::path::{Path, PathBuf};

fn sample_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

struct Fixture {
    dir: tempfile::TempDir,
    home: PathBuf,
    host: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let host = dir.path().join("bin").join("friendlypass-browser-host");
        std::fs::create_dir_all(host.parent().unwrap()).unwrap();
        std::fs::write(&host, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Fixture { dir, home, host }
    }

    fn manifest(&self, browser: Browser) -> PathBuf {
        self.home
            .join(Platform::Linux.manifest_dir(browser))
            .join(format!("{HOST_NAME}.json"))
    }
}

fn manifest_host(path: &Path) -> String {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("missing {}: {error}", path.display()));
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["path"].as_str().unwrap().to_owned()
}

#[test]
fn browser_settings_toggles_write_and_remove_manifests() {
    let fixture = Fixture::new();
    let db_path = fixture.dir.path().join("sample4.kdbx");
    std::fs::copy(sample_path("sample4.kdbx"), &db_path).unwrap();

    let home = fixture.home.clone();
    let host = fixture.host.clone();
    let path_str = db_path.display().to_string();
    let mut harness = Harness::new_eframe(move |_cc| {
        let key = DatabaseKey::new().with_password("testpassword");
        let mut app = friendlypass_gui::App::with_open_database(&path_str, key);
        app.browser_install_home = home.clone();
        app.browser_install_platform = Some(Platform::Linux);
        app.browser_install_host = Some(host.clone());
        app
    });
    harness.set_size(egui::Vec2::new(1150.0, 900.0));
    harness.run();

    harness.get_by_label("Settings and tools").click();
    harness.run();
    harness.get_by_label("Browser…").click();
    harness.run();

    assert!(!harness.state().prefs.browser_integration);
    assert!(
        !fixture.home.join(".config").exists(),
        "nothing is written before the user opts in"
    );

    // Enable integration: every selected browser gets a manifest.
    harness.get_by_label("Enable browser integration").click();
    harness.run();
    assert!(harness.state().prefs.browser_integration);
    for browser in Browser::ALL {
        assert!(
            fixture.manifest(browser).exists(),
            "{} manifest written",
            browser.label()
        );
    }
    assert_eq!(
        manifest_host(&fixture.manifest(Browser::Chrome)),
        std::fs::canonicalize(&fixture.host)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    );
    assert!(harness.state().status.contains("manifest(s) written"));
    let chrome: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture.manifest(Browser::Chrome)).unwrap())
            .unwrap();
    assert_eq!(
        chrome["allowed_origins"],
        serde_json::json!(["chrome-extension://pfdmagadklmhbghfipamhfbphcljdkbi/"])
    );

    // Deselecting one browser removes only that browser's manifest.
    harness.get_by_label("Brave").click();
    harness.run();
    assert!(!harness.state().prefs.browser_brave);
    assert!(!fixture.manifest(Browser::Brave).exists());
    assert!(fixture.manifest(Browser::Chrome).exists());
    assert!(fixture.manifest(Browser::Firefox).exists());

    // Turning integration off removes everything that is left.
    harness.get_by_label("Enable browser integration").click();
    harness.run();
    assert!(!harness.state().prefs.browser_integration);
    for browser in Browser::ALL {
        assert!(
            !fixture.manifest(browser).exists(),
            "{} manifest removed",
            browser.label()
        );
    }
    assert!(harness.state().status.contains("disabled"));

    // The underlying browser directories (which may hold other hosts) stay.
    assert!(fixture.home.join(".config/google-chrome").is_dir());
}

#[test]
fn unticking_every_browser_removes_the_manifests() {
    let fixture = Fixture::new();
    let mut app = friendlypass_gui::App::default();
    app.browser_install_home = fixture.home.clone();
    app.browser_install_platform = Some(Platform::Linux);
    app.browser_install_host = Some(fixture.host.clone());
    app.prefs.browser_integration = true;

    friendlypass_gui::browser_bridge::sync_native_messaging(&mut app);
    for browser in Browser::ALL {
        assert!(
            fixture.manifest(browser).exists(),
            "{} written",
            browser.label()
        );
    }

    for browser in Browser::ALL {
        app.prefs.set_browser_enabled(browser, false);
    }
    friendlypass_gui::browser_bridge::sync_native_messaging(&mut app);
    for browser in Browser::ALL {
        assert!(
            !fixture.manifest(browser).exists(),
            "{} removed when nothing is ticked",
            browser.label()
        );
    }
    assert!(app.status.contains("no browser"), "status: {}", app.status);
}

#[test]
fn startup_refresh_rewrites_a_stale_host_path() {
    let fixture = Fixture::new();
    let mut app = friendlypass_gui::App::default();
    let mut prefs = friendlypass_gui::config::Preferences::default();
    prefs.browser_integration = true;
    prefs.browser_chrome = true;
    prefs.browser_chromium = false;
    prefs.browser_brave = false;
    prefs.browser_edge = false;
    prefs.browser_firefox = false;
    app.prefs = prefs;
    app.browser_install_home = fixture.home.clone();
    app.browser_install_platform = Some(Platform::Linux);
    app.browser_install_host = Some(fixture.host.clone());

    friendlypass_gui::browser_bridge::refresh_native_messaging(&mut app);
    let chrome = fixture.manifest(Browser::Chrome);
    assert!(chrome.exists());
    assert_eq!(
        manifest_host(&chrome),
        std::fs::canonicalize(&fixture.host)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    );

    // The app moved: the next startup rewrites the manifest to the new path.
    let moved = fixture
        .dir
        .path()
        .join("moved")
        .join("friendlypass-browser-host");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::copy(&fixture.host, &moved).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    app.browser_install_host = Some(moved.clone());
    app.status = "Opened vault".into();
    friendlypass_gui::browser_bridge::refresh_native_messaging(&mut app);
    assert_eq!(
        manifest_host(&chrome),
        std::fs::canonicalize(&moved)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    );
    // A refresh does not replace the status message of a normal startup.
    assert_eq!(app.status, "Opened vault");
}
