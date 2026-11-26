//! Native-messaging manifest installation: every browser × both platforms in a
//! throw-away `$HOME`. This is the shared implementation the GUI and
//! `installer/install.sh` (via `friendlypass-browser-host --install`) use.

use std::path::{Path, PathBuf};

use friendlypass_browser::native_messaging::{
    self, Browser, InstallOptions, Platform, DEFAULT_CHROME_EXTENSION_ID,
    DEFAULT_FIREFOX_EXTENSION_ID, HOST_NAME,
};

const CHROME_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
const FIREFOX_ID: &str = "friendlypass@test.invalid";

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
        let host = dir
            .path()
            .join("bin")
            .join(native_messaging::HOST_BINARY_NAME);
        std::fs::create_dir_all(host.parent().unwrap()).unwrap();
        std::fs::write(&host, "#!/bin/sh\nexit 0\n").unwrap();
        make_executable(&host);
        Fixture { dir, home, host }
    }

    fn options(&self, platform: Platform, browsers: Vec<Browser>) -> InstallOptions {
        let mut options = InstallOptions::new(&self.home, platform, &self.host);
        options.chrome_extension_id = CHROME_ID.into();
        options.firefox_extension_id = FIREFOX_ID.into();
        options.browsers = browsers;
        options
    }

    fn path(&self, platform: Platform, browser: Browser) -> PathBuf {
        self.home
            .join(platform.manifest_dir(browser))
            .join(format!("{HOST_NAME}.json"))
    }

    /// A browser is only registered when its per-user config root exists.
    fn install_roots(&self, platform: Platform, browsers: &[Browser]) {
        for &browser in browsers {
            std::fs::create_dir_all(self.home.join(platform.config_root(browser))).unwrap();
        }
    }
}

fn make_executable(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(_path, perms).unwrap();
    }
}

fn read_manifest(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("missing manifest {}: {error}", path.display()));
    serde_json::from_str(&text).expect("manifest is valid JSON")
}

/// The path a manifest should contain for `path`. On Windows
/// `std::fs::canonicalize` returns a `\\?\` verbatim path, while the installer
/// writes a normal drive/UNC path.
fn expected_manifest_path(path: &Path) -> String {
    let canonical = std::fs::canonicalize(path).expect("canonical path");
    let text = canonical.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
}

#[test]
fn installs_every_browser_on_macos_and_linux() {
    for platform in [Platform::MacOs, Platform::Linux] {
        let fixture = Fixture::new();
        fixture.install_roots(platform, &Browser::ALL);
        let options = fixture.options(platform, Browser::ALL.to_vec());
        let report = native_messaging::install(&options).unwrap();
        assert_eq!(report.changed.len(), Browser::ALL.len());
        assert!(report.skipped.is_empty());
        assert!(report.unchanged.is_empty());

        let host = expected_manifest_path(&fixture.host);
        for browser in Browser::ALL {
            let path = fixture.path(platform, browser);
            assert_eq!(path, options.manifest_path(browser));
            let value = read_manifest(&path);
            assert_eq!(value["name"], HOST_NAME);
            assert_eq!(value["type"], "stdio");
            assert_eq!(value["path"], host.as_str());
            assert!(value["description"].as_str().is_some_and(|d| !d.is_empty()));
            if browser == Browser::Firefox {
                assert_eq!(value["allowed_extensions"], serde_json::json!([FIREFOX_ID]));
                assert!(value.get("allowed_origins").is_none());
            } else {
                assert_eq!(
                    value["allowed_origins"],
                    serde_json::json!([format!("chrome-extension://{CHROME_ID}/")])
                );
                assert!(value.get("allowed_extensions").is_none());
            }
        }

        // Only this host's manifest exists in each directory.
        for browser in Browser::ALL {
            let dir = fixture.home.join(platform.manifest_dir(browser));
            let names: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(names, vec![format!("{HOST_NAME}.json")]);
        }
        drop(fixture.dir);
    }
}

#[test]
fn install_is_idempotent_and_unchanged_files_are_not_rewritten() {
    let fixture = Fixture::new();
    fixture.install_roots(Platform::Linux, &[Browser::Chrome]);
    let options = fixture.options(Platform::Linux, vec![Browser::Chrome]);

    let first = native_messaging::install(&options).unwrap();
    assert_eq!(first.changed.len(), 1);
    let path = fixture.path(Platform::Linux, Browser::Chrome);
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let contents = std::fs::read_to_string(&path).unwrap();

    let second = native_messaging::install(&options).unwrap();
    assert!(
        second.changed.is_empty(),
        "unchanged manifest is not rewritten"
    );
    assert_eq!(second.unchanged, vec![path.clone()]);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
    let after = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(
        before, after,
        "mtime must not move on an idempotent install"
    );
}

#[test]
fn a_changed_host_path_rewrites_the_manifest() {
    let fixture = Fixture::new();
    fixture.install_roots(Platform::MacOs, &[Browser::Chrome]);
    let options = fixture.options(Platform::MacOs, vec![Browser::Chrome]);
    let path = fixture.path(Platform::MacOs, Browser::Chrome);
    native_messaging::install(&options).unwrap();

    // The app moved (or was updated): the same browser now points elsewhere.
    let moved = fixture
        .dir
        .path()
        .join("moved")
        .join("friendlypass-browser-host");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::copy(&fixture.host, &moved).unwrap();
    make_executable(&moved);
    let mut moved_options = options.clone();
    moved_options.host_path = moved.clone();

    let report = native_messaging::install(&moved_options).unwrap();
    assert_eq!(report.changed, vec![path.clone()]);
    let value = read_manifest(&path);
    assert_eq!(value["path"], expected_manifest_path(&moved));
}

#[test]
fn uninstall_removes_only_our_manifest_and_is_repeatable() {
    let fixture = Fixture::new();
    fixture.install_roots(Platform::MacOs, &Browser::ALL);
    let options = fixture.options(Platform::MacOs, Browser::ALL.to_vec());

    // A different native host already lives in every browser directory.
    for browser in Browser::ALL {
        let dir = fixture.home.join(Platform::MacOs.manifest_dir(browser));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("com.example.other.json"), b"{\"name\":\"other\"}").unwrap();
    }

    native_messaging::install(&options).unwrap();
    let report = native_messaging::uninstall(&options).unwrap();
    assert_eq!(report.removed.len(), Browser::ALL.len());
    assert!(report.absent.is_empty());

    for browser in Browser::ALL {
        let dir = fixture.home.join(Platform::MacOs.manifest_dir(browser));
        assert!(!dir.join(format!("{HOST_NAME}.json")).exists());
        assert!(
            dir.join("com.example.other.json").exists(),
            "another host's manifest must survive"
        );
    }

    let again = native_messaging::uninstall(&options).unwrap();
    assert!(again.removed.is_empty());
    assert_eq!(again.absent.len(), Browser::ALL.len());
}

#[test]
fn uninstall_can_target_a_subset_of_browsers() {
    let fixture = Fixture::new();
    fixture.install_roots(Platform::Linux, &Browser::ALL);
    let all = fixture.options(Platform::Linux, Browser::ALL.to_vec());
    native_messaging::install(&all).unwrap();

    let chrome = fixture.options(Platform::Linux, vec![Browser::Chrome]);
    native_messaging::uninstall(&chrome).unwrap();
    assert!(!fixture.path(Platform::Linux, Browser::Chrome).exists());
    assert!(fixture.path(Platform::Linux, Browser::Firefox).exists());
}

#[test]
fn firefox_only_install_leaves_chrome_alone() {
    let fixture = Fixture::new();
    fixture.install_roots(Platform::Linux, &[Browser::Firefox]);
    let firefox = fixture.options(Platform::Linux, vec![Browser::Firefox]);
    native_messaging::install(&firefox).unwrap();
    assert!(fixture.path(Platform::Linux, Browser::Firefox).exists());
    assert!(!fixture.path(Platform::Linux, Browser::Chrome).exists());
}

#[test]
fn install_skips_browsers_without_a_config_root() {
    for platform in [Platform::MacOs, Platform::Linux] {
        let fixture = Fixture::new();
        fixture.install_roots(platform, &[Browser::Chrome, Browser::Firefox]);
        let options = fixture.options(platform, Browser::ALL.to_vec());

        let report = native_messaging::install(&options).unwrap();
        assert_eq!(
            report.changed,
            vec![
                fixture.path(platform, Browser::Chrome),
                fixture.path(platform, Browser::Firefox),
            ]
        );
        assert_eq!(
            report.skipped,
            vec![Browser::Chromium, Browser::Brave, Browser::Edge]
        );
        assert!(report.unchanged.is_empty());

        for browser in [Browser::Chromium, Browser::Brave, Browser::Edge] {
            assert!(
                !fixture.home.join(platform.config_root(browser)).exists(),
                "{} config root must not be created",
                browser.label()
            );
            assert!(!fixture.path(platform, browser).exists());
        }
        // The existing roots are untouched and only our manifest was added.
        assert!(fixture
            .home
            .join(platform.config_root(Browser::Chrome))
            .is_dir());
        drop(fixture.dir);
    }
}

#[test]
fn force_installs_missing_browsers_and_creates_their_roots() {
    let fixture = Fixture::new();
    let mut options = fixture.options(Platform::Linux, Browser::ALL.to_vec());
    options.force = true;

    let report = native_messaging::install(&options).unwrap();
    assert_eq!(report.changed.len(), Browser::ALL.len());
    assert!(report.skipped.is_empty());
    for browser in Browser::ALL {
        assert!(fixture
            .home
            .join(Platform::Linux.config_root(browser))
            .is_dir());
        assert!(fixture.path(Platform::Linux, browser).exists());
    }
}

#[test]
fn uninstall_removes_a_manifest_left_by_a_previous_version() {
    let fixture = Fixture::new();
    let options = fixture.options(Platform::Linux, vec![Browser::Chrome, Browser::Firefox]);
    // Manifests written by an older build, with no install options/root
    // detection involved: uninstall still finds and removes them.
    for browser in [Browser::Chrome, Browser::Firefox] {
        let dir = fixture.home.join(Platform::Linux.manifest_dir(browser));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{HOST_NAME}.json")),
            b"{\"name\":\"org.friendlypass.browser\"}",
        )
        .unwrap();
    }

    let report = native_messaging::uninstall(&options).unwrap();
    assert_eq!(report.removed.len(), 2);
    assert!(!fixture.path(Platform::Linux, Browser::Chrome).exists());
    assert!(!fixture.path(Platform::Linux, Browser::Firefox).exists());
}

#[test]
fn uninstall_with_no_browser_roots_is_a_harmless_noop() {
    let fixture = Fixture::new();
    let options = fixture.options(Platform::Linux, Browser::ALL.to_vec());
    let report = native_messaging::uninstall(&options).unwrap();
    assert!(report.removed.is_empty());
    assert_eq!(report.absent.len(), Browser::ALL.len());
    assert!(!fixture.home.join(".config").exists());
    assert!(!fixture.home.join(".mozilla").exists());
}

#[test]
fn dry_run_reports_changes_without_touching_the_filesystem() {
    let fixture = Fixture::new();
    fixture.install_roots(Platform::Linux, &Browser::ALL);
    let mut options = fixture.options(Platform::Linux, Browser::ALL.to_vec());
    options.dry_run = true;

    let report = native_messaging::install(&options).unwrap();
    assert_eq!(report.changed.len(), Browser::ALL.len());
    for browser in Browser::ALL {
        assert!(!fixture
            .home
            .join(Platform::Linux.manifest_dir(browser))
            .exists());
    }

    let uninstall = native_messaging::uninstall(&options).unwrap();
    assert!(uninstall.removed.is_empty());
    assert_eq!(uninstall.absent.len(), Browser::ALL.len());
}

#[test]
fn invalid_options_are_rejected() {
    let fixture = Fixture::new();

    let mut bad_id = fixture.options(Platform::Linux, vec![Browser::Chrome]);
    bad_id.chrome_extension_id = "not-an-id".into();
    let error = native_messaging::install(&bad_id).unwrap_err().to_string();
    assert!(error.contains("extension id"), "{error}");

    let mut empty_firefox = fixture.options(Platform::Linux, vec![Browser::Chrome]);
    empty_firefox.firefox_extension_id = String::new();
    assert!(native_messaging::install(&empty_firefox).is_err());

    let missing = fixture.options(Platform::Linux, vec![Browser::Chrome]);
    let mut missing = missing;
    missing.host_path = fixture.dir.path().join("does-not-exist");
    assert!(native_messaging::install(&missing).is_err());

    #[cfg(unix)]
    {
        let not_executable = fixture.dir.path().join("plain-host");
        std::fs::write(&not_executable, b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&not_executable, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut plain = fixture.options(Platform::Linux, vec![Browser::Chrome]);
        plain.host_path = not_executable;
        assert!(native_messaging::install(&plain).is_err());
    }

    let mut no_browsers = fixture.options(Platform::Linux, Vec::new());
    no_browsers.browsers.clear();
    assert!(native_messaging::install(&no_browsers).is_err());

    let mut missing_home = fixture.options(Platform::Linux, vec![Browser::Chrome]);
    missing_home.home = fixture.dir.path().join("no-such-home");
    assert!(native_messaging::install(&missing_home).is_err());
    assert!(native_messaging::uninstall(&missing_home).is_err());
}

#[test]
fn default_extension_ids_are_the_pinned_ones() {
    let fixture = Fixture::new();
    let options = InstallOptions::new(&fixture.home, Platform::Linux, &fixture.host);
    assert_eq!(options.chrome_extension_id, DEFAULT_CHROME_EXTENSION_ID);
    assert_eq!(options.firefox_extension_id, DEFAULT_FIREFOX_EXTENSION_ID);
    assert_eq!(options.browsers, Browser::ALL.to_vec());
}

#[test]
fn every_manifest_path_is_absolute_under_home() {
    let fixture = Fixture::new();
    for platform in [Platform::MacOs, Platform::Linux] {
        let options = fixture.options(platform, Browser::ALL.to_vec());
        for browser in Browser::ALL {
            let path = options.manifest_path(browser);
            assert!(path.starts_with(&fixture.home));
            let dir_name = path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_lowercase();
            assert!(dir_name.contains("messaging"), "{dir_name}");
            assert_eq!(
                path.file_name().unwrap().to_string_lossy(),
                format!("{HOST_NAME}.json")
            );
        }
    }
    // Firefox's Linux directory does not follow the Chrome naming.
    assert_eq!(
        Platform::Linux.manifest_dir(Browser::Firefox),
        ".mozilla/native-messaging-hosts"
    );
}
