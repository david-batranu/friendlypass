//! Native-messaging manifest installation, shared by the GUI and the host
//! binary.
//!
//! Chrome-family browsers and Firefox discover a native host through a small
//! JSON manifest in a per-user directory. This module is the single
//! implementation that writes and removes `org.friendlypass.browser.json` for
//! every supported browser on macOS and Linux:
//!
//! * the GUI calls it when the Browser Integration settings change and on
//!   startup (so a moved/updated app rewrites a stale `path`);
//! * `friendlypass-browser-host --install/--uninstall` exposes it on the
//!   command line, which is what `installer/install.sh` delegates to.
//!
//! Only this host's own manifest is ever written or removed. A browser's
//! `NativeMessagingHosts` directory may contain manifests for other hosts;
//! those are left untouched.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// The host name the extension passes to `chrome.runtime.connectNative()`.
pub const HOST_NAME: &str = "org.friendlypass.browser";
/// Human-readable description written into every manifest.
pub const HOST_DESCRIPTION: &str = "friendlypass browser integration host";
/// File name of `friendlypass-browser-host` next to the GUI executable.
pub const HOST_BINARY_NAME: &str = "friendlypass-browser-host";

/// Chrome extension id derived from the RSA public key pinned in
/// `extension/src/manifest.json`. See `installer/README.md` to recompute it.
pub const DEFAULT_CHROME_EXTENSION_ID: &str = "pfdmagadklmhbghfipamhfbphcljdkbi";
/// Firefox add-on id (`browser_specific_settings.gecko.id`).
pub const DEFAULT_FIREFOX_EXTENSION_ID: &str = "friendlypass@friendlypass.org";

/// A browser whose native-messaging directory we know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Browser {
    Chrome,
    Chromium,
    Brave,
    Edge,
    Firefox,
}

impl Browser {
    /// Every supported browser, in the order the settings UI lists them.
    pub const ALL: [Browser; 5] = [
        Browser::Chrome,
        Browser::Chromium,
        Browser::Brave,
        Browser::Edge,
        Browser::Firefox,
    ];

    /// Stable lowercase identifier used on the command line.
    pub fn id(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Chromium => "chromium",
            Browser::Brave => "brave",
            Browser::Edge => "edge",
            Browser::Firefox => "firefox",
        }
    }

    /// Name shown in the settings UI.
    pub fn label(self) -> &'static str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Chromium => "Chromium",
            Browser::Brave => "Brave",
            Browser::Edge => "Edge",
            Browser::Firefox => "Firefox",
        }
    }

    /// Parse a command-line identifier (`chrome`, `firefox`, …).
    pub fn from_id(id: &str) -> Option<Browser> {
        Browser::ALL.into_iter().find(|browser| browser.id() == id)
    }

    /// Firefox uses `allowed_extensions` instead of `allowed_origins`.
    pub fn is_firefox(self) -> bool {
        matches!(self, Browser::Firefox)
    }
}

/// The platform layout used for manifest paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
}

impl Platform {
    /// The platform this binary runs on, or `None` elsewhere (Windows is not
    /// a supported browser-integration target yet).
    pub fn current() -> Option<Platform> {
        if cfg!(target_os = "macos") {
            Some(Platform::MacOs)
        } else if cfg!(target_os = "linux") {
            Some(Platform::Linux)
        } else {
            None
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Platform::MacOs => "macos",
            Platform::Linux => "linux",
        }
    }

    pub fn from_id(id: &str) -> Option<Platform> {
        match id {
            "macos" => Some(Platform::MacOs),
            "linux" => Some(Platform::Linux),
            _ => None,
        }
    }

    /// `$HOME`-relative directory holding `<host>.json` for `browser`.
    pub fn manifest_dir(self, browser: Browser) -> &'static str {
        match (self, browser) {
            (Platform::MacOs, Browser::Chrome) => {
                "Library/Application Support/Google/Chrome/NativeMessagingHosts"
            }
            (Platform::MacOs, Browser::Chromium) => {
                "Library/Application Support/Chromium/NativeMessagingHosts"
            }
            (Platform::MacOs, Browser::Brave) => {
                "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
            }
            (Platform::MacOs, Browser::Edge) => {
                "Library/Application Support/Microsoft Edge/NativeMessagingHosts"
            }
            (Platform::MacOs, Browser::Firefox) => {
                "Library/Application Support/Mozilla/NativeMessagingHosts"
            }
            (Platform::Linux, Browser::Chrome) => ".config/google-chrome/NativeMessagingHosts",
            (Platform::Linux, Browser::Chromium) => ".config/chromium/NativeMessagingHosts",
            (Platform::Linux, Browser::Brave) => {
                ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
            }
            (Platform::Linux, Browser::Edge) => ".config/microsoft-edge/NativeMessagingHosts",
            (Platform::Linux, Browser::Firefox) => ".mozilla/native-messaging-hosts",
        }
    }
}

/// Everything needed to install or remove the manifests.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// The `$HOME` whose browser configuration directories are used.
    pub home: PathBuf,
    pub platform: Platform,
    /// The host binary to register. Made absolute (and symlink-resolved)
    /// before it is written into a manifest.
    pub host_path: PathBuf,
    pub chrome_extension_id: String,
    pub firefox_extension_id: String,
    pub browsers: Vec<Browser>,
    /// Report what would change without touching the filesystem.
    pub dry_run: bool,
}

impl InstallOptions {
    /// Options with the pinned extension ids and every browser selected.
    pub fn new(
        home: impl Into<PathBuf>,
        platform: Platform,
        host_path: impl Into<PathBuf>,
    ) -> Self {
        InstallOptions {
            home: home.into(),
            platform,
            host_path: host_path.into(),
            chrome_extension_id: DEFAULT_CHROME_EXTENSION_ID.to_owned(),
            firefox_extension_id: DEFAULT_FIREFOX_EXTENSION_ID.to_owned(),
            browsers: Browser::ALL.to_vec(),
            dry_run: false,
        }
    }

    /// Absolute path of the manifest for `browser`.
    pub fn manifest_path(&self, browser: Browser) -> PathBuf {
        self.home
            .join(self.platform.manifest_dir(browser))
            .join(format!("{HOST_NAME}.json"))
    }
}

/// What [`install`] or [`uninstall`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InstallReport {
    /// Manifests written (or, in a dry run, that would be written).
    pub changed: Vec<PathBuf>,
    /// Manifests that already had the desired contents.
    pub unchanged: Vec<PathBuf>,
    /// Manifests removed (or, in a dry run, that would be removed).
    pub removed: Vec<PathBuf>,
    /// Manifests that were already absent.
    pub absent: Vec<PathBuf>,
}

impl InstallReport {
    pub fn is_noop(&self) -> bool {
        self.changed.is_empty() && self.removed.is_empty()
    }
}

/// A Chrome-family extension id is 32 characters in the range `a`–`p`.
pub fn validate_chrome_extension_id(id: &str) -> Result<()> {
    if id.len() != 32 || !id.bytes().all(|byte| (b'a'..=b'p').contains(&byte)) {
        bail!("extension id must be 32 characters in the range a-p, got: {id}");
    }
    Ok(())
}

/// A Firefox add-on id is any non-empty, control-character-free string.
pub fn validate_firefox_extension_id(id: &str) -> Result<()> {
    if id.trim().is_empty() {
        bail!("Firefox extension id must not be empty");
    }
    if id.chars().any(|ch| ch.is_control()) {
        bail!("Firefox extension id contains control characters");
    }
    Ok(())
}

/// The exact manifest text for `browser`.
pub fn manifest_json(
    browser: Browser,
    host_path: &Path,
    chrome_extension_id: &str,
    firefox_extension_id: &str,
) -> String {
    let mut map = serde_json::Map::new();
    map.insert("name".into(), serde_json::Value::from(HOST_NAME));
    map.insert(
        "description".into(),
        serde_json::Value::from(HOST_DESCRIPTION),
    );
    map.insert(
        "path".into(),
        serde_json::Value::from(host_path.to_string_lossy().into_owned()),
    );
    map.insert("type".into(), serde_json::Value::from("stdio"));
    if browser.is_firefox() {
        map.insert(
            "allowed_extensions".into(),
            serde_json::json!([firefox_extension_id]),
        );
    } else {
        map.insert(
            "allowed_origins".into(),
            serde_json::json!([format!("chrome-extension://{chrome_extension_id}/")]),
        );
    }
    let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(map))
        .expect("manifest is serialisable");
    text.push('\n');
    text
}

/// Resolve and validate the host binary path that goes into the manifest.
fn resolve_host_binary(path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("host binary does not exist: {}", path.display()))?;
    if !path.is_file() {
        bail!("host binary does not exist: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .with_context(|| format!("cannot stat host binary: {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            bail!("host binary is not executable: {}", path.display());
        }
    }
    Ok(path)
}

/// Validate common preconditions, returning the canonical host path.
fn prepare(opts: &InstallOptions, need_host: bool) -> Result<Option<PathBuf>> {
    if !opts.home.is_dir() {
        bail!("home directory does not exist: {}", opts.home.display());
    }
    if need_host {
        let host = resolve_host_binary(&opts.host_path)?;
        Ok(Some(host))
    } else {
        Ok(None)
    }
}

/// Write (or refresh) the manifests in `opts.browsers`.
///
/// Idempotent: a manifest whose bytes already match is left alone. All
/// directories are created as needed, but nothing else in them is touched.
pub fn install(opts: &InstallOptions) -> Result<InstallReport> {
    if opts.browsers.is_empty() {
        bail!("no browsers selected");
    }
    validate_chrome_extension_id(&opts.chrome_extension_id)?;
    validate_firefox_extension_id(&opts.firefox_extension_id)?;
    let host = prepare(opts, true)?.expect("host path requested");

    let mut report = InstallReport::default();
    for &browser in &opts.browsers {
        let path = opts.manifest_path(browser);
        let contents = manifest_json(
            browser,
            &host,
            &opts.chrome_extension_id,
            &opts.firefox_extension_id,
        );
        let current = std::fs::read_to_string(&path).ok();
        if current.as_deref() == Some(contents.as_str()) {
            report.unchanged.push(path);
            continue;
        }
        if opts.dry_run {
            report.changed.push(path);
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        write_atomic(&path, contents.as_bytes())
            .with_context(|| format!("cannot write {}", path.display()))?;
        report.changed.push(path);
    }
    Ok(report)
}

/// Remove this host's manifest for every browser in `opts.browsers`.
///
/// Missing files are reported in [`InstallReport::absent`] and are not an
/// error, so repeated uninstalls (and per-browser toggles) are safe.
pub fn uninstall(opts: &InstallOptions) -> Result<InstallReport> {
    prepare(opts, false)?;
    let mut report = InstallReport::default();
    for &browser in &opts.browsers {
        let path = opts.manifest_path(browser);
        if !path.exists() {
            report.absent.push(path);
            continue;
        }
        if !opts.dry_run {
            std::fs::remove_file(&path)
                .with_context(|| format!("cannot remove {}", path.display()))?;
        }
        report.removed.push(path);
    }
    Ok(report)
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The host binary that sits next to `exe` (the GUI or the host itself).
///
/// The macOS bundle keeps both binaries in `Contents/MacOS`; a development
/// build keeps both in `target/<profile>`.
pub fn host_path_for_exe(exe: &Path) -> PathBuf {
    match exe.parent() {
        Some(dir) => dir.join(HOST_BINARY_NAME),
        None => PathBuf::from(HOST_BINARY_NAME),
    }
}

/// Locate `friendlypass-browser-host` for the running process.
///
/// First the sibling of the current executable (the app bundle and
/// `target/<profile>` layouts), then `target/{debug,release}/` in the current
/// directory or one of its ancestors (running the GUI through `cargo run`
/// keeps the sibling in `target/<profile>`, so this is only a safety net).
pub fn resolve_host_path() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = host_path_for_exe(&exe);
        if sibling.is_file() {
            return Some(sibling);
        }
    }
    let cwd = std::env::current_dir().ok()?;
    for ancestor in cwd.ancestors() {
        for profile in ["debug", "release"] {
            let candidate = ancestor.join("target").join(profile).join(HOST_BINARY_NAME);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_ids_round_trip() {
        for browser in Browser::ALL {
            assert_eq!(Browser::from_id(browser.id()), Some(browser));
            assert!(!browser.label().is_empty());
        }
        assert_eq!(Browser::from_id("netscape"), None);
    }

    #[test]
    fn manifest_dirs_match_the_documented_layout() {
        assert_eq!(
            Platform::MacOs.manifest_dir(Browser::Chrome),
            "Library/Application Support/Google/Chrome/NativeMessagingHosts"
        );
        assert_eq!(
            Platform::Linux.manifest_dir(Browser::Firefox),
            ".mozilla/native-messaging-hosts"
        );
    }

    #[test]
    fn chrome_ids_are_validated() {
        assert!(validate_chrome_extension_id(DEFAULT_CHROME_EXTENSION_ID).is_ok());
        assert!(validate_chrome_extension_id("abcdefghijklmnopabcdefghijklmnop").is_ok());
        assert!(validate_chrome_extension_id("not-an-id").is_err());
        assert!(validate_chrome_extension_id("abcdefghijklmnopabcdefghijklmnoq").is_err());
    }

    #[test]
    fn manifest_json_carries_the_right_permissions() {
        let host =
            Path::new("/Applications/friendlypass.app/Contents/MacOS/friendlypass-browser-host");
        let chrome = manifest_json(
            Browser::Chrome,
            host,
            "abcdefghijklmnopabcdefghijklmnop",
            "ff@test",
        );
        let value: serde_json::Value = serde_json::from_str(&chrome).unwrap();
        assert_eq!(value["name"], HOST_NAME);
        assert_eq!(value["type"], "stdio");
        assert_eq!(value["path"], host.to_string_lossy().as_ref());
        assert_eq!(
            value["allowed_origins"],
            serde_json::json!(["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"])
        );
        assert!(value.get("allowed_extensions").is_none());

        let firefox = manifest_json(Browser::Firefox, host, "ignored", "ff@test");
        let value: serde_json::Value = serde_json::from_str(&firefox).unwrap();
        assert_eq!(value["allowed_extensions"], serde_json::json!(["ff@test"]));
        assert!(value.get("allowed_origins").is_none());
    }

    #[test]
    fn host_path_is_a_sibling_of_the_executable() {
        assert_eq!(
            host_path_for_exe(Path::new(
                "/Applications/friendlypass.app/Contents/MacOS/friendlypass-gui"
            )),
            PathBuf::from(
                "/Applications/friendlypass.app/Contents/MacOS/friendlypass-browser-host"
            )
        );
        assert_eq!(
            host_path_for_exe(Path::new("/repo/target/debug/friendlypass-gui")),
            PathBuf::from("/repo/target/debug/friendlypass-browser-host")
        );
    }
}
