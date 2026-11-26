//! Native-messaging manifest installation, shared by the GUI and the host
//! binary.
//!
//! Chrome-family browsers and Firefox discover a native host through a small
//! JSON manifest in a per-user directory. This module is the single
//! implementation that writes and removes `org.friendlypass.browser.json` for
//! every supported browser on macOS, Linux and Windows:
//!
//! * the GUI calls it when the Browser Integration settings change and on
//!   startup (so a moved/updated app rewrites a stale `path`);
//! * `friendlypass-browser-host --install/--uninstall` exposes it on the
//!   command line, which is what `installer/install.sh` delegates to;
//! * on Windows the manifest lives under `%LOCALAPPDATA%\friendlypass` and the
//!   browser is registered through its `HKCU\...\NativeMessagingHosts` key
//!   instead of a profile directory.
//!
//! Only this host's own manifest is ever written or removed. A browser's
//! `NativeMessagingHosts` directory may contain manifests for other hosts;
//! those are left untouched. A browser is only registered when its per-user
//! configuration root already exists (for example `~/.config/google-chrome`),
//! so selecting a browser that was never started cannot create junk
//! directories; `--force` is the explicit override.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// The host name the extension passes to `chrome.runtime.connectNative()`.
pub const HOST_NAME: &str = "org.friendlypass.browser";
/// Human-readable description written into every manifest.
pub const HOST_DESCRIPTION: &str = "friendlypass browser integration host";
/// File name of `friendlypass-browser-host` next to the GUI executable.
pub const HOST_BINARY_NAME: &str = "friendlypass-browser-host";

/// The host executable's actual file name on this platform.
pub fn host_binary_file_name() -> &'static str {
    if cfg!(windows) {
        "friendlypass-browser-host.exe"
    } else {
        HOST_BINARY_NAME
    }
}

/// The current user's home/profile directory (`$HOME`, or `%USERPROFILE%` on
/// Windows where `HOME` is normally unset).
pub fn user_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|home| !home.is_empty()))
        .map(std::path::PathBuf::from)
}

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
    Windows,
}

impl Platform {
    /// The platform this binary runs on, or `None` elsewhere.
    pub fn current() -> Option<Platform> {
        if cfg!(target_os = "macos") {
            Some(Platform::MacOs)
        } else if cfg!(target_os = "linux") {
            Some(Platform::Linux)
        } else if cfg!(windows) {
            Some(Platform::Windows)
        } else {
            None
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Platform::MacOs => "macos",
            Platform::Linux => "linux",
            Platform::Windows => "windows",
        }
    }

    pub fn from_id(id: &str) -> Option<Platform> {
        match id {
            "macos" => Some(Platform::MacOs),
            "linux" => Some(Platform::Linux),
            "windows" => Some(Platform::Windows),
            _ => None,
        }
    }

    /// `$HOME`-relative root of the browser's per-user configuration.
    ///
    /// A browser counts as installed only when this directory already exists.
    /// We never create it: a browser that was never started has no profile,
    /// and writing into a guessed path would leave junk directories behind.
    pub fn config_root(self, browser: Browser) -> &'static str {
        match (self, browser) {
            (Platform::MacOs, Browser::Chrome) => "Library/Application Support/Google/Chrome",
            (Platform::MacOs, Browser::Chromium) => "Library/Application Support/Chromium",
            (Platform::MacOs, Browser::Brave) => {
                "Library/Application Support/BraveSoftware/Brave-Browser"
            }
            (Platform::MacOs, Browser::Edge) => "Library/Application Support/Microsoft Edge",
            (Platform::MacOs, Browser::Firefox) => "Library/Application Support/Mozilla",
            (Platform::Linux, Browser::Chrome) => ".config/google-chrome",
            (Platform::Linux, Browser::Chromium) => ".config/chromium",
            (Platform::Linux, Browser::Brave) => ".config/BraveSoftware/Brave-Browser",
            (Platform::Linux, Browser::Edge) => ".config/microsoft-edge",
            (Platform::Linux, Browser::Firefox) => ".mozilla",
            (Platform::Windows, Browser::Chrome) => "AppData/Local/Google/Chrome/User Data",
            (Platform::Windows, Browser::Chromium) => "AppData/Local/Chromium/User Data",
            (Platform::Windows, Browser::Brave) => {
                "AppData/Local/BraveSoftware/Brave-Browser/User Data"
            }
            (Platform::Windows, Browser::Edge) => "AppData/Local/Microsoft/Edge/User Data",
            (Platform::Windows, Browser::Firefox) => "AppData/Roaming/Mozilla/Firefox",
        }
    }

    /// True when `browser` has a per-user configuration root under `home`.
    pub fn is_browser_installed(self, home: &Path, browser: Browser) -> bool {
        home.join(self.config_root(browser)).is_dir()
    }

    /// Every browser with an existing configuration root under `home`.
    pub fn installed_browsers(self, home: &Path) -> Vec<Browser> {
        Browser::ALL
            .into_iter()
            .filter(|&browser| self.is_browser_installed(home, browser))
            .collect()
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
            // On Windows the manifest lives under %LOCALAPPDATA%\friendlypass
            // and the browser's registry key points at it, so there is no
            // per-browser directory in the browser profile. One subdirectory
            // per browser keeps the Chrome and Firefox manifest variants
            // (allowed_origins vs allowed_extensions) separate.
            (Platform::Windows, Browser::Chrome) => "AppData/Local/friendlypass/chrome",
            (Platform::Windows, Browser::Chromium) => "AppData/Local/friendlypass/chromium",
            (Platform::Windows, Browser::Brave) => "AppData/Local/friendlypass/brave",
            (Platform::Windows, Browser::Edge) => "AppData/Local/friendlypass/edge",
            (Platform::Windows, Browser::Firefox) => "AppData/Local/friendlypass/firefox",
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
    /// Register a missing browser anyway (creates its configuration root).
    /// Without this, only browsers whose per-user config root already exists
    /// are touched.
    pub force: bool,
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
            force: false,
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
    /// Browsers with no per-user configuration root. Without `force`, no
    /// manifest is written for them (and no directory is created).
    pub skipped: Vec<Browser>,
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
    #[cfg(windows)]
    let path = strip_windows_verbatim_prefix(path);
    Ok(path)
}

/// `std::fs::canonicalize` returns a `\\?\` verbatim path on Windows. Browsers
/// hand the manifest's `path` to `CreateProcess`, which is happiest with a
/// normal drive/UNC path, so drop the extended-length prefix.
#[cfg(windows)]
fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path
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
/// A browser is installed when its per-user configuration root exists (for
/// example `~/.config/google-chrome`); missing roots are reported in
/// [`InstallReport::skipped`] and never created unless `force` is set.
/// Idempotent: a manifest whose bytes already match is left alone. Only the
/// `NativeMessagingHosts` directory below an existing root is created.
pub fn install(opts: &InstallOptions) -> Result<InstallReport> {
    if opts.browsers.is_empty() {
        bail!("no browsers selected");
    }
    validate_chrome_extension_id(&opts.chrome_extension_id)?;
    validate_firefox_extension_id(&opts.firefox_extension_id)?;
    let host = prepare(opts, true)?.expect("host path requested");

    let mut report = InstallReport::default();
    for &browser in &opts.browsers {
        let root = opts.home.join(opts.platform.config_root(browser));
        if !opts.force && !root.is_dir() {
            report.skipped.push(browser);
            continue;
        }
        let path = opts.manifest_path(browser);
        let contents = manifest_json(
            browser,
            &host,
            &opts.chrome_extension_id,
            &opts.firefox_extension_id,
        );
        let current = std::fs::read_to_string(&path).ok();
        let manifest_needs_write = current.as_deref() != Some(contents.as_str());
        let manifest_path = path.to_string_lossy().into_owned();
        // On Windows the browser finds the manifest through HKCU, so a stale
        // or missing value must be repaired even when the file is unchanged.
        let registry_needs_write = opts.platform == Platform::Windows
            && !opts.dry_run
            && registry_value(browser)?.as_deref() != Some(manifest_path.as_str());
        if !manifest_needs_write && !registry_needs_write {
            report.unchanged.push(path);
            continue;
        }
        if opts.dry_run {
            report.changed.push(path);
            continue;
        }
        if manifest_needs_write {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create {}", parent.display()))?;
            }
            write_atomic(&path, contents.as_bytes())
                .with_context(|| format!("cannot write {}", path.display()))?;
        }
        if opts.platform == Platform::Windows {
            set_registry_value(browser, &path)?;
        }
        report.changed.push(path);
    }
    Ok(report)
}

/// Remove this host's manifest and Windows registry key for every browser in
/// `opts.browsers`.
///
/// Missing files and keys are reported in [`InstallReport::absent`] and are
/// not an error, so repeated uninstalls (and per-browser toggles) are safe.
pub fn uninstall(opts: &InstallOptions) -> Result<InstallReport> {
    prepare(opts, false)?;
    let mut report = InstallReport::default();
    for &browser in &opts.browsers {
        let path = opts.manifest_path(browser);
        let had_file = path.exists();
        let had_registry = opts.platform == Platform::Windows
            && !opts.dry_run
            && registry_value(browser)?.is_some();
        if !had_file && !had_registry {
            report.absent.push(path);
            continue;
        }
        if !opts.dry_run {
            if opts.platform == Platform::Windows {
                remove_registry_value(browser)?;
            }
            if had_file {
                std::fs::remove_file(&path)
                    .with_context(|| format!("cannot remove {}", path.display()))?;
            }
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

/// The `HKCU` subkey a Windows browser reads to find our native host.
///
/// Chrome, Chromium, Brave and Edge use their vendor key with the host name
/// below `NativeMessagingHosts`; Firefox uses `Software\Mozilla`. The default
/// value of the key is the absolute path of the manifest.
pub fn registry_key(browser: Browser) -> &'static str {
    match browser {
        Browser::Chrome => r"Software\Google\Chrome\NativeMessagingHosts\org.friendlypass.browser",
        Browser::Chromium => r"Software\Chromium\NativeMessagingHosts\org.friendlypass.browser",
        Browser::Brave => {
            r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\org.friendlypass.browser"
        }
        Browser::Edge => r"Software\Microsoft\Edge\NativeMessagingHosts\org.friendlypass.browser",
        Browser::Firefox => r"Software\Mozilla\NativeMessagingHosts\org.friendlypass.browser",
    }
}

/// Read the manifest path a browser registry key currently points at.
#[cfg(windows)]
fn registry_value(browser: Browser) -> Result<Option<String>> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ};

    let key = wide(registry_key(browser));
    let mut buffer = [0u16; 32_768];
    let mut size = (buffer.len() * std::mem::size_of::<u16>()) as u32;
    let mut value_type = 0u32;
    // SAFETY: `buffer` is valid for `size` bytes and `key` is NUL-terminated.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            std::ptr::null(),
            RRF_RT_REG_SZ,
            &mut value_type,
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        bail!(
            "cannot read registry value HKCU\\{} ({status})",
            registry_key(browser)
        );
    }
    let units = (size as usize / std::mem::size_of::<u16>()).min(buffer.len());
    let text = String::from_utf16_lossy(&buffer[..units]);
    let text = text.trim_end_matches('\0').to_owned();
    Ok((!text.is_empty()).then_some(text))
}

#[cfg(not(windows))]
fn registry_value(_browser: Browser) -> Result<Option<String>> {
    Ok(None)
}

/// Point a browser's registry key at `manifest`.
#[cfg(windows)]
fn set_registry_value(browser: Browser, manifest: &Path) -> Result<()> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    let key_name = wide(registry_key(browser));
    let mut key = std::ptr::null_mut();
    // SAFETY: `key_name` is NUL-terminated and `key` is a valid output pointer.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_name.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        bail!(
            "cannot create registry key HKCU\\{} ({status})",
            registry_key(browser)
        );
    }
    let value = wide(manifest.as_os_str());
    let bytes = (value.len() * std::mem::size_of::<u16>()) as u32;
    // SAFETY: `value` is a NUL-terminated UTF-16 string valid for `bytes`
    // bytes, and `key` was just opened.
    let status = unsafe {
        RegSetValueExW(
            key,
            std::ptr::null(),
            0,
            REG_SZ,
            value.as_ptr().cast(),
            bytes,
        )
    };
    // SAFETY: `key` is owned by this function.
    unsafe {
        RegCloseKey(key);
    }
    if status != ERROR_SUCCESS {
        bail!(
            "cannot write registry value HKCU\\{} ({status})",
            registry_key(browser)
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_registry_value(_browser: Browser, _manifest: &Path) -> Result<()> {
    Ok(())
}

/// Remove our browser registry key (only this host's key, nothing else).
#[cfg(windows)]
fn remove_registry_value(browser: Browser) -> Result<()> {
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows_sys::Win32::System::Registry::{RegDeleteTreeW, HKEY_CURRENT_USER};

    let key_name = wide(registry_key(browser));
    // SAFETY: `key_name` is NUL-terminated.
    let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, key_name.as_ptr()) };
    // Deleting an absent key is exactly the "already uninstalled" case.
    if status != 0 && status != ERROR_FILE_NOT_FOUND {
        bail!(
            "cannot remove registry key HKCU\\{} ({status})",
            registry_key(browser)
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_registry_value(_browser: Browser) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// The host binary that sits next to `exe` (the GUI or the host itself).
///
/// The macOS bundle keeps both binaries in `Contents/MacOS`; a development
/// build keeps both in `target/<profile>`.
pub fn host_path_for_exe(exe: &Path) -> PathBuf {
    match exe.parent() {
        Some(dir) => dir.join(host_binary_file_name()),
        None => PathBuf::from(host_binary_file_name()),
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
            let candidate = ancestor
                .join("target")
                .join(profile)
                .join(host_binary_file_name());
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
        assert_eq!(
            Platform::MacOs.config_root(Browser::Brave),
            "Library/Application Support/BraveSoftware/Brave-Browser"
        );
        assert_eq!(Platform::Linux.config_root(Browser::Firefox), ".mozilla");
        assert_eq!(
            Platform::Linux.manifest_dir(Browser::Chrome),
            format!(
                "{}/NativeMessagingHosts",
                Platform::Linux.config_root(Browser::Chrome)
            )
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
        // Expected values are built with `join`, so the separator between the
        // directory and the file name is the platform's own (`\` on Windows).
        // The file name comes from `host_binary_file_name()`, which carries
        // `.exe` on Windows.
        let macos_dir = Path::new("/Applications/friendlypass.app/Contents/MacOS");
        assert_eq!(
            host_path_for_exe(&macos_dir.join("friendlypass-gui")),
            macos_dir.join(host_binary_file_name())
        );

        let debug_dir = Path::new("/repo/target/debug");
        assert_eq!(
            host_path_for_exe(&debug_dir.join("friendlypass-gui")),
            debug_dir.join(host_binary_file_name())
        );

        #[cfg(windows)]
        assert_eq!(host_binary_file_name(), "friendlypass-browser-host.exe");
        #[cfg(not(windows))]
        assert_eq!(host_binary_file_name(), "friendlypass-browser-host");
    }

    #[cfg(windows)]
    #[test]
    fn windows_registry_and_manifest_paths_per_browser() {
        assert_eq!(
            Platform::Windows.manifest_dir(Browser::Chrome),
            "AppData/Local/friendlypass/chrome"
        );
        assert_eq!(
            Platform::Windows.manifest_dir(Browser::Firefox),
            "AppData/Local/friendlypass/firefox"
        );
        assert_eq!(
            Platform::Windows.config_root(Browser::Chrome),
            "AppData/Local/Google/Chrome/User Data"
        );
        assert_eq!(
            Platform::Windows.config_root(Browser::Firefox),
            "AppData/Roaming/Mozilla/Firefox"
        );

        for browser in Browser::ALL {
            let key = registry_key(browser);
            assert!(key.starts_with("Software\\"), "{key}");
            assert!(
                key.ends_with(r"NativeMessagingHosts\org.friendlypass.browser"),
                "{key}"
            );
        }
        assert_eq!(
            registry_key(Browser::Chrome),
            r"Software\Google\Chrome\NativeMessagingHosts\org.friendlypass.browser"
        );
        assert_eq!(
            registry_key(Browser::Chromium),
            r"Software\Chromium\NativeMessagingHosts\org.friendlypass.browser"
        );
        assert_eq!(
            registry_key(Browser::Brave),
            r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\org.friendlypass.browser"
        );
        assert_eq!(
            registry_key(Browser::Edge),
            r"Software\Microsoft\Edge\NativeMessagingHosts\org.friendlypass.browser"
        );
        assert_eq!(
            registry_key(Browser::Firefox),
            r"Software\Mozilla\NativeMessagingHosts\org.friendlypass.browser"
        );

        let options = InstallOptions::new(
            r"C:\Users\alice",
            Platform::Windows,
            r"C:\Program Files\friendlypass\friendlypass-browser-host.exe",
        );
        assert_eq!(
            options.manifest_path(Browser::Chrome),
            PathBuf::from(
                r"C:\Users\alice\AppData\Local\friendlypass\chrome\org.friendlypass.browser.json"
            )
        );
        assert_eq!(
            host_path_for_exe(Path::new(
                r"C:\Program Files\friendlypass\friendlypass-gui.exe"
            )),
            PathBuf::from(r"C:\Program Files\friendlypass\friendlypass-browser-host.exe")
        );

        assert_eq!(
            strip_windows_verbatim_prefix(PathBuf::from(
                r"\\?\C:\Program Files\friendlypass\x.exe"
            )),
            PathBuf::from(r"C:\Program Files\friendlypass\x.exe")
        );
        assert_eq!(
            strip_windows_verbatim_prefix(PathBuf::from(r"\\?\UNC\server\share\x.exe")),
            PathBuf::from(r"\\server\share\x.exe")
        );
    }
}
