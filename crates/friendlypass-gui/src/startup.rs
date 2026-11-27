//! Startup integration: auto-unlock secrets in the OS keychain and
//! "launch at login" (macOS LaunchAgent).
//!
//! The unlock material is never written to disk by the app. The operating
//! system keychain encrypts it at rest and controls access by code identity:
//! macOS Keychain, Windows Credential Manager, or the Secret Service on
//! Linux. The app asks the keychain for the last database's secret on
//! startup and rebuilds the KeePass key (password + key-file bytes +
//! challenge-response secret) from it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Keychain service name (one item per database path as the account).
pub const KEYCHAIN_SERVICE: &str = "org.friendlypass.friendlypass.auto-unlock";

/// The unlock material remembered for one database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSecret {
    pub password: String,
    /// Raw key-file bytes (so auto-unlock keeps working if the file moves).
    pub keyfile: Option<Vec<u8>>,
    pub keyfile_name: Option<String>,
    pub challenge_response: String,
}

impl StoredSecret {
    pub fn is_empty(&self) -> bool {
        self.password.is_empty()
            && self.keyfile.is_none()
            && self.challenge_response.is_empty()
    }
}

/// Stable keychain account name for a database path.
pub fn account_key(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.to_owned())
}

/// Where auto-unlock secrets live.
pub trait SecretStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<StoredSecret>>;
    fn set(&self, account: &str, secret: &StoredSecret) -> Result<()>;
    fn delete(&self, account: &str) -> Result<()>;
}

/// The platform keychain.
pub struct KeychainStore;

impl SecretStore for KeychainStore {
    fn get(&self, account: &str) -> Result<Option<StoredSecret>> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .context("unable to open the system keychain")?;
        match entry.get_password() {
            Ok(json) => Ok(Some(
                serde_json::from_str(&json).context("invalid auto-unlock secret in the keychain")?,
            )),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("unable to read the system keychain: {e}")),
        }
    }

    fn set(&self, account: &str, secret: &StoredSecret) -> Result<()> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .context("unable to open the system keychain")?;
        let json = serde_json::to_string(secret)?;
        entry
            .set_password(&json)
            .map_err(|e| anyhow::anyhow!("unable to store the auto-unlock key in the system keychain: {e}"))
    }

    fn delete(&self, account: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .context("unable to open the system keychain")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("unable to delete the stored unlock key: {e}")),
        }
    }
}

/// An in-memory store used by tests (never for real databases).
#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<HashMap<String, StoredSecret>>,
}

impl SecretStore for MemoryStore {
    fn get(&self, account: &str) -> Result<Option<StoredSecret>> {
        Ok(self.items.lock().unwrap().get(account).cloned())
    }

    fn set(&self, account: &str, secret: &StoredSecret) -> Result<()> {
        self.items
            .lock()
            .unwrap()
            .insert(account.to_owned(), secret.clone());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<()> {
        self.items.lock().unwrap().remove(account);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Launch at login
// ---------------------------------------------------------------------------

pub const LAUNCH_AGENT_LABEL: &str = "org.friendlypass.friendlypass";

/// Whether "launch at login" is implemented for this platform.
pub fn launch_at_login_supported() -> bool {
    true
}

pub fn launch_agent_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCH_AGENT_LABEL}.plist"))
    })
}

/// The arguments launchd should run. Inside a `.app` bundle we ask
/// LaunchServices to open the bundle; otherwise run the executable directly.
pub fn program_arguments(exe: &Path) -> Vec<String> {
    let bundle = exe
        .ancestors()
        .find(|p| p.extension().is_some_and(|ext| ext == "app"));
    match bundle {
        Some(bundle) => vec![
            "/usr/bin/open".to_owned(),
            "-a".to_owned(),
            bundle.display().to_string(),
        ],
        None => vec![exe.display().to_string()],
    }
}

/// Render the macOS LaunchAgent property list.
pub fn launch_agent_plist(args: &[String]) -> String {
    let mut arg_xml = String::new();
    for arg in args {
        arg_xml.push_str(&format!("\t\t<string>{}</string>\n", xml_escape(arg)));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LAUNCH_AGENT_LABEL}</string>
	<key>ProgramArguments</key>
	<array>
{arg_xml}	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
"#
    )
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(target_os = "macos")]
fn current_uid() -> Result<String> {
    let out = std::process::Command::new("id")
        .arg("-u")
        .output()
        .context("unable to determine the user id")?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Install/remove the per-user login item. Returns the path/registry key used.
pub fn set_launch_at_login(enabled: bool) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        set_macos_launch_at_login(enabled)
    }
    #[cfg(windows)]
    {
        set_windows_launch_at_login(enabled)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        set_linux_launch_at_login(enabled)
    }
}

#[cfg(target_os = "macos")]
fn set_macos_launch_at_login(enabled: bool) -> Result<PathBuf> {
    let path = launch_agent_path().context("no home directory")?;
    if !enabled {
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &format!("gui/{}", current_uid()?), &path.display().to_string()])
            .output();
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("unable to remove {}", path.display()))?;
        }
        return Ok(path);
    }

    let exe = std::env::current_exe().context("unable to find the executable")?;
    let plist = launch_agent_plist(&program_arguments(&exe));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("unable to create {}", parent.display()))?;
    }
    std::fs::write(&path, plist).with_context(|| format!("unable to write {}", path.display()))?;
    let uid = current_uid()?;
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}"), &path.display().to_string()])
        .output();
    let out = std::process::Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{uid}"), &path.display().to_string()])
        .output()
        .context("unable to run launchctl bootstrap")?;
    if !out.status.success() {
        anyhow::bail!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(path)
}

#[cfg(windows)]
fn windows_run_subkey() -> &'static str {
    r"Software\Microsoft\Windows\CurrentVersion\Run"
}

#[cfg(windows)]
fn windows_run_key() -> &'static str {
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn set_windows_launch_at_login(enabled: bool) -> Result<PathBuf> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    let subkey_w = to_wide(windows_run_subkey());
    let name_w = to_wide(crate::brand::NAME);

    if enabled {
        let exe = std::env::current_exe().context("unable to find the executable")?;
        let value = format!("\"{}\"", exe.display());
        let value_w = to_wide(&value);
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            anyhow::bail!("RegCreateKeyExW failed with error {status}");
        }
        let set_status = unsafe {
            let bytes = std::slice::from_raw_parts(
                value_w.as_ptr() as *const u8,
                value_w.len() * std::mem::size_of::<u16>(),
            );
            let res = RegSetValueExW(
                hkey,
                name_w.as_ptr(),
                0,
                REG_SZ,
                bytes.as_ptr(),
                bytes.len() as u32,
            );
            RegCloseKey(hkey);
            res
        };
        if set_status != ERROR_SUCCESS {
            anyhow::bail!("RegSetValueExW failed with error {set_status}");
        }
    } else {
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            )
        };
        if status == ERROR_SUCCESS {
            let del_status = unsafe {
                let res = RegDeleteValueW(hkey, name_w.as_ptr());
                RegCloseKey(hkey);
                res
            };
            // Ignore "not found": disabling an already disabled entry is fine.
            if del_status != ERROR_SUCCESS && del_status != ERROR_FILE_NOT_FOUND {
                anyhow::bail!("RegDeleteValueW failed with error {del_status}");
            }
        } else if status != ERROR_FILE_NOT_FOUND {
            anyhow::bail!("RegOpenKeyExW failed with error {status}");
        }
    }
    Ok(PathBuf::from(windows_run_key()))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_autostart_path() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(config.join(format!("autostart/{LAUNCH_AGENT_LABEL}.desktop")))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn set_linux_launch_at_login(enabled: bool) -> Result<PathBuf> {
    let path = linux_autostart_path().context("no config directory")?;
    if !enabled {
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("unable to remove {}", path.display()))?;
        }
        return Ok(path);
    }
    let exe = std::env::current_exe().context("unable to find the executable")?;
    let exec = exe.display().to_string().replace('"', "\\\"");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("unable to create {}", parent.display()))?;
    }
    std::fs::write(
        &path,
        format!(
            "[Desktop Entry]\nType=Application\nName={}\nExec=\"{exec}\" \nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            crate::brand::NAME
        ),
    )
    .with_context(|| format!("unable to write {}", path.display()))?;
    Ok(path)
}

pub fn launch_at_login_enabled() -> bool {
    #[cfg(target_os = "macos")]
    {
        return launch_agent_path().is_some_and(|p| p.exists());
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE,
        };

        let subkey_w = to_wide(windows_run_subkey());
        let name_w = to_wide(crate::brand::NAME);
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut hkey,
            )
        };
        if status != ERROR_SUCCESS {
            return false;
        }
        let exists = unsafe {
            let mut size = 0u32;
            let res = RegQueryValueExW(
                hkey,
                name_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            );
            RegCloseKey(hkey);
            res == ERROR_SUCCESS
        };
        return exists;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return linux_autostart_path().is_some_and(|p| p.exists());
    }
    #[allow(unreachable_code)]
    false
}

/// The auto-unlock secret store for this platform. On Windows,
/// `use_windows_file` selects the DPAPI-protected file (for accounts without
/// a login password) instead of Credential Manager.
pub fn platform_store(use_windows_file: bool) -> std::sync::Arc<dyn SecretStore> {
    #[cfg(windows)]
    {
        if use_windows_file {
            return std::sync::Arc::new(DpapiStore);
        }
    }
    let _ = use_windows_file;
    std::sync::Arc::new(KeychainStore)
}

// ---------------------------------------------------------------------------
// Windows: DPAPI-protected file fallback
// ---------------------------------------------------------------------------

/// Stores the secrets in `%APPDATA%\friendlypass-gui\auto-unlock.dpapi`, encrypted
/// with Windows DPAPI (user scope). This works when the account has no
/// Windows login password, where Credential Manager may be unavailable — but
/// it is correspondingly weaker: anything running as that user can ask DPAPI
/// to decrypt it.
#[cfg(windows)]
pub struct DpapiStore;

#[cfg(windows)]
impl DpapiStore {
    fn path() -> Result<PathBuf> {
        let config = crate::config::config_path().context("no config directory")?;
        let dir = config.parent().context("no config directory")?;
        Ok(dir.join("auto-unlock.dpapi"))
    }

    fn load(&self) -> Result<HashMap<String, StoredSecret>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(HashMap::new());
        }
        let encrypted = std::fs::read(&path)
            .with_context(|| format!("unable to read {}", path.display()))?;
        let plain = dpapi_unprotect(&encrypted)?;
        Ok(serde_json::from_slice(&plain).unwrap_or_default())
    }

    fn save(&self, items: &HashMap<String, StoredSecret>) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let plain = serde_json::to_vec(items)?;
        let encrypted = dpapi_protect(&plain)?;
        let tmp = path.with_extension("dpapi.tmp");
        std::fs::write(&tmp, encrypted)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

#[cfg(windows)]
impl SecretStore for DpapiStore {
    fn get(&self, account: &str) -> Result<Option<StoredSecret>> {
        Ok(self.load()?.get(account).cloned())
    }

    fn set(&self, account: &str, secret: &StoredSecret) -> Result<()> {
        let mut items = self.load()?;
        items.insert(account.to_owned(), secret.clone());
        self.save(&items)
    }

    fn delete(&self, account: &str) -> Result<()> {
        let mut items = self.load()?;
        items.remove(account);
        self.save(&items)
    }
}

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>> {
    dpapi(data, true)
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>> {
    dpapi(data, false)
}

#[cfg(windows)]
fn dpapi(data: &[u8], protect: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        anyhow::bail!("DPAPI failed: {}", std::io::Error::last_os_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
    };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_roundtrips_through_json() {
        let secret = StoredSecret {
            password: "pässword".into(),
            keyfile: Some(vec![0, 1, 2, 255]),
            keyfile_name: Some("id.keyx".into()),
            challenge_response: "0102".into(),
        };
        let json = serde_json::to_string(&secret).unwrap();
        let back: StoredSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(back, secret);
        assert!(!back.is_empty());
    }

    #[test]
    fn memory_store_roundtrips_and_deletes() {
        let store = MemoryStore::default();
        let secret = StoredSecret {
            password: "pw".into(),
            keyfile: None,
            keyfile_name: None,
            challenge_response: String::new(),
        };
        assert_eq!(store.get("/db.kdbx").unwrap(), None);
        store.set("/db.kdbx", &secret).unwrap();
        assert_eq!(store.get("/db.kdbx").unwrap(), Some(secret));
        store.delete("/db.kdbx").unwrap();
        assert_eq!(store.get("/db.kdbx").unwrap(), None);
    }

    #[test]
    fn bundle_uses_launchservices_open_arguments() {
        let args = program_arguments(Path::new(
            "/Applications/friendlypass.app/Contents/MacOS/friendlypass-gui",
        ));
        assert_eq!(
            args,
            vec![
                "/usr/bin/open",
                "-a",
                "/Applications/friendlypass.app"
            ]
        );
    }

    #[test]
    fn launch_agent_plist_has_run_at_load_and_escapes_args() {
        let plist = launch_agent_plist(&[
            "/usr/bin/open".into(),
            "-a".into(),
            "/Applications/A & B.app".into(),
        ]);
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains(LAUNCH_AGENT_LABEL));
        assert!(plist.contains("/Applications/A &amp; B.app"));
        assert!(plist.contains("<array>"));
    }

    #[test]
    fn non_bundle_uses_the_executable_directly() {
        let args = program_arguments(Path::new("/tmp/target/release/friendlypass-gui"));
        assert_eq!(args, vec!["/tmp/target/release/friendlypass-gui"]);
    }
}
