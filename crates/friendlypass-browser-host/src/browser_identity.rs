//! Which browser launched this host, and is it one we trust?
//!
//! The frozen pairing contract (§4) asks the host to identify its parent
//! process — the browser launches the native-messaging host directly — and to
//! report it in the `host-identify` frame. The app uses that claim, together
//! with its own verification that the socket peer is our host binary, to
//! auto-approve `associate`.
//!
//! Rules (contract §4):
//!
//! - macOS: the parent is *verified* iff its running code is validly signed
//!   (`SecCodeCheckValidity`) and carries one of the team IDs we know. The
//!   browser kind comes from the team ID; without a known team ID it comes from
//!   the executable name and `verified` stays false (Chromium, unsigned dev
//!   builds, …).
//! - Linux: the parent is *verified* iff `/proc/<pid>/exe` is owned by root, is
//!   not writable by group/other, lives under a system prefix and its file name
//!   is a known browser binary.
//! - Windows: the parent is *verified* iff `WinVerifyTrust` accepts its
//!   Authenticode signature and the signer's certificate subject is the vendor
//!   expected for the browser family (Google LLC, Microsoft Corporation,
//!   Brave Software, Mozilla Corporation). Chromium and unsigned builds are
//!   named from the image path but stay unverified.
//!
//! Verification is best effort and **never** fails the host: every error path
//! degrades to `kind: unknown` / `verified: false`. The split between pure
//! classification (team ID → kind, name → kind, Linux metadata → verdict) and
//! the OS calls keeps the rules unit-testable on any platform.
//!
//! The identity is computed once per process (see [`cached_identity`]) because
//! the parent of a native-messaging host cannot change while it runs.

use std::path::Path;
use std::sync::OnceLock;

use serde_json::{json, Value};

/// Browsers we recognise, matching the `kind` values of contract §2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserKind {
    Chrome,
    Chromium,
    Brave,
    Edge,
    Firefox,
    Unknown,
}

impl BrowserKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Chromium => "chromium",
            Self::Brave => "brave",
            Self::Edge => "edge",
            Self::Firefox => "firefox",
            Self::Unknown => "unknown",
        }
    }
}

/// What the host knows about its launcher. `executable`/`team_id` are `None`
/// when the OS call failed or the value does not apply (Linux has no team ID).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserIdentity {
    pub kind: BrowserKind,
    pub verified: bool,
    pub executable: Option<String>,
    pub team_id: Option<String>,
}

impl BrowserIdentity {
    /// The "nothing is known" identity; also the error fallback.
    pub fn unknown() -> Self {
        Self {
            kind: BrowserKind::Unknown,
            verified: false,
            executable: None,
            team_id: None,
        }
    }
}

/// Team IDs accepted as proof of a genuine browser build (contract §4).
#[cfg(any(target_os = "macos", test))]
pub const TEAM_GOOGLE: &str = "EQHXZ8M8AV";
#[cfg(any(target_os = "macos", test))]
pub const TEAM_MOZILLA: &str = "43AQ936H96";
#[cfg(any(target_os = "macos", test))]
pub const TEAM_BRAVE: &str = "KL8N8XSYF4";
#[cfg(any(target_os = "macos", test))]
pub const TEAM_MICROSOFT: &str = "UBF8T346G9";

/// The team identifiers accepted as proof of a genuine browser build.
#[cfg(target_os = "macos")]
pub const KNOWN_TEAMS: &[&str] = &[TEAM_GOOGLE, TEAM_MOZILLA, TEAM_BRAVE, TEAM_MICROSOFT];

/// Map an Apple team identifier to a browser kind. Exact match only: a
/// non-canonical spelling is a different value, not a friendly variant.
#[cfg(any(target_os = "macos", test))]
pub fn kind_from_team_id(team_id: &str) -> Option<BrowserKind> {
    match team_id {
        TEAM_GOOGLE => Some(BrowserKind::Chrome),
        TEAM_MOZILLA => Some(BrowserKind::Firefox),
        TEAM_BRAVE => Some(BrowserKind::Brave),
        TEAM_MICROSOFT => Some(BrowserKind::Edge),
        _ => None,
    }
}

/// Map an executable file name to a browser kind. Used when the signature is
/// unusable (Linux, unsigned Chromium builds) or the team ID is unknown.
pub fn kind_from_executable_name(name: &str) -> BrowserKind {
    let name = name.trim().to_ascii_lowercase();
    if name.contains("firefox") {
        BrowserKind::Firefox
    } else if name.contains("brave") {
        BrowserKind::Brave
    } else if name.contains("microsoft edge")
        || name.contains("msedge")
        || name.starts_with("microsoft-edge")
        || name == "edge"
    {
        BrowserKind::Edge
    } else if name.contains("chromium") {
        BrowserKind::Chromium
    } else if name.contains("chrome") {
        BrowserKind::Chrome
    } else {
        BrowserKind::Unknown
    }
}

/// `file_name` of an executable path, falling back to the whole path.
pub fn executable_name(executable: &str) -> &str {
    Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable)
}

/// macOS rule, pure: matched requirement + executable → identity.
///
/// `matched_team` is the team ID of the **code requirement that the running
/// process satisfied** (see the `platform` module), not a value read from the
/// code signature. Only such a match makes the identity verified; an
/// unrecognised value (which cannot come from our known-requirement loop, but
/// keeps the function total) still names the browser yet stays unverified.
#[cfg(any(target_os = "macos", test))]
pub fn classify_signed(matched_team: Option<&str>, executable: Option<&str>) -> BrowserIdentity {
    let matched_kind = matched_team.and_then(kind_from_team_id);
    let kind = matched_kind
        .or_else(|| {
            executable
                .map(executable_name)
                .map(kind_from_executable_name)
        })
        .unwrap_or(BrowserKind::Unknown);
    BrowserIdentity {
        kind,
        verified: matched_kind.is_some(),
        executable: executable.map(str::to_owned),
        team_id: matched_team.map(str::to_owned),
    }
}

/// Path prefixes where Linux distributions install browser binaries.
///
/// Compiled everywhere so the rules stay unit-testable off Linux; only the
/// Linux platform code uses them at runtime.
#[cfg(any(target_os = "linux", test))]
pub const LINUX_SYSTEM_PREFIXES: &[&str] = &["/usr", "/opt", "/snap", "/var/lib/flatpak"];

/// File names of known browser binaries on Linux (see above).
#[cfg(any(target_os = "linux", test))]
pub const LINUX_BROWSER_BINARIES: &[&str] = &[
    "chrome",
    "google-chrome",
    "google-chrome-stable",
    "google-chrome-beta",
    "chromium",
    "chromium-browser",
    "brave",
    "brave-browser",
    "microsoft-edge",
    "microsoft-edge-stable",
    "msedge",
    "firefox",
    "firefox-esr",
    "firefox-bin",
];

#[cfg(any(target_os = "linux", test))]
pub fn is_under_system_prefix(executable: &Path) -> bool {
    LINUX_SYSTEM_PREFIXES
        .iter()
        .any(|prefix| executable.starts_with(prefix))
}

#[cfg(any(target_os = "linux", test))]
pub fn is_known_linux_browser_binary(name: &str) -> bool {
    LINUX_BROWSER_BINARIES.contains(&name)
}

/// Linux rule, pure: ownership/permissions/path/name → trusted.
///
/// `uid` and `mode` come from the metadata of `/proc/<pid>/exe` (which follows
/// the symlink to the real binary). Group/other write bits (`0o022`) must be
/// clear, matching the contract's "not writable by group/other".
#[cfg(any(target_os = "linux", test))]
pub fn linux_parent_is_trusted(uid: u32, mode: u32, executable: &Path) -> bool {
    let Some(name) = executable.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    uid == 0
        && mode & 0o022 == 0
        && is_under_system_prefix(executable)
        && is_known_linux_browser_binary(name)
}

/// Linux rule, pure: executable path + trust verdict → identity.
#[cfg(any(target_os = "linux", test))]
pub fn classify_linux(executable: Option<&str>, trusted: bool) -> BrowserIdentity {
    let kind = executable
        .map(executable_name)
        .map(kind_from_executable_name)
        .unwrap_or(BrowserKind::Unknown);
    BrowserIdentity {
        kind,
        verified: trusted,
        executable: executable.map(str::to_owned),
        team_id: None,
    }
}

/// Windows vendor names accepted as proof of a genuine browser build.
#[cfg(windows)]
pub const VENDOR_GOOGLE: &str = "Google LLC";
#[cfg(windows)]
pub const VENDOR_MICROSOFT: &str = "Microsoft Corporation";
#[cfg(windows)]
pub const VENDOR_BRAVE: &str = "Brave Software";
#[cfg(windows)]
pub const VENDOR_MOZILLA: &str = "Mozilla Corporation";

/// The Authenticode signer expected for a browser family on Windows.
/// Chromium (open-source builds) has no single vendor, so it is never
/// signature-verified.
#[cfg(windows)]
pub fn expected_windows_vendor(kind: BrowserKind) -> Option<&'static str> {
    match kind {
        BrowserKind::Chrome => Some(VENDOR_GOOGLE),
        BrowserKind::Edge => Some(VENDOR_MICROSOFT),
        BrowserKind::Brave => Some(VENDOR_BRAVE),
        BrowserKind::Firefox => Some(VENDOR_MOZILLA),
        BrowserKind::Chromium | BrowserKind::Unknown => None,
    }
}

/// Windows rule, pure: executable path + Authenticode signer → identity.
///
/// `signature_vendor` is the signer certificate's simple display name after a
/// successful `WinVerifyTrust`. The browser is verified only when that vendor
/// is the one expected for the family named by the executable.
#[cfg(windows)]
pub fn classify_windows(
    executable: Option<&str>,
    signature_vendor: Option<&str>,
) -> BrowserIdentity {
    let kind = executable
        .map(executable_name)
        .map(kind_from_executable_name)
        .unwrap_or(BrowserKind::Unknown);
    let verified = match (expected_windows_vendor(kind), signature_vendor) {
        (Some(expected), Some(actual)) => actual
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase()),
        _ => false,
    };
    BrowserIdentity {
        kind,
        verified,
        executable: executable.map(str::to_owned),
        // Windows has no Apple team identifier; the contract allows null.
        team_id: None,
    }
}

/// Identify the parent process. Never panics, never blocks for long: every OS
/// failure degrades to [`BrowserIdentity::unknown`] or a name-only kind.
pub fn identify_parent() -> BrowserIdentity {
    #[cfg(unix)]
    let pid = unsafe { libc::getppid() };
    #[cfg(windows)]
    let pid = platform::parent_pid();
    #[cfg(not(any(unix, windows)))]
    let pid: i32 = -1;
    identify_process(pid)
}

/// Identify one running process. Exposed for tests (the test binary itself is
/// ad-hoc signed and must never verify) and used for the parent by
/// [`identify_parent`].
pub fn identify_process(pid: i32) -> BrowserIdentity {
    if pid <= 0 {
        return BrowserIdentity::unknown();
    }

    #[cfg(target_os = "macos")]
    {
        platform::identify(pid)
    }
    #[cfg(target_os = "linux")]
    {
        platform::identify(u32::try_from(pid).unwrap_or(0))
    }
    #[cfg(target_os = "windows")]
    {
        platform::identify(pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        BrowserIdentity::unknown()
    }
}

/// The process-wide identity, computed on first use. Startup calls this (from
/// `main`) so the cost is paid once and logged.
pub fn cached_identity() -> &'static BrowserIdentity {
    static CACHED: OnceLock<BrowserIdentity> = OnceLock::new();
    CACHED.get_or_init(identify_parent)
}

/// The `host-identify` frame of contract §2 (without the trailing newline; the
/// app socket carries raw objects).
pub fn identify_frame(identity: &BrowserIdentity) -> Value {
    json!({
        "action": "host-identify",
        "hostVersion": crate::dispatch::HOST_VERSION,
        "browser": {
            "kind": identity.kind.as_str(),
            "verified": identity.verified,
            "executable": identity.executable,
            "teamId": identity.team_id,
        }
    })
}

/// Cached serialised `host-identify` frame, ready to be written first on every
/// app-socket connection.
pub fn identify_frame_bytes() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        // Serialising this fixed shape cannot fail; the fallback keeps the
        // "identify first" rule even if it somehow did.
        serde_json::to_vec(&identify_frame(cached_identity()))
            .unwrap_or_else(|_| br#"{"action":"host-identify"}"#.to_vec())
    })
}

/// The additive `browser` object in `hello` / status pushes: `{kind, verified}`.
/// Deliberately smaller than the `host-identify` payload — the executable path
/// and team ID stay host↔app only.
pub fn summary_json() -> Value {
    let identity = cached_identity();
    json!({
        "kind": identity.kind.as_str(),
        "verified": identity.verified,
    })
}

/// Debug-level startup logging, enabled only with `FP_HOST_DEBUG` set. Host
/// diagnostics go to stderr and never include credentials; this is process
/// metadata only.
pub fn log_identity_debug(identity: &BrowserIdentity) {
    if std::env::var_os("FP_HOST_DEBUG").is_none() {
        return;
    }
    eprintln!(
        "friendlypass-browser-host: browser identity: kind={} verified={} executable={} team_id={}",
        identity.kind.as_str(),
        identity.verified,
        identity.executable.as_deref().unwrap_or("-"),
        identity.team_id.as_deref().unwrap_or("-"),
    );
}

#[cfg(target_os = "macos")]
mod platform {
    //! macOS: `proc_pidpath` + Security framework code signing.
    //!
    //! `SecCodeCopyGuestWithAttributes` with a NULL host asks the kernel (the
    //! code-signing root of trust) for the running code object of `pid`.
    //!
    //! Validation is done against an explicit, Apple-anchored requirement per
    //! known vendor — never by reading `kSecCodeInfoTeamIdentifier`. A team ID
    //! in the code directory is attacker-controlled: a self-signed binary can
    //! claim any OU. `anchor apple generic` forces the signature to chain to
    //! Apple, and `certificate leaf[subject.OU]` pins the vendor's certificate
    //! on that chain, so only a genuine vendor build can satisfy it.
    //!
    //! The browser kind comes from the requirement that matched; `teamId` in
    //! the identity is that same matched constant, not a value read back from
    //! the signature.

    use std::ffi::c_void;
    use std::ptr;

    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};

    use super::{classify_signed, BrowserIdentity, KNOWN_TEAMS};

    type SecCodeRef = CFTypeRef;
    type SecRequirementRef = CFTypeRef;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributePid: CFStringRef;

        fn SecCodeCopyGuestWithAttributes(
            host: SecCodeRef,
            attributes: CFDictionaryRef,
            flags: u32,
            code: *mut SecCodeRef,
        ) -> i32;
        fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: CFTypeRef) -> i32;
        fn SecRequirementCreateWithString(
            text: CFStringRef,
            flags: u32,
            requirement: *mut SecRequirementRef,
        ) -> i32;
    }

    pub fn identify(pid: i32) -> BrowserIdentity {
        let executable = executable_path(pid);
        let matched_team = matched_team(pid);
        classify_signed(matched_team, executable.as_deref())
    }

    /// Canonical path of the running process (`proc_pidpath`).
    fn executable_path(pid: i32) -> Option<String> {
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let length = unsafe {
            libc::proc_pidpath(
                pid,
                buffer.as_mut_ptr().cast::<c_void>(),
                buffer.len() as u32,
            )
        };
        if length <= 0 {
            return None;
        }
        buffer.truncate(length as usize);
        let path = String::from_utf8_lossy(&buffer).into_owned();
        (!path.is_empty()).then_some(path)
    }

    /// The first known vendor requirement satisfied by the running code.
    fn matched_team(pid: i32) -> Option<&'static str> {
        let code = guest_code(pid)?;
        KNOWN_TEAMS
            .iter()
            .copied()
            .find(|team| satisfies_requirement(&code, team))
    }

    /// `anchor apple generic and certificate leaf[subject.OU] = "<team>"` — the
    /// signature must chain to Apple and the leaf certificate must belong to
    /// `team`.
    fn satisfies_requirement(code: &CFType, team: &str) -> bool {
        let text = CFString::new(&format!(
            r#"anchor apple generic and certificate leaf[subject.OU] = "{team}""#
        ));
        let mut requirement: SecRequirementRef = ptr::null();
        let status = unsafe {
            SecRequirementCreateWithString(text.as_concrete_TypeRef(), 0, &mut requirement)
        };
        if status != 0 || requirement.is_null() {
            return false;
        }
        let requirement = unsafe { CFType::wrap_under_create_rule(requirement) };
        // kSecCSDefaultFlags; the requirement carries the security decision.
        unsafe { SecCodeCheckValidity(code.as_CFTypeRef(), 0, requirement.as_CFTypeRef()) == 0 }
    }

    fn guest_code(pid: i32) -> Option<CFType> {
        let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) };
        let attributes =
            CFDictionary::from_CFType_pairs(&[(key.as_CFType(), CFNumber::from(pid).as_CFType())]);
        let mut code: SecCodeRef = ptr::null();
        let status = unsafe {
            SecCodeCopyGuestWithAttributes(
                ptr::null(),
                attributes.as_concrete_TypeRef(),
                0,
                &mut code,
            )
        };
        if status != 0 || code.is_null() {
            return None;
        }
        Some(unsafe { CFType::wrap_under_create_rule(code) })
    }
}

#[cfg(target_os = "linux")]
mod platform {
    //! Linux: `/proc/<pid>/exe` + metadata of the real binary.

    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use super::{classify_linux, linux_parent_is_trusted, BrowserIdentity};

    pub fn identify(pid: u32) -> BrowserIdentity {
        // An empty pid would read `/proc//exe` (the current process); refuse.
        if pid == 0 {
            return BrowserIdentity::unknown();
        }
        let link = format!("/proc/{pid}/exe");
        // read_link resolves the magic symlink without needing the target to
        // be readable. A kernel thread has no exe at all.
        let Some(target) = std::fs::read_link(&link).ok() else {
            return BrowserIdentity::unknown();
        };
        // `/proc/<pid>/exe` gains a " (deleted)" suffix after an upgrade.
        let target = strip_deleted_suffix(&target);
        // Metadata of the proc link follows the symlink to the real file, so
        // ownership and mode are those of the binary, not of procfs.
        let trusted = std::fs::metadata(&link)
            .map(|metadata| linux_parent_is_trusted(metadata.uid(), metadata.mode(), &target))
            .unwrap_or(false);
        let executable = target.to_str();
        classify_linux(executable, trusted)
    }

    fn strip_deleted_suffix(path: &Path) -> std::path::PathBuf {
        let text = path.to_string_lossy();
        match text.strip_suffix(" (deleted)") {
            Some(trimmed) => std::path::PathBuf::from(trimmed),
            None => path.to_path_buf(),
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    //! Windows: Toolhelp parent pid + `QueryFullProcessImageNameW` +
    //! Authenticode (`WinVerifyTrust`) signer check.
    //!
    //! Unlike the macOS path, which pins a team ID in an Apple-anchored
    //! requirement, the Windows verdict is "the signature is valid and the
    //! signer's certificate subject is the vendor expected for this browser
    //! family". A self-signed binary cannot pass `WinVerifyTrust`; a valid
    //! but unrelated vendor is rejected by the expected-vendor comparison.

    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Cryptography::{
        CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{classify_windows, BrowserIdentity};

    pub fn identify(pid: i32) -> BrowserIdentity {
        let Some(pid) = u32::try_from(pid).ok().filter(|pid| *pid != 0) else {
            return BrowserIdentity::unknown();
        };
        let executable = executable_path(pid);
        let vendor = executable
            .as_deref()
            .and_then(|path| signature_vendor(Path::new(path)));
        classify_windows(executable.as_deref(), vendor.as_deref())
    }

    /// The parent pid of this process (the browser for a native-messaging
    /// host), from a Toolhelp process snapshot.
    pub fn parent_pid() -> i32 {
        let own = unsafe { GetCurrentProcessId() };
        // SAFETY: TH32CS_SNAPPROCESS takes no process handle and needs no
        // cleanup beyond CloseHandle.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return -1;
        }
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut parent = -1;
        // SAFETY: `entry` is valid and sized as required.
        let mut found = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while found {
            if entry.th32ProcessID == own {
                parent = i32::try_from(entry.th32ParentProcessID).unwrap_or(-1);
                break;
            }
            // SAFETY: `entry` remains valid for the next call.
            found = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        unsafe {
            CloseHandle(snapshot);
        }
        parent
    }

    /// Full image path of a running process.
    fn executable_path(pid: u32) -> Option<String> {
        // SAFETY: OpenProcess has no out-parameters and the pid is validated.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; 32_768];
        let mut length = buffer.len() as u32;
        // SAFETY: `buffer` is valid for `length` UTF-16 code units.
        let ok =
            unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) };
        unsafe {
            CloseHandle(process);
        }
        if ok == 0 || length == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buffer[..length as usize]);
        (!path.is_empty()).then_some(path)
    }

    /// The signer certificate's simple display name when `path` has a valid
    /// Authenticode signature; `None` otherwise.
    fn signature_vendor(path: &Path) -> Option<String> {
        let mut wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_mut_ptr(),
            hFile: std::ptr::null_mut(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `data` points at the file info for the duration of the
        // call; all pointers in the structure are valid.
        let status = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action as *mut _,
                &mut data as *mut WINTRUST_DATA as *mut c_void,
            )
        };
        let vendor = if status == 0 {
            signer_name(data.hWVTStateData)
        } else {
            None
        };
        // Free the provider state WinVerifyTrust allocated.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: closing the same state data is the documented cleanup.
        unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action as *mut _,
                &mut data as *mut WINTRUST_DATA as *mut c_void,
            );
        }
        vendor
    }

    /// Read the signer certificate's display name from the provider state.
    fn signer_name(state: HANDLE) -> Option<String> {
        if state.is_null() {
            return None;
        }
        // SAFETY: `state` came from a successful WinVerifyTrust.
        let provider = unsafe { WTHelperProvDataFromStateData(state) };
        if provider.is_null() {
            return None;
        }
        // SAFETY: the provider data owns the signer chain.
        let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
        if signer.is_null() {
            return None;
        }
        // SAFETY: the signer owns its certificate chain.
        let certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
        if certificate.is_null() {
            return None;
        }
        // SAFETY: `certificate` points at a provider cert whose `pCert` is a
        // valid CERT_CONTEXT on success.
        let context = unsafe { (*certificate).pCert };
        if context.is_null() {
            return None;
        }
        // SAFETY: the first call sizes the NUL-terminated display name.
        let needed = unsafe {
            CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            )
        };
        if needed <= 1 {
            return None;
        }
        let mut buffer = vec![0u16; needed as usize];
        // SAFETY: `buffer` is valid for `needed` UTF-16 code units.
        let written = unsafe {
            CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                buffer.as_mut_ptr(),
                needed,
            )
        };
        if written == 0 {
            return None;
        }
        let name = String::from_utf16_lossy(&buffer[..(written as usize - 1)]);
        (!name.is_empty()).then_some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_ids_map_to_browser_kinds() {
        assert_eq!(kind_from_team_id(TEAM_GOOGLE), Some(BrowserKind::Chrome));
        assert_eq!(kind_from_team_id("43AQ936H96"), Some(BrowserKind::Firefox));
        assert_eq!(kind_from_team_id("KL8N8XSYF4"), Some(BrowserKind::Brave));
        assert_eq!(kind_from_team_id("UBF8T346G9"), Some(BrowserKind::Edge));
        // Exact match only: no trimming, no case folding.
        assert_eq!(kind_from_team_id(" EQHXZ8M8AV "), None);
        assert_eq!(kind_from_team_id("eqhxz8m8av"), None);
        assert_eq!(kind_from_team_id(""), None);
        assert_eq!(kind_from_team_id("ABCDE12345"), None);
    }

    #[test]
    fn executable_names_map_to_browser_kinds() {
        assert_eq!(
            kind_from_executable_name("Google Chrome"),
            BrowserKind::Chrome
        );
        assert_eq!(kind_from_executable_name("Chromium"), BrowserKind::Chromium);
        assert_eq!(
            kind_from_executable_name("chrome_crashpad_handler"),
            BrowserKind::Chrome
        );
        assert_eq!(
            kind_from_executable_name("Brave Browser"),
            BrowserKind::Brave
        );
        assert_eq!(
            kind_from_executable_name("Microsoft Edge"),
            BrowserKind::Edge
        );
        assert_eq!(kind_from_executable_name("msedge"), BrowserKind::Edge);
        assert_eq!(kind_from_executable_name("firefox"), BrowserKind::Firefox);
        assert_eq!(
            kind_from_executable_name("firefox-esr"),
            BrowserKind::Firefox
        );
        assert_eq!(kind_from_executable_name("FIREFOX"), BrowserKind::Firefox);
        assert_eq!(kind_from_executable_name("Safari"), BrowserKind::Unknown);
        assert_eq!(kind_from_executable_name(""), BrowserKind::Unknown);
    }

    #[test]
    fn executable_name_strips_directories() {
        assert_eq!(
            executable_name("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            "Google Chrome"
        );
        assert_eq!(executable_name("firefox"), "firefox");
        assert_eq!(executable_name(""), "");
    }

    #[test]
    fn matched_vendor_requirement_verifies_the_browser() {
        let identity = classify_signed(
            Some(TEAM_MOZILLA),
            Some("/Applications/Firefox.app/Contents/MacOS/firefox"),
        );
        assert_eq!(identity.kind, BrowserKind::Firefox);
        assert!(identity.verified);
        assert_eq!(identity.team_id.as_deref(), Some(TEAM_MOZILLA));
        assert_eq!(
            identity.executable.as_deref(),
            Some("/Applications/Firefox.app/Contents/MacOS/firefox")
        );
    }

    #[test]
    fn unmatched_requirement_is_not_verified() {
        // No known vendor requirement matched (unsigned, ad-hoc signed, or a
        // self-signed binary claiming a team in its code directory): kind from
        // the name, never verified.
        let identity = classify_signed(None, Some("/opt/google/chrome/google-chrome"));
        assert_eq!(identity.kind, BrowserKind::Chrome);
        assert!(!identity.verified);
        assert_eq!(identity.team_id, None);

        let identity = classify_signed(None, Some("Google Chrome"));
        assert_eq!(identity.kind, BrowserKind::Chrome);
        assert!(!identity.verified);

        // An unrecognised matched value still names the browser but cannot
        // verify it (the real matcher only returns known teams).
        let identity = classify_signed(Some("NOTABROWSER"), Some("Brave Browser"));
        assert_eq!(identity.kind, BrowserKind::Brave);
        assert!(!identity.verified);

        // Nothing usable at all.
        let identity = classify_signed(None, None);
        assert_eq!(identity, BrowserIdentity::unknown());
    }

    /// The test binary is ad-hoc signed (no Apple anchor, no vendor team).
    /// Even if its code directory claimed a team ID, the requirement-based
    /// check must reject it.
    #[test]
    fn ad_hoc_signed_process_is_not_verified() {
        let identity = identify_process(std::process::id() as i32);
        assert!(
            !identity.verified,
            "the ad-hoc signed test binary must never verify: {identity:?}"
        );
        assert_eq!(identity.team_id, None);
    }

    #[test]
    fn linux_rule_accepts_only_root_owned_system_browsers() {
        let chrome = Path::new("/usr/bin/google-chrome");
        assert!(linux_parent_is_trusted(0, 0o755, chrome));
        assert!(linux_parent_is_trusted(0, 0o555, chrome));
        // Group/other write access disqualifies even a root-owned binary.
        assert!(!linux_parent_is_trusted(0, 0o775, chrome));
        assert!(!linux_parent_is_trusted(0, 0o757, chrome));
        // Only root may own it.
        assert!(!linux_parent_is_trusted(501, 0o755, chrome));
        // User-writable locations are rejected.
        assert!(!linux_parent_is_trusted(
            0,
            0o755,
            Path::new("/home/alice/firefox")
        ));
        assert!(!linux_parent_is_trusted(
            0,
            0o755,
            Path::new("/usrlocal/bin/chrome")
        ));
        // Known names only — a root-owned shell under /usr is not a browser.
        assert!(!linux_parent_is_trusted(0, 0o755, Path::new("/usr/bin/sh")));
        // Nested vendor layout (snap/flatpak) still needs a known file name.
        assert!(linux_parent_is_trusted(
            0,
            0o755,
            Path::new("/snap/firefox/current/usr/lib/firefox/firefox")
        ));
        assert!(!linux_parent_is_trusted(
            0,
            0o755,
            Path::new("/snap/firefox/current/usr/lib/firefox/helper")
        ));
        // No file name at all.
        assert!(!linux_parent_is_trusted(0, 0o755, Path::new("/")));
    }

    #[test]
    fn system_prefixes_are_component_wise() {
        assert!(is_under_system_prefix(Path::new("/usr/bin/chromium")));
        assert!(is_under_system_prefix(Path::new(
            "/opt/brave.com/brave/brave"
        )));
        assert!(is_under_system_prefix(Path::new(
            "/var/lib/flatpak/app/org.mozilla.firefox/firefox"
        )));
        assert!(!is_under_system_prefix(Path::new("/usrlocal/bin/chrome")));
        assert!(!is_under_system_prefix(Path::new("/tmp/chrome")));
        assert!(!is_under_system_prefix(Path::new("/")));
    }

    #[test]
    fn linux_classification_uses_name_and_trust() {
        let identity = classify_linux(Some("/usr/bin/chromium"), true);
        assert_eq!(identity.kind, BrowserKind::Chromium);
        assert!(identity.verified);
        assert_eq!(identity.team_id, None);

        // An unsigned/untrusted parent still names the browser.
        let identity = classify_linux(Some("/home/a/brave-browser"), false);
        assert_eq!(identity.kind, BrowserKind::Brave);
        assert!(!identity.verified);

        let identity = classify_linux(None, false);
        assert_eq!(identity, BrowserIdentity::unknown());
    }

    #[test]
    fn identify_frame_matches_the_contract_shape() {
        let identity = BrowserIdentity {
            kind: BrowserKind::Chrome,
            verified: true,
            executable: Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
            team_id: Some(TEAM_GOOGLE.into()),
        };
        let frame = identify_frame(&identity);
        assert_eq!(frame["action"], "host-identify");
        assert_eq!(frame["hostVersion"], crate::dispatch::HOST_VERSION);
        assert_eq!(frame["browser"]["kind"], "chrome");
        assert_eq!(frame["browser"]["verified"], true);
        assert_eq!(
            frame["browser"]["executable"],
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        );
        assert_eq!(frame["browser"]["teamId"], TEAM_GOOGLE);

        // `teamId` is explicit JSON null when not applicable (contract §2).
        let unknown = identify_frame(&BrowserIdentity::unknown());
        assert_eq!(unknown["browser"]["kind"], "unknown");
        assert_eq!(unknown["browser"]["verified"], false);
        assert!(unknown["browser"]["teamId"].is_null());
        assert!(unknown["browser"]["executable"].is_null());

        // The cached bytes are the same frame.
        let bytes = identify_frame_bytes();
        let decoded: Value = serde_json::from_slice(bytes).expect("cached frame is JSON");
        assert_eq!(decoded["action"], "host-identify");
        assert_eq!(decoded["browser"]["kind"], summary_json()["kind"]);
        assert_eq!(decoded["browser"]["verified"], summary_json()["verified"]);
    }

    #[test]
    fn summary_has_only_kind_and_verified() {
        let summary = summary_json();
        let object = summary.as_object().expect("summary is an object");
        assert_eq!(object.len(), 2, "summary must stay minimal: {summary}");
        assert!(object.contains_key("kind"));
        assert!(object.contains_key("verified"));
    }

    #[test]
    fn identify_parent_never_panics_and_is_cached() {
        // Runs the real OS path. Whatever the test runner's parent is, the
        // result must be a well-formed identity and the cache must be stable.
        let identity = identify_parent();
        assert!(matches!(
            identity.kind,
            BrowserKind::Chrome
                | BrowserKind::Chromium
                | BrowserKind::Brave
                | BrowserKind::Edge
                | BrowserKind::Firefox
                | BrowserKind::Unknown
        ));
        assert_eq!(cached_identity(), cached_identity());
        // No parent process (or an unknown one) is never reported as verified.
        if identity.kind == BrowserKind::Unknown {
            assert!(!identity.verified);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_image_paths_map_to_browser_kinds() {
        let cases = [
            (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                BrowserKind::Chrome,
            ),
            (
                r"C:\Program Files\Chromium\Application\chromium.exe",
                BrowserKind::Chromium,
            ),
            (
                r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                BrowserKind::Brave,
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                BrowserKind::Edge,
            ),
            (
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                BrowserKind::Firefox,
            ),
            (r"C:\Windows\notepad.exe", BrowserKind::Unknown),
        ];
        for (path, expected) in cases {
            assert_eq!(
                kind_from_executable_name(executable_name(path)),
                expected,
                "{path}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_signature_vendor_must_match_the_browser_family() {
        let chrome = classify_windows(
            Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Some(VENDOR_GOOGLE),
        );
        assert_eq!(chrome.kind, BrowserKind::Chrome);
        assert!(chrome.verified);
        assert_eq!(chrome.team_id, None);

        // A valid signature from a different vendor does not verify Chrome.
        let impostor = classify_windows(
            Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Some(VENDOR_MOZILLA),
        );
        assert_eq!(impostor.kind, BrowserKind::Chrome);
        assert!(!impostor.verified);

        // Unsigned/unknown-signature builds are named but never verified.
        let unsigned = classify_windows(
            Some(r"C:\Program Files\Chromium\Application\chromium.exe"),
            None,
        );
        assert_eq!(unsigned.kind, BrowserKind::Chromium);
        assert!(!unsigned.verified);

        let firefox = classify_windows(
            Some(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
            Some(VENDOR_MOZILLA),
        );
        assert_eq!(firefox.kind, BrowserKind::Firefox);
        assert!(firefox.verified);
    }
}
