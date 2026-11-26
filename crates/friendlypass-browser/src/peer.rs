//! App-side peer verification for the app socket (contract §3).
//!
//! Every accepted connection is attributable to a process: macOS reports it
//! with `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`, Linux with
//! `getsockopt(SOL_SOCKET, SO_PEERCRED)`. The process's executable is then
//! resolved (`proc_pidpath` / `/proc/<pid>/exe`) and matched against the native
//! host binary the app expects (`ServerConfig::trusted_host_path`).
//!
//! macOS additionally compares code identities: the running process must be
//! validly signed and its `cdhash` (`kSecCodeInfoUnique`) must equal the
//! `cdhash` of the expected on-disk host. Ad-hoc signed developer builds have a
//! cdhash too, so this works without a Developer ID.
//!
//! Every failure — unsupported platform, missing pid, unreadable executable,
//! unsigned peer, Security framework error — yields `trusted: false`. This
//! module never panics.

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// What the app knows about the process at the other end of one connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerInfo {
    /// Peer process id, when the platform exposed it.
    pub pid: Option<i32>,
    /// Peer executable, when it could be resolved.
    pub executable: Option<PathBuf>,
    /// `true` only when the peer is provably our native host (§3).
    pub trusted: bool,
}

/// Identify the peer of `stream` and decide whether `expected_host` may be
/// trusted for it.
///
/// `expected_host` of `None` never trusts anything: the auto-approve path is
/// opt-in and requires a configured host path.
#[cfg(unix)]
pub fn verify_peer(stream: &UnixStream, expected_host: Option<&Path>) -> PeerInfo {
    let pid = peer_pid(stream);
    let executable = pid.and_then(executable_for_pid);
    let trusted = match (expected_host, executable.as_deref()) {
        (Some(expected), Some(actual)) => verify_identity(pid, expected, actual),
        _ => false,
    };
    PeerInfo {
        pid,
        executable,
        trusted,
    }
}

/// Windows has no app socket yet, so no peer can ever be trusted. The generic
/// parameter keeps the signature usable from code that will gain a Windows
/// transport later.
#[cfg(not(unix))]
pub fn verify_peer<S>(_stream: &S, _expected_host: Option<&Path>) -> PeerInfo {
    PeerInfo::default()
}

/// The pid of the process at the other end of `stream`.
#[cfg(unix)]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    peer_pid_impl(stream.as_raw_fd())
}

#[cfg(all(unix, target_os = "macos"))]
fn peer_pid_impl(fd: std::os::unix::io::RawFd) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` and `len` are valid writable pointers of the sizes passed.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    (result == 0 && pid > 0).then_some(pid)
}

#[cfg(all(unix, target_os = "linux"))]
fn peer_pid_impl(fd: std::os::unix::io::RawFd) -> Option<i32> {
    // `struct ucred` is not exported for every libc target; its layout is
    // stable across Linux architectures.
    #[repr(C)]
    struct UCred {
        pid: libc::pid_t,
        uid: libc::uid_t,
        gid: libc::gid_t,
    }
    const SO_PEERCRED: libc::c_int = 17;

    let mut cred = UCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<UCred>() as libc::socklen_t;
    // SAFETY: `cred` is a valid writable pointer with `len` bytes available.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PEERCRED,
            (&mut cred as *mut UCred).cast(),
            &mut len,
        )
    };
    (result == 0 && cred.pid > 0).then_some(cred.pid)
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn peer_pid_impl(_fd: std::os::unix::io::RawFd) -> Option<i32> {
    None
}

/// The executable path of `pid`.
#[cfg(unix)]
fn executable_for_pid(pid: i32) -> Option<PathBuf> {
    executable_for_pid_impl(pid)
}

#[cfg(all(unix, target_os = "macos"))]
fn executable_for_pid_impl(pid: i32) -> Option<PathBuf> {
    let mut buffer = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is valid for `buffer.len()` writable bytes.
    let length = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            buffer.len() as libc::c_uint,
        )
    };
    if length <= 0 {
        return None;
    }
    let text = std::str::from_utf8(&buffer[..length as usize]).ok()?;
    (!text.is_empty()).then(|| PathBuf::from(text))
}

#[cfg(all(unix, target_os = "linux"))]
fn executable_for_pid_impl(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .filter(|path| !path.as_os_str().is_empty())
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn executable_for_pid_impl(_pid: i32) -> Option<PathBuf> {
    None
}

/// Canonical path equality plus, on macOS, a code-identity comparison.
#[cfg(unix)]
fn verify_identity(pid: Option<i32>, expected: &Path, actual: &Path) -> bool {
    if !same_file(expected, actual) {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        pid.is_some_and(|pid| code_identity_matches(pid, expected))
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Linux only compares the resolved executable (contract §3).
        let _ = pid;
        true
    }
}

/// Compare two paths after resolving symlinks and `..`; a missing path never
/// matches.
#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> bool {
    let Ok(left) = std::fs::canonicalize(left) else {
        return false;
    };
    let Ok(right) = std::fs::canonicalize(right) else {
        return false;
    };
    left == right
}

/// macOS: the running process must be validly signed and its cdhash must equal
/// the cdhash of the expected on-disk host.
#[cfg(target_os = "macos")]
fn code_identity_matches(pid: i32, expected: &Path) -> bool {
    let Some(running) = running_cdhash(pid) else {
        return false;
    };
    let Some(on_disk) = disk_cdhash(expected) else {
        return false;
    };
    !running.is_empty() && running == on_disk
}

// Security.framework entry points we need that the maintained binding crates
// do not expose (`SecCodeCopySigningInformation` and the
// `kSecCodeInfoUnique`/`kSecGuestAttributePid` constants).
#[cfg(target_os = "macos")]
#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecCodeCopyGuestWithAttributes(
        host: *mut std::ffi::c_void,
        attributes: core_foundation::dictionary::CFDictionaryRef,
        flags: u32,
        guest: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn SecCodeCheckValidity(code: *mut std::ffi::c_void, flags: u32, requirement: *mut std::ffi::c_void) -> i32;
    fn SecCodeCopySigningInformation(
        code: *mut std::ffi::c_void,
        flags: u32,
        information: *mut core_foundation::dictionary::CFDictionaryRef,
    ) -> i32;
    fn SecStaticCodeCreateWithPath(
        path: core_foundation::url::CFURLRef,
        flags: u32,
        code: *mut *mut std::ffi::c_void,
    ) -> i32;
    static kSecGuestAttributePid: core_foundation::string::CFStringRef;
    static kSecCodeInfoUnique: core_foundation::string::CFStringRef;
}

/// The cdhash of the running process `pid`, after checking that its code is
/// validly signed.
#[cfg(target_os = "macos")]
fn running_cdhash(pid: i32) -> Option<Vec<u8>> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;

    let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) };
    let value = CFNumber::from(pid);
    let mut attributes = CFMutableDictionary::<CFString, CFNumber>::with_capacity(1);
    attributes.add(&key, &value);

    let mut guest: *mut std::ffi::c_void = std::ptr::null_mut();
    let status = unsafe {
        SecCodeCopyGuestWithAttributes(
            std::ptr::null_mut(),
            attributes.as_concrete_TypeRef(),
            0,
            &mut guest,
        )
    };
    if status != 0 || guest.is_null() {
        return None;
    }
    // A CFType guard releases the SecCodeRef when it goes out of scope.
    let guest = unsafe { CFType::wrap_under_create_rule(guest as core_foundation::base::CFTypeRef) };

    // `NULL` requirement = check the signature's own validity (works for
    // ad-hoc signed developer builds too).
    let valid = unsafe { SecCodeCheckValidity(guest.as_CFTypeRef() as *mut _, 0, std::ptr::null_mut()) };
    if valid != 0 {
        return None;
    }
    signing_information(guest.as_CFTypeRef() as *mut _)
}

/// The cdhash recorded in the on-disk code signature of `path`.
#[cfg(target_os = "macos")]
fn disk_cdhash(path: &Path) -> Option<Vec<u8>> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::url::CFURL;

    let url = CFURL::from_path(path, false)?;
    let mut code: *mut std::ffi::c_void = std::ptr::null_mut();
    let status = unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &mut code) };
    if status != 0 || code.is_null() {
        return None;
    }
    let code = unsafe { CFType::wrap_under_create_rule(code as core_foundation::base::CFTypeRef) };
    signing_information(code.as_CFTypeRef() as *mut _)
}

/// Read `kSecCodeInfoUnique` (the cdhash, a `CFData`) from a code object.
#[cfg(target_os = "macos")]
fn signing_information(code: *mut std::ffi::c_void) -> Option<Vec<u8>> {
    use core_foundation::base::{CFGetTypeID, CFRelease, CFTypeRef};
    use core_foundation::data::{CFData, CFDataGetTypeID, CFDataRef};
    use core_foundation::dictionary::{CFDictionaryGetValue, CFDictionaryRef};
    use core_foundation::string::CFString;
    use core_foundation::base::TCFType;

    let mut information: CFDictionaryRef = std::ptr::null();
    let status = unsafe { SecCodeCopySigningInformation(code, 0, &mut information) };
    if status != 0 || information.is_null() {
        return None;
    }
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoUnique) };
    let value = unsafe { CFDictionaryGetValue(information, key.as_CFTypeRef()) };
    let cdhash = if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFDataGetTypeID() } {
        None
    } else {
        let data = unsafe { CFData::wrap_under_get_rule(value as CFDataRef) };
        let bytes = data.bytes().to_vec();
        (!bytes.is_empty()).then_some(bytes)
    };
    unsafe { CFRelease(information as CFTypeRef) };
    cdhash
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn current_exe() -> PathBuf {
        std::fs::canonicalize(std::env::current_exe().expect("current_exe"))
            .expect("canonical current_exe")
    }

    #[test]
    fn socketpair_peer_is_identified() {
        let (ours, _peer) = UnixStream::pair().expect("socketpair");
        let info = verify_peer(&ours, None);
        assert_eq!(info.pid, Some(std::process::id() as i32));
        let actual = info
            .executable
            .as_deref()
            .map(|path| std::fs::canonicalize(path).expect("canonical peer executable"));
        assert_eq!(actual, Some(current_exe()));
        assert!(!info.trusted, "no expected host path never trusts");
    }

    #[test]
    fn our_own_binary_is_trusted_when_expected() {
        let (ours, _peer) = UnixStream::pair().expect("socketpair");
        let info = verify_peer(&ours, Some(&current_exe()));
        #[cfg(target_os = "macos")]
        {
            // Cargo-built test binaries are ad-hoc signed on Apple silicon and
            // thus have a cdhash; an unsigned build cannot be trusted.
            if disk_cdhash(&current_exe()).is_none() {
                eprintln!("test binary is unsigned; skipping the trusted assertion");
                assert!(!info.trusted);
                return;
            }
        }
        assert!(info.trusted, "our own executable is the expected host: {info:?}");
    }

    #[test]
    fn a_different_host_path_is_untrusted() {
        let (ours, _peer) = UnixStream::pair().expect("socketpair");
        let info = verify_peer(&ours, Some(Path::new("/bin/sh")));
        assert!(!info.trusted);
        assert!(info.executable.is_some(), "the peer executable is still reported");
    }

    #[test]
    fn a_missing_or_odd_path_is_untrusted() {
        let (ours, _peer) = UnixStream::pair().expect("socketpair");
        let missing = std::env::temp_dir().join("friendlypass-does-not-exist-host");
        assert!(!verify_peer(&ours, Some(&missing)).trusted);
        assert!(!verify_peer(&ours, Some(Path::new(""))).trusted);
        // A directory is not a code object / executable.
        assert!(!verify_peer(&ours, Some(Path::new("/"))).trusted);
    }
}
