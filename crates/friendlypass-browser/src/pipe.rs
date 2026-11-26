//! Named-pipe transport for the friendlypass app link on Windows.
//!
//! The protocol framing is identical to the Unix socket (`server_core.rs`):
//! raw concatenated compact-JSON objects. A pipe instance is created per
//! accepted connection and the connected handle is handed to the shared
//! connection loop. Reads and writes use overlapped I/O so a timeout (for push
//! polling and shutdown) and bounded writes work exactly like the Unix socket
//! options.
//!
//! The pipe is per-user: the name carries the Windows user name and the DACL
//! grants access to the object owner only. `PIPE_REJECT_REMOTE_CLIENTS` keeps
//! the endpoint local to this machine.

use std::ffi::OsStr;
use std::io::{self, ErrorKind, Read, Write};
use std::mem::{self, size_of};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE,
    HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use crate::transport::AppStream;

/// A named pipe that has been opened for the app link.
///
/// Clones share one Windows handle (reads and writes are independent on a
/// byte-mode duplex pipe), so a reader and a writer can run concurrently
/// without duplicating the object.
pub struct PipeStream {
    inner: Arc<Inner>,
}

struct Inner {
    handle: HANDLE,
    read_timeout_ms: AtomicU64,
    write_timeout_ms: AtomicU64,
}

// SAFETY: a named-pipe handle is a process-wide kernel object handle and is
// valid to use from several threads. Reads and writes on a byte-mode duplex
// pipe do not conflict; the connection loop only ever has one reader and one
// writer.
unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            // SAFETY: `handle` was returned by CreateNamedPipeW/CreateFileW
            // and is owned by this value.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

impl PipeStream {
    fn from_handle(handle: HANDLE) -> Self {
        Self {
            inner: Arc::new(Inner {
                handle,
                read_timeout_ms: AtomicU64::new(INFINITE as u64),
                write_timeout_ms: AtomicU64::new(INFINITE as u64),
            }),
        }
    }

    /// Create the next server instance. `first` enables
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE`, which makes a second process's attempt
    /// fail with `ERROR_ACCESS_DENIED` — the Windows equivalent of the Unix
    /// "already listening" check.
    pub fn create_server(name: &Path, first: bool) -> io::Result<Self> {
        let wide = wide_path(name);
        let (attributes, descriptor) = per_user_security_attributes()?;
        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: `wide` is NUL-terminated and the security attributes live
        // until CreateNamedPipeW returns. The descriptor is freed below.
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                open_mode,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &attributes,
            )
        };
        // SAFETY: the descriptor was allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(descriptor as _);
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self::from_handle(handle))
    }

    /// Connect the client end to an existing server instance.
    pub fn connect(name: &Path) -> io::Result<Self> {
        let wide = wide_path(name);
        // SAFETY: `wide` is a NUL-terminated path; the remaining arguments are
        // the documented values for opening a duplex byte-mode pipe.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self::from_handle(handle))
    }

    /// Block until a client connects to this server instance.
    pub fn accept(&self) -> io::Result<()> {
        let event = create_event()?;
        let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
        overlapped.hEvent = event;
        // SAFETY: `overlapped` is a valid structure for the duration of the
        // call and `event` stays alive until the operation completes.
        let connected = unsafe { ConnectNamedPipe(self.inner.handle, &mut overlapped) };
        let result = if connected != 0 {
            Ok(())
        } else {
            match unsafe { GetLastError() } {
                // A client connected between CreateNamedPipeW and this call.
                ERROR_PIPE_CONNECTED => Ok(()),
                ERROR_IO_PENDING => {
                    if unsafe { WaitForSingleObject(event, INFINITE) } == WAIT_OBJECT_0 {
                        let mut transferred = 0u32;
                        // SAFETY: the overlapped operation was signalled.
                        if unsafe {
                            GetOverlappedResult(self.inner.handle, &overlapped, &mut transferred, 0)
                        } != 0
                        {
                            Ok(())
                        } else {
                            Err(io::Error::last_os_error())
                        }
                    } else {
                        Err(io::Error::last_os_error())
                    }
                }
                error => Err(io::Error::from_raw_os_error(error as i32)),
            }
        };
        unsafe {
            CloseHandle(event);
        }
        result
    }

    /// Pid of the client at the other end, for peer verification.
    pub fn client_process_id(&self) -> Option<u32> {
        let mut pid = 0u32;
        // SAFETY: `pid` is a valid writable pointer.
        let ok = unsafe { GetNamedPipeClientProcessId(self.inner.handle, &mut pid) };
        (ok != 0 && pid != 0).then_some(pid)
    }

    fn timeout_ms(&self, read: bool) -> u32 {
        let stored = if read {
            self.inner.read_timeout_ms.load(Ordering::Relaxed)
        } else {
            self.inner.write_timeout_ms.load(Ordering::Relaxed)
        };
        stored.min(u32::MAX as u64) as u32
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(u32::MAX as usize) as u32;
        let timeout = self.timeout_ms(true);
        let handle = self.inner.handle;
        let pointer = buf.as_mut_ptr();
        // SAFETY: `pointer` is valid for `len` writable bytes and `handle` is
        // owned by this stream.
        overlapped_io(handle, timeout, |overlapped, transferred| unsafe {
            ReadFile(handle, pointer, len, transferred, overlapped)
        })
        .map(|transferred| transferred as usize)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(u32::MAX as usize) as u32;
        let timeout = self.timeout_ms(false);
        let handle = self.inner.handle;
        let pointer = buf.as_ptr();
        // SAFETY: `pointer` is valid for `len` readable bytes and `handle` is
        // owned by this stream.
        overlapped_io(handle, timeout, |overlapped, transferred| unsafe {
            WriteFile(handle, pointer, len, transferred, overlapped)
        })
        .map(|transferred| transferred as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Named-pipe writes are unbuffered; FlushFileBuffers would wait for
        // the peer to read and could block a writer indefinitely.
        Ok(())
    }
}

impl AppStream for PipeStream {
    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: Arc::clone(&self.inner),
        })
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.read_timeout_ms.store(
            timeout.map(duration_ms).unwrap_or(INFINITE as u64),
            Ordering::Relaxed,
        );
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.write_timeout_ms.store(
            timeout.map(duration_ms).unwrap_or(INFINITE as u64),
            Ordering::Relaxed,
        );
        Ok(())
    }

    fn shutdown(&self) {
        // Cancel a pending overlapped read so a connection thread can exit.
        // Passing a NULL OVERLAPPED cancels every operation on the handle.
        // SAFETY: `handle` is owned by this stream and the call has no
        // out-parameters.
        unsafe {
            CancelIoEx(self.inner.handle, std::ptr::null());
        }
    }
}

fn duration_ms(timeout: Duration) -> u64 {
    timeout.as_millis().min(u32::MAX as u128) as u64
}

/// Run one overlapped read/write with the given timeout in milliseconds.
fn overlapped_io<F>(handle: HANDLE, timeout_ms: u32, operation: F) -> io::Result<u32>
where
    F: FnOnce(*mut OVERLAPPED, *mut u32) -> i32,
{
    let event = create_event()?;
    let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
    overlapped.hEvent = event;
    let mut transferred = 0u32;

    let started = operation(&mut overlapped, &mut transferred);
    let result = if started != 0 {
        Ok(transferred)
    } else {
        match unsafe { GetLastError() } {
            ERROR_IO_PENDING => match unsafe { WaitForSingleObject(event, timeout_ms) } {
                WAIT_OBJECT_0 => {
                    // SAFETY: the overlapped operation completed.
                    if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 0) } != 0
                    {
                        Ok(transferred)
                    } else {
                        Err(io::Error::last_os_error())
                    }
                }
                WAIT_TIMEOUT => {
                    // Cancel and wait so the caller's buffer is no longer in
                    // use when this function returns.
                    // SAFETY: `overlapped` identifies the pending operation.
                    unsafe {
                        CancelIoEx(handle, &overlapped);
                        let mut cancelled = 0u32;
                        let _ = GetOverlappedResult(handle, &overlapped, &mut cancelled, 1);
                    }
                    Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "named pipe I/O timed out",
                    ))
                }
                _ => Err(io::Error::last_os_error()),
            },
            error => Err(io::Error::from_raw_os_error(error as i32)),
        }
    };

    unsafe {
        CloseHandle(event);
    }
    result
}

fn create_event() -> io::Result<HANDLE> {
    // SAFETY: all attributes are NULL/default; the event is manual-reset and
    // initially non-signalled.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(event)
    }
}

fn per_user_security_attributes() -> io::Result<(SECURITY_ATTRIBUTES, PSECURITY_DESCRIPTOR)> {
    // `OW` is the object-owner SID, i.e. the user creating the pipe. Granting
    // generic access to it limits the endpoint to the current user without
    // baking a user name (which may change) into the descriptor. SYSTEM is
    // deliberately not added: the app link never needs it.
    let sddl = wide(OsStr::new("D:P(A;;GA;;;OW)"));
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and the output pointer is valid.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    Ok((attributes, descriptor))
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    wide(path.as_os_str())
}

/// The pipe name for `user` (`\\.\pipe\<name>_<user>`).
pub fn pipe_name(name: &str, user: &str) -> PathBuf {
    PathBuf::from(format!(r"\\.\pipe\{name}_{user}"))
}

/// The current Windows user name, as used in the pipe name.
pub fn current_user_name() -> String {
    std::env::var("USERNAME")
        .ok()
        .filter(|user| !user.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_names_are_per_user_and_branded() {
        let name = pipe_name("org.friendlypass.BrowserServer", "alice");
        assert_eq!(
            name.to_string_lossy(),
            r"\\.\pipe\org.friendlypass.BrowserServer_alice"
        );
        assert!(!name.to_string_lossy().to_lowercase().contains("keepassxc"));
    }

    #[test]
    fn first_pipe_instance_rejects_a_second_server() {
        let name = pipe_name("friendlypass-browser-test-second-server", "owner");
        let first = PipeStream::create_server(&name, true).expect("first pipe instance");
        let error = match PipeStream::create_server(&name, true) {
            Ok(_) => panic!("a second first-instance must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error.raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
        );
        drop(first);
    }
}
