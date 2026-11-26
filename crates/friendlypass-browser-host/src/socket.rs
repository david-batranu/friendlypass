//! The platform app link used by the host: a Unix domain socket on Unix, a
//! named pipe on Windows. Both implement the shared
//! [`friendlypass_browser::transport::AppStream`] trait, so the rest of the
//! host never names a platform socket type.

use std::io;
use std::path::Path;

#[cfg(unix)]
pub type AppSocket = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type AppSocket = friendlypass_browser::pipe::PipeStream;

pub use friendlypass_browser::transport::AppStream;

pub fn connect(path: &Path) -> io::Result<AppSocket> {
    AppSocket::connect(path)
}
