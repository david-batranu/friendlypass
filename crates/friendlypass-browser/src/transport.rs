//! Stream abstraction shared by the Unix-socket and Windows named-pipe
//! servers.
//!
//! The protocol state machine in [`crate::server_core`] is written once over
//! [`AppStream`]; only listening, accepting and peer verification differ per
//! platform. Keeping the trait this small means the Unix implementation is a
//! thin wrapper around `UnixStream` and Windows names the few handle operations
//! a byte-mode named pipe needs.

use std::io::{self, Read, Write};
use std::time::Duration;

/// A connected, full-duplex byte stream that behaves enough like a Unix socket
/// for the connection loop.
pub trait AppStream: Read + Write + Send + Sized + 'static {
    /// A second handle to the same connection, used so the reader and the
    /// writer (plus pushes) never block each other.
    fn try_clone(&self) -> io::Result<Self>;

    /// Bound a blocking read, so the reader can notice pushes and shutdown.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Bound a write so a stalled peer cannot wedge a connection thread.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Wake a reader blocked in [`Read`] and release the connection.
    fn shutdown(&self);
}

#[cfg(unix)]
impl AppStream for std::os::unix::net::UnixStream {
    fn try_clone(&self) -> io::Result<Self> {
        std::os::unix::net::UnixStream::try_clone(self)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, timeout)
    }

    fn shutdown(&self) {
        let _ = std::os::unix::net::UnixStream::shutdown(self, std::net::Shutdown::Both);
    }
}
