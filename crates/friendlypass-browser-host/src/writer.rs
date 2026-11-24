//! stdout frame writer.
//!
//! stdout is the protocol channel: the only bytes written are complete
//! native-messaging frames (`protocol/ACTIONS.md` §1.1). Diagnostics go to
//! stderr. Frames are serialised through one mutex so a forwarded reply and a
//! push can never interleave.

use std::io::{self, Write};
use std::sync::Mutex;

use serde_json::Value;

use crate::framing::MAX_PAYLOAD;

pub struct Writer {
    inner: Mutex<io::BufWriter<io::Stdout>>,
}

impl Writer {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(io::BufWriter::new(io::stdout())),
        }
    }

    /// Write one already-encoded payload as a native-messaging frame.
    pub fn frame(&self, payload: &[u8]) -> io::Result<()> {
        // Host-originated frames are small (errors, ping/hello). A forwarded
        // payload was already checked against the cap on the way in.
        let len = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload does not fit a native-messaging frame",
            )
        })?;
        if payload.len() > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload exceeds the 1 MiB frame cap",
            ));
        }
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.write_all(&len.to_le_bytes())?;
        guard.write_all(payload)?;
        guard.flush()
    }

    /// Serialise and write a JSON value as one frame.
    pub fn value(&self, value: &Value) -> io::Result<()> {
        let payload =
            serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.frame(&payload)
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}
