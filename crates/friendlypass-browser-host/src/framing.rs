//! Framing for both channels.
//!
//! Browser <-> host uses the frozen native-messaging frame from
//! `protocol/ACTIONS.md` §1.1: a 4-byte little-endian payload length followed
//! by exactly that many bytes of UTF-8 JSON. The host -> app socket format is
//! an internal concern (WP1/WP7a); the current app server reads a stream of
//! concatenated compact JSON objects, so the host writes the payload bytes
//! unchanged and splits replies with [`ObjectFramer`].

use std::io::{self, Read};

/// Maximum payload in either direction (`protocol/ACTIONS.md` §1.1).
pub const MAX_PAYLOAD: usize = 1_048_576;

/// The app socket buffer cap, mirroring the server's own limit. A desynchronised
/// buffer beyond this is dropped rather than grown without bound.
const MAX_SOCKET_BUFFER: usize = 2 * MAX_PAYLOAD;

/// One result of reading a native-messaging frame.
pub enum FrameRead {
    /// A complete payload.
    Frame(Vec<u8>),
    /// The length prefix exceeded [`MAX_PAYLOAD`]; exactly that many payload
    /// bytes were discarded.
    TooLarge(u32),
    /// Clean end of the stream (browser closed the port).
    Eof,
}

/// Read one native-messaging frame.
///
/// Split reads are handled by `read_exact`; coalesced frames are returned one
/// at a time because the caller loops. A truncated prefix or payload returns
/// `UnexpectedEof` and the caller exits cleanly.
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<FrameRead> {
    let mut prefix = [0u8; 4];
    if !read_prefix(reader, &mut prefix)? {
        return Ok(FrameRead::Eof);
    }

    let len = u32::from_le_bytes(prefix);
    if len as usize > MAX_PAYLOAD {
        // Contract: discard exactly `len` bytes, do not parse them.
        let discarded = io::copy(&mut reader.by_ref().take(u64::from(len)), &mut io::sink())?;
        if discarded < u64::from(len) {
            return Ok(FrameRead::Eof);
        }
        return Ok(FrameRead::TooLarge(len));
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    Ok(FrameRead::Frame(payload))
}

/// Read the 4-byte prefix, distinguishing "no frame at all" from a truncated
/// one. `Ok(false)` means clean EOF before the first byte.
fn read_prefix<R: Read>(reader: &mut R, prefix: &mut [u8; 4]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < prefix.len() {
        match reader.read(&mut prefix[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame length prefix",
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Splits concatenated JSON objects out of the app socket byte stream.
///
/// The app writes one compact object per message with nothing between them
/// (`crates/friendlypass-browser/src/server.rs` parses the same way), so brace
/// counting with string/escape awareness — not newlines — defines a frame.
#[derive(Default)]
pub struct ObjectFramer {
    buffer: Vec<u8>,
}

impl ObjectFramer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append bytes from the socket.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
        if self.buffer.len() > MAX_SOCKET_BUFFER {
            // The peer is not speaking our framing; start over instead of
            // growing without bound. The current chunk was likely garbage.
            self.buffer.clear();
        }
    }

    /// Return the next complete top-level object, if one is buffered.
    pub fn next_object(&mut self) -> Option<Vec<u8>> {
        let end = find_object_end(&self.buffer)?;
        Some(self.buffer.drain(..end).collect())
    }
}

/// End index (exclusive) of the first complete top-level JSON object.
fn find_object_end(buffer: &[u8]) -> Option<usize> {
    let start = buffer.iter().position(|&b| b == b'{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in buffer.iter().enumerate().skip(start) {
        if escape {
            escape = false;
            continue;
        }
        match b {
            b'\\' if in_string => escape = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Chunked {
        chunks: Vec<Vec<u8>>,
        index: usize,
    }

    impl Read for Chunked {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.index >= self.chunks.len() {
                return Ok(0);
            }
            let chunk = &self.chunks[self.index];
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            if n == chunk.len() {
                self.index += 1;
            } else {
                self.chunks[self.index] = chunk[n..].to_vec();
            }
            Ok(n)
        }
    }

    #[test]
    fn reads_a_frame_split_across_reads() {
        let mut stream = Chunked {
            chunks: vec![vec![5, 0], vec![0, 0, b'{', b'"'], vec![b'a', b'"', b'}']],
            index: 0,
        };
        match read_frame(&mut stream).expect("frame") {
            FrameRead::Frame(payload) => assert_eq!(payload, br#"{"a"}"#),
            _ => panic!("expected a frame"),
        }
        assert!(matches!(
            read_frame(&mut stream).expect("eof"),
            FrameRead::Eof
        ));
    }

    #[test]
    fn reads_coalesced_frames_one_at_a_time() {
        let mut stream = Chunked {
            chunks: vec![
                vec![7, 0, 0, 0],
                br#"{"a":1}"#.to_vec(),
                vec![7, 0, 0, 0],
                br#"{"a":2}"#.to_vec(),
            ],
            index: 0,
        };
        let first = match read_frame(&mut stream).expect("first") {
            FrameRead::Frame(p) => p,
            _ => panic!("expected first frame"),
        };
        let second = match read_frame(&mut stream).expect("second") {
            FrameRead::Frame(p) => p,
            _ => panic!("expected second frame"),
        };
        assert_eq!(first, br#"{"a":1}"#);
        assert_eq!(second, br#"{"a":2}"#);
    }

    #[test]
    fn rejects_oversize_and_discards_exactly_the_payload() {
        let size = MAX_PAYLOAD + 1;
        let mut bytes = (size as u32).to_le_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(b'x', size));
        bytes.extend(7u32.to_le_bytes());
        bytes.extend(br#"{"a":9}"#);
        let mut stream = Chunked {
            chunks: vec![bytes],
            index: 0,
        };
        match read_frame(&mut stream).expect("oversize") {
            FrameRead::TooLarge(n) => assert_eq!(n as usize, size),
            _ => panic!("expected oversize"),
        }
        // The next frame must still be aligned.
        match read_frame(&mut stream).expect("next") {
            FrameRead::Frame(p) => assert_eq!(p, br#"{"a":9}"#),
            _ => panic!("expected next frame"),
        }
    }

    #[test]
    fn object_framer_handles_split_and_coalesced_objects() {
        let mut framer = ObjectFramer::new();
        framer.push(br#"{"a":"}"}"#);
        framer.push(b"{\"b\":1}");
        let first = framer.next_object().expect("first");
        let second = framer.next_object().expect("second");
        assert!(framer.next_object().is_none());
        assert_eq!(first, br#"{"a":"}"}"#);
        assert_eq!(second, br#"{"b":1}"#);
    }
}
