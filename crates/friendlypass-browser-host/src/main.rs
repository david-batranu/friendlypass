//! `friendlypass-browser-host` — the native-messaging host registered with
//! Chrome/Firefox as `org.friendlypass.browser`.
//!
//! Owned by WP1. It will speak 4-byte-LE length-prefixed JSON on stdin/stdout,
//! keep itself alive while the app socket is down, answer host-level
//! `ping`/`hello` locally, and relay everything else to the app socket.
//! See `protocol/ACTIONS.md`.
//!
//! TODO(WP1): implement the host. This scaffold only proves the crate builds
//! and that the workspace wires it correctly.

fn main() {
    // stdout is the protocol channel: diagnostics belong on stderr.
    eprintln!("friendlypass-browser-host: TODO (WP1) — not implemented yet");
}
