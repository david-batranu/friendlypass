//! Host-originated error frames (`protocol/ACTIONS.md` §3.6, §5.6).
//!
//! Same envelope as a KeePassXC outer error plus `"hostError": true`, so one
//! client parser handles both. Codes are 1000+ except the deliberate reuse of
//! KeePassXC code 5 for "app unavailable" when the failed request was an
//! encrypted app action (§5.6).

use serde_json::{json, Value};

pub const FRAME_TOO_LARGE: u32 = 1001;
pub const MALFORMED_FRAME: u32 = 1002;
pub const UNKNOWN_HOST_ACTION: u32 = 1003;

/// KeePassXC `TIMEOUT_OR_NOT_CONNECTED`, reused for encrypted app actions so
/// stock clients treat a missing app as a transient connection failure.
pub const APP_UNAVAILABLE_COMPAT: u32 = 5;

/// Build a host error frame. `action` is echoed when the host could parse it.
pub fn host_error(action: &str, code: u32, message: &str) -> Value {
    json!({
        "action": action,
        "error": message,
        "errorCode": code.to_string(),
        "hostError": true,
    })
}
