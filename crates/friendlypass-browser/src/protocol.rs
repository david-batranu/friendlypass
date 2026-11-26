//! KeePassXC-Browser protocol actions, error codes, and message shaping —
//! matching KeePassXC 2.8.0's `BrowserAction`/`BrowserMessageBuilder`.
//!
//! The wire contract is frozen in `protocol/ACTIONS.md`. Everything emitted
//! here is deliberately compatible with the official keepassxc-browser
//! extension: `errorCode` is a string, `success` is the string `"true"`, the
//! inner `version` is `"2.8.0"` (an opaque feature-gating version), and error
//! replies carry no nonce.

use serde_json::{json, Map, Value};

use std::path::PathBuf;

/// The feature-gating protocol version reported inside every encrypted
/// response. friendlypass's real version is exposed through `hello.appVersion`.
pub const PROTOCOL_ACTION_VERSION: &str = "2.8.0";

/// friendlypass protocol version (host-level `ping`/`hello`).
pub const PROTOCOL_VERSION: u64 = 1;

/// Supported KeePassXC actions.
pub const ACTION_CHANGE_PUBLIC_KEYS: &str = "change-public-keys";
pub const ACTION_GET_DATABASEHASH: &str = "get-databasehash";
pub const ACTION_ASSOCIATE: &str = "associate";
pub const ACTION_TEST_ASSOCIATE: &str = "test-associate";
pub const ACTION_GET_LOGINS: &str = "get-logins";
pub const ACTION_SET_LOGIN: &str = "set-login";
pub const ACTION_GET_TOTP: &str = "get-totp";
pub const ACTION_GET_DATABASE_GROUPS: &str = "get-database-groups";
pub const ACTION_GENERATE_PASSWORD: &str = "generate-password";
pub const ACTION_LOCK_DATABASE: &str = "lock-database";
pub const ACTION_PASSKEYS_REGISTER: &str = "passkeys-register";
pub const ACTION_PASSKEYS_GET: &str = "passkeys-get";

/// friendlypass host-level actions / pushes.
pub const ACTION_PING: &str = "ping";
pub const ACTION_HELLO: &str = "hello";
/// Host → app identity frame sent as the first frame of every connection (§2).
pub const ACTION_HOST_IDENTIFY: &str = "host-identify";
pub const ACTION_DATABASE_LOCKED: &str = "database-locked";
pub const ACTION_DATABASE_UNLOCKED: &str = "database-unlocked";
pub const ACTION_DATABASE_CHANGED: &str = "database-changed";

/// Error codes (`BrowserMessageBuilder.h`).
pub const ERROR_DATABASE_NOT_OPENED: i32 = 1;
pub const ERROR_DATABASE_HASH_NOT_RECEIVED: i32 = 2;
pub const ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED: i32 = 3;
pub const ERROR_CANNOT_DECRYPT_MESSAGE: i32 = 4;
pub const ERROR_TIMEOUT_OR_NOT_CONNECTED: i32 = 5;
pub const ERROR_ACTION_CANCELLED_OR_DENIED: i32 = 6;
pub const ERROR_CANNOT_ENCRYPT_MESSAGE: i32 = 7;
pub const ERROR_ASSOCIATION_FAILED: i32 = 8;
pub const ERROR_KEY_CHANGE_FAILED: i32 = 9;
pub const ERROR_ENCRYPTION_KEY_UNRECOGNIZED: i32 = 10;
pub const ERROR_NO_SAVED_DATABASES_FOUND: i32 = 11;
pub const ERROR_INCORRECT_ACTION: i32 = 12;
pub const ERROR_EMPTY_MESSAGE_RECEIVED: i32 = 13;
pub const ERROR_NO_URL_PROVIDED: i32 = 14;
pub const ERROR_NO_LOGINS_FOUND: i32 = 15;
pub const ERROR_NO_GROUPS_FOUND: i32 = 16;
pub const ERROR_CANNOT_CREATE_NEW_GROUP: i32 = 17;
pub const ERROR_NO_VALID_UUID_PROVIDED: i32 = 18;
pub const ERROR_ACCESS_TO_ALL_ENTRIES_DENIED: i32 = 19;
pub const ERROR_PASSKEYS_ATTESTATION_NOT_SUPPORTED: i32 = 20;
pub const ERROR_PASSKEYS_CREDENTIAL_IS_EXCLUDED: i32 = 21;
pub const ERROR_PASSKEYS_REQUEST_CANCELED: i32 = 22;
pub const ERROR_PASSKEYS_INVALID_USER_VERIFICATION: i32 = 23;
pub const ERROR_PASSKEYS_EMPTY_PUBLIC_KEY: i32 = 24;
pub const ERROR_PASSKEYS_INVALID_URL_PROVIDED: i32 = 25;
pub const ERROR_PASSKEYS_ORIGIN_NOT_ALLOWED: i32 = 26;
pub const ERROR_PASSKEYS_DOMAIN_IS_NOT_VALID: i32 = 27;
pub const ERROR_PASSKEYS_DOMAIN_RPID_MISMATCH: i32 = 28;
pub const ERROR_PASSKEYS_NO_SUPPORTED_ALGORITHMS: i32 = 29;
pub const ERROR_PASSKEYS_WAIT_FOR_LIFETIMER: i32 = 30;
pub const ERROR_PASSKEYS_UNKNOWN_ERROR: i32 = 31;
pub const ERROR_PASSKEYS_INVALID_CHALLENGE: i32 = 32;
pub const ERROR_PASSKEYS_INVALID_USER_ID: i32 = 33;
pub const ERROR_CANNOT_USE_REFERENCES: i32 = 34;
pub const ERROR_PASSKEYS_EVAL_BY_CREDENTIAL_NOT_SUPPORTED: i32 = 35;
pub const ERROR_PASSKEYS_EVAL_BY_CREDENTIAL_NOT_EMPTY: i32 = 36;
pub const ERROR_PASSKEYS_EVAL_BY_CREDENTIAL_NOT_FOUND: i32 = 37;

/// friendlypass host error codes (§5.6).
pub const HOST_ERROR_FRAME_TOO_LARGE: i32 = 1001;
pub const HOST_ERROR_MALFORMED_FRAME: i32 = 1002;
pub const HOST_ERROR_UNKNOWN_HOST_ACTION: i32 = 1003;
pub const HOST_ERROR_HOST_INTERNAL: i32 = 1004;
pub const HOST_ERROR_APP_UNAVAILABLE: i32 = 1005;
pub const HOST_ERROR_ENCRYPTION_REQUIRED: i32 = 1006;

pub fn error_message(code: i32) -> &'static str {
    match code {
        ERROR_DATABASE_NOT_OPENED => "Database not opened",
        ERROR_DATABASE_HASH_NOT_RECEIVED => "Database hash not available",
        ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED => "Client public key not received",
        ERROR_CANNOT_DECRYPT_MESSAGE => "Cannot decrypt message",
        ERROR_TIMEOUT_OR_NOT_CONNECTED => "Timeout or not connected",
        ERROR_ACTION_CANCELLED_OR_DENIED => "Action cancelled or denied",
        ERROR_CANNOT_ENCRYPT_MESSAGE => "Message encryption failed.",
        ERROR_ASSOCIATION_FAILED => "KeePassXC association failed, try again",
        ERROR_KEY_CHANGE_FAILED => "Key change failed",
        ERROR_ENCRYPTION_KEY_UNRECOGNIZED => "Encryption key unrecognized",
        ERROR_NO_SAVED_DATABASES_FOUND => "No saved databases found",
        ERROR_INCORRECT_ACTION => "Incorrect action",
        ERROR_EMPTY_MESSAGE_RECEIVED => "Empty message received",
        ERROR_NO_URL_PROVIDED => "No URL provided",
        ERROR_NO_LOGINS_FOUND => "No logins found",
        ERROR_NO_GROUPS_FOUND => "No groups found",
        ERROR_CANNOT_CREATE_NEW_GROUP => "Cannot create new group",
        ERROR_NO_VALID_UUID_PROVIDED => "No valid UUID provided",
        ERROR_ACCESS_TO_ALL_ENTRIES_DENIED => "Access to all entries denied",
        ERROR_PASSKEYS_ATTESTATION_NOT_SUPPORTED => "Attestation not supported",
        ERROR_PASSKEYS_CREDENTIAL_IS_EXCLUDED => "Credential is excluded",
        ERROR_PASSKEYS_REQUEST_CANCELED => "Passkeys request canceled",
        ERROR_PASSKEYS_INVALID_USER_VERIFICATION => "Invalid user verification",
        ERROR_PASSKEYS_EMPTY_PUBLIC_KEY => "Empty public key",
        ERROR_PASSKEYS_INVALID_URL_PROVIDED => "Invalid URL provided",
        ERROR_PASSKEYS_ORIGIN_NOT_ALLOWED => "Origin is empty or not allowed",
        ERROR_PASSKEYS_DOMAIN_IS_NOT_VALID => "Effective domain is not a valid domain",
        ERROR_PASSKEYS_DOMAIN_RPID_MISMATCH => "Origin and RP ID do not match",
        ERROR_PASSKEYS_NO_SUPPORTED_ALGORITHMS => "No supported algorithms were provided",
        ERROR_PASSKEYS_WAIT_FOR_LIFETIMER => "Wait for timer to expire",
        ERROR_PASSKEYS_UNKNOWN_ERROR => "Unknown passkeys error",
        ERROR_PASSKEYS_INVALID_CHALLENGE => "Challenge is shorter than required minimum length",
        ERROR_PASSKEYS_INVALID_USER_ID => "user.id does not match the required length",
        ERROR_CANNOT_USE_REFERENCES => "Username or password cannot contain references",
        ERROR_PASSKEYS_EVAL_BY_CREDENTIAL_NOT_SUPPORTED => "Passkeys evaluate-by-credential is not supported",
        ERROR_PASSKEYS_EVAL_BY_CREDENTIAL_NOT_EMPTY => "Passkeys evaluate-by-credential is not empty",
        ERROR_PASSKEYS_EVAL_BY_CREDENTIAL_NOT_FOUND => "Passkeys evaluate-by-credential was not found",
        HOST_ERROR_FRAME_TOO_LARGE => "Message exceeds the 1 MiB frame limit",
        HOST_ERROR_MALFORMED_FRAME => "Malformed frame",
        HOST_ERROR_UNKNOWN_HOST_ACTION => "Unknown host action",
        HOST_ERROR_HOST_INTERNAL => "Internal host error",
        HOST_ERROR_APP_UNAVAILABLE => "friendlypass is not running",
        HOST_ERROR_ENCRYPTION_REQUIRED => "Encryption required",
        _ => "Unknown error",
    }
}

/// Unencrypted error reply: same shape as the C++ `getErrorReply`.
///
/// `errorCode` is a JSON **string** and there is deliberately no nonce.
pub fn error_reply(action: &str, code: i32) -> Value {
    json!({
        "action": action,
        "errorCode": code.to_string(),
        "error": error_message(code),
    })
}

/// Host-originated error frame (§3.6): same envelope plus `hostError: true`.
pub fn host_error_reply(action: &str, code: i32, message: &str) -> Value {
    json!({
        "action": action,
        "errorCode": code.to_string(),
        "error": message,
        "hostError": true,
    })
}

/// The inner response body all successful replies share
/// (`buildMessage`: version + success + nonce), plus extra params.
pub fn build_message(nonce_b64: &str, params: &[(&str, Value)]) -> Map<String, Value> {
    let mut message = Map::new();
    message.insert("version".into(), json!(PROTOCOL_ACTION_VERSION));
    message.insert("success".into(), json!("true"));
    message.insert("nonce".into(), json!(nonce_b64));
    for (k, v) in params {
        message.insert((*k).into(), v.clone());
    }
    message
}

/// Encrypted outer response frame: `{action, message, nonce}`.
pub fn encrypted_reply(action: &str, message_b64: &str, nonce_b64: &str) -> Value {
    json!({
        "action": action,
        "message": message_b64,
        "nonce": nonce_b64,
    })
}

/// Extract a string field from a JSON object.
pub fn get_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Extract a boolean-ish protocol field (`"true"`/`"false"`, a JSON bool or a
/// number) into `bool`. Unknown/missing values are `false`.
pub fn get_bool(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::String(text)) => text.eq_ignore_ascii_case("true") || text == "1",
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_i64().is_some_and(|n| n != 0),
        _ => false,
    }
}

/// Normalise a UUID string to dashless lowercase 32-hex, if valid.
pub fn normalize_uuid(text: &str) -> Option<String> {
    let mut out = String::with_capacity(32);
    for ch in text.chars() {
        if ch == '-' {
            continue;
        }
        if ch.is_ascii_hexdigit() {
            out.push(ch.to_ascii_lowercase());
        } else {
            return None;
        }
    }
    (out.len() == 32).then_some(out)
}

/// `true` when a value references another entry (`{REF:…}`), which
/// `set-login` must reject with error 34.
pub fn has_reference(value: &str) -> bool {
    value.to_ascii_uppercase().contains("{REF:")
}

/// The browser identity reported by the native host in `host-identify` (§2).
///
/// The app only ever stores one of these when the socket peer is trusted; an
/// untrusted peer's claims are ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BrowserIdentity {
    /// `chrome` | `chromium` | `brave` | `edge` | `firefox` | `unknown`.
    pub kind: String,
    /// The host verified the browser's code signature.
    pub verified: bool,
    /// Browser executable, when the host could resolve it.
    pub executable: Option<PathBuf>,
    /// macOS team id; `None` on Linux, unsigned builds or Firefox ESR cases.
    pub team_id: Option<String>,
}

impl BrowserIdentity {
    /// The human-readable name used in association names and notices.
    pub fn display_name(&self) -> &'static str {
        Self::display_name_for_kind(&self.kind).unwrap_or("Browser")
    }

    /// Whether a display name is one of the known browser kinds (used to
    /// recognise auto-approved association names after a restart).
    pub fn display_name_for_kind(kind: &str) -> Option<&'static str> {
        match kind.to_ascii_lowercase().as_str() {
            "chrome" => Some("Chrome"),
            "chromium" => Some("Chromium"),
            "brave" => Some("Brave"),
            "edge" => Some("Edge"),
            "firefox" => Some("Firefox"),
            _ => None,
        }
    }
}

/// Parse the optional `browser` object of a `host-identify` frame. Unknown
/// kinds and unknown fields are tolerated; a missing/invalid object is `None`.
pub fn browser_identity(value: &Value) -> Option<BrowserIdentity> {
    let browser = value.get("browser")?.as_object()?;
    let kind = browser
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    let kind = if BrowserIdentity::display_name_for_kind(&kind).is_some() {
        kind
    } else {
        "unknown".to_owned()
    };
    Some(BrowserIdentity {
        kind,
        verified: browser.get("verified").is_some_and(|flag| match flag {
            Value::Bool(flag) => *flag,
            Value::String(text) => text.eq_ignore_ascii_case("true"),
            _ => false,
        }),
        executable: browser
            .get("executable")
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from),
        team_id: browser
            .get("teamId")
            .and_then(Value::as_str)
            .filter(|team| !team.is_empty())
            .map(str::to_owned),
    })
}

/// The `host-identify` reply (§2): `success` is the string `"true"` and
/// `trusted` reports this connection's peer verification (§3).
pub fn host_identify_reply(trusted: bool) -> Value {
    json!({
        "action": ACTION_HOST_IDENTIFY,
        "success": "true",
        "trusted": trusted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_strings() {
        let reply = error_reply("get-logins", ERROR_NO_LOGINS_FOUND);
        assert_eq!(reply["errorCode"], "15");
        assert!(reply.get("nonce").is_none());
    }

    #[test]
    fn message_prefix_uses_feature_gating_version() {
        let message = build_message("abc", &[("count", json!(0))]);
        assert_eq!(message["version"], "2.8.0");
        assert_eq!(message["success"], "true");
    }

    #[test]
    fn uuid_normalisation() {
        assert_eq!(
            normalize_uuid("BB710C2F-8767-61BB-9074-8CC271FF8FAE").as_deref(),
            Some("bb710c2f876761bb90748cc271ff8fae")
        );
        assert_eq!(normalize_uuid("not-a-uuid"), None);
        assert_eq!(normalize_uuid("bb710c2f876761bb90748cc271ff8fa"), None);
    }

    #[test]
    fn host_identify_reply_reports_trust() {
        let reply = host_identify_reply(false);
        assert_eq!(reply["action"], "host-identify");
        assert_eq!(reply["success"], "true");
        assert_eq!(reply["trusted"], false);
        assert_eq!(host_identify_reply(true)["trusted"], true);
    }

    #[test]
    fn browser_identity_tolerates_unknown_fields_and_kinds() {
        let identity = browser_identity(&json!({
            "action": "host-identify",
            "browser": {
                "kind": "brave",
                "verified": true,
                "executable": "/usr/bin/brave",
                "teamId": null,
                "futureField": 42,
            },
            "unknownTopLevel": true,
        }))
        .expect("identity");
        assert_eq!(identity.kind, "brave");
        assert_eq!(identity.display_name(), "Brave");
        assert!(identity.verified);
        assert_eq!(identity.executable.as_deref(), Some(std::path::Path::new("/usr/bin/brave")));
        assert_eq!(identity.team_id, None);

        let unknown = browser_identity(&json!({"browser": {"kind": "opera"}})).expect("identity");
        assert_eq!(unknown.kind, "unknown");
        assert_eq!(unknown.display_name(), "Browser");
        assert!(!unknown.verified);

        assert_eq!(browser_identity(&json!({"action": "host-identify"})), None);
        assert_eq!(browser_identity(&json!({"browser": "chrome"})), None);
    }
}
