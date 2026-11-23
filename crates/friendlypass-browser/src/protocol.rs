//! KeePassXC-Browser protocol actions, error codes, and message shaping —
//! matching KeePassXC 2.8.0's `BrowserAction`/`BrowserMessageBuilder`.

use serde_json::{json, Map, Value};

/// Supported actions.
pub const ACTION_CHANGE_PUBLIC_KEYS: &str = "change-public-keys";
pub const ACTION_GET_DATABASEHASH: &str = "get-databasehash";
pub const ACTION_ASSOCIATE: &str = "associate";
pub const ACTION_TEST_ASSOCIATE: &str = "test-associate";
pub const ACTION_GET_LOGINS: &str = "get-logins";
pub const ACTION_GENERATE_PASSWORD: &str = "generate-password";
pub const ACTION_LOCK_DATABASE: &str = "lock-database";

/// Error codes (BrowserMessageBuilder.h).
pub const ERROR_DATABASE_NOT_OPENED: i32 = 1;
pub const ERROR_DATABASE_HASH_NOT_RECEIVED: i32 = 2;
pub const ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED: i32 = 3;
pub const ERROR_CANNOT_DECRYPT_MESSAGE: i32 = 4;
pub const ERROR_CANNOT_ENCRYPT_MESSAGE: i32 = 7;
pub const ERROR_ASSOCIATION_FAILED: i32 = 8;
pub const ERROR_INCORRECT_ACTION: i32 = 12;
pub const ERROR_NO_URL_PROVIDED: i32 = 14;
pub const ERROR_NO_LOGINS_FOUND: i32 = 15;

pub fn error_message(code: i32) -> &'static str {
    match code {
        ERROR_DATABASE_NOT_OPENED => "Database not opened",
        ERROR_DATABASE_HASH_NOT_RECEIVED => "Database hash not available",
        ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED => "Client public key not received",
        ERROR_CANNOT_DECRYPT_MESSAGE => "Cannot decrypt message",
        ERROR_CANNOT_ENCRYPT_MESSAGE => "Message encryption failed.",
        ERROR_ASSOCIATION_FAILED => "KeePassXC association failed, try again",
        ERROR_INCORRECT_ACTION => "Incorrect action",
        ERROR_NO_URL_PROVIDED => "No URL provided",
        ERROR_NO_LOGINS_FOUND => "No logins found",
        _ => "Unknown error",
    }
}

/// Error reply (unencrypted): same shape as the C++ `getErrorReply`.
pub fn error_reply(action: &str, code: i32) -> Value {
    json!({
        "action": action,
        "errorCode": code.to_string(),
        "error": error_message(code),
    })
}

/// The inner response body all successful replies share
/// (`buildMessage`: version + success + nonce), plus extra params.
pub fn build_message(nonce_b64: &str, params: &[(&str, Value)]) -> Map<String, Value> {
    let mut message = Map::new();
    message.insert("version".into(), json!("2.8.0-RS"));
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
