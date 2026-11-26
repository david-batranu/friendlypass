//! Wire-side logic for KeePassXC-Browser's `passkeys-register` and
//! `passkeys-get` (`protocol/ACTIONS.md` §4.12).
//!
//! This is a faithful port of KeePassXC 2.8's passkey path:
//!
//! * `BrowserAction::handlePasskeysRegister` / `handlePasskeysGet` — envelope,
//!   `publicKey`/`origin` checks, and the inner `{response: …}` shape;
//! * `PasskeyUtils` (`getEffectiveDomain`, `validateRpId`,
//!   `parseCredentialTypes`, `buildClientDataJson`,
//!   `getAllowedCredentialsFromAssertionOptions`);
//! * `BrowserPasskeysClient` (`getCredentialCreationOptions`,
//!   `getAssertionOptions`) and `BrowserPasskeys`
//!   (`buildRegisterPublicKeyCredential`, `buildGetPublicKeyCredential`).
//!
//! The crypto and the `KPEX_PASSKEY_*` storage format come from
//! [`friendlypass_passkey`], which is KeePassXC-compatible and already used by
//! the Android app.
//!
//! Nothing here logs: the creation options contain a user handle, and the
//! credential object must never be stringified into a log line.

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use friendlypass_passkey::{self as pk, StoredPasskey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::protocol::*;

/// Group created for passkey entries when no default group is configured.
///
/// Existing databases may still have the upstream `KeePassXC-Browser Passkeys`
/// group; entries there are left untouched.
pub const PASSKEYS_DEFAULT_GROUP_NAME: &str = "Passkeys";
/// The tag KeePassXC adds to passkey entries.
pub const PASSKEYS_TAG: &str = "Passkey";
/// Minimum decoded challenge length (`PasskeyUtils::checkLimits`).
pub const MIN_CHALLENGE_BYTES: usize = 16;

const TRANSPORTS_INTERNAL: &str = "internal";
const TRANSPORTS_NFC: &str = "nfc";
const TRANSPORTS_USB: &str = "usb";

/// A registration request that passed KeePassXC's validation. Contains the
/// serialised `clientDataJSON` that must be signed over, so the GUI and the
/// headless bridge produce byte-identical responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRegistration {
    pub rp_id: String,
    pub rp_name: String,
    /// `user.name` (stored as `KPEX_PASSKEY_USERNAME`).
    pub username: String,
    /// `user.id` base64url without padding.
    pub user_handle_b64: String,
    /// Decoded `user.id`.
    pub user_handle: Vec<u8>,
    /// Supported algorithms in the relying party's order (ES256, EdDSA, RS256).
    pub algorithms: Vec<i64>,
    /// Credential ids the RP already has (`excludeCredentials`).
    pub exclude_credentials: Vec<Vec<u8>>,
    pub timeout: u64,
    /// The exact `webauthn.create` client data.
    pub client_data_json: Vec<u8>,
}

/// The credential created for a validated [`PreparedRegistration`].
pub struct CompletedRegistration {
    pub passkey: StoredPasskey,
    /// The `publicKeyCredential` object KeePassXC returns in `response`.
    pub credential: Value,
}

/// A sign-in request that passed KeePassXC's validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAssertion {
    pub rp_id: String,
    /// Credential ids allowed by the page (empty = discoverable credential).
    pub allow_credentials: Vec<Vec<u8>>,
    /// `true` when the page sent `allowCredentials` but none had a usable id or
    /// transport; no entry may be used then (`getPasskeyAllowedEntries`).
    pub allow_credentials_rejected: bool,
    pub timeout: u64,
    /// The exact `webauthn.get` client data.
    pub client_data_json: Vec<u8>,
}

fn error(code: i32) -> i32 {
    code
}

/// Decode a base64 value the way `BrowserMessageBuilder::getArrayFromBase64`
/// does: standard alphabet first, then the URL-safe variant (the extension
/// sends base64url for credential ids and user handles).
pub fn decode_b64(value: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

/// `PasskeyUtils::checkLimits`: challenge (≥ 16 decoded bytes) and `user.id`
/// (1–64 decoded bytes).
fn check_challenge(public_key: &Value) -> Result<Vec<u8>, i32> {
    let challenge = public_key
        .get("challenge")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let decoded = decode_b64(challenge).unwrap_or_default();
    if decoded.len() < MIN_CHALLENGE_BYTES {
        return Err(error(ERROR_PASSKEYS_INVALID_CHALLENGE));
    }
    Ok(decoded)
}

/// `PasskeyUtils::checkLimits`: challenge and, for registration, `user.id`.
fn check_limits(public_key: &Value) -> Result<Vec<u8>, i32> {
    let decoded = check_challenge(public_key)?;

    let user_id = public_key
        .get("user")
        .and_then(|user| user.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let user_id = decode_b64(user_id).unwrap_or_default();
    if user_id.is_empty() || user_id.len() > 64 {
        return Err(error(ERROR_PASSKEYS_INVALID_USER_ID));
    }
    Ok(decoded)
}

/// `PasskeyUtils::parseCredentialTypes`: keep only `public-key` entries with
/// ES256 (-7), EdDSA (-8) or RS256 (-257), in the RP's order. An empty list
/// means ES256 + RS256, like the C++ default.
fn parse_credential_types(public_key: &Value) -> Vec<i64> {
    let offered = public_key
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if offered.is_empty() {
        return vec![pk::ES256, pk::RS256];
    }
    offered
        .iter()
        .filter(|param| param.get("type").and_then(Value::as_str) == Some("public-key"))
        .filter_map(|param| param.get("alg").and_then(json_int))
        .filter(|alg| matches!(*alg, pk::ES256 | pk::EDDSA | pk::RS256))
        .collect()
}

/// JSON numbers arrive as integers; browsers may hand the extension a string.
fn json_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn is_object(value: &Value) -> bool {
    matches!(value, Value::Object(map) if !map.is_empty())
}

/// `PasskeyUtils::getEffectiveDomain`: the origin's host, rejected when it is
/// empty, not ASCII, has illegal characters, or is an IP address.
fn effective_domain(origin: &str) -> Result<String, i32> {
    if origin.is_empty() {
        return Err(error(ERROR_PASSKEYS_ORIGIN_NOT_ALLOWED));
    }
    let url = Url::parse(origin).map_err(|_| error(ERROR_PASSKEYS_DOMAIN_IS_NOT_VALID))?;
    let host = url.host_str().ok_or(error(ERROR_PASSKEYS_DOMAIN_IS_NOT_VALID))?;
    if !is_domain(host) {
        return Err(error(ERROR_PASSKEYS_DOMAIN_IS_NOT_VALID));
    }
    Ok(host.to_owned())
}

fn is_domain(host: &str) -> bool {
    if host.is_empty() || host.ends_with('.') || host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    if !host.is_ascii() {
        return false;
    }
    host.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' || ch == '_')
        && !host.starts_with('-')
        && !host.ends_with('-')
}

/// `PasskeyUtils::validateRpId`: defaults to the effective domain, otherwise
/// requires a registrable-domain suffix of it.
fn validate_rp_id(rp_id: Option<&str>, effective: &str) -> Result<String, i32> {
    match rp_id {
        None => Ok(effective.to_owned()),
        Some("") => Ok(effective.to_owned()),
        Some(value) if value == effective => Ok(effective.to_owned()),
        Some(value) => {
            let suffix = format!(".{value}");
            let is_suffix = effective.ends_with(&suffix);
            let looks_registrable = value.contains('.') && !is_public_suffix(value);
            (is_suffix && looks_registrable)
                .then(|| value.to_owned())
                .ok_or_else(|| error(ERROR_PASSKEYS_DOMAIN_RPID_MISMATCH))
        }
    }
}

/// A pragmatic public-suffix check. KeePassXC uses the full PSL; the browser
/// only ever calls this with the page's own effective domain, so rejecting the
/// obvious multi-label suffixes is enough to stop `com`/`co.uk` from being used
/// as an RP id.
fn is_public_suffix(value: &str) -> bool {
    const MULTI_LABEL: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.nz",
        "com.br", "com.cn", "github.io", "pages.dev", "workers.dev",
    ];
    !value.contains('.') || MULTI_LABEL.contains(&value.to_ascii_lowercase().as_str())
}

/// `PasskeyUtils::isOriginAllowedWithLocalhost`. `allow_localhost` mirrors
/// KeePassXC's "Allow localhost with passkeys" browser setting.
pub fn origin_allowed(origin: &str, allow_localhost: bool) -> bool {
    if origin.starts_with("https://") || (allow_localhost && origin.starts_with("file://")) {
        return true;
    }
    if !allow_localhost {
        return false;
    }
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    let host = url.host_str().unwrap_or_default();
    host == "localhost" || host == "localhost." || host.ends_with(".localhost") || host.ends_with(".localhost.")
}

fn request_rp_id(public_key: &Value, origin: &str, get: bool) -> Result<String, i32> {
    let effective = effective_domain(origin)?;
    let rp_id = if get {
        public_key.get("rpId").and_then(Value::as_str)
    } else {
        public_key
            .get("rp")
            .and_then(|rp| rp.get("id"))
            .and_then(Value::as_str)
    };
    validate_rp_id(rp_id, &effective)
}

/// `BrowserPasskeysClient::getCredentialCreationOptions` plus the RP/origin
/// checks `BrowserAction::handlePasskeysRegister` performs first.
pub fn prepare_registration(public_key: &Value, origin: &str) -> Result<PreparedRegistration, i32> {
    if !is_object(public_key) {
        return Err(error(ERROR_PASSKEYS_EMPTY_PUBLIC_KEY));
    }
    let challenge = check_limits(public_key)?;

    let rp_id = request_rp_id(public_key, origin, false)?;
    let rp_name = public_key
        .get("rp")
        .and_then(|rp| rp.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let offered = public_key
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .map(|params| params.len())
        .unwrap_or(0);
    let algorithms = parse_credential_types(public_key);
    if algorithms.is_empty() && offered > 0 {
        return Err(error(ERROR_PASSKEYS_NO_SUPPORTED_ALGORITHMS));
    }

    // `isAuthenticatorSelectionValid`: this authenticator supports resident
    // keys and user verification, so only an unknown attachment can fail.
    if let Some(attachment) = public_key
        .get("authenticatorSelection")
        .and_then(|value| value.get("authenticatorAttachment"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        if attachment != "platform" && attachment != "cross-platform" {
            return Err(error(ERROR_PASSKEYS_WAIT_FOR_LIFETIMER));
        }
    }

    let user = public_key.get("user").cloned().unwrap_or(Value::Null);
    let username = user
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let user_handle = decode_b64(
        user.get("id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .unwrap_or_default();

    let exclude_credentials = public_key
        .get("excludeCredentials")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|cred| cred.get("id").and_then(Value::as_str))
                .filter_map(decode_b64)
                .collect()
        })
        .unwrap_or_default();

    Ok(PreparedRegistration {
        rp_id,
        rp_name,
        username,
        user_handle_b64: pk::b64url_encode(&user_handle),
        user_handle,
        algorithms,
        exclude_credentials,
        timeout: public_key.get("timeout").and_then(json_int).unwrap_or(0).max(0) as u64,
        client_data_json: pk::client_data_json("webauthn.create", &challenge, origin, None).into_bytes(),
    })
}

impl PreparedRegistration {
    /// Builds KeePassXC's `BrowserPasskeys::buildRegisterPublicKeyCredential`:
    /// attestation format `none`, a random 32-byte credential id and a fresh
    /// PKCS#8 key for the first algorithm the RP offered.
    pub fn complete(&self) -> Result<CompletedRegistration, pk::PasskeyError> {
        let registration = pk::register(
            &self.rp_id,
            &self.username,
            &self.user_handle,
            &self.algorithms,
        )?;

        let credential_id_b64 = pk::b64url_encode(&registration.credential_id);
        let response = json!({
            "attestationObject": crate::b64(&registration.attestation_object),
            "clientDataJSON": crate::b64(&self.client_data_json),
            "clientExtensionResults": {},
            // Additions the extension-side wrapper reads (KeePassXC sends them).
            "authenticatorData": crate::b64(&registration.authenticator_data),
            "publicKey": crate::b64(&registration.public_key_spki_der),
            "publicKeyAlgorithm": registration.algorithm,
        });

        Ok(CompletedRegistration {
            passkey: registration.passkey,
            credential: json!({
                "authenticatorAttachment": "platform",
                "id": credential_id_b64,
                "response": response,
                "type": "public-key",
            }),
        })
    }
}

/// `BrowserPasskeysClient::getAssertionOptions` plus
/// `BrowserAction::handlePasskeysGet`.
pub fn prepare_assertion(public_key: &Value, origin: &str) -> Result<PreparedAssertion, i32> {
    if !is_object(public_key) {
        return Err(error(ERROR_PASSKEYS_EMPTY_PUBLIC_KEY));
    }
    let challenge = check_challenge(public_key)?;
    let rp_id = request_rp_id(public_key, origin, true)?;

    let allow_list: Vec<&Value> = public_key
        .get("allowCredentials")
        .and_then(Value::as_array)
        .map(|list| list.iter().collect())
        .unwrap_or_default();
    let mut allow_credentials = Vec::new();
    for cred in &allow_list {
        if cred.get("type").and_then(Value::as_str) != Some("public-key") {
            continue;
        }
        let transports = cred
            .get("transports")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let supported = transports.is_empty()
            || transports.iter().any(|transport| {
                matches!(
                    *transport,
                    TRANSPORTS_INTERNAL | TRANSPORTS_NFC | TRANSPORTS_USB
                )
            });
        let Some(id) = cred
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        if !supported {
            continue;
        }
        if let Some(decoded) = decode_b64(id) {
            allow_credentials.push(decoded);
        }
    }

    Ok(PreparedAssertion {
        rp_id,
        allow_credentials_rejected: !allow_list.is_empty() && allow_credentials.is_empty(),
        allow_credentials,
        timeout: public_key.get("timeout").and_then(json_int).unwrap_or(0).max(0) as u64,
        client_data_json: pk::client_data_json("webauthn.get", &challenge, origin, None).into_bytes(),
    })
}

impl PreparedAssertion {
    /// `getPasskeyAllowedEntries`: with `allowCredentials`, the credential id
    /// must be listed; without it, discoverable credentials need a user handle.
    pub fn matches_credential(&self, credential_id: &[u8], has_user_handle: bool) -> bool {
        if self.allow_credentials_rejected {
            return false;
        }
        if self.allow_credentials.is_empty() {
            return has_user_handle;
        }
        self.allow_credentials
            .iter()
            .any(|allowed| allowed.as_slice() == credential_id)
    }

    /// Builds the assertion for the selected entry
    /// (`BrowserPasskeys::buildGetPublicKeyCredential`).
    pub fn complete(&self, passkey: &StoredPasskey) -> Result<Value, pk::PasskeyError> {
        let client_data_hash: [u8; 32] = Sha256::digest(&self.client_data_json).into();
        let assertion = pk::assert(passkey, &client_data_hash)?;

        Ok(json!({
            "authenticatorAttachment": "platform",
            "id": pk::b64url_encode(&passkey.credential_id),
            "response": {
                "authenticatorData": crate::b64(&assertion.authenticator_data),
                "clientDataJSON": crate::b64(&self.client_data_json),
                "clientExtensionResults": {},
                "signature": crate::b64(&assertion.signature),
                "userHandle": pk::b64url_encode(&assertion.user_handle),
            },
            "type": "public-key",
        }))
    }
}

/// The error object KeePassXC nests in `response`
/// (`BrowserService::getPasskeyError`).
pub fn passkey_error(code: i32) -> Value {
    json!({ "errorCode": code })
}

/// Entry title for a new passkey (`BrowserService::addPasskeyToGroup`):
/// `"<rp.name> (Passkey)"`, falling back to the RP id.
pub fn passkey_entry_title(rp_name: &str, rp_id: &str) -> String {
    let name = if rp_name.is_empty() { rp_id } else { rp_name };
    format!("{name} ({PASSKEYS_TAG})")
}

/// The URL stored on a new passkey entry: the page origin.
pub fn passkey_entry_url(origin: &str) -> String {
    origin.trim_end_matches('/').to_owned()
}

/// KeePassXC's `Entry::hasPasskey`: any `KPEX_PASSKEY*` attribute.
pub fn has_passkey_fields<'a>(keys: impl Iterator<Item = &'a str>) -> bool {
    keys.into_iter().any(|key| key.starts_with("KPEX_PASSKEY"))
}

/// Reads a stored passkey the way KeePassXC reads entries, including the
/// StrongBox credential-id alias, then delegates to
/// [`StoredPasskey::from_fields`].
pub fn stored_passkey(get: impl Fn(&str) -> Option<String>) -> Option<StoredPasskey> {
    StoredPasskey::from_fields(&get)
}

/// `PasskeyUtils::getCredentialIdFromEntry`: the StrongBox alias wins.
pub fn credential_id_from_fields(get: impl Fn(&str) -> Option<String>) -> Option<Vec<u8>> {
    let value = get(pk::KPEX_PASSKEY_GENERATED_USER_ID)
        .or_else(|| get(pk::KPEX_PASSKEY_CREDENTIAL_ID))?;
    pk::b64url_decode(&value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64_url(bytes: &[u8]) -> String {
        pk::b64url_encode(bytes)
    }

    fn options(extra: Value) -> Value {
        let mut object = json!({
            "challenge": STANDARD.encode([7u8; 32]),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": pk::ES256},
                {"type": "public-key", "alg": pk::RS256},
            ],
            "rp": {"id": "login.example.com", "name": "Example"},
            "user": {
                "id": b64_url(b"user-handle-1"),
                "name": "alice@example.com",
                "displayName": "Alice",
            },
            "timeout": 60000,
        });
        if let Value::Object(extra) = extra {
            for (key, value) in extra {
                object[key] = value;
            }
        }
        object
    }

    #[test]
    fn registration_sets_the_rp_from_the_origin_and_defaults() {
        let prepared = prepare_registration(&options(json!({})), "https://login.example.com")
            .expect("valid options");
        assert_eq!(prepared.rp_id, "login.example.com");
        assert_eq!(prepared.rp_name, "Example");
        assert_eq!(prepared.username, "alice@example.com");
        assert_eq!(prepared.user_handle, b"user-handle-1");
        assert_eq!(prepared.user_handle_b64, b64_url(b"user-handle-1"));
        assert_eq!(prepared.algorithms, vec![pk::ES256, pk::RS256]);
        assert_eq!(
            String::from_utf8(prepared.client_data_json.clone()).unwrap(),
            format!(
                "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://login.example.com\",\"crossOrigin\":false}}",
                pk::b64url_encode(&[7u8; 32])
            )
        );
    }

    #[test]
    fn registration_validates_challenge_user_id_origin_and_rp_id() {
        let origin = "https://login.example.com";
        let mut short = options(json!({}));
        short["challenge"] = json!(STANDARD.encode([1u8; 8]));
        assert_eq!(
            prepare_registration(&short, origin),
            Err(ERROR_PASSKEYS_INVALID_CHALLENGE)
        );

        let mut no_user = options(json!({}));
        no_user["user"]["id"] = json!("");
        assert_eq!(
            prepare_registration(&no_user, origin),
            Err(ERROR_PASSKEYS_INVALID_USER_ID)
        );

        let mut long_user = options(json!({}));
        long_user["user"]["id"] = json!(b64_url(&[1u8; 65]));
        assert_eq!(
            prepare_registration(&long_user, origin),
            Err(ERROR_PASSKEYS_INVALID_USER_ID)
        );

        let mut wrong_rp = options(json!({}));
        wrong_rp["rp"]["id"] = json!("evil.example.net");
        assert_eq!(
            prepare_registration(&wrong_rp, origin),
            Err(ERROR_PASSKEYS_DOMAIN_RPID_MISMATCH)
        );

        assert_eq!(
            prepare_registration(&options(json!({})), ""),
            Err(ERROR_PASSKEYS_ORIGIN_NOT_ALLOWED)
        );
        assert_eq!(
            prepare_registration(&options(json!({})), "http://192.168.1.4:8080"),
            Err(ERROR_PASSKEYS_DOMAIN_IS_NOT_VALID)
        );

        let mut no_algs = options(json!({}));
        no_algs["pubKeyCredParams"] = json!([{"type": "public-key", "alg": -999}]);
        assert_eq!(
            prepare_registration(&no_algs, origin),
            Err(ERROR_PASSKEYS_NO_SUPPORTED_ALGORITHMS)
        );

        let mut bad_attachment = options(json!({}));
        bad_attachment["authenticatorSelection"] = json!({"authenticatorAttachment": "usb"});
        assert_eq!(
            prepare_registration(&bad_attachment, origin),
            Err(ERROR_PASSKEYS_WAIT_FOR_LIFETIMER)
        );
    }

    #[test]
    fn completed_registration_reports_spki_and_attestation_none() {
        let prepared = prepare_registration(&options(json!({})), "https://login.example.com")
            .expect("valid options");
        let completed = prepared.complete().expect("credential");
        assert_eq!(completed.credential["type"], "public-key");
        assert_eq!(completed.credential["authenticatorAttachment"], "platform");
        let response = &completed.credential["response"];
        let attestation = STANDARD
            .decode(response["attestationObject"].as_str().unwrap())
            .unwrap();
        let expected_prefix: &[u8] = &[0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e'];
        assert_eq!(&attestation[..expected_prefix.len()], expected_prefix);
        let spki = STANDARD.decode(response["publicKey"].as_str().unwrap()).unwrap();
        assert!(!spki.is_empty());
        assert_eq!(response["publicKeyAlgorithm"], pk::ES256);
        assert_eq!(completed.passkey.rp_id, "login.example.com");
        assert_eq!(completed.passkey.user_handle, b"user-handle-1");
    }

    #[test]
    fn exclude_credentials_are_parsed() {
        let credential = [9u8; 32];
        let request = options(json!({
            "excludeCredentials": [{"type": "public-key", "id": b64_url(&credential)}],
        }));
        let prepared = prepare_registration(&request, "https://login.example.com").unwrap();
        assert_eq!(prepared.exclude_credentials, vec![credential.to_vec()]);
    }

    #[test]
    fn assertion_filters_allow_credentials_like_keepassxc() {
        let id = [3u8; 32];
        let request = json!({
            "challenge": STANDARD.encode([5u8; 32]),
            "rpId": "login.example.com",
            "allowCredentials": [
                {"type": "public-key", "id": b64_url(&id), "transports": ["internal"]},
                {"type": "public-key", "id": b64_url(&[4u8; 32]), "transports": ["hybrid"]},
            ],
        });
        let prepared = prepare_assertion(&request, "https://login.example.com").unwrap();
        assert_eq!(prepared.allow_credentials, vec![id.to_vec()]);
        assert!(!prepared.allow_credentials_rejected);
        assert!(prepared.matches_credential(&id, true));

        let rejected = json!({
            "challenge": STANDARD.encode([5u8; 32]),
            "rpId": "login.example.com",
            "allowCredentials": [
                {"type": "public-key", "id": b64_url(&id), "transports": ["hybrid"]},
            ],
        });
        let prepared = prepare_assertion(&rejected, "https://login.example.com").unwrap();
        assert!(prepared.allow_credentials_rejected);
        assert!(!prepared.matches_credential(&id, true));

        let discoverable = json!({
            "challenge": STANDARD.encode([5u8; 32]),
            "rpId": "login.example.com",
        });
        let prepared = prepare_assertion(&discoverable, "https://login.example.com").unwrap();
        assert!(prepared.matches_credential(&id, true));
        assert!(!prepared.matches_credential(&id, false));
        assert!(prepared.allow_credentials.is_empty());
        assert!(!prepared.allow_credentials_rejected);
    }

    #[test]
    fn origin_allowed_matches_keepassxc_with_the_localhost_opt_in() {
        assert!(origin_allowed("https://example.com", false));
        assert!(!origin_allowed("http://example.com", false));
        assert!(!origin_allowed("http://localhost:8080", false));
        assert!(origin_allowed("http://localhost:8080", true));
        assert!(origin_allowed("http://app.localhost:3000", true));
        assert!(!origin_allowed("http://127.0.0.1:8080", true));
        assert!(!origin_allowed("", true));
    }

    #[test]
    fn entry_title_and_url_follow_keepassxc() {
        assert_eq!(
            passkey_entry_title("Example", "example.com"),
            "Example (Passkey)"
        );
        assert_eq!(passkey_entry_title("", "example.com"), "example.com (Passkey)");
        assert_eq!(passkey_entry_url("https://example.com/"), "https://example.com");
    }
}
