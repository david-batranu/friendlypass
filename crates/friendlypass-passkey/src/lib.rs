//! WebAuthn authenticator and KeePassXC passkey storage.
//!
//! This crate is deliberately storage-agnostic: it works on a field map
//! (`name -> value`), so it can sit on top of the KDBX engine, a UniFFI vault,
//! or a plain in-memory map. The field names, value encodings and protected
//! flags are exactly KeePassXC's `KPEX_PASSKEY_*` attributes
//! (`core/EntryAttributes.cpp`, `browser/BrowserService.cpp`), so a passkey
//! registered by KeePassXC can be asserted here and vice versa:
//!
//! * credential id, user handle: base64url **without** padding
//! * private key: PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`), stored protected
//! * relying party and the backup flags: plain attributes
//!
//! Attestation is `fmt: "none"` with an all-zero AAGUID, user verification and
//! presence are always asserted, and the signature counter is always 0, which
//! is what KeePassXC does (it does not implement counters).

#![forbid(unsafe_code)]

mod cose;
mod keys;

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub use cose::{ALG_EDDSA as EDDSA, ALG_ES256 as ES256, ALG_RS256 as RS256};

/// KeePassXC storage attribute names (`core/EntryAttributes.cpp`).
pub const KPEX_PASSKEY_USERNAME: &str = "KPEX_PASSKEY_USERNAME";
pub const KPEX_PASSKEY_CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub const KPEX_PASSKEY_PRIVATE_KEY_PEM: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const KPEX_PASSKEY_RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub const KPEX_PASSKEY_USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
pub const KPEX_PASSKEY_FLAG_BE: &str = "KPEX_PASSKEY_FLAG_BE";
pub const KPEX_PASSKEY_FLAG_BS: &str = "KPEX_PASSKEY_FLAG_BS";

/// Read-only aliases KeePassXC accepts for passkeys imported from other
/// managers (StrongBox writes `KPEX_PASSKEY_GENERATED_USER_ID`, KPXC writes
/// `KPXC_PASSKEY_USERNAME`). They are never written by [`StoredPasskey::to_fields`].
pub const KPEX_PASSKEY_GENERATED_USER_ID: &str = "KPEX_PASSKEY_GENERATED_USER_ID";
pub const KPXC_PASSKEY_USERNAME: &str = "KPXC_PASSKEY_USERNAME";

/// KeePassXC's credential id length (`ID_BYTES` in `BrowserPasskeys.h`).
pub const CREDENTIAL_ID_LEN: usize = 32;

/// AAGUID reported in authenticator data. The frozen Android contract requires
/// all zeros (KeePassXC advertises `fdb141b2-...`); RPs do not verify it for
/// `fmt: "none"` attestation.
pub const AAGUID: [u8; 16] = [0u8; 16];

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

/// Errors returned by this crate. No variant carries key material.
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("invalid base64url data")]
    InvalidBase64,
    #[error("unsupported WebAuthn algorithm: {0}")]
    UnsupportedAlgorithm(i64),
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("invalid client data hash: expected 32 bytes, got {len}")]
    InvalidClientDataHash { len: usize },
    #[error("empty relying party id")]
    EmptyRpId,
    #[error("random number generator failed")]
    Random,
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
}

/// A passkey as stored in an entry's attributes (KeePassXC `KPEX_PASSKEY_*`).
#[derive(Clone, PartialEq, Eq)]
pub struct StoredPasskey {
    pub credential_id: Vec<u8>,
    pub private_key_pem: String,
    pub rp_id: String,
    pub username: String,
    pub user_handle: Vec<u8>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

impl std::fmt::Debug for StoredPasskey {
    /// Redacts the private key so an accidental `{:?}` cannot leak it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredPasskey")
            .field("credential_id", &b64url_encode(&self.credential_id))
            .field("private_key_pem", &"<redacted>")
            .field("rp_id", &self.rp_id)
            .field("username", &self.username)
            .field("user_handle", &b64url_encode(&self.user_handle))
            .field("backup_eligible", &self.backup_eligible)
            .field("backup_state", &self.backup_state)
            .finish()
    }
}

/// One entry attribute. `protected` says whether the value must be stored in
/// the KDBX protected stream, matching KeePassXC's `attributes()->set(..., true)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyField {
    pub name: &'static str,
    pub value: String,
    pub protected: bool,
}

impl StoredPasskey {
    /// Reads a passkey out of an entry's attributes.
    ///
    /// Returns `None` when the entry does not carry a usable passkey: one of
    /// the required attributes is missing, the credential id or user handle is
    /// not valid base64url, or a required value is empty.
    pub fn from_fields(get: impl Fn(&str) -> Option<String>) -> Option<StoredPasskey> {
        let credential_id = b64url_decode(
            &get(KPEX_PASSKEY_CREDENTIAL_ID).or_else(|| get(KPEX_PASSKEY_GENERATED_USER_ID))?,
        )
        .ok()?;
        let private_key_pem = get(KPEX_PASSKEY_PRIVATE_KEY_PEM)?;
        let rp_id = get(KPEX_PASSKEY_RELYING_PARTY)?;
        if credential_id.is_empty() || private_key_pem.trim().is_empty() || rp_id.is_empty() {
            return None;
        }

        let username = get(KPEX_PASSKEY_USERNAME)
            .or_else(|| get(KPXC_PASSKEY_USERNAME))
            .unwrap_or_default();

        let user_handle = match get(KPEX_PASSKEY_USER_HANDLE) {
            Some(value) if !value.is_empty() => b64url_decode(&value).ok()?,
            _ => Vec::new(),
        };

        // KeePassXC defaults missing BE/BS attributes to true
        // (DEFAULT_BE_FLAG / DEFAULT_BS_FLAG) and accepts "1" or "true".
        let flag = |name: &str| match get(name) {
            Some(value) => value == "1" || value.eq_ignore_ascii_case("true"),
            None => true,
        };

        Some(StoredPasskey {
            credential_id,
            private_key_pem,
            rp_id,
            username,
            user_handle,
            backup_eligible: flag(KPEX_PASSKEY_FLAG_BE),
            backup_state: flag(KPEX_PASSKEY_FLAG_BS),
        })
    }

    /// Serialises the passkey into KeePassXC's attributes, in the order
    /// `BrowserService::addPasskeyToEntry` writes them.
    pub fn to_fields(&self) -> Vec<PasskeyField> {
        vec![
            PasskeyField {
                name: KPEX_PASSKEY_USERNAME,
                value: self.username.clone(),
                protected: false,
            },
            PasskeyField {
                name: KPEX_PASSKEY_CREDENTIAL_ID,
                value: b64url_encode(&self.credential_id),
                protected: true,
            },
            PasskeyField {
                name: KPEX_PASSKEY_PRIVATE_KEY_PEM,
                value: self.private_key_pem.clone(),
                protected: true,
            },
            PasskeyField {
                name: KPEX_PASSKEY_RELYING_PARTY,
                value: self.rp_id.clone(),
                protected: false,
            },
            PasskeyField {
                name: KPEX_PASSKEY_USER_HANDLE,
                value: b64url_encode(&self.user_handle),
                protected: true,
            },
            PasskeyField {
                name: KPEX_PASSKEY_FLAG_BE,
                value: flag_value(self.backup_eligible),
                protected: false,
            },
            PasskeyField {
                name: KPEX_PASSKEY_FLAG_BS,
                value: flag_value(self.backup_state),
                protected: false,
            },
        ]
    }
}

fn flag_value(value: bool) -> String {
    if value { "1" } else { "0" }.to_owned()
}

/// Result of a passkey registration (`navigator.credentials.create`).
#[derive(Clone, Debug)]
pub struct Registration {
    /// The credentials to persist through [`StoredPasskey::to_fields`].
    pub passkey: StoredPasskey,
    pub credential_id: Vec<u8>,
    /// `authData` with the attested credential (flags `UP|UV|AT|BE|BS`).
    pub authenticator_data: Vec<u8>,
    /// CBOR `{"fmt":"none","attStmt":{},"authData":bytes}`.
    pub attestation_object: Vec<u8>,
    /// The COSE_Key embedded in `authData`.
    pub public_key_cose: Vec<u8>,
    /// The same public key as SubjectPublicKeyInfo DER.
    pub public_key_spki_der: Vec<u8>,
    /// One of [`ES256`], [`EDDSA`], [`RS256`].
    pub algorithm: i64,
}

/// Result of a passkey assertion (`navigator.credentials.get`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    /// `authData` without attested credential data (flags `UP|UV|BE|BS`).
    pub authenticator_data: Vec<u8>,
    /// DER for ES256, raw RSA signature for RS256, 64 raw bytes for EdDSA.
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// Registers a new credential for `rp_id`.
///
/// Picks the first supported algorithm from `algorithms` in the order the
/// relying party offered them, falling back to ES256 when the list is empty
/// or contains no supported algorithm (KeePassXC does the same). Generates a
/// 32-byte credential id and a fresh PKCS#8 key, exactly like KeePassXC.
pub fn register(
    rp_id: &str,
    username: &str,
    user_handle: &[u8],
    algorithms: &[i64],
) -> Result<Registration, PasskeyError> {
    if rp_id.is_empty() {
        return Err(PasskeyError::EmptyRpId);
    }

    let algorithm = select_algorithm(algorithms);
    let key = keys::generate(algorithm)?;
    let credential_id = random_bytes::<CREDENTIAL_ID_LEN>()?.to_vec();
    let authenticator_data = registration_auth_data(rp_id, &credential_id, &key.cose_public_key);

    let passkey = StoredPasskey {
        credential_id: credential_id.clone(),
        private_key_pem: key.private_key_pem,
        rp_id: rp_id.to_owned(),
        username: username.to_owned(),
        user_handle: user_handle.to_vec(),
        backup_eligible: true,
        backup_state: true,
    };

    Ok(Registration {
        passkey,
        credential_id,
        attestation_object: cose::attestation_object(&authenticator_data),
        authenticator_data,
        public_key_cose: key.cose_public_key,
        public_key_spki_der: key.spki_der,
        algorithm,
    })
}

/// Selects the algorithm: first supported entry, otherwise ES256.
fn select_algorithm(algorithms: &[i64]) -> i64 {
    algorithms
        .iter()
        .copied()
        .find(|alg| matches!(*alg, ES256 | EDDSA | RS256))
        .unwrap_or(ES256)
}

/// Produces an assertion for `client_data_hash` (the SHA-256 of the
/// `clientDataJSON` the client built).
///
/// The stored key's algorithm is read from its PKCS#8 metadata. A missing,
/// corrupt, encrypted or unsupported key returns [`PasskeyError::InvalidKey`];
/// this function never panics on entry contents.
pub fn assert(p: &StoredPasskey, client_data_hash: &[u8]) -> Result<Assertion, PasskeyError> {
    if client_data_hash.len() != 32 {
        return Err(PasskeyError::InvalidClientDataHash {
            len: client_data_hash.len(),
        });
    }

    let authenticator_data =
        assertion_auth_data(p.rp_id.as_str(), p.backup_eligible, p.backup_state);

    let mut signed = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    signed.extend_from_slice(&authenticator_data);
    signed.extend_from_slice(client_data_hash);

    Ok(Assertion {
        credential_id: p.credential_id.clone(),
        authenticator_data,
        signature: keys::sign(&p.private_key_pem, &signed)?,
        user_handle: p.user_handle.clone(),
    })
}

/// Builds `clientDataJSON` in the WebAuthn serialization order:
/// `type, challenge, origin, crossOrigin[, androidPackageName]`.
pub fn client_data_json(
    kind: &str,
    challenge: &[u8],
    origin: &str,
    android_package: Option<&str>,
) -> String {
    let mut out = String::with_capacity(160);
    out.push_str("{\"type\":\"");
    json_escape(kind, &mut out);
    out.push_str("\",\"challenge\":\"");
    out.push_str(&b64url_encode(challenge));
    out.push_str("\",\"origin\":\"");
    json_escape(origin, &mut out);
    out.push_str("\",\"crossOrigin\":false");
    if let Some(package) = android_package {
        out.push_str(",\"androidPackageName\":\"");
        json_escape(package, &mut out);
        out.push('"');
    }
    out.push('}');
    out
}

/// base64url without padding (KeePassXC's `getBase64FromArray`).
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url with or without padding.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, PasskeyError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .map_err(|_| PasskeyError::InvalidBase64)
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

fn registration_auth_data(rp_id: &str, credential_id: &[u8], cose_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + AAGUID.len() + 2 + credential_id.len() + cose_key.len());
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE | FLAG_BS);
    out.extend_from_slice(&[0, 0, 0, 0]); // signature counter, always 0
    out.extend_from_slice(&AAGUID);
    // Credential id length is a big-endian u16, like KeePassXC's two-byte
    // {0x00, ID_BYTES}.
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(cose_key);
    out
}

fn assertion_auth_data(rp_id: &str, backup_eligible: bool, backup_state: bool) -> Vec<u8> {
    let mut flags = FLAG_UP | FLAG_UV;
    if backup_eligible {
        flags |= FLAG_BE;
    }
    if backup_state {
        flags |= FLAG_BS;
    }

    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(flags);
    out.extend_from_slice(&[0, 0, 0, 0]); // signature counter, always 0
    out
}

fn random_bytes<const N: usize>() -> Result<[u8; N], PasskeyError> {
    let mut out = [0u8; N];
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|_| PasskeyError::Random)?;
    Ok(out)
}

fn json_escape(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}
