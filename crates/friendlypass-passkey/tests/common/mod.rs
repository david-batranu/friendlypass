//! Test-only helpers: a small CBOR decoder for the structures this crate
//! emits, authenticator-data parsing, and signature verification with the
//! same pure-Rust crates the authenticator uses.
#![allow(dead_code)]

use ed25519_dalek::pkcs8::spki::SubjectPublicKeyInfoRef;
use p256::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;
pub const RS256: i64 = -257;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    UInt(u64),
    NInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

/// Decodes exactly one CBOR item and asserts there is no trailing data.
pub fn decode(bytes: &[u8]) -> Value {
    let (value, used) = decode_at(bytes, 0);
    assert_eq!(used, bytes.len(), "trailing data after CBOR item");
    value
}

fn decode_at(bytes: &[u8], pos: usize) -> (Value, usize) {
    let initial = bytes[pos];
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let (len, body) = read_len(bytes, pos, additional);

    match major {
        0 => (Value::UInt(len), body),
        1 => {
            let value = -1 - i64::try_from(len).expect("negative integer overflow");
            (Value::NInt(value), body)
        }
        2 => {
            let end = body + len as usize;
            (Value::Bytes(bytes[body..end].to_vec()), end)
        }
        3 => {
            let end = body + len as usize;
            (
                Value::Text(String::from_utf8(bytes[body..end].to_vec()).expect("CBOR text")),
                end,
            )
        }
        4 => {
            let mut items = Vec::with_capacity(len as usize);
            let mut next = body;
            for _ in 0..len {
                let (item, used) = decode_at(bytes, next);
                items.push(item);
                next = used;
            }
            (Value::Array(items), next)
        }
        5 => {
            let mut pairs = Vec::with_capacity(len as usize);
            let mut next = body;
            for _ in 0..len {
                let (key, used) = decode_at(bytes, next);
                let (value, used) = decode_at(bytes, used);
                pairs.push((key, value));
                next = used;
            }
            (Value::Map(pairs), next)
        }
        7 => match additional {
            20 => (Value::Bool(false), body),
            21 => (Value::Bool(true), body),
            22 => (Value::Null, body),
            other => panic!("unsupported CBOR simple value {other}"),
        },
        other => panic!("unsupported CBOR major type {other}"),
    }
}

fn read_len(bytes: &[u8], pos: usize, additional: u8) -> (u64, usize) {
    match additional {
        0..=23 => (additional as u64, pos + 1),
        24 => (bytes[pos + 1] as u64, pos + 2),
        25 => (
            u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as u64,
            pos + 3,
        ),
        26 => (
            u32::from_be_bytes([
                bytes[pos + 1],
                bytes[pos + 2],
                bytes[pos + 3],
                bytes[pos + 4],
            ]) as u64,
            pos + 5,
        ),
        27 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[pos + 1..pos + 9]);
            (u64::from_be_bytes(raw), pos + 9)
        }
        other => panic!("unsupported CBOR length encoding {other}"),
    }
}

impl Value {
    pub fn int_key(&self, key: i64) -> Option<&Value> {
        let Value::Map(pairs) = self else {
            return None;
        };
        pairs.iter().find_map(|(k, v)| match (k, key) {
            (Value::UInt(actual), expected) if *actual == expected as u64 => Some(v),
            (Value::NInt(actual), expected) if *actual == expected => Some(v),
            _ => None,
        })
    }

    pub fn as_int(&self) -> i64 {
        match self {
            Value::UInt(v) => *v as i64,
            Value::NInt(v) => *v,
            other => panic!("expected CBOR integer, got {other:?}"),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Value::Bytes(v) => v,
            other => panic!("expected CBOR byte string, got {other:?}"),
        }
    }

    pub fn as_text(&self) -> &str {
        match self {
            Value::Text(v) => v,
            other => panic!("expected CBOR text string, got {other:?}"),
        }
    }

    pub fn as_map(&self) -> &[(Value, Value)] {
        match self {
            Value::Map(v) => v,
            other => panic!("expected CBOR map, got {other:?}"),
        }
    }

    pub fn map_len(&self) -> usize {
        self.as_map().len()
    }
}

/// Required COSE_Key members as an easy struct for assertions.
pub struct CoseKey {
    pub kty: i64,
    pub alg: i64,
    pub crv: Option<i64>,
    pub x: Option<Vec<u8>>,
    pub y: Option<Vec<u8>>,
    pub n: Option<Vec<u8>>,
    pub e: Option<Vec<u8>>,
}

pub fn parse_cose_key(bytes: &[u8]) -> CoseKey {
    let value = decode(bytes);
    CoseKey {
        kty: value.int_key(1).expect("COSE kty").as_int(),
        alg: value.int_key(3).expect("COSE alg").as_int(),
        crv: value.int_key(-1).map(Value::as_int),
        x: value.int_key(-2).map(|v| v.as_bytes().to_vec()),
        y: value.int_key(-3).map(|v| v.as_bytes().to_vec()),
        n: None,
        e: None,
    }
}

pub fn parse_rsa_cose_key(bytes: &[u8]) -> CoseKey {
    let value = decode(bytes);
    CoseKey {
        kty: value.int_key(1).expect("COSE kty").as_int(),
        alg: value.int_key(3).expect("COSE alg").as_int(),
        crv: None,
        x: None,
        y: None,
        n: value.int_key(-1).map(|v| v.as_bytes().to_vec()),
        e: value.int_key(-2).map(|v| v.as_bytes().to_vec()),
    }
}

pub struct Attestation {
    pub fmt: String,
    pub att_stmt_is_empty_map: bool,
    pub auth_data: Vec<u8>,
}

pub fn parse_attestation(bytes: &[u8]) -> Attestation {
    let value = decode(bytes);
    let pairs = value.as_map();
    let mut fmt = None;
    let mut att_stmt_is_empty_map = false;
    let mut auth_data = None;
    for (key, value) in pairs {
        match key.as_text() {
            "fmt" => fmt = Some(value.as_text().to_owned()),
            "attStmt" => {
                att_stmt_is_empty_map = matches!(value, Value::Map(map) if map.is_empty());
            }
            "authData" => auth_data = Some(value.as_bytes().to_vec()),
            other => panic!("unexpected attestation key {other}"),
        }
    }
    Attestation {
        fmt: fmt.expect("fmt"),
        att_stmt_is_empty_map,
        auth_data: auth_data.expect("authData"),
    }
}

pub struct AuthData {
    pub rp_id_hash: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
    pub aaguid: Option<Vec<u8>>,
    pub credential_id: Option<Vec<u8>>,
    pub cose_key: Option<Vec<u8>>,
}

pub fn parse_auth_data(bytes: &[u8]) -> AuthData {
    assert!(bytes.len() >= 37, "authData shorter than 37 bytes");
    let rp_id_hash = bytes[..32].to_vec();
    let flags = bytes[32];
    let counter = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

    if flags & 0x40 != 0 {
        assert!(bytes.len() >= 55, "attested credential data truncated");
        let aaguid = bytes[37..53].to_vec();
        let cred_len = u16::from_be_bytes([bytes[53], bytes[54]]) as usize;
        let cred_end = 55 + cred_len;
        assert!(bytes.len() >= cred_end, "credential id truncated");
        AuthData {
            rp_id_hash,
            flags,
            counter,
            aaguid: Some(aaguid),
            credential_id: Some(bytes[55..cred_end].to_vec()),
            cose_key: Some(bytes[cred_end..].to_vec()),
        }
    } else {
        AuthData {
            rp_id_hash,
            flags,
            counter,
            aaguid: None,
            credential_id: None,
            cose_key: None,
        }
    }
}

pub fn verify_es256(spki_der: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der).expect("P-256 SPKI");
    let signature = match p256::ecdsa::Signature::from_der(signature_der) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    key.verify(message, &signature).is_ok()
}

pub fn verify_eddsa(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&spki_ed25519_public_key(spki_der))
        .expect("Ed25519 SPKI");
    let signature = match ed25519_dalek::Signature::from_slice(signature) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    key.verify(message, &signature).is_ok()
}

pub fn verify_rs256(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use rsa::signature::Verifier;
    let key = rsa::RsaPublicKey::from_public_key_der(spki_der).expect("RSA SPKI");
    let verifier = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key);
    let signature = match rsa::pkcs1v15::Signature::try_from(signature) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    verifier.verify(message, &signature).is_ok()
}

pub fn verify(alg: i64, spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match alg {
        ES256 => verify_es256(spki_der, message, signature),
        EDDSA => verify_eddsa(spki_der, message, signature),
        RS256 => verify_rs256(spki_der, message, signature),
        other => panic!("unexpected algorithm {other}"),
    }
}

/// The raw Ed25519 public key from a SubjectPublicKeyInfo.
pub fn spki_ed25519_public_key(spki_der: &[u8]) -> [u8; 32] {
    let info = SubjectPublicKeyInfoRef::try_from(spki_der).expect("SPKI");
    info.subject_public_key
        .raw_bytes()
        .try_into()
        .expect("32-byte Ed25519 public key")
}

pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// Uncompressed SEC1 point (`0x04 || x || y`) from a P-256 SPKI.
pub fn spki_p256_point(spki_der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der).expect("P-256 SPKI");
    let point = key.to_encoded_point(false);
    (
        point.x().expect("x").to_vec(),
        point.y().expect("y").to_vec(),
    )
}

/// RSA (modulus, exponent) from an SPKI, big-endian without leading zeros.
pub fn spki_rsa_parts(spki_der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use rsa::pkcs8::DecodePublicKey as _;
    let key = rsa::RsaPublicKey::from_public_key_der(spki_der).expect("RSA SPKI");
    (key.n().to_bytes_be(), key.e().to_bytes_be())
}

/// Decodes base64url (with or without padding) relative to the crate helper.
pub fn b64url(s: &str) -> Vec<u8> {
    friendlypass_passkey::b64url_decode(s).expect("base64url")
}
