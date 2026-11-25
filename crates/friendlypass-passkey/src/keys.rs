//! Pure-Rust credential key generation, PKCS#8 PEM encoding and signing.
//!
//! The PEM encoding is what KeePassXC stores in `KPEX_PASSKEY_PRIVATE_KEY_PEM`
//! (Botan's `PKCS8::PEM_encode`), so keys created here load in KeePassXC and
//! keys created there sign here.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use crate::cose;
use crate::PasskeyError;

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

/// The freshly generated credential key, in every representation the caller
/// needs: the stored PEM, the COSE key for `authData`, and the SPKI DER that
/// KeePassXC reports to the extension as `response.publicKey`.
pub(crate) struct CredentialKey {
    pub(crate) private_key_pem: String,
    pub(crate) cose_public_key: Vec<u8>,
    pub(crate) spki_der: Vec<u8>,
}

pub(crate) fn generate(alg: i64) -> Result<CredentialKey, PasskeyError> {
    match alg {
        cose::ALG_ES256 => generate_es256(),
        cose::ALG_EDDSA => generate_eddsa(),
        cose::ALG_RS256 => generate_rs256(),
        other => Err(PasskeyError::UnsupportedAlgorithm(other)),
    }
}

fn generate_es256() -> Result<CredentialKey, PasskeyError> {
    let secret = p256::SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| PasskeyError::Crypto("missing EC x coordinate".into()))?;
    let y = point
        .y()
        .ok_or_else(|| PasskeyError::Crypto("missing EC y coordinate".into()))?;

    let spki_der = pkcs8::EncodePublicKey::to_public_key_der(&public)
        .map_err(|e| PasskeyError::Crypto(e.to_string()))?
        .as_bytes()
        .to_vec();
    let pem = pkcs8::EncodePrivateKey::to_pkcs8_pem(&secret, pkcs8::LineEnding::LF)
        .map_err(|e| PasskeyError::Crypto(e.to_string()))?
        .as_str()
        .to_owned();

    Ok(CredentialKey {
        private_key_pem: pem,
        cose_public_key: cose::ec2_public_key(cose::ALG_ES256, x, y),
        spki_der,
    })
}

fn generate_eddsa() -> Result<CredentialKey, PasskeyError> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let spki_der = pkcs8::EncodePublicKey::to_public_key_der(&verifying_key)
        .map_err(|e| PasskeyError::Crypto(e.to_string()))?
        .as_bytes()
        .to_vec();
    let pem = pkcs8::EncodePrivateKey::to_pkcs8_pem(&signing_key, pkcs8::LineEnding::LF)
        .map_err(|e| PasskeyError::Crypto(e.to_string()))?
        .as_str()
        .to_owned();

    Ok(CredentialKey {
        private_key_pem: pem,
        cose_public_key: cose::okp_public_key(cose::ALG_EDDSA, &verifying_key.to_bytes()),
        spki_der,
    })
}

fn generate_rs256() -> Result<CredentialKey, PasskeyError> {
    // KeePassXC uses RSA_BITS = 2048 and RSA_EXPONENT = 65537.
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|e| PasskeyError::Crypto(format!("RSA key generation failed: {e}")))?;
    let public_key = private_key.to_public_key();
    let modulus = public_key.n().to_bytes_be();
    let exponent = public_key.e().to_bytes_be();

    let spki_der = pkcs8::EncodePublicKey::to_public_key_der(&public_key)
        .map_err(|e| PasskeyError::Crypto(e.to_string()))?
        .as_bytes()
        .to_vec();
    let pem = pkcs8::EncodePrivateKey::to_pkcs8_pem(&private_key, pkcs8::LineEnding::LF)
        .map_err(|e| PasskeyError::Crypto(e.to_string()))?
        .as_str()
        .to_owned();

    Ok(CredentialKey {
        private_key_pem: pem,
        cose_public_key: cose::rsa_public_key(cose::ALG_RS256, &modulus, &exponent),
        spki_der,
    })
}

/// Signs `message` with the PKCS#8 private key stored in the entry.
///
/// The key algorithm is selected from the PKCS#8 `AlgorithmIdentifier`; any
/// other key (garbage, encrypted keys, unsupported curves or algorithms)
/// yields [`PasskeyError::InvalidKey`] instead of panicking.
pub(crate) fn sign(private_key_pem: &str, message: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    let pem = normalize_pem(private_key_pem)?;
    let (label, document) = pkcs8::SecretDocument::from_pem(&pem)
        .map_err(|e| PasskeyError::InvalidKey(e.to_string()))?;
    if label != "PRIVATE KEY" {
        return Err(PasskeyError::InvalidKey(format!(
            "expected an unencrypted PKCS#8 PRIVATE KEY, found \"{label}\""
        )));
    }

    let info = pkcs8::PrivateKeyInfo::try_from(document.as_bytes())
        .map_err(|e| PasskeyError::InvalidKey(e.to_string()))?;
    let oid = info.algorithm.oid;

    if oid == pkcs8::ObjectIdentifier::new_unwrap(OID_EC_PUBLIC_KEY) {
        let secret = p256::SecretKey::from_pkcs8_der(document.as_bytes())
            .map_err(|e| PasskeyError::InvalidKey(e.to_string()))?;
        let signing_key = p256::ecdsa::SigningKey::from(&secret);
        let signature: p256::ecdsa::Signature =
            p256::ecdsa::signature::Signer::sign(&signing_key, message);
        // ES256 signatures are ASN.1 DER encoded (r, s), as Botan's
        // "EMSA1(SHA-256)" with DerSequence produces.
        Ok(signature.to_der().as_bytes().to_vec())
    } else if oid == pkcs8::ObjectIdentifier::new_unwrap(OID_ED25519) {
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(document.as_bytes())
            .map_err(|e| PasskeyError::InvalidKey(e.to_string()))?;
        // Pure EdDSA: the message is signed directly (no pre-hash).
        let signature: ed25519_dalek::Signature =
            ed25519_dalek::Signer::sign(&signing_key, message);
        Ok(signature.to_bytes().to_vec())
    } else if oid == pkcs8::ObjectIdentifier::new_unwrap(OID_RSA_ENCRYPTION) {
        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(document.as_bytes())
            .map_err(|e| PasskeyError::InvalidKey(e.to_string()))?;
        let digest = Sha256::digest(message);
        private_key
            .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| PasskeyError::Crypto(format!("RSA signing failed: {e}")))
    } else {
        Err(PasskeyError::InvalidKey(format!(
            "unsupported private key algorithm OID {oid}"
        )))
    }
}

/// Rewrites a PKCS#8 PEM with 64-character body lines.
///
/// KeePassXC stores whatever Botan produced (64-character wrapping), but
/// imported passkey files and hand-edited entries can carry an unwrapped or
/// unevenly wrapped body. The strict PEM parser rejects lines longer than the
/// declared width, so normalise first. The stored value is never modified.
fn normalize_pem(pem: &str) -> Result<String, PasskeyError> {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";

    let invalid = |what: &str| PasskeyError::InvalidKey(what.to_owned());

    let begin = pem
        .find(BEGIN)
        .ok_or_else(|| invalid("missing PEM BEGIN line"))?;
    let label_end = pem[begin + BEGIN.len()..]
        .find("-----")
        .map(|i| begin + BEGIN.len() + i + "-----".len())
        .ok_or_else(|| invalid("malformed PEM BEGIN line"))?;
    let header = &pem[begin..label_end];

    let end = pem[label_end..]
        .find(END)
        .map(|i| label_end + i)
        .ok_or_else(|| invalid("missing PEM END line"))?;
    let footer_end = pem[end + END.len()..]
        .find("-----")
        .map(|i| end + END.len() + i + "-----".len())
        .ok_or_else(|| invalid("malformed PEM END line"))?;
    let footer = &pem[end..footer_end];

    let body: String = pem[label_end..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err(invalid("empty PEM body"));
    }

    let mut normalized = String::with_capacity(header.len() + body.len() + body.len() / 64 + 4);
    normalized.push_str(header);
    normalized.push('\n');
    for chunk in body.as_bytes().chunks(64) {
        // The body was filtered char-by-char, so it is still valid UTF-8 here;
        // base64 is ASCII anyway.
        normalized
            .push_str(std::str::from_utf8(chunk).map_err(|_| invalid("PEM body is not UTF-8"))?);
        normalized.push('\n');
    }
    normalized.push_str(footer);
    normalized.push('\n');
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_pem_wraps_unwrapped_bodies() {
        let body = "A".repeat(100);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
        let normalized = normalize_pem(&pem).unwrap();
        let lines: Vec<&str> = normalized.lines().collect();
        assert_eq!(lines[0], "-----BEGIN PRIVATE KEY-----");
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[2].len(), 36);
        assert_eq!(lines[3], "-----END PRIVATE KEY-----");
    }

    #[test]
    fn normalize_pem_wraps_single_line_pem() {
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----{}-----END PRIVATE KEY-----",
            "B".repeat(100)
        );
        assert_eq!(normalize_pem(&pem).unwrap().lines().count(), 4);
    }

    #[test]
    fn garbage_keys_are_rejected() {
        for pem in [
            "",
            "not a pem",
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(matches!(
                sign(pem, b"message"),
                Err(PasskeyError::InvalidKey(_))
            ));
        }
    }
}
