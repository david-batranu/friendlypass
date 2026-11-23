//! Protocol crypto: X25519 keypairs, nonces, and libsodium-compatible
//! `crypto_box_easy` sealing (XSalsa20-Poly1305 with a 16-byte MAC prefix).

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use crypto_box::aead::Aead;
use crypto_box::{PublicKey, SecretKey, SalsaBox};

pub const NONCE_LEN: usize = 24;

/// An X25519 keypair (libsodium crypto_box_kx keypair equivalent).
#[derive(Clone)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub secret: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> Result<KeyPair> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)?;
        let secret_key = SecretKey::from_slice(&secret);
        if secret_key.is_err() {
            bail!("bad secret key length");
        }
        let secret_key = secret_key.unwrap();
        let public = *secret_key.public_key().as_bytes();
        Ok(KeyPair { public, secret: secret.to_vec() })
    }
}

/// A fresh random 24-byte nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    let _ = getrandom::fill(&mut nonce);
    nonce
}

/// libsodium `sodium_increment` for the 24-byte nonce: little-endian +1.
pub fn increment_nonce(nonce: &[u8]) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(nonce);
    let mut i = 0;
    while i < NONCE_LEN {
        let (v, carry) = out[i].overflowing_add(1);
        out[i] = v;
        if !carry {
            break;
        }
        i += 1;
    }
    out
}

/// Seal `plaintext` for `recipient_public` using `sender_secret`
/// (crypto_box_easy: MAC || ciphertext, base64-encoded like the protocol).
pub fn seal(recipient_public: &[u8], sender_secret: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<String> {
    let Ok(recipient) = PublicKey::from_slice(recipient_public) else {
        bail!("bad public key");
    };
    let Ok(sender) = SecretKey::from_slice(sender_secret) else {
        bail!("bad secret key");
    };
    if nonce.len() != NONCE_LEN {
        bail!("bad nonce length");
    }
    let box_ = SalsaBox::new(&recipient, &sender);
    let ciphertext = box_
        .encrypt(&crypto_box::Nonce::from_slice(nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok(B64.encode(ciphertext))
}

/// Open a base64 crypto_box_easy ciphertext.
pub fn open(sender_public: &[u8], recipient_secret: &[u8], nonce: &[u8], b64: &str) -> Result<Vec<u8>> {
    let Ok(sender) = PublicKey::from_slice(sender_public) else {
        bail!("bad public key");
    };
    let Ok(recipient) = SecretKey::from_slice(recipient_secret) else {
        bail!("bad secret key");
    };
    if nonce.len() != NONCE_LEN {
        bail!("bad nonce length");
    }
    let ciphertext = B64
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("bad base64 message: {e}"))?;
    let box_ = SalsaBox::new(&sender, &recipient);
    let plaintext = box_
        .decrypt(&crypto_box::Nonce::from_slice(nonce), ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("decryption failed"))?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_and_box_roundtrip() {
        let client = KeyPair::generate().unwrap();
        let server = KeyPair::generate().unwrap();
        let nonce = random_nonce();

        // Client -> server: sealed with server pub + client secret.
        let sealed = seal(&server.public, &client.secret, &nonce, b"hello protocol").unwrap();
        let opened = open(&client.public, &server.secret, &nonce, &sealed).unwrap();
        assert_eq!(opened, b"hello protocol");
    }

    #[test]
    fn nonce_increment_is_sodium_semantics() {
        // sodium_increment is little-endian; 0xFF -> 0x00 with carry.
        assert_eq!(increment_nonce(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])[0], 1);
        let mut n = [0u8; NONCE_LEN];
        n[0] = 0xFF;
        let inc = increment_nonce(&n);
        assert_eq!(inc[0], 0x00);
        assert_eq!(inc[1], 0x01);
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let client = KeyPair::generate().unwrap();
        let server = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let nonce = random_nonce();
        let sealed = seal(&server.public, &client.secret, &nonce, b"secret").unwrap();
        assert!(open(&other.public, &server.secret, &nonce, &sealed).is_err());
    }
}
