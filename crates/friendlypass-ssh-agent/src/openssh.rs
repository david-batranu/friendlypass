//! OpenSSH key format handling (the subset used by the SSH agent feature).
//!
//! Supported: unencrypted `ssh-ed25519` private keys in the modern
//! `-----BEGIN OPENSSH PRIVATE KEY-----` format, plus public key blobs.
//! (KeePassXC also supports RSA/ECDSA and passphrase-encrypted keys; that is
//! out of scope for this subset and documented in the README.)

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// An ssh-ed25519 identity: seed (private), public key, and a comment.
#[derive(Clone)]
pub struct SshIdentity {
    pub seed: [u8; 32],
    pub public: [u8; 32],
    /// Comment shown by `ssh-add -l` (we use the entry title).
    pub comment: String,
}

impl SshIdentity {
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    /// The public key blob as sent over the agent protocol:
    /// `string "ssh-ed25519", string pub`.
    pub fn public_blob(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(51);
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &self.public);
        blob
    }

    /// Sign `data` and return the SSH signature format:
    /// `string "ssh-ed25519", string sig`.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key().sign(data);
        let mut out = Vec::with_capacity(70);
        put_string(&mut out, b"ssh-ed25519");
        put_string(&mut out, sig.to_bytes().as_slice());
        out
    }

    /// `ssh-add -l` style fingerprint: `SHA256:<base64-nopad>`.
    pub fn fingerprint_sha256(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.public_blob());
        B64.encode(digest)
            .trim_end_matches('=')
            .to_string()
    }

    /// The `authorized_keys` / `id_ed25519.pub` one-line form.
    pub fn public_line(&self) -> String {
        format!(
            "ssh-ed25519 {} {}\n",
            B64.encode(self.public_blob()),
            self.comment
        )
    }
}

// ---------------------------------------------------------------------------
// wire primitives (big-endian)
// ---------------------------------------------------------------------------

pub fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// A reader over a big-endian SSH wire blob.
pub struct BlobReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BlobReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BlobReader { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            bail!("unexpected end of data reading u32");
        }
        let v = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            bail!("unexpected end of data reading {n} bytes");
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn read_string(&mut self) -> Result<&'a [u8]> {
        let n = self.read_u32()? as usize;
        self.read_bytes(n).context("string contents")
    }
}

// ---------------------------------------------------------------------------
// public key parsing
// ---------------------------------------------------------------------------

/// Parse a public key blob (`ssh-ed25519` only).
pub fn parse_public_blob(blob: &[u8]) -> Result<([u8; 32], String)> {
    let mut r = BlobReader::new(blob);
    let keytype = r.read_string()?;
    if keytype != b"ssh-ed25519" {
        bail!("unsupported public key type: {}", String::from_utf8_lossy(keytype));
    }
    let pub_bytes = r.read_string()?;
    if pub_bytes.len() != 32 {
        bail!("bad ed25519 public key length: {}", pub_bytes.len());
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(pub_bytes);
    Ok((public, "ssh-ed25519".to_string()))
}

// ---------------------------------------------------------------------------
// private key parsing / writing (unencrypted openssh-key-v1)
// ---------------------------------------------------------------------------

const PRIVATE_KEY_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PRIVATE_KEY_FOOTER: &str = "-----END OPENSSH PRIVATE KEY-----";

/// Is this attachment content an OpenSSH private key?
pub fn looks_like_private_key(content: &[u8]) -> bool {
    content.starts_with(PRIVATE_KEY_HEADER.as_bytes())
}

/// Parse an unencrypted OpenSSH private key (any embedded key type; only
/// `ssh-ed25519` yields an identity).
pub fn parse_private_key(content: &[u8], comment_hint: &str) -> Result<SshIdentity> {
    let text = std::str::from_utf8(content).context("private key is not valid UTF-8")?;
    let body = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(PRIVATE_KEY_HEADER) && !l.starts_with(PRIVATE_KEY_FOOTER))
        .collect::<Vec<_>>()
        .join("");
    let raw = B64
        .decode(body.as_bytes())
        .map_err(|e| anyhow!("invalid private key base64: {e}"))?;

    let mut r = BlobReader::new(&raw);
    // The magic "openssh-key-v1\0" is NOT length-prefixed (unlike the
    // strings that follow) — verified against real ssh-keygen output.
    let magic = r.read_bytes(15)?;
    if magic != b"openssh-key-v1\x00" {
        bail!("not an openssh-key-v1 private key");
    }
    let cipher = r.read_string()?;
    if cipher != b"none" {
        bail!("passphrase-encrypted private keys are not supported by this subset");
    }
    let _kdf = r.read_string()?;
    let _kdf_options = r.read_string()?;
    let nkeys = r.read_u32()?;
    if nkeys != 1 {
        bail!("expected exactly one key in the private key, found {nkeys}");
    }
    let _pubblob = r.read_string()?;
    let privsection = r.read_string()?;

    // Private section: checkint x2, keytype, key fields, comment.
    let mut p = BlobReader::new(privsection);
    let check1 = p.read_u32()?;
    let check2 = p.read_u32()?;
    if check1 != check2 {
        bail!("private key check bytes mismatch (wrong passphrase or corrupt key)");
    }
    let keytype = p.read_string()?;
    if keytype != b"ssh-ed25519" {
        bail!(
            "unsupported key type: {} (this subset serves ssh-ed25519)",
            String::from_utf8_lossy(keytype)
        );
    }
    let pub_bytes = p.read_string()?;
    if pub_bytes.len() != 32 {
        bail!("bad ed25519 public key length: {}", pub_bytes.len());
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(pub_bytes);

    // OpenSSH stores the 64-byte (seed || public) as the private key field.
    let priv_bytes = p.read_string()?;
    let seed = match priv_bytes.len() {
        32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(priv_bytes);
            s
        }
        64 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&priv_bytes[..32]);
            if &priv_bytes[32..] != public {
                bail!("private key public part does not match the key's public key");
            }
            s
        }
        n => bail!("unexpected ed25519 private key length: {n}"),
    };
    let comment = std::str::from_utf8(p.read_string().unwrap_or_default())
        .unwrap_or_default()
        .to_string();

    let signing = SigningKey::from_bytes(&seed);
    if signing.verifying_key().as_bytes() != &public {
        bail!("seed does not match the recorded public key");
    }

    Ok(SshIdentity {
        seed,
        public,
        comment: if comment.is_empty() { comment_hint.to_string() } else { comment },
    })
}

/// Write an unencrypted OpenSSH private key file for this identity.
pub fn write_private_key(identity: &SshIdentity) -> String {
    let mut pubblob = Vec::with_capacity(51);
    put_string(&mut pubblob, b"ssh-ed25519");
    put_string(&mut pubblob, &identity.public);

    let mut privsection = Vec::new();
    privsection.extend_from_slice(&0x1234_5678_u32.to_be_bytes()); // checkint
    privsection.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
    put_string(&mut privsection, b"ssh-ed25519");
    put_string(&mut privsection, &identity.public);
    // OpenSSH stores seed || public as the private field.
    let mut priv_field = identity.seed.to_vec();
    priv_field.extend_from_slice(&identity.public);
    put_string(&mut privsection, &priv_field);
    put_string(&mut privsection, identity.comment.as_bytes());
    // padding to a multiple of the block size (8)
    let block = 8;
    let pad = (block - (privsection.len() % block)) % block;
    for i in 1..=pad {
        privsection.push(i as u8);
    }

    let mut raw = Vec::new();
    raw.extend_from_slice(b"openssh-key-v1\x00"); // magic: NOT length-prefixed
    put_string(&mut raw, b"none"); // ciphername
    put_string(&mut raw, b"none"); // kdfname
    put_string(&mut raw, b""); // kdfoptions
    raw.extend_from_slice(&1_u32.to_be_bytes()); // nkeys
    put_string(&mut raw, &pubblob);
    put_string(&mut raw, &privsection);

    let b64 = B64.encode(&raw);
    let mut out = String::new();
    out.push_str(PRIVATE_KEY_HEADER);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(PRIVATE_KEY_FOOTER);
    out.push('\n');
    out
}

/// Collect SSH identities from the attachments of a database's entries
/// (KeePassXC-style: any attachment containing an OpenSSH private key).
/// Unsupported key types are skipped and reported.
pub fn collect_identities(db: &keepass::db::Database) -> (Vec<SshIdentity>, Vec<String>) {
    let mut identities = Vec::new();
    let mut skipped = Vec::new();
    for entry in db.iter_all_entries() {
        let title = entry.get("Title").unwrap_or_default().to_string();
        for (_name, attachment) in entry.attachments_named() {
            let content = attachment.data.get().clone();
            if !looks_like_private_key(&content) {
                continue;
            }
            match parse_private_key(&content, &title) {
                Ok(mut identity) => {
                    // Prefer the entry title as the comment (KeePassXC shows
                    // the entry name in `ssh-add -l`).
                    identity.comment = title.clone();
                    identities.push(identity);
                }
                Err(e) => skipped.push(format!("{title}: {e}")),
            }
        }
    }
    (identities, skipped)
}

/// Verify a signature (used by tests and the agent's self-check).
pub fn verify(public: &[u8; 32], data: &[u8], signature: &[u8]) -> bool {
    let Ok(verifying) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let mut r = BlobReader::new(signature);
    let (Ok(sigtype), Ok(sig)) = (r.read_string(), r.read_string()) else {
        return false;
    };
    if sigtype != b"ssh-ed25519" || sig.len() != 64 {
        return false;
    }
    let sig: Signature = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying.verify(data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> SshIdentity {
        use ed25519_dalek::Signer;
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing.verifying_key().as_bytes().to_owned();
        SshIdentity {
            seed: [7u8; 32],
            public,
            comment: "test entry".into(),
        }
        .clone()
    }

    #[test]
    fn write_then_parse_roundtrip() {
        let identity = test_identity();
        let pem = write_private_key(&identity);
        assert!(looks_like_private_key(pem.as_bytes()));
        let parsed = parse_private_key(pem.as_bytes(), "hint").unwrap();
        assert_eq!(parsed.seed, identity.seed);
        assert_eq!(parsed.public, identity.public);
        assert_eq!(parsed.comment, "test entry");
    }

    #[test]
    fn public_blob_and_line_roundtrip() {
        let identity = test_identity();
        let blob = identity.public_blob();
        let (public, keytype) = parse_public_blob(&blob).unwrap();
        assert_eq!(public, identity.public);
        assert_eq!(keytype, "ssh-ed25519");

        let line = identity.public_line();
        // "ssh-ed25519 <base64> test entry"
        let mut parts = line.split_whitespace();
        assert_eq!(parts.next(), Some("ssh-ed25519"));
        let b64 = parts.next().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), blob);
    }

    #[test]
    fn sign_and_verify() {
        let identity = test_identity();
        let sig = identity.sign(b"hello world");
        assert!(verify(&identity.public, b"hello world", &sig));
        assert!(!verify(&identity.public, b"tampered", &sig));
    }

    #[test]
    fn rejects_non_openssh_content() {
        assert!(!looks_like_private_key(b"just some text"));
        assert!(parse_private_key(b"-----BEGIN OPENSSH PRIVATE KEY-----\n!!!\n-----END OPENSSH PRIVATE KEY-----", "h").is_err());
    }
}
