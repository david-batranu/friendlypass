//! KeeShare **signed** shares: RSA + X.509 identities and signed share
//! containers in KeePassXC's exact format.
//!
//! A signed share (KeePassXC `.kdbx.share`) is a ZIP with two entries:
//!
//! * `container.share.kdbx` — the exported database bytes
//! * `container.share.signature` — XML:
//!   `<KeeShare><Signature>rsa|&lt;hex&gt;</Signature><Certificate>`
//!   `<Signer>NAME</Signer><Key>base64(ssh-rsa public key blob)</Key>`
//!   `</Certificate></KeeShare>`
//!
//! The signature is RSA PKCS#1 v1.5 with SHA-256 over the raw database bytes,
//! hex-encoded with the `rsa|` prefix — matching KeePassXC 2.8.0's
//! `ShareExport::signData`. The public key inside the signature file is the
//! SSH `ssh-rsa` wire blob (string "ssh-rsa", mpint e, mpint n), exactly
//! like KeePassXC's `KeeShareSettings::Sign::serialize`.
//!
//! Unlike KeePassXC 2.8.0's importer (which ignores the signature file), the
//! importer here *verifies* the signature before merging and reports the
//! signer.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::UtcTime;
use x509_cert::der::{Decode, Encode, EncodePem};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use std::str::FromStr;
use x509_cert::time::Validity;

use crate::keeshare::{self, ImportInfo};

/// File names inside a signed share container (KeePassXC's constants).
pub const CONTAINER_FILE: &str = "container.share.kdbx";
pub const SIGNATURE_FILE: &str = "container.share.signature";

/// How many bits for generated RSA keys (KeePassXC uses 2048).
const RSA_BITS: usize = 2048;

/// A signing identity: RSA keypair + a self-signed X.509 certificate.
pub struct Identity {
    pub signer: String,
    key: RsaPrivateKey,
    /// PEM-encoded self-signed X.509 certificate (CN = signer).
    pub certificate_pem: String,
}

impl Identity {
    /// Generate a new identity with a self-signed X.509 certificate.
    pub fn generate(signer: &str) -> Result<Identity> {
        let mut rng = rand_core::OsRng;
        let key = RsaPrivateKey::new(&mut rng, RSA_BITS).context("RSA key generation failed")?;
        let certificate_pem = self_signed_certificate(&key, signer)?;
        Ok(Identity {
            signer: signer.to_owned(),
            key,
            certificate_pem,
        })
    }

    /// Load an identity from PEM certificate + PKCS#8 private key files.
    pub fn from_files(cert_path: &Path, key_path: &Path, signer: &str) -> Result<Identity> {
        let certificate_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("cannot read certificate {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("cannot read private key {}", key_path.display()))?;
        let key = RsaPrivateKey::from_pkcs8_pem(&key_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&key_pem))
            .context("invalid RSA private key PEM")?;
        Ok(Identity {
            signer: signer.to_owned(),
            key,
            certificate_pem,
        })
    }

    /// Write the certificate + private key (PKCS#8 PEM) next to each other.
    pub fn save_pem(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        std::fs::write(cert_path, &self.certificate_pem)?;
        let key_pem = self
            .key
            .to_pkcs8_pem(LineEnding::LF)
            .context("cannot encode RSA key")?;
        std::fs::write(key_path, key_pem.as_bytes())?;
        Ok(())
    }

    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey::from(&self.key)
    }

    /// The SSH `ssh-rsa` public key blob (string "ssh-rsa", mpint e, mpint n).
    pub fn public_key_ssh_blob(&self) -> Vec<u8> {
        let public = self.public_key();
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-rsa");
        put_mpint(&mut blob, &public.e().to_bytes_be());
        put_mpint(&mut blob, &public.n().to_bytes_be());
        blob
    }

    /// Sign data: `rsa|<hex>` PKCS#1 v1.5 SHA-256 (KeePassXC's format).
    pub fn sign(&self, data: &[u8]) -> String {
        let signing_key = SigningKey::<Sha256>::new(self.key.clone());
        let signature: Signature = signing_key.sign(data);
        format!("rsa|{}", hex::encode(signature.to_bytes()))
    }

    /// Security fingerprint: hex SHA-256 of the SSH public key blob.
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        hex::encode(Sha256::digest(self.public_key_ssh_blob()))
    }
}

/// Default location of the signing identity (KeeShare-style config dir).
/// `KPXC_KEESHARE_DIR` overrides the base directory (used by tests).
pub fn identity_paths() -> (PathBuf, PathBuf) {
    let base = if let Some(dir) = std::env::var_os("KPXC_KEESHARE_DIR") {
        PathBuf::from(dir)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME").unwrap_or_default();
                PathBuf::from(home).join(".config")
            })
    };
    let base = base.join("kpxc").join("keeshare");
    (base.join("keeshare.crt"), base.join("keeshare.key"))
}

/// Load the local identity, generating and persisting one on first use.
pub fn load_or_create_identity(signer: &str) -> Result<Identity> {
    let (cert, key) = identity_paths();
    if cert.exists() && key.exists() {
        return Identity::from_files(&cert, &key, signer);
    }
    let identity = Identity::generate(signer)?;
    if let Some(parent) = cert.parent() {
        std::fs::create_dir_all(parent)?;
    }
    identity.save_pem(&cert, &key)?;
    Ok(identity)
}

/// Build a self-signed X.509 certificate for the RSA key (CN = signer).
fn self_signed_certificate(key: &RsaPrivateKey, signer: &str) -> Result<String> {
    let public = RsaPublicKey::from(key);
    let spki_der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&public)
        .context("cannot encode RSA public key")?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())
        .context("cannot parse SPKI")?;

    let subject = Name::from_str(&format!("CN={signer}"))
        .map_err(|e| anyhow::anyhow!("invalid signer name: {e}"))?;

    // Validity: 2020-01-01 .. 2045-01-01 (stable, self-signed trust anchor).
    let not_before = UtcTime::from_unix_duration(std::time::Duration::from_secs(1_577_836_800))
        .expect("valid time");
    let not_after = UtcTime::from_unix_duration(std::time::Duration::from_secs(2_366_841_600))
        .expect("valid time");
    let validity = Validity::from_now(std::time::Duration::from_secs(20 * 365 * 24 * 3600))
        .or_else(|_| Ok::<_, x509_cert::der::Error>(Validity {
            not_before: x509_cert::time::Time::UtcTime(not_before),
            not_after: x509_cert::time::Time::UtcTime(not_after),
        }))?;
    let _ = (not_before, not_after);

    let serial = SerialNumber::from(0x4b50_5843u64);
    let signing_key = SigningKey::<Sha256>::new(key.clone());
    let builder = CertificateBuilder::new(
        Profile::Root,
        serial,
        validity,
        subject,
        spki,
        &signing_key,
    )
    .map_err(|e| anyhow::anyhow!("cannot build certificate: {e}"))?;
    let cert = builder
        .build()
        .map_err(|e| anyhow::anyhow!("cannot sign certificate: {e}"))?;
    let pem = cert
        .to_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("cannot encode certificate PEM: {e}"))?;
    Ok(pem)
}

/// SSH wire helpers.
fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// SSH mpint: big-endian, zero-prefixed when the high bit is set.
fn put_mpint(out: &mut Vec<u8>, data: &[u8]) {
    let trimmed: &[u8] = {
        let mut start = 0;
        while start + 1 < data.len() && data[start] == 0 {
            start += 1;
        }
        &data[start..]
    };
    if trimmed.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        let mut v = vec![0u8];
        v.extend_from_slice(trimmed);
        put_string(out, &v);
    } else {
        put_string(out, trimmed);
    }
}

/// Parse an SSH `ssh-rsa` public key blob into an RSA public key.
pub fn public_key_from_ssh_blob(blob: &[u8]) -> Result<RsaPublicKey> {
    let mut pos = 0usize;
    let read_string = |pos: &mut usize| -> Result<Vec<u8>> {
        if *pos + 4 > blob.len() {
            bail!("truncated SSH blob");
        }
        let len = u32::from_be_bytes(blob[*pos..*pos + 4].try_into().unwrap()) as usize;
        *pos += 4;
        if *pos + len > blob.len() {
            bail!("truncated SSH blob string");
        }
        let out = blob[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(out)
    };
    let keytype = read_string(&mut pos)?;
    if keytype != b"ssh-rsa" {
        bail!("unsupported public key type in signature file");
    }
    let e = read_string(&mut pos)?;
    let n = read_string(&mut pos)?;
    let e = rsa::BigUint::from_bytes_be(&e);
    let n = rsa::BigUint::from_bytes_be(&n);
    RsaPublicKey::new(n, e).context("invalid RSA public key in signature file")
}

/// Serialize the signature file (KeePassXC's `Sign::serialize`).
pub fn signature_file_xml(signer: &str, public_blob: &[u8], signature: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><KeeShare><Signature>{signature}</Signature>\
         <Certificate><Signer>{signer}</Signer><Key>{}</Key></Certificate></KeeShare>",
        B64.encode(public_blob)
    )
}

/// A verified signature.
pub struct VerifiedSignature {
    pub signer: String,
    pub fingerprint: String,
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Sign `db_bytes` and write the KeePassXC-format signed ZIP container.
pub fn write_signed_container(
    path: &Path,
    db_bytes: &[u8],
    identity: &Identity,
) -> Result<()> {
    let signature = identity.sign(db_bytes);
    let signature_xml = signature_file_xml(
        &escape_xml(&identity.signer),
        &identity.public_key_ssh_blob(),
        &signature,
    );

    let file = std::fs::File::create(path)
        .with_context(|| format!("cannot create share container {}", path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    use std::io::Write;
    zip.start_file(SIGNATURE_FILE, options)?;
    zip.write_all(signature_xml.as_bytes())?;
    zip.start_file(CONTAINER_FILE, options)?;
    zip.write_all(db_bytes)?;
    zip.finish()?;
    Ok(())
}

/// Is this file a ZIP-based (signed) share container?
pub fn is_signed_container(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06")
}

/// Read a signed container: extract the DB bytes + signature file.
fn read_container(path: &Path) -> Result<(Vec<u8>, String)> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open share container {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("invalid signed share container (ZIP)")?;
    let mut db_bytes = None;
    let mut signature = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_owned();
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut data)?;
        match name.as_str() {
            CONTAINER_FILE => db_bytes = Some(data),
            SIGNATURE_FILE => {
                signature = Some(String::from_utf8(data).context("signature file is not UTF-8")?)
            }
            _ => {}
        }
    }
    match (db_bytes, signature) {
        (Some(db), Some(sig)) => Ok((db, sig)),
        _ => bail!("signed share container is missing its database or signature file"),
    }
}

/// Verify a signature file against the database bytes.
pub fn verify_signature_file(xml: &str, db_bytes: &[u8]) -> Result<VerifiedSignature> {
    let mut signature = None;
    let mut signer = None;
    let mut key_blob = None;
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut current: Option<String> = None;
    let mut buf = Vec::new();
    loop {
        use quick_xml::events::Event;
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => current = Some(e.name().as_ref().to_owned()),
            Ok(Event::Text(t)) => {
                let text = quick_xml::escape::unescape(&t).unwrap_or_default().to_string();
                match current.as_deref() {
                    Some("Signature") => signature = Some(text),
                    Some("Signer") => signer = Some(text),
                    Some("Key") => key_blob = Some(text),
                    _ => {}
                }
            }
            Ok(Event::End(_)) => current = None,
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => bail!("invalid signature file XML: {e}"),
        }
        buf.clear();
    }

    let signature = signature.context("signature file has no signature")?;
    let signer = signer.unwrap_or_default();
    let key_blob = B64
        .decode(key_blob.context("signature file has no key")?.trim())
        .context("signature key is not base64")?;

    let Some(hex_sig) = signature.strip_prefix("rsa|") else {
        bail!("unsupported signature algorithm (expected rsa|…)");
    };
    let sig_bytes = hex::decode(hex_sig).context("signature is not hex")?;
    let sig = Signature::try_from(sig_bytes.as_slice()).context("invalid RSA signature length")?;

    let public = public_key_from_ssh_blob(&key_blob)?;
    use sha2::Digest;
    let fingerprint = hex::encode(Sha256::digest(&key_blob));

    let verifying_key = VerifyingKey::<Sha256>::new(public);
    verifying_key
        .verify(db_bytes, &sig)
        .context("share signature does not match the container contents")?;

    Ok(VerifiedSignature { signer, fingerprint })
}

/// Result of a signed import.
#[derive(Debug)]
pub struct SignedImportInfo {
    pub import: ImportInfo,
    pub signer: String,
    pub fingerprint: String,
}

/// Export a group subtree as a **signed** KeeShare container
/// (`*.kdbx.share` ZIP with `container.share.kdbx` + `container.share.signature`).
pub fn export_signed(
    db: &keepass::db::Database,
    group_id: keepass::db::GroupId,
    path: &Path,
    password: &str,
    identity: &Identity,
) -> Result<crate::keeshare::ExportInfo> {
    let (bytes, info) = crate::keeshare::export_share_bytes(db, group_id, password)?;
    write_signed_container(path, &bytes, identity)?;
    Ok(crate::keeshare::ExportInfo {
        path: path.to_path_buf(),
        ..info
    })
}

/// Verify and import a signed share container into `group_id`.
pub fn import_signed(
    db: &mut keepass::db::Database,
    group_id: keepass::db::GroupId,
    path: &Path,
    password: &str,
) -> Result<SignedImportInfo> {
    let (db_bytes, signature_xml) = read_container(path)?;
    let verified = verify_signature_file(&signature_xml, &db_bytes)?;

    // Write the DB bytes to a temp file? No: parse the KDBX directly.
    let source = keepass::Database::parse(&db_bytes, keepass::DatabaseKey::new().with_password(password))
        .map_err(|e| anyhow::anyhow!("cannot read shared database (wrong password?): {e}"))?;
    let import = crate::keeshare::merge_shared_entries(db, group_id, &source)?;
    Ok(SignedImportInfo {
        import,
        signer: verified.signer,
        fingerprint: verified.fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_signs_and_verifies() {
        let identity = Identity::generate("Test Signer").unwrap();
        assert!(identity.certificate_pem.contains("BEGIN CERTIFICATE"));
        let sig = identity.sign(b"hello share");
        assert!(sig.starts_with("rsa|"));

        let xml = signature_file_xml("Test Signer", &identity.public_key_ssh_blob(), &sig);
        let verified = verify_signature_file(&xml, b"hello share").unwrap();
        assert_eq!(verified.signer, "Test Signer");
        assert_eq!(verified.fingerprint, identity.fingerprint());
        // Tampered data fails.
        assert!(verify_signature_file(&xml, b"tampered share").is_err());
    }

    #[test]
    fn signature_matches_keepassxc_shape() {
        let identity = Identity::generate("Shape").unwrap();
        let xml = signature_file_xml(
            "Shape",
            &identity.public_key_ssh_blob(),
            &identity.sign(b"data"),
        );
        assert!(xml.starts_with("<?xml version=\"1.0\"?><KeeShare><Signature>rsa|"));
        assert!(xml.contains("<Signer>Shape</Signer><Key>"));
        // The key is an ssh-rsa blob.
        let key_b64 = xml
            .split("<Key>")
            .nth(1)
            .unwrap()
            .split("</Key>")
            .next()
            .unwrap();
        let blob = B64.decode(key_b64).unwrap();
        // SSH string length prefix for "ssh-rsa" (7 bytes).
        assert!(blob.starts_with(&7u32.to_be_bytes()));
        assert!(blob[4..].starts_with(b"ssh-rsa"));
        let public = public_key_from_ssh_blob(&blob).unwrap();
        assert_eq!(public.n(), identity.public_key().n());
    }

    #[test]
    fn signed_container_zip_layout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.kdbx.share");
        let identity = Identity::generate("Layout").unwrap();
        write_signed_container(&path, b"fake database bytes", &identity).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(is_signed_container(&bytes), "ZIP magic");
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![CONTAINER_FILE.to_string(), SIGNATURE_FILE.to_string()]
        );
    }

    #[test]
    fn identity_pem_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = (dir.path().join("id.crt"), dir.path().join("id.key"));
        let identity = Identity::generate("Roundtrip").unwrap();
        identity.save_pem(&cert_path, &key_path).unwrap();
        let loaded = Identity::from_files(&cert_path, &key_path, "Roundtrip").unwrap();
        assert_eq!(loaded.public_key().n(), identity.public_key().n());
        // Cross-signature check.
        let sig = identity.sign(b"payload");
        let xml = signature_file_xml("Roundtrip", &loaded.public_key_ssh_blob(), &sig);
        assert!(verify_signature_file(&xml, b"payload").is_ok());
    }
}
