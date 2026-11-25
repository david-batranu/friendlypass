//! Minimal CBOR encoding for the WebAuthn structures KeePassXC writes.
//!
//! Only the subset needed by `attestation_object` and COSE public keys is
//! implemented. The encoder always uses the shortest definite-length form,
//! which is what `QCborStreamWriter` (used by KeePassXC's `BrowserCbor`)
//! produces, so the bytes are interchangeable.

/// COSE key type values (RFC 8152 / RFC 8230).
const COSE_KTY_OKP: i64 = 1;
const COSE_KTY_EC2: i64 = 2;
const COSE_KTY_RSA: i64 = 3;

/// COSE curve value for NIST P-256 (RFC 9053 §7.1).
const COSE_CRV_P256: i64 = 1;
/// COSE curve value for Ed25519 (RFC 9053 §7.1).
const COSE_CRV_ED25519: i64 = 6;

/// WebAuthn algorithm identifiers (RFC 8152 / RFC 8230).
pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_RS256: i64 = -257;

/// Encodes an `attestationObject` with format `none` and an empty statement:
/// `{"fmt": "none", "attStmt": {}, "authData": h'...'}`.
pub(crate) fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len() + 40);
    write_map_header(&mut out, 3);
    write_text(&mut out, "fmt");
    write_text(&mut out, "none");
    write_text(&mut out, "attStmt");
    write_map_header(&mut out, 0);
    write_text(&mut out, "authData");
    write_bytes(&mut out, auth_data);
    out
}

/// Encodes an EC2/P-256 COSE public key, matching KeePassXC's key order:
/// `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
pub(crate) fn ec2_public_key(alg: i64, x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(x.len() + y.len() + 16);
    write_map_header(&mut out, 5);
    write_int(&mut out, 1);
    write_int(&mut out, COSE_KTY_EC2);
    write_int(&mut out, 3);
    write_int(&mut out, alg);
    write_int(&mut out, -1);
    write_int(&mut out, COSE_CRV_P256);
    write_int(&mut out, -2);
    write_bytes(&mut out, x);
    write_int(&mut out, -3);
    write_bytes(&mut out, y);
    out
}

/// Encodes an OKP/Ed25519 COSE public key, matching KeePassXC's key order:
/// `{1: 1, 3: -8, -1: 6, -2: x}`.
pub(crate) fn okp_public_key(alg: i64, x: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(x.len() + 12);
    write_map_header(&mut out, 4);
    write_int(&mut out, 1);
    write_int(&mut out, COSE_KTY_OKP);
    write_int(&mut out, 3);
    write_int(&mut out, alg);
    write_int(&mut out, -1);
    write_int(&mut out, COSE_CRV_ED25519);
    write_int(&mut out, -2);
    write_bytes(&mut out, x);
    out
}

/// Encodes an RSA COSE public key, matching KeePassXC's key order:
/// `{1: 3, 3: -257, -1: n, -2: e}`.
pub(crate) fn rsa_public_key(alg: i64, modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(modulus.len() + exponent.len() + 16);
    write_map_header(&mut out, 4);
    write_int(&mut out, 1);
    write_int(&mut out, COSE_KTY_RSA);
    write_int(&mut out, 3);
    write_int(&mut out, alg);
    write_int(&mut out, -1);
    write_bytes(&mut out, modulus);
    write_int(&mut out, -2);
    write_bytes(&mut out, exponent);
    out
}

fn write_type_len(out: &mut Vec<u8>, major: u8, len: usize) {
    let major = major << 5;
    if len < 24 {
        out.push(major | len as u8);
    } else if len <= u8::MAX as usize {
        out.push(major | 24);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(major | 25);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= u32::MAX as usize {
        out.push(major | 26);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
}

fn write_map_header(out: &mut Vec<u8>, len: usize) {
    write_type_len(out, 5, len);
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_type_len(out, 2, bytes.len());
    out.extend_from_slice(bytes);
}

fn write_text(out: &mut Vec<u8>, text: &str) {
    write_type_len(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}

fn write_int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        write_type_len(out, 0, value as usize);
    } else {
        // CBOR negative integers encode -(n + 1).
        write_type_len(out, 1, (-1 - value) as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    // From KeePassXC tests/TestPasskeys.cpp::testCreatingAttestationObjectWithEC.
    const KPXC_AUTH_DATA: &str = concat!(
        "74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0",
        "5d00000000",
        "fdb141b25d84443e8a354698c205a502",
        "0020",
        "cabcc52799707294f060c39d5d29b11796f9718425a813336db53f77ea052cef",
        "a501020326200121582006ecaf345b6291616d195903a6502aca31c495a869e5",
        "f087e5d4b832cd0885dd225820e2ee7fe90f0ee91d07834a0309db4224b10bd3",
        "25ff1832e15399b71d4204e783",
    );

    const KPXC_ATTESTATION: &str = concat!(
        "a363666d74646e6f6e656761747453746d74a068617574684461746158a4",
        "74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0",
        "5d00000000fdb141b25d84443e8a354698c205a5020020cabcc52799707294f0",
        "60c39d5d29b11796f9718425a813336db53f77ea052cefa50102032620012158",
        "2006ecaf345b6291616d195903a6502aca31c495a869e5f087e5d4b832cd0885",
        "dd225820e2ee7fe90f0ee91d07834a0309db4224b10bd325ff1832e15399b7",
        "1d4204e783",
    );

    #[test]
    fn cose_ec2_matches_keepassxc_bytes() {
        let x = hex("06ecaf345b6291616d195903a6502aca31c495a869e5f087e5d4b832cd0885dd");
        let y = hex("e2ee7fe90f0ee91d07834a0309db4224b10bd325ff1832e15399b71d4204e783");
        let expected = hex(concat!(
            "a501020326200121582006ecaf345b6291616d195903a6502aca31c495a869e5",
            "f087e5d4b832cd0885dd225820e2ee7fe90f0ee91d07834a0309db4224b10bd3",
            "25ff1832e15399b71d4204e783",
        ));
        assert_eq!(ec2_public_key(ALG_ES256, &x, &y), expected);
    }

    #[test]
    fn attestation_object_matches_keepassxc_bytes() {
        assert_eq!(
            attestation_object(&hex(KPXC_AUTH_DATA)),
            hex(KPXC_ATTESTATION)
        );
    }

    #[test]
    fn okp_and_rsa_keys_use_canonical_encoding() {
        let x = [0x11u8; 32];
        assert_eq!(
            okp_public_key(ALG_EDDSA, &x),
            hex(concat!(
                "a4010103272006215820",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ))
        );

        let modulus = [0xabu8; 256];
        let key = rsa_public_key(ALG_RS256, &modulus, &[0x01, 0x00, 0x01]);
        assert_eq!(&key[..11], &hex("a401030339010020590100"));
        assert_eq!(&key[key.len() - 5..], &hex("2143010001"));
    }
}
