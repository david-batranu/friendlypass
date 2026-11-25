//! register -> assert round-trip for ES256, EdDSA and RS256, with independent
//! signature verification and COSE/SPKI cross-checks.

mod common;

use friendlypass_passkey::*;
use pkcs8::DecodePrivateKey;

const RP_ID: &str = "login.example.com";
const ORIGIN: &str = "https://login.example.com";

#[test]
fn register_then_assert_round_trip_for_every_algorithm() {
    for alg in [ES256, EDDSA, RS256] {
        let user_handle = b"user-handle-42".to_vec();
        let registration = register(RP_ID, "alice@example.com", &user_handle, &[alg])
            .unwrap_or_else(|e| panic!("register({alg}) failed: {e}"));

        assert_eq!(registration.algorithm, alg);
        assert_eq!(registration.credential_id.len(), CREDENTIAL_ID_LEN);

        // ---- attestation object ------------------------------------------
        let attestation = common::parse_attestation(&registration.attestation_object);
        assert_eq!(attestation.fmt, "none");
        assert!(attestation.att_stmt_is_empty_map);
        assert_eq!(attestation.auth_data, registration.authenticator_data);

        // ---- authenticator data ------------------------------------------
        let auth_data = common::parse_auth_data(&registration.authenticator_data);
        assert_eq!(auth_data.rp_id_hash, common::sha256(RP_ID.as_bytes()));
        assert_eq!(auth_data.flags, 0x5d, "UP|UV|AT|BE|BS during registration");
        assert_eq!(auth_data.counter, 0, "KeePassXC never increments counters");
        assert_eq!(auth_data.aaguid.as_deref(), Some(&[0u8; 16][..]));
        assert_eq!(
            auth_data.credential_id.as_deref(),
            Some(registration.credential_id.as_slice())
        );
        assert_eq!(
            auth_data.cose_key.as_deref(),
            Some(registration.public_key_cose.as_slice()),
            "the COSE key inside authData must be exactly the reported one"
        );

        // ---- COSE key vs SPKI DER ----------------------------------------
        match alg {
            ES256 => {
                let cose = common::parse_cose_key(&registration.public_key_cose);
                assert_eq!((cose.kty, cose.alg, cose.crv), (2, ES256, Some(1)));
                let (x, y) = common::spki_p256_point(&registration.public_key_spki_der);
                assert_eq!(x.len(), 32);
                assert_eq!(y.len(), 32);
                assert_eq!(cose.x.as_deref(), Some(x.as_slice()));
                assert_eq!(cose.y.as_deref(), Some(y.as_slice()));
            }
            EDDSA => {
                let cose = common::parse_cose_key(&registration.public_key_cose);
                assert_eq!((cose.kty, cose.alg, cose.crv), (1, EDDSA, Some(6)));
                let raw = common::spki_ed25519_public_key(&registration.public_key_spki_der);
                assert_eq!(cose.x.as_deref(), Some(raw.as_slice()));
                assert_eq!(cose.y, None);
            }
            RS256 => {
                let cose = common::parse_rsa_cose_key(&registration.public_key_cose);
                assert_eq!((cose.kty, cose.alg), (3, RS256));
                let (n, e) = common::spki_rsa_parts(&registration.public_key_spki_der);
                assert_eq!(n.len(), 256, "2048-bit RSA like KeePassXC");
                assert_eq!(e, vec![0x01, 0x00, 0x01]);
                assert_eq!(cose.n.as_deref(), Some(n.as_slice()));
                assert_eq!(cose.e.as_deref(), Some(e.as_slice()));
            }
            other => panic!("unexpected algorithm {other}"),
        }

        // ---- assertion ----------------------------------------------------
        let client_data = client_data_json("webauthn.get", b"random-challenge", ORIGIN, None);
        let client_data_hash = common::sha256(client_data.as_bytes());
        let assertion = assert(&registration.passkey, &client_data_hash)
            .unwrap_or_else(|e| panic!("assert({alg}) failed: {e}"));

        assert_eq!(assertion.credential_id, registration.credential_id);
        assert_eq!(assertion.user_handle, user_handle);

        let asserted = common::parse_auth_data(&assertion.authenticator_data);
        assert_eq!(asserted.rp_id_hash, common::sha256(RP_ID.as_bytes()));
        assert_eq!(asserted.flags, 0x1d, "UP|UV|BE|BS during assertion");
        assert_eq!(asserted.counter, 0);
        assert_eq!(asserted.aaguid, None);
        assert_eq!(asserted.credential_id, None);
        assert_eq!(asserted.cose_key, None);

        let mut signed = assertion.authenticator_data.clone();
        signed.extend_from_slice(&client_data_hash);
        assert!(
            common::verify(
                alg,
                &registration.public_key_spki_der,
                &signed,
                &assertion.signature
            ),
            "signature for algorithm {alg} must verify with the SPKI public key"
        );

        // A different client data hash must not verify.
        let other_hash = common::sha256(b"other client data");
        let mut other_signed = assertion.authenticator_data.clone();
        other_signed.extend_from_slice(&other_hash);
        assert!(!common::verify(
            alg,
            &registration.public_key_spki_der,
            &other_signed,
            &assertion.signature
        ));
    }
}

#[test]
fn assertion_flags_follow_the_stored_backup_flags() {
    let registration = register(RP_ID, "dave", b"dave-handle", &[ES256]).expect("registration");

    let mut passkey = registration.passkey.clone();
    passkey.backup_eligible = false;
    passkey.backup_state = false;
    let hash = common::sha256(b"client data");
    let assertion = assert(&passkey, &hash).unwrap();
    assert_eq!(assertion.authenticator_data[32], 0x05, "UP|UV only");

    passkey.backup_eligible = false;
    passkey.backup_state = true;
    let assertion = assert(&passkey, &hash).unwrap();
    assert_eq!(assertion.authenticator_data[32], 0x15, "UP|UV|BS");

    passkey.backup_eligible = true;
    passkey.backup_state = false;
    let assertion = assert(&passkey, &hash).unwrap();
    assert_eq!(assertion.authenticator_data[32], 0x0d, "UP|UV|BE");
}

#[test]
fn algorithm_selection_takes_the_first_supported_offer() {
    // Empty list -> ES256 (KeePassXC's default).
    let registration = register(RP_ID, "erin", b"h", &[]).unwrap();
    assert_eq!(registration.algorithm, ES256);

    // Unknown algorithms are skipped.
    let registration = register(RP_ID, "erin", b"h", &[-35, EDDSA, ES256]).unwrap();
    assert_eq!(registration.algorithm, EDDSA);

    // Nothing supported -> ES256 fallback, matching KeePassXC.
    let registration = register(RP_ID, "erin", b"h", &[-35, -36]).unwrap();
    assert_eq!(registration.algorithm, ES256);
}

#[test]
fn assert_rejects_garbage_and_mismatched_keys_without_panicking() {
    let registration = register(RP_ID, "frank", b"frank-handle", &[ES256]).unwrap();
    let hash = common::sha256(b"client data");

    let mut passkey = registration.passkey.clone();
    for pem in [
        String::new(),
        "garbage".to_owned(),
        "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n".to_owned(),
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".to_owned(),
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
            .to_owned(),
    ] {
        passkey.private_key_pem = pem.clone();
        assert!(
            matches!(assert(&passkey, &hash), Err(PasskeyError::InvalidKey(_))),
            "garbage key {pem:?} must be rejected"
        );
    }

    // A SubjectPublicKeyInfo PEM is not a private key.
    let public_pem = pkcs8::Document::try_from(registration.public_key_spki_der.as_slice())
        .unwrap()
        .to_pem("PUBLIC KEY", pkcs8::LineEnding::LF)
        .unwrap();
    passkey.private_key_pem = public_pem;
    assert!(matches!(
        assert(&passkey, &hash),
        Err(PasskeyError::InvalidKey(_))
    ));

    // A key from a different credential still signs, but never panics.
    let other = register(RP_ID, "grace", b"grace", &[EDDSA]).unwrap();
    assert!(assert(&other.passkey, &hash).is_ok());

    // Wrong client data hash length is refused.
    passkey.private_key_pem = registration.passkey.private_key_pem.clone();
    for len in [0usize, 16, 31, 33, 64] {
        assert!(matches!(
            assert(&passkey, &vec![0u8; len]),
            Err(PasskeyError::InvalidClientDataHash { len: actual }) if actual == len
        ));
    }

    // The same key is accepted after the checks.
    assert!(assert(&passkey, &hash).is_ok());
}

#[test]
fn register_rejects_an_empty_relying_party() {
    assert!(matches!(
        register("", "user", b"handle", &[ES256]),
        Err(PasskeyError::EmptyRpId)
    ));
}

#[test]
fn credential_ids_are_random_and_32_bytes() {
    let first = register(RP_ID, "user", b"handle", &[ES256]).unwrap();
    let second = register(RP_ID, "user", b"handle", &[ES256]).unwrap();
    assert_eq!(first.credential_id.len(), 32);
    assert_ne!(first.credential_id, second.credential_id);
    assert_ne!(
        first.public_key_spki_der, second.public_key_spki_der,
        "a fresh key pair must be generated for every registration"
    );
}

#[test]
fn generated_pems_are_standard_pkcs8_and_parse_without_normalisation() {
    // KeePassXC hands KPEX_PASSKEY_PRIVATE_KEY_PEM to Botan's PKCS8::load_key
    // directly, so our PEM must be well-formed PKCS#8 with 64-column wrapping.
    for alg in [ES256, EDDSA, RS256] {
        let registration = register(RP_ID, "heidi", b"heidi-handle", &[alg]).unwrap();
        let pem = &registration.passkey.private_key_pem;

        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines.first(), Some(&"-----BEGIN PRIVATE KEY-----"), "{alg}");
        assert_eq!(lines.last(), Some(&"-----END PRIVATE KEY-----"), "{alg}");
        for body in &lines[1..lines.len() - 1] {
            assert!(
                body.len() <= 64,
                "PEM body line too long for algorithm {alg}"
            );
        }

        match alg {
            ES256 => assert!(p256::SecretKey::from_pkcs8_pem(pem).is_ok()),
            EDDSA => assert!(ed25519_dalek::SigningKey::from_pkcs8_pem(pem).is_ok()),
            RS256 => assert!(rsa::RsaPrivateKey::from_pkcs8_pem(pem).is_ok()),
            other => panic!("unexpected algorithm {other}"),
        }
    }
}

#[test]
fn base64url_helpers_match_keepassxc_encoding() {
    // KeePassXC's getBase64FromArray test vector (TestPasskeys::testBase64WithHexStrings).
    let bytes: Vec<u8> = vec![
        31, 141, 30, 29, 142, 73, 5, 239, 242, 84, 187, 202, 40, 54, 15, 223, 201, 0, 108, 109,
        209, 104, 207, 239, 160, 89, 208, 117, 134, 66, 42, 12, 31, 66, 163, 248, 221, 88, 241,
        164, 6, 55, 182, 97, 186, 243, 162, 162, 81, 220, 55, 60, 93, 207, 170, 222, 56, 234, 227,
        45, 115, 175, 138, 182,
    ];
    assert_eq!(
        b64url_encode(&bytes),
        "H40eHY5JBe_yVLvKKDYP38kAbG3RaM_voFnQdYZCKgwfQqP43VjxpAY3tmG686KiUdw3PF3Pqt446uMtc6-Ktg"
    );
    assert_eq!(b64url_decode("H40eHY5JBe_yVLvKKDYP38kAbG3RaM_voFnQdYZCKgwfQqP43VjxpAY3tmG686KiUdw3PF3Pqt446uMtc6-Ktg").unwrap(), bytes);

    // Padded input is accepted too.
    assert_eq!(b64url_decode("AQI").unwrap(), vec![1, 2]);
    assert_eq!(b64url_decode("AQI=").unwrap(), vec![1, 2]);
    assert!(b64url_decode("not!base64!").is_err());
}
