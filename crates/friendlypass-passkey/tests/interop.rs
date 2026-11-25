//! Interoperability with KeePassXC's own test vectors (TestPasskeys.cpp).

mod common;

use friendlypass_passkey::*;

/// From `TestPasskeys::testLoadingECPrivateKeyFromPem` / `testGet`
/// (Botan generated this key, hence PKCS#8 over SEC1 ECPrivateKey).
const KPXC_EC_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5DX2R6I37nMSZqCpXfHlE3UeitkGGE03FqGsdfxIBoOhRANCAAQG7K80W2KRYW0ZWQOmUCrKMcSVqGnl8Ifl1LgyzQiF3eLuf+kPDukdB4NKAwnbQiSxC9Ml/xgy4VOZtx1CBOeD-----END PRIVATE KEY-----";

/// From `TestPasskeys::testLoadingRSAPrivateKeyFromPem`.
const KPXC_RSA_PRIVATE_KEY_PEM: &str = concat!(
    "-----BEGIN PRIVATE KEY-----MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC5OHjBHQaRfxxX\n",
    "4WHRmqq7e7JgTFRs1bd4dIOFAOZnhNE3vAg2IF5VurmeB+9ye9xh7frw8ubrL0cv\n",
    "sBWiJfN5CY3SYGRLbGTtBC0fZ6OhhhjwvVM1GW6nVeRU66atzuo4NBfYXJWIYECd\n",
    "pRBU4+xsDL4vJnn1mj05+v/Tqp6Uo1HrEPx9+DcoYJD+cw7+OQ83XeGmjD+Dtm5z\n",
    "NIyYdweaafVR4PEUlB3CYZuOq9xcpxay3ps2MuYT1zGoiQqk6flad+0tBWGY8Lwp\n",
    "CVulXCv7ljNJ4gxgQtOqWX8j2hC0hBxeqNYDYbrkECid3TsMTEMcV5uaVJXULg4t\n",
    "n6UItA11AgMBAAECggEAC3B0WBxHuieIfllOOOC4H9/7S7fDH2f7+W2cFtQ6pqo9\n",
    "Cq0WBmkYMmwXx9hpHoq4TnhhHyL9WzPzuKYD0Vx4gvacV/ckkppFScnQKJ2hF+99\n",
    "Lax1DbU+UImSknfDDFPYbYldb1CD2rpJG1i6X2fRQ6NuK+F7jE05mqcIyE+ZajK+\n",
    "Ipx8XFmE+tI1EEWsn3CzxMLiTQfXyFt/drM9iGYfcDjYY+q5vzGU3Kxj68gjc96A\n",
    "Ora79DGOmwX+4zIwo5sSzI3noHnhWPLsaRtE5jWu21Qkb+1BvBjPmbQfN274OQfy\n",
    "8/BNNR/NZM1mJm/8x4Mt+h5d946XlIo0AkyYZXY/UQKBgQDYI3G3BCwaYk6MDMeT\n",
    "IamRZo25phPtr3if47dhT2xFWJplIt35sW+6KjD6c1Qpb2aGOUh7JPmb57H54OgJ\n",
    "mojkS5tv9YEQZFfgCCZoeuqBx+ArqtJdkXOiNEFS0dpt44I+eO3Do5pnwKRemH+Y\n",
    "cqJ/eMH96UMzYDO7WNsyOyo5UQKBgQDbYU0KbGbTrMEV4T9Q41rZ2TnWzs5moqn2\n",
    "CRtB8LOdKAZUG7FRsw5KgC1CvFn3Xuk+qphYGUQeJvv7FjxMRUv4BktNpXju6eUj\n",
    "3tWHzI2QOkHaeq/XibwbNomfkdyTjtLX2+v8DBHcZnCSlukxcJISyPqZ6CnTjXGE\n",
    "EGB+itBI5QKBgQCA+gWttOusguVkZWvivL+3aH9CPXy+5WsR3o1boE13xDu+BmR3\n",
    "0A5gBTVc/t1GLJf9mMlL0vCwvD5UYoWU1YbC1OtYkCQIaBiYM8TXrCGseF2pMTJ/\n",
    "a4CZVp10ko3J7W2XYgpgKIzHRQnQ+SeLDT0y3BjHMB9N1SaJsah7/RphQQKBgQCr\n",
    "L+4yKAzFOJUjQbVqpT8Lp5qeqJofNOdzef+vIOjHxafKkiF4I0UPlZ276cY6ZfGU\n",
    "WQKwHGcvMDSI5fz/d0OksySn3mvT4uhPaV8urMv6s7sXhY0Zn/0NLy2NOwDolBar\n",
    "Io2vDKwTVEyb1u75CWKzDemfl66ryj++Uhk6JZAKkQKBgQCcNYVe7m648DzD0nu9\n",
    "3lgetBTaAS1zZmMs8Cinj44v0ksfqxrRBzBZcO9kCQqiJZ7uCAaVYcQ+PwkY+05C\n",
    "+w1+KvdGcKM+8TQYTQM3s2B9IyKExRS/dbQf9F7stJL+k5vbt6OUerwfmbNI9R3t\n",
    "gDZ4DEfopPivs9dnequ9wfaPOw==-----END PRIVATE KEY-----",
);

/// `response.signature` from `TestPasskeys::testLoadingRSAPrivateKeyFromPem`.
/// RSASSA-PKCS1-v1_5 is deterministic, so the bytes must match exactly.
const KPXC_RSA_EXPECTED_SIGNATURE: &str = concat!(
    "MOGw6KrerCgPf2mPig7FOTFIUDXYAU1v2uZj89_NgQTg2UddWnAB3JId3pa4zXghj8CkjjadVOI_LvweJGCEpmPQnRby71yFXnja6j",
    "Y3woX2b2klG2fB2alGZHHrVg6yVEmnAii4kYSdmoWxI7SmzLftoZfCJNFPFHujx2Pbr-6dIB02sZhtncetT0cpyWobtj9r7C5dIGfm",
    "J5n-LccP-F9gXGqtbN605VrIkC2WNztjdk3dAt5FGM_dlIwSe-vP1dKfIuNqAEbgr2IVZAUFn_ZfzUo-XbXTysksuz9JZfEopJBiUi",
    "9tjQDNvrYQFqB6wDPqkZAomkbRCohUb3TzCg",
);

/// The assertion `clientDataJSON` KeePassXC built in `testGet`/`testLoading*`.
const KPXC_GET_CLIENT_DATA_JSON: &str = concat!(
    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiOXozNnZUZlFUTDk1TGY3V25aZ3l0ZTdvaEdlRi1YUmlMeGtMLUx1R1Ux",
    "em9wUm1NSVVBMUxWd3pHcHlJbTFmT0JuMVFuUmEwUUgyN0FEQWFKR0h5c1EiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwi",
    "Y3Jvc3NPcmlnaW4iOmZhbHNlfQ",
);

/// The registration `clientDataJSON` KeePassXC built for `webauthn.io`.
const KPXC_CREATE_CLIENT_DATA_JSON: &str = concat!(
    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoibFZlSHpWeFdzcjhNUXhNa1pGMHRpNkZYaGRnTWxqcUt6Z0EtcV96",
    "azJNbmlpM2VKNDdWRjk3c3FVb1lrdFZDODVXQVoxdUlBU20tYV9sREZad3NMZnciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlv",
    "IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
);

const KPXC_CREDENTIAL_ID: &str = "yrzFJ5lwcpTwYMOdXSmxF5b5cYQlqBMzbbU_d-oFLO8";
const KPXC_RP_ID: &str = "webauthn.io";
const KPXC_ORIGIN: &str = "https://webauthn.io";
const KPXC_GET_CHALLENGE: &str =
    "9z36vTfQTL95Lf7WnZgyte7ohGeF-XRiLxkL-LuGU1zopRmMIUA1LVwzGpyIm1fOBn1QnRa0QH27ADAaJGHysQ";
const KPXC_CREATE_CHALLENGE: &str =
    "lVeHzVxWsr8MQxMkZF0ti6FXhdgMljqKzgA-q_zk2Mnii3eJ47VF97sqUoYktVC85WAZ1uIASm-a_lDFZwsLfw";

fn keepassxc_passkey(pem: &str, backup_eligible: bool, backup_state: bool) -> StoredPasskey {
    let mut fields = std::collections::HashMap::new();
    fields.insert(KPEX_PASSKEY_USERNAME, "Test User".to_owned());
    fields.insert(KPEX_PASSKEY_CREDENTIAL_ID, KPXC_CREDENTIAL_ID.to_owned());
    fields.insert(KPEX_PASSKEY_PRIVATE_KEY_PEM, pem.to_owned());
    fields.insert(KPEX_PASSKEY_RELYING_PARTY, KPXC_RP_ID.to_owned());
    fields.insert(KPEX_PASSKEY_USER_HANDLE, String::new());
    fields.insert(
        KPEX_PASSKEY_FLAG_BE,
        if backup_eligible { "1" } else { "0" }.to_owned(),
    );
    fields.insert(
        KPEX_PASSKEY_FLAG_BS,
        if backup_state { "1" } else { "0" }.to_owned(),
    );
    StoredPasskey::from_fields(|name| fields.get(name).cloned())
        .expect("KeePassXC field set must parse")
}

#[test]
fn client_data_json_matches_keepassxc_byte_for_byte() {
    let expected_get = String::from_utf8(common::b64url(KPXC_GET_CLIENT_DATA_JSON)).unwrap();
    let challenge = common::b64url(KPXC_GET_CHALLENGE);
    let built = client_data_json("webauthn.get", &challenge, KPXC_ORIGIN, None);
    assert_eq!(built, expected_get);
    assert_eq!(
        built,
        concat!(
            "{\"type\":\"webauthn.get\",",
            "\"challenge\":\"9z36vTfQTL95Lf7WnZgyte7ohGeF-XRiLxkL-LuGU1zopRmMIUA1LVwzGpyIm1fOBn1QnRa0QH27ADAaJGHysQ\",",
            "\"origin\":\"https://webauthn.io\",\"crossOrigin\":false}"
        )
    );

    let expected_create = String::from_utf8(common::b64url(KPXC_CREATE_CLIENT_DATA_JSON)).unwrap();
    let challenge = common::b64url(KPXC_CREATE_CHALLENGE);
    assert_eq!(
        client_data_json("webauthn.create", &challenge, KPXC_ORIGIN, None),
        expected_create
    );
}

#[test]
fn keepassxc_ec_key_assertion_verifies_and_matches_expected_auth_data() {
    let expected_client_data =
        String::from_utf8(common::b64url(KPXC_GET_CLIENT_DATA_JSON)).unwrap();
    let client_data_hash = common::sha256(expected_client_data.as_bytes());

    // testLoadingECPrivateKeyFromPem passes beFlag=false, bsFlag=false.
    let passkey = keepassxc_passkey(KPXC_EC_PRIVATE_KEY_PEM, false, false);
    let assertion = assert(&passkey, &client_data_hash).expect("KeePassXC key must sign here");

    // Byte-for-byte the authData KeePassXC's test vector uses.
    assert_eq!(
        b64url_encode(&assertion.authenticator_data),
        "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAAAA"
    );
    assert_eq!(assertion.credential_id, common::b64url(KPXC_CREDENTIAL_ID));
    assert!(assertion.user_handle.is_empty());

    // The signature (ASN.1 DER) verifies with the public key in that PEM,
    // computed independently through the p256 crate.
    let spki = ec_spki_from_pem(KPXC_EC_PRIVATE_KEY_PEM);
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&client_data_hash);
    assert!(common::verify_es256(&spki, &signed, &assertion.signature));

    // testGet uses KeePassXC's default beFlag/bsFlag (both true).
    let passkey = keepassxc_passkey(KPXC_EC_PRIVATE_KEY_PEM, true, true);
    let assertion = assert(&passkey, &client_data_hash).expect("KeePassXC key must sign here");
    assert_eq!(
        b64url_encode(&assertion.authenticator_data),
        "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAdAAAAAA"
    );
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&client_data_hash);
    assert!(common::verify_es256(&spki, &signed, &assertion.signature));
}

#[test]
fn keepassxc_rsa_key_produces_the_same_signature_bytes() {
    let expected_client_data =
        String::from_utf8(common::b64url(KPXC_GET_CLIENT_DATA_JSON)).unwrap();
    let client_data_hash = common::sha256(expected_client_data.as_bytes());

    // testLoadingRSAPrivateKeyFromPem signs this authData (flags 0x05).
    let passkey = keepassxc_passkey(KPXC_RSA_PRIVATE_KEY_PEM, false, false);
    let assertion = assert(&passkey, &client_data_hash).expect("KeePassXC RSA key must sign here");

    assert_eq!(
        b64url_encode(&assertion.authenticator_data),
        "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAAAA"
    );
    // PKCS#1 v1.5 is deterministic: the signature must be identical.
    assert_eq!(
        b64url_encode(&assertion.signature),
        KPXC_RSA_EXPECTED_SIGNATURE
    );

    let spki = rsa_spki_from_pem(KPXC_RSA_PRIVATE_KEY_PEM);
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&client_data_hash);
    assert!(common::verify_rs256(&spki, &signed, &assertion.signature));
}

/// Derives the SPKI from the KeePassXC PEM with an independent code path:
/// the base64 body is decoded directly and parsed as PKCS#8 DER, so the
/// crate's own PEM normaliser and `assert` are not involved.
fn ec_spki_from_pem(pem: &str) -> Vec<u8> {
    use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
    let key = p256::SecretKey::from_pkcs8_der(&pem_der(pem)).expect("Botan EC PKCS#8");
    key.public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn rsa_spki_from_pem(pem: &str) -> Vec<u8> {
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
    let key = rsa::RsaPrivateKey::from_pkcs8_der(&pem_der(pem)).expect("Botan RSA PKCS#8");
    key.to_public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// Decodes the base64 body between the PEM guards (the C++ test constants are
/// not wrapped at 64 columns).
fn pem_der(pem: &str) -> Vec<u8> {
    use base64::Engine as _;
    let begin = pem.find("-----BEGIN").expect("PEM begin");
    let after_begin = pem[begin + 5..]
        .find("-----")
        .map(|i| begin + 5 + i + 5)
        .expect("PEM label end");
    let end = pem[after_begin..]
        .find("-----END")
        .map(|i| after_begin + i)
        .expect("PEM end");
    let body: String = pem[after_begin..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("PEM base64")
}
