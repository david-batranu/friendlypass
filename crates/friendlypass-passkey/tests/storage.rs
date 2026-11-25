//! Field-map storage: KeePassXC attribute names, protected flags, round-trips.

mod common;

use std::collections::HashMap;

use friendlypass_passkey::*;

fn sample() -> Registration {
    register("example.com", "alice@example.com", b"user-handle", &[ES256]).unwrap()
}

fn field_map(fields: &[PasskeyField]) -> HashMap<&'static str, String> {
    fields
        .iter()
        .map(|field| (field.name, field.value.clone()))
        .collect()
}

#[test]
fn to_fields_uses_keepassxc_names_values_and_protected_flags() {
    let registration = sample();
    let fields = registration.passkey.to_fields();

    let names_and_protection: Vec<(&str, bool)> = fields
        .iter()
        .map(|field| (field.name, field.protected))
        .collect();
    assert_eq!(
        names_and_protection,
        vec![
            (KPEX_PASSKEY_USERNAME, false),
            (KPEX_PASSKEY_CREDENTIAL_ID, true),
            (KPEX_PASSKEY_PRIVATE_KEY_PEM, true),
            (KPEX_PASSKEY_RELYING_PARTY, false),
            (KPEX_PASSKEY_USER_HANDLE, true),
            (KPEX_PASSKEY_FLAG_BE, false),
            (KPEX_PASSKEY_FLAG_BS, false),
        ]
    );

    let map = field_map(&fields);
    assert_eq!(map[KPEX_PASSKEY_USERNAME], "alice@example.com");
    assert_eq!(map[KPEX_PASSKEY_RELYING_PARTY], "example.com");
    assert_eq!(map[KPEX_PASSKEY_FLAG_BE], "1");
    assert_eq!(map[KPEX_PASSKEY_FLAG_BS], "1");

    // base64url without padding, as KeePassXC's getBase64FromArray writes.
    let credential_id = &map[KPEX_PASSKEY_CREDENTIAL_ID];
    assert_eq!(credential_id, &b64url_encode(&registration.credential_id));
    assert!(!credential_id.contains('='));
    assert!(!credential_id.contains('+'));
    assert!(!credential_id.contains('/'));
    assert_eq!(map[KPEX_PASSKEY_USER_HANDLE], "dXNlci1oYW5kbGU");
    assert!(
        map[KPEX_PASSKEY_PRIVATE_KEY_PEM].starts_with("-----BEGIN PRIVATE KEY-----\n"),
        "private key must be a PKCS#8 PEM like KeePassXC stores"
    );
    assert!(map[KPEX_PASSKEY_PRIVATE_KEY_PEM]
        .trim_end()
        .ends_with("-----END PRIVATE KEY-----"));
}

#[test]
fn fields_round_trip_for_every_algorithm() {
    for alg in [ES256, EDDSA, RS256] {
        let registration = register("example.com", "bob", b"bob-handle", &[alg]).unwrap();
        let fields = registration.passkey.to_fields();
        let map = field_map(&fields);

        let restored = StoredPasskey::from_fields(|name| map.get(name).cloned())
            .expect("stored passkey should be parseable");
        assert_eq!(restored, registration.passkey, "algorithm {alg}");
        assert_eq!(restored.credential_id, registration.credential_id);
        assert!(restored.backup_eligible);
        assert!(restored.backup_state);

        // A second serialisation must be identical.
        assert_eq!(restored.to_fields(), fields);
    }
}

#[test]
fn from_fields_accepts_keepassxc_flag_spellings_and_defaults() {
    let registration = sample();
    let fields = registration.passkey.to_fields();
    let mut map = field_map(&fields);

    // KeePassXC also treats "true" as set.
    map.insert(KPEX_PASSKEY_FLAG_BE, "true".to_owned());
    map.insert(KPEX_PASSKEY_FLAG_BS, "0".to_owned());
    let restored = StoredPasskey::from_fields(|name| map.get(name).cloned()).unwrap();
    assert!(restored.backup_eligible);
    assert!(!restored.backup_state);

    // Missing flags default to true (DEFAULT_BE_FLAG / DEFAULT_BS_FLAG).
    map.remove(KPEX_PASSKEY_FLAG_BE);
    map.remove(KPEX_PASSKEY_FLAG_BS);
    let restored = StoredPasskey::from_fields(|name| map.get(name).cloned()).unwrap();
    assert!(restored.backup_eligible);
    assert!(restored.backup_state);
}

#[test]
fn from_fields_accepts_strongbox_and_kpxc_aliases() {
    let registration = sample();
    let mut map = field_map(&registration.passkey.to_fields());

    // StrongBox writes the generated user id; KeePassXC falls back to it.
    let credential_id = map.remove(KPEX_PASSKEY_CREDENTIAL_ID).unwrap();
    map.insert(KPEX_PASSKEY_GENERATED_USER_ID, credential_id);

    // Some imports only carry KPXC_PASSKEY_USERNAME.
    map.remove(KPEX_PASSKEY_USERNAME);
    map.insert(KPXC_PASSKEY_USERNAME, "imported-user".to_owned());

    let restored = StoredPasskey::from_fields(|name| map.get(name).cloned()).unwrap();
    assert_eq!(restored.credential_id, registration.credential_id);
    assert_eq!(restored.username, "imported-user");
    assert_eq!(restored.user_handle, registration.passkey.user_handle);
}

#[test]
fn from_fields_rejects_incomplete_or_corrupt_records() {
    let registration = sample();
    let complete = field_map(&registration.passkey.to_fields());

    for missing in [
        KPEX_PASSKEY_CREDENTIAL_ID,
        KPEX_PASSKEY_PRIVATE_KEY_PEM,
        KPEX_PASSKEY_RELYING_PARTY,
    ] {
        let mut map = complete.clone();
        map.remove(missing);
        assert!(
            StoredPasskey::from_fields(|name| map.get(name).cloned()).is_none(),
            "missing {missing} must not produce a passkey"
        );
    }

    for (field, value) in [
        (KPEX_PASSKEY_CREDENTIAL_ID, "not!base64!"),
        (KPEX_PASSKEY_USER_HANDLE, "not!base64!"),
        (KPEX_PASSKEY_CREDENTIAL_ID, ""),
        (KPEX_PASSKEY_PRIVATE_KEY_PEM, "   "),
        (KPEX_PASSKEY_RELYING_PARTY, ""),
    ] {
        let mut map = complete.clone();
        map.insert(field, value.to_owned());
        assert!(
            StoredPasskey::from_fields(|name| map.get(name).cloned()).is_none(),
            "{field} = {value:?} must not produce a passkey"
        );
    }

    assert!(StoredPasskey::from_fields(|_| None).is_none());
}

#[test]
fn missing_user_handle_is_an_empty_handle() {
    let registration = sample();
    let mut map = field_map(&registration.passkey.to_fields());
    map.remove(KPEX_PASSKEY_USER_HANDLE);
    let restored = StoredPasskey::from_fields(|name| map.get(name).cloned()).unwrap();
    assert!(restored.user_handle.is_empty());
}

#[test]
fn debug_does_not_reveal_the_private_key() {
    let registration = sample();
    let debug = format!("{:?}", registration.passkey);
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("BEGIN PRIVATE KEY"));
    assert!(!debug.contains(&registration.passkey.private_key_pem));
}

#[test]
fn user_handle_bytes_survive_round_trip() {
    let handle: Vec<u8> = (0..=255u8).collect();
    let registration = register("example.com", "carol", &handle, &[ES256]).unwrap();
    let map = field_map(&registration.passkey.to_fields());
    let restored = StoredPasskey::from_fields(|name| map.get(name).cloned()).unwrap();
    assert_eq!(restored.user_handle, handle);

    let client_data = client_data_json("webauthn.get", b"challenge", "https://example.com", None);
    let assertion = assert(&restored, &common::sha256(client_data.as_bytes())).unwrap();
    assert_eq!(assertion.user_handle, handle);
}
