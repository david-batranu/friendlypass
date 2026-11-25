//! End-to-end tests for the UniFFI vault surface, driven the same way Kotlin
//! drives it: KDBX bytes in, records out, bytes back.
//!
//! Fixtures and passwords are the public values from the repository README:
//! `sample4.kdbx` / `sample4_keyfile.kdbx` use `testpassword`,
//! `sample4.keyx` is the matching key file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use friendlypass_mobile::{
    open_vault, NewLogin, PasskeyCreateRequest, PasskeyRegistration, Vault, VaultError,
};
use friendlypass_passkey::{
    KPEX_PASSKEY_CREDENTIAL_ID, KPEX_PASSKEY_FLAG_BE, KPEX_PASSKEY_FLAG_BS,
    KPEX_PASSKEY_PRIVATE_KEY_PEM, KPEX_PASSKEY_RELYING_PARTY, KPEX_PASSKEY_USERNAME,
    KPEX_PASSKEY_USER_HANDLE,
};
use keepass::config::{DatabaseVersion, InnerCipherConfig};
use keepass::db::{fields, Database, TOTP};
use keepass::DatabaseKey;
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).expect("fixture readable")
}

fn open_sample4() -> Arc<Vault> {
    open_vault(
        fixture("sample4.kdbx"),
        Some("testpassword".to_owned()),
        None,
    )
    .expect("sample4 opens with its documented password")
}

fn expect_invalid_credentials(result: Result<Arc<Vault>, VaultError>) {
    match result {
        Err(VaultError::InvalidCredentials) => {}
        Err(other) => panic!("expected InvalidCredentials, got {other:?}"),
        Ok(_) => panic!("expected the open to fail"),
    }
}

fn summary_uuid(vault: &Vault, title: &str) -> String {
    vault
        .all_entries()
        .into_iter()
        .find(|entry| entry.title == title)
        .unwrap_or_else(|| panic!("entry {title:?} exists"))
        .uuid
}

#[test]
fn wrong_password_is_invalid_credentials() {
    expect_invalid_credentials(open_vault(
        fixture("sample4.kdbx"),
        Some("not-the-password".to_owned()),
        None,
    ));
}

#[test]
fn keyfile_database_opens_with_password_and_keyfile() {
    let vault = open_vault(
        fixture("sample4_keyfile.kdbx"),
        Some("testpassword".to_owned()),
        Some(fixture("sample4.keyx")),
    )
    .expect("password + XML v2 keyfile opens");

    let titles: Vec<String> = vault
        .all_entries()
        .into_iter()
        .map(|entry| entry.title)
        .collect();
    assert_eq!(titles, vec!["Keyfile Entry"]);
    let entry = vault.entry(summary_uuid(&vault, "Keyfile Entry")).unwrap();
    assert_eq!(entry.summary.username, "kfuser");
}

#[test]
fn keyfile_database_without_the_keyfile_is_invalid_credentials() {
    expect_invalid_credentials(open_vault(
        fixture("sample4_keyfile.kdbx"),
        Some("testpassword".to_owned()),
        None,
    ));
}

#[test]
fn groups_entries_and_search() {
    let vault = open_sample4();
    let root_uuid = vault.root_group_uuid();

    let groups = vault.groups();
    let names: Vec<&str> = groups.iter().map(|group| group.name.as_str()).collect();
    assert_eq!(names, vec!["Passwords", "Web", "Bank"]);
    assert_eq!(groups[0].uuid, root_uuid);
    assert_eq!(groups[0].parent_uuid, None);
    let web = groups.iter().find(|group| group.name == "Web").unwrap();
    assert_eq!(web.parent_uuid.as_deref(), Some(root_uuid.as_str()));
    assert_eq!(web.entry_count, 0);

    let root_entries = vault.entries_in_group(root_uuid.clone());
    assert_eq!(
        root_entries
            .iter()
            .map(|entry| entry.title.as_str())
            .collect::<Vec<_>>(),
        vec!["Sample Entry", "Web Login"]
    );
    assert!(root_entries.iter().all(|entry| entry.group_path == "Root"));

    assert!(vault.entries_in_group(web.uuid.clone()).is_empty());

    let all: Vec<String> = vault
        .all_entries()
        .into_iter()
        .map(|entry| entry.title)
        .collect();
    assert_eq!(all, vec!["Sample Entry", "Web Login"]);

    let search = vault.search("WEB".to_owned());
    assert_eq!(search.len(), 1);
    assert_eq!(search[0].title, "Web Login");

    let search = vault.search("user@example".to_owned());
    assert_eq!(search.len(), 1);
    assert_eq!(search[0].title, "Sample Entry");

    assert!(vault.search("no-such-entry".to_owned()).is_empty());
    assert!(vault.entries_in_group("not-a-uuid".to_owned()).is_empty());
    assert!(vault
        .groups()
        .iter()
        .all(|group| group.name != "Recycle Bin"));
}

#[test]
fn entry_detail_returns_fields_and_flags() {
    let vault = open_sample4();
    let uuid = summary_uuid(&vault, "Sample Entry");
    let detail = vault.entry(uuid.clone()).unwrap();

    assert_eq!(detail.summary.uuid, uuid);
    assert_eq!(detail.summary.title, "Sample Entry");
    assert_eq!(detail.summary.username, "user@example.com");
    assert_eq!(detail.summary.url, "https://example.com");
    assert_eq!(detail.summary.group_path, "Root");
    assert!(!detail.summary.has_totp);
    assert!(!detail.summary.has_passkey);

    assert_eq!(detail.notes, "some notes");
    assert_eq!(detail.password.len(), 20);
    assert!(detail
        .password
        .chars()
        .all(|character| character.is_ascii_alphanumeric()));
    assert_eq!(detail.urls, vec!["https://example.com"]);
    assert!(detail.android_apps.is_empty());
    assert!(detail.tags.is_empty());

    let web = vault.entry(summary_uuid(&vault, "Web Login")).unwrap();
    assert_eq!(web.summary.username, "webuser");
    assert_eq!(web.summary.url, "https://web.example.org");
    assert_eq!(web.notes, "web note");
    assert_eq!(web.urls, vec!["https://web.example.org"]);

    assert!(matches!(
        vault.entry("ffffffffffffffffffffffffffffffff".to_owned()),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        vault.entry("garbage".to_owned()),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn totp_uses_the_requested_time() {
    // RFC 6238 SHA-1 vector: secret "12345678901234567890", 8 digits,
    // T=59 -> 94287082 (same vector the GUI's TOTP test uses).
    let mut database = Database::new();
    database.config.version = DatabaseVersion::KDB4(1);
    database.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    {
        let mut root = database.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "TOTP Entry");
        entry.set_unprotected(
            fields::OTP,
            "otpauth://totp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1",
        );
    }
    let mut bytes = Vec::new();
    database
        .save(&mut bytes, DatabaseKey::new().with_password("pw"))
        .expect("test database saves");

    let vault = open_vault(bytes, Some("pw".to_owned()), None).expect("created database opens");
    let uuid = summary_uuid(&vault, "TOTP Entry");
    assert!(vault.all_entries()[0].has_totp);

    let code = vault.totp(uuid.clone(), 59).expect("TOTP entry has a code");
    assert_eq!(code.code, "94287082");
    assert_eq!(code.period_secs, 30);
    assert_eq!(code.remaining_secs, 1);

    // The same secret with the usual six digits at T=59.
    let six_digit: TOTP =
        "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30"
            .parse()
            .unwrap();
    assert_eq!(six_digit.value_at(59).code, "287082");

    assert!(vault.totp(summary_uuid(&vault, "TOTP Entry"), 60).is_some());
    assert!(vault
        .totp("ffffffffffffffffffffffffffffffff".to_owned(), 59)
        .is_none());
}

#[test]
fn match_web_finds_the_fixture_entry() {
    let vault = open_sample4();

    let matches = vault.match_web("https://web.example.org".to_owned());
    assert_eq!(
        matches.first().map(|entry| entry.title.as_str()),
        Some("Web Login")
    );

    let matches = vault.match_web("https://web.example.org/login".to_owned());
    assert_eq!(
        matches.first().map(|entry| entry.title.as_str()),
        Some("Web Login")
    );

    let matches = vault.match_web("https://example.com".to_owned());
    assert_eq!(
        matches.first().map(|entry| entry.title.as_str()),
        Some("Sample Entry")
    );

    assert!(vault
        .match_web("https://unrelated.invalid".to_owned())
        .is_empty());
}

#[test]
fn add_login_saves_and_reopens() {
    let vault = open_sample4();
    assert!(!vault.is_modified());

    let uuid = vault
        .add_login(NewLogin {
            title: "App Login".to_owned(),
            username: "appuser".to_owned(),
            password: "app-secret".to_owned(),
            url: Some("https://app.example.com".to_owned()),
            android_app: Some("com.example.app".to_owned()),
        })
        .expect("add_login succeeds");
    assert!(vault.is_modified());
    assert_eq!(uuid.len(), 32);

    let detail = vault.entry(uuid.clone()).unwrap();
    assert_eq!(detail.summary.title, "App Login");
    assert_eq!(detail.summary.username, "appuser");
    assert_eq!(detail.summary.url, "https://app.example.com");
    assert_eq!(detail.urls, vec!["https://app.example.com"]);
    assert_eq!(detail.android_apps, vec!["com.example.app"]);
    assert!(detail
        .custom_fields
        .iter()
        .any(|field| field.name == "AndroidApp"
            && field.value == "com.example.app"
            && !field.protected));

    let app_matches = vault.match_app("com.example.app".to_owned());
    assert_eq!(
        app_matches.first().map(|entry| entry.uuid.as_str()),
        Some(uuid.as_str())
    );
    assert!(vault.match_app("com.example.other".to_owned()).is_empty());

    let web_matches = vault.match_web("https://app.example.com".to_owned());
    assert_eq!(
        web_matches.first().map(|entry| entry.uuid.as_str()),
        Some(uuid.as_str())
    );

    let bytes = vault.save().expect("save succeeds");
    assert!(!vault.is_modified());
    assert!(!bytes.is_empty());

    let reopened = open_vault(bytes, Some("testpassword".to_owned()), None)
        .expect("saved bytes reopen with the same credentials");
    let detail = reopened
        .entry(uuid.clone())
        .expect("added entry survives save");
    assert_eq!(detail.summary.title, "App Login");
    assert_eq!(detail.password, "app-secret");
    assert_eq!(detail.android_apps, vec!["com.example.app"]);
    assert_eq!(
        reopened.match_app("com.example.app".to_owned())[0].uuid,
        uuid
    );
}

#[test]
fn password_only_database_created_here_round_trips() {
    // No keyfile: a database the keepass crate creates in the test.
    let mut database = Database::new();
    database.config.version = DatabaseVersion::KDB4(1);
    database.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    {
        let mut root = database.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "Local Entry");
        entry.set_unprotected(fields::USERNAME, "localuser");
        entry.set_protected(fields::PASSWORD, "local-secret");

        let mut email = root.add_group();
        email.name = "Email".to_owned();
        let mut nested = email.add_entry();
        nested.set_unprotected(fields::TITLE, "Nested Entry");
        nested.set_unprotected(fields::USERNAME, "nesteduser");
    }
    let mut bytes = Vec::new();
    database
        .save(&mut bytes, DatabaseKey::new().with_password("pw"))
        .expect("test database saves");

    let vault = open_vault(bytes, Some("pw".to_owned()), None).expect("opens");
    assert_eq!(vault.all_entries().len(), 2);
    let nested = vault
        .all_entries()
        .into_iter()
        .find(|entry| entry.title == "Nested Entry")
        .expect("nested entry listed");
    assert_eq!(nested.group_path, "Root/Email");
    let email = vault
        .groups()
        .into_iter()
        .find(|group| group.name == "Email")
        .expect("nested group listed");
    assert_eq!(email.entry_count, 1);
    vault
        .add_login(NewLogin {
            title: "Second".to_owned(),
            username: "second".to_owned(),
            password: "second-secret".to_owned(),
            url: None,
            android_app: None,
        })
        .unwrap();
    let saved = vault.save().expect("save");

    let reopened = open_vault(saved, Some("pw".to_owned()), None).expect("reopens");
    let titles: Vec<String> = reopened
        .all_entries()
        .into_iter()
        .map(|entry| entry.title)
        .collect();
    assert_eq!(titles, vec!["Local Entry", "Nested Entry", "Second"]);
}

#[test]
fn empty_credentials_are_rejected() {
    expect_invalid_credentials(open_vault(fixture("sample4.kdbx"), None, None));
}

fn registration_request(rp_id: &str, user_name: &str) -> PasskeyCreateRequest {
    PasskeyCreateRequest {
        rp_id: rp_id.to_owned(),
        rp_name: "Example".to_owned(),
        user_name: user_name.to_owned(),
        user_display_name: "Example User".to_owned(),
        user_handle: b"user-handle".to_vec(),
        algorithms: vec![friendlypass_passkey::ES256],
        exclude_credential_ids: Vec::new(),
    }
}

fn assert_es256_signature(
    registration: &PasskeyRegistration,
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    signature: &[u8],
) {
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(&registration.public_key_spki_der)
        .expect("registration returns a P-256 SPKI key");
    let signature = p256::ecdsa::Signature::from_der(signature).expect("DER ECDSA signature");
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(client_data_hash);
    key.verify(&signed, &signature)
        .expect("assertion signature verifies with the registration public key");
}

#[test]
fn register_passkey_round_trips_survives_save_and_asserts() {
    let vault = open_sample4();
    let registration = vault
        .register_passkey(registration_request("passkey.example", "alice"))
        .expect("register_passkey succeeds");
    assert_eq!(registration.algorithm, friendlypass_passkey::ES256);
    assert_eq!(registration.credential_id.len(), 32);
    assert_eq!(registration.entry_uuid.len(), 32);
    assert!(vault.is_modified());

    // The new entry lives in the root group, titled with the relying party.
    let detail = vault.entry(registration.entry_uuid.clone()).unwrap();
    assert_eq!(detail.summary.title, "passkey.example");
    assert_eq!(detail.summary.username, "alice");
    assert_eq!(detail.summary.url, "https://passkey.example");
    assert_eq!(detail.summary.group_path, "Root");
    assert!(detail.summary.has_passkey);
    assert!(vault
        .entries_in_group(vault.root_group_uuid())
        .iter()
        .any(|entry| entry.uuid == registration.entry_uuid));

    // KeePassXC's protected attributes stay protected.
    for name in [
        KPEX_PASSKEY_CREDENTIAL_ID,
        KPEX_PASSKEY_PRIVATE_KEY_PEM,
        KPEX_PASSKEY_USER_HANDLE,
    ] {
        let field = detail
            .custom_fields
            .iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("{name} is present"));
        assert!(field.protected, "{name} must stay protected");
    }
    for name in [
        KPEX_PASSKEY_USERNAME,
        KPEX_PASSKEY_RELYING_PARTY,
        KPEX_PASSKEY_FLAG_BE,
        KPEX_PASSKEY_FLAG_BS,
    ] {
        let field = detail
            .custom_fields
            .iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("{name} is present"));
        assert!(!field.protected, "{name} must be unprotected");
    }

    // Before saving, the passkey is discoverable and filters by credential id.
    let found = vault.passkeys_for_rp("passkey.example".to_owned(), Vec::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].entry_uuid, registration.entry_uuid);
    assert_eq!(found[0].credential_id, registration.credential_id);
    assert_eq!(found[0].username, "alice");
    assert_eq!(found[0].user_handle, b"user-handle".to_vec());
    assert!(vault
        .passkeys_for_rp("passkey.example".to_owned(), vec![vec![9, 9, 9]])
        .is_empty());
    assert_eq!(
        vault
            .passkeys_for_rp(
                "passkey.example".to_owned(),
                vec![registration.credential_id.clone()],
            )
            .len(),
        1
    );
    assert!(vault
        .passkeys_for_rp("other.example".to_owned(), Vec::new())
        .is_empty());

    let bytes = vault.save().expect("save succeeds");
    let reopened =
        open_vault(bytes, Some("testpassword".to_owned()), None).expect("saved database reopens");
    let found = reopened.passkeys_for_rp("passkey.example".to_owned(), Vec::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].entry_uuid, registration.entry_uuid);

    // Protection flags survive serialisation too.
    let reopened_detail = reopened.entry(registration.entry_uuid.clone()).unwrap();
    for name in [
        KPEX_PASSKEY_CREDENTIAL_ID,
        KPEX_PASSKEY_PRIVATE_KEY_PEM,
        KPEX_PASSKEY_USER_HANDLE,
    ] {
        let field = reopened_detail
            .custom_fields
            .iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("{name} is present after reopening"));
        assert!(field.protected, "{name} must stay protected across save");
    }

    let client_data_json = friendlypass_passkey::client_data_json(
        "webauthn.get",
        b"challenge",
        "https://passkey.example",
        None,
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let assertion = reopened
        .assert_passkey(
            registration.entry_uuid.clone(),
            "passkey.example".to_owned(),
            client_data_hash.to_vec(),
        )
        .expect("assert_passkey succeeds after reopening");
    assert_eq!(assertion.credential_id, registration.credential_id);
    assert_eq!(assertion.user_handle, b"user-handle".to_vec());
    assert_es256_signature(
        &registration,
        &assertion.authenticator_data,
        &client_data_hash,
        &assertion.signature,
    );

    assert!(matches!(
        reopened.assert_passkey(
            registration.entry_uuid,
            "other.example".to_owned(),
            client_data_hash.to_vec(),
        ),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        reopened.assert_passkey(
            "ffffffffffffffffffffffffffffffff".to_owned(),
            "passkey.example".to_owned(),
            client_data_hash.to_vec(),
        ),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn keepassxc_format_passkey_entry_is_found_and_signs() {
    // Build an entry the way KeePassXC writes it: the exact KPEX_PASSKEY_*
    // attribute names, protected flags and base64url values.
    let registration = friendlypass_passkey::register(
        "keepassxc.example",
        "bob@example.com",
        b"kpdx-handle",
        &[friendlypass_passkey::ES256],
    )
    .expect("generate a KeePassXC passkey");

    let mut database = Database::new();
    database.config.version = DatabaseVersion::KDB4(1);
    database.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    {
        let mut root = database.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "KeePassXC Passkey");
        entry.set_unprotected(fields::USERNAME, "bob@example.com");
        for field in registration.passkey.to_fields() {
            if field.protected {
                entry.set_protected(field.name, field.value);
            } else {
                entry.set_unprotected(field.name, field.value);
            }
        }
    }
    let mut bytes = Vec::new();
    database
        .save(&mut bytes, DatabaseKey::new().with_password("pw"))
        .expect("test database saves");

    let vault = open_vault(bytes, Some("pw".to_owned()), None).expect("opens");
    let found = vault.passkeys_for_rp("keepassxc.example".to_owned(), Vec::new());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].credential_id, registration.credential_id);
    assert_eq!(found[0].username, "bob@example.com");
    assert!(found[0].entry_uuid.len() == 32);

    let entry = vault
        .all_entries()
        .into_iter()
        .find(|entry| entry.title == "KeePassXC Passkey")
        .expect("KeePassXC entry listed");
    assert!(entry.has_passkey);

    let client_data_json = friendlypass_passkey::client_data_json(
        "webauthn.get",
        b"challenge",
        "https://keepassxc.example",
        None,
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let assertion = vault
        .assert_passkey(
            entry.uuid,
            "keepassxc.example".to_owned(),
            client_data_hash.to_vec(),
        )
        .expect("KeePassXC-format passkey signs");
    assert_eq!(assertion.credential_id, registration.credential_id);

    let key = p256::ecdsa::VerifyingKey::from_public_key_der(&registration.public_key_spki_der)
        .expect("P-256 SPKI");
    let signature = p256::ecdsa::Signature::from_der(&assertion.signature).expect("DER signature");
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&client_data_hash);
    key.verify(&signed, &signature)
        .expect("KeePassXC-format assertion verifies");
}

#[test]
fn register_passkey_honours_excluded_credentials() {
    let vault = open_sample4();
    let registration = vault
        .register_passkey(registration_request("excluded.example", "carol"))
        .unwrap();

    let mut request = registration_request("excluded.example", "carol");
    request.exclude_credential_ids = vec![registration.credential_id];
    assert!(matches!(
        vault.register_passkey(request),
        Err(VaultError::Unsupported { .. })
    ));
}
