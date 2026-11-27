//! Integration tests for the macOS AutoFill Credential Provider bridge
//! (Passkeys, Passwords, TOTP) over a real peer-verified Unix domain socket.

#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use eframe::egui;
use friendlypass_gui::macos_provider::{
    self, CredentialKind, Request, Response, ResponsePayload,
};
use keepass::db::{fields, Database};
use keepass::DatabaseKey;

fn send_request(socket: &Path, req: &Request) -> std::io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let bytes = serde_json::to_vec(req).unwrap();
    macos_provider::write_frame(&mut stream, &bytes)?;
    let raw = macos_provider::read_frame(&mut stream)?;
    let resp = serde_json::from_slice::<Response>(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(resp)
}

fn create_test_kdbx4(path: &Path) -> DatabaseKey {
    let mut db = Database::new();
    db.config.version = keepass::config::DatabaseVersion::KDB4(1);
    db.meta.recyclebin_enabled = Some(true);

    let recycle_uuid = {
        let mut root = db.root_mut();
        let mut recycle = root.add_group();
        recycle.name = "Recycle Bin".to_owned();
        let mut trashed = recycle.add_entry();
        trashed.set_unprotected(fields::TITLE, "Trashed Entry");
        trashed.set_unprotected(fields::USERNAME, "gone@example.com");
        trashed.set_protected(fields::PASSWORD, "should-never-appear");
        trashed.set_unprotected(fields::URL, "https://trashed.example.com");
        recycle.id().uuid()
    };
    db.meta.recyclebin_uuid = Some(recycle_uuid);

    {
        let mut root = db.root_mut();

        let mut gh = root.add_entry();
        gh.set_unprotected(fields::TITLE, "GitHub");
        gh.set_unprotected(fields::USERNAME, "octocat");
        gh.set_protected(fields::PASSWORD, "gh-secret-pass");
        gh.set_unprotected(fields::URL, "https://github.com/login");
        gh.set_protected(
            fields::OTP,
            "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30",
        );

        let mut other = root.add_entry();
        other.set_unprotected(fields::TITLE, "Example Forum");
        other.set_unprotected(fields::USERNAME, "alice");
        other.set_protected(fields::PASSWORD, "forum-secret");
        other.set_unprotected(fields::URL, "https://forum.example.org");
    }

    // Add a pre-existing passkey entry using KeePassXC's KPEX_PASSKEY_* format.
    let reg = friendlypass_passkey::register(
        "passkey.example.com",
        "pk-user",
        b"user-handle-01",
        &[friendlypass_passkey::ES256],
    )
    .unwrap();
    friendlypass_browser::passkey_write::create_passkey_entry(
        &mut db,
        &reg.passkey,
        "passkey.example.com",
        "https://passkey.example.com",
        "Passkeys",
    )
    .unwrap();

    let key = DatabaseKey::new().with_password("testpw");
    friendlypass::saveutil::save(path, &mut db, key.clone()).unwrap();
    key
}

fn temp_socket_dir() -> tempfile::TempDir {
    // Keep Unix socket paths short (< 104 bytes on macOS).
    tempfile::Builder::new().prefix("fpcp").tempdir().unwrap()
}

#[test]
fn locked_and_unlocked_status_and_identities() {
    let dir = temp_socket_dir();
    let sock = dir.path().join("cp.sock");
    let db_path = dir.path().join("vault.kdbx");
    let key = create_test_kdbx4(&db_path);

    let self_exe = std::env::current_exe().unwrap();
    let provider = macos_provider::start_with_config(sock.clone(), self_exe).unwrap();

    let mut app = friendlypass_gui::App::default();
    app.macos_provider = Some(provider);
    let ctx = egui::Context::default();
    macos_provider::pump(&mut app, &ctx);

    // While locked: status reports unlocked = false, credential queries return vault_locked.
    let status = send_request(&sock, &Request::Status { request_unlock: false }).unwrap();
    assert!(status.ok);
    match status.payload {
        Some(ResponsePayload::Status { unlocked, .. }) => assert!(!unlocked),
        other => panic!("unexpected payload: {other:?}"),
    }

    let locked_ids = send_request(&sock, &Request::ListIdentities).unwrap();
    assert!(!locked_ids.ok);
    assert_eq!(locked_ids.error.as_deref(), Some("vault_locked"));

    // Unlock the database and pump once.
    let path_str = db_path.display().to_string();
    let mut unlocked_app = friendlypass_gui::App::with_open_database(&path_str, key);
    unlocked_app.macos_provider = app.macos_provider.take();
    macos_provider::pump(&mut unlocked_app, &ctx);

    let status = send_request(&sock, &Request::Status { request_unlock: false }).unwrap();
    assert!(status.ok);
    match status.payload {
        Some(ResponsePayload::Status { unlocked, db_name }) => {
            assert!(unlocked);
            assert_eq!(db_name.as_deref(), Some("vault.kdbx"));
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    // ListIdentities returns passkey + passwords + TOTP, excluding Recycle Bin.
    let ids = send_request(&sock, &Request::ListIdentities).unwrap();
    assert!(ids.ok);
    match ids.payload {
        Some(ResponsePayload::Identities {
            passkeys,
            passwords,
            totps,
        }) => {
            assert_eq!(passkeys.len(), 1);
            assert_eq!(passkeys[0].rp_id, "passkey.example.com");
            assert_eq!(passkeys[0].username, "pk-user");

            assert!(passwords.iter().any(|p| p.service == "github.com" && p.username == "octocat"));
            assert!(passwords.iter().any(|p| p.service == "forum.example.org" && p.username == "alice"));
            assert!(
                !passwords.iter().any(|p| p.service.contains("trashed")),
                "recycled entries must be excluded"
            );

            assert_eq!(totps.len(), 1);
            assert_eq!(totps[0].service, "github.com");
            assert_eq!(totps[0].label, "octocat");
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn list_credentials_matching_and_get_password_and_totp() {
    let dir = temp_socket_dir();
    let sock = dir.path().join("cp.sock");
    let db_path = dir.path().join("vault.kdbx");
    let key = create_test_kdbx4(&db_path);

    let self_exe = std::env::current_exe().unwrap();
    let provider = macos_provider::start_with_config(sock.clone(), self_exe).unwrap();

    let path_str = db_path.display().to_string();
    let mut app = friendlypass_gui::App::with_open_database(&path_str, key);
    app.macos_provider = Some(provider);
    let ctx = egui::Context::default();
    macos_provider::pump(&mut app, &ctx);

    // Match passwords for github.com: GitHub should rank first with matched = true.
    let list = send_request(
        &sock,
        &Request::ListCredentials {
            kind: CredentialKind::Password,
            service_identifiers: vec!["https://github.com/login".to_owned()],
            rp_id: None,
            allowed_credential_ids_b64: None,
            query: None,
        },
    )
    .unwrap();
    assert!(list.ok);
    let items = match list.payload {
        Some(ResponsePayload::Credentials { items }) => items,
        other => panic!("unexpected payload: {other:?}"),
    };
    assert!(!items.is_empty());
    assert_eq!(items[0].title, "GitHub");
    assert!(items[0].matched);
    let gh_uuid = items[0].uuid.clone();

    // Fetch password by UUID.
    let pw = send_request(&sock, &Request::GetPassword { uuid: gh_uuid.clone() }).unwrap();
    assert!(pw.ok);
    match pw.payload {
        Some(ResponsePayload::Password { username, password }) => {
            assert_eq!(username, "octocat");
            assert_eq!(password, "gh-secret-pass");
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    // List TOTP credentials and fetch a live 6-digit code.
    let totp_list = send_request(
        &sock,
        &Request::ListCredentials {
            kind: CredentialKind::Totp,
            service_identifiers: vec!["github.com".to_owned()],
            rp_id: None,
            allowed_credential_ids_b64: None,
            query: None,
        },
    )
    .unwrap();
    assert!(totp_list.ok);
    let totp_items = match totp_list.payload {
        Some(ResponsePayload::Credentials { items }) => items,
        other => panic!("unexpected payload: {other:?}"),
    };
    assert_eq!(totp_items.len(), 1);
    assert_eq!(totp_items[0].uuid, gh_uuid);
    assert!(totp_items[0].matched);

    let totp = send_request(&sock, &Request::GetTotp { uuid: gh_uuid }).unwrap();
    assert!(totp.ok);
    match totp.payload {
        Some(ResponsePayload::Totp {
            code,
            valid_for_secs,
        }) => {
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            assert!(valid_for_secs <= 30);
        }
        other => panic!("unexpected payload: {other:?}"),
    }
}

#[test]
fn register_and_assert_passkey_end_to_end_with_autosave() {
    let dir = temp_socket_dir();
    let sock = dir.path().join("cp.sock");
    let db_path = dir.path().join("vault.kdbx");
    let key = create_test_kdbx4(&db_path);

    let self_exe = std::env::current_exe().unwrap();
    let provider = macos_provider::start_with_config(sock.clone(), self_exe).unwrap();

    let path_str = db_path.display().to_string();
    let mut app = friendlypass_gui::App::with_open_database(&path_str, key.clone());
    app.macos_provider = Some(provider);
    let ctx = egui::Context::default();
    macos_provider::pump(&mut app, &ctx);

    let client_hash = [0x42u8; 32];
    let sock_clone = sock.clone();
    let reg_thread = std::thread::spawn(move || {
        send_request(
            &sock_clone,
            &Request::RegisterPasskey {
                rp_id: "webauthn.io".to_owned(),
                username: "david@example.com".to_owned(),
                user_handle_b64: B64.encode(b"david-user-handle"),
                client_data_hash_b64: B64.encode(client_hash),
                algorithms: vec![friendlypass_passkey::ES256, friendlypass_passkey::EDDSA],
                excluded_credential_ids_b64: vec![],
            },
        )
    });

    // Pump the GUI thread until registration completes (simulates eframe loop).
    let start = Instant::now();
    while !reg_thread.is_finished() {
        macos_provider::pump(&mut app, &ctx);
        assert!(start.elapsed() < Duration::from_secs(5), "registration timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    let reg_resp = reg_thread.join().unwrap().unwrap();
    assert!(reg_resp.ok, "registration failed: {reg_resp:?}");
    let (new_uuid, cred_id_b64, att_obj_b64) = match reg_resp.payload {
        Some(ResponsePayload::PasskeyRegistration {
            uuid,
            relying_party,
            credential_id_b64,
            attestation_object_b64,
        }) => {
            assert_eq!(relying_party, "webauthn.io");
            (uuid, credential_id_b64, attestation_object_b64)
        }
        other => panic!("unexpected payload: {other:?}"),
    };
    assert_eq!(B64.decode(&cred_id_b64).unwrap().len(), 32);
    assert!(!B64.decode(&att_obj_b64).unwrap().is_empty());

    // Pump once more so the snapshot reflects the newly saved entry.
    macos_provider::pump(&mut app, &ctx);
    assert!(!app.dirty, "KDBX 4 database should auto-save after passkey registration");

    // Re-open the KDBX file from disk to prove the passkey was persisted.
    let reopened = friendlypass_gui::app::open_database(&path_str, &key).unwrap();
    let persisted = friendlypass_browser::passkey_write::entry_passkey(&reopened, &new_uuid)
        .expect("new passkey must be persisted on disk");
    assert_eq!(persisted.rp_id, "webauthn.io");
    assert_eq!(persisted.username, "david@example.com");
    assert_eq!(persisted.credential_id, B64.decode(&cred_id_b64).unwrap());

    // Re-registering with the new credential ID in excluded_credential_ids fails.
    let sock_clone2 = sock.clone();
    let cred_clone = cred_id_b64.clone();
    let excl_thread = std::thread::spawn(move || {
        send_request(
            &sock_clone2,
            &Request::RegisterPasskey {
                rp_id: "webauthn.io".to_owned(),
                username: "david@example.com".to_owned(),
                user_handle_b64: B64.encode(b"david-user-handle"),
                client_data_hash_b64: B64.encode(client_hash),
                algorithms: vec![friendlypass_passkey::ES256],
                excluded_credential_ids_b64: vec![cred_clone],
            },
        )
    });
    let start = Instant::now();
    while !excl_thread.is_finished() {
        macos_provider::pump(&mut app, &ctx);
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    let excl_resp = excl_thread.join().unwrap().unwrap();
    assert!(!excl_resp.ok);
    assert_eq!(excl_resp.error.as_deref(), Some("credential_excluded"));

    // Assert the newly created passkey over the Unix socket.
    let assertion_hash = [0x99u8; 32];
    let assert_resp = send_request(
        &sock,
        &Request::AssertPasskey {
            uuid: Some(new_uuid.clone()),
            rp_id: "webauthn.io".to_owned(),
            credential_id_b64: Some(cred_id_b64.clone()),
            client_data_hash_b64: B64.encode(assertion_hash),
        },
    )
    .unwrap();
    assert!(assert_resp.ok, "assertion failed: {assert_resp:?}");
    match assert_resp.payload {
        Some(ResponsePayload::PasskeyAssertion {
            relying_party,
            credential_id_b64,
            user_handle_b64,
            authenticator_data_b64,
            signature_b64,
        }) => {
            assert_eq!(relying_party, "webauthn.io");
            assert_eq!(credential_id_b64, cred_id_b64);
            assert_eq!(B64.decode(&user_handle_b64).unwrap(), b"david-user-handle");
            assert_eq!(B64.decode(&authenticator_data_b64).unwrap().len(), 37);
            assert!(!B64.decode(&signature_b64).unwrap().is_empty());
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    // Wrong RP ID must be rejected.
    let bad_rp = send_request(
        &sock,
        &Request::AssertPasskey {
            uuid: Some(new_uuid),
            rp_id: "evil.example.com".to_owned(),
            credential_id_b64: Some(cred_id_b64),
            client_data_hash_b64: B64.encode(assertion_hash),
        },
    )
    .unwrap();
    assert!(!bad_rp.ok);
    assert_eq!(bad_rp.error.as_deref(), Some("credential_not_found"));
}

#[test]
fn untrusted_peer_is_rejected() {
    let dir = temp_socket_dir();
    let sock = dir.path().join("cp.sock");

    // Expect a completely different binary than our test runner.
    let other_bin = PathBuf::from("/bin/sh");
    let _provider = macos_provider::start_with_config(sock.clone(), other_bin).unwrap();

    let result = send_request(&sock, &Request::Status { request_unlock: false });
    assert!(
        result.is_err(),
        "untrusted peer must be disconnected without a response, got {result:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn swift_ipc_client_end_to_end_roundtrip() {
    let dir = temp_socket_dir();
    let sock = dir.path().join("cp.sock");
    let db_path = dir.path().join("vault.kdbx");
    let key = create_test_kdbx4(&db_path);

    let ipc_swift = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/macos/credential-provider/Sources/IPCClient.swift");
    let driver_swift = dir.path().join("main.swift");
    let driver_bin = dir.path().join("swift_ipc_driver");

    std::fs::write(
        &driver_swift,
        r#"
import Foundation

let client = IPCClient()
let st = try client.status(requestUnlock: false)
guard st.unlocked, st.dbName == "vault.kdbx" else {
    fputs("unexpected status\n", stderr); exit(2)
}
let ids = try client.listIdentities()
guard ids.passkeys.count == 1, ids.passwords.count >= 2, ids.totps.count == 1 else {
    fputs("unexpected identities\n", stderr); exit(3)
}
let creds = try client.listCredentials(kind: "password", serviceIdentifiers: ["https://github.com/login"])
guard let first = creds.first, first.title == "GitHub", first.matched else {
    fputs("unexpected credentials\n", stderr); exit(4)
}
let pw = try client.getPassword(uuid: first.uuid)
guard pw.username == "octocat", pw.password == "gh-secret-pass" else {
    fputs("unexpected password\n", stderr); exit(5)
}
let totp = try client.getTotp(uuid: first.uuid)
guard totp.code.count == 6 else {
    fputs("unexpected totp\n", stderr); exit(6)
}
let hash = Data(repeating: 0x55, count: 32)
let reg = try client.registerPasskey(
    rpId: "swift-test.example.com",
    username: "swift@example.com",
    userHandle: Data("swift-handle".utf8),
    clientDataHash: hash,
    algorithms: [-7],
    excludedCredentialIDs: []
)
guard reg.relyingParty == "swift-test.example.com", reg.credentialID.count == 32 else {
    fputs("unexpected registration\n", stderr); exit(7)
}
let assertion = try client.assertPasskey(
    uuid: reg.uuid,
    rpId: "swift-test.example.com",
    credentialID: reg.credentialID,
    clientDataHash: hash
)
guard assertion.relyingParty == "swift-test.example.com",
      assertion.authenticatorData.count == 37,
      !assertion.signature.isEmpty else {
    fputs("unexpected assertion\n", stderr); exit(8)
}
print("OK")
"#,
    )
    .unwrap();

    let compile = std::process::Command::new("xcrun")
        .args(["swiftc", "-O", "-o"])
        .arg(&driver_bin)
        .arg(&ipc_swift)
        .arg(&driver_swift)
        .output()
        .expect("xcrun swiftc should be available on macOS");
    assert!(
        compile.status.success(),
        "swiftc failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    // Ad-hoc sign the Swift test binary so macOS cdhash peer verification passes.
    let sign = std::process::Command::new("codesign")
        .args(["--force", "--sign", "-"])
        .arg(&driver_bin)
        .status()
        .unwrap();
    assert!(sign.success(), "codesign failed");

    let provider = macos_provider::start_with_config(sock.clone(), driver_bin.clone()).unwrap();
    let path_str = db_path.display().to_string();
    let mut app = friendlypass_gui::App::with_open_database(&path_str, key);
    app.macos_provider = Some(provider);
    let ctx = egui::Context::default();
    macos_provider::pump(&mut app, &ctx);

    let mut child = std::process::Command::new(&driver_bin)
        .env(macos_provider::ENV_SOCKET, &sock)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let start = Instant::now();
    loop {
        macos_provider::pump(&mut app, &ctx);
        if let Some(_status) = child.try_wait().unwrap() {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "swift driver timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Swift IPCClient roundtrip failed (status {:?}):\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "OK");
}
