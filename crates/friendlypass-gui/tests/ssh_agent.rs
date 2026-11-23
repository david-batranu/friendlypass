//! SSH agent GUI integration: the window detects entry attachments holding
//! SSH keys, serves them, and the REAL `ssh-add` confirms the protocol.

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use keepass::db::{fields, Value};
use keepass::DatabaseKey;
use friendlypass_ssh_agent::openssh::{write_private_key, SshIdentity};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name)
}

#[test]
fn ssh_agent_window_serves_real_keys() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &db_path).unwrap();
    let socket = dir.path().join("gui-agent.sock");

    // A deterministic SSH identity, written with our OpenSSH writer.
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x5A; 32]);
    let identity = SshIdentity {
        seed: [0x5A; 32],
        public: signing.verifying_key().as_bytes().to_owned(),
        comment: "Server Key".into(),
    };
    let pem = write_private_key(&identity);

    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = db_path.display().to_string();
    let socket_str = socket.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| friendlypass_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 720.0));
    harness.run();

    // Attach the SSH private key to a new entry (the GUI convention).
    {
        let state = harness.state_mut();
        let db = state.db.as_mut().unwrap();
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "Server Key");
        entry.add_attachment("id_ed25519", Value::unprotected(pem.clone().into_bytes()));
    }
    // Use a deterministic socket path for the agent.
    harness.state_mut().ssh_socket = socket_str.clone();
    harness.run();

    // Open the SSH Agent window; the key is detected and listed.
    harness.get_by_label("Settings and tools").click();
    harness.run();
    harness.get_by_label("SSH Agent…").click();
    harness.run();
    // ("Server Key" also matches the entry-table row, so assert on the
    // window's own unique labels.)
    harness.get_by_label("1 SSH key(s) available:");
    let fingerprint = identity.fingerprint_sha256();
    harness.get_by_label_contains(&format!("SHA256:{fingerprint}"));

    // Start serving.
    harness.get_by_label("Start serving").click();
    harness.run();
    assert!(socket.exists(), "agent socket created");

    // The REAL ssh-add lists the key served through the GUI.
    let out = std::process::Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &socket)
        .output()
        .unwrap();
    assert!(out.status.success(), "ssh-add failed: {}", String::from_utf8_lossy(&out.stderr));
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        listing.contains(&format!("SHA256:{fingerprint}")) && listing.contains("Server Key"),
        "ssh-add -l via the GUI-served agent: {listing}"
    );

    // Stop serving: the socket is cleaned up.
    harness.get_by_label("Stop serving").click();
    harness.run();
    assert!(!socket.exists(), "socket removed on stop");
    let state = harness.state();
    assert!(state.ssh_handle.is_none());
    assert_eq!(state.status, "SSH agent stopped");
}
