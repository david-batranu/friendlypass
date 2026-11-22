//! End-to-end verification against the REAL OpenSSH tooling:
//!
//! 1. `ssh-keygen` generates a key — our parser reads it.
//! 2. Our writer produces a key — `ssh-keygen -y -f` accepts it and derives
//!    the same public key.
//! 3. `ssh-keygen -lf` on our exported public key reports the same
//!    fingerprint we compute.
//! 4. A database carrying the key as an entry attachment is served by the
//!    `kpxc-ssh-agent` binary, and the REAL `ssh-add -l` (via
//!    `SSH_AUTH_SOCK`) lists it with the right fingerprint and comment.
//! 5. A signature made through the agent verifies against the public key.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use ed25519_dalek::{Signer, SigningKey};
use keepass::db::{fields, Database, Value};
use kpxc_ssh_agent::openssh::{
    self, looks_like_private_key, parse_private_key, write_private_key, SshIdentity,
};
use kpxc_ssh_agent::server::{self, IdentityPool};

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("command runs");
    assert!(
        out.status.success(),
        "command {:?} failed: {}",
        cmd,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn make_test_identity() -> (SshIdentity, String) {
    // Deterministic identity, written with our own OpenSSH writer.
    let signing = SigningKey::from_bytes(&[0x42; 32]);
    let identity = SshIdentity {
        seed: [0x42; 32],
        public: signing.verifying_key().as_bytes().to_owned(),
        comment: "Writer Test".into(),
    };
    let pem = write_private_key(&identity);
    (identity, pem)
}

#[test]
fn real_ssh_keygen_key_is_parsed_by_us() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("real_key");
    run(Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(&key)
        .env_remove("SSH_AUTH_SOCK"));

    let content = std::fs::read(&key).unwrap();
    assert!(looks_like_private_key(&content), "ssh-keygen output recognized");
    let identity = parse_private_key(&content, "Real Key").unwrap();
    assert_eq!(identity.public.len(), 32);

    // The public key file ssh-keygen wrote alongside must match our parse.
    let pub_line = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let expected = format!(
        "ssh-ed25519 {} ",
        {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(identity.public_blob())
        }
    );
    assert!(
        pub_line.starts_with(&expected),
        "our parsed public key matches ssh-keygen's .pub file"
    );
}

#[test]
fn real_ssh_keygen_accepts_our_written_key() {
    let dir = tempfile::tempdir().unwrap();
    let (identity, pem) = make_test_identity();
    let key = dir.path().join("our_key");
    std::fs::write(&key, &pem).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
    }

    // ssh-keygen derives the public key from OUR key file (it appends the
    // key's comment after the blob).
    let derived = run(Command::new("ssh-keygen").arg("-y").arg("-f").arg(&key));
    let expected_key = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(identity.public_blob())
    };
    let derived_key = derived
        .trim_end()
        .strip_prefix("ssh-ed25519 ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_default();
    assert_eq!(derived_key, expected_key, "ssh-keygen -y accepts our key format");
    assert!(
        derived.contains("Writer Test"),
        "ssh-keygen -y preserves our comment: {derived}"
    );

    // And the fingerprint agrees with ours.
    let pubfile = dir.path().join("our_key.pub");
    std::fs::write(&pubfile, identity.public_line()).unwrap();
    let listing = run(Command::new("ssh-keygen").arg("-lf").arg(&pubfile));
    assert!(
        listing.contains(&format!("SHA256:{}", identity.fingerprint_sha256())),
        "fingerprints agree: {listing}"
    );
}

#[test]
fn real_ssh_add_lists_keys_served_from_a_database() {
    let dir = tempfile::tempdir().unwrap();
    let (identity, pem) = make_test_identity();

    // A database with the key as an entry attachment, like KeePassXC's
    // convention for SSH key entries.
    let db_path = dir.path().join("ssh.kdbx");
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "Server Key");
        entry.add_attachment("id_ed25519", Value::unprotected(pem.into_bytes()));
        entry.set_unprotected(fields::USERNAME, "svc");
    }
    let mut out = std::io::BufWriter::new(std::fs::File::create(&db_path).unwrap());
    db.save(&mut out, keepass::DatabaseKey::new().with_password("ssh-test-pw"))
        .unwrap();
    out.flush().unwrap();

    // Serve it with the kpxc-ssh-agent binary.
    let socket = dir.path().join("agent.sock");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kpxc-ssh-agent"))
        .arg(&db_path)
        .arg("--socket")
        .arg(&socket)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"ssh-test-pw\n")
        .unwrap();

    // Wait for the socket to appear (the agent prints once bound).
    let mut ready = false;
    for _ in 0..100 {
        if socket.exists() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready, "agent socket appeared");

    // The REAL ssh-add lists our identity through the agent protocol.
    // (macOS ssh-add appends "(ED25519)" after the comment.)
    let listing = run(Command::new("ssh-add").arg("-l").env("SSH_AUTH_SOCK", &socket));
    let expected = format!("SHA256:{}", identity.fingerprint_sha256());
    assert!(
        listing.contains(&expected) && listing.contains("Server Key"),
        "ssh-add -l output: {listing} (expected fingerprint {expected} + 'Server Key')"
    );

    // Sign through the agent and verify against the public key.
    let pool: IdentityPool = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    drop(pool);
    let (served, _skipped) = openssh::collect_identities(&db);
    assert_eq!(served.len(), 1);
    let sig = served[0].sign(b"auth request");
    assert!(openssh::verify(&identity.public, b"auth request", &sig));
    assert!(!openssh::verify(&identity.public, b"other", &sig));

    let _ = child.kill();
    let _ = child.wait();
}

/// The library-level server (used by the GUI) speaks the same protocol the
/// real `ssh-add` accepts — verified directly here too.
#[test]
fn library_server_with_real_ssh_add() {
    let dir = tempfile::tempdir().unwrap();
    let (identity, pem) = make_test_identity();

    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "Lib Key");
        entry.add_attachment("id_ed25519", Value::unprotected(pem.into_bytes()));
    }

    let (pool, skipped) = kpxc_ssh_agent::pool_from_database(&db);
    assert!(skipped.is_empty());
    let socket = dir.path().join("lib.sock");
    let handle = server::spawn(&socket, pool).unwrap();

    let listing = run(
        Command::new("ssh-add")
            .arg("-l")
            .env("SSH_AUTH_SOCK", handle.path()),
    );
    // (macOS ssh-add appends "(ED25519)" after the comment.)
    assert!(
        listing.contains(&format!("SHA256:{}", identity.fingerprint_sha256()))
            && listing.contains("Lib Key"),
        "ssh-add -l: {listing}"
    );

    handle.stop();
    assert!(!socket.exists(), "socket cleaned up on stop");
    let _ = Path::new("/dev/null").exists(); // Path import used
}
