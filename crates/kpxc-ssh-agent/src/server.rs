//! The SSH agent socket server: listens on a Unix domain socket, answers
//! `RequestIdentities` with the identities snapshot shared with the GUI, and
//! signs with the matching identity's key — the same serving model as
//! KeePassXC's SSH agent integration.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::openssh::{parse_public_blob, SshIdentity};
use crate::protocol::{
    encode_failure, encode_identities_answer, encode_sign_response, parse_request, AgentRequest,
};

/// The shared identity pool: refreshed by the GUI side, read by the agent
/// thread per request (so new keys are served without restarting).
pub type IdentityPool = Arc<Mutex<Vec<SshIdentity>>>;

/// A running agent server.
pub struct AgentHandle {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AgentHandle {
    /// Socket path (for `SSH_AUTH_SOCK`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop the server (best effort) and join the thread.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Poke the listener by connecting once so the accept loop wakes up.
        if let Ok(stream) = std::os::unix::net::UnixStream::connect(&self.path) {
            drop(stream);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for AgentHandle {
    fn drop(&mut self) {
        // Same procedure as stop(): poke the listener so the accept loop can
        // observe the stop flag even if it is blocked in accept().
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = std::os::unix::net::UnixStream::connect(&self.path) {
            drop(stream);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Start the agent server on `path`, serving the given shared identity pool.
pub fn spawn(path: &Path, pool: IdentityPool) -> Result<AgentHandle> {
    // A fresh socket: remove a stale file first (like ssh-agent does).
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("cannot bind SSH agent socket {}", path.display()))?;
    // Standard ssh-agent socket permissions: only the owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let path_owned = path.to_path_buf();

    let thread = std::thread::Builder::new()
        .name("kpxc-ssh-agent".into())
        .spawn(move || {
            let listener = listener;
            let path_owned = path_owned;
            for stream in listener.incoming() {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { break };
                // Serve each client on its own thread: clients may keep
                // their connection open (ssh-add reuses one connection),
                // and this also keeps the accept loop responsive to a
                // stop-poke.
                let pool = Arc::clone(&pool);
                let _ = std::thread::Builder::new()
                    .name("kpxc-ssh-agent-conn".into())
                    .spawn(move || handle_connection(stream, &pool));
            }
            let _ = std::fs::remove_file(&path_owned);
        })
        .context("cannot start SSH agent thread")?;

    Ok(AgentHandle {
        path: path.to_path_buf(),
        stop,
        thread: Some(thread),
    })
}

fn handle_connection(mut stream: std::os::unix::net::UnixStream, pool: &IdentityPool) {
    // ssh clients may keep the connection open and send several requests.
    loop {
        let body = match read_message(&mut stream) {
            Ok(body) => body,
            Err(_) => return,
        };
        let response = match parse_request(&body) {
            Ok(AgentRequest::RequestIdentities) => {
                let identities = pool.lock().map(|p| p.clone()).unwrap_or_default();
                encode_identities_answer(&identities)
            }
            Ok(AgentRequest::SignRequest { keyblob, data, .. }) => {
                let identities = pool.lock().map(|p| p.clone()).unwrap_or_default();
                match sign_matching(&identities, &keyblob, &data) {
                    Some(sig) => encode_sign_response(&sig),
                    None => encode_failure(),
                }
            }
            Ok(AgentRequest::Unsupported(_)) | Err(_) => encode_failure(),
        };
        if stream.write_all(&response).is_err() {
            return;
        }
    }
}

/// Find the identity matching the requested public key blob and sign.
fn sign_matching(identities: &[SshIdentity], keyblob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let (wanted, _) = parse_public_blob(keyblob).ok()?;
    identities
        .iter()
        .find(|identity| identity.public == wanted)
        .map(|identity| identity.sign(data))
}

/// Read one length-prefixed agent message.
fn read_message(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 1024 * 1024 {
        anyhow::bail!("bad agent message length: {len}");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openssh::SshIdentity;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_identity() -> SshIdentity {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        SshIdentity {
            seed: [9u8; 32],
            public: signing.verifying_key().as_bytes().to_owned(),
            comment: "agent-test".into(),
        }
    }

    /// Minimal in-process agent client (used by tests and the e2e suite).
    pub struct TestClient {
        stream: std::os::unix::net::UnixStream,
    }

    impl TestClient {
        pub fn connect(path: &Path) -> Result<Self> {
            Ok(Self {
                stream: std::os::unix::net::UnixStream::connect(path)?,
            })
        }

        pub fn request_identities(&mut self) -> Result<Vec<SshIdentity>> {
            use crate::protocol::SSH_AGENT_IDENTITIES_ANSWER;
            let msg = crate::protocol::encode_message(&[crate::protocol::SSH_AGENT_REQUEST_IDENTITIES]);
            self.stream.write_all(&msg)?;
            let body = read_message(&mut self.stream)?;
            if body[0] != SSH_AGENT_IDENTITIES_ANSWER {
                anyhow::bail!("unexpected identities answer type: {}", body[0]);
            }
            let mut r = crate::openssh::BlobReader::new(&body[1..]);
            let n = r.read_u32()?;
            let mut out = Vec::new();
            for _ in 0..n {
                let blob = r.read_string()?.to_vec();
                let comment = r.read_string()?.to_vec();
                let (public, _) = parse_public_blob(&blob)?;
                out.push(SshIdentity {
                    seed: [0u8; 32],
                    public,
                    comment: String::from_utf8_lossy(&comment).to_string(),
                });
            }
            Ok(out)
        }

        pub fn sign(&mut self, keyblob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
            use crate::openssh::put_string;
            use crate::protocol::{SSH_AGENT_SIGN_REQUEST, SSH_AGENT_SIGN_RESPONSE};
            let mut body = vec![SSH_AGENT_SIGN_REQUEST];
            put_string(&mut body, keyblob);
            put_string(&mut body, data);
            body.extend_from_slice(&0_u32.to_be_bytes());
            self.stream.write_all(&crate::protocol::encode_message(&body))?;
            let resp = read_message(&mut self.stream)?;
            if resp[0] != SSH_AGENT_SIGN_RESPONSE {
                anyhow::bail!("agent refused to sign");
            }
            let mut r = crate::openssh::BlobReader::new(&resp[1..]);
            Ok(r.read_string()?.to_vec())
        }
    }

    #[test]
    fn server_serves_identities_and_signs() {
        let dir = tempfile_dir();
        let socket = dir.path().join("agent.sock");
        let identity = test_identity();
        let pool: IdentityPool = Arc::new(Mutex::new(vec![identity.clone()]));
        let handle = spawn(&socket, Arc::clone(&pool)).unwrap();

        let mut client = TestClient::connect(handle.path()).unwrap();
        let identities = client.request_identities().unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].public, identity.public);
        assert_eq!(identities[0].comment, "agent-test");

        let sig = client
            .sign(&identity.public_blob(), b"session data")
            .unwrap();
        assert!(crate::openssh::verify(&identity.public, b"session data", &sig));

        handle.stop();
    }

    #[test]
    fn pool_updates_without_restart() {
        let dir = tempfile_dir();
        let socket = dir.path().join("agent2.sock");
        let pool: IdentityPool = Arc::new(Mutex::new(Vec::new()));
        let handle = spawn(&socket, Arc::clone(&pool)).unwrap();

        let mut client = TestClient::connect(handle.path()).unwrap();
        assert!(client.request_identities().unwrap().is_empty());

        // GUI side adds a key: served on the next request.
        pool.lock().unwrap().push(test_identity());
        assert_eq!(client.request_identities().unwrap().len(), 1);

        handle.stop();
    }

    fn tempfile_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
}
