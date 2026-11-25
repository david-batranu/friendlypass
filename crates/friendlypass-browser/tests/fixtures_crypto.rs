//! Golden-vector crypto test for `protocol/fixtures/*.json` (WP0).
//!
//! This test deliberately verifies ONLY the cryptographic round-trip of the
//! generated frames — it does not implement the protocol actions (that is
//! WP7a/WP3). For every vector it proves:
//!
//!  * the fixed nonce is 24 bytes and the fixed keys are 32 bytes;
//!  * an encrypted request decrypts with `client secret + host public` to the
//!    exact `plaintextJson` bytes and re-seals to the exact `message`;
//!  * an encrypted response decrypts with `host secret + client public` and
//!    re-seals identically;
//!  * unencrypted frames (handshake, host actions, pushes, errors) carry no
//!    `message`;
//!  * the response nonce is the request nonce incremented little-endian by one
//!    (or echoed, for `ping`), matching the frozen rule in ACTIONS.md.
//!
//! Run: `cargo test -p friendlypass-browser --test fixtures_crypto`

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use friendlypass_browser::crypto::{increment_nonce, open, seal};
use serde_json::Value;

#[derive(Clone, Copy)]
enum Author {
    Client,
    Host,
}

struct KeyMaterial {
    client_public: Vec<u8>,
    client_secret: Vec<u8>,
    host_public: Vec<u8>,
    host_secret: Vec<u8>,
}

impl KeyMaterial {
    fn from_document(document: &Value) -> KeyMaterial {
        KeyMaterial {
            client_public: b64_at(document, "/keys/client/publicKey"),
            client_secret: b64_at(document, "/keys/client/secretKey"),
            host_public: b64_at(document, "/keys/host/publicKey"),
            host_secret: b64_at(document, "/keys/host/secretKey"),
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures_dir() -> PathBuf {
    repo_root().join("protocol/fixtures")
}

fn b64_at(document: &Value, pointer: &str) -> Vec<u8> {
    let encoded = document
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing Base64 field {pointer}"));
    B64.decode(encoded)
        .unwrap_or_else(|error| panic!("field {pointer} is not Base64: {error}"))
}

fn nonce_of(frame: &Value, label: &str) -> Option<Vec<u8>> {
    match frame.get("nonce") {
        None | Some(Value::Null) => None,
        Some(Value::String(encoded)) => {
            let nonce = B64
                .decode(encoded)
                .unwrap_or_else(|error| panic!("{label}: nonce is not Base64: {error}"));
            assert_eq!(nonce.len(), 24, "{label}: nonce must be 24 bytes");
            Some(nonce)
        }
        Some(other) => panic!("{label}: nonce must be a string or null, got {other}"),
    }
}

fn check_frame(
    frame: &Value,
    nonce: Option<&[u8]>,
    author: Author,
    keys: &KeyMaterial,
    label: &str,
) {
    let outer = frame
        .get("frame")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{label}: missing outer frame object"));

    match nonce {
        Some(nonce) => {
            let encoded = outer
                .get("nonce")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{label}: outer frame is missing nonce"));
            assert_eq!(
                B64.decode(encoded).unwrap(),
                nonce,
                "{label}: outer frame nonce must equal the documented nonce"
            );
        }
        None => {
            assert!(
                !outer.contains_key("nonce"),
                "{label}: unencrypted/error frame must not carry a nonce"
            );
        }
    }

    let plaintext_json = match frame.get("plaintextJson") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(other) => panic!("{label}: plaintextJson must be a string or null, got {other}"),
    };

    let message = outer.get("message").and_then(Value::as_str);

    match plaintext_json {
        None => {
            assert!(
                message.is_none(),
                "{label}: unencrypted frame must not carry `message`"
            );
            assert!(
                frame.get("plaintext").is_none_or(Value::is_null),
                "{label}: unencrypted frame must not document plaintext"
            );
        }
        Some(plaintext_json) => {
            let message =
                message.unwrap_or_else(|| panic!("{label}: encrypted frame is missing `message`"));
            let nonce =
                nonce.unwrap_or_else(|| panic!("{label}: encrypted frame is missing nonce"));

            let sender_public = match author {
                Author::Client => &keys.client_public,
                Author::Host => &keys.host_public,
            };
            let receiver_secret = match author {
                Author::Client => &keys.host_secret,
                Author::Host => &keys.client_secret,
            };
            let sender_secret = match author {
                Author::Client => &keys.client_secret,
                Author::Host => &keys.host_secret,
            };
            let receiver_public = match author {
                Author::Client => &keys.host_public,
                Author::Host => &keys.client_public,
            };

            let opened = open(sender_public, receiver_secret, nonce, message)
                .unwrap_or_else(|error| panic!("{label}: decrypt failed: {error}"));
            assert_eq!(
                opened,
                plaintext_json.as_bytes(),
                "{label}: decrypted bytes must equal plaintextJson"
            );

            let resealed = seal(
                receiver_public,
                sender_secret,
                nonce,
                plaintext_json.as_bytes(),
            )
            .unwrap_or_else(|error| panic!("{label}: re-seal failed: {error}"));
            assert_eq!(
                resealed, message,
                "{label}: fixed keys/nonce must reproduce the exact ciphertext"
            );

            let actual: Value = serde_json::from_slice(&opened)
                .unwrap_or_else(|error| panic!("{label}: plaintextJson is not JSON: {error}"));
            let expected = frame
                .get("plaintext")
                .unwrap_or_else(|| panic!("{label}: missing parsed plaintext"));
            assert_eq!(&actual, expected, "{label}: plaintext object mismatch");
        }
    }
}

#[test]
fn protocol_fixtures_crypto_round_trip() {
    let dir = fixtures_dir();
    assert!(
        dir.is_dir(),
        "fixtures directory missing: {} (run `node protocol/gen-fixtures.mjs`)",
        dir.display()
    );

    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("read fixtures dir")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no fixture JSON files found in {}",
        dir.display()
    );

    let mut vector_count = 0usize;
    let mut encrypted_frame_count = 0usize;

    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let document: Value = serde_json::from_str(
            &fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{name}: read failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("{name}: invalid JSON: {error}"));

        assert_eq!(
            document["schemaVersion"], 1,
            "{name}: unexpected fixture schema version"
        );
        assert_eq!(
            document["protocolVersion"], 1,
            "{name}: fixture must document protocol version 1"
        );
        assert_eq!(
            document["generatedBy"], "protocol/gen-fixtures.mjs",
            "{name}: generatedBy must point at the generator"
        );

        let keys = KeyMaterial::from_document(&document);
        assert_eq!(
            keys.client_public.len(),
            32,
            "{name}: client public key size"
        );
        assert_eq!(
            keys.client_secret.len(),
            32,
            "{name}: client secret key size"
        );
        assert_eq!(keys.host_public.len(), 32, "{name}: host public key size");
        assert_eq!(keys.host_secret.len(), 32, "{name}: host secret key size");

        let vectors = document["vectors"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: vectors must be an array"));
        assert!(!vectors.is_empty(), "{name}: no vectors");

        for vector in vectors {
            vector_count += 1;
            let label = format!(
                "{name}::{}",
                vector["name"].as_str().unwrap_or("<unnamed vector>")
            );
            let action = vector["action"]
                .as_str()
                .unwrap_or_else(|| panic!("{label}: missing action"));
            let relation = vector["nonceRelation"]
                .as_str()
                .unwrap_or_else(|| panic!("{label}: missing nonceRelation"));

            let request = vector.get("request").filter(|value| !value.is_null());
            let response = vector.get("response").filter(|value| !value.is_null());

            let request_nonce = request.map(|frame| {
                assert_eq!(
                    frame["frame"]["action"].as_str(),
                    Some(action),
                    "{label}: request frame action mismatch"
                );
                nonce_of(frame, &format!("{label} request"))
            });
            let response_nonce = response.map(|frame| {
                let frame_action = frame["frame"]["action"].as_str().unwrap_or_default();
                assert_eq!(
                    frame_action, action,
                    "{label}: response frame action mismatch"
                );
                nonce_of(frame, &format!("{label} response"))
            });

            if let (Some(request), Some(Some(nonce))) = (request, &request_nonce) {
                check_frame(
                    request,
                    Some(nonce),
                    Author::Client,
                    &keys,
                    &format!("{label} request"),
                );
                if request["plaintextJson"].is_string() {
                    encrypted_frame_count += 1;
                }
            }

            if let (Some(response), Some(Some(nonce))) = (response, &response_nonce) {
                check_frame(
                    response,
                    Some(nonce),
                    Author::Host,
                    &keys,
                    &format!("{label} response"),
                );
                if response["plaintextJson"].is_string() {
                    encrypted_frame_count += 1;
                }
            } else if let Some(response) = response {
                // Unencrypted error/push frame: no nonce to check.
                check_frame(
                    response,
                    None,
                    Author::Host,
                    &keys,
                    &format!("{label} response"),
                );
            }

            match relation {
                "increment" => {
                    let request_nonce = request_nonce
                        .flatten()
                        .unwrap_or_else(|| panic!("{label}: increment needs a request nonce"));
                    let response_nonce = response_nonce
                        .flatten()
                        .unwrap_or_else(|| panic!("{label}: increment needs a response nonce"));
                    assert_eq!(
                        response_nonce,
                        increment_nonce(&request_nonce),
                        "{label}: response nonce must be request nonce + 1 (little-endian)"
                    );
                }
                "echo" => {
                    assert_eq!(
                        response_nonce.flatten(),
                        request_nonce.flatten(),
                        "{label}: echoed nonce must be identical"
                    );
                }
                "none" => {}
                other => panic!("{label}: unknown nonceRelation {other}"),
            }
        }
    }

    assert!(
        vector_count >= 20,
        "expected the full action set, got {vector_count} vectors"
    );
    assert!(
        encrypted_frame_count >= 20,
        "expected encrypted request+response pairs, got {encrypted_frame_count}"
    );
}

#[test]
fn protocol_version_file_matches_fixtures() {
    let version = fs::read_to_string(repo_root().join("protocol/version"))
        .expect("protocol/version must exist");
    assert_eq!(version.trim(), "1", "protocol version must be 1");
}
