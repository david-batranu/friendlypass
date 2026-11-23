//! The browser-protocol action state machine: per-connection client state,
//! associations, and credential lookup — mirroring KeePassXC 2.8.0's
//! `BrowserAction` + `BrowserService` behavior for the supported subset.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use crate::crypto::{increment_nonce, open, seal, KeyPair};
use crate::protocol::*;

/// One credential served to `get-logins`.
#[derive(Clone, Debug)]
pub struct CredentialEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub uuid: String,
}

/// The database snapshot the server serves (refreshed by the GUI side).
#[derive(Default)]
pub struct ServiceState {
    pub db_hash: String,
    pub entries: Vec<CredentialEntry>,
    /// association id -> client identification key (persisted by the GUI).
    pub associations: HashMap<String, String>,
    /// New associations created since the last GUI refresh (to persist).
    pub new_associations: Vec<(String, String)>,
}

impl ServiceState {
    pub fn db_hash(&self) -> &str {
        &self.db_hash
    }

    /// Find credentials matching a URL host (like KeePassXC's findEntries
    /// host-based matching).
    pub fn find_entries(&self, url: &str) -> Vec<&CredentialEntry> {
        let host = url_host(url);
        self.entries
            .iter()
            .filter(|e| {
                let entry_host = url_host(&e.url);
                !entry_host.is_empty() && (entry_host == host || host.ends_with(&format!(".{entry_host}")))
            })
            .collect()
    }
}

fn url_host(url: &str) -> String {
    let rest = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let host = rest
        .split(['/', ':', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    host.strip_prefix("www.").unwrap_or(&host).to_owned()
}

/// Per-connection protocol state (like the C++ `BrowserAction` instance).
pub struct ClientSession {
    keypair: KeyPair,
    client_public: Option<Vec<u8>>,
    associated: bool,
}

impl ClientSession {
    pub fn new() -> ClientSession {
        ClientSession {
            keypair: KeyPair::generate().expect("RNG available"),
            client_public: None,
            associated: false,
        }
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.keypair.public)
    }

    /// Handle one outer request frame; returns the outer response frame.
    pub fn handle(&mut self, state: &mut ServiceState, request: &Value) -> Value {
        let Some(action) = get_str(request, "action") else {
            return error_reply("", ERROR_INCORRECT_ACTION);
        };

        // change-public-keys is the only unencrypted action.
        if action == ACTION_CHANGE_PUBLIC_KEYS {
            return self.handle_change_public_keys(request, &action);
        }

        // Everything else is encrypted with this session's keys.
        let Some(client_public) = self.client_public.clone() else {
            return error_reply(&action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        };
        let Some(nonce_b64) = get_str(request, "nonce") else {
            return error_reply(&action, ERROR_CANNOT_DECRYPT_MESSAGE);
        };
        let Some(message_b64) = get_str(request, "message") else {
            return error_reply(&action, ERROR_CANNOT_DECRYPT_MESSAGE);
        };

        let nonce = B64
            .decode(nonce_b64.as_bytes())
            .unwrap_or_default();
        if nonce.len() != crate::crypto::NONCE_LEN {
            return error_reply(&action, ERROR_CANNOT_DECRYPT_MESSAGE);
        }

        let Ok(inner) = open(&client_public, &self.keypair.secret, &nonce, &message_b64) else {
            return error_reply(&action, ERROR_CANNOT_DECRYPT_MESSAGE);
        };
        let Ok(inner) = serde_json::from_slice::<Value>(&inner) else {
            return error_reply(&action, ERROR_CANNOT_DECRYPT_MESSAGE);
        };

        // Responses use the request nonce + 1 (KeePassXC-Browser rule).
        let response_nonce_bytes = increment_nonce(&nonce);
        let response_nonce = B64.encode(response_nonce_bytes);

        let inner_action = get_str(&inner, "action").unwrap_or_default();
        let params = match action.as_str() {
            ACTION_GET_DATABASEHASH => self.get_database_hash(&inner, &inner_action),
            ACTION_ASSOCIATE => self.associate(state, &inner, &client_public),
            ACTION_TEST_ASSOCIATE => self.test_associate(state, &inner),
            ACTION_GET_LOGINS => self.get_logins(state, &inner),
            ACTION_GENERATE_PASSWORD => Ok(vec![(
                "password",
                json!(generate_password()),
            )]),
            ACTION_LOCK_DATABASE => Ok(vec![]),
            _ => Err(ERROR_INCORRECT_ACTION),
        };

        match params {
            Ok(params) => {
                let message = build_message(&response_nonce, &params);
                let Ok(plaintext) = serde_json::to_vec(&Value::Object(message)) else {
                    return error_reply(&action, ERROR_CANNOT_ENCRYPT_MESSAGE);
                };
        let Ok(sealed) = seal(&client_public, &self.keypair.secret, &response_nonce_bytes, &plaintext)
                else {
                    return error_reply(&action, ERROR_CANNOT_ENCRYPT_MESSAGE);
                };
                encrypted_reply(&action, &sealed, &response_nonce)
            }
            Err(code) => error_reply(&action, code),
        }
    }

    fn handle_change_public_keys(&mut self, request: &Value, action: &str) -> Value {
        let Some(nonce) = get_str(request, "nonce") else {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        };
        let Some(public_key) = get_str(request, "publicKey") else {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        };
        let nonce_bytes = B64
            .decode(nonce.as_bytes())
            .unwrap_or_default();
        if nonce_bytes.len() != crate::crypto::NONCE_LEN {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        }
        let Ok(public) = B64.decode(public_key.as_bytes()) else {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        };

        // A new key handshake resets the association state for this
        // connection (same as the C++).
        self.associated = false;
        self.client_public = Some(public);

        // Unencrypted reply: version/success/nonce + action + publicKey,
        // with the nonce incremented by one.
        let incremented = B64.encode(increment_nonce(&nonce_bytes));
        let mut response = build_message(&incremented, &[]);
        response.insert("action".into(), json!(action));
        response.insert("publicKey".into(), json!(self.public_key_b64()));
        Value::Object(response)
    }

    fn get_database_hash(
        &self,
        inner: &Value,
        inner_action: &str,
    ) -> Result<Vec<(&'static str, Value)>, i32> {
        let hash = get_str(inner, "hash").unwrap_or_default();
        if hash.is_empty() {
            return Err(ERROR_DATABASE_HASH_NOT_RECEIVED);
        }
        if inner_action != ACTION_GET_DATABASEHASH {
            return Err(ERROR_CANNOT_DECRYPT_MESSAGE);
        }
        // KeePassXC 2.8.0 echoes the client's database hash back.
        Ok(vec![("hash", json!(hash))])
    }

    fn associate(
        &mut self,
        state: &mut ServiceState,
        inner: &Value,
        client_public: &[u8],
    ) -> Result<Vec<(&'static str, Value)>, i32> {
        let key = get_str(inner, "key").unwrap_or_default();
        if key.is_empty() {
            return Err(ERROR_ASSOCIATION_FAILED);
        }
        // The key must match the public key used for this connection.
        if B64.encode(client_public) != key {
            return Err(ERROR_ASSOCIATION_FAILED);
        }
        // Identification key: defaults to the connection key (backwards
        // compatibility, like the C++).
        let id_key = get_str(inner, "idKey").unwrap_or(key);

        // Store (or reuse) the association.
        if let Some((existing_id, _)) = state.associations.iter().find(|(_, v)| **v == id_key) {
            let id = existing_id.clone();
            self.associated = true;
            let hash = get_str(inner, "hash").unwrap_or_default();
            return Ok(vec![("hash", json!(hash)), ("id", json!(id))]);
        }
        let n = state.associations.len() + 1;
        let id = format!("KeePassXC-Browser_Identifier_{n}");
        state.associations.insert(id.clone(), id_key.clone());
        state.new_associations.push((id.clone(), id_key));
        self.associated = true;

        let hash = get_str(inner, "hash").unwrap_or_default();
        Ok(vec![("hash", json!(hash)), ("id", json!(id))])
    }

    fn test_associate(&mut self, state: &ServiceState, inner: &Value) -> Result<Vec<(&'static str, Value)>, i32> {
        let key = get_str(inner, "key").unwrap_or_default();
        let id = get_str(inner, "id").unwrap_or_default();
        if key.is_empty() || id.is_empty() {
            return Err(ERROR_DATABASE_NOT_OPENED);
        }
        match state.associations.get(&id) {
            Some(stored) if *stored == key => {
                self.associated = true;
                let hash = get_str(inner, "hash").unwrap_or_default();
                Ok(vec![("hash", json!(hash)), ("id", json!(id))])
            }
            _ => Err(ERROR_ASSOCIATION_FAILED),
        }
    }

    fn get_logins(&self, state: &ServiceState, inner: &Value) -> Result<Vec<(&'static str, Value)>, i32> {
        if !self.associated {
            return Err(ERROR_ASSOCIATION_FAILED);
        }
        let url = get_str(inner, "url").unwrap_or_default();
        if url.is_empty() {
            return Err(ERROR_NO_URL_PROVIDED);
        }
        let id = get_str(inner, "id").unwrap_or_default();
        let hash = get_str(inner, "hash").unwrap_or_default();

        let matches = state.find_entries(&url);
        if matches.is_empty() {
            return Err(ERROR_NO_LOGINS_FOUND);
        }
        let entries: Vec<Value> = matches
            .iter()
            .map(|e| {
                json!({
                    "login": B64.encode(e.username.as_bytes()),
                    "password": B64.encode(e.password.as_bytes()),
                    "name": e.title,
                    "uuid": e.uuid,
                    "url": e.url,
                })
            })
            .collect();
        Ok(vec![
            ("count", json!(entries.len())),
            ("entries", Value::Array(entries)),
            ("hash", json!(hash)),
            ("id", json!(id)),
        ])
    }
}

/// Generate a password for `generate-password` (printable, like KeePassXC).
pub fn generate_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = vec![0u8; 24];
    let _ = getrandom::fill(&mut buf);
    buf.iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}
