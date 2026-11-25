//! The browser-protocol action state machine: per-connection client state,
//! associations, and credential lookup — mirroring KeePassXC 2.8.0's
//! `BrowserAction` + `BrowserService` behavior for the supported subset.
//!
//! The server holds [`ServiceState`] behind a mutex shared with the GUI. Long
//! operations that need the user (association approval, `set-login`) are
//! handled by cloning the [`BrowserBridge`] and calling it **without** holding
//! the state lock, so the GUI can keep painting and updating the snapshot.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use friendlypass::matching::{self, MatchCandidate, MatchTarget};
use serde_json::{json, Value};

use crate::bridge::{AssociationRequest, BrowserBridge, DenyAllBridge, SetLoginRequest};
use crate::crypto::{increment_nonce, open, seal, KeyPair};
use crate::peer::PeerInfo;
use crate::protocol::*;
use crate::push::PushHub;

/// One credential served to `get-logins`.
#[derive(Clone, Debug, Default)]
pub struct CredentialEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    /// Dashless 32-hex RFC 4122 UUID.
    pub uuid: String,
    /// Immediate group name.
    pub group: String,
    /// Immediate group UUID (dashless).
    pub group_uuid: String,
    /// Additional URLs (`KP2A_URL`, `KP2A_URL_1`, …).
    pub additional_urls: Vec<String>,
    /// The raw `otp` attribute; the current code is computed on demand.
    pub totp_url: Option<String>,
    pub expired: bool,
    /// `"true"` / `"false"` when configured on the entry/group.
    pub skip_auto_submit: Option<String>,
    /// `KPH: …` string fields `(key, value)`.
    pub string_fields: Vec<(String, String)>,
    pub http_only: bool,
    pub not_http_auth: bool,
}

/// One node of the `get-database-groups` tree (recycle bin excluded).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupNode {
    pub name: String,
    /// Dashless 32-hex RFC 4122 UUID.
    pub uuid: String,
    pub children: Vec<GroupNode>,
}

impl GroupNode {
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "uuid": self.uuid,
            "children": self.children.iter().map(GroupNode::to_json).collect::<Vec<_>>(),
        })
    }
}

/// What the Browser Integration dialog shows for one association.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssociationInfo {
    /// Display name of the browser that created the association.
    pub browser: String,
    /// The host verified the browser's code signature.
    pub verified: bool,
    /// The association was approved without a dialog (§5).
    pub auto_approved: bool,
}

/// Shared server state, refreshed by the GUI side.
#[derive(Default)]
pub struct ServiceState {
    /// Empty while locked or when no hash can be produced.
    pub db_hash: String,
    /// `true` when no database is unlocked. Credential actions then fail with
    /// error 1 and the hash is reported as unavailable.
    pub locked: bool,
    pub entries: Vec<CredentialEntry>,
    pub groups: Vec<GroupNode>,
    /// association id -> browser identification public key (Base64).
    pub associations: HashMap<String, String>,
    /// Per-association display metadata captured while the browser is
    /// connected. Only the current app run knows this; associations loaded
    /// from database metadata fall back to their name (see the GUI).
    pub associations_info: HashMap<String, AssociationInfo>,
    /// Set when the association set changed and the GUI should persist it.
    pub associations_changed: bool,
    /// GUI-provided snapshot fingerprint; the server never interprets it.
    pub snapshot_signature: u64,
    pub bridge: Option<Arc<dyn BrowserBridge>>,
    pub push: Arc<PushHub>,
    /// Version reported by host-level `ping`/`hello`.
    pub app_version: String,
}

impl ServiceState {
    pub fn db_hash(&self) -> &str {
        &self.db_hash
    }

    pub fn set_bridge(&mut self, bridge: Arc<dyn BrowserBridge>) {
        self.bridge = Some(bridge);
    }

    fn bridge(&self) -> Arc<dyn BrowserBridge> {
        self.bridge
            .clone()
            .unwrap_or_else(|| Arc::new(DenyAllBridge))
    }

    /// Find credentials matching a URL host/path (KeePassXC's `findEntries`
    /// subset), sorted by match quality. Recycle-bin entries never reach this
    /// list — the snapshot excludes them.
    ///
    /// Scoring lives in [`friendlypass::matching`] so the Android vault matches
    /// URLs exactly like the browser does.
    pub fn find_entries(
        &self,
        url: &str,
        submit_url: Option<&str>,
        http_auth: bool,
    ) -> Vec<&CredentialEntry> {
        let allowed = |entry: &&CredentialEntry| {
            if http_auth {
                !entry.not_http_auth
            } else {
                !entry.http_only
            }
        };

        // `keepassxc://by-uuid/<uuid>` is used by the extension's diagnostics
        // and names one entry directly rather than scoring URLs.
        if let Some(uuid) = matching::by_uuid_target(url) {
            return self
                .entries
                .iter()
                .filter(allowed)
                .filter(|entry| entry.uuid == uuid)
                .collect();
        }

        let target = MatchTarget {
            web_url: Some(url),
            android_package: None,
        };
        let form_target = submit_url.map(|form| MatchTarget {
            web_url: Some(form),
            android_package: None,
        });
        let mut matches: Vec<(u16, &CredentialEntry)> = self
            .entries
            .iter()
            .filter(allowed)
            .filter_map(|entry| {
                let candidate = MatchCandidate {
                    url: &entry.url,
                    additional_urls: &entry.additional_urls,
                    android_apps: &[],
                };
                let mut best = matching::score(&candidate, &target);
                if let Some(form) = &form_target {
                    if let Some(form_score) = matching::score(&candidate, form) {
                        best = Some(best.map_or(form_score, |score| score.min(form_score)));
                    }
                }
                best.map(|score| (score, entry))
            })
            .collect();
        matches.sort_by_key(|(score, entry)| (*score, entry.title.to_lowercase()));
        matches.into_iter().map(|(_, entry)| entry).collect()
    }
}

/// Per-connection protocol state (like the C++ `BrowserAction` instance).
pub struct ClientSession {
    keypair: KeyPair,
    client_public: Option<Vec<u8>>,
    associated: bool,
    /// The association id this connection verified, if any.
    association_id: Option<String>,
    session_id: String,
    client_id: String,
    /// What the app verified about the socket peer (§3).
    peer: PeerInfo,
    /// Browser identity from `host-identify`, only kept for a trusted peer.
    browser: Option<BrowserIdentity>,
}

impl ClientSession {
    pub fn new() -> ClientSession {
        ClientSession::with_keypair_impl(KeyPair::generate().unwrap_or(KeyPair {
            public: [0u8; 32],
            secret: vec![0u8; 32],
        }))
    }

    /// Attach the peer verification result the server computed on accept.
    pub fn with_peer(mut self, peer: PeerInfo) -> ClientSession {
        self.peer = peer;
        self
    }

    /// Build a session around a fixed host keypair (golden-vector tests and
    /// deterministic fixtures). Production always uses [`ClientSession::new`].
    pub fn with_keypair(keypair: KeyPair) -> ClientSession {
        ClientSession::with_keypair_impl(keypair)
    }

    fn with_keypair_impl(keypair: KeyPair) -> ClientSession {
        ClientSession {
            keypair,
            client_public: None,
            associated: false,
            association_id: None,
            session_id: generate_session_id(),
            client_id: String::new(),
            peer: PeerInfo::default(),
            browser: None,
        }
    }

    /// Trust a client session public key without running
    /// `change-public-keys`. Only for deterministic fixture harnesses.
    pub fn accept_client_key(&mut self, public: Vec<u8>) {
        self.client_public = Some(public);
    }

    pub fn is_associated(&self) -> bool {
        self.associated
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.keypair.public)
    }

    /// Handle one outer request frame; returns the outer response frame.
    pub fn handle(&mut self, state: &SharedState, request: &Value) -> Value {
        let Some(action) = get_str(request, "action") else {
            return error_reply("", ERROR_INCORRECT_ACTION);
        };
        if let Some(client_id) = get_str(request, "clientID") {
            self.client_id = client_id;
        }

        match action.as_str() {
            ACTION_CHANGE_PUBLIC_KEYS => return self.handle_change_public_keys(request, &action),
            ACTION_PING | ACTION_HELLO => return self.handle_status(state, request, &action),
            ACTION_HOST_IDENTIFY => return self.handle_host_identify(request),
            _ => {}
        }

        // Every other action requires an unlocked database. `triggerUnlock`
        // asks the GUI to raise its unlock UI; the reply is still error 1.
        let (locked, bridge) = {
            let guard = lock_state(state);
            (guard.locked, guard.bridge.clone())
        };
        if locked {
            if get_bool(request, "triggerUnlock") {
                if let Some(bridge) = bridge {
                    bridge.request_unlock();
                }
            }
            return error_reply(&action, ERROR_DATABASE_NOT_OPENED);
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
        if message_b64.is_empty() {
            return error_reply(&action, ERROR_EMPTY_MESSAGE_RECEIVED);
        }

        let Ok(nonce) = B64.decode(nonce_b64.as_bytes()) else {
            return error_reply(&action, ERROR_CANNOT_DECRYPT_MESSAGE);
        };
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

        let inner_action = get_str(&inner, "action").unwrap_or_default();
        if inner_action != action {
            let code = if action == ACTION_GET_DATABASEHASH {
                ERROR_CANNOT_DECRYPT_MESSAGE
            } else {
                ERROR_INCORRECT_ACTION
            };
            return error_reply(&action, code);
        }

        let result = match action.as_str() {
            ACTION_GET_DATABASEHASH => Self::get_database_hash(state),
            ACTION_ASSOCIATE => self.associate(state, &inner, &client_public),
            ACTION_TEST_ASSOCIATE => self.test_associate(state, &inner),
            ACTION_GET_LOGINS => self.get_logins(state, &inner),
            ACTION_SET_LOGIN => self.set_login(state, &inner),
            ACTION_GET_TOTP => self.get_totp(state, &inner),
            ACTION_GET_DATABASE_GROUPS => self.get_database_groups(state),
            ACTION_GENERATE_PASSWORD => self.generate_password(state),
            ACTION_LOCK_DATABASE => Self::lock_database(state),
            _ => Err(ERROR_INCORRECT_ACTION),
        };

        match result {
            Ok(params) => {
                self.encrypt_reply(&action, &client_public, &response_nonce_bytes, params)
            }
            Err(code) => error_reply(&action, code),
        }
    }

    fn encrypt_reply(
        &self,
        action: &str,
        client_public: &[u8],
        nonce: &[u8],
        params: Vec<(&'static str, Value)>,
    ) -> Value {
        let response_nonce = B64.encode(nonce);
        let message = build_message(&response_nonce, &params);
        let Ok(plaintext) = serde_json::to_vec(&Value::Object(message)) else {
            return error_reply(action, ERROR_CANNOT_ENCRYPT_MESSAGE);
        };
        let Ok(sealed) = seal(client_public, &self.keypair.secret, nonce, &plaintext) else {
            return error_reply(action, ERROR_CANNOT_ENCRYPT_MESSAGE);
        };
        encrypted_reply(action, &sealed, &response_nonce)
    }

    /// A session's association stays valid only while the GUI still lists it
    /// (revoking an association invalidates live sessions).
    fn still_associated(&self, state: &SharedState) -> bool {
        let Some(id) = self.association_id.as_deref() else {
            return false;
        };
        lock_state(state).associations.contains_key(id)
    }

    fn handle_change_public_keys(&mut self, request: &Value, action: &str) -> Value {
        let Some(nonce) = get_str(request, "nonce") else {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        };
        let Some(public_key) = get_str(request, "publicKey") else {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        };
        let Ok(nonce_bytes) = B64.decode(nonce.as_bytes()) else {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        };
        if nonce_bytes.len() != crate::crypto::NONCE_LEN {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        }
        let Ok(public) = B64.decode(public_key.as_bytes()) else {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        };
        if public.len() != 32 {
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
        }

        // A fresh host session keypair and association flag per handshake.
        let Ok(keypair) = KeyPair::generate() else {
            return error_reply(action, ERROR_ENCRYPTION_KEY_UNRECOGNIZED);
        };
        self.keypair = keypair;
        self.associated = false;
        self.association_id = None;
        self.client_public = Some(public);

        // Unencrypted reply: the common prefix plus action + publicKey, with
        // the nonce incremented by one.
        let incremented = B64.encode(increment_nonce(&nonce_bytes));
        let mut response = build_message(&incremented, &[]);
        response.insert("action".into(), json!(action));
        response.insert("publicKey".into(), json!(self.public_key_b64()));
        Value::Object(response)
    }

    /// **[friendlypass]** host-level `ping`/`hello`, answered unencrypted.
    /// ACTIONS.md specifies these for the host; the app answers them too so a
    /// direct connection (tests, diagnostics, a future proxy-less host) gets
    /// consistent status.
    fn handle_status(&self, state: &SharedState, request: &Value, action: &str) -> Value {
        let (locked, hash) = {
            let guard = lock_state(state);
            (guard.locked, guard.db_hash.clone())
        };
        let app_version = {
            let guard = lock_state(state);
            if guard.app_version.is_empty() {
                env!("CARGO_PKG_VERSION").to_owned()
            } else {
                guard.app_version.clone()
            }
        };
        let mut response = serde_json::Map::new();
        response.insert("action".into(), json!(action));
        response.insert("success".into(), json!("true"));
        response.insert("protocolVersion".into(), json!(PROTOCOL_VERSION));
        response.insert("hostVersion".into(), json!(env!("CARGO_PKG_VERSION")));
        response.insert("appRunning".into(), json!(true));
        response.insert("appVersion".into(), json!(app_version));
        response.insert("locked".into(), json!(locked));
        response.insert(
            "databaseHash".into(),
            if locked || hash.is_empty() {
                Value::Null
            } else {
                json!(hash)
            },
        );
        if action == ACTION_PING {
            if let Some(nonce) = get_str(request, "nonce") {
                // Host-level ping echoes the nonce verbatim (not incremented).
                response.insert("nonce".into(), json!(nonce));
            }
        } else {
            response.insert("sessionId".into(), json!(self.session_id));
            response.insert("hostPid".into(), json!(std::process::id()));
        }
        Value::Object(response)
    }

    /// **[friendlypass]** `host-identify` (§2). Host-level and unencrypted: it
    /// answers the connection's trust state and, only for a trusted peer,
    /// stores the browser identity for the association decision.
    fn handle_host_identify(&mut self, request: &Value) -> Value {
        if self.peer.trusted {
            self.browser = browser_identity(request);
        }
        host_identify_reply(self.peer.trusted)
    }

    /// Contract §5: the auto-approve chain needs our host as the socket peer
    /// and a browser the host itself verified.
    fn auto_approvable(&self) -> bool {
        self.peer.trusted
            && self
                .browser
                .as_ref()
                .is_some_and(|browser| browser.verified)
    }

    /// Remember how this association came about, for the Browser Integration
    /// dialog ("Chrome · verified" / "Chrome · approved manually").
    fn remember_association(&self, state: &SharedState, id: &str, auto_name: Option<&str>) {
        let Some(browser) = self.browser.as_ref() else {
            return;
        };
        let mut state = lock_state(state);
        let previous = state
            .associations_info
            .get(id)
            .map(|info| info.auto_approved);
        // On a later `test-associate` (auto_name = None) the earlier verdict
        // stays; for an association loaded from database metadata the name
        // shape is all that is left.
        let auto_approved = match auto_name {
            Some(name) => name == id,
            None => previous
                .unwrap_or_else(|| crate::bridge::automatic_association_browser(id).is_some()),
        };
        state.associations_info.insert(
            id.to_owned(),
            AssociationInfo {
                browser: browser.display_name().to_owned(),
                verified: browser.verified,
                auto_approved,
            },
        );
    }

    fn get_database_hash(state: &SharedState) -> Result<Vec<(&'static str, Value)>, i32> {
        let guard = lock_state(state);
        if guard.locked {
            return Err(ERROR_DATABASE_NOT_OPENED);
        }
        if guard.db_hash.is_empty() {
            return Err(ERROR_DATABASE_HASH_NOT_RECEIVED);
        }
        Ok(vec![("hash", json!(guard.db_hash))])
    }

    fn associate(
        &mut self,
        state: &SharedState,
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
        let id_key = get_str(inner, "idKey")
            .filter(|value| !value.is_empty())
            .unwrap_or(key);
        if B64.decode(id_key.as_bytes()).map(|bytes| bytes.len()) != Ok(32) {
            return Err(ERROR_ASSOCIATION_FAILED);
        }

        // Existing association for this identification key: reuse its id.
        let (existing_id, bridge, hash, client_id) = {
            let guard = lock_state(state);
            (
                guard
                    .associations
                    .iter()
                    .find(|(_, stored)| **stored == id_key)
                    .map(|(id, _)| id.clone()),
                guard.bridge.clone(),
                guard.db_hash.clone(),
                self.client_id.clone(),
            )
        };
        if let Some(id) = existing_id {
            self.associated = true;
            self.association_id = Some(id.clone());
            self.remember_association(state, &id, None);
            return Ok(vec![("hash", json!(hash)), ("id", json!(id))]);
        }

        // A new association needs explicit user approval. The bridge call is
        // made without the state lock so the GUI can keep working.
        let Some(bridge) = bridge else {
            return Err(ERROR_ACTION_CANCELLED_OR_DENIED);
        };
        let (auto_approvable, browser) = (self.auto_approvable(), self.browser.clone());
        let request = AssociationRequest {
            client_id,
            suggested_id: default_association_id(&self.session_id),
            browser,
            auto_approvable,
        };
        let auto_name = auto_approvable.then(|| request.auto_approved_name());
        let Some(chosen) = bridge.approve_association(&request) else {
            return Err(ERROR_ACTION_CANCELLED_OR_DENIED);
        };
        let chosen = chosen.trim().to_owned();
        if chosen.is_empty() {
            return Err(ERROR_ACTION_CANCELLED_OR_DENIED);
        }

        let hash = {
            let mut guard = lock_state(state);
            if guard
                .associations
                .get(&chosen)
                .is_some_and(|existing| *existing != id_key)
            {
                // A different browser already owns that id: fail closed
                // rather than overwrite (the user can approve another name).
                return Err(ERROR_ASSOCIATION_FAILED);
            }
            guard.associations.insert(chosen.clone(), id_key);
            guard.associations_changed = true;
            guard.db_hash.clone()
        };

        self.associated = true;
        self.association_id = Some(chosen.clone());
        self.remember_association(state, &chosen, auto_name.as_deref());
        Ok(vec![("hash", json!(hash)), ("id", json!(chosen))])
    }

    fn test_associate(
        &mut self,
        state: &SharedState,
        inner: &Value,
    ) -> Result<Vec<(&'static str, Value)>, i32> {
        let key = get_str(inner, "key").unwrap_or_default();
        let id = get_str(inner, "id").unwrap_or_default();
        if key.is_empty() || id.is_empty() {
            return Err(ERROR_DATABASE_NOT_OPENED);
        }
        let guard = lock_state(state);
        match guard.associations.get(&id) {
            Some(stored) if *stored == key => {
                drop(guard);
                self.associated = true;
                self.association_id = Some(id.clone());
                self.remember_association(state, &id, None);
                let hash = lock_state(state).db_hash.clone();
                Ok(vec![("hash", json!(hash)), ("id", json!(id))])
            }
            _ => Err(ERROR_ASSOCIATION_FAILED),
        }
    }

    fn get_logins(
        &self,
        state: &SharedState,
        inner: &Value,
    ) -> Result<Vec<(&'static str, Value)>, i32> {
        if !self.associated || !self.still_associated(state) {
            return Err(ERROR_ASSOCIATION_FAILED);
        }
        let url = get_str(inner, "url").unwrap_or_default();
        // KeePassXC caps the URL at 8 KiB; anything longer cannot be a real
        // page and would only inflate the reply.
        if url.is_empty() || url.len() > 8 * 1024 {
            return Err(ERROR_NO_URL_PROVIDED);
        }
        let submit_url = get_str(inner, "submitUrl");
        let http_auth = get_bool(inner, "httpAuth");
        let requested_id = get_str(inner, "id")
            .filter(|id| !id.is_empty())
            .or_else(|| self.association_id.clone())
            .unwrap_or_default();

        let guard = lock_state(state);
        if !keys_authorised(&guard, inner) {
            return Err(ERROR_NO_LOGINS_FOUND);
        }
        let matches = guard.find_entries(&url, submit_url.as_deref(), http_auth);
        if matches.is_empty() {
            return Err(ERROR_NO_LOGINS_FOUND);
        }
        let entries: Vec<Value> = matches.iter().map(|entry| entry_to_json(entry)).collect();
        Ok(vec![
            ("count", json!(entries.len())),
            ("entries", Value::Array(entries)),
            ("hash", json!(guard.db_hash)),
            ("id", json!(requested_id)),
        ])
    }

    fn set_login(
        &self,
        state: &SharedState,
        inner: &Value,
    ) -> Result<Vec<(&'static str, Value)>, i32> {
        if !self.associated || !self.still_associated(state) {
            return Err(ERROR_ASSOCIATION_FAILED);
        }
        let url = get_str(inner, "url").unwrap_or_default();
        if url.is_empty() {
            return Err(ERROR_NO_URL_PROVIDED);
        }
        let login = get_str(inner, "login").unwrap_or_default();
        let password = get_str(inner, "password").unwrap_or_default();
        if has_reference(&login) || has_reference(&password) {
            return Err(ERROR_CANNOT_USE_REFERENCES);
        }
        let uuid = match get_str(inner, "uuid") {
            Some(raw) if !raw.is_empty() => {
                Some(normalize_uuid(&raw).ok_or(ERROR_NO_VALID_UUID_PROVIDED)?)
            }
            _ => None,
        };
        let request = SetLoginRequest {
            acting_id: get_str(inner, "id").unwrap_or_else(|| self.client_id.clone()),
            login,
            password,
            url,
            submit_url: get_str(inner, "submitUrl").filter(|value| !value.is_empty()),
            group: get_str(inner, "group").filter(|value| !value.is_empty()),
            group_uuid: get_str(inner, "groupUuid").filter(|value| !value.is_empty()),
            uuid,
            download_favicon: get_bool(inner, "downloadFavicon"),
            title: get_str(inner, "title").filter(|value| !value.is_empty()),
        };
        let bridge = lock_state(state).bridge();
        let accepted = bridge.apply_set_login(&request);
        let hash = lock_state(state).db_hash.clone();
        Ok(vec![
            ("count", Value::Null),
            ("entries", Value::Null),
            ("error", json!(if accepted { "success" } else { "error" })),
            ("hash", json!(hash)),
        ])
    }

    fn get_totp(
        &self,
        state: &SharedState,
        inner: &Value,
    ) -> Result<Vec<(&'static str, Value)>, i32> {
        if !self.associated || !self.still_associated(state) {
            return Err(ERROR_ASSOCIATION_FAILED);
        }
        let raw = get_str(inner, "uuid").unwrap_or_default();
        let uuid = normalize_uuid(&raw).ok_or(ERROR_NO_VALID_UUID_PROVIDED)?;
        let guard = lock_state(state);
        let entry = guard.entries.iter().find(|entry| entry.uuid == uuid);
        let code = entry
            .and_then(|entry| entry.totp_url.as_deref())
            .and_then(current_totp_code)
            .unwrap_or_default();
        Ok(vec![("totp", json!(code))])
    }

    fn get_database_groups(&self, state: &SharedState) -> Result<Vec<(&'static str, Value)>, i32> {
        if !self.associated || !self.still_associated(state) {
            return Err(ERROR_ASSOCIATION_FAILED);
        }
        let guard = lock_state(state);
        if guard.groups.is_empty() {
            return Err(ERROR_NO_GROUPS_FOUND);
        }
        let roots: Vec<Value> = guard.groups.iter().map(GroupNode::to_json).collect();
        // Intentionally nested: the official extension reads response.groups.groups.
        Ok(vec![("groups", json!({ "groups": roots }))])
    }

    fn generate_password(&self, state: &SharedState) -> Result<Vec<(&'static str, Value)>, i32> {
        if !self.associated || !self.still_associated(state) {
            return Err(ERROR_ASSOCIATION_FAILED);
        }
        // `action` makes the asynchronous reply self-describing so the host can
        // retire its pending entry (WP1 request 4); the extra field is additive
        // and ignored by KeePassXC clients.
        Ok(vec![
            ("action", json!(ACTION_GENERATE_PASSWORD)),
            ("password", json!(generate_password())),
        ])
    }

    fn lock_database(state: &SharedState) -> Result<Vec<(&'static str, Value)>, i32> {
        let (bridge, push) = {
            let guard = lock_state(state);
            if guard.locked {
                return Err(ERROR_DATABASE_NOT_OPENED);
            }
            (guard.bridge(), Arc::clone(&guard.push))
        };
        bridge.lock_database();
        {
            let mut guard = lock_state(state);
            guard.locked = true;
        }
        push.send_locked();
        Ok(vec![])
    }
}

impl Default for ClientSession {
    fn default() -> Self {
        Self::new()
    }
}

/// The shared server state handle.
pub type SharedState = Arc<Mutex<ServiceState>>;

pub fn lock_state(state: &SharedState) -> MutexGuard<'_, ServiceState> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `keys` is the extension's full keyring. When present it must contain an
/// association that matches this database; an empty list matches nothing
/// (KeePassXC returns error 15, not an empty result).
fn keys_authorised(state: &ServiceState, inner: &Value) -> bool {
    let Some(keys) = inner.get("keys") else {
        return true;
    };
    let Some(keys) = keys.as_array() else {
        return false;
    };
    if keys.is_empty() {
        return false;
    }
    keys.iter().any(|pair| {
        let id = pair.get("id").and_then(Value::as_str).unwrap_or_default();
        let key = pair.get("key").and_then(Value::as_str).unwrap_or_default();
        !key.is_empty()
            && state
                .associations
                .get(id)
                .is_some_and(|stored| stored == key)
    })
}

fn entry_to_json(entry: &CredentialEntry) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("login".into(), json!(entry.username));
    object.insert("password".into(), json!(entry.password));
    object.insert("name".into(), json!(entry.title));
    object.insert("uuid".into(), json!(entry.uuid));
    object.insert("group".into(), json!(entry.group));
    if let Some(code) = entry.totp_url.as_deref().and_then(current_totp_code) {
        object.insert("totp".into(), json!(code));
    }
    if entry.expired {
        object.insert("expired".into(), json!("true"));
    }
    if let Some(skip) = &entry.skip_auto_submit {
        object.insert("skipAutoSubmit".into(), json!(skip));
    }
    if !entry.string_fields.is_empty() {
        let fields: Vec<Value> = entry
            .string_fields
            .iter()
            .map(|(key, value)| json!({ key.clone(): value }))
            .collect();
        object.insert("stringFields".into(), Value::Array(fields));
    }
    Value::Object(object)
}

fn current_totp_code(url: &str) -> Option<String> {
    let totp: keepass::db::TOTP = url.parse().ok()?;
    Some(totp.value_now().ok()?.code)
}

fn generate_session_id() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    // UUID v4 layout, formatted like the fixture (`hello.sessionId`).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn default_association_id(session_id: &str) -> String {
    let suffix: String = session_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(6)
        .collect();
    if suffix.is_empty() {
        "chrome-browser".into()
    } else {
        format!("chrome-browser-{suffix}")
    }
}

/// Generate a password for `generate-password` (printable, like KeePassXC).
pub fn generate_password() -> String {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-=?@^_";
    const MAX_ATTEMPT: u32 = 256;
    let mut buf = vec![0u8; 24];
    // Rejection sampling avoids modulo bias while staying deterministic in
    // size.
    let limit = (u8::MAX as usize / ALPHABET.len()) * ALPHABET.len();
    let mut out = String::with_capacity(24);
    let mut attempt = 0u32;
    while out.len() < 24 && attempt < MAX_ATTEMPT {
        attempt += 1;
        let _ = getrandom::fill(&mut buf);
        for &byte in &buf {
            if (byte as usize) < limit {
                out.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
                if out.len() == 24 {
                    break;
                }
            }
        }
    }
    while out.len() < 24 {
        // RNG failure is not expected; produce a safe fallback rather than
        // returning a short password.
        out.push('x');
    }
    out
}
