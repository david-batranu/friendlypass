//! macOS AutoFill Credential Provider bridge (Passkeys, Passwords, TOTP).
//!
//! The sandboxed `FriendlyPassCredentialProvider.appex` embedded in
//! `friendlypass.app/Contents/PlugIns/` connects to this server over a
//! per-user Unix domain socket inside the shared App Group container
//! (`cp.sock`). Every incoming connection is authenticated with
//! [`friendlypass_browser::peer::verify_peer`] (`LOCAL_PEERPID` + executable
//! path + macOS `cdhash`) before any frame is read.
//!
//! Read operations (`status`, `list_identities`, `list_credentials`,
//! `get_password`, `get_totp`, `assert_passkey`) are answered directly from an
//! in-memory snapshot kept in sync with the open database (and cleared the
//! moment the database locks). Passkey registration (`register_passkey`) runs
//! on the GUI thread so it mutates the live `Database`, saves atomically, and
//! refreshes both snapshots and macOS's `ASCredentialIdentityStore`.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use eframe::egui;
use friendlypass::matching::{self, MatchCandidate, MatchTarget};
use friendlypass_passkey::StoredPasskey;
use keepass::db::Database;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::app::App;

/// Maximum wire frame size (1 MiB).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// How long a socket thread waits for the GUI thread to complete a passkey
/// registration.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(15);
/// Environment variable overriding the credential provider Unix socket path.
pub const ENV_SOCKET: &str = "FP_CREDENTIAL_PROVIDER_SOCKET";
/// Environment variable overriding the expected peer executable path.
pub const ENV_PEER: &str = "FP_CREDENTIAL_PROVIDER_PEER";

// ---------------------------------------------------------------------------
// macOS Objective-C FFI (ASCredentialIdentityStore + App Group container)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_ffi {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int};
    use std::path::PathBuf;

    extern "C" {
        fn fp_macos_app_group_dir(buf: *mut c_char, len: usize) -> bool;
        fn fp_macos_credential_store_enabled() -> c_int;
        fn fp_macos_replace_credential_identities(json_utf8: *const c_char) -> c_int;
    }

    pub fn app_group_dir() -> Option<PathBuf> {
        let mut buf = vec![0u8; 1024];
        let ok = unsafe { fp_macos_app_group_dir(buf.as_mut_ptr().cast(), buf.len()) };
        if !ok {
            return None;
        }
        let cstr = unsafe { CStr::from_ptr(buf.as_ptr().cast()) };
        let text = cstr.to_str().ok()?;
        (!text.is_empty()).then(|| PathBuf::from(text))
    }

    pub fn credential_store_enabled() -> bool {
        unsafe { fp_macos_credential_store_enabled() == 1 }
    }

    /// Returns `Ok(true)` when synced, `Ok(false)` when disabled, `Err(())` on OS error.
    pub fn replace_credential_identities(json: &str) -> Result<bool, ()> {
        let cstr = CString::new(json).map_err(|_| ())?;
        match unsafe { fp_macos_replace_credential_identities(cstr.as_ptr()) } {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire protocol (4-byte LE length + UTF-8 JSON)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    All,
    Passkey,
    Password,
    Totp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status {
        #[serde(default)]
        request_unlock: bool,
    },
    ListIdentities,
    ListCredentials {
        kind: CredentialKind,
        #[serde(default)]
        service_identifiers: Vec<String>,
        #[serde(default)]
        rp_id: Option<String>,
        #[serde(default)]
        allowed_credential_ids_b64: Option<Vec<String>>,
        #[serde(default)]
        query: Option<String>,
    },
    GetPassword {
        uuid: String,
    },
    GetTotp {
        uuid: String,
    },
    AssertPasskey {
        #[serde(default)]
        uuid: Option<String>,
        rp_id: String,
        #[serde(default)]
        credential_id_b64: Option<String>,
        client_data_hash_b64: String,
    },
    RegisterPasskey {
        rp_id: String,
        username: String,
        user_handle_b64: String,
        client_data_hash_b64: String,
        #[serde(default)]
        algorithms: Vec<i64>,
        #[serde(default)]
        excluded_credential_ids_b64: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyIdentity {
    pub uuid: String,
    pub rp_id: String,
    pub username: String,
    pub credential_id_b64: String,
    pub user_handle_b64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordIdentity {
    pub uuid: String,
    pub service: String,
    pub is_url: bool,
    pub username: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpIdentity {
    pub uuid: String,
    pub service: String,
    pub is_url: bool,
    pub label: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBundle {
    pub passkeys: Vec<PasskeyIdentity>,
    pub passwords: Vec<PasswordIdentity>,
    pub totps: Vec<TotpIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialItem {
    pub kind: CredentialKind,
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub subtitle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id_b64: Option<String>,
    pub matched: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponsePayload {
    Status {
        unlocked: bool,
        db_name: Option<String>,
    },
    Identities {
        passkeys: Vec<PasskeyIdentity>,
        passwords: Vec<PasswordIdentity>,
        totps: Vec<TotpIdentity>,
    },
    Credentials {
        items: Vec<CredentialItem>,
    },
    Password {
        username: String,
        password: String,
    },
    Totp {
        code: String,
        valid_for_secs: u64,
    },
    PasskeyAssertion {
        relying_party: String,
        credential_id_b64: String,
        user_handle_b64: String,
        authenticator_data_b64: String,
        signature_b64: String,
    },
    PasskeyRegistration {
        uuid: String,
        relying_party: String,
        credential_id_b64: String,
        attestation_object_b64: String,
    },
}

impl std::fmt::Debug for ResponsePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status { unlocked, db_name } => f
                .debug_struct("Status")
                .field("unlocked", unlocked)
                .field("db_name", db_name)
                .finish(),
            Self::Identities {
                passkeys,
                passwords,
                totps,
            } => f
                .debug_struct("Identities")
                .field("passkeys", &passkeys.len())
                .field("passwords", &passwords.len())
                .field("totps", &totps.len())
                .finish(),
            Self::Credentials { items } => f
                .debug_struct("Credentials")
                .field("items", &items.len())
                .finish(),
            Self::Password { username, .. } => f
                .debug_struct("Password")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Totp { valid_for_secs, .. } => f
                .debug_struct("Totp")
                .field("code", &"<redacted>")
                .field("valid_for_secs", valid_for_secs)
                .finish(),
            Self::PasskeyAssertion { relying_party, .. } => f
                .debug_struct("PasskeyAssertion")
                .field("relying_party", relying_party)
                .field("signature", &"<redacted>")
                .finish(),
            Self::PasskeyRegistration {
                uuid,
                relying_party,
                ..
            } => f
                .debug_struct("PasskeyRegistration")
                .field("uuid", uuid)
                .field("relying_party", relying_party)
                .finish(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<ResponsePayload>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("ok", &self.ok)
            .field("error", &self.error)
            .field("message", &self.message)
            .field("has_payload", &self.payload.is_some())
            .finish()
    }
}

impl Response {
    pub fn success(payload: ResponsePayload) -> Self {
        Self {
            ok: true,
            error: None,
            message: None,
            payload: Some(payload),
        }
    }

    pub fn err(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(code.into()),
            message: Some(message.into()),
            payload: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire framing helpers (4-byte LE length + JSON)
// ---------------------------------------------------------------------------

pub fn write_frame<W: std::io::Write>(writer: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds size limit",
        ));
    }
    let len = (bytes.len() as u32).to_le_bytes();
    writer.write_all(&len)?;
    writer.write_all(bytes)?;
    writer.flush()
}

pub fn read_frame<R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Snapshot built from the open Database
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SnapshotEntry {
    uuid: String,
    title: String,
    username: String,
    password: String,
    url: String,
    additional_urls: Vec<String>,
    totp_url: Option<String>,
    passkey: Option<StoredPasskey>,
    expired: bool,
}

impl std::fmt::Debug for SnapshotEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotEntry")
            .field("uuid", &self.uuid)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("has_totp", &self.totp_url.is_some())
            .field("passkey", &self.passkey)
            .field("expired", &self.expired)
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct ProviderSnapshot {
    pub unlocked: bool,
    pub db_name: Option<String>,
    pub signature: u64,
    entries: Vec<SnapshotEntry>,
}

impl std::fmt::Debug for ProviderSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderSnapshot")
            .field("unlocked", &self.unlocked)
            .field("db_name", &self.db_name)
            .field("signature", &self.signature)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl ProviderSnapshot {
    pub fn locked() -> Self {
        Self::default()
    }

    pub fn from_database(db: &Database, db_name: Option<String>) -> Self {
        let recycle = recycle_group_ids(db);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);

        let entries = db
            .iter_all_entries()
            .filter(|entry| !recycle.contains(&entry.parent().id().uuid().simple().to_string()))
            .map(|entry| {
                let mut additional_urls = Vec::new();
                if let Some(u) = entry.get("KP2A_URL").filter(|u| !u.is_empty()) {
                    additional_urls.push(u.to_owned());
                }
                let mut idx = 1u32;
                while let Some(u) = entry.get(&format!("KP2A_URL_{idx}")) {
                    if !u.is_empty() {
                        additional_urls.push(u.to_owned());
                    }
                    idx += 1;
                }
                let totp_url = entry
                    .get("otp")
                    .filter(|s| !s.is_empty())
                    .filter(|_| crate::totp::totp_of(&entry).is_some())
                    .map(str::to_owned);
                let passkey = StoredPasskey::from_fields(|k| entry.get(k).map(str::to_owned));
                let expired = entry.times.expires.unwrap_or(false)
                    && entry.times.expiry.and_utc().timestamp() < now_secs;

                SnapshotEntry {
                    uuid: entry.id().uuid().simple().to_string(),
                    title: entry.get("Title").unwrap_or_default().to_owned(),
                    username: entry.get("UserName").unwrap_or_default().to_owned(),
                    password: entry.get("Password").unwrap_or_default().to_owned(),
                    url: entry.get("URL").unwrap_or_default().to_owned(),
                    additional_urls,
                    totp_url,
                    passkey,
                    expired,
                }
            })
            .collect();

        Self {
            unlocked: true,
            db_name,
            signature: friendlypass_browser::snapshot_signature(db),
            entries,
        }
    }

    pub fn identities(&self) -> IdentityBundle {
        let mut bundle = IdentityBundle::default();
        if !self.unlocked {
            return bundle;
        }
        for entry in &self.entries {
            if entry.expired {
                continue;
            }
            if let Some(pk) = &entry.passkey {
                bundle.passkeys.push(PasskeyIdentity {
                    uuid: entry.uuid.clone(),
                    rp_id: pk.rp_id.clone(),
                    username: pk.username.clone(),
                    credential_id_b64: B64.encode(&pk.credential_id),
                    user_handle_b64: B64.encode(&pk.user_handle),
                });
            }

            let mut domains = entry_domains(entry);
            if domains.is_empty() {
                if let Some(pk) = &entry.passkey {
                    if !pk.rp_id.is_empty() {
                        domains.push(pk.rp_id.to_ascii_lowercase());
                    }
                }
            }

            if !entry.password.is_empty() {
                for domain in &domains {
                    bundle.passwords.push(PasswordIdentity {
                        uuid: entry.uuid.clone(),
                        service: domain.clone(),
                        is_url: false,
                        username: entry.username.clone(),
                    });
                }
            }

            if entry.totp_url.is_some() {
                let label = if !entry.username.is_empty() {
                    entry.username.clone()
                } else if !entry.title.is_empty() {
                    entry.title.clone()
                } else {
                    "One-Time Code".to_owned()
                };
                for domain in &domains {
                    bundle.totps.push(TotpIdentity {
                        uuid: entry.uuid.clone(),
                        service: domain.clone(),
                        is_url: false,
                        label: label.clone(),
                    });
                }
            }
        }
        bundle
    }
}

fn recycle_group_ids(db: &Database) -> HashSet<String> {
    let mut set = HashSet::new();
    let Some(recycle_uuid) = db.meta.recyclebin_uuid else {
        return set;
    };
    if recycle_uuid.is_nil() {
        return set;
    }
    let Some(group) = db
        .iter_all_groups()
        .find(|g| g.id().uuid() == recycle_uuid)
    else {
        return set;
    };
    collect_group_uuids(&group, &mut set);
    set
}

fn collect_group_uuids(group: &keepass::db::GroupRef<'_>, out: &mut HashSet<String>) {
    out.insert(group.id().uuid().simple().to_string());
    for child in group.groups() {
        collect_group_uuids(&child, out);
    }
}

/// Extracts normalized, deduplicated web domains from an entry's URL and
/// `KP2A_URL*` fields.
fn entry_domains(entry: &SnapshotEntry) -> Vec<String> {
    let mut domains = Vec::new();
    let mut seen = HashSet::new();
    let iter = std::iter::once(entry.url.as_str())
        .chain(entry.additional_urls.iter().map(String::as_str));
    for raw in iter {
        if let Some(domain) = extract_domain(raw) {
            if seen.insert(domain.clone()) {
                domains.push(domain);
            }
        }
    }
    domains
}

pub fn extract_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if trimmed.contains("://") {
        let lower = trimmed.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            return None;
        }
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&candidate).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    if host.is_empty() || host == "*" || host.contains('*') {
        return None;
    }
    Some(host)
}

fn rp_matches_service(rp_id: &str, service_identifiers: &[String], requested_rp: Option<&str>) -> bool {
    let rp = rp_id.trim().to_ascii_lowercase();
    if rp.is_empty() {
        return false;
    }
    if let Some(req) = requested_rp {
        let req = req.trim().to_ascii_lowercase();
        if !req.is_empty() {
            return rp == req;
        }
    }
    for sid in service_identifiers {
        if let Some(domain) = extract_domain(sid) {
            if domain == rp || domain.ends_with(&format!(".{rp}")) || rp.ends_with(&format!(".{domain}")) {
                return true;
            }
        }
    }
    false
}

fn best_service_score(entry: &SnapshotEntry, service_identifiers: &[String]) -> Option<u16> {
    let candidate = MatchCandidate {
        url: &entry.url,
        additional_urls: &entry.additional_urls,
        android_apps: &[],
    };
    let mut best: Option<u16> = None;
    for sid in service_identifiers {
        let target = MatchTarget {
            web_url: Some(sid.as_str()),
            android_package: None,
        };
        if let Some(s) = matching::score(&candidate, &target) {
            best = Some(best.map_or(s, |cur| cur.min(s)));
        }
    }
    best
}

fn matches_query(entry: &SnapshotEntry, query: &str) -> bool {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return true;
    }
    entry.title.to_ascii_lowercase().contains(&q)
        || entry.username.to_ascii_lowercase().contains(&q)
        || entry.url.to_ascii_lowercase().contains(&q)
        || entry.passkey.as_ref().is_some_and(|pk| {
            pk.rp_id.to_ascii_lowercase().contains(&q)
                || pk.username.to_ascii_lowercase().contains(&q)
        })
}

fn handle_read_request(
    snapshot: &ProviderSnapshot,
    request: &Request,
) -> Option<Response> {
    match request {
        Request::Status { .. } => Some(Response::success(ResponsePayload::Status {
            unlocked: snapshot.unlocked,
            db_name: snapshot.db_name.clone(),
        })),
        Request::ListIdentities => {
            if !snapshot.unlocked {
                return Some(Response::err("vault_locked", "friendlypass database is locked"));
            }
            let bundle = snapshot.identities();
            Some(Response::success(ResponsePayload::Identities {
                passkeys: bundle.passkeys,
                passwords: bundle.passwords,
                totps: bundle.totps,
            }))
        }
        Request::ListCredentials {
            kind,
            service_identifiers,
            rp_id,
            allowed_credential_ids_b64,
            query,
        } => {
            if !snapshot.unlocked {
                return Some(Response::err("vault_locked", "friendlypass database is locked"));
            }
            let allowed_ids: Option<Vec<Vec<u8>>> = allowed_credential_ids_b64.as_ref().map(|ids| {
                ids.iter()
                    .filter_map(|b64| B64.decode(b64).ok())
                    .collect()
            });
            let query_str = query.as_deref().unwrap_or("");
            let mut scored: Vec<(u8, u16, CredentialItem)> = Vec::new();

            for entry in &snapshot.entries {
                if entry.expired || !matches_query(entry, query_str) {
                    continue;
                }

                if matches!(kind, CredentialKind::All | CredentialKind::Passkey) {
                    if let Some(pk) = &entry.passkey {
                        let allowed_ok = match &allowed_ids {
                            Some(ids) if !ids.is_empty() => {
                                ids.iter().any(|id| id == &pk.credential_id)
                            }
                            _ => true,
                        };
                        if allowed_ok {
                            let matched = rp_matches_service(
                                &pk.rp_id,
                                service_identifiers,
                                rp_id.as_deref(),
                            );
                            // When a specific RP or allow-list is requested without a
                            // search query, prefer matching entries; still include
                            // unmatched passkeys when there is no allow-list so the
                            // user can browse/search.
                            let include = matched
                                || allowed_ids
                                    .as_ref()
                                    .map_or(true, |ids| ids.is_empty());
                            if include {
                                scored.push((
                                    if matched { 0 } else { 2 },
                                    0,
                                    CredentialItem {
                                        kind: CredentialKind::Passkey,
                                        uuid: entry.uuid.clone(),
                                        title: if entry.title.is_empty() {
                                            pk.rp_id.clone()
                                        } else {
                                            entry.title.clone()
                                        },
                                        username: pk.username.clone(),
                                        subtitle: pk.rp_id.clone(),
                                        rp_id: Some(pk.rp_id.clone()),
                                        credential_id_b64: Some(B64.encode(&pk.credential_id)),
                                        matched,
                                    },
                                ));
                            }
                        }
                    }
                }

                if matches!(kind, CredentialKind::All | CredentialKind::Password)
                    && !entry.password.is_empty()
                {
                    let score = best_service_score(entry, service_identifiers);
                    let matched = score.is_some();
                    let subtitle = extract_domain(&entry.url).unwrap_or_else(|| entry.url.clone());
                    scored.push((
                        if matched { 1 } else { 3 },
                        score.unwrap_or(u16::MAX),
                        CredentialItem {
                            kind: CredentialKind::Password,
                            uuid: entry.uuid.clone(),
                            title: entry.title.clone(),
                            username: entry.username.clone(),
                            subtitle,
                            rp_id: None,
                            credential_id_b64: None,
                            matched,
                        },
                    ));
                }

                if matches!(kind, CredentialKind::Totp) && entry.totp_url.is_some() {
                    let score = best_service_score(entry, service_identifiers);
                    let matched = score.is_some()
                        || entry.passkey.as_ref().is_some_and(|pk| {
                            rp_matches_service(&pk.rp_id, service_identifiers, rp_id.as_deref())
                        });
                    let subtitle = extract_domain(&entry.url)
                        .or_else(|| entry.passkey.as_ref().map(|pk| pk.rp_id.clone()))
                        .unwrap_or_else(|| entry.url.clone());
                    scored.push((
                        if matched { 0 } else { 2 },
                        score.unwrap_or(u16::MAX),
                        CredentialItem {
                            kind: CredentialKind::Totp,
                            uuid: entry.uuid.clone(),
                            title: entry.title.clone(),
                            username: entry.username.clone(),
                            subtitle,
                            rp_id: None,
                            credential_id_b64: None,
                            matched,
                        },
                    ));
                }
            }

            scored.sort_by(|a, b| {
                a.0.cmp(&b.0)
                    .then_with(|| a.1.cmp(&b.1))
                    .then_with(|| {
                        a.2.title
                            .to_ascii_lowercase()
                            .cmp(&b.2.title.to_ascii_lowercase())
                    })
                    .then_with(|| {
                        a.2.username
                            .to_ascii_lowercase()
                            .cmp(&b.2.username.to_ascii_lowercase())
                    })
            });

            let items = scored.into_iter().map(|(_, _, item)| item).collect();
            Some(Response::success(ResponsePayload::Credentials { items }))
        }
        Request::GetPassword { uuid } => {
            if !snapshot.unlocked {
                return Some(Response::err("vault_locked", "friendlypass database is locked"));
            }
            let Some(entry) = snapshot.entries.iter().find(|e| &e.uuid == uuid) else {
                return Some(Response::err(
                    "credential_not_found",
                    "matching entry not found",
                ));
            };
            Some(Response::success(ResponsePayload::Password {
                username: entry.username.clone(),
                password: entry.password.clone(),
            }))
        }
        Request::GetTotp { uuid } => {
            if !snapshot.unlocked {
                return Some(Response::err("vault_locked", "friendlypass database is locked"));
            }
            let Some(entry) = snapshot.entries.iter().find(|e| &e.uuid == uuid) else {
                return Some(Response::err(
                    "credential_not_found",
                    "matching entry not found",
                ));
            };
            let Some(otp_url) = entry.totp_url.as_deref() else {
                return Some(Response::err(
                    "credential_not_found",
                    "entry has no one-time code",
                ));
            };
            let Ok(totp) = otp_url.parse::<keepass::db::TOTP>() else {
                return Some(Response::err(
                    "invalid_totp",
                    "entry TOTP configuration is invalid",
                ));
            };
            let Ok(val) = totp.value_now() else {
                return Some(Response::err("invalid_totp", "unable to compute TOTP code"));
            };
            Some(Response::success(ResponsePayload::Totp {
                code: val.code,
                valid_for_secs: val.valid_for.as_secs(),
            }))
        }
        Request::AssertPasskey {
            uuid,
            rp_id,
            credential_id_b64,
            client_data_hash_b64,
        } => {
            if !snapshot.unlocked {
                return Some(Response::err("vault_locked", "friendlypass database is locked"));
            }
            let Ok(client_data_hash) = B64.decode(client_data_hash_b64) else {
                return Some(Response::err(
                    "invalid_request",
                    "client_data_hash_b64 is not valid base64",
                ));
            };
            if client_data_hash.len() != 32 {
                return Some(Response::err(
                    "invalid_request",
                    "client_data_hash must be 32 bytes",
                ));
            }
            let expected_cred_id = match credential_id_b64.as_deref() {
                Some(b64) if !b64.is_empty() => match B64.decode(b64) {
                    Ok(bytes) => Some(bytes),
                    Err(_) => {
                        return Some(Response::err(
                            "invalid_request",
                            "credential_id_b64 is not valid base64",
                        ));
                    }
                },
                _ => None,
            };

            let passkey = snapshot.entries.iter().find_map(|entry| {
                let pk = entry.passkey.as_ref()?;
                if !pk.rp_id.eq_ignore_ascii_case(rp_id) {
                    return None;
                }
                if let Some(target_uuid) = uuid.as_deref() {
                    if entry.uuid != target_uuid {
                        return None;
                    }
                }
                if let Some(cred_id) = expected_cred_id.as_deref() {
                    if pk.credential_id != cred_id {
                        return None;
                    }
                }
                if uuid.is_none() && expected_cred_id.is_none() {
                    return None;
                }
                Some(pk)
            });

            let Some(passkey) = passkey else {
                return Some(Response::err(
                    "credential_not_found",
                    "matching passkey not found",
                ));
            };

            match friendlypass_passkey::assert(passkey, &client_data_hash) {
                Ok(assertion) => Some(Response::success(ResponsePayload::PasskeyAssertion {
                    relying_party: passkey.rp_id.clone(),
                    credential_id_b64: B64.encode(&assertion.credential_id),
                    user_handle_b64: B64.encode(&assertion.user_handle),
                    authenticator_data_b64: B64.encode(&assertion.authenticator_data),
                    signature_b64: B64.encode(&assertion.signature),
                })),
                Err(_) => Some(Response::err("signing_failed", "passkey assertion failed")),
            }
        }
        Request::RegisterPasskey { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Pending registration queue & GUI bridge
// ---------------------------------------------------------------------------

struct PendingRegistration {
    rp_id: String,
    username: String,
    user_handle: Vec<u8>,
    algorithms: Vec<i64>,
    excluded_credential_ids: Vec<Vec<u8>>,
    reply: Arc<(Mutex<Option<Response>>, Condvar)>,
}

/// Status summary for Settings UI on macOS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MacosProviderStatus {
    pub extension_bundled: bool,
    pub store_enabled: bool,
    pub server_listening: bool,
    pub socket_path: Option<PathBuf>,
    pub synced_passkeys: usize,
    pub synced_passwords: usize,
    pub synced_totps: usize,
}

/// Shared state between the GUI thread and the background Unix socket server.
pub struct GuiMacosProvider {
    snapshot: Mutex<ProviderSnapshot>,
    registrations: Mutex<VecDeque<PendingRegistration>>,
    egui_ctx: Mutex<Option<egui::Context>>,
    unlock_requested: AtomicBool,
    stop: AtomicBool,
    socket_path: Option<PathBuf>,
    extension_bundled: bool,
    last_synced_signature: Mutex<Option<u64>>,
    last_counts: Mutex<(usize, usize, usize)>,
    #[cfg(unix)]
    listener_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl GuiMacosProvider {
    fn lock_snapshot(&self) -> std::sync::MutexGuard<'_, ProviderSnapshot> {
        self.snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wake_gui(&self) {
        if let Some(ctx) = self
            .egui_ctx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            ctx.request_repaint();
        }
    }

    pub fn set_snapshot(&self, snap: ProviderSnapshot) {
        *self.lock_snapshot() = snap;
    }

    /// Process a single decoded request (called from the socket worker thread
    /// and unit tests).
    pub fn handle_request(&self, request: Request) -> Response {
        if let Request::Status { request_unlock: true } = &request {
            self.unlock_requested.store(true, Ordering::SeqCst);
            self.wake_gui();
        }
        {
            let snap = self.lock_snapshot();
            if let Some(response) = handle_read_request(&snap, &request) {
                return response;
            }
        }
        match request {
            Request::RegisterPasskey {
                rp_id,
                username,
                user_handle_b64,
                client_data_hash_b64,
                algorithms,
                excluded_credential_ids_b64,
            } => {
                if rp_id.trim().is_empty() {
                    return Response::err("invalid_request", "relying party id is empty");
                }
                let Ok(user_handle) = B64.decode(&user_handle_b64) else {
                    return Response::err(
                        "invalid_request",
                        "user_handle_b64 is not valid base64",
                    );
                };
                let Ok(client_data_hash) = B64.decode(&client_data_hash_b64) else {
                    return Response::err(
                        "invalid_request",
                        "client_data_hash_b64 is not valid base64",
                    );
                };
                if client_data_hash.len() != 32 {
                    return Response::err(
                        "invalid_request",
                        "client_data_hash must be 32 bytes",
                    );
                }
                let excluded_credential_ids = excluded_credential_ids_b64
                    .iter()
                    .filter_map(|s| B64.decode(s).ok())
                    .collect();

                if !self.lock_snapshot().unlocked {
                    return Response::err("vault_locked", "friendlypass database is locked");
                }

                let reply = Arc::new((Mutex::new(None), Condvar::new()));
                {
                    let mut queue = self
                        .registrations
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    queue.push_back(PendingRegistration {
                        rp_id,
                        username,
                        user_handle,
                        algorithms,
                        excluded_credential_ids,
                        reply: Arc::clone(&reply),
                    });
                }
                self.wake_gui();

                let (lock, cvar) = &*reply;
                let mut guard = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let deadline = std::time::Instant::now() + REGISTER_TIMEOUT;
                while guard.is_none() {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        return Response::err(
                            "timeout",
                            "timed out waiting for friendlypass to save passkey",
                        );
                    }
                    let (next, wait) = cvar
                        .wait_timeout(guard, remaining)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard = next;
                    if wait.timed_out() && guard.is_none() {
                        return Response::err(
                            "timeout",
                            "timed out waiting for friendlypass to save passkey",
                        );
                    }
                }
                guard
                    .take()
                    .unwrap_or_else(|| Response::err("internal_error", "missing reply"))
            }
            _ => Response::err("internal_error", "unhandled request"),
        }
    }

    pub fn socket_path(&self) -> Option<&PathBuf> {
        self.socket_path.as_ref()
    }
}

impl Drop for GuiMacosProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        #[cfg(unix)]
        if let Some(path) = &self.socket_path {
            // Wake the accept loop with a quick non-blocking connect, then
            // remove the socket file.
            let _ = std::os::unix::net::UnixStream::connect(path);
            let _ = std::fs::remove_file(path);
        }
        #[cfg(unix)]
        if let Some(handle) = self
            .listener_thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Socket path & expected peer discovery
// ---------------------------------------------------------------------------

/// Sibling `.appex` executable inside `friendlypass.app/Contents/PlugIns/`.
pub fn bundled_extension_executable() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let contents = exe.parent()?.parent()?;
    let candidate = contents
        .join("PlugIns")
        .join("FriendlyPassCredentialProvider.appex")
        .join("Contents")
        .join("MacOS")
        .join("FriendlyPassCredentialProvider");
    candidate.is_file().then_some(candidate)
}

fn default_socket_and_peer() -> Option<(PathBuf, PathBuf)> {
    let peer = std::env::var_os(ENV_PEER)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(bundled_extension_executable)?;

    if let Some(override_sock) = std::env::var_os(ENV_SOCKET).filter(|v| !v.is_empty()) {
        return Some((PathBuf::from(override_sock), peer));
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(group_dir) = macos_ffi::app_group_dir() {
            return Some((group_dir.join("cp.sock"), peer));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Unix socket listener
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn start_listener(
    socket_path: PathBuf,
    expected_peer: PathBuf,
    extension_bundled: bool,
) -> std::io::Result<Arc<GuiMacosProvider>> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = UnixListener::bind(&socket_path)?;
    let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));

    let provider = Arc::new(GuiMacosProvider {
        snapshot: Mutex::new(ProviderSnapshot::locked()),
        registrations: Mutex::new(VecDeque::new()),
        egui_ctx: Mutex::new(None),
        unlock_requested: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        socket_path: Some(socket_path.clone()),
        extension_bundled,
        last_synced_signature: Mutex::new(None),
        last_counts: Mutex::new((0, 0, 0)),
        listener_thread: Mutex::new(None),
    });

    let thread_provider = Arc::clone(&provider);
    let handle = std::thread::Builder::new()
        .name("fp-macos-provider".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                if thread_provider.stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = incoming else {
                    if thread_provider.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let peer_info =
                    friendlypass_browser::peer::verify_peer(&stream, Some(&expected_peer));
                if !peer_info.trusted {
                    // Reject untrusted local processes before reading any data.
                    drop(stream);
                    continue;
                }
                let worker_provider = Arc::clone(&thread_provider);
                let _ = std::thread::Builder::new()
                    .name("fp-macos-provider-req".into())
                    .spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        let Ok(raw) = read_frame(&mut stream) else {
                            return;
                        };
                        let response = match serde_json::from_slice::<Request>(&raw) {
                            Ok(req) => worker_provider.handle_request(req),
                            Err(_) => Response::err("invalid_request", "malformed JSON request"),
                        };
                        if let Ok(bytes) = serde_json::to_vec(&response) {
                            let _ = write_frame(&mut stream, &bytes);
                        }
                    });
            }
        })?;

    *provider
        .listener_thread
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
    Ok(provider)
}

/// Start a real Unix socket server at an explicit path and expected peer
/// executable (used by integration tests).
#[cfg(unix)]
pub fn start_with_config(
    socket_path: PathBuf,
    expected_peer: PathBuf,
) -> std::io::Result<Arc<GuiMacosProvider>> {
    start_listener(socket_path, expected_peer, true)
}

// ---------------------------------------------------------------------------
// GUI lifecycle hooks
// ---------------------------------------------------------------------------

/// Start the macOS Credential Provider server in the background when running
/// from a packaged `.app` bundle (or when `FP_CREDENTIAL_PROVIDER_SOCKET` and
/// `FP_CREDENTIAL_PROVIDER_PEER` are explicitly configured).
pub fn start_background(app: &mut App) {
    if app.macos_provider.is_some() {
        return;
    }
    #[cfg(unix)]
    {
        if let Some((socket_path, peer)) = default_socket_and_peer() {
            let bundled = bundled_extension_executable().is_some();
            if let Ok(provider) = start_listener(socket_path, peer, bundled) {
                app.macos_provider = Some(provider);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = app;
    }
}

/// Run once per GUI frame. Keeps the provider snapshot synced with `app.db`,
/// drains pending passkey registrations from the `.appex`, and updates
/// macOS's `ASCredentialIdentityStore` whenever the vault changes.
pub fn pump(app: &mut App, ctx: &egui::Context) {
    let Some(provider) = app.macos_provider.clone() else {
        return;
    };
    {
        let mut slot = provider
            .egui_ctx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(ctx.clone());
        }
    }

    if provider.unlock_requested.swap(false, Ordering::SeqCst) && app.db.is_none() {
        app.focus_password = true;
        app.unlock_error.clear();
        app.status = "Unlock friendlypass to use macOS AutoFill & Passkeys".into();
        ctx.request_repaint();
    }

    // Drain any pending passkey registrations from the extension.
    loop {
        let next = provider
            .registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front();
        let Some(job) = next else {
            break;
        };
        let response = apply_registration(app, &job);
        // Refresh the served snapshot BEFORE waking the waiting extension so
        // an immediate `list_identities` or `assert_passkey` never sees stale state.
        let _ = sync_snapshot(app, &provider);
        let (lock, cvar) = &*job.reply;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(response);
        cvar.notify_all();
        ctx.request_repaint();
    }

    // Keep the served snapshot in sync with the open database.
    let changed_sig = sync_snapshot(app, &provider);
    if let Some(sig) = changed_sig {
        trigger_identity_store_sync(&provider, sig);
    }
}

fn db_display_name(app: &App) -> Option<String> {
    if app.db_path.is_empty() {
        return Some("Untitled.kdbx".to_owned());
    }
    PathBuf::from(&app.db_path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
}

fn sync_snapshot(app: &App, provider: &GuiMacosProvider) -> Option<u64> {
    let Some(db) = app.db.as_ref() else {
        let mut snap = provider.lock_snapshot();
        if snap.unlocked {
            *snap = ProviderSnapshot::locked();
        }
        return None;
    };

    let sig = friendlypass_browser::snapshot_signature(db);
    let needs_update = {
        let snap = provider.lock_snapshot();
        !snap.unlocked || snap.signature != sig
    };
    if needs_update {
        let fresh = ProviderSnapshot::from_database(db, db_display_name(app));
        let bundle = fresh.identities();
        *provider
            .last_counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (
            bundle.passkeys.len(),
            bundle.passwords.len(),
            bundle.totps.len(),
        );
        provider.set_snapshot(fresh);
    }

    let last = *provider
        .last_synced_signature
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (last != Some(sig)).then_some(sig)
}

fn apply_registration(app: &mut App, job: &PendingRegistration) -> Response {
    let Some(db) = app.db.as_mut() else {
        return Response::err("vault_locked", "friendlypass database is locked");
    };

    // WebAuthn excludeCredentials check across all non-recycled passkeys for rp_id.
    if !job.excluded_credential_ids.is_empty() {
        let recycle = recycle_group_ids(db);
        let excluded = db
            .iter_all_entries()
            .filter(|e| !recycle.contains(&e.parent().id().uuid().simple().to_string()))
            .filter_map(|e| StoredPasskey::from_fields(|k| e.get(k).map(str::to_owned)))
            .any(|pk| {
                pk.rp_id.eq_ignore_ascii_case(&job.rp_id)
                    && job
                        .excluded_credential_ids
                        .iter()
                        .any(|id| id == &pk.credential_id)
            });
        if excluded {
            return Response::err(
                "credential_excluded",
                "a matching passkey already exists in friendlypass",
            );
        }
    }

    let reg = match friendlypass_passkey::register(
        &job.rp_id,
        &job.username,
        &job.user_handle,
        &job.algorithms,
    ) {
        Ok(reg) => reg,
        Err(_) => return Response::err("registration_failed", "passkey generation failed"),
    };

    let group = app.prefs.passkey_default_group.trim().to_owned();
    let origin = format!("https://{}", job.rp_id);
    let Some(uuid) = friendlypass_browser::passkey_write::create_passkey_entry(
        db,
        &reg.passkey,
        &job.rp_id,
        &origin,
        &group,
    ) else {
        return Response::err("registration_failed", "unable to create passkey entry");
    };

    app.dirty = true;
    app.status = format!("Saved a passkey for {}", job.rp_id);

    // Auto-save atomically when safe (already KDBX 4 or upgrade confirmed, and
    // backed by a path + key) so background passkey creation survives app exit.
    let can_autosave = !app.db_path.is_empty()
        && app.db_key.is_some()
        && (app.upgrade_confirmed
            || app.db.as_ref().is_some_and(|d| {
                matches!(d.config.version, keepass::config::DatabaseVersion::KDB4(_))
            }));
    if can_autosave {
        app.perform_save(None);
    }

    Response::success(ResponsePayload::PasskeyRegistration {
        uuid,
        relying_party: reg.passkey.rp_id,
        credential_id_b64: B64.encode(&reg.credential_id),
        attestation_object_b64: B64.encode(&reg.attestation_object),
    })
}

fn trigger_identity_store_sync(provider: &Arc<GuiMacosProvider>, sig: u64) {
    *provider
        .last_synced_signature
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sig);

    #[cfg(target_os = "macos")]
    {
        let bundle = provider.lock_snapshot().identities();
        if let Ok(json) = serde_json::to_string(&bundle) {
            let _ = std::thread::Builder::new()
                .name("fp-macos-identity-sync".into())
                .spawn(move || {
                    let _ = macos_ffi::replace_credential_identities(&json);
                });
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (provider, sig);
    }
}

/// Force an immediate identity-store sync from Settings (macOS).
pub fn sync_identity_store_now(app: &App) -> Result<bool, String> {
    let Some(db) = app.db.as_ref() else {
        return Err("Unlock a database first.".to_owned());
    };
    let snap = ProviderSnapshot::from_database(db, db_display_name(app));
    let bundle = snap.identities();
    if let Some(provider) = app.macos_provider.as_ref() {
        *provider
            .last_counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (
            bundle.passkeys.len(),
            bundle.passwords.len(),
            bundle.totps.len(),
        );
    }
    #[cfg(target_os = "macos")]
    {
        let json = serde_json::to_string(&bundle).map_err(|e| e.to_string())?;
        macos_ffi::replace_credential_identities(&json)
            .map_err(|_| "macOS declined to update AutoFill credentials.".to_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(false)
    }
}

/// Snapshot of macOS AutoFill & Passkey provider state for Settings UI.
pub fn status_summary(app: &App) -> MacosProviderStatus {
    let bundled = app
        .macos_provider
        .as_ref()
        .map_or_else(|| bundled_extension_executable().is_some(), |p| p.extension_bundled);
    let (synced_passkeys, synced_passwords, synced_totps) = app
        .macos_provider
        .as_ref()
        .map(|p| {
            *p.last_counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
        .unwrap_or_else(|| {
            app.db
                .as_ref()
                .map(|db| {
                    let b = ProviderSnapshot::from_database(db, db_display_name(app)).identities();
                    (b.passkeys.len(), b.passwords.len(), b.totps.len())
                })
                .unwrap_or((0, 0, 0))
        });

    #[cfg(target_os = "macos")]
    let store_enabled = macos_ffi::credential_store_enabled();
    #[cfg(not(target_os = "macos"))]
    let store_enabled = false;

    MacosProviderStatus {
        extension_bundled: bundled,
        store_enabled,
        server_listening: app.macos_provider.is_some(),
        socket_path: app
            .macos_provider
            .as_ref()
            .and_then(|p| p.socket_path.clone()),
        synced_passkeys,
        synced_passwords,
        synced_totps,
    }
}

/// Opens System Settings → AutoFill & Passwords on macOS.
#[cfg(target_os = "macos")]
pub fn open_system_autofill_settings() {
    let _ = std::process::Command::new("open")
        .arg("x-apple.systempreferences:com.apple.Passwords-Settings.extension")
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_normalizes_web_urls_and_skips_non_web() {
        assert_eq!(
            extract_domain("https://www.Example.com:8443/login?next=/"),
            Some("example.com".to_owned())
        );
        assert_eq!(
            extract_domain("sub.github.com/account"),
            Some("sub.github.com".to_owned())
        );
        assert_eq!(extract_domain("androidapp://com.example.app"), None);
        assert_eq!(extract_domain("keepassxc://by-uuid/1234"), None);
        assert_eq!(extract_domain("*.example.com"), None);
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn frame_roundtrip_and_limits() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"ok\":true}").unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor).unwrap();
        assert_eq!(decoded, b"{\"ok\":true}");

        // Reject zero-length frame
        let mut zero = std::io::Cursor::new(0u32.to_le_bytes());
        assert!(read_frame(&mut zero).is_err());
    }
}
