//! `friendlypass_mobile` — the UniFFI boundary the Android app calls.
//!
//! The contract (android/CONTRACT.md) is frozen: one [`Vault`] object opened
//! from KDBX bytes, read-only browsing/search/matching on top of the `keepass`
//! crate, and `add_login`/`save` for writes. Everything stays in memory; the
//! Android layer owns persistence (SAF/`DatabaseStore`).
//!
//! Passwords and keyfile bytes are moved into [`zeroize::Zeroizing`] buffers
//! and then into the `keepass` key (which zeroizes on drop). Nothing is ever
//! printed.

uniffi::setup_scaffolding!();

use std::collections::HashSet;
use std::io::Cursor;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use friendlypass::matching::{self, MatchCandidate, MatchTarget};
use friendlypass_passkey::StoredPasskey;
use keepass::config::{DatabaseVersion, InnerCipherConfig};
use keepass::db::{fields, Database, Entry, EntryId, EntryRef, GroupId, GroupRef, History, Times, TOTP};
use keepass::DatabaseKey;
use zeroize::Zeroizing;

/// KeePassXC's passkey credential-id field; its presence marks an entry as
/// having a passkey (stored by the wave-2 `friendlypass-passkey` crate).
const PASSKEY_CREDENTIAL_ID_FIELD: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
/// KeePassDX's single-app field; numbered variants are `AndroidApp_1`, …
const ANDROID_APP_FIELD: &str = "AndroidApp";
/// URL scheme KP2A uses for Android app associations.
const ANDROID_APP_SCHEME: &str = "androidapp://";
/// Field prefix for additional URLs (`KP2A_URL`, `KP2A_URL_1`, …).
const KP2A_URL_FIELD: &str = "KP2A_URL";

/// Errors crossing the UniFFI boundary.
#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum VaultError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("corrupt database: {msg}")]
    Corrupt { msg: String },
    #[error("unsupported: {msg}")]
    Unsupported { msg: String },
    #[error("not found")]
    NotFound,
    #[error("I/O error: {msg}")]
    Io { msg: String },
}

/// A credential summary, as shown in lists and autofill pickers.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    /// Dashless lowercase hex RFC 4122 UUID.
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    /// Slash-separated group path from the root, e.g. `"Root/Email"`.
    pub group_path: String,
    pub has_totp: bool,
    pub has_passkey: bool,
}

/// One string field of an entry.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct EntryField {
    pub name: String,
    pub value: String,
    pub protected: bool,
}

/// Everything the detail screen shows.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct EntryDetail {
    pub summary: EntrySummary,
    pub group_uuid: String,
    pub password: String,
    pub notes: String,
    /// Raw `otp` field value (e.g. `otpauth://totp/...`), if present.
    pub otp_uri: Option<String>,
    /// The main URL first, then additional URLs.
    pub urls: Vec<String>,
    pub android_apps: Vec<String>,
    /// Fields that are not one of the standard Title/UserName/Password/URL/
    /// Notes/otp fields.
    pub custom_fields: Vec<EntryField>,
    pub tags: Vec<String>,
}

/// Full input for creating or updating an entry.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct EntryInput {
    /// Target group UUID (falls back to root group when empty).
    pub group_uuid: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// Either a full `otpauth://` URI or a raw Base32 secret. Empty/None clears TOTP.
    pub totp: Option<String>,
    pub android_apps: Vec<String>,
    pub custom_fields: Vec<EntryField>,
    pub tags: Vec<String>,
}

/// One node of the flat group list (recycle bin excluded).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct GroupNode {
    pub uuid: String,
    pub name: String,
    pub parent_uuid: Option<String>,
    /// Entries directly in this group (not descendants).
    pub entry_count: u32,
}

/// A TOTP code at a requested instant.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub period_secs: u32,
    pub remaining_secs: u32,
}

/// A login to add to the root group.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct NewLogin {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    /// Written to the `AndroidApp` field when set.
    pub android_app: Option<String>,
}

/// A passkey stored in an entry (KeePassXC `KPEX_PASSKEY_*` attributes).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    pub entry_uuid: String,
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub username: String,
    pub user_handle: Vec<u8>,
}

/// A `navigator.credentials.create` request.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCreateRequest {
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_handle: Vec<u8>,
    pub algorithms: Vec<i64>,
    pub exclude_credential_ids: Vec<Vec<u8>>,
}

/// The result of creating a passkey; `entry_uuid` is the new root-group entry.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRegistration {
    pub entry_uuid: String,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub public_key_spki_der: Vec<u8>,
    pub algorithm: i64,
}

/// The result of asserting a passkey.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// Summary of changes merged in from an external copy of the same database.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct MergeResult {
    pub created_entries: u32,
    pub updated_entries: u32,
    pub deleted_entries: u32,
    pub moved_entries: u32,
    pub created_groups: u32,
    pub updated_groups: u32,
    pub deleted_groups: u32,
    pub moved_groups: u32,
    pub custom_data_updated: u32,
    /// Short human-readable summary (e.g. `"1 added, 2 updated"`).
    pub description: String,
}

/// An unlocked database. Interior mutability (`Mutex`) lets Kotlin share one
/// `Arc<Vault>` across threads; reads never block on a pending save beyond the
/// database lock.
#[derive(uniffi::Object)]
pub struct Vault {
    database: Mutex<Database>,
    /// The same credentials the database was opened with; `save` reuses them.
    key: DatabaseKey,
    modified: AtomicBool,
}

/// Create a brand-new KDBX 4.1 database and return its serialized bytes.
#[uniffi::export]
pub fn create_database(
    name: String,
    password: Option<String>,
    keyfile: Option<Vec<u8>>,
) -> Result<Vec<u8>, VaultError> {
    let password = password.map(Zeroizing::new);
    let keyfile = keyfile.map(Zeroizing::new);

    let has_password = password.as_deref().is_some_and(|p| !p.is_empty());
    let has_keyfile = keyfile.as_deref().is_some_and(|k| !k.is_empty());
    if !has_password && !has_keyfile {
        return Err(VaultError::InvalidCredentials);
    }

    let mut key = DatabaseKey::new();
    if let Some(password) = password.as_deref().filter(|p| !p.is_empty()) {
        key = key.with_password(password);
    }
    if let Some(keyfile) = keyfile.as_deref().filter(|k| !k.is_empty()) {
        key = key
            .with_keyfile(&mut Cursor::new(keyfile))
            .map_err(|error| VaultError::Io {
                msg: error.to_string(),
            })?;
    }

    let mut database = Database::new();
    database.config.version = DatabaseVersion::KDB4(1);
    database.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    let db_name = if name.trim().is_empty() {
        "Passwords".to_owned()
    } else {
        name.trim().to_owned()
    };
    database.meta.database_name = Some(db_name.clone());
    database.meta.recyclebin_enabled = Some(true);
    {
        let mut root = database.root_mut();
        root.name = db_name;
    }

    let mut out = Vec::new();
    database.save(&mut out, key).map_err(save_error)?;
    Ok(out)
}

/// Generate a cryptographically random password guaranteeing at least one
/// character from each enabled character class.
#[uniffi::export]
pub fn generate_password(
    length: u32,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, VaultError> {
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"23456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

    let mut classes: Vec<&[u8]> = Vec::new();
    if uppercase {
        classes.push(UPPER);
    }
    if lowercase {
        classes.push(LOWER);
    }
    if digits {
        classes.push(DIGITS);
    }
    if symbols {
        classes.push(SYMBOLS);
    }
    if classes.is_empty() {
        return Err(VaultError::Unsupported {
            msg: "select at least one character set".to_owned(),
        });
    }

    let len = (length as usize).clamp(classes.len().max(4), 128);
    let mut pool: Vec<u8> = Vec::new();
    for class in &classes {
        pool.extend_from_slice(class);
    }

    let mut chars: Vec<u8> = Vec::with_capacity(len);
    for class in &classes {
        chars.push(class[random_index(class.len())?]);
    }
    while chars.len() < len {
        chars.push(pool[random_index(pool.len())?]);
    }
    // Fisher-Yates shuffle.
    for i in (1..chars.len()).rev() {
        let j = random_index(i + 1)?;
        chars.swap(i, j);
    }
    Ok(String::from_utf8(chars).expect("ASCII password"))
}

/// Open a KDBX database from memory.
///
/// `password` and `keyfile` are optional; at least one is normally required.
/// The keyfile goes through the `keepass` crate's parser, which handles
/// KeePassXC XML v1/v2 keyfiles as well as 32-byte binary, 64-byte hex and
/// hashed keyfiles.
#[uniffi::export]
pub fn open_vault(
    kdbx: Vec<u8>,
    password: Option<String>,
    keyfile: Option<Vec<u8>>,
) -> Result<Arc<Vault>, VaultError> {
    let password = password.map(Zeroizing::new);
    let keyfile = keyfile.map(Zeroizing::new);

    let mut key = DatabaseKey::new();
    if let Some(password) = password.as_deref() {
        key = key.with_password(password);
    }
    if let Some(keyfile) = keyfile.as_deref() {
        key = key
            .with_keyfile(&mut Cursor::new(keyfile))
            .map_err(|error| VaultError::Io {
                msg: error.to_string(),
            })?;
    }

    let mut source = Cursor::new(kdbx);
    let database = Database::open(&mut source, key.clone()).map_err(open_error)?;
    Ok(Arc::new(Vault {
        database: Mutex::new(database),
        key,
        modified: AtomicBool::new(false),
    }))
}

#[uniffi::export]
impl Vault {
    pub fn database_name(&self) -> String {
        self.database()
            .meta
            .database_name
            .clone()
            .unwrap_or_default()
    }

    pub fn root_group_uuid(&self) -> String {
        let database = self.database();
        uuid_of_group(&database.root())
    }

    /// Every group except the recycle bin and its descendants, root first.
    pub fn groups(&self) -> Vec<GroupNode> {
        let database = self.database();
        let recycle = recycle_ids(&database);
        let mut out = Vec::new();
        collect_groups(&database.root(), None, &recycle, &mut out);
        out
    }

    pub fn entries_in_group(&self, group_uuid: String) -> Vec<EntrySummary> {
        let database = self.database();
        let recycle = recycle_ids(&database);
        let Some(uuid) = normalize_uuid(&group_uuid) else {
            return Vec::new();
        };
        let Some(group) = database
            .iter_all_groups()
            .find(|group| uuid_of_group(group) == uuid)
        else {
            return Vec::new();
        };
        if recycle.contains(&uuid) {
            return Vec::new();
        }
        let mut out: Vec<EntrySummary> = group.entries().map(|entry| summary(&entry)).collect();
        sort_summaries(&mut out);
        out
    }

    /// Every non-recycle entry, sorted by title.
    pub fn all_entries(&self) -> Vec<EntrySummary> {
        let database = self.database();
        let recycle = recycle_ids(&database);
        let mut out: Vec<EntrySummary> = database
            .iter_all_entries()
            .filter(|entry| !in_recycle(entry, &recycle))
            .map(|entry| summary(&entry))
            .collect();
        sort_summaries(&mut out);
        out
    }

    /// Case-insensitive search over title, username, URL, notes and tags.
    pub fn search(&self, query: String) -> Vec<EntrySummary> {
        let database = self.database();
        let recycle = recycle_ids(&database);
        let needle = query.to_lowercase();
        let mut out: Vec<EntrySummary> = database
            .iter_all_entries()
            .filter(|entry| !in_recycle(entry, &recycle))
            .filter(|entry| {
                let matches = |value: &str| value.to_lowercase().contains(&needle);
                matches(entry.get(fields::TITLE).unwrap_or_default())
                    || matches(entry.get(fields::USERNAME).unwrap_or_default())
                    || matches(entry.get(fields::URL).unwrap_or_default())
                    || matches(entry.get(fields::NOTES).unwrap_or_default())
                    || entry.tags.iter().any(|tag| matches(tag))
            })
            .map(|entry| summary(&entry))
            .collect();
        sort_summaries(&mut out);
        out
    }

    pub fn entry(&self, uuid: String) -> Result<EntryDetail, VaultError> {
        let database = self.database();
        let entry = find_entry(&database, &uuid).ok_or(VaultError::NotFound)?;
        let (urls, android_apps) = urls_and_apps(&entry);
        let mut custom_fields: Vec<EntryField> = entry
            .fields
            .iter()
            .filter(|(name, _)| !is_standard_field(name))
            .map(|(name, value)| EntryField {
                name: name.clone(),
                value: value.get().clone(),
                protected: value.is_protected(),
            })
            .collect();
        custom_fields.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(EntryDetail {
            summary: summary(&entry),
            group_uuid: uuid_of_group(&entry.parent()),
            password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
            otp_uri: entry
                .get(fields::OTP)
                .filter(|v| !v.is_empty())
                .map(str::to_owned),
            urls,
            android_apps,
            custom_fields,
            tags: entry.tags.clone(),
        })
    }

    /// The TOTP code at `unix_secs`, or `None` when the entry has no valid
    /// `otpauth://` configuration.
    pub fn totp(&self, uuid: String, unix_secs: u64) -> Option<TotpCode> {
        let database = self.database();
        let entry = find_entry(&database, &uuid)?;
        let totp = entry.get_otp().ok()?;
        let code = totp.value_at(unix_secs);
        Some(TotpCode {
            code: code.code,
            period_secs: u32::try_from(code.period.as_secs()).unwrap_or(u32::MAX),
            remaining_secs: u32::try_from(code.valid_for.as_secs()).unwrap_or(u32::MAX),
        })
    }

    /// Entries whose URL (or additional URL) matches a web page, best first.
    pub fn match_web(&self, url: String) -> Vec<EntrySummary> {
        self.match_target(MatchTarget {
            web_url: Some(&url),
            android_package: None,
        })
    }

    /// Entries whose `AndroidApp*` field or `androidapp://` URL names the
    /// package, best first.
    pub fn match_app(&self, package: String) -> Vec<EntrySummary> {
        self.match_target(MatchTarget {
            web_url: None,
            android_package: Some(&package),
        })
    }

    /// Add a login to the root group and return its UUID.
    pub fn add_login(&self, login: NewLogin) -> Result<String, VaultError> {
        let NewLogin {
            title,
            username,
            password,
            url,
            android_app,
        } = login;
        let password = Zeroizing::new(password);
        let uuid = {
            let mut database = self.lock_database();
            let now = Times::now();
            let mut root = database.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, &title);
            entry.set_unprotected(fields::USERNAME, &username);
            entry.set_protected(fields::PASSWORD, password.as_str());
            entry.set_unprotected(fields::URL, url.as_deref().unwrap_or_default());
            if let Some(app) = android_app.as_deref().filter(|app| !app.trim().is_empty()) {
                entry.set_unprotected(ANDROID_APP_FIELD, app.trim());
            }
            entry.times.creation = Some(now);
            entry.times.last_modification = Some(now);
            entry.times.location_changed = Some(now);
            uuid_of_entry(&entry)
        };
        self.modified.store(true, Ordering::SeqCst);
        Ok(uuid)
    }

    /// Create a full entry in the specified group (or root if empty) and return its UUID.
    pub fn create_entry(&self, input: EntryInput) -> Result<String, VaultError> {
        let normalized_otp = match input.totp.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => Some(normalize_otp(raw, &input.title, &input.username)?),
            None => None,
        };
        let password = Zeroizing::new(input.password);
        let uuid = {
            let mut database = self.lock_database();
            let target_group_id = find_group_id(&database, &input.group_uuid)
                .unwrap_or_else(|| database.root().id());
            let now = Times::now();
            let mut group = database
                .group_mut(target_group_id)
                .ok_or(VaultError::NotFound)?;
            let mut entry = group.add_entry();
            apply_entry_fields(
                &mut entry,
                &input.title,
                &input.username,
                password.as_str(),
                &input.url,
                &input.notes,
                normalized_otp.as_deref(),
                &input.android_apps,
                &input.custom_fields,
                &input.tags,
            );
            entry.times.creation = Some(now);
            entry.times.last_modification = Some(now);
            entry.times.location_changed = Some(now);
            uuid_of_entry(&entry)
        };
        self.modified.store(true, Ordering::SeqCst);
        Ok(uuid)
    }

    /// Update an existing entry in place (recording a history snapshot first and
    /// moving it if `input.group_uuid` changed). Preserves `KPEX_PASSKEY_*` fields
    /// and attachments.
    pub fn update_entry(&self, uuid: String, input: EntryInput) -> Result<(), VaultError> {
        let normalized_otp = match input.totp.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => Some(normalize_otp(raw, &input.title, &input.username)?),
            None => None,
        };
        let password = Zeroizing::new(input.password);
        {
            let mut database = self.lock_database();
            let entry_id = find_entry_id(&database, &uuid).ok_or(VaultError::NotFound)?;
            let current_parent_id = database
                .entry(entry_id)
                .ok_or(VaultError::NotFound)?
                .parent()
                .id();
            let target_group_id = find_group_id(&database, &input.group_uuid)
                .unwrap_or(current_parent_id);
            let now = Times::now();

            {
                let mut entry = database.entry_mut(entry_id).ok_or(VaultError::NotFound)?;
                // Preserve previous version in history before mutating.
                let mut snapshot = entry.as_ref().deref().clone();
                snapshot.history = None;
                let history = entry.history.get_or_insert_with(History::default);
                history.add_entry(snapshot);

                apply_entry_fields(
                    &mut entry,
                    &input.title,
                    &input.username,
                    password.as_str(),
                    &input.url,
                    &input.notes,
                    normalized_otp.as_deref(),
                    &input.android_apps,
                    &input.custom_fields,
                    &input.tags,
                );
                entry.times.last_modification = Some(now);
            }

            if target_group_id != current_parent_id {
                if let Some(mut entry) = database.entry_mut(entry_id) {
                    entry.track_changes().move_to(target_group_id).map_err(|e| {
                        VaultError::Corrupt {
                            msg: format!("could not move entry: {e}"),
                        }
                    })?;
                    entry.times.location_changed = Some(now);
                }
            }
        }
        self.modified.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Delete an entry: moves to the Recycle Bin when enabled (creating it on demand),
    /// or permanently removes it with a KDBX tombstone for cloud sync.
    pub fn delete_entry(&self, uuid: String) -> Result<(), VaultError> {
        {
            let mut database = self.lock_database();
            let entry_id = find_entry_id(&database, &uuid).ok_or(VaultError::NotFound)?;
            let recycle = recycle_ids(&database);
            let already_in_recycle = database
                .entry(entry_id)
                .map(|e| in_recycle(&e, &recycle))
                .unwrap_or(false);
            let use_recycle = database.meta.recyclebin_enabled.unwrap_or(true) && !already_in_recycle;

            if use_recycle {
                let bin_id = ensure_recycle_bin(&mut database);
                if let Some(mut entry) = database.entry_mut(entry_id) {
                    entry.track_changes().move_to(bin_id).map_err(|e| {
                        VaultError::Corrupt {
                            msg: format!("could not move entry to recycle bin: {e}"),
                        }
                    })?;
                }
            } else if let Some(mut entry) = database.entry_mut(entry_id) {
                entry.track_changes().remove();
            }
        }
        self.modified.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Create a new group under `parent_uuid` (or root when empty) and return its UUID.
    pub fn create_group(&self, parent_uuid: String, name: String) -> Result<String, VaultError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(VaultError::Unsupported {
                msg: "group name cannot be empty".to_owned(),
            });
        }
        let uuid = {
            let mut database = self.lock_database();
            let parent_id = find_group_id(&database, &parent_uuid)
                .unwrap_or_else(|| database.root().id());
            let now = Times::now();
            let mut parent = database.group_mut(parent_id).ok_or(VaultError::NotFound)?;
            let mut group = parent.add_group();
            group.name = trimmed.to_owned();
            group.times.creation = Some(now);
            group.times.last_modification = Some(now);
            group.times.location_changed = Some(now);
            group.id().uuid().simple().to_string()
        };
        self.modified.store(true, Ordering::SeqCst);
        Ok(uuid)
    }

    /// Rename an existing group.
    pub fn rename_group(&self, group_uuid: String, name: String) -> Result<(), VaultError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(VaultError::Unsupported {
                msg: "group name cannot be empty".to_owned(),
            });
        }
        {
            let mut database = self.lock_database();
            let group_id = find_group_id(&database, &group_uuid).ok_or(VaultError::NotFound)?;
            let mut group = database.group_mut(group_id).ok_or(VaultError::NotFound)?;
            group.name = trimmed.to_owned();
            group.times.last_modification = Some(Times::now());
        }
        self.modified.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Delete a non-root group (moves to Recycle Bin when enabled, otherwise removes with tombstone).
    pub fn delete_group(&self, group_uuid: String) -> Result<(), VaultError> {
        {
            let mut database = self.lock_database();
            let group_id = find_group_id(&database, &group_uuid).ok_or(VaultError::NotFound)?;
            if group_id == database.root().id() {
                return Err(VaultError::Unsupported {
                    msg: "cannot delete the root group".to_owned(),
                });
            }
            let recycle = recycle_ids(&database);
            let already_in_recycle = recycle.contains(&group_id.uuid().simple().to_string());
            let use_recycle = database.meta.recyclebin_enabled.unwrap_or(true) && !already_in_recycle;

            if use_recycle {
                let bin_id = ensure_recycle_bin(&mut database);
                if let Some(mut group) = database.group_mut(group_id) {
                    group.track_changes().move_to(bin_id).map_err(|e| {
                        VaultError::Corrupt {
                            msg: format!("could not move group to recycle bin: {e}"),
                        }
                    })?;
                }
            } else if let Some(mut group) = database.group_mut(group_id) {
                group.track_changes().remove().map_err(|e| {
                    VaultError::Corrupt {
                        msg: format!("could not delete group: {e}"),
                    }
                })?;
            }
        }
        self.modified.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn is_modified(&self) -> bool {
        self.modified.load(Ordering::SeqCst)
    }

    /// Every passkey for `rp_id`, optionally narrowed to `allow_credential_ids`
    /// (the WebAuthn `allowCredentials` list). Recycle-bin entries are skipped.
    pub fn passkeys_for_rp(
        &self,
        rp_id: String,
        allow_credential_ids: Vec<Vec<u8>>,
    ) -> Vec<PasskeyInfo> {
        let database = self.database();
        let recycle = recycle_ids(&database);
        database
            .iter_all_entries()
            .filter(|entry| !in_recycle(entry, &recycle))
            .filter_map(|entry| {
                let passkey = stored_passkey(&entry)?;
                if passkey.rp_id != rp_id {
                    return None;
                }
                if !allow_credential_ids.is_empty()
                    && !allow_credential_ids
                        .iter()
                        .any(|id| id.as_slice() == passkey.credential_id.as_slice())
                {
                    return None;
                }
                Some(PasskeyInfo {
                    entry_uuid: uuid_of_entry(&entry),
                    credential_id: passkey.credential_id,
                    rp_id: passkey.rp_id,
                    username: passkey.username,
                    user_handle: passkey.user_handle,
                })
            })
            .collect()
    }

    /// Create a passkey and store it in a new root-group entry titled `rp_id`.
    ///
    /// The entry carries KeePassXC's `KPEX_PASSKEY_*` attributes, with the
    /// credential id, private key and user handle in the protected stream.
    pub fn register_passkey(
        &self,
        req: PasskeyCreateRequest,
    ) -> Result<PasskeyRegistration, VaultError> {
        let PasskeyCreateRequest {
            rp_id,
            rp_name: _,
            user_name,
            user_display_name: _,
            user_handle,
            algorithms,
            exclude_credential_ids,
        } = req;

        if !exclude_credential_ids.is_empty() {
            let database = self.database();
            let excluded = database.iter_all_entries().any(|entry| {
                stored_passkey(&entry).is_some_and(|passkey| {
                    passkey.rp_id == rp_id
                        && exclude_credential_ids
                            .iter()
                            .any(|id| id.as_slice() == passkey.credential_id.as_slice())
                })
            });
            if excluded {
                return Err(VaultError::Unsupported {
                    msg: "a matching credential is excluded".to_owned(),
                });
            }
        }

        let registration =
            friendlypass_passkey::register(&rp_id, &user_name, &user_handle, &algorithms)
                .map_err(passkey_error)?;

        let entry_uuid = {
            let mut database = self.lock_database();
            let now = Times::now();
            let mut root = database.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, rp_id.clone());
            entry.set_unprotected(fields::USERNAME, user_name.clone());
            entry.set_unprotected(fields::URL, format!("https://{rp_id}"));
            for field in registration.passkey.to_fields() {
                if field.protected {
                    entry.set_protected(field.name, field.value);
                } else {
                    entry.set_unprotected(field.name, field.value);
                }
            }
            entry.times.creation = Some(now);
            entry.times.last_modification = Some(now);
            entry.times.location_changed = Some(now);
            uuid_of_entry(&entry)
        };
        self.modified.store(true, Ordering::SeqCst);

        Ok(PasskeyRegistration {
            entry_uuid,
            credential_id: registration.credential_id,
            authenticator_data: registration.authenticator_data,
            attestation_object: registration.attestation_object,
            public_key_spki_der: registration.public_key_spki_der,
            algorithm: registration.algorithm,
        })
    }

    /// Sign `client_data_hash` with the passkey stored on `entry_uuid`.
    pub fn assert_passkey(
        &self,
        entry_uuid: String,
        rp_id: String,
        client_data_hash: Vec<u8>,
    ) -> Result<PasskeyAssertion, VaultError> {
        let database = self.database();
        let entry = find_entry(&database, &entry_uuid).ok_or(VaultError::NotFound)?;
        let passkey = stored_passkey(&entry).ok_or(VaultError::NotFound)?;
        if passkey.rp_id != rp_id {
            return Err(VaultError::NotFound);
        }
        let assertion =
            friendlypass_passkey::assert(&passkey, &client_data_hash).map_err(passkey_error)?;
        Ok(PasskeyAssertion {
            credential_id: assertion.credential_id,
            authenticator_data: assertion.authenticator_data,
            signature: assertion.signature,
            user_handle: assertion.user_handle,
        })
    }

    /// Merge a newer external copy of the same database (opened with this
    /// vault's credentials) into the in-memory database, preserving both
    /// sides' edits.
    ///
    /// Uses [`friendlypass::sync::merge_databases`] (UUID + timestamp +
    /// `deleted_objects` tombstones + conflict history + attachments +
    /// `meta.custom_data` + root UUID check).
    pub fn merge_from_bytes(&self, kdbx: Vec<u8>) -> Result<MergeResult, VaultError> {
        let mut source_cursor = Cursor::new(kdbx);
        let source = Database::open(&mut source_cursor, self.key.clone()).map_err(open_error)?;
        let mut database = self.lock_database();
        let summary = friendlypass::sync::merge_databases(&mut database, &source).map_err(|err| {
            VaultError::Corrupt {
                msg: err.to_string(),
            }
        })?;
        drop(database);
        if summary.total_changes() > 0 {
            self.modified.store(true, Ordering::SeqCst);
        }
        Ok(MergeResult {
            created_entries: u32::try_from(summary.created_entries).unwrap_or(u32::MAX),
            updated_entries: u32::try_from(summary.updated_entries).unwrap_or(u32::MAX),
            deleted_entries: u32::try_from(summary.deleted_entries).unwrap_or(u32::MAX),
            moved_entries: u32::try_from(summary.moved_entries).unwrap_or(u32::MAX),
            created_groups: u32::try_from(summary.created_groups).unwrap_or(u32::MAX),
            updated_groups: u32::try_from(summary.updated_groups).unwrap_or(u32::MAX),
            deleted_groups: u32::try_from(summary.deleted_groups).unwrap_or(u32::MAX),
            moved_groups: u32::try_from(summary.moved_groups).unwrap_or(u32::MAX),
            custom_data_updated: u32::try_from(summary.custom_data_updated).unwrap_or(u32::MAX),
            description: summary.describe(),
        })
    }

    /// Serialize to KDBX 4.1 bytes with the credentials the vault was opened
    /// with. KDBX 3 databases are upgraded for saving (the `keepass` writer
    /// only emits KDBX 4), exactly like the desktop app.
    pub fn save(&self) -> Result<Vec<u8>, VaultError> {
        let mut database = self.lock_database();
        if !matches!(database.config.version, DatabaseVersion::KDB4(_)) {
            database.config.version = DatabaseVersion::KDB4(1);
            database.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        }
        let mut out = Vec::new();
        database
            .save(&mut out, self.key.clone())
            .map_err(save_error)?;
        drop(database);
        self.modified.store(false, Ordering::SeqCst);
        Ok(out)
    }
}

impl Vault {
    fn lock_database(&self) -> MutexGuard<'_, Database> {
        self.database.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn database(&self) -> MutexGuard<'_, Database> {
        self.lock_database()
    }

    fn match_target(&self, target: MatchTarget<'_>) -> Vec<EntrySummary> {
        let database = self.database();
        let recycle = recycle_ids(&database);
        let mut scored: Vec<(u16, EntrySummary)> = database
            .iter_all_entries()
            .filter(|entry| !in_recycle(entry, &recycle))
            .filter_map(|entry| {
                let (_, android_apps) = urls_and_apps(&entry);
                let additional = additional_urls(&entry);
                let candidate = MatchCandidate {
                    url: entry.get(fields::URL).unwrap_or_default(),
                    additional_urls: &additional,
                    android_apps: &android_apps,
                };
                matching::score(&candidate, &target).map(|score| (score, summary(&entry)))
            })
            .collect();
        scored.sort_by(|(left_score, left), (right_score, right)| {
            left_score
                .cmp(right_score)
                .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
                .then_with(|| left.uuid.cmp(&right.uuid))
        });
        scored.into_iter().map(|(_, entry)| entry).collect()
    }
}

fn open_error(error: keepass::db::DatabaseOpenError) -> VaultError {
    use keepass::db::DatabaseOpenError as Error;
    match error {
        // Wrong password / keyfile, and KDBX3 padding errors before the stream
        // start check, all mean "invalid credentials" to the caller.
        Error::Key(_) | Error::Cryptography(_) => VaultError::InvalidCredentials,
        Error::UnsupportedVersion => VaultError::Unsupported {
            msg: "unsupported database version".to_owned(),
        },
        Error::Io(error) => VaultError::Io {
            msg: error.to_string(),
        },
        Error::UnexpectedEof => VaultError::Corrupt {
            msg: "unexpected end of file".to_owned(),
        },
        Error::VersionParse(error) => VaultError::Corrupt {
            msg: error.to_string(),
        },
        Error::Format(error) => VaultError::Corrupt {
            msg: error.to_string(),
        },
        _ => VaultError::Corrupt {
            msg: "unrecognized database error".to_owned(),
        },
    }
}

fn save_error(error: keepass::db::DatabaseSaveError) -> VaultError {
    use keepass::db::DatabaseSaveError as Error;
    match error {
        Error::Io(error) => VaultError::Io {
            msg: error.to_string(),
        },
        Error::UnsupportedVersion => VaultError::Unsupported {
            msg: "this database version cannot be written".to_owned(),
        },
        _ => VaultError::Corrupt {
            msg: format!("could not serialize database: {error}"),
        },
    }
}

fn uuid_of_entry(entry: &Entry) -> String {
    entry.id().uuid().simple().to_string()
}

fn uuid_of_group(group: &GroupRef<'_>) -> String {
    group.id().uuid().simple().to_string()
}

/// KeePassXC UUIDs are dashless lowercase hex; accept dashed input too.
fn normalize_uuid(text: &str) -> Option<String> {
    let mut out = String::with_capacity(32);
    for character in text.chars() {
        if character == '-' {
            continue;
        }
        if character.is_ascii_hexdigit() {
            out.push(character.to_ascii_lowercase());
        } else {
            return None;
        }
    }
    (out.len() == 32).then_some(out)
}

fn find_entry<'a>(database: &'a Database, uuid: &str) -> Option<EntryRef<'a>> {
    let uuid = normalize_uuid(uuid)?;
    database
        .iter_all_entries()
        .find(|entry| uuid_of_entry(entry) == uuid)
}

fn find_entry_id(database: &Database, uuid: &str) -> Option<EntryId> {
    find_entry(database, uuid).map(|e| e.id())
}

fn find_group_id(database: &Database, uuid: &str) -> Option<GroupId> {
    let uuid = normalize_uuid(uuid)?;
    let recycle = recycle_ids(database);
    if recycle.contains(&uuid) {
        return None;
    }
    database
        .iter_all_groups()
        .find(|group| uuid_of_group(group) == uuid)
        .map(|group| group.id())
}

fn ensure_recycle_bin(database: &mut Database) -> GroupId {
    if let Some(bin) = database.recycle_bin() {
        return bin.id();
    }
    let now = Times::now();
    let bin_id = {
        let mut root = database.root_mut();
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".to_owned();
        bin.times.creation = Some(now);
        bin.times.last_modification = Some(now);
        bin.times.location_changed = Some(now);
        bin.id()
    };
    database.meta.recyclebin_uuid = Some(bin_id.uuid());
    database.meta.recyclebin_enabled = Some(true);
    bin_id
}

#[allow(clippy::too_many_arguments)]
fn apply_entry_fields(
    entry: &mut Entry,
    title: &str,
    username: &str,
    password: &str,
    url: &str,
    notes: &str,
    otp: Option<&str>,
    android_apps: &[String],
    custom_fields: &[EntryField],
    tags: &[String],
) {
    entry.set_unprotected(fields::TITLE, title);
    entry.set_unprotected(fields::USERNAME, username);
    entry.set_protected(fields::PASSWORD, password);
    entry.set_unprotected(fields::URL, url);
    entry.set_unprotected(fields::NOTES, notes);

    match otp {
        Some(uri) if !uri.is_empty() => {
            entry.set_protected(fields::OTP, uri);
        }
        _ => {
            entry.fields.remove(fields::OTP);
        }
    }

    // Remove previous non-standard, non-passkey fields (including old AndroidApp* fields)
    // so deleted custom fields and removed Android apps don't linger.
    let to_remove: Vec<String> = entry
        .fields
        .keys()
        .filter(|name| !is_standard_field(name) && !name.starts_with("KPEX_PASSKEY_"))
        .cloned()
        .collect();
    for name in to_remove {
        entry.fields.remove(&name);
    }

    let cleaned_apps: Vec<&str> = android_apps
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    for (idx, app) in cleaned_apps.iter().enumerate() {
        let field_name = if idx == 0 {
            ANDROID_APP_FIELD.to_owned()
        } else {
            format!("{ANDROID_APP_FIELD}_{idx}")
        };
        entry.set_unprotected(field_name, *app);
    }

    for field in custom_fields {
        let name = field.name.trim();
        if name.is_empty()
            || is_standard_field(name)
            || is_android_app_field(name)
            || name.starts_with("KPEX_PASSKEY_")
        {
            continue;
        }
        if field.protected {
            entry.set_protected(name, field.value.as_str());
        } else {
            entry.set_unprotected(name, field.value.as_str());
        }
    }

    entry.tags = tags
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect();
}

fn normalize_otp(raw: &str, title: &str, username: &str) -> Result<String, VaultError> {
    let uri = if raw.starts_with("otpauth://") {
        raw.to_owned()
    } else {
        let secret: String = raw
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let label = if !username.trim().is_empty() {
            username.trim()
        } else if !title.trim().is_empty() {
            title.trim()
        } else {
            "account"
        };
        format!("otpauth://totp/{label}?secret={secret}&digits=6&period=30&algorithm=SHA1")
    };
    uri.parse::<TOTP>().map_err(|_| VaultError::Unsupported {
        msg: "invalid TOTP secret or otpauth:// URI".to_owned(),
    })?;
    Ok(uri)
}

fn random_index(bound: usize) -> Result<usize, VaultError> {
    debug_assert!(bound > 0 && bound <= 256);
    let limit = (256 / bound) * bound;
    let mut byte = [0u8; 1];
    loop {
        getrandom::fill(&mut byte).map_err(|e| VaultError::Io {
            msg: format!("random number generator failed: {e}"),
        })?;
        let value = byte[0] as usize;
        if value < limit {
            return Ok(value % bound);
        }
    }
}

/// Reads a KeePassXC-format passkey from an entry's fields. Protected values
/// are transparently unprotected by the `keepass` crate here; they stay
/// protected in the database and in the saved bytes.
fn stored_passkey(entry: &EntryRef<'_>) -> Option<StoredPasskey> {
    StoredPasskey::from_fields(|name| entry.get(name).map(str::to_owned))
}

fn passkey_error(error: friendlypass_passkey::PasskeyError) -> VaultError {
    use friendlypass_passkey::PasskeyError as Error;
    match error {
        Error::EmptyRpId => VaultError::Unsupported {
            msg: "empty relying party id".to_owned(),
        },
        Error::UnsupportedAlgorithm(algorithm) => VaultError::Unsupported {
            msg: format!("unsupported WebAuthn algorithm: {algorithm}"),
        },
        Error::InvalidBase64 => VaultError::Corrupt {
            msg: "invalid base64url data in a passkey field".to_owned(),
        },
        Error::InvalidKey(msg) => VaultError::Corrupt {
            msg: format!("invalid passkey private key: {msg}"),
        },
        Error::InvalidClientDataHash { len } => VaultError::Corrupt {
            msg: format!("invalid client data hash length: {len}"),
        },
        Error::Random => VaultError::Io {
            msg: "random number generator failed".to_owned(),
        },
        Error::Crypto(msg) => VaultError::Io {
            msg: format!("cryptographic operation failed: {msg}"),
        },
    }
}

fn recycle_ids(database: &Database) -> HashSet<String> {
    fn collect(group: &GroupRef<'_>, out: &mut HashSet<String>) {
        out.insert(uuid_of_group(group));
        for child in group.groups() {
            collect(&child, out);
        }
    }

    let mut out = HashSet::new();
    if let Some(recycle) = database.recycle_bin() {
        collect(&recycle, &mut out);
    }
    out
}

fn in_recycle(entry: &EntryRef<'_>, recycle: &HashSet<String>) -> bool {
    recycle.contains(&uuid_of_group(&entry.parent()))
}

fn collect_groups(
    group: &GroupRef<'_>,
    parent_uuid: Option<&str>,
    recycle: &HashSet<String>,
    out: &mut Vec<GroupNode>,
) {
    let uuid = uuid_of_group(group);
    if recycle.contains(&uuid) {
        return;
    }
    let name = if group.name.is_empty() && parent_uuid.is_none() {
        "Root".to_owned()
    } else {
        group.name.clone()
    };
    out.push(GroupNode {
        uuid: uuid.clone(),
        name,
        parent_uuid: parent_uuid.map(str::to_owned),
        entry_count: u32::try_from(group.entries().count()).unwrap_or(u32::MAX),
    });
    for child in group.groups() {
        collect_groups(&child, Some(&uuid), recycle, out);
    }
}

fn group_path(group: &GroupRef<'_>) -> String {
    let database = group.database();
    let mut names = Vec::new();
    let mut current = Some(group.id());
    while let Some(id) = current {
        let Some(group) = database.group(id) else {
            break;
        };
        let name = if group.parent().is_none() {
            // The contract's group paths always start at a logical "Root",
            // even though KeePassXC may name the actual root group
            // "Passwords".
            "Root".to_owned()
        } else {
            group.name.clone()
        };
        names.push(name);
        current = group.parent().map(|parent| parent.id());
    }
    names.reverse();
    names.join("/")
}

fn summary(entry: &EntryRef<'_>) -> EntrySummary {
    EntrySummary {
        uuid: uuid_of_entry(entry),
        title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
        username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
        url: entry.get(fields::URL).unwrap_or_default().to_owned(),
        group_path: group_path(&entry.parent()),
        has_totp: entry.get_otp().is_ok(),
        has_passkey: entry
            .get(PASSKEY_CREDENTIAL_ID_FIELD)
            .is_some_and(|value| !value.is_empty()),
    }
}

fn sort_summaries(entries: &mut [EntrySummary]) {
    entries.sort_by(|left, right| {
        left.title
            .to_lowercase()
            .cmp(&right.title.to_lowercase())
            .then_with(|| left.uuid.cmp(&right.uuid))
    });
}

/// Standard fields shown by dedicated UI, not in `custom_fields`.
fn is_standard_field(name: &str) -> bool {
    matches!(
        name,
        fields::TITLE
            | fields::USERNAME
            | fields::PASSWORD
            | fields::URL
            | fields::NOTES
            | fields::OTP
    )
}

fn is_android_app_field(name: &str) -> bool {
    name == ANDROID_APP_FIELD
        || name
            .strip_prefix(ANDROID_APP_FIELD)
            .is_some_and(|rest| rest.starts_with('_'))
}

fn is_android_app_url(value: &str) -> bool {
    value.starts_with(ANDROID_APP_SCHEME)
}

fn package_from_url(value: &str) -> Option<&str> {
    value
        .strip_prefix(ANDROID_APP_SCHEME)
        .map(|package| package.trim_end_matches('/'))
        .filter(|package| !package.is_empty())
}

/// `KP2A_URL`, `KP2A_URL_1`, … in numeric order, then any field whose value is
/// an `androidapp://…` URL (as the matching contract requires).
fn additional_urls(entry: &EntryRef<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |url: &str| {
        if !url.is_empty() && !out.contains(&url.to_owned()) {
            out.push(url.to_owned());
        }
    };

    if let Some(url) = entry.get(KP2A_URL_FIELD) {
        push(url);
    }
    let mut index = 1u32;
    while let Some(url) = entry.get(&format!("{KP2A_URL_FIELD}_{index}")) {
        push(url);
        index += 1;
    }
    let mut extra: Vec<(&str, &str)> = entry
        .fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.get().as_str()))
        .filter(|(_, value)| is_android_app_url(value))
        .collect();
    extra.sort_by(|left, right| left.0.cmp(right.0));
    for (_, value) in extra {
        push(value);
    }
    out
}

/// The displayable URL list (main first) and Android packages.
fn urls_and_apps(entry: &EntryRef<'_>) -> (Vec<String>, Vec<String>) {
    let mut urls = Vec::new();
    let mut push_url = |url: &str| {
        if !url.is_empty() && !urls.contains(&url.to_owned()) {
            urls.push(url.to_owned());
        }
    };
    push_url(entry.get(fields::URL).unwrap_or_default());
    for url in additional_urls(entry) {
        push_url(&url);
    }

    let mut apps = Vec::new();
    let mut push_app = |app: &str| {
        let app = app.trim();
        if !app.is_empty() && !apps.contains(&app.to_owned()) {
            apps.push(app.to_owned());
        }
    };
    let mut named: Vec<(&str, &str)> = entry
        .fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.get().as_str()))
        .filter(|(name, _)| is_android_app_field(name))
        .collect();
    named.sort_by(|left, right| left.0.cmp(right.0));
    for (_, value) in named {
        push_app(value);
    }
    for url in &urls {
        if let Some(package) = package_from_url(url) {
            push_app(package);
        }
    }

    (urls, apps)
}
