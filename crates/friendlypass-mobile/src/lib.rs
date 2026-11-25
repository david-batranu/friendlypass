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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use friendlypass::matching::{self, MatchCandidate, MatchTarget};
use keepass::config::{DatabaseVersion, InnerCipherConfig};
use keepass::db::{fields, Database, Entry, EntryRef, GroupRef, Times};
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
    pub password: String,
    pub notes: String,
    /// The main URL first, then additional URLs.
    pub urls: Vec<String>,
    pub android_apps: Vec<String>,
    /// Fields that are not one of the standard Title/UserName/Password/URL/
    /// Notes/otp fields.
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
            password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
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
            uuid_of_entry(&entry)
        };
        self.modified.store(true, Ordering::SeqCst);
        Ok(uuid)
    }

    pub fn is_modified(&self) -> bool {
        self.modified.load(Ordering::SeqCst)
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
