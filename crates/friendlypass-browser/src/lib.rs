//! `friendlypass-browser` — friendlypass browser integration: the
//! KeePassXC-Browser protocol server.
//!
//! Implements the socket side of the protocol that KeePassXC's `BrowserHost`
//! serves and the shipped `keepassxc-proxy` relays: the X25519
//! `change-public-keys` handshake, encrypted actions (`get-databasehash`,
//! `associate`, `test-associate`, `get-logins`, `set-login`, `get-totp`,
//! `get-database-groups`, `generate-password`, `lock-database`) with
//! libsodium-compatible `crypto_box_easy` sealing and nonce-increment
//! responses — all matching KeePassXC 2.8.0's message shapes.
//!
//! The wire contract is `protocol/ACTIONS.md`. Golden vectors live in
//! `protocol/fixtures/`; `tests/fixtures_crypto.rs` (WP0) proves the crypto
//! round-trip and `tests/fixtures_actions.rs` drives this server with the
//! exact fixture frames.

pub mod bridge;
pub mod crypto;
pub mod entry_write;
pub mod file_bridge;
pub mod native_messaging;
pub mod passkey_write;
pub mod passkeys;
pub mod peer;
pub mod protocol;
pub mod push;
pub mod server;
pub mod service;

pub use bridge::{
    AssociationRequest, AutoApproveBridge, BrowserBridge, DenyAllBridge, PasskeyCandidate,
    PasskeyGetRequest, PasskeyRegisterRequest, SetLoginRequest,
};
pub use file_bridge::FileBridge;
pub use peer::{verify_peer, PeerInfo};
pub use push::PushHub;
pub use server::{browser_server_path, start, start_with_config, user_temp_dir, ServerConfig, ServerHandle};
pub use service::SharedState;
pub use service::{AssociationInfo, CredentialEntry, GroupNode, PasskeyRecord, ServiceState};

use base64::Engine as _;

/// Standard base64 with padding, as KeePassXC's `getBase64FromArray` emits it.
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// base64url without padding (KeePassXC's credential ids and user handles).
pub fn b64url(bytes: &[u8]) -> String {
    friendlypass_passkey::b64url_encode(bytes)
}

use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use keepass::db::{CustomDataItem, CustomDataValue, Database};
use sha2::{Digest, Sha256};

/// KeePassXC's database-metadata key prefix for browser associations.
pub const BROWSER_CUSTOM_DATA_PREFIX: &str = "KPXC_BROWSER_";

/// The database hash reported to browser clients: lowercase hex SHA-256 of the
/// dashless RFC 4122 root-group UUID — exactly KeePassXC's
/// `BrowserService::getDatabaseHash`.
pub fn database_hash(root_uuid: &str) -> String {
    let normalised = root_uuid
        .chars()
        .filter(|ch| *ch != '-')
        .map(|ch| ch.to_ascii_lowercase())
        .collect::<String>();
    hex_lower(&Sha256::digest(normalised.as_bytes()))
}

fn hex_lower(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the served snapshot from a keepass database: hash, groups, entries
/// (recycle bin excluded), associations from database metadata and a cheap
/// fingerprint the GUI uses to detect changes.
pub fn snapshot_from_database(db: &Database) -> ServiceState {
    let root_uuid = db.root().id().uuid().simple().to_string();
    let recycle = recycle_group_ids(db);
    let groups = group_nodes(&db.root(), &recycle);
    let entries = db
        .iter_all_entries()
        .filter(|entry| !recycle.contains(&entry.parent().id().uuid().simple().to_string()))
        .map(|entry| {
            let parent = entry.parent();
            let mut additional_urls: Vec<String> = Vec::new();
            if let Some(url) = entry.get("KP2A_URL") {
                if !url.is_empty() {
                    additional_urls.push(url.to_owned());
                }
            }
            let mut index = 1u32;
            while let Some(url) = entry.get(&format!("KP2A_URL_{index}")) {
                if !url.is_empty() {
                    additional_urls.push(url.to_owned());
                }
                index += 1;
            }
            let string_fields = entry
                .fields
                .iter()
                .filter(|(key, _)| key.starts_with("KPH: "))
                .map(|(key, value)| (key.clone(), value.get().clone()))
                .collect();
            let http_only = resolve_flag(&entry, "BrowserOnlyHttpAuth");
            let not_http_auth = resolve_flag(&entry, "BrowserNotHttpAuth");
            let skip_auto_submit = resolve_tristate(&entry, "BrowserSkipAutoSubmit");
            let expired = entry.times.expires.unwrap_or(false)
                && entry.times.expiry.and_utc().timestamp()
                    < std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |duration| duration.as_secs() as i64);
            CredentialEntry {
                title: entry.get("Title").unwrap_or_default().to_owned(),
                username: entry.get("UserName").unwrap_or_default().to_owned(),
                password: entry.get("Password").unwrap_or_default().to_owned(),
                url: entry.get("URL").unwrap_or_default().to_owned(),
                uuid: entry.id().uuid().simple().to_string(),
                group: parent.name.clone(),
                group_uuid: parent.id().uuid().simple().to_string(),
                additional_urls,
                totp_url: entry.get("otp").filter(|otp| !otp.is_empty()).map(str::to_owned),
                expired,
                skip_auto_submit,
                string_fields,
                http_only,
                not_http_auth,
            }
        })
        .collect();

    let passkeys = db
        .iter_all_entries()
        .filter(|entry| !recycle.contains(&entry.parent().id().uuid().simple().to_string()))
        .filter_map(|entry| passkey_record(&entry))
        .collect();

    let associations = db
        .meta
        .custom_data
        .iter()
        .filter_map(|(key, item)| {
            let id = key.strip_prefix(BROWSER_CUSTOM_DATA_PREFIX)?;
            let value = custom_string(item)?;
            (!id.is_empty() && !value.is_empty()).then(|| (id.to_owned(), value))
        })
        .collect();

    ServiceState {
        db_hash: database_hash(&root_uuid),
        locked: false,
        entries,
        groups,
        passkeys,
        allow_localhost_passkeys: false,
        associations,
        associations_info: Default::default(),
        associations_changed: false,
        snapshot_signature: snapshot_signature(db),
        bridge: None,
        push: Default::default(),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

/// The passkey fields of one entry, read exactly like KeePassXC
/// (`Entry::hasPasskey` + `KPEX_PASSKEY_*`, including the StrongBox alias).
/// `None` when the entry has no passkey attributes.
fn passkey_record(entry: &keepass::db::EntryRef<'_>) -> Option<PasskeyRecord> {
    let get = |key: &str| entry.get(key).map(str::to_owned);
    if !passkeys::has_passkey_fields(entry.fields.keys().map(String::as_str)) {
        return None;
    }
    let rp_id = get(friendlypass_passkey::KPEX_PASSKEY_RELYING_PARTY).unwrap_or_default();
    if rp_id.is_empty() {
        return None;
    }
    let username = friendlypass_passkey::StoredPasskey::from_fields(|key| get(key))
        .map(|passkey| passkey.username)
        .unwrap_or_default();
    let user_handle = get(friendlypass_passkey::KPEX_PASSKEY_USER_HANDLE)
        .filter(|handle| !handle.is_empty())
        .and_then(|handle| friendlypass_passkey::b64url_decode(&handle).ok())
        .unwrap_or_default();
    let credential_id = passkeys::credential_id_from_fields(get)?;
    Some(PasskeyRecord {
        uuid: entry.id().uuid().simple().to_string(),
        title: entry.get("Title").unwrap_or_default().to_owned(),
        username,
        rp_id,
        credential_id,
        user_handle,
    })
}

/// Browser associations stored in database metadata (`KPXC_BROWSER_<id>`).
pub fn associations_from_database(db: &Database) -> std::collections::HashMap<String, String> {
    db.meta
        .custom_data
        .iter()
        .filter_map(|(key, item)| {
            let id = key.strip_prefix(BROWSER_CUSTOM_DATA_PREFIX)?;
            let value = custom_string(item)?;
            (!id.is_empty() && !value.is_empty()).then(|| (id.to_owned(), value))
        })
        .collect()
}

pub fn custom_string(item: &CustomDataItem) -> Option<String> {
    match item.value.as_ref()? {
        CustomDataValue::String(value) => Some(value.clone()),
        CustomDataValue::Binary(_) => None,
    }
}

/// A cheap, deterministic change fingerprint: root id, counts, the newest
/// modification time and the group-name total. The GUI resyncs when it moves.
pub fn snapshot_signature(db: &Database) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    db.root().id().uuid().hash(&mut hasher);
    db.num_entries().hash(&mut hasher);
    db.num_groups().hash(&mut hasher);
    let newest = db
        .iter_all_entries()
        .filter_map(|entry| entry.times.last_modification)
        .chain(db.iter_all_groups().filter_map(|group| group.times.last_modification))
        .max();
    newest.hash(&mut hasher);
    db.iter_all_groups().map(|group| group.name.len()).sum::<usize>().hash(&mut hasher);
    hasher.finish()
}

/// UUIDs of the recycle-bin group and every descendant, as dashless strings.
pub fn recycle_group_ids(db: &Database) -> HashSet<String> {
    let mut ids = HashSet::new();
    if let Some(recycle) = db.recycle_bin() {
        collect_group_ids(&recycle, &mut ids);
    }
    ids
}

fn collect_group_ids(group: &keepass::db::GroupRef<'_>, ids: &mut HashSet<String>) {
    ids.insert(group.id().uuid().simple().to_string());
    for child in group.groups() {
        collect_group_ids(&child, ids);
    }
}

fn group_nodes(group: &keepass::db::GroupRef<'_>, recycle: &HashSet<String>) -> Vec<GroupNode> {
    let uuid = group.id().uuid().simple().to_string();
    if recycle.contains(&uuid) {
        return Vec::new();
    }
    let children = group
        .groups()
        .flat_map(|child| group_nodes(&child, recycle))
        .collect();
    vec![GroupNode {
        name: if group.name.is_empty() {
            "Root".to_owned()
        } else {
            group.name.clone()
        },
        uuid,
        children,
    }]
}

fn resolve_flag(entry: &keepass::db::EntryRef<'_>, key: &str) -> bool {
    resolve_tristate(entry, key).is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

/// Entry custom data wins over the group chain, like KeePassXC's
/// `resolveCustomDataTriState`.
fn resolve_tristate(entry: &keepass::db::EntryRef<'_>, key: &str) -> Option<String> {
    if let Some(value) = entry.custom_data.get(key).and_then(custom_string) {
        if !value.is_empty() {
            return Some(value);
        }
    }
    let parent = entry.parent();
    let database = parent.database();
    let mut group_id = Some(parent.id());
    while let Some(id) = group_id {
        let Some(current) = database.group(id) else {
            break;
        };
        if let Some(value) = current.custom_data.get(key).and_then(custom_string) {
            if !value.is_empty() {
                return Some(value);
            }
        }
        group_id = current.parent().map(|parent| parent.id());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_hash_ignores_dashes_and_case() {
        assert_eq!(
            database_hash("BB710C2F-8767-61BB-9074-8CC271FF8FAE"),
            database_hash("bb710c2f876761bb90748cc271ff8fae")
        );
        assert_eq!(database_hash("bb710c2f876761bb90748cc271ff8fae").len(), 64);
    }

    #[test]
    fn snapshot_excludes_recycle_bin() {
        let mut db = Database::new();
        let recycle_uuid;
        {
            let mut root = db.root_mut();
            let mut keep = root.add_entry();
            keep.set_unprotected("Title", "Keep");
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".into();
            recycle_uuid = bin.id().uuid();
            let mut gone = bin.add_entry();
            gone.set_unprotected("Title", "Gone");
        }
        db.meta.recyclebin_uuid = Some(recycle_uuid);
        let snapshot = snapshot_from_database(&db);
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].title, "Keep");
        assert_eq!(snapshot.entries[0].uuid.len(), 32);
        assert!(!snapshot.db_hash.is_empty());
        let groups = serde_json::to_value(GroupNode::to_json(&snapshot.groups[0])).unwrap();
        assert_eq!(groups["children"].as_array().unwrap().len(), 0);
    }
}
