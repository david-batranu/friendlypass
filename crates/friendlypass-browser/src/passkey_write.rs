//! Passkey entry creation for `passkeys-register`, shared by every bridge.
//!
//! Mirrors KeePassXC 2.8's `BrowserService::addPasskeyToGroup` /
//! `addPasskeyToEntry`:
//!
//! * a new entry goes into the passkey group (the extension's `groupName`, the
//!   app's "Passkey default group" setting, or `KeePassXC-Browser Passkeys`,
//!   created on demand like `createNewGroup(..., true)`);
//! * its title is `"<rp.name> (Passkey)"`, its user name `user.name`, its URL
//!   the page origin, and it carries the tag `Passkey`;
//! * the `KPEX_PASSKEY_*` attributes are written with the exact names, values
//!   and protected flags from [`StoredPasskey::to_fields`], so KeePassXC can
//!   use the credential and vice versa.
//!
//! The entry icon is KeePassXC's passkey icon id (13), applied with
//! `set_icon_builtin` so it never replaces an unrelated custom icon.

use chrono::NaiveDateTime;
use friendlypass_passkey::StoredPasskey;
use keepass::db::{fields, Database, GroupId, Times};

use crate::passkeys;

/// Built-in icon KeePassXC gives passkey entries.
pub const PASSKEY_ICON_ID: usize = 13;

/// Add the passkey attributes to `entry`, replacing any previous passkey.
fn write_passkey(
    entry: &mut keepass::db::EntryMut<'_>,
    passkey: &StoredPasskey,
    now: NaiveDateTime,
) {
    for field in passkey.to_fields() {
        if field.protected {
            entry.set_protected(field.name, field.value);
        } else {
            entry.set_unprotected(field.name, field.value);
        }
    }
    if !entry.tags.iter().any(|tag| tag == passkeys::PASSKEYS_TAG) {
        entry.tags.push(passkeys::PASSKEYS_TAG.to_owned());
    }
    entry.times.last_modification = Some(now);
}

/// Resolve (or create) the group passkey entries are written to.
///
/// `group_name` is the extension's `groupName` (KeePassXC's "Passkey default
/// group"), falling back to [`passkeys::PASSKEYS_DEFAULT_GROUP_NAME`]. Like
/// `BrowserService::createNewGroup`, the group is created when it does not
/// exist.
pub fn passkey_group(db: &mut Database, group_name: &str) -> GroupId {
    let name = if group_name.trim().is_empty() {
        passkeys::PASSKEYS_DEFAULT_GROUP_NAME
    } else {
        group_name.trim()
    };
    if let Some(group) = db.iter_all_groups().find(|group| group.name == name) {
        return group.id();
    }
    let root = db.root().id();
    let mut parent = match db.group_mut(root) {
        Some(parent) => parent,
        None => return root,
    };
    let now = Times::now();
    let mut group = parent.add_group();
    group.name = name.to_owned();
    group.times.creation = Some(now);
    group.times.last_modification = Some(now);
    group.set_icon_builtin(PASSKEY_ICON_ID);
    group.id()
}

/// Create a new passkey entry (`addPasskeyToGroup`). Returns its UUID
/// (dashless 32-hex), or `None` if the group vanished.
pub fn create_passkey_entry(
    db: &mut Database,
    passkey: &StoredPasskey,
    rp_name: &str,
    origin: &str,
    group_name: &str,
) -> Option<String> {
    let group = passkey_group(db, group_name);
    let now = Times::now();
    let mut parent = db.group_mut(group)?;
    let mut entry = parent.add_entry();
    let uuid = entry.id().uuid().simple().to_string();
    entry.set_unprotected(
        fields::TITLE,
        passkeys::passkey_entry_title(rp_name, &passkey.rp_id),
    );
    entry.set_unprotected(fields::USERNAME, &passkey.username);
    entry.set_unprotected(fields::URL, passkeys::passkey_entry_url(origin));
    entry.set_protected(fields::PASSWORD, "");
    entry.set_icon_builtin(PASSKEY_ICON_ID);
    entry.times.creation = Some(now);
    write_passkey(&mut entry, passkey, now);
    Some(uuid)
}

/// Replace the passkey of an existing entry (`addPasskeyToEntry`). Returns
/// `false` when the UUID is not in this database.
pub fn update_passkey_entry(db: &mut Database, uuid: &str, passkey: &StoredPasskey) -> bool {
    let Some(id) = db
        .iter_all_entries()
        .find(|entry| entry.id().uuid().simple().to_string() == uuid)
        .map(|entry| entry.id())
    else {
        return false;
    };
    let Some(mut entry) = db.entry_mut(id) else {
        return false;
    };
    let now = Times::now();
    write_passkey(&mut entry, passkey, now);
    true
}

/// Reads the stored passkey of one entry (`None` when it has none).
pub fn entry_passkey(db: &Database, uuid: &str) -> Option<StoredPasskey> {
    let entry = db
        .iter_all_entries()
        .find(|entry| entry.id().uuid().simple().to_string() == uuid)?;
    let get = |key: &str| entry.get(key).map(str::to_owned);
    passkeys::stored_passkey(get)
}

#[cfg(test)]
mod tests {
    use super::*;
    use friendlypass_passkey::{register, ES256};

    fn sample() -> StoredPasskey {
        register("example.com", "alice@example.com", b"handle-1", &[ES256])
            .unwrap()
            .passkey
    }

    #[test]
    fn creates_an_entry_in_the_default_group_with_keepassxc_fields() {
        let mut db = Database::new();
        let passkey = sample();
        let uuid = create_passkey_entry(&mut db, &passkey, "Example", "https://example.com", "")
            .expect("entry created");

        let entry = db
            .iter_all_entries()
            .find(|entry| entry.id().uuid().simple().to_string() == uuid)
            .expect("entry present");
        assert_eq!(entry.get(fields::TITLE), Some("Example (Passkey)"));
        assert_eq!(entry.get(fields::USERNAME), Some("alice@example.com"));
        assert_eq!(entry.get(fields::URL), Some("https://example.com"));
        assert_eq!(
            entry.get("KPEX_PASSKEY_RELYING_PARTY"),
            Some("example.com")
        );
        assert_eq!(
            entry.get("KPEX_PASSKEY_CREDENTIAL_ID"),
            Some(friendlypass_passkey::b64url_encode(&passkey.credential_id).as_str())
        );
        assert!(entry
            .get("KPEX_PASSKEY_PRIVATE_KEY_PEM")
            .unwrap()
            .starts_with("-----BEGIN"));
        assert!(entry.tags.iter().any(|tag| tag == passkeys::PASSKEYS_TAG));
        assert_eq!(entry.parent().name, passkeys::PASSKEYS_DEFAULT_GROUP_NAME);

        // The stored attributes parse back into the same passkey through the
        // KeePassXC field format.
        let read = entry_passkey(&db, &uuid).expect("passkey readable");
        assert_eq!(read.credential_id, passkey.credential_id);
        assert_eq!(read.rp_id, "example.com");
        assert_eq!(read.user_handle, b"handle-1");
        assert_eq!(read.username, "alice@example.com");
        assert_eq!(read.backup_eligible, passkey.backup_eligible);
        assert_eq!(read.backup_state, passkey.backup_state);
    }

    #[test]
    fn the_protected_flags_follow_keepassxc() {
        let mut db = Database::new();
        let passkey = sample();
        let uuid = create_passkey_entry(&mut db, &passkey, "Example", "https://example.com", "")
            .unwrap();
        let entry = db
            .iter_all_entries()
            .find(|entry| entry.id().uuid().simple().to_string() == uuid)
            .unwrap();
        let protection = |name: &str| entry.fields.get(name).map(|value| value.is_protected());
        assert_eq!(protection("KPEX_PASSKEY_USERNAME"), Some(false));
        assert_eq!(protection("KPEX_PASSKEY_CREDENTIAL_ID"), Some(true));
        assert_eq!(protection("KPEX_PASSKEY_PRIVATE_KEY_PEM"), Some(true));
        assert_eq!(protection("KPEX_PASSKEY_RELYING_PARTY"), Some(false));
        assert_eq!(protection("KPEX_PASSKEY_USER_HANDLE"), Some(true));
        assert_eq!(protection("KPEX_PASSKEY_FLAG_BE"), Some(false));
        assert_eq!(protection("KPEX_PASSKEY_FLAG_BS"), Some(false));
    }

    #[test]
    fn a_named_group_is_found_or_created_once() {
        let mut db = Database::new();
        let passkey = sample();
        let first = create_passkey_entry(&mut db, &passkey, "Example", "https://example.com", "Web")
            .unwrap();
        let second =
            create_passkey_entry(&mut db, &passkey, "Example", "https://example.com", "Web").unwrap();
        assert_ne!(first, second);
        let web_groups = db.iter_all_groups().filter(|group| group.name == "Web").count();
        assert_eq!(web_groups, 1, "the group is reused, not duplicated");
    }

    #[test]
    fn updating_replaces_the_passkey_in_place() {
        let mut db = Database::new();
        let old = sample();
        let uuid = create_passkey_entry(&mut db, &old, "Example", "https://example.com", "").unwrap();
        let mut updated = sample();
        updated.username = "bob@example.com".into();
        assert!(update_passkey_entry(&mut db, &uuid, &updated));
        let read = entry_passkey(&db, &uuid).unwrap();
        assert_eq!(read.credential_id, updated.credential_id);
        assert_eq!(read.username, "bob@example.com");
        assert_eq!(db.iter_all_entries().count(), 1);
        assert!(!update_passkey_entry(
            &mut db,
            "d5ec68c35705b72fde380bd469aa149f",
            &updated
        ));
    }
}
