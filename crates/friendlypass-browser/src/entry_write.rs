//! Entry creation/update for `set-login`, shared by every bridge.
//!
//! The GUI bridge ([`crate::bridge::BrowserBridge`] implementation in
//! `friendlypass-gui`) and the headless [`crate::FileBridge`] must write the
//! database identically: title derived from the URL, the target group, the
//! protected password field, `KP2A_URL` when the submit URL differs, and the
//! modification timestamp. Only the *decision to persist* differs (the GUI
//! marks the database dirty and its normal save path writes it; the headless
//! bridge saves the file immediately).
//!
//! This module holds the database mutation only, so it can be unit-tested and
//! reviewed once.

use keepass::db::{fields, Database, GroupId, Times};

use crate::bridge::SetLoginRequest;
use crate::protocol::normalize_uuid;

/// Create or update one entry from a `set-login` request.
///
/// Returns `false` when an update names a UUID that is not in this database, or
/// when the target group cannot be resolved. A `false` result maps to the inner
/// `"error"` field of the `set-login` reply and never changes the outer
/// `success`.
pub fn apply_set_login(db: &mut Database, request: &SetLoginRequest) -> bool {
    let now = Times::now();

    if let Some(uuid) = request.uuid.as_deref().and_then(normalize_uuid) {
        let target = db
            .iter_all_entries()
            .find(|entry| entry.id().uuid().simple().to_string() == uuid)
            .map(|entry| entry.id());
        let Some(id) = target else {
            return false;
        };
        let Some(mut entry) = db.entry_mut(id) else {
            return false;
        };
        entry.set_unprotected(fields::USERNAME, &request.login);
        entry.set_protected(fields::PASSWORD, &request.password);
        entry.set_unprotected(fields::URL, &request.url);
        // [friendlypass] Change the title only when the extension supplied a
        // non-empty value that differs. The save card prefills the existing
        // title on updates, so an untouched field is a no-op.
        if let Some(title) = request.title.as_deref().filter(|value| !value.is_empty()) {
            if entry.get(fields::TITLE) != Some(title) {
                entry.set_unprotected(fields::TITLE, title);
            }
        }
        if let Some(submit) = &request.submit_url {
            if submit != &request.url {
                entry.set_unprotected("KP2A_URL", submit);
            }
        }
        entry.times.last_modification = Some(now);
        true
    } else {
        let group_id = target_group(db, request.group_uuid.as_deref(), request.group.as_deref());
        let Some(mut group) = db.group_mut(group_id) else {
            return false;
        };
        let mut entry = group.add_entry();
        let title = request
            .title
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| title_for_url(&request.url));
        entry.set_unprotected(fields::TITLE, &title);
        entry.set_unprotected(fields::USERNAME, &request.login);
        entry.set_protected(fields::PASSWORD, &request.password);
        entry.set_unprotected(fields::URL, &request.url);
        if let Some(submit) = &request.submit_url {
            if submit != &request.url {
                entry.set_unprotected("KP2A_URL", submit);
            }
        }
        entry.times.creation = Some(now);
        entry.times.last_modification = Some(now);
        true
    }
}

/// Resolve the target group: UUID first, then name, then the database root.
fn target_group(db: &Database, uuid: Option<&str>, name: Option<&str>) -> GroupId {
    if let Some(uuid) = uuid.and_then(normalize_uuid) {
        if let Some(group) = db
            .iter_all_groups()
            .find(|group| group.id().uuid().simple().to_string() == uuid)
        {
            return group.id();
        }
    }
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        if let Some(group) = db.iter_all_groups().find(|group| group.name == name) {
            return group.id();
        }
    }
    db.root().id()
}

/// Entry title for a new login: the host name without `www.`.
///
/// Mirrors the GUI's previous private helper so existing databases keep the
/// same titles when a login is saved from the browser.
pub fn title_for_url(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_start_matches("www.");
    if host.is_empty() {
        "Browser login".to_owned()
    } else {
        host.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> SetLoginRequest {
        SetLoginRequest {
            acting_id: "browser".into(),
            login: "alice@example.com".into(),
            password: "s3cret".into(),
            url: url.into(),
            submit_url: None,
            group: None,
            group_uuid: None,
            uuid: None,
            download_favicon: false,
            title: None,
        }
    }

    #[test]
    fn creates_an_entry_with_title_username_password_and_url() {
        let mut db = Database::new();
        assert!(apply_set_login(&mut db, &request("https://www.example.com/login")));
        let entries: Vec<_> = db.iter_all_entries().collect();
        assert_eq!(entries.len(), 1);
        let entry = entries.first().expect("one entry");
        assert_eq!(entry.get(fields::TITLE), Some("example.com"));
        assert_eq!(entry.get(fields::USERNAME), Some("alice@example.com"));
        assert_eq!(entry.get(fields::PASSWORD), Some("s3cret"));
        assert_eq!(entry.get(fields::URL), Some("https://www.example.com/login"));
    }

    #[test]
    fn create_uses_a_supplied_title_instead_of_the_url_host() {
        let mut db = Database::new();
        let mut create = request("https://www.example.com/login");
        create.title = Some("My custom title".into());
        assert!(apply_set_login(&mut db, &create));
        let entry = db.iter_all_entries().next().expect("one entry");
        assert_eq!(entry.get(fields::TITLE), Some("My custom title"));
    }

    #[test]
    fn update_only_changes_the_title_when_the_requested_value_differs() {
        let mut db = Database::new();
        let mut create = request("https://example.com/login");
        create.title = Some("Original title".into());
        assert!(apply_set_login(&mut db, &create));
        let uuid = db
            .iter_all_entries()
            .next()
            .unwrap()
            .id()
            .uuid()
            .simple()
            .to_string();

        // Same title from the prefilled save card: no change.
        let mut same = request("https://example.com/login");
        same.uuid = Some(uuid.clone());
        same.title = Some("Original title".into());
        assert!(apply_set_login(&mut db, &same));
        assert_eq!(
            db.iter_all_entries().next().unwrap().get(fields::TITLE),
            Some("Original title")
        );

        // Absent title: keep the existing one.
        let mut absent = request("https://example.com/login");
        absent.uuid = Some(uuid.clone());
        assert!(apply_set_login(&mut db, &absent));
        assert_eq!(
            db.iter_all_entries().next().unwrap().get(fields::TITLE),
            Some("Original title")
        );

        // A changed title is applied.
        let mut changed = request("https://example.com/login");
        changed.uuid = Some(uuid);
        changed.title = Some("Renamed by user".into());
        assert!(apply_set_login(&mut db, &changed));
        assert_eq!(
            db.iter_all_entries().next().unwrap().get(fields::TITLE),
            Some("Renamed by user")
        );
    }

    #[test]
    fn update_uses_the_uuid_and_keeps_the_title() {
        let mut db = Database::new();
        assert!(apply_set_login(&mut db, &request("https://example.com/login")));
        let (uuid, title) = {
            let entry = db.iter_all_entries().next().unwrap();
            (
                entry.id().uuid().simple().to_string(),
                entry.get(fields::TITLE).unwrap_or_default().to_owned(),
            )
        };

        let mut update = request("https://example.com/login");
        update.uuid = Some(uuid);
        update.password = "new-secret".into();
        assert!(apply_set_login(&mut db, &update));

        let entry = db.iter_all_entries().next().unwrap();
        assert_eq!(entry.get(fields::TITLE), Some(title.as_str()));
        assert_eq!(entry.get(fields::PASSWORD), Some("new-secret"));
        assert_eq!(db.iter_all_entries().count(), 1);
    }

    #[test]
    fn unknown_update_uuid_reports_failure_without_creating() {
        let mut db = Database::new();
        let mut update = request("https://example.com/login");
        update.uuid = Some("d5ec68c35705b72fde380bd469aa149f".into());
        assert!(!apply_set_login(&mut db, &update));
        assert_eq!(db.iter_all_entries().count(), 0);
    }

    #[test]
    fn submit_url_is_stored_only_when_it_differs() {
        let mut db = Database::new();
        let mut create = request("https://example.com/login");
        create.submit_url = Some("https://login.example.com/session".into());
        assert!(apply_set_login(&mut db, &create));
        let entry = db.iter_all_entries().next().unwrap();
        assert_eq!(
            entry.get("KP2A_URL"),
            Some("https://login.example.com/session")
        );

        let mut same = request("https://example.com/login2");
        same.submit_url = Some("https://example.com/login2".into());
        assert!(apply_set_login(&mut db, &same));
        let entry = db
            .iter_all_entries()
            .find(|entry| entry.get(fields::URL) == Some("https://example.com/login2"))
            .unwrap();
        assert_eq!(entry.get("KP2A_URL"), None);
    }
}
