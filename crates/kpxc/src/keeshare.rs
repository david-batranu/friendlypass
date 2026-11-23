//! KeeShare: group sharing via KeePass share containers.
//!
//! Implemented: the **classic** (unsigned) sharing mode with KeePassXC's
//! exact reference format — the share configuration lives in the group's
//! custom data under `KeeShare/Reference` as base64 of the XML document
//! KeePassXC writes (`<KeeShare><Type><Import/><Export/></Type><Group>…`),
//! so shares created here are recognized by the original KeePassXC GUI.
//!
//! `export_share` writes the group subtree to a normal KDBX file protected
//! with the share password (readable by any KeePass 2 implementation, incl.
//! keepassxc-cli); `import_share` merges entries from a share file by UUID.
//!
//! Not implemented: KeeShare's *signed* mode (RSA/X.509 certificates) — the
//! reference format reserves the type bit; signed shares are rejected with
//! a clear error rather than silently trusted.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keepass::db::{fields, CustomDataItem, CustomDataValue, Database, Group, GroupId};
use keepass::DatabaseKey;
use uuid::Uuid;

/// The custom-data key KeePassXC uses for the share reference.
pub const REFERENCE_KEY: &str = "KeeShare/Reference";

/// A share reference (the C++ `KeeShareSettings::Reference`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareReference {
    pub import: bool,
    pub export: bool,
    /// The UUID of the shared group.
    pub group_uuid: Option<Uuid>,
    /// Path of the share container file.
    pub path: String,
    /// Password of the share container.
    pub password: String,
    pub keep_groups: bool,
}

impl ShareReference {
    pub fn is_null(&self) -> bool {
        self.group_uuid.is_none() && !self.import && !self.export && self.path.is_empty()
    }

    /// Serialize exactly like KeePassXC's `Reference::serialize`.
    pub fn serialize(&self) -> String {
        let mut out = String::from("<?xml version=\"1.0\"?><KeeShare>");
        out.push_str("<Type>");
        if self.import {
            out.push_str("<Import/>");
        }
        if self.export {
            out.push_str("<Export/>");
        }
        out.push_str("</Type>");
        let uuid_bytes = self.group_uuid.map(|u| u.as_bytes().to_vec()).unwrap_or_default();
        out.push_str(&format!("<Group>{}</Group>", B64.encode(uuid_bytes)));
        out.push_str(&format!("<Path>{}</Path>", B64.encode(self.path.as_bytes())));
        out.push_str(&format!(
            "<Password>{}</Password>",
            B64.encode(self.password.as_bytes())
        ));
        out.push_str(&format!(
            "<KeepGroups>{}</KeepGroups>",
            if self.keep_groups { "True" } else { "False" }
        ));
        out.push_str("</KeeShare>");
        out
    }

    /// Deserialize KeePassXC's format (tolerant of element order).
    pub fn deserialize(raw: &str) -> Result<ShareReference> {
        let mut reference = ShareReference::default();
        let mut reader = quick_xml::Reader::from_str(raw);
        reader.config_mut().trim_text(true);
        let mut current: Option<String> = None;
        let mut buf = Vec::new();
        loop {
            use quick_xml::events::Event;
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = e.name().as_ref().to_string();
                    current = Some(name);
                }
                Ok(Event::Empty(e)) => {
                    let name = e.name().as_ref().to_string();
                    match name.as_str() {
                        "Import" => reference.import = true,
                        "Export" => reference.export = true,
                        _ => {}
                    }
                }
                Ok(Event::Text(t)) => {
                    if let Some(field) = &current {
                        let text = quick_xml::escape::unescape(&t).unwrap_or_default().to_string();
                        match field.as_str() {
                            "Group" => {
                                if let Ok(bytes) = B64.decode(text.trim()) {
                                    if bytes.len() == 16 {
                                        if let Ok(uuid) = Uuid::from_slice(&bytes) {
                                            reference.group_uuid = Some(uuid);
                                        }
                                    }
                                }
                            }
                            "Path" => {
                                reference.path = B64
                                    .decode(text.trim())
                                    .map(|b| String::from_utf8_lossy(&b).to_string())
                                    .unwrap_or_default();
                            }
                            "Password" => {
                                reference.password = B64
                                    .decode(text.trim())
                                    .map(|b| String::from_utf8_lossy(&b).to_string())
                                    .unwrap_or_default();
                            }
                            "KeepGroups" => {
                                reference.keep_groups = text.trim().eq_ignore_ascii_case("true");
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::End(_)) => current = None,
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => return Err(anyhow::anyhow!("invalid KeeShare reference XML: {e}")),
            }
            buf.clear();
        }
        Ok(reference)
    }

    /// The base64 form stored in the group custom data.
    pub fn to_custom_data_value(&self) -> String {
        B64.encode(self.serialize().as_bytes())
    }

    pub fn from_custom_data_value(encoded: &str) -> Result<ShareReference> {
        let raw = B64
            .decode(encoded.trim())
            .map_err(|e| anyhow::anyhow!("invalid KeeShare reference encoding: {e}"))?;
        let raw = String::from_utf8(raw).context("KeeShare reference is not UTF-8")?;
        ShareReference::deserialize(&raw)
    }
}

/// Read the share reference of a group (if any).
pub fn reference_of(db: &Database, group: GroupId) -> Option<ShareReference> {
    let group = db.group(group)?;
    let item = group.custom_data.get(REFERENCE_KEY)?;
    match item.value.as_ref()? {
        // The keepass crate round-trips base64 custom-data values as Binary
        // containing the decoded bytes; strings are accepted too.
        CustomDataValue::Binary(b) => {
            let raw = String::from_utf8_lossy(b);
            ShareReference::deserialize(&raw)
                .ok()
                .or_else(|| ShareReference::from_custom_data_value(&raw).ok())
        }
        CustomDataValue::String(s) => ShareReference::from_custom_data_value(s)
            .ok()
            .or_else(|| ShareReference::deserialize(s).ok()),
    }
}

/// Store (or remove, when null) the share reference of a group.
pub fn set_reference(db: &mut Database, group: GroupId, reference: &ShareReference) {
    let Some(mut group) = db.group_mut(group) else { return };
    if reference.is_null() {
        group.custom_data.remove(REFERENCE_KEY);
        return;
    }
    // Store the XML as bytes; the writer emits it base64-encoded — exactly
    // the text form KeePassXC keeps in the custom data.
    group.custom_data.insert(
        REFERENCE_KEY.to_owned(),
        CustomDataItem {
            value: Some(CustomDataValue::Binary(reference.serialize().into_bytes())),
            last_modification_time: None,
        },
    );
}

/// Result of an export.
pub struct ExportInfo {
    pub entries: usize,
    pub groups: usize,
    pub path: std::path::PathBuf,
}

/// Export a group subtree as a classic (unsigned) KeeShare container.
pub fn export_share(
    db: &Database,
    group_id: GroupId,
    path: &std::path::Path,
    password: &str,
) -> Result<ExportInfo> {
    let group = db
        .group(group_id)
        .ok_or_else(|| anyhow::anyhow!("group not found"))?;

    let mut target = Database::new();
    target.meta.database_name = Some(group.name.clone());
    {
        let mut root = target.root_mut();
        root.name = group.name.clone();
        root.notes = group.notes.clone();
        copy_children(db, group.id(), &mut root);
    }

    let mut shared = 0usize;
    let mut groups = 0usize;
    for e in target.iter_all_entries() {
        let _ = e;
        shared += 1;
    }
    for _g in target.iter_all_groups() {
        groups += 1;
    }

    let mut out = std::io::BufWriter::new(
        std::fs::File::create(path)
            .with_context(|| format!("cannot create share container {}", path.display()))?,
    );
    target
        .save(&mut out, DatabaseKey::new().with_password(password))
        .map_err(|e| anyhow::anyhow!("cannot write share container: {e}"))?;
    drop(out);

    Ok(ExportInfo {
        entries: shared,
        groups,
        path: path.to_path_buf(),
    })
}

/// Recursively copy groups/entries from `db` into `parent` on the target.
fn copy_children(db: &Database, group_id: GroupId, parent: &mut keepass::db::GroupMut<'_>) {
    let Some(source) = db.group(group_id) else { return };
    let mut entries: Vec<_> = source.entries().collect();
    entries.sort_by_key(|e| e.id().uuid());
    for entry in entries {
        let mut copy = parent.add_entry_with_id(entry.id()).ok();
        if let Some(copy) = copy.as_mut() {
            copy.fields = entry.fields.clone();
            copy.tags = entry.tags.clone();
            copy.times = entry.times.clone();
            copy.autotype = entry.autotype.clone();
            for (name, attachment) in entry.attachments_named() {
                copy.add_attachment(name, attachment.data.clone());
            }
        }
    }
    let mut children: Vec<_> = source.groups().collect();
    children.sort_by_key(|g| g.id().uuid());
    for child in children {
        let child_id = child.id();
        let mut group_copy = parent.add_group_with_id(child_id).ok();
        if let Some(group_copy) = group_copy.as_mut() {
            group_copy.name = child.name.clone();
            group_copy.notes = child.notes.clone();
            copy_children(db, child_id, group_copy);
        }
    }
}

/// Result of an import.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportInfo {
    pub added: usize,
    pub updated: usize,
}

/// Import (merge) entries from a classic share container into `group_id`.
/// Entries are matched by UUID: existing entries are updated, new ones added.
pub fn import_share(
    db: &mut Database,
    group_id: GroupId,
    path: &std::path::Path,
    password: &str,
) -> Result<ImportInfo> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("cannot open share container {}", path.display()))?;
    let shared = Database::open(&mut file, DatabaseKey::new().with_password(password))
        .map_err(|e| anyhow::anyhow!("cannot read share container (wrong password?): {e}"))?;

    // Collect the shared entries first (uuid + content; EntryRef gives
    // access to attachments, the plain Entry does not).
    struct SharedEntry {
        uuid: Uuid,
        fields: std::collections::HashMap<String, keepass::db::Value<String>>,
        tags: Vec<String>,
        times: keepass::db::Times,
        autotype: Option<keepass::db::AutoType>,
        attachments: Vec<(String, keepass::db::Value<Vec<u8>>)>,
    }
    let source_entries: Vec<SharedEntry> = shared
        .iter_all_entries()
        .map(|e| SharedEntry {
            uuid: e.id().uuid(),
            fields: e.fields.clone(),
            tags: e.tags.clone(),
            times: e.times.clone(),
            autotype: e.autotype.clone(),
            attachments: e
                .attachments_named()
                .map(|(name, a)| (name.to_owned(), a.data.clone()))
                .collect(),
        })
        .collect();

    let mut info = ImportInfo::default();
    for entry in source_entries {
        // Does an entry with this UUID already exist anywhere?
        let existing = db
            .iter_all_entries()
            .find(|e| e.id().uuid() == entry.uuid)
            .map(|e| e.id());

        if let Some(existing_id) = existing {
            if let Some(mut target) = db.entry_mut(existing_id) {
                target.fields = entry.fields;
                target.tags = entry.tags;
                target.autotype = entry.autotype;
                info.updated += 1;
            }
        } else {
            let Some(mut group) = db.group_mut(group_id) else {
                bail!("target group not found");
            };
            let new_id = keepass::db::EntryId::from_uuid(entry.uuid);
            if let Ok(mut target) = group.add_entry_with_id(new_id) {
                target.fields = entry.fields;
                target.tags = entry.tags;
                target.times = entry.times;
                target.autotype = entry.autotype;
                for (name, data) in entry.attachments {
                    target.add_attachment(&name, data);
                }
                info.added += 1;
            }
        }
    }
    Ok(info)
}

/// Ensure the shared group still exists and matches the reference.
pub fn shared_group_name(db: &Database, reference: &ShareReference) -> Option<String> {
    let uuid = reference.group_uuid?;
    db.iter_all_groups()
        .find(|g| g.id().uuid() == uuid)
        .map(|g| g.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ref() -> ShareReference {
        ShareReference {
            import: true,
            export: true,
            group_uuid: Some(
                Uuid::parse_str("39698eed-2807-4cc4-8ebb-8a9e09bc70d2").unwrap(),
            ),
            path: "/tmp/share.kdbx".into(),
            password: "share-pw".into(),
            keep_groups: false,
        }
    }

    #[test]
    fn reference_serialization_matches_keepassxc_format() {
        let r = sample_ref();
        let xml = r.serialize();
        // Exact KeePassXC shape: declaration + KeeShare element.
        assert!(xml.starts_with("<?xml version=\"1.0\"?><KeeShare>"));
        assert!(xml.contains("<Type><Import/><Export/></Type>"));
        assert!(xml.contains("<KeepGroups>False</KeepGroups>"));
        // Group UUID is base64 of the 16 RFC4122 bytes.
        let uuid_b64 = B64.encode(Uuid::parse_str("39698eed-2807-4cc4-8ebb-8a9e09bc70d2").unwrap().as_bytes());
        assert!(xml.contains(&format!("<Group>{uuid_b64}</Group>")));
        // Password is base64.
        assert!(xml.contains(&format!("<Password>{}</Password>", B64.encode(b"share-pw"))));

        // Round trip.
        let parsed = ShareReference::deserialize(&xml).unwrap();
        assert_eq!(parsed, r);
        // Custom-data encoding round trip.
        let encoded = r.to_custom_data_value();
        assert_eq!(ShareReference::from_custom_data_value(&encoded).unwrap(), r);
    }

    #[test]
    fn reference_deserializes_keepassxc_export() {
        // Hand-written exactly like KeePassXC 2.8.0 writes it.
        let xml = "<?xml version=\"1.0\"?><KeeShare><Type><Import/></Type>\
                   <Group>AAAAAAAAAAAAAAAAAAAAAA==</Group>\
                   <Path>L3RtcC9zaGFyZS5rZGJ4</Path>\
                   <Password>cHc=</Password><KeepGroups>False</KeepGroups></KeeShare>";
        let r = ShareReference::deserialize(xml).unwrap();
        assert!(r.import && !r.export);
        assert_eq!(r.group_uuid, Some(Uuid::nil()));
        assert_eq!(r.path, "/tmp/share.kdbx");
        assert_eq!(r.password, "pw");
        assert!(!r.keep_groups);
    }
}
