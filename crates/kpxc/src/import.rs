//! Importers for KeePass 2 XML, CSV, Bitwarden JSON, 1Password 1PUX and
//! KeePass 1.x (KDB) databases.
//!
//! Importing always produces a new [`Database`] (or merges into one, for the
//! GUI wizard) with the entries converted to KeePassXC's field model.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use keepass::db::{
    fields, AutoType, DataTransferObfuscation, Database, EntryId, GroupId, Times, Value,
};
use keepass::DatabaseKey;

/// Supported import formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Xml,
    Csv,
    Bitwarden,
    ProtonPass,
    OnePux,
    Kdb,
    Kdbx,
}

impl ImportFormat {
    /// Guess from the file extension (KeePassXC's wizard does the same).
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "xml" => Some(Self::Xml),
            "csv" => Some(Self::Csv),
            "json" => Some(Self::Bitwarden),
            "1pux" => Some(Self::OnePux),
            "kdb" => Some(Self::Kdb),
            "kdbx" => Some(Self::Kdbx),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "xml" | "keepass2" => Some(Self::Xml),
            "csv" => Some(Self::Csv),
            "bitwarden" => Some(Self::Bitwarden),
            "proton" | "protonpass" | "proton-pass" => Some(Self::ProtonPass),
            "1pux" | "1password" => Some(Self::OnePux),
            "kdb" | "keepass1" => Some(Self::Kdb),
            "kdbx" | "keepass2-kdbx" => Some(Self::Kdbx),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Xml => "KeePass 2 XML",
            Self::Csv => "CSV",
            Self::Bitwarden => "Bitwarden JSON",
            Self::ProtonPass => "Proton Pass JSON",
            Self::OnePux => "1Password 1PUX",
            Self::Kdb => "KeePass 1 (KDB)",
            Self::Kdbx => "KeePass 2 (KDBX)",
        }
    }
}

/// Import a file into a new database. `password` (and optional key file) are
/// used for the encrypted formats KDB/KDBX.
pub fn import_file(path: &Path, password: Option<&str>, key_file: Option<&Path>) -> Result<Database> {
    let bytes = std::fs::read(path).with_context(|| format!("unable to read {}", path.display()))?;
    let format = ImportFormat::from_path(path).or_else(|| sniff_format(&bytes)).with_context(|| {
        format!(
            "cannot determine the import format of {} (use --format)",
            path.display()
        )
    })?;
    import_bytes(&bytes, format, password, key_file)
}

/// Import bytes in the given format.
pub fn import_bytes(
    bytes: &[u8],
    format: ImportFormat,
    password: Option<&str>,
    key_file: Option<&Path>,
) -> Result<Database> {
    match format {
        ImportFormat::Xml => import_xml(bytes),
        ImportFormat::Csv => import_csv(bytes),
        ImportFormat::Bitwarden => import_bitwarden(bytes),
        ImportFormat::ProtonPass => import_proton_pass(bytes),
        ImportFormat::OnePux => import_1pux(bytes),
        ImportFormat::Kdb => crate::kdb::import_kdb(bytes, password.unwrap_or_default()),
        ImportFormat::Kdbx => {
            let password = password.unwrap_or_default();
            let mut key = DatabaseKey::new();
            if !password.is_empty() {
                key = key.with_password(password);
            }
            if let Some(kf) = key_file {
                let mut f = std::fs::File::open(kf)
                    .with_context(|| format!("unable to open key file {}", kf.display()))?;
                key = key.with_keyfile(&mut f)?;
            }
            let mut cursor = std::io::Cursor::new(bytes);
            let db = Database::open(&mut cursor, key)
                .context("unable to open the database (wrong password or key file?)")?;
            Ok(db)
        }
    }
}

fn sniff_format(bytes: &[u8]) -> Option<ImportFormat> {
    if bytes.starts_with(&[0x03, 0xd9, 0xa2, 0x9a]) {
        return Some(ImportFormat::Kdb);
    }
    if bytes.starts_with(&[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]) {
        return Some(ImportFormat::Kdbx);
    }
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
    let trimmed = text.trim_start();
    if trimmed.starts_with("<") && trimmed.contains("KeePassFile") {
        return Some(ImportFormat::Xml);
    }
    if trimmed.starts_with('{') {
        return Some(ImportFormat::Bitwarden);
    }
    None
}

// ---------------------------------------------------------------------------
// KeePass 2 XML
// ---------------------------------------------------------------------------

struct XmlContext {
    custom_icons: HashMap<String, Vec<u8>>,
    binaries: HashMap<String, Vec<u8>>,
}

/// Import a KeePass 2 XML export (the output of `keepassxc-cli export -f xml`).
pub fn import_xml(bytes: &[u8]) -> Result<Database> {
    let text = std::str::from_utf8(bytes).context("XML import: the file is not UTF-8")?;
    let doc = roxmltree::Document::parse(text).context("XML import: invalid document")?;
    let root = doc.root_element();
    if root.tag_name().name() != "KeePassFile" {
        bail!("XML import: not a KeePass 2 XML file");
    }
    let meta = child(root, "Meta");
    let mut db = Database::new();
    if let Some(meta) = meta {
        db.meta.database_name = text_of(meta, "DatabaseName").filter(|s| !s.is_empty());
        db.meta.database_description =
            text_of(meta, "DatabaseDescription").filter(|s| !s.is_empty());
        if let Some(v) = text_of(meta, "RecycleBinEnabled") {
            db.meta.recyclebin_enabled = Some(v.eq_ignore_ascii_case("true"));
        }
        if let Some(uuid) = meta
            .children()
            .find(|n| n.has_tag_name("RecycleBinUUID"))
            .and_then(|n| parse_uuid(n.text().unwrap_or("")))
        {
            db.meta.recyclebin_uuid = Some(uuid);
        }
        let mut custom_icons = HashMap::new();
        if let Some(icons) = child(meta, "CustomIcons") {
            for icon in icons.children().filter(|n| n.has_tag_name("Icon")) {
                if let (Some(uuid), Some(data)) = (text_of(icon, "UUID"), text_of(icon, "Data")) {
                    if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(data.trim()) {
                        custom_icons.insert(uuid, data);
                    }
                }
            }
        }
        let mut binaries = HashMap::new();
        if let Some(bins) = child(meta, "Binaries") {
            for bin in bins.children().filter(|n| n.has_tag_name("Binary")) {
                let Some(id) = bin.attribute("ID") else { continue };
                let Some(encoded) = bin.text() else { continue };
                let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
                    continue;
                };
                let data = if bin
                    .attribute("Compressed")
                    .is_some_and(|v| v.eq_ignore_ascii_case("true"))
                {
                    let mut out = Vec::new();
                    if flate2::read::GzDecoder::new(std::io::Cursor::new(raw))
                        .read_to_end(&mut out)
                        .is_ok()
                    {
                        out
                    } else {
                        continue;
                    }
                } else {
                    raw
                };
                binaries.insert(id.to_owned(), data);
            }
        }
        let ctx = XmlContext {
            custom_icons,
            binaries,
        };
        let root_group = child(root, "Root")
            .and_then(|r| child(r, "Group"))
            .context("XML import: no root group")?;
        let root_id = db.root().id();
        // The XML's root <Group> *is* the database's root group (KeePassXC's
        // importer does the same), not a new child called "Passwords".
        import_xml_root(&mut db, root_group, &ctx)?;
        for child_group in root_group.children().filter(|n| n.has_tag_name("Group")) {
            import_xml_group(&mut db, root_id, child_group, &ctx)?;
        }
    }
    Ok(db)
}

/// Apply the XML root group's own fields to the database root, then import
/// its entries (child groups are handled by the caller).
fn import_xml_root(
    db: &mut Database,
    node: roxmltree::Node<'_, '_>,
    ctx: &XmlContext,
) -> Result<()> {
    let name = text_of(node, "Name").unwrap_or_default();
    let notes = text_of(node, "Notes").unwrap_or_default();
    let tags = text_of(node, "Tags").unwrap_or_default();
    let is_expanded = text_of(node, "IsExpanded")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let times = parse_times(node);
    let icon_id = text_of(node, "IconID").and_then(|s| s.parse::<usize>().ok());
    let custom_icon = text_of(node, "CustomIconUUID").and_then(|s| ctx.custom_icons.get(&s).cloned());
    {
        let mut root = db.root_mut();
        root.name = name;
        root.notes = if notes.is_empty() { None } else { Some(notes) };
        root.tags = split_tags(&tags);
        root.times = times;
        root.is_expanded = is_expanded;
        match icon_id {
            Some(id) => root.set_icon_builtin(id),
            None => {
                if let Some(data) = custom_icon {
                    root.set_icon_custom_new(data);
                }
            }
        }
    }
    let root_id = db.root().id();
    for entry in node.children().filter(|n| n.has_tag_name("Entry")) {
        import_xml_entry(db, root_id, entry, ctx)?;
    }
    Ok(())
}

fn import_xml_group(
    db: &mut Database,
    parent: GroupId,
    node: roxmltree::Node<'_, '_>,
    ctx: &XmlContext,
) -> Result<GroupId> {
    let gid = text_of(node, "UUID")
        .and_then(|s| parse_uuid(&s))
        .map(GroupId::from_uuid)
        .unwrap_or_else(GroupId::new);
    let name = text_of(node, "Name").unwrap_or_default();
    let notes = text_of(node, "Notes").unwrap_or_default();
    let tags = text_of(node, "Tags").unwrap_or_default();
    let is_expanded = text_of(node, "IsExpanded")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let times = parse_times(node);
    let icon_id = text_of(node, "IconID").and_then(|s| s.parse::<usize>().ok());
    let custom_icon = text_of(node, "CustomIconUUID").and_then(|s| ctx.custom_icons.get(&s).cloned());

    let duplicate = db.group(gid).is_some();
    let actual_id = {
        let mut parent_mut = db.group_mut(parent).context("XML import: parent group missing")?;
        let mut group = if duplicate {
            parent_mut.add_group()
        } else {
            parent_mut
                .add_group_with_id(gid)
                .expect("group id is not a duplicate")
        };
        group.name = name;
        group.notes = if notes.is_empty() { None } else { Some(notes) };
        group.tags = split_tags(&tags);
        group.times = times;
        group.is_expanded = is_expanded;
        match icon_id {
            Some(id) => group.set_icon_builtin(id),
            None => {
                if let Some(data) = custom_icon {
                    group.set_icon_custom_new(data);
                }
            }
        }
        group.id()
    };

    for entry in node.children().filter(|n| n.has_tag_name("Entry")) {
        import_xml_entry(db, actual_id, entry, ctx)?;
    }
    for child_group in node.children().filter(|n| n.has_tag_name("Group")) {
        import_xml_group(db, actual_id, child_group, ctx)?;
    }
    Ok(actual_id)
}

fn import_xml_entry(
    db: &mut Database,
    group: GroupId,
    node: roxmltree::Node<'_, '_>,
    ctx: &XmlContext,
) -> Result<()> {
    let eid = text_of(node, "UUID")
        .and_then(|s| parse_uuid(&s))
        .map(EntryId::from_uuid)
        .unwrap_or_else(EntryId::new);
    let times = parse_times(node);
    let tags = split_tags(&text_of(node, "Tags").unwrap_or_default());
    let icon_id = text_of(node, "IconID").and_then(|s| s.parse::<usize>().ok());
    let custom_icon = text_of(node, "CustomIconUUID").and_then(|s| ctx.custom_icons.get(&s).cloned());

    let mut fields_map: HashMap<String, Value<String>> = HashMap::new();
    let mut binaries: Vec<(String, Vec<u8>)> = Vec::new();
    for s in node.children().filter(|n| n.has_tag_name("String")) {
        let Some(key) = text_of(s, "Key") else { continue };
        let value_node = child(s, "Value");
        let protected = value_node
            .and_then(|v| v.attribute("ProtectInMemory"))
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let value = value_node.and_then(|v| v.text()).unwrap_or("");
        let value = if protected {
            Value::protected(value.to_owned())
        } else {
            Value::unprotected(value.to_owned())
        };
        fields_map.insert(key, value);
    }
    for b in node.children().filter(|n| n.has_tag_name("Binary")) {
        let Some(name) = text_of(b, "Key") else { continue };
        let Some(value) = child(b, "Value") else { continue };
        if let Some(id) = value.attribute("Ref") {
            if let Some(data) = ctx.binaries.get(id) {
                binaries.push((name, data.clone()));
            }
        } else if let Some(encoded) = value.text() {
            if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
                binaries.push((name, data));
            }
        }
    }
    let autotype = child(node, "AutoType").map(|a| AutoType {
        enabled: text_of(a, "Enabled")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true),
        default_sequence: text_of(a, "DefaultSequence").filter(|s| !s.is_empty()),
        data_transfer_obfuscation: match text_of(a, "DataTransferObfuscation").as_deref() {
            Some("1") => DataTransferObfuscation::UseClipboard,
            _ => DataTransferObfuscation::None,
        },
        associations: a
            .children()
            .filter(|n| n.has_tag_name("Association"))
            .filter_map(|assoc| {
                Some(keepass::db::AutoTypeAssociation {
                    window: text_of(assoc, "Window")?,
                    sequence: text_of(assoc, "KeystrokeSequence").unwrap_or_default(),
                })
            })
            .collect(),
    });

    let duplicate = db.entry(eid).is_some();
    let mut parent = db.group_mut(group).context("XML import: parent group missing")?;
    let mut entry = if duplicate {
        parent.add_entry()
    } else {
        parent
            .add_entry_with_id(eid)
            .expect("entry id is not a duplicate")
    };
    entry.fields = fields_map;
    entry.tags = tags;
    entry.times = times;
    entry.autotype = autotype;
    match icon_id {
        Some(id) => entry.set_icon_builtin(id),
        None => {
            if let Some(data) = custom_icon {
                entry.set_icon_custom_new(data);
            }
        }
    }
    for (name, data) in binaries {
        entry.add_attachment(name, Value::<Vec<u8>>::unprotected(data));
    }
    Ok(())
}

fn parse_times(node: roxmltree::Node<'_, '_>) -> Times {
    let Some(t) = child(node, "Times") else {
        return Times::new();
    };
    let time = |name: &str| {
        text_of(t, name)
            .and_then(|s| chrono::NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%dT%H:%M:%SZ").ok())
    };
    let mut times = Times::new();
    times.creation = time("CreationTime");
    times.last_modification = time("LastModificationTime");
    times.last_access = time("LastAccessTime");
    if let Some(expiry) = time("ExpiryTime") {
        times.expiry = expiry;
    }
    times.location_changed = time("LocationChanged");
    times.expires = text_of(t, "Expires").map(|v| v.eq_ignore_ascii_case("true"));
    times.usage_count = text_of(t, "UsageCount").and_then(|s| s.parse().ok());
    times
}

fn split_tags(tags: &str) -> Vec<String> {
    tags.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_uuid(text: &str) -> Option<uuid::Uuid> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()?;
    uuid::Uuid::from_slice(&raw).ok()
}

fn child<'a, 'b>(node: roxmltree::Node<'a, 'b>, name: &str) -> Option<roxmltree::Node<'a, 'b>> {
    node.children().find(|n| n.is_element() && n.tag_name().name() == name)
}

fn text_of(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    child(node, name).and_then(|n| n.text()).map(str::to_owned)
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// Import CSV, auto-detecting KeePassXC's own export header and common
/// alternatives (LastPass/Bitwarden/Chrome exports).
pub fn import_csv(bytes: &[u8]) -> Result<Database> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(bytes);
    let headers = reader.headers()?.clone();
    let index = |names: &[&str]| -> Option<usize> {
        headers.iter().position(|h| {
            let key = h.trim().to_ascii_lowercase().replace([' ', '_'], "");
            names.iter().any(|n| key == *n)
        })
    };
    let col_group = index(&["group", "grouppath", "folder", "groupname"]);
    let col_title = index(&["title", "name", "account", "site"]);
    let col_username = index(&["username", "login", "user"]);
    let col_password = index(&["password"]);
    let col_url = index(&["url", "website", "loginurl"]);
    let col_notes = index(&["notes", "note", "comments", "comment", "extra"]);
    let col_totp = index(&["totp", "otp"]);
    let col_icon = index(&["icon", "iconid"]);
    let col_modified = index(&["lastmodified", "modified"]);
    let col_created = index(&["created", "creationtime", "createdat"]);
    if col_title.is_none() && col_password.is_none() {
        bail!("CSV import: no Title or Password column found (header: {headers:?})");
    }

    let mut db = Database::new();
    db.meta.database_name = Some("Imported CSV".into());
    let known = [
        col_group,
        col_title,
        col_username,
        col_password,
        col_url,
        col_notes,
        col_totp,
        col_icon,
        col_modified,
        col_created,
    ];
    let value = |record: &csv::StringRecord, col: Option<usize>| -> String {
        col.and_then(|i| record.get(i)).unwrap_or_default().trim().to_owned()
    };

    let mut first_row = true;
    for record in reader.records() {
        let record = record?;
        // KeePassXC's CSV export includes the source root group in the Group
        // column ("Passwords/Sample Entry"). Treat that first segment as the
        // new database's root, as KeePassXC's own import does.
        if first_row {
            first_row = false;
            if let Some(root_name) = value(&record, col_group)
                .split('/')
                .map(str::trim)
                .find(|s| !s.is_empty())
            {
                db.root_mut().name = root_name.to_owned();
            }
        }
        let group = if value(&record, col_group).is_empty() {
            db.root().id()
        } else {
            ensure_group_path(&mut db, &value(&record, col_group))
        };
        let mut group_mut = db.group_mut(group).context("CSV import: group missing")?;
        let mut entry = group_mut.add_entry();
        let title = value(&record, col_title);
        let username = value(&record, col_username);
        let password = value(&record, col_password);
        let url = value(&record, col_url);
        let notes = value(&record, col_notes);
        entry.set_unprotected(fields::TITLE, title.clone());
        entry.set_unprotected(fields::USERNAME, username.clone());
        entry.set_protected(fields::PASSWORD, password.clone());
        entry.set_unprotected(fields::URL, url.clone());
        entry.set_unprotected(fields::NOTES, notes.clone());
        let totp = value(&record, col_totp);
        if !totp.is_empty() {
            entry.set_unprotected(fields::OTP, totp);
        }
        if let Ok(icon) = value(&record, col_icon).parse::<usize>() {
            entry.set_icon_builtin(icon);
        }
        if let Some(t) = parse_iso_time(&value(&record, col_modified)) {
            entry.times.last_modification = Some(t);
        }
        if let Some(t) = parse_iso_time(&value(&record, col_created)) {
            entry.times.creation = Some(t);
        }
        // Unmapped columns become custom attributes (LastPass "extra", etc.).
        for (i, header) in headers.iter().enumerate() {
            if known.contains(&Some(i)) {
                continue;
            }
            let text = record.get(i).unwrap_or_default().trim();
            if !text.is_empty() && !header.trim().is_empty() {
                entry.set_unprotected(header.trim(), text);
            }
        }
    }
    Ok(db)
}

fn parse_iso_time(s: &str) -> Option<chrono::NaiveDateTime> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ] {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(t, fmt) {
            return Some(t);
        }
        if let Ok(d) = chrono::NaiveDate::parse_from_str(t, fmt) {
            return d.and_hms_opt(0, 0, 0);
        }
    }
    None
}

fn ensure_group_path(db: &mut Database, path: &str) -> GroupId {
    let root_id = db.root().id();
    let root_name = db.root().name.clone();
    let mut parent = root_id;
    for (i, segment) in path.split('/').map(str::trim).filter(|s| !s.is_empty()).enumerate() {
        if i == 0 && segment == root_name {
            continue;
        }
        let existing = db
            .group(parent)
            .and_then(|g| g.groups().find(|child| child.name == segment).map(|g| g.id()));
        parent = match existing {
            Some(id) => id,
            None => {
                let Some(mut group) = db.group_mut(parent) else {
                    break;
                };
                let mut child = group.add_group();
                child.name = segment.to_owned();
                child.id()
            }
        };
    }
    parent
}

// ---------------------------------------------------------------------------
// Bitwarden JSON
// ---------------------------------------------------------------------------

/// Import an unencrypted Bitwarden JSON export.
pub fn import_bitwarden(bytes: &[u8]) -> Result<Database> {
    let json: serde_json::Value =
        serde_json::from_slice(bytes).context("Bitwarden import: invalid JSON")?;
    if json.get("vaults").is_some() {
        return import_proton_pass(bytes);
    }
    if json
        .get("encrypted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        bail!("Bitwarden import: encrypted exports are not supported — export an unencrypted JSON");
    }
    let mut db = Database::new();
    db.meta.database_name = Some("Imported Bitwarden".into());
    let mut folders = HashMap::new();
    if let Some(items) = json.get("folders").and_then(|v| v.as_array()) {
        for folder in items {
            if let (Some(id), Some(name)) = (
                folder.get("id").and_then(|v| v.as_str()),
                folder.get("name").and_then(|v| v.as_str()),
            ) {
                let gid = ensure_group_path(&mut db, name);
                folders.insert(id.to_owned(), gid);
            }
        }
    }
    let mut count = 0usize;
    if let Some(items) = json.get("items").and_then(|v| v.as_array()) {
        for item in items {
            let kind = item.get("type").and_then(|v| v.as_u64()).unwrap_or(1);
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let notes = item.get("notes").and_then(|v| v.as_str()).unwrap_or("");
            let folder_id = item.get("folderId").and_then(|v| v.as_str());
            let group = folder_id
                .and_then(|id| folders.get(id).copied())
                .unwrap_or_else(|| db.root().id());
            let Some(mut group_mut) = db.group_mut(group) else {
                continue;
            };
            let mut entry = group_mut.add_entry();
            entry.set_unprotected(fields::TITLE, name);
            entry.set_unprotected(fields::NOTES, notes);
            if let Some(login) = item.get("login") {
                if kind == 1 {
                    entry.set_unprotected(
                        fields::USERNAME,
                        login.get("username").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    entry.set_protected(
                        fields::PASSWORD,
                        login.get("password").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    if let Some(uri) = login
                        .get("uris")
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                    {
                        entry.set_unprotected(
                            fields::URL,
                            uri.get("uri").and_then(|v| v.as_str()).unwrap_or(""),
                        );
                    }
                    let totp = login.get("totp").and_then(|v| v.as_str()).unwrap_or("");
                    if !totp.is_empty() {
                        entry.set_unprotected(fields::OTP, totp);
                    }
                }
            }
            if let Some(custom) = item.get("fields").and_then(|v| v.as_array()) {
                for field in custom {
                    let Some(key) = field.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let val = field.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    if key.is_empty() || fields::KNOWN_FIELDS.contains(&key) {
                        continue;
                    }
                    let hidden = field.get("type").and_then(|v| v.as_u64()) == Some(1);
                    if hidden {
                        entry.set_protected(key, val);
                    } else {
                        entry.set_unprotected(key, val);
                    }
                }
            }
            count += 1;
        }
    }
    if count == 0 {
        bail!("Bitwarden import: the export contains no items");
    }
    Ok(db)
}

// ---------------------------------------------------------------------------
// Proton Pass JSON
// ---------------------------------------------------------------------------

/// Import a Proton Pass JSON export (unencrypted).
pub fn import_proton_pass(bytes: &[u8]) -> Result<Database> {
    let json: serde_json::Value =
        serde_json::from_slice(bytes).context("Proton Pass import: invalid JSON")?;
    if json
        .get("encrypted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        bail!("Proton Pass import: encrypted exports are not supported");
    }
    let vaults = json
        .get("vaults")
        .and_then(|v| v.as_object())
        .context("Proton Pass import: no vaults in the export")?;
    let mut db = Database::new();
    db.meta.database_name = Some("Proton Pass Import".into());
    let mut count = 0usize;
    for vault in vaults.values() {
        let name = vault.get("name").and_then(|v| v.as_str()).unwrap_or("Proton Pass");
        let description = vault.get("description").and_then(|v| v.as_str()).unwrap_or("");
        let group = ensure_group_path(&mut db, name);
        if !description.is_empty() {
            if let Some(mut g) = db.group_mut(group) {
                g.notes = Some(description.to_owned());
            }
        }
        let items = vault
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for item in items {
            let data = item.get("data").cloned().unwrap_or_default();
            let metadata = data.get("metadata").cloned().unwrap_or_default();
            let title = metadata.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let notes = metadata.get("note").and_then(|v| v.as_str()).unwrap_or("");
            let Some(mut group_mut) = db.group_mut(group) else {
                continue;
            };
            let mut entry = group_mut.add_entry();
            entry.set_unprotected(fields::TITLE, title);
            entry.set_unprotected(fields::NOTES, notes);
            let item_type = data
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let content = data.get("content").cloned().unwrap_or_default();
            match item_type.as_str() {
                "login" => {
                    let username = content
                        .get("itemUsername")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let email = content.get("itemEmail").and_then(|v| v.as_str()).unwrap_or("");
                    entry.set_unprotected(
                        fields::USERNAME,
                        if username.is_empty() { email } else { username },
                    );
                    entry.set_protected(
                        fields::PASSWORD,
                        content.get("password").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    if let Some(urls) = content.get("urls").and_then(|v| v.as_array()) {
                        if let Some(url) = urls.first().and_then(|v| v.as_str()) {
                            entry.set_unprotected(fields::URL, url);
                        }
                        for (i, url) in urls.iter().skip(1).filter_map(|v| v.as_str()).enumerate() {
                            entry.set_unprotected(format!("KP2A_URL_{}", i + 2), url);
                        }
                    }
                    let totp = content.get("totpUri").and_then(|v| v.as_str()).unwrap_or("");
                    if !totp.is_empty() {
                        let totp = if totp.starts_with("otpauth://") {
                            totp.to_owned()
                        } else {
                            format!(
                                "otpauth://totp/{}:{}?secret={}",
                                urlencoding(title),
                                urlencoding(
                                    content
                                        .get("itemUsername")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                ),
                                urlencoding(totp)
                            )
                        };
                        entry.set_unprotected(fields::OTP, totp);
                    }
                }
                "creditcard" => {
                    entry.set_unprotected(
                        fields::USERNAME,
                        content.get("number").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    entry.set_protected(
                        fields::PASSWORD,
                        content
                            .get("verificationNumber")
                            .and_then(|v| v.as_str())
                            .unwrap_or(""),
                    );
                    for (key, attr) in [
                        ("cardholderName", "card_cardholderName"),
                        ("pin", "card_pin"),
                        ("expirationDate", "card_expirationDate"),
                    ] {
                        let value = content.get(key).and_then(|v| v.as_str()).unwrap_or("");
                        if !value.is_empty() {
                            if key == "pin" {
                                entry.set_protected(attr, value);
                            } else {
                                entry.set_unprotected(attr, value);
                            }
                        }
                    }
                }
                "wifi" => {
                    entry.set_unprotected(
                        fields::USERNAME,
                        content.get("ssid").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    entry.set_protected(
                        fields::PASSWORD,
                        content.get("password").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    entry.set_unprotected(
                        "wifi_security",
                        content.get("security").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
                "sshkey" => {
                    for (key, protected) in [
                        ("publicKey", false),
                        ("privateKey", true),
                    ] {
                        let value = content.get(key).and_then(|v| v.as_str()).unwrap_or("");
                        if !value.is_empty() {
                            let name = if protected {
                                "ssh_private_key"
                            } else {
                                "ssh_public_key"
                            };
                            if protected {
                                entry.set_protected(name, value);
                            } else {
                                entry.set_unprotected(name, value);
                            }
                        }
                    }
                }
                "note" | "custom" | "" => {}
                other => {
                    entry.set_unprotected(
                        fields::NOTES,
                        format!("Unknown Proton Pass item type '{other}'.\n{notes}"),
                    );
                    if let Some(map) = content.as_object() {
                        for (key, value) in map {
                            if let Some(value) = value.as_str() {
                                entry.set_unprotected(format!("content_{key}"), value);
                            }
                        }
                    }
                }
            }
            if let Some(extra) = data.get("extraFields").and_then(|v| v.as_array()) {
                for field in extra {
                    let Some(field_name) = field.get("fieldName").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let field_type = field
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let value = if field_type.eq_ignore_ascii_case("totp") {
                        field.pointer("/data/totpUri").and_then(|v| v.as_str())
                    } else {
                        field.pointer("/data/content").and_then(|v| v.as_str())
                    }
                    .unwrap_or("");
                    if field_type.eq_ignore_ascii_case("hidden") {
                        entry.set_protected(field_name, value);
                    } else {
                        entry.set_unprotected(field_name, value);
                    }
                }
            }
            count += 1;
        }
    }
    if count == 0 {
        bail!("Proton Pass import: the export contains no items");
    }
    Ok(db)
}

fn urlencoding(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1Password 1PUX
// ---------------------------------------------------------------------------

/// Import a 1Password 1PUX export (a ZIP containing `export.data`).
pub fn import_1pux(bytes: &[u8]) -> Result<Database> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("1PUX import: invalid ZIP")?;
    let mut data = None;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.name().ends_with("export.data") {
            let mut text = String::new();
            file.read_to_string(&mut text)?;
            data = Some(text);
            break;
        }
    }
    let text = data.context("1PUX import: export.data not found in the ZIP")?;
    let json: serde_json::Value =
        serde_json::from_str(&text).context("1PUX import: invalid export.data")?;

    let mut db = Database::new();
    db.meta.database_name = Some("Imported 1Password".into());
    let mut count = 0usize;
    let accounts = json
        .pointer("/data/accounts")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for account in accounts {
        let vaults = account
            .get("vaults")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for vault in vaults {
            let vault_name = vault
                .pointer("/attrs/name")
                .and_then(|v| v.as_str())
                .unwrap_or("1Password");
            let group = ensure_group_path(&mut db, vault_name);
            let items = vault
                .get("items")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for item in items {
                let title = item
                    .pointer("/overview/title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let notes = item
                    .pointer("/details/notesPlain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let Some(mut group_mut) = db.group_mut(group) else {
                    continue;
                };
                let mut entry = group_mut.add_entry();
                entry.set_unprotected(fields::TITLE, title);
                entry.set_unprotected(fields::NOTES, notes);
                if let Some(url) = item
                    .pointer("/overview/urls/0/url")
                    .and_then(|v| v.as_str())
                {
                    entry.set_unprotected(fields::URL, url);
                }
                if let Some(login_fields) = item
                    .pointer("/details/loginFields")
                    .and_then(|v| v.as_array())
                {
                    for field in login_fields {
                        let designation = field
                            .get("designation")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let value = field.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        match designation {
                            "username" => entry.set_unprotected(fields::USERNAME, value),
                            "password" => entry.set_protected(fields::PASSWORD, value),
                            _ => {}
                        }
                    }
                }
                if let Some(sections) = item
                    .pointer("/details/sections")
                    .and_then(|v| v.as_array())
                {
                    for section in sections {
                        let Some(section_name) =
                            section.pointer("/title").and_then(|v| v.as_str())
                        else {
                            continue;
                        };
                        for field in section
                            .get("fields")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default()
                        {
                            let Some(name) = field.pointer("/title").and_then(|v| v.as_str())
                            else {
                                continue;
                            };
                            let Some(value) = field.get("value").and_then(|v| v.as_str()) else {
                                continue;
                            };
                            let key = format!("{section_name}/{name}");
                            if !fields::KNOWN_FIELDS.contains(&key.as_str()) {
                                entry.set_unprotected(key, value);
                            }
                        }
                    }
                }
                count += 1;
            }
        }
    }
    if count == 0 {
        bail!("1PUX import: no login items found");
    }
    Ok(db)
}

/// Merge `source` into `target` under `parent`, regenerating UUIDs (the
/// import-wizard behavior). Returns the number of imported entries.
pub fn merge_into(target: &mut Database, source: &Database, parent: GroupId) -> usize {
    fn copy_group(
        target: &mut Database,
        source: &Database,
        source_group: &keepass::db::GroupRef<'_>,
        parent: GroupId,
    ) -> usize {
        let mut count = 0;
        let new_id = {
            let Some(mut target_group) = target.group_mut(parent) else {
                return 0;
            };
            let mut group = target_group.add_group();
            group.name = source_group.name.clone();
            group.notes = source_group.notes.clone();
            group.tags = source_group.tags.clone();
            group.times = source_group.times.clone();
            group.is_expanded = source_group.is_expanded;
            group.id()
        };
        for entry in source_group.entries() {
            let Some(mut target_group) = target.group_mut(new_id) else {
                break;
            };
            let mut e = target_group.add_entry();
            e.fields = entry.fields.clone();
            e.tags = entry.tags.clone();
            e.times = entry.times.clone();
            e.autotype = entry.autotype.clone();
            if let Some(keepass::db::Icon::BuiltIn(n)) = entry.icon() {
                e.set_icon_builtin(*n);
            }
            for (name, attachment) in entry.attachments_named() {
                e.add_attachment(
                    name.to_owned(),
                    Value::<Vec<u8>>::unprotected(attachment.data.get().clone()),
                );
            }
            count += 1;
        }
        for child in source_group.groups() {
            count += copy_group(target, source, &child, new_id);
        }
        count
    }

    // The root group's name is not copied; its children are.
    let source_root = source.root();
    let mut count = 0;
    for entry in source_root.entries() {
        let Some(mut target_group) = target.group_mut(parent) else {
            break;
        };
        let mut e = target_group.add_entry();
        e.fields = entry.fields.clone();
        e.tags = entry.tags.clone();
        e.times = entry.times.clone();
        e.autotype = entry.autotype.clone();
        for (name, attachment) in entry.attachments_named() {
            e.add_attachment(
                name.to_owned(),
                Value::<Vec<u8>>::unprotected(attachment.data.get().clone()),
            );
        }
        count += 1;
    }
    for group in source_root.groups() {
        count += copy_group(target, source, &group, parent);
    }
    count
}
