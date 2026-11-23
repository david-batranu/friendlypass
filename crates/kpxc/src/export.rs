//! Plain-text export formats, compatible with `keepassxc-cli export`:
//! KeePass 2 XML (the format `keepassxc-cli import` accepts), CSV and HTML.
//!
//! Exports are unencrypted by definition; callers must warn the user.

use std::collections::BTreeMap;

use base64::Engine;
use keepass::db::{fields, Database, Entry, GroupRef, Icon, Times, Value};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

use anyhow::Result;

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------

/// Export the database as KeePass 2 XML (unencrypted), the format emitted by
/// `keepassxc-cli export -f xml` and read by `keepassxc-cli import`.
pub fn export_xml(db: &Database) -> Result<String> {
    let mut w = Writer::new_with_indent(Vec::new(), b'\t', 1);
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), Some("yes"))))?;

    start(&mut w, "KeePassFile")?;
    write_meta(&mut w, db)?;
    start(&mut w, "Root")?;
    write_group(&mut w, db, &db.root())?;
    end(&mut w, "Root")?;
    end(&mut w, "KeePassFile")?;

    Ok(String::from_utf8(w.into_inner())?)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn iso(t: chrono::NaiveDateTime) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn opt_iso(t: Option<chrono::NaiveDateTime>) -> String {
    iso(t.unwrap_or_else(Times::epoch))
}

fn start<W: std::io::Write>(w: &mut Writer<W>, name: &str) -> Result<()> {
    w.write_event(Event::Start(BytesStart::new(name)))?;
    Ok(())
}

fn end<W: std::io::Write>(w: &mut Writer<W>, name: &str) -> Result<()> {
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn text<W: std::io::Write>(w: &mut Writer<W>, name: &str, value: &str) -> Result<()> {
    start(w, name)?;
    w.write_event(Event::Text(BytesText::new(value)))?;
    end(w, name)?;
    Ok(())
}

fn bool_text<W: std::io::Write>(w: &mut Writer<W>, name: &str, value: bool) -> Result<()> {
    text(w, name, if value { "True" } else { "False" })
}

fn uuid_text<W: std::io::Write>(w: &mut Writer<W>, name: &str, uuid: uuid::Uuid) -> Result<()> {
    text(w, name, &b64(uuid.as_bytes()))
}

fn write_meta<W: std::io::Write>(w: &mut Writer<W>, db: &Database) -> Result<()> {
    let meta = &db.meta;
    start(w, "Meta")?;
    text(w, "Generator", meta.generator.as_deref().unwrap_or("KeePassXC-RS"))?;
    text(w, "DatabaseName", meta.database_name.as_deref().unwrap_or(""))?;
    text(
        w,
        "DatabaseNameChanged",
        &opt_iso(meta.database_name_changed),
    )?;
    text(
        w,
        "DatabaseDescription",
        meta.database_description.as_deref().unwrap_or(""),
    )?;
    text(
        w,
        "DatabaseDescriptionChanged",
        &opt_iso(meta.database_description_changed),
    )?;
    text(w, "DefaultUserName", meta.default_username.as_deref().unwrap_or(""))?;
    text(
        w,
        "DefaultUserNameChanged",
        &opt_iso(meta.default_username_changed),
    )?;
    text(
        w,
        "MaintenanceHistoryDays",
        &meta.maintenance_history_days.unwrap_or(365).to_string(),
    )?;
    text(w, "Color", "")?;
    text(w, "MasterKeyChanged", &opt_iso(meta.master_key_changed))?;
    text(
        w,
        "MasterKeyChangeRec",
        &meta.master_key_change_rec.unwrap_or(-1).to_string(),
    )?;
    text(
        w,
        "MasterKeyChangeForce",
        &meta.master_key_change_force.unwrap_or(-1).to_string(),
    )?;

    let mp = meta.memory_protection.clone().unwrap_or_default();
    start(w, "MemoryProtection")?;
    bool_text(w, "ProtectTitle", mp.protect_title)?;
    bool_text(w, "ProtectUserName", mp.protect_username)?;
    bool_text(w, "ProtectPassword", mp.protect_password)?;
    bool_text(w, "ProtectURL", mp.protect_url)?;
    bool_text(w, "ProtectNotes", mp.protect_notes)?;
    end(w, "MemoryProtection")?;

    // Custom icons (referenced by UUID from entries/groups).
    start(w, "CustomIcons")?;
    for icon in db.iter_all_custom_icons() {
        start(w, "Icon")?;
        uuid_text(w, "UUID", icon.id().uuid())?;
        text(w, "Data", &b64(&icon.data))?;
        end(w, "Icon")?;
    }
    end(w, "CustomIcons")?;

    bool_text(w, "RecycleBinEnabled", meta.recyclebin_enabled.unwrap_or(true))?;
    uuid_text(
        w,
        "RecycleBinUUID",
        meta.recyclebin_uuid.unwrap_or(uuid::Uuid::nil()),
    )?;
    text(w, "RecycleBinChanged", &opt_iso(meta.recyclebin_changed))?;
    uuid_text(
        w,
        "EntryTemplatesGroup",
        meta.entry_templates_group.unwrap_or(uuid::Uuid::nil()),
    )?;
    text(
        w,
        "EntryTemplatesGroupChanged",
        &opt_iso(meta.entry_templates_group_changed),
    )?;
    uuid_text(
        w,
        "LastSelectedGroup",
        meta.last_selected_group.unwrap_or(uuid::Uuid::nil()),
    )?;
    uuid_text(
        w,
        "LastTopVisibleGroup",
        meta.last_top_visible_group.unwrap_or(uuid::Uuid::nil()),
    )?;
    text(
        w,
        "HistoryMaxItems",
        &meta.history_max_items.unwrap_or(10).to_string(),
    )?;
    text(
        w,
        "HistoryMaxSize",
        &meta.history_max_size.unwrap_or(6_291_456).to_string(),
    )?;

    // Attachments referenced from entries (KDBX 4 style binaries).
    let mut binaries: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    for entry in db.iter_all_entries() {
        for (_name, attachment) in entry.attachments_named() {
            binaries
                .entry(attachment.id().id())
                .or_insert_with(|| attachment.data.get().clone());
        }
    }
    start(w, "Binaries")?;
    for (id, data) in &binaries {
        let mut start = BytesStart::new("Binary");
        start.push_attribute(("ID", id.to_string().as_str()));
        start.push_attribute(("Compressed", "False"));
        w.write_event(Event::Start(start))?;
        w.write_event(Event::Text(BytesText::new(&b64(data))))?;
        end(w, "Binary")?;
    }
    end(w, "Binaries")?;

    if !meta.custom_data.is_empty() {
        start(w, "CustomData")?;
        for (key, item) in &meta.custom_data {
            start(w, "Item")?;
            text(w, "Key", key)?;
            if let Some(keepass::db::CustomDataValue::String(value)) = &item.value {
                text(w, "Value", value)?;
            }
            end(w, "Item")?;
        }
        end(w, "CustomData")?;
    }

    end(w, "Meta")?;
    Ok(())
}

fn write_group<W: std::io::Write>(w: &mut Writer<W>, db: &Database, group: &GroupRef<'_>) -> Result<()> {
    start(w, "Group")?;
    uuid_text(w, "UUID", group.id().uuid())?;
    text(w, "Name", &group.name)?;
    text(w, "Notes", group.notes.as_deref().unwrap_or(""))?;
    write_icon(w, db, group.icon())?;
    text(w, "Tags", &group.tags.join(","))?;
    write_times(w, &group.times)?;
    bool_text(w, "IsExpanded", group.is_expanded)?;
    text(
        w,
        "DefaultAutoTypeSequence",
        group.default_autotype_sequence.as_deref().unwrap_or(""),
    )?;
    match group.enable_autotype {
        Some(v) => bool_text(w, "EnableAutoType", v)?,
        None => text(w, "EnableAutoType", "null")?,
    }
    match group.enable_searching {
        Some(v) => bool_text(w, "EnableSearching", v)?,
        None => text(w, "EnableSearching", "null")?,
    }
    uuid_text(w, "LastTopVisibleEntry", uuid::Uuid::nil())?;

    for entry in group.entries() {
        let attachments: Vec<(String, usize)> = entry
            .attachments_named()
            .map(|(name, attachment)| (name.to_owned(), attachment.id().id()))
            .collect();
        write_entry(w, &entry, &attachments, true)?;
    }
    for child in group.groups() {
        write_group(w, db, &child)?;
    }

    end(w, "Group")?;
    Ok(())
}

fn write_icon<W: std::io::Write>(w: &mut Writer<W>, db: &Database, icon: Option<&Icon>) -> Result<()> {
    match icon {
        Some(Icon::BuiltIn(n)) => text(w, "IconID", &n.to_string()),
        Some(Icon::Custom(id)) => match db.custom_icon(*id) {
            Some(ci) => uuid_text(w, "CustomIconUUID", ci.id().uuid()),
            None => text(w, "IconID", "0"),
        },
        None => text(w, "IconID", "0"),
    }
}

fn write_times<W: std::io::Write>(w: &mut Writer<W>, times: &Times) -> Result<()> {
    start(w, "Times")?;
    text(w, "LastModificationTime", &opt_iso(times.last_modification))?;
    text(w, "CreationTime", &opt_iso(times.creation))?;
    text(w, "LastAccessTime", &opt_iso(times.last_access))?;
    text(w, "ExpiryTime", &iso(times.expiry))?;
    bool_text(w, "Expires", times.expires.unwrap_or(false))?;
    text(w, "UsageCount", &times.usage_count.unwrap_or(0).to_string())?;
    text(
        w,
        "LocationChanged",
        &opt_iso(times.location_changed),
    )?;
    end(w, "Times")?;
    Ok(())
}

fn write_entry<W: std::io::Write>(
    w: &mut Writer<W>,
    entry: &Entry,
    attachments: &[(String, usize)],
    with_history: bool,
) -> Result<()> {
    start(w, "Entry")?;
    uuid_text(w, "UUID", entry.id().uuid())?;
    match entry.icon() {
        Some(Icon::BuiltIn(n)) => text(w, "IconID", &n.to_string())?,
        _ => text(w, "IconID", "0")?,
    }
    text(
        w,
        "ForegroundColor",
        &entry
            .foreground_color
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_default(),
    )?;
    text(
        w,
        "BackgroundColor",
        &entry
            .background_color
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_default(),
    )?;
    text(w, "OverrideURL", entry.override_url.as_deref().unwrap_or(""))?;
    text(w, "Tags", &entry.tags.join(","))?;
    write_times(w, &entry.times)?;

    let mut keys: Vec<&String> = entry.fields.keys().collect();
    keys.sort();
    for key in keys {
        let value = &entry.fields[key];
        start(w, "String")?;
        text(w, "Key", key)?;
        write_value(w, value)?;
        end(w, "String")?;
    }

    for (name, id) in attachments {
        start(w, "Binary")?;
        text(w, "Key", name)?;
        let mut start = BytesStart::new("Value");
        let id = id.to_string();
        start.push_attribute(("Ref", id.as_str()));
        w.write_event(Event::Empty(start))?;
        end(w, "Binary")?;
    }

    if let Some(auto) = &entry.autotype {
        start(w, "AutoType")?;
        bool_text(w, "Enabled", auto.enabled)?;
        text(
            w,
            "DataTransferObfuscation",
            match auto.data_transfer_obfuscation {
                keepass::db::DataTransferObfuscation::UseClipboard => "1",
                keepass::db::DataTransferObfuscation::None => "0",
            },
        )?;
        text(
            w,
            "DefaultSequence",
            auto.default_sequence.as_deref().unwrap_or(""),
        )?;
        for assoc in &auto.associations {
            start(w, "Association")?;
            text(w, "Window", &assoc.window)?;
            text(w, "KeystrokeSequence", &assoc.sequence)?;
            end(w, "Association")?;
        }
        end(w, "AutoType")?;
    }

    if with_history {
        if let Some(history) = &entry.history {
            start(w, "History")?;
            for old in history.get_entries() {
                write_entry(w, old, &[], false)?;
            }
            end(w, "History")?;
        }
    }

    end(w, "Entry")?;
    Ok(())
}

fn write_value<W: std::io::Write>(w: &mut Writer<W>, value: &Value<String>) -> Result<()> {
    let mut start = BytesStart::new("Value");
    if value.is_protected() {
        start.push_attribute(("ProtectInMemory", "True"));
    }
    w.write_event(Event::Start(start))?;
    w.write_event(Event::Text(BytesText::new(value.get())))?;
    end(w, "Value")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// Export in KeePassXC's CSV layout.
pub fn export_csv(db: &Database) -> String {
    let mut out = String::new();
    let header = [
        "Group",
        "Title",
        "Username",
        "Password",
        "URL",
        "Notes",
        "TOTP",
        "Icon",
        "Last Modified",
        "Created",
    ];
    push_csv_row(&mut out, &header);

    fn walk(out: &mut String, db: &Database, group: &GroupRef<'_>, path: &str) {
        let path = if path.is_empty() {
            group.name.clone()
        } else {
            format!("{path}/{}", group.name)
        };
        for entry in group.entries() {
            let icon = match entry.icon() {
                Some(Icon::BuiltIn(n)) => n.to_string(),
                _ => "0".to_string(),
            };
            let row = [
                path.clone(),
                entry.get(fields::TITLE).unwrap_or_default().to_owned(),
                entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
                entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
                entry.get(fields::URL).unwrap_or_default().to_owned(),
                entry.get(fields::NOTES).unwrap_or_default().to_owned(),
                entry.get(fields::OTP).unwrap_or_default().to_owned(),
                icon,
                opt_iso(entry.times.last_modification),
                opt_iso(entry.times.creation),
            ];
            let refs: Vec<&str> = row.iter().map(String::as_str).collect();
            push_csv_row(out, &refs);
        }
        for child in group.groups() {
            walk(out, db, &child, &path);
        }
    }
    walk(&mut out, db, &db.root(), "");
    out
}

fn push_csv_row(out: &mut String, fields: &[&str]) {
    let mut first = true;
    for field in fields {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(&field.replace('"', "\"\""));
        out.push('"');
    }
    out.push('\n');
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

/// Export as a self-contained HTML page, following KeePassXC's HtmlExporter.
pub fn export_html(db: &Database, db_path: &str) -> String {
    let name = db.meta.database_name.as_deref().unwrap_or("");
    let description = db
        .meta
        .database_description
        .as_deref()
        .unwrap_or("")
        .replace('\n', "<br>");
    let mut out = String::new();
    out.push_str(
        "<html><head><meta charset=\"UTF-8\"><title>",
    );
    out.push_str(&html_escape(name));
    out.push_str(
        "</title><style>body { font-family: \"Open Sans\", Helvetica, Arial, sans-serif; }\
h3 { margin-left: 2em; }caption { text-align: left; font-weight: bold; font-size: 150%; \
border-bottom: .15em solid #4ca; margin-bottom: .5em;} th, td { text-align: left; \
vertical-align: top; padding: 1px; }th { min-width: 7em; width: 15%; } \
.username, .password, .url, .attr { font-size: larger; font-family: monospace; \
overflow-wrap: anywhere;} .notes { font-size: small; } </style></head>\n<body><h1>",
    );
    out.push_str(&html_escape(name));
    out.push_str("</h1><p>");
    out.push_str(&description);
    out.push_str("</p><p><code>");
    out.push_str(&html_escape(db_path));
    out.push_str("</code></p>");

    write_html_group(&mut out, db, &db.root(), "");
    out.push_str("</body></html>");
    out
}

fn write_html_group(out: &mut String, db: &Database, group: &GroupRef<'_>, parent: &str) {
    if db
        .recycle_bin()
        .is_some_and(|bin| bin.id() == group.id())
    {
        return;
    }
    let path = if parent.is_empty() {
        html_escape(&group.name)
    } else {
        format!("{parent} &rarr; {}", html_escape(&group.name))
    };
    let notes = group.notes.as_deref().unwrap_or("");
    if group.entries().next().is_some() || !notes.is_empty() {
        out.push_str("<hr><h2>");
        out.push_str(&path);
        out.push_str("</h2>\n");
        if !notes.is_empty() {
            out.push_str("<p>");
            out.push_str(&html_escape(notes).replace('\n', "<br>"));
            out.push_str("</p>");
        }
    }

    out.push_str("<table width=\"95%\">");
    for entry in group.entries() {
        let mut rows = String::new();
        let username = entry.get(fields::USERNAME).unwrap_or_default();
        let password = entry.get(fields::PASSWORD).unwrap_or_default();
        let url = entry.get(fields::URL).unwrap_or_default();
        let notes = entry.get(fields::NOTES).unwrap_or_default();
        if !username.is_empty() {
            rows.push_str(&format!(
                "<tr><th>User name</th><td class=\"username\">{}</td></tr>",
                html_escape(username)
            ));
        }
        if !password.is_empty() {
            rows.push_str(&format!(
                "<tr><th>Password</th><td class=\"password\">{}</td></tr>",
                html_escape(password)
            ));
        }
        if !url.is_empty() {
            let shown = if url.len() > 100 {
                format!("{}&hellip;", html_escape(&url[..100]))
            } else {
                html_escape(url)
            };
            rows.push_str(&format!(
                "<tr><th>URL</th><td class=\"url\"><a href=\"{}\">{}</a></td></tr>",
                html_escape(url),
                shown
            ));
        }
        let mut keys: Vec<&String> = entry.fields.keys().collect();
        keys.sort();
        for key in keys {
            if fields::KNOWN_FIELDS.contains(&key.as_str()) {
                continue;
            }
            let value = entry.fields[key].get();
            rows.push_str(&format!(
                "<tr><th>{}</th><td class=\"attr\">{}</td></tr>",
                html_escape(key),
                html_escape(value).replace(' ', "&nbsp;").replace('\n', "<br>")
            ));
        }
        if !notes.is_empty() {
            rows.push_str(&format!(
                "<tr><th>Notes</th><td class=\"notes\">{}</td></tr>",
                html_escape(notes).replace('\n', "<br>")
            ));
        }
        out.push_str(&format!(
            "<tr><td style=\"padding-bottom: 0.5em;\"><table width=\"100%\"><caption>{}</caption>{rows}</table></td></tr>",
            html_escape(entry.get(fields::TITLE).unwrap_or_default())
        ));
    }
    out.push_str("</table>\n");

    for child in group.groups() {
        write_html_group(out, db, &child, &path);
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
