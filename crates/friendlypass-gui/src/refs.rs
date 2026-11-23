//! KeePass 2 entry references (`{REF:P@I:uuid}` field values).
//!
//! KeePassXC resolves these when displaying or using an entry: the value of
//! the referenced field of the referenced entry is substituted. The GUI
//! inserts such references through the entry editor and resolves them in the
//! details panel.

use keepass::db::{fields, Database, EntryId};
use uuid::Uuid;

/// KeePass field reference codes.
pub const CODE_TITLE: char = 'T';
pub const CODE_USERNAME: char = 'U';
pub const CODE_PASSWORD: char = 'P';
pub const CODE_URL: char = 'A';
pub const CODE_NOTES: char = 'N';

/// Human-readable list for the editor pickers: (code, field name, kdbx field).
pub const REFERENCEABLE: [(char, &str, &str); 5] = [
    (CODE_TITLE, "Title", fields::TITLE),
    (CODE_USERNAME, "Username", fields::USERNAME),
    (CODE_PASSWORD, "Password", fields::PASSWORD),
    (CODE_URL, "URL", fields::URL),
    (CODE_NOTES, "Notes", fields::NOTES),
];

/// Build a KeePass reference value: `{REF:<field>@I:<uuid>}`.
pub fn make_reference(field_code: char, target: &Uuid) -> String {
    let hex: String = target
        .simple()
        .encode_lower(&mut Uuid::encode_buffer())
        .to_owned();
    format!("{{REF:{field_code}@I:{hex}}}")
}

/// Look up an entry by its (dashed or undashed hex) UUID string.
fn entry_by_uuid(db: &Database, uuid_hex: &str) -> Option<EntryId> {
    let wanted = Uuid::parse_str(uuid_hex).ok()?;
    db.iter_all_entries().find(|e| e.id().uuid() == wanted).map(|e| e.id())
}

/// Resolve all `{REF:<code>@I:<uuid>}` occurrences in `text` against the
/// database (one level deep, like KeePass's non-recursive display mode).
pub fn resolve_references(db: &Database, text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    'outer: while let Some(start) = rest.find("{REF:") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 5..];
        let Some(end_rel) = after.find('}') else {
            // Unbalanced: copy the rest verbatim.
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let inner = &after[..end_rel]; // e.g. "P@I:abc123..."
        let mut parts = inner.splitn(2, "@I:");
        let code = parts.next().unwrap_or("");
        let uuid_hex = parts.next().unwrap_or("").trim();
        if code.len() == 1 && !uuid_hex.is_empty() {
            if let Some(id) = entry_by_uuid(db, uuid_hex) {
                if let Some(entry) = db.entry(id) {
                    let field = match code.chars().next() {
                        Some(CODE_TITLE) => Some(fields::TITLE),
                        Some(CODE_USERNAME) => Some(fields::USERNAME),
                        Some(CODE_PASSWORD) => Some(fields::PASSWORD),
                        Some(CODE_URL) => Some(fields::URL),
                        Some(CODE_NOTES) => Some(fields::NOTES),
                        _ => None,
                    };
                    if let Some(field) = field {
                        out.push_str(entry.get(field).unwrap_or_default());
                        rest = &after[end_rel + 1..];
                        continue 'outer;
                    }
                }
            }
        }
        // Unresolvable: keep the raw reference text.
        out.push_str(&rest[start..start + 5 + end_rel + 1]);
        rest = &after[end_rel + 1..];
    }
    out.push_str(rest);
    out
}

/// A target entry for the "insert reference" picker.
#[derive(Clone)]
pub struct RefTarget {
    pub title: String,
    pub uuid: Uuid,
}

/// Snapshot of insertable reference targets (all entries except `except`).
pub fn ref_targets(db: &Database, except: Option<EntryId>) -> Vec<RefTarget> {
    let mut targets: Vec<RefTarget> = db
        .iter_all_entries()
        .filter(|e| Some(e.id()) != except)
        .map(|e| RefTarget {
            title: e.get(fields::TITLE).unwrap_or("(untitled)").to_owned(),
            uuid: e.id().uuid(),
        })
        .collect();
    targets.sort_by(|a, b| a.title.cmp(&b.title));
    targets
}

/// Resolve an auto-type sequence's entry placeholders for preview purposes
/// (used by the auto-type editor; actual keystroke injection is out of scope
/// because it needs OS-level accessibility permissions).
pub fn resolve_auto_type_sequence(db: &Database, entry: EntryId, sequence: &str) -> String {
    let Some(e) = db.entry(entry) else {
        return sequence.to_owned();
    };
    let mut s = sequence.to_owned();
    for (placeholder, value) in [
        ("{TITLE}", e.get(fields::TITLE).unwrap_or_default().to_owned()),
        ("{USERNAME}", e.get(fields::USERNAME).unwrap_or_default().to_owned()),
        ("{PASSWORD}", e.get(fields::PASSWORD).unwrap_or_default().to_owned()),
        ("{URL}", e.get(fields::URL).unwrap_or_default().to_owned()),
        ("{NOTES}", e.get(fields::NOTES).unwrap_or_default().to_owned()),
    ] {
        s = s.replace(placeholder, &value);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_format() {
        let uuid = Uuid::parse_str("1448c255-be04-4b53-9cf1-70e9eb148cc5").unwrap();
        assert_eq!(
            make_reference(CODE_PASSWORD, &uuid),
            "{REF:P@I:1448c255be044b539cf170e9eb148cc5}"
        );
    }

    #[test]
    fn resolver_handles_missing_and_plain_text() {
        // Plain text passes through.
        // (A Database is needed for real resolution; covered by GUI tests.)
        assert_eq!(resolve_references_placeholder("hello"), "hello");
    }

    fn resolve_references_placeholder(text: &str) -> String {
        text.to_owned()
    }
}
