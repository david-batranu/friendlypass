//! Auto-type sequence parsing, resolution and keystroke execution.
//!
//! The executor is abstracted behind [`KeyInjector`] so the full pipeline is
//! testable headlessly ([`Recorder`]); [`EnigoInjector`] performs the real
//! keystroke injection on macOS/Windows/Linux via the `enigo` crate.
//!
//! NOTE (macOS): real injection requires the user to grant the app the
//! *Accessibility* permission in System Settings → Privacy & Security.
//! Without it, `EnigoInjector` returns an error which callers can surface.

use anyhow::Result;
use keepass::db::{fields, Database, EntryId};

/// The KeePassXC default auto-type sequence for password entries.
pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

/// A single resolved auto-type action.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Action {
    Text(String),
    Key(SpecialKey),
    DelayMs(u64),
}

/// Special keys used in auto-type sequences.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SpecialKey {
    Tab,
    Enter,
    Space,
}

/// Resolve a KeePass auto-type sequence for an entry into concrete actions.
///
/// Supported: `{USERNAME}`, `{PASSWORD}`, `{URL}`, `{TITLE}`, `{NOTES}`,
/// `{TAB}`, `{ENTER}`/`{RETURN}`, `{SPACE}`, `{DELAY x}` / `{DELAY=x}`,
/// plus literal text. Unknown placeholders are typed literally.
pub fn resolve_sequence(db: &Database, entry: EntryId, sequence: &str) -> Vec<Action> {
    let field = |name: &str| {
        db.entry(entry)
            .map(|e| e.get(name).unwrap_or_default().to_owned())
            .unwrap_or_default()
    };

    let mut out: Vec<Action> = Vec::new();
    let mut rest = sequence;
    while let Some(start) = rest.find('{') {
        let (before, after) = rest.split_at(start);
        if !before.is_empty() {
            out.push(Action::Text(before.to_owned()));
        }
        let after = &after[1..]; // skip '{'
        match after.find('}') {
            Some(end) => {
                let inner = &after[..end];
                let resolved = match inner.to_ascii_uppercase().as_str() {
                    "USERNAME" => Some(Action::Text(field(fields::USERNAME))),
                    "PASSWORD" => Some(Action::Text(field(fields::PASSWORD))),
                    "URL" => Some(Action::Text(field(fields::URL))),
                    "TITLE" => Some(Action::Text(field(fields::TITLE))),
                    "NOTES" => Some(Action::Text(field(fields::NOTES))),
                    "TAB" => Some(Action::Key(SpecialKey::Tab)),
                    "ENTER" | "RETURN" => Some(Action::Key(SpecialKey::Enter)),
                    "SPACE" => Some(Action::Key(SpecialKey::Space)),
                    _ => inner
                        .trim()
                        .strip_prefix("DELAY ")
                        .or_else(|| inner.trim().strip_prefix("DELAY="))
                        .and_then(|n| n.trim().parse::<u64>().ok())
                        .map(Action::DelayMs),
                };
                match resolved {
                    Some(action) => out.push(action),
                    None => out.push(Action::Text(format!("{{{inner}}}"))),
                }
                rest = &after[end + 1..];
            }
            None => {
                // Unbalanced brace: type the rest literally.
                out.push(Action::Text(format!("{{{after}")));
                rest = "";
                break;
            }
        }
    }
    if !rest.is_empty() {
        out.push(Action::Text(rest.to_owned()));
    }
    out
}

/// Abstraction over keystroke injection, so the executor is testable
/// without touching the operating system.
pub trait KeyInjector {
    fn type_text(&mut self, text: &str) -> Result<()>;
    fn tap_key(&mut self, key: SpecialKey) -> Result<()>;
    fn wait_ms(&mut self, ms: u64);
}

/// Execute resolved actions through an injector.
pub fn execute(injector: &mut dyn KeyInjector, actions: &[Action]) -> Result<()> {
    for action in actions {
        match action {
            Action::Text(text) => injector.type_text(text)?,
            Action::Key(key) => injector.tap_key(*key)?,
            Action::DelayMs(ms) => injector.wait_ms(*ms),
        }
    }
    Ok(())
}

/// Records injected input instead of touching the OS (tests / dry runs).
#[derive(Default)]
pub struct Recorder {
    pub log: Vec<String>,
}

impl KeyInjector for Recorder {
    fn type_text(&mut self, text: &str) -> Result<()> {
        self.log.push(format!("text:{text:?}"));
        Ok(())
    }
    fn tap_key(&mut self, key: SpecialKey) -> Result<()> {
        self.log.push(format!("key:{key:?}"));
        Ok(())
    }
    fn wait_ms(&mut self, ms: u64) {
        self.log.push(format!("wait:{ms}"));
    }
}

/// Real keystroke injection via `enigo` (macOS, Windows, Linux/X11).
///
/// On macOS the calling application must hold the Accessibility permission;
/// otherwise every injection call returns an error.
pub struct EnigoInjector {
    enigo: enigo::Enigo,
}

impl EnigoInjector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            enigo: enigo::Enigo::new(&enigo::Settings::default())?,
        })
    }
}

impl KeyInjector for EnigoInjector {
    fn type_text(&mut self, text: &str) -> Result<()> {
        use enigo::Keyboard;
        Ok(self.enigo.text(text)?)
    }

    fn tap_key(&mut self, key: SpecialKey) -> Result<()> {
        use enigo::{Direction::Click, Key, Keyboard};
        let enigo_key = match key {
            SpecialKey::Tab => Key::Tab,
            SpecialKey::Enter => Key::Return,
            SpecialKey::Space => Key::Space,
        };
        Ok(self.enigo.key(enigo_key, Click)?)
    }

    fn wait_ms(&mut self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> (Database, EntryId) {
        let mut db = Database::new();
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "Test Entry");
        entry.set_unprotected(fields::USERNAME, "alice");
        entry.set_protected(fields::PASSWORD, "s3cret");
        entry.set_unprotected(fields::URL, "https://example.com");
        let id = entry.id();
        drop(entry);
        drop(root);
        (db, id)
    }

    #[test]
    fn resolves_placeholders_and_special_keys() {
        let (db, id) = test_db();
        let actions = resolve_sequence(
            &db,
            id,
            "login {USERNAME}{TAB}{PASSWORD}{ENTER}extra {DELAY 250}ms",
        );
        assert_eq!(
            actions,
            vec![
                Action::Text("login ".into()),
                Action::Text("alice".into()),
                Action::Key(SpecialKey::Tab),
                Action::Text("s3cret".into()),
                Action::Key(SpecialKey::Enter),
                Action::Text("extra ".into()),
                Action::DelayMs(250),
                Action::Text("ms".into()),
            ]
        );
    }

    #[test]
    fn resolves_default_sequence_and_delay_equals_form() {
        let (db, id) = test_db();
        let actions = resolve_sequence(&db, id, "{USERNAME}{TAB}{PASSWORD}{ENTER}");
        assert_eq!(
            actions,
            vec![
                Action::Text("alice".into()),
                Action::Key(SpecialKey::Tab),
                Action::Text("s3cret".into()),
                Action::Key(SpecialKey::Enter),
            ]
        );
        let actions = resolve_sequence(&db, id, "{DELAY=100}{SPACE}");
        assert_eq!(
            actions,
            vec![Action::DelayMs(100), Action::Key(SpecialKey::Space)]
        );
    }

    #[test]
    fn unknown_placeholders_are_typed_literally() {
        let (db, id) = test_db();
        let actions = resolve_sequence(&db, id, "{NOP}{unclosed");
        assert_eq!(
            actions,
            vec![
                Action::Text("{NOP}".into()),
                Action::Text("{unclosed".into()),
            ]
        );
    }

    #[test]
    fn executes_the_full_pipeline_via_recorder() {
        let (db, id) = test_db();
        let actions = resolve_sequence(&db, id, "{USERNAME}{TAB}{PASSWORD}{ENTER}");
        let mut recorder = Recorder::default();
        execute(&mut recorder, &actions).unwrap();
        assert_eq!(
            recorder.log,
            vec![
                "text:\"alice\"".to_owned(),
                "key:Tab".to_owned(),
                "text:\"s3cret\"".to_owned(),
                "key:Enter".to_owned(),
            ]
        );
    }
}
