//! Application state, the eframe `App` implementation, the unlock screen
//! and the main window chrome (toolbar / status bar / save logic).

use eframe::egui;
use eframe::egui::Ui;
use keepass::db::{Database, GroupId};
use keepass::DatabaseKey;
use std::path::PathBuf;

use crate::browser;
use crate::dialogs::{self, Dialog};
use crate::icons::IconCache;
use keepass::db::EntryId;

/// Which entry field a keyboard shortcut copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyField {
    Password,
    Username,
    Url,
    Totp,
}

/// Column to sort the entry list by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Tags,
}

impl SortColumn {
    pub fn label(&self) -> &'static str {
        match self {
            SortColumn::Title => "Title",
            SortColumn::Username => "UserName",
            SortColumn::Password => "Password",
            SortColumn::Url => "URL",
            SortColumn::Notes => "Notes",
            SortColumn::Tags => "Tags",
        }
    }
}

/// The main GUI application.
pub struct App {
    // -- unlock screen state --------------------------------------------
    pub db_path: String,
    pub password: String,
    pub key_file: String,
    /// Optional local challenge-response secret (hex) — the software
    /// equivalent of a YubiKey HMAC-SHA1 response.
    pub challenge_response: String,
    pub unlock_error: String,

    // -- open database state --------------------------------------------
    pub db: Option<Database>,
    pub db_key: Option<DatabaseKey>,
    pub dirty: bool,
    /// Set once the KDBX3→4.1 upgrade has been confirmed, so we don't ask
    /// again on every save.
    pub upgrade_confirmed: bool,

    // -- browsing state --------------------------------------------------
    pub search: String,
    /// Set to focus the search box on the next frame (Cmd/Ctrl+F).
    pub focus_search: bool,
    pub selected_group: Option<GroupId>, // None = root
    pub selected_entry: Option<keepass::db::EntryId>,
    /// Multi-selection (Ctrl/Cmd-click) for batch operations.
    pub selected_entries: std::collections::HashSet<EntryId>,
    pub sort_column: SortColumn,
    pub sort_desc: bool,
    pub show_passwords: bool,
    pub status: String,
    pub dialog: Dialog,
    /// Lazily-uploaded icon textures (standard + custom icons).
    pub icon_cache: IconCache,
    /// The running SSH agent server (KeePassXC's SSH agent integration).
    pub ssh_handle: Option<kpxc_ssh_agent::server::AgentHandle>,
    pub ssh_pool: Option<kpxc_ssh_agent::server::IdentityPool>,
    /// Socket path for the SSH agent (editable before starting).
    pub ssh_socket: String,
    /// The running browser-protocol server (KeePassXC-Browser integration).
    pub browser_handle: Option<kpxc_browser::ServerHandle>,
    pub browser_state: Option<kpxc_browser::SharedState>,
}

impl Default for App {
    fn default() -> Self {
        App {
            db_path: String::new(),
            password: String::new(),
            key_file: String::new(),
            challenge_response: String::new(),
            unlock_error: String::new(),
            db: None,
            db_key: None,
            dirty: false,
            upgrade_confirmed: false,
            search: String::new(),
            focus_search: false,
            selected_group: None,
            selected_entry: None,
            selected_entries: std::collections::HashSet::new(),
            sort_column: SortColumn::Title,
            sort_desc: false,
            show_passwords: false,
            status: String::new(),
            dialog: Dialog::None,
            icon_cache: IconCache::default(),
            ssh_handle: None,
            ssh_pool: None,
            ssh_socket: kpxc_ssh_agent::default_socket_path().display().to_string(),
            browser_handle: None,
            browser_state: None,
        }
    }
}

impl App {
    pub fn new(initial_db: Option<String>) -> Self {
        let mut app = App::default();
        if let Some(path) = initial_db {
            app.db_path = path;
        }
        app
    }

    /// Open a database directly (used by tests and scripting entry points).
    pub fn with_open_database(path: &str, key: DatabaseKey) -> Self {
        let mut app = App::default();
        app.db_path = path.to_string();
        match open_database(path, &key) {
            Ok(db) => {
                app.db = Some(db);
                app.db_key = Some(key);
                app.status = format!("Opened {}", path);
            }
            Err(e) => app.unlock_error = format!("{e:#}"),
        }
        app
    }

    /// Attempt to unlock using the fields on the welcome screen.
    pub fn try_unlock(&mut self) {
        self.unlock_error.clear();

        if self.db_path.trim().is_empty() {
            self.unlock_error = "Select a database file first.".into();
            return;
        }
        if self.password.is_empty() && self.key_file.trim().is_empty() {
            self.unlock_error = "Enter a password and/or select a key file.".into();
            return;
        }

        let mut key = DatabaseKey::new();
        if !self.password.is_empty() {
            key = key.with_password(&self.password);
        }
        if !self.key_file.trim().is_empty() {
            match std::fs::File::open(&self.key_file) {
                Ok(mut f) => match key.with_keyfile(&mut f) {
                    Ok(k) => key = k,
                    Err(e) => {
                        self.unlock_error = format!("unable to read key file: {e}");
                        return;
                    }
                },
                Err(e) => {
                    self.unlock_error = format!("unable to open key file: {e}");
                    return;
                }
            }
        }

        if !self.challenge_response.trim().is_empty() {
            match kpxc::key::with_challenge_response(key, &self.challenge_response) {
                Ok(k) => key = k,
                Err(e) => {
                    self.unlock_error = format!("{e:#}");
                    return;
                }
            }
        }

        match open_database(&self.db_path, &key) {
            Ok(db) => {
                self.db = Some(db);
                self.db_key = Some(key);
                self.password.clear();
                self.dirty = false;
                self.upgrade_confirmed = false;
                self.search.clear();
                self.selected_group = None;
                self.selected_entry = None;
                self.status = format!("Opened {}", self.db_path);
            }
            Err(e) => {
                self.unlock_error = format!("{e:#}");
            }
        }
    }

    /// Lock the database and return to the unlock screen.
    pub fn lock(&mut self) {
        self.db = None;
        self.db_key = None;
        self.dirty = false;
        self.upgrade_confirmed = false;
        self.selected_entry = None;
        self.selected_group = None;
        self.search.clear();
        self.dialog = Dialog::None;
        self.status = "Database locked".into();
        self.password.clear();
    }

    /// Save button: checks whether an upgrade confirmation is needed first.
    pub fn request_save(&mut self) {
        let needs_upgrade = self
            .db
            .as_ref()
            .map(|db| !matches!(db.config.version, keepass::config::DatabaseVersion::KDB4(_)))
            .unwrap_or(false);
        if needs_upgrade && !self.upgrade_confirmed {
            self.dialog = Dialog::ConfirmUpgrade;
            return;
        }
        self.perform_save(None);
    }

    /// Perform the actual save (optionally to a new path).
    pub fn perform_save(&mut self, new_path: Option<String>) {
        let Some(path) = new_path.clone().or_else(|| Some(self.db_path.clone())) else {
            return;
        };
        let Some(db) = self.db.as_mut() else { return };
        let Some(key) = self.db_key.clone() else { return };

        // KDBX 3.x can only be saved after upgrading to KDBX 4.1.
        kpxc::commands::ensure_writable_version(db);

        let path = PathBuf::from(&path);
        match kpxc::saveutil::save(&path, db, key) {
            Ok(()) => {
                if let Some(p) = new_path {
                    self.db_path = p;
                }
                self.dirty = false;
                self.upgrade_confirmed = true;
                self.dialog = Dialog::None;
                self.status = format!("Saved {}", self.db_path);
            }
            Err(e) => {
                self.status = format!("{e:#}");
            }
        }
    }

    /// Copy text to the system clipboard; reports failures in the status bar.
    pub fn copy_to_clipboard(&mut self, text: String) {
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
            Ok(()) => self.status = "Copied to clipboard".into(),
            Err(e) => self.status = format!("clipboard unavailable: {e}"),
        }
    }

    /// Copy a field of the selected entry (keyboard shortcuts).
    pub fn copy_selected(&mut self, field: CopyField) {
        let Some(id) = self.selected_entry else {
            self.status = "No entry selected".into();
            return;
        };
        let Some(db) = self.db.as_ref() else { return };
        let Some(entry) = db.entry(id) else { return };
        let (label, value) = match field {
            CopyField::Password => ("password", entry.get("Password").unwrap_or_default().to_owned()),
            CopyField::Username => ("username", entry.get("UserName").unwrap_or_default().to_owned()),
            CopyField::Url => ("URL", entry.get("URL").unwrap_or_default().to_owned()),
            CopyField::Totp => ("TOTP", match crate::totp::current_code(&entry) {
                Some((code, _)) => code,
                None => {
                    self.status = "This entry has no TOTP".into();
                    return;
                }
            }),
        };
        if value.is_empty() {
            self.status = format!("This entry has no {label}");
            return;
        }
        self.copy_to_clipboard(value);
        self.status = format!("Copied {label} to clipboard");
    }

    /// Handle global keyboard shortcuts on the database screen.
    /// Returns true if a shortcut consumed a key this frame.
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        use egui::{Key, Modifiers};
        // Shortcuts are ignored while a dialog is open (dialogs handle their
        // own keys, see `dialogs::show`).
        if !matches!(self.dialog, Dialog::None) {
            return;
        }
        let cmd = Modifiers::COMMAND;
        let shift = Modifiers::COMMAND | Modifiers::SHIFT;
        // True while a text field (e.g. the search box) has focus. Typing
        // keys then belong to the field; global commands still work.
        let typing = ctx.egui_wants_keyboard_input();

        // Global commands: available even while typing.
        if ctx.input_mut(|i| i.consume_key(cmd, Key::S)) {
            self.request_save();
        }
        if ctx.input_mut(|i| i.consume_key(shift, Key::S)) {
            self.dialog = Dialog::SaveAs(self.db_path.clone());
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::L)) {
            self.lock();
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::F)) {
            self.focus_search = true;
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::G)) {
            self.dialog = Dialog::Generator(Box::new(dialogs::Generator::default()));
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::N)) {
            self.new_entry_dialog(self.selected_group);
        }
        if ctx.input_mut(|i| i.consume_key(shift, Key::N)) {
            let parent = self
                .selected_group
                .unwrap_or_else(|| self.db.as_ref().unwrap().root().id());
            self.dialog = Dialog::GroupNew(Box::new(dialogs::GroupEdit::new(parent)));
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F1)) {
            self.dialog = Dialog::Shortcuts;
        }
        if typing {
            return;
        }
        // Entry commands: only when no text field is focused, so Cmd+C in
        // the search box still copies text and Delete edits the query.
        if ctx.input_mut(|i| i.consume_key(cmd, Key::C)) {
            self.copy_selected(CopyField::Password);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::B)) {
            self.copy_selected(CopyField::Username);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::U)) {
            self.copy_selected(CopyField::Url);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::T)) {
            self.copy_selected(CopyField::Totp);
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::E)) {
            if let Some(id) = self.selected_entry {
                self.edit_entry_dialog(id);
            }
        }
        if ctx.input_mut(|i| i.consume_key(cmd, Key::H)) {
            if let Some(id) = self.selected_entry {
                self.dialog = Dialog::History(id);
            }
        }
        // Delete key (macOS Backspace) recycles the selected entry.
        let delete = ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Delete))
            || ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Backspace));
        if delete {
            if let Some(id) = self.selected_entry {
                self.dialog = Dialog::ConfirmDeleteEntry(id);
            }
        }
        // Enter opens the selected entry for editing.
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Enter)) {
            if let Some(id) = self.selected_entry {
                self.edit_entry_dialog(id);
            }
        }
        // Escape clears an active search.
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) && !self.search.is_empty() {
            self.search.clear();
        }
    }

    /// Open the entry editor for a new entry in the given group.
    pub fn new_entry_dialog(&mut self, group: Option<GroupId>) {
        let parent = group
            .or(self.selected_group)
            .unwrap_or_else(|| self.db.as_ref().map(|db| db.root().id()).expect("db open"));
        let targets = self
            .db
            .as_ref()
            .map(|db| crate::refs::ref_targets(db, None))
            .unwrap_or_default();
        let custom_icons = self.custom_icon_snapshot();
        self.dialog = Dialog::EntryEdit(Box::new(dialogs::EntryEdit::new(parent, targets, custom_icons)));
    }

    /// Open the entry editor for an existing entry (loads its fields).
    pub fn edit_entry_dialog(&mut self, id: keepass::db::EntryId) {
        let Some(db) = self.db.as_ref() else { return };
        let Some(entry) = db.entry(id) else { return };
        let targets = crate::refs::ref_targets(db, Some(id));
        let custom_icons = self.custom_icon_snapshot();
        self.dialog = Dialog::EntryEdit(Box::new(dialogs::EntryEdit::from_entry(
            id,
            &entry,
            targets,
            custom_icons,
        )));
    }

    /// Snapshot of the database custom icon pool (for editor pickers).
    fn custom_icon_snapshot(&self) -> Vec<(keepass::db::CustomIconId, Vec<u8>)> {
        self.db
            .as_ref()
            .map(|db| {
                db.iter_all_custom_icons()
                    .map(|ci| (ci.id(), ci.data.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Delete an entry (after confirmation), mirroring KeePassXC's behavior:
    /// if the recycle bin is enabled and the entry is not already inside it,
    /// the entry is *moved* to the recycle bin group (created on demand);
    /// otherwise it is deleted permanently.
    pub fn delete_entry(&mut self, id: keepass::db::EntryId) {
        let to_recycle = self.deletes_to_recycle_bin_entry(id);
        let bin_id = to_recycle.then(|| self.ensure_recycle_bin());
        let Some(db) = self.db.as_mut() else { return };

        if let Some(bin_id) = bin_id {
            if let Some(mut entry) = db.entry_mut(id) {
                match entry.track_changes().move_to(bin_id) {
                    Ok(()) => {
                        self.dirty = true;
                        self.selected_entry = None;
                        self.status = "Entry moved to the Recycle Bin".into();
                    }
                    Err(e) => self.status = format!("cannot move entry to recycle bin: {e}"),
                }
            }
        } else if let Some(entry) = db.entry_mut(id) {
            entry.remove();
            self.dirty = true;
            if self.selected_entry == Some(id) {
                self.selected_entry = None;
            }
            self.status = "Entry deleted permanently".into();
        }
    }

    /// Delete a group (after confirmation) with the same recycle-bin
    /// semantics as [`App::delete_entry`]. The root group cannot be deleted.
    pub fn delete_group(&mut self, id: GroupId) {
        // Decide first (immutable), then mutate.
        let bin_id_current = self.db.as_ref().and_then(|db| db.recycle_bin()).map(|b| b.id());
        let in_bin = self
            .db
            .as_ref()
            .and_then(|db| db.group(id))
            .and_then(|g| g.parent().map(|p| p.id()))
            .map(|pid| Some(pid) == bin_id_current)
            .unwrap_or(false);
        let is_bin_itself = bin_id_current == Some(id);
        let to_recycle = self.recycle_bin_enabled() && !in_bin && !is_bin_itself;

        let bin_id = to_recycle.then(|| self.ensure_recycle_bin());
        let Some(db) = self.db.as_mut() else { return };

        if let Some(bin_id) = bin_id {
            if let Some(mut group) = db.group_mut(id) {
                match group.track_changes().move_to(bin_id) {
                    Ok(()) => {
                        self.dirty = true;
                        if self.selected_group == Some(id) {
                            self.selected_group = None;
                        }
                        self.status = "Group moved to the Recycle Bin".into();
                    }
                    Err(e) => self.status = format!("cannot move group to recycle bin: {e}"),
                }
            }
        } else if let Some(mut group) = db.group_mut(id) {
            match group.track_changes().remove() {
                Ok(()) => {
                    self.dirty = true;
                    if self.selected_group == Some(id) {
                        self.selected_group = None;
                    }
                    self.status = "Group deleted permanently".into();
                }
                Err(e) => self.status = format!("cannot delete group: {e}"),
            }
        }
    }

    /// Perform auto-type for an entry: resolves the entry's auto-type
    /// sequence (or the KeePass default) and injects the keystrokes on a
    /// background thread after a short countdown, so the user can focus the
    /// target window — the same UX as KeePassXC.
    ///
    /// On macOS this requires the Accessibility permission; failures are
    /// logged (the GUI cannot inject without the user granting it).
    pub fn perform_auto_type(&mut self, id: keepass::db::EntryId) {
        let Some(db) = self.db.as_ref() else { return };
        let Some(entry) = db.entry(id) else { return };
        let sequence = entry
            .autotype
            .as_ref()
            .and_then(|a| a.default_sequence.clone())
            .unwrap_or_else(|| crate::autotype::DEFAULT_SEQUENCE.to_owned());
        let actions = crate::autotype::resolve_sequence(db, id, &sequence);

        std::thread::spawn(move || {
            // Countdown so the user can focus the target window.
            std::thread::sleep(std::time::Duration::from_millis(1500));
            let result = crate::autotype::EnigoInjector::new()
                .and_then(|mut injector| crate::autotype::execute(&mut injector, &actions));
            if let Err(e) = result {
                eprintln!("auto-type failed: {e:#} (on macOS, grant the app the Accessibility permission)");
            }
        });
        self.status =
            "Auto-Type starts in 1.5 seconds - focus the target window".into();
    }

    /// Move a group to another group (drag & drop), with the same
    /// cycle-prevention as KeePassXC: a group cannot be dropped into itself
    /// or into one of its own descendants.
    pub fn move_group_to(&mut self, group: GroupId, target: Option<GroupId>) {
        let Some(db) = self.db.as_ref() else { return };
        let root_id = db.root().id();
        let target_id = target.unwrap_or(root_id);

        if target_id == group {
            self.status = "Cannot move a group into itself".into();
            return;
        }
        // Reject dropping a group into its own subtree.
        let mut cur = Some(target_id);
        while let Some(c) = cur {
            if c == group {
                self.status = "Cannot move a group into one of its own groups".into();
                return;
            }
            cur = self
                .db
                .as_ref()
                .and_then(|db| db.group(c))
                .and_then(|g| g.parent().map(|p| p.id()));
        }

        let group_name = self
            .db
            .as_ref()
            .and_then(|db| db.group(group))
            .map(|g| g.name.clone())
            .unwrap_or_default();
        let target_name = target
            .and_then(|t| self.db.as_ref().and_then(|db| db.group(t)).map(|g| g.name.clone()))
            .unwrap_or_else(|| {
                self.db
                    .as_ref()
                    .map(|db| db.root().name.clone())
                    .unwrap_or_default()
            });

        let Some(db) = self.db.as_mut() else { return };
        if let Some(mut g) = db.group_mut(group) {
            match g.track_changes().move_to(target_id) {
                Ok(()) => {
                    self.dirty = true;
                    self.selected_group = Some(group);
                    self.status = format!("Moved group {group_name} to {target_name}");
                }
                Err(e) => self.status = format!("cannot move group: {e}"),
            }
        }
    }

    /// Move a batch of entries to a group (batch operation on the
    /// multi-selection).
    pub fn move_entries_to(&mut self, ids: &[EntryId], target: GroupId) {
        let mut moved = 0;
        if let Some(db) = self.db.as_mut() {
            for id in ids {
                if let Some(mut entry) = db.entry_mut(*id) {
                    if entry.track_changes().move_to(target).is_ok() {
                        moved += 1;
                    }
                }
            }
        }
        if moved > 0 {
            self.dirty = true;
            let target_name = self
                .db
                .as_ref()
                .and_then(|db| db.group(target))
                .map(|g| g.name.clone())
                .unwrap_or_default();
            let plural = if moved == 1 { "entry" } else { "entries" };
            self.status = format!("Moved {moved} {plural} to {target_name}");
        }
        self.selected_entries.clear();
        self.selected_entry = None;
    }

    /// Recycle a batch of entries (multi-selection delete).
    pub fn recycle_entries(&mut self, ids: Vec<EntryId>) {
        let n = ids.len();
        for id in ids {
            self.delete_entry(id);
        }
        self.status = format!("Moved {n} entries to the Recycle Bin");
        self.selected_entries.clear();
        self.selected_entry = None;
    }

    /// Snapshot of all groups (for the batch-move dialog), with paths.
    pub fn group_snapshot(&self) -> Vec<(GroupId, String)> {
        let Some(db) = self.db.as_ref() else { return Vec::new() };
        let mut out = vec![(db.root().id(), "(root)".into())];
        fn walk(db: &keepass::db::Database, id: GroupId, prefix: &str, out: &mut Vec<(GroupId, String)>) {
            if let Some(g) = db.group(id) {
                let mut children: Vec<(GroupId, String)> = g
                    .groups()
                    .map(|c| (c.id(), c.name.clone()))
                    .collect();
                children.sort_by(|a, b| a.1.cmp(&b.1));
                for (cid, name) in children {
                    let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
                    out.push((cid, path.clone()));
                    walk(db, cid, &path, out);
                }
            }
        }
        let root = db.root().id();
        walk(db, root, "", &mut out);
        out
    }

    /// Permanently remove everything inside the recycle bin.
    pub fn empty_recycle_bin(&mut self) {
        let Some(db) = self.db.as_mut() else { return };
        let Some(bin) = db.recycle_bin() else {
            self.status = "No recycle bin in this database".into();
            return;
        };
        let entry_ids: Vec<_> = bin.entries().map(|e| e.id()).collect();
        let group_ids: Vec<_> = bin.groups().map(|g| g.id()).collect();
        let n = entry_ids.len() + group_ids.len();

        for id in entry_ids {
            if let Some(entry) = db.entry_mut(id) {
                entry.remove();
            }
        }
        for id in group_ids {
            if let Some(mut group) = db.group_mut(id) {
                let _ = group.track_changes().remove();
            }
        }
        self.dirty = true;
        self.selected_entry = None;
        self.status = format!("Emptied the Recycle Bin ({n} objects removed)");
    }

    /// Whether the recycle bin is enabled in this database's metadata.
    pub fn recycle_bin_enabled(&self) -> bool {
        self.db
            .as_ref()
            .map(|db| db.meta.recyclebin_enabled.unwrap_or(true))
            .unwrap_or(true)
    }

    /// Whether deleting this entry would move it to the recycle bin
    /// (used to word the confirmation dialog like KeePassXC does).
    pub fn deletes_to_recycle_bin_entry(&self, id: keepass::db::EntryId) -> bool {
        let Some(db) = self.db.as_ref() else { return false };
        if !self.recycle_bin_enabled() {
            return false;
        }
        let bin_id = db.recycle_bin().map(|b| b.id());
        // Already inside the bin (or inside a group within the bin)?
        let mut parent = db.entry(id).map(|e| e.parent().id());
        while let Some(pid) = parent {
            if Some(pid) == bin_id {
                return false;
            }
            parent = db.group(pid).and_then(|g| g.parent().map(|p| p.id()));
        }
        true
    }

    /// Get the recycle bin group id, creating the group (and registering it
    /// in the metadata) on first use, exactly like KeePassXC.
    fn ensure_recycle_bin(&mut self) -> GroupId {
        if let Some(bin) = self.db.as_ref().and_then(|db| db.recycle_bin()) {
            return bin.id();
        }
        let Some(db) = self.db.as_mut() else { unreachable!("db is open") };
        let mut root = db.root_mut();
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".into();
        let id = bin.id();
        drop(bin);
        drop(root);
        db.meta.recyclebin_uuid = Some(id.uuid());
        db.meta.recyclebin_changed = Some(chrono::Utc::now().naive_utc());
        self.dirty = true;
        id
    }

    /// Restore a historical revision of an entry: copies all fields of the
    /// revision into the current entry. Like KeePassXC, the restore itself
    /// is recorded in the entry's history.
    pub fn restore_history_entry(&mut self, id: keepass::db::EntryId, index: usize) {
        let Some(db) = self.db.as_mut() else { return };

        // Snapshot the historical fields.
        let historical_fields = db
            .entry(id)
            .and_then(|e| e.historical(index).map(|h| h.fields.clone()));

        let Some(fields) = historical_fields else {
            self.status = "History revision not found".into();
            return;
        };

        if let Some(mut entry) = db.entry_mut(id) {
            entry.track_changes().edit(|e| {
                e.fields = fields;
            });
            self.dirty = true;
            self.dialog = Dialog::None;
            self.status = "Restored entry from history".into();
        }
    }

}

/// Open a database with friendly error mapping (shared with the CLI layer).
pub fn open_database(path: &str, key: &DatabaseKey) -> anyhow::Result<Database> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("unable to open database file {path}: {e}"))?;
    match Database::open(&mut file, key.clone()) {
        Ok(db) => Ok(db),
        Err(e) => anyhow::bail!("unable to open database {path} (wrong password or key file?): {e}"),
    }
}

// ---------------------------------------------------------------------------
// eframe integration
// ---------------------------------------------------------------------------

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        if self.db.is_none() {
            self.unlock_screen(ui);
        } else {
            self.database_screen(ui);
        }
    }
}

/// A form row on the unlock screen: fixed-width label + field content.
/// (egui 0.37's Grid clamps TextEdit widths to the previous column width,
/// leaving the fields tiny; manual rows honor `desired_width`.)
fn unlock_row(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui, egui::Id)) {
    ui.horizontal(|ui| {
        let label_resp = ui.add_sized(
            [320.0, ui.spacing().interact_size.y],
            egui::Label::new(label),
        );
        add(ui, label_resp.id);
    });
}

impl App {
    /// The unlock / welcome screen.
    fn unlock_screen(&mut self, root: &mut Ui) {
        let ctx = root.ctx().clone();
        egui::CentralPanel::default().show(root, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.heading("KeePassXC-RS");
                ui.label("KeePassXC core, migrated to Rust");
                ui.add_space(24.0);
            });

            // Manual rows (egui 0.37 Grid clamps TextEdit widths to the tiny
            // previous column width; see `form_row` in dialogs.rs).
            unlock_row(ui, "Database file:", |ui, id| {
                let path_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.db_path)
                        .hint_text("/path/to/database.kdbx")
                        .desired_width(460.0),
                );
                path_resp.labelled_by(id);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("KeePass database", &["kdbx", "kdb"])
                        .pick_file()
                    {
                        self.db_path = p.display().to_string();
                    }
                }
            });

            let mut unlock_on_enter = false;
            unlock_row(ui, "Password:", |ui, id| {
                let pw_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(true)
                        .hint_text("password")
                        .desired_width(460.0),
                );
                // Enter in the password field unlocks.
                unlock_on_enter =
                    pw_resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                pw_resp.labelled_by(id);
            });
            if unlock_on_enter {
                self.try_unlock();
            }

            unlock_row(ui, "Key file (optional):", |ui, id| {
                let kf_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.key_file)
                        .hint_text("/path/to/keyfile.keyx")
                        .desired_width(460.0),
                );
                kf_resp.labelled_by(id);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Key file", &["keyx", "key"])
                        .pick_file()
                    {
                        self.key_file = p.display().to_string();
                    }
                }
            });

            unlock_row(ui, "Challenge-response secret (hex, optional):", |ui, id| {
                let cr_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.challenge_response)
                        .hint_text("YubiKey-equivalent HMAC-SHA1 secret")
                        .desired_width(460.0),
                );
                cr_resp.labelled_by(id);
            });

            ui.add_space(16.0);
            ui.vertical_centered(|ui| {
                if ui.button("Unlock").clicked() {
                    self.try_unlock();
                }
                ui.add_space(8.0);
                if ui.button("Create new database…").clicked() {
                    self.dialog = Dialog::NewDb(Box::new(dialogs::NewDb::default()));
                }
            });

            if !self.unlock_error.is_empty() {
                ui.add_space(12.0);
                ui.colored_label(egui::Color32::RED, &self.unlock_error);
            }

            dialogs::show(self, &ctx);
        });
    }

    /// The main database screen: toolbar, group tree, entry list, details.
    fn database_screen(&mut self, root: &mut Ui) {
        let ctx = root.ctx().clone();

        // Global keyboard shortcuts (skipped while dialogs or text fields
        // have focus).
        self.handle_shortcuts(&ctx);
        if self.db.is_none() {
            return; // e.g. Cmd+L locked the database this frame
        }

        // Toolbar ---------------------------------------------------------
        egui::Panel::top("toolbar")
            .resizable(false)
            .default_size(42.0)
            .show(root, |ui| {
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    let name = std::path::Path::new(&self.db_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "database".into());
                    ui.strong(format!("{name}{}", if self.dirty { "  *" } else { "" }));
                    ui.separator();

                    let search_label = ui.label("Search:");
                    let search_resp =
                        ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("search all entries… (Cmd+F)"));
                    if self.focus_search {
                        search_resp.request_focus();
                        self.focus_search = false;
                    }
                    search_resp.labelled_by(search_label.id);
                    if !self.search.is_empty() && ui.button("Clear search").clicked() {
                        self.search.clear();
                    }
                    ui.separator();

                    if ui.button("New Entry").clicked() {
                        self.new_entry_dialog(self.selected_group);
                    }
                    if ui.button("New Group").clicked() {
                        let parent = self
                            .selected_group
                            .unwrap_or_else(|| self.db.as_ref().unwrap().root().id());
                        self.dialog = Dialog::GroupNew(Box::new(dialogs::GroupEdit::new(parent)));
                    }
                    if ui.button("Password Generator…").clicked() {
                        self.dialog = Dialog::Generator(Box::new(dialogs::Generator::default()));
                    }
                    if ui.button("Database Info…").clicked() {
                        self.dialog = Dialog::DbInfo;
                    }
                    if ui.button("Shortcuts…").clicked() {
                        self.dialog = Dialog::Shortcuts;
                    }
                    if ui.button("SSH Agent…").clicked() {
                        self.dialog = Dialog::SshAgent;
                    }
                    if ui.button("Browser…").clicked() {
                        self.dialog = Dialog::Browser;
                    }
                    ui.separator();
                    let save = ui.add_enabled(self.dirty, egui::Button::new("Save"));
                    if save.clicked() {
                        self.request_save();
                    }
                    if ui.button("Save As…").clicked() {
                        self.dialog = Dialog::SaveAs(self.db_path.clone());
                    }
                ui.separator();
                ui.checkbox(&mut self.show_passwords, "Show passwords");
                if ui.button("Lock").clicked() {
                    self.lock();
                }
            });

            // Batch operations on the multi-selection get their own row so
            // the toolbar never overflows the window width.
            let n = self.selected_entries.len();
            if n >= 2 {
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.label(format!("{n} entries selected:"));
                    if ui.button(format!("Move {n} to group…")).clicked() {
                        let ids: Vec<EntryId> = self.selected_entries.iter().copied().collect();
                        let groups = self.group_snapshot();
                        self.dialog = Dialog::BatchMove(Box::new(dialogs::BatchMove {
                            entries: ids,
                            groups,
                            target: None,
                        }));
                    }
                    if ui.button(format!("Recycle {n} entries…")).clicked() {
                        let ids: Vec<EntryId> = self.selected_entries.iter().copied().collect();
                        self.recycle_entries(ids);
                    }
                });
                ui.add_space(2.0);
            } else {
                ui.add_space(4.0);
            }
        });

        // Status bar ------------------------------------------------------
        egui::Panel::bottom("statusbar")
            .resizable(false)
            .exact_size(24.0)
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(&self.status);
                });
            });

        // Details panel ----------------------------------------------------
        let selected_entry = self.selected_entry;
        if selected_entry.is_some() {
            egui::Panel::bottom("details")
                .resizable(true)
                .default_size(170.0)
                .show(root, |ui| {
                    browser::entry_details(ui, self, selected_entry);
                });
        }

        // Group tree --------------------------------------------------------
        egui::Panel::left("groups")
            .resizable(true)
            .default_size(230.0)
            .show(root, |ui| {
                browser::group_tree(ui, self);
            });

        // Entry list ---------------------------------------------------------
        egui::CentralPanel::default().show(root, |ui| {
            browser::entry_table(ui, self);
        });

        dialogs::show(self, &ctx);
    }
}
