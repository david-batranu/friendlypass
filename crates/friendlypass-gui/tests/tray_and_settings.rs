//! Regression tests for:
//! 1. Settings dialog caching (no per-frame SecretStore / OS keychain queries).
//! 2. Start minimized in the taskbar.
//! 3. Close to status area (tray hide, Show, Lock, Quit).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use eframe::egui::{self, ViewportCommand, ViewportId};
use friendlypass_gui::dialogs::Dialog;
use friendlypass_gui::startup::{SecretStore, StoredSecret};
use friendlypass_gui::tray::{TrayBackend, TrayCommand};
use friendlypass_gui::App;
use keepass::DatabaseKey;

struct CountingSecretStore {
    gets: AtomicUsize,
    secret: Mutex<Option<StoredSecret>>,
}

impl CountingSecretStore {
    fn new(secret: Option<StoredSecret>) -> Self {
        Self {
            gets: AtomicUsize::new(0),
            secret: Mutex::new(secret),
        }
    }

    fn get_count(&self) -> usize {
        self.gets.load(Ordering::Relaxed)
    }
}

impl SecretStore for CountingSecretStore {
    fn get(&self, _account: &str) -> Result<Option<StoredSecret>> {
        self.gets.fetch_add(1, Ordering::Relaxed);
        Ok(self.secret.lock().unwrap().clone())
    }

    fn set(&self, _account: &str, secret: &StoredSecret) -> Result<()> {
        *self.secret.lock().unwrap() = Some(secret.clone());
        Ok(())
    }

    fn delete(&self, _account: &str) -> Result<()> {
        *self.secret.lock().unwrap() = None;
        Ok(())
    }
}

#[derive(Default)]
struct MockTrayState {
    syncs: Vec<(bool, bool)>,
    commands: VecDeque<TrayCommand>,
}

#[derive(Clone, Default)]
struct MockTrayBackend {
    state: Arc<Mutex<MockTrayState>>,
}

impl MockTrayBackend {
    fn push(&self, cmd: TrayCommand) {
        self.state.lock().unwrap().commands.push_back(cmd);
    }

    fn last_sync(&self) -> Option<(bool, bool)> {
        self.state.lock().unwrap().syncs.last().copied()
    }
}

impl TrayBackend for MockTrayBackend {
    fn is_supported(&self) -> bool {
        true
    }

    fn sync(&self, enabled: bool, unlocked: bool) {
        self.state.lock().unwrap().syncs.push((enabled, unlocked));
    }

    fn drain_commands(&self) -> Vec<TrayCommand> {
        self.state.lock().unwrap().commands.drain(..).collect()
    }

    fn set_egui_ctx(&self, _ctx: &egui::Context) {}
}

fn step_app_frame(
    ctx: &egui::Context,
    app: &mut App,
    close_requested: bool,
) -> Vec<ViewportCommand> {
    let mut raw = egui::RawInput::default();
    if close_requested {
        raw.viewports
            .entry(ViewportId::ROOT)
            .or_default()
            .events
            .push(egui::ViewportEvent::Close);
    }
    let mut out = ctx.run_ui(raw, |ui| {
        let ctx = ui.ctx().clone();
        app.pump_window_lifecycle(&ctx);
        app.pump_start_minimized(&ctx);
        friendlypass_gui::dialogs::show(app, &ctx);
    });
    out.textures_delta.clear();
    out.viewport_output
        .get(&ViewportId::ROOT)
        .map(|v| v.commands.clone())
        .unwrap_or_default()
}

#[test]
fn settings_dialog_caches_secret_store_lookup_across_frames() {
    let secret = StoredSecret {
        password: "secret".into(),
        keyfile: None,
        keyfile_name: None,
        challenge_response: String::new(),
    };
    let store = Arc::new(CountingSecretStore::new(Some(secret)));
    let mut app = App::default().with_secret_store(store.clone());
    app.db_path = "/tmp/fake-vault.kdbx".into();
    app.dialog = Dialog::Settings;

    let ctx = egui::Context::default();
    for _ in 0..10 {
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            friendlypass_gui::dialogs::show(&mut app, ui.ctx());
        });
        out.textures_delta.clear();
    }

    assert_eq!(
        store.get_count(),
        1,
        "Settings dialog must query SecretStore at most once, not on every frame"
    );

    // Forgetting the secret updates the cache without hitting SecretStore::get again.
    assert!(app.forget_saved_secret());
    assert!(!app.cached_has_saved_secret());
    assert_eq!(store.get_count(), 1);
}

#[test]
fn close_to_tray_intercepts_close_and_tray_commands_show_lock_quit() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sample4.kdbx");
    let key = DatabaseKey::new().with_password("testpassword");
    let tray = MockTrayBackend::default();
    let mut app = App::with_open_database(&fixture.display().to_string(), key)
        .with_tray(Arc::new(tray.clone()));
    app.prefs.close_to_tray = true;

    let ctx = egui::Context::default();

    // Closing the window while close_to_tray is enabled cancels close and hides the window.
    let cmds = step_app_frame(&ctx, &mut app, true);
    assert!(cmds.contains(&ViewportCommand::CancelClose));
    assert!(cmds.contains(&ViewportCommand::Visible(false)));
    assert!(app.hidden_to_tray);
    assert_eq!(tray.last_sync(), Some((true, true)));

    // Tray "Show" restores and focuses the window.
    tray.push(TrayCommand::Show);
    let show_cmds = step_app_frame(&ctx, &mut app, false);
    assert!(!app.hidden_to_tray);
    assert!(show_cmds.contains(&ViewportCommand::Visible(true)));
    assert!(show_cmds.contains(&ViewportCommand::Minimized(false)));
    assert!(show_cmds.contains(&ViewportCommand::Focus));

    // Tray "Lock" locks the open database and reports locked to the tray.
    tray.push(TrayCommand::Lock);
    let _ = step_app_frame(&ctx, &mut app, false);
    assert!(app.db.is_none());
    assert_eq!(tray.last_sync(), Some((true, false)));

    // Tray "Quit" disables the tray icon, allows closing, and emits Close.
    tray.push(TrayCommand::Quit);
    let quit_cmds = step_app_frame(&ctx, &mut app, false);
    assert!(app.allow_close);
    assert!(quit_cmds.contains(&ViewportCommand::Close));
    assert_eq!(tray.last_sync(), Some((false, false)));
    assert!(!app.should_hide_on_close());
}

#[test]
fn close_without_close_to_tray_does_not_cancel_close() {
    let tray = MockTrayBackend::default();
    let mut app = App::default().with_tray(Arc::new(tray));
    app.prefs.close_to_tray = false;

    let ctx = egui::Context::default();
    let cmds = step_app_frame(&ctx, &mut app, true);
    assert!(!cmds.contains(&ViewportCommand::CancelClose));
    assert!(!app.hidden_to_tray);
}

#[test]
fn start_minimized_emits_minimized_once_after_first_frame() {
    let mut app = App::default();
    app.pending_start_minimized = true;

    let ctx = egui::Context::default();
    // Frame 1: lets eframe finish initial reveal before minimizing.
    let cmds1 = step_app_frame(&ctx, &mut app, false);
    assert!(!cmds1.contains(&ViewportCommand::Minimized(true)));
    assert!(app.pending_start_minimized);

    // Frame 2: minimizes once.
    let cmds2 = step_app_frame(&ctx, &mut app, false);
    assert!(cmds2.contains(&ViewportCommand::Minimized(true)));
    assert!(!app.pending_start_minimized);

    // Frame 3: steady state, does not re-minimize.
    let cmds3 = step_app_frame(&ctx, &mut app, false);
    assert!(!cmds3.contains(&ViewportCommand::Minimized(true)));
}
