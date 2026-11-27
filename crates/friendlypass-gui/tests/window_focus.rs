//! Tests proving that browser passkey / approval / unlock prompts wake and
//! raise a minimized or backgrounded desktop window once per prompt, float it
//! AlwaysOnTop while awaiting confirmation, and restore WindowLevel::Normal,
//! minimize state, and focus back to the previous app once dismissed.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, UserAttentionType, ViewportCommand, ViewportId, WindowLevel};
use friendlypass_browser::bridge::{BrowserBridge, PasskeyCandidate, PasskeyGetRequest};
use friendlypass_browser::passkeys::PreparedAssertion;
use friendlypass_gui::browser_bridge;
use friendlypass_gui::window_focus::{
    ActivePrompt, FocusSnapshot, WindowFocusCoordinator, WindowFocusDriver,
};
use keepass::DatabaseKey;

#[derive(Debug, Default)]
struct DriverLog {
    wakes: usize,
    activations: Vec<bool>,
    restores: Vec<isize>,
    next_snapshot: FocusSnapshot,
}

#[derive(Clone, Default)]
struct RecordingFocusDriver {
    log: Arc<Mutex<DriverLog>>,
}

impl RecordingFocusDriver {
    fn with_snapshot(snap: FocusSnapshot) -> Self {
        Self {
            log: Arc::new(Mutex::new(DriverLog {
                next_snapshot: snap,
                ..Default::default()
            })),
        }
    }

    fn set_next_snapshot(&self, snap: FocusSnapshot) {
        self.log.lock().unwrap().next_snapshot = snap;
    }

    fn snapshot_log(&self) -> (usize, Vec<bool>, Vec<isize>) {
        let g = self.log.lock().unwrap();
        (g.wakes, g.activations.clone(), g.restores.clone())
    }
}

impl WindowFocusDriver for RecordingFocusDriver {
    fn wake_from_background(&self) {
        self.log.lock().unwrap().wakes += 1;
    }

    fn activate_for_prompt(&self, _ctx: &egui::Context, stay_on_top: bool) -> FocusSnapshot {
        let mut g = self.log.lock().unwrap();
        g.activations.push(stay_on_top);
        g.next_snapshot
    }

    fn restore_after_prompt(&self, prev_handle: isize) {
        self.log.lock().unwrap().restores.push(prev_handle);
    }
}

fn run_frame(ctx: &egui::Context, body: impl FnMut(&egui::Context)) -> Vec<ViewportCommand> {
    let mut body = body;
    let mut out = ctx.run_ui(egui::RawInput::default(), |ui| body(ui.ctx()));
    out.textures_delta.clear();
    out.viewport_output
        .get(&ViewportId::ROOT)
        .map(|v| v.commands.clone())
        .unwrap_or_default()
}

fn dummy_get_request() -> PasskeyGetRequest {
    PasskeyGetRequest {
        acting_id: "test-browser".to_owned(),
        prepared: PreparedAssertion {
            rp_id: "example.com".to_owned(),
            allow_credentials: vec![],
            allow_credentials_rejected: false,
            timeout: 60_000,
            client_data_json: b"{}".to_vec(),
        },
        candidates: vec![PasskeyCandidate {
            uuid: "00000000000000000000000000000001".to_owned(),
            title: "Example".to_owned(),
            username: "alice".to_owned(),
            credential_id: "AAAA".to_owned(),
        }],
    }
}

#[test]
fn coordinator_raises_once_per_prompt_and_restores_previous_app_and_minimize() {
    let driver = RecordingFocusDriver::with_snapshot(FocusSnapshot {
        prev_handle: 4242,
        was_minimized: true,
        was_hidden: false,
        was_focused: false,
    });
    let mut coord = WindowFocusCoordinator::new(Arc::new(driver.clone()));
    let ctx = egui::Context::default();

    // Prompt 1 opens: raises, unminimizes, pins AlwaysOnTop, requests critical attention.
    let cmds = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, Some(ActivePrompt::Passkey(1)));
    });
    assert!(cmds.contains(&ViewportCommand::Visible(true)));
    assert!(cmds.contains(&ViewportCommand::Minimized(false)));
    assert!(cmds.contains(&ViewportCommand::WindowLevel(WindowLevel::AlwaysOnTop)));
    assert!(cmds.contains(&ViewportCommand::RequestUserAttention(
        UserAttentionType::Critical
    )));
    assert!(cmds.contains(&ViewportCommand::Focus));
    assert_eq!(driver.snapshot_log().1, vec![true]);

    // Subsequent frame with the same prompt does not re-activate or spam commands.
    let cmds2 = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, Some(ActivePrompt::Passkey(1)));
    });
    assert!(cmds2.is_empty(), "expected no commands on steady frame, got {cmds2:?}");
    assert_eq!(driver.snapshot_log().1, vec![true]);

    // Back-to-back second prompt arrives while friendlypass is now focused:
    // original restore snapshot (browser 4242, minimized = true) must be preserved.
    driver.set_next_snapshot(FocusSnapshot {
        prev_handle: 0,
        was_minimized: false,
        was_hidden: false,
        was_focused: true,
    });
    let cmds3 = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, Some(ActivePrompt::Passkey(2)));
    });
    assert!(cmds3.contains(&ViewportCommand::Focus));
    assert_eq!(driver.snapshot_log().1, vec![true, true]);

    // All prompts finish: drops AlwaysOnTop, clears attention, re-minimizes, restores browser 4242.
    let cmds4 = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, None);
    });
    assert!(cmds4.contains(&ViewportCommand::WindowLevel(WindowLevel::Normal)));
    assert!(cmds4.contains(&ViewportCommand::RequestUserAttention(
        UserAttentionType::Reset
    )));
    assert!(cmds4.contains(&ViewportCommand::Minimized(true)));
    assert_eq!(driver.snapshot_log().2, vec![4242]);
}

#[test]
fn coordinator_does_not_minimize_or_steal_back_when_already_focused() {
    let driver = RecordingFocusDriver::with_snapshot(FocusSnapshot {
        prev_handle: 9999,
        was_minimized: false,
        was_hidden: false,
        was_focused: true,
    });
    let mut coord = WindowFocusCoordinator::new(Arc::new(driver.clone()));
    let ctx = egui::Context::default();

    let _ = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, Some(ActivePrompt::Approval("client-1".to_owned())));
    });
    let cmds = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, None);
    });
    assert!(cmds.contains(&ViewportCommand::WindowLevel(WindowLevel::Normal)));
    assert!(!cmds.contains(&ViewportCommand::Minimized(true)));
    // Passes 0 (clear native topmost only, do not switch away from friendlypass).
    assert_eq!(driver.snapshot_log().2, vec![0]);
}

#[test]
fn browser_bridge_passkey_prompt_wakes_background_window_and_restores_on_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("sample4.kdbx");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sample4.kdbx");
    std::fs::copy(fixture, &db_path).unwrap();
    let sock = dir.path().join("fp-focus-test.sock");
    std::env::set_var("FP_APP_SOCKET", &sock);

    let driver = RecordingFocusDriver::with_snapshot(FocusSnapshot {
        prev_handle: 7777,
        was_minimized: true,
        was_hidden: false,
        was_focused: false,
    });
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = db_path.display().to_string();
    let mut app = friendlypass_gui::App::with_open_database(&path_str, key)
        .with_window_focus(Arc::new(driver.clone()));
    browser_bridge::start_background(&mut app);

    let bridge = app.browser_bridge.clone().expect("browser bridge started");
    let ctx = egui::Context::default();

    // Initial idle pump wires egui_ctx into the bridge.
    let _ = run_frame(&ctx, |ctx| browser_bridge::pump(&mut app, ctx));
    assert_eq!(driver.snapshot_log().0, 0);

    // Background browser request arrives: must wake immediately before pump() even runs.
    let bg_bridge = Arc::clone(&bridge);
    let handle = std::thread::spawn(move || bg_bridge.passkeys_get(&dummy_get_request()));

    let start = Instant::now();
    while bridge.pending_passkey().is_none() {
        assert!(start.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        driver.snapshot_log().0 >= 1,
        "background passkey arrival must call wake_from_background immediately"
    );

    // Next GUI frame raises the window with AlwaysOnTop + Critical attention.
    let raise_cmds = run_frame(&ctx, |ctx| browser_bridge::pump(&mut app, ctx));
    assert!(raise_cmds.contains(&ViewportCommand::Minimized(false)));
    assert!(raise_cmds.contains(&ViewportCommand::WindowLevel(WindowLevel::AlwaysOnTop)));
    assert!(raise_cmds.contains(&ViewportCommand::Focus));
    assert_eq!(driver.snapshot_log().1, vec![true]);

    // User cancels the passkey dialog: next pump restores Normal level, re-minimizes, and restores browser 7777.
    browser_bridge::deny_passkey(&mut app);
    let restore_cmds = run_frame(&ctx, |ctx| browser_bridge::pump(&mut app, ctx));
    assert!(restore_cmds.contains(&ViewportCommand::WindowLevel(WindowLevel::Normal)));
    assert!(restore_cmds.contains(&ViewportCommand::Minimized(true)));
    assert_eq!(driver.snapshot_log().2, vec![7777]);

    assert!(handle.join().unwrap().is_err());
    browser_bridge::stop(&mut app);
}

#[test]
fn unlock_request_wakes_without_pinning_always_on_top() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("fp-unlock-focus-test.sock");
    std::env::set_var("FP_APP_SOCKET", &sock);

    let driver = RecordingFocusDriver::with_snapshot(FocusSnapshot {
        prev_handle: 8888,
        was_minimized: true,
        was_hidden: false,
        was_focused: false,
    });
    let mut app = friendlypass_gui::App::default().with_window_focus(Arc::new(driver.clone()));
    browser_bridge::start_background(&mut app);

    let bridge = app.browser_bridge.clone().unwrap();
    let ctx = egui::Context::default();
    let _ = run_frame(&ctx, |ctx| browser_bridge::pump(&mut app, ctx));

    bridge.request_unlock();
    assert_eq!(driver.snapshot_log().0, 1);

    let cmds = run_frame(&ctx, |ctx| browser_bridge::pump(&mut app, ctx));
    assert!(cmds.contains(&ViewportCommand::Minimized(false)));
    assert!(cmds.contains(&ViewportCommand::Focus));
    assert!(
        !cmds.contains(&ViewportCommand::WindowLevel(WindowLevel::AlwaysOnTop)),
        "unlock prompt must not pin AlwaysOnTop"
    );
    assert_eq!(driver.snapshot_log().1, vec![false]);

    browser_bridge::stop(&mut app);
}

#[test]
fn coordinator_re_hides_window_hidden_in_tray_unless_explicitly_shown() {
    let driver = RecordingFocusDriver::with_snapshot(FocusSnapshot {
        prev_handle: 5151,
        was_minimized: false,
        was_hidden: true,
        was_focused: false,
    });
    let mut coord = WindowFocusCoordinator::new(Arc::new(driver.clone()));
    let ctx = egui::Context::default();

    // Prompt wakes a window hidden in the status area.
    let raise_cmds = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, Some(ActivePrompt::Passkey(10)));
    });
    assert!(raise_cmds.contains(&ViewportCommand::Visible(true)));

    // Prompt closes: window hides back to the status area and hands focus back.
    let restore_cmds = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, None);
    });
    assert!(restore_cmds.contains(&ViewportCommand::Visible(false)));
    assert!(!restore_cmds.contains(&ViewportCommand::Minimized(true)));
    assert_eq!(driver.snapshot_log().2, vec![5151]);

    // Second prompt wakes it, then the user explicitly clicks Show in the tray:
    // closing the prompt must NOT re-hide the window.
    let _ = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, Some(ActivePrompt::Passkey(11)));
        coord.show_and_focus(ctx);
    });
    let after_show_cmds = run_frame(&ctx, |ctx| {
        coord.sync_prompt(ctx, None);
    });
    assert!(!after_show_cmds.contains(&ViewportCommand::Visible(false)));
}
