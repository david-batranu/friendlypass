//! `friendlypass-gui` binary: the cross-platform (egui) GUI of friendlypass.

// On Windows, release builds are GUI-subsystem binaries: launching the .exe
// does not open a console window. Debug builds keep the console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result {
    // Must be called before creating any window so Windows taskbar pinning
    // associates the running window with friendlypass-gui.exe and its icon.
    friendlypass_gui::window_focus::init_platform_app_id();

    // Startup helpers (used by the installer/Settings): write or remove the
    // login item without opening a window.
    let mut initial_db = None;
    let mut cli_minimized = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--enable-launch-at-login" => {
                match friendlypass_gui::startup::set_launch_at_login(true) {
                    Ok(path) => println!("Launch at login enabled: {}", path.display()),
                    Err(e) => {
                        eprintln!("Unable to enable launch at login: {e:#}");
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
            "--disable-launch-at-login" => {
                match friendlypass_gui::startup::set_launch_at_login(false) {
                    Ok(path) => println!("Launch at login disabled: {}", path.display()),
                    Err(e) => {
                        eprintln!("Unable to disable launch at login: {e:#}");
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
            "--minimized" => cli_minimized = true,
            other if !other.starts_with('-') => initial_db = Some(other.to_owned()),
            _ => {}
        }
    }

    let start_minimized = cli_minimized
        || friendlypass_gui::config::config_path()
            .map(|p| friendlypass_gui::config::Preferences::load(&p).start_minimized)
            .unwrap_or(false);

    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 820.0])
        .with_title(friendlypass_gui::brand::NAME);
    if start_minimized {
        // Avoid stealing focus while launching minimized (e.g. at login).
        viewport = viewport.with_active(false);
    }
    // Window/taskbar icon; on Linux this is the only icon a window manager
    // ever sees (the .desktop file covers launchers).
    if let Some(icon) = friendlypass_gui::brand::window_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        friendlypass_gui::brand::NAME,
        native_options,
        Box::new(move |cc| {
            #[cfg(windows)]
            {
                use raw_window_handle::{HasWindowHandle as _, RawWindowHandle};
                if let Ok(handle) = cc.window_handle() {
                    if let RawWindowHandle::Win32(win32) = handle.as_raw() {
                        friendlypass_gui::window_focus::register_windows_main_hwnd(
                            win32.hwnd.get(),
                        );
                    }
                }
            }
            let mut app = friendlypass_gui::App::new(initial_db);
            app.attach_egui_ctx(&cc.egui_ctx);
            if start_minimized {
                app.pending_start_minimized = true;
            }
            Ok(Box::new(app))
        }),
    )
}
