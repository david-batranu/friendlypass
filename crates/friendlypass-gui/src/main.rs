//! `friendlypass-gui` binary: the cross-platform (egui) GUI of friendlypass.

// On Windows, release builds are GUI-subsystem binaries: launching the .exe
// does not open a console window. Debug builds keep the console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result {
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 820.0])
        .with_title(friendlypass_gui::brand::NAME);
    // Window/taskbar icon; on Linux this is the only icon a window manager
    // ever sees (the .desktop file covers launchers).
    if let Some(icon) = friendlypass_gui::brand::window_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    // Startup helpers (used by the installer/Settings): write or remove the
    // login item without opening a window.
    let mut initial_db = None;
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
            other if !other.starts_with('-') => initial_db = Some(other.to_owned()),
            _ => {}
        }
    }

    eframe::run_native(
        friendlypass_gui::brand::NAME,
        native_options,
        Box::new(move |_cc| Ok(Box::new(friendlypass_gui::App::new(initial_db)))),
    )
}
