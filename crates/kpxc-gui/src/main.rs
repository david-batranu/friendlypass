//! `kpxc-gui` binary: the cross-platform (egui) GUI of the KeePassXC Rust
//! migration.

// On Windows, release builds are GUI-subsystem binaries: launching the .exe
// does not open a console window. Debug builds keep the console for logs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1150.0, 720.0])
            .with_title("KeePassXC-RS"),
        ..Default::default()
    };

    // Startup helpers (used by the installer/Settings): write or remove the
    // login item without opening a window.
    let mut initial_db = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--enable-launch-at-login" => {
                match kpxc_gui::startup::set_launch_at_login(true) {
                    Ok(path) => println!("Launch at login enabled: {}", path.display()),
                    Err(e) => {
                        eprintln!("Unable to enable launch at login: {e:#}");
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
            "--disable-launch-at-login" => {
                match kpxc_gui::startup::set_launch_at_login(false) {
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
        "KeePassXC-RS",
        native_options,
        Box::new(move |_cc| Ok(Box::new(kpxc_gui::App::new(initial_db)))),
    )
}
