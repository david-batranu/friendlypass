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

    // Optional: pass a database path as the first argument.
    let initial_db = std::env::args().nth(1);

    eframe::run_native(
        "KeePassXC-RS",
        native_options,
        Box::new(move |_cc| Ok(Box::new(kpxc_gui::App::new(initial_db)))),
    )
}
