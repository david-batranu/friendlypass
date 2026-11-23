//! `kpxc-gui` binary: the cross-platform (egui) GUI of the KeePassXC Rust
//! migration.

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
        Box::new(move |_cc| Ok(Box::new(kpxc_gui_egui::App::new(initial_db)))),
    )
}
