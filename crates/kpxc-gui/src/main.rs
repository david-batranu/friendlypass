//! `kpxc-gui` binary: the BUI (Blender UI) front-end.

use blenderui::prelude::*;
use kpxc_gui::BuiApp;

fn main() {
    // Optional database path as the first argument (prefills the form).
    let initial_db = std::env::args().nth(1);

    Application::new().run(move |cx| {
        let opts = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds {
                origin: point(px(0.0), px(0.0)),
                size: size(px(1200.0), px(800.0)),
            })),
            is_resizable: Some(true),
            window_min_size: Some(size(px(900.0), px(600.0))),
            ..Default::default()
        };
        cx.open_window(opts, move |_, cx| {
            let db = initial_db.clone();
            cx.new(|_| BuiApp::new(db))
        })
        .expect("open the BUI window");
    });
}
