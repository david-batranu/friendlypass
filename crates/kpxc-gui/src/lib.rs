//! `kpxc-gui` — the KeePassXC Rust migration's GUI, drawn with **BUI**
//! (Blender's UI, <https://github.com/ppmpreetham/BUI>).
//!
//! The state and file-format work live in [`state`]; [`ui`] builds the
//! Blender-styled widget tree with the `blenderui` crate. The headless
//! tests drive the same tree (element bounds, clicks, typing) and render
//! PNG screenshots from BUI's software rasterizer.

pub mod state;
pub mod ui;

pub use state::BuiApp;
