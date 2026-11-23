//! `friendlypass-gui` — the cross-platform (egui) GUI of friendlypass.
//!
//! Feature set mirrors KeePassXC's core GUI flow: unlock screen (password +
//! key file), group tree, entry list, search, entry details with clipboard
//! actions, entry/group editing with history, password generator, database
//! info, save / save-as (with KDBX 3 → 4.1 upgrade), new database creation,
//! and lock.
//!
//! The GUI is a thin layer over the same engine used by the `friendlypass`
//! CLI and the `keepass` crate — all file-format behavior is shared and
//! verified by the existing 13 integration tests + `verify.sh`.

pub mod app;
pub mod autotype;
pub mod brand;
pub mod browser;
pub mod clipboard;
pub mod config;
pub mod dialogs;
pub mod icons;
pub mod refs;
pub mod startup;
pub mod theme;
pub mod totp;

pub use app::App;
