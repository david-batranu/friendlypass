//! `kpxc-gui` — the cross-platform (egui) GUI of the KeePassXC Rust
//! migration.
//!
//! Feature set mirrors KeePassXC's core GUI flow: unlock screen (password +
//! key file), group tree, entry list, search, entry details with clipboard
//! actions, entry/group editing with history, password generator, database
//! info, save / save-as (with KDBX 3 → 4.1 upgrade), new database creation,
//! and lock.
//!
//! The GUI is a thin layer over the same engine used by the `kpxc` CLI (the
//! `keepass` crate) — all file-format behavior is shared and verified by the
//! existing 13 integration tests + `verify.sh`.

pub mod app;
pub mod autotype;
pub mod browser;
pub mod dialogs;
pub mod icons;
pub mod refs;
pub mod totp;

pub use app::App;
