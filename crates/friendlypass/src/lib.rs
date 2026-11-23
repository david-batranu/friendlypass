//! `friendlypass` — friendlypass core engine and CLI.
//!
//! A pragmatic Rust reimplementation of KeePassXC's headless core (the
//! `keepassxc-cli` functionality), built on existing crates wherever they
//! provide the functionality, and the engine behind the friendlypass GUI:
//!
//! * KDBX 3.1/4.0/4.1 container parsing and writing, Argon2/AES-KDF key
//!   derivation, AES/Twofish/ChaCha20 ciphers, keyfile handling — the
//!   [`keepass`] crate.
//! * CLI parsing — [`clap`]; password prompts — [`rpassword`].
//! * This crate provides the behavior layer: keepassxc-cli-compatible
//!   commands (`db-create`, `db-info`, `ls`, `show`, `search`, `add`,
//!   `mkdir`, `attachment-export`), KeePassXC-compatible XML-v2 keyfile
//!   generation, password generation, KDBX3→KDBX4.1 upgrade-on-save, and
//!   atomic database writes.
//!
//! Verified against KeePassXC 2.8.0 itself: databases created by
//! `keepassxc-cli` open here, and databases written here open in
//! `keepassxc-cli` (see `verify.sh`).

/// Product name stamped into files this crate writes (export `Generator`,
/// KeeShare signer, user agent).
pub const PRODUCT_NAME: &str = "friendlypass";

pub mod cli;
pub mod commands;
pub mod export;
pub mod import;
pub mod kdb;
pub mod keeshare;
pub mod keeshare_signed;
pub mod key;
pub mod saveutil;
