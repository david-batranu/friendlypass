//! clap command-line definitions for `kpxc`.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Arguments shared by every command that opens a database.
#[derive(Args, Debug, Clone)]
pub struct DbArgs {
    /// Path of the database
    pub database: PathBuf,

    /// Key file of the database
    #[arg(short = 'k', long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Deactivate the password key for the database (use keyfile only)
    #[arg(long = "no-password")]
    pub no_password: bool,

    /// Local challenge-response secret (hex). This is the software equivalent
    /// of a YubiKey's HMAC-SHA1 challenge-response (the same construction
    /// KeePassXC uses); live USB YubiKey hardware is not supported.
    #[arg(long = "challenge-response")]
    pub challenge_response: Option<String>,
}

#[derive(Parser, Debug)]
#[command(
    name = "kpxc",
    version,
    about = "KeePassXC core engine + CLI, migrated to Rust",
    long_about = "A Rust migration of KeePassXC's headless core (keepassxc-cli functionality).\nBuilt on the `keepass` crate for KDBX parsing/writing."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new database
    DbCreate {
        #[command(flatten)]
        db: DbCreateArgs,
    },
    /// Show a database's information
    DbInfo {
        #[command(flatten)]
        db: DbArgs,
    },
    /// List database entries (recursively, with full paths)
    Ls {
        #[command(flatten)]
        db: DbArgs,
    },
    /// Show an entry's information
    Show {
        #[command(flatten)]
        db: DbArgs,

        /// Title of the entry to show
        entry: String,

        /// Also show non-standard attribute names
        #[arg(short = 'a', long)]
        show_attributes: bool,
    },
    /// Find entries quickly by matching the search term
    Search {
        #[command(flatten)]
        db: DbArgs,

        /// Search term
        term: String,
    },
    /// Add a new entry to a database
    Add {
        #[command(flatten)]
        db: DbArgs,

        /// Title of the new entry
        title: String,

        /// Username for the entry
        #[arg(short = 'u', long)]
        username: Option<String>,

        /// URL for the entry
        #[arg(short = 'U', long = "url")]
        url: Option<String>,

        /// Notes for the entry
        #[arg(long)]
        notes: Option<String>,

        /// Group to add the entry to (e.g. "Web/Sub"); default: root
        #[arg(long)]
        group: Option<String>,

        /// Prompt for the entry's password
        #[arg(short = 'p', long = "password-prompt")]
        password_prompt: bool,

        /// Generate a random password for the entry
        #[arg(short = 'g', long)]
        generate: bool,

        /// Length of the generated password
        #[arg(short = 'L', long, default_value = "24")]
        length: usize,
    },
    /// Adds a new group to a database
    Mkdir {
        #[command(flatten)]
        db: DbArgs,

        /// Path of the group to add (e.g. "Web/Sub")
        group: String,
    },
    /// Export the database to an unencrypted file (XML, CSV or HTML)
    Export {
        #[command(flatten)]
        db: DbArgs,

        /// Output format: xml (KeePass 2), csv or html
        #[arg(short = 'f', long, default_value = "xml")]
        format: String,
    },
    /// Import an XML/CSV/Bitwarden/1PUX/KDB/KDBX file into a new database
    Import {
        /// File to import
        source: PathBuf,

        /// Path of the new database
        database: PathBuf,

        /// Format (xml, csv, bitwarden, 1pux, kdb, kdbx); auto-detected by default
        #[arg(short = 'f', long)]
        format: Option<String>,

        /// Set (prompt for) a password for the new database
        #[arg(short = 'p', long = "set-password")]
        set_password: bool,

        /// Set (or create) a key file for the new database
        #[arg(short = 'k', long = "set-key-file")]
        key_file: Option<PathBuf>,
    },
    /// Export an attachment of an entry
    AttachmentExport {
        #[command(flatten)]
        db: DbArgs,

        /// Title of the entry
        entry: String,

        /// Name of the attachment
        name: String,

        /// Output file (defaults to the attachment name)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
pub struct DbCreateArgs {
    /// Path of the database to create
    pub database: PathBuf,

    /// Set a password for the database
    #[arg(short = 'p', long = "set-password")]
    pub set_password: bool,

    /// Set (or create, if missing) a key file for the database
    #[arg(short = 'k', long = "set-key-file")]
    pub key_file: Option<PathBuf>,

    /// Local challenge-response secret (hex): protects the database with an
    /// HMAC-SHA1 challenge-response component (the software equivalent of a
    /// YubiKey; live USB hardware is not supported).
    #[arg(long = "challenge-response")]
    pub challenge_response: Option<String>,

    /// Database name
    #[arg(long)]
    pub name: Option<String>,

    /// Key derivation function: argon2id (default), argon2d, or aes
    #[arg(long, default_value = "argon2id")]
    pub kdf: String,

    /// Outer cipher: aes256 (default), chacha20, or twofish
    #[arg(long, default_value = "aes256")]
    pub cipher: String,

    /// Compression: gzip (default) or none
    #[arg(long, default_value = "gzip")]
    pub compression: String,

    /// Argon2 iterations (time cost)
    #[arg(long, default_value = "10")]
    pub argon2_iterations: u64,

    /// Argon2 memory in MiB
    #[arg(long, default_value = "8")]
    pub argon2_memory_mib: u64,

    /// Argon2 parallelism (lanes)
    #[arg(long, default_value = "2")]
    pub argon2_parallelism: u32,

    /// AES-KDF rounds (with --kdf aes)
    #[arg(long)]
    pub aes_rounds: Option<u64>,
}
