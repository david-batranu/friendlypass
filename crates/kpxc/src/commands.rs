//! Implementations of the `kpxc` commands, mirroring keepassxc-cli behavior.

use anyhow::{bail, Context, Result};
use keepass::config::{CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};
use keepass::db::{fields, Database, EntryRef, GroupId, GroupRef, Value};
use keepass::DatabaseKey;
use std::path::PathBuf;

use crate::cli::{DbArgs, DbCreateArgs};
use crate::key;
use crate::saveutil;

// ---------------------------------------------------------------------------
// db-create
// ---------------------------------------------------------------------------

pub fn db_create(args: DbCreateArgs, stdin_is_tty: bool) -> Result<()> {
    let path = &args.database;
    if path.exists() {
        bail!("database {} already exists", path.display());
    }

    let mut key = DatabaseKey::new();
    if args.set_password {
        let pw = key::read_new_password_confirm(stdin_is_tty)?;
        key = key.with_password(&pw);
    } else {
        println!("Note: creating a database without a password key.");
    }
    if let Some(secret) = &args.challenge_response {
        key = key::with_challenge_response(key, secret)?;
    }
    if let Some(kf) = &args.key_file {
        key::ensure_key_file(kf)?;
        let mut f = std::fs::File::open(kf)?;
        key = key.with_keyfile(&mut f)?;
    }
    if !args.set_password && args.key_file.is_none() {
        bail!("no key is set. Aborting database creation.");
    }

    // Configure the new database.
    let mut db = Database::new();
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.outer_cipher_config = parse_outer_cipher(&args.cipher)?;
    db.config.compression_config = parse_compression(&args.compression)?;
    db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    db.config.kdf_config = match args.kdf.as_str() {
        "argon2id" => KdfConfig::Argon2id {
            iterations: args.argon2_iterations,
            memory: args.argon2_memory_mib * 1024 * 1024,
            parallelism: args.argon2_parallelism,
            version: argon2::Version::Version13,
        },
        "argon2d" => KdfConfig::Argon2 {
            iterations: args.argon2_iterations,
            memory: args.argon2_memory_mib * 1024 * 1024,
            parallelism: args.argon2_parallelism,
            version: argon2::Version::Version13,
        },
        "aes" => KdfConfig::Aes {
            rounds: args.aes_rounds.unwrap_or(600_000),
        },
        other => bail!("unknown KDF {other:?} (use argon2id, argon2d or aes)"),
    };
    if let Some(name) = &args.name {
        db.meta.database_name = Some(name.clone());
    }

    saveutil::save(path, &db, key)?;
    println!("Successfully created new database {}.", path.display());
    Ok(())
}

fn parse_outer_cipher(s: &str) -> Result<OuterCipherConfig> {
    match s {
        "aes256" => Ok(OuterCipherConfig::AES256),
        "chacha20" => Ok(OuterCipherConfig::ChaCha20),
        "twofish" => Ok(OuterCipherConfig::Twofish),
        other => bail!("unknown cipher {other:?} (use aes256, chacha20 or twofish)"),
    }
}

fn parse_compression(s: &str) -> Result<CompressionConfig> {
    match s {
        "gzip" => Ok(CompressionConfig::GZip),
        "none" => Ok(CompressionConfig::None),
        other => bail!("unknown compression {other:?} (use gzip or none)"),
    }
}

// ---------------------------------------------------------------------------
// db-info
// ---------------------------------------------------------------------------

pub fn db_info(args: &DbArgs, key: DatabaseKey) -> Result<()> {
    let db = saveutil::open(&args.database, key)?;

    println!("Version:      {}", version_string(&db.config.version));
    println!("Cipher:       {}", outer_cipher_name(&db.config.outer_cipher_config));
    println!("Compression:  {}", compression_name(&db.config.compression_config));
    println!("Inner cipher: {}", inner_cipher_name(&db.config.inner_cipher_config));
    println!("KDF:          {}", kdf_name(&db.config.kdf_config));
    println!("Name:         {}", db.meta.database_name.as_deref().unwrap_or("(none)"));
    println!("Generator:    {}", db.meta.generator.as_deref().unwrap_or("(none)"));
    println!("Groups:       {}", db.num_groups());
    println!("Entries:      {}", db.num_entries());
    Ok(())
}

/// Human-readable database version string (shared with the GUI).
pub fn version_string(v: &DatabaseVersion) -> String {    match v {
        DatabaseVersion::KDB(_) => "KDB 1.x".into(),
        DatabaseVersion::KDB2(m) => format!("KDBX 2.{m}"),
        DatabaseVersion::KDB3(m) => format!("KDBX 3.{m}"),
        DatabaseVersion::KDB4(m) => format!("KDBX 4.{m}"),
    }
}

/// Human-readable outer cipher name (shared with the GUI).
pub fn outer_cipher_name(c: &OuterCipherConfig) -> &'static str {
    match c {
        OuterCipherConfig::AES256 => "AES 256-bit",
        OuterCipherConfig::Twofish => "Twofish 256-bit",
        OuterCipherConfig::ChaCha20 => "ChaCha20 256-bit",
        _ => "Unknown",
    }
}

/// Human-readable compression name (shared with the GUI).
pub fn compression_name(c: &CompressionConfig) -> &'static str {
    match c {
        CompressionConfig::None => "None",
        CompressionConfig::GZip => "GZip",
        _ => "Unknown",
    }
}

/// Human-readable inner cipher name (shared with the GUI).
pub fn inner_cipher_name(c: &InnerCipherConfig) -> &'static str {
    match c {
        InnerCipherConfig::Salsa20 => "Salsa20",
        InnerCipherConfig::ChaCha20 => "ChaCha20",
        _ => "Unknown",
    }
}

/// Human-readable KDF description (shared with the GUI).
pub fn kdf_name(k: &KdfConfig) -> String {
    match k {
        KdfConfig::Aes { rounds } => format!("AES-KDF ({rounds} rounds)"),
        KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            ..
        } => format!(
            "Argon2d ({iterations} iterations, {} MiB, {parallelism} lanes)",
            memory / 1024 / 1024
        ),
        KdfConfig::Argon2id {
            iterations,
            memory,
            parallelism,
            ..
        } => format!(
            "Argon2id ({iterations} iterations, {} MiB, {parallelism} lanes)",
            memory / 1024 / 1024
        ),
        _ => format!("{k:?}"),
    }
}

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

pub fn ls(args: &DbArgs, key: DatabaseKey) -> Result<()> {
    let db = saveutil::open(&args.database, key)?;

    let mut groups: Vec<String> = Vec::new();
    for group in db.iter_all_groups() {
        if group.parent().is_none() {
            continue; // skip the root group itself
        }
        groups.push(format!("{}/", group_path(&group)));
    }
    groups.sort();

    let mut entries: Vec<String> = Vec::new();
    for entry in db.iter_all_entries() {
        let path = group_path(&entry.parent());
        entries.push(entry_path(&path, entry.get(fields::TITLE).unwrap_or_default()));
    }
    entries.sort();

    for g in groups {
        println!("{g}");
    }
    for e in entries {
        println!("{e}");
    }
    Ok(())
}

/// Full path of a group ("Web/Sub"), excluding the root group itself.
/// Returns an empty string for the root group.
fn group_path(group: &GroupRef<'_>) -> String {
    let db = group.database();
    if group.parent().is_none() {
        return String::new();
    }
    let mut parts = vec![group.name.clone()];
    // Walk up the parent chain, collecting names of non-root ancestors.
    let mut current_id = group.id();
    while let Some(parent_id) = db
        .group(current_id)
        .and_then(|g| g.parent().map(|p| p.id()))
    {
        let parent = db.group(parent_id).expect("parent exists");
        if parent.parent().is_some() {
            parts.push(parent.name.clone());
        }
        current_id = parent_id;
    }
    parts.reverse();
    parts.join("/")
}

/// Join a group path and an entry title into an entry path.
fn entry_path(group_path: &str, title: &str) -> String {
    if group_path.is_empty() {
        title.to_string()
    } else {
        format!("{group_path}/{title}")
    }
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

pub fn show(args: &DbArgs, key: DatabaseKey, entry_title: &str, show_attributes: bool) -> Result<()> {
    let db = saveutil::open(&args.database, key)?;

    let mut found = 0;
    for entry in db.iter_all_entries() {
        if entry.get(fields::TITLE) == Some(entry_title) {
            found += 1;
            print_entry(&entry, show_attributes);
        }
    }
    if found == 0 {
        bail!("entry with title '{entry_title}' not found");
    }
    Ok(())
}

fn print_entry(entry: &EntryRef<'_>, show_attributes: bool) {
    println!("Title:    {}", entry.get(fields::TITLE).unwrap_or_default());
    println!("UserName: {}", entry.get(fields::USERNAME).unwrap_or_default());
    println!("Password: {}", entry.get(fields::PASSWORD).unwrap_or_default());
    println!("URL:      {}", entry.get(fields::URL).unwrap_or_default());
    println!("Notes:    {}", entry.get(fields::NOTES).unwrap_or_default());

    if !entry.tags.is_empty() {
        println!("Tags:     {}", entry.tags.join(", "));
    }

    for (name, attachment) in entry.attachments_named() {
        println!("Attachment: {name} ({} bytes)", attachment.data.get().len());
    }

    if show_attributes {
        for key in entry.fields.keys() {
            if !fields::KNOWN_FIELDS.contains(&key.as_str()) {
                println!("Attribute: {key} = {}", entry.get(key).unwrap_or_default());
            }
        }
    }
    println!();
}

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------

pub fn search(args: &DbArgs, key: DatabaseKey, term: &str) -> Result<()> {
    let db = saveutil::open(&args.database, key)?;
    let term = term.to_lowercase();

    let mut matches: Vec<String> = Vec::new();
    for entry in db.iter_all_entries() {
        let haystack = [
            entry.get(fields::TITLE).unwrap_or_default(),
            entry.get(fields::USERNAME).unwrap_or_default(),
            entry.get(fields::URL).unwrap_or_default(),
            entry.get(fields::NOTES).unwrap_or_default(),
        ]
        .concat()
        .to_lowercase();
        if haystack.contains(&term) {
            let path = group_path(&entry.parent());
            matches.push(entry_path(&path, entry.get(fields::TITLE).unwrap_or_default()));
        }
    }

    if matches.is_empty() {
        println!("No matches found.");
    } else {
        for m in matches {
            println!("{m}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// add / mkdir (modifying commands: open, edit, save)
// ---------------------------------------------------------------------------

pub fn add(
    args: &DbArgs,
    key: DatabaseKey,
    title: &str,
    username: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    group_path: Option<&str>,
    password_prompt: bool,
    generate: bool,
    length: usize,
    stdin_is_tty: bool,
) -> Result<()> {
    let mut db = saveutil::open(&args.database, key.clone())?;
    ensure_writable_version(&mut db);

    let mut entry_password = String::new();
    if password_prompt {
        entry_password = if stdin_is_tty {
            rpassword::prompt_password("Please enter the new password for the entry: ")?
        } else {
            key::read_password_stdin()?
        };
    } else if generate {
        entry_password = generate_password(length);
    }

    let root_id = db.root().id();
    let mut group_id = root_id;
    if let Some(gp) = group_path {
        group_id = find_or_create_group(&mut db, gp)?;
    }

    let mut group = db
        .group_mut(group_id)
        .ok_or_else(|| anyhow::anyhow!("group not found"))?;
    let mut entry = group.add_entry();
    entry.set_unprotected(fields::TITLE, title);
    if let Some(u) = username {
        entry.set_unprotected(fields::USERNAME, u);
    }
    if let Some(u) = url {
        entry.set_unprotected(fields::URL, u);
    }
    if let Some(n) = notes {
        entry.set_unprotected(fields::NOTES, n);
    }
    entry.set_protected(fields::PASSWORD, &entry_password);
    drop(entry);
    drop(group);

    saveutil::save(&args.database, &db, key)?;
    println!("Successfully added entry {title}.");
    Ok(())
}

pub fn mkdir(args: &DbArgs, key: DatabaseKey, group_path: &str) -> Result<()> {
    let mut db = saveutil::open(&args.database, key.clone())?;
    ensure_writable_version(&mut db);

    find_or_create_group(&mut db, group_path)?;

    saveutil::save(&args.database, &db, key)?;
    println!("Successfully added group {group_path}.");
    Ok(())
}

/// Walk (and create) a group path like "Web/Sub" from the root.
fn find_or_create_group(db: &mut Database, path: &str) -> Result<GroupId> {
    let mut current = db.root().id();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        let existing = db
            .group_mut(current)
            .ok_or_else(|| anyhow::anyhow!("group not found"))?
            .as_ref()
            .group_by_name(part)
            .map(|g| g.id());
        current = match existing {
            Some(id) => id,
            None => {
                let mut group = db.group_mut(current).unwrap();
                let mut child = group.add_group();
                child.name = part.to_string();
                child.id()
            }
        };
    }
    Ok(current)
}

/// Upgrade a KDBX3 database to KDBX 4.1 so that it can be saved.
/// (Public: the GUI reuses this for its save path.)
pub fn ensure_writable_version(db: &mut Database) {
    if !matches!(db.config.version, DatabaseVersion::KDB4(_)) {
        let old = version_string(&db.config.version);
        db.config.version = DatabaseVersion::KDB4(1);
        db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        eprintln!("Note: upgrading database from {old} to KDBX 4.1 for saving.");
    }
}

// ---------------------------------------------------------------------------
// attachment-export
// ---------------------------------------------------------------------------

pub fn attachment_export(
    args: &DbArgs,
    key: DatabaseKey,
    entry_title: &str,
    name: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let db = saveutil::open(&args.database, key)?;

    for entry in db.iter_all_entries() {
        if entry.get(fields::TITLE) == Some(entry_title) {
            if let Some(attachment) = entry.attachment_by_name(name) {
                let data: &Value<Vec<u8>> = &attachment.data;
                let out_path = output.unwrap_or_else(|| PathBuf::from(name));
                std::fs::write(&out_path, data.get())
                    .with_context(|| format!("unable to write {}", out_path.display()))?;
                println!("Successfully exported attachment {name} to {}.", out_path.display());
                return Ok(());
            }
        }
    }
    bail!("no attachment named {name:?} on entry {entry_title:?}");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Generate a random password from a printable alphabet.
pub fn generate_password(length: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = vec![0u8; length];
    getrandom::fill(&mut buf).expect("RNG failure");
    buf.iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

/// Generate a random password with configurable character classes
/// (used by the GUI's password generator dialog).
pub fn generate_password_opts(
    length: usize,
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
) -> String {
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";
    let mut alphabet: Vec<u8> = Vec::new();
    if upper {
        alphabet.extend_from_slice(UPPER);
    }
    if lower {
        alphabet.extend_from_slice(LOWER);
    }
    if digits {
        alphabet.extend_from_slice(DIGITS);
    }
    if symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }
    if alphabet.is_empty() {
        alphabet.extend_from_slice(LOWER);
    }
    let mut buf = vec![0u8; length];
    getrandom::fill(&mut buf).expect("RNG failure");
    buf.iter()
        .map(|b| alphabet[(*b as usize) % alphabet.len()] as char)
        .collect()
}
