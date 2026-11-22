//! Building the composite [`DatabaseKey`] from CLI arguments: password
//! prompt / stdin and optional key file — mirroring keepassxc-cli behavior.

use anyhow::{bail, Context, Result};
use keepass::DatabaseKey;
use std::path::Path;

use crate::cli::DbArgs;

/// Build the database key for opening an existing database.
pub fn build_key(db: &DbArgs, stdin_is_tty: bool) -> Result<DatabaseKey> {
    let mut key = DatabaseKey::new();

    if !db.no_password {
        let password = read_password(&db.database.display().to_string(), stdin_is_tty)?;
        key = key.with_password(&password);
    }

    if let Some(kf) = &db.key_file {
        let mut file = std::fs::File::open(kf)
            .with_context(|| format!("unable to open key file {}", kf.display()))?;
        key = key
            .with_keyfile(&mut file)
            .with_context(|| format!("unable to read key file {}", kf.display()))?;
    }

    if db.no_password && db.key_file.is_none() {
        anyhow::bail!("refusing to open with an empty key (use a password and/or key file)");
    }

    Ok(key)
}

/// Read the database password: from a hidden prompt on a TTY, or one line
/// from stdin when piped (like keepassxc-cli).
pub fn read_password(db_name: &str, stdin_is_tty: bool) -> Result<String> {
    if stdin_is_tty {
        rpassword::prompt_password(format!("Enter password to unlock {db_name}: "))
            .context("failed to read password")
    } else {
        read_password_stdin()
    }
}

/// Read a password from stdin (one line) when stdin is not a terminal.
pub fn read_password_stdin() -> Result<String> {
    use std::io::BufRead;
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line)?;
    if n == 0 {
        bail!("no password provided on stdin");
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Read a new password twice (with confirmation), for database creation.
pub fn read_new_password_confirm(stdin_is_tty: bool) -> Result<String> {
    if stdin_is_tty {
        let pw = rpassword::prompt_password("Enter password to encrypt database: ")
            .context("failed to read password")?;
        let pw2 = rpassword::prompt_password("Repeat password: ").context("failed to read password")?;
        if pw != pw2 {
            anyhow::bail!("passwords do not match");
        }
        Ok(pw)
    } else {
        // Piped: first line is the password, optional second line the repeat.
        let pw = read_password_stdin()?;
        use std::io::BufRead;
        let mut line2 = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line2);
        let line2 = line2.trim_end_matches(['\r', '\n']);
        if !line2.is_empty() && line2 != pw {
            anyhow::bail!("passwords do not match");
        }
        Ok(pw)
    }
}

/// Generate a KeePass 2 XML v2 key file (like keepassxc-cli) if it does not
/// exist yet. Returns the key file path.
pub fn ensure_key_file(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }

    use sha2::{Digest, Sha256};
    // 32 bytes of key data: KeePassXC uses the first 32 bytes of the decoded
    // data as the key element, while the keepass crate uses the whole array —
    // with exactly 32 bytes both agree.
    let mut key = vec![0u8; 32];
    getrandom::fill(&mut key).context("RNG failure")?;

    let checksum = Sha256::digest(&key);
    let hash_attr = hex::encode_upper(&checksum[..4]);

    // Pretty-printed uppercase hex, 8 chars per group / 32 per line.
    let hexkey = hex::encode_upper(&key);
    let mut data_text = String::new();
    for (i, ch) in hexkey.chars().enumerate() {
        if i > 0 && i % 32 == 0 {
            data_text.push_str("\n            ");
        } else if i > 0 && i % 8 == 0 {
            data_text.push(' ');
        }
        data_text.push(ch);
    }

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile>\n    <Meta>\n        <Version>2.0</Version>\n    </Meta>\n    <Key>\n        <Data Hash=\"{hash_attr}\">\n            {data_text}\n        </Data>\n    </Key>\n</KeyFile>\n"
    );

    std::fs::write(path, xml).with_context(|| format!("unable to write key file {}", path.display()))?;
    println!("Generated new key file {}", path.display());
    Ok(())
}
