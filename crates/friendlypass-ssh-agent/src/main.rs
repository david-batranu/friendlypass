//! CLI: `friendlypass-ssh-agent <database.kdbx> [--socket <path>]` — unlock the
//! database and serve its SSH keys, like KeePassXC's SSH agent integration.

use anyhow::Result;
use keepass::DatabaseKey;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(db_path) = args.next() else {
        anyhow::bail!("usage: friendlypass-ssh-agent <database.kdbx> [--socket <path>]");
    };
    let socket_path = match (args.next().as_deref(), args.next()) {
        (Some("--socket"), Some(p)) => std::path::PathBuf::from(p),
        _ => friendlypass_ssh_agent::default_socket_path(),
    };

    // Read the password like keepassxc-cli: prompt on a TTY, one line from
    // stdin when piped.
    let password = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        rpassword::prompt_password("Enter password to unlock database: ")?
    } else {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };

    let mut file = std::fs::File::open(&db_path).unwrap();
    let key = DatabaseKey::new().with_password(&password);
    let db = keepass::Database::open(&mut file, key)
        .map_err(|e| anyhow::anyhow!("cannot unlock database (wrong password?): {e}"))?;

    let (pool, skipped) = friendlypass_ssh_agent::pool_from_database(&db);
    let identities = pool.lock().unwrap().clone();
    for note in &skipped {
        eprintln!("skipped: {note}");
    }
    if identities.is_empty() {
        anyhow::bail!("no SSH keys found in the database attachments");
    }

    let handle = friendlypass_ssh_agent::start(&socket_path, std::sync::Arc::clone(&pool))?;
    println!("Serving {} SSH key(s) on {}", identities.len(), handle.path().display());
    for identity in &identities {
        println!(
            "  ssh-ed25519 SHA256:{} {}",
            identity.fingerprint_sha256(),
            identity.comment
        );
    }
    println!("Use: export SSH_AUTH_SOCK={}", handle.path().display());
    println!("Press Ctrl+C to stop.");

    // Serve until interrupted.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
