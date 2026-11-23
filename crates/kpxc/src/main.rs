//! `kpxc` binary entry point: parse arguments and dispatch to commands.

use clap::Parser;
use std::io::IsTerminal;

use kpxc::cli::{Cli, Command};
use kpxc::{commands, key};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let stdin_is_tty = std::io::stdin().is_terminal();

    match cli.command {
        Command::DbCreate { db } => commands::db_create(db, stdin_is_tty),
        Command::DbInfo { db } => {
            let key = key::build_key(&db, stdin_is_tty)?;
            commands::db_info(&db, key)
        }
        Command::Ls { db } => {
            let key = key::build_key(&db, stdin_is_tty)?;
            commands::ls(&db, key)
        }
        Command::Show {
            db,
            entry,
            show_attributes,
        } => {
            let key = key::build_key(&db, stdin_is_tty)?;
            commands::show(&db, key, &entry, show_attributes)
        }
        Command::Search { db, term } => {
            let key = key::build_key(&db, stdin_is_tty)?;
            commands::search(&db, key, &term)
        }
        Command::Add {
            db,
            title,
            username,
            url,
            notes,
            group,
            password_prompt,
            generate,
            length,
        } => {
            let key = key::build_key(&db, stdin_is_tty)?;
            commands::add(
                &db,
                key,
                &title,
                username.as_deref(),
                url.as_deref(),
                notes.as_deref(),
                group.as_deref(),
                password_prompt,
                generate,
                length,
                stdin_is_tty,
            )
        }
        Command::Mkdir { db, group } => {
            let key = key::build_key(&db, stdin_is_tty)?;
            commands::mkdir(&db, key, &group)
        }
        Command::Export { db, format } => {
            let key = key::build_key(&db, stdin_is_tty)?;
            commands::export(&db, key, &format)
        }
        Command::Import {
            source,
            database,
            format,
            set_password,
            key_file,
        } => commands::import(&source, &database, format.as_deref(), set_password, key_file, stdin_is_tty),
        Command::AttachmentExport {
            db,
            entry,
            name,
            output,
        } => {
            let key = key::build_key(&db, stdin_is_tty)?;
            commands::attachment_export(&db, key, &entry, &name, output)
        }
    }
}
