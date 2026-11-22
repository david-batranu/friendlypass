# keepassxc-rs

**KeePassXC, migrated to Rust** — the headless core *and* a cross-platform
GUI, composing the Rust ecosystem instead of rewriting existing
functionality.

The original C++ lives in `../keepassxc` (cloned from
https://github.com/keepassxreboot/keepassxc). This folder contains the Rust
migration.

## What it does

`kpxc` (the binary) is a drop-in-style replacement for the core
`keepassxc-cli` commands:

| command             | keepassxc-cli equivalent | notes                                     |
|---------------------|--------------------------|-------------------------------------------|
| `db-create`         | `db-create`              | KDBX 4.1; Argon2id/Argon2d/AES-KDF; AES256/ChaCha20/Twofish; GZip/none; optional generated `.keyx` keyfile |
| `db-info`           | `db-info`                | version, cipher, KDF, compression, counts |
| `ls`                | `ls -f`                  | recursive listing with full paths         |
| `show`              | `show`                   | decodes protected fields (`-a`: extra attributes) |
| `search`            | `search`                 | title/username/URL/notes matching        |
| `add`               | `add`                    | prompts / generates entry passwords      |
| `mkdir`             | `mkdir`                  | nested paths (`Web/Sub`)                 |
| `attachment-export` | `attachment-export`     | byte-identical export                    |

Passwords are read from a hidden prompt on a TTY, or one line from stdin when
piped (same convention as keepassxc-cli: `printf 'pw\n' | kpxc ls db.kdbx`).

Modifying a KDBX 3.x database transparently upgrades it to KDBX 4.1 on save
(the `keepass` writer supports KDBX 4), which is also KeePassXC's
modernization direction. Saves are atomic (temp file + rename).

## Architecture: built on existing crates

Per the project requirement, existing Rust packages provide the engine
layers; this project is the behavior/compatibility layer on top:

* [`keepass`](https://crates.io/crates/keepass) 0.17 — KDBX 3.1/4.0/4.1
  container parsing **and** writing, Argon2d/Argon2id and AES-KDF, AES-256 /
  Twofish / ChaCha20 outer ciphers, Salsa20/ChaCha20 inner streams, GZip,
  XML v1/v2 keyfiles, the XML document model.
* `clap` — CLI; `rpassword` — prompts; `rust-argon2` — KDF parameter types;
  `sha2`/`getrandom` — keyfile generation; `anyhow` — errors.
* `kpxc` itself contributes the keepassxc-cli-compatible commands, the
  KeePassXC-compatible XML-v2 keyfile *generator* (with the correct Hash
  attribute and 32-byte key data so KeePassXC and keepass-rs agree),
  password generation, the KDBX3→4.1 upgrade-on-save, atomic writes, and
  friendly credential errors.

## Compatibility, verified

`./verify.sh` runs the full cross-check against the **real KeePassXC
2.8.0** (`keepassxc-cli`):

1. every fixture created by keepassxc-cli opens in `kpxc` — KDBX 3.1
   (AES256, AES-KDF up to 14.3M rounds, Salsa20 inner stream, attachments,
   keyfiles, empty password, non-ASCII password) and KDBX 4.0 (ChaCha20);
2. databases created *and modified* by `kpxc` open in keepassxc-cli, across
   all cipher/KDF/compression variants;
3. a KDBX 3.1 database upgraded to 4.1 by `kpxc` opens in keepassxc-cli with
   all entries and attachments intact;
4. attachments and generated keyfiles round-trip byte-identically;
5. `cargo test --release` — 13 integration tests over the same fixtures.

Current result: **20/20 checks, 13/13 tests.**

## Layout

```
crates/kpxc/          the CLI + library (commands, key handling, save logic)
crates/kpxc-gui/      the cross-platform GUI (egui) + headless UI tests
crates/kpxc/tests/    integration tests against the fixtures
fixtures/             real .kdbx files (see passwords below)
verify.sh             end-to-end Rust <=> KeePassXC cross-verification
../keepassxc/         the original C++ (reference clone)
```

## Fixture passwords

| file                 | password        | created by                    |
|----------------------|-----------------|-------------------------------|
| `sample4*.kdbx`      | `testpassword`  | keepassxc-cli 2.8.0           |
| `sample4.keyx`       | — (keyfile)     | keepassxc-cli 2.8.0           |
| `Format400.kdbx`     | `t`             | KeePassXC repo test data     |
| `Compressed.kdbx`    | *(empty)*       | KeePassXC repo test data     |
| `NonAscii.kdbx`      | `Δöض`           | KeePassXC repo test data     |
| `ProtectedStrings.kdbx` | `masterpw`   | KeePassXC repo test data     |

## Usage

```console
$ cargo build --release
$ printf 'mypw\n' | target/release/kpxc ls fixtures/sample4.kdbx
Bank/
Web/
Sample Entry
Web Login
$ printf 'mypw\n' | target/release/kpxc show fixtures/sample4.kdbx "Sample Entry"
Title:    Sample Entry
UserName: user@example.com
...
```

## GUI (`kpxc-gui`)

`cargo run --release -p kpxc-gui -- [database.kdbx]` launches the
cross-platform GUI (egui/eframe — pure Rust, runs on macOS, Windows and
Linux). It mirrors KeePassXC's core GUI workflow:

* **Unlock screen** — database file, password (Enter to unlock), optional
  key file, friendly error reporting for bad credentials
* **Group tree** — navigate, add / rename / delete groups
* **Entry table** — sortable columns (Title / UserName / Password / URL /
  Notes / Tags), password masking with a global reveal toggle,
  double-click to edit, search across all groups
* **Entry details** — copy username / password / URL to the clipboard,
  attachments with export, edit, delete
* **Entry editor** — full field editing with a built-in password
  generator and reveal toggle; edits record entry history like KeePassXC
* **Password generator dialog** — length, character classes, preview,
  copy to clipboard
* **Save / Save As** — with the KDBX 3.1 → 4.1 upgrade dialog
  (Cmd/Ctrl+S shortcut), atomic writes
* **Create new database** — Argon2id parameters, optional generated
  keyfile
* **Database info** dialog, **lock** button

The GUI is tested **headlessly with `egui_kittest`**
(`cargo test -p kpxc-gui`): the tests drive the real `eframe` app by
clicking widgets and typing text, assert on the rendered UI and app
state, and produce image snapshots of the actual UI in
`crates/kpxc-gui/tests/snapshots/`. One test creates and saves a
database entirely through the GUI dialogs, which the original C++
`keepassxc-cli 2.8.0` then opens successfully (`verify.sh`, section 7).

## Status & scope

Migrated and verified: the headless core (database open/save, all cipher and
KDF variants, entries/groups/attachments/protected fields, CLI commands
above) and the GUI workflow described above — verified against KeePassXC
2.8.0 in both directions (`./verify.sh`: 23/23 checks, 18+5 tests).

Not migrated (out of scope for this migration): browser integration, SSH
agent, KeeShare, auto-type window matching, and challenge-response
(YubiKey) keys. The GUI covers the core workflow; advanced KeePassXC GUI
features (icons editor, custom attribute editor, multi-selection, drag &
drop, referencer/entry references) are not yet implemented.
