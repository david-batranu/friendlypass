//! KeePass 1.x (KDB) importer.
//!
//! The KDB container is the original KeePass format: a fixed header, an
//! AES-256-CBC encrypted stream (the whole body, no inner cipher), and a
//! field-based group/entry serialization. KeePassXC reads it through
//! `KeePass1Reader`; this is a Rust port of the parts needed to convert a
//! KDB database into the `keepass` crate's model.
//!
//! Supported: AES-256 KDB (the common case). Twofish KDB is reported as
//! unsupported.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use aes::cipher::{BlockDecryptMut, BlockEncrypt, KeyInit, KeyIvInit};
use twofish::Twofish;
use aes::Aes256;
use anyhow::{bail, Context, Result};
use cbc::cipher::block_padding::Pkcs7;
use chrono::NaiveDateTime;
use keepass::db::{fields, AutoType, AutoTypeAssociation, Database, Icon, Times, Value};
use sha2::{Digest, Sha256};

const SIGNATURE_1: u32 = 0x9AA2_D903;
const SIGNATURE_2: u32 = 0xB54B_FB65;
const FILE_VERSION: u32 = 0x0003_0002;
const FILE_VERSION_CRITICAL_MASK: u32 = 0xFFFF_FF00;

/// Import a KeePass 1.x KDB database protected by `password`.
pub fn import_kdb(bytes: &[u8], password: &str) -> Result<Database> {
    let mut r = Cursor::new(bytes);
    let sig1 = read_u32(&mut r)?;
    let sig2 = read_u32(&mut r)?;
    if sig1 != SIGNATURE_1 || sig2 != SIGNATURE_2 {
        bail!("KDB import: not a KeePass 1 database");
    }
    let flags = read_u32(&mut r)?;
    let version = read_u32(&mut r)?;
    if version & FILE_VERSION_CRITICAL_MASK != FILE_VERSION & FILE_VERSION_CRITICAL_MASK {
        bail!("KDB import: unsupported KeePass 1 database version {version:#010x}");
    }
    let twofish = flags & 0x8 != 0;
    if flags & 0x2 == 0 && !twofish {
        bail!("KDB import: unknown encryption (expected AES-256 or Twofish)");
    }

    let mut master_seed = [0u8; 16];
    r.read_exact(&mut master_seed)?;
    let mut iv = [0u8; 16];
    r.read_exact(&mut iv)?;
    let num_groups = read_u32(&mut r)?;
    let num_entries = read_u32(&mut r)?;
    let mut content_hash = [0u8; 32];
    r.read_exact(&mut content_hash)?;
    let mut transform_seed = [0u8; 32];
    r.read_exact(&mut transform_seed)?;
    let rounds = read_u32(&mut r)?;

    let content_pos = r.position() as usize;
    let master_key = derive_key(password, &master_seed, &transform_seed, rounds);

    // AES-256-CBC decrypt the rest of the file.
    let mut buf = bytes[content_pos..].to_vec();
    if buf.is_empty() || buf.len() % 16 != 0 {
        bail!("KDB import: invalid encrypted content length");
    }
    let plain: Vec<u8> = if twofish {
        let cipher = cbc::Decryptor::<twofish::Twofish>::new(&master_key.into(), &iv.into());
        cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| anyhow::anyhow!("KDB import: wrong password or corrupted database"))?
            .to_vec()
    } else {
        let cipher = cbc::Decryptor::<Aes256>::new(&master_key.into(), &iv.into());
        cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| anyhow::anyhow!("KDB import: wrong password or corrupted database"))?
            .to_vec()
    };

    if Sha256::digest(&plain).as_slice() != content_hash {
        bail!("KDB import: wrong password or corrupted database (content hash mismatch)");
    }

    let mut s = Cursor::new(plain.as_slice());
    let mut groups = Vec::with_capacity(num_groups as usize);
    for _ in 0..num_groups {
        groups.push(read_group(&mut s)?);
    }
    let mut entries = Vec::with_capacity(num_entries as usize);
    for _ in 0..num_entries {
        entries.push(read_entry(&mut s)?);
    }

    build_database(groups, entries)
}

fn derive_key(password: &str, master_seed: &[u8; 16], transform_seed: &[u8; 32], rounds: u32) -> [u8; 32] {
    // KeePass 1: composite key = SHA256(password), transformed with AES-256
    // ECB under the transform seed, then SHA256(master_seed || transformed).
    let composite = Sha256::digest(password.as_bytes());
    let mut block1 = [0u8; 16];
    let mut block2 = [0u8; 16];
    block1.copy_from_slice(&composite[..16]);
    block2.copy_from_slice(&composite[16..]);
    let aes = Aes256::new(transform_seed.into());
    for _ in 0..rounds {
        let mut b1 = aes::Block::clone_from_slice(&block1);
        let mut b2 = aes::Block::clone_from_slice(&block2);
        aes.encrypt_block(&mut b1);
        aes.encrypt_block(&mut b2);
        block1.copy_from_slice(&b1);
        block2.copy_from_slice(&b2);
    }
    // KeePassXC hashes the transformed key again before combining it with
    // the master seed.
    let mut transformed = Sha256::new();
    transformed.update(block1);
    transformed.update(block2);
    let transformed = transformed.finalize();
    let mut hasher = Sha256::new();
    hasher.update(master_seed);
    hasher.update(transformed);
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

#[derive(Default, Clone)]
struct KdbGroup {
    source_id: u32,
    level: u16,
    name: String,
    icon: usize,
    times: Times,
}

struct KdbEntry {
    group_id: u32,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    icon: usize,
    tags: Vec<String>,
    times: Times,
    fields: Vec<(String, String, bool)>,
    binaries: Vec<(String, Vec<u8>)>,
    autotype_sequence: Option<String>,
    autotype_windows: Vec<(String, String)>,
}

fn read_group(r: &mut Cursor<&[u8]>) -> Result<KdbGroup> {
    let mut group = KdbGroup::default();
    let mut level_set = false;
    loop {
        let field_type = read_u16(r)?;
        let data = read_field(r)?;
        if field_type == 0xFFFF {
            break;
        }
        match field_type {
            0x0001 => group.source_id = le_u32(&data)?,
            0x0002 => group.name = kdb_text(&data),
            0x0003 => set_time(&mut group.times, &data, |t, v| t.creation = Some(v)),
            0x0004 => set_time(&mut group.times, &data, |t, v| t.last_modification = Some(v)),
            0x0005 => set_time(&mut group.times, &data, |t, v| t.last_access = Some(v)),
            0x0006 => set_time(&mut group.times, &data, |t, v| {
                t.expiry = v;
                t.expires = Some(true);
            }),
            0x0007 => group.icon = le_u32(&data)? as usize,
            0x0008 => {
                group.level = le_u16(&data)?;
                level_set = true;
            }
            0x0009 | 0x0000 => {}
            _ => bail!("KDB import: unknown group field {field_type:#06x}"),
        }
    }
    if !level_set {
        bail!("KDB import: group without a level");
    }
    Ok(group)
}

fn read_entry(r: &mut Cursor<&[u8]>) -> Result<KdbEntry> {
    let mut e = KdbEntry {
        group_id: 0,
        title: String::new(),
        username: String::new(),
        password: String::new(),
        url: String::new(),
        notes: String::new(),
        icon: 0,
        tags: Vec::new(),
        times: Times::new(),
        fields: Vec::new(),
        binaries: Vec::new(),
        autotype_sequence: None,
        autotype_windows: Vec::new(),
    };
    let mut binary_name = String::new();
    loop {
        let field_type = read_u16(r)?;
        let data = read_field(r)?;
        if field_type == 0xFFFF {
            break;
        }
        let text = || kdb_text(&data);
        match field_type {
            0x0001 | 0x0000 => {}
            0x0002 => e.group_id = le_u32(&data)?,
            0x0003 => e.icon = le_u32(&data)? as usize,
            0x0004 => e.title = text(),
            0x0005 => e.url = text(),
            0x0006 => e.username = text(),
            0x0007 => e.password = text(),
            0x0008 => e.notes = text(),
            0x0009 => set_time(&mut e.times, &data, |t, v| t.creation = Some(v)),
            0x000A => set_time(&mut e.times, &data, |t, v| t.last_modification = Some(v)),
            0x000B => set_time(&mut e.times, &data, |t, v| t.last_access = Some(v)),
            0x000C => set_time(&mut e.times, &data, |t, v| {
                t.expiry = v;
                t.expires = Some(true);
            }),
            0x000D => binary_name = text(),
            0x000E => {
                if !data.is_empty() {
                    e.binaries.push((binary_name.clone(), data));
                }
            }
            _ => bail!("KDB import: unknown entry field {field_type:#06x}"),
        }
    }
    parse_autotype(&mut e);
    Ok(e)
}

/// KeePass 1 stored auto-type associations as lines in the notes field.
fn parse_autotype(entry: &mut KdbEntry) {
    let mut notes = Vec::new();
    let mut last_was_autotype = false;
    for line in entry.notes.split('\n') {
        let line = line.trim_end_matches('\r');
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("auto-type-window: ") {
            let original = &line[line.len() - rest.len()..];
            let (window, sequence) = match rest.split_once(" | ") {
                Some((w, seq)) => (
                    original[..w.len()].to_owned(),
                    original[w.len() + 3..].to_owned(),
                ),
                None => (original.to_owned(), String::new()),
            };
            entry.autotype_windows.push((window, sequence));
            last_was_autotype = true;
        } else if let Some(rest) = lower.strip_prefix("auto-type: ") {
            entry.autotype_sequence = Some(line[line.len() - rest.len()..].to_owned());
            last_was_autotype = true;
        } else {
            if !last_was_autotype || !line.is_empty() {
                notes.push(line.to_owned());
            }
            last_was_autotype = false;
        }
    }
    entry.notes = notes.join("\n");
}

fn build_database(groups: Vec<KdbGroup>, entries: Vec<KdbEntry>) -> Result<Database> {
    let mut db = Database::new();
    db.meta.database_name = Some("Imported KeePass 1".into());
    // KeePassXC wraps the KDB group list in a synthetic root named "Root";
    // every KDB group (including level 0) is a child of it.
    let root_id = db.root().id();
    db.root_mut().name = "Root".into();
    let mut group_ids: HashMap<u32, keepass::db::GroupId> = HashMap::new();
    let mut level_stack: Vec<(i32, keepass::db::GroupId)> = vec![(-1, root_id)];
    for group in &groups {
        while level_stack
            .last()
            .is_some_and(|(level, _)| *level >= group.level as i32)
        {
            level_stack.pop();
        }
        let parent = level_stack.last().map(|(_, id)| *id).unwrap_or(root_id);
        let gid = {
            let Some(mut parent_mut) = db.group_mut(parent) else {
                continue;
            };
            let mut g = parent_mut.add_group();
            g.name = group.name.clone();
            g.times = group.times.clone();
            g.set_icon_builtin(group.icon);
            g.id()
        };
        group_ids.insert(group.source_id, gid);
        level_stack.push((group.level as i32, gid));
    }

    for entry in entries {
        if is_meta_stream(&entry) {
            continue;
        }
        let gid = group_ids
            .get(&entry.group_id)
            .copied()
            .unwrap_or(root_id);
        let Some(mut group) = db.group_mut(gid) else {
            continue;
        };
        let mut e = group.add_entry();
        e.set_unprotected(fields::TITLE, entry.title);
        e.set_unprotected(fields::USERNAME, entry.username);
        e.set_protected(fields::PASSWORD, entry.password);
        e.set_unprotected(fields::URL, entry.url);
        e.set_unprotected(fields::NOTES, entry.notes);
        e.tags = entry.tags;
        e.times = entry.times;
        e.set_icon_builtin(entry.icon);
        if entry.autotype_sequence.is_some() || !entry.autotype_windows.is_empty() {
            e.autotype = Some(AutoType {
                enabled: true,
                default_sequence: entry.autotype_sequence,
                data_transfer_obfuscation: keepass::db::DataTransferObfuscation::None,
                associations: entry
                    .autotype_windows
                    .into_iter()
                    .map(|(window, sequence)| AutoTypeAssociation { window, sequence })
                    .collect(),
            });
        }
        for (name, data) in entry.binaries {
            e.add_attachment(name, Value::<Vec<u8>>::unprotected(data));
        }
    }
    Ok(db)
}

/// KeePassXC hides its KeePass 1 meta streams (templates and custom icons):
/// they are entries titled "Meta-Info" with a `bin-stream` attachment.
fn is_meta_stream(entry: &KdbEntry) -> bool {
    entry.title == "Meta-Info"
        && entry.username == "SYSTEM"
        && entry.url == "$"
        && entry.icon == 0
        && !entry.notes.is_empty()
        && entry.binaries.iter().any(|(name, _)| name == "bin-stream")
}

fn set_time(times: &mut Times, data: &[u8], set: impl FnOnce(&mut Times, NaiveDateTime)) {
    if let Some(time) = packed_time(data) {
        set(times, time);
    }
}

/// KeePass 1's 5-byte packed timestamp.
fn packed_time(data: &[u8]) -> Option<NaiveDateTime> {
    if data.len() != 5 {
        return None;
    }
    let d1 = data[0] as u32;
    let d2 = data[1] as u32;
    let d3 = data[2] as u32;
    let d4 = data[3] as u32;
    let d5 = data[4] as u32;
    let year = (d1 << 6) | (d2 >> 2);
    let month = ((d2 & 0x3) << 2) | (d3 >> 6);
    let day = (d3 >> 1) & 0x1F;
    let hour = ((d3 & 0x1) << 4) | (d4 >> 4);
    let minute = ((d4 & 0xF) << 2) | (d5 >> 6);
    let second = d5 & 0x3F;
    if year == 2999 && month == 12 && day == 28 {
        return None; // KeePass's "never"
    }
    chrono::NaiveDate::from_ymd_opt(year as i32, month, day)
        .and_then(|d| d.and_hms_opt(hour, minute, second))
}

fn read_u16(r: &mut Cursor<&[u8]>) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf).context("KDB import: truncated field")?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(r: &mut Cursor<&[u8]>) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).context("KDB import: truncated header")?;
    Ok(u32::from_le_bytes(buf))
}

fn read_field(r: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let size = read_u32(r)? as usize;
    if size > 64 * 1024 * 1024 {
        bail!("KDB import: invalid field size");
    }
    let mut data = vec![0u8; size];
    r.read_exact(&mut data)
        .context("KDB import: truncated field data")?;
    Ok(data)
}

/// KDB strings are NUL-terminated; drop the terminator like KeePassXC's
/// `QString::fromUtf8(constData())` does.
fn kdb_text(data: &[u8]) -> String {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn le_u16(data: &[u8]) -> Result<u16> {
    if data.len() < 2 {
        bail!("KDB import: short field");
    }
    Ok(u16::from_le_bytes([data[0], data[1]]))
}

fn le_u32(data: &[u8]) -> Result<u32> {
    if data.len() < 4 {
        bail!("KDB import: short field");
    }
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}
