//! Import/export tests: our KeePass 2 XML export must be readable by our
//! importer (and by `keepassxc-cli`, cross-checked in verify.sh), CSV must
//! match KeePassXC's layout, and the Bitwarden/1PUX importers must map
//! logins, folders, notes and custom fields.

use std::io::Write;
use std::path::{Path, PathBuf};

use keepass::db::{fields, Database};
use keepass::DatabaseKey;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn sample() -> Database {
    let key = DatabaseKey::new().with_password("testpassword");
    kpxc::saveutil::open(&fixture("sample4.kdbx"), key).unwrap()
}

fn find<'a>(db: &'a Database, title: &str) -> keepass::db::EntryRef<'a> {
    db.iter_all_entries()
        .find(|e| e.get(fields::TITLE) == Some(title))
        .unwrap_or_else(|| panic!("entry {title:?}"))
}

#[test]
fn xml_roundtrip_preserves_entries_fields_and_attachments() {
    let db = sample();
    let xml = kpxc::export::export_xml(&db).unwrap();
    assert!(xml.starts_with("<?xml version=\"1.0\""));
    assert!(xml.contains("<KeePassFile>"));
    assert!(xml.contains("<Group>"));
    assert!(xml.contains("<String>"));

    let imported = kpxc::import::import_xml(xml.as_bytes()).unwrap();
    assert_eq!(
        imported.iter_all_entries().count(),
        db.iter_all_entries().count()
    );

    let entry = find(&imported, "Sample Entry");
    assert_eq!(entry.get(fields::USERNAME), Some("user@example.com"));
    assert_eq!(entry.get(fields::PASSWORD), Some("YvWQMCdkU9NkwU5cEHsj"));
    assert_eq!(entry.get(fields::URL), Some("https://example.com"));
    assert_eq!(entry.get(fields::NOTES), Some("some notes"));

    // Attachments survive via Meta/Binaries + Binary Ref.
    let attachments: Vec<(&str, Vec<u8>)> = entry
        .attachments_named()
        .map(|(name, a)| (name, a.data.get().clone()))
        .collect();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].0, "attach.txt");
    assert_eq!(attachments[0].1, b"Content\n");

    // Groups survive too.
    assert!(imported
        .root()
        .groups()
        .any(|g| g.name == "Web" || g.name == "Bank"));
    // Passwords stay protected in the imported database model.
    let current = imported.entry(entry.id()).unwrap();
    let raw = current.fields.get(fields::PASSWORD).unwrap();
    assert!(raw.is_protected());
}

#[test]
fn xml_export_can_be_read_by_keepassxc_cli_layout() {
    // The structural elements keepassxc-cli's XML reader requires.
    let xml = kpxc::export::export_xml(&sample()).unwrap();
    for element in [
        "<Meta>",
        "<Generator>",
        "<MemoryProtection>",
        "<RecycleBinEnabled>",
        "<Root>",
        "<UUID>",
        "<Times>",
        "<Entry>",
        "<String>",
        "<Key>Title</Key>",
        "<AutoType>",
        "<History>",
    ] {
        assert!(xml.contains(element), "missing {element}");
    }
}

#[test]
fn csv_export_matches_keepassxc_layout_and_roundtrips() {
    let csv = kpxc::export::export_csv(&sample());
    let mut lines = csv.lines();
    assert_eq!(
        lines.next().unwrap(),
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\""
    );
    assert!(csv.contains(
        "\"Passwords\",\"Sample Entry\",\"user@example.com\",\"YvWQMCdkU9NkwU5cEHsj\",\"https://example.com\",\"some notes\",\"\",\"0\""
    ));

    let imported = kpxc::import::import_csv(csv.as_bytes()).unwrap();
    let entry = find(&imported, "Sample Entry");
    assert_eq!(entry.get(fields::USERNAME), Some("user@example.com"));
    assert_eq!(entry.get(fields::PASSWORD), Some("YvWQMCdkU9NkwU5cEHsj"));
    assert_eq!(entry.get(fields::URL), Some("https://example.com"));
    // The CSV's root group ("Passwords") is the new database's root, so the
    // entries are top-level rather than nested one level down.
    assert_eq!(imported.root().entries().count(), 2);
    assert_eq!(imported.root().name, "Passwords");
}

#[test]
fn csv_import_accepts_common_exports_and_custom_columns() {
    let csv = b"Title,Username,Password,URL,Notes,Folder,Extra\n\
                Mail,me@example.org,secret,https://mail.example,Fallback,,Recovery codes\n\
                Router,admin,adminpw,http://192.168.1.1,,Network,\n";
    let imported = kpxc::import::import_csv(csv).unwrap();
    assert_eq!(imported.iter_all_entries().count(), 2);
    let mail = find(&imported, "Mail");
    assert_eq!(mail.get(fields::USERNAME), Some("me@example.org"));
    assert_eq!(mail.get("Extra"), Some("Recovery codes"));
    assert!(imported
        .root()
        .groups()
        .any(|g| g.name == "Network"));
}

#[test]
fn bitwarden_json_import_maps_folders_logins_and_fields() {
    let json = br#"{
        "encrypted": false,
        "folders": [{"id": "f1", "name": "Work"}],
        "items": [
            {
                "type": 1,
                "name": "GitHub",
                "notes": "2FA enabled",
                "folderId": "f1",
                "login": {
                    "username": "octocat",
                    "password": "hunter2",
                    "totp": "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP",
                    "uris": [{"uri": "https://github.com"}]
                },
                "fields": [
                    {"name": "API token", "value": "tok_123", "type": 1},
                    {"name": "Account", "value": "personal", "type": 0}
                ]
            },
            {"type": 2, "name": "Wifi", "notes": "guest network", "secureNote": {"type": 0}}
        ]
    }"#;
    let imported = kpxc::import::import_bitwarden(json).unwrap();
    assert_eq!(imported.iter_all_entries().count(), 2);
    let gh = find(&imported, "GitHub");
    assert_eq!(gh.get(fields::USERNAME), Some("octocat"));
    assert_eq!(gh.get(fields::PASSWORD), Some("hunter2"));
    assert_eq!(gh.get(fields::URL), Some("https://github.com"));
    assert_eq!(gh.get("API token"), Some("tok_123"));
    assert_eq!(gh.get("Account"), Some("personal"));
    assert_eq!(gh.parent().name, "Work");
    assert_eq!(find(&imported, "Wifi").get(fields::NOTES), Some("guest network"));
}

#[test]
fn proton_pass_json_import_maps_logins_and_vaults() {
    let json = br#"{
      "encrypted": false,
      "vaults": {
        "v1": {
          "name": "Personal",
          "description": "my vault",
          "items": [
            {
              "data": {
                "metadata": {"name": "Proton Mail", "note": "primary"},
                "type": "login",
                "content": {
                  "itemUsername": "david",
                  "itemEmail": "david@example.org",
                  "password": "protonpw",
                  "urls": ["https://mail.proton.me", "https://account.proton.me"],
                  "totpUri": "otpauth://totp/Proton:david?secret=JBSWY3DPEHPK3PXP"
                },
                "extraFields": [
                  {"fieldName": "Recovery", "type": "hidden", "data": {"content": "codes"}},
                  {"fieldName": "Plan", "type": "text", "data": {"content": "Plus"}}
                ]
              }
            },
            {
              "data": {
                "metadata": {"name": "Wifi Home", "note": ""},
                "type": "wifi",
                "content": {"ssid": "HomeNet", "password": "wifipw", "security": "WPA2"}
              }
            }
          ]
        }
      }
    }"#;
    let imported = kpxc::import::import_proton_pass(json).unwrap();
    let mail = find(&imported, "Proton Mail");
    assert_eq!(mail.get(fields::USERNAME), Some("david"));
    assert_eq!(mail.get(fields::PASSWORD), Some("protonpw"));
    assert_eq!(mail.get(fields::URL), Some("https://mail.proton.me"));
    assert_eq!(mail.get("KP2A_URL_2"), Some("https://account.proton.me"));
    assert_eq!(mail.get("Recovery"), Some("codes"));
    assert_eq!(mail.get("Plan"), Some("Plus"));
    assert!(mail.get(fields::OTP).unwrap().starts_with("otpauth://"));
    assert_eq!(mail.parent().name, "Personal");
    let wifi = find(&imported, "Wifi Home");
    assert_eq!(wifi.get(fields::USERNAME), Some("HomeNet"));
    assert_eq!(wifi.get(fields::PASSWORD), Some("wifipw"));
    assert_eq!(wifi.get("wifi_security"), Some("WPA2"));

    // A .json extension is auto-detected as Bitwarden, but its sniffer
    // recognises the Proton Pass vault layout.
    let auto = kpxc::import::import_bytes(
        json,
        kpxc::import::ImportFormat::Bitwarden,
        None,
        None,
    )
    .unwrap();
    assert!(find(&auto, "Proton Mail").get(fields::PASSWORD) == Some("protonpw"));
}

#[test]
fn onepux_import_reads_a_zip_export() {
    let data = br#"{
      "data": {
        "accounts": [{
          "attrs": {"name": "Personal"},
          "vaults": [{
            "attrs": {"name": "Private"},
            "items": [{
              "type": "login",
              "overview": {"title": "Bank", "urls": [{"url": "https://bank.example"}]},
              "details": {
                "notesPlain": "call first",
                "loginFields": [
                  {"designation": "username", "value": "david"},
                  {"designation": "password", "value": "s3cret"}
                ],
                "sections": [{
                  "title": "Account",
                  "fields": [{"title": "PIN", "value": "1234"}]
                }]
              }
            }]
          }]
        }]
      }
    }"#;

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("export.data", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(data).unwrap();
    let bytes = zip.finish().unwrap().into_inner();

    let imported = kpxc::import::import_1pux(&bytes).unwrap();
    let bank = find(&imported, "Bank");
    assert_eq!(bank.get(fields::USERNAME), Some("david"));
    assert_eq!(bank.get(fields::PASSWORD), Some("s3cret"));
    assert_eq!(bank.get(fields::URL), Some("https://bank.example"));
    assert_eq!(bank.get(fields::NOTES), Some("call first"));
    assert_eq!(bank.get("Account/PIN"), Some("1234"));
    assert_eq!(bank.parent().name, "Private");
}

#[test]
fn html_export_escapes_and_contains_entries() {
    let html = kpxc::export::export_html(&sample(), "fixtures/sample4.kdbx");
    assert!(html.starts_with("<html>"));
    assert!(html.contains("<caption>Sample Entry</caption>"));
    assert!(html.contains("user@example.com"));
    assert!(html.contains("https://example.com"));
    assert!(html.contains("some notes"));
    assert!(html.contains("fixtures/sample4.kdbx"));
    // No group is emitted for the recycle bin, and the structure is closed.
    assert!(html.ends_with("</body></html>"));

    let mut evil = Database::new();
    {
        let mut root = evil.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "<script>alert(1)</script>");
    }
    let html = kpxc::export::export_html(&evil, "x");
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("<script>alert(1)</script>"));
}

#[test]
fn import_format_detection() {
    use kpxc::import::ImportFormat;
    assert_eq!(ImportFormat::from_path(Path::new("a.xml")), Some(ImportFormat::Xml));
    assert_eq!(ImportFormat::from_path(Path::new("a.CSV")), Some(ImportFormat::Csv));
    assert_eq!(
        ImportFormat::from_path(Path::new("a.1pux")),
        Some(ImportFormat::OnePux)
    );
    assert_eq!(ImportFormat::from_path(Path::new("a.kdb")), Some(ImportFormat::Kdb));
    assert_eq!(ImportFormat::from_path(Path::new("a.bin")), None);
}

#[test]
fn kdb_import_reads_keepass1_fixture() {
    let bytes = std::fs::read(fixture("keepass1.kdb")).unwrap();
    let db = kpxc::kdb::import_kdb(&bytes, "masterpw").unwrap();
    let entry = find(&db, "Test entry");
    assert_eq!(entry.get(fields::USERNAME), Some("I"));
    assert_eq!(entry.get(fields::PASSWORD), Some("secretpassword"));
    assert_eq!(entry.get(fields::URL), Some("http://example.com/"));
    assert_eq!(entry.get(fields::NOTES), Some("Lorem ipsum\ndolor sit amet"));
    let attachments: Vec<(&str, Vec<u8>)> = entry
        .attachments_named()
        .map(|(name, a)| (name, a.data.get().clone()))
        .collect();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].0, "attachment.txt");
    assert_eq!(attachments[0].1, b"hello world\n");
    let root = db.root();
    let internet = root
        .groups()
        .find(|g| g.name == "Internet")
        .expect("Internet group");
    assert!(internet.groups().any(|g| g.name == "Subgroup 1"));
    assert!(db
        .iter_all_entries()
        .any(|e| e.get(fields::TITLE) == Some("Auto-Type Test 1")));
    // Twofish-encrypted KeePass 1 databases are supported too.
    let twofish = std::fs::read(fixture("keepass1-twofish.kdb")).unwrap();
    let tf = kpxc::kdb::import_kdb(&twofish, "masterpw").unwrap();
    assert!(tf.root().groups().any(|g| g.name == "Twofish"));

    // Wrong password is rejected by the content hash, not by a hang.
    assert!(kpxc::kdb::import_kdb(&bytes, "wrong").is_err());
}
