//! Entry attachment management: the details panel's ATTACHMENTS card can
//! add a file, overwrite one of the same name, delete with confirmation, and
//! every change records an entry history revision (so it is undoable). The
//! tests drive the real app and re-open the saved database to prove the
//! changes reach the KDBX file.

use eframe::egui;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use keepass::DatabaseKey;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

/// Open a writable copy of the sample database with "Sample Entry" selected.
/// The fixture entry ships with one attachment (`attach.txt`).
fn open_sample_with_details() -> (tempfile::TempDir, PathBuf, Harness<'static, friendlypass_gui::App>) {
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("sample4.kdbx");
    std::fs::copy(fixture("sample4.kdbx"), &dst).unwrap();
    let key = DatabaseKey::new().with_password("testpassword");
    let path_str = dst.display().to_string();
    let mut harness =
        Harness::new_eframe(move |_cc| friendlypass_gui::App::with_open_database(&path_str, key));
    harness.set_size(egui::Vec2::new(1150.0, 1500.0));
    harness.run();
    harness.get_by_label("Sample Entry").click();
    harness.run();
    (dir, dst, harness)
}

fn entry_id(harness: &Harness<'_, friendlypass_gui::App>, title: &str) -> keepass::db::EntryId {
    let db = harness.state().db.as_ref().unwrap();
    db.iter_all_entries()
        .find(|e| e.get("Title") == Some(title))
        .expect("entry exists")
        .id()
}

fn attachment_bytes(
    harness: &Harness<'_, friendlypass_gui::App>,
    title: &str,
    name: &str,
) -> Option<Vec<u8>> {
    let db = harness.state().db.as_ref().unwrap();
    db.iter_all_entries()
        .find(|e| e.get("Title") == Some(title))?
        .attachment_by_name(name)
        .map(|a| a.data.get().clone())
}

fn attachment_names(harness: &Harness<'_, friendlypass_gui::App>, title: &str) -> Vec<String> {
    let db = harness.state().db.as_ref().unwrap();
    let mut names: Vec<String> = db
        .iter_all_entries()
        .find(|e| e.get("Title") == Some(title))
        .unwrap()
        .attachments_named()
        .map(|(n, _)| n.to_owned())
        .collect();
    names.sort();
    names
}

fn history_len(harness: &Harness<'_, friendlypass_gui::App>, id: keepass::db::EntryId) -> usize {
    let db = harness.state().db.as_ref().unwrap();
    db.entry(id)
        .and_then(|e| e.history.as_ref().map(|h| h.get_entries().len()))
        .unwrap_or(0)
}

#[test]
fn attachments_card_explains_when_empty_and_lists_existing_files() {
    let (_dir, _path, mut harness) = open_sample_with_details();

    // The fixture's "Sample Entry" has one attachment, shown with a size.
    assert_eq!(attachment_names(&harness, "Sample Entry"), vec!["attach.txt"]);
    let size = attachment_bytes(&harness, "Sample Entry", "attach.txt")
        .unwrap()
        .len();
    let expected = friendlypass_gui::app::format_size(size);
    assert!(
        harness.query_all_by_label_contains(&expected).count() >= 1,
        "details panel shows the formatted size {expected:?}"
    );
    // The card footer summarises the count and total size.
    assert!(
        harness.query_all_by_label_contains("1 attachment \u{b7}").count() >= 1,
        "card footer reports one attachment"
    );
    assert!(harness.query_by_label("Add file…").is_some());

    // An entry with no attachments still shows the section and its hint.
    harness.get_by_label("Web Login").click();
    harness.run();
    assert!(harness.query_by_label("No attachments").is_some());
    assert!(harness.query_by_label("Add file…").is_some());
}

#[test]
fn adding_an_attachment_records_history_and_persists_to_disk() {
    let (_dir, path, mut harness) = open_sample_with_details();
    let id = entry_id(&harness, "Sample Entry");
    let before = history_len(&harness, id);

    let payload = b"\x89PNG fake screenshot bytes".to_vec();
    harness
        .state_mut()
        .add_entry_attachment(id, "screenshot.png", payload.clone())
        .expect("attachment added");
    harness.run();

    // In memory: attachment present, entry dirty, history grew by one.
    assert_eq!(
        attachment_bytes(&harness, "Sample Entry", "screenshot.png"),
        Some(payload.clone())
    );
    assert!(harness.state().dirty);
    assert!(harness.state().status.contains("Added attachment 'screenshot.png'"));
    assert_eq!(history_len(&harness, id), before + 1);

    // On disk: save through the app's own save path, then re-open the file.
    harness
        .state_mut()
        .perform_save(Some(path.display().to_string()));
    harness.run();
    assert!(!harness.state().dirty);

    let mut file = std::fs::File::open(&path).unwrap();
    let db = keepass::Database::open(&mut file, DatabaseKey::new().with_password("testpassword"))
        .unwrap();
    let sample = db
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("Sample Entry"))
        .unwrap();
    assert_eq!(
        sample
            .attachment_by_name("screenshot.png")
            .map(|a| a.data.get().clone()),
        Some(payload),
        "the new attachment is in the saved KDBX"
    );
    // The pre-existing attachment survived too.
    assert!(sample.attachment_by_name("attach.txt").is_some());
}

#[test]
fn attaching_under_an_existing_name_replaces_it() {
    let (_dir, _path, mut harness) = open_sample_with_details();
    let id = entry_id(&harness, "Sample Entry");
    let original = attachment_bytes(&harness, "Sample Entry", "attach.txt").unwrap();

    harness
        .state_mut()
        .add_entry_attachment(id, "attach.txt", b"new contents".to_vec())
        .unwrap();
    harness.run();

    assert_eq!(
        attachment_bytes(&harness, "Sample Entry", "attach.txt"),
        Some(b"new contents".to_vec())
    );
    assert!(harness.state().status.starts_with("Replaced attachment"));
    // Still exactly one attachment under that name — no duplicate.
    assert_eq!(
        attachment_names(&harness, "Sample Entry")
            .iter()
            .filter(|n| *n == "attach.txt")
            .count(),
        1
    );
    // A revision was recorded before the overwrite (keepass snapshots keep
    // the entry's fields; the attached bytes are referenced by the live
    // entry only, so compare the live data).
    let db = harness.state().db.as_ref().unwrap();
    let entry = db.entry(id).unwrap();
    assert!(entry.historical(0).is_some(), "history revision recorded");
    assert_ne!(
        attachment_bytes(&harness, "Sample Entry", "attach.txt"),
        Some(original),
        "the new bytes replaced the old ones"
    );
}

#[test]
fn deleting_an_attachment_asks_first_then_removes_it() {
    let (_dir, path, mut harness) = open_sample_with_details();
    let id = entry_id(&harness, "Sample Entry");
    let before = history_len(&harness, id);

    // The row's Delete button opens a confirmation instead of deleting.
    // (The toolbar also has a disabled "Delete group…", so pick the button
    // that sits in the details panel.)
    // index 0: the attachments card's row button (the toolbar has no plain "Delete").
    click_labelled(&mut harness, "Delete", 0);
    assert!(
        harness.query_by_label("Delete Attachment").is_some(),
        "confirmation dialog is shown"
    );
    assert!(
        attachment_bytes(&harness, "Sample Entry", "attach.txt").is_some(),
        "nothing is removed before confirming"
    );

    // Cancel leaves it alone…
    harness.get_by_label("Cancel").click();
    harness.run();
    assert!(harness.query_by_label("Delete Attachment").is_none());
    assert!(attachment_bytes(&harness, "Sample Entry", "attach.txt").is_some());

    // …confirming removes it, records history and marks the database dirty.
    click_labelled(&mut harness, "Delete", 0);
    confirm_dialog(&mut harness, "Delete Attachment", "Delete");
    assert_eq!(attachment_names(&harness, "Sample Entry"), Vec::<String>::new());
    assert!(harness.state().dirty);
    assert!(harness
        .state()
        .status
        .contains("Removed attachment 'attach.txt'"));
    assert_eq!(history_len(&harness, id), before + 1);
    assert!(harness.query_by_label("No attachments").is_some());

    // Saved database no longer carries the attachment.
    harness
        .state_mut()
        .perform_save(Some(path.display().to_string()));
    harness.run();
    let mut file = std::fs::File::open(&path).unwrap();
    let db = keepass::Database::open(&mut file, DatabaseKey::new().with_password("testpassword"))
        .unwrap();
    let sample = db
        .iter_all_entries()
        .find(|e| e.get("Title") == Some("Sample Entry"))
        .unwrap();
    assert!(sample.attachment_by_name("attach.txt").is_none());
    // …but the entry history still has an older revision, so the removal is
    // undoable through Entry History.
    assert!(sample
        .history
        .as_ref()
        .is_some_and(|h| !h.get_entries().is_empty()));
}

#[test]
fn removing_an_unknown_attachment_reports_an_error() {
    let (_dir, _path, mut harness) = open_sample_with_details();
    let id = entry_id(&harness, "Sample Entry");
    let err = harness
        .state_mut()
        .remove_entry_attachment(id, "does-not-exist.txt")
        .unwrap_err();
    assert!(format!("{err:#}").contains("no attachment named"));
    // Removing an existing one twice also fails the second time.
    harness
        .state_mut()
        .remove_entry_attachment(id, "attach.txt")
        .expect("first removal works");
    assert!(harness
        .state_mut()
        .remove_entry_attachment(id, "attach.txt")
        .is_err());
}

#[test]
fn attachment_names_are_reduced_to_a_bare_file_name() {
    use friendlypass_gui::app::attachment_name;
    assert_eq!(attachment_name("notes.txt"), "notes.txt");
    assert_eq!(attachment_name("/Users/me/Documents/scan.pdf"), "scan.pdf");
    assert_eq!(attachment_name("C:\\Users\\me\\file.txt"), "file.txt");
    assert_eq!(attachment_name("  padded.bin  "), "padded.bin");
    assert_eq!(attachment_name(""), "");
    assert_eq!(attachment_name("///"), "");
}

#[test]
fn sizes_are_human_readable() {
    use friendlypass_gui::app::format_size;
    assert_eq!(format_size(0), "0 bytes");
    assert_eq!(format_size(512), "512 bytes");
    assert_eq!(format_size(2048), "2.0 KB");
    assert_eq!(format_size(1024 * 1024 * 3 + 512 * 1024), "3.5 MB");
}

/// Click a button labelled `label` via the accesskit action, which does not
/// depend on which widget is topmost under the cursor. When several buttons
/// share the label (`Delete` exists in the attachments card *and* in the
/// confirmation dialog), `inside` picks the ones inside a dialog subtree.
fn click_labelled(
    harness: &mut Harness<'_, friendlypass_gui::App>,
    label: &str,
    index: usize,
) {
    let nodes: Vec<_> = harness.query_all_by_label(label).collect();
    let node = nodes
        .get(index)
        .unwrap_or_else(|| panic!("no button #{index} labelled {label:?} (found {})", nodes.len()));
    node.click_accesskit();
    harness.run();
}

/// Click `button` inside the dialog titled `title`. The dialog is addressed
/// by its accessible descendants, so this also works while a same-labelled
/// button exists in the page behind it.
fn confirm_dialog(harness: &mut Harness<'_, friendlypass_gui::App>, title: &str, button: &str) {
    use egui_kittest::kittest::NodeT;
    let title_node = harness.get_by_label(title);
    // Walk up to the window that draws the dialog (egui exposes the floating
    // window as a container node above the title label).
    let dialog = title_node
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| title_node);
    let target = dialog
        .children_recursive()
        .find(|n| n.accesskit_node().label() == Some(button.into()))
        .unwrap_or_else(|| panic!("no {button:?} inside dialog {title:?}"));
    target.click_accesskit();
    harness.run();
}
