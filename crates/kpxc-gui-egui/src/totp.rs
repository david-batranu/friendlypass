//! TOTP (time-based one-time password) display helpers.
//!
//! KeePassXC stores TOTP configuration in the `otp` entry attribute as an
//! `otpauth://totp/...` URL. The keepass crate's `totp` feature parses it
//! and generates codes (`Entry::get_otp`, `TOTP::value_now`); this module
//! is the thin glue for the GUI.

use keepass::db::Entry;
use keepass::db::TOTP;

/// The parsed TOTP configuration of an entry, if it has a valid `otp` URL.
pub fn totp_of(entry: &Entry) -> Option<TOTP> {
    entry.get_otp().ok()
}

/// The current code and its remaining validity, if the entry has a TOTP.
pub fn current_code(entry: &Entry) -> Option<(String, u64)> {
    let totp = totp_of(entry)?;
    let code = totp.value_now().ok()?;
    Some((code.code, code.valid_for.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{fields, Database};

    fn entry_with_otp(url: &str) -> Database {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "TOTP Entry");
            e.set_unprotected(fields::OTP, url);
        }
        db
    }

    #[test]
    fn rfc6238_sha1_vector() {
        // RFC 6238 test vector: secret "12345678901234567890", SHA-1,
        // 8 digits, T=59 -> 94287082.
        let db = entry_with_otp(
            "otpauth://totp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1",
        );
        let entry = db.iter_all_entries().next().unwrap();
        let totp = totp_of(&entry).expect("otp parsed");
        assert_eq!(totp.digits, 8);
        let code = totp.value_at(59);
        assert_eq!(code.code, "94287082");
        assert_eq!(code.valid_for.as_secs(), 1); // 59 % 30 = 29 -> 1s left
    }

    #[test]
    fn rfc6238_default_six_digits() {
        // Same secret with the common 6-digit TOTP: T=59 -> 287082.
        let db = entry_with_otp(
            "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30",
        );
        let entry = db.iter_all_entries().next().unwrap();
        let totp = totp_of(&entry).expect("otp parsed");
        assert_eq!(totp.value_at(59).code, "287082");
        // The GUI helper returns a 6-digit code with the remaining time.
        let (code, valid_for) = current_code(&entry).expect("current code");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(valid_for <= 30);
    }

    #[test]
    fn entries_without_otp_return_none() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "No TOTP");
        }
        let entry = db.iter_all_entries().next().unwrap();
        assert!(current_code(&entry).is_none());
    }

    #[test]
    fn invalid_otp_url_is_ignored() {
        let db = entry_with_otp("not-an-otpauth-url");
        let entry = db.iter_all_entries().next().unwrap();
        assert!(current_code(&entry).is_none());
    }
}
