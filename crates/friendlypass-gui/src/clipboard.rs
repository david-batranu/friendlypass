//! Clipboard access with automatic clearing.
//!
//! Copying a password leaves it on the system clipboard indefinitely unless
//! something removes it. After a configurable delay we clear the clipboard,
//! but only when it still holds the value we put there: if the user has
//! copied something else in the meantime, that is theirs and is left alone.
//!
//! The backend is a trait so the clearing logic can be tested without a real
//! clipboard (CI machines often have none).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Somewhere text can be copied to and read back from.
pub trait ClipboardBackend: Send + Sync {
    fn set_text(&self, text: &str) -> Result<(), String>;
    /// The current text content, or `None` when it is empty, not text, or
    /// unreadable.
    fn get_text(&self) -> Option<String>;
    /// Remove the content.
    fn clear(&self) -> Result<(), String>;
}

/// The operating system clipboard (via `arboard`).
pub struct SystemClipboard;

impl ClipboardBackend for SystemClipboard {
    fn set_text(&self, text: &str) -> Result<(), String> {
        arboard::Clipboard::new()
            .and_then(|mut c| c.set_text(text.to_owned()))
            .map_err(|e| e.to_string())
    }

    fn get_text(&self) -> Option<String> {
        arboard::Clipboard::new().ok()?.get_text().ok()
    }

    fn clear(&self) -> Result<(), String> {
        arboard::Clipboard::new()
            .and_then(|mut c| c.clear())
            .map_err(|e| e.to_string())
    }
}

/// An in-memory clipboard for tests. Cloning shares the same content, so a
/// test can keep a handle and inspect or overwrite what the app copied.
#[derive(Clone, Default)]
pub struct MemoryClipboard(Arc<Mutex<Option<String>>>);

impl MemoryClipboard {
    pub fn contents(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
}

impl ClipboardBackend for MemoryClipboard {
    fn set_text(&self, text: &str) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }

    fn get_text(&self) -> Option<String> {
        self.contents()
    }

    fn clear(&self) -> Result<(), String> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// A scheduled clear: remembers a fingerprint of the copied value (not the
/// value itself) and when to clear it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingClear {
    fingerprint: u64,
    pub deadline: Instant,
}

impl PendingClear {
    pub fn new(value: &str, now: Instant, after: Duration) -> Self {
        PendingClear {
            fingerprint: fingerprint(value),
            deadline: now + after,
        }
    }

    /// Whether `current` (the clipboard's content now) is still our value.
    pub fn matches(&self, current: Option<&str>) -> bool {
        current.is_some_and(|c| fingerprint(c) == self.fingerprint)
    }

    /// Whole seconds left before the clear (rounded up).
    pub fn remaining_secs(&self, now: Instant) -> u64 {
        let left = self.deadline.saturating_duration_since(now);
        left.as_secs() + u64::from(left.subsec_nanos() > 0)
    }
}

fn fingerprint(value: &str) -> u64 {
    let mut h = DefaultHasher::new();
    value.hash(&mut h);
    h.finish()
}

/// What [`clear_if_due`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    /// The deadline has not passed yet.
    NotDue,
    /// The clipboard still held our value and was cleared.
    Cleared,
    /// The user copied something else meanwhile; nothing was touched.
    Replaced,
    /// Clearing failed (clipboard unavailable).
    Failed,
}

/// Clear the clipboard if `pending` is due and the clipboard still holds the
/// value we copied. `force` ignores the deadline (used when locking).
pub fn clear_if_due(
    backend: &dyn ClipboardBackend,
    pending: &PendingClear,
    now: Instant,
    force: bool,
) -> ClearOutcome {
    if !force && now < pending.deadline {
        return ClearOutcome::NotDue;
    }
    let current = backend.get_text();
    if !pending.matches(current.as_deref()) {
        return ClearOutcome::Replaced;
    }
    match backend.clear() {
        Ok(()) => ClearOutcome::Cleared,
        Err(_) => ClearOutcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_after_the_deadline_and_only_our_value() {
        let clip = MemoryClipboard::default();
        let t0 = Instant::now();
        clip.set_text("s3cret").unwrap();
        let pending = PendingClear::new("s3cret", t0, Duration::from_secs(30));

        assert_eq!(pending.remaining_secs(t0), 30);
        assert_eq!(
            clear_if_due(&clip, &pending, t0 + Duration::from_secs(29), false),
            ClearOutcome::NotDue
        );
        assert_eq!(clip.contents().as_deref(), Some("s3cret"));
        assert_eq!(
            clear_if_due(&clip, &pending, t0 + Duration::from_secs(30), false),
            ClearOutcome::Cleared
        );
        assert_eq!(clip.contents(), None);
    }

    #[test]
    fn leaves_something_the_user_copied_later() {
        let clip = MemoryClipboard::default();
        let t0 = Instant::now();
        clip.set_text("s3cret").unwrap();
        let pending = PendingClear::new("s3cret", t0, Duration::from_secs(30));
        clip.set_text("my own text").unwrap();
        assert_eq!(
            clear_if_due(&clip, &pending, t0 + Duration::from_secs(31), false),
            ClearOutcome::Replaced
        );
        assert_eq!(clip.contents().as_deref(), Some("my own text"));
    }

    #[test]
    fn force_clears_early() {
        let clip = MemoryClipboard::default();
        let t0 = Instant::now();
        clip.set_text("s3cret").unwrap();
        let pending = PendingClear::new("s3cret", t0, Duration::from_secs(30));
        assert_eq!(clear_if_due(&clip, &pending, t0, true), ClearOutcome::Cleared);
        assert_eq!(clip.contents(), None);
    }
}
