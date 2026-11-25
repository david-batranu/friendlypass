//! The application-side bridge the protocol server calls into.
//!
//! The server never touches the database directly for operations that need
//! the user or the GUI: association approval and `set-login` are forwarded to
//! a [`BrowserBridge`] implementation. The GUI installs its own bridge
//! (`friendlypass-gui/src/browser_bridge.rs`); tests install a small fake.
//!
//! Implementations **must** be bounded: a bridge call may block a connection
//! thread but must eventually return. The GUI bridge enforces deadlines; the
//! server treats a missing/denied answer as error 6 and never waits forever.

use sha2::{Digest, Sha256};

use crate::protocol::BrowserIdentity;

/// A request to approve (or name) a new browser association.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssociationRequest {
    /// Opaque per-connection client id (diagnostics only, never authentication).
    pub client_id: String,
    /// A suggested, human-readable name (e.g. `chrome-browser`).
    pub suggested_id: String,
    /// The browser identity the host reported for this connection, but only
    /// when the socket peer was trusted (§2/§3). Untrusted claims are dropped
    /// by the server before the bridge ever sees them.
    pub browser: Option<BrowserIdentity>,
    /// `true` when the peer is our native host AND the host verified the
    /// browser (§5). The GUI still applies its "Require approval for new
    /// browsers" setting before approving without a dialog.
    pub auto_approvable: bool,
}

impl AssociationRequest {
    /// The contract §5 automatic name: `"<Browser> · <4 hex>"`, e.g.
    /// `"Chrome · 3f9a"`. The four hex digits are a stable digest of the
    /// connection identity, so two browsers never collide by accident.
    pub fn auto_approved_name(&self) -> String {
        let browser = self
            .browser
            .as_ref()
            .map(BrowserIdentity::display_name)
            .unwrap_or("Browser");
        format!("{browser} · {}", self.suffix())
    }

    fn suffix(&self) -> String {
        let seed = if self.client_id.is_empty() {
            self.suggested_id.as_str()
        } else {
            self.client_id.as_str()
        };
        let digest = Sha256::digest(seed.as_bytes());
        format!("{:02x}{:02x}", digest[0], digest[1])
    }
}

/// The contract §5 decision, shared by the GUI bridge and its tests.
///
/// Returns the association name to approve with when the peer/host/browser
/// chain is trusted and the user has not opted into a prompt; otherwise
/// `None` means "use the existing approval dialog".
pub fn auto_approve_name(request: &AssociationRequest, require_approval: bool) -> Option<String> {
    (request.auto_approvable && !require_approval).then(|| request.auto_approved_name())
}

/// Recognise an automatically approved association name (`"Chrome · 3f9a"`)
/// and return the browser's display name. Used after a restart, when only the
/// database metadata (the name) is left.
pub fn automatic_association_browser(id: &str) -> Option<&'static str> {
    let (prefix, suffix) = id.split_once(" · ")?;
    let browser = BrowserIdentity::display_name_for_kind(prefix)?;
    let looks_automatic = suffix.len() == 4 && suffix.chars().all(|ch| ch.is_ascii_hexdigit());
    looks_automatic.then_some(browser)
}

/// A request to create or update one credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetLoginRequest {
    pub acting_id: String,
    pub login: String,
    pub password: String,
    pub url: String,
    pub submit_url: Option<String>,
    pub group: Option<String>,
    pub group_uuid: Option<String>,
    /// When present, update this entry instead of creating one.
    pub uuid: Option<String>,
    pub download_favicon: bool,
    /// [friendlypass] Optional entry title from the extension.
    ///
    /// New entries use it when non-empty; updates replace the existing title
    /// only when it differs. KeePassXC ignores the unknown field.
    pub title: Option<String>,
}

/// What the server needs from the application.
pub trait BrowserBridge: Send + Sync {
    /// Ask the user to approve a new association.
    ///
    /// Returns the chosen id, or `None` when the user denied/cancelled (the
    /// server maps that to error 6).
    fn approve_association(&self, request: &AssociationRequest) -> Option<String>;

    /// Raise the application's unlock UI (`triggerUnlock` / `ping` recovery).
    fn request_unlock(&self);

    /// Ask the application to lock the database.
    fn lock_database(&self);

    /// Create or update a login in the open database.
    ///
    /// Returns `false` when the write was declined or failed; the server then
    /// reports the operation result through the inner `error` field.
    fn apply_set_login(&self, request: &SetLoginRequest) -> bool;
}

/// A bridge that refuses every interactive operation. Used as the default so a
/// server cannot silently create associations without a GUI.
#[derive(Debug, Default)]
pub struct DenyAllBridge;

impl BrowserBridge for DenyAllBridge {
    fn approve_association(&self, _request: &AssociationRequest) -> Option<String> {
        None
    }

    fn request_unlock(&self) {}

    fn lock_database(&self) {}

    fn apply_set_login(&self, _request: &SetLoginRequest) -> bool {
        false
    }
}

/// Test/GUI helper: approve associations automatically under a fixed name.
#[derive(Debug, Clone)]
pub struct AutoApproveBridge {
    pub id: String,
}

impl AutoApproveBridge {
    pub fn new(id: impl Into<String>) -> Self {
        AutoApproveBridge { id: id.into() }
    }
}

impl BrowserBridge for AutoApproveBridge {
    fn approve_association(&self, _request: &AssociationRequest) -> Option<String> {
        Some(self.id.clone())
    }

    fn request_unlock(&self) {}

    fn lock_database(&self) {}

    fn apply_set_login(&self, _request: &SetLoginRequest) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified_chrome() -> AssociationRequest {
        AssociationRequest {
            client_id: "Y2xpZW50LWlkLTAwMDAwMDAw".into(),
            suggested_id: "chrome-browser-abcdef".into(),
            browser: Some(BrowserIdentity {
                kind: "chrome".into(),
                verified: true,
                executable: Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
                team_id: Some("EQHXZ8M8AV".into()),
            }),
            auto_approvable: true,
        }
    }

    #[test]
    fn automatic_name_is_browser_and_four_hex_digits() {
        let name = verified_chrome().auto_approved_name();
        let (browser, suffix) = name.split_once(" · ").expect("separator");
        assert_eq!(browser, "Chrome");
        assert_eq!(suffix.len(), 4);
        assert!(suffix.chars().all(|ch| ch.is_ascii_hexdigit()), "{name}");
        // Stable for the same connection.
        assert_eq!(name, verified_chrome().auto_approved_name());
    }

    #[test]
    fn unknown_browsers_still_get_a_name() {
        let mut request = verified_chrome();
        request.browser = None;
        assert!(request.auto_approved_name().starts_with("Browser · "));
    }

    #[test]
    fn automatic_names_are_recognised() {
        assert_eq!(automatic_association_browser("Chrome · 3f9a"), Some("Chrome"));
        assert_eq!(automatic_association_browser("Firefox · ABCD"), Some("Firefox"));
        assert_eq!(automatic_association_browser("Chrome · 3f9"), None);
        assert_eq!(automatic_association_browser("Chrome · 3f9g"), None);
        assert_eq!(automatic_association_browser("chrome-browser"), None);
        assert_eq!(automatic_association_browser("Opera · 3f9a"), None);
    }

    #[test]
    fn auto_approve_requires_trust_and_the_setting_off() {
        let request = verified_chrome();
        assert!(auto_approve_name(&request, false).is_some());
        assert_eq!(auto_approve_name(&request, true), None);
        let mut untrusted = request.clone();
        untrusted.auto_approvable = false;
        assert_eq!(auto_approve_name(&untrusted, false), None);
    }
}
