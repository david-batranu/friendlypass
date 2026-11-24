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

/// A request to approve (or name) a new browser association.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssociationRequest {
    /// Opaque per-connection client id (diagnostics only, never authentication).
    pub client_id: String,
    /// A suggested, human-readable name (e.g. `chrome-browser`).
    pub suggested_id: String,
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
