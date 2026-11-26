//! `friendlypass-browser-host` — the native-messaging host registered with
//! Chrome/Firefox as `org.friendlypass.browser`.
//!
//! It is the native-messaging host used by the friendlypass extension. It
//! never exits when the app is down: it keeps the browser port open, answers
//! host-level `ping`/`hello` locally, and reconnects to the app socket in the
//! background. See `protocol/ACTIONS.md` for the frozen contract.
//!
//! stdout carries protocol frames only; all diagnostics go to stderr.

mod app;
mod browser_identity;
mod dispatch;
mod errors;
mod framing;
mod install_cli;
mod socket;
mod status;
mod writer;

use std::sync::Arc;

use app::AppLink;
use dispatch::Runtime;
use status::StatusCell;
use writer::Writer;

fn main() {
    // `--install`/`--uninstall` (used by the app settings and install.sh)
    // never speak the native-messaging protocol, so they are handled first.
    if let Some(code) = install_cli::run_if_requested(std::env::args().skip(1)) {
        std::process::exit(code);
    }

    // Identify the launching browser once. Debug-level only (`FP_HOST_DEBUG`):
    // this is process metadata, never credentials, but normal runs stay quiet.
    let identity = browser_identity::cached_identity();
    browser_identity::log_identity_debug(identity);

    let socket_path = friendlypass_browser::browser_server_path();
    eprintln!(
        "{} {} (protocol {}, pid {}, app link {})",
        dispatch::HOST_NAME,
        dispatch::HOST_VERSION,
        dispatch::PROTOCOL_VERSION,
        std::process::id(),
        socket_path.display()
    );

    let out = Arc::new(Writer::new());
    let status = Arc::new(StatusCell::new());
    let app = AppLink::start(socket_path, Arc::clone(&out), Arc::clone(&status));
    let runtime = Runtime::new(out, app, status);

    // stdin EOF — the browser closed the port — ends the process cleanly.
    let _ = dispatch::run(std::io::stdin(), &runtime);
}
