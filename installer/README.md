# friendlypass native-messaging host installer

Registers `friendlypass-browser-host` with browsers as
`org.friendlypass.browser`, the host name the extension uses with
`chrome.runtime.connectNative()`.

Most people do not need this script: the app writes the same manifests from
**Settings and tools → Browser… → Enable browser integration**. The script is
for terminal installs, automation and development builds. It finds the host
binary and forwards every option to
`friendlypass-browser-host --install/--uninstall`, so the app and the installer
share one implementation (the `friendlypass_browser::native_messaging` module).

## End-user flow

1. Install the app (see [`../packaging/README.md`](../packaging/README.md)).
2. Start friendlypass → **Settings and tools → Browser…** → tick **Enable
   browser integration** and the browsers you use.
3. Install the friendlypass extension in those browsers.

Only browsers that have been started at least once are registered: the app and
the installer require the browser's per-user configuration root to exist (for
example `~/.config/google-chrome` or
`~/Library/Application Support/Google/Chrome`). Browsers without one are shown
as disabled with “(not installed)” in the settings dialog and skipped by the
command-line installer, so ticking every box never creates empty Brave/Edge
directories. Start the browser and reopen the dialog (or run the installer
again) to register it; `--force` overrides the check explicitly.

The app rewrites a stale manifest on every start (for example after the app is
moved or updated) and removes the manifest (and, on Windows, the `HKCU`
registration) when a browser is unticked. It only ever touches
`org.friendlypass.browser.json` and its own host key; other native hosts'
manifests and registry entries are left alone. Uninstall does not need the browser to still be installed: any
manifest of ours that exists is removed.

## Build the host first

```sh
cargo build --release -p friendlypass-browser-host
```

The installer looks for `target/release/friendlypass-browser-host`, then
`target/debug/…`, then the macOS app bundle
(`/Applications/friendlypass.app/Contents/MacOS/…`), then
`friendlypass-browser-host` on `PATH`. Use `--host-path` to point at another
binary (it must be executable and the path is written absolute).

## Install

```sh
./installer/install.sh
```

The Chrome-family id is stable and baked in: the extension pins an RSA public
key in `extension/src/manifest.json`, and the installer's default id
(`pfdmagadklmhbghfipamhfbphcljdkbi`) is the SHA-256-derived id of that key. No
`--extension-id` is needed; pass it only to override the default (for example a
temporary unpacked build loaded without the key). Firefox uses
`browser_specific_settings.gecko.id` (`friendlypass@friendlypass.org`).

The private key lives outside the repository at
`/Users/david/Work/Projects/friendlypass/secrets/extension-key.pem` (never
commit or ship it). Recompute the id with:

```sh
openssl pkey -in secrets/extension-key.pem -pubout -outform DER |
  openssl dgst -sha256 -binary | xxd -p -c 256 | cut -c1-32 |
  tr '0-9a-f' 'a-p'
```

Options (the script forwards them to the host CLI):

| Option | Meaning |
|---|---|
| `--extension-id ID` | Chrome-family extension id (default: the pinned-key id; 32 chars `a`–`p`). |
| `--firefox-extension-id ID` | Firefox add-on id; default `friendlypass@friendlypass.org`. |
| `--host-path PATH` | Override the host binary. |
| `--home DIR` | Use `DIR` as `$HOME` (tests, alternate profiles). |
| `--platform macos\|linux\|windows` | Override detection (tests). On Windows manifests go under `%LOCALAPPDATA%\\friendlypass` and are registered in `HKCU`. |
| `--browsers LIST` | Comma list of `chrome,chromium,brave,edge,firefox`; default all. Missing browsers are skipped. |
| `--force` | Register a selected browser even when its per-user config root does not exist (creates it). |
| `--dry-run` | Print targets, write nothing. |
| `--uninstall` | Remove the manifests (no extension id needed). |

The host binary accepts the same options directly, with `--browser NAME`
(repeatable, or comma-separated via `--browsers`) instead of `--browsers LIST`:

```sh
friendlypass-browser-host --install --browser chrome --browser firefox
friendlypass-browser-host --uninstall --browser firefox --home /tmp/test-home
```

## Where the manifests go

| Browser | macOS (`$HOME/...`) | Linux (`$HOME/...`) |
|---|---|---|
| Chrome | `Library/Application Support/Google/Chrome/NativeMessagingHosts` | `.config/google-chrome/NativeMessagingHosts` |
| Chromium | `Library/Application Support/Chromium/NativeMessagingHosts` | `.config/chromium/NativeMessagingHosts` |
| Brave | `Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts` | `.config/BraveSoftware/Brave-Browser/NativeMessagingHosts` |
| Edge | `Library/Application Support/Microsoft Edge/NativeMessagingHosts` | `.config/microsoft-edge/NativeMessagingHosts` |
| Firefox | `Library/Application Support/Mozilla/NativeMessagingHosts` | `.mozilla/native-messaging-hosts` |

On Windows browsers do not read a per-profile manifest directory: the manifest
lives under `%LOCALAPPDATA%\friendlypass\<browser>\org.friendlypass.browser.json`
and the default value of
`HKCU\Software\{Google\Chrome|Chromium|BraveSoftware\Brave-Browser|Microsoft\Edge|Mozilla}\NativeMessagingHosts\org.friendlypass.browser`
points at it. The registry entry is what `--install`/`--uninstall` (and the
GUI) update; the manifest content rules below are unchanged.

The file name is always `org.friendlypass.browser.json`. Chrome-family manifests
carry `allowed_origins: ["chrome-extension://<id>/"]`; Firefox manifests carry
`allowed_extensions: ["<add-on id>"]`.

The table shows the configuration root that must already exist
(`.../Google/Chrome`, `.config/chromium`, …); only its `NativeMessagingHosts`
child is created. The root itself is never created, so no manifest appears for
a browser that is not installed.

## Uninstall

```sh
./installer/install.sh --uninstall
```

Only this host's manifest is removed; the browser directories (which may hold
other native hosts) stay.

## Tests

```sh
./installer/tests/install.sh
```

Runs the installer in a temporary `$HOME` for both layouts, validates every
JSON file with Python, checks idempotence, browser selection, installed-browser
detection/skip/`--force`, validation errors, dry-run and uninstall. It builds
`target/debug/friendlypass-browser-host` when needed and also exercises the
host's `--install/--uninstall --browser` flags directly.

The Rust-level tests (all browsers × both platforms, path-change rewrite,
idempotence, uninstall leaving other hosts alone) live in
`crates/friendlypass-browser/tests/native_messaging_install.rs`:

```sh
cargo test -p friendlypass-browser --test native_messaging_install
```
