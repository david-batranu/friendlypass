# friendlypass native-messaging host installer

Registers `friendlypass-browser-host` with browsers as
`org.friendlypass.browser`, the host name the extension uses with
`chrome.runtime.connectNative()`.

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
./installer/install.sh --extension-id <your-extension-id>
```

`<your-extension-id>` is the 32-character id from `chrome://extensions`
(chrome-family browsers only; Firefox ignores it). To get a stable id during
development, load the unpacked `extension/dist` build once and copy the id shown
on the extensions page, or pin a `key` in the manifest (requested from WP0).

Options:

| Option | Meaning |
|---|---|
| `--extension-id ID` | Chrome-family extension id (required to install; 32 chars `a`–`p`). |
| `--firefox-extension-id ID` | Firefox add-on id; default `friendlypass@friendlypass.org`. |
| `--host-path PATH` | Override the host binary. |
| `--home DIR` | Use `DIR` as `$HOME` (tests, alternate profiles). |
| `--platform macos\|linux` | Override detection (tests). |
| `--browsers LIST` | Comma list of `chrome,chromium,brave,edge,firefox`; default all. |
| `--dry-run` | Print targets, write nothing. |
| `--uninstall` | Remove the manifests (no extension id needed). |

## Where the manifests go

| Browser | macOS (`$HOME/...`) | Linux (`$HOME/...`) |
|---|---|---|
| Chrome | `Library/Application Support/Google/Chrome/NativeMessagingHosts` | `.config/google-chrome/NativeMessagingHosts` |
| Chromium | `Library/Application Support/Chromium/NativeMessagingHosts` | `.config/chromium/NativeMessagingHosts` |
| Brave | `Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts` | `.config/BraveSoftware/Brave-Browser/NativeMessagingHosts` |
| Edge | `Library/Application Support/Microsoft Edge/NativeMessagingHosts` | `.config/microsoft-edge/NativeMessagingHosts` |
| Firefox | `Library/Application Support/Mozilla/NativeMessagingHosts` | `.mozilla/native-messaging-hosts` |

The file name is always `org.friendlypass.browser.json`. Chrome-family manifests
carry `allowed_origins: ["chrome-extension://<id>/"]`; Firefox manifests carry
`allowed_extensions: ["<add-on id>"]`.

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
JSON file with Python, checks idempotence, browser selection, validation
errors, dry-run and uninstall.
