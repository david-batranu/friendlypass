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

Options:

| Option | Meaning |
|---|---|
| `--extension-id ID` | Chrome-family extension id (default: the pinned-key id; 32 chars `a`–`p`). |
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
