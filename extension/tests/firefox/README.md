# WP9 Firefox e2e harness

```sh
npm run e2e:firefox                 # builds dist-firefox, then runs the suite
FP_FIREFOX=1 bash ../scripts/e2e.sh # Chromium e2e, then the Firefox suite
```

The suite uses the **real** stack, exactly like the Chromium harness:

- real `dist-firefox` add-on, installed temporarily through WebDriver BiDi;
- real `target/debug/friendlypass-browser-host` from a Firefox native-messaging
  manifest (`allowed_extensions: ["friendlypass@friendlypass.org"]`);
- real `target/debug/examples/test_server` on a temp unix socket, with a
  scenario KDBX created and verified through the `friendlypass` CLI.

Each scenario gets a fresh temp root containing `HOME`, the Firefox profile, the
app socket, logs and native manifests. Nothing outside that root is touched.
On macOS, `CFFIXED_USER_HOME` is set as well because Foundation ignores `$HOME`
for `~/Library/Application Support`.

## Why Puppeteer + WebDriver BiDi

Puppeteer 23+ ships production WebDriver BiDi support for Firefox, including
`browser.installExtension()` for temporary add-ons. That avoids a separate
geckodriver download/version matrix, and this suite needs none of the features
that BiDi lacks (no CDP-only APIs, no request interception): navigation, DOM
interaction, typing and screenshots all work. Selenium + geckodriver would add
a second pinned binary and a WebDriver session to maintain for no gain.

Firefox has no `--load-extension` flag, so runtime installation is mandatory;
`browser.installExtension()` is the supported way to do it.

The browser is pinned in `config.mjs` (`stable_161.0`) and downloaded on first
use into `extension/.cache/firefox/` (git-ignored) with `@puppeteer/browsers`
from Mozilla's official release archive. Override with `FP_FIREFOX_VERSION`.
(Firefox 140 ESR cannot start its WebDriver BiDi remote agent on current macOS,
so the suite could not connect there; 161 is the pinned current stable.)

## Firefox quirks the harness works around

- `page.goto("moz-extension://…")` commits the document but Firefox never emits
  the load event Puppeteer waits for, so `goto` reports a timeout even though
  `location.href` is the extension page. `openExtensionPage()` navigates
  best-effort and then waits for `location.href` inside the page.
- `action.openPopup()` requires a user gesture in Firefox and rejects when called
  from a content-script message; the extension falls back to a window. Firefox
  creates that window first and then loads `popup/popup.html` into its tab with
  `tabs.update`, because a brand-new popup window can show an empty document if
  it is handed a `moz-extension:` URL directly. The popup scenario asserts the
  rendered page, not just that a window exists.
- Firefox MV3 event pages load `background.scripts`, not a service worker, and
  enforce a 1-minute `alarms` minimum period.
- `chrome.storage` is callback-only in Firefox's `chrome` namespace; the shared
  platform adapter wraps reads/writes.

## Association

A fresh extension is not associated with the database. The popup's **Connect**
button calls the internal `association.create` request, which the Rust server
auto-approves. The harness opens `popup/popup.html` in a real `moz-extension://`
page and sends the same internal request through `chrome.runtime.sendMessage`
(see `extensionRequest()`). This is the extension's public message API, not a
test-only backdoor. Association is setup, as in the Chromium specs; every
assertion afterwards goes through the in-page UI or the real KDBX.

## Scenarios

1. Connect + `get-logins`: the login icon reports a matching entry.
2. Fill a classic login form from the inline icon.
3. Inline menu → **Open friendlypass** → the fallback window renders
   `popup/popup.html` (not an empty `moz-extension:` window).
4. Save banner → click Save → the entry is read back from the KDBX with the CLI.
5. HTTP Basic auto-fill through the Firefox `["blocking"]` adapter.
6. App killed and restarted five times: the read-only `status.get` snapshot must
   flip back to running/associated on its own, and the next page load must show
   the matching icon, without a manual reconnect.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `FP_FIREFOX_VERSION` | `stable_161.0` | pinned `@puppeteer/browsers` build id |
| `FP_FIREFOX_HEADED` | unset | `1` runs a real window |
| `FP_FIREFOX_DUMPIO` | unset | `1` forwards the browser process output |
| `FP_KEEP_TEMP` | unset | `1` keeps the temp HOME/profile/logs |
| `FP_E2E_TMPDIR` | OS temp | base directory for temp roots |
| `FP_TEST_SERVER_BINARY` | not read | the harness always uses `target/debug/examples/test_server` |

## Security

- Credentials are never printed; diagnostics contain host/app lifecycle events
  and stderr only.
- The native-messaging wrapper and the app socket live in the temp root; the app
  socket is created by `test_server` under the OS umask.
