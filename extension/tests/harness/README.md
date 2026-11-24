# WP8 e2e harness

One command:

```sh
scripts/e2e.sh            # builds extension + host, runs Playwright
scripts/e2e.sh smoke      # extra args are passed to `playwright test`
```

The harness launches **Playwright Chromium** (persistent context, new headless
or headed under Xvfb), loads `extension/dist`, installs a native-messaging
manifest in a **temp HOME/profile**, runs an app mock on a temp unix socket and
starts the native host through Chrome exactly as a real install would.

Nothing outside the temp directory is touched: Chromium gets `HOME`,
`XDG_CONFIG_HOME`, `TMPDIR` and (on macOS) `CFFIXED_USER_HOME` pointing at a
fresh `friendlypass-e2e-*` directory.

## Pieces

| Path | Purpose |
|---|---|
| `frames.mjs` | 4-byte LE + UTF-8 framing, 1 MiB cap, `sodium_increment` nonce |
| `stub-host.mjs` | Node stand-in for WP1: `ping`/`hello`, forwards the rest to the app socket, survives bad frames and a missing app |
| `app-mock.ts` | unix-socket app mock: `change-public-keys`, `get-databasehash`, `associate`, `test-associate`, `get-logins`, `get-totp`, `lock-database`, pushes |
| `setup.ts` | temp HOME/profile, extension ID derivation, native-manifest install, host wrapper |
| `host-probe.ts` | `FP_HOST=auto` liveness probe for the real host binary |
| `harness.ts` | Playwright fixture + fault-injection API |
| `smoke.spec.ts` | proves every piece end to end |

The app mock uses the fixed keys, database hash and entries from
`protocol/fixtures/*.json`. Tests replay the fixture requests verbatim; responses
are re-sealed with the request's incremented nonce.

## Host selection

`FP_HOST=auto` (default) probes `target/debug/friendlypass-browser-host` with a
framed `ping`:

- answers `ping` and connects to the harness app socket → **real** host (WP1);
- missing/exits/does not answer/never connects the app socket → **stub** host
  (`stub-host.mjs`).

`FP_HOST=real` fails loudly if the probe fails; `FP_HOST=stub` always uses the
stub. CI uses `auto`.

The real host's app-socket framing is an internal WP1 concern and may differ
from the harness's 4-byte-LE JSON framing. `FP_HOST=real` therefore proves the
stdio/`ping`/Chrome-manifest path; app actions through the real host need WP1's
framing to match the app mock (listed as a known gap).

## Fault injection API

Available on the `harness` fixture:

```ts
await harness.killHost();        // SIGKILL the host process; Chrome respawns on reconnect
await harness.killApp();         // close the app socket + all host connections
await harness.restartApp();      // re-listen on the same socket
harness.stallApp(1500);          // delay app request handling for 1.5 s
harness.sendCorruptFrame();      // app -> host invalid JSON (expects host error 1002)
await harness.simulateSleep();   // browser/extension restart (see below)
await harness.reloadExtension(); // alias of simulateSleep()
```

`simulateSleep()` closes and relaunches the persistent context with the same
temp profile. This is deliberate: Chrome for Testing marks an unpacked
`--load-extension` extension as **DISABLED** when an extension API reloads it
(`disableReasons.unsupportedDeveloperExtension`), so `chrome.runtime.reload()`
cannot be used in the harness. A full context restart is the strongest fault
that still leaves the extension loadable, and it kills the service worker and
native host just like browser sleep plus a restart.

## Native messaging from a spec

`harness.ping(nonce)` / `harness.hello()` open a real
`chrome.runtime.connectNative("org.friendlypass.browser")` port in the extension
service worker and return the first host reply. This proves
Chrome → manifest → host independently of WP2's transport.

`harness.openNativeProbePort()`, `harness.nativeProbeFrames()` and
`harness.closeNativeProbePort()` keep a port open to observe unsolicited host
frames, such as the 1002 reply to a corrupt app frame.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `FP_HOST` | `auto` | `auto` \| `stub` \| `real` |
| `FP_HOST_BINARY` | `target/debug/friendlypass-browser-host` | real host path |
| `FP_HEADED` | `0` | `1` opens a real window (CI Linux uses Xvfb) |
| `FP_CHANNEL` | `chromium` | Playwright channel (`chromium` or `chrome`) |
| `FP_KEEP_TEMP` | unset | `1` keeps the temp HOME/profile/logs |
| `FP_E2E_TMPDIR` | OS temp | base directory for temp roots |

## Security

- Credentials/keys never go to a log. Host logs contain action names, byte
  counts and error codes only; the app mock log contains action names only.
  Specs assert that fixture credentials are absent from the app log.
- The harness never writes to the user's real browser profile or native-
  messaging directories. On macOS this requires `CFFIXED_USER_HOME`, because
  Foundation ignores `$HOME` for `~/Library/Application Support`.
- The app socket lives in the temp root and is chmod 0600.
