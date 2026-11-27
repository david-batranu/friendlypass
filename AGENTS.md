# AGENTS.md — friendlypass project map

This file is the fast path into the repository. Read it before exploring; a
task description normally names the files you may change, and this map tells you what
everything else is and how to prove a change.

## What the project is

friendlypass is a Rust port of KeePassXC: `friendlypass` is the KDBX engine and
`keepassxc-cli`-compatible CLI, `friendlypass-gui` is the egui/eframe desktop
app, and `friendlypass-ssh-agent` serves SSH keys from database attachments.
It also ships its own browser integration: an MV3 extension hard-forked from
keepassxc-browser, a native-messaging host, and a friendlypass-branded browser
socket server in the GUI. Databases remain standard KDBX files and are
cross-checked against KeePassXC 2.8.0 (`verify.sh`).

## Map

| Path | Purpose | Open first |
|---|---|---|
| `crates/friendlypass/` | Core library + `friendlypass` CLI: commands, KDBX open/save, keyfiles, import/export, KeeShare. | `src/commands.rs`, `src/import.rs`, `src/export.rs`, `src/saveutil.rs`, `src/key.rs`, `tests/integration.rs` |
| `crates/friendlypass-gui/` | egui/eframe GUI, dialogs, browser bridge, macOS AutoFill Credential Provider bridge (`macos_provider.rs` + `macos_identity_store.m`), auto-type, TOTP, icons; headless `egui_kittest` tests and PNG snapshots. | `src/app.rs`, `src/dialogs.rs`, `src/browser_bridge.rs`, `src/macos_provider.rs`, `src/autotype.rs`, `src/icons.rs`, `tests/gui.rs`, `tests/browser.rs`, `tests/macos_provider.rs` |
| `crates/friendlypass-ssh-agent/` | SSH agent (unencrypted `ssh-ed25519` subset) plus `friendlypass-ssh-agent` binary. | `src/server.rs`, `src/openssh.rs`, `tests/e2e.rs` |
| `crates/friendlypass-mobile/` | UniFFI cdylib `friendlypass_mobile` for Android: vault open/search/save, mobile passkey records. | `src/lib.rs`, `src/bin/uniffi-bindgen.rs`, `Cargo.toml` |
| `crates/friendlypass-passkey/` | WebAuthn authenticator (ES256/EdDSA/RSA) and KeePassXC `KPEX_PASSKEY_*` field format, no keepass dependency. | `src/lib.rs`, `tests/` |
| `crates/friendlypass-browser/` | Socket-side KeePassXC-Browser protocol: crypto, sessions, actions, passkeys, push, peer verification, native-messaging manifests. | `src/server.rs`, `src/service.rs`, `src/crypto.rs`, `src/protocol.rs`, `src/peer.rs`, `src/bridge.rs`, `src/passkeys.rs`, `src/passkey_write.rs`, `tests/fixtures_*.rs`, `tests/passkeys_actions.rs` |
| `crates/friendlypass-browser-host/` | `friendlypass-browser-host`: native-messaging stdio ↔ app link (Unix socket / Windows named pipe), registered as `org.friendlypass.browser`. | `src/dispatch.rs`, `src/app.rs`, `src/socket.rs`, `src/framing.rs`, `src/browser_identity.rs`, `src/install_cli.rs`, `tests/host_identify.rs`, `tests/transport_roundtrip.rs` |
| `extension/` | MV3 browser extension (hard fork of keepassxc-browser): transport, session, actions, passkey interception, content/fill engine, popup/options. | `src/background/transport.ts`, `src/background/session.ts`, `src/background/actions.ts`, `src/content/fill.ts`, `src/content/passkeys.ts`, `src/content/passkeys-page.ts`, `tests/unit/`, `tests/e2e/passkeys.spec.ts` |
| `android/` | Android app (`org.friendlypass.android`): Compose UI, UniFFI vault, SAF storage, autofill service, Credential Manager provider, debug-only `:testapp` and `:credtest` drivers, instrumented tests. Contract is frozen. | `CONTRACT.md`, `app/src/main/java/org/friendlypass/android/`, `app/src/androidTest/`, `app/build.gradle.kts` |
| `protocol/` | Frozen wire contract, golden frames, file ownership. | `ACTIONS.md`, `OWNERSHIP.md`, `version`, `fixtures/` |
| `installer/` | Registers the native host with Chrome-family browsers and Firefox; thin delegate to `friendlypass-browser-host --install`. | `install.sh`, `tests/install.sh` |
| `packaging/` | macOS `.app` bundle (GUI + browser host + Swift `FriendlyPassCredentialProvider.appex` for macOS Passkeys/Passwords/TOTP) and Linux tarball/desktop entry. | `macos/package.sh`, `macos/credential-provider/`, `linux/package.sh`, `README.md` |
| `branding/` | Logo, derived app icons, icon generation script. | `generate-icons.sh`, `derived/` |
| `fixtures/` | Real KDBX/KDB databases and keyfiles used by Rust and e2e tests. | `sample4.kdbx`, `sample4.keyx` (passwords in `README.md`) |
| `vendor/challenge-response/` | Local platform shim for `challenge_response` 0.5.46 (its nusb backend does not build on macOS). | `Cargo.toml`, `src/` |
| `docs/` | Screenshots referenced by the README. | `screenshots/details.png` |
| `scripts/` | Browser e2e entry point. | `e2e.sh` |
| `.github/` | CI for the extension + browser crates + installer. `release.yml` builds every platform and the extension on a `vX.Y.Z` tag and publishes one GitHub Release (`workflow_dispatch` = dry run). | `workflows/browser-ext.yml`, `workflows/release.yml` |
| `verify.sh` | Cross-verification of Rust ↔ real KeePassXC 2.8.0 plus the whole workspace and extension suites (release build; slow). | whole file |

Also at the root: `LICENSE` (GPL-3.0-only), `NOTICE.md` (upstream provenance),
and `Cargo.toml` (workspace + local `challenge_response` patch).

## Browser integration architecture

```
extension (MV3 SW) --native messaging (4-byte LE length + JSON)--> friendlypass-browser-host
                                                                        | app link
                                                                        v
                                                          friendlypass GUI / friendlypass-browser
                                            Unix: <user temp>/org.friendlypass.BrowserServer
                                     Windows: \\.\pipe\org.friendlypass.BrowserServer_<USERNAME>
```

- The host answers host-level `ping`/`hello` locally, reconnects with backoff,
  and forwards every other frame byte-for-byte to the app socket/pipe. `stdout`
  is protocol frames only; diagnostics go to `stderr`.
- The app side is `crates/friendlypass-browser`: X25519 `change-public-keys`,
  libsodium-compatible `crypto_box_easy`, nonce increment, then encrypted
  `associate`/`test-associate`/`get-logins`/`set-login`/`get-totp`/etc.
  `server_core.rs` holds the shared reader/worker/push loop; `server.rs` is the
  Unix listener and `server_windows.rs`/`pipe.rs` the named-pipe listener.
- `protocol/ACTIONS.md` is the **frozen** wire contract (version in
  `protocol/version`). Read it before touching framing, crypto, actions or
  golden fixtures. `protocol/fixtures/` is generated by `protocol/gen-fixtures.mjs`.
- Trust chain: on every new app connection the host sends `host-identify` and
  reports its parent browser (macOS code signature / team IDs; Linux
  `/proc/<pid>/exe`; Windows Authenticode signer), the app verifies the app
  link peer is really our host (macOS `LOCAL_PEERPID` + executable + cdhash;
  Linux `SO_PEERCRED` + `/proc/<pid>/exe`; Windows
  `GetNamedPipeClientProcessId` + image path), and auto-approves `associate`
  only when peer trusted + browser verified + "Require approval for new
  browsers" is off.
- The reader thread answers `ping` immediately while every other request waits
  in order for the connection worker; liveness must never block on a pending
  action. Tests: `ping_during_approval.rs`, `ping_during_associate.rs`.
- `FP_APP_SOCKET` overrides the socket path (tests and relocated apps); on
  Windows it is the pipe path. The host derives the same value, so both ends
  stay in sync.
- Windows registers the host through `HKCU\Software\...\NativeMessagingHosts\
  org.friendlypass.browser` (Chrome/Chromium/Edge/Brave, and Firefox under
  `Software\Mozilla`), pointing at manifests under `%LOCALAPPDATA%\friendlypass`.
- Push messages (lock/unlock/changed) come from the GUI through a bounded
  channel; a slow browser cannot stall the app.

## Commands

Measured on an Apple-silicon Mac with a warm `target/`; a cold build can add
several minutes. Run Rust commands from the repo root and extension commands
from `extension/`.

| Area | Command | Typical |
|---|---|---|
| Build workspace | `cargo build --workspace` | ~6 s warm; minutes cold |
| Core / CLI tests | `cargo test -p friendlypass` | ~40 s |
| GUI tests | `cargo test -p friendlypass-gui` | ~1–2 min (see gotcha below) |
| Single GUI test | `cargo test -p friendlypass-gui --test gui <name>` | ~25 s incl. build |
| SSH agent tests | `cargo test -p friendlypass-ssh-agent` | ~5 s |
| Browser + host tests | `cargo test -p friendlypass-browser -p friendlypass-browser-host` | ~30 s |
| Frozen protocol fixtures (CI gate) | `cargo test -p friendlypass-browser --test fixtures_crypto` | ~5 s |
| Installer tests | `./installer/tests/install.sh` | ~2 s |
| Extension deps (first) | `npm ci --prefer-offline` | ~4 s |
| Extension unit tests | `npx vitest run` (or `npm test`) | ~2 s, 214 tests |
| Extension typecheck | `npm run typecheck` | ~4 s |
| Extension build | `npm run build` (Firefox: `npm run build:firefox`) | <1 s |
| Chromium e2e | `FP_SKIP_BROWSER_INSTALL=1 bash scripts/e2e.sh` | ~5 min 20 s |
| Firefox e2e | `npm run e2e:firefox` (from `extension/`) | ~2 min after first download |
| Package extension zips | `npm run package` | ~2 s |
| macOS app bundle | `packaging/macos/package.sh` | slow, not run (release build) |
| Full cross-check | `./verify.sh` | ~1 min warm, minutes cold (81 gates: workspace + extension + real KeePassXC) |
| Clean clippy (browser + host) | `cargo clippy -p friendlypass-browser -p friendlypass-browser-host --all-targets --no-deps -- -D warnings` | ~5 s warm |
| Windows cross-check (browser + host) | `cargo check --target x86_64-pc-windows-gnu -p friendlypass-browser -p friendlypass-browser-host --all-targets`, then the same with `cargo clippy … -- -D warnings` | ~1 min warm |
| Release workflow lint | `actionlint .github/workflows/release.yml` | ~1 s |
| Windows build (CI) | `cargo build --release -p friendlypass -p friendlypass-gui -p friendlypass-browser-host` on `windows-latest` | GitHub Actions only |
| Full release build | push tag `vX.Y.Z` or run the `release` workflow manually | GitHub Actions only |

`friendlypass-gui` and the core `friendlypass` crate have pre-existing clippy
findings. Do not add new ones, and do not run `-D warnings` on them expecting a
clean result.

The Windows cross-check needs the Rust target once:
`rustup target add x86_64-pc-windows-gnu` (installed in this checkout). The GUI
crate cannot be cross-checked on this Mac because some of its dependencies need
a Windows C toolchain; `browser-ext.yml`'s `windows-latest` job and
`release.yml` are the proof for Windows-only code and the GUI.

## Android

Run every `./gradlew` command from `android/`. The Rust half is cross-compiled
by `cargo-ndk`; `uniffi-bindgen` generates the Kotlin bindings into
`app/build/generated/uniffi` before `compileDebugKotlin`.

Requirements (set these up for your own machine; nothing here is fixed to one
layout):

- A rustup toolchain with the Android targets (`aarch64-linux-android`,
  `x86_64-linux-android`) and `cargo-ndk`, with `cargo` and `cargo-ndk` on `PATH`
  (`$HOME/.cargo/bin` is the usual location).
- `ANDROID_HOME` = your Android SDK root (Android Studio default:
  `~/Library/Android/sdk` on macOS, `~/Android/Sdk` on Linux).
- `ANDROID_NDK_HOME` = the NDK `28.2.13676358` inside that SDK
  (`$ANDROID_HOME/ndk/28.2.13676358`).
- `JAVA_HOME` = a JDK 21 installation.
- Optional: `CARGO_TARGET_DIR` set to a directory outside the repository to keep
  Android build objects separate from the desktop `target/`.

```sh
export ANDROID_HOME=/path/to/Android/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358
export JAVA_HOME=/path/to/jdk-21
export CARGO_TARGET_DIR=/path/to/android-target   # optional
```

| Area | Command | Notes |
|---|---|---|
| Build debug | `./gradlew :app:assembleDebug` | cargo-ndk builds arm64-v8a + x86_64 |
| JVM unit tests | `./gradlew :app:testDebugUnitTest` | 94 tests; results under `app/build/test-results/` |
| Instrumented tests | `ANDROID_SERIAL=emulator-<port> ./gradlew :app:connectedDebugAndroidTest` | installs `:testapp` and `:credtest` first via task dependencies |
| Release APK | `./gradlew :app:assembleRelease` | unsigned, R8/minify off, release cargo profile |
| One test class | `ANDROID_SERIAL=emulator-<port> ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=<fqcn>` | append `#method` for one method |

Emulators: use the assigned port only and always pass `-s emulator-<port>` to
adb; run read-only so instances do not collide:
`$ANDROID_HOME/emulator/emulator -avd <your-avd> -read-only -no-window -no-audio -no-snapshot-save -port <port>`
(use an AVD of your choice; API 36 is recommended)
(then `adb -s emulator-<port> wait-for-device` and poll
`getprop sys.boot_completed`). Kill only your own with
`adb -s emulator-<port> emu kill`.

Debug-only extras and test hooks (never in release):
- `org.friendlypass.android.DEMO_DATABASE=true` opens the in-memory Kotlin fake
  (password `test`); `org.friendlypass.android.ALLOW_CAPTURE=true` skips
  `FLAG_SECURE` for screenshots.
- `org.friendlypass.android.DEBUG_DATABASE_FILE=<path>` opens a `file://` KDBX
  copied into app storage. `SafDatabaseStore` accepts `file://` only in debug
  builds; instrumented tests stage fixtures with
  `app/src/debug/.../DebugVaultFile.kt`.
- Instrumented tests use `sample4.kdbx` from `app/src/androidTest/assets`
  (password `testpassword`) and drive `:credtest` with the rpId
  `credtest.friendlypass.test`. The credential provider is selected in tests by
  `settings put secure credential_service …`; the emulator's default is Google
  Password Manager.
- OTP autofill tests use `app/src/androidTest/assets/otp-autofill.kdbx`
  (password `testpassword`, one `OTP Account` entry with an `otp` field,
  `URL=https://appassets.androidplatform.net` and
  `AndroidApp=org.friendlypass.testapp`). `:testapp` serves
  `assets/otp.html`, `assets/otp-split.html` and `assets/otp-combined.html`
  through `WebLoginActivity` (`-e org.friendlypass.testapp.PAGE otp-split`),
  and `LoginActivity` continues to `OtpActivity` for the username `otp-user`.

## Known gotchas (all checked in this checkout)

- **GUI snapshot in worktrees:** `cargo test -p friendlypass-gui` fails
  `wrong_password_shows_error` because `tests/snapshots/gui_unlock_error.png`
  renders the absolute fixture path, which differs in
  a checkout at a different path. It passes in the checkout the snapshot was
  rendered in. Do not run `UPDATE_SNAPSHOTS=1` from a checkout at a different
  path; run the remaining GUI tests with
  `cargo test -p friendlypass-gui -- --skip wrong_password_shows_error` when
  reporting.
- **`e2e_proxy` and the real KeePassXC:** `crates/friendlypass-browser/tests/e2e_proxy.rs`
  drives the upstream `keepassxc-proxy`, which has the legacy
  `org.keepassxc.KeePassXC.BrowserServer` path compiled in. The test skips when
  that path already exists (KeePassXC's browser integration is serving it) and
  otherwise removes the path when it is done. friendlypass itself always serves
  `org.friendlypass.BrowserServer` (`FP_APP_SOCKET` overrides either).
- **Extension deps:** `extension/node_modules` is git-ignored and required by
  every npm/vitest/Playwright command. Run `npm ci --prefer-offline` once.
- **Firefox e2e is pinned:** the test browser version lives in
  `extension/tests/firefox/config.mjs` (`stable_161.0` unless
  `FP_FIREFOX_VERSION` overrides). The harness downloads it into
  `extension/.cache/firefox`; the first run is slow.
- **KDBX `IconID` is preserved:** editing/saving must not replace an entry's or
  group's standard icon. Covered by
  `crates/friendlypass-gui/tests/gui.rs::non_default_icon_ids_survive_edit_and_save`.
- **Never log credentials or keys:** no passwords, key-file bytes, session keys,
  association keys or decrypted frames in logs/stdout. The host's stdout is a
  protocol channel; use stderr for diagnostics. Test fixture passwords are the
  public values documented in `README.md`.
- **Windows: browser integration works, the SSH agent does not (yet).** The app
  link is a per-user named pipe (`pipe.rs`, `server_windows.rs`), peer
  verification uses `GetNamedPipeClientProcessId` + image path, the host's
  parent browser is identified from its Authenticode signer, and
  `friendlypass-browser-host --install` writes `HKCU` registry entries for
  Chrome/Chromium/Edge/Brave/Firefox. The native-messaging host binary is built
  and shipped in the Windows zip. The SSH agent still needs a Unix domain
  socket and keeps its "not available on Windows yet" dialog. Windows CI jobs:
  `browser-ext.yml` runs the browser/host tests, `release.yml` builds the GUI,
  CLI and host. On a macOS host, `cargo check/clippy --target
  x86_64-pc-windows-gnu` type-checks the Windows code; Windows-only tests can
  only run on `windows-latest`.
- **Licence:** GPL-3.0-only (`LICENSE`, workspace `license`). When copying
  third-party code or assets, record provenance and licences in `NOTICE.md` and
  `LICENSES/`; the extension and app bundle must keep the notices.

## Working rules

- Do not commit, push, merge, rebase or tag unless the person coordinating the
  change asks for it.
- Stay inside the files named by the task. Read anything, edit only your
  scope; if a shared/frozen file (`protocol/*`, generated fixtures, build
  plumbing) must change, stop and report it.
- Do not weaken, delete or skip tests, and do not raise timeouts to hide a
  failure. The only acceptable skip is the documented worktree snapshot above,
  and only for a report run, not by editing the test.
- Prove every fix with a test that fails without the fix and passes with it;
  name the test in your report.
- Keep `AGENTS.md` honest: if you add/move a key file or command, update this
  map in the same change.
- Finish with a factual report: files changed, test names + exact commands +
  results, commands not run and why, and any remaining gaps.
