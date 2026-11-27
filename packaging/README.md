# Packaging

The GUI is a normal Rust binary; these files make desktop launchers start it
as a GUI instead of opening a terminal.

The macOS bundle, the Linux tarball and the Windows zip ship two executables:
`friendlypass-gui` and `friendlypass-browser-host` (the native-messaging host).
The app finds the host next to its own executable and registers it with
browsers from Settings → Browser Integration, so the binaries must stay in the
same directory. On Windows the host is `friendlypass-browser-host.exe`.

## End-user flow (browser integration)

1. Install the app (macOS `.app` bundle, Linux tarball/`install.sh`, or the
   Windows zip).
2. Start friendlypass and open **Settings and tools → Browser…**. Tick
   **Enable browser integration** and the browsers you use. This writes
   `org.friendlypass.browser.json` in each browser's own native-messaging
   folder (or under `%LOCALAPPDATA%\friendlypass\` plus the browser's `HKCU`
   registry key on Windows), pointing at the bundled host.
3. Install the friendlypass extension in those browsers (Chrome Web Store /
   Firefox add-ons, or a development build). The extension then talks to the
   running app.

Only browsers that have been started at least once are listed as available:
the app checks for the browser's per-user configuration root and shows missing
browsers disabled as “(not installed)”. Nothing is written for them, so
enabling integration never leaves empty Brave/Edge directories in `$HOME`.

Turning a browser off (or integration itself off) removes only that
`org.friendlypass.browser.json`; other native hosts are never touched. On
every start the app re-writes an outdated manifest, so moving or updating the
app keeps the registration valid.

## macOS

```sh
./packaging/macos/install.sh                    # build + install to /Applications
open -b org.friendlypass.friendlypass           # or open it from Finder/Launchpad
```

`package.sh` builds `target/release/friendlypass.app` (or
`./packaging/macos/package.sh debug`) if you prefer to copy it yourself.

`package.sh` builds `friendlypass-gui`, `friendlypass-browser-host`, and the
macOS AutoFill Credential Provider extension
(`Contents/PlugIns/FriendlyPassCredentialProvider.appex`, supporting Passkeys,
Passwords, and macOS 15+ One-Time Codes), installs `Info.plist` and
`AppIcon.icns`, and signs the bundle inside-out.

### Enabling macOS Passkeys & AutoFill

macOS requires the restricted
`com.apple.developer.authentication-services.autofill-credential-provider`
entitlement (plus a shared App Group) backed by Apple provisioning profiles
before the extension appears in **System Settings → General → AutoFill &
Passwords**:

1. In Apple Developer Portal, create:
   - An **App Group** (keep it short so the Unix socket path stays under 104 bytes, e.g. `<TEAM_ID>.org.friendlypass`).
   - An **App ID** for the host app (e.g. `org.friendlypass.friendlypass`) with **AutoFill Credential Provider** and **App Groups** enabled.
   - An **App ID** for the extension (`<app-bundle-id>.credential-provider`) with **AutoFill Credential Provider** and **App Groups** enabled.
   - Two macOS **Provisioning Profiles** (Development or Developer ID), one for the host app and one for the extension.
2. Build and sign using `package.sh` (or `install.sh` to copy into `/Applications` and register with LaunchServices):

```sh
FP_CODESIGN_IDENTITY="Apple Development: Your Name (TEAMID)" \
FP_APP_PROFILE=/path/to/friendlypass_app.provisionprofile \
FP_EXT_PROFILE=/path/to/friendlypass_ext.provisionprofile \
./packaging/macos/install.sh release
```

`package.sh` automatically reads the bundle IDs, Team ID, and App Group from the
provisioning profiles (all can still be overridden with `FP_BUNDLE_ID`,
`FP_EXT_BUNDLE_ID`, `FP_TEAM_ID`, and `FP_APP_GROUP`), embeds the profiles,
signs inside-out with the required entitlements, and verifies with
`codesign --verify --deep --strict`.

3. Open **friendlypass** once (so LaunchServices registers the embedded `.appex`),
   then enable **friendlypass** under **System Settings → General → AutoFill &
   Passwords**.

Without `FP_CODESIGN_IDENTITY` and the provisioning profiles, `package.sh` still
builds and bundles the `.appex` with an ad-hoc sandbox-only signature (omitting
the restricted entitlement so AMFI does not block launch).

Verify the bundle contains the host and credential provider extension:

```sh
ls -l target/release/friendlypass.app/Contents/MacOS/
ls -l target/release/friendlypass.app/Contents/PlugIns/
codesign --verify --deep --strict target/release/friendlypass.app
```

## Windows

Release builds carry `#![cfg_attr(not(debug_assertions), windows_subsystem =
"windows")]`, so `friendlypass-gui.exe` is a GUI-subsystem binary and double-clicking
it opens no console. Debug builds keep the console for diagnostics.

The Windows zip contains `friendlypass-gui.exe`, `friendlypass.exe` (CLI) and
`friendlypass-browser-host.exe`; keep them together. Browser integration works
exactly as on macOS/Linux: the GUI serves the browser protocol on the per-user
named pipe `\\.\pipe\org.friendlypass.BrowserServer_<USERNAME>` and registers
the native host in each browser's `HKCU` key (Chrome, Chromium, Edge, Brave and
Firefox). The host manifest files live under `%LOCALAPPDATA%\friendlypass\`.

End-user flow:

1. Unzip the release anywhere and run `friendlypass-gui.exe` once. On startup
   it rewrites a stale native-host registration, so a moved/updated install
   keeps working.
2. Open **Settings and tools → Browser…**, tick **Enable browser integration**
   and the browsers you use.
3. Install the friendlypass extension in those browsers.

The SSH agent remains Unix-only for now (it serves a Unix domain socket); its
dialog says so on Windows.

## Linux

Build a relocatable, user-installable tarball:

```sh
./packaging/linux/package.sh release
# target/release/friendlypass-<version>-linux-<arch>.tar.gz
```

The tarball contains:

```
bin/friendlypass-gui
bin/friendlypass-browser-host
share/applications/friendlypass.desktop
share/icons/hicolor/<size>/apps/friendlypass.png
install.sh
```

Install it for the current user (`PREFIX` defaults to `~/.local`):

```sh
tar -xzf target/release/friendlypass-*-linux-*.tar.gz
./friendlypass-*-linux-*/install.sh
# or, from a source checkout (builds debug/release as needed):
./packaging/linux/install.sh release
PREFIX=/opt/friendlypass ./packaging/linux/install.sh release
```

`install.sh` puts both binaries in `$PREFIX/bin`, writes the desktop entry
with an absolute `Exec=` (works without `$PREFIX/bin` on `PATH`) and copies
the hicolor icons. It deliberately does **not** register browser manifests:
that is the Browser Integration settings' job, so ticking/unticking browsers
in the app stays the single source of truth.

[`linux/friendlypass.desktop`](linux/friendlypass.desktop) and the hicolor
icon set are what desktop environments read. `Terminal=false` makes the
desktop launch the GUI without a terminal emulator. Installing the files
manually also works:

```sh
install -Dm644 packaging/linux/friendlypass.desktop \
    ~/.local/share/applications/friendlypass.desktop
install -Dm644 packaging/linux/icons/hicolor/256x256/apps/friendlypass.png \
    ~/.local/share/icons/hicolor/256x256/apps/friendlypass.png
```

The window itself also carries the icon (`brand::window_icon` in
`crates/friendlypass-gui/src/brand.rs`), which is what most window managers
use when the app is started from a terminal.

## Releases

`.github/workflows/release.yml` builds every artifact and publishes one GitHub
Release. Push a version tag:

```sh
# 1. All four version fields must agree (the workflow's `version` job fails
#    otherwise): Cargo.toml [workspace.package].version, extension/package.json,
#    extension/src/manifest.json, android/app/build.gradle.kts appVersionName.
# 2. Tag and push.
git tag v0.1.0
git push origin v0.1.0
```

The release is titled `friendlypass 0.1.0` and contains:

| File | Contents |
|---|---|
| `friendlypass-0.1.0-macos-arm64.zip` | `friendlypass.app` (GUI + browser host) for Apple silicon, ad-hoc signed, not notarized |
| `friendlypass-0.1.0-macos-x86_64.zip` | the same bundle for Intel Macs |
| `friendlypass-0.1.0-linux-x86_64.tar.gz` | the `packaging/linux/package.sh release` tarball (GUI + browser host) |
| `friendlypass-0.1.0-linux-aarch64.tar.gz` | the same tarball for arm64 |
| `friendlypass-0.1.0-windows-x86_64.zip` | `friendlypass-gui.exe`, `friendlypass.exe` (CLI), `friendlypass-browser-host.exe`, `LICENSE` and `NOTICE.md` |
| `friendlypass-0.1.0-android.apk` | signed release APK |
| `friendlypass-chrome-0.1.0.zip` | unpacked Chrome extension build |
| `friendlypass-firefox-0.1.0.zip` | unpacked Firefox extension build |
| `SHA256SUMS` | checksums of the files above |

Run **Actions → release → Run workflow** (`workflow_dispatch`) for a dry run:
the same builds run and are uploaded as run artifacts, but no release is
created. Android is unsigned in that mode unless the secrets below are set.

### Android signing secrets

The release APK is signed from four repository secrets; no keystore or
password is ever committed to the repository.

| Secret | Value |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | base64 of the `.jks`/`.p12` keystore |
| `ANDROID_KEYSTORE_PASSWORD` | keystore password |
| `ANDROID_KEY_ALIAS` | key alias |
| `ANDROID_KEY_PASSWORD` | key password |

A tag build requires all four (it fails otherwise) and verifies the APK with
`apksigner verify --print-certs` before upload. A `workflow_dispatch` run with
no secrets builds an unsigned APK and prints a warning; a partially configured
set is an error in both modes. The decoded keystore's format (JKS or PKCS#12)
is detected automatically.

Create the base64 value and store the keystore somewhere safe outside the
repository:

```sh
# macOS
base64 -i release.jks | pbcopy
# Linux
base64 -w0 release.jks
```

`versionName` comes from `appVersionName` in
`android/app/build.gradle.kts`; `versionCode` is derived from it as
`major*10000 + minor*100 + patch` (0.1.0 → 100), so it grows with every
release.

## Icon artwork

One 1024×1024 RGBA master — `crates/friendlypass-gui/assets/app-icon.png` —
feeds everything else:

* `packaging/macos/AppIcon.icns` — the same master at 16/32/128/256/512/1024
  (`iconutil -c icns` on a standard `AppIcon.iconset/` directory).
* `packaging/linux/icons/hicolor/<size>/apps/friendlypass.png` — per-size
  PNGs.
* the embedded window icon, compiled into the binary.

To change the icon, replace the master and regenerate the derived files:

```sh
# icns (macOS): sizes 16, 32, 128, 256, 512, 1024 into a standard iconset
python3 - <<'PY'
from PIL import Image
m = Image.open('crates/friendlypass-gui/assets/app-icon.png')
spec = {'icon_16x16.png': 16, 'icon_16x16@2x.png': 32, 'icon_32x32.png': 32,
        'icon_32x32@2x.png': 64, 'icon_128x128.png': 128,
        'icon_128x128@2x.png': 256, 'icon_256x256.png': 256,
        'icon_256x256@2x.png': 512, 'icon_512x512@2x.png': 1024}
for name, px in spec.items():
    m.resize((px, px), Image.LANCZOS).save('AppIcon.iconset/' + name)
PY
iconutil -c icns AppIcon.iconset -o packaging/macos/AppIcon.icns
# hicolor PNGs (Linux)
for s in 16 32 64 128 256 512 1024; do
    mkdir -p packaging/linux/icons/hicolor/${s}x${s}/apps
    sips -z $s $s crates/friendlypass-gui/assets/app-icon.png \
        --out packaging/linux/icons/hicolor/${s}x${s}/apps/friendlypass.png >/dev/null
done
```
