# Packaging

The GUI is a normal Rust binary; these files make desktop launchers start it
as a GUI instead of opening a terminal.

## macOS

```sh
./packaging/macos/install.sh                    # build + install to /Applications
open -b org.friendlypass.friendlypass           # or open it from Finder/Launchpad
```

`package.sh` builds only `target/release/friendlypass.app` (or
`./packaging/macos/package.sh debug`) if you prefer to copy it yourself.

`package.sh` builds `friendlypass-gui`, copies it into
`friendlypass.app/Contents/MacOS`, installs `Info.plist` (bundle id
`org.friendlypass.friendlypass`) and `AppIcon.icns`, and ad-hoc signs the
bundle. LaunchServices then starts the executable directly, so no Terminal
window appears. Replace the ad-hoc signature with a Developer ID
(`codesign --sign "Developer ID Application: …"`) before distributing.

## Windows

Release builds carry `#![cfg_attr(not(debug_assertions), windows_subsystem =
"windows")]`, so `friendlypass-gui.exe` is a GUI-subsystem binary and double-clicking
it opens no console. Debug builds keep the console for diagnostics.

## Linux

[`linux/friendlypass.desktop`](linux/friendlypass.desktop) and the hicolor
icon set are what desktop environments read; installing both makes the
launcher show the icon (the `Exec=` line assumes `friendlypass-gui` is on
`PATH`). `Terminal=false` makes the desktop launch the GUI without a
terminal emulator.

```sh
install -Dm644 packaging/linux/friendlypass.desktop \
    ~/.local/share/applications/friendlypass.desktop
install -Dm644 packaging/linux/icons/hicolor/256x256/apps/friendlypass.png \
    ~/.local/share/icons/hicolor/256x256/apps/friendlypass.png
```

The window itself also carries the icon (`brand::window_icon` in
`crates/friendlypass-gui/src/brand.rs`), which is what most window managers
use when the app is started from a terminal.

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
