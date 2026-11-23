# Packaging

The GUI is a normal Rust binary; these files make desktop launchers start it
as a GUI instead of opening a terminal.

## macOS

```sh
./packaging/macos/install.sh          # build + install to /Applications
open -b org.keepassxc.rs              # or open it from Finder/Launchpad
```

`package.sh` builds only `target/release/KeePassXC-RS.app` (or
`./packaging/macos/package.sh debug`) if you prefer to copy it yourself.

`package.sh` builds `kpxc-gui`, copies it into `KeePassXC-RS.app/Contents/MacOS`,
installs `Info.plist` (bundle id `org.keepassxc.rs`) and the icon, and ad-hoc
signs the bundle. LaunchServices then starts the executable directly, so no
Terminal window appears. Replace the ad-hoc signature with a Developer ID
(`codesign --sign "Developer ID Application: …"`) before distributing.

## Windows

Release builds carry `#![cfg_attr(not(debug_assertions), windows_subsystem =
"windows")]`, so `kpxc-gui.exe` is a GUI-subsystem binary and double-clicking
it opens no console. Debug builds keep the console for diagnostics.

## Linux

Copy `linux/kpxc-gui.desktop` to `~/.local/share/applications/` (adjust
`Exec=` if the binary is not on `PATH`). `Terminal=false` makes the desktop
launch the GUI without a terminal emulator.
