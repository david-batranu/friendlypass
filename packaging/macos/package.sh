#!/bin/sh
# Build KeePassXC-RS.app so macOS launches the GUI directly, without a
# Terminal window. Usage: packaging/macos/package.sh [debug|release]
set -eu
PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/target/$PROFILE/KeePassXC-RS.app"

cargo build --profile "$PROFILE" -p kpxc-gui --manifest-path "$ROOT/Cargo.toml"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$ROOT/target/$PROFILE/kpxc-gui" "$APP/Contents/MacOS/kpxc-gui"
cp "$ROOT/packaging/macos/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/packaging/macos/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
chmod +x "$APP/Contents/MacOS/kpxc-gui"

# Ad-hoc signature: enough for a locally built bundle, and keeps Gatekeeper
# from treating it as a broken app. Replace with a Developer ID for shipping.
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true

echo "Created $APP"
echo "Launch it with: open \"$APP\"   (or double-click it in Finder)"
