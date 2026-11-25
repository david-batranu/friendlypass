#!/bin/sh
# Build friendlypass.app so macOS launches the GUI directly, without a
# Terminal window. The browser-integration host is bundled next to the GUI so
# the app can register itself with browsers from Settings.
# Usage: packaging/macos/package.sh [debug|release]
set -eu
PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/target/$PROFILE/friendlypass.app"

cargo build --profile "$PROFILE" -p friendlypass-gui -p friendlypass-browser-host \
    --manifest-path "$ROOT/Cargo.toml"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$ROOT/target/$PROFILE/friendlypass-gui" "$APP/Contents/MacOS/friendlypass-gui"
cp "$ROOT/target/$PROFILE/friendlypass-browser-host" \
    "$APP/Contents/MacOS/friendlypass-browser-host"
cp "$ROOT/packaging/macos/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/packaging/macos/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
chmod +x "$APP/Contents/MacOS/friendlypass-gui"
chmod +x "$APP/Contents/MacOS/friendlypass-browser-host"

# Ad-hoc signature: enough for a locally built bundle, and keeps Gatekeeper
# from treating it as a broken app. The native-messaging host is a nested
# executable, so it is signed exactly like the GUI. Replace with a Developer
# ID for shipping.
sign() {
    codesign --force --sign - "$1" >/dev/null 2>&1 || true
}
sign "$APP/Contents/MacOS/friendlypass-browser-host"
sign "$APP/Contents/MacOS/friendlypass-gui"
sign "$APP"

echo "Created $APP"
echo "  GUI:  $APP/Contents/MacOS/friendlypass-gui"
echo "  host: $APP/Contents/MacOS/friendlypass-browser-host"
echo "Launch it with: open \"$APP\"   (or double-click it in Finder)"
