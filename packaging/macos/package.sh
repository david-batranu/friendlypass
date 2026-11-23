#!/bin/sh
# Build friendlypass.app so macOS launches the GUI directly, without a
# Terminal window. Usage: packaging/macos/package.sh [debug|release]
set -eu
PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/target/$PROFILE/friendlypass.app"

cargo build --profile "$PROFILE" -p friendlypass-gui --manifest-path "$ROOT/Cargo.toml"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$ROOT/target/$PROFILE/friendlypass-gui" "$APP/Contents/MacOS/friendlypass-gui"
cp "$ROOT/packaging/macos/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/packaging/macos/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
chmod +x "$APP/Contents/MacOS/friendlypass-gui"

# Ad-hoc signature: enough for a locally built bundle, and keeps Gatekeeper
# from treating it as a broken app. Replace with a Developer ID for shipping.
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true

echo "Created $APP"
echo "Launch it with: open \"$APP\"   (or double-click it in Finder)"
