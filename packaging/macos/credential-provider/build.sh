#!/bin/sh
# Compile FriendlyPassCredentialProvider.appex directly with swiftc (no Xcode project).
# Usage: build.sh <output.appex> <app-bundle-id> <ext-bundle-id> <app-group> <version> [debug|release]
set -eu

OUT_APPEX="$1"
APP_BUNDLE_ID="$2"
EXT_BUNDLE_ID="$3"
APP_GROUP="$4"
VERSION="$5"
PROFILE="${6:-release}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK="$(xcrun --show-sdk-path --sdk macosx)"
ARCH="$(uname -m)"
case "$ARCH" in
    arm64|x86_64) ;;
    *) echo "Unsupported macOS architecture: $ARCH" >&2; exit 1 ;;
esac

OPT_FLAG="-O"
if [ "$PROFILE" = "debug" ]; then
    OPT_FLAG="-Onone"
fi

rm -rf "$OUT_APPEX"
mkdir -p "$OUT_APPEX/Contents/MacOS" "$OUT_APPEX/Contents/Resources"

xcrun swiftc \
    -parse-as-library \
    -application-extension \
    -module-name FriendlyPassCredentialProvider \
    "$OPT_FLAG" \
    -target "${ARCH}-apple-macos14.0" \
    -sdk "$SDK" \
    -framework Foundation \
    -framework AppKit \
    -framework AuthenticationServices \
    -Xlinker -e -Xlinker _NSExtensionMain \
    "$SCRIPT_DIR/Sources/IPCClient.swift" \
    "$SCRIPT_DIR/Sources/IdentitySync.swift" \
    "$SCRIPT_DIR/Sources/CredentialProviderViewController.swift" \
    -o "$OUT_APPEX/Contents/MacOS/FriendlyPassCredentialProvider"

chmod +x "$OUT_APPEX/Contents/MacOS/FriendlyPassCredentialProvider"

sed \
    -e "s|__APP_BUNDLE_ID__|${APP_BUNDLE_ID}|g" \
    -e "s|__EXT_BUNDLE_ID__|${EXT_BUNDLE_ID}|g" \
    -e "s|__APP_GROUP__|${APP_GROUP}|g" \
    -e "s|__VERSION__|${VERSION}|g" \
    "$SCRIPT_DIR/Info.plist.template" > "$OUT_APPEX/Contents/Info.plist"

plutil -lint "$OUT_APPEX/Contents/Info.plist" >/dev/null
