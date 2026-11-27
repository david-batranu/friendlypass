#!/bin/sh
# Build friendlypass.app so macOS launches the GUI directly, without a
# Terminal window. Bundles:
#   - friendlypass-gui (desktop app)
#   - friendlypass-browser-host (browser native-messaging host)
#   - PlugIns/FriendlyPassCredentialProvider.appex (macOS Passkey, Password & TOTP provider)
#
# Usage:
#   packaging/macos/package.sh [debug|release]
#
# Optional signing environment variables (for macOS System Settings -> AutoFill & Passwords):
#   FP_CODESIGN_IDENTITY  Signing identity (e.g. "Apple Development: ..." or "Developer ID Application: ...")
#   FP_APP_PROFILE        Path to macOS .provisionprofile for the host app
#   FP_EXT_PROFILE        Path to macOS .provisionprofile for the credential provider .appex
#   FP_BUNDLE_ID          Override host bundle ID (auto-detected from FP_APP_PROFILE if set)
#   FP_EXT_BUNDLE_ID      Override extension bundle ID (auto-detected from FP_EXT_PROFILE if set)
#   FP_TEAM_ID            Override Apple Team ID (auto-detected from FP_APP_PROFILE if set)
#   FP_APP_GROUP          Override App Group ID (auto-detected from FP_EXT_PROFILE if set)
set -eu

PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/target/$PROFILE/friendlypass.app"
CP_DIR="$ROOT/packaging/macos/credential-provider"
PLIST_BUDDY=/usr/libexec/PlistBuddy

VERSION="$("$PLIST_BUDDY" -c 'Print :CFBundleShortVersionString' "$ROOT/packaging/macos/Info.plist")"

# Extract a key from a .provisionprofile CMS envelope using security + PlistBuddy.
profile_value() {
    PROFILE_PATH="$1"
    KEY_PATH="$2"
    TMP_PLIST="$(mktemp)"
    if security cms -D -i "$PROFILE_PATH" > "$TMP_PLIST" 2>/dev/null; then
        VAL="$("$PLIST_BUDDY" -c "Print :${KEY_PATH}" "$TMP_PLIST" 2>/dev/null || true)"
    else
        VAL=""
    fi
    rm -f "$TMP_PLIST"
    printf '%s' "$VAL"
}

SIGN_ID="${FP_CODESIGN_IDENTITY:-}"
APP_PROFILE="${FP_APP_PROFILE:-}"
EXT_PROFILE="${FP_EXT_PROFILE:-}"
TEAM_ID="${FP_TEAM_ID:-}"
APP_BUNDLE_ID="${FP_BUNDLE_ID:-}"
EXT_BUNDLE_ID="${FP_EXT_BUNDLE_ID:-}"
APP_GROUP="${FP_APP_GROUP:-}"

if [ -n "$APP_PROFILE" ]; then
    if [ ! -f "$APP_PROFILE" ]; then
        echo "FP_APP_PROFILE not found: $APP_PROFILE" >&2
        exit 1
    fi
    if [ -z "$TEAM_ID" ]; then
        TEAM_ID="$(profile_value "$APP_PROFILE" 'TeamIdentifier:0')"
    fi
    if [ -z "$APP_BUNDLE_ID" ]; then
        FULL_ID="$(profile_value "$APP_PROFILE" 'Entitlements:com.apple.application-identifier')"
        if [ -n "$TEAM_ID" ] && [ -n "$FULL_ID" ]; then
            APP_BUNDLE_ID="${FULL_ID#${TEAM_ID}.}"
        fi
    fi
fi

if [ -n "$EXT_PROFILE" ]; then
    if [ ! -f "$EXT_PROFILE" ]; then
        echo "FP_EXT_PROFILE not found: $EXT_PROFILE" >&2
        exit 1
    fi
    if [ -z "$TEAM_ID" ]; then
        TEAM_ID="$(profile_value "$EXT_PROFILE" 'TeamIdentifier:0')"
    fi
    if [ -z "$EXT_BUNDLE_ID" ]; then
        FULL_EXT_ID="$(profile_value "$EXT_PROFILE" 'Entitlements:com.apple.application-identifier')"
        if [ -n "$TEAM_ID" ] && [ -n "$FULL_EXT_ID" ]; then
            EXT_BUNDLE_ID="${FULL_EXT_ID#${TEAM_ID}.}"
        fi
    fi
    if [ -z "$APP_GROUP" ]; then
        APP_GROUP="$(profile_value "$EXT_PROFILE" 'Entitlements:com.apple.security.application-groups:0')"
    fi
fi

APP_BUNDLE_ID="${APP_BUNDLE_ID:-org.friendlypass.friendlypass}"
EXT_BUNDLE_ID="${EXT_BUNDLE_ID:-${APP_BUNDLE_ID}.credential-provider}"
if [ -z "$APP_GROUP" ]; then
    if [ -n "$TEAM_ID" ]; then
        APP_GROUP="${TEAM_ID}.org.friendlypass"
    else
        APP_GROUP="org.friendlypass.shared"
    fi
fi

cargo build --profile "$PROFILE" -p friendlypass-gui -p friendlypass-browser-host \
    --manifest-path "$ROOT/Cargo.toml"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/PlugIns"
cp "$ROOT/target/$PROFILE/friendlypass-gui" "$APP/Contents/MacOS/friendlypass-gui"
cp "$ROOT/target/$PROFILE/friendlypass-browser-host" \
    "$APP/Contents/MacOS/friendlypass-browser-host"
cp "$ROOT/packaging/macos/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/packaging/macos/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp "$ROOT/LICENSE" "$APP/Contents/Resources/LICENSE"
cp "$ROOT/NOTICE.md" "$APP/Contents/Resources/NOTICE.md"
chmod +x "$APP/Contents/MacOS/friendlypass-gui"
chmod +x "$APP/Contents/MacOS/friendlypass-browser-host"

"$PLIST_BUDDY" -c "Set :CFBundleIdentifier $APP_BUNDLE_ID" "$APP/Contents/Info.plist"
"$PLIST_BUDDY" -c "Set :FPAppGroupIdentifier $APP_GROUP" "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null

# Build the macOS AutoFill Credential Provider extension (Passkeys, Passwords, TOTP).
APPEX="$APP/Contents/PlugIns/FriendlyPassCredentialProvider.appex"
"$CP_DIR/build.sh" \
    "$APPEX" \
    "$APP_BUNDLE_ID" \
    "$EXT_BUNDLE_ID" \
    "$APP_GROUP" \
    "$VERSION" \
    "$PROFILE"

ENT_TMP="$(mktemp -d)"
trap 'rm -rf "$ENT_TMP"' EXIT

if [ -n "$SIGN_ID" ] && [ -n "$APP_PROFILE" ] && [ -n "$EXT_PROFILE" ]; then
    cp "$EXT_PROFILE" "$APPEX/Contents/embedded.provisionprofile"
    cp "$APP_PROFILE" "$APP/Contents/embedded.provisionprofile"

    sed "s|__APP_GROUP__|${APP_GROUP}|g" \
        "$CP_DIR/Extension.entitlements.template" > "$ENT_TMP/Extension.entitlements"
    sed "s|__APP_GROUP__|${APP_GROUP}|g" \
        "$CP_DIR/App.entitlements.template" > "$ENT_TMP/App.entitlements"

    # Enable hardened runtime + secure timestamp for Developer ID distribution builds.
    SIGN_EXTRA=""
    case "$SIGN_ID" in
        "Developer ID Application:"*)
            SIGN_EXTRA="--options runtime --timestamp"
            ;;
        *)
            SIGN_EXTRA="--timestamp=none"
            ;;
    esac

    # Sign inside-out so nested binaries and the .appex have valid signatures.
    # shellcheck disable=SC2086
    codesign --force --sign "$SIGN_ID" $SIGN_EXTRA \
        --entitlements "$ENT_TMP/Extension.entitlements" \
        "$APPEX"
    # shellcheck disable=SC2086
    codesign --force --sign "$SIGN_ID" $SIGN_EXTRA \
        "$APP/Contents/MacOS/friendlypass-browser-host"
    # shellcheck disable=SC2086
    codesign --force --sign "$SIGN_ID" $SIGN_EXTRA \
        --entitlements "$ENT_TMP/App.entitlements" \
        "$APP/Contents/MacOS/friendlypass-gui"
    # shellcheck disable=SC2086
    codesign --force --sign "$SIGN_ID" $SIGN_EXTRA \
        --entitlements "$ENT_TMP/App.entitlements" \
        "$APP"

    codesign --verify --deep --strict "$APP"
    SIGN_MODE="signed ($SIGN_ID, AutoFill Credential Provider entitled)"
else
    # Ad-hoc signature (or Developer cert without provisioning profiles):
    # Do not attach the restricted autofill-credential-provider entitlement
    # without matching embedded provisioning profiles, or AMFI will reject launch.
    TARGET_SIGN="${SIGN_ID:--}"
    codesign --force --sign "$TARGET_SIGN" \
        --entitlements "$CP_DIR/Extension.adhoc.entitlements" \
        "$APPEX"
    codesign --force --sign "$TARGET_SIGN" "$APP/Contents/MacOS/friendlypass-browser-host"
    codesign --force --sign "$TARGET_SIGN" "$APP/Contents/MacOS/friendlypass-gui"
    codesign --force --sign "$TARGET_SIGN" "$APP"
    codesign --verify --deep --strict "$APP"
    SIGN_MODE="ad-hoc (set FP_CODESIGN_IDENTITY, FP_APP_PROFILE, FP_EXT_PROFILE to enable System Settings -> AutoFill & Passwords)"
fi

echo "Created $APP ($SIGN_MODE)"
echo "  GUI:       $APP/Contents/MacOS/friendlypass-gui"
echo "  host:      $APP/Contents/MacOS/friendlypass-browser-host"
echo "  extension: $APPEX ($EXT_BUNDLE_ID, group $APP_GROUP)"
echo "Launch it with: open \"$APP\"   (or double-click it in Finder)"
