#!/bin/sh
# Build a user-installable Linux tarball:
#
#   friendlypass-<version>-linux-<arch>/
#     bin/friendlypass-gui
#     bin/friendlypass-browser-host
#     share/applications/friendlypass.desktop
#     share/icons/hicolor/<size>/apps/friendlypass.png
#     install.sh
#
# The tarball carries the native-messaging host next to the GUI; the app
# registers it from Settings → Browser Integration.
#
# Usage: packaging/linux/package.sh [debug|release]
set -eu
PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
[ -n "$VERSION" ] || {
    echo "cannot read the workspace version from Cargo.toml" >&2
    exit 1
}
ARCH="$(uname -m)"
NAME="friendlypass-$VERSION-linux-$ARCH"
STAGE="$ROOT/target/$PROFILE/$NAME"
TARBALL="$ROOT/target/$PROFILE/$NAME.tar.gz"

cargo build --profile "$PROFILE" -p friendlypass-gui -p friendlypass-browser-host \
    --manifest-path "$ROOT/Cargo.toml"

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/share/applications"
cp "$ROOT/target/$PROFILE/friendlypass-gui" "$STAGE/bin/friendlypass-gui"
cp "$ROOT/target/$PROFILE/friendlypass-browser-host" "$STAGE/bin/friendlypass-browser-host"
chmod +x "$STAGE/bin/friendlypass-gui" "$STAGE/bin/friendlypass-browser-host"
cp "$ROOT/packaging/linux/friendlypass.desktop" "$STAGE/share/applications/friendlypass.desktop"
cp "$ROOT/packaging/linux/install.sh" "$STAGE/install.sh"
chmod +x "$STAGE/install.sh"

for png in "$ROOT"/packaging/linux/icons/hicolor/*/apps/friendlypass.png; do
    [ -f "$png" ] || continue
    size="$(basename "$(dirname "$(dirname "$png")")")"
    install -d "$STAGE/share/icons/hicolor/$size/apps"
    install -m644 "$png" "$STAGE/share/icons/hicolor/$size/apps/friendlypass.png"
done

rm -f "$TARBALL"
tar -C "$ROOT/target/$PROFILE" -czf "$TARBALL" "$NAME"

echo "Created $TARBALL"
echo "Install it with: tar -xzf \"$TARBALL\" && ./$NAME/install.sh"
