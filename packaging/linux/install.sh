#!/bin/sh
# Install friendlypass for the current user:
#
#   $PREFIX/bin/friendlypass-gui          (PREFIX defaults to ~/.local)
#   $PREFIX/bin/friendlypass-browser-host (registered from Settings)
#   $PREFIX/share/applications/friendlypass.desktop
#   $PREFIX/share/icons/hicolor/.../friendlypass.png
#
# Works from this repository (builds if needed) and from an extracted release
# tarball that already contains bin/ and share/.
#
# Usage:
#   packaging/linux/install.sh [debug|release]
#   PREFIX=/opt/friendlypass ./install.sh release
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${1:-release}"

case "$PROFILE" in
    debug|release) ;;
    *)
        echo "usage: $0 [debug|release]" >&2
        exit 1
        ;;
esac

if [ -x "$HERE/bin/friendlypass-gui" ] && [ -x "$HERE/bin/friendlypass-browser-host" ]; then
    # Extracted release tarball.
    GUI="$HERE/bin/friendlypass-gui"
    HOST="$HERE/bin/friendlypass-browser-host"
    DESKTOP="$HERE/share/applications/friendlypass.desktop"
    ICON_ROOT="$HERE/share/icons/hicolor"
else
    # Source checkout: build both binaries.
    ROOT="$(cd "$HERE/../.." && pwd)"
    if [ ! -x "$ROOT/target/$PROFILE/friendlypass-gui" ] ||
        [ ! -x "$ROOT/target/$PROFILE/friendlypass-browser-host" ]; then
        cargo build --profile "$PROFILE" -p friendlypass-gui -p friendlypass-browser-host \
            --manifest-path "$ROOT/Cargo.toml"
    fi
    GUI="$ROOT/target/$PROFILE/friendlypass-gui"
    HOST="$ROOT/target/$PROFILE/friendlypass-browser-host"
    DESKTOP="$ROOT/packaging/linux/friendlypass.desktop"
    ICON_ROOT="$ROOT/packaging/linux/icons/hicolor"
fi

PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"
APPS="$PREFIX/share/applications"
ICONS="$PREFIX/share/icons/hicolor"

install -d "$BIN" "$APPS"
install -m755 "$GUI" "$BIN/friendlypass-gui"
install -m755 "$HOST" "$BIN/friendlypass-browser-host"

# Absolute Exec= works even when $PREFIX/bin is not on PATH.
sed "s|^Exec=friendlypass-gui|Exec=$BIN/friendlypass-gui|" \
    "$DESKTOP" > "$APPS/friendlypass.desktop"

for png in "$ICON_ROOT"/*/apps/friendlypass.png; do
    [ -f "$png" ] || continue
    size="$(basename "$(dirname "$(dirname "$png")")")"
    install -d "$ICONS/$size/apps"
    install -m644 "$png" "$ICONS/$size/apps/friendlypass.png"
done

# Best-effort desktop caches; the entry works without them.
command -v update-desktop-database >/dev/null 2>&1 &&
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache >/dev/null 2>&1 &&
    gtk-update-icon-cache -q -t "$ICONS" >/dev/null 2>&1 || true

echo "Installed friendlypass to $PREFIX"
echo "  GUI:  $BIN/friendlypass-gui"
echo "  host: $BIN/friendlypass-browser-host"
echo
echo "Next: start friendlypass, open Settings and tools → Browser…, enable"
echo "browser integration, then install the browser extension."
