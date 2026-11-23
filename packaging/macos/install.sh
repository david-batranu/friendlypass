#!/bin/sh
# Build and install friendlypass.app into /Applications (or ~/Applications
# when /Applications is not writable). Usage: packaging/macos/install.sh
set -eu
PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

"$ROOT/packaging/macos/package.sh" "$PROFILE"

DEST=/Applications
if [ ! -w "$DEST" ]; then
    DEST="$HOME/Applications"
    mkdir -p "$DEST"
fi
rm -rf "$DEST/friendlypass.app"
ditto "$ROOT/target/$PROFILE/friendlypass.app" "$DEST/friendlypass.app"

LSREG=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$LSREG" -f "$DEST/friendlypass.app" >/dev/null 2>&1 || true

echo "Installed $DEST/friendlypass.app"
echo "Open it from Finder/Launchpad, or: open -b org.friendlypass.friendlypass"
