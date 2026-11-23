#!/bin/sh
# Build and install KeePassXC-RS.app into /Applications (or ~/Applications
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
rm -rf "$DEST/KeePassXC-RS.app"
ditto "$ROOT/target/$PROFILE/KeePassXC-RS.app" "$DEST/KeePassXC-RS.app"

LSREG=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$LSREG" -f "$DEST/KeePassXC-RS.app" >/dev/null 2>&1 || true

echo "Installed $DEST/KeePassXC-RS.app"
echo "Open it from Finder/Launchpad, or: open -b org.keepassxc.rs"
