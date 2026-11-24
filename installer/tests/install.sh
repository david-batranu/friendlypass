#!/usr/bin/env bash
#
# Exercise installer/install.sh in a throw-away HOME, for both macOS and Linux
# manifest layouts. Writes nothing outside the temp directory.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL="$HERE/../install.sh"

CHROME_ID="abcdefghijklmnopabcdefghijklmnop"
FF_ID="friendlypass@test.invalid"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/fp-installer.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

ok() {
    printf 'ok - %s\n' "$*"
}

[[ -x "$INSTALL" ]] || fail "install.sh is not executable: $INSTALL"

FAKE_HOST="$TMP_ROOT/bin/friendlypass-browser-host"
mkdir -p "$(dirname "$FAKE_HOST")"
printf '#!/bin/sh\nexit 0\n' > "$FAKE_HOST"
chmod +x "$FAKE_HOST"

install_ok() {
    if ! "$INSTALL" "$@" >"$TMP_ROOT/last.log" 2>&1; then
        cat "$TMP_ROOT/last.log" >&2
        fail "install.sh failed: $*"
    fi
}

expect_fail() {
    if "$INSTALL" "$@" >"$TMP_ROOT/last.log" 2>&1; then
        fail "expected install.sh to fail: $*"
    fi
}

check_manifest() {
    local file="$1" kind="$2"
    [[ -f "$file" ]] || fail "missing manifest: $file"
    python3 - "$file" "$kind" "$FAKE_HOST" "$CHROME_ID" "$FF_ID" <<'PY'
import json
import os
import sys

path, kind, host, chrome_id, firefox_id = sys.argv[1:6]
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)

assert data["name"] == "org.friendlypass.browser", data
assert data["type"] == "stdio", data
assert data["description"], data
assert os.path.isabs(data["path"]), data
assert data["path"] == os.path.realpath(host) or os.path.realpath(data["path"]) == os.path.realpath(host), (
    data["path"],
    os.path.realpath(host),
)
if kind == "firefox":
    assert data["allowed_extensions"] == [firefox_id], data
    assert "allowed_origins" not in data, data
else:
    assert data["allowed_origins"] == [f"chrome-extension://{chrome_id}/"], data
    assert "allowed_extensions" not in data, data
PY
}

# ---------------------------------------------------------------------------
# macOS layout
# ---------------------------------------------------------------------------

MAC_HOME="$TMP_ROOT/home mac" # a space proves the quoting
mkdir -p "$MAC_HOME"

install_ok --platform macos --home "$MAC_HOME" --extension-id "$CHROME_ID" \
    --firefox-extension-id "$FF_ID" --host-path "$FAKE_HOST"

MAC_CHROME="Library/Application Support/Google/Chrome/NativeMessagingHosts"
MAC_CHROMIUM="Library/Application Support/Chromium/NativeMessagingHosts"
MAC_BRAVE="Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
MAC_EDGE="Library/Application Support/Microsoft Edge/NativeMessagingHosts"
MAC_FIREFOX="Library/Application Support/Mozilla/NativeMessagingHosts"

for dir in "$MAC_CHROME" "$MAC_CHROMIUM" "$MAC_BRAVE" "$MAC_EDGE"; do
    check_manifest "$MAC_HOME/$dir/org.friendlypass.browser.json" chromium
done
check_manifest "$MAC_HOME/$MAC_FIREFOX/org.friendlypass.browser.json" firefox
ok "macOS manifests for chrome, chromium, brave, edge, firefox"

# Idempotent re-install.
install_ok --platform macos --home "$MAC_HOME" --extension-id "$CHROME_ID" \
    --firefox-extension-id "$FF_ID" --host-path "$FAKE_HOST"
check_manifest "$MAC_HOME/$MAC_CHROME/org.friendlypass.browser.json" chromium
ok "macOS re-install is idempotent"

# ---------------------------------------------------------------------------
# Linux layout
# ---------------------------------------------------------------------------

LINUX_HOME="$TMP_ROOT/home-linux"
mkdir -p "$LINUX_HOME"

install_ok --platform linux --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --firefox-extension-id "$FF_ID" --host-path "$FAKE_HOST"

LINUX_CHROME=".config/google-chrome/NativeMessagingHosts"
LINUX_CHROMIUM=".config/chromium/NativeMessagingHosts"
LINUX_BRAVE=".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
LINUX_EDGE=".config/microsoft-edge/NativeMessagingHosts"
LINUX_FIREFOX=".mozilla/native-messaging-hosts"

for dir in "$LINUX_CHROME" "$LINUX_CHROMIUM" "$LINUX_BRAVE" "$LINUX_EDGE"; do
    check_manifest "$LINUX_HOME/$dir/org.friendlypass.browser.json" chromium
done
check_manifest "$LINUX_HOME/$LINUX_FIREFOX/org.friendlypass.browser.json" firefox
ok "Linux manifests for chrome, chromium, brave, edge, firefox"

# ---------------------------------------------------------------------------
# Browser selection
# ---------------------------------------------------------------------------

SELECT_HOME="$TMP_ROOT/home-select"
mkdir -p "$SELECT_HOME"
install_ok --platform linux --home "$SELECT_HOME" --extension-id "$CHROME_ID" \
    --host-path "$FAKE_HOST" --browsers chrome,firefox

[[ -f "$SELECT_HOME/$LINUX_CHROME/org.friendlypass.browser.json" ]] || fail "chrome not written"
[[ -f "$SELECT_HOME/$LINUX_FIREFOX/org.friendlypass.browser.json" ]] || fail "firefox not written"
[[ ! -e "$SELECT_HOME/$LINUX_BRAVE/org.friendlypass.browser.json" ]] || fail "brave written unexpectedly"
ok "--browsers limits the manifests written"

# --extension-id=value spelling also works.
install_ok --platform=linux --home="$SELECT_HOME" --extension-id="$CHROME_ID" \
    --host-path="$FAKE_HOST" --browsers=chromium
[[ -f "$SELECT_HOME/$LINUX_CHROMIUM/org.friendlypass.browser.json" ]] || fail "chromium not written"
ok "--option=value spelling works"

# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

expect_fail --platform linux --home "$LINUX_HOME" --host-path "$FAKE_HOST"
ok "missing --extension-id is rejected"

expect_fail --platform linux --home "$LINUX_HOME" --extension-id "not-an-id" \
    --host-path "$FAKE_HOST"
ok "invalid --extension-id is rejected"

expect_fail --platform linux --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --host-path "$TMP_ROOT/does-not-exist"
ok "missing host binary is rejected"

expect_fail --platform linux --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --host-path "$FAKE_HOST" --browsers netscape
ok "unknown browser is rejected"

expect_fail --platform windows --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --host-path "$FAKE_HOST"
ok "unsupported platform is rejected"

# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

DRY_HOME="$TMP_ROOT/home-dry"
mkdir -p "$DRY_HOME"
install_ok --platform linux --home "$DRY_HOME" --extension-id "$CHROME_ID" \
    --host-path "$FAKE_HOST" --dry-run
[[ ! -e "$DRY_HOME/.config" ]] || fail "--dry-run wrote files"
ok "--dry-run writes nothing"

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

install_ok --uninstall --platform linux --home "$LINUX_HOME"
for dir in "$LINUX_CHROME" "$LINUX_CHROMIUM" "$LINUX_BRAVE" "$LINUX_EDGE" "$LINUX_FIREFOX"; do
    [[ ! -e "$LINUX_HOME/$dir/org.friendlypass.browser.json" ]] || fail "uninstall left $dir"
done
ok "Linux uninstall removes every manifest"

# Uninstall is idempotent and needs no extension id.
install_ok --uninstall --platform linux --home "$LINUX_HOME"
ok "second uninstall is a no-op"

install_ok --uninstall --platform macos --home "$MAC_HOME"
[[ ! -e "$MAC_HOME/$MAC_CHROME/org.friendlypass.browser.json" ]] || fail "macOS uninstall left chrome"
ok "macOS uninstall removes manifests"

printf 'all installer tests passed\n'
