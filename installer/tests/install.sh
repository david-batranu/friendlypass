#!/usr/bin/env bash
#
# Exercise installer/install.sh in a throw-away HOME, for both macOS and Linux
# manifest layouts. Writes nothing outside the temp directory.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL="$HERE/../install.sh"
ROOT="$(cd "$HERE/../.." && pwd)"

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

# A browser is only registered when its per-user config root already exists.
make_mac_roots() {
    local home="$1"
    for root in \
        "Library/Application Support/Google/Chrome" \
        "Library/Application Support/Chromium" \
        "Library/Application Support/BraveSoftware/Brave-Browser" \
        "Library/Application Support/Microsoft Edge" \
        "Library/Application Support/Mozilla"
    do
        mkdir -p "$home/$root"
    done
}

make_linux_roots() {
    local home="$1"
    for root in \
        ".config/google-chrome" \
        ".config/chromium" \
        ".config/BraveSoftware/Brave-Browser" \
        ".config/microsoft-edge" \
        ".mozilla"
    do
        mkdir -p "$home/$root"
    done
}

[[ -x "$INSTALL" ]] || fail "install.sh is not executable: $INSTALL"

# The manifest logic now lives in the host binary (install.sh is a thin
# delegate), so these tests exercise the real host CLI's --install/--uninstall
# flags rather than a stub.
HOST_BIN="$ROOT/target/debug/friendlypass-browser-host"
if [[ ! -x "$HOST_BIN" ]]; then
    (cd "$ROOT" && cargo build -q -p friendlypass-browser-host) ||
        fail "cannot build friendlypass-browser-host"
fi
[[ -x "$HOST_BIN" ]] || fail "missing friendlypass-browser-host: $HOST_BIN"

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
    python3 - "$file" "$kind" "$HOST_BIN" "$CHROME_ID" "$FF_ID" <<'PY'
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
make_mac_roots "$MAC_HOME"

install_ok --platform macos --home "$MAC_HOME" --extension-id "$CHROME_ID" \
    --firefox-extension-id "$FF_ID" --host-path "$HOST_BIN"

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
    --firefox-extension-id "$FF_ID" --host-path "$HOST_BIN"
check_manifest "$MAC_HOME/$MAC_CHROME/org.friendlypass.browser.json" chromium
ok "macOS re-install is idempotent"

# ---------------------------------------------------------------------------
# Linux layout
# ---------------------------------------------------------------------------

LINUX_HOME="$TMP_ROOT/home-linux"
mkdir -p "$LINUX_HOME"
make_linux_roots "$LINUX_HOME"

install_ok --platform linux --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --firefox-extension-id "$FF_ID" --host-path "$HOST_BIN"

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
mkdir -p "$SELECT_HOME/.config/google-chrome" "$SELECT_HOME/.mozilla" \
    "$SELECT_HOME/.config/chromium"
install_ok --platform linux --home "$SELECT_HOME" --extension-id "$CHROME_ID" \
    --host-path "$HOST_BIN" --browsers chrome,firefox

[[ -f "$SELECT_HOME/$LINUX_CHROME/org.friendlypass.browser.json" ]] || fail "chrome not written"
[[ -f "$SELECT_HOME/$LINUX_FIREFOX/org.friendlypass.browser.json" ]] || fail "firefox not written"
[[ ! -e "$SELECT_HOME/$LINUX_BRAVE/org.friendlypass.browser.json" ]] || fail "brave written unexpectedly"
ok "--browsers limits the manifests written"

# --extension-id=value spelling also works.
install_ok --platform=linux --home="$SELECT_HOME" --extension-id="$CHROME_ID" \
    --host-path="$HOST_BIN" --browsers=chromium
[[ -f "$SELECT_HOME/$LINUX_CHROMIUM/org.friendlypass.browser.json" ]] || fail "chromium not written"
ok "--option=value spelling works"

# ---------------------------------------------------------------------------
# Installed-browser detection (only existing config roots are touched)
# ---------------------------------------------------------------------------

SKIP_HOME="$TMP_ROOT/home-skip"
mkdir -p "$SKIP_HOME/.config/google-chrome"
install_ok --platform linux --home "$SKIP_HOME" --extension-id "$CHROME_ID" \
    --host-path "$HOST_BIN"
[[ -f "$SKIP_HOME/$LINUX_CHROME/org.friendlypass.browser.json" ]] || fail "chrome not written"
for root in ".config/chromium" ".config/BraveSoftware/Brave-Browser" \
    ".config/microsoft-edge" ".mozilla"
do
    [[ ! -e "$SKIP_HOME/$root" ]] || fail "missing browser root was created: $root"
done
grep -q "skipped Chromium: not installed" "$TMP_ROOT/last.log" ||
    fail "missing skip message for Chromium"
ok "missing browsers are skipped and their config roots are not created"

install_ok --platform linux --home "$SKIP_HOME" --extension-id "$CHROME_ID" \
    --host-path "$HOST_BIN" --browsers edge
[[ ! -e "$SKIP_HOME/$LINUX_EDGE/org.friendlypass.browser.json" ]] ||
    fail "--browsers edge wrote a missing browser"
grep -q "skipped Edge: not installed" "$TMP_ROOT/last.log" ||
    fail "explicit missing browser was not reported"
ok "explicit --browsers edge for a missing browser skips with a message"

# --force is the explicit opt-in for registering a browser before it starts.
install_ok --force --platform linux --home "$SKIP_HOME" --extension-id "$CHROME_ID" \
    --host-path "$HOST_BIN" --browsers edge
check_manifest "$SKIP_HOME/$LINUX_EDGE/org.friendlypass.browser.json" chromium
ok "--force registers a missing browser"

# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

# No --extension-id: the pinned manifest key's id becomes the default.
DEFAULT_HOME="$TMP_ROOT/default-home"
mkdir -p "$DEFAULT_HOME/.config/google-chrome"
install_ok --platform linux --home "$DEFAULT_HOME" --host-path "$HOST_BIN" --browsers chrome
DEFAULT_MANIFEST="$DEFAULT_HOME/.config/google-chrome/NativeMessagingHosts/org.friendlypass.browser.json"
grep -q 'chrome-extension://pfdmagadklmhbghfipamhfbphcljdkbi/' "$DEFAULT_MANIFEST" ||
    fail "default extension id was not used"
ok "default extension id is used when --extension-id is omitted"

expect_fail --platform linux --home "$LINUX_HOME" --extension-id "not-an-id" \
    --host-path "$HOST_BIN"
ok "invalid --extension-id is rejected"

expect_fail --platform linux --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --host-path "$TMP_ROOT/does-not-exist"
ok "missing host binary is rejected"

expect_fail --platform linux --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --host-path "$HOST_BIN" --browsers netscape
ok "unknown browser is rejected"

expect_fail --platform linux --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --host-path "$HOST_BIN" --browsers ""
ok "empty browser list is rejected"

expect_fail --platform solaris --home "$LINUX_HOME" --extension-id "$CHROME_ID" \
    --host-path "$HOST_BIN"
ok "unsupported platform is rejected"

# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

DRY_HOME="$TMP_ROOT/home-dry"
mkdir -p "$DRY_HOME"
make_linux_roots "$DRY_HOME"
install_ok --platform linux --home "$DRY_HOME" --extension-id "$CHROME_ID" \
    --host-path "$HOST_BIN" --dry-run
for dir in "$LINUX_CHROME" "$LINUX_CHROMIUM" "$LINUX_BRAVE" "$LINUX_EDGE" "$LINUX_FIREFOX"; do
    [[ ! -e "$DRY_HOME/$dir/org.friendlypass.browser.json" ]] ||
        fail "--dry-run wrote $dir"
done
ok "--dry-run writes nothing"

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

install_ok --uninstall --platform linux --home "$LINUX_HOME" --host-path "$HOST_BIN"
for dir in "$LINUX_CHROME" "$LINUX_CHROMIUM" "$LINUX_BRAVE" "$LINUX_EDGE" "$LINUX_FIREFOX"; do
    [[ ! -e "$LINUX_HOME/$dir/org.friendlypass.browser.json" ]] || fail "uninstall left $dir"
done
ok "Linux uninstall removes every manifest"

# Uninstall is idempotent and needs no extension id.
install_ok --uninstall --platform linux --home "$LINUX_HOME" --host-path "$HOST_BIN"
ok "second uninstall is a no-op"

install_ok --uninstall --platform macos --home "$MAC_HOME" --host-path "$HOST_BIN"
[[ ! -e "$MAC_HOME/$MAC_CHROME/org.friendlypass.browser.json" ]] || fail "macOS uninstall left chrome"
ok "macOS uninstall removes manifests"

# ---------------------------------------------------------------------------
# The host CLI itself (install.sh forwards to these exact flags)
# ---------------------------------------------------------------------------

DIRECT_HOME="$TMP_ROOT/home-direct"
mkdir -p "$DIRECT_HOME/.config/microsoft-edge"
"$HOST_BIN" --install --platform linux --home "$DIRECT_HOME" \
    --host-path "$HOST_BIN" --extension-id "$CHROME_ID" \
    --firefox-extension-id "$FF_ID" --browser edge >/dev/null
check_manifest "$DIRECT_HOME/$LINUX_EDGE/org.friendlypass.browser.json" chromium
[[ ! -e "$DIRECT_HOME/$LINUX_CHROME/org.friendlypass.browser.json" ]] ||
    fail "host --browser edge wrote chrome"
"$HOST_BIN" --uninstall --platform linux --home "$DIRECT_HOME" \
    --browser edge >/dev/null
[[ ! -e "$DIRECT_HOME/$LINUX_EDGE/org.friendlypass.browser.json" ]] ||
    fail "host --uninstall --browser edge left the manifest"
ok "host --install/--uninstall --browser flags work directly"

printf 'all installer tests passed\n'
