#!/usr/bin/env bash
#
# Install (or remove) the friendlypass native-messaging host manifests for
# Chrome, Chromium, Brave, Edge and Firefox on macOS and Linux.
#
# The host binary is registered as `org.friendlypass.browser`, the name the
# extension uses with `chrome.runtime.connectNative()`.
#
# Usage:
#   ./installer/install.sh --extension-id <chrome-extension-id> [options]
#   ./installer/install.sh --uninstall [options]
#
# Options:
#   --extension-id ID        Chrome-family extension id (required to install).
#                           32 characters a-p, from chrome://extensions.
#   --firefox-extension-id  Firefox add-on id (default: friendlypass@friendlypass.org).
#   --host-path PATH        friendlypass-browser-host binary. Default: newest
#                           of target/release, target/debug, then $PATH.
#   --home DIR              Use DIR as $HOME (for tests).
#   --platform macos|linux  Override platform detection (for tests).
#   --browsers LIST         Comma list of chrome,chromium,brave,edge,firefox.
#                           Default: all.
#   --uninstall             Remove the manifests instead of installing.
#   --dry-run               Show what would be written, write nothing.
#   -h, --help              This help.

set -euo pipefail

HOST_NAME="org.friendlypass.browser"
HOST_DESCRIPTION="friendlypass browser integration host"
DEFAULT_FIREFOX_ID="friendlypass@friendlypass.org"
ALL_BROWSERS=(chrome chromium brave edge firefox)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '%s\n' "$*" >&2
}

EXTENSION_ID=""
FIREFOX_ID="$DEFAULT_FIREFOX_ID"
HOST_PATH=""
HOME_DIR="${HOME:-}"
PLATFORM=""
BROWSERS=""
UNINSTALL=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --extension-id)
            [[ $# -ge 2 ]] || die "--extension-id needs a value"
            EXTENSION_ID="$2"
            shift 2
            ;;
        --extension-id=*)
            EXTENSION_ID="${1#*=}"
            shift
            ;;
        --firefox-extension-id)
            [[ $# -ge 2 ]] || die "--firefox-extension-id needs a value"
            FIREFOX_ID="$2"
            shift 2
            ;;
        --firefox-extension-id=*)
            FIREFOX_ID="${1#*=}"
            shift
            ;;
        --host-path)
            [[ $# -ge 2 ]] || die "--host-path needs a value"
            HOST_PATH="$2"
            shift 2
            ;;
        --host-path=*)
            HOST_PATH="${1#*=}"
            shift
            ;;
        --home)
            [[ $# -ge 2 ]] || die "--home needs a value"
            HOME_DIR="$2"
            shift 2
            ;;
        --home=*)
            HOME_DIR="${1#*=}"
            shift
            ;;
        --platform)
            [[ $# -ge 2 ]] || die "--platform needs a value"
            PLATFORM="$2"
            shift 2
            ;;
        --platform=*)
            PLATFORM="${1#*=}"
            shift
            ;;
        --browsers)
            [[ $# -ge 2 ]] || die "--browsers needs a value"
            BROWSERS="$2"
            shift 2
            ;;
        --browsers=*)
            BROWSERS="${1#*=}"
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1 (try --help)"
            ;;
    esac
done

if [[ -z "$PLATFORM" ]]; then
    case "$(uname -s)" in
        Darwin) PLATFORM="macos" ;;
        Linux) PLATFORM="linux" ;;
        *) die "unsupported platform: $(uname -s) (only macOS and Linux are supported)" ;;
    esac
fi
case "$PLATFORM" in
    macos|linux) ;;
    *) die "--platform must be macos or linux, got: $PLATFORM" ;;
esac

[[ -n "$HOME_DIR" ]] || die "HOME is not set; pass --home DIR"
[[ -d "$HOME_DIR" ]] || die "home directory does not exist: $HOME_DIR"

if [[ -z "$BROWSERS" ]]; then
    BROWSERS="$(IFS=,; printf '%s' "${ALL_BROWSERS[*]}")"
fi
IFS=',' read -r -a SELECTED <<< "$BROWSERS"
[[ ${#SELECTED[@]} -gt 0 ]] || die "--browsers must not be empty"
for browser in "${SELECTED[@]}"; do
    found=0
    for known in "${ALL_BROWSERS[@]}"; do
        [[ "$browser" == "$known" ]] && found=1
    done
    [[ $found -eq 1 ]] || die "unknown browser: $browser (known: ${ALL_BROWSERS[*]})"
done

# ---------------------------------------------------------------------------
# Manifest locations
# ---------------------------------------------------------------------------

manifest_dir() {
    local browser="$1"
    case "$PLATFORM/$browser" in
        macos/chrome)   printf '%s/Library/Application Support/Google/Chrome/NativeMessagingHosts' "$HOME_DIR" ;;
        macos/chromium) printf '%s/Library/Application Support/Chromium/NativeMessagingHosts' "$HOME_DIR" ;;
        macos/brave)    printf '%s/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts' "$HOME_DIR" ;;
        macos/edge)     printf '%s/Library/Application Support/Microsoft Edge/NativeMessagingHosts' "$HOME_DIR" ;;
        macos/firefox)  printf '%s/Library/Application Support/Mozilla/NativeMessagingHosts' "$HOME_DIR" ;;
        linux/chrome)   printf '%s/.config/google-chrome/NativeMessagingHosts' "$HOME_DIR" ;;
        linux/chromium) printf '%s/.config/chromium/NativeMessagingHosts' "$HOME_DIR" ;;
        linux/brave)    printf '%s/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts' "$HOME_DIR" ;;
        linux/edge)     printf '%s/.config/microsoft-edge/NativeMessagingHosts' "$HOME_DIR" ;;
        linux/firefox)  printf '%s/.mozilla/native-messaging-hosts' "$HOME_DIR" ;;
        *) return 1 ;;
    esac
}

manifest_path() {
    printf '%s/%s.json' "$(manifest_dir "$1")" "$HOST_NAME"
}

# Escape a value for a JSON string literal.
json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

if [[ $UNINSTALL -eq 1 ]]; then
    status=0
    for browser in "${SELECTED[@]}"; do
        file="$(manifest_path "$browser")"
        if [[ -f "$file" ]]; then
            if [[ $DRY_RUN -eq 1 ]]; then
                note "would remove $file"
            else
                rm -f "$file"
                note "removed $file"
            fi
        else
            note "not installed: $file"
        fi
        # Leave the directory in place: the browser owns it and may hold other
        # native-messaging hosts.
    done
    exit $status
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

[[ -n "$EXTENSION_ID" ]] || die "--extension-id is required to install (the id from chrome://extensions)"
if [[ ! "$EXTENSION_ID" =~ ^[a-p]{32}$ ]]; then
    die "--extension-id must be 32 characters in the range a-p, got: $EXTENSION_ID"
fi

if [[ -z "$HOST_PATH" ]]; then
    for candidate in \
        "$REPO_ROOT/target/release/friendlypass-browser-host" \
        "$REPO_ROOT/target/debug/friendlypass-browser-host" \
        "/Applications/friendlypass.app/Contents/MacOS/friendlypass-browser-host" \
        "$HOME_DIR/Applications/friendlypass.app/Contents/MacOS/friendlypass-browser-host"
    do
        if [[ -x "$candidate" ]]; then
            HOST_PATH="$candidate"
            break
        fi
    done
    if [[ -z "$HOST_PATH" ]]; then
        HOST_PATH="$(command -v friendlypass-browser-host || true)"
    fi
fi
[[ -n "$HOST_PATH" ]] || die "cannot find friendlypass-browser-host; build it or pass --host-path"

# Manifests require an absolute path.
case "$HOST_PATH" in
    /*) ;;
    *) HOST_PATH="$PWD/$HOST_PATH" ;;
esac
HOST_DIR="$(cd "$(dirname "$HOST_PATH")" && pwd)"
HOST_PATH="$HOST_DIR/$(basename "$HOST_PATH")"
[[ -f "$HOST_PATH" ]] || die "host binary does not exist: $HOST_PATH"
[[ -x "$HOST_PATH" ]] || die "host binary is not executable: $HOST_PATH"

ESCAPED_HOST="$(json_escape "$HOST_PATH")"
ESCAPED_CHROME_ID="$(json_escape "$EXTENSION_ID")"
ESCAPED_FIREFOX_ID="$(json_escape "$FIREFOX_ID")"

write_manifest() {
    local browser="$1" file="$2"
    if [[ $DRY_RUN -eq 1 ]]; then
        note "would write $file"
        return 0
    fi
    mkdir -p "$(dirname "$file")"
    if [[ "$browser" == "firefox" ]]; then
        cat > "$file" <<EOF
{
  "name": "$HOST_NAME",
  "description": "$HOST_DESCRIPTION",
  "path": "$ESCAPED_HOST",
  "type": "stdio",
  "allowed_extensions": ["$ESCAPED_FIREFOX_ID"]
}
EOF
    else
        cat > "$file" <<EOF
{
  "name": "$HOST_NAME",
  "description": "$HOST_DESCRIPTION",
  "path": "$ESCAPED_HOST",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$ESCAPED_CHROME_ID/"]
}
EOF
    fi
    note "wrote $file"
}

for browser in "${SELECTED[@]}"; do
    write_manifest "$browser" "$(manifest_path "$browser")"
done

if [[ $DRY_RUN -eq 1 ]]; then
    note "dry run: nothing written"
else
    note "friendlypass native host installed for: ${SELECTED[*]} ($PLATFORM)"
fi
