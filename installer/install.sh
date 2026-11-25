#!/usr/bin/env bash
#
# Install (or remove) the friendlypass native-messaging host manifests for
# Chrome, Chromium, Brave, Edge and Firefox on macOS and Linux.
#
# The host binary is registered as `org.friendlypass.browser`, the name the
# extension uses with `chrome.runtime.connectNative()`.
#
# All manifest writing lives in the Rust library
# (`friendlypass_browser::native_messaging`). This script only locates the host
# binary and forwards the options to
# `friendlypass-browser-host --install/--uninstall`, so the installer and the
# app's Browser Integration settings can never disagree.
#
# Usage:
#   ./installer/install.sh [--extension-id <chrome-extension-id>] [options]
#   ./installer/install.sh --uninstall [options]
#
# Options:
#   --extension-id ID        Chrome-family extension id. Default: the id baked
#                            into the extension manifest key (32 chars a-p).
#   --firefox-extension-id   Firefox add-on id (default: friendlypass@friendlypass.org).
#   --host-path PATH         friendlypass-browser-host binary. Default: newest
#                            of target/release, target/debug, the app bundles,
#                            then $PATH.
#   --home DIR               Use DIR as $HOME (for tests).
#   --platform macos|linux   Override platform detection (for tests).
#   --browsers LIST          Comma list of chrome,chromium,brave,edge,firefox.
#                            Default: all.
#   --force                  Register a browser even when its per-user config
#                            root does not exist (creates the directory).
#   --uninstall              Remove the manifests instead of installing.
#   --dry-run                Show what would be written, write nothing.
#   -h, --help               This help.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    sed -n '3,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

EXTENSION_ID=""
FIREFOX_ID=""
HOST_PATH=""
HOME_DIR="${HOME:-}"
PLATFORM=""
BROWSERS=""
BROWSERS_SET=0
UNINSTALL=0
DRY_RUN=0
FORCE=0

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
            BROWSERS_SET=1
            shift 2
            ;;
        --browsers=*)
            BROWSERS="${1#*=}"
            BROWSERS_SET=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --force)
            FORCE=1
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

[[ -n "$HOME_DIR" ]] || die "HOME is not set; pass --home DIR"
if [[ $BROWSERS_SET -eq 1 && -z "$BROWSERS" ]]; then
    die "--browsers must not be empty"
fi

# ---------------------------------------------------------------------------
# Locate the host binary
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Delegate to the host binary (one implementation of the manifest logic)
# ---------------------------------------------------------------------------

ARGS=()
if [[ $UNINSTALL -eq 1 ]]; then
    ARGS+=(--uninstall)
else
    ARGS+=(--install)
fi
ARGS+=(--host-path "$HOST_PATH" --home "$HOME_DIR")
[[ -n "$PLATFORM" ]] && ARGS+=(--platform "$PLATFORM")
[[ -n "$EXTENSION_ID" ]] && ARGS+=(--extension-id "$EXTENSION_ID")
[[ -n "$FIREFOX_ID" ]] && ARGS+=(--firefox-extension-id "$FIREFOX_ID")
if [[ -n "$BROWSERS" ]]; then
    IFS=',' read -r -a SELECTED <<< "$BROWSERS"
    [[ ${#SELECTED[@]} -gt 0 ]] || die "--browsers must not be empty"
    for browser in "${SELECTED[@]}"; do
        ARGS+=(--browser "$browser")
    done
fi
[[ $DRY_RUN -eq 1 ]] && ARGS+=(--dry-run)
[[ $FORCE -eq 1 ]] && ARGS+=(--force)

exec "$HOST_PATH" "${ARGS[@]}"
