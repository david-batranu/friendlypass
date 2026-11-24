#!/usr/bin/env bash
#
# WP8 one-command e2e entry point.
#
#   scripts/e2e.sh [playwright args...]
#
# Builds the extension bundle and the native host, then runs Playwright with the
# harness in `extension/tests/harness/`. Deterministic by construction:
#   - `FP_HOST=auto` uses the real host only when it answers `ping`; otherwise
#     the in-repo Node stub host is used (WP1 may still be a scaffold).
#   - every test gets a fresh temp HOME/profile/app socket (see harness).
#   - one worker, no retries (configured in extension/playwright.config.ts).
#
# Env knobs:
#   FP_HOST=auto|stub|real     host selection (default: auto)
#   FP_HOST_BINARY=<path>      override target/debug/friendlypass-browser-host
#   FP_TEST_SERVER_BINARY=<p>  override target/debug/examples/test_server
#   FP_HEADED=1                run a real window (CI uses xvfb on Linux)
#   FP_CHANNEL=chromium|chrome Chromium channel (default: chromium)
#   FP_KEEP_TEMP=1             keep the harness temp dirs for debugging
#   FP_SKIP_BROWSER_INSTALL=1  do not run `playwright install chromium`
#   FP_FIREFOX=1               after Playwright, run `npm run e2e:firefox`
#                              (downloads the pinned Firefox once into
#                              extension/.cache, then uses the real host +
#                              real Rust server)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT="$ROOT/extension"
export FP_HOST="${FP_HOST:-auto}"
export FP_HOST_BINARY="${FP_HOST_BINARY:-$ROOT/target/debug/friendlypass-browser-host}"

echo "==> building extension"
if [[ ! -d "$EXT/node_modules" ]]; then
  (cd "$EXT" && npm ci)
fi
(cd "$EXT" && npm run build)

echo "==> building native host"
cargo build --manifest-path "$ROOT/Cargo.toml" -p friendlypass-browser-host

echo "==> building headless protocol server (Phase-1 exit test)"
cargo build --manifest-path "$ROOT/Cargo.toml" -p friendlypass-browser --example test_server

if [[ "${FP_SKIP_BROWSER_INSTALL:-0}" != "1" ]]; then
  echo "==> ensuring Playwright Chromium is installed"
  (cd "$EXT" && npx playwright install chromium >/dev/null)
fi

cd "$EXT"

PLAYWRIGHT=(npx playwright test "$@")

# Linux CI runs headed under Xvfb because that is the most reliable way to load
# an extension; locally a headless new-mode Chromium works fine.
if [[ "${FP_HEADED:-0}" == "1" && -z "${DISPLAY:-}" && "$(uname -s)" == "Linux" ]]; then
  if command -v xvfb-run >/dev/null 2>&1; then
    echo "==> running under xvfb-run"
    xvfb-run -a --server-args="-screen 0 1280x1024x24" "${PLAYWRIGHT[@]}"
    if [[ "${FP_FIREFOX:-0}" == "1" ]]; then
      echo "==> running Firefox e2e (Puppeteer/WebDriver BiDi)"
      npm run e2e:firefox
    fi
    exit 0
  fi
  echo "FP_HEADED=1 but no DISPLAY and no xvfb-run; continuing headless" >&2
fi

"${PLAYWRIGHT[@]}"

if [[ "${FP_FIREFOX:-0}" == "1" ]]; then
  echo "==> running Firefox e2e (Puppeteer/WebDriver BiDi)"
  npm run e2e:firefox
fi
