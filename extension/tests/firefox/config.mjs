/**
 * Shared constants for the Firefox e2e harness (WP9).
 *
 * The Firefox binary is pinned and downloaded into `extension/.cache/` (git-
 * ignored) with `@puppeteer/browsers` from Mozilla's official release archive.
 * It is used for tests only; nothing here ships.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

/** repo root: extension/tests/firefox → extension/tests → extension → repo */
export const REPO_ROOT = path.resolve(here, "../../..");
export const EXTENSION_ROOT = path.resolve(here, "../..");

/** The Firefox MV3 build produced by `npm run build:firefox`. */
export const FIREFOX_DIST = path.join(EXTENSION_ROOT, "dist-firefox");

/** Pinned test browser. Override with FP_FIREFOX_VERSION for a manual bisect. */
export const FIREFOX_VERSION = process.env.FP_FIREFOX_VERSION ?? "stable_140.0";

export const FIREFOX_CACHE = path.join(EXTENSION_ROOT, ".cache", "firefox");

export const NATIVE_HOST_NAME = "org.friendlypass.browser";

/** The Gecko id pinned in the Firefox manifest. */
export const FIREFOX_ADDON_ID = "friendlypass@friendlypass.org";

/** Matches `test_server`'s default (`FP_TEST_DB_PASSWORD` unset). */
export const TEST_DB_PASSWORD = "testpassword";

/** Built Rust binaries (the harness never uses the stub host). */
export const FRIENDLYPASS_CLI = path.join(REPO_ROOT, "target/debug/friendlypass");
export const NATIVE_HOST_BINARY = path.join(
  REPO_ROOT,
  "target/debug/friendlypass-browser-host",
);
export const TEST_SERVER_BINARY = path.join(
  REPO_ROOT,
  "target/debug/examples/test_server",
);

/** Fixture database copied into every scenario's temp root. */
export const SAMPLE_DATABASE = path.join(REPO_ROOT, "fixtures/sample4.kdbx");

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
