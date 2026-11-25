import { defineConfig } from "@playwright/test";

/**
 * Playwright configuration for the friendlypass browser extension (WP8).
 *
 * `scripts/e2e.sh` builds `extension/dist` and the native host, then runs this
 * config. Specs live under `tests/` so WP2/WP5's `tests/e2e/*.spec.ts` are
 * picked up automatically; WP8's harness lives in `tests/harness/`.
 *
 * Determinism:
 *   - one worker, no parallel browser contexts;
 *   - no retries (a flaky test must be fixed, not masked);
 *   - a fresh temp HOME/profile/app socket per test (see tests/harness).
 */
export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  timeout: 60_000,
  expect: { timeout: 8_000 },
  reporter: process.env.CI
    ? [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]]
    : [["list"]],
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  outputDir: "test-results",
});
