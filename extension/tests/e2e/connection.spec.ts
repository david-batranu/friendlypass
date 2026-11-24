/**
 * WP2 end-to-end connection spec.
 *
 * The real harness (stub native host, a mock app socket, `--load-extension`
 * and fault injection) is owned by WP8 and is not present in this worktree.
 * This spec therefore skips with an explicit reason; when WP8 exports
 * `FRIENDLYPASS_E2E=1` and `FRIENDLYPASS_EXTENSION_PATH`, it becomes a smoke
 * test of the service worker ↔ host connection.
 *
 * Intended acceptance coverage once the harness lands (REPORT §8.1 WP2):
 *   1. kill the stub host → the next `status.get` fails fast with code 5 and
 *      the service worker reconnects in under 2 s;
 *   2. stop the mock app for 60 s, then start it → status flips back to
 *      appRunning without any user action;
 *   3. reload the extension (service-worker restart) → the alarm watchdog
 *      reconnects and `status.get` answers again.
 *
 * The imports are dynamic and guarded because vitest (which owns
 * `tests/unit/`) also collects `*.spec.ts`. This file must be inert, but still
 * register a skipped test, under vitest.
 */

const runningUnderVitest =
  process.env.VITEST === "true" || process.env.VITEST_WORKER_ID !== undefined;

const extensionPath = process.env.FRIENDLYPASS_EXTENSION_PATH;
const harnessReady =
  process.env.FRIENDLYPASS_E2E === "1" && Boolean(extensionPath);

if (runningUnderVitest) {
  const { describe, it } = await import("vitest");
  describe.skip("WP2 e2e (Playwright-only)", () => {
    it("is executed by `npm run e2e`, not by vitest", () => {
      // Intentionally empty: the real test lives in the Playwright branch.
    });
  });
} else {
  const { chromium, expect, test } = await import("@playwright/test");

  test.describe("WP2 native transport connection", () => {
    test.skip(
      !harnessReady,
      "WP8 Playwright harness not available in this worktree. Set FRIENDLYPASS_E2E=1 and FRIENDLYPASS_EXTENSION_PATH=<built extension dir> after WP8 lands tests/harness + playwright.config.ts.",
    );

    test("service worker answers status.get over the native port", async () => {
      const context = await chromium.launchPersistentContext("", {
        headless: false,
        args: [
          `--disable-extensions-except=${extensionPath}`,
          `--load-extension=${extensionPath}`,
        ],
      });

      try {
        let worker = context.serviceWorkers()[0];
        if (!worker) {
          worker = await context.waitForEvent("serviceworker");
        }

        const response = await worker.evaluate(async () => {
          return new Promise<unknown>((resolve) => {
            chrome.runtime.sendMessage(
              {
                channel: "friendlypass",
                action: "status.get",
                args: undefined,
                requestId: "wp2-e2e-status",
              },
              (reply: unknown) => resolve(reply),
            );
          });
        });

        expect(response).toMatchObject({
          ok: true,
          value: { connected: true },
        });
      } finally {
        await context.close();
      }
    });
  });
}
