/**
 * Firefox end-to-end suite (WP9).
 *
 *   npm run e2e:firefox
 *
 * Drives the pinned Firefox with the real `dist-firefox` add-on, the real
 * `friendlypass-browser-host` and the real Rust `test_server` (see harness.mjs).
 * Scenarios:
 *   1. connect + get-logins: the in-page icon reports a matching login;
 *   2. fill a classic login form;
 *   3. save banner → entry in the KDBX, verified with the friendlypass CLI;
 *   4. HTTP Basic auto-fill (Firefox blocking webRequest adapter);
 *   5. app killed/restarted five times: the next page load recovers without a
 *      manual reconnect.
 *
 * No credentials are printed or written to logs.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { HttpAuthServer, fetchStats } from "../fixtures/http-auth-server.mjs";
import { ensureBinaries, createDatabase, readEntryViaCli } from "./cli.mjs";
import {
  EXTENSION_ROOT,
  FIREFOX_DIST,
  FIREFOX_VERSION,
  sleep,
} from "./config.mjs";
import { FirefoxHarness, LOGIN_ICON, LOGIN_ICON_MATCHES, BANNER, waitFor } from "./harness.mjs";
import { startPages } from "./pages.mjs";

// ---------------------------------------------------------------------------
// Shadow DOM helpers (the inline menu lives in an open shadow root)
// ---------------------------------------------------------------------------

/** Click an element inside (possibly nested) open shadow roots. */
async function clickInShadows(page, selector) {
  const clicked = await page.evaluate((innerSelector) => {
    const find = (root) => {
      const direct = root.querySelector(innerSelector);
      if (direct) return direct;
      for (const element of root.querySelectorAll("*")) {
        if (element.shadowRoot) {
          const found = find(element.shadowRoot);
          if (found) return found;
        }
      }
      return null;
    };
    const node = find(document);
    if (!node) return false;
    node.click();
    return true;
  }, selector);
  assert.equal(clicked, true, `could not click ${selector}`);
}

/** Like `waitFor`, but returns the first truthy predicate value. */
async function waitForValue(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await sleep(50);
  }
  throw new Error(`timed out waiting for ${label}`);
}

/** Wait for the toolbar popup's fallback window and return its page. */
async function waitForPopupPage(harness, timeoutMs = 15_000) {
  return await waitForValue(
    async () => {
      for (const page of await harness.browser.pages()) {
        // `connect()` keeps a plain popup page open for its internal
        // requests; the fallback window is a new page with `?tab=`.
        if (page === harness.extensionPage) continue;
        try {
          const href = await page.evaluate(() => location.href);
          if (href.includes("/popup/popup.html")) return page;
        } catch {
          // A context may disappear while a window closes.
        }
      }
      return null;
    },
    timeoutMs,
    "popup window",
  );
}

// ---------------------------------------------------------------------------
// Prerequisites
// ---------------------------------------------------------------------------

function buildExtension() {
  process.stderr.write("[firefox-e2e] building dist-firefox\n");
  const result = spawnSync(process.execPath, ["scripts/build.mjs", "firefox"], {
    cwd: EXTENSION_ROOT,
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error("npm run build:firefox failed");
  }
  if (!fs.existsSync(path.join(FIREFOX_DIST, "manifest.json"))) {
    throw new Error("dist-firefox/manifest.json is missing");
  }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/** Common harness lifecycle for one scenario. */
async function withHarness(entriesFor, run, extraContext = {}) {
  const harness = await FirefoxHarness.start({
    prepareDatabase: ({ databasePath }) => {
      createDatabase(databasePath, entriesFor(extraContext));
    },
  });
  try {
    // Association is the Firefox equivalent of the Chromium harness's
    // `association.create` setup call: the popup's "Connect" button sends the
    // same internal request. Every scenario then runs against a real,
    // associated database.
    await harness.connect();
    return await run(harness, extraContext);
  } catch (error) {
    const diagnostics = harness.diagnostics();
    process.stderr.write(
      `[firefox-e2e] diagnostics (temp root ${diagnostics.root}, host pid ${diagnostics.hostPid})\n` +
        `--- host stderr ---\n${diagnostics.hostStderr}\n` +
        `--- app log ---\n${diagnostics.appLog}\n`,
    );
    throw error;
  } finally {
    await harness.close().catch(() => undefined);
  }
}

async function scenarioConnectAndGetLogins() {
  const pages = await startPages();
  try {
    await withHarness(
      () => [
        {
          title: "Firefox login",
          username: "alice@example.com",
          password: "correct horse battery staple",
          url: `${pages.baseUrl}/login`,
        },
      ],
      async (harness) => {
        await harness.waitForAppConnection(30_000);
        assert.ok(harness.extensionId.length > 0, "extension id missing");
        const status = await harness.status();
        assert.equal(status.appRunning, true, "the app is not reachable");
        assert.equal(status.associated, true, "the browser is not associated");
        const page = await harness.newPage();
        await harness.open(page, `${pages.baseUrl}/login`);

        // The icon only reaches `matches` after the content script asked the
        // background, the background spoke the protocol over the native port
        // and `get-logins` returned the stored entry.
        await page.waitForSelector(LOGIN_ICON_MATCHES, { timeout: 30_000 });
        assert.equal(await page.$$eval(LOGIN_ICON, (nodes) => nodes.length), 1);

        const counts = harness.app
          .lifecycle()
          .filter((event) => event.event === "client-count");
        assert.ok(
          counts.some((event) => typeof event.count === "number" && event.count >= 1),
          "the native host never reported a live app connection",
        );
        await page.close();
      },
    );
  } finally {
    await pages.close().catch(() => undefined);
  }
}

async function scenarioFillLoginForm() {
  const pages = await startPages();
  const password = "correct horse battery staple";
  try {
    await withHarness(
      () => [
        {
          title: "Firefox fill",
          username: "fill@example.com",
          password,
          url: `${pages.baseUrl}/login`,
        },
      ],
      async (harness) => {
        const page = await harness.newPage();
        await harness.open(page, `${pages.baseUrl}/login`);
        await page.waitForSelector(LOGIN_ICON_MATCHES, { timeout: 30_000 });

        await page.click(LOGIN_ICON);
        await page.waitForFunction(
          (expected) => {
            const username = document.querySelector("#username");
            const secret = document.querySelector("#password");
            return (
              username instanceof HTMLInputElement &&
              secret instanceof HTMLInputElement &&
              username.value === "fill@example.com" &&
              secret.value === expected
            );
          },
          { timeout: 15_000 },
          password,
        );

        assert.equal(await page.$eval("#username", (el) => el.value), "fill@example.com");
        assert.equal(await page.$eval("#password", (el) => el.value), password);
        await page.close();
      },
    );
  } finally {
    await pages.close().catch(() => undefined);
  }
}

async function scenarioOpenFriendlypassPopup() {
  const pages = await startPages();
  try {
    await withHarness(
      () => [
        {
          title: "Elsewhere",
          username: "other@example.com",
          password: "other-password",
          url: "https://example.invalid/elsewhere",
        },
      ],
      async (harness) => {
        const page = await harness.newPage();
        await harness.open(page, `${pages.baseUrl}/login`);
        // No login matches /login, so the inline icon is shown in the empty
        // state and its menu offers "Open friendlypass".
        await page.waitForSelector(LOGIN_ICON, { timeout: 30_000 });
        await page.waitForFunction(
          (selector) =>
            document
              .querySelector(selector)
              ?.getAttribute("data-friendlypass-state") === "empty",
          { timeout: 30_000 },
          LOGIN_ICON,
        );
        await page.click(LOGIN_ICON);
        await waitFor(
          () =>
            page.evaluate(() => {
              const find = (root) => {
                const direct = root.querySelector(
                  '[data-friendlypass="menu-action"][data-action="open-friendlypass"]',
                );
                if (direct) return true;
                for (const element of root.querySelectorAll("*")) {
                  if (element.shadowRoot && find(element.shadowRoot)) return true;
                }
                return false;
              };
              return find(document);
            }),
          15_000,
          "Open friendlypass menu item",
        );
        await clickInShadows(
          page,
          '[data-friendlypass="menu-action"][data-action="open-friendlypass"]',
        );

        // The fallback window must actually render the popup page, not an
        // empty moz-extension window.
        const popup = await waitForPopupPage(harness);
        const rendered = await waitForValue(
          async () => {
            try {
              const info = await popup.evaluate(() => ({
                href: location.href,
                text: document.body?.innerText ?? "",
                ready: document.readyState,
              }));
              return info.ready === "complete" && info.text.trim().length > 0
                ? info
                : null;
            } catch {
              return null;
            }
          },
          15_000,
          "popup content",
        );
        // The caller's tab is carried into the popup window.
        assert.match(rendered.href, /\/popup\/popup\.html\?tab=\d+$/);
        assert.match(rendered.text, /Generate password/i);
        assert.match(rendered.text, /Settings/i);
        await page.close();
      },
    );
  } finally {
    await pages.close().catch(() => undefined);
  }
}

async function scenarioSaveBannerReachesKdbx() {
  const pages = await startPages();
  const username = "saved@example.com";
  const password = "saved-password";
  const title = new URL(pages.baseUrl).host;
  try {
    await withHarness(
      () => [
        {
          title: "Untouched",
          username: "other@example.com",
          password: "other-password",
          url: `${pages.baseUrl}/login`,
        },
      ],
      async (harness) => {
        const page = await harness.newPage();
        await harness.open(page, `${pages.baseUrl}/save`);
        // A login form without a matching entry still gets the (empty) icon.
        await page.waitForSelector(LOGIN_ICON, { timeout: 30_000 });

        await page.type("#username", username);
        await page.type("#password", password);
        await page.click("#submit");
        await page.waitForFunction(() => location.pathname === "/save-done", {
          timeout: 15_000,
        });

        await page.waitForSelector(BANNER, { timeout: 20_000 });
        assert.equal(
          await page.$eval(BANNER, (node) => node.getAttribute("data-friendlypass-kind")),
          "create",
        );
        // The banner's action buttons live in an open shadow root.
        await page.evaluate(() => {
          const banner = document.querySelector('[data-friendlypass="banner"]');
          const button = banner?.shadowRoot?.querySelector('[data-action="save"]');
          if (!(button instanceof HTMLElement)) {
            throw new Error("save button not found in the banner shadow root");
          }
          button.click();
        });
        await page.waitForFunction(
          () => document.querySelector('[data-friendlypass="banner"]') === null,
          { timeout: 10_000 },
        );

        // Another process reopens the real KDBX: the save reached disk.
        const deadline = Date.now() + 20_000;
        let entry = null;
        while (Date.now() < deadline) {
          entry = readEntryViaCli(harness.app.databasePath, title);
          if (entry) break;
          await sleep(100);
        }
        assert.ok(entry, `no "${title}" entry was written to the KDBX`);
        assert.equal(entry.UserName, username);
        assert.equal(entry.Password, password);
        assert.equal(entry.URL, `${pages.baseUrl}/save`);
        await page.close();
      },
    );
  } finally {
    await pages.close().catch(() => undefined);
  }
}

async function scenarioHttpBasic() {
  const auth = new HttpAuthServer({
    host: "127.0.0.1",
    mode: "basic",
    realm: "friendlypass-firefox-basic",
    users: { alice: "alice-secret" },
    name: "firefox-basic",
  });
  await auth.start();
  try {
    await withHarness(
      () => [
        {
          title: "Firefox HTTP Basic",
          username: "alice",
          password: "alice-secret",
          url: `${auth.origin}/`,
        },
      ],
      async (harness) => {
        const page = await harness.newPage();
        const response = await page.goto(`${auth.origin}/private`, {
          waitUntil: "domcontentloaded",
          timeout: 30_000,
        });
        assert.equal(response?.status(), 200);
        assert.match(await page.$eval("body", (el) => el.textContent ?? ""), /ok basic:alice/);

        const stats = await fetchStats(auth);
        const pathStats = stats.byPath["/private"] ?? {
          challenges: 0,
          attempts: 0,
          successes: 0,
        };
        assert.equal(pathStats.challenges, 1);
        assert.equal(pathStats.attempts, 1);
        assert.equal(pathStats.successes, 1);
        await page.close();
      },
    );
  } finally {
    await auth.stop().catch(() => undefined);
  }
}

async function scenarioAppRestarts() {
  const pages = await startPages();
  try {
    await withHarness(
      () => [
        {
          title: "Firefox restart",
          username: "restart@example.com",
          password: "restart-password",
          url: `${pages.baseUrl}/login`,
        },
      ],
      async (harness) => {
        const first = await harness.openAndWait(
          `${pages.baseUrl}/login`,
          LOGIN_ICON_MATCHES,
          30_000,
        );
        await first.close();
        await harness.app.waitForPersistedAssociation(10_000);

        for (let round = 1; round <= 5; round += 1) {
          await harness.app.stop();
          await sleep(250);
          await harness.app.start();

          // Recovery must be automatic: `status.get` is a read-only snapshot;
          // it never calls ensureSession/reconnect on the caller's behalf.
          await waitFor(
            async () => {
              const status = await harness.status();
              return (
                status.appRunning === true &&
                status.associated === true &&
                status.locked === false
              );
            },
            25_000,
            `round ${round}: background to notice the restarted app`,
          );

          // A normal page load must recover the session; no reconnect command
          // and no user action is performed anywhere in this loop.
          const page = await harness.openAndWait(
            `${pages.baseUrl}/login`,
            LOGIN_ICON_MATCHES,
            30_000,
          );
          assert.equal(
            await page.$$eval(LOGIN_ICON_MATCHES, (nodes) => nodes.length),
            1,
            `round ${round}: matches icon missing after app restart`,
          );
          await page.close();
        }

        const listening = harness.app
          .lifecycle()
          .filter((event) => event.event === "listening").length;
        assert.ok(
          listening >= 6,
          `expected 6 app starts (initial + 5), saw ${listening}`,
        );
      },
    );
  } finally {
    await pages.close().catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const scenarios = [
  ["connect + get-logins", scenarioConnectAndGetLogins],
  ["fill a classic login form", scenarioFillLoginForm],
  ["Open friendlypass renders the popup", scenarioOpenFriendlypassPopup],
  ["save banner writes the KDBX entry", scenarioSaveBannerReachesKdbx],
  ["HTTP Basic auto-fill", scenarioHttpBasic],
  ["app kill/restart x5 recovers", scenarioAppRestarts],
];

async function main() {
  buildExtension();
  ensureBinaries();

  process.stderr.write(
    `[firefox-e2e] Firefox ${FIREFOX_VERSION} (BiDi/Puppeteer), real host + real Rust server\n`,
  );

  const failures = [];
  for (const [name, run] of scenarios) {
    const started = Date.now();
    try {
      await run();
      console.log(`ok - ${name} (${Date.now() - started} ms)`);
    } catch (error) {
      failures.push(name);
      console.error(`not ok - ${name} (${Date.now() - started} ms)`);
      console.error(error?.stack ?? String(error));
    }
  }

  if (failures.length > 0) {
    console.error(`\n${failures.length} Firefox scenario(s) failed: ${failures.join(", ")}`);
    process.exitCode = 1;
    return;
  }
  console.log(`\nall ${scenarios.length} Firefox scenarios passed`);
}

await main();
