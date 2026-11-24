/**
 * WP6a — options page end-to-end.
 *
 * The options page is opened as a normal extension tab. Tests drive the real
 * controls and verify through the background (`settings.get`) that every change
 * was persisted, and through a `settings.changed` listener that the change was
 * broadcast to other extension pages.
 *
 * Site exceptions: WP6b makes the content scripts honour them; WP6a owns the
 * settings round-trip, the broadcast, and the popup's own "filling disabled"
 * state, all covered here.
 */

import { expect, test as base } from "@playwright/test";
import type { Page } from "@playwright/test";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { Harness } from "../harness/harness";
import { sleep } from "../harness/frames.mjs";

const SHOTS = "/Users/david/Work/Projects/friendlypass/briefs/shots/wp6a-popup";
const SHOTS_WP6C = "/Users/david/Work/Projects/friendlypass/briefs/shots/wp6c-polish";

async function capture(page: Page, name: string): Promise<void> {
  await page.emulateMedia({ colorScheme: "light" });
  await sleep(60);
  await page.screenshot({ path: path.join(SHOTS, `${name}-light.png`), fullPage: true });
  await page.emulateMedia({ colorScheme: "dark" });
  await sleep(60);
  await page.screenshot({ path: path.join(SHOTS, `${name}-dark.png`), fullPage: true });
  await page.emulateMedia({ colorScheme: "light" });
}

/** Screenshot one section, light then dark (WP6c shots). */
async function captureSection(
  page: Page,
  selector: string,
  name: string,
): Promise<void> {
  const section = page.locator(selector);
  await page.emulateMedia({ colorScheme: "light" });
  await sleep(60);
  await section.screenshot({ path: path.join(SHOTS_WP6C, `${name}-light.png`) });
  await page.emulateMedia({ colorScheme: "dark" });
  await sleep(60);
  await section.screenshot({ path: path.join(SHOTS_WP6C, `${name}-dark.png`) });
  await page.emulateMedia({ colorScheme: "light" });
}

const LOGIN_FORM = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
<h1>Sign in</h1>
<form id="login-form" action="/login" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Log in</button>
</form>
</body></html>`;

interface PagesServer {
  baseUrl: string;
  close(): Promise<void>;
}

async function startPages(): Promise<PagesServer> {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(LOGIN_FORM);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

interface Stack {
  harness: Harness;
  pages: PagesServer;
}

const test = base.extend<{ stack: Stack }>({
  stack: async ({}, use) => {
    const pages = await startPages();
    const harness = await Harness.start();
    try {
      await use({ harness, pages });
    } finally {
      await harness.close().catch(() => undefined);
      await pages.close().catch(() => undefined);
    }
  },
});

test.beforeAll(() => {
  fs.mkdirSync(SHOTS, { recursive: true });
  fs.mkdirSync(SHOTS_WP6C, { recursive: true });
});

interface SettingsLike {
  autoFillSingleEntry: boolean;
  showFieldIcons: boolean;
  httpAuthAutoFill: boolean;
  autoFillAndSubmit: boolean;
  launchAppOnConnect: boolean;
  defaultGroup: string;
  defaultGroupAlwaysAsk: boolean;
  debugLogging: boolean;
  siteExceptions: Array<{
    origin: string;
    disableFill?: boolean;
    disableSave?: boolean;
    disableIcons?: boolean;
  }>;
}

async function getSettings(harness: Harness): Promise<SettingsLike> {
  return (await harness.internalRequest("settings.get")) as SettingsLike;
}

async function associate(harness: Harness): Promise<void> {
  await expect
    .poll(
      async () => {
        try {
          await harness.internalRequest("association.create");
          const status = (await harness.internalRequest("status.get")) as {
            associated: boolean;
          };
          return status.associated;
        } catch {
          return false;
        }
      },
      { timeout: 30_000, intervals: [250, 500, 1_000] },
    )
    .toBe(true);
}

async function openOptions(harness: Harness): Promise<Page> {
  const worker = await harness.currentServiceWorker();
  const nextPage = harness.context.waitForEvent("page", { timeout: 15_000 });
  await worker.evaluate(() =>
    chrome.tabs.create({
      url: chrome.runtime.getURL("options/options.html"),
      active: true,
    }),
  );
  const page = await nextPage;
  await page.setViewportSize({ width: 900, height: 1_240 });
  await page.waitForLoadState("load");
  await expect(page.locator("#opt-showFieldIcons")).toBeAttached();
  return page;
}

/** Record `settings.changed` events observed by the options page itself. */
async function recordSettingsEvents(page: Page): Promise<void> {
  await page.evaluate(() => {
    const target = window as unknown as { __fpSettingsEvents: unknown[] };
    target.__fpSettingsEvents = [];
    chrome.runtime.onMessage.addListener((message: unknown) => {
      const record = message as { channel?: string; action?: string; args?: unknown };
      if (record?.channel === "friendlypass" && record.action === "settings.changed") {
        target.__fpSettingsEvents.push(record.args);
      }
      return false;
    });
  });
}

function observedEvents(page: Page): Promise<unknown[]> {
  return page.evaluate(
    () => (window as unknown as { __fpSettingsEvents?: unknown[] }).__fpSettingsEvents ?? [],
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("defaults render and every change persists across a reload", async ({
  stack,
}) => {
  const { harness } = stack;
  const options = await openOptions(harness);

  await expect(options.locator("#opt-showFieldIcons")).toBeChecked();
  await expect(options.locator("#opt-httpAuthAutoFill")).toBeChecked();
  await expect(options.locator("#opt-autoFillSingleEntry")).not.toBeChecked();
  await expect(options.locator("#opt-autoFillAndSubmit")).not.toBeChecked();
  await expect(options.locator("#opt-launchAppOnConnect")).not.toBeChecked();
  await expect(options.locator("#opt-defaultGroupAlwaysAsk")).not.toBeChecked();
  await expect(options.locator("#opt-debugLogging")).not.toBeChecked();
  await expect(options.locator("#opt-defaultGroup")).toHaveValue("");
  // Wait for a settled connection label so the screenshot is not "Checking…".
  await expect(options.locator("#conn-state")).toHaveText(
    /Connected|Not connected to this database|Database locked|friendlypass is not running/,
  );

  await capture(options, "options-defaults");

  await options.locator("#opt-showFieldIcons").uncheck();
  await expect(options.locator("#save-state")).toHaveText("Saved");
  await expect
    .poll(async () => (await getSettings(harness)).showFieldIcons)
    .toBe(false);

  await options.locator("#opt-httpAuthAutoFill").uncheck();
  await expect
    .poll(async () => (await getSettings(harness)).httpAuthAutoFill)
    .toBe(false);

  await options.locator("#opt-autoFillSingleEntry").check();
  await options.locator("#opt-autoFillAndSubmit").check();
  await options.locator("#opt-defaultGroupAlwaysAsk").check();
  await options.locator("#opt-debugLogging").check();
  await options.locator("#opt-launchAppOnConnect").check();

  await options.locator("#opt-defaultGroup").fill("Web");
  await options.locator("#opt-defaultGroup").blur();

  await expect
    .poll(async () => {
      const settings = await getSettings(harness);
      return {
        autoFillSingleEntry: settings.autoFillSingleEntry,
        autoFillAndSubmit: settings.autoFillAndSubmit,
        defaultGroupAlwaysAsk: settings.defaultGroupAlwaysAsk,
        debugLogging: settings.debugLogging,
        launchAppOnConnect: settings.launchAppOnConnect,
        defaultGroup: settings.defaultGroup,
      };
    })
    .toEqual({
      autoFillSingleEntry: true,
      autoFillAndSubmit: true,
      defaultGroupAlwaysAsk: true,
      debugLogging: true,
      launchAppOnConnect: true,
      defaultGroup: "Web",
    });

  await capture(options, "options-changed");

  await options.reload();
  await expect(options.locator("#opt-showFieldIcons")).not.toBeChecked();
  await expect(options.locator("#opt-httpAuthAutoFill")).not.toBeChecked();
  await expect(options.locator("#opt-autoFillSingleEntry")).toBeChecked();
  await expect(options.locator("#opt-autoFillAndSubmit")).toBeChecked();
  await expect(options.locator("#opt-defaultGroupAlwaysAsk")).toBeChecked();
  await expect(options.locator("#opt-debugLogging")).toBeChecked();
  await expect(options.locator("#opt-launchAppOnConnect")).toBeChecked();
  await expect(options.locator("#opt-defaultGroup")).toHaveValue("Web");

  await options.close();
});

test("site exceptions add, toggle, broadcast and remove", async ({ stack }) => {
  const { harness, pages } = stack;
  await associate(harness);
  const origin = new URL(pages.baseUrl).origin;
  const options = await openOptions(harness);
  await recordSettingsEvents(options);

  await expect(options.locator("#exception-empty")).toBeVisible();

  await options.locator("#exception-origin").fill(`${origin}/login`);
  await options.locator("#exception-add").click();

  const row = options.locator(`tr[data-origin="${origin}"]`);
  await expect(row).toHaveCount(1);
  await expect(row.locator(".origin-cell")).toHaveText(origin);
  await expect(options.locator("#exception-empty")).toBeHidden();

  await row.locator('[data-exception-toggle="disableFill"]').check();
  await row.locator('[data-exception-toggle="disableSave"]').check();

  await expect
    .poll(async () => (await getSettings(harness)).siteExceptions)
    .toEqual([{ origin, disableFill: true, disableSave: true }]);

  // The change was broadcast with the full settings payload.
  await expect.poll(async () => (await observedEvents(options)).length).toBeGreaterThan(0);
  const events = (await observedEvents(options)) as SettingsLike[];
  expect(events[events.length - 1].siteExceptions).toEqual([
    { origin, disableFill: true, disableSave: true },
  ]);

  await capture(options, "options-site-exceptions");

  // The popup honours the origin: filling is disabled for that site.
  const page = await harness.context.newPage();
  await page.goto(`${origin}/login`, { waitUntil: "load" });
  const worker = await harness.currentServiceWorker();
  const tabId = await worker.evaluate(async (target) => {
    const tabs = await chrome.tabs.query({});
    return tabs.find((tab) => tab.url === target)?.id ?? -1;
  }, `${origin}/login`);
  const popup = await harness.context.newPage();
  await popup.setViewportSize({ width: 360, height: 620 });
  await popup.goto(
    `chrome-extension://${harness.extensionId}/popup/popup.html?tab=${tabId}`,
    { waitUntil: "load" },
  );
  await expect(popup.locator('[data-action="fill"]')).toBeDisabled();
  await expect(popup.locator("#logins")).toContainText(
    "Filling is disabled for this site.",
  );
  await capture(popup, "popup-site-exception");
  await popup.close();
  await page.close();

  // Remove the row again: the settings round-trip in both directions.
  await options.locator(`tr[data-origin="${origin}"] [data-action="remove-exception"]`).click();
  await expect.poll(async () => (await getSettings(harness)).siteExceptions).toEqual([]);
  await expect(options.locator("#exception-empty")).toBeVisible();

  await options.locator("#exception-origin").fill("not a url!");
  await options.locator("#exception-add").click();
  await expect(options.locator("#exception-error")).toContainText("Enter a site");

  await options.close();
});

test("shortcut section shows the effective commands and links to Chrome", async ({
  stack,
}) => {
  const { harness } = stack;
  const options = await openOptions(harness);

  const rows = options.locator("#shortcut-list .shortcut-row");
  await expect(rows).toHaveCount(4, { timeout: 10_000 });
  await expect(options.locator("#shortcut-list")).toContainText("Open friendlypass");
  await expect(options.locator("#shortcut-list")).toContainText("Fill login");
  await expect(options.locator("#shortcuts-hint")).toHaveText(
    "chrome://extensions/shortcuts",
  );
  await expect(options.locator("#open-shortcuts")).toBeEnabled();

  // The shipped manifest no longer uses Chrome's bookmark-manager shortcut.
  const manifestKey = await options.evaluate(() => {
    const manifest = chrome.runtime.getManifest() as {
      commands?: Record<string, { suggested_key?: { default?: string; mac?: string } }>;
    };
    return manifest.commands?.["_execute_action"]?.suggested_key ?? null;
  });
  expect(manifestKey).toEqual({ default: "Alt+Shift+F", mac: "Alt+Shift+F" });

  await captureSection(options, "#shortcuts-section", "options-shortcuts");
  await options.close();
});

test("connection details and reconnect", async ({ stack }) => {
  const { harness } = stack;
  await associate(harness);
  const options = await openOptions(harness);

  await expect(options.locator("#conn-state")).toHaveText("Connected");
  await expect(options.locator("#conn-protocol")).toHaveText("v1");
  await expect(options.locator("#conn-host")).not.toHaveText("—");
  // The host reports the app version only when the app advertises one; "—" is
  // the documented placeholder, so accept either.
  await expect(options.locator("#conn-app")).toHaveText(/^(—|\d+\.\d+)/);
  await expect(options.locator("#conn-database")).toContainText("4265c37d");
  await capture(options, "options-connection");

  await options.locator("#reconnect").click();
  await expect(options.locator("#reconnect-status")).toHaveText("Reconnected", {
    timeout: 20_000,
  });
  await expect(options.locator("#conn-state")).toHaveText("Connected", {
    timeout: 20_000,
  });

  // App down: the page follows status.changed without a reload.
  await harness.killApp();
  await harness.internalRequest("connection.ping").catch(() => undefined);
  await expect(options.locator("#conn-state")).toHaveText(
    "friendlypass is not running",
  );
  await capture(options, "options-app-not-running");

  await options.close();
});
