/**
 * WP6a — toolbar popup end-to-end.
 *
 * The popup is a normal extension page, so each test opens it as a tab at
 * `chrome-extension://<id>/popup/popup.html?tab=<tabId>` (exactly the shape the
 * brief specifies). Everything else is the production stack: real native host,
 * real service worker, real content script, real protocol messages.
 *
 * States covered: Connected, Locked, App not running, Not connected to this
 * database, Connecting. Every visual state is captured in light and dark mode
 * under `briefs/shots/wp6a-popup/`.
 */

import { expect, test as base } from "@playwright/test";
import type { Page } from "@playwright/test";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { AppMock } from "../harness/app-mock";
import { Harness } from "../harness/harness";
import { sleep } from "../harness/frames.mjs";

// ---------------------------------------------------------------------------
// Screenshots (outside the repo)
// ---------------------------------------------------------------------------

const SHOTS = "/Users/david/Work/Projects/friendlypass/briefs/shots/wp6a-popup";

/** Capture one state in light and dark mode, cropped to the popup body. */
async function capture(page: Page, name: string): Promise<void> {
  const body = page.locator("body");
  await page.emulateMedia({ colorScheme: "light" });
  await sleep(60);
  await body.screenshot({ path: path.join(SHOTS, `${name}-light.png`) });
  await page.emulateMedia({ colorScheme: "dark" });
  await sleep(60);
  await body.screenshot({ path: path.join(SHOTS, `${name}-dark.png`) });
  await page.emulateMedia({ colorScheme: "light" });
}

// ---------------------------------------------------------------------------
// Local pages
// ---------------------------------------------------------------------------

const LOGIN_FORM = `<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
<h1>Sign in</h1>
<form id="login-form" action="/login" method="post">
  <label>Username <input id="username" name="username" type="text" autocomplete="username"></label>
  <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
  <button id="submit" type="submit">Log in</button>
</form>
</body></html>`;

const PLAIN_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Plain</title></head>
<body><h1>No login here</h1></body></html>`;

interface PagesServer {
  baseUrl: string;
  close(): Promise<void>;
}

async function startPages(): Promise<PagesServer> {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const html = url.pathname.startsWith("/login") ? LOGIN_FORM : PLAIN_PAGE;
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(html);
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

// ---------------------------------------------------------------------------
// Stack helpers
// ---------------------------------------------------------------------------

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
});

async function waitForStatus(
  harness: Harness,
  predicate: (status: Record<string, unknown>) => boolean,
  timeoutMs = 15_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown = null;
  while (Date.now() < deadline) {
    try {
      const status = (await harness.internalRequest("status.get")) as Record<string, unknown>;
      last = status;
      if (predicate(status)) return;
    } catch (cause) {
      last = cause;
    }
    await sleep(100);
  }
  throw new Error(`status never matched; last: ${JSON.stringify(last)}`);
}

/** Wait for the automatic pairing to associate the test database. */
async function associate(harness: Harness): Promise<void> {
  try {
    await waitForStatus(harness, (status) => status.associated === true, 20_000);
    return;
  } catch {
    // Automatic pairing may have been denied; fall back to the manual request
    // exactly like the popup's Connect button.
  }
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      await harness.internalRequest("association.create");
      await waitForStatus(harness, (status) => status.associated === true);
      return;
    } catch {
      await sleep(200);
    }
  }
  throw new Error("could not associate the test database");
}

/** `chrome.tabs` id of the tab showing `url`. */
async function tabIdFor(harness: Harness, url: string): Promise<number> {
  const worker = await harness.currentServiceWorker();
  const id = await worker.evaluate(async (target) => {
    const tabs = await chrome.tabs.query({});
    return tabs.find((tab) => tab.url === target)?.id ?? -1;
  }, url);
  if (id < 0) {
    throw new Error(`no tab found for ${url}`);
  }
  return id;
}

async function openLocalPage(stack: Stack, pathname: string): Promise<Page> {
  const page = await stack.harness.context.newPage();
  await page.goto(`${stack.pages.baseUrl}${pathname}`, { waitUntil: "load" });
  return page;
}

async function openExtensionPage(
  harness: Harness,
  relative: string,
  viewport: { width: number; height: number },
): Promise<Page> {
  const worker = await harness.currentServiceWorker();
  const nextPage = harness.context.waitForEvent("page", { timeout: 15_000 });
  await worker.evaluate(
    (target) => chrome.tabs.create({ url: chrome.runtime.getURL(target), active: true }),
    relative,
  );
  const page = await nextPage;
  await page.setViewportSize(viewport);
  await page.waitForLoadState("load");
  return page;
}

async function openPopup(
  harness: Harness,
  tabId: number,
  query = "",
): Promise<Page> {
  return openExtensionPage(
    harness,
    `popup/popup.html?tab=${tabId}${query}`,
    { width: 360, height: 420 },
  );
}

function statusTitle(popup: Page) {
  return popup.locator("#status-title");
}

function loginCards(popup: Page) {
  return popup.locator('[data-testid="login"]');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("connected: shows the database, lists the login and fills the page", async ({
  stack,
}) => {
  const { harness, pages } = stack;
  await associate(harness);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);

  await expect(statusTitle(popup)).toHaveText("Connected");
  await expect(popup.locator("#status-detail")).toContainText("Database 4265c37d");

  await expect(loginCards(popup)).toHaveCount(1);
  const card = loginCards(popup).first();
  await expect(card.locator(".login-title")).toHaveText("Example account");
  await expect(card.locator(".login-username")).toHaveText("alice@example.com");
  await expect(card.locator(".login-monogram")).toHaveText("E");
  // The fixture entry carries a TOTP secret.
  await expect(card.locator('[data-action="copy-totp"]')).toHaveCount(1);
  await expect(popup.locator("#search-wrap")).toBeVisible();

  await capture(popup, "popup-connected");

  await card.locator('[data-action="fill"]').click();
  await expect(page.locator("#username")).toHaveValue("alice@example.com");
  await expect(page.locator("#password")).toHaveValue(
    "correct horse battery staple",
  );
  await expect(card.locator(".login-status")).toHaveText("Filled");

  await popup.close();
  await page.close();
});

test("copy actions copy the username, password and a fresh TOTP code", async ({
  stack,
}) => {
  const { harness, pages } = stack;
  await associate(harness);
  await harness.context
    .grantPermissions(["clipboard-read", "clipboard-write"], {
      origin: `chrome-extension://${harness.extensionId}`,
    })
    .catch(() => undefined);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);
  const card = loginCards(popup).first();
  await expect(card).toBeVisible();

  const debug = () =>
    popup.evaluate(() =>
      (
        window as unknown as {
          __fpPopupDebug?: {
            lastCopy(): { text: string; label: string } | null;
            clipboardCleared(): boolean;
          };
        }
      ).__fpPopupDebug?.lastCopy() ?? null,
    );

  await card.locator('[data-action="copy-username"]').click();
  await expect(card.locator(".login-status")).toHaveText("Username copied");
  await expect.poll(debug).toEqual({ text: "alice@example.com", label: "Username", at: expect.any(Number) });

  await card.locator('[data-action="copy-password"]').click();
  await expect(card.locator(".login-status")).toHaveText("Password copied");
  await expect
    .poll(async () => (await debug())?.text)
    .toBe("correct horse battery staple");

  // get-totp is asked for a current code (the app mock answers 492183).
  await card.locator('[data-action="copy-totp"]').click();
  await expect(card.locator(".login-status")).toHaveText("TOTP code copied");
  await expect.poll(async () => (await debug())?.text).toBe("492183");
  await expect.poll(async () => (await debug())?.label).toBe("TOTP code");

  await capture(popup, "popup-copy-feedback");
  await popup.close();
  await page.close();
});

test("copied secrets are cleared after the clipboard lifetime", async ({ stack }) => {
  const { harness, pages } = stack;
  await associate(harness);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  // Short lifetime so the test does not wait 30 s; production is 30 000 ms.
  const popup = await openPopup(harness, tabId, "&clipboardClearMs=400");
  const card = loginCards(popup).first();
  await expect(card).toBeVisible();

  await card.locator('[data-action="copy-password"]').click();
  await expect(card.locator(".login-status")).toHaveText("Password copied");

  await expect
    .poll(
      () =>
        popup.evaluate(
          () =>
            (
              window as unknown as {
                __fpPopupDebug?: { clipboardCleared(): boolean };
              }
            ).__fpPopupDebug?.clipboardCleared() ?? false,
        ),
      { timeout: 5_000 },
    )
    .toBe(true);

  await popup.close();
  await page.close();
});

test("search filters the login list and can be cleared with Escape", async ({
  stack,
}) => {
  const { harness, pages } = stack;
  await associate(harness);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);
  await expect(loginCards(popup)).toHaveCount(1);

  await popup.locator("#search").fill("nomatch");
  await expect(loginCards(popup)).toHaveCount(0);
  await expect(popup.locator("#logins .empty-state").first()).toContainText(
    "No logins match",
  );
  await capture(popup, "popup-search-empty");

  await popup.locator("#search").fill("alice");
  await expect(loginCards(popup)).toHaveCount(1);

  await popup.locator("#search").press("Escape");
  await expect(popup.locator("#search")).toHaveValue("");
  await expect(loginCards(popup)).toHaveCount(1);

  // Keyboard-only path: "/" focuses the search box.
  await popup.locator("#status-title").click();
  await popup.keyboard.press("/");
  await expect(popup.locator("#search")).toBeFocused();

  await popup.close();
  await page.close();
});

test("empty state names the site when no login matches", async ({ stack }) => {
  const { harness, pages } = stack;
  await associate(harness);

  // The app mock refuses URLs containing this marker with NO_LOGINS_FOUND.
  const page = await openLocalPage(stack, "/no-match.invalid/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/no-match.invalid/login`);
  const popup = await openPopup(harness, tabId);

  await expect(statusTitle(popup)).toHaveText("Connected");
  await expect(popup.locator("#logins .empty-state")).toHaveText(
    "No logins for 127.0.0.1",
  );
  await expect(loginCards(popup)).toHaveCount(0);
  await expect(popup.locator("#search-wrap")).toBeHidden();

  await capture(popup, "popup-empty");
  await popup.close();
  await page.close();
});

test("generate password shows a value, regenerates and copies it", async ({
  stack,
}) => {
  const { harness, pages } = stack;
  await associate(harness);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);

  await popup.locator("#generate-toggle").click();
  await expect(popup.locator("#generate-value")).toHaveText(
    "generated-password-1",
  );

  await popup.locator("#generate-regenerate").click();
  await expect(popup.locator("#generate-value")).toHaveText(
    "generated-password-2",
  );
  await capture(popup, "popup-generate");

  await popup.locator("#generate-copy").click();
  await expect
    .poll(() =>
      popup.evaluate(
        () =>
          (
            window as unknown as {
              __fpPopupDebug?: {
                lastCopy(): { text: string; label: string } | null;
              };
            }
          ).__fpPopupDebug?.lastCopy()?.label ?? null,
      ),
    )
    .toBe("Generated password");

  await popup.close();
  await page.close();
});

test("app not running: shows help and recovers live when the app returns", async ({
  stack,
}) => {
  const { harness, pages } = stack;
  await associate(harness);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);
  await expect(statusTitle(popup)).toHaveText("Connected");

  await harness.killApp();
  // A host-level ping observes the app socket; the popup must follow the
  // resulting status.changed event without polling or reloading.
  await harness.internalRequest("connection.ping").catch(() => undefined);

  await expect(statusTitle(popup)).toHaveText("App not running");
  await expect(popup.locator("#status-detail")).toContainText("Start friendlypass");
  await expect(popup.locator("#status-action")).toHaveText("Retry");
  await expect(popup.locator("#logins .empty-state")).toContainText(
    "Start friendlypass",
  );
  await expect(popup.locator("#lock-database")).toBeDisabled();
  await capture(popup, "popup-app-not-running");

  await harness.restartApp();
  await harness.internalRequest("connection.reconnect").catch(() => undefined);
  // Live recovery: no reload, no reopening the popup.
  await expect(statusTitle(popup)).toHaveText("Connected", { timeout: 30_000 });
  await expect(loginCards(popup)).toHaveCount(1, { timeout: 30_000 });
  await expect(popup.locator("#status-action")).toBeHidden();

  await popup.close();
  await page.close();
});

test("locked: the unlock button asks the app to unlock", async ({ stack }) => {
  const { harness, pages } = stack;
  await associate(harness);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);
  await expect(statusTitle(popup)).toHaveText("Connected");

  await harness.internalRequest("database.lock");
  await expect(statusTitle(popup)).toHaveText("Locked");
  await expect(popup.locator("#status-detail")).toHaveText(
    "Locked — unlock friendlypass to continue",
  );
  await expect(popup.locator("#status-action")).toHaveText("Unlock friendlypass");
  await expect(popup.locator("#logins .empty-state")).toHaveText(
    "Unlock friendlypass to see logins.",
  );
  await capture(popup, "popup-locked");

  // Clicking unlock must not throw while the app still reports "locked".
  await popup.locator("#status-action").click();
  await expect(statusTitle(popup)).toHaveText("Locked");

  // Unlocking in the app is picked up live, without reopening the popup.
  const app = harness.app;
  expect(app).toBeInstanceOf(AppMock);
  (app as AppMock).setLocked(false);
  await expect(statusTitle(popup)).toHaveText("Connected", { timeout: 20_000 });

  await popup.close();
  await page.close();
});

test("automatic pairing: the popup reaches Connected without clicking anything", async ({
  stack,
}) => {
  const { harness, pages } = stack;
  // No setup call and no click anywhere: the background must associate on its
  // own when it sees an unlocked database without a working association.
  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);

  await expect(statusTitle(popup)).toHaveText("Connected", { timeout: 25_000 });
  await expect(popup.locator("#status-action")).toBeHidden();
  await expect(loginCards(popup)).toHaveCount(1);

  await capture(popup, "popup-auto-connected");
  await popup.close();
  await page.close();
});

test("denied automatic pairing: manual Connect associates the browser", async () => {
  const pages = await startPages();
  const harness = await Harness.start({ denyAssociations: true });
  try {
    const page = await harness.context.newPage();
    await page.goto(`${pages.baseUrl}/login`, { waitUntil: "load" });
    const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
    const popup = await openPopup(harness, tabId);

    // The automatic attempt was denied (error 6): show the manual fallback.
    await expect(statusTitle(popup)).toHaveText(
      "Not connected to this database",
      { timeout: 25_000 },
    );
    await expect(popup.locator("#status-action")).toHaveText("Connect");
    await expect(popup.locator("#logins .empty-state")).toContainText(
      "Connect this browser",
    );
    await capture(popup, "popup-not-connected");

    harness.setAssociationDenied(false);
    await popup.locator("#status-action").click();
    await expect(statusTitle(popup)).toHaveText("Connected");
    await expect(loginCards(popup)).toHaveCount(1);

    await popup.close();
    await page.close();
  } finally {
    await harness.close().catch(() => undefined);
    await pages.close().catch(() => undefined);
  }
});

test("connecting: a stalled handshake shows the spinner state", async ({
  stack,
}) => {
  const { harness, pages } = stack;
  await associate(harness);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);
  await expect(statusTitle(popup)).toHaveText("Connected");

  // Lock first: the Unlock action always runs a fresh handshake, so a stalled
  // app keeps the popup in the Connecting state deterministically.
  await harness.internalRequest("database.lock");
  await expect(statusTitle(popup)).toHaveText("Locked");

  harness.stallApp(4_000);
  await popup.locator("#status-action").click();
  await expect(statusTitle(popup)).toHaveText("Connecting", { timeout: 8_000 });
  await expect(popup.locator("#status-indicator")).toHaveClass(/fp-spinner/);
  await capture(popup, "popup-connecting");

  // The app is still locked after the stalled handshake.
  await expect(statusTitle(popup)).toHaveText("Locked", { timeout: 15_000 });
  await popup.close();
  await page.close();
});

test("footer: lock database and diagnostics", async ({ stack }) => {
  const { harness, pages } = stack;
  await associate(harness);

  const page = await openLocalPage(stack, "/login");
  const tabId = await tabIdFor(harness, `${pages.baseUrl}/login`);
  const popup = await openPopup(harness, tabId);
  await expect(statusTitle(popup)).toHaveText("Connected");

  await popup.locator("#diagnostics > summary").click();
  await expect(popup.locator("#diag-protocol")).toHaveText("v1");
  await expect(popup.locator("#diag-host")).not.toHaveText("—");
  await expect(popup.locator("#diag-error")).toHaveText("None");
  await expect(popup.locator("#diag-reconnects")).toHaveText(/^\d+$/);
  await capture(popup, "popup-diagnostics");

  await popup.locator("#lock-database").click();
  await expect(statusTitle(popup)).toHaveText("Locked");

  // Settings opens the options page in a new tab.
  const [options] = await Promise.all([
    harness.context.waitForEvent("page", { timeout: 10_000 }),
    popup.locator("#open-settings").click(),
  ]);
  await options.waitForLoadState("load");
  expect(options.url()).toContain("/options/options.html");
  await options.close();

  await popup.close();
  await page.close();
});
