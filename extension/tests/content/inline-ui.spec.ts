/**
 * WP6b in-page UI helper tests (real Chromium layout).
 *
 * Loads the same `dist/content/testing.js` bundle the production content
 * script imports, so the settings/icon/position/search tables are the shipped
 * code rather than a copy. Interaction with the real extension stack lives in
 * `tests/e2e/inline.spec.ts`.
 */

import { expect, test } from "@playwright/test";
import { fileURLToPath } from "node:url";

const TEST_API_PATH = fileURLToPath(
  new URL("../../dist/content/testing.js", import.meta.url),
);

interface MenuEntryShape {
  uuid: string;
  title: string;
  username: string;
  group?: string;
}

interface ContentTestApi {
  defaultSettings: {
    autoFillSingleEntry: boolean;
    showFieldIcons: boolean;
    siteExceptions: unknown[];
  };
  normaliseSettings(raw: unknown): Record<string, unknown>;
  sitePolicyFor(
    settings: { siteExceptions: unknown[] },
    origin: string,
  ): { disableFill: boolean; disableSave: boolean; disableIcons: boolean };
  iconStateFor(input: Record<string, boolean>): string;
  computeMenuPosition(
    anchor: Record<string, number>,
    menu: Record<string, number>,
    viewport: Record<string, number>,
  ): { top: number; left: number; width: number; maxHeight: number; placement: string };
  filterMenuEntries(entries: MenuEntryShape[], query: string): MenuEntryShape[];
  monogramFor(entry: { title: string; username: string }): string;
  isNewPasswordField(field: HTMLInputElement): boolean;
  bannerTimeoutMs: number;
}

/** Read the test API without augmenting the global `Window` type (the WP4
 * content spec owns that declaration in this same TypeScript program). */

test.beforeEach(async ({ page }) => {
  await page.setContent(
    `<!doctype html><html><body>
      <form id="signup">
        <input id="user" type="text" autocomplete="username">
        <input id="new-pass" type="password" autocomplete="new-password">
        <input id="repeat-pass" type="password" autocomplete="new-password">
      </form>
      <form id="login">
        <input id="login-user" type="text" autocomplete="username">
        <input id="login-pass" type="password" autocomplete="current-password">
      </form>
    </body></html>`,
    { waitUntil: "load" },
  );
  await page.addScriptTag({ path: TEST_API_PATH });
  await page.waitForFunction(() =>
    Boolean((window as unknown as Record<string, unknown>).__friendlypassContentTest),
  );
});

test("WP6 defaults survive a settings payload that predates the new fields", async ({
  page,
}) => {
  const result = await page.evaluate(() => {
    const api = (
      window as unknown as { __friendlypassContentTest: ContentTestApi }
    ).__friendlypassContentTest;
    return {
      defaults: api.defaultSettings,
      normalised: api.normaliseSettings({
        autoFillHttpAuth: false,
        autoFillAndSubmit: true,
      }),
    };
  });
  expect(result.defaults.autoFillSingleEntry).toBe(false);
  expect(result.defaults.showFieldIcons).toBe(true);
  expect(result.defaults.siteExceptions).toEqual([]);
  expect(result.normalised.httpAuthAutoFill).toBe(false);
  expect(result.normalised.autoFillAndSubmit).toBe(true);
  expect(result.normalised.showFieldIcons).toBe(true);
  expect(result.normalised.siteExceptions).toEqual([]);
});

test("site exceptions disable exactly one origin", async ({ page }) => {
  const result = await page.evaluate(() => {
    const api = (
      window as unknown as { __friendlypassContentTest: ContentTestApi }
    ).__friendlypassContentTest;
    const settings = api.normaliseSettings({
      siteExceptions: [
        { origin: "https://example.com", disableIcons: true, disableFill: true },
      ],
    }) as unknown as { siteExceptions: unknown[] };
    return {
      same: api.sitePolicyFor(settings, "https://example.com"),
      other: api.sitePolicyFor(settings, "https://other.example"),
    };
  });
  expect(result.same).toEqual({
    disableFill: true,
    disableSave: false,
    disableIcons: true,
  });
  expect(result.other).toEqual({
    disableFill: false,
    disableSave: false,
    disableIcons: false,
  });
});

test("icon states and menu placement helpers", async ({ page }) => {
  const result = await page.evaluate(() => {
    const api = (
      window as unknown as { __friendlypassContentTest: ContentTestApi }
    ).__friendlypassContentTest;
    const base = {
      visible: true,
      appRunning: true,
      locked: false,
      databaseOpen: true,
      associated: true,
      hasMatches: true,
    };
    return {
      matches: api.iconStateFor(base),
      empty: api.iconStateFor({ ...base, hasMatches: false }),
      locked: api.iconStateFor({ ...base, locked: true }),
      down: api.iconStateFor({ ...base, appRunning: false }),
      hidden: api.iconStateFor({ ...base, visible: false }),
      below: api.computeMenuPosition(
        { top: 100, left: 80, right: 380, bottom: 132, width: 300, height: 32 },
        { width: 300, height: 220 },
        { width: 900, height: 700 },
      ),
      above: api.computeMenuPosition(
        { top: 640, left: 80, right: 380, bottom: 672, width: 300, height: 32 },
        { width: 300, height: 220 },
        { width: 900, height: 700 },
      ),
    };
  });
  expect(result.matches).toBe("matches");
  expect(result.empty).toBe("empty");
  expect(result.locked).toBe("locked");
  expect(result.down).toBe("hidden");
  expect(result.hidden).toBe("hidden");
  expect(result.below.placement).toBe("below");
  expect(result.above.placement).toBe("above");
  expect(result.above.top).toBe(640 - 4 - 220);
});

test("menu search filters and monograms render", async ({ page }) => {
  const result = await page.evaluate(() => {
    const api = (
      window as unknown as { __friendlypassContentTest: ContentTestApi }
    ).__friendlypassContentTest;
    const entries = [
      { uuid: "a", title: "GitHub", username: "alice", group: "Work" },
      { uuid: "b", title: "Bank", username: "bob", group: "Personal" },
    ];
    return {
      all: api.filterMenuEntries(entries, "").length,
      work: api.filterMenuEntries(entries, "work").map((entry) => entry.uuid),
      none: api.filterMenuEntries(entries, "zzz").length,
      monogram: api.monogramFor({ title: "github", username: "alice" }),
    };
  });
  expect(result.all).toBe(2);
  expect(result.work).toEqual(["a"]);
  expect(result.none).toBe(0);
  expect(result.monogram).toBe("G");
});

test("new-password detection drives the generate action", async ({ page }) => {
  const result = await page.evaluate(() => {
    const api = (
      window as unknown as { __friendlypassContentTest: ContentTestApi }
    ).__friendlypassContentTest;
    return {
      newField: api.isNewPasswordField(
        document.getElementById("new-pass") as HTMLInputElement,
      ),
      currentField: api.isNewPasswordField(
        document.getElementById("login-pass") as HTMLInputElement,
      ),
    };
  });
  expect(result.newField).toBe(true);
  expect(result.currentField).toBe(false);
});

test("the save card auto-dismisses after 60 seconds", async ({ page }) => {
  const timeout = await page.evaluate(() => {
    const api = (
      window as unknown as { __friendlypassContentTest: ContentTestApi }
    ).__friendlypassContentTest;
    return api.bannerTimeoutMs;
  });
  expect(timeout).toBe(60_000);
});
