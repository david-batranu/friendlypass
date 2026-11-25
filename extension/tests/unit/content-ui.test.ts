/**
 * WP6b pure-helper unit tests (vitest / Node).
 *
 * The in-page UI itself is exercised by Playwright (real shadow DOM, real
 * stack); this file locks the decision tables that are easy to get subtly
 * wrong: settings normalisation, per-origin policy, icon states, menu
 * placement/filtering.
 */

import { describe, expect, it } from "vitest";
import {
  monogramFor,
  filterMenuEntries,
  type MenuEntry,
} from "../../src/content/autocomplete";
import { BANNER_TIMEOUT_MS } from "../../src/content/banner";
import { iconStateFor } from "../../src/content/icon-state";
import { computeMenuPosition } from "../../src/content/position";
import {
  DEFAULT_CONTENT_SETTINGS,
  mergeLegacySettings,
  normaliseSettings,
  sitePolicyFor,
} from "../../src/content/settings";

const ENTRIES: MenuEntry[] = [
  { uuid: "1", title: "GitHub", username: "alice@example.com", group: "Work" },
  { uuid: "2", title: "Bank", username: "alice@example.org", group: "Personal" },
  { uuid: "3", title: "Zeta", username: "bob", group: "Old" },
];

describe("settings normalisation", () => {
  it("applies the WP6 defaults to an empty payload", () => {
    expect(normaliseSettings(null)).toEqual(DEFAULT_CONTENT_SETTINGS);
    expect(normaliseSettings({})).toEqual(DEFAULT_CONTENT_SETTINGS);
    expect(DEFAULT_CONTENT_SETTINGS.siteExceptions).toEqual([]);
    expect(DEFAULT_CONTENT_SETTINGS.showFieldIcons).toBe(true);
    expect(DEFAULT_CONTENT_SETTINGS.autoFillSingleEntry).toBe(false);
    expect(DEFAULT_CONTENT_SETTINGS.httpAuthAutoFill).toBe(true);
  });

  it("reads the final field names", () => {
    const settings = normaliseSettings({
      autoFillSingleEntry: true,
      showFieldIcons: false,
      httpAuthAutoFill: false,
      autoFillAndSubmit: true,
      launchAppOnConnect: true,
      defaultGroup: "Work/Prod",
      defaultGroupAlwaysAsk: true,
      debugLogging: true,
      siteExceptions: [{ origin: "https://example.com", disableFill: true }],
    });
    expect(settings.autoFillSingleEntry).toBe(true);
    expect(settings.showFieldIcons).toBe(false);
    expect(settings.httpAuthAutoFill).toBe(false);
    expect(settings.autoFillAndSubmit).toBe(true);
    expect(settings.launchAppOnConnect).toBe(true);
    expect(settings.defaultGroup).toBe("Work/Prod");
    expect(settings.defaultGroupAlwaysAsk).toBe(true);
    expect(settings.debugLogging).toBe(true);
    expect(settings.siteExceptions).toEqual([
      { origin: "https://example.com", disableFill: true },
    ]);
  });

  it("accepts the pre-WP6 http-auth name as an alias", () => {
    expect(normaliseSettings({ autoFillHttpAuth: false }).httpAuthAutoFill).toBe(false);
    expect(
      normaliseSettings({ autoFillHttpAuth: false, httpAuthAutoFill: true })
        .httpAuthAutoFill,
    ).toBe(true);
  });

  it("drops malformed and duplicate exceptions", () => {
    const settings = normaliseSettings({
      siteExceptions: [
        { origin: "https://a.example", disableIcons: true },
        { origin: "https://a.example", disableFill: true },
        { origin: "", disableFill: true },
        { disableSave: true },
        "nope",
        { origin: "https://b.example", disableFill: "yes" },
      ],
    });
    expect(settings.siteExceptions).toEqual([
      { origin: "https://a.example", disableIcons: true },
      { origin: "https://b.example" },
    ]);
  });

  it("keeps legacy content settings working", () => {
    const merged = mergeLegacySettings(
      { ...DEFAULT_CONTENT_SETTINGS },
      { autoFillSingleEntry: true, showIcons: false },
    );
    expect(merged.autoFillSingleEntry).toBe(true);
    expect(merged.showFieldIcons).toBe(false);
  });
});

describe("site policy", () => {
  const settings = normaliseSettings({
    siteExceptions: [
      { origin: "https://example.com", disableIcons: true },
      { origin: "https://fill.example", disableFill: true },
      { origin: "https://save.example", disableSave: true },
    ],
  });

  it("matches the exact origin only", () => {
    expect(sitePolicyFor(settings, "https://example.com").disableIcons).toBe(true);
    expect(sitePolicyFor(settings, "https://example.com:8443").disableIcons).toBe(false);
    expect(sitePolicyFor(settings, "https://sub.example.com").disableIcons).toBe(false);
    expect(sitePolicyFor(settings, "https://fill.example").disableFill).toBe(true);
    expect(sitePolicyFor(settings, "https://save.example").disableSave).toBe(true);
  });

  it("has no policy for unknown or empty origins", () => {
    expect(sitePolicyFor(settings, "https://unknown.example")).toEqual({
      disableFill: false,
      disableSave: false,
      disableIcons: false,
    });
    expect(sitePolicyFor(settings, "")).toEqual({
      disableFill: false,
      disableSave: false,
      disableIcons: false,
    });
  });
});

describe("icon state", () => {
  const base = {
    visible: true,
    appRunning: true,
    locked: false,
    databaseOpen: true,
    associated: true,
    hasMatches: true,
  };

  it("is hidden when icons are disabled or the app is down", () => {
    expect(iconStateFor({ ...base, visible: false })).toBe("hidden");
    expect(iconStateFor({ ...base, appRunning: false })).toBe("hidden");
  });

  it("is locked when the database/association is unavailable", () => {
    expect(iconStateFor({ ...base, locked: true })).toBe("locked");
    expect(iconStateFor({ ...base, databaseOpen: false })).toBe("locked");
    expect(iconStateFor({ ...base, associated: false })).toBe("locked");
  });

  it("distinguishes matches from no matches", () => {
    expect(iconStateFor(base)).toBe("matches");
    expect(iconStateFor({ ...base, hasMatches: false })).toBe("empty");
  });
});

describe("menu positioning", () => {
  const viewport = { width: 1024, height: 768 };

  it("opens below the field with room", () => {
    const result = computeMenuPosition(
      { top: 100, left: 100, right: 400, bottom: 132, width: 300, height: 32 },
      { width: 300, height: 240 },
      viewport,
    );
    expect(result.placement).toBe("below");
    expect(result.top).toBe(136);
    expect(result.left).toBe(100);
  });

  it("flips above near the viewport bottom", () => {
    const result = computeMenuPosition(
      { top: 700, left: 100, right: 400, bottom: 732, width: 300, height: 32 },
      { width: 300, height: 240 },
      viewport,
    );
    expect(result.placement).toBe("above");
    expect(result.top).toBe(700 - 4 - 240);
  });

  it("clamps the left edge and the width to the viewport", () => {
    const result = computeMenuPosition(
      { top: 100, left: 1000, right: 1300, bottom: 132, width: 300, height: 32 },
      { width: 300, height: 200 },
      viewport,
    );
    expect(result.left).toBeLessThanOrEqual(viewport.width - result.width - 8);
    expect(result.width).toBeLessThanOrEqual(420);
  });

  it("caps the height to the space below", () => {
    const result = computeMenuPosition(
      { top: 600, left: 10, right: 310, bottom: 632, width: 300, height: 32 },
      { width: 300, height: 320 },
      viewport,
    );
    // Below is short, above is short too: the menu is capped and clamped.
    expect(result.maxHeight).toBeGreaterThanOrEqual(72);
    expect(result.maxHeight).toBeLessThanOrEqual(320);
  });
});

describe("menu search", () => {
  it("filters by title, username and group, case-insensitively", () => {
    expect(filterMenuEntries(ENTRIES, "").map((entry) => entry.uuid)).toEqual([
      "1",
      "2",
      "3",
    ]);
    expect(filterMenuEntries(ENTRIES, "git").map((entry) => entry.uuid)).toEqual(["1"]);
    expect(filterMenuEntries(ENTRIES, "ALICE").map((entry) => entry.uuid)).toEqual([
      "1",
      "2",
    ]);
    expect(filterMenuEntries(ENTRIES, "personal").map((entry) => entry.uuid)).toEqual([
      "2",
    ]);
    expect(filterMenuEntries(ENTRIES, "nothing")).toEqual([]);
  });

  it("derives a monogram from the title, then the username", () => {
    expect(monogramFor({ title: "github", username: "alice" })).toBe("G");
    expect(monogramFor({ title: "", username: "bob" })).toBe("B");
    expect(monogramFor({ title: "", username: "" })).toBe("F");
  });
});

describe("banner", () => {
  it("auto-dismisses after 60 seconds", () => {
    expect(BANNER_TIMEOUT_MS).toBe(60_000);
  });
});
