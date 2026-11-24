/**
 * WP6a — unified settings: defaults, validation, migration and broadcast.
 *
 * The state store is the only writer of `ExtensionSettings`; the popup, the
 * options page, the content scripts and HTTP authentication all read it
 * through `settings.get`. These tests pin the contract:
 *
 *  - every field exists with the documented default;
 *  - garbage, unknown keys and wrong types never reach storage;
 *  - the pre-WP6a `autoFillHttpAuth` flag is migrated once;
 *  - the legacy `friendlypass.httpAuth.v1` flag is copied once and removed;
 *  - every successful `settings.set` broadcasts the full settings object.
 */

import { describe, expect, it, vi } from "vitest";

import {
  DEFAULT_SETTINGS,
  MAX_SITE_EXCEPTIONS,
  MemoryStorageArea,
  createStateStore,
  defaultSettings,
  normaliseOrigin,
  sanitiseSettings,
} from "../../src/background/state";
import {
  HTTP_AUTH_MIGRATION_KEY,
  HTTP_AUTH_STORAGE_KEY,
  createUnifiedHttpAuthSettingsStore,
  migrateHttpAuthAutoFill,
  type HttpAuthSettingsBridge,
} from "../../src/background/http-auth";
import type { ExtensionSettings } from "../../src/common/types";

function bridge(initial: boolean): HttpAuthSettingsBridge & {
  value: boolean;
  writes: boolean[];
} {
  const state = {
    value: initial,
    writes: [] as boolean[],
    getAutoFill: async () => state.value,
    setAutoFill: async (value: boolean) => {
      state.writes.push(value);
      state.value = value;
    },
  };
  return state;
}

function storage(initial: Record<string, unknown> = {}): {
  data: Record<string, unknown>;
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
} {
  const data: Record<string, unknown> = { ...initial };
  return {
    data,
    async get(key) {
      return key in data ? { [key]: data[key] } : {};
    },
    async set(items) {
      Object.assign(data, items);
    },
  };
}

describe("settings defaults", () => {
  it("matches the unified contract exactly", () => {
    expect(DEFAULT_SETTINGS).toMatchObject({
      autoFillSingleEntry: false,
      showFieldIcons: true,
      httpAuthAutoFill: true,
      autoFillAndSubmit: false,
      launchAppOnConnect: false,
      defaultGroup: "",
      defaultGroupAlwaysAsk: false,
      debugLogging: false,
      siteExceptions: [],
    });
    expect(Object.keys(defaultSettings()).sort()).toEqual(
      [
        "autoFillAndSubmit",
        "autoFillSingleEntry",
        "debugLogging",
        "defaultGroup",
        "defaultGroupAlwaysAsk",
        "httpAuthAutoFill",
        "launchAppOnConnect",
        "showFieldIcons",
        "siteExceptions",
      ].sort(),
    );
  });

  it("returns an independent copy each time", () => {
    const first = defaultSettings();
    first.siteExceptions.push({ origin: "https://example.com", disableFill: true });
    first.debugLogging = true;
    expect(defaultSettings().siteExceptions).toEqual([]);
    expect(defaultSettings().debugLogging).toBe(false);
    expect(DEFAULT_SETTINGS.siteExceptions).toEqual([]);
  });
});

describe("settings validation", () => {
  it("ignores garbage and unknown keys", () => {
    expect(sanitiseSettings(null)).toEqual(defaultSettings());
    expect(sanitiseSettings("nope")).toEqual(defaultSettings());
    expect(
      sanitiseSettings({ unknown: 1, debugLogging: "yes", showFieldIcons: false }),
    ).toEqual({ ...defaultSettings(), showFieldIcons: false });
  });

  it("migrates autoFillHttpAuth to httpAuthAutoFill", () => {
    expect(sanitiseSettings({ autoFillHttpAuth: false }).httpAuthAutoFill).toBe(false);
    // The new field always wins when both are present.
    expect(
      sanitiseSettings({ autoFillHttpAuth: false, httpAuthAutoFill: true })
        .httpAuthAutoFill,
    ).toBe(true);
    expect(sanitiseSettings({ autoFillHttpAuth: "no" }).httpAuthAutoFill).toBe(true);
  });

  it("normalises defaultGroup and drops control characters", () => {
    expect(sanitiseSettings({ defaultGroup: "  Web\u0000 " }).defaultGroup).toBe("Web");
    expect(
      sanitiseSettings({ defaultGroup: "x".repeat(1_000) }).defaultGroup.length,
    ).toBeLessThanOrEqual(256);
  });

  it("validates and normalises site exceptions", () => {
    const settings = sanitiseSettings({
      siteExceptions: [
        { origin: "https://example.com/login", disableFill: true },
        { origin: "https://example.com/" },
        { origin: "example.org", disableSave: true, disableIcons: "yes" },
        { origin: "ftp://example.net" },
        { origin: 42 },
        "not-an-object",
      ],
    });
    expect(settings.siteExceptions).toEqual([
      { origin: "https://example.com", disableFill: true },
      { origin: "https://example.org", disableSave: true },
    ]);
  });

  it("caps the exception list", () => {
    const many = Array.from({ length: MAX_SITE_EXCEPTIONS + 25 }, (_, index) => ({
      origin: `https://site${index}.example`,
    }));
    expect(sanitiseSettings({ siteExceptions: many }).siteExceptions).toHaveLength(
      MAX_SITE_EXCEPTIONS,
    );
  });

  it("normalises origins the way the options form does", () => {
    expect(normaliseOrigin("example.com")).toBe("https://example.com");
    expect(normaliseOrigin("https://example.com/account?x=1")).toBe(
      "https://example.com",
    );
    expect(normaliseOrigin("http://localhost:8080/")).toBe("http://localhost:8080");
    expect(normaliseOrigin("  ")).toBeNull();
    expect(normaliseOrigin("ftp://example.com")).toBeNull();
    expect(normaliseOrigin("not a url")).toBeNull();
  });
});

describe("state store settings", () => {
  it("merges patches, persists and broadcasts the full settings", async () => {
    const storageArea = new MemoryStorageArea();
    const broadcastSettings = vi.fn<(settings: ExtensionSettings) => void>();
    const store = createStateStore({
      storage: storageArea,
      broadcast: () => undefined,
      broadcastSettings,
    });

    const updated = await store.setSettings({ debugLogging: true });
    expect(updated).toMatchObject({ debugLogging: true, showFieldIcons: true });
    expect(broadcastSettings).toHaveBeenCalledTimes(1);
    expect(broadcastSettings.mock.calls[0][0]).toEqual(updated);

    // A second store over the same storage sees the persisted value.
    const reopened = createStateStore({
      storage: storageArea,
      broadcast: () => undefined,
      broadcastSettings: vi.fn(),
    });
    expect(await reopened.getSettings()).toMatchObject({ debugLogging: true });
  });

  it("rejects invalid values on write without losing the old ones", async () => {
    const store = createStateStore({
      storage: new MemoryStorageArea(),
      broadcast: () => undefined,
      broadcastSettings: () => undefined,
    });
    await store.setSettings({ showFieldIcons: false });
    const result = await store.setSettings({
      showFieldIcons: "nope",
      siteExceptions: [{ origin: "ftp://example.com" }],
    } as unknown as Partial<ExtensionSettings>);
    expect(result.showFieldIcons).toBe(false);
    expect(result.siteExceptions).toEqual([]);
  });

  it("notifies settings subscribers with a copy", async () => {
    const store = createStateStore({
      storage: new MemoryStorageArea(),
      broadcast: () => undefined,
      broadcastSettings: () => undefined,
    });
    const seen: ExtensionSettings[] = [];
    const unsubscribe = store.subscribeSettings((settings) => seen.push(settings));
    await store.setSettings({ autoFillSingleEntry: true });
    unsubscribe();
    await store.setSettings({ autoFillSingleEntry: false });
    expect(seen).toHaveLength(1);
    expect(seen[0].autoFillSingleEntry).toBe(true);
  });

  it("migrates a persisted autoFillHttpAuth record on load", async () => {
    const storageArea = new MemoryStorageArea();
    await storageArea.set({
      "friendlypass.state.v1": {
        clientId: null,
        keyRing: {},
        settings: { autoFillHttpAuth: false },
      },
    });
    const store = createStateStore({
      storage: storageArea,
      broadcast: () => undefined,
      broadcastSettings: () => undefined,
    });
    expect((await store.getSettings()).httpAuthAutoFill).toBe(false);
  });
});

describe("http-auth settings migration", () => {
  it("copies the legacy flag once and removes it from the old record", async () => {
    const legacy = storage({
      [HTTP_AUTH_STORAGE_KEY]: {
        httpAuthAutoFill: false,
        lastUsed: { "https://example.com/": "alice" },
        realms: {},
      },
    });
    const target = bridge(true);

    await expect(
      migrateHttpAuthAutoFill({ bridge: target, storage: legacy }),
    ).resolves.toBe("migrated");
    expect(target.writes).toEqual([false]);
    expect(legacy.data[HTTP_AUTH_MIGRATION_KEY]).toBe(true);
    expect(legacy.data[HTTP_AUTH_STORAGE_KEY]).toEqual({
      lastUsed: { "https://example.com/": "alice" },
      realms: {},
    });

    // A user change afterwards must survive a second startup.
    target.value = true;
    await expect(
      migrateHttpAuthAutoFill({ bridge: target, storage: legacy }),
    ).resolves.toBe("skipped");
    expect(target.writes).toEqual([false]);
  });

  it("records the marker when there is nothing to migrate", async () => {
    const legacy = storage({});
    const target = bridge(true);
    await expect(
      migrateHttpAuthAutoFill({ bridge: target, storage: legacy }),
    ).resolves.toBe("none");
    expect(target.writes).toEqual([]);
    expect(legacy.data[HTTP_AUTH_MIGRATION_KEY]).toBe(true);
  });

  it("reads httpAuthAutoFill from the unified settings, hints from the legacy key", async () => {
    const target = bridge(false);
    const legacyStore = {
      load: async () => ({
        httpAuthAutoFill: true,
        lastUsed: { "https://example.com/": "alice" },
        realms: { deadbeef: "realm" },
      }),
      rememberLastUsed: vi.fn(async () => undefined),
      rememberRealm: vi.fn(async () => undefined),
      setAutoFill: vi.fn(async () => undefined),
    };
    const merged = createUnifiedHttpAuthSettingsStore(target, legacyStore);
    const loaded = await merged.load();
    expect(loaded.httpAuthAutoFill).toBe(false);
    expect(loaded.lastUsed).toEqual({ "https://example.com/": "alice" });
    expect(loaded.realms).toEqual({ deadbeef: "realm" });

    await merged.setAutoFill(true);
    expect(target.writes).toEqual([true]);
    expect(legacyStore.setAutoFill).not.toHaveBeenCalled();
  });
});
