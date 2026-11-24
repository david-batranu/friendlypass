/**
 * WP9 unit tests — the cross-browser adapters.
 *
 * These tests exercise the small surface that differs between Chrome and
 * Firefox: browser detection, callback-vs-promise storage, the `alarms`
 * minimum period, native-port error reporting and the options shortcut link.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CHROME_MIN_ALARM_MINUTES,
  FIREFOX_MIN_ALARM_MINUTES,
  alarmPeriodMinutes,
  detectBrowserKind,
  getAllCommands,
  getTab,
  nativePortErrorMessage,
  queryTabs,
  shortcutUi,
  storageGet,
  storageRemove,
  storageSet,
  tabsCreate,
  windowsCreate,
  windowsRemove,
  type StorageAreaLike,
} from "../../src/common/platform";

interface GlobalWithApis {
  chrome?: Record<string, unknown>;
  browser?: Record<string, unknown>;
}

const globals = globalThis as unknown as GlobalWithApis;

afterEach(() => {
  delete globals.chrome;
  delete globals.browser;
  vi.restoreAllMocks();
});

describe("browser detection", () => {
  it("recognises Firefox through runtime.getBrowserInfo", () => {
    globals.browser = { runtime: { getBrowserInfo: () => Promise.resolve({}) } };
    globals.chrome = { runtime: {} };
    expect(detectBrowserKind()).toBe("firefox");
  });

  it("falls back to the user agent", () => {
    expect(
      detectBrowserKind({
        navigator: { userAgent: "Mozilla/5.0 Firefox/140.0" },
      }),
    ).toBe("firefox");
  });

  it("defaults to Chrome without browser hints", () => {
    expect(
      detectBrowserKind({
        navigator: { userAgent: "Mozilla/5.0 Chrome/124.0" },
      }),
    ).toBe("chrome");
    expect(detectBrowserKind({})).toBe("chrome");
  });
});

describe("alarm period", () => {
  it("keeps Chrome's 30 s minimum", () => {
    expect(alarmPeriodMinutes(0.5, "chrome")).toBe(CHROME_MIN_ALARM_MINUTES);
    expect(alarmPeriodMinutes(0.1, "chrome")).toBe(CHROME_MIN_ALARM_MINUTES);
    expect(alarmPeriodMinutes(5, "chrome")).toBe(5);
  });

  it("raises the period to Firefox's 1 minute minimum", () => {
    expect(alarmPeriodMinutes(0.5, "firefox")).toBe(FIREFOX_MIN_ALARM_MINUTES);
    expect(alarmPeriodMinutes(0, "firefox")).toBe(FIREFOX_MIN_ALARM_MINUTES);
    expect(alarmPeriodMinutes(2, "firefox")).toBe(2);
  });
});

/** Firefox's `chrome.storage` namespace: callback only. */
function callbackArea(initial: Record<string, unknown> = {}): StorageAreaLike & {
  data: Map<string, unknown>;
} {
  const data = new Map<string, unknown>(Object.entries(initial));
  return {
    data,
    get(key, callback) {
      const result = data.has(key) ? { [key]: data.get(key) } : {};
      callback?.(result);
      return undefined;
    },
    set(items, callback) {
      for (const [key, value] of Object.entries(items)) data.set(key, value);
      callback?.();
      return undefined;
    },
    remove(key, callback) {
      data.delete(key);
      callback?.();
      return undefined;
    },
  };
}

describe("storage adapters", () => {
  it("awaits callback-style storage (Firefox)", async () => {
    const area = callbackArea({ greeting: { hello: "world" } });
    await expect(storageGet(area, "greeting")).resolves.toEqual({
      greeting: { hello: "world" },
    });
    await storageSet(area, { added: 1 });
    expect(area.data.get("added")).toBe(1);
    await storageRemove(area, "added");
    expect(area.data.has("added")).toBe(false);
  });

  it("also accepts promise-style storage", async () => {
    const data = new Map<string, unknown>([["key", { value: 7 }]]);
    const area: StorageAreaLike = {
      get: async (key) => (data.has(key) ? { [key]: data.get(key) } : {}),
      set: async (items) => {
        for (const [key, value] of Object.entries(items)) data.set(key, value);
      },
      remove: async (key) => {
        data.delete(key);
      },
    };
    await expect(storageGet(area, "key")).resolves.toEqual({ key: { value: 7 } });
    await storageSet(area, { key2: true });
    expect(data.get("key2")).toBe(true);
    await storageRemove(area, "key");
    expect(data.has("key")).toBe(false);
  });

  it("returns an empty object for a missing key and survives a throwing area", async () => {
    const area = callbackArea();
    await expect(storageGet(area, "missing")).resolves.toEqual({});
    const broken: StorageAreaLike = {
      get() {
        throw new Error("storage unavailable");
      },
      set() {
        throw new Error("storage unavailable");
      },
    };
    await expect(storageGet(broken, "x")).rejects.toThrow("storage unavailable");
  });
});

describe("native port error", () => {
  it("prefers Firefox's port.error", () => {
    expect(
      nativePortErrorMessage({ error: { message: "no such native application" } }),
    ).toBe("no such native application");
  });

  it("falls back to and consumes runtime.lastError (Chrome)", () => {
    globals.chrome = {
      runtime: { lastError: { message: "Specified native messaging host not found." } },
    };
    expect(nativePortErrorMessage(null)).toBe(
      "Specified native messaging host not found.",
    );
    expect(nativePortErrorMessage(null)).toBe(
      "Specified native messaging host not found.",
    );
  });

  it("returns undefined when neither is set", () => {
    expect(nativePortErrorMessage(undefined)).toBeUndefined();
  });
});

describe("callback/promise API wrappers", () => {
  it("reads commands through a callback", async () => {
    globals.chrome = {
      commands: {
        getAll: (callback: (commands: unknown[]) => void) => {
          callback([{ name: "fill-login", shortcut: "Ctrl+Shift+L" }]);
        },
      },
    };
    await expect(getAllCommands()).resolves.toEqual([
      { name: "fill-login", shortcut: "Ctrl+Shift+L" },
    ]);
  });

  it("returns an empty command list when the API is missing", async () => {
    await expect(getAllCommands()).resolves.toEqual([]);
  });

  it("queries tabs through a callback", async () => {
    globals.chrome = {
      tabs: {
        query: (query: Record<string, unknown>, callback: (tabs: unknown[]) => void) => {
          expect(query).toEqual({ active: true });
          callback([{ id: 3, url: "https://example.com/" }]);
        },
        get: (id: number, callback: (tab: unknown) => void) => {
          callback({ id, url: "https://example.com/" });
        },
        create: (options: Record<string, unknown>, callback: (tab: unknown) => void) => {
          callback({ id: 12, url: String(options["url"]) });
        },
      },
    };
    await expect(queryTabs({ active: true })).resolves.toEqual([
      { id: 3, url: "https://example.com/" },
    ]);
    await expect(getTab(9)).resolves.toEqual({
      id: 9,
      url: "https://example.com/",
    });
    await expect(tabsCreate({ url: "https://example.com/help" })).resolves.toEqual({
      id: 12,
      url: "https://example.com/help",
    });
  });

  it("creates and removes windows through callbacks", async () => {
    const removed: number[] = [];
    globals.chrome = {
      windows: {
        create: (options: Record<string, unknown>, callback: (window: unknown) => void) => {
          expect(options["type"]).toBe("popup");
          callback({ id: 11 });
        },
        remove: (id: number, callback: () => void) => {
          removed.push(id);
          callback();
        },
      },
    };
    await expect(windowsCreate({ type: "popup" })).resolves.toEqual({ id: 11 });
    await expect(windowsRemove(11)).resolves.toBeUndefined();
    expect(removed).toEqual([11]);
  });
});

describe("shortcut settings link", () => {
  it("points Chrome at chrome://extensions/shortcuts", () => {
    expect(shortcutUi("chrome").url).toBe("chrome://extensions/shortcuts");
    expect(shortcutUi("chrome").hint).toBe("chrome://extensions/shortcuts");
  });

  it("points Firefox at about:addons", () => {
    expect(shortcutUi("firefox").url).toBe("about:addons");
    expect(shortcutUi("firefox").hint).toContain("Manage Extension Shortcuts");
  });
});
