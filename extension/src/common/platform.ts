/**
 * Thin cross-browser adapters (WP9).
 *
 * The extension is written against the callback-style `chrome.*` namespace,
 * which both Chrome and Firefox implement. Only a handful of places need a
 * browser-specific decision; they all live here so the rest of the source tree
 * stays one implementation:
 *
 *  - `chrome.storage.*.get(key)` without a callback returns a Promise in Chrome
 *    MV3 but is callback-only in Firefox's `chrome` namespace, so every awaited
 *    read goes through {@link storageGet}.
 *  - `chrome.alarms` enforces a 30 s minimum period in Chrome MV3 but a 1 minute
 *    minimum in Firefox; {@link alarmPeriodMinutes} clamps accordingly.
 *  - A native-messaging port reports its terminal error on `port.error` in
 *    Firefox and on `chrome.runtime.lastError` in Chrome.
 *  - `chrome.commands.getAll()`, `chrome.tabs.query()` and
 *    `chrome.windows.create()` return Promises in Chrome and take callbacks in
 *    Firefox; {@link getAllCommands}, {@link queryTabs} and
 *    {@link windowsCreate} accept either return style.
 *  - Options links differ (`chrome://extensions/shortcuts` vs `about:addons`).
 *
 * Nothing here touches target data or credentials.
 */

export type BrowserKind = "chrome" | "firefox";

/** 30 s, the Chrome MV3 minimum for `alarms` periods. */
export const CHROME_MIN_ALARM_MINUTES = 0.5;

/** 1 minute, the Firefox minimum for `alarms` periods. */
export const FIREFOX_MIN_ALARM_MINUTES = 1;

interface RuntimeLike {
  getBrowserInfo?: unknown;
  lastError?: { message?: string } | null;
}

interface BrowserScope {
  browser?: { runtime?: RuntimeLike };
  chrome?: { runtime?: RuntimeLike };
  navigator?: { userAgent?: string };
}

export interface CommandLike {
  name?: string;
  description?: string;
  shortcut?: string;
}

export interface TabLike {
  id?: number;
  url?: string;
  title?: string;
}

export interface StorageAreaLike {
  get(
    keys: string,
    callback?: (items: Record<string, unknown>) => void,
  ): unknown;
  set(items: Record<string, unknown>, callback?: () => void): unknown;
  remove?(keys: string, callback?: () => void): unknown;
}

export interface PortErrorLike {
  error?: { message?: string } | null;
}

function scopeOf(scope: unknown): BrowserScope {
  return (scope ?? {}) as BrowserScope;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    (typeof value === "object" || typeof value === "function") &&
    value !== null &&
    typeof (value as PromiseLike<unknown>).then === "function"
  );
}

/**
 * Firefox exposes `runtime.getBrowserInfo()`; Chrome does not. The user-agent
 * check is a fallback for tests and very old builds.
 */
export function detectBrowserKind(scope: unknown = globalThis): BrowserKind {
  const value = scopeOf(scope);
  const runtime = value.browser?.runtime ?? value.chrome?.runtime;
  if (runtime && typeof runtime.getBrowserInfo === "function") {
    return "firefox";
  }
  const userAgent = value.navigator?.userAgent;
  if (typeof userAgent === "string" && /\bFirefox\//.test(userAgent)) {
    return "firefox";
  }
  return "chrome";
}

/** Read (and consume) `chrome.runtime.lastError.message`, if any. */
export function lastErrorMessage(scope: unknown = globalThis): string | undefined {
  const value = scopeOf(scope);
  try {
    const runtime = value.chrome?.runtime ?? value.browser?.runtime;
    const message = runtime?.lastError?.message;
    return typeof message === "string" && message.length > 0 ? message : undefined;
  } catch {
    // Accessing lastError outside a callback context can throw in some builds.
    return undefined;
  }
}

/**
 * The error of a closed native-messaging port. Firefox sets `port.error`;
 * Chrome sets `runtime.lastError` while `onDisconnect` runs.
 */
export function nativePortErrorMessage(
  port?: PortErrorLike | null,
  scope: unknown = globalThis,
): string | undefined {
  const portMessage = port?.error?.message;
  if (typeof portMessage === "string" && portMessage.length > 0) {
    return portMessage;
  }
  return lastErrorMessage(scope);
}

/**
 * `alarms` minimum period. Chrome MV3 accepts 30 s; Firefox silently treats
 * anything below 1 minute as invalid, so the watchdog period is clamped.
 */
export function alarmPeriodMinutes(
  requested: number,
  kind: BrowserKind = detectBrowserKind(),
): number {
  const minimum =
    kind === "firefox" ? FIREFOX_MIN_ALARM_MINUTES : CHROME_MIN_ALARM_MINUTES;
  if (!Number.isFinite(requested) || requested <= 0) {
    return minimum;
  }
  return Math.max(requested, minimum);
}

/**
 * Promise wrapper that works for both callback-style and promise-style APIs.
 *
 * `invoke` receives a callback; if the API returns a Promise instead (or as
 * well), that also settles the wrapper. The first settlement wins.
 */
function callWithCallback<T>(
  invoke: (callback: (value: T) => void) => unknown,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (value: unknown): void => {
      if (settled) return;
      settled = true;
      resolve(value as T);
    };
    try {
      const returned = invoke((value) => {
        // Consume lastError so Chrome does not log an unchecked error.
        void lastErrorMessage();
        finish(value);
      });
      if (isThenable(returned)) {
        returned.then(finish, reject);
      }
    } catch (cause) {
      reject(cause);
    }
  });
}

/** `chrome.storage.*.get(key)` for both namespaces. */
export function storageGet(
  area: StorageAreaLike,
  key: string,
): Promise<Record<string, unknown>> {
  return new Promise<Record<string, unknown>>((resolve, reject) => {
    let settled = false;
    const finish = (value: unknown): void => {
      if (settled) return;
      settled = true;
      resolve(isRecord(value) ? value : {});
    };
    try {
      const returned = area.get(key, (items) => {
        void lastErrorMessage();
        finish(items);
      });
      if (isThenable(returned)) {
        returned.then(finish, reject);
      }
    } catch (cause) {
      reject(cause);
    }
  });
}

/** `chrome.storage.*.set(items)` for both namespaces. */
export function storageSet(
  area: StorageAreaLike,
  items: Record<string, unknown>,
): Promise<void> {
  return callWithCallback<void>((callback) => area.set(items, callback));
}

/** `chrome.storage.*.remove(key)` for both namespaces. */
export function storageRemove(
  area: StorageAreaLike,
  key: string,
): Promise<void> {
  if (typeof area.remove !== "function") {
    return Promise.resolve();
  }
  return callWithCallback<void>((callback) => area.remove?.(key, callback));
}

/** `chrome.commands.getAll()` as a Promise on both browsers. */
export function getAllCommands(): Promise<CommandLike[]> {
  const api = (
    globalThis as unknown as {
      chrome?: {
        commands?: {
          getAll?: (callback: (commands: CommandLike[]) => void) => unknown;
        };
      };
    }
  ).chrome?.commands;
  if (!api?.getAll) {
    return Promise.resolve([]);
  }
  return callWithCallback<CommandLike[]>((callback) =>
    api.getAll?.((commands) => callback(Array.isArray(commands) ? commands : [])),
  ).catch(() => []);
}

/** `chrome.tabs.query(query)` as a Promise on both browsers. */
export function queryTabs(query: Record<string, unknown>): Promise<TabLike[]> {  const api = (
    globalThis as unknown as {
      chrome?: {
        tabs?: {
          query?: (
            info: Record<string, unknown>,
            callback: (tabs: TabLike[]) => void,
          ) => unknown;
        };
      };
    }
  ).chrome?.tabs;
  if (!api?.query) {
    return Promise.resolve([]);
  }
  return callWithCallback<TabLike[]>((callback) =>
    api.query?.(query, (tabs) => callback(Array.isArray(tabs) ? tabs : [])),
  );
}

/** `chrome.tabs.create(options)` as a Promise on both browsers. */
export function tabsCreate(options: Record<string, unknown>): Promise<TabLike | null> {
  const api = (
    globalThis as unknown as {
      chrome?: {
        tabs?: {
          create?: (
            data: Record<string, unknown>,
            callback: (tab: TabLike) => void,
          ) => unknown;
        };
      };
    }
  ).chrome?.tabs;
  if (!api?.create) {
    return Promise.reject(new Error("tabs API unavailable"));
  }
  return callWithCallback<TabLike | null>((callback) =>
    api.create?.(options, (tab) => callback(tab ?? null)),
  );
}

/** `chrome.tabs.get(tabId)` as a Promise on both browsers. */
export function getTab(tabId: number): Promise<TabLike | null> {
  const api = (
    globalThis as unknown as {
      chrome?: {
        tabs?: {
          get?: (id: number, callback: (tab: TabLike) => void) => unknown;
        };
      };
    }
  ).chrome?.tabs;
  if (!api?.get) {
    return Promise.resolve(null);
  }
  return callWithCallback<TabLike | null>((callback) =>
    api.get?.(tabId, (tab) => callback(tab ?? null)),
  ).catch(() => null);
}

/** `chrome.windows.create(options)` as a Promise on both browsers. */
export function windowsCreate(options: Record<string, unknown>): Promise<unknown> {
  const api = (
    globalThis as unknown as {
      chrome?: {
        windows?: {
          create?: (
            data: Record<string, unknown>,
            callback: (window: unknown) => void,
          ) => unknown;
        };
      };
    }
  ).chrome?.windows;
  if (!api?.create) {
    return Promise.reject(new Error("windows API unavailable"));
  }
  return callWithCallback<unknown>((callback) =>
    api.create?.(options, (window) => callback(window)),
  );
}

/** `chrome.windows.remove(windowId)` as a Promise on both browsers. */
export function windowsRemove(windowId: number): Promise<void> {
  const api = (
    globalThis as unknown as {
      chrome?: {
        windows?: {
          remove?: (id: number, callback: () => void) => unknown;
        };
      };
    }
  ).chrome?.windows;
  if (!api?.remove) {
    return Promise.resolve();
  }
  return callWithCallback<void>((callback) => api.remove?.(windowId, callback));
}

/** Where the browser manages extension keyboard shortcuts. */
export interface ShortcutUi {
  /** URL opened by the options page button. */
  url: string;
  /** Inline hint shown next to the button. */
  hint: string;
  /** Card copy naming the browser. */
  copy: string;
}

export function shortcutUi(
  kind: BrowserKind = detectBrowserKind(),
): ShortcutUi {
  if (kind === "firefox") {
    return {
      url: "about:addons",
      hint: "about:addons → ⚙ → Manage Extension Shortcuts",
      copy:
        "These are the keys Firefox currently reports for friendlypass. Change them in about:addons (⚙ → Manage Extension Shortcuts).",
    };
  }
  return {
    url: "chrome://extensions/shortcuts",
    hint: "chrome://extensions/shortcuts",
    copy:
      "These are the keys Chrome currently reports for friendlypass. Change them in chrome://extensions/shortcuts.",
  };
}
