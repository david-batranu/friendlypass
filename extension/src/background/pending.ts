/**
 * Pending submitted credentials (WP4b).
 *
 * A login form usually navigates the page when it submits. The content script
 * therefore reports the submitted pair to the service worker *before* the
 * document unloads, and the next page in the same tab asks for it and shows the
 * save/update banner. The store lives in `chrome.storage.session`: it survives
 * service-worker restarts, is never written to disk, and is dropped when the
 * browser session ends.
 *
 * Isolation rules (all enforced here, not in the page):
 *  - keyed by tab, so one tab can never see another tab's submission;
 *  - only returned to the submitting frame;
 *  - only returned on the same registrable site (IP hosts compare
 *    scheme/host/port, so two local test servers are different sites);
 *  - expires after {@link PENDING_TTL_MS} (a test-only setting may shorten it);
 *  - never stored for an origin the user chose "never for this site" for.
 *
 * Passwords are only ever kept in the session map and in the returned value;
 * nothing in this module logs or serialises them outside storage.
 */

import type { PendingCredential } from "../common/types";

/** `chrome.storage.session` key holding `{ "<tabId>": StoredPending }`. */
export const PENDING_STORAGE_KEY = "friendlypass.pending.v1";

/** `chrome.storage.local` key holding origins the user opted out of saving on. */
export const PENDING_NEVER_STORAGE_KEY = "friendlypass.pending.never.v1";

/**
 * `chrome.storage.local` key for test-only store settings (`{ ttlMs }`). The
 * e2e expiry test shortens the TTL so it does not sleep for a minute.
 */
export const PENDING_SETTINGS_KEY = "friendlypass.pending.settings.v1";

/** Default lifetime of a submitted pair. */
export const PENDING_TTL_MS = 60_000;

/** Shortest accepted test TTL; below this the value is treated as unusable. */
export const PENDING_MIN_TTL_MS = 100;

/** Minimal storage surface, shared by `chrome.storage.session`/`local` and tests. */
export interface PendingStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export interface PendingSubmissionInput {
  tabId: number;
  /** Submitting frame; only that frame is offered the banner again. */
  frameId?: number;
  /** URL of the page that contained the form. */
  url: string;
  username: string;
  password: string;
  submitUrl?: string;
}

/** The value handed to a content script; contains the plaintext password. */
export type { PendingCredential };

interface StoredPending extends PendingCredential {
  tabId: number;
  frameId?: number;
  /** Registrable site used for the cross-site check. */
  site: string;
  expiresAt: number;
}

export interface PendingStoreOptions {
  /** `chrome.storage.session` in the service worker. */
  storage: PendingStorageArea;
  /** `chrome.storage.local`; enables "never for this site" persistence. */
  neverStorage?: PendingStorageArea;
  now?: () => number;
  /** Fixed TTL or a (possibly async) getter, read on every store. */
  ttlMs?: number | (() => number | Promise<number>);
}

export interface PendingStore {
  /** Store a submission; `false` when it was rejected/ignored. */
  store(input: PendingSubmissionInput): Promise<boolean>;
  /** Consume the pending pair for this tab/frame/page, if it may be shown. */
  take(input: {
    tabId: number;
    frameId?: number;
    url: string;
  }): Promise<PendingCredential | null>;
  /** Drop any pending pair for the tab (save, dismiss, never-for-site). */
  clear(tabId: number): Promise<void>;
  /** Remember that this origin must never get a save banner. */
  never(origin: string): Promise<void>;
  /** Whether the user opted this origin out. */
  isNever(origin: string): Promise<boolean>;
  /** Remove expired entries (called by every operation; exposed for tests). */
  prune(): Promise<void>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Public suffixes that need three labels for the registrable domain. */
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "co.jp",
  "ne.jp",
  "or.jp",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "com.br",
  "com.cn",
  "com.mx",
  "co.in",
  "co.za",
  "com.tr",
]);

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * Registrable-site key used for the cross-site suppression check.
 *
 * IP hosts and `localhost` include scheme and port: two test servers on
 * different ports are genuinely different sites. Domain names use the
 * registrable domain, so `app.example.com` and `login.example.com` match.
 * Non-HTTP(S) URLs have no key and are never stored.
 */
export function siteKeyFromUrl(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return null;
  }
  const host = url.hostname.toLowerCase();
  if (!host) {
    return null;
  }
  if (host === "localhost" || host.endsWith(".localhost") || IPV4.test(host) || host.includes(":")) {
    return `${url.protocol}//${host}:${url.port}`;
  }
  const labels = host.split(".").filter((label) => label.length > 0);
  if (labels.length <= 2) {
    return host;
  }
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

/** Normalised origin (`scheme://host[:port]`), or `null` for a bad URL. */
export function originOfUrl(raw: string): string | null {
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

/**
 * Runtime TTL for new submissions. Defaults to one minute; a test-only
 * `chrome.storage.local` setting may only shorten it.
 */
export async function readPendingTtlMs(storage: PendingStorageArea): Promise<number> {
  try {
    const stored = await storage.get(PENDING_SETTINGS_KEY);
    const raw = stored[PENDING_SETTINGS_KEY];
    if (isRecord(raw) && typeof raw["ttlMs"] === "number") {
      const value = raw["ttlMs"];
      if (Number.isFinite(value) && value >= PENDING_MIN_TTL_MS) {
        return Math.min(value, PENDING_TTL_MS);
      }
    }
  } catch {
    // Storage can be unavailable while the extension starts; the default is safe.
  }
  return PENDING_TTL_MS;
}

function toCredential(entry: StoredPending): PendingCredential {
  return {
    url: entry.url,
    origin: entry.origin,
    username: entry.username,
    password: entry.password,
    ...(entry.submitUrl ? { submitUrl: entry.submitUrl } : {}),
    submittedAt: entry.submittedAt,
  };
}

/** Create a store. State lives only in the injected storage area. */
export function createPendingStore(options: PendingStoreOptions): PendingStore {
  const now = options.now ?? (() => Date.now());
  const ttlOption = options.ttlMs ?? PENDING_TTL_MS;

  // One storage write at a time: two frames submitting at once must not lose
  // one another's entry through read-modify-write races.
  let queue: Promise<unknown> = Promise.resolve();
  function serialise<T>(task: () => Promise<T>): Promise<T> {
    const run = queue.then(task, task);
    queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async function readMap(): Promise<Record<string, StoredPending>> {
    try {
      const stored = await options.storage.get(PENDING_STORAGE_KEY);
      const raw = stored[PENDING_STORAGE_KEY];
      if (!isRecord(raw)) {
        return {};
      }
      const map: Record<string, StoredPending> = {};
      for (const [tabId, value] of Object.entries(raw)) {
        if (isRecord(value) && typeof value["password"] === "string") {
          map[tabId] = value as unknown as StoredPending;
        }
      }
      return map;
    } catch {
      return {};
    }
  }

  async function writeMap(map: Record<string, StoredPending>): Promise<void> {
    if (Object.keys(map).length === 0) {
      await options.storage.remove(PENDING_STORAGE_KEY);
      return;
    }
    await options.storage.set({ [PENDING_STORAGE_KEY]: map });
  }

  function dropExpired(map: Record<string, StoredPending>, at: number): boolean {
    let changed = false;
    for (const [key, entry] of Object.entries(map)) {
      if (!isRecord(entry) || typeof entry.expiresAt !== "number" || entry.expiresAt <= at) {
        delete map[key];
        changed = true;
      }
    }
    return changed;
  }

  async function readNever(): Promise<Set<string>> {
    if (!options.neverStorage) {
      return new Set();
    }
    try {
      const stored = await options.neverStorage.get(PENDING_NEVER_STORAGE_KEY);
      const raw = stored[PENDING_NEVER_STORAGE_KEY];
      if (isRecord(raw) && Array.isArray(raw["origins"])) {
        return new Set(
          raw["origins"].filter((origin): origin is string => typeof origin === "string"),
        );
      }
    } catch {
      // Fall through: failing to read the opt-out must not block a save banner.
    }
    return new Set();
  }

  async function writeNever(origins: Set<string>): Promise<void> {
    if (!options.neverStorage) {
      return;
    }
    await options.neverStorage.set({
      [PENDING_NEVER_STORAGE_KEY]: { origins: [...origins] },
    });
  }

  async function ttlMs(): Promise<number> {
    try {
      const value = typeof ttlOption === "function" ? await ttlOption() : ttlOption;
      if (Number.isFinite(value) && value >= PENDING_MIN_TTL_MS) {
        return Math.min(value, PENDING_TTL_MS);
      }
    } catch {
      // A broken test setting must not disable the feature.
    }
    return PENDING_TTL_MS;
  }

  return {
    store(input) {
      return serialise(async () => {
        const site = siteKeyFromUrl(input.url);
        const origin = originOfUrl(input.url);
        if (!site || !origin || !input.password) {
          return false;
        }
        if ((await readNever()).has(origin)) {
          return false;
        }
        const at = now();
        const map = await readMap();
        dropExpired(map, at);
        const expiresAt = at + (await ttlMs());
        const entry: StoredPending = {
          tabId: input.tabId,
          ...(input.frameId !== undefined ? { frameId: input.frameId } : {}),
          url: input.url,
          origin,
          site,
          username: input.username,
          password: input.password,
          ...(input.submitUrl ? { submitUrl: input.submitUrl } : {}),
          submittedAt: at,
          expiresAt,
        };
        map[String(input.tabId)] = entry;
        await writeMap(map);
        return true;
      });
    },

    take(input) {
      return serialise(async () => {
        const at = now();
        const map = await readMap();
        let changed = dropExpired(map, at);
        const key = String(input.tabId);
        const entry = map[key];
        if (!entry) {
          if (changed) {
            await writeMap(map);
          }
          return null;
        }
        if (entry.expiresAt <= at) {
          delete map[key];
          await writeMap(map);
          return null;
        }
        if (
          entry.frameId !== undefined &&
          input.frameId !== undefined &&
          entry.frameId !== input.frameId
        ) {
          if (changed) {
            await writeMap(map);
          }
          return null;
        }
        const pageSite = siteKeyFromUrl(input.url);
        if (!pageSite || pageSite !== entry.site) {
          if (changed) {
            await writeMap(map);
          }
          return null;
        }
        delete map[key];
        await writeMap(map);
        return toCredential(entry);
      });
    },

    clear(tabId) {
      return serialise(async () => {
        const map = await readMap();
        if (map[String(tabId)]) {
          delete map[String(tabId)];
          await writeMap(map);
        }
      });
    },

    never(origin) {
      return serialise(async () => {
        const normalised = originOfUrl(origin);
        if (!normalised) {
          return;
        }
        const origins = await readNever();
        origins.add(normalised);
        await writeNever(origins);
      });
    },

    isNever(origin) {
      return serialise(async () => {
        const normalised = originOfUrl(origin);
        return normalised ? (await readNever()).has(normalised) : false;
      });
    },

    prune() {
      return serialise(async () => {
        const map = await readMap();
        if (dropExpired(map, now())) {
          await writeMap(map);
        }
      });
    },
  };
}
