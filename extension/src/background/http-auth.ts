/**
 * HTTP Basic/Digest authentication (WP5).
 *
 * Registers `webRequest.onAuthRequired` **synchronously** at service-worker top
 * level through {@link installHttpAuthListener} (called from `sw.ts`), then:
 *
 *  - looks credentials up with `get-logins` + `"httpAuth": "true"`;
 *  - answers a single match automatically (`httpAuthAutoFill` from the unified
 *    {@link ExtensionSettings}, default ON; WP6a);
 *  - shows a small extension picker for multiple matches unless the username
 *    last used for that origin is still among them;
 *  - retries at most once with the *next* candidate when the browser
 *    re-challenges the same `requestId` (wrong password loop guard);
 *  - never answers proxy auth (`isProxy`) automatically;
 *  - settles every callback exactly once with an 8 s hard deadline and answers
 *    `{cancel: false}` on any doubt, so Chrome shows its normal prompt and the
 *    page never hangs.
 *
 * Firefox is intentionally not implemented yet: `HttpAuthAdapter` isolates the
 * Chrome `asyncBlocking` registration so a `blocking`/Promise adapter can be
 * added without touching the controller.
 *
 * Never log credentials, entries or decrypted payloads.
 */

import type { CredentialEntry, ConnectionSnapshot } from "../common/types";
import type { ActionContext, GetLoginsArgs } from "./actions";

// ---------------------------------------------------------------------------
// Public constants / types
// ---------------------------------------------------------------------------

/** Hard deadline for one auth challenge; after this Chrome shows its prompt. */
export const HTTP_AUTH_DEADLINE_MS = 8_000;

/** Picker lifetime; always clamped to the remaining challenge budget. */
export const HTTP_AUTH_PICKER_TIMEOUT_MS = 6_000;

/** Kept for the loop guard after a request completes (diagnostics only). */
const HISTORY_TTL_MS = 30_000;

/** `chrome.storage.local` key holding non-secret HTTP-auth preferences. */
export const HTTP_AUTH_STORAGE_KEY = "friendlypass.httpAuth.v1";

/**
 * Marker set once the legacy `httpAuthAutoFill` flag has been copied into the
 * unified {@link ExtensionSettings} (WP6a). Never re-run after this is set.
 */
export const HTTP_AUTH_MIGRATION_KEY = "friendlypass.httpAuthAutoFill.migrated.v1";

/** Internal picker page channel (never used by content scripts). */
export const HTTP_AUTH_PICKER_CHANNEL = "friendlypass-http-auth";

export interface HttpAuthSettings {
  /** Fill a single match automatically. Default ON (the WP5 requirement). */
  httpAuthAutoFill: boolean;
  /** Origin (`scheme://host:port/`) → username last used there. */
  lastUsed: Record<string, string>;
  /** Entry UUID → realm the user approved it for (optional, local only). */
  realms: Record<string, string>;
}

export function defaultHttpAuthSettings(): HttpAuthSettings {
  return { httpAuthAutoFill: true, lastUsed: {}, realms: {} };
}

/** The subset of `chrome.webRequest.OnAuthRequiredDetails` we use. */
export interface HttpAuthChallengeDetails {
  requestId: string;
  url: string;
  realm?: string;
  scheme?: string;
  isProxy?: boolean;
  tabId?: number;
  challenger?: { host?: string; port?: number };
}

export interface HttpAuthCredentials {
  username: string;
  password: string;
}

export interface HttpAuthResponse {
  cancel?: boolean;
  authCredentials?: HttpAuthCredentials;
}

export type HttpAuthCallback = (response: HttpAuthResponse) => void;

/**
 * Small platform adapter. Chrome registers `asyncBlocking`; a future Firefox
 * adapter returns a Promise from a `blocking` listener instead.
 */
export interface HttpAuthAdapter {
  readonly kind: "chrome" | "firefox";
  install(
    listener: (details: HttpAuthChallengeDetails, callback: HttpAuthCallback) => void,
  ): void;
  onCompleted(listener: (details: { requestId: string }) => void): void;
  onErrorOccurred(listener: (details: { requestId: string }) => void): void;
}

export interface HttpAuthLookupRequest {
  /** Origin URL with a trailing slash, e.g. `https://host:8443/`. */
  url: string;
  origin: string;
  realm?: string;
  scheme: string;
  isProxy: boolean;
}

export type HttpAuthLookup = (
  request: HttpAuthLookupRequest,
) => Promise<CredentialEntry[]>;

/** Persistence for the non-secret preferences above. */
export interface HttpAuthSettingsStore {
  load(): Promise<HttpAuthSettings>;
  rememberLastUsed(origin: string, username: string): Promise<void>;
  rememberRealm(uuid: string, realm: string): Promise<void>;
  setAutoFill(value: boolean): Promise<void>;
}

/**
 * WP6a bridge: `httpAuthAutoFill` now lives in the unified
 * {@link ExtensionSettings} (`settings.get` / `settings.set`). The
 * service worker installs one before {@link installHttpAuthListener} runs.
 */
export interface HttpAuthSettingsBridge {
  getAutoFill(): Promise<boolean>;
  setAutoFill(value: boolean): Promise<void>;
}

let unifiedSettingsBridge: HttpAuthSettingsBridge | null = null;

/**
 * Route the `httpAuthAutoFill` flag through the unified settings.
 *
 * Called once at service-worker startup (WP6a). Pass `null` to fall back to the
 * legacy `chrome.storage.local` flag (unit tests, Firefox shim).
 */
export function setHttpAuthSettingsBridge(
  bridge: HttpAuthSettingsBridge | null,
): void {
  unifiedSettingsBridge = bridge;
}

/**
 * Settings store for the controller: `httpAuthAutoFill` is read from and
 * written to the unified settings, while the non-secret per-origin hints
 * (`lastUsed`, `realms`) stay in the legacy key, which they have always used.
 */
export function createUnifiedHttpAuthSettingsStore(
  bridge: HttpAuthSettingsBridge,
  legacy: HttpAuthSettingsStore | null,
): HttpAuthSettingsStore {
  const base = legacy ?? createMemoryHttpAuthSettingsStore();
  return {
    async load() {
      let settings: HttpAuthSettings;
      try {
        settings = sanitiseHttpAuthSettings(await base.load());
      } catch {
        settings = defaultHttpAuthSettings();
      }
      try {
        settings.httpAuthAutoFill = await bridge.getAutoFill();
      } catch {
        // Keep the legacy/default value when the unified store is unavailable.
      }
      return settings;
    },
    rememberLastUsed: (origin, username) => base.rememberLastUsed(origin, username),
    rememberRealm: (uuid, realm) => base.rememberRealm(uuid, realm),
    setAutoFill: (value) => bridge.setAutoFill(value),
  };
}

/** Minimal storage surface used by {@link migrateHttpAuthAutoFill}. */
export interface HttpAuthLegacyStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

/**
 * Copy the pre-WP6a `chrome.storage.local["friendlypass.httpAuth.v1"]
 * .httpAuthAutoFill` value into the unified settings once, then drop it from
 * the legacy record (its `lastUsed`/`realms` siblings stay).
 *
 * Returns `"migrated"` when a value was copied, `"none"` when there was nothing
 * to copy, and `"skipped"` when the migration marker was already set.
 */
export async function migrateHttpAuthAutoFill(options: {
  bridge: HttpAuthSettingsBridge;
  storage?: HttpAuthLegacyStorage | null;
  log?: (event: string, detail?: string) => void;
}): Promise<"migrated" | "none" | "skipped"> {
  const storage =
    options.storage ??
    (typeof chrome !== "undefined" && chrome.storage?.local
      ? {
          get: (key: string) => chromeStorageGet(key),
          set: (items: Record<string, unknown>) => chromeStorageSet(items),
        }
      : null);
  if (storage === null) {
    return "none";
  }

  const marker = await storage.get(HTTP_AUTH_MIGRATION_KEY);
  if (marker[HTTP_AUTH_MIGRATION_KEY] === true) {
    return "skipped";
  }

  const items = await storage.get(HTTP_AUTH_STORAGE_KEY);
  const legacy = items[HTTP_AUTH_STORAGE_KEY];
  const value =
    isRecord(legacy) && typeof legacy["httpAuthAutoFill"] === "boolean"
      ? legacy["httpAuthAutoFill"]
      : null;

  if (value === null) {
    await storage.set({ [HTTP_AUTH_MIGRATION_KEY]: true });
    return "none";
  }

  await options.bridge.setAutoFill(value);
  const rest: Record<string, unknown> = { ...(legacy as Record<string, unknown>) };
  delete rest["httpAuthAutoFill"];
  await storage.set({
    [HTTP_AUTH_STORAGE_KEY]: rest,
    [HTTP_AUTH_MIGRATION_KEY]: true,
  });
  options.log?.("http-auth", "migrated httpAuthAutoFill into unified settings");
  return "migrated";
}

export interface HttpAuthPickerRequest {
  token: string;
  origin: string;
  realm?: string;
  entries: CredentialEntry[];
  timeoutMs: number;
}

/** Resolves with the chosen entry UUID, or null for cancel/timeout. */
export interface HttpAuthPicker {
  show(request: HttpAuthPickerRequest): Promise<string | null>;
  /** Close any open picker for `token` (deadline/cancel). */
  cancel(token: string): void;
}

export interface HttpAuthDiagnostics {
  /** Challenges with an unanswered browser callback. */
  active: number;
  challenges: number;
  settled: number;
  autoFilled: number;
  pickers: number;
  fallbacks: number;
  lastReason: string | null;
  lastOrigin: string | null;
  lastSettledAt: number | null;
  /** Sanitised name/code of the last failed credential lookup. */
  lastLookupError: string | null;
}

/** Dependencies the service worker can provide without importing `sw.ts`. */
export interface HttpAuthBackgroundDependencies {
  logins: (ctx: ActionContext, args: GetLoginsArgs) => Promise<CredentialEntry[]>;
  snapshot: (triggerUnlock?: boolean) => Promise<ConnectionSnapshot>;
  context: (snapshot?: ConnectionSnapshot) => Promise<ActionContext>;
}

export interface HttpAuthControllerOptions {
  lookup: HttpAuthLookup;
  adapter?: HttpAuthAdapter | null;
  settings?: HttpAuthSettingsStore;
  picker?: HttpAuthPicker | null;
  deadlineMs?: number;
  pickerTimeoutMs?: number;
  now?: () => number;
  log?: (event: string, detail?: string) => void;
}

export interface InstallHttpAuthOptions
  extends Partial<HttpAuthBackgroundDependencies> {
  adapter?: HttpAuthAdapter | null;
  settings?: HttpAuthSettingsStore;
  picker?: HttpAuthPicker | null;
  lookup?: HttpAuthLookup;
  deadlineMs?: number;
  pickerTimeoutMs?: number;
  now?: () => number;
  log?: (event: string, detail?: string) => void;
}

export interface HttpAuthController {
  readonly adapterKind: string;
  install(): void;
  diagnostics(): HttpAuthDiagnostics;
  /** Settle everything and remove listeners/timers (tests and teardown). */
  shutdown(): void;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

type Timer = ReturnType<typeof setTimeout>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function candidateKey(entry: CredentialEntry): string {
  return entry.uuid || `${entry.login}\u0000${entry.name}`;
}

function isUsable(entry: CredentialEntry): boolean {
  if (!isRecord(entry)) return false;
  if (entry.expired === "true") return false;
  const login = typeof entry.login === "string" ? entry.login : "";
  const password = typeof entry.password === "string" ? entry.password : "";
  return login.length > 0 || password.length > 0;
}

function cloneSettings(settings: HttpAuthSettings): HttpAuthSettings {
  return {
    httpAuthAutoFill: settings.httpAuthAutoFill,
    lastUsed: { ...settings.lastUsed },
    realms: { ...settings.realms },
  };
}

export function sanitiseHttpAuthSettings(raw: unknown): HttpAuthSettings {
  const settings = defaultHttpAuthSettings();
  if (!isRecord(raw)) return settings;
  if (typeof raw["httpAuthAutoFill"] === "boolean") {
    settings.httpAuthAutoFill = raw["httpAuthAutoFill"];
  }
  if (isRecord(raw["lastUsed"])) {
    for (const [origin, username] of Object.entries(raw["lastUsed"])) {
      if (typeof username === "string" && username.length > 0) {
        settings.lastUsed[origin] = username;
      }
    }
  }
  if (isRecord(raw["realms"])) {
    for (const [uuid, realm] of Object.entries(raw["realms"])) {
      if (typeof realm === "string" && realm.length > 0) {
        settings.realms[uuid] = realm;
      }
    }
  }
  return settings;
}

function randomToken(): string {
  try {
    if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
      return crypto.randomUUID();
    }
  } catch {
    /* fall through */
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
}

function originOf(details: HttpAuthChallengeDetails): string | null {
  if (details.isProxy) {
    const host = details.challenger?.host;
    if (typeof host !== "string" || host.length === 0) return null;
    const port =
      typeof details.challenger?.port === "number" && details.challenger.port > 0
        ? `:${details.challenger.port}`
        : "";
    return `http://${host}${port}/`;
  }
  try {
    const url = new URL(details.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return `${url.protocol}//${url.host}/`;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// In-memory settings store (tests, and the fallback without chrome.storage)
// ---------------------------------------------------------------------------

export function createMemoryHttpAuthSettingsStore(
  initial: Partial<HttpAuthSettings> = {},
): HttpAuthSettingsStore {
  let settings = cloneSettings({ ...defaultHttpAuthSettings(), ...initial });
  return {
    async load() {
      return cloneSettings(settings);
    },
    async rememberLastUsed(origin, username) {
      settings.lastUsed[origin] = username;
    },
    async rememberRealm(uuid, realm) {
      settings.realms[uuid] = realm;
    },
    async setAutoFill(value) {
      settings.httpAuthAutoFill = value;
    },
  };
}

function chromeStorageGet(key: string): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(key, (items) => {
        // Reading `lastError` also consumes it so it cannot surface elsewhere.
        void chrome.runtime.lastError;
        resolve(isRecord(items) ? items : {});
      });
    } catch {
      resolve({});
    }
  });
}

function chromeStorageSet(items: Record<string, unknown>): Promise<void> {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.set(items, () => {
        void chrome.runtime.lastError;
        resolve();
      });
    } catch {
      resolve();
    }
  });
}

/**
 * `chrome.storage.local`-backed preferences. Writes are serialised so 20
 * simultaneous challenges cannot lose a last-used update.
 */
export function createChromeHttpAuthSettingsStore(): HttpAuthSettingsStore | null {
  if (typeof chrome === "undefined" || !chrome.storage?.local) {
    return null;
  }
  let writeChain: Promise<void> = Promise.resolve();

  async function read(): Promise<HttpAuthSettings> {
    const items = await chromeStorageGet(HTTP_AUTH_STORAGE_KEY);
    return sanitiseHttpAuthSettings(items[HTTP_AUTH_STORAGE_KEY]);
  }

  function update(mutate: (settings: HttpAuthSettings) => void): Promise<void> {
    writeChain = writeChain
      .then(async () => {
        const settings = await read();
        mutate(settings);
        await chromeStorageSet({ [HTTP_AUTH_STORAGE_KEY]: settings });
      })
      .catch(() => undefined);
    return writeChain;
  }

  return {
    load: read,
    rememberLastUsed: (origin, username) =>
      update((settings) => {
        settings.lastUsed[origin] = username;
      }),
    rememberRealm: (uuid, realm) =>
      update((settings) => {
        settings.realms[uuid] = realm;
      }),
    setAutoFill: (value) =>
      update((settings) => {
        settings.httpAuthAutoFill = value;
      }),
  };
}

// ---------------------------------------------------------------------------
// Chrome webRequest adapter
// ---------------------------------------------------------------------------

function fromChromeChallenge(
  details: chrome.webRequest.OnAuthRequiredDetails,
): HttpAuthChallengeDetails {
  const challenger = details.challenger;
  return {
    requestId: details.requestId,
    url: details.url,
    realm: details.realm,
    scheme: details.scheme,
    isProxy: details.isProxy === true,
    tabId: details.tabId,
    challenger: challenger
      ? { host: challenger.host, port: challenger.port }
      : undefined,
  };
}

/**
 * Chrome MV3 adapter: `asyncBlocking` requires `webRequest` +
 * `webRequestAuthProvider` (both already in the manifest).
 *
 * Returns null when the API is unavailable, so unit tests and non-extension
 * contexts can import this module safely.
 */
export function createChromeHttpAuthAdapter(): HttpAuthAdapter | null {
  if (
    typeof chrome === "undefined" ||
    !chrome.webRequest?.onAuthRequired?.addListener
  ) {
    return null;
  }
  const filter: chrome.webRequest.RequestFilter = { urls: ["<all_urls>"] };
  return {
    kind: "chrome",
    install(listener) {
      chrome.webRequest.onAuthRequired.addListener(
        (details, callback) => {
          listener(fromChromeChallenge(details), (response) => {
            try {
              callback?.(response as chrome.webRequest.BlockingResponse);
            } catch {
              // The request is already gone; the callback must still have been
              // consumed exactly once, so nothing else to do here.
            }
          });
          return undefined;
        },
        filter,
        ["asyncBlocking"],
      );
    },
    onCompleted(listener) {
      chrome.webRequest.onCompleted.addListener((details) => {
        listener({ requestId: details.requestId });
      }, filter);
    },
    onErrorOccurred(listener) {
      chrome.webRequest.onErrorOccurred.addListener((details) => {
        listener({ requestId: details.requestId });
      }, filter);
    },
  };
}

// ---------------------------------------------------------------------------
// Chrome extension-window picker
// ---------------------------------------------------------------------------

interface PickerPending {
  token: string;
  origin: string;
  realm?: string;
  entries: Array<{ uuid: string; login: string; name: string; group: string }>;
  resolve(uuid: string | null): void;
  settled: boolean;
  windowId: number | null;
  timer: Timer | null;
}

function safePickerEntries(
  entries: CredentialEntry[],
): Array<{ uuid: string; login: string; name: string; group: string }> {
  // Passwords never leave the service worker: the picker only needs labels.
  return entries.map((entry) => ({
    uuid: entry.uuid,
    login: entry.login,
    name: entry.name,
    group: entry.group,
  }));
}

/**
 * Opens `auth/picker.html` in a small popup window and waits for a choice.
 * The picker is strictly best-effort: if a window cannot be created (headless,
 * policy), it resolves `null`, which makes the caller fall back to Chrome.
 */
export function createChromeHttpAuthPicker(): HttpAuthPicker | null {
  if (
    typeof chrome === "undefined" ||
    !chrome.windows?.create ||
    !chrome.runtime?.onMessage
  ) {
    return null;
  }

  const pending = new Map<string, PickerPending>();
  let installed = false;

  function closeWindow(p: PickerPending): void {
    if (p.windowId === null) return;
    const windowId = p.windowId;
    p.windowId = null;
    try {
      chrome.windows.remove(windowId, () => void chrome.runtime.lastError);
    } catch {
      /* already gone */
    }
  }

  function finish(p: PickerPending, uuid: string | null): void {
    if (p.settled) return;
    p.settled = true;
    if (p.timer !== null) {
      clearTimeout(p.timer);
      p.timer = null;
    }
    pending.delete(p.token);
    closeWindow(p);
    p.resolve(uuid);
  }

  function ensureInstalled(): void {
    if (installed) return;
    installed = true;
    try {
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        const record = message as Record<string, unknown> | null;
        if (
          !isRecord(record) ||
          record["channel"] !== HTTP_AUTH_PICKER_CHANNEL ||
          typeof record["token"] !== "string"
        ) {
          return false;
        }
        const token = record["token"];
        const p = pending.get(token);
        if (!p) {
          sendResponse({ ok: false, error: "unknown picker request" });
          return false;
        }
        const pickerUrl =
          typeof chrome.runtime.getURL === "function"
            ? chrome.runtime.getURL("auth/picker.html")
            : null;
        if (pickerUrl && sender.url && !sender.url.startsWith(pickerUrl)) {
          sendResponse({ ok: false, error: "unexpected picker sender" });
          return false;
        }
        const action = record["action"];
        if (action === "list") {
          sendResponse({
            ok: true,
            value: {
              origin: p.origin,
              realm: p.realm ?? null,
              entries: p.entries,
            },
          });
          return false;
        }
        if (action === "choose") {
          const uuid = typeof record["uuid"] === "string" ? record["uuid"] : "";
          const known = p.entries.some((entry) => entry.uuid === uuid);
          sendResponse({ ok: true, value: null });
          finish(p, known ? uuid : null);
          return false;
        }
        if (action === "cancel") {
          sendResponse({ ok: true, value: null });
          finish(p, null);
          return false;
        }
        sendResponse({ ok: false, error: "unknown picker action" });
        return false;
      });
      chrome.windows.onRemoved.addListener((windowId) => {
        for (const p of [...pending.values()]) {
          if (p.windowId === windowId) {
            finish(p, null);
          }
        }
      });
    } catch {
      // Without a message channel the picker cannot work; `show` then resolves
      // null immediately (Chrome's own prompt is the fallback).
    }
  }

  return {
    async show(request) {
      ensureInstalled();
      const token = request.token;
      return await new Promise<string | null>((resolve) => {
        const p: PickerPending = {
          token,
          origin: request.origin,
          realm: request.realm,
          entries: safePickerEntries(request.entries),
          resolve,
          settled: false,
          windowId: null,
          timer: null,
        };
        pending.set(token, p);
        p.timer = setTimeout(
          () => finish(p, null),
          Math.max(1, request.timeoutMs),
        );
        try {
          const url = `${chrome.runtime.getURL("auth/picker.html")}?token=${encodeURIComponent(token)}`;
          chrome.windows.create(
            {
              url,
              type: "popup",
              width: 420,
              height: 480,
              focused: true,
            },
            (window) => {
              const lastError = chrome.runtime.lastError;
              if (lastError) {
                finish(p, null);
                return;
              }
              p.windowId =
                typeof window?.id === "number" ? window.id : null;
            },
          );
        } catch {
          finish(p, null);
        }
      });
    },
    cancel(token) {
      const p = pending.get(token);
      if (p) finish(p, null);
    },
  };
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

interface ChallengeHistory {
  requestId: string;
  origin: string;
  candidates: CredentialEntry[];
  tried: Set<string>;
  retries: number;
  challenges: number;
  deadlineAt: number;
  cleanupTimer: Timer | null;
}

interface ActivePending {
  requestId: string;
  pickerToken: string | null;
  settled: boolean;
  deadlineTimer: Timer | null;
  callback: HttpAuthCallback;
}

export function createHttpAuthController(
  options: HttpAuthControllerOptions,
): HttpAuthController {
  const deadlineMs = options.deadlineMs ?? HTTP_AUTH_DEADLINE_MS;
  const pickerTimeoutMs =
    options.pickerTimeoutMs ?? HTTP_AUTH_PICKER_TIMEOUT_MS;
  const now = options.now ?? (() => Date.now());
  const log = options.log ?? (() => undefined);
  const settingsStore =
    options.settings ?? createMemoryHttpAuthSettingsStore();
  const adapter = options.adapter ?? null;
  const picker = options.picker ?? null;

  const histories = new Map<string, ChallengeHistory>();
  const active = new Set<ActivePending>();
  const diagnostics: HttpAuthDiagnostics = {
    active: 0,
    challenges: 0,
    settled: 0,
    autoFilled: 0,
    pickers: 0,
    fallbacks: 0,
    lastReason: null,
    lastOrigin: null,
    lastSettledAt: null,
    lastLookupError: null,
  };

  let installed = false;
  let shutdownRequested = false;
  const cleanups: Array<() => void> = [];

  function updateActive(): void {
    diagnostics.active = active.size;
  }

  function remember(origin: string, username: string): void {
    // Only the last-used username is recorded automatically. The wire protocol
    // has no `realm` field (ACTIONS.md §5.5), so a realm can only be approved
    // explicitly (picker/future options UI); auto-filling must not pin an entry
    // to one realm and hide it from another.
    void settingsStore.rememberLastUsed(origin, username).catch(() => undefined);
  }

  function clearHistoryTimer(history: ChallengeHistory): void {
    if (history.cleanupTimer !== null) {
      clearTimeout(history.cleanupTimer);
      history.cleanupTimer = null;
    }
  }

  function scheduleHistoryCleanup(history: ChallengeHistory): void {
    clearHistoryTimer(history);
    history.cleanupTimer = setTimeout(() => {
      histories.delete(history.requestId);
    }, HISTORY_TTL_MS);
  }

  function dropHistory(requestId: string): void {
    const history = histories.get(requestId);
    if (history) {
      clearHistoryTimer(history);
      histories.delete(requestId);
    }
  }

  function finishPending(
    pending: ActivePending,
    response: HttpAuthResponse,
    reason: string,
    origin: string | null,
  ): void {
    if (pending.settled) return;
    pending.settled = true;
    if (pending.deadlineTimer !== null) {
      clearTimeout(pending.deadlineTimer);
      pending.deadlineTimer = null;
    }
    active.delete(pending);
    updateActive();
    diagnostics.settled += 1;
    diagnostics.lastReason = reason;
    diagnostics.lastOrigin = origin;
    diagnostics.lastSettledAt = now();
    if (response.cancel === false && !response.authCredentials) {
      diagnostics.fallbacks += 1;
    }
    pending.callback(response);
  }

  function makePending(
    requestId: string,
    callback: HttpAuthCallback,
    remainingMs: number,
  ): ActivePending {
    const pending: ActivePending = {
      requestId,
      pickerToken: null,
      settled: false,
      deadlineTimer: null,
      callback: (response: HttpAuthResponse) => {
        try {
          callback(response);
        } catch {
          // Chrome already discarded the request; it can only be answered once.
        }
      },
    };
    pending.deadlineTimer = setTimeout(() => {
      if (pending.settled) return;
      const token = pending.pickerToken;
      if (token !== null && picker) {
        try {
          picker.cancel(token);
        } catch {
          /* ignore */
        }
      }
      finishPending(pending, { cancel: false }, "deadline", null);
    }, Math.max(1, remainingMs));
    active.add(pending);
    updateActive();
    return pending;
  }

  function pickCandidate(
    candidates: CredentialEntry[],
    tried: Set<string>,
  ): CredentialEntry | null {
    for (const candidate of candidates) {
      if (!tried.has(candidateKey(candidate))) return candidate;
    }
    return null;
  }

  async function openPicker(
    pending: ActivePending,
    history: ChallengeHistory,
    origin: string,
    realm: string | undefined,
    candidateList: CredentialEntry[],
    remainingMs: number,
  ): Promise<void> {
    if (!picker) {
      finishPending(pending, { cancel: false }, "picker-unavailable", origin);
      return;
    }
    const token = randomToken();
    pending.pickerToken = token;
    diagnostics.pickers += 1;
    const budget = Math.max(1, Math.min(pickerTimeoutMs, remainingMs));
    let choice: string | null = null;
    try {
      choice = await picker.show({
        token,
        origin,
        realm,
        // A picker only needs labels. Blank the password here so no custom
        // picker implementation can receive a credential by accident.
        entries: candidateList.map((candidate) => ({
          ...candidate,
          password: "",
        })),
        timeoutMs: budget,
      });
    } catch {
      choice = null;
    }
    if (pending.settled) return;
    pending.pickerToken = null;
    if (choice === null) {
      finishPending(pending, { cancel: false }, "picker-cancelled", origin);
      return;
    }
    const chosen = candidateList.find(
      (candidate) =>
        candidate.uuid === choice ||
        candidateKey(candidate) === choice ||
        candidate.login === choice,
    );
    if (!chosen) {
      finishPending(pending, { cancel: false }, "picker-unknown", origin);
      return;
    }
    useCandidate(pending, history, origin, chosen, "picker");
  }

  function useCandidate(
    pending: ActivePending,
    history: ChallengeHistory,
    origin: string,
    entry: CredentialEntry,
    reason: string,
  ): void {
    history.tried.add(candidateKey(entry));
    remember(origin, entry.login);
    diagnostics.autoFilled += 1;
    finishPending(
      pending,
      {
        authCredentials: {
          username: entry.login,
          password: entry.password,
        },
      },
      reason,
      origin,
    );
  }

  async function firstChallenge(
    pending: ActivePending,
    details: HttpAuthChallengeDetails,
    origin: string,
    scheme: string,
    remainingMs: number,
  ): Promise<void> {
    const history: ChallengeHistory = {
      requestId: details.requestId,
      origin,
      candidates: [],
      tried: new Set<string>(),
      retries: 0,
      challenges: 1,
      deadlineAt: now() + deadlineMs,
      cleanupTimer: null,
    };
    histories.set(details.requestId, history);
    scheduleHistoryCleanup(history);

    let settings = defaultHttpAuthSettings();
    let entries: CredentialEntry[] = [];
    try {
      const [settingsResult, entriesResult] = await Promise.allSettled([
        settingsStore.load(),
        options.lookup({
          url: origin,
          origin,
          realm: details.realm,
          scheme,
          isProxy: details.isProxy === true,
        }),
      ]);
      if (settingsResult.status === "fulfilled") {
        settings = sanitiseHttpAuthSettings(settingsResult.value);
      }
      if (entriesResult.status === "fulfilled") {
        entries = Array.isArray(entriesResult.value)
          ? entriesResult.value
          : [];
      } else {
        const reason = entriesResult.reason as
          | { name?: unknown; code?: unknown; message?: unknown }
          | undefined;
        diagnostics.lastLookupError =
          typeof reason?.name === "string"
            ? `${reason.name}${typeof reason.code === "number" ? ` (${reason.code})` : ""}`
            : "lookup failed";
        log("http-auth", "credential lookup failed");
      }
    } catch {
      entries = [];
    }
    if (pending.settled) return;

    const seen = new Set<string>();
    const candidates = entries.filter((entry) => {
      if (!isUsable(entry)) return false;
      const storedRealm = entry.uuid ? settings.realms[entry.uuid] : undefined;
      if (
        storedRealm !== undefined &&
        details.realm !== undefined &&
        storedRealm !== details.realm
      ) {
        return false;
      }
      const key = candidateKey(entry);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    history.candidates = candidates;

    if (candidates.length === 0) {
      finishPending(pending, { cancel: false }, "no-match", origin);
      return;
    }

    if (!settings.httpAuthAutoFill) {
      await openPicker(
        pending,
        history,
        origin,
        details.realm,
        candidates,
        remainingMs,
      );
      return;
    }

    if (candidates.length === 1) {
      useCandidate(pending, history, origin, candidates[0], "single");
      return;
    }

    const lastUsed = settings.lastUsed[origin];
    const preferred =
      lastUsed === undefined
        ? undefined
        : candidates.find((candidate) => candidate.login === lastUsed);
    if (preferred) {
      useCandidate(pending, history, origin, preferred, "last-used");
      return;
    }

    await openPicker(
      pending,
      history,
      origin,
      details.realm,
      candidates,
      remainingMs,
    );
  }

  function repeatedChallenge(
    pending: ActivePending,
    history: ChallengeHistory,
  ): void {
    history.challenges += 1;
    scheduleHistoryCleanup(history);

    if (history.retries >= 1) {
      finishPending(pending, { cancel: false }, "retry-exhausted", history.origin);
      return;
    }
    if (history.tried.size === 0) {
      // The previous answer did not use a credential (picker/no match), so a
      // second challenge must not start guessing.
      finishPending(pending, { cancel: false }, "no-credentials-used", history.origin);
      return;
    }
    const next = pickCandidate(history.candidates, history.tried);
    if (!next) {
      finishPending(pending, { cancel: false }, "no-next-candidate", history.origin);
      return;
    }
    history.retries += 1;
    useCandidate(pending, history, history.origin, next, "retry");
  }

  function onChallenge(
    details: HttpAuthChallengeDetails,
    callback: HttpAuthCallback,
  ): void {
    if (shutdownRequested) {
      try {
        callback({ cancel: false });
      } catch {
        /* request already gone */
      }
      return;
    }
    diagnostics.challenges += 1;

    const requestId =
      typeof details.requestId === "string" ? details.requestId : "";
    if (requestId.length === 0) {
      try {
        callback({ cancel: false });
      } catch {
        /* ignore */
      }
      return;
    }

    // Proxy auth is never answered automatically (ACTIONS.md §5.5).
    if (details.isProxy === true) {
      try {
        callback({ cancel: false });
      } catch {
        /* ignore */
      }
      diagnostics.fallbacks += 1;
      diagnostics.lastReason = "proxy";
      return;
    }

    const scheme = (details.scheme ?? "").toLowerCase();
    if (scheme !== "basic" && scheme !== "digest") {
      try {
        callback({ cancel: false });
      } catch {
        /* ignore */
      }
      diagnostics.fallbacks += 1;
      diagnostics.lastReason = "unsupported-scheme";
      return;
    }

    const origin = originOf(details);
    if (origin === null) {
      try {
        callback({ cancel: false });
      } catch {
        /* ignore */
      }
      diagnostics.fallbacks += 1;
      diagnostics.lastReason = "unsupported-origin";
      return;
    }

    const existing = histories.get(requestId);
    const deadlineAt = existing?.deadlineAt ?? now() + deadlineMs;
    const remainingMs = Math.max(1, deadlineAt - now());

    const pending = makePending(requestId, callback, remainingMs);
    if (existing) {
      // Keep the original deadline across retries.
      existing.deadlineAt = deadlineAt;
    }

    if (remainingMs <= 1) {
      // The challenge arrived after the hard deadline; never start a new
      // lookup or retry, just let Chrome show its own prompt.
      finishPending(pending, { cancel: false }, "deadline", origin);
      return;
    }

    if (existing) {
      repeatedChallenge(pending, existing);
      return;
    }

    void firstChallenge(pending, details, origin, scheme, remainingMs).catch(
      () => {
        finishPending(pending, { cancel: false }, "lookup-error", origin);
      },
    );
  }

  function cleanupRequest(requestId: string): void {
    dropHistory(requestId);
    for (const pending of [...active]) {
      if (pending.requestId === requestId) {
        const token = pending.pickerToken;
        if (token !== null && picker) {
          try {
            picker.cancel(token);
          } catch {
            /* ignore */
          }
        }
        finishPending(pending, { cancel: false }, "request-completed", null);
      }
    }
  }

  return {
    get adapterKind() {
      return adapter?.kind ?? "none";
    },

    install() {
      if (installed) return;
      if (!adapter) {
        log("http-auth", "webRequest API unavailable; listener not installed");
        return;
      }
      installed = true;
      adapter.install((details, callback) => onChallenge(details, callback));
      adapter.onCompleted((details) => cleanupRequest(details.requestId));
      adapter.onErrorOccurred((details) => cleanupRequest(details.requestId));
      cleanups.push(() => {
        // Chrome has no removeListener hook in our adapter surface; tearing
        // down the controller settles everything so no callback can hang.
      });
    },

    diagnostics() {
      return { ...diagnostics };
    },

    shutdown() {
      shutdownRequested = true;
      for (const cleanup of cleanups.splice(0)) {
        try {
          cleanup();
        } catch {
          /* ignore */
        }
      }
      for (const requestId of [...histories.keys()]) {
        cleanupRequest(requestId);
      }
      for (const pending of [...active]) {
        finishPending(pending, { cancel: false }, "shutdown", null);
      }
      histories.clear();
      updateActive();
    },
  };
}

// ---------------------------------------------------------------------------
// Service-worker entry point
// ---------------------------------------------------------------------------

let defaultController: HttpAuthController | null = null;

function lookupFromBackground(
  deps: HttpAuthBackgroundDependencies,
): HttpAuthLookup {
  return async (request) => {
    const snapshot = await deps.snapshot();
    const context = await deps.context(snapshot);
    const entries = await deps.logins(context, {
      url: request.url,
      httpAuth: true,
    });
    return Array.isArray(entries) ? entries : [];
  };
}

/**
 * Register `onAuthRequired` synchronously. Must be called at service-worker
 * top level (it is, from `sw.ts`), before the first navigation can produce a
 * 401.
 */
export function installHttpAuthListener(
  options: InstallHttpAuthOptions = {},
): void {
  if (defaultController !== null) {
    return;
  }
  const adapter =
    options.adapter === undefined
      ? createChromeHttpAuthAdapter()
      : options.adapter;
  const picker =
    options.picker === undefined ? createChromeHttpAuthPicker() : options.picker;
  const legacySettings = createChromeHttpAuthSettingsStore();
  const settings =
    options.settings ??
    (unifiedSettingsBridge
      ? createUnifiedHttpAuthSettingsStore(unifiedSettingsBridge, legacySettings)
      : legacySettings ?? createMemoryHttpAuthSettingsStore());

  let lookup = options.lookup;
  if (!lookup) {
    if (options.logins && options.snapshot && options.context) {
      lookup = lookupFromBackground({
        logins: options.logins,
        snapshot: options.snapshot,
        context: options.context,
      });
    } else {
      // No way to reach the database; the controller will always fall back.
      lookup = async () => [];
    }
  }

  defaultController = createHttpAuthController({
    lookup,
    adapter,
    picker,
    settings,
    deadlineMs: options.deadlineMs,
    pickerTimeoutMs: options.pickerTimeoutMs,
    now: options.now,
    log: options.log,
  });
  defaultController.install();

  // Test/diagnostics bridge, reachable from the service-worker context only
  // (Playwright `worker.evaluate`, DevTools). It never exposes credentials.
  try {
    (globalThis as unknown as { __friendlypassHttpAuth?: HttpAuthController })
      .__friendlypassHttpAuth = defaultController;
  } catch {
    /* ignore */
  }
}
