/**
 * Persisted extension state and observable connection state (WP3).
 *
 * Split of storage areas:
 *  - `chrome.storage.local`: keyring (survives browser restarts), settings,
 *    stable client id. Nothing here is a secret: the keyring stores the
 *    identification *public* key only, exactly as `protocol/ACTIONS.md` §2.4
 *    specifies.
 *  - in-memory (rebuilt on service-worker restart): connection snapshot,
 *    server session public key, pending requests. `session.ts` rebuilds the
 *    latter with a fresh handshake; the snapshot starts DISCONNECTED.
 *
 * `createStateStore()` never touches `chrome` at module scope, so unit tests
 * (Node/vitest) and the service worker share the same implementation. Pass a
 * `storage` area to inject an in-memory or mock backend.
 *
 * Event emitter: popup, options and content scripts subscribe with
 * `store.subscribe()`. The service worker can additionally forward events with
 * `broadcast`, which defaults to `sendBackgroundEvent()` when `chrome.runtime`
 * exists. At most one event is emitted per state change; listeners must be
 * cheap.
 */

import { sendBackgroundEvent } from "../common/messages";
import {
  SUPPORTED_PROTOCOL_VERSION,
  type AssociationRecord,
  type ConnectionSnapshot,
  type DbHash,
  type DiagnosticEntry,
  type DiagnosticsSnapshot,
  type ExtensionSettings,
  type HostStatus,
  type PersistedState,
  type SiteException,
  type StatusSummary,
} from "../common/types";

/**
 * Unified settings defaults (WP6a). This object is frozen; callers always get
 * a deep copy (the `siteExceptions` array is cloned) so no consumer can mutate
 * the defaults.
 */
export const DEFAULT_SETTINGS: Readonly<ExtensionSettings> = Object.freeze({
  autoFillSingleEntry: false,
  showFieldIcons: true,
  httpAuthAutoFill: true,
  autoFillAndSubmit: false,
  launchAppOnConnect: false,
  defaultGroup: "",
  defaultGroupAlwaysAsk: false,
  debugLogging: false,
  siteExceptions: Object.freeze([]) as unknown as SiteException[],
});

/** Boolean settings, in the order the options page groups them. */
const BOOLEAN_SETTINGS = [
  "autoFillSingleEntry",
  "showFieldIcons",
  "httpAuthAutoFill",
  "autoFillAndSubmit",
  "launchAppOnConnect",
  "defaultGroupAlwaysAsk",
  "debugLogging",
] as const;

/** Upper bound on the number of stored site exceptions. */
export const MAX_SITE_EXCEPTIONS = 500;

/** Upper bound on `defaultGroup` (a group path, not a document). */
export const MAX_DEFAULT_GROUP_LENGTH = 256;

/** A fresh, mutable copy of the defaults. */
export function defaultSettings(): ExtensionSettings {
  return { ...DEFAULT_SETTINGS, siteExceptions: [] };
}

/** Deep copy; `siteExceptions` entries are plain records. */
export function cloneSettings(settings: ExtensionSettings): ExtensionSettings {
  return {
    ...settings,
    siteExceptions: settings.siteExceptions.map((entry) => ({ ...entry })),
  };
}

/**
 * Normalise a user-supplied origin to `scheme://host[:port]`.
 *
 * `example.com` and `https://example.com/login` both become
 * `https://example.com` (a bare host defaults to HTTPS). Returns null for
 * anything that is not a plausible http(s) origin.
 */
export function normaliseOrigin(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const text = value.trim();
  // An origin never contains whitespace; Chrome's URL parser would otherwise
  // silently percent-encode it ("https://not a url!").
  if (text.length === 0 || text.length > 2048 || /\s/.test(text)) {
    return null;
  }
  try {
    const url = new URL(text.includes("://") ? text : `https://${text}`);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    if (url.hostname.length === 0 || /\s/.test(url.hostname)) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

function sanitiseSiteExceptions(value: unknown): SiteException[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const out: SiteException[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (out.length >= MAX_SITE_EXCEPTIONS) {
      break;
    }
    if (!isRecord(raw)) {
      continue;
    }
    const origin = normaliseOrigin(raw["origin"]);
    if (origin === null || seen.has(origin)) {
      continue;
    }
    seen.add(origin);
    const entry: SiteException = { origin };
    if (typeof raw["disableFill"] === "boolean") {
      entry.disableFill = raw["disableFill"];
    }
    if (typeof raw["disableSave"] === "boolean") {
      entry.disableSave = raw["disableSave"];
    }
    if (typeof raw["disableIcons"] === "boolean") {
      entry.disableIcons = raw["disableIcons"];
    }
    out.push(entry);
  }
  return out;
}

/** `chrome.storage.local` key holding the persisted {@link PersistedState}. */
export const STORAGE_KEY = "friendlypass.state.v1";

const MAX_DIAGNOSTICS = 200;

/** Minimal promise-based storage surface (a subset of `chrome.storage.StorageArea`). */
export interface StorageAreaLike {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export interface StateStoreOptions {
  /** Defaults to `chrome.storage.local`, or an in-memory area when absent. */
  storage?: StorageAreaLike;
  now?: () => number;
  maxDiagnostics?: number;
  /** Called after every emitted status; defaults to `sendBackgroundEvent`. */
  broadcast?: (status: StatusSummary) => void;
  /** Called after every settings change; defaults to `sendBackgroundEvent`. */
  broadcastSettings?: (settings: ExtensionSettings) => void;
}

export type StateListener = (
  status: StatusSummary,
  snapshot: ConnectionSnapshot,
) => void;

export type SettingsListener = (settings: ExtensionSettings) => void;

export interface StateStore {
  load(): Promise<PersistedState>;
  save(partial: Partial<PersistedState>): Promise<PersistedState>;
  getSettings(): Promise<ExtensionSettings>;
  setSettings(partial: Partial<ExtensionSettings>): Promise<ExtensionSettings>;
  /** Subscribe to settings changes; returns an unsubscribe function. */
  subscribeSettings(listener: SettingsListener): () => void;
  keyRing(): Promise<Record<DbHash, AssociationRecord>>;
  putAssociation(hash: DbHash, record: AssociationRecord): Promise<void>;
  deleteAssociation(hash: DbHash): Promise<void>;
  touchAssociation(hash: DbHash, at?: number): Promise<void>;
  getClientId(): Promise<string | null>;
  setClientId(clientId: string): Promise<void>;
  snapshot(): ConnectionSnapshot;
  setSnapshot(snapshot: ConnectionSnapshot): void;
  updateSnapshot(patch: Partial<ConnectionSnapshot>): ConnectionSnapshot;
  status(): StatusSummary;
  diagnostics(): DiagnosticsSnapshot;
  log(entry: Omit<DiagnosticEntry, "at">): void;
  /** Subscribe to state events; returns an unsubscribe function. */
  subscribe(listener: StateListener): () => void;
}

export function initialSnapshot(): ConnectionSnapshot {
  return {
    state: "DISCONNECTED",
    appRunning: false,
    databaseOpen: false,
    locked: false,
    associated: false,
    databaseHash: null,
    hostVersion: null,
    appVersion: null,
    protocolVersion: SUPPORTED_PROTOCOL_VERSION,
    attempt: 0,
    lastError: null,
  };
}

function emptyPersistedState(): PersistedState {
  return {
    clientId: null,
    keyRing: {},
    settings: defaultSettings(),
  };
}

/** In-memory storage used by tests and as the fallback without `chrome.storage`. */
export class MemoryStorageArea implements StorageAreaLike {
  private readonly data = new Map<string, unknown>();

  async get(key: string): Promise<Record<string, unknown>> {
    return this.data.has(key) ? { [key]: this.data.get(key) } : {};
  }

  async set(items: Record<string, unknown>): Promise<void> {
    for (const [key, value] of Object.entries(items)) {
      // Structured clone keeps the same isolation semantics as chrome.storage.
      this.data.set(key, structuredCloneSafe(value));
    }
  }
}

function structuredCloneSafe<T>(value: T): T {
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value)) as T;
}

function chromeLocalStorage(): StorageAreaLike | null {
  if (typeof chrome === "undefined" || !chrome.storage?.local) {
    return null;
  }
  const area = chrome.storage.local;
  return {
    get: (key) => area.get(key),
    set: (items) => area.set(items),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * Validate an arbitrary value into {@link ExtensionSettings}.
 *
 * Rules (WP6a):
 *  - unknown keys are dropped; wrong types fall back to the default;
 *  - `autoFillHttpAuth` (the pre-WP6a field) is migrated to `httpAuthAutoFill`
 *    once, and only when the new field is absent;
 *  - site exceptions are normalised to a bare origin, de-duplicated, and
 *    capped at {@link MAX_SITE_EXCEPTIONS}.
 *
 * Exported for the unit suite; the state store is the only production caller.
 */
export function sanitiseSettings(value: unknown): ExtensionSettings {
  const settings = defaultSettings();
  if (!isRecord(value)) {
    return settings;
  }
  for (const key of BOOLEAN_SETTINGS) {
    if (typeof value[key] === "boolean") {
      settings[key] = value[key] as boolean;
    }
  }
  // Legacy migration: the extension previously stored `autoFillHttpAuth`
  // (default false) outside the unified record. Prefer an explicit new value.
  if (
    typeof value["httpAuthAutoFill"] !== "boolean" &&
    typeof value["autoFillHttpAuth"] === "boolean"
  ) {
    settings.httpAuthAutoFill = value["autoFillHttpAuth"];
  }
  if (typeof value["defaultGroup"] === "string") {
    settings.defaultGroup = value["defaultGroup"]
      .replace(/[\u0000-\u001f\u007f]/g, "")
      .trim()
      .slice(0, MAX_DEFAULT_GROUP_LENGTH);
  }
  settings.siteExceptions = sanitiseSiteExceptions(value["siteExceptions"]);
  return settings;
}

/**
 * Keep only the keys of `partial` that have an acceptable type, so a bad write
 * can never silently reset an unrelated valid setting.
 */
function validSettingsPatch(partial: Partial<ExtensionSettings>): Partial<ExtensionSettings> {
  const out: Partial<ExtensionSettings> = {};
  if (!isRecord(partial)) {
    return out;
  }
  for (const key of BOOLEAN_SETTINGS) {
    if (typeof partial[key] === "boolean") {
      out[key] = partial[key] as boolean;
    }
  }
  if (typeof partial.defaultGroup === "string") {
    out.defaultGroup = partial.defaultGroup;
  }
  if (Array.isArray(partial.siteExceptions)) {
    out.siteExceptions = partial.siteExceptions;
  }
  return out;
}

function sanitiseAssociation(value: unknown): AssociationRecord | null {
  if (!isRecord(value)) {
    return null;
  }
  const id = asString(value["id"]);
  const key = asString(value["key"]);
  const hash = asString(value["hash"]);
  if (!id || !key || !hash) {
    return null;
  }
  const created =
    typeof value["created"] === "number" && Number.isFinite(value["created"])
      ? value["created"]
      : 0;
  const lastUsed =
    typeof value["lastUsed"] === "number" && Number.isFinite(value["lastUsed"])
      ? value["lastUsed"]
      : created;
  return { id, key, hash, created, lastUsed };
}

function sanitisePersisted(value: unknown): PersistedState {
  const state = emptyPersistedState();
  if (!isRecord(value)) {
    return state;
  }
  state.clientId = asString(value["clientId"]);
  state.settings = sanitiseSettings(value["settings"]);
  if (isRecord(value["keyRing"])) {
    for (const [hash, raw] of Object.entries(value["keyRing"])) {
      const record = sanitiseAssociation(raw);
      if (record && record.hash === hash) {
        state.keyRing[hash] = record;
      }
    }
  }
  return state;
}

function statusFromSnapshot(snapshot: ConnectionSnapshot): StatusSummary {
  return {
    connected:
      snapshot.state === "HANDSHAKING" ||
      snapshot.state === "READY" ||
      snapshot.state === "LOCKED",
    appRunning: snapshot.appRunning,
    databaseOpen: snapshot.databaseOpen,
    locked: snapshot.locked,
    associated: snapshot.associated,
    databaseHash: snapshot.databaseHash,
    state: snapshot.state,
    hostVersion: snapshot.hostVersion,
    appVersion: snapshot.appVersion,
    protocolVersion: snapshot.protocolVersion,
    error: snapshot.lastError,
  };
}

function sameSnapshot(a: ConnectionSnapshot, b: ConnectionSnapshot): boolean {
  return (
    a.state === b.state &&
    a.appRunning === b.appRunning &&
    a.databaseOpen === b.databaseOpen &&
    a.locked === b.locked &&
    a.associated === b.associated &&
    a.databaseHash === b.databaseHash &&
    a.hostVersion === b.hostVersion &&
    a.appVersion === b.appVersion &&
    a.protocolVersion === b.protocolVersion &&
    a.attempt === b.attempt &&
    a.lastError?.code === b.lastError?.code &&
    a.lastError?.message === b.lastError?.message
  );
}

export function createStateStore(options: StateStoreOptions = {}): StateStore {
  const storage = options.storage ?? chromeLocalStorage() ?? new MemoryStorageArea();
  const now = options.now ?? (() => Date.now());
  const maxDiagnostics = options.maxDiagnostics ?? MAX_DIAGNOSTICS;
  const broadcast =
    options.broadcast ??
    ((status: StatusSummary) => sendBackgroundEvent("status.changed", status));
  const broadcastSettings =
    options.broadcastSettings ??
    ((settings: ExtensionSettings) =>
      sendBackgroundEvent("settings.changed", settings));

  let cached: PersistedState | null = null;
  let loading: Promise<PersistedState> | null = null;
  let snapshot = initialSnapshot();
  let reconnects = 0;
  const listeners = new Set<StateListener>();
  const settingsListeners = new Set<SettingsListener>();
  const diagnostics: DiagnosticEntry[] = [];

  async function load(): Promise<PersistedState> {
    if (cached) {
      return cached;
    }
    if (loading) {
      return loading;
    }
    loading = (async () => {
      let raw: Record<string, unknown> = {};
      try {
        raw = await storage.get(STORAGE_KEY);
      } catch {
        // A storage read failure must not stop the service worker. Start from
        // defaults; the next successful write repairs the record.
        raw = {};
      }
      cached = sanitisePersisted(raw[STORAGE_KEY]);
      return cached;
    })().finally(() => {
      loading = null;
    });
    return loading;
  }

  async function persist(next: PersistedState): Promise<void> {
    cached = next;
    await storage.set({ [STORAGE_KEY]: next });
  }

  async function save(partial: Partial<PersistedState>): Promise<PersistedState> {
    const current = await load();
    const next: PersistedState = {
      clientId:
        partial.clientId !== undefined ? partial.clientId : current.clientId,
      keyRing:
        partial.keyRing !== undefined
          ? sanitisePersisted({ keyRing: partial.keyRing }).keyRing
          : current.keyRing,
      settings:
        partial.settings !== undefined
          ? sanitiseSettings(partial.settings)
          : current.settings,
    };
    await persist(next);
    return next;
  }

  function emit(): void {
    const status = statusFromSnapshot(snapshot);
    for (const listener of [...listeners]) {
      try {
        listener(status, { ...snapshot });
      } catch {
        // A broken listener must not break the state machine.
      }
    }
    try {
      broadcast(status);
    } catch {
      // Broadcast is best-effort (no popup/content context may be alive).
    }
  }

  return {
    load,
    save,

    async getSettings() {
      return cloneSettings((await load()).settings);
    },

    async setSettings(partial) {
      const current = await load();
      const next = await save({
        settings: sanitiseSettings({
          ...current.settings,
          ...validSettingsPatch(partial),
        }),
      });
      const settings = cloneSettings(next.settings);
      for (const listener of [...settingsListeners]) {
        try {
          listener(cloneSettings(settings));
        } catch {
          // A broken UI listener must not break settings persistence.
        }
      }
      try {
        broadcastSettings(cloneSettings(settings));
      } catch {
        // No page is listening; the persisted value is authoritative.
      }
      return settings;
    },

    subscribeSettings(listener) {
      settingsListeners.add(listener);
      return () => settingsListeners.delete(listener);
    },

    async keyRing() {
      return { ...(await load()).keyRing };
    },

    async putAssociation(hash, record) {
      const current = await load();
      await save({ keyRing: { ...current.keyRing, [hash]: { ...record, hash } } });
    },

    async deleteAssociation(hash) {
      const current = await load();
      if (!(hash in current.keyRing)) {
        return;
      }
      const keyRing = { ...current.keyRing };
      delete keyRing[hash];
      await save({ keyRing });
    },

    async touchAssociation(hash, at = now()) {
      const current = await load();
      const record = current.keyRing[hash];
      if (!record) {
        return;
      }
      await save({
        keyRing: { ...current.keyRing, [hash]: { ...record, lastUsed: at } },
      });
    },

    async getClientId() {
      return (await load()).clientId;
    },

    async setClientId(clientId) {
      await save({ clientId });
    },

    snapshot() {
      return { ...snapshot, lastError: snapshot.lastError ? { ...snapshot.lastError } : null };
    },

    setSnapshot(next) {
      const merged: ConnectionSnapshot = {
        ...next,
        protocolVersion: next.protocolVersion || SUPPORTED_PROTOCOL_VERSION,
        lastError: next.lastError ? { ...next.lastError } : null,
      };
      const changed = !sameSnapshot(snapshot, merged);
      if (changed && snapshot.state !== "DISCONNECTED" && merged.state === "DISCONNECTED") {
        // A lost connection (not the initial DISCONNECTED snapshot).
        reconnects += 1;
      }
      snapshot = merged;
      if (changed) {
        emit();
      }
    },

    updateSnapshot(patch) {
      this.setSnapshot({ ...snapshot, ...patch });
      return this.snapshot();
    },

    status() {
      return statusFromSnapshot(snapshot);
    },

    diagnostics() {
      const host: HostStatus | null =
        snapshot.state === "DISCONNECTED" || snapshot.state === "CONNECTING"
          ? null
          : {
              appRunning: snapshot.appRunning,
              appVersion: snapshot.appVersion,
              locked: snapshot.locked,
              databaseHash: snapshot.databaseHash,
            };
      return {
        entries: diagnostics.map((entry) => ({ ...entry })),
        connection: this.snapshot(),
        host,
        reconnects,
      };
    },

    log(entry) {
      diagnostics.push({ ...entry, at: now() });
      if (diagnostics.length > maxDiagnostics) {
        diagnostics.splice(0, diagnostics.length - maxDiagnostics);
      }
    },

    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
