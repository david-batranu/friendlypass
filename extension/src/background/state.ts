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
  type StatusSummary,
} from "../common/types";

export const DEFAULT_SETTINGS: Readonly<ExtensionSettings> = Object.freeze({
  autoFillHttpAuth: false,
  autoFillAndSubmit: false,
  launchAppOnConnect: false,
  defaultGroup: "",
  defaultGroupAlwaysAsk: false,
  debugLogging: false,
});

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
}

export type StateListener = (
  status: StatusSummary,
  snapshot: ConnectionSnapshot,
) => void;

export interface StateStore {
  load(): Promise<PersistedState>;
  save(partial: Partial<PersistedState>): Promise<PersistedState>;
  getSettings(): Promise<ExtensionSettings>;
  setSettings(partial: Partial<ExtensionSettings>): Promise<ExtensionSettings>;
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
    settings: { ...DEFAULT_SETTINGS },
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

function sanitiseSettings(value: unknown): ExtensionSettings {
  const settings: ExtensionSettings = { ...DEFAULT_SETTINGS };
  if (!isRecord(value)) {
    return settings;
  }
  if (typeof value["autoFillHttpAuth"] === "boolean") {
    settings.autoFillHttpAuth = value["autoFillHttpAuth"];
  }
  if (typeof value["autoFillAndSubmit"] === "boolean") {
    settings.autoFillAndSubmit = value["autoFillAndSubmit"];
  }
  if (typeof value["launchAppOnConnect"] === "boolean") {
    settings.launchAppOnConnect = value["launchAppOnConnect"];
  }
  if (typeof value["defaultGroup"] === "string") {
    settings.defaultGroup = value["defaultGroup"];
  }
  if (typeof value["defaultGroupAlwaysAsk"] === "boolean") {
    settings.defaultGroupAlwaysAsk = value["defaultGroupAlwaysAsk"];
  }
  if (typeof value["debugLogging"] === "boolean") {
    settings.debugLogging = value["debugLogging"];
  }
  return settings;
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

  let cached: PersistedState | null = null;
  let loading: Promise<PersistedState> | null = null;
  let snapshot = initialSnapshot();
  const listeners = new Set<StateListener>();
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
      return { ...(await load()).settings };
    },

    async setSettings(partial) {
      const current = await load();
      const next = await save({
        settings: sanitiseSettings({ ...current.settings, ...partial }),
      });
      return { ...next.settings };
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
