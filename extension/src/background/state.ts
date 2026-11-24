/**
 * Persisted extension state (WP3).
 *
 * Split of storage areas:
 *  - `chrome.storage.local`: keyring (survives browser restarts), settings,
 *    stable client id. NOT secrets beyond the identification public key.
 *  - `chrome.storage.session` (or in-memory): connection snapshot, server
 *    public key, pending request metadata. Lost on service-worker restart by
 *    design; `ensureSession()` rebuilds it.
 *
 * TODO(WP3): implement. Never persist plaintext passwords or the session
 * secret key.
 */

import type {
  AssociationRecord,
  ConnectionSnapshot,
  DbHash,
  DiagnosticsSnapshot,
  ExtensionSettings,
  PersistedState,
  StatusSummary,
} from "../common/types";

export const DEFAULT_SETTINGS: Readonly<ExtensionSettings> = Object.freeze({
  autoFillHttpAuth: false,
  autoFillAndSubmit: false,
  launchAppOnConnect: false,
  defaultGroup: "",
  defaultGroupAlwaysAsk: false,
  debugLogging: false,
});

export interface StateStore {
  load(): Promise<PersistedState>;
  save(partial: Partial<PersistedState>): Promise<PersistedState>;
  getSettings(): Promise<ExtensionSettings>;
  setSettings(partial: Partial<ExtensionSettings>): Promise<ExtensionSettings>;
  keyRing(): Promise<Record<DbHash, AssociationRecord>>;
  putAssociation(hash: DbHash, record: AssociationRecord): Promise<void>;
  deleteAssociation(hash: DbHash): Promise<void>;
  snapshot(): ConnectionSnapshot;
  setSnapshot(snapshot: ConnectionSnapshot): void;
  status(): StatusSummary;
  diagnostics(): DiagnosticsSnapshot;
  log(entry: Omit<DiagnosticsSnapshot["entries"][number], "at">): void;
}

export function createStateStore(): StateStore {
  throw new Error("TODO(WP3): implement persisted state store");
}
