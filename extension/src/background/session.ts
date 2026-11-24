/**
 * Protocol session (WP3).
 *
 * Owns: keypair generation, `change-public-keys`, `get-databasehash`,
 * `test-associate`/`associate`, serialised `ensureSession()`, association
 * keyring access, and the request/response correlation by incremented nonce.
 *
 * Rules (see `protocol/ACTIONS.md` §2 and §7):
 *  - `ensureSession()` is serialised through one promise.
 *  - A request with an encrypted action MUST never be sent before
 *    `serverPublicKey` is known.
 *  - Responses must carry `nonce == increment(request.nonce)`; errors carry no
 *    nonce and are correlated by `action`.
 *
 * TODO(WP3): implement. The interface below is the boundary WP5/WP6 code
 * against.
 */

import type { ConnectionSnapshot, DbHash } from "../common/types";

export interface SessionDependencies {
  /** Send a frame and resolve with the next response frame for that action. */
  send(frame: unknown, timeoutMs?: number): Promise<unknown>;
  /** Persisted state accessors (`state.ts`). */
  loadKeyRing(): Promise<Record<DbHash, { id: string; key: string }>>;
  saveAssociation(hash: DbHash, id: string, key: string): Promise<void>;
  onSnapshot(snapshot: ConnectionSnapshot): void;
}

export interface ProtocolSession {
  /** Current snapshot; never contains secrets. */
  snapshot(): ConnectionSnapshot;
  /**
   * Serialised handshake: connect if needed, `change-public-keys`, then
   * `get-databasehash` and `test-associate`. Resolves when the session is
   * usable, or with a snapshot carrying the error.
   */
  ensureSession(options?: { triggerUnlock?: boolean }): Promise<ConnectionSnapshot>;
  /** Re-handshake after a port loss or a `database-*` push. */
  reset(reason: string): void;
}

export function createSession(_deps: SessionDependencies): ProtocolSession {
  throw new Error("TODO(WP3): implement protocol session");
}
