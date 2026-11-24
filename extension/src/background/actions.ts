/**
 * Typed protocol actions (WP3).
 *
 * One function per wire action, each building the inner JSON, encrypting it
 * through the session, sending it and validating the decrypted response.
 * Callers never touch nonces or ciphertext.
 *
 * TODO(WP3): implement on top of `session.ts`.
 */

import type {
  CreatedGroup,
  CredentialEntry,
  DatabaseGroup,
  DbHash,
  HexUuid,
  SaveLoginArgs,
  SaveLoginResult,
} from "../common/types";

export interface ActionContext {
  clientID: string;
  dbHash: DbHash;
  association: { id: string; key: string } | null;
  timeoutMs?: number;
}

export async function fetchDatabaseHash(
  _ctx: ActionContext,
): Promise<DbHash> {
  throw new Error("TODO(WP3): implement get-databasehash");
}

export async function associate(
  _ctx: ActionContext,
): Promise<{ id: string; hash: DbHash }> {
  throw new Error("TODO(WP3): implement associate");
}

export async function testAssociate(
  _ctx: ActionContext,
): Promise<{ id: string; hash: DbHash }> {
  throw new Error("TODO(WP3): implement test-associate");
}

export async function getLogins(
  _ctx: ActionContext,
  _args: {
    url: string;
    submitUrl?: string;
    httpAuth?: boolean;
    keys: Array<{ id: string; key: string }>;
  },
): Promise<CredentialEntry[]> {
  throw new Error("TODO(WP3): implement get-logins");
}

export async function setLogin(
  _ctx: ActionContext,
  _args: SaveLoginArgs,
): Promise<SaveLoginResult> {
  throw new Error("TODO(WP3): implement set-login");
}

export async function getTotp(
  _ctx: ActionContext,
  _uuid: HexUuid,
): Promise<string> {
  throw new Error("TODO(WP3): implement get-totp");
}

export async function getDatabaseGroups(
  _ctx: ActionContext,
): Promise<DatabaseGroup[]> {
  throw new Error("TODO(WP3): implement get-database-groups");
}

export async function createNewGroup(
  _ctx: ActionContext,
  _name: string,
): Promise<CreatedGroup> {
  throw new Error("TODO(WP3): create-new-group is out of scope for phase 1");
}

export async function generatePassword(_ctx: ActionContext): Promise<string> {
  throw new Error("TODO(WP3): implement generate-password");
}

export async function lockDatabase(_ctx: ActionContext): Promise<void> {
  throw new Error("TODO(WP3): implement lock-database");
}
