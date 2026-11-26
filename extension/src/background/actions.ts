/**
 * Typed protocol actions (WP3).
 *
 * One function per wire action (`protocol/ACTIONS.md` §4), each building the
 * inner JSON in the frozen field order, encrypting it through `session.ts`,
 * sending it and validating the decrypted response. Callers never touch nonces
 * or ciphertext and never see a `message`/`nonce` pair.
 *
 * Errors are the typed `ProtocolError` values produced by the session (mapped
 * from the wire `errorCode`). Credential lookups therefore reject with code 15
 * when nothing matches rather than returning an empty array; callers that treat
 * "no logins" as normal should catch code 15 explicitly.
 *
 * Never log decrypted entries: `get-logins` returns plaintext passwords.
 */

import { newRequestId } from "../common/messages";
import type { ProtocolSession } from "./session";
import {
  buildGetDatabaseGroupsInner,
  buildGetLoginsInner,
  buildGetTotpInner,
  buildLockDatabaseInner,
  buildGeneratePasswordInner,
  buildPasskeysGetInner,
  buildPasskeysRegisterInner,
  buildSetLoginInner,
  isHexUuid,
} from "./session";
import { makeProtocolError } from "../common/messages";
import {
  KpxcAction,
  KpxcErrorCode,
  LONG_REQUEST_TIMEOUT_MS,
  type CreatedGroup,
  type CredentialEntry,
  type DatabaseGroup,
  type DbHash,
  type GetDatabaseGroupsResponse,
  type GetLoginsResponse,
  type GetTotpResponse,
  type HexUuid,
  type PasskeysResponse,
  type SaveLoginArgs,
  type SaveLoginResult,
  type SetLoginResponse,
} from "../common/types";

/** A passkey prompt can wait for the user for up to two minutes. */
const PASSKEYS_REQUEST_TIMEOUT_MS = 120_000;

export interface ActionContext {
  /** Live protocol session (authoritative for clientID/association/hash). */
  session: ProtocolSession;
  /** Optional per-call timeout override in milliseconds. */
  timeoutMs?: number;
  /** Diagnostics only; the session is authoritative. */
  clientID?: string;
  /** Diagnostics only; the session is authoritative. */
  dbHash?: DbHash;
  /** Diagnostics only; the session is authoritative. */
  association?: { id: string; key: string } | null;
}

export interface GetLoginsArgs {
  url: string;
  submitUrl?: string;
  /** HTTP Basic/Digest lookup path (`httpAuth: "true"`). */
  httpAuth?: boolean;
  /**
   * Full keyring. Defaults to every persisted association when omitted so
   * callers cannot accidentally send an empty list.
   */
  keys?: Array<{ id: string; key: string }>;
  /** Ask the app to raise its unlock UI (can take up to 30 s). */
  triggerUnlock?: boolean;
}

function timeoutFor(
  ctx: ActionContext,
  options: { long?: boolean } = {},
): number | undefined {
  return ctx.timeoutMs ?? (options.long ? LONG_REQUEST_TIMEOUT_MS : undefined);
}

function associationId(ctx: ActionContext): string | undefined {
  return ctx.association?.id ?? ctx.session.currentAssociation()?.id;
}

export async function fetchDatabaseHash(ctx: ActionContext): Promise<DbHash> {
  return ctx.session.getDatabaseHash();
}

export async function associate(
  ctx: ActionContext,
): Promise<{ id: string; hash: DbHash }> {
  return ctx.session.associate();
}

export async function testAssociate(
  ctx: ActionContext,
): Promise<{ id: string; hash: DbHash }> {
  return ctx.session.testAssociate();
}

export async function getLogins(
  ctx: ActionContext,
  args: GetLoginsArgs,
): Promise<CredentialEntry[]> {
  if (!args.url) {
    throw makeProtocolError(KpxcErrorCode.NO_URL_PROVIDED);
  }
  const keys = args.keys?.length
    ? args.keys
    : await ctx.session.connectionKeys();
  const long = args.httpAuth === true || args.triggerUnlock === true;

  const response = await ctx.session.request<GetLoginsResponse>({
    action: KpxcAction.GET_LOGINS,
    requiresAssociation: true,
    triggerUnlock: args.triggerUnlock,
    timeoutMs: timeoutFor(ctx, { long }),
    buildInner: () =>
      buildGetLoginsInner({
        id: associationId(ctx),
        url: args.url,
        submitUrl: args.submitUrl,
        httpAuth: args.httpAuth ? "true" : undefined,
        keys,
      }),
  });

  if (!Array.isArray(response.entries)) {
    throw makeProtocolError(
      KpxcErrorCode.CANNOT_DECRYPT_MESSAGE,
      "get-logins response has no entries array",
    );
  }

  // The app may return the same entry through several aliases (URL, submitUrl,
  // subdomain). De-duplicate by UUID, preserving server order.
  const seen = new Set<string>();
  const entries: CredentialEntry[] = [];
  for (const entry of response.entries) {
    const uuid = typeof entry?.uuid === "string" ? entry.uuid : "";
    if (uuid && seen.has(uuid)) {
      continue;
    }
    if (uuid) {
      seen.add(uuid);
    }
    entries.push(entry);
  }
  return entries;
}

export async function setLogin(
  ctx: ActionContext,
  args: SaveLoginArgs,
): Promise<SaveLoginResult> {
  if (!args.url) {
    throw makeProtocolError(KpxcErrorCode.NO_URL_PROVIDED);
  }
  if (args.login.includes("{REF:") || args.password.includes("{REF:")) {
    throw makeProtocolError(KpxcErrorCode.CANNOT_USE_REFERENCES);
  }

  const update = typeof args.uuid === "string" && args.uuid.length > 0;
  const response = await ctx.session.request<SetLoginResponse>({
    action: KpxcAction.SET_LOGIN,
    requiresAssociation: true,
    triggerUnlock: true,
    timeoutMs: timeoutFor(ctx, { long: true }),
    buildInner: () =>
      buildSetLoginInner({
        id: associationId(ctx),
        login: args.login,
        password: args.password,
        url: args.url,
        submitUrl: args.submitUrl,
        uuid: update ? args.uuid : undefined,
        group: update ? undefined : args.group,
        groupUuid: update ? undefined : args.groupUuid,
        downloadFavicon: update ? undefined : "true",
        title: args.title,
      }),
  });

  // `set-login` reports the operation result in the *inner* `error` field while
  // `success` stays "true" (ACTIONS.md §4.6).
  const ok = response.error === "success";
  return {
    success: ok,
    message: ok
      ? "success"
      : response.error === "error"
        ? "The save was declined"
        : String(response.error ?? "Unknown save result"),
  };
}

export async function getTotp(
  ctx: ActionContext,
  uuid: HexUuid,
): Promise<string> {
  if (!isHexUuid(uuid)) {
    throw makeProtocolError(KpxcErrorCode.NO_VALID_UUID_PROVIDED);
  }
  const response = await ctx.session.request<GetTotpResponse>({
    action: KpxcAction.GET_TOTP,
    requiresAssociation: true,
    timeoutMs: timeoutFor(ctx),
    buildInner: () => buildGetTotpInner(uuid),
  });
  return typeof response.totp === "string" ? response.totp : "";
}

export async function getDatabaseGroups(
  ctx: ActionContext,
): Promise<DatabaseGroup[]> {
  const response = await ctx.session.request<GetDatabaseGroupsResponse>({
    action: KpxcAction.GET_DATABASE_GROUPS,
    requiresAssociation: true,
    timeoutMs: timeoutFor(ctx),
    buildInner: () => buildGetDatabaseGroupsInner(),
  });
  // Frozen compatibility quirk: the wire value is `{groups: {groups: [root]}}`.
  const groups = response.groups?.groups;
  if (!Array.isArray(groups) || groups.length === 0) {
    throw makeProtocolError(KpxcErrorCode.NO_GROUPS_FOUND);
  }
  return groups;
}

export async function createNewGroup(
  ctx: ActionContext,
  name: string,
): Promise<CreatedGroup> {
  void ctx;
  void name;
  // Reserved by protocol v1 (ACTIONS.md §4.11). The save UI must restrict the
  // user to existing groups in phase 1.
  throw makeProtocolError(
    KpxcErrorCode.CANNOT_CREATE_NEW_GROUP,
    "create-new-group is not implemented in protocol v1",
  );
}

export async function generatePassword(ctx: ActionContext): Promise<string> {
  const requestID = newRequestId();
  const response = await ctx.session.request<{ password?: string; entries?: string }>({
    action: KpxcAction.GENERATE_PASSWORD,
    requestID,
    timeoutMs: timeoutFor(ctx, { long: true }),
    buildInner: ({ nonce, clientID }) =>
      buildGeneratePasswordInner({ nonce, clientID, requestID }),
  });
  if (typeof response.password === "string" && response.password.length > 0) {
    return response.password;
  }
  // Legacy servers return the password in `entries`.
  return typeof response.entries === "string" ? response.entries : "";
}

export interface PasskeyArgs {
  publicKey: Record<string, unknown>;
  origin: string;
  groupName?: string;
}

/** `passkeys-register` (ACTIONS.md §4.12). Errors are typed protocol errors. */
export async function passkeysRegister(
  ctx: ActionContext,
  args: PasskeyArgs,
): Promise<PasskeysResponse> {
  const keys = await ctx.session.connectionKeys();
  return ctx.session.request<PasskeysResponse>({
    action: KpxcAction.PASSKEYS_REGISTER,
    requiresAssociation: true,
    timeoutMs: PASSKEYS_REQUEST_TIMEOUT_MS,
    buildInner: () =>
      buildPasskeysRegisterInner({
        publicKey: args.publicKey,
        origin: args.origin,
        groupName: args.groupName,
        keys,
      }),
  });
}

/** `passkeys-get` (ACTIONS.md §4.12). */
export async function passkeysGet(
  ctx: ActionContext,
  args: PasskeyArgs,
): Promise<PasskeysResponse> {
  const keys = await ctx.session.connectionKeys();
  return ctx.session.request<PasskeysResponse>({
    action: KpxcAction.PASSKEYS_GET,
    requiresAssociation: true,
    timeoutMs: PASSKEYS_REQUEST_TIMEOUT_MS,
    buildInner: () =>
      buildPasskeysGetInner({
        publicKey: args.publicKey,
        origin: args.origin,
        keys,
      }),
  });
}

export async function lockDatabase(ctx: ActionContext): Promise<void> {
  try {
    await ctx.session.request<unknown>({
      action: KpxcAction.LOCK_DATABASE,
      timeoutMs: timeoutFor(ctx),
      buildInner: () => buildLockDatabaseInner(),
    });
  } catch (cause) {
    // KeePassXC answers error 1 when the database was already locked. The
    // outcome the caller asked for is true either way (ACTIONS.md §4.9).
    const code = (cause as { code?: unknown } | null)?.code;
    if (code !== KpxcErrorCode.DATABASE_NOT_OPENED) {
      throw cause;
    }
  }
  // The app also broadcasts `database-locked`; update local state immediately in
  // case the push is lost.
  ctx.session.markLocked();
}
