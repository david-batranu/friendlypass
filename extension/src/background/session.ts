/**
 * Protocol session (WP3).
 *
 * Owns: keypair generation, `change-public-keys`, `get-databasehash`,
 * `test-associate`/`associate`, serialised `ensureSession()`, association
 * keyring access, and request/response correlation by incremented nonce.
 *
 * Rules (see `protocol/ACTIONS.md` §2, §6 and §7):
 *  - `ensureSession()` is serialised through one shared promise: 20 tabs waking
 *    at once produce exactly one handshake.
 *  - An encrypted action MUST never be sent before `serverPublicKey` is known.
 *    The only way to reach `transport.send()` without a key is
 *    `change-public-keys`; there is no plaintext fallback anywhere.
 *  - Responses must carry `nonce == increment(request.nonce)`; error replies
 *    carry no nonce and are correlated by `action`.
 *  - Every request settles: value, typed error, or timeout. Nothing hangs.
 *
 * Wiring (the service worker composes transport + session; neither module
 * creates the other):
 *
 * ```ts
 * const store = createStateStore();
 * const transport = createNativeTransport(session.transportHandlers);
 * const session = createSession({ transport, store });
 * ```
 *
 * The session depends on the transport only through the `NativeTransport`
 * interface from `transport.ts`; tests inject a mock.
 *
 * Never log a decrypted inner message: it contains plaintext credentials.
 */

import nacl from "tweetnacl";

import {
  isChangePublicKeysResponse,
  isErrorFrame,
  isHostErrorFrame,
  isHostPingResponse,
  isPushFrame,
  isRecord,
  isSuccessFrame,
  makeProtocolError,
  protocolErrorFromFrame,
} from "../common/messages";
import {
  KpxcAction,
  KpxcErrorCode,
  LONG_REQUEST_TIMEOUT_MS,
  PushAction,
  REQUEST_TIMEOUT_MS,
  SUPPORTED_PROTOCOL_VERSION,
  type AssociateRequest,
  type AssociateResponse,
  type B64,
  type ChangePublicKeysRequestFrame,
  type ConnectionKey,
  type ConnectionSnapshot,
  type DatabaseHashResponse,
  type DbHash,
  type EncryptedRequestFrame,
  type GeneratePasswordRequest,
  type GetDatabaseGroupsRequest,
  type GetDatabaseHashRequest,
  type GetLoginsRequest,
  type GetTotpRequest,
  type HostHelloResponse,
  type HostPingResponse,
  type HostToExtensionFrame,
  type KpxcActionName,
  type KpxcInnerResponse,
  type LockDatabaseRequest,
  type NativeErrorFrame,
  type NativeRequestFrame,
  type NativeSuccessFrame,
  type ProtocolError,
  type SetLoginRequest,
  type TestAssociateRequest,
  type AssociationRecord,
} from "../common/types";
import type {
  NativeTransport,
  TransportDisconnectReason,
  TransportHandlers,
} from "./transport";
import { mergeObservedStatus } from "./transport";

// ---------------------------------------------------------------------------
// Sizes and base64
// ---------------------------------------------------------------------------

/** X25519 public/secret key size in bytes. */
export const KEY_BYTES = 32;
/** XSalsa20-Poly1305 nonce size in bytes. */
export const NONCE_BYTES = 24;
/** Poly1305 authentication tag prepended to every ciphertext. */
export const BOX_OVERHEAD_BYTES = 16;

export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(
      ...bytes.subarray(offset, Math.min(offset + chunk, bytes.length)),
    );
  }
  return btoa(binary);
}

/** Strict standard-Base64 decoder. Throws on malformed input. */
export function decodeBase64(value: string): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new Error("invalid Base64 value");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new Error("invalid Base64 value");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function decodeBase64OrThrow(value: unknown, expectedBytes: number): Uint8Array {
  if (typeof value !== "string") {
    throw new Error("missing Base64 value");
  }
  const bytes = decodeBase64(value);
  if (bytes.length !== expectedBytes) {
    throw new Error(`expected ${expectedBytes} bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * libsodium `sodium_increment`: add one to the 24-byte little-endian integer,
 * propagating carry and wrapping at 2^192. Returns a new array.
 */
export function incrementNonce(nonce: Uint8Array): Uint8Array {
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`nonce must be ${NONCE_BYTES} bytes`);
  }
  const result = new Uint8Array(nonce);
  let carry = 1;
  for (let i = 0; i < result.length && carry !== 0; i += 1) {
    const sum = result[i] + carry;
    result[i] = sum & 0xff;
    carry = sum >> 8;
  }
  return result;
}

export function incrementNonceBase64(nonce: B64): B64 {
  return encodeBase64(incrementNonce(decodeBase64(nonce)));
}

/** Bounded memory of response nonces that already settled a request. */
const SETTLED_NONCE_MEMORY = 128;

// ---------------------------------------------------------------------------
// TweetNaCl wrappers (pure, exported for tests and actions)
// ---------------------------------------------------------------------------

export interface BoxKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface SessionKeys {
  /** Ephemeral client (extension) secret key for this handshake. */
  clientSecretKey: Uint8Array;
  /** Ephemeral client public key, sent in `associate.key`. */
  clientPublicKey: Uint8Array;
  /** Host (app) session public key from `change-public-keys`. */
  serverPublicKey: Uint8Array;
}

export function generateBoxKeyPair(): BoxKeyPair {
  return nacl.box.keyPair();
}

/** UTF-8 encode without BOM; compact JSON is the caller's responsibility. */
function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

/**
 * Seal one inner message. `plaintext` is compact JSON (`JSON.stringify`), as
 * required for byte-exact fixtures.
 *
 * @throws when `nonce`/keys have the wrong length or TweetNaCl fails.
 */
export function sealInnerMessage(
  inner: unknown,
  nonce: Uint8Array,
  keys: Pick<SessionKeys, "clientSecretKey" | "serverPublicKey">,
): string {
  if (nonce.length !== NONCE_BYTES) {
    throw makeProtocolError(
      KpxcErrorCode.CANNOT_ENCRYPT_MESSAGE,
      "nonce must be 24 bytes",
    );
  }
  if (
    keys.clientSecretKey.length !== KEY_BYTES ||
    keys.serverPublicKey.length !== KEY_BYTES
  ) {
    throw makeProtocolError(
      KpxcErrorCode.CANNOT_ENCRYPT_MESSAGE,
      "session keys must be 32 bytes",
    );
  }
  const plaintext = utf8Encode(JSON.stringify(inner));
  let ciphertext: Uint8Array;
  try {
    ciphertext = nacl.box(
      plaintext,
      nonce,
      keys.serverPublicKey,
      keys.clientSecretKey,
    );
  } catch {
    throw makeProtocolError(
      KpxcErrorCode.CANNOT_ENCRYPT_MESSAGE,
      "Message encryption failed",
    );
  }
  return encodeBase64(ciphertext);
}

/**
 * Open one inner message. All failure modes collapse to error 4
 * (`CANNOT_DECRYPT_MESSAGE`) so callers cannot distinguish key/nonce/JSON
 * failures and credentials never leak through error text.
 */
export function openInnerMessage(
  message: B64,
  nonce: B64,
  keys: Pick<SessionKeys, "clientSecretKey" | "serverPublicKey">,
): unknown {
  let ciphertext: Uint8Array;
  let nonceBytes: Uint8Array;
  try {
    ciphertext = decodeBase64(message);
    nonceBytes = decodeBase64OrThrow(nonce, NONCE_BYTES);
  } catch {
    throw makeProtocolError(KpxcErrorCode.CANNOT_DECRYPT_MESSAGE);
  }
  if (ciphertext.length < BOX_OVERHEAD_BYTES) {
    throw makeProtocolError(KpxcErrorCode.CANNOT_DECRYPT_MESSAGE);
  }
  let plaintext: Uint8Array | null;
  try {
    plaintext = nacl.box.open(
      ciphertext,
      nonceBytes,
      keys.serverPublicKey,
      keys.clientSecretKey,
    );
  } catch {
    plaintext = null;
  }
  if (!plaintext) {
    throw makeProtocolError(KpxcErrorCode.CANNOT_DECRYPT_MESSAGE);
  }
  try {
    const parsed: unknown = JSON.parse(utf8Decode(plaintext));
    if (!isRecord(parsed)) {
      throw new Error("inner message is not a JSON object");
    }
    return parsed;
  } catch {
    throw makeProtocolError(KpxcErrorCode.CANNOT_DECRYPT_MESSAGE);
  }
}

// ---------------------------------------------------------------------------
// Frame builders (shared with actions.ts; fixtures use them directly)
// ---------------------------------------------------------------------------

export function buildChangePublicKeysFrame(params: {
  publicKey: B64;
  nonce: B64;
  clientID: B64;
}): ChangePublicKeysRequestFrame {
  return {
    action: KpxcAction.CHANGE_PUBLIC_KEYS,
    publicKey: params.publicKey,
    nonce: params.nonce,
    clientID: params.clientID,
  };
}

export interface EncryptedFrameParams {
  action: KpxcActionName;
  inner: unknown;
  nonce: Uint8Array;
  clientID: B64;
  keys: Pick<SessionKeys, "clientSecretKey" | "serverPublicKey">;
  requestID?: string;
  triggerUnlock?: boolean;
}

/**
 * Build the outer encrypted frame. Property insertion order is normative for
 * the golden fixtures (`action`, `message`, `nonce`, `clientID`, then the two
 * optional bookkeeping fields).
 */
export function buildEncryptedRequestFrame(
  params: EncryptedFrameParams,
): EncryptedRequestFrame {
  const frame: EncryptedRequestFrame = {
    action: params.action,
    message: sealInnerMessage(params.inner, params.nonce, params.keys),
    nonce: encodeBase64(params.nonce),
    clientID: params.clientID,
  };
  if (params.requestID !== undefined) {
    frame.requestID = params.requestID;
  }
  if (params.triggerUnlock) {
    frame.triggerUnlock = "true";
  }
  return frame;
}

export function buildGetDatabaseHashInner(
  input: { connectedKeys?: string[] } = {},
): GetDatabaseHashRequest {
  const request: GetDatabaseHashRequest = {
    action: KpxcAction.GET_DATABASEHASH,
  };
  if (input.connectedKeys !== undefined) {
    request.connectedKeys = input.connectedKeys;
  }
  return request;
}

export function buildAssociateInner(input: {
  key: B64;
  idKey?: B64;
}): AssociateRequest {
  const request: AssociateRequest = {
    action: KpxcAction.ASSOCIATE,
    key: input.key,
  };
  if (input.idKey !== undefined) {
    request.idKey = input.idKey;
  }
  return request;
}

export function buildTestAssociateInner(input: {
  id: string;
  key: B64;
}): TestAssociateRequest {
  return {
    action: KpxcAction.TEST_ASSOCIATE,
    id: input.id,
    key: input.key,
  };
}

export function buildGetLoginsInner(input: {
  id?: string;
  url: string;
  submitUrl?: string;
  httpAuth?: "true";
  keys?: ConnectionKey[];
}): GetLoginsRequest {
  return {
    action: KpxcAction.GET_LOGINS,
    ...(input.id !== undefined ? { id: input.id } : {}),
    url: input.url,
    ...(input.submitUrl !== undefined ? { submitUrl: input.submitUrl } : {}),
    ...(input.httpAuth !== undefined ? { httpAuth: input.httpAuth } : {}),
    ...(input.keys !== undefined ? { keys: input.keys } : {}),
  };
}

export function buildSetLoginInner(input: {
  id?: string;
  login: string;
  password: string;
  url: string;
  submitUrl?: string;
  uuid?: string;
  group?: string;
  groupUuid?: string;
  downloadFavicon?: "true";
}): SetLoginRequest {
  return {
    action: KpxcAction.SET_LOGIN,
    ...(input.id !== undefined ? { id: input.id } : {}),
    login: input.login,
    password: input.password,
    url: input.url,
    ...(input.submitUrl !== undefined ? { submitUrl: input.submitUrl } : {}),
    ...(input.uuid !== undefined ? { uuid: input.uuid } : {}),
    ...(input.group !== undefined ? { group: input.group } : {}),
    ...(input.groupUuid !== undefined ? { groupUuid: input.groupUuid } : {}),
    ...(input.downloadFavicon !== undefined
      ? { downloadFavicon: input.downloadFavicon }
      : {}),
  };
}

export function buildGetTotpInner(uuid: string): GetTotpRequest {
  return { action: KpxcAction.GET_TOTP, uuid };
}

export function buildGetDatabaseGroupsInner(): GetDatabaseGroupsRequest {
  return { action: KpxcAction.GET_DATABASE_GROUPS };
}

export function buildLockDatabaseInner(): LockDatabaseRequest {
  return { action: KpxcAction.LOCK_DATABASE };
}

export function buildGeneratePasswordInner(input: {
  nonce: B64;
  clientID: B64;
  requestID?: string;
}): GeneratePasswordRequest {
  const request: GeneratePasswordRequest = {
    action: KpxcAction.GENERATE_PASSWORD,
    nonce: input.nonce,
    clientID: input.clientID,
  };
  if (input.requestID !== undefined) {
    request.requestID = input.requestID;
  }
  return request;
}

// ---------------------------------------------------------------------------
// Response validation
// ---------------------------------------------------------------------------

/**
 * Validate an encrypted success frame and return its inner message.
 *
 * Enforces the three frozen rules: outer nonce == increment(request nonce),
 * inner `nonce` equals the outer nonce, and inner `success` is the string
 * `"true"`. Any mismatch maps to error 4.
 */
export function openSuccessFrame(
  frame: NativeSuccessFrame,
  keys: Pick<SessionKeys, "clientSecretKey" | "serverPublicKey">,
  requestNonce: B64,
): KpxcInnerResponse {
  const expected = incrementNonceBase64(requestNonce);
  if (frame.nonce !== expected) {
    throw makeProtocolError(
      KpxcErrorCode.CANNOT_DECRYPT_MESSAGE,
      "Response nonce does not match the request nonce",
    );
  }
  const inner = openInnerMessage(frame.message, frame.nonce, keys);
  if (!isRecord(inner) || inner["success"] !== "true") {
    throw makeProtocolError(
      KpxcErrorCode.CANNOT_DECRYPT_MESSAGE,
      "Inner response is not a success",
    );
  }
  if (inner["nonce"] !== frame.nonce) {
    throw makeProtocolError(
      KpxcErrorCode.CANNOT_DECRYPT_MESSAGE,
      "Inner response nonce does not match the outer frame",
    );
  }
  return inner as unknown as KpxcInnerResponse;
}

interface VerifiedHandshake {
  serverPublicKey: Uint8Array;
  version: string | null;
}

/**
 * Verify a `change-public-keys` reply: success `"true"`, a 32-byte key and the
 * incremented request nonce. Failure is `KEY_CHANGE_FAILED` (9), the code
 * KeePassXC uses for a rejected handshake.
 */
export function verifyChangePublicKeysResponse(
  frame: unknown,
  requestNonce: B64,
): VerifiedHandshake {
  if (!isChangePublicKeysResponse(frame)) {
    throw makeProtocolError(
      KpxcErrorCode.KEY_CHANGE_FAILED,
      "Malformed change-public-keys response",
    );
  }
  if (frame.nonce !== incrementNonceBase64(requestNonce)) {
    throw makeProtocolError(
      KpxcErrorCode.KEY_CHANGE_FAILED,
      "Handshake response nonce does not match the request nonce",
    );
  }
  let serverPublicKey: Uint8Array;
  try {
    serverPublicKey = decodeBase64OrThrow(frame.publicKey, KEY_BYTES);
  } catch {
    throw makeProtocolError(
      KpxcErrorCode.KEY_CHANGE_FAILED,
      "Handshake response has no valid host public key",
    );
  }
  return {
    serverPublicKey,
    version: typeof frame.version === "string" ? frame.version : null,
  };
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/** Persistence/snapshot surface the session needs (satisfied by `StateStore`). */
export interface SessionStore {
  snapshot(): ConnectionSnapshot;
  updateSnapshot(patch: Partial<ConnectionSnapshot>): ConnectionSnapshot;
  getClientId(): Promise<string | null>;
  setClientId(clientId: string): Promise<void>;
  keyRing(): Promise<Record<DbHash, AssociationRecord>>;
  putAssociation(hash: DbHash, record: AssociationRecord): Promise<void>;
  deleteAssociation(hash: DbHash): Promise<void>;
  touchAssociation(hash: DbHash, at?: number): Promise<void>;
}

export interface SessionDependencies {
  transport: NativeTransport;
  store: SessionStore;
  now?: () => number;
  /** Injectable RNG for tests; defaults to `nacl.randomBytes`. */
  randomBytes?: (length: number) => Uint8Array;
  /** Injectable keypair generation for deterministic fixture tests. */
  generateSessionKeyPair?: () => BoxKeyPair;
  generateIdentityKeyPair?: () => BoxKeyPair;
  defaultTimeoutMs?: number;
  longTimeoutMs?: number;
}

export interface SessionRequestOptions {
  action: KpxcActionName;
  /**
   * Build the inner request. `nonce`/`clientID` are the exact values already
   * placed in the outer frame; `generate-password` must echo them.
   */
  buildInner: (context: { nonce: B64; clientID: B64 }) => unknown;
  triggerUnlock?: boolean;
  requestID?: string;
  timeoutMs?: number;
  /** Credential actions require a successful `test-associate` first. */
  requiresAssociation?: boolean;
}

export interface SessionHandshakeOptions {
  triggerUnlock?: boolean;
}

export interface ProtocolSession {
  /** Current snapshot; never contains secrets. */
  snapshot(): ConnectionSnapshot;
  /** Stable persisted client id (created on first use). */
  getClientId(): Promise<string>;
  /**
   * Serialised handshake: connect if needed, `change-public-keys`, then
   * `get-databasehash` and `test-associate`. Always resolves with a snapshot
   * (success or typed error); it never rejects.
   */
  ensureSession(options?: SessionHandshakeOptions): Promise<ConnectionSnapshot>;
  /** Re-handshake after a port loss or explicit user request. */
  reset(reason: string): void;
  /** Typed encrypted action; `ensureSession()` runs first when needed. */
  request<T>(options: SessionRequestOptions): Promise<T>;
  getDatabaseHash(): Promise<DbHash>;
  associate(): Promise<{ id: string; hash: DbHash }>;
  testAssociate(): Promise<{ id: string; hash: DbHash }>;
  /** Association used by the current session, or null. */
  currentAssociation(): { id: string; key: B64 } | null;
  /** Full keyring as `{id,key}` pairs for `get-logins.keys`. */
  connectionKeys(): Promise<ConnectionKey[]>;
  markLocked(): void;
  markUnlocked(): void;
  handleFrame(frame: HostToExtensionFrame): void;
  handleConnect(): void;
  handleDisconnect(reason: TransportDisconnectReason, detail?: string): void;
  /** Handlers to pass to `createNativeTransport()`. */
  readonly transportHandlers: TransportHandlers;
  /** Last protocol error, for diagnostics/tests. */
  readonly lastError: ProtocolError | null;
}

interface PendingBase {
  action: string;
  requestNonce: B64;
  expectedNonce: B64 | null;
  requestID?: string;
  settled: boolean;
  timer: ReturnType<typeof setTimeout> | null;
  resolve(value: unknown): void;
  reject(error: ProtocolError): void;
}

interface HandshakePending extends PendingBase {
  kind: "handshake";
}

interface EncryptedPending extends PendingBase {
  kind: "encrypted";
  keys: Pick<SessionKeys, "clientSecretKey" | "serverPublicKey">;
}

type Pending = HandshakePending | EncryptedPending;

function asProtocolError(
  cause: unknown,
  fallbackCode: number = KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
): ProtocolError {
  if (
    isRecord(cause) &&
    typeof cause["code"] === "number" &&
    typeof cause["name"] === "string" &&
    typeof cause["message"] === "string"
  ) {
    return {
      code: cause["code"],
      name: cause["name"],
      message: cause["message"],
      retryable: cause["retryable"] === true,
    };
  }
  const message = cause instanceof Error ? cause.message : String(cause);
  return makeProtocolError(fallbackCode, message || undefined);
}

function newRandomNonce(randomBytes: (length: number) => Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_BYTES);
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) {
    throw makeProtocolError(
      KpxcErrorCode.CANNOT_ENCRYPT_MESSAGE,
      "Random nonce generation failed",
    );
  }
  return nonce;
}

/** Bound any transport promise so a broken port can never hang a caller. */
function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  onTimeout: () => ProtocolError,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(onTimeout()), Math.max(1, timeoutMs));
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (cause: unknown) => {
        clearTimeout(timer);
        reject(cause);
      },
    );
  });
}

const HEX_UUID = /^[0-9a-f]{32}$/;

export function isHexUuid(value: string): boolean {
  return HEX_UUID.test(value);
}

export function createSession(deps: SessionDependencies): ProtocolSession {
  const { transport, store } = deps;
  const now = deps.now ?? (() => Date.now());
  const randomBytes = deps.randomBytes ?? ((length: number) => nacl.randomBytes(length));
  const makeSessionKeyPair = deps.generateSessionKeyPair ?? generateBoxKeyPair;
  const makeIdentityKeyPair = deps.generateIdentityKeyPair ?? generateBoxKeyPair;
  const defaultTimeout = deps.defaultTimeoutMs ?? REQUEST_TIMEOUT_MS;
  const longTimeout = deps.longTimeoutMs ?? LONG_REQUEST_TIMEOUT_MS;

  let clientId: string | null = null;
  let keys: SessionKeys | null = null;
  let sessionValid = false;
  let associated = false;
  let association: { id: string; key: B64 } | null = null;
  let generation = 0;
  let inFlight: Promise<ConnectionSnapshot> | null = null;
  let revalidationQueued = false;
  let revalidationAgain = false;
  let lastError: ProtocolError | null = null;

  const pendingByNonce = new Map<B64, Pending>();
  const pendingByAction = new Map<string, Pending[]>();
  const settledNonces: string[] = [];
  const settledNonceSet = new Set<string>();

  function rememberSettledNonce(nonce: string): void {
    settledNonces.push(nonce);
    settledNonceSet.add(nonce);
    if (settledNonces.length > SETTLED_NONCE_MEMORY) {
      const evicted = settledNonces.shift();
      if (evicted !== undefined) {
        settledNonceSet.delete(evicted);
      }
    }
  }

  function updateSnapshot(patch: Partial<ConnectionSnapshot>): ConnectionSnapshot {
    return store.updateSnapshot(patch);
  }

  function clearKeys(): void {
    keys = null;
    sessionValid = false;
    associated = false;
    association = null;
  }

  function removePending(pending: Pending): void {
    if (pending.expectedNonce !== null) {
      const existing = pendingByNonce.get(pending.expectedNonce);
      if (existing === pending) {
        pendingByNonce.delete(pending.expectedNonce);
      }
    }
    const list = pendingByAction.get(pending.action);
    if (list) {
      const index = list.indexOf(pending);
      if (index >= 0) {
        list.splice(index, 1);
      }
      if (list.length === 0) {
        pendingByAction.delete(pending.action);
      }
    }
  }

  function settlePending(
    pending: Pending,
    error?: ProtocolError,
    value?: unknown,
  ): void {
    if (pending.settled) {
      return;
    }
    pending.settled = true;
    if (pending.timer !== null) {
      clearTimeout(pending.timer);
      pending.timer = null;
    }
    removePending(pending);
    if (error) {
      pending.reject(error);
    } else {
      pending.resolve(value);
    }
  }

  function registerPending(pending: Pending, timeoutMs: number): Promise<unknown> {
    const promise = new Promise<unknown>((resolve, reject) => {
      pending.resolve = resolve;
      pending.reject = reject;
    });
    if (pending.expectedNonce !== null) {
      // A collision would make response correlation ambiguous. Random 24-byte
      // nonces make this practically impossible; if it happens, fail closed.
      if (pendingByNonce.has(pending.expectedNonce)) {
        settlePending(
          pending,
          makeProtocolError(
            KpxcErrorCode.CANNOT_ENCRYPT_MESSAGE,
            "Nonce collision; refusing to reuse a nonce",
          ),
        );
        return promise;
      }
      pendingByNonce.set(pending.expectedNonce, pending);
    }
    const list = pendingByAction.get(pending.action) ?? [];
    list.push(pending);
    pendingByAction.set(pending.action, list);
    pending.timer = setTimeout(() => {
      settlePending(
        pending,
        makeProtocolError(
          KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
          `${pending.action} timed out`,
        ),
      );
    }, Math.max(1, timeoutMs));
    return promise;
  }

  function sendFrame(frame: NativeRequestFrame, pending: Pending): void {
    try {
      const sent = transport.send(frame);
      void Promise.resolve(sent).catch((cause: unknown) => {
        settlePending(pending, asProtocolError(cause));
      });
    } catch (cause) {
      settlePending(pending, asProtocolError(cause));
    }
  }

  function noteLocked(error: ProtocolError = makeProtocolError(KpxcErrorCode.DATABASE_NOT_OPENED)): void {
    associated = false;
    lastError = error;
    updateSnapshot({
      state: "LOCKED",
      locked: true,
      databaseOpen: false,
      associated: false,
      lastError: error,
    });
  }

  async function requireClientId(): Promise<B64> {
    if (clientId !== null) {
      return clientId;
    }
    const persisted = await store.getClientId();
    if (persisted) {
      try {
        if (decodeBase64(persisted).length === NONCE_BYTES) {
          clientId = persisted;
          return persisted;
        }
      } catch {
        // Corrupt persisted id: replace it below.
      }
    }
    const created = encodeBase64(randomBytes(NONCE_BYTES));
    await store.setClientId(created);
    clientId = created;
    return created;
  }

  async function rejectAllPending(error: ProtocolError): Promise<void> {
    const all = [...pendingByAction.values()].flat();
    for (const pending of all) {
      settlePending(pending, error);
    }
    pendingByNonce.clear();
    pendingByAction.clear();
  }

  function handleSuccessFrame(frame: NativeSuccessFrame): void {
    const pending = pendingByNonce.get(frame.nonce);
    if (!pending) {
      // Not correlated by its response nonce. A nonce we already settled is a
      // duplicate and is ignored (ACTIONS.md §2.5). Otherwise, if exactly one
      // request of this action is in flight, the frame can only be its
      // corrupted/mismatched reply: fail it closed now instead of timing out.
      if (settledNonceSet.has(frame.nonce)) {
        return;
      }
      const list = pendingByAction.get(frame.action);
      if (list?.length === 1 && list[0].kind === "encrypted") {
        settlePending(
          list[0],
          makeProtocolError(
            KpxcErrorCode.CANNOT_DECRYPT_MESSAGE,
            "Response nonce does not match the request nonce",
          ),
        );
      }
      return;
    }
    if (pending.kind !== "encrypted") {
      return;
    }
    rememberSettledNonce(frame.nonce);
    try {
      const inner = openSuccessFrame(frame, pending.keys, pending.requestNonce);
      settlePending(pending, undefined, inner);
    } catch (cause) {
      settlePending(pending, asProtocolError(cause, KpxcErrorCode.CANNOT_DECRYPT_MESSAGE));
    }
  }

  function handleErrorFrame(frame: NativeErrorFrame): void {
    const error = protocolErrorFromFrame(frame);
    if (error.code === KpxcErrorCode.DATABASE_NOT_OPENED) {
      noteLocked(error);
    } else if (
      error.code === KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED &&
      isHostErrorFrame(frame)
    ) {
      // The host synthesises code 5 when the app socket stays down. Keep the
      // port (the host will come back) but drop stale keys and report app-down
      // so the next action triggers a fresh handshake instead of reusing a
      // session the app has forgotten.
      clearKeys();
      lastError = error;
      updateSnapshot({
        state: "READY",
        appRunning: false,
        databaseOpen: false,
        locked: false,
        associated: false,
        lastError: error,
      });
    }
    const list = pendingByAction.get(frame.action);
    if (!list || list.length === 0) {
      if (frame.action === "") {
        // Host-level failure with an unreadable action (oversized/malformed
        // frame). It cannot be correlated; fail every pending request closed.
        for (const pending of [...pendingByAction.values()].flat()) {
          settlePending(pending, error);
        }
      }
      return;
    }
    const requestId = (frame as unknown as { requestID?: unknown }).requestID;
    const pending =
      (typeof requestId === "string"
        ? list.find((candidate) => candidate.requestID === requestId)
        : undefined) ?? list[0];
    settlePending(pending, error);
  }

  function handleHandshakeFrame(frame: unknown): void {
    if (!isRecord(frame)) {
      return;
    }
    const nonce = typeof frame["nonce"] === "string" ? frame["nonce"] : null;
    const pending = nonce !== null ? pendingByNonce.get(nonce) : undefined;
    if (!pending) {
      if (nonce !== null && !settledNonceSet.has(nonce)) {
        const list = pendingByAction.get(KpxcAction.CHANGE_PUBLIC_KEYS);
        if (list?.length === 1 && list[0].kind === "handshake") {
          settlePending(
            list[0],
            makeProtocolError(
              KpxcErrorCode.KEY_CHANGE_FAILED,
              "Handshake response nonce does not match the request nonce",
            ),
          );
        }
      }
      return;
    }
    if (pending.kind !== "handshake") {
      return;
    }
    if (nonce !== null) {
      rememberSettledNonce(nonce);
    }
    try {
      const verified = verifyChangePublicKeysResponse(frame, pending.requestNonce);
      settlePending(pending, undefined, verified);
    } catch (cause) {
      settlePending(pending, asProtocolError(cause, KpxcErrorCode.KEY_CHANGE_FAILED));
    }
  }

  function handlePingFrame(frame: HostPingResponse): void {
    const previous = store.snapshot();
    const appRunning = frame.appRunning === true;
    if (!appRunning && previous.appRunning) {
      // The app went away while the port stayed alive. Drop the stale session
      // but keep the port; the host reports `appRunning: true` when it returns.
      clearKeys();
      generation += 1;
      inFlight = null;
      const error = makeProtocolError(
        KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
        "friendlypass is not running",
      );
      lastError = error;
      updateSnapshot({
        state: "READY",
        appRunning: false,
        appVersion: frame.appVersion ?? null,
        locked: frame.locked ?? false,
        databaseHash: frame.databaseHash ?? null,
        databaseOpen: false,
        associated: false,
        lastError: error,
      });
      return;
    }

    updateSnapshot({
      appRunning,
      appVersion: frame.appVersion ?? null,
      hostVersion: frame.hostVersion ?? previous.hostVersion,
      protocolVersion:
        typeof frame.protocolVersion === "number"
          ? frame.protocolVersion
          : previous.protocolVersion,
      locked: frame.locked ?? previous.locked,
      databaseHash: frame.databaseHash ?? previous.databaseHash,
    });
    if (appRunning && !previous.appRunning) {
      // The app answered again: move READY back to a fresh handshake. When a
      // handshake is already running it may have read a stale app-down `hello`,
      // so re-run it once it settles rather than dropping the transition.
      if (previous.state !== "HANDSHAKING") {
        updateSnapshot({ state: "READY", lastError: null });
      }
      scheduleRevalidate(true);
    }
  }

  function handlePushFrame(frame: HostToExtensionFrame): void {
    if (!isPushFrame(frame)) {
      return;
    }
    switch (frame.action) {
      case PushAction.DATABASE_LOCKED:
        noteLocked();
        break;
      case PushAction.DATABASE_UNLOCKED:
        invalidateSession();
        updateSnapshot({
          state: "HANDSHAKING",
          locked: false,
          databaseOpen: false,
          associated: false,
          lastError: null,
        });
        scheduleRevalidate(true);
        break;
      case PushAction.DATABASE_CHANGED: {
        const nextHash =
          typeof frame.hash === "string" ? frame.hash : null;
        const current = store.snapshot();
        if (nextHash !== null && nextHash !== current.databaseHash) {
          // A different database/root UUID: the old association no longer
          // applies, so rebuild the session and let test-associate decide.
          invalidateSession();
          updateSnapshot({
            state: "HANDSHAKING",
            databaseOpen: false,
            associated: false,
            lastError: null,
            databaseHash: nextHash,
          });
          scheduleRevalidate(true);
        } else if (nextHash !== null) {
          updateSnapshot({ databaseHash: nextHash });
        }
        // Content-only changes (no hash) do not invalidate keys or association.
        break;
      }
      default:
        break;
    }
  }

  function invalidateSession(): void {
    clearKeys();
    generation += 1;
    inFlight = null;
  }

  /**
   * Rebuild the session in the background. `afterInFlight` marks events whose
   * truth may post-date a handshake that is already running (status transitions,
   * pushes); those must run again once it settles, otherwise the event is lost.
   */
  function scheduleRevalidate(afterInFlight = false): void {
    if (inFlight !== null) {
      // A handshake that started before this event may already have consumed a
      // stale `hello` (app down). Dropping the event here used to leave the app
      // marked down until the next status change or the 20 s heartbeat, so
      // remember to run once more when that handshake settles.
      if (afterInFlight) {
        revalidationAgain = true;
      }
      return;
    }
    if (revalidationQueued) {
      return;
    }
    revalidationQueued = true;
    // `ensureSession()` never rejects, but keep a catch so a future change can
    // never surface an unhandled rejection from this fire-and-forget path.
    void ensureSession()
      .catch(() => store.snapshot())
      .finally(() => {
        revalidationQueued = false;
        if (revalidationAgain) {
          revalidationAgain = false;
          scheduleRevalidate();
        }
      })
      .catch(() => undefined);
  }

  /**
   * Ask the host for the app status (a host-level `ping`, answered locally in
   * microseconds). Returns null when the port is gone or the host does not
   * answer; the reconnect loop owns that failure mode, so callers then fail
   * fast instead of waiting.
   */
  async function probeAppStatus(): Promise<HostPingResponse | null> {
    if (!transport.connected) {
      return null;
    }
    try {
      return await transport.ping();
    } catch {
      return null;
    }
  }

  // --- handshake -----------------------------------------------------------

  async function changePublicKeys(
    token: number,
  ): Promise<void> {
    const id = await requireClientId();
    if (token !== generation) {
      throw makeProtocolError(
        KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
        "Handshake superseded",
      );
    }
    const keyPair = makeSessionKeyPair();
    if (
      keyPair.publicKey.length !== KEY_BYTES ||
      keyPair.secretKey.length !== KEY_BYTES
    ) {
      throw makeProtocolError(
        KpxcErrorCode.ENCRYPTION_KEY_UNRECOGNIZED,
        "Keypair generation failed",
      );
    }
    const nonce = newRandomNonce(randomBytes);
    const requestNonce = encodeBase64(nonce);
    const expectedNonce = incrementNonceBase64(requestNonce);
    const pending: HandshakePending = {
      kind: "handshake",
      action: KpxcAction.CHANGE_PUBLIC_KEYS,
      requestNonce,
      expectedNonce,
      settled: false,
      timer: null,
      resolve: () => undefined,
      reject: () => undefined,
    };
    const promise = registerPending(pending, defaultTimeout);
    sendFrame(
      buildChangePublicKeysFrame({
        publicKey: encodeBase64(keyPair.publicKey),
        nonce: requestNonce,
        clientID: id,
      }),
      pending,
    );
    const verified = (await promise) as VerifiedHandshake;
    if (token !== generation) {
      throw makeProtocolError(
        KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
        "Handshake superseded",
      );
    }
    keys = {
      clientSecretKey: keyPair.secretKey,
      clientPublicKey: keyPair.publicKey,
      serverPublicKey: verified.serverPublicKey,
    };
    updateSnapshot({ state: "HANDSHAKING", lastError: null });
  }

  async function fetchDatabaseHashNow(
    triggerUnlock: boolean,
  ): Promise<DatabaseHashResponse> {
    const keyRing = await store.keyRing();
    const response = await sendEncryptedNow<DatabaseHashResponse>(
      KpxcAction.GET_DATABASEHASH,
      () => buildGetDatabaseHashInner({ connectedKeys: Object.keys(keyRing) }),
      { triggerUnlock, timeoutMs: defaultTimeout },
    );
    if (typeof response.hash !== "string" || !/^[0-9a-f]{64}$/.test(response.hash)) {
      throw makeProtocolError(
        KpxcErrorCode.DATABASE_HASH_NOT_RECEIVED,
        "Database hash is missing or malformed",
      );
    }
    return response;
  }

  async function testAssociateNow(
    token: number,
    oldHash: DbHash | undefined,
  ): Promise<boolean> {
    const snapshot = store.snapshot();
    const hash = snapshot.databaseHash;
    if (!hash) {
      association = null;
      return false;
    }
    const keyRing = await store.keyRing();
    let record = keyRing[hash];
    let sourceHash = hash;
    if (!record && oldHash && keyRing[oldHash]) {
      record = keyRing[oldHash];
      sourceHash = oldHash;
    }
    if (!record) {
      association = null;
      return false;
    }
    await sendEncryptedNow<AssociateResponse>(
      KpxcAction.TEST_ASSOCIATE,
      () => buildTestAssociateInner({ id: record.id, key: record.key }),
      { timeoutMs: defaultTimeout },
    );
    if (token !== generation) {
      return false;
    }
    const at = now();
    if (sourceHash !== hash) {
      // Legacy keyring migration (`get-databasehash.oldHash`): move the entry
      // to the new hash so future sessions find it without the hint.
      await store.putAssociation(hash, {
        ...record,
        hash,
        lastUsed: at,
      });
      await store.deleteAssociation(sourceHash);
    } else {
      await store.touchAssociation(hash, at);
    }
    association = { id: record.id, key: record.key };
    return true;
  }

  async function runSession(
    token: number,
    options: SessionHandshakeOptions,
  ): Promise<ConnectionSnapshot> {
    lastError = null;
    try {
      await requireClientId();
      if (token !== generation) {
        return store.snapshot();
      }
      updateSnapshot({
        state: "CONNECTING",
        protocolVersion: SUPPORTED_PROTOCOL_VERSION,
        lastError: null,
      });

      let hello: HostHelloResponse;
      try {
        hello = await withTimeout(
          transport.connect(),
          defaultTimeout,
          () =>
            makeProtocolError(
              KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
              "Native connection timed out",
            ),
        );
      } catch (cause) {
        throw asProtocolError(cause, KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED);
      }
      if (token !== generation) {
        return store.snapshot();
      }
      if (
        !hello ||
        typeof hello.protocolVersion !== "number" ||
        hello.protocolVersion < SUPPORTED_PROTOCOL_VERSION
      ) {
        throw makeProtocolError(
          KpxcErrorCode.KEY_CHANGE_FAILED,
          `Native host protocol version ${String(
            hello?.protocolVersion,
          )} is older than ${SUPPORTED_PROTOCOL_VERSION}`,
        );
      }

      updateSnapshot({
        appRunning: hello.appRunning === true,
        appVersion: hello.appVersion ?? null,
        hostVersion: hello.hostVersion ?? null,
        protocolVersion: hello.protocolVersion,
        locked: hello.locked === true,
        databaseHash: hello.databaseHash ?? null,
      });

      if (hello.appRunning !== true) {
        // The host stays connected while the app is down. Never trust a single
        // `hello` snapshot here: a host that was spawned a moment ago answers
        // from a status cache its first app probe has not filled yet, and an
        // on-demand credential action must not wait for a status push (which
        // can race this handshake) or the 20 s heartbeat. Ask the host once —
        // it owns liveness — so recovery costs one round trip (§6.2).
        const status = await probeAppStatus();
        if (token !== generation) {
          return store.snapshot();
        }
        if (status !== null && status.appRunning === true) {
          hello = mergeObservedStatus(hello, status);
          updateSnapshot({
            appRunning: true,
            appVersion: hello.appVersion ?? null,
            locked: hello.locked === true,
            databaseHash: hello.databaseHash ?? null,
          });
        }
      }

      if (hello.appRunning !== true) {
        // No keys yet; actions fail fast until the host reports the app up.
        clearKeys();
        updateSnapshot({
          state: "READY",
          appRunning: false,
          databaseOpen: false,
          locked: hello.locked === true,
          associated: false,
          databaseHash: hello.databaseHash ?? null,
          attempt: 0,
          lastError: null,
        });
        return store.snapshot();
      }

      updateSnapshot({ state: "HANDSHAKING", lastError: null });
      await changePublicKeys(token);
      if (token !== generation) {
        return store.snapshot();
      }

      let hashResponse: DatabaseHashResponse;
      try {
        hashResponse = await fetchDatabaseHashNow(options.triggerUnlock === true);
      } catch (cause) {
        const error = asProtocolError(cause);
        if (error.code === KpxcErrorCode.DATABASE_NOT_OPENED) {
          // Keys are valid; the database is merely locked. `database-unlocked`
          // or a triggerUnlock action resumes from here.
          sessionValid = true;
          noteLocked(error);
          return store.snapshot();
        }
        throw error;
      }
      if (token !== generation) {
        return store.snapshot();
      }

      const hash = hashResponse.hash;
      updateSnapshot({
        databaseHash: hash,
        databaseOpen: true,
        locked: false,
        associated: false,
        lastError: null,
      });

      try {
        const ok = await testAssociateNow(token, hashResponse.oldHash);
        if (token !== generation) {
          return store.snapshot();
        }
        associated = ok;
      } catch (cause) {
        const error = asProtocolError(cause, KpxcErrorCode.ASSOCIATION_FAILED);
        if (error.code === KpxcErrorCode.DATABASE_NOT_OPENED) {
          sessionValid = true;
          noteLocked(error);
          return store.snapshot();
        }
        if (error.code !== KpxcErrorCode.ASSOCIATION_FAILED) {
          throw error;
        }
        // A stale/unknown association is not a connection failure: stay READY
        // but unassociated so the UI can ask the user to associate again.
        associated = false;
        association = null;
        lastError = error;
      }

      sessionValid = true;
      updateSnapshot({
        state: "READY",
        appRunning: true,
        databaseOpen: true,
        locked: false,
        associated,
        databaseHash: hash,
        attempt: 0,
        lastError,
      });
      return store.snapshot();
    } catch (cause) {
      return failSession(token, cause);
    }
  }

  function failSession(token: number, cause: unknown): ConnectionSnapshot {
    const error = asProtocolError(cause);
    lastError = error;
    if (token === generation) {
      if (error.code !== KpxcErrorCode.DATABASE_NOT_OPENED) {
        clearKeys();
      }
      const locked = error.code === KpxcErrorCode.DATABASE_NOT_OPENED;
      updateSnapshot({
        state: locked ? "LOCKED" : "DISCONNECTED",
        locked,
        databaseOpen: false,
        associated: false,
        lastError: error,
      });
    }
    return store.snapshot();
  }

  async function ensureSession(
    options: SessionHandshakeOptions = {},
  ): Promise<ConnectionSnapshot> {
    if (inFlight) {
      return inFlight;
    }
    const snapshot = store.snapshot();
    if (snapshot.state === "READY" && sessionValid) {
      return snapshot;
    }
    if (snapshot.state === "LOCKED" && options.triggerUnlock !== true) {
      return snapshot;
    }

    const token = ++generation;
    let promise: Promise<ConnectionSnapshot>;
    promise = runSession(token, options)
      .catch((cause: unknown) => failSession(token, cause))
      .finally(() => {
        if (inFlight === promise) {
          inFlight = null;
        }
      });
    inFlight = promise;
    return promise;
  }

  // --- encrypted requests --------------------------------------------------

  async function sendEncryptedNow<T>(
    action: KpxcActionName,
    buildInner: (context: { nonce: B64; clientID: B64 }) => unknown,
    options: {
      triggerUnlock?: boolean;
      requestID?: string;
      timeoutMs?: number;
    } = {},
  ): Promise<T> {
    const currentKeys = keys;
    if (!currentKeys) {
      // The hard rule: never send an encrypted action without a server key.
      throw makeProtocolError(
        KpxcErrorCode.CLIENT_PUBLIC_KEY_NOT_RECEIVED,
        "No session public key; run change-public-keys first",
      );
    }
    if (!transport.connected) {
      throw makeProtocolError(
        KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
        "Native transport is not connected",
      );
    }
    const id = await requireClientId();
    const nonce = newRandomNonce(randomBytes);
    const requestNonce = encodeBase64(nonce);
    const expectedNonce = incrementNonceBase64(requestNonce);
    let inner: unknown;
    try {
      inner = buildInner({ nonce: requestNonce, clientID: id });
    } catch (cause) {
      throw asProtocolError(cause, KpxcErrorCode.CANNOT_ENCRYPT_MESSAGE);
    }
    const frame = buildEncryptedRequestFrame({
      action,
      inner,
      nonce,
      clientID: id,
      keys: currentKeys,
      requestID: options.requestID,
      triggerUnlock: options.triggerUnlock,
    });
    const pending: EncryptedPending = {
      kind: "encrypted",
      action,
      requestNonce,
      expectedNonce,
      requestID: options.requestID,
      keys: {
        clientSecretKey: currentKeys.clientSecretKey,
        serverPublicKey: currentKeys.serverPublicKey,
      },
      settled: false,
      timer: null,
      resolve: () => undefined,
      reject: () => undefined,
    };
    const promise = registerPending(
      pending,
      options.timeoutMs ??
        (options.triggerUnlock ? longTimeout : defaultTimeout),
    );
    sendFrame(frame, pending);
    return (await promise) as T;
  }

  async function request<T>(options: SessionRequestOptions): Promise<T> {
    const snapshot = await ensureSession({
      triggerUnlock: options.triggerUnlock === true,
    });
    if (!snapshot.appRunning) {
      throw makeProtocolError(
        KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
        "friendlypass is not running",
      );
    }
    if (snapshot.state === "LOCKED") {
      throw (
        snapshot.lastError ??
        makeProtocolError(KpxcErrorCode.DATABASE_NOT_OPENED)
      );
    }
    if (snapshot.state !== "READY") {
      throw (
        snapshot.lastError ??
        makeProtocolError(
          KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
          "Session is not ready",
        )
      );
    }
    if (options.requiresAssociation && !snapshot.associated) {
      throw (
        snapshot.lastError?.code === KpxcErrorCode.ASSOCIATION_FAILED
          ? snapshot.lastError
          : makeProtocolError(
              KpxcErrorCode.ASSOCIATION_FAILED,
              "This browser is not associated with the current database",
            )
      );
    }
    if (!keys || !sessionValid) {
      throw makeProtocolError(
        KpxcErrorCode.CLIENT_PUBLIC_KEY_NOT_RECEIVED,
        "No session public key; handshake required",
      );
    }
    return sendEncryptedNow<T>(options.action, options.buildInner, {
      triggerUnlock: options.triggerUnlock,
      requestID: options.requestID,
      timeoutMs: options.timeoutMs,
    });
  }

  // --- public surface ------------------------------------------------------

  function handleFrameImpl(frame: HostToExtensionFrame): void {
    if (isPushFrame(frame)) {
      handlePushFrame(frame);
      return;
    }
    if (isErrorFrame(frame)) {
      handleErrorFrame(frame);
      return;
    }
    if (isHostPingResponse(frame)) {
      handlePingFrame(frame);
      return;
    }
    if (isSuccessFrame(frame)) {
      handleSuccessFrame(frame);
      return;
    }
    const candidate = frame as unknown as Record<string, unknown>;
    if (candidate["action"] === KpxcAction.CHANGE_PUBLIC_KEYS) {
      handleHandshakeFrame(candidate);
      return;
    }
    // Bare `{}` (asynchronous generate-password placeholder), host responses
    // routed here by mistake, and unknown pushes are ignored by design.
  }

  function handleConnectImpl(): void {
    // A new port invalidates any key material from the previous one. Pending
    // requests were already rejected by onDisconnect; this is defensive.
    clearKeys();
    updateSnapshot({ state: "HANDSHAKING", lastError: null });
    // If the transport reconnected on its own (watchdog/backoff), rebuild the
    // session without waiting for a user action. During an `ensureSession()`
    // initiated connect this joins the in-flight handshake.
    scheduleRevalidate();
  }

  function handleDisconnectImpl(
    reason: TransportDisconnectReason,
    detail?: string,
  ): void {
    invalidateSession();
    const error = makeProtocolError(
      KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
      detail ?? `Native connection lost (${reason})`,
    );
    lastError = error;
    void rejectAllPending(error);
    updateSnapshot({
      state: "DISCONNECTED",
      appRunning: false,
      databaseOpen: false,
      locked: false,
      associated: false,
      databaseHash: null,
      lastError: error,
    });
  }

  const transportHandlers: TransportHandlers = {
    onFrame(frame) {
      handleFrameImpl(frame);
    },
    onDisconnect(reason, detail) {
      handleDisconnectImpl(reason, detail);
    },
    onConnect() {
      handleConnectImpl();
    },
  };

  const session: ProtocolSession = {
    transportHandlers,

    snapshot() {
      return store.snapshot();
    },

    async getClientId() {
      return requireClientId();
    },

    ensureSession,

    request,

    reset(reason: string) {
      invalidateSession();
      const error = makeProtocolError(
        KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
        `Session reset: ${reason}`,
      );
      lastError = error;
      void rejectAllPending(error);
      updateSnapshot({
        state: "DISCONNECTED",
        appRunning: false,
        databaseOpen: false,
        locked: false,
        associated: false,
        databaseHash: null,
        lastError: error,
      });
    },

    async getDatabaseHash() {
      const snapshot = await ensureSession();
      if (!snapshot.appRunning) {
        throw makeProtocolError(
          KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
          "friendlypass is not running",
        );
      }
      if (snapshot.state === "LOCKED") {
        throw (
          snapshot.lastError ??
          makeProtocolError(KpxcErrorCode.DATABASE_NOT_OPENED)
        );
      }
      if (snapshot.state !== "READY") {
        throw (
          snapshot.lastError ??
          makeProtocolError(
            KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
            "Session is not ready",
          )
        );
      }
      if (!keys || !sessionValid) {
        throw makeProtocolError(
          KpxcErrorCode.CLIENT_PUBLIC_KEY_NOT_RECEIVED,
          "No session public key; handshake required",
        );
      }
      const response = await fetchDatabaseHashNow(false);
      const previousHash = store.snapshot().databaseHash;
      const hashChanged =
        previousHash !== null && previousHash !== response.hash;
      if (hashChanged) {
        // The database was switched outside a push (e.g. the extension woke up
        // after a change). The old association no longer applies.
        associated = false;
        association = null;
      }
      updateSnapshot({
        databaseHash: response.hash,
        databaseOpen: true,
        locked: false,
        ...(hashChanged ? { associated: false } : {}),
      });
      return response.hash;
    },

    async associate() {
      const snapshot = await ensureSession({ triggerUnlock: true });
      if (!snapshot.appRunning) {
        throw makeProtocolError(
          KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
          "friendlypass is not running",
        );
      }
      if (snapshot.state === "LOCKED") {
        throw (
          snapshot.lastError ??
          makeProtocolError(KpxcErrorCode.DATABASE_NOT_OPENED)
        );
      }
      if (snapshot.state !== "READY") {
        throw (
          snapshot.lastError ??
          makeProtocolError(
            KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
            "Session is not ready",
          )
        );
      }
      if (!keys || !sessionValid) {
        throw makeProtocolError(
          KpxcErrorCode.CLIENT_PUBLIC_KEY_NOT_RECEIVED,
          "No session public key; handshake required",
        );
      }
      const sessionKeys = keys;
      const identity = makeIdentityKeyPair();
      if (identity.publicKey.length !== KEY_BYTES) {
        throw makeProtocolError(
          KpxcErrorCode.ENCRYPTION_KEY_UNRECOGNIZED,
          "Identity keypair generation failed",
        );
      }
      const idKey = encodeBase64(identity.publicKey);
      const response = await sendEncryptedNow<AssociateResponse>(
        KpxcAction.ASSOCIATE,
        () =>
          buildAssociateInner({
            key: encodeBase64(sessionKeys.clientPublicKey),
            idKey,
          }),
        { triggerUnlock: true, timeoutMs: longTimeout },
      );
      if (typeof response.id !== "string" || response.id.length === 0) {
        throw makeProtocolError(
          KpxcErrorCode.ASSOCIATION_FAILED,
          "Association response has no id",
        );
      }
      if (!/^[0-9a-f]{64}$/.test(response.hash ?? "")) {
        throw makeProtocolError(
          KpxcErrorCode.DATABASE_HASH_NOT_RECEIVED,
          "Association response has no database hash",
        );
      }
      const at = now();
      const record: AssociationRecord = {
        id: response.id,
        key: idKey,
        hash: response.hash,
        created: at,
        lastUsed: at,
      };
      await store.putAssociation(response.hash, record);
      associated = true;
      association = { id: record.id, key: record.key };
      lastError = null;
      updateSnapshot({
        state: "READY",
        appRunning: true,
        databaseOpen: true,
        locked: false,
        associated: true,
        databaseHash: response.hash,
        lastError: null,
      });
      return { id: response.id, hash: response.hash };
    },

    async testAssociate() {
      const snapshot = await ensureSession();
      if (!snapshot.databaseHash) {
        throw makeProtocolError(
          KpxcErrorCode.ASSOCIATION_FAILED,
          "No database hash; cannot test the association",
        );
      }
      if (snapshot.state !== "READY") {
        throw (
          snapshot.lastError ??
          makeProtocolError(KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED)
        );
      }
      const ok = await testAssociateNow(generation, undefined);
      if (!ok || !association) {
        associated = false;
        throw makeProtocolError(
          KpxcErrorCode.ASSOCIATION_FAILED,
          "This browser is not associated with the current database",
        );
      }
      associated = true;
      lastError = null;
      updateSnapshot({ associated: true, lastError: null });
      return { id: association.id, hash: snapshot.databaseHash };
    },

    currentAssociation() {
      return association ? { ...association } : null;
    },

    async connectionKeys() {
      const keyRing = await store.keyRing();
      return Object.values(keyRing).map((record) => ({
        id: record.id,
        key: record.key,
      }));
    },

    markLocked() {
      noteLocked();
    },

    markUnlocked() {
      invalidateSession();
      updateSnapshot({
        state: "HANDSHAKING",
        locked: false,
        databaseOpen: false,
        associated: false,
        lastError: null,
      });
      scheduleRevalidate();
    },

    handleFrame(frame: HostToExtensionFrame) {
      handleFrameImpl(frame);
    },

    handleConnect() {
      handleConnectImpl();
    },

    handleDisconnect(reason: TransportDisconnectReason, detail?: string) {
      handleDisconnectImpl(reason, detail);
    },

    get lastError() {
      return lastError;
    },
  };

  return session;
}
