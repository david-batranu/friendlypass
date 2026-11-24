/**
 * friendlypass browser extension — shared types.
 *
 * This file is the TypeScript mirror of `protocol/ACTIONS.md` (protocol
 * version 1). It contains:
 *
 *   1. the KeePassXC-Browser wire protocol (outer native-messaging frames and
 *      decrypted inner messages) that the official extension also speaks;
 *   2. the friendlypass host-level additions (`ping`, `hello`, host error
 *      codes, `database-*` push messages);
 *   3. the typed *internal* message API used between the service worker,
 *      content scripts and the popup/options pages.
 *
 * Ownership: WP3 (see `protocol/OWNERSHIP.md`). The wire shapes in sections 1
 * and 2 are frozen by `protocol/ACTIONS.md`; do not change them without the
 * architect updating the protocol version and golden fixtures.
 *
 * Never log decrypted inner messages: they contain plaintext credentials.
 */

// ---------------------------------------------------------------------------
// Primitive aliases
// ---------------------------------------------------------------------------

/** Standard Base64 (RFC 4648, with padding), as produced by `tweetnacl-util`. */
export type B64 = string;

/** Dashless RFC 4122 UUID, 32 lowercase hex characters (KeePassXC format). */
export type HexUuid = string;

/** SHA-256 hex digest, 64 lowercase hex characters (database hash). */
export type DbHash = string;

/** The protocol version in `protocol/version`; carried by host-level actions. */
export const SUPPORTED_PROTOCOL_VERSION = 1;

/** Native messaging host name registered with the browser. */
export const NATIVE_HOST_NAME = "org.friendlypass.browser";

/** Maximum accepted native-messaging frame payload (1 MiB). */
export const MAX_FRAME_BYTES = 1024 * 1024;

// ---------------------------------------------------------------------------
// Error codes (frozen — KeePassXC BrowserMessageBuilder.h / client.js kpErrors)
// ---------------------------------------------------------------------------

/**
 * KeePassXC-Browser error codes. Values are wire values and MUST NOT change.
 * Emitted as a JSON *string* in `errorCode` (KeePassXC uses
 * `QString::number(errorCode)`).
 */
export const KpxcErrorCode = {
  UNKNOWN_ERROR: 0,
  DATABASE_NOT_OPENED: 1,
  DATABASE_HASH_NOT_RECEIVED: 2,
  CLIENT_PUBLIC_KEY_NOT_RECEIVED: 3,
  CANNOT_DECRYPT_MESSAGE: 4,
  TIMEOUT_OR_NOT_CONNECTED: 5,
  ACTION_CANCELLED_OR_DENIED: 6,
  CANNOT_ENCRYPT_MESSAGE: 7,
  ASSOCIATION_FAILED: 8,
  KEY_CHANGE_FAILED: 9,
  ENCRYPTION_KEY_UNRECOGNIZED: 10,
  NO_SAVED_DATABASES_FOUND: 11,
  INCORRECT_ACTION: 12,
  EMPTY_MESSAGE_RECEIVED: 13,
  NO_URL_PROVIDED: 14,
  NO_LOGINS_FOUND: 15,
  NO_GROUPS_FOUND: 16,
  CANNOT_CREATE_NEW_GROUP: 17,
  NO_VALID_UUID_PROVIDED: 18,
  ACCESS_TO_ALL_ENTRIES_DENIED: 19,
  PASSKEYS_ATTESTATION_NOT_SUPPORTED: 20,
  PASSKEYS_CREDENTIAL_IS_EXCLUDED: 21,
  PASSKEYS_REQUEST_CANCELED: 22,
  PASSKEYS_INVALID_USER_VERIFICATION: 23,
  PASSKEYS_EMPTY_PUBLIC_KEY: 24,
  PASSKEYS_INVALID_URL_PROVIDED: 25,
  PASSKEYS_ORIGIN_NOT_ALLOWED: 26,
  PASSKEYS_DOMAIN_IS_NOT_VALID: 27,
  PASSKEYS_DOMAIN_RPID_MISMATCH: 28,
  PASSKEYS_NO_SUPPORTED_ALGORITHMS: 29,
  PASSKEYS_WAIT_FOR_LIFETIMER: 30,
  PASSKEYS_UNKNOWN_ERROR: 31,
  PASSKEYS_INVALID_CHALLENGE: 32,
  PASSKEYS_INVALID_USER_ID: 33,
  CANNOT_USE_REFERENCES: 34,
  PASSKEYS_EVAL_BY_CREDENTIAL_NOT_SUPPORTED: 35,
  PASSKEYS_EVAL_BY_CREDENTIAL_NOT_EMPTY: 36,
  PASSKEYS_EVAL_BY_CREDENTIAL_NOT_FOUND: 37,
} as const;

export type KpxcErrorCodeValue =
  (typeof KpxcErrorCode)[keyof typeof KpxcErrorCode];

/**
 * friendlypass host-level error codes (extension `ping`/`hello` and framing).
 * 1000+ never collides with a KeePassXC code; the host emits them in the same
 * `{action, error, errorCode}` envelope so clients can reuse one parser.
 */
export const HostErrorCode = {
  /** Frame length prefix exceeded `MAX_FRAME_BYTES`; frame body discarded. */
  FRAME_TOO_LARGE: 1001,
  /** Frame was not valid UTF-8 JSON, or was not a JSON object. */
  MALFORMED_FRAME: 1002,
  /** Unencrypted action the host does not implement (not forwarded). */
  UNKNOWN_HOST_ACTION: 1003,
  /** Unexpected failure inside the native host process. */
  HOST_INTERNAL_ERROR: 1004,
  /** The app socket stayed unavailable past the forwarding grace period. */
  APP_UNAVAILABLE: 1005,
  /** Host-level action received over a channel that requires encryption. */
  ENCRYPTION_REQUIRED: 1006,
} as const;

export type HostErrorCodeValue =
  (typeof HostErrorCode)[keyof typeof HostErrorCode];

export type AnyErrorCode = KpxcErrorCodeValue | HostErrorCodeValue;

/** Normalised error carried by internal APIs (never by the wire). */
export interface ProtocolError {
  code: AnyErrorCode | number;
  /** Stable symbolic name, e.g. "ASSOCIATION_FAILED". */
  name: string;
  /** Human-readable English text; mirrors the KeePassXC message. */
  message: string;
  /** Whether retrying the same request can plausibly succeed. */
  retryable: boolean;
}

// ---------------------------------------------------------------------------
// Action names
// ---------------------------------------------------------------------------

/** KeePassXC-Browser actions implemented by friendlypass protocol v1. */
export const KpxcAction = {
  CHANGE_PUBLIC_KEYS: "change-public-keys",
  GET_DATABASEHASH: "get-databasehash",
  ASSOCIATE: "associate",
  TEST_ASSOCIATE: "test-associate",
  GET_LOGINS: "get-logins",
  SET_LOGIN: "set-login",
  GET_TOTP: "get-totp",
  GET_DATABASE_GROUPS: "get-database-groups",
  LOCK_DATABASE: "lock-database",
  GENERATE_PASSWORD: "generate-password",
} as const;

export type KpxcActionName = (typeof KpxcAction)[keyof typeof KpxcAction];

/** friendlypass host-level actions, answered without touching the app. */
export const HostAction = {
  PING: "ping",
  HELLO: "hello",
} as const;

export type HostActionName = (typeof HostAction)[keyof typeof HostAction];

/** App → extension push messages (unencrypted, no nonce). */
export const PushAction = {
  DATABASE_LOCKED: "database-locked",
  DATABASE_UNLOCKED: "database-unlocked",
  DATABASE_CHANGED: "database-changed",
} as const;

export type PushActionName = (typeof PushAction)[keyof typeof PushAction];

// ---------------------------------------------------------------------------
// Outer native-messaging frames (plaintext JSON on the stdio channel)
// ---------------------------------------------------------------------------

/** `{id, key}` pair identifying a database association. */
export interface ConnectionKey {
  /** Association id returned by `associate` (e.g. "chrome-laptop"). */
  id: string;
  /** Base64 X25519 identification public key. */
  key: B64;
}

export interface ChangePublicKeysRequestFrame {
  action: typeof KpxcAction.CHANGE_PUBLIC_KEYS;
  /** Base64 X25519 session public key (32 bytes). */
  publicKey: B64;
  /** Base64 nonce (24 bytes). */
  nonce: B64;
  /** Opaque Base64 24-byte client id; regenerated per session by upstream. */
  clientID: B64;
}

/** Any encrypted (inner-message) request frame. */
export interface EncryptedRequestFrame {
  action: KpxcActionName;
  /** Base64 `crypto_box_easy` ciphertext of the UTF-8 JSON inner message. */
  message: B64;
  /** Base64 24-byte request nonce. */
  nonce: B64;
  /** Opaque Base64 24-byte client id. */
  clientID: B64;
  /** Echoed by `generate-password` error replies. */
  requestID?: string;
  /** String "true" asks the app to raise its unlock UI. */
  triggerUnlock?: "true";
}

export type NativeRequestFrame =
  | ChangePublicKeysRequestFrame
  | EncryptedRequestFrame;

/** Encrypted successful reply. */
export interface NativeSuccessFrame {
  action: KpxcActionName;
  /** Base64 ciphertext of the inner JSON response. */
  message: B64;
  /** Request nonce incremented little-endian by one. */
  nonce: B64;
}

/**
 * Unencrypted error reply. `errorCode` is a string on the wire.
 * Error replies never carry a nonce; correlate them by `action`.
 */
export interface NativeErrorFrame {
  action: string;
  error: string;
  errorCode: `${number}`;
}

export interface DatabaseLockedPush {
  action: typeof PushAction.DATABASE_LOCKED;
}

export interface DatabaseUnlockedPush {
  action: typeof PushAction.DATABASE_UNLOCKED;
}

export interface DatabaseChangedPush {
  action: typeof PushAction.DATABASE_CHANGED;
  /** New database hash when it changed, otherwise omitted. */
  hash?: DbHash;
}

export type NativePushFrame =
  | DatabaseLockedPush
  | DatabaseUnlockedPush
  | DatabaseChangedPush;

// ---------------------------------------------------------------------------
// Host-level actions (unencrypted, answered by friendlypass-browser-host)
// ---------------------------------------------------------------------------

export interface HostPingRequest {
  action: typeof HostAction.PING;
  /** Optional client nonce, echoed verbatim to measure round-trip time. */
  nonce?: B64;
}

export interface HostHelloRequest {
  action: typeof HostAction.HELLO;
  clientID?: B64;
  extensionVersion?: string;
  /**
   * Ask the host to push an unsolicited `ping` frame whenever `appRunning`
   * changes. Additive; hosts that do not support it simply stay quiet and the
   * 20 s heartbeat still converges.
   */
  statusPush?: boolean;
}

export type HostRequestFrame = HostPingRequest | HostHelloRequest;

export interface HostStatus {
  /** True when the host currently has a live socket to the app. */
  appRunning: boolean;
  /** Real friendlypass application version, null when the app is down. */
  appVersion: string | null;
  /** True/false when known, null when the app is down or still handshaking. */
  locked: boolean | null;
  /** Database hash when unlocked and known, otherwise null. */
  databaseHash: DbHash | null;
}

export interface HostPingResponse extends HostStatus {
  action: typeof HostAction.PING;
  success: "true";
  /** Protocol version from `protocol/version` (currently 1). */
  protocolVersion: number;
  /** Version of the native host binary. */
  hostVersion: string;
  /** Echo of the request nonce, when one was supplied. */
  nonce?: B64;
}

export interface HostHelloResponse extends HostStatus {
  action: typeof HostAction.HELLO;
  success: "true";
  protocolVersion: number;
  hostVersion: string;
  /**
   * Host-generated id for this stdio connection. Stable for the lifetime of
   * the native port; not a cryptographic session.
   */
  sessionId: string;
  /** OS process id of the host, useful in diagnostics. */
  hostPid?: number;
}

/** Host-originated error, same envelope as KeePassXC errors plus a marker. */
export interface HostErrorFrame {
  action: string;
  error: string;
  errorCode: `${number}`;
  hostError: true;
}

export type HostResponseFrame = HostPingResponse | HostHelloResponse;

/** Everything the host may write to stdout. */
export type HostToExtensionFrame =
  | NativeSuccessFrame
  | NativeErrorFrame
  | HostResponseFrame
  | HostErrorFrame
  | NativePushFrame;

// ---------------------------------------------------------------------------
// Decrypted inner messages
// ---------------------------------------------------------------------------

/** Shared prefix of every successful inner response. */
export interface InnerSuccessBase {
  /** KeePassXC-compatible feature version string, e.g. "2.8.0". */
  version: string;
  success: "true";
  /** Base64 response nonce = request nonce incremented by one. */
  nonce: B64;
}

// --- requests --------------------------------------------------------------

export interface GetDatabaseHashRequest {
  action: typeof KpxcAction.GET_DATABASEHASH;
  /**
   * Deprecated: the app injects its own database hash before dispatch. Clients
   * may send the list of known keyring hashes; servers ignore it.
   */
  connectedKeys?: string[];
}

export interface AssociateRequest {
  action: typeof KpxcAction.ASSOCIATE;
  /** Base64 of the session public key used for this connection. */
  key: B64;
  /** Base64 identification public key to store for future sessions. */
  idKey?: B64;
}

export interface TestAssociateRequest {
  action: typeof KpxcAction.TEST_ASSOCIATE;
  id: string;
  key: B64;
}

export interface GetLoginsRequest {
  action: typeof KpxcAction.GET_LOGINS;
  /** Association id for the active database. */
  id?: string;
  /** Page URL, including scheme and path. */
  url: string;
  /** Form action URL when the form posts elsewhere. */
  submitUrl?: string;
  /** String "true" for HTTP Basic/Digest lookups. */
  httpAuth?: "true";
  /** All associations known to the extension (lets the app find the DB). */
  keys?: ConnectionKey[];
}

export interface SetLoginRequest {
  action: typeof KpxcAction.SET_LOGIN;
  id?: string;
  login: string;
  password: string;
  url: string;
  submitUrl?: string;
  /** Present when updating an existing entry. */
  uuid?: HexUuid;
  group?: string;
  groupUuid?: HexUuid;
  /** String "true" asks the app to download a favicon for a new entry. */
  downloadFavicon?: "true";
}

export interface GetTotpRequest {
  action: typeof KpxcAction.GET_TOTP;
  uuid: HexUuid;
}

export interface GetDatabaseGroupsRequest {
  action: typeof KpxcAction.GET_DATABASE_GROUPS;
}

export interface LockDatabaseRequest {
  action: typeof KpxcAction.LOCK_DATABASE;
}

/**
 * Unlike other actions, `generate-password` carries bookkeeping fields in the
 * *inner* message as well (upstream builds the message from these fields).
 */
export interface GeneratePasswordRequest {
  action: typeof KpxcAction.GENERATE_PASSWORD;
  nonce: B64;
  clientID: B64;
  requestID?: string;
}

export type KpxcInnerRequest =
  | GetDatabaseHashRequest
  | AssociateRequest
  | TestAssociateRequest
  | GetLoginsRequest
  | SetLoginRequest
  | GetTotpRequest
  | GetDatabaseGroupsRequest
  | LockDatabaseRequest
  | GeneratePasswordRequest;

// --- responses -------------------------------------------------------------

export interface DatabaseHashResponse extends InnerSuccessBase {
  hash: DbHash;
  /**
   * Legacy (root + recycle-bin) hash, sent only when migrating an old keyring.
   */
  oldHash?: DbHash;
}

export interface AssociateResponse extends InnerSuccessBase {
  hash: DbHash;
  id: string;
}

export type TestAssociateResponse = AssociateResponse;

export interface CredentialEntry {
  /** Plaintext username (never Base64 on the wire). */
  login: string;
  /** Plaintext password (never Base64 on the wire). */
  password: string;
  /** Entry title. */
  name: string;
  uuid: HexUuid;
  /** Name of the entry's group. */
  group: string;
  /** Current TOTP code, when the entry has a valid TOTP secret. */
  totp?: string;
  /** String "true" when the entry is expired. */
  expired?: "true";
  /** String "true"/"false" when the entry/group opts out of auto-submit. */
  skipAutoSubmit?: "true" | "false";
  /** KeePassXC `KPH: ` string fields, each as a single-key object. */
  stringFields?: Array<Record<string, string>>;
}

export interface GetLoginsResponse extends InnerSuccessBase {
  count: number;
  entries: CredentialEntry[];
  hash: DbHash;
  id: string;
}

export interface SetLoginResponse extends InnerSuccessBase {
  count: null;
  entries: null;
  /** "success" or "error" (KeePassXC uses this field, not `success`). */
  error: "success" | "error";
  hash: DbHash;
}

export interface GetTotpResponse extends InnerSuccessBase {
  /** Current TOTP code; empty string when the entry has no TOTP secret. */
  totp: string;
}

export interface DatabaseGroup {
  name: string;
  uuid: HexUuid;
  children: DatabaseGroup[];
}

/**
 * KeePassXC 2.8.0 wraps the root group array in an object before passing it as
 * the `groups` parameter, so the wire value is `{"groups": [ ... ]}` (one
 * entry: the root group). The official extension reads
 * `response.groups.groups`. Kept intentionally for compatibility.
 */
export interface DatabaseGroupsContainer {
  groups: DatabaseGroup[];
}

export interface GetDatabaseGroupsResponse extends InnerSuccessBase {
  groups: DatabaseGroupsContainer;
}

/** `lock-database` success has no extra parameters. */
export type LockDatabaseResponse = InnerSuccessBase;

export interface GeneratePasswordResponse extends InnerSuccessBase {
  password: string;
  /** Legacy field some clients still read. */
  entries?: string;
}

export type KpxcInnerResponse =
  | DatabaseHashResponse
  | AssociateResponse
  | TestAssociateResponse
  | GetLoginsResponse
  | SetLoginResponse
  | GetTotpResponse
  | GetDatabaseGroupsResponse
  | LockDatabaseResponse
  | GeneratePasswordResponse;

// ---------------------------------------------------------------------------
// Extension connection state machine (protocol/ACTIONS.md §6)
// ---------------------------------------------------------------------------

export type ConnectionState =
  | "DISCONNECTED"
  | "CONNECTING"
  | "HANDSHAKING"
  | "READY"
  | "LOCKED";

/** Backoff schedule in milliseconds, reset on READY. */
export const RECONNECT_BACKOFF_MS = [500, 1000, 2000, 4000, 8000, 15000, 30000] as const;

/** Heartbeat interval and per-ping timeout. */
export const HEARTBEAT_INTERVAL_MS = 20000;
export const HEARTBEAT_TIMEOUT_MS = 3000;
/** Consecutive missed heartbeats that force a reconnect. */
export const HEARTBEAT_MAX_MISSES = 2;
/** `chrome.alarms` watchdog period (Chrome minimum is 30 s). */
export const WATCHDOG_ALARM_PERIOD_MINUTES = 0.5;
/** Default and long request timeouts. */
export const REQUEST_TIMEOUT_MS = 10000;
export const LONG_REQUEST_TIMEOUT_MS = 30000;

export interface ConnectionSnapshot {
  state: ConnectionState;
  /** Host-level `appRunning`; true only while the app socket is live. */
  appRunning: boolean;
  /** True when the app answered `get-databasehash` and a hash is known. */
  databaseOpen: boolean;
  /** True when the database is locked (or the app is down). */
  locked: boolean;
  /** True when `test-associate` succeeded for the current keyring entry. */
  associated: boolean;
  /** Current database hash, when known. */
  databaseHash: DbHash | null;
  hostVersion: string | null;
  appVersion: string | null;
  protocolVersion: number;
  /** Consecutive failed connection attempts, index into the backoff table. */
  attempt: number;
  /** Last error, cleared on READY. */
  lastError: ProtocolError | null;
}

// ---------------------------------------------------------------------------
// Persisted extension state (chrome.storage.local / session)
// ---------------------------------------------------------------------------

export interface AssociationRecord {
  id: string;
  key: B64;
  hash: DbHash;
  created: number;
  lastUsed: number;
}

export interface PersistedState {
  /** Stable per-extension-install client id (Base64 24 bytes). */
  clientId: B64 | null;
  /** Keyring keyed by database hash. */
  keyRing: Record<DbHash, AssociationRecord>;
  settings: ExtensionSettings;
}

export interface ExtensionSettings {
  /** Fill HTTP Basic/Digest credentials automatically. Default false. */
  autoFillHttpAuth: boolean;
  /** Submit forms after filling. Default false. */
  autoFillAndSubmit: boolean;
  /** Ask the app to launch when the extension connects. Default false. */
  launchAppOnConnect: boolean;
  /** Default group for saved entries; empty means the app's default. */
  defaultGroup: string;
  /** Always show the group picker when saving. */
  defaultGroupAlwaysAsk: boolean;
  /** Show diagnostics logging in the service worker console. */
  debugLogging: boolean;
}

// ---------------------------------------------------------------------------
// Internal message API (extension pages/content ↔ service worker)
// ---------------------------------------------------------------------------

/** Every internal message carries this literal so handlers ignore foreign tabs. */
export const INTERNAL_CHANNEL = "friendlypass" as const;
export type InternalChannel = typeof INTERNAL_CHANNEL;

export interface InternalEnvelope<A extends string, P> {
  channel: InternalChannel;
  action: A;
  /** Present for requests; commands from the background omit it. */
  args: P;
  /** Correlation id for logs/diagnostics. */
  requestId: string;
}

export interface InternalOk<T> {
  ok: true;
  value: T;
}

export interface InternalErrorBody {
  code: AnyErrorCode | number | "INTERNAL_ERROR" | "NOT_IMPLEMENTED";
  name: string;
  message: string;
  retryable: boolean;
}

export interface InternalErr {
  ok: false;
  error: InternalErrorBody;
}

export type InternalResult<T> = InternalOk<T> | InternalErr;

export interface StatusSummary {
  connected: boolean;
  appRunning: boolean;
  databaseOpen: boolean;
  locked: boolean;
  associated: boolean;
  databaseHash: DbHash | null;
  state: ConnectionState;
  hostVersion: string | null;
  appVersion: string | null;
  protocolVersion: number;
  error: ProtocolError | null;
}

export interface SaveLoginArgs {
  url: string;
  submitUrl?: string;
  login: string;
  password: string;
  /** Existing entry to update. */
  uuid?: HexUuid;
  group?: string;
  groupUuid?: HexUuid;
}

export interface SaveLoginResult {
  success: boolean;
  /** "success" / "error" or a local failure description. */
  message: string;
}

export interface CreatedGroup {
  name: string;
  uuid: HexUuid;
}

export interface HttpAuthLookupArgs {
  requestId: string;
  url: string;
  realm?: string;
  scheme: string;
  isProxy: boolean;
}

export interface TotpArgs {
  uuid: HexUuid;
  /** Value already known by the caller; returned when the app is too old. */
  fallback?: string;
}

/**
 * A submitted login waiting for the next page (WP4b). Stored in
 * `chrome.storage.session`, keyed by tab; the plaintext password never touches
 * `chrome.storage.local` or a disk-backed store.
 */
export interface PendingCredential {
  /** URL of the page that contained the form. */
  url: string;
  origin: string;
  username: string;
  password: string;
  /** Form action, when it differed from the page URL. */
  submitUrl?: string;
  /** Epoch milliseconds of the submission. */
  submittedAt: number;
}

export interface StoreSubmittedArgs {
  url: string;
  username: string;
  password: string;
  submitUrl?: string;
}

export interface StoreSubmittedResult {
  /** False when the submission was ignored (never-for-site, bad URL, empty). */
  stored: boolean;
}

/**
 * Requests handled by the service worker. `args: void` means "call with no
 * arguments"; `sendBackgroundMessage` enforces that at compile time.
 */
export interface BackgroundRequestMap {
  "status.get": { args: void; result: StatusSummary };
  "status.refresh": { args: { triggerUnlock?: boolean } | void; result: StatusSummary };
  "connection.connect": { args: void; result: StatusSummary };
  "connection.reconnect": { args: void; result: StatusSummary };
  "connection.ping": { args: void; result: HostPingResponse };
  "association.create": { args: void; result: { id: string; hash: DbHash } };
  "logins.get": {
    args: {
      url: string;
      submitUrl?: string;
      httpAuth?: boolean;
      triggerUnlock?: boolean;
    };
    result: CredentialEntry[];
  };
  "logins.save": { args: SaveLoginArgs; result: SaveLoginResult };
  "totp.get": { args: TotpArgs; result: string };
  "password.generate": { args: void; result: string };
  "groups.list": { args: void; result: DatabaseGroup[] };
  "group.create": { args: { name: string }; result: CreatedGroup };
  "database.lock": { args: void; result: StatusSummary };
  "database.unlock": { args: void; result: StatusSummary };
  "httpAuth.lookup": {
    args: HttpAuthLookupArgs;
    result: CredentialEntry | null;
  };
  "httpAuth.choose": {
    args: HttpAuthLookupArgs & { entries: CredentialEntry[] };
    result: CredentialEntry | null;
  };
  "settings.get": { args: void; result: ExtensionSettings };
  "settings.set": { args: Partial<ExtensionSettings>; result: ExtensionSettings };
  "diagnostics.get": { args: void; result: DiagnosticsSnapshot };
  /** Store the pair a form just submitted, before the page can unload. */
  "submit.store": { args: StoreSubmittedArgs; result: StoreSubmittedResult };
  /** Consume the pending pair for the calling tab/frame/page. */
  "submit.pending": { args: { url: string }; result: PendingCredential | null };
  /** Drop the pending pair for the calling tab (save, dismiss). */
  "submit.clear": { args: void; result: void };
  /** Never offer to save on this origin again. */
  "submit.never": { args: { origin: string }; result: void };
}

export type BackgroundRequestAction = keyof BackgroundRequestMap;
export type BackgroundRequestArgs<A extends BackgroundRequestAction> =
  BackgroundRequestMap[A]["args"];
export type BackgroundRequestResult<A extends BackgroundRequestAction> =
  BackgroundRequestMap[A]["result"];

/**
 * Fire-and-forget notifications sent by the service worker to every connected
 * extension context (popup, options, content scripts). They are *not* requests:
 * no response is expected and listeners must never throw on a malformed one.
 *
 * This is an internal API extension (WP3); the wire protocol is unchanged.
 */
export interface BackgroundEventMap {
  /** Emitted on every connection/association/lock transition. */
  "status.changed": StatusSummary;
  /** Full connection snapshot, for diagnostics views. */
  "state.snapshot": ConnectionSnapshot;
}

export type BackgroundEventAction = keyof BackgroundEventMap;
export type BackgroundEventArgs<A extends BackgroundEventAction> =
  BackgroundEventMap[A];

/**
 * Commands sent by the service worker to a content script. Content scripts
 * must not answer with credentials; they only fill or clear.
 */
export interface ContentCommandMap {
  "content.fillLogin": {
    args: { entry: CredentialEntry; frameId?: number };
    result: void;
  };
  "content.fillTotp": { args: { totp: string }; result: void };
  "content.clearCredentials": { args: void; result: void };
  "content.redetectFields": { args: void; result: void };
  "content.showSaveBanner": {
    args: { kind: "create" | "update"; entry?: CredentialEntry };
    result: void;
  };
  "content.showConnectedStatus": {
    args: { status: StatusSummary };
    result: void;
  };
}

export type ContentCommandAction = keyof ContentCommandMap;
export type ContentCommandArgs<A extends ContentCommandAction> =
  ContentCommandMap[A]["args"];
export type ContentCommandResult<A extends ContentCommandAction> =
  ContentCommandMap[A]["result"];

/** Diagnostic ring-buffer entry; never contains secrets. */
export interface DiagnosticEntry {
  at: number;
  level: "debug" | "info" | "warn" | "error";
  /** Host/app action name or internal action name. */
  action: string;
  /** Origin only (no path/query), used to explain site matching. */
  origin?: string;
  message: string;
  errorCode?: number | string;
}

export interface DiagnosticsSnapshot {
  entries: DiagnosticEntry[];
  connection: ConnectionSnapshot;
  host: HostStatus | null;
}
