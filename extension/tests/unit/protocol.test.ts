/**
 * WP3 protocol tests.
 *
 * Covers:
 *  - every golden vector in `protocol/fixtures/*.json` (decrypt with the fixed
 *    keys, and re-build encrypted request frames byte-exactly);
 *  - nonce increment / response-nonce rejection;
 *  - serialised `ensureSession()`, test-associate before credential actions,
 *    re-handshake after a port loss, stale associations, lock/unlock;
 *  - typed actions (get-logins incl. httpAuth, set-login, get-totp, groups,
 *    generate-password, lock) and typed error mapping;
 *  - `state.ts` persistence/events and `urls.ts` normalisation/matching.
 *
 * The fake host below performs the inverse TweetNaCl operation with the fixed
 * fixture keys, so the session is exercised over real crypto without a native
 * port. No test prints a decrypted payload.
 */

import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  buildAssociateInner,
  buildChangePublicKeysFrame,
  buildEncryptedRequestFrame,
  buildGeneratePasswordInner,
  buildGetDatabaseGroupsInner,
  buildGetDatabaseHashInner,
  buildGetLoginsInner,
  buildGetTotpInner,
  buildLockDatabaseInner,
  buildSetLoginInner,
  buildTestAssociateInner,
  createSession,
  decodeBase64,
  encodeBase64,
  incrementNonce,
  incrementNonceBase64,
  openInnerMessage,
  openSuccessFrame,
  sealInnerMessage,
  verifyChangePublicKeysResponse,
} from "../../src/background/session";
import type {
  BoxKeyPair,
  ProtocolSession,
  SessionKeys,
} from "../../src/background/session";
import {
  DEFAULT_SETTINGS,
  MemoryStorageArea,
  createStateStore,
  initialSnapshot,
} from "../../src/background/state";
import {
  associate,
  fetchDatabaseHash,
  generatePassword,
  getDatabaseGroups,
  getLogins,
  getTotp,
  lockDatabase,
  setLogin,
  testAssociate,
} from "../../src/background/actions";
import { errorMessageFor } from "../../src/common/messages";
import {
  KpxcErrorCode,
  type AssociationRecord,
  type HostHelloResponse,
  type HostToExtensionFrame,
  type NativeRequestFrame,
} from "../../src/common/types";
import type {
  NativeTransport,
  TransportHandlers,
} from "../../src/background/transport";
import {
  getBaseDomain,
  getHost,
  getOrigin,
  getPath,
  getPort,
  isSameOrigin,
  isSameSite,
  isSubdomainOf,
  matchUrl,
  normalizeUrl,
  pathMatches,
  sanitizeForLookup,
} from "../../src/common/urls";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FIXTURE_DIR = new URL("../../../protocol/fixtures/", import.meta.url);

interface FixtureVector {
  name: string;
  action: string;
  kind?: string;
  nonceRelation?: "increment" | "echo" | "none";
  request: {
    nonce: string | null;
    plaintextJson: string | null;
    plaintext: Record<string, unknown> | null;
    frame: Record<string, unknown> | null;
  } | null;
  response: {
    nonce: string | null;
    plaintextJson: string | null;
    plaintext: Record<string, unknown> | null;
    frame: Record<string, unknown> | null;
  } | null;
}

interface FixtureDocument {
  keys: {
    client: { publicKey: string; secretKey: string };
    host: { publicKey: string; secretKey: string };
    identity: { publicKey: string; secretKey: string };
  };
  clientID: string;
  database: { databaseHash: string };
  vectors: FixtureVector[];
}

function loadFixture(name: string): FixtureDocument {
  return JSON.parse(
    readFileSync(new URL(name, FIXTURE_DIR), "utf8"),
  ) as FixtureDocument;
}

const changeFixture = loadFixture("change-public-keys.json");
const CLIENT_PUBLIC = decodeBase64(changeFixture.keys.client.publicKey);
const CLIENT_SECRET = decodeBase64(changeFixture.keys.client.secretKey);
const HOST_PUBLIC = decodeBase64(changeFixture.keys.host.publicKey);
const HOST_SECRET = decodeBase64(changeFixture.keys.host.secretKey);
const IDENTITY_PUBLIC = decodeBase64(changeFixture.keys.identity.publicKey);
const IDENTITY_SECRET = decodeBase64(changeFixture.keys.identity.secretKey);
const CLIENT_ID = changeFixture.clientID;
const DB_HASH = changeFixture.database.databaseHash;
const SESSION_KEYPAIR: BoxKeyPair = {
  publicKey: CLIENT_PUBLIC,
  secretKey: CLIENT_SECRET,
};
const IDENTITY_KEYPAIR: BoxKeyPair = {
  publicKey: IDENTITY_PUBLIC,
  secretKey: IDENTITY_SECRET,
};
const CLIENT_KEYS: Pick<SessionKeys, "clientSecretKey" | "serverPublicKey"> = {
  clientSecretKey: CLIENT_SECRET,
  serverPublicKey: HOST_PUBLIC,
};

const fixtureFiles = readdirSync(FIXTURE_DIR)
  .filter((name) => name.endsWith(".json"))
  .sort();
const allFixtures = fixtureFiles.map((name) => ({
  file: name,
  document: loadFixture(name),
}));

function buildInnerForFixture(
  action: string,
  plaintext: Record<string, unknown>,
): unknown {
  switch (action) {
    case "get-databasehash":
      return buildGetDatabaseHashInner({
        connectedKeys: plaintext["connectedKeys"] as string[] | undefined,
      });
    case "associate":
      return buildAssociateInner({
        key: plaintext["key"] as string,
        idKey: plaintext["idKey"] as string | undefined,
      });
    case "test-associate":
      return buildTestAssociateInner({
        id: plaintext["id"] as string,
        key: plaintext["key"] as string,
      });
    case "get-logins":
      return buildGetLoginsInner({
        id: plaintext["id"] as string | undefined,
        url: plaintext["url"] as string,
        submitUrl: plaintext["submitUrl"] as string | undefined,
        httpAuth: plaintext["httpAuth"] as "true" | undefined,
        keys: plaintext["keys"] as Array<{ id: string; key: string }> | undefined,
      });
    case "set-login":
      return buildSetLoginInner({
        id: plaintext["id"] as string | undefined,
        login: plaintext["login"] as string,
        password: plaintext["password"] as string,
        url: plaintext["url"] as string,
        submitUrl: plaintext["submitUrl"] as string | undefined,
        uuid: plaintext["uuid"] as string | undefined,
        group: plaintext["group"] as string | undefined,
        groupUuid: plaintext["groupUuid"] as string | undefined,
        downloadFavicon: plaintext["downloadFavicon"] as "true" | undefined,
      });
    case "get-totp":
      return buildGetTotpInner(plaintext["uuid"] as string);
    case "get-database-groups":
      return buildGetDatabaseGroupsInner();
    case "lock-database":
      return buildLockDatabaseInner();
    case "generate-password":
      return buildGeneratePasswordInner({
        nonce: plaintext["nonce"] as string,
        clientID: plaintext["clientID"] as string,
        requestID: plaintext["requestID"] as string | undefined,
      });
    default:
      throw new Error(`no builder for ${action}`);
  }
}

// ---------------------------------------------------------------------------
// Fake native transport + fake app
// ---------------------------------------------------------------------------

interface HostState {
  locked: boolean;
  associated: boolean;
  associations: AssociationRecord[];
  logins: Array<Record<string, unknown>>;
  groups: unknown;
}

interface Harness {
  session: ProtocolSession;
  store: ReturnType<typeof createStateStore>;
  transport: FakeTransport;
  host: HostState;
  counters: { changePublicKeys: number; testAssociate: number };
  requests: Array<{ frame: Record<string, unknown>; inner: Record<string, unknown> }>;
  corruptNextResponseNonce(): void;
  lastInner(action: string): Record<string, unknown> | undefined;
}

class FakeTransport implements NativeTransport {
  connected = false;
  state: "DISCONNECTED" | "CONNECTING" | "READY" = "DISCONNECTED";
  appRunning = true;
  status: NativeTransport["status"] = {
    state: "DISCONNECTED",
    connected: false,
    appRunning: true,
    hostVersion: "0.1.0",
    appVersion: "0.1.0",
    protocolVersion: 1,
    attempt: 0,
    lastError: null,
    legacyMode: false,
  };
  frames: NativeRequestFrame[] = [];
  handlers!: TransportHandlers;
  responder: ((frame: NativeRequestFrame) => void) | null = null;
  hello: HostHelloResponse;

  constructor(hello: HostHelloResponse) {
    this.hello = hello;
  }

  async connect(): Promise<HostHelloResponse> {
    this.connected = true;
    this.handlers.onConnect();
    return this.hello;
  }

  disconnect(): void {
    this.connected = false;
    this.handlers.onDisconnect("shutdown");
  }

  async ping() {
    return {
      action: "ping" as const,
      success: "true" as const,
      protocolVersion: 1,
      hostVersion: "0.1.0",
      appRunning: true,
      appVersion: "0.1.0",
      locked: false,
      databaseHash: DB_HASH,
    };
  }

  async send(frame: NativeRequestFrame): Promise<void> {
    if (!this.connected) {
      throw new Error("native transport is not connected");
    }
    this.frames.push(frame);
    this.responder?.(frame);
  }

  async request(
    frame: NativeRequestFrame | { action: string; nonce?: string },
  ): Promise<HostToExtensionFrame> {
    await this.send(frame as NativeRequestFrame);
    return {
      action: "ping",
      success: "true",
      protocolVersion: 1,
      hostVersion: "0.1.0",
      appRunning: true,
      appVersion: "0.1.0",
      locked: false,
      databaseHash: null,
    };
  }
}

function helloResponse(overrides: Partial<HostHelloResponse> = {}): HostHelloResponse {
  return {
    action: "hello",
    success: "true",
    protocolVersion: 1,
    hostVersion: "0.1.0",
    appRunning: true,
    appVersion: "0.1.0",
    locked: false,
    databaseHash: null,
    sessionId: "test-session",
    ...overrides,
  };
}

async function createHarness(options: {
  association?: AssociationRecord | null;
  locked?: boolean;
  appRunning?: boolean;
  groups?: unknown;
  clientId?: string | null;
} = {}): Promise<Harness> {
  const storage = new MemoryStorageArea();
  const store = createStateStore({
    storage,
    now: () => 1_763_925_600_000,
    broadcast: () => undefined,
  });
  if (options.clientId !== null) {
    await store.setClientId(options.clientId ?? CLIENT_ID);
  }
  if (options.association) {
    await store.putAssociation(DB_HASH, options.association);
  }

  const transport = new FakeTransport(
    helloResponse({
      appRunning: options.appRunning ?? true,
      locked: options.locked ?? false,
    }),
  );

  const host: HostState = {
    locked: options.locked ?? false,
    associated: false,
    associations: options.association ? [{ ...options.association }] : [],
    logins: [
      {
        login: "alice@example.com",
        password: "correct horse battery staple",
        name: "Example account",
        uuid: "d5ec68c35705b72fde380bd469aa149f",
        group: "KeePassXC-Browser Passwords",
        totp: "123456",
      },
    ],
    groups:
      options.groups ??
      ({
        groups: [
          {
            name: "Root",
            uuid: "bb710c2f876761bb90748cc271ff8fae",
            children: [],
          },
        ],
      } as unknown),
  };
  const counters = { changePublicKeys: 0, testAssociate: 0 };
  const requests: Harness["requests"] = [];
  let corruptNonce = false;
  let session: ProtocolSession;

  function replyError(action: string, code: number): void {
    const frame = {
      action,
      error: errorMessageFor(code),
      errorCode: String(code),
    } as unknown as HostToExtensionFrame;
    session.handleFrame(frame);
  }

  function replySuccess(
    action: string,
    requestNonce: string,
    extra: Record<string, unknown>,
  ): void {
    const responseNonceBytes = corruptNonce
      ? new Uint8Array(24).fill(0x5a)
      : incrementNonce(decodeBase64(requestNonce));
    corruptNonce = false;
    const responseNonce = encodeBase64(responseNonceBytes);
    const inner = {
      version: "2.8.0",
      success: "true",
      nonce: responseNonce,
      ...extra,
    };
    const message = sealInnerMessage(inner, responseNonceBytes, {
      clientSecretKey: HOST_SECRET,
      serverPublicKey: CLIENT_PUBLIC,
    });
    session.handleFrame({
      action,
      message,
      nonce: responseNonce,
    } as unknown as HostToExtensionFrame);
  }

  function handleEncrypted(frame: NativeRequestFrame & { message: string }): void {
    const inner = openInnerMessage(frame.message, frame.nonce, {
      clientSecretKey: HOST_SECRET,
      serverPublicKey: CLIENT_PUBLIC,
    }) as Record<string, unknown>;
    requests.push({ frame: frame as unknown as Record<string, unknown>, inner });
    const action = String(inner["action"]);

    switch (action) {
      case "get-databasehash":
        if (host.locked) {
          replyError(frame.action, KpxcErrorCode.DATABASE_NOT_OPENED);
          return;
        }
        replySuccess(frame.action, frame.nonce, { hash: DB_HASH });
        return;

      case "test-associate": {
        counters.testAssociate += 1;
        const match = host.associations.some(
          (record) =>
            record.id === inner["id"] && record.key === inner["key"],
        );
        if (!match) {
          replyError(frame.action, KpxcErrorCode.ASSOCIATION_FAILED);
          return;
        }
        host.associated = true;
        replySuccess(frame.action, frame.nonce, {
          hash: DB_HASH,
          id: inner["id"],
        });
        return;
      }

      case "associate": {
        const id = "chrome-work-laptop";
        const key = (inner["idKey"] as string | undefined) ?? (inner["key"] as string);
        host.associations.push({
          id,
          key,
          hash: DB_HASH,
          created: 1_763_925_600_000,
          lastUsed: 1_763_925_600_000,
        });
        host.associated = true;
        replySuccess(frame.action, frame.nonce, { hash: DB_HASH, id });
        return;
      }

      case "get-logins":
        if (!host.associated) {
          replyError(frame.action, KpxcErrorCode.ASSOCIATION_FAILED);
          return;
        }
        replySuccess(frame.action, frame.nonce, {
          count: host.logins.length,
          entries: host.logins,
          hash: DB_HASH,
          id: "chrome-work-laptop",
        });
        return;

      case "set-login":
        if (!host.associated) {
          replyError(frame.action, KpxcErrorCode.ASSOCIATION_FAILED);
          return;
        }
        replySuccess(frame.action, frame.nonce, {
          count: null,
          entries: null,
          error: "success",
          hash: DB_HASH,
        });
        return;

      case "get-totp":
        replySuccess(frame.action, frame.nonce, { totp: "492183" });
        return;

      case "get-database-groups":
        replySuccess(frame.action, frame.nonce, { groups: host.groups });
        return;

      case "lock-database":
        host.locked = true;
        replySuccess(frame.action, frame.nonce, {});
        return;

      case "generate-password":
        // Real hosts first write a bare `{}` placeholder, then answer later.
        session.handleFrame({} as unknown as HostToExtensionFrame);
        setTimeout(() => {
          replySuccess(frame.action, frame.nonce, {
            password: "oX9#vK2!mQ7@wZ4$",
          });
        }, 5);
        return;

      default:
        replyError(frame.action, KpxcErrorCode.INCORRECT_ACTION);
    }
  }

  session = createSession({
    transport,
    store,
    now: () => 1_763_925_600_000,
    generateSessionKeyPair: () => SESSION_KEYPAIR,
    generateIdentityKeyPair: () => IDENTITY_KEYPAIR,
    defaultTimeoutMs: 1000,
    longTimeoutMs: 2000,
  });
  transport.handlers = session.transportHandlers;
  transport.responder = (frame) => {
    if (frame.action === "change-public-keys") {
      counters.changePublicKeys += 1;
      const responseNonce = incrementNonceBase64(frame.nonce);
      session.handleFrame({
        action: "change-public-keys",
        version: "2.8.0",
        success: "true",
        nonce: responseNonce,
        publicKey: encodeBase64(HOST_PUBLIC),
      } as unknown as HostToExtensionFrame);
      return;
    }
    handleEncrypted(frame as NativeRequestFrame & { message: string });
  };

  return {
    session,
    store,
    transport,
    host,
    counters,
    requests,
    corruptNextResponseNonce() {
      corruptNonce = true;
    },
    lastInner(action: string) {
      for (let i = requests.length - 1; i >= 0; i -= 1) {
        if (requests[i].inner["action"] === action) {
          return requests[i].inner;
        }
      }
      return undefined;
    },
  };
}

const STANDARD_ASSOCIATION: AssociationRecord = {
  id: "chrome-work-laptop",
  key: changeFixture.keys.identity.publicKey,
  hash: DB_HASH,
  created: 1_763_925_600_000,
  lastUsed: 1_763_925_600_000,
};

// ---------------------------------------------------------------------------
// Golden fixtures
// ---------------------------------------------------------------------------

describe("golden fixtures", () => {
  for (const { file, document } of allFixtures) {
    describe(file, () => {
      for (const vector of document.vectors) {
        it(`${vector.name}: decrypts with the fixed keys and validates nonces`, () => {
          const request = vector.request;
          const response = vector.response;

          if (request?.nonce && request.plaintextJson && request.frame) {
            const decrypted = openInnerMessage(
              request.frame["message"] as string,
              request.nonce,
              CLIENT_KEYS,
            );
            expect(JSON.stringify(decrypted)).toBe(request.plaintextJson);
            expect(decrypted).toEqual(request.plaintext);
          }

          if (response?.nonce && response.plaintextJson && response.frame) {
            const decrypted = openInnerMessage(
              response.frame["message"] as string,
              response.nonce,
              {
                clientSecretKey: HOST_SECRET,
                serverPublicKey: CLIENT_PUBLIC,
              },
            );
            expect(JSON.stringify(decrypted)).toBe(response.plaintextJson);
            expect(decrypted).toEqual(response.plaintext);

            if (request?.nonce) {
              const inner = openSuccessFrame(
                response.frame as never,
                CLIENT_KEYS,
                request.nonce,
              );
              expect(inner.nonce).toBe(response.nonce);
            }
          }

          if (vector.nonceRelation === "increment") {
            expect(request?.nonce).toBeTruthy();
            expect(response?.nonce).toBeTruthy();
            expect(response!.nonce).toBe(incrementNonceBase64(request!.nonce!));
          } else if (vector.nonceRelation === "echo") {
            expect(response?.nonce).toBe(request?.nonce);
          } else if (vector.nonceRelation === "none" && response?.frame) {
            expect("nonce" in response.frame).toBe(false);
          }
        });
      }
    });
  }

  it("re-builds every encrypted request frame byte-exactly", () => {
    let checked = 0;
    for (const { document } of allFixtures) {
      for (const vector of document.vectors) {
        const request = vector.request;
        if (!request?.frame || !request.nonce || !request.plaintext) {
          continue;
        }
        if (typeof request.frame["message"] !== "string") {
          continue;
        }

        const inner = buildInnerForFixture(vector.action, request.plaintext);
        expect(JSON.stringify(inner)).toBe(request.plaintextJson);

        const frame = buildEncryptedRequestFrame({
          action: vector.action as never,
          inner,
          nonce: decodeBase64(request.nonce),
          clientID: document.clientID,
          keys: CLIENT_KEYS,
          requestID: request.frame["requestID"] as string | undefined,
          triggerUnlock: request.frame["triggerUnlock"] === "true",
        });
        expect(frame).toEqual(request.frame);
        expect(JSON.stringify(frame)).toBe(JSON.stringify(request.frame));
        checked += 1;
      }
    }
    expect(checked).toBeGreaterThan(15);
  });

  it("builds the change-public-keys frame byte-exactly", () => {
    const vector = changeFixture.vectors[0];
    const frame = buildChangePublicKeysFrame({
      publicKey: changeFixture.keys.client.publicKey,
      nonce: vector.request!.nonce!,
      clientID: CLIENT_ID,
    });
    expect(frame).toEqual(vector.request!.frame);
  });
});

// ---------------------------------------------------------------------------
// Nonce rules
// ---------------------------------------------------------------------------

describe("nonce increment", () => {
  it("increments little-endian and propagates carry", () => {
    const zero = new Uint8Array(24);
    expect([...incrementNonce(zero).slice(0, 3)]).toEqual([1, 0, 0]);

    const ff = new Uint8Array(24).fill(0xff);
    const wrapped = incrementNonce(ff);
    expect([...wrapped]).toEqual(new Array(24).fill(0));

    const carry = new Uint8Array(24);
    carry[0] = 0xff;
    carry[1] = 0x00;
    const carried = incrementNonce(carry);
    expect([...carried.slice(0, 3)]).toEqual([0, 1, 0]);
  });

  it("rejects a handshake response with a wrong nonce", () => {
    const vector = changeFixture.vectors[0];
    const requestNonce = vector.request!.nonce!;
    const wrong = {
      ...vector.response!.frame,
      nonce: requestNonce,
    };
    expect(() => verifyChangePublicKeysResponse(wrong, requestNonce)).toThrowError(
      expect.objectContaining({ code: KpxcErrorCode.KEY_CHANGE_FAILED }),
    );
  });

  it("rejects an encrypted response whose nonce was not incremented", async () => {
    const harness = await createHarness({ association: STANDARD_ASSOCIATION });
    await harness.session.ensureSession();
    harness.corruptNextResponseNonce();
    await expect(
      harness.session.request({
        action: "get-logins",
        requiresAssociation: true,
        buildInner: () =>
          buildGetLoginsInner({
            id: "chrome-work-laptop",
            url: "https://accounts.example.com/login",
            keys: [{ id: "chrome-work-laptop", key: STANDARD_ASSOCIATION.key }],
          }),
      }),
    ).rejects.toMatchObject({ code: KpxcErrorCode.CANNOT_DECRYPT_MESSAGE });
  });
});

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

describe("session lifecycle", () => {
  it("shares one handshake between concurrent callers and runs test-associate", async () => {
    const harness = await createHarness({ association: STANDARD_ASSOCIATION });
    const [first, second] = await Promise.all([
      harness.session.ensureSession(),
      harness.session.ensureSession(),
      harness.session.ensureSession(),
    ]);

    expect(harness.counters.changePublicKeys).toBe(1);
    expect(harness.counters.testAssociate).toBe(1);
    for (const snapshot of [first, second]) {
      expect(snapshot.state).toBe("READY");
      expect(snapshot.appRunning).toBe(true);
      expect(snapshot.databaseOpen).toBe(true);
      expect(snapshot.associated).toBe(true);
      expect(snapshot.databaseHash).toBe(DB_HASH);
      expect(snapshot.lastError).toBeNull();
    }
    // One handshake, one hash request, one test-associate.
    expect(harness.transport.frames).toHaveLength(3);
    expect(await harness.store.getClientId()).toBe(CLIENT_ID);
  });

  it("creates and persists a stable client id when none exists", async () => {
    const harness = await createHarness({
      association: STANDARD_ASSOCIATION,
      clientId: null,
    });
    const created = await harness.session.getClientId();
    expect(decodeBase64(created)).toHaveLength(24);
    expect(await harness.store.getClientId()).toBe(created);

    await harness.session.ensureSession();
    expect(await harness.store.getClientId()).toBe(created);
    expect(harness.transport.frames[0]).toMatchObject({ clientID: created });
  });

  it("refuses to send an encrypted action when no server key exists", async () => {
    const harness = await createHarness({ association: STANDARD_ASSOCIATION });
    // Make the handshake fail before a host key is learned.
    harness.transport.responder = (frame) => {
      if (frame.action === "change-public-keys") {
        harness.session.handleFrame({
          action: "change-public-keys",
          error: "Key change failed",
          errorCode: "9",
        } as unknown as HostToExtensionFrame);
      }
    };

    await expect(
      harness.session.request({
        action: "get-logins",
        requiresAssociation: false,
        buildInner: () => buildGetLoginsInner({ url: "https://example.com/" }),
      }),
    ).rejects.toMatchObject({ code: KpxcErrorCode.KEY_CHANGE_FAILED });

    // Nothing with a `message` was sent: no plaintext fallback exists.
    expect(harness.transport.frames).not.toHaveLength(0);
    for (const frame of harness.transport.frames) {
      expect(frame.action).toBe("change-public-keys");
      expect("message" in frame).toBe(false);
    }
  });

  it("re-handshakes once and re-runs test-associate after a port loss", async () => {
    const harness = await createHarness({ association: STANDARD_ASSOCIATION });
    const first = await harness.session.ensureSession();
    expect(first.associated).toBe(true);

    harness.transport.handlers.onDisconnect("port-closed", "host died");
    const lost = harness.session.snapshot();
    expect(lost.state).toBe("DISCONNECTED");
    expect(lost.associated).toBe(false);
    expect(lost.lastError?.code).toBe(KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED);

    harness.host.associated = false; // a new connection is unassociated app-side
    harness.transport.connected = false;
    const [recovered, joined] = await Promise.all([
      harness.session.ensureSession(),
      harness.session.ensureSession(),
    ]);
    expect(recovered.state).toBe("READY");
    expect(recovered.associated).toBe(true);
    expect(joined.associated).toBe(true);
    expect(harness.counters.changePublicKeys).toBe(2);
    expect(harness.counters.testAssociate).toBe(2);
  });

  it("stays READY but unassociated when the stored association is stale", async () => {
    const stale: AssociationRecord = {
      ...STANDARD_ASSOCIATION,
      id: "stale-id",
    };
    const harness = await createHarness({ association: stale });
    // The app does not know this association (stale id/key).
    harness.host.associations = [];
    const snapshot = await harness.session.ensureSession();
    expect(snapshot.state).toBe("READY");
    expect(snapshot.associated).toBe(false);
    expect(snapshot.lastError?.code).toBe(KpxcErrorCode.ASSOCIATION_FAILED);

    await expect(
      harness.session.request({
        action: "get-logins",
        requiresAssociation: true,
        buildInner: () => buildGetLoginsInner({ url: "https://example.com/" }),
      }),
    ).rejects.toMatchObject({ code: KpxcErrorCode.ASSOCIATION_FAILED });
  });

  it("associates on demand, persists the keyring and then serves credential actions", async () => {
    const harness = await createHarness({ association: null });
    const ready = await harness.session.ensureSession();
    expect(ready.associated).toBe(false);

    const result = await associate({ session: harness.session });
    expect(result).toEqual({ id: "chrome-work-laptop", hash: DB_HASH });
    expect(harness.session.snapshot().associated).toBe(true);
    expect(harness.session.currentAssociation()).toEqual({
      id: "chrome-work-laptop",
      key: changeFixture.keys.identity.publicKey,
    });

    const keyRing = await harness.store.keyRing();
    expect(keyRing[DB_HASH].id).toBe("chrome-work-laptop");
    expect(keyRing[DB_HASH].key).toBe(changeFixture.keys.identity.publicKey);

    // A later handshake must find and use the persisted association.
    harness.host.associated = false;
    harness.transport.handlers.onDisconnect("port-closed");
    harness.transport.connected = false;
    const second = await harness.session.ensureSession();
    expect(second.associated).toBe(true);
    expect(harness.counters.testAssociate).toBe(1);
  });

  it("reports LOCKED and recovers on database-unlocked", async () => {
    const harness = await createHarness({
      association: STANDARD_ASSOCIATION,
      locked: true,
    });
    const locked = await harness.session.ensureSession();
    expect(locked.state).toBe("LOCKED");
    expect(locked.locked).toBe(true);
    expect(locked.associated).toBe(false);

    await expect(
      harness.session.request({
        action: "get-logins",
        requiresAssociation: true,
        buildInner: () => buildGetLoginsInner({ url: "https://example.com/" }),
      }),
    ).rejects.toMatchObject({ code: KpxcErrorCode.DATABASE_NOT_OPENED });

    harness.host.locked = false;
    harness.session.handleFrame({
      action: "database-unlocked",
    } as unknown as HostToExtensionFrame);
    const recovered = await harness.session.ensureSession();
    expect(recovered.state).toBe("READY");
    expect(recovered.associated).toBe(true);
  });

  it("fails fast while the app is down, without spinning", async () => {
    const harness = await createHarness({
      association: STANDARD_ASSOCIATION,
      appRunning: false,
    });
    const snapshot = await harness.session.ensureSession();
    expect(snapshot.state).toBe("READY");
    expect(snapshot.appRunning).toBe(false);
    expect(harness.transport.frames).toHaveLength(0);

    await expect(
      harness.session.request({
        action: "get-logins",
        buildInner: () => buildGetLoginsInner({ url: "https://example.com/" }),
      }),
    ).rejects.toMatchObject({ code: KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED });
  });

  it("does not re-handshake for a content-only database-changed push", async () => {
    const harness = await createHarness({ association: STANDARD_ASSOCIATION });
    await harness.session.ensureSession();
    const handshakes = harness.counters.changePublicKeys;

    harness.session.handleFrame({
      action: "database-changed",
      hash: DB_HASH,
    } as unknown as HostToExtensionFrame);

    expect(harness.counters.changePublicKeys).toBe(handshakes);
    expect(harness.session.snapshot().state).toBe("READY");
    expect(harness.session.snapshot().associated).toBe(true);
  });

  it("moves READY (app down) back through a handshake when a ping reports the app up", async () => {
    const harness = await createHarness({
      association: STANDARD_ASSOCIATION,
      appRunning: false,
    });
    await harness.session.ensureSession();
    expect(harness.session.snapshot().appRunning).toBe(false);

    harness.transport.hello = { ...harness.transport.hello, appRunning: true };
    harness.session.handleFrame({
      action: "ping",
      success: "true",
      protocolVersion: 1,
      hostVersion: "0.1.0",
      appRunning: true,
      appVersion: "0.1.0",
      locked: false,
      databaseHash: null,
    } as unknown as HostToExtensionFrame);

    const recovered = await harness.session.ensureSession();
    expect(recovered.appRunning).toBe(true);
    expect(recovered.state).toBe("READY");
    expect(recovered.associated).toBe(true);
    expect(harness.counters.changePublicKeys).toBe(1);
  });

  it("treats a host APP_UNAVAILABLE frame as app-down and recovers", async () => {
    const harness = await createHarness({ association: STANDARD_ASSOCIATION });
    await harness.session.ensureSession();
    const original = harness.transport.responder;
    harness.transport.responder = (frame) => {
      if (frame.action === "change-public-keys") {
        return;
      }
      harness.session.handleFrame({
        action: frame.action,
        error: "friendlypass is not running",
        errorCode: "5",
        hostError: true,
      } as unknown as HostToExtensionFrame);
    };

    await expect(
      getLogins(
        { session: harness.session },
        { url: "https://accounts.example.com/" },
      ),
    ).rejects.toMatchObject({ code: KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED });
    expect(harness.session.snapshot().appRunning).toBe(false);

    harness.transport.responder = original;
    harness.host.associated = false;
    const recovered = await harness.session.ensureSession();
    expect(recovered.state).toBe("READY");
    expect(recovered.appRunning).toBe(true);
    expect(recovered.associated).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Typed actions
// ---------------------------------------------------------------------------

describe("typed actions", () => {
  async function associatedHarness(): Promise<Harness> {
    const harness = await createHarness({ association: STANDARD_ASSOCIATION });
    await harness.session.ensureSession();
    return harness;
  }

  it("get-logins returns plaintext entries and sends httpAuth", async () => {
    const harness = await associatedHarness();
    const entries = await getLogins(
      { session: harness.session },
      {
        url: "https://accounts.example.com/login",
        httpAuth: true,
        keys: [{ id: "chrome-work-laptop", key: STANDARD_ASSOCIATION.key }],
      },
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ login: "alice@example.com" });
    expect(entries[0].password).toBe("correct horse battery staple");

    const inner = harness.lastInner("get-logins");
    expect(inner?.["httpAuth"]).toBe("true");
    expect(inner?.["url"]).toBe("https://accounts.example.com/login");
    expect(inner?.["id"]).toBe("chrome-work-laptop");
  });

  it("maps NO_LOGINS_FOUND to a typed error", async () => {
    const harness = await associatedHarness();
    harness.transport.responder = (frame) => {
      if (frame.action === "change-public-keys") return;
      harness.session.handleFrame({
        action: frame.action,
        error: "No logins found",
        errorCode: "15",
      } as unknown as HostToExtensionFrame);
    };
    await expect(
      getLogins(
        { session: harness.session },
        { url: "https://unknown.example/" },
      ),
    ).rejects.toMatchObject({
      code: KpxcErrorCode.NO_LOGINS_FOUND,
      name: "NO_LOGINS_FOUND",
      retryable: false,
    });
  });

  it("de-duplicates entries by uuid", async () => {
    const harness = await associatedHarness();
    harness.host.logins = [
      harness.host.logins[0],
      { ...harness.host.logins[0] },
    ];
    const entries = await getLogins(
      { session: harness.session },
      { url: "https://accounts.example.com/" },
    );
    expect(entries).toHaveLength(1);
    expect(harness.lastInner("get-logins")?.["keys"]).toEqual([
      {
        id: STANDARD_ASSOCIATION.id,
        key: STANDARD_ASSOCIATION.key,
      },
    ]);
  });

  it("set-login sends an update uuid or create group fields", async () => {
    const harness = await associatedHarness();
    const created = await setLogin(
      { session: harness.session },
      {
        url: "https://accounts.example.com/login",
        login: "alice@example.com",
        password: "correct horse battery staple",
        group: "KeePassXC-Browser Passwords",
        groupUuid: "17a19761914f9005f195c781475d37be",
      },
    );
    expect(created).toEqual({ success: true, message: "success" });
    let inner = harness.lastInner("set-login");
    expect(inner?.["downloadFavicon"]).toBe("true");
    expect(inner?.["groupUuid"]).toBe("17a19761914f9005f195c781475d37be");
    expect(inner?.["uuid"]).toBeUndefined();

    await setLogin(
      { session: harness.session },
      {
        url: "https://accounts.example.com/login",
        login: "alice@example.com",
        password: "new password",
        uuid: "d5ec68c35705b72fde380bd469aa149f",
      },
    );
    inner = harness.lastInner("set-login");
    expect(inner?.["uuid"]).toBe("d5ec68c35705b72fde380bd469aa149f");
    expect(inner?.["downloadFavicon"]).toBeUndefined();
    expect(inner?.["group"]).toBeUndefined();
  });

  it("set-login rejects references client-side", async () => {
    const harness = await associatedHarness();
    await expect(
      setLogin(
        { session: harness.session },
        {
          url: "https://example.com",
          login: "{REF:u@I:1234}",
          password: "x",
        },
      ),
    ).rejects.toMatchObject({ code: KpxcErrorCode.CANNOT_USE_REFERENCES });
  });

  it("get-totp validates the UUID and returns the code", async () => {
    const harness = await associatedHarness();
    await expect(
      getTotp({ session: harness.session }, "not-a-uuid"),
    ).rejects.toMatchObject({ code: KpxcErrorCode.NO_VALID_UUID_PROVIDED });
    await expect(
      getTotp(
        { session: harness.session },
        "d5ec68c35705b72fde380bd469aa149f",
      ),
    ).resolves.toBe("492183");
  });

  it("get-database-groups unwraps the frozen nested shape", async () => {
    const harness = await associatedHarness();
    const groups = await getDatabaseGroups({ session: harness.session });
    expect(groups).toHaveLength(1);
    expect(groups[0].name).toBe("Root");
  });

  it("generate-password tolerates the asynchronous empty frame", async () => {
    const harness = await associatedHarness();
    await expect(
      generatePassword({ session: harness.session }),
    ).resolves.toBe("oX9#vK2!mQ7@wZ4$");
    const inner = harness.lastInner("generate-password");
    expect(typeof inner?.["requestID"]).toBe("string");
    expect(inner?.["nonce"]).toBeTruthy();
    expect(inner?.["clientID"]).toBe(CLIENT_ID);
  });

  it("lock-database updates local state", async () => {
    const harness = await associatedHarness();
    await lockDatabase({ session: harness.session });
    expect(harness.session.snapshot().state).toBe("LOCKED");
    expect(harness.session.snapshot().locked).toBe(true);
  });

  it("exposes fetchDatabaseHash/testAssociate wrappers", async () => {
    const harness = await associatedHarness();
    await expect(fetchDatabaseHash({ session: harness.session })).resolves.toBe(
      DB_HASH,
    );
    await expect(
      testAssociate({ session: harness.session }),
    ).resolves.toEqual({ id: "chrome-work-laptop", hash: DB_HASH });
  });
});

// ---------------------------------------------------------------------------
// State store
// ---------------------------------------------------------------------------

describe("state store", () => {
  it("starts disconnected and persists client id and associations", async () => {
    const storage = new MemoryStorageArea();
    const first = createStateStore({ storage, broadcast: () => undefined });
    expect(first.snapshot()).toEqual(initialSnapshot());
    expect(await first.getSettings()).toEqual(DEFAULT_SETTINGS);

    await first.setClientId(CLIENT_ID);
    const record: AssociationRecord = { ...STANDARD_ASSOCIATION };
    await first.putAssociation(DB_HASH, record);
    await first.touchAssociation(DB_HASH, 2_000);

    const second = createStateStore({ storage, broadcast: () => undefined });
    expect(await second.getClientId()).toBe(CLIENT_ID);
    const keyRing = await second.keyRing();
    expect(keyRing[DB_HASH]).toMatchObject({
      id: record.id,
      key: record.key,
      hash: DB_HASH,
      lastUsed: 2_000,
    });

    await second.deleteAssociation(DB_HASH);
    expect(await second.keyRing()).toEqual({});
  });

  it("repairs corrupt persisted state instead of throwing", async () => {
    const storage = new MemoryStorageArea();
    await storage.set({
      "friendlypass.state.v1": {
        clientId: 42,
        keyRing: { broken: { id: "" } },
        settings: { autoFillHttpAuth: "yes" },
      },
    });
    const store = createStateStore({ storage, broadcast: () => undefined });
    expect(await store.getClientId()).toBeNull();
    expect(await store.keyRing()).toEqual({});
    expect((await store.getSettings()).autoFillHttpAuth).toBe(false);
  });

  it("merges settings and emits status events", async () => {
    const events: string[] = [];
    const store = createStateStore({
      storage: new MemoryStorageArea(),
      broadcast: () => undefined,
    });
    const unsubscribe = store.subscribe((status) => {
      events.push(status.state);
    });

    store.updateSnapshot({ state: "READY", appRunning: true, associated: true });
    expect(store.status()).toMatchObject({
      connected: true,
      appRunning: true,
      associated: true,
      state: "READY",
    });
    expect(events).toEqual(["READY"]);

    expect(await store.setSettings({ debugLogging: true })).toMatchObject({
      debugLogging: true,
      autoFillHttpAuth: false,
    });
    unsubscribe();
    store.updateSnapshot({ state: "DISCONNECTED" });
    expect(events).toEqual(["READY"]);
  });

  it("keeps a bounded diagnostics ring without secrets", () => {
    const store = createStateStore({
      storage: new MemoryStorageArea(),
      maxDiagnostics: 3,
      broadcast: () => undefined,
      now: () => 7,
    });
    for (let i = 0; i < 6; i += 1) {
      store.log({ level: "info", action: "get-logins", message: `event ${i}` });
    }
    const diagnostics = store.diagnostics();
    expect(diagnostics.entries).toHaveLength(3);
    expect(diagnostics.entries[2]).toMatchObject({
      at: 7,
      action: "get-logins",
      message: "event 5",
    });
  });
});

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

describe("urls", () => {
  it("normalises host, origin, port and path", () => {
    expect(getHost("https://Example.COM./Path?q=1#frag")).toBe("example.com");
    expect(getHost("not a url")).toBe("");
    expect(getHost("javascript:alert(1)")).toBe("");
    expect(getOrigin("https://example.com:443/a/b?c#d")).toBe(
      "https://example.com/",
    );
    expect(getPort("https://example.com:8443/")).toBe(8443);
    expect(getPort("https://example.com/")).toBeNull();
    expect(normalizeUrl("HTTPS://Example.com:443/a?#frag")).toBe(
      "https://example.com/a",
    );
    expect(getPath("https://example.com")).toBe("/");
  });

  it("handles IDN and base domains without a full PSL", () => {
    expect(getHost("https://bücher.example/login")).toBe(
      "xn--bcher-kva.example",
    );
    expect(getBaseDomain("https://login.bücher.example/")).toBe(
      "xn--bcher-kva.example",
    );
    expect(getBaseDomain("https://a.b.example.co.uk/")).toBe("example.co.uk");
    expect(getBaseDomain("https://www.example.com/")).toBe("example.com");
    expect(getBaseDomain("http://localhost:3000/")).toBe("localhost");
    expect(getBaseDomain("http://192.168.0.1/")).toBe("192.168.0.1");
  });

  it("matches same site, origin, paths and subdomains", () => {
    expect(isSameSite("https://www.example.com/a", "https://login.example.com/b"))
      .toBe(true);
    expect(isSameSite("https://example.com", "http://example.com")).toBe(false);
    expect(isSameSite("https://a.example.co.uk", "https://b.example.co.uk")).toBe(
      true,
    );
    expect(isSameOrigin("https://example.com/a", "https://example.com:443/b"))
      .toBe(true);
    expect(isSameOrigin("https://example.com", "http://example.com")).toBe(false);
    expect(isSubdomainOf("login.example.com", "example.com")).toBe(true);
    expect(isSubdomainOf("notexample.com", "example.com")).toBe(false);
    expect(pathMatches("/login", "/login/step2")).toBe(true);
    expect(pathMatches("/login", "/loginx")).toBe(false);
    expect(pathMatches("/", "/anything")).toBe(true);
  });

  it("ranks entry/page matches", () => {
    expect(
      matchUrl("https://example.com/login", "https://example.com/login"),
    ).toEqual({ kind: "exact", score: 100 });
    expect(
      matchUrl("https://example.com/login", "https://example.com/login/step2"),
    ).toEqual({ kind: "path", score: 80 });
    expect(
      matchUrl("https://example.com/login", "https://example.com/other"),
    ).toEqual({ kind: "origin", score: 60 });
    expect(
      matchUrl("https://example.com", "https://login.example.com/"),
    ).toEqual({ kind: "subdomain", score: 40 });
    expect(matchUrl("https://example.com", "https://evil.com/")).toBeNull();
    // Scheme downgrade never matches.
    expect(matchUrl("https://example.com", "http://example.com/")).toBeNull();
  });

  it("sanitises lookup URLs and drops fragments", () => {
    expect(
      sanitizeForLookup("https://example.com/login?next=1#frag"),
    ).toBe("https://example.com/login?next=1");
    expect(sanitizeForLookup("javascript:alert(1)")).toBe("");
  });
});
