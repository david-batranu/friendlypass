/**
 * Automatic pairing state machine (contract §6).
 *
 * These tests drive the real `createSession()` over real TweetNaCl frames with
 * a fake host, and assert the frozen rules:
 *  - one automatic `associate` per database hash per service-worker lifetime;
 *  - a new database hash gets its own attempt;
 *  - a denial (error 6) or failure exposes `pairing: "failed"` and never loops;
 *  - no automatic attempt while locked or while the app is down;
 *  - concurrent triggers never send two `associate` frames at once.
 *
 * No decrypted payload is printed. The fake host uses the fixture keys from
 * `protocol/fixtures`, so the session performs real crypto in both directions.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  buildGetLoginsInner,
  createSession,
  decodeBase64,
  encodeBase64,
  incrementNonce,
  incrementNonceBase64,
  openInnerMessage,
  sealInnerMessage,
} from "../../src/background/session";
import type { BoxKeyPair, ProtocolSession } from "../../src/background/session";
import {
  MemoryStorageArea,
  createStateStore,
} from "../../src/background/state";
import { errorMessageFor } from "../../src/common/messages";
import {
  KpxcErrorCode,
  type AssociationRecord,
  type GetLoginsResponse,
  type HostHelloResponse,
  type HostToExtensionFrame,
  type NativeRequestFrame,
} from "../../src/common/types";
import type {
  NativeTransport,
  TransportHandlers,
} from "../../src/background/transport";

// ---------------------------------------------------------------------------
// Fixed fixture keys
// ---------------------------------------------------------------------------

const FIXTURE_DIR = new URL("../../../protocol/fixtures/", import.meta.url);

interface FixtureDocument {
  keys: {
    client: { publicKey: string; secretKey: string };
    host: { publicKey: string; secretKey: string };
    identity: { publicKey: string; secretKey: string };
  };
  clientID: string;
}

const fixture = JSON.parse(
  readFileSync(new URL("change-public-keys.json", FIXTURE_DIR), "utf8"),
) as FixtureDocument;

const CLIENT_PUBLIC = decodeBase64(fixture.keys.client.publicKey);
const CLIENT_SECRET = decodeBase64(fixture.keys.client.secretKey);
const HOST_PUBLIC = decodeBase64(fixture.keys.host.publicKey);
const HOST_SECRET = decodeBase64(fixture.keys.host.secretKey);
const IDENTITY_PUBLIC = decodeBase64(fixture.keys.identity.publicKey);
const IDENTITY_SECRET = decodeBase64(fixture.keys.identity.secretKey);
const CLIENT_ID = fixture.clientID;

const SESSION_KEYPAIR: BoxKeyPair = {
  publicKey: CLIENT_PUBLIC,
  secretKey: CLIENT_SECRET,
};
const IDENTITY_KEYPAIR: BoxKeyPair = {
  publicKey: IDENTITY_PUBLIC,
  secretKey: IDENTITY_SECRET,
};

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

const STANDARD_ASSOCIATION: AssociationRecord = {
  id: "chrome-work-laptop",
  key: fixture.keys.identity.publicKey,
  hash: HASH_A,
  created: 1_763_925_600_000,
  lastUsed: 1_763_925_600_000,
};

// ---------------------------------------------------------------------------
// Fake host + transport
// ---------------------------------------------------------------------------

interface FakeApp {
  hash: string;
  locked: boolean;
  denyAssociations: boolean;
  /** When set, `associate` is answered only after this promise resolves. */
  associateGate: Promise<void> | null;
  /** Association ids that `test-associate` accepts. */
  validIds: Set<string>;
}

interface PairingHarness {
  session: ProtocolSession;
  store: ReturnType<typeof createStateStore>;
  transport: PairingTransport;
  host: FakeApp;
  counters: {
    associate: number;
    testAssociate: number;
    activeAssociates: number;
    maxConcurrentAssociates: number;
    associatedHashes: string[];
  };
}

class PairingTransport implements NativeTransport {
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
  handlers!: TransportHandlers;
  responder: ((frame: NativeRequestFrame) => void) | null = null;
  hello: HostHelloResponse;
  liveAppRunning: boolean;

  constructor(hello: HostHelloResponse) {
    this.hello = hello;
    this.liveAppRunning = hello.appRunning;
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
    const frame = {
      action: "ping" as const,
      success: "true" as const,
      protocolVersion: 1,
      hostVersion: "0.1.0",
      appRunning: this.liveAppRunning,
      appVersion: "0.1.0",
      locked: false,
      databaseHash: null,
    };
    this.hello = { ...this.hello, appRunning: frame.appRunning };
    this.handlers.onFrame(frame as unknown as HostToExtensionFrame);
    return frame;
  }

  async send(frame: NativeRequestFrame): Promise<void> {
    if (!this.connected) {
      throw new Error("native transport is not connected");
    }
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

function helloResponse(
  overrides: Partial<HostHelloResponse> = {},
): HostHelloResponse {
  return {
    action: "hello",
    success: "true",
    protocolVersion: 1,
    hostVersion: "0.1.0",
    appRunning: true,
    appVersion: "0.1.0",
    locked: false,
    databaseHash: HASH_A,
    sessionId: "pairing-test",
    ...overrides,
  };
}

async function createPairingHarness(
  options: {
    association?: AssociationRecord | null;
    locked?: boolean;
    appRunning?: boolean;
    denyAssociations?: boolean;
    associateGate?: Promise<void> | null;
    hello?: Partial<HostHelloResponse>;
  } = {},
): Promise<PairingHarness> {
  const storage = new MemoryStorageArea();
  const store = createStateStore({
    storage,
    now: () => 1_763_925_600_000,
    broadcast: () => undefined,
  });
  await store.setClientId(CLIENT_ID);
  if (options.association) {
    await store.putAssociation(options.association.hash, options.association);
  }

  const transport = new PairingTransport(
    helloResponse({
      appRunning: options.appRunning ?? true,
      locked: options.locked ?? false,
      ...options.hello,
    }),
  );

  const host: FakeApp = {
    hash: HASH_A,
    locked: options.locked ?? false,
    denyAssociations: options.denyAssociations ?? false,
    associateGate: options.associateGate ?? null,
    validIds: new Set(options.association ? [options.association.id] : []),
  };

  const counters: PairingHarness["counters"] = {
    associate: 0,
    testAssociate: 0,
    activeAssociates: 0,
    maxConcurrentAssociates: 0,
    associatedHashes: [],
  };

  let session: ProtocolSession;

  function replyError(action: string, code: number): void {
    session.handleFrame({
      action,
      error: errorMessageFor(code),
      errorCode: String(code),
    } as unknown as HostToExtensionFrame);
  }

  function replySuccess(
    action: string,
    requestNonce: string,
    extra: Record<string, unknown>,
  ): void {
    const responseNonceBytes = incrementNonce(decodeBase64(requestNonce));
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
    const action = String(inner["action"]);

    switch (action) {
      case "get-databasehash":
        if (host.locked) {
          replyError(frame.action, KpxcErrorCode.DATABASE_NOT_OPENED);
          return;
        }
        replySuccess(frame.action, frame.nonce, { hash: host.hash });
        return;

      case "test-associate": {
        counters.testAssociate += 1;
        if (!host.validIds.has(String(inner["id"]))) {
          replyError(frame.action, KpxcErrorCode.ASSOCIATION_FAILED);
          return;
        }
        replySuccess(frame.action, frame.nonce, {
          hash: host.hash,
          id: inner["id"],
        });
        return;
      }

      case "associate": {
        counters.associate += 1;
        counters.activeAssociates += 1;
        counters.maxConcurrentAssociates = Math.max(
          counters.maxConcurrentAssociates,
          counters.activeAssociates,
        );
        const finish = (): void => {
          counters.activeAssociates -= 1;
          if (host.locked) {
            replyError(frame.action, KpxcErrorCode.DATABASE_NOT_OPENED);
            return;
          }
          if (host.denyAssociations) {
            replyError(frame.action, KpxcErrorCode.ACTION_CANCELLED_OR_DENIED);
            return;
          }
          const id = "chrome-work-laptop";
          host.validIds.add(id);
          counters.associatedHashes.push(host.hash);
          replySuccess(frame.action, frame.nonce, { hash: host.hash, id });
        };
        if (host.associateGate !== null) {
          void host.associateGate.then(finish);
        } else {
          finish();
        }
        return;
      }

      case "get-logins":
        if (!host.validIds.has(String(inner["id"] ?? "chrome-work-laptop"))) {
          replyError(frame.action, KpxcErrorCode.ASSOCIATION_FAILED);
          return;
        }
        replySuccess(frame.action, frame.nonce, {
          count: 1,
          entries: [
            {
              login: "alice@example.com",
              password: "correct horse battery staple",
              name: "Example account",
              uuid: "d5ec68c35705b72fde380bd469aa149f",
              group: "KeePassXC-Browser Passwords",
            },
          ],
          hash: host.hash,
          id: "chrome-work-laptop",
        });
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
      session.handleFrame({
        action: "change-public-keys",
        version: "2.8.0",
        success: "true",
        nonce: incrementNonceBase64(frame.nonce),
        publicKey: encodeBase64(HOST_PUBLIC),
      } as unknown as HostToExtensionFrame);
      return;
    }
    handleEncrypted(frame as NativeRequestFrame & { message: string });
  };

  return { session, store, transport, host, counters };
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 3000,
  label = "condition",
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`timed out waiting for ${label}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("automatic pairing", () => {
  it("associates once when READY with no stored association", async () => {
    const harness = await createPairingHarness();
    await harness.session.ensureSession();

    await waitFor(
      () => harness.counters.associate === 1 && harness.store.snapshot().associated,
      3000,
      "the automatic association",
    );
    const snapshot = harness.store.snapshot();
    expect(snapshot.state).toBe("READY");
    expect(snapshot.associated).toBe(true);
    expect(snapshot.pairing).toBe("idle");
    expect(harness.store.status().pairing).toBe("idle");
    expect(harness.store.status().associated).toBe(true);
    expect(harness.counters.associatedHashes).toEqual([HASH_A]);
    // Older hosts omit the optional trust fields; they must stay null rather
    // than leaking undefined into the diagnostics UI.
    expect(snapshot.appTrusted).toBeNull();
    expect(snapshot.browser).toBeNull();

    // Same hash for the rest of this service-worker lifetime: no second try,
    // even after a reconnect/handshake that re-runs test-associate.
    await harness.session.handleConnect();
    await harness.session.ensureSession();
    await waitFor(
      () => harness.store.snapshot().associated,
      2000,
      "revalidation",
    );
    expect(harness.counters.associate).toBe(1);
  });

  it("exposes pairing while the associate is in flight", async () => {
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const harness = await createPairingHarness({ associateGate: gate });
    await harness.session.ensureSession();

    await waitFor(
      () => harness.store.snapshot().pairing === "pairing",
      3000,
      "pairing state",
    );
    expect(harness.store.status().pairing).toBe("pairing");
    expect(harness.store.snapshot().associated).toBe(false);

    release();
    await waitFor(
      () => harness.store.snapshot().associated,
      3000,
      "association after release",
    );
    expect(harness.store.snapshot().pairing).toBe("idle");
    expect(harness.counters.associate).toBe(1);
  });

  it("a new database hash gets its own automatic attempt", async () => {
    const harness = await createPairingHarness();
    await harness.session.ensureSession();
    await waitFor(
      () => harness.counters.associate === 1 && harness.store.snapshot().associated,
      3000,
      "hash A association",
    );

    harness.host.hash = HASH_B;
    harness.session.handleFrame({
      action: "database-changed",
      hash: HASH_B,
    } as unknown as HostToExtensionFrame);

    await waitFor(
      () =>
        harness.counters.associate === 2 &&
        harness.store.snapshot().associated &&
        harness.store.snapshot().databaseHash === HASH_B,
      4000,
      "hash B association",
    );
    expect(harness.counters.associatedHashes).toEqual([HASH_A, HASH_B]);
    expect(Object.keys(await harness.store.keyRing())).toEqual(
      expect.arrayContaining([HASH_A, HASH_B]),
    );
  });

  it("a denial sets pairing failed and never loops", async () => {
    const harness = await createPairingHarness({ denyAssociations: true });
    await harness.session.ensureSession();

    await waitFor(
      () => harness.store.snapshot().pairing === "failed",
      3000,
      "the failed pairing state",
    );
    expect(harness.counters.associate).toBe(1);
    expect(harness.store.snapshot().associated).toBe(false);
    expect(harness.store.status().pairing).toBe("failed");
    expect(harness.store.snapshot().lastError?.code).toBe(
      KpxcErrorCode.ACTION_CANCELLED_OR_DENIED,
    );

    // Revalidations and a fresh handshake for the same hash must not retry.
    await harness.session.handleConnect();
    await harness.session.ensureSession();
    harness.session.handleFrame({
      action: "database-unlocked",
    } as unknown as HostToExtensionFrame);
    await sleep(300);
    expect(harness.counters.associate).toBe(1);
    expect(harness.store.snapshot().pairing).toBe("failed");
  });

  it("does not associate automatically while the database is locked", async () => {
    const harness = await createPairingHarness({ locked: true });
    await harness.session.ensureSession();

    expect(harness.store.snapshot().state).toBe("LOCKED");
    expect(harness.store.snapshot().pairing).toBe("idle");
    expect(harness.counters.associate).toBe(0);

    // Unlocking resumes the automatic attempt for the same hash.
    harness.host.locked = false;
    harness.transport.hello = { ...harness.transport.hello, locked: false };
    harness.session.handleFrame({
      action: "database-unlocked",
    } as unknown as HostToExtensionFrame);
    await waitFor(
      () => harness.counters.associate === 1 && harness.store.snapshot().associated,
      4000,
      "the post-unlock association",
    );
  });

  it("does not associate automatically while the app is down", async () => {
    const harness = await createPairingHarness({ appRunning: false });
    harness.transport.liveAppRunning = false;
    await harness.session.ensureSession();

    expect(harness.store.snapshot().appRunning).toBe(false);
    expect(harness.store.snapshot().pairing).toBe("idle");
    expect(harness.counters.associate).toBe(0);
  });

  it("does not re-associate when a stored association passes test-associate", async () => {
    const harness = await createPairingHarness({
      association: STANDARD_ASSOCIATION,
    });
    await harness.session.ensureSession();

    await waitFor(
      () => harness.store.snapshot().associated,
      3000,
      "test-associate",
    );
    expect(harness.counters.testAssociate).toBe(1);
    expect(harness.counters.associate).toBe(0);
    expect(harness.store.snapshot().pairing).toBe("idle");
  });

  it("accepts the optional host trust/browser fields when present", async () => {
    const harness = await createPairingHarness({
      hello: {
        appTrusted: true,
        browser: { kind: "chrome", verified: true },
      },
    });
    await harness.session.ensureSession();
    expect(harness.store.snapshot().appTrusted).toBe(true);
    expect(harness.store.snapshot().browser).toEqual({
      kind: "chrome",
      verified: true,
    });
  });

  it("concurrent triggers produce exactly one associate at a time", async () => {
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const harness = await createPairingHarness({ associateGate: gate });
    await harness.session.ensureSession();
    await waitFor(
      () => harness.counters.associate === 1,
      3000,
      "the associate in flight",
    );

    // Several callers wake at once while the automatic attempt is pending.
    // A credential action must wait for pairing instead of racing it and
    // getting a spurious error 8.
    const pendingLogin = harness.session.request<GetLoginsResponse>({
      action: "get-logins",
      requiresAssociation: true,
      buildInner: () => buildGetLoginsInner({ url: "https://example.com/" }),
    });
    const results = await Promise.allSettled([
      harness.session.ensureSession(),
      harness.session.ensureSession(),
      harness.session.getDatabaseHash(),
      harness.session.ensureSession({ triggerUnlock: true }),
    ]);
    // The encrypted action is allowed to run alongside; what must never happen
    // is a second `associate` frame before the first settles.
    expect(harness.counters.associate).toBe(1);
    expect(harness.counters.maxConcurrentAssociates).toBe(1);
    expect(results.length).toBe(4);

    release();
    await waitFor(
      () => harness.store.snapshot().associated,
      3000,
      "the association",
    );
    const logins = await pendingLogin;
    expect(logins.entries).toHaveLength(1);
    expect(logins.entries[0].login).toBe("alice@example.com");
    expect(harness.counters.associate).toBe(1);
    expect(harness.counters.maxConcurrentAssociates).toBe(1);
  });
});
