/**
 * In-process friendlypass **app mock** for the e2e harness (WP8).
 *
 * Implements the subset of `protocol/ACTIONS.md` needed by the harness and the
 * Phase-1 specs:
 *
 *   change-public-keys, get-databasehash, associate, test-associate,
 *   get-logins, get-totp, generate-password, lock-database
 *
 * Crypto uses the fixed fixture keys from `protocol/fixtures/*.json`, so the
 * golden vectors can be replayed byte-for-byte-ish (the app re-seals responses
 * with the request's incremented nonce; ciphertext is deterministic for the
 * same inputs).
 *
 * Fault injection is deliberately part of this class so Playwright specs can
 * call `killApp()`, `restartApp()` and `stallApp(ms)` against the same socket
 * path. `killApp` closes the listener *and* every live host connection.
 *
 * The app socket speaks the real app's framing (see the app-socket section of
 * `protocol/ACTIONS.md`): raw concatenated compact JSON objects, no length
 * prefix, no newline. That is exactly what
 * `crates/friendlypass-browser/src/server.rs` reads, so the real host and the
 * real Rust test server can be used interchangeably with this mock.
 *
 * Never log decrypted payloads or credentials. The log contains action names,
 * error codes and counters only.
 */

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import nacl from "tweetnacl";
import {
  ObjectStreamDecoder,
  encodeObject,
  incrementNonce,
  sleep,
} from "./frames.mjs";

const MAX_FRAME_BYTES = 1024 * 1024;
const here = path.dirname(fileURLToPath(import.meta.url));
/** repo root: extension/tests/harness -> extension/tests -> extension -> repo */
export const REPO_ROOT = path.resolve(here, "../../..");
export const EXTENSION_DIST = path.resolve(REPO_ROOT, "extension/dist");
export const STUB_HOST_PATH = path.join(here, "stub-host.mjs");
export const PROTOCOL_FIXTURES = path.join(REPO_ROOT, "protocol/fixtures");

const ASSOCIATION_ID = "chrome-work-laptop";

/** @param {string} value */
function fromB64(value: string) {
  return new Uint8Array(Buffer.from(value, "base64"));
}

/** @param {Uint8Array} value */
function toB64(value: Uint8Array) {
  return Buffer.from(value).toString("base64");
}

interface Fixture {
  keys: {
    client: { publicKey: string; secretKey: string };
    host: { publicKey: string; secretKey: string };
    identity: { publicKey: string; secretKey: string };
  };
  database: { databaseHash: string; rootGroupUuid: string };
  entries: Array<Record<string, string>>;
}

function loadFixture(): Fixture {
  const file = path.join(PROTOCOL_FIXTURES, "get-logins.json");
  const json = JSON.parse(fs.readFileSync(file, "utf8")) as {
    keys: Fixture["keys"];
    database: Fixture["database"];
    vectors: Array<{ response: { plaintext: { entries: Fixture["entries"] } } }>;
  };
  return {
    keys: json.keys,
    database: json.database,
    entries: json.vectors[0].response.plaintext.entries,
  };
}

export interface AppMockOptions {
  socketPath: string;
  logPath: string;
  /**
   * Start with `associate` denied (error 6). Used by the automatic-pairing
   * tests to observe the manual Connect fallback without a GUI prompt.
   */
  denyAssociations?: boolean;
  /**
   * Accept `passkeys-register`/`passkeys-get` but never answer them — models
   * the GUI's pending passkey dialog without stalling the session handshake.
   */
  holdPasskeys?: boolean;
}

interface Session {
  clientPublicKey: Uint8Array | null;
  clientID: string;
  associatedIds: Set<string>;
}

interface AppMockCounters {
  connections: number;
  handshakes: number;
  requests: Record<string, number>;
  corruptFramesSent: number;
}

export class AppMock {
  readonly socketPath: string;
  readonly logPath: string;

  private readonly fixture = loadFixture();
  private readonly hostSecretKey = fromB64(this.fixture.keys.host.secretKey);
  private readonly hostPublicKey = this.fixture.keys.host.publicKey;

  private server: net.Server | null = null;
  private readonly sockets = new Set<net.Socket>();
  private readonly sessions = new WeakMap<net.Socket, Session>();
  private readonly timers = new Set<NodeJS.Timeout>();

  private stallUntil = 0;
  private locked = false;
  private associationDenied: boolean;
  private readonly holdPasskeys: boolean;
  /** Monotonic counter so `generate-password` returns a distinct value. */
  private generatedPasswords = 0;

  readonly counters: AppMockCounters = {
    connections: 0,
    handshakes: 0,
    requests: {},
    corruptFramesSent: 0,
  };

  constructor(options: AppMockOptions) {
    this.socketPath = options.socketPath;
    this.logPath = options.logPath;
    this.associationDenied = options.denyAssociations === true;
    this.holdPasskeys = options.holdPasskeys === true;
  }

  get listening(): boolean {
    return this.server !== null;
  }

  /** `true` while `associate` is answered with error 6 (user denial). */
  get isAssociationDenied(): boolean {
    return this.associationDenied;
  }

  /** Simulate the user approving or denying association prompts. */
  setAssociationDenied(denied: boolean): void {
    this.associationDenied = denied;
    this.appendLog({ event: "association-policy", denied });
  }

  get connectionCount(): number {
    return this.counters.connections;
  }

  get currentConnections(): number {
    return this.sockets.size;
  }

  get isLocked(): boolean {
    return this.locked;
  }

  async start(): Promise<void> {
    if (this.server) return;
    fs.mkdirSync(path.dirname(this.socketPath), { recursive: true });
    fs.rmSync(this.socketPath, { force: true });
    fs.mkdirSync(path.dirname(this.logPath), { recursive: true });

    const server = net.createServer((socket) => this.accept(socket));
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.socketPath, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    try {
      fs.chmodSync(this.socketPath, 0o600);
    } catch {
      /* best effort on platforms without unix permissions */
    }
    server.on("error", (error) => {
      this.appendLog({ event: "server-error", message: String(error) });
    });
    this.appendLog({ event: "app-listening" });
  }

  /**
   * Simulates the friendlypass app exiting: close the listener and destroy
   * every host connection. The host must survive and reconnect on restart.
   */
  async stop(): Promise<void> {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();

    const server = this.server;
    this.server = null;
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    fs.rmSync(this.socketPath, { force: true });
    this.appendLog({ event: "app-stopped" });
  }

  async restart(): Promise<void> {
    await this.stop();
    await this.start();
    this.appendLog({ event: "app-restarted" });
  }

  /** Alias used by the Playwright fixture naming. */
  async close(): Promise<void> {
    await this.stop();
  }

  /**
   * Delay every request handled in the next `ms` milliseconds.
   * @returns the number of milliseconds requested
   */
  stall(ms: number): number {
    const until = Date.now() + Math.max(0, ms);
    this.stallUntil = Math.max(this.stallUntil, until);
    this.appendLog({ event: "stall", ms });
    return Math.max(0, ms);
  }

  /**
   * Emit a correctly framed but syntactically invalid JSON payload from the app
   * to the host. The host must answer 1002 and stay alive.
   */
  sendCorruptFrame(): boolean {
    if (this.sockets.size === 0) return false;
    // Brace-balanced but syntactically invalid JSON: the raw-object framer
    // yields it, the host must answer 1002 and stay alive. Sent to every host
    // connection because each native port is a separate host process.
    const payload = Buffer.from('{"action":}', "utf8");
    for (const socket of this.sockets) socket.write(payload);
    this.counters.corruptFramesSent += 1;
    this.appendLog({ event: "corrupt-frame-sent", sockets: this.sockets.size });
    return true;
  }

  /** Broadcast an unsolicited app → extension push. */
  push(action: string, fields: Record<string, unknown> = {}): number {
    const frame = { action, ...fields };
    for (const socket of this.sockets) socket.write(encodeObject(frame));
    this.appendLog({ event: "push", action });
    return this.sockets.size;
  }

  setLocked(locked: boolean): void {
    this.locked = locked;
    this.appendLog({ event: "lock-state", locked });
    this.push(locked ? "database-locked" : "database-unlocked");
  }

  private accept(socket: net.Socket): void {
    socket.setNoDelay(true);
    this.sockets.add(socket);
    this.counters.connections += 1;
    this.sessions.set(socket, {
      clientPublicKey: null,
      clientID: "",
      associatedIds: new Set(),
    });
    this.appendLog({ event: "host-connected" });

    const decoder = new ObjectStreamDecoder({ maxBytes: MAX_FRAME_BYTES });
    socket.on("data", (chunk: Buffer) => {
      for (const decoded of decoder.push(chunk)) {
        if (decoded.type === "error") {
          this.appendLog({
            event: "host-frame-error",
            errorCode: decoded.errorCode,
          });
          continue;
        }
        const session = this.sessions.get(socket);
        if (!session) continue;
        this.schedule(socket, session, decoded.value);
      }
    });
    socket.on("error", () => {
      /* close handler cleans up */
    });
    socket.on("close", () => {
      this.sockets.delete(socket);
      this.appendLog({ event: "host-disconnected" });
    });
  }

  private schedule(
    socket: net.Socket,
    session: Session,
    frame: Record<string, unknown>,
  ): void {
    const delay = this.stallUntil - Date.now();
    if (delay > 0) {
      const timer = setTimeout(() => {
        this.timers.delete(timer);
        this.handle(socket, session, frame);
      }, delay);
      this.timers.add(timer);
    } else {
      this.handle(socket, session, frame);
    }
  }

  private handle(
    socket: net.Socket,
    session: Session,
    frame: Record<string, unknown>,
  ): void {
    const action = typeof frame.action === "string" ? frame.action : "";
    session.clientID =
      typeof frame.clientID === "string" ? frame.clientID : session.clientID;
    this.counters.requests[action] = (this.counters.requests[action] ?? 0) + 1;
    this.appendLog({ event: "request", action });

    if (action === "change-public-keys") {
      this.handleChangePublicKeys(socket, session, frame);
      return;
    }
    this.handleEncrypted(socket, session, frame, action);
  }

  private handleChangePublicKeys(
    socket: net.Socket,
    session: Session,
    frame: Record<string, unknown>,
  ): void {
    const publicKey =
      typeof frame.publicKey === "string" ? fromB64(frame.publicKey) : null;
    const nonce = typeof frame.nonce === "string" ? fromB64(frame.nonce) : null;
    if (!publicKey || publicKey.length !== 32 || !nonce || nonce.length !== 24) {
      this.outerError(
        socket,
        "change-public-keys",
        3,
        "Client public key or nonce missing",
      );
      return;
    }
    session.clientPublicKey = publicKey;
    this.counters.handshakes += 1;
    this.write(socket, {
      action: "change-public-keys",
      version: "2.8.0",
      success: "true",
      nonce: incrementNonce(String(frame.nonce)),
      publicKey: this.hostPublicKey,
    });
  }

  private handleEncrypted(
    socket: net.Socket,
    session: Session,
    frame: Record<string, unknown>,
    action: string,
  ): void {
    const requestNonce = typeof frame.nonce === "string" ? frame.nonce : "";
    const clientPublicKey = session.clientPublicKey;

    if (!clientPublicKey) {
      this.outerError(socket, action, 3, "Client public key not received");
      return;
    }
    if (this.locked) {
      this.outerError(socket, action, 1, "Database not opened");
      return;
    }
    if (
      typeof frame.message !== "string" ||
      requestNonce.length === 0 ||
      Buffer.from(requestNonce, "base64").length !== 24
    ) {
      this.outerError(socket, action, 4, "Cannot decrypt message");
      return;
    }

    let inner: Record<string, unknown>;
    try {
      const opened = nacl.box.open(
        fromB64(frame.message),
        fromB64(requestNonce),
        clientPublicKey,
        this.hostSecretKey,
      );
      if (!opened) throw new Error("box.open failed");
      inner = JSON.parse(Buffer.from(opened).toString("utf8"));
      if (inner === null || typeof inner !== "object" || Array.isArray(inner)) {
        throw new Error("inner payload is not an object");
      }
    } catch {
      this.outerError(socket, action, 4, "Cannot decrypt message");
      return;
    }

    const innerAction =
      typeof inner.action === "string" ? inner.action : "";
    if (innerAction !== action) {
      this.outerError(socket, action, 12, "Incorrect action");
      return;
    }

    switch (action) {
      case "get-databasehash":
        this.sendInner(socket, session, action, requestNonce, {
          hash: this.fixture.database.databaseHash,
        });
        return;

      case "associate": {
        if (this.associationDenied) {
          this.appendLog({ event: "associate-denied" });
          this.outerError(socket, action, 6, "Association denied");
          return;
        }
        // The extension generates a fresh identity key per install, so the mock
        // accepts whatever 32-byte key it is given (production stores it and
        // verifies it on `test-associate`). Golden-vector replays still work:
        // they send the fixture identity key and get the fixture reply.
        const idKey = typeof inner.idKey === "string" ? inner.idKey : "";
        if (!idKey) {
          this.outerError(socket, action, 8, "Association failed");
          return;
        }
        session.associatedIds.add(ASSOCIATION_ID);
        this.sendInner(socket, session, action, requestNonce, {
          hash: this.fixture.database.databaseHash,
          id: ASSOCIATION_ID,
        });
        return;
      }

      case "test-associate": {
        const id = typeof inner.id === "string" ? inner.id : "";
        const key = typeof inner.key === "string" ? inner.key : "";
        if (!id || !key) {
          this.outerError(
            socket,
            action,
            1,
            "Association id or key missing",
          );
          return;
        }
        if (id !== ASSOCIATION_ID) {
          this.outerError(socket, action, 8, "Association failed");
          return;
        }
        session.associatedIds.add(id);
        this.sendInner(socket, session, action, requestNonce, {
          hash: this.fixture.database.databaseHash,
          id,
        });
        return;
      }

      case "get-logins": {
        const url = typeof inner.url === "string" ? inner.url : "";
        const id = typeof inner.id === "string" ? inner.id : "";
        if (!url) {
          this.outerError(socket, action, 14, "No URL provided");
          return;
        }
        if (!session.associatedIds.has(id)) {
          this.outerError(socket, action, 8, "Association failed");
          return;
        }
        if (url.includes("no-match.invalid")) {
          this.outerError(socket, action, 15, "No logins found");
          return;
        }
        this.sendInner(socket, session, action, requestNonce, {
          count: this.fixture.entries.length,
          entries: this.fixture.entries,
          hash: this.fixture.database.databaseHash,
          id: ASSOCIATION_ID,
        });
        return;
      }

      case "get-totp": {
        const uuid = typeof inner.uuid === "string" ? inner.uuid : "";
        if (!uuid) {
          this.outerError(socket, action, 18, "No valid UUID provided");
          return;
        }
        this.sendInner(socket, session, action, requestNonce, {
          totp: "492183",
        });
        return;
      }

      case "generate-password":
        // WP6a popup: deterministic, printable, and obviously not a secret.
        this.generatedPasswords += 1;
        this.sendInner(socket, session, action, requestNonce, {
          password: `generated-password-${this.generatedPasswords}`,
        });
        return;

      case "lock-database":
        this.locked = true;
        this.sendInner(socket, session, action, requestNonce, {});
        this.push("database-locked");
        return;

      case "passkeys-register":
      case "passkeys-get":
        if (this.holdPasskeys) {
          // The real app is showing its passkey dialog; do not answer.
          this.appendLog({ event: "passkey-held", action });
          return;
        }
        this.outerError(socket, action, 12, "Incorrect action");
        return;

      default:
        this.outerError(socket, action, 12, "Incorrect action");
    }
  }

  private sendInner(
    socket: net.Socket,
    session: Session,
    action: string,
    requestNonce: string,
    fields: Record<string, unknown>,
  ): void {
    if (!session.clientPublicKey) {
      this.outerError(socket, action, 3, "Client public key not received");
      return;
    }
    const responseNonce = incrementNonce(requestNonce);
    const plaintext = {
      version: "2.8.0",
      success: "true",
      nonce: responseNonce,
      ...fields,
    };
    const sealed = nacl.box(
      Buffer.from(JSON.stringify(plaintext), "utf8"),
      fromB64(responseNonce),
      session.clientPublicKey,
      this.hostSecretKey,
    );
    this.write(socket, {
      action,
      message: toB64(sealed),
      nonce: responseNonce,
    });
  }

  private outerError(
    socket: net.Socket,
    action: string,
    code: number,
    message: string,
  ): void {
    this.write(socket, {
      action,
      errorCode: String(code),
      error: message,
    });
    this.appendLog({ event: "error", action, errorCode: String(code) });
  }

  private write(socket: net.Socket, frame: Record<string, unknown>): void {
    if (!this.sockets.has(socket)) return;
    socket.write(encodeObject(frame));
  }

  private appendLog(event: Record<string, unknown>): void {
    try {
      fs.appendFileSync(
        this.logPath,
        `${JSON.stringify({ ts: Date.now(), ...event })}\n`,
      );
    } catch {
      /* logging must never break the mock */
    }
  }
}

/**
 * Wait until the app has at least one live host connection.
 * Useful before fault injection that needs a connection to corrupt.
 */
export async function waitForAppConnection(
  app: { currentConnections: number },
  timeoutMs = 5000,
  minimum = 1,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (app.currentConnections >= minimum) return;
    await sleep(25);
  }
  throw new Error(
    `app mock did not get ${minimum} host connection(s) within ${timeoutMs} ms`,
  );
}
