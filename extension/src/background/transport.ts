/**
 * Native-messaging transport (WP2).
 *
 * Owns: `chrome.runtime.connectNative(NATIVE_HOST_NAME)`, request/response
 * correlation, heartbeat, reconnect backoff, pending-request rejection and the
 * transport half of the connection state machine (`protocol/ACTIONS.md` §6).
 *
 * It deliberately does not understand KeePassXC actions, nonces inside
 * ciphertext, or association state — that is `session.ts` (WP3). It only
 * matches complete host frames to the request that is waiting for them:
 *
 *  - encrypted success frames by `action` + incremented request nonce;
 *  - unencrypted error frames by `action` (they never carry a nonce);
 *  - `ping` by nonce echo and `hello` by action.
 *
 * Every pending request settles: a response, a typed `TransportError`, or a
 * timeout. Losing the port rejects every waiter with code 5 and schedules a
 * jittered reconnect. A `chrome.alarms` watchdog (see `lifecycle.ts`) covers a
 * service worker that was suspended and restarted.
 */

import {
  HostErrorCode,
  KpxcErrorCode,
  NATIVE_HOST_NAME,
  RECONNECT_BACKOFF_MS,
  HEARTBEAT_INTERVAL_MS,
  HEARTBEAT_MAX_MISSES,
  HEARTBEAT_TIMEOUT_MS,
  REQUEST_TIMEOUT_MS,
  SUPPORTED_PROTOCOL_VERSION,
} from "../common/types";
import type {
  B64,
  HostHelloResponse,
  HostPingResponse,
  HostRequestFrame,
  HostToExtensionFrame,
  NativeRequestFrame,
  ProtocolError,
} from "../common/types";
import {
  isErrorFrame,
  isHostHelloResponse,
  isHostPingResponse,
  isRecord,
  isSuccessFrame,
  makeProtocolError,
  protocolErrorFromFrame,
} from "../common/messages";

/** Ten-second guard for `connectNative()` + `hello` (§6.3). */
const CONNECT_GUARD_MS = 10000;

/** The transport-visible subset of the state machine. */
export type TransportConnectionState = "DISCONNECTED" | "CONNECTING" | "READY";

export type TransportDisconnectReason =
  | "port-closed"
  | "host-exited"
  | "heartbeat-timeout"
  | "shutdown";

/** Status snapshot; safe to expose to the popup (no secrets). */
export interface TransportStatus {
  state: TransportConnectionState;
  /** True while a native port object exists (even during `hello`). */
  connected: boolean;
  /** Host-reported app liveness; false when unknown/down. */
  appRunning: boolean;
  hostVersion: string | null;
  appVersion: string | null;
  protocolVersion: number;
  /** Consecutive failed attempts, index into `RECONNECT_BACKOFF_MS`. */
  attempt: number;
  lastError: ProtocolError | null;
  /** True when the host did not answer `hello` (KeePassXC proxy fallback). */
  legacyMode: boolean;
}

/**
 * Transport-level state events. The full state machine additionally has
 * `HANDSHAKING`/`LOCKED`, which are owned by `session.ts`; `READY` here means
 * "port open and host reachable", with `appRunning` carrying app liveness.
 */
export type TransportStateEvent =
  | { type: "connecting" }
  | { type: "connected"; hello: HostHelloResponse; legacy: boolean }
  | { type: "appDown"; hello: HostHelloResponse | null }
  | { type: "appUp"; hello: HostHelloResponse | null }
  | {
      type: "disconnected";
      reason: TransportDisconnectReason;
      detail?: string;
      error: ProtocolError;
    };

export interface TransportHandlers {
  /** Called for every complete frame read from the host, including pushes. */
  onFrame(frame: HostToExtensionFrame): void;
  /** Called once when the port is gone. Pending requests must be rejected. */
  onDisconnect(reason: TransportDisconnectReason, detail?: string): void;
  /** Called after the port opens (before `hello` completes). */
  onConnect(): void;
  /**
   * Optional transport status notifications. `onFrame`/`onDisconnect` remain
   * the primary callbacks for WP3; this is the connected/appDown/disconnected
   * feed used by the service worker and diagnostics.
   */
  onStateChange?(event: TransportStateEvent): void;
}

export interface NativeTransport {
  readonly connected: boolean;
  readonly state: TransportConnectionState;
  readonly appRunning: boolean;
  readonly hello: HostHelloResponse | null;
  readonly status: TransportStatus;
  /** Idempotent: opens the port and performs `hello`. */
  connect(): Promise<HostHelloResponse>;
  disconnect(): void;
  /** Host-level liveness probe with a 3 s timeout. */
  ping(): Promise<HostPingResponse>;
  /** Sends an already-built protocol frame. Rejects if the port is gone. */
  send(frame: NativeRequestFrame): Promise<void>;
  /**
   * Sends a frame and resolves with the matching response frame. Timeouts and
   * disconnect reject with a typed `TransportError`. Additive to the WP3
   * boundary (`send`) so WP3 can build its request adapter on it.
   */
  request(
    frame: NativeRequestFrame | HostRequestFrame,
    timeoutMs?: number,
  ): Promise<HostToExtensionFrame>;
}

/** Minimal `chrome.runtime.Port` surface, injectable for unit tests. */
export interface NativePortLike {
  postMessage(message: unknown): void;
  disconnect(): void;
  onMessage: {
    addListener(listener: (message: unknown, port: NativePortLike) => void): void;
    removeListener(
      listener: (message: unknown, port: NativePortLike) => void,
    ): void;
  };
  onDisconnect: {
    addListener(listener: (port: NativePortLike) => void): void;
    removeListener(listener: (port: NativePortLike) => void): void;
  };
}

export interface NativeTransportOptions {
  /** Override `chrome.runtime.connectNative` (tests, Firefox shim). */
  connectNative?: (hostName: string) => NativePortLike;
  /** Default true. Tests may disable the automatic reconnect loop. */
  autoReconnect?: boolean;
  /** Default true. Fall back to KeePassXC mode when `hello` is unsupported. */
  legacyHelloFallback?: boolean;
  /** Injectable RNG for deterministic jitter. */
  random?: () => number;
  /** Injectable timers (vitest fake timers work through the globals too). */
  setTimeout?: typeof setTimeout;
  clearTimeout?: typeof clearTimeout;
  heartbeatIntervalMs?: number;
  heartbeatTimeoutMs?: number;
  /** Default request timeout; callers can override per request. */
  requestTimeoutMs?: number;
  connectTimeoutMs?: number;
  extensionVersion?: string;
  /** Persisted stable client id, when WP3 has one. */
  clientId?: () => string | null;
}

/** Typed rejection for every transport failure. */
export class TransportError extends Error {
  /** Numeric wire-style code (`5` for connection lost/timeout). */
  readonly code: number;
  /** Symbolic code name, e.g. `TIMEOUT_OR_NOT_CONNECTED`. */
  readonly errorName: string;
  readonly retryable: boolean;
  /** Normalised error, matching `common/types.ts` `ProtocolError`. */
  readonly protocol: ProtocolError;

  constructor(protocol: ProtocolError, cause?: unknown) {
    super(protocol.message);
    this.name = protocol.name;
    this.code = protocol.code;
    this.errorName = protocol.name;
    this.retryable = protocol.retryable;
    this.protocol = protocol;
    if (cause !== undefined) {
      (this as Error & { cause?: unknown }).cause = cause;
    }
  }
}

interface PendingRequest {
  action: string;
  nonce: string | null;
  resolve(frame: HostToExtensionFrame): void;
  reject(error: TransportError): void;
  timer: ReturnType<typeof setTimeout> | null;
}

function defaultConnectNative(hostName: string): NativePortLike {
  return chrome.runtime.connectNative(hostName) as unknown as NativePortLike;
}

function defaultRandom(): number {
  return Math.random();
}

function asError(cause: unknown): Error {
  return cause instanceof Error ? cause : new Error(String(cause));
}

function transportError(cause: unknown): TransportError {
  if (cause instanceof TransportError) {
    return cause;
  }
  return new TransportError(makeProtocolError(KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED, asError(cause).message));
}

function randomNonce(): B64 {
  const bytes = new Uint8Array(24);
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** libsodium `sodium_increment` on a Base64 24-byte nonce. */
export function incrementBase64Nonce(nonce: string): string | null {
  let binary: string;
  try {
    binary = atob(nonce);
  } catch {
    return null;
  }
  if (binary.length !== 24) {
    return null;
  }
  const bytes = new Uint8Array(24);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  let carry = 1;
  for (let i = 0; i < bytes.length; i += 1) {
    const value = bytes[i] + carry;
    bytes[i] = value & 0xff;
    carry = value >> 8;
  }
  let out = "";
  for (const byte of bytes) {
    out += String.fromCharCode(byte);
  }
  try {
    return btoa(out);
  } catch {
    return null;
  }
}

export function createNativeTransport(
  handlers: TransportHandlers,
  options: NativeTransportOptions = {},
): NativeTransport {
  return new NativeTransportImpl(handlers, options);
}

class NativeTransportImpl implements NativeTransport {
  private readonly handlers: TransportHandlers;
  private readonly options: NativeTransportOptions;

  private port: NativePortLike | null = null;
  private portMessageListener:
    | ((message: unknown, port: NativePortLike) => void)
    | null = null;
  private portDisconnectListener: ((port: NativePortLike) => void) | null = null;

  private stateValue: TransportConnectionState = "DISCONNECTED";
  private helloValue: HostHelloResponse | null = null;
  private appRunningValue = false;
  private hostVersionValue: string | null = null;
  private appVersionValue: string | null = null;
  private protocolVersionValue = SUPPORTED_PROTOCOL_VERSION;
  private attemptValue = 0;
  private lastErrorValue: ProtocolError | null = null;
  private legacyModeValue = false;

  private connectPromise: Promise<HostHelloResponse> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatMisses = 0;
  private heartbeatInFlight = false;
  private shuttingDown = false;

  private readonly pending: PendingRequest[] = [];

  constructor(handlers: TransportHandlers, options: NativeTransportOptions) {
    this.handlers = handlers;
    this.options = options;
  }

  get connected(): boolean {
    return this.port !== null;
  }

  get state(): TransportConnectionState {
    return this.stateValue;
  }

  get appRunning(): boolean {
    return this.appRunningValue;
  }

  get hello(): HostHelloResponse | null {
    return this.helloValue;
  }

  get status(): TransportStatus {
    return {
      state: this.stateValue,
      connected: this.port !== null,
      appRunning: this.appRunningValue,
      hostVersion: this.hostVersionValue,
      appVersion: this.appVersionValue,
      protocolVersion: this.protocolVersionValue,
      attempt: this.attemptValue,
      lastError: this.lastErrorValue,
      legacyMode: this.legacyModeValue,
    };
  }

  // -------------------------------------------------------------------------
  // Connect / disconnect
  // -------------------------------------------------------------------------

  connect(): Promise<HostHelloResponse> {
    // A manual connect (SW start, alarm, user gesture) re-arms the loop.
    this.shuttingDown = false;

    if (this.port !== null && this.helloValue !== null) {
      return Promise.resolve(this.helloValue);
    }
    if (this.connectPromise !== null) {
      return this.connectPromise;
    }

    this.clearReconnectTimer();
    const promise = this.openPort();
    this.connectPromise = promise;
    promise.then(
      () => {
        if (this.connectPromise === promise) {
          this.connectPromise = null;
        }
      },
      () => {
        if (this.connectPromise === promise) {
          this.connectPromise = null;
        }
      },
    );
    return promise;
  }

  disconnect(): void {
    this.shuttingDown = true;
    this.clearReconnectTimer();
    this.stopHeartbeat();
    if (this.port !== null) {
      this.losePort("shutdown", "Extension transport shut down", false);
      return;
    }
    this.stateValue = "DISCONNECTED";
    this.appRunningValue = false;
  }

  private async openPort(): Promise<HostHelloResponse> {
    this.stateValue = "CONNECTING";
    this.lastErrorValue = null;
    this.legacyModeValue = false;
    this.helloValue = null;
    this.handlers.onStateChange?.({ type: "connecting" });

    let port: NativePortLike;
    try {
      const factory = this.options.connectNative ?? defaultConnectNative;
      port = factory(NATIVE_HOST_NAME);
    } catch (cause) {
      const error = new TransportError(
        makeProtocolError(
          KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
          `Cannot open native messaging port: ${asError(cause).message}`,
        ),
        cause,
      );
      this.lastErrorValue = error.protocol;
      this.stateValue = "DISCONNECTED";
      this.scheduleReconnect();
      throw error;
    }

    if (
      port === null ||
      typeof port.postMessage !== "function" ||
      !port.onMessage ||
      !port.onDisconnect
    ) {
      const error = new TransportError(
        makeProtocolError(
          HostErrorCode.HOST_INTERNAL_ERROR,
          "connectNative() returned an invalid port",
        ),
      );
      this.lastErrorValue = error.protocol;
      this.stateValue = "DISCONNECTED";
      this.scheduleReconnect();
      throw error;
    }

    this.port = port;
    this.attachPort(port);
    try {
      this.handlers.onConnect();
    } catch (cause) {
      // Listener bugs must never break the transport.
      console.warn("[friendlypass] transport onConnect handler failed:", asError(cause).message);
    }

    try {
      const hello = await this.requestHello();
      this.helloValue = hello;
      this.hostVersionValue = hello.hostVersion;
      this.appVersionValue = hello.appVersion;
      this.protocolVersionValue = hello.protocolVersion;
      this.appRunningValue = hello.appRunning;
      this.attemptValue = 0;
      this.lastErrorValue = null;
      this.stateValue = "READY";

      this.handlers.onStateChange?.({ type: "connected", hello, legacy: false });
      if (!hello.appRunning) {
        this.handlers.onStateChange?.({ type: "appDown", hello });
      }

      this.startHeartbeat();
      return hello;
    } catch (cause) {
      const error = transportError(cause);

      // A real KeePassXC proxy does not implement `hello`. If the port is
      // still open, keep it and let the (legacy) handshake probe the app.
      if (
        this.port === port &&
        this.options.legacyHelloFallback !== false &&
        this.isLegacyHelloCause(error)
      ) {
        const hello = this.legacyHello();
        this.legacyModeValue = true;
        this.helloValue = hello;
        this.hostVersionValue = hello.hostVersion;
        this.appVersionValue = null;
        this.protocolVersionValue = SUPPORTED_PROTOCOL_VERSION;
        this.appRunningValue = true;
        this.attemptValue = 0;
        this.lastErrorValue = null;
        this.stateValue = "READY";
        console.info(
          "[friendlypass] native host does not implement hello; using legacy KeePassXC-compatible mode",
        );
        this.handlers.onStateChange?.({ type: "connected", hello, legacy: true });
        return hello;
      }

      if (this.port === port) {
        this.losePort("host-exited", error.message, true);
      }
      throw error;
    }
  }

  private isLegacyHelloCause(error: TransportError): boolean {
    return (
      error.code === HostErrorCode.UNKNOWN_HOST_ACTION ||
      error.code === KpxcErrorCode.INCORRECT_ACTION ||
      error.code === KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED
    );
  }

  private legacyHello(): HostHelloResponse {
    return {
      action: "hello",
      success: "true",
      protocolVersion: SUPPORTED_PROTOCOL_VERSION,
      hostVersion: "unknown",
      appRunning: true,
      appVersion: null,
      locked: null,
      databaseHash: null,
      sessionId: "legacy-kpxc",
    };
  }

  private async requestHello(): Promise<HostHelloResponse> {
    const clientID = this.options.clientId?.() ?? null;
    const frame: HostRequestFrame = {
      action: "hello",
      ...(clientID ? { clientID } : {}),
      extensionVersion: this.options.extensionVersion ?? "0.1.0",
    };
    const response = await this.request(
      frame,
      this.options.connectTimeoutMs ?? CONNECT_GUARD_MS,
    );
    if (!isHostHelloResponse(response)) {
      throw new TransportError(
        makeProtocolError(
          HostErrorCode.HOST_INTERNAL_ERROR,
          "Native host returned a malformed hello response",
        ),
      );
    }
    if (response.protocolVersion < SUPPORTED_PROTOCOL_VERSION) {
      throw new TransportError({
        code: HostErrorCode.HOST_INTERNAL_ERROR,
        name: "PROTOCOL_VERSION_UNSUPPORTED",
        message: `Native host protocol v${response.protocolVersion} is older than required v${SUPPORTED_PROTOCOL_VERSION}`,
        retryable: false,
      });
    }
    return response;
  }

  // -------------------------------------------------------------------------
  // Port plumbing
  // -------------------------------------------------------------------------

  private attachPort(port: NativePortLike): void {
    this.detachPort();

    const onMessage = (message: unknown): void => {
      if (this.port !== port) {
        return;
      }
      this.handleFrame(message);
    };
    const onDisconnect = (): void => {
      if (this.port !== port) {
        return;
      }
      const detail = safeLastError();
      this.losePort("port-closed", detail, true);
    };

    this.portMessageListener = onMessage;
    this.portDisconnectListener = onDisconnect;
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
  }

  private detachPort(): void {
    const port = this.port;
    if (port === null) {
      return;
    }
    if (this.portMessageListener !== null) {
      try {
        port.onMessage.removeListener(this.portMessageListener);
      } catch {
        /* port already gone */
      }
    }
    if (this.portDisconnectListener !== null) {
      try {
        port.onDisconnect.removeListener(this.portDisconnectListener);
      } catch {
        /* port already gone */
      }
    }
    this.portMessageListener = null;
    this.portDisconnectListener = null;
  }

  /**
   * Tears the port down exactly once: detaches listeners, rejects every
   * pending request with code 5, notifies the handlers and optionally arms the
   * reconnect timer.
   */
  private losePort(
    reason: TransportDisconnectReason,
    detail: string | undefined,
    reconnect: boolean,
  ): void {
    const port = this.port;
    if (port === null) {
      if (reconnect) {
        this.scheduleReconnect();
      }
      return;
    }

    this.detachPort();
    this.port = null;
    this.stopHeartbeat();
    this.helloValue = null;
    this.appRunningValue = false;
    this.legacyModeValue = false;
    this.stateValue = "DISCONNECTED";

    const protocol = makeProtocolError(
      KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
      `Native connection lost (${reason})${detail ? `: ${detail}` : ""}`,
    );
    this.lastErrorValue = protocol;
    this.rejectAllPending(protocol);

    try {
      port.disconnect();
    } catch {
      /* already disconnected */
    }

    try {
      this.handlers.onDisconnect(reason, detail);
    } catch (cause) {
      console.warn("[friendlypass] transport onDisconnect handler failed:", asError(cause).message);
    }
    this.handlers.onStateChange?.({ type: "disconnected", reason, detail, error: protocol });

    if (reconnect && !this.shuttingDown && this.options.autoReconnect !== false) {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.shuttingDown || this.options.autoReconnect === false) {
      return;
    }
    if (this.reconnectTimer !== null) {
      return;
    }

    const table = RECONNECT_BACKOFF_MS;
    const index = Math.min(this.attemptValue, table.length - 1);
    const random = this.options.random ?? defaultRandom;
    const jitter = 0.8 + random() * 0.4;
    const delay = Math.max(0, Math.round(table[index] * jitter));
    this.attemptValue = Math.min(this.attemptValue + 1, table.length);

    this.reconnectTimer = this.setTimer(() => {
      this.reconnectTimer = null;
      if (this.shuttingDown) {
        return;
      }
      void this.connect().catch(() => {
        // openPort()/losePort() already scheduled the next attempt; swallowing
        // here keeps an unattended retry loop from producing an unhandled
        // rejection.
      });
    }, delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      this.clearTimer(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  // -------------------------------------------------------------------------
  // Requests and correlation
  // -------------------------------------------------------------------------

  async send(frame: NativeRequestFrame): Promise<void> {
    const port = this.port;
    if (port === null) {
      throw new TransportError(
        makeProtocolError(
          KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
          "Native messaging port is not open",
        ),
      );
    }
    try {
      port.postMessage(frame);
    } catch (cause) {
      if (this.port === port) {
        this.losePort(
          "host-exited",
          `Native messaging send failed: ${asError(cause).message}`,
          true,
        );
      }
      throw new TransportError(
        makeProtocolError(
          KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
          `Native messaging send failed: ${asError(cause).message}`,
        ),
        cause,
      );
    }
  }

  request(
    frame: NativeRequestFrame | HostRequestFrame,
    timeoutMs?: number,
  ): Promise<HostToExtensionFrame> {
    const port = this.port;
    if (port === null) {
      return Promise.reject(
        new TransportError(
          makeProtocolError(
            KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
            "Native messaging port is not open",
          ),
        ),
      );
    }

    const action = frame.action;
    const nonce =
      "nonce" in frame && typeof frame.nonce === "string" ? frame.nonce : null;
    const timeout =
      timeoutMs ?? this.options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;

    return new Promise<HostToExtensionFrame>((resolve, reject) => {
      const pending: PendingRequest = {
        action,
        nonce,
        resolve,
        reject,
        timer: null,
      };

      pending.timer = this.setTimer(() => {
        this.removePending(pending);
        reject(
          new TransportError(
            makeProtocolError(
              KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
              `Native request "${action}" timed out after ${timeout} ms`,
            ),
          ),
        );
      }, Math.max(0, timeout));

      this.pending.push(pending);

      try {
        port.postMessage(frame);
      } catch (cause) {
        this.removePending(pending);
        if (this.port === port) {
          this.losePort(
            "host-exited",
            `Native messaging send failed: ${asError(cause).message}`,
            true,
          );
        }
        reject(
          new TransportError(
            makeProtocolError(
              KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED,
              `Native messaging send failed: ${asError(cause).message}`,
            ),
            cause,
          ),
        );
      }
    });
  }

  private handleFrame(message: unknown): void {
    if (!isRecord(message)) {
      // Chrome always hands us parsed JSON objects; ignore anything else
      // rather than crashing the service worker.
      return;
    }

    // WP3 sees every frame (including pushes); correlation below only settles
    // requests and never mutates the frame.
    try {
      this.handlers.onFrame(message as unknown as HostToExtensionFrame);
    } catch (cause) {
      console.warn("[friendlypass] transport onFrame handler failed:", asError(cause).message);
    }

    if (isErrorFrame(message)) {
      const error = protocolErrorFromFrame(message);
      const action = typeof message.action === "string" ? message.action : "";
      const target = this.takePendingForError(action);
      if (target !== null) {
        target.reject(new TransportError(error));
      } else {
        // No waiter: remember it for diagnostics. Do not tear the port down;
        // error frames (including host errors) keep the channel alive.
        this.lastErrorValue = error;
      }
      return;
    }

    if (
      message.action === "ping" ||
      message.action === "hello" ||
      message.action === "change-public-keys"
    ) {
      this.settleHostResponse(message);
      return;
    }

    if (isSuccessFrame(message)) {
      this.settleSuccess(message);
    }
  }

  private settleHostResponse(frame: Record<string, unknown>): void {
    const action = frame.action;
    if (
      action !== "ping" &&
      action !== "hello" &&
      action !== "change-public-keys"
    ) {
      return;
    }
    const responseNonce = typeof frame.nonce === "string" ? frame.nonce : null;
    const target = this.takePending((pending) => {
      if (pending.action !== action) {
        return false;
      }
      if (action === "hello" || pending.nonce === null || responseNonce === null) {
        return true;
      }
      if (action === "ping") {
        // `ping` echoes its nonce verbatim (§5.2).
        return pending.nonce === responseNonce;
      }
      // `change-public-keys` increments its nonce once (§2.2).
      return nonceMatches(pending.nonce, responseNonce);
    });
    if (target !== null) {
      target.resolve(frame as unknown as HostToExtensionFrame);
    }
  }

  private settleSuccess(frame: { action: string; message: string; nonce: string }): void {
    const target = this.takePending(
      (pending) =>
        pending.action === frame.action &&
        nonceMatches(pending.nonce, frame.nonce),
    );
    if (target !== null) {
      target.resolve(frame as unknown as HostToExtensionFrame);
    }
    // No waiter: duplicate/late response or `generate-password`'s bare
    // bookkeeping frame. Ignore; `onFrame` has already seen it.
  }

  private takePending(
    predicate: (pending: PendingRequest) => boolean,
  ): PendingRequest | null {
    const index = this.pending.findIndex(predicate);
    if (index < 0) {
      return null;
    }
    return this.removePendingAt(index);
  }

  private takePendingForError(action: string): PendingRequest | null {
    if (action === "") {
      // The host could not decode the action (e.g. 1001 frame-too-large).
      // Settle the oldest waiter rather than leaving it hanging.
      return this.pending.length > 0 ? this.removePendingAt(0) : null;
    }
    return this.takePending((pending) => pending.action === action);
  }

  private removePending(pending: PendingRequest): void {
    const index = this.pending.indexOf(pending);
    if (index >= 0) {
      this.removePendingAt(index);
    }
  }

  private removePendingAt(index: number): PendingRequest {
    const [pending] = this.pending.splice(index, 1);
    if (pending.timer !== null) {
      this.clearTimer(pending.timer);
      pending.timer = null;
    }
    return pending;
  }

  private rejectAllPending(protocol: ProtocolError): void {
    const pending = this.pending.splice(0, this.pending.length);
    for (const request of pending) {
      if (request.timer !== null) {
        this.clearTimer(request.timer);
        request.timer = null;
      }
      request.reject(new TransportError(protocol));
    }
  }

  // -------------------------------------------------------------------------
  // Heartbeat
  // -------------------------------------------------------------------------

  async ping(): Promise<HostPingResponse> {
    const nonce = randomNonce();
    const frame: HostRequestFrame = { action: "ping", nonce };
    const response = await this.request(
      frame,
      this.options.heartbeatTimeoutMs ?? HEARTBEAT_TIMEOUT_MS,
    );

    if (!isHostPingResponse(response)) {
      throw new TransportError(
        makeProtocolError(
          HostErrorCode.HOST_INTERNAL_ERROR,
          "Native host returned a malformed ping response",
        ),
      );
    }
    if (response.protocolVersion < SUPPORTED_PROTOCOL_VERSION) {
      throw new TransportError({
        code: HostErrorCode.HOST_INTERNAL_ERROR,
        name: "PROTOCOL_VERSION_UNSUPPORTED",
        message: `Native host protocol v${response.protocolVersion} is older than required v${SUPPORTED_PROTOCOL_VERSION}`,
        retryable: false,
      });
    }

    this.noteHostStatus(response);
    return response;
  }

  private noteHostStatus(status: HostPingResponse): void {
    const wasRunning = this.appRunningValue;
    this.appRunningValue = status.appRunning;
    if (typeof status.hostVersion === "string") {
      this.hostVersionValue = status.hostVersion;
    }
    this.appVersionValue = status.appVersion;
    this.protocolVersionValue = status.protocolVersion;

    if (status.appRunning !== wasRunning) {
      const event: TransportStateEvent = status.appRunning
        ? { type: "appUp", hello: this.helloValue }
        : { type: "appDown", hello: this.helloValue };
      this.handlers.onStateChange?.(event);
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    if (this.legacyModeValue) {
      // KeePassXC's proxy has no host-level ping; the session handshake is the
      // liveness signal there.
      return;
    }

    const interval = this.options.heartbeatIntervalMs ?? HEARTBEAT_INTERVAL_MS;
    const tick = (): void => {
      this.heartbeatTimer = null;
      if (this.port === null || this.shuttingDown || this.legacyModeValue) {
        return;
      }
      this.heartbeatTimer = this.setTimer(tick, interval);
      void this.heartbeatOnce();
    };
    this.heartbeatTimer = this.setTimer(tick, interval);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      this.clearTimer(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    this.heartbeatMisses = 0;
    this.heartbeatInFlight = false;
  }

  private async heartbeatOnce(): Promise<void> {
    if (this.heartbeatInFlight || this.port === null) {
      return;
    }
    this.heartbeatInFlight = true;
    try {
      await this.ping();
      this.heartbeatMisses = 0;
    } catch {
      this.heartbeatMisses += 1;
      if (
        this.heartbeatMisses >= HEARTBEAT_MAX_MISSES &&
        this.port !== null &&
        !this.shuttingDown
      ) {
        this.losePort(
          "heartbeat-timeout",
          `${this.heartbeatMisses} consecutive heartbeats failed`,
          true,
        );
      }
    } finally {
      this.heartbeatInFlight = false;
    }
  }

  // -------------------------------------------------------------------------
  // Timer helpers
  // -------------------------------------------------------------------------

  private setTimer(callback: () => void, delayMs: number): ReturnType<typeof setTimeout> {
    const setTimer = this.options.setTimeout;
    if (setTimer) {
      return setTimer(callback, delayMs);
    }
    return setTimeout(callback, delayMs);
  }

  private clearTimer(handle: ReturnType<typeof setTimeout>): void {
    const clearTimer = this.options.clearTimeout;
    if (clearTimer) {
      clearTimer(handle);
      return;
    }
    clearTimeout(handle);
  }
}

function nonceMatches(requestNonce: string | null, responseNonce: string): boolean {
  if (requestNonce === null) {
    return true;
  }
  if (requestNonce === responseNonce) {
    return true;
  }
  const incremented = incrementBase64Nonce(requestNonce);
  return incremented !== null && incremented === responseNonce;
}

function safeLastError(): string | undefined {
  try {
    const lastError = chrome.runtime.lastError;
    return lastError?.message;
  } catch {
    return undefined;
  }
}
