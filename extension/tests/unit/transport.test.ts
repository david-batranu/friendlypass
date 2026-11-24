/**
 * WP2 unit tests — native transport, reconnects, heartbeats and framing.
 *
 * These run without a browser: `FakePort` implements the small
 * `chrome.runtime.Port` surface the transport uses, under vitest fake timers.
 * Golden host frames come from `protocol/fixtures/host-actions.json`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createNativeTransport,
  incrementBase64Nonce,
} from "../../src/background/transport";
import type {
  NativePortLike,
  NativeTransport,
  NativeTransportOptions,
  TransportStateEvent,
} from "../../src/background/transport";
import {
  encodeNativeFrame,
  FrameError,
  NativeFrameDecoder,
} from "../../src/common/messages";
import { HostErrorCode, MAX_FRAME_BYTES } from "../../src/common/types";
import type {
  HostHelloResponse,
  HostToExtensionFrame,
} from "../../src/common/types";
import hostActionsFixture from "../../../protocol/fixtures/host-actions.json";
import changePublicKeysFixture from "../../../protocol/fixtures/change-public-keys.json";

// ---------------------------------------------------------------------------
// Fake native-messaging host
// ---------------------------------------------------------------------------

class FakePort implements NativePortLike {
  readonly sent: unknown[] = [];
  closed = false;

  private readonly messageListeners = new Set<
    (message: unknown, port: NativePortLike) => void
  >();
  private readonly disconnectListeners = new Set<(port: NativePortLike) => void>();

  readonly onMessage = {
    addListener: (listener: (message: unknown, port: NativePortLike) => void) => {
      this.messageListeners.add(listener);
    },
    removeListener: (listener: (message: unknown, port: NativePortLike) => void) => {
      this.messageListeners.delete(listener);
    },
  };

  readonly onDisconnect = {
    addListener: (listener: (port: NativePortLike) => void) => {
      this.disconnectListeners.add(listener);
    },
    removeListener: (listener: (port: NativePortLike) => void) => {
      this.disconnectListeners.delete(listener);
    },
  };

  constructor(private readonly host: FakeHost) {}

  postMessage(message: unknown): void {
    if (this.closed) {
      throw new Error("Attempting to use a disconnected port object");
    }
    this.sent.push(message);
    this.host.receive(this, message);
  }

  disconnect(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.emitDisconnect();
  }

  /** Host process SIGKILL / Chrome closing the port. */
  simulateHostExit(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.emitDisconnect();
  }

  reply(frame: unknown): void {
    for (const listener of [...this.messageListeners]) {
      listener(frame, this);
    }
  }

  private emitDisconnect(): void {
    for (const listener of [...this.disconnectListeners]) {
      listener(this);
    }
  }
}

class FakeHost {
  appRunning = true;
  silentHello = false;
  silentPing = false;
  holdRequests = false;
  helloOverride: Partial<HostHelloResponse> = {};

  readonly ports: FakePort[] = [];
  readonly requests: Array<Record<string, unknown>> = [];

  readonly connectNative = (_hostName: string): NativePortLike => {
    const port = new FakePort(this);
    this.ports.push(port);
    return port;
  };

  receive(port: FakePort, message: unknown): void {
    const frame = message as Record<string, unknown>;
    switch (frame.action) {
      case "hello":
        if (!this.silentHello) {
          this.replyHello(port);
        }
        return;
      case "ping":
        if (!this.silentPing) {
          this.replyPing(port, typeof frame.nonce === "string" ? frame.nonce : null);
        }
        return;
      case "change-public-keys":
        port.reply({
          action: "change-public-keys",
          version: "2.8.0",
          success: "true",
          nonce:
            typeof frame.nonce === "string"
              ? incrementBase64Nonce(frame.nonce) ?? frame.nonce
              : "",
          publicKey: "kdXTzQk5wy03DYMrsZRull3ZBjsIB7xR1oStaAr5cDY=",
        });
        return;
      default:
        this.requests.push(frame);
        if (!this.holdRequests) {
          port.reply({
            action: frame.action,
            message: "ciphertext",
            nonce: typeof frame.nonce === "string" ? frame.nonce : "",
          });
        }
    }
  }

  replyHello(port: FakePort): void {
    port.reply({
      action: "hello",
      success: "true",
      protocolVersion: 1,
      hostVersion: "0.1.0",
      appRunning: this.appRunning,
      appVersion: this.appRunning ? "0.1.0" : null,
      locked: this.appRunning ? false : null,
      databaseHash: null,
      sessionId: "test-session",
      hostPid: 4242,
      ...this.helloOverride,
    });
  }

  replyPing(port: FakePort, nonce: string | null): void {
    port.reply({
      action: "ping",
      success: "true",
      protocolVersion: 1,
      hostVersion: "0.1.0",
      appRunning: this.appRunning,
      appVersion: this.appRunning ? "0.1.0" : null,
      locked: this.appRunning ? false : null,
      databaseHash: null,
      ...(nonce === null ? {} : { nonce }),
    });
  }
}

interface Harness {
  transport: NativeTransport;
  events: TransportStateEvent[];
  frames: HostToExtensionFrame[];
  disconnects: string[];
}

function setup(
  host: FakeHost,
  options: Partial<NativeTransportOptions> = {},
): Harness {
  const events: TransportStateEvent[] = [];
  const frames: HostToExtensionFrame[] = [];
  const disconnects: string[] = [];

  const transport = createNativeTransport(
    {
      onFrame: (frame) => frames.push(frame),
      onConnect: () => undefined,
      onDisconnect: (reason) => disconnects.push(reason),
      onStateChange: (event) => events.push(event),
    },
    {
      connectNative: host.connectNative,
      random: () => 0.5, // jitter factor 1.0 -> deterministic delays
      ...options,
    },
  );

  return { transport, events, frames, disconnects };
}

function nonce(index: number): string {
  // The transport only compares strings for correlated replies; a real 24-byte
  // Base64 nonce is used where the increment rule matters.
  return `nonce-${index}`;
}

function requestFrame(index: number, action = "get-logins"): {
  action: string;
  message: string;
  nonce: string;
  clientID: string;
} {
  return {
    action,
    message: `ciphertext-${index}`,
    nonce: nonce(index),
    clientID: "client-id",
  };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Connect / correlation
// ---------------------------------------------------------------------------

describe("native transport connect", () => {
  it("is idempotent and performs hello once", async () => {
    const host = new FakeHost();
    const { transport } = setup(host);

    const [a, b, c] = await Promise.all([
      transport.connect(),
      transport.connect(),
      transport.connect(),
    ]);

    expect(a.action).toBe("hello");
    expect(b).toBe(a);
    expect(c).toBe(a);
    expect(host.ports).toHaveLength(1);
    expect(transport.connected).toBe(true);
    expect(transport.status.state).toBe("READY");
    expect(transport.appRunning).toBe(true);

    // A later call joins the already-established session.
    await transport.connect();
    expect(host.ports).toHaveLength(1);
  });

  it("correlates out-of-order success frames by action and nonce", async () => {
    const host = new FakeHost();
    host.holdRequests = true;
    const { transport } = setup(host);
    await transport.connect();
    const port = host.ports[0];

    const first = transport.request(requestFrame(1, "get-logins"));
    const second = transport.request(requestFrame(2, "get-totp"));
    const sent = port.sent.filter(
      (frame) => (frame as Record<string, unknown>).action !== "hello",
    ) as Array<Record<string, unknown>>;

    // Respond newest-first: the transport must not rely on arrival order.
    port.reply({
      action: "get-totp",
      message: "totp-response",
      nonce: sent[1].nonce,
    });
    port.reply({
      action: "get-logins",
      message: "login-response",
      nonce: sent[0].nonce,
    });

    await expect(second).resolves.toMatchObject({
      action: "get-totp",
      message: "totp-response",
    });
    await expect(first).resolves.toMatchObject({
      action: "get-logins",
      message: "login-response",
    });
  });

  it("accepts the incremented nonce on change-public-keys (golden vector)", async () => {
    const vector = changePublicKeysFixture.vectors[0];
    expect(incrementBase64Nonce(vector.request.nonce)).toBe(vector.response.nonce);

    const host = new FakeHost();
    const { transport } = setup(host);
    await transport.connect();
    const port = host.ports[0];

    const pending = transport.request({
      action: "change-public-keys",
      publicKey: vector.request.frame.publicKey,
      nonce: vector.request.nonce,
      clientID: vector.request.frame.clientID,
    });
    const sent = port.sent.at(-1) as Record<string, unknown>;
    expect(sent.action).toBe("change-public-keys");
    await expect(pending).resolves.toMatchObject({
      action: "change-public-keys",
      nonce: vector.response.nonce,
    });
  });

  it("ignores a success frame with a nonce that matches no request", async () => {
    const host = new FakeHost();
    host.holdRequests = true;
    const { transport, frames } = setup(host);
    await transport.connect();
    const port = host.ports[0];

    const pending = transport.request(requestFrame(1));
    port.reply({ action: "get-logins", message: "stale", nonce: nonce(99) });

    // Still pending; settle with the correct response afterwards.
    port.reply({
      action: "get-logins",
      message: "fresh",
      nonce: nonce(1),
    });
    await expect(pending).resolves.toMatchObject({ message: "fresh" });
    expect(frames.some((frame) => (frame as { message?: string }).message === "stale")).toBe(true);
  });

  it("settles a request with a typed error frame and keeps the port", async () => {
    const host = new FakeHost();
    host.holdRequests = true;
    const { transport } = setup(host);
    await transport.connect();
    const port = host.ports[0];

    const pending = transport.request(requestFrame(1));
    port.reply({
      action: "get-logins",
      error: "No logins found",
      errorCode: "15",
    });

    await expect(pending).rejects.toMatchObject({
      code: 15,
      retryable: false,
    });
    expect(transport.connected).toBe(true);
  });

  it("times out a request with code 5 without losing the port", async () => {
    const host = new FakeHost();
    host.holdRequests = true;
    const { transport } = setup(host);
    await transport.connect();

    const pending = transport.request(requestFrame(1), 50);
    const rejection = expect(pending).rejects.toMatchObject({
      code: 5,
      retryable: true,
    });

    await vi.advanceTimersByTimeAsync(50);
    await rejection;
    expect(transport.connected).toBe(true);
    expect(transport.status.lastError).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Port loss / reconnect
// ---------------------------------------------------------------------------

describe("native transport reconnect", () => {
  it("rejects pending requests on host SIGKILL, fails fast, then reconnects", async () => {
    const host = new FakeHost();
    host.holdRequests = true;
    const { transport, events } = setup(host);
    await transport.connect();
    const firstPort = host.ports[0];

    const inFlight = transport.request(requestFrame(1));
    const rejection = expect(inFlight).rejects.toMatchObject({ code: 5 });

    // SIGKILL equivalent: Chrome fires onDisconnect without a reply.
    firstPort.simulateHostExit();
    await rejection;
    expect(transport.connected).toBe(false);
    expect(transport.status.state).toBe("DISCONNECTED");
    expect(events.some((event) => event.type === "disconnected")).toBe(true);

    // No port: the next request fails immediately with the typed error.
    await expect(transport.request(requestFrame(2))).rejects.toMatchObject({
      code: 5,
    });

    // First backoff step is 500 ms (jitter factor 1.0 in the harness).
    await vi.advanceTimersByTimeAsync(500);
    expect(host.ports).toHaveLength(2);
    expect(transport.connected).toBe(true);
    expect(transport.status.state).toBe("READY");

    host.holdRequests = false;
    await expect(transport.request(requestFrame(3))).resolves.toMatchObject({
      action: "get-logins",
    });
  });

  it("recovers after the app is down for 60 s without user action", async () => {
    const host = new FakeHost();
    host.appRunning = false;
    const { transport, events } = setup(host);

    await transport.connect();
    expect(transport.appRunning).toBe(false);
    expect(events.some((event) => event.type === "appDown")).toBe(true);

    // The host stays alive while the app is down, so no reconnect happens.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(transport.appRunning).toBe(false);
    expect(host.ports).toHaveLength(1);
    expect(transport.connected).toBe(true);

    host.appRunning = true;
    await vi.advanceTimersByTimeAsync(20_000);

    expect(transport.appRunning).toBe(true);
    expect(events.some((event) => event.type === "appUp")).toBe(true);
    expect(host.ports).toHaveLength(1);
  });

  it("destroys the port after two missed heartbeats", async () => {
    const host = new FakeHost();
    host.silentPing = true;
    host.holdRequests = true;
    const { transport, events } = setup(host, {
      autoReconnect: false,
      heartbeatIntervalMs: 1000,
      heartbeatTimeoutMs: 100,
    });

    await transport.connect();
    const pending = transport.request(requestFrame(1));
    const rejection = expect(pending).rejects.toMatchObject({ code: 5 });

    await vi.advanceTimersByTimeAsync(1200); // first ping times out
    expect(transport.connected).toBe(true);

    await vi.advanceTimersByTimeAsync(1200); // second miss -> destroy
    await rejection;

    expect(transport.connected).toBe(false);
    expect(host.ports).toHaveLength(1);
    expect(
      events.some(
        (event) =>
          event.type === "disconnected" && event.reason === "heartbeat-timeout",
      ),
    ).toBe(true);
  });

  it("settles 50 concurrent requests when the port dies", async () => {
    const host = new FakeHost();
    host.holdRequests = true;
    const { transport } = setup(host);
    await transport.connect();
    const port = host.ports[0];

    const requests = Array.from({ length: 50 }, (_, index) =>
      transport.request(requestFrame(index)),
    );
    const resultsPromise = Promise.allSettled(requests);

    port.simulateHostExit();
    const results = await resultsPromise;

    expect(results).toHaveLength(50);
    for (const result of results) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected") {
        expect(result.reason).toMatchObject({ code: 5 });
      }
    }
  });

  it("settles 50 concurrent requests that all succeed", async () => {
    const host = new FakeHost();
    host.holdRequests = true;
    const { transport } = setup(host);
    await transport.connect();
    const port = host.ports[0];

    const frames = Array.from({ length: 50 }, (_, index) =>
      requestFrame(index, index % 2 === 0 ? "get-logins" : "get-totp"),
    );
    const requests = frames.map((frame) => transport.request(frame));

    // Answer in reverse order to exercise nonce correlation under load.
    for (const frame of [...frames].reverse()) {
      port.reply({
        action: frame.action,
        message: `response-${frame.nonce}`,
        nonce: frame.nonce,
      });
    }

    const results = await Promise.allSettled(requests);
    expect(results.every((result) => result.status === "fulfilled")).toBe(true);
  });

  it("rehydrates cleanly after a simulated service-worker restart", async () => {
    const host = new FakeHost();
    host.holdRequests = true;
    const first = setup(host);
    await first.transport.connect();
    const oldPort = host.ports[0];

    const pending = first.transport.request(requestFrame(1));
    const rejection = expect(pending).rejects.toMatchObject({ code: 5 });

    // SW shutdown/reload: the old instance settles everything and closes.
    first.transport.disconnect();
    await rejection;
    expect(first.transport.connected).toBe(false);

    // New worker/module instance rehydrates from scratch.
    host.holdRequests = false;
    const second = setup(host);
    await second.transport.connect();

    expect(host.ports).toHaveLength(2);
    expect(host.ports[1]).not.toBe(oldPort);
    await expect(second.transport.request(requestFrame(2))).resolves.toMatchObject({
      action: "get-logins",
    });
  });

  it("does not create unhandled rejections when pending requests die", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);

    try {
      const host = new FakeHost();
      host.holdRequests = true;
      const { transport } = setup(host);
      await transport.connect();
      const port = host.ports[0];

      const requests = Array.from({ length: 8 }, (_, index) =>
        transport.request(requestFrame(index)),
      );
      const settled = Promise.allSettled(requests);
      port.simulateHostExit();
      await settled;

      // Let any microtask-scheduled rejections surface.
      await Promise.resolve();
      await Promise.resolve();

      expect(unhandled).toHaveLength(0);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});

// ---------------------------------------------------------------------------
// Golden host frames + framing decoder (protocol/ACTIONS.md §7.3)
// ---------------------------------------------------------------------------

describe("host-level frames", () => {
  it("uses the golden ping/hello shapes from protocol/fixtures", async () => {
    const helloVector = hostActionsFixture.vectors.find(
      (vector) => vector.name === "host/hello-startup",
    );
    const pingVector = hostActionsFixture.vectors.find(
      (vector) => vector.name === "host/ping-app-up",
    );
    expect(helloVector?.response?.frame.action).toBe("hello");
    expect(pingVector?.response?.frame.action).toBe("ping");

    const host = new FakeHost();
    const { transport } = setup(host);
    const hello = await transport.connect();
    expect(hello).toMatchObject({
      action: "hello",
      protocolVersion: 1,
      appRunning: true,
    });

    const ping = await transport.ping();
    expect(ping).toMatchObject({
      action: "ping",
      appRunning: true,
      protocolVersion: 1,
    });
    expect(typeof ping.nonce).toBe("string");
  });
});

describe("NativeFrameDecoder", () => {
  it("reassembles a frame split across chunks", () => {
    const frame = encodeNativeFrame({ action: "ping" });
    const decoder = new NativeFrameDecoder();

    expect(decoder.push(frame.subarray(0, 2))).toEqual([]);
    expect(decoder.pendingBytes).toBe(2);
    expect(decoder.push(frame.subarray(2))).toEqual([{ action: "ping" }]);
    expect(decoder.pendingBytes).toBe(0);
  });

  it("returns coalesced frames", () => {
    const first = encodeNativeFrame({ action: "ping" });
    const second = encodeNativeFrame({ action: "hello" });
    const joined = new Uint8Array(first.byteLength + second.byteLength);
    joined.set(first, 0);
    joined.set(second, first.byteLength);

    const decoder = new NativeFrameDecoder();
    expect(decoder.push(joined)).toEqual([
      { action: "ping" },
      { action: "hello" },
    ]);
  });

  it("rejects an oversized frame with code 1001", () => {
    const frame = new Uint8Array(4);
    new DataView(frame.buffer).setUint32(0, MAX_FRAME_BYTES + 1, true);
    const decoder = new NativeFrameDecoder();

    try {
      decoder.push(frame);
      throw new Error("expected FrameError");
    } catch (cause) {
      expect(cause).toBeInstanceOf(FrameError);
      expect((cause as FrameError).code).toBe(HostErrorCode.FRAME_TOO_LARGE);
    }
    expect(decoder.pendingBytes).toBe(0);
  });

  it("rejects garbage JSON with code 1002", () => {
    const payload = new TextEncoder().encode("not json");
    const frame = new Uint8Array(4 + payload.byteLength);
    new DataView(frame.buffer).setUint32(0, payload.byteLength, true);
    frame.set(payload, 4);
    const decoder = new NativeFrameDecoder();

    try {
      decoder.push(frame);
      throw new Error("expected FrameError");
    } catch (cause) {
      expect(cause).toBeInstanceOf(FrameError);
      expect((cause as FrameError).code).toBe(HostErrorCode.MALFORMED_FRAME);
    }
  });

  it("rejects a non-object JSON payload", () => {
    const payload = new TextEncoder().encode("[]");
    const frame = new Uint8Array(4 + payload.byteLength);
    new DataView(frame.buffer).setUint32(0, payload.byteLength, true);
    frame.set(payload, 4);
    const decoder = new NativeFrameDecoder();

    expect(() => decoder.push(frame)).toThrow(FrameError);
  });
});
