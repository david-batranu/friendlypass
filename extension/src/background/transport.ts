/**
 * Native-messaging transport (WP2).
 *
 * Owns: `chrome.runtime.connectNative(NATIVE_HOST_NAME)`, framing
 * (`NativeFrameDecoder`), heartbeat, reconnect backoff, request queueing and
 * pending-request rejection. Never reassembles or correlates app actions —
 * that is `session.ts`.
 *
 * TODO(WP2): implement. The interface below is the boundary WP3 codes against.
 */

import type {
  HostHelloResponse,
  HostPingResponse,
  HostToExtensionFrame,
  NativeRequestFrame,
} from "../common/types";

export type TransportDisconnectReason =
  | "port-closed"
  | "host-exited"
  | "heartbeat-timeout"
  | "shutdown";

export interface TransportHandlers {
  /** Called for every complete frame read from the host, including pushes. */
  onFrame(frame: HostToExtensionFrame): void;
  /** Called once when the port is gone. Pending requests must be rejected. */
  onDisconnect(reason: TransportDisconnectReason, detail?: string): void;
  /** Called after the port opens (before `hello` completes). */
  onConnect(): void;
}

export interface NativeTransport {
  readonly connected: boolean;
  /** Idempotent: opens the port and performs `hello`. */
  connect(): Promise<HostHelloResponse>;
  disconnect(): void;
  /** Host-level liveness probe with a 3 s timeout. */
  ping(): Promise<HostPingResponse>;
  /** Sends an already-built protocol frame. Rejects if the port is gone. */
  send(frame: NativeRequestFrame): Promise<void>;
}

export function createNativeTransport(
  _handlers: TransportHandlers,
): NativeTransport {
  throw new Error("TODO(WP2): implement native transport");
}
