/**
 * friendlypass browser extension — shared message helpers and constants.
 *
 * This is the runtime counterpart of `types.ts`: native-messaging framing,
 * error-code tables, type guards, and the typed internal messaging helpers.
 *
 * Wire values are frozen by `protocol/ACTIONS.md`. Owned by WP3; see
 * `protocol/OWNERSHIP.md`.
 */

import {
  HostErrorCode,
  INTERNAL_CHANNEL,
  KpxcAction,
  KpxcErrorCode,
  MAX_FRAME_BYTES,
  PushAction,
} from "./types";
import type {
  B64,
  BackgroundEventAction,
  BackgroundEventArgs,
  BackgroundRequestAction,
  BackgroundRequestArgs,
  BackgroundRequestResult,
  ContentCommandAction,
  ContentCommandArgs,
  ContentCommandResult,
  HostErrorFrame,
  HostHelloResponse,
  HostPingResponse,
  InternalEnvelope,
  InternalErr,
  InternalResult,
  NativeErrorFrame,
  NativePushFrame,
  NativeRequestFrame,
  NativeSuccessFrame,
  ProtocolError,
} from "./types";

// ---------------------------------------------------------------------------
// Error tables (mirror KeePassXC BrowserMessageBuilder::getErrorMessage)
// ---------------------------------------------------------------------------

/**
 * English error strings. KeePassXC localises these with Qt translations; the
 * wire value is whatever the server sends, so clients MUST NOT switch on this
 * text — switch on `errorCode`.
 */
export const ERROR_MESSAGES: Readonly<Record<number, string>> = Object.freeze({
  0: "Unknown error",
  1: "Database not opened",
  2: "Database hash not available",
  3: "Client public key not received",
  4: "Cannot decrypt message",
  5: "Timed out or not connected",
  6: "Action cancelled or denied",
  7: "Message encryption failed.",
  8: "KeePassXC association failed, try again",
  9: "Key change failed",
  10: "Encryption key is not recognized",
  11: "No saved databases found",
  12: "Incorrect action",
  13: "Empty message received",
  14: "No URL provided",
  15: "No logins found",
  16: "No groups found",
  17: "Cannot create new group",
  18: "No valid UUID provided",
  19: "Access to all entries is denied",
  20: "Attestation not supported",
  21: "Credential is excluded",
  22: "Passkeys request canceled",
  23: "Invalid user verification",
  24: "Empty public key",
  25: "Invalid URL provided",
  26: "Origin is empty or not allowed",
  27: "Effective domain is not a valid domain",
  28: "Origin and RP ID do not match",
  29: "No supported algorithms were provided",
  30: "Wait for timer to expire",
  31: "Unknown passkeys error",
  32: "Challenge is shorter than required minimum length",
  33: "user.id does not match the required length",
  34: "Username or password cannot contain references",
  35: "Passkeys evaluate-by-credential is not supported",
  36: "Passkeys evaluate-by-credential is not empty",
  37: "Passkeys evaluate-by-credential was not found",

  // friendlypass host-level codes (1000+)
  1001: "Message exceeds the 1 MiB frame limit",
  1002: "Malformed native message",
  1003: "Unknown host action",
  1004: "Native host internal error",
  1005: "friendlypass is not running",
  1006: "Encryption required for this action",
});

const ERROR_NAMES: Readonly<Record<number, string>> = Object.freeze({
  ...Object.fromEntries(
    Object.entries(KpxcErrorCode).map(([name, code]) => [code, name]),
  ),
  ...Object.fromEntries(
    Object.entries(HostErrorCode).map(([name, code]) => [code, name]),
  ),
});

export function errorMessageFor(code: number): string {
  return ERROR_MESSAGES[code] ?? ERROR_MESSAGES[0];
}

export function errorNameFor(code: number): string {
  return ERROR_NAMES[code] ?? "UNKNOWN_ERROR";
}

/** Errors that may succeed if retried after the connection recovers. */
export function isRetryableError(code: number): boolean {
  return (
    code === KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED ||
    code === KpxcErrorCode.DATABASE_NOT_OPENED ||
    code === KpxcErrorCode.ACTION_CANCELLED_OR_DENIED ||
    code === HostErrorCode.APP_UNAVAILABLE ||
    code === HostErrorCode.HOST_INTERNAL_ERROR
  );
}

export function makeProtocolError(
  code: number,
  message = errorMessageFor(code),
): ProtocolError {
  return {
    code,
    name: errorNameFor(code),
    message,
    retryable: isRetryableError(code),
  };
}

/** Parse any wire error envelope into a normalised error. */
export function protocolErrorFromFrame(
  frame: NativeErrorFrame | HostErrorFrame,
): ProtocolError {
  const code = Number.parseInt(frame.errorCode, 10);
  if (!Number.isFinite(code)) {
    return makeProtocolError(0, frame.error || "Unknown error");
  }
  return makeProtocolError(code, frame.error || errorMessageFor(code));
}

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isNativeRequestFrame(
  value: unknown,
): value is NativeRequestFrame {
  return (
    isRecord(value) &&
    typeof value["action"] === "string" &&
    typeof value["nonce"] === "string" &&
    typeof value["clientID"] === "string" &&
    (typeof value["message"] === "string" ||
      typeof value["publicKey"] === "string")
  );
}

/** An unencrypted error reply, from KeePassXC or from the friendlypass host. */
export function isErrorFrame(
  value: unknown,
): value is NativeErrorFrame | HostErrorFrame {
  return (
    isRecord(value) &&
    typeof value["action"] === "string" &&
    typeof value["error"] === "string" &&
    typeof value["errorCode"] === "string" &&
    !isRecord(value["message"])
  );
}

export function isSuccessFrame(value: unknown): value is NativeSuccessFrame {
  return (
    isRecord(value) &&
    typeof value["action"] === "string" &&
    typeof value["message"] === "string" &&
    typeof value["nonce"] === "string"
  );
}

/**
 * Unencrypted `change-public-keys` reply. Unlike encrypted successes it carries
 * `success`/`publicKey` in the outer frame and no `message` field.
 */
export interface ChangePublicKeysResponseFrame {
  action: typeof KpxcAction.CHANGE_PUBLIC_KEYS;
  version?: string;
  success: "true";
  nonce: B64;
  publicKey: B64;
}

export function isChangePublicKeysResponse(
  value: unknown,
): value is ChangePublicKeysResponseFrame {
  return (
    isRecord(value) &&
    value["action"] === KpxcAction.CHANGE_PUBLIC_KEYS &&
    value["success"] === "true" &&
    typeof value["nonce"] === "string" &&
    typeof value["publicKey"] === "string"
  );
}

/** Host-originated error (marked with `hostError: true`). */
export function isHostErrorFrame(value: unknown): value is HostErrorFrame {
  return (
    isErrorFrame(value) &&
    (value as unknown as Record<string, unknown>)["hostError"] === true
  );
}

/** Decrypted inner response that passed the `success: "true"` prefix check. */
export function isInnerSuccessResponse(
  value: unknown,
): value is Record<string, unknown> & { success: "true"; nonce: string } {
  return (
    isRecord(value) &&
    value["success"] === "true" &&
    typeof value["nonce"] === "string"
  );
}

export function isHostPingResponse(value: unknown): value is HostPingResponse {
  return (
    isRecord(value) &&
    value["action"] === "ping" &&
    value["success"] === "true" &&
    typeof value["protocolVersion"] === "number" &&
    typeof value["hostVersion"] === "string"
  );
}

export function isHostHelloResponse(value: unknown): value is HostHelloResponse {
  return (
    isRecord(value) &&
    value["action"] === "hello" &&
    value["success"] === "true" &&
    typeof value["protocolVersion"] === "number" &&
    typeof value["hostVersion"] === "string"
  );
}

export function isPushFrame(value: unknown): value is NativePushFrame {
  return (
    isRecord(value) &&
    (value["action"] === PushAction.DATABASE_LOCKED ||
      value["action"] === PushAction.DATABASE_UNLOCKED ||
      value["action"] === PushAction.DATABASE_CHANGED)
  );
}

/** True for actions answered by the host without the app. */
export function isHostAction(action: string): boolean {
  return action === "ping" || action === "hello";
}

/** True for actions that must always be encrypted with the session key. */
export function isEncryptedAction(action: string): boolean {
  return (
    action !== KpxcAction.CHANGE_PUBLIC_KEYS && !isHostAction(action)
  );
}

// ---------------------------------------------------------------------------
// Native messaging framing: 4-byte little-endian length + UTF-8 JSON
// ---------------------------------------------------------------------------

export class FrameError extends Error {
  readonly code:
    | typeof HostErrorCode.FRAME_TOO_LARGE
    | typeof HostErrorCode.MALFORMED_FRAME;

  constructor(
    code:
      | typeof HostErrorCode.FRAME_TOO_LARGE
      | typeof HostErrorCode.MALFORMED_FRAME,
    message: string,
  ) {
    super(message);
    this.name = "FrameError";
    this.code = code;
  }
}

/** Serialise one protocol object into a native-messaging frame. */
export function encodeNativeFrame(value: unknown): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(value));
  if (payload.byteLength > MAX_FRAME_BYTES) {
    throw new FrameError(
      HostErrorCode.FRAME_TOO_LARGE,
      `frame payload ${payload.byteLength} exceeds ${MAX_FRAME_BYTES} bytes`,
    );
  }

  const frame = new Uint8Array(4 + payload.byteLength);
  new DataView(frame.buffer).setUint32(0, payload.byteLength, true);
  frame.set(payload, 4);
  return frame;
}

/**
 * Incremental native-messaging parser.
 *
 * Chrome delivers arbitrary chunks; a chunk may contain a partial frame, a
 * complete frame, or several frames. `push()` returns every complete frame and
 * retains the remainder. Oversized frames raise `FrameError` (the caller must
 * discard the frame and keep the port open) and reset the buffer, because the
 * rest of the oversized payload cannot be resynchronised safely.
 */
export class NativeFrameDecoder {
  private buffer = new Uint8Array(0);
  private readonly decoder = new TextDecoder("utf-8", { fatal: true });

  push(chunk: Uint8Array): unknown[] {
    if (chunk.byteLength > 0) {
      const next = new Uint8Array(this.buffer.byteLength + chunk.byteLength);
      next.set(this.buffer, 0);
      next.set(chunk, this.buffer.byteLength);
      this.buffer = next;
    }

    const frames: unknown[] = [];
    let offset = 0;

    while (this.buffer.byteLength - offset >= 4) {
      const view = new DataView(
        this.buffer.buffer,
        this.buffer.byteOffset + offset,
        4,
      );
      const length = view.getUint32(0, true);
      if (length > MAX_FRAME_BYTES) {
        this.reset();
        throw new FrameError(
          HostErrorCode.FRAME_TOO_LARGE,
          `frame payload ${length} exceeds ${MAX_FRAME_BYTES} bytes`,
        );
      }
      if (this.buffer.byteLength - offset - 4 < length) {
        break;
      }

      const start = offset + 4;
      const payload = this.buffer.subarray(start, start + length);
      let parsed: unknown;
      try {
        parsed = JSON.parse(this.decoder.decode(payload));
      } catch (cause) {
        this.reset();
        throw new FrameError(
          HostErrorCode.MALFORMED_FRAME,
          `frame is not valid UTF-8 JSON: ${String(cause)}`,
        );
      }
      if (!isRecord(parsed)) {
        this.reset();
        throw new FrameError(
          HostErrorCode.MALFORMED_FRAME,
          "frame payload must be a JSON object",
        );
      }
      frames.push(parsed);
      offset = start + length;
    }

    this.buffer = this.buffer.slice(offset);
    return frames;
  }

  /** Bytes retained for the next chunk (diagnostics/tests). */
  get pendingBytes(): number {
    return this.buffer.byteLength;
  }

  reset(): void {
    this.buffer = new Uint8Array(0);
  }
}

// ---------------------------------------------------------------------------
// Internal message API helpers
// ---------------------------------------------------------------------------

function nextRequestId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Correlation id for diagnostics and `generate-password` `requestID`s. */
export function newRequestId(): string {
  return nextRequestId();
}

export function internalError(
  code: number | InternalErr["error"]["code"],
  message: string,
): InternalErr {
  const numeric = typeof code === "number" ? code : undefined;
  return {
    ok: false,
    error: {
      code,
      name: numeric === undefined ? String(code) : errorNameFor(numeric),
      message,
      retryable: numeric === undefined ? false : isRetryableError(numeric),
    },
  };
}

export function isInternalResult(value: unknown): value is InternalResult<unknown> {
  return (
    isRecord(value) &&
    typeof value["ok"] === "boolean" &&
    (value["ok"] === true ? "value" in value : isRecord(value["error"]))
  );
}

function isInternalEnvelope(value: unknown): value is InternalEnvelope<string, unknown> {
  return (
    isRecord(value) &&
    value["channel"] === INTERNAL_CHANNEL &&
    typeof value["action"] === "string" &&
    typeof value["requestId"] === "string"
  );
}

/**
 * Send a typed request to the service worker.
 *
 * ```ts
 * const status = await sendBackgroundMessage("status.get");
 * const logins = await sendBackgroundMessage("logins.get", { url });
 * ```
 */
export function sendBackgroundMessage<A extends BackgroundRequestAction>(
  action: A,
  ...args: BackgroundRequestArgs<A> extends void
    ? []
    : [BackgroundRequestArgs<A>]
): Promise<InternalResult<BackgroundRequestResult<A>>> {
  const envelope: InternalEnvelope<A, BackgroundRequestArgs<A> | undefined> = {
    channel: INTERNAL_CHANNEL,
    action,
    args: args[0],
    requestId: nextRequestId(),
  };

  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(envelope, (response: unknown) => {
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          resolve(
            internalError(
              "INTERNAL_ERROR",
              lastError.message ?? "Extension messaging channel closed",
            ),
          );
          return;
        }
        resolve(
          isInternalResult(response)
            ? (response as InternalResult<BackgroundRequestResult<A>>)
            : internalError(
                "INTERNAL_ERROR",
                "Malformed response from the service worker",
              ),
        );
      });
    } catch (cause) {
      resolve(internalError("INTERNAL_ERROR", String(cause)));
    }
  });
}

type AnyBackgroundHandler = (
  args: unknown,
  sender: chrome.runtime.MessageSender,
) => unknown;

/**
 * Register the service worker's request handlers. Returns an unsubscribe
 * function. Listeners must be registered synchronously at worker startup.
 */
export function onBackgroundMessage(handlers: {
  [A in BackgroundRequestAction]: (
    args: BackgroundRequestArgs<A>,
    sender: chrome.runtime.MessageSender,
  ) =>
    | BackgroundRequestResult<A>
    | Promise<BackgroundRequestResult<A>>;
}): () => void {
  const listener = (
    message: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void,
  ): boolean => {
    if (!isInternalEnvelope(message)) {
      return false;
    }

    const handler = (handlers as Record<string, AnyBackgroundHandler>)[
      message.action
    ];
    if (!handler) {
      sendResponse(
        internalError(
          "NOT_IMPLEMENTED",
          `No handler for internal action "${message.action}"`,
        ),
      );
      return true;
    }

    Promise.resolve()
      .then(() => handler(message.args, sender))
      .then((value) => sendResponse({ ok: true, value }))
      .catch((cause: unknown) =>
        sendResponse(internalError("INTERNAL_ERROR", String(cause))),
      );
    return true;
  };

  chrome.runtime.onMessage.addListener(listener);
  return () => chrome.runtime.onMessage.removeListener(listener);
}

/**
 * Send a command to one content-script frame. Rejects only for transport
 * failures; the command result is returned unwrapped.
 */
export function sendContentCommand<A extends ContentCommandAction>(
  tabId: number,
  action: A,
  ...args: ContentCommandArgs<A> extends void ? [] : [ContentCommandArgs<A>]
): Promise<InternalResult<ContentCommandResult<A>>> {
  const envelope: InternalEnvelope<A, ContentCommandArgs<A> | undefined> = {
    channel: INTERNAL_CHANNEL,
    action,
    args: args[0],
    requestId: nextRequestId(),
  };

  return new Promise((resolve) => {
    try {
      chrome.tabs.sendMessage(tabId, envelope, (response: unknown) => {
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          resolve(
            internalError(
              "INTERNAL_ERROR",
              lastError.message ?? `No content script in tab ${tabId}`,
            ),
          );
          return;
        }
        resolve(
          isInternalResult(response)
            ? (response as InternalResult<ContentCommandResult<A>>)
            : internalError(
                "INTERNAL_ERROR",
                "Malformed response from the content script",
              ),
        );
      });
    } catch (cause) {
      resolve(internalError("INTERNAL_ERROR", String(cause)));
    }
  });
}

/**
 * Register content-script command handlers. Content scripts must register at
 * document_start so fills do not race page load.
 */
export function onContentCommand(handlers: {
  [A in ContentCommandAction]: (
    args: ContentCommandArgs<A>,
    sender: chrome.runtime.MessageSender,
  ) => ContentCommandResult<A> | Promise<ContentCommandResult<A>>;
}): () => void {
  const listener = (
    message: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void,
  ): boolean => {
    if (!isInternalEnvelope(message)) {
      return false;
    }

    const handler = (handlers as Record<string, AnyBackgroundHandler>)[
      message.action
    ];
    if (!handler) {
      sendResponse(
        internalError(
          "NOT_IMPLEMENTED",
          `No handler for content action "${message.action}"`,
        ),
      );
      return true;
    }

    Promise.resolve()
      .then(() => handler(message.args, sender))
      .then((value) => sendResponse({ ok: true, value }))
      .catch((cause: unknown) =>
        sendResponse(internalError("INTERNAL_ERROR", String(cause))),
      );
    return true;
  };

  chrome.runtime.onMessage.addListener(listener);
  return () => chrome.runtime.onMessage.removeListener(listener);
}

// ---------------------------------------------------------------------------
// Background -> extension-context events (internal, fire-and-forget)
// ---------------------------------------------------------------------------

function isEventEnvelope(
  value: unknown,
): value is InternalEnvelope<string, unknown> {
  return (
    isRecord(value) &&
    value["channel"] === INTERNAL_CHANNEL &&
    typeof value["action"] === "string" &&
    typeof value["requestId"] === "string"
  );
}

/**
 * Broadcast a `status.changed` / `state.snapshot` event. Never throws and never
 * rejects: when no context is listening, Chrome reports "receiving end does not
 * exist"; that is normal and must not surface as an unhandled rejection.
 */
export function sendBackgroundEvent<A extends BackgroundEventAction>(
  action: A,
  payload: BackgroundEventArgs<A>,
): void {
  if (typeof chrome === "undefined" || !chrome.runtime?.sendMessage) {
    return;
  }
  const envelope: InternalEnvelope<A, BackgroundEventArgs<A>> = {
    channel: INTERNAL_CHANNEL,
    action,
    args: payload,
    requestId: nextRequestId(),
  };
  try {
    const result = chrome.runtime.sendMessage(envelope) as unknown;
    if (
      typeof result === "object" &&
      result !== null &&
      typeof (result as Promise<unknown>).catch === "function"
    ) {
      (result as Promise<unknown>).catch(() => undefined);
    }
  } catch {
    // No listener (service worker starting, all pages closed) or a context that
    // was destroyed mid-send. Events are best-effort by design.
  }
}

/**
 * Subscribe to background events. The listener must be cheap and must not
 * throw; malformed events are ignored. Returns an unsubscribe function.
 */
export function onBackgroundEvent(
  listener: (
    action: BackgroundEventAction,
    payload: unknown,
    requestId: string,
  ) => void,
): () => void {
  const handler = (message: unknown): false => {
    if (!isEventEnvelope(message)) {
      return false;
    }
    if (message.action === "status.changed" || message.action === "state.snapshot") {
      try {
        listener(
          message.action as BackgroundEventAction,
          message.args,
          message.requestId,
        );
      } catch {
        // A broken UI listener must not break the messaging channel.
      }
    }
    return false;
  };

  chrome.runtime.onMessage.addListener(handler);
  return () => chrome.runtime.onMessage.removeListener(handler);
}
