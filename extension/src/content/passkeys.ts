/**
 * Passkey interception, content-script half (ACTIONS.md §4.12).
 *
 * Ported from keepassxc-browser `content/passkeys-inject.js` and
 * `content/passkeys-utils.js`. The page's MAIN world gets a small wrapper
 * (`passkeys-page.js`) that replaces `navigator.credentials.create/get`; this
 * isolated-world script receives the page's WebAuthn options, serialises the
 * binary fields to base64url and asks the service worker for the passkey.
 *
 * It is registered at `document_start` so the page cannot call the native API
 * before the wrapper exists. Nothing here logs keys or credential material.
 */

import { errorMessageFor, sendBackgroundMessage } from "../common/messages";
import type { ExtensionSettings, PasskeysResponse } from "../common/types";
import { normaliseSettings, type ContentSettings } from "./settings";
import { showPersistentNotification } from "./ui";

const REQUEST_EVENT = "friendlypass-passkeys-request";
const RESPONSE_EVENT = "friendlypass-passkeys-response";

const PASSKEYS_NO_LOGINS_FOUND = 15;
const PASSKEYS_CREDENTIAL_IS_EXCLUDED = 21;
const PASSKEYS_REQUEST_CANCELED = 22;
const PASSKEYS_WAIT_FOR_LIFETIMER = 30;
const PASSKEYS_UNKNOWN_ERROR = 31;

const MINIMUM_TIMEOUT = 15_000;
const DEFAULT_TIMEOUT = 30_000;
const DISCOURAGED_TIMEOUT = 120_000;

/** Timer that lets a rejected request wait out the page's own timeout. */
interface LifetimeTimer {
  promise: Promise<void>;
  abort(): void;
}

let passkeysLifetimeTimerAbortFunc: (() => void) | null = null;

function startTimer(timeout: number | undefined): LifetimeTimer {
  let resolve!: () => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  const timerId = setTimeout(resolve, timeout);
  return {
    promise,
    abort() {
      clearTimeout(timerId);
      reject(new Error("the timer has been aborted"));
    },
  };
}

function isFirefox(): boolean {
  return (
    typeof navigator !== "undefined" &&
    /firefox/i.test(navigator.userAgent)
  );
}

/** From ArrayBuffer/TypedArray to base64url without padding. */
export function arrayBufferToBase64Url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    buffer instanceof Uint8Array
      ? buffer
      : ArrayBuffer.isView(buffer)
        ? new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
        : new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function getTimeout(
  userVerification: unknown,
  timeout: unknown,
): number {
  const numeric = Number(timeout);
  if (!timeout || numeric === 0 || Number.isNaN(numeric)) {
    return userVerification === "discouraged"
      ? DISCOURAGED_TIMEOUT
      : DEFAULT_TIMEOUT;
  }
  if (numeric < MINIMUM_TIMEOUT || numeric > DISCOURAGED_TIMEOUT) {
    return DEFAULT_TIMEOUT;
  }
  return numeric;
}

export class PasskeyOptionError extends Error {
  readonly code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

/** `byteLength` without relying on the page's `ArrayBuffer` realm. */
function byteLength(value: unknown): number {
  if (typeof value === "object" && value !== null) {
    const length = (value as { byteLength?: unknown }).byteLength;
    if (typeof length === "number") {
      return length;
    }
  }
  return 0;
}

function checkOptions(publicKey: unknown, sameOriginWithAncestors: boolean): asserts publicKey is Record<string, unknown> {
  if (typeof publicKey !== "object" || publicKey === null) {
    throw new PasskeyOptionError(
      PASSKEYS_UNKNOWN_ERROR,
      "No publicKey configuration options were provided",
    );
  }
  if (!sameOriginWithAncestors) {
    throw new PasskeyOptionError(
      PASSKEYS_UNKNOWN_ERROR,
      "Cross-origin register or authentication is not allowed.",
    );
  }
  const challenge = (publicKey as Record<string, unknown>)["challenge"];
  if (byteLength(challenge) < 16) {
    throw new PasskeyOptionError(
      32,
      "challenge is shorter than required minimum length.",
    );
  }
}

/** Port of `buildCredentialCreationOptions` (binary values → base64url). */
export function buildCredentialCreationOptions(
  options: Record<string, unknown>,
  sameOriginWithAncestors: boolean,
): Record<string, unknown> {
  checkOptions(options, sameOriginWithAncestors);
  const publicKey: Record<string, unknown> = {
    attestation: options["attestation"],
    authenticatorSelection: options["authenticatorSelection"],
    challenge: arrayBufferToBase64Url(options["challenge"] as ArrayBuffer),
    extensions: options["extensions"],
  };

  publicKey["pubKeyCredParams"] = [];
  const params = options["pubKeyCredParams"];
  if (Array.isArray(params)) {
    publicKey["pubKeyCredParams"] = params.map((credParam) => ({
      type: (credParam as Record<string, unknown>)?.type,
      alg: (credParam as Record<string, unknown>)?.alg
        ? Number((credParam as Record<string, unknown>)["alg"])
        : 0,
    }));
  }

  publicKey["rp"] = options["rp"];
  const selection = options["authenticatorSelection"] as
    | Record<string, unknown>
    | undefined;
  publicKey["timeout"] = getTimeout(
    selection?.["userVerification"],
    options["timeout"],
  );

  publicKey["excludeCredentials"] = [];
  const exclude = options["excludeCredentials"];
  if (Array.isArray(exclude) && exclude.length > 0) {
    publicKey["excludeCredentials"] = exclude.map((cred) => ({
      id: arrayBufferToBase64Url(
        (cred as Record<string, unknown>)["id"] as ArrayBuffer,
      ),
      transports: (cred as Record<string, unknown>)["transports"],
      type: (cred as Record<string, unknown>)["type"],
    }));
  }

  const user = (options["user"] ?? {}) as Record<string, unknown>;
  publicKey["user"] = {
    displayName: user["displayName"],
    id: arrayBufferToBase64Url(user["id"] as ArrayBuffer),
    name: user["name"],
  };
  return publicKey;
}

/** Port of `buildCredentialRequestOptions` (binary values → base64url). */
export function buildCredentialRequestOptions(
  options: Record<string, unknown>,
  sameOriginWithAncestors: boolean,
): Record<string, unknown> {
  checkOptions(options, sameOriginWithAncestors);
  const publicKey: Record<string, unknown> = {
    challenge: arrayBufferToBase64Url(options["challenge"] as ArrayBuffer),
    enterpriseAttestationPossible: false,
    extensions: options["extensions"],
    rpId: options["rpId"],
    timeout: getTimeout(options["userVerification"], options["timeout"]),
    userVerification: options["userVerification"],
  };

  publicKey["allowCredentials"] = [];
  const allow = options["allowCredentials"];
  if (Array.isArray(allow) && allow.length > 0) {
    publicKey["allowCredentials"] = allow.map((cred) => {
      const transports = Array.isArray((cred as Record<string, unknown>)["transports"])
        ? [...((cred as Record<string, unknown>)["transports"] as string[])]
        : [];
      return {
        id: arrayBufferToBase64Url(
          (cred as Record<string, unknown>)["id"] as ArrayBuffer,
        ),
        transports: [...transports, "internal"],
        type: (cred as Record<string, unknown>)["type"],
      };
    });
  }
  return publicKey;
}

function isAllowedByPolicy(action: "create" | "get"): boolean {
  const feature = `publickey-credentials-${action}`;
  const policy = (
    document as unknown as {
      featurePolicy?: { features(): string[]; allowsFeature(f: string): boolean };
      permissionsPolicy?: { features(): string[]; allowsFeature(f: string): boolean };
    }
  ).featurePolicy ?? (
    document as unknown as {
      permissionsPolicy?: { features(): string[]; allowsFeature(f: string): boolean };
    }
  ).permissionsPolicy;
  if (
    action === "get" &&
    policy?.features().includes(feature)
  ) {
    return policy.allowsFeature(feature);
  }
  try {
    return window.origin === window.top?.origin;
  } catch {
    return false;
  }
}

function sendResponse(
  id: number,
  detail: Record<string, unknown>,
  fallback: boolean,
): void {
  const response = { id, fallback, ...detail };
  const target = response as unknown;
  const clone =
    isFirefox() &&
    typeof (globalThis as unknown as { cloneInto?: unknown }).cloneInto ===
      "function"
      ? (
          globalThis as unknown as {
            cloneInto: (value: unknown, scope: unknown) => unknown;
          }
        ).cloneInto(target, document.defaultView)
      : target;
  document.dispatchEvent(
    new CustomEvent(RESPONSE_EVENT, { detail: clone }),
  );
}

function letTimerRunOut(errorCode: number): boolean {
  return [
    PASSKEYS_NO_LOGINS_FOUND,
    PASSKEYS_CREDENTIAL_IS_EXCLUDED,
    PASSKEYS_REQUEST_CANCELED,
    PASSKEYS_WAIT_FOR_LIFETIMER,
  ].includes(errorCode);
}

async function handleRequest(
  detail: Record<string, unknown>,
  settings: ContentSettings,
): Promise<void> {
  const id = typeof detail["id"] === "number" ? detail["id"] : 0;
  const action = detail["action"];
  if (action === "abort") {
    passkeysLifetimeTimerAbortFunc?.();
    passkeysLifetimeTimerAbortFunc = null;
    return;
  }
  if (action !== "passkeys_create" && action !== "passkeys_get") {
    return;
  }
  if (!window.isSecureContext) {
    sendResponse(
      id,
      {
        errorCode: PASSKEYS_UNKNOWN_ERROR,
        errorMessage: "Passkeys require a secure context",
      },
      settings.passkeysFallback,
    );
    return;
  }

  let publicKey: Record<string, unknown>;
  try {
    publicKey =
      action === "passkeys_create"
        ? buildCredentialCreationOptions(
            detail["publicKey"] as Record<string, unknown>,
            isAllowedByPolicy("create"),
          )
        : buildCredentialRequestOptions(
            detail["publicKey"] as Record<string, unknown>,
            isAllowedByPolicy("get"),
          );
  } catch (cause) {
    const code = cause instanceof PasskeyOptionError ? cause.code : PASSKEYS_UNKNOWN_ERROR;
    sendResponse(
      id,
      { errorCode: code, errorMessage: errorMessageFor(code) },
      settings.passkeysFallback,
    );
    return;
  }

  const lifetimeTimer = startTimer(
    typeof publicKey["timeout"] === "number"
      ? (publicKey["timeout"] as number)
      : DEFAULT_TIMEOUT,
  );
  passkeysLifetimeTimerAbortFunc = lifetimeTimer.abort;

  // The desktop app opens its own passkey dialog, which is easy to miss when
  // the browser has focus. Keep a hint on the page until the app answers.
  const approval = showPersistentNotification(
    "info",
    action === "passkeys_create"
      ? "Approve saving this passkey in friendlypass — open the app if it is hidden."
      : "Approve this passkey sign-in in friendlypass — open the app if it is hidden.",
  );

  const result = await sendBackgroundMessage(
    action === "passkeys_create" ? "passkeys.register" : "passkeys.get",
    action === "passkeys_create"
      ? {
          publicKey,
          origin: window.location.origin,
          ...(settings.defaultPasskeyGroup
            ? { groupName: settings.defaultPasskeyGroup }
            : {}),
        }
      : { publicKey, origin: window.location.origin },
  ).finally(() => approval.dismiss());

  passkeysLifetimeTimerAbortFunc = null;

  let errorCode: number | undefined;
  let errorMessage: string | undefined;
  let credential: unknown;
  if (result.ok) {
    const response = result.value as PasskeysResponse;
    const value = response?.response;
    if (
      typeof value === "object" &&
      value !== null &&
      typeof (value as { errorCode?: unknown }).errorCode === "number"
    ) {
      errorCode = (value as { errorCode: number }).errorCode;
      errorMessage = errorMessageFor(errorCode);
    } else {
      credential = value;
    }
  } else {
    errorCode =
      typeof result.error.code === "number"
        ? result.error.code
        : PASSKEYS_REQUEST_CANCELED;
    errorMessage = result.error.message;
  }

  if (errorCode !== undefined) {
    if (!settings.passkeysFallback && letTimerRunOut(errorCode)) {
      try {
        await lifetimeTimer.promise;
      } catch {
        sendResponse(id, { errorCode: "abort" }, false);
        return;
      }
    }
    sendResponse(
      id,
      { errorCode, errorMessage: errorMessage ?? errorMessageFor(errorCode) },
      settings.passkeysFallback,
    );
    lifetimeTimer.promise.catch(() => undefined);
    lifetimeTimer.abort();
    return;
  }

  lifetimeTimer.promise.catch(() => undefined);
  lifetimeTimer.abort();
  sendResponse(id, { publicKey: credential }, settings.passkeysFallback);
}

function injectPageScript(): void {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("content/passkeys-page.js");
  script.async = false;
  document.documentElement.appendChild(script);
  script.remove();
}

async function init(): Promise<void> {
  const contentType = document?.documentElement?.ownerDocument?.contentType;
  if (contentType !== "text/html" && contentType !== "application/xhtml+xml") {
    return;
  }
  let settings: ExtensionSettings;
  try {
    const result = await sendBackgroundMessage("settings.get");
    if (!result.ok) {
      return;
    }
    settings = result.value;
  } catch {
    return;
  }
  const normalised = normaliseSettings(settings);
  if (!normalised.passkeys) {
    return;
  }
  document.addEventListener(REQUEST_EVENT, (event) => {
    const detail = (event as CustomEvent).detail as Record<string, unknown>;
    void handleRequest(detail, normalised).catch(() => {
      // Never let a failure leave the page hanging.
      const id = typeof detail?.["id"] === "number" ? detail["id"] : 0;
      sendResponse(
        id,
        {
          errorCode: PASSKEYS_UNKNOWN_ERROR,
          errorMessage: errorMessageFor(PASSKEYS_UNKNOWN_ERROR),
        },
        normalised.passkeysFallback,
      );
    });
  });
  injectPageScript();
}

// Content scripts run in the page; unit tests import the pure helpers under
// Node, where `chrome` does not exist.
if (typeof chrome !== "undefined" && chrome.runtime?.id) {
  void init();
}
