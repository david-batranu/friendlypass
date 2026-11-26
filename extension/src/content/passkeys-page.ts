/**
 * Passkey interception, page MAIN-world half (ACTIONS.md §4.12).
 *
 * Ported from keepassxc-browser `content/passkeys.js`. This file is injected
 * as a `<script>` by `passkeys.ts`, so it runs with the page's own globals and
 * replaces `navigator.credentials.create/get`. When the extension answers with
 * a credential it is wrapped as a real `PublicKeyCredential`-shaped object;
 * when it fails, the original browser API is used if fallback is enabled.
 *
 * The injected file must never import modules; it is bundled as an IIFE.
 */

(() => {
  const REQUEST_EVENT = "friendlypass-passkeys-request";
  const RESPONSE_EVENT = "friendlypass-passkeys-response";

  const PASSKEYS_NO_LOGINS_FOUND = 15;
  const PASSKEYS_ATTESTATION_NOT_SUPPORTED = 20;
  const PASSKEYS_CREDENTIAL_IS_EXCLUDED = 21;
  const PASSKEYS_REQUEST_CANCELED = 22;
  const PASSKEYS_INVALID_USER_VERIFICATION = 23;
  const PASSKEYS_EMPTY_PUBLIC_KEY = 24;
  const PASSKEYS_INVALID_URL_PROVIDED = 25;
  const PASSKEYS_ORIGIN_NOT_ALLOWED = 26;
  const PASSKEYS_DOMAIN_IS_NOT_VALID = 27;
  const PASSKEYS_DOMAIN_RPID_MISMATCH = 28;
  const PASSKEYS_NO_SUPPORTED_ALGORITHMS = 29;
  const PASSKEYS_WAIT_FOR_LIFETIMER = 30;
  const PASSKEYS_UNKNOWN_ERROR = 31;
  const PASSKEYS_INVALID_CHALLENGE = 32;
  const PASSKEYS_INVALID_USER_ID = 33;
  const PASSKEYS_EVAL_BY_CREDENTIAL_NOT_SUPPORTED = 35;
  const PASSKEYS_EVAL_BY_CREDENTIAL_NOT_EMPTY = 36;
  const PASSKEYS_EVAL_BY_CREDENTIAL_NOT_FOUND = 37;

  interface ExtensionResponse {
    id?: number;
    publicKey?: {
      authenticatorAttachment?: string;
      id: string;
      response?: Record<string, unknown>;
      type: string;
      clientExtensionResults?: Record<string, unknown>;
    };
    errorCode?: number | "abort";
    errorMessage?: string;
    fallback?: boolean;
  }

  interface PendingRequest {
    resolve(response: ExtensionResponse): void;
    reject(reason: unknown): void;
  }

  const pending = new Map<number, PendingRequest>();
  let nextRequestId = 1;

  function stringToArrayBuffer(value: string): ArrayBuffer {
    const bytes = Uint8Array.from(value, (char) => char.charCodeAt(0));
    return bytes.buffer;
  }

  function base64ToArrayBuffer(value: string | undefined): ArrayBuffer {
    if (!value) {
      return new ArrayBuffer(0);
    }
    return stringToArrayBuffer(
      window.atob(value.replaceAll("-", "+").replaceAll("_", "/")),
    );
  }

  function arrayBufferToBase64(value: ArrayBuffer): string {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return window.btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  }

  function publicKeyCredentialJson(
    credential: PublicKeyCredential,
    publicKey: NonNullable<ExtensionResponse["publicKey"]>,
  ) {
    const clientExtensionResults = credential.getClientExtensionResults();
    let response: Record<string, unknown> | undefined;
    if (credential.response instanceof AuthenticatorAttestationResponse) {
      const responsePublicKey = credential.response.getPublicKey();
      response = {
        clientDataJSON: publicKey.response?.["clientDataJSON"],
        authenticatorData: publicKey.response?.["authenticatorData"],
        transports: credential.response.getTransports(),
        publicKey: responsePublicKey
          ? arrayBufferToBase64(responsePublicKey)
          : null,
        publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm(),
        attestationObject: publicKey.response?.["attestationObject"],
      };
    } else if (credential.response instanceof AuthenticatorAssertionResponse) {
      response = {
        clientDataJSON: publicKey.response?.["clientDataJSON"],
        authenticatorData: publicKey.response?.["authenticatorData"],
        signature: publicKey.response?.["signature"],
        userHandle: publicKey.response?.["userHandle"] ?? undefined,
      };
    }
    return {
      id: publicKey.id,
      rawId: publicKey.id,
      response,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults,
      type: credential.type,
    };
  }

  function createAttestationResponse(publicKey: NonNullable<ExtensionResponse["publicKey"]>) {
    const response: Record<string, unknown> = {
      attestationObject: base64ToArrayBuffer(
        publicKey.response?.["attestationObject"] as string | undefined,
      ),
      clientDataJSON: base64ToArrayBuffer(
        publicKey.response?.["clientDataJSON"] as string | undefined,
      ),
      getAuthenticatorData: () =>
        base64ToArrayBuffer(
          publicKey.response?.["authenticatorData"] as string | undefined,
        ),
      getPublicKey: () =>
        publicKey.response?.["publicKey"]
          ? base64ToArrayBuffer(publicKey.response["publicKey"] as string)
          : null,
      getPublicKeyAlgorithm: () => publicKey.response?.["publicKeyAlgorithm"],
      getTransports: () => ["internal"],
    };
    const extensionResults = publicKey.response?.["clientExtensionResults"];
    if (extensionResults) {
      response["clientExtensionResults"] = extensionResults;
    }
    return Object.setPrototypeOf(
      response,
      AuthenticatorAttestationResponse.prototype,
    ) as AuthenticatorAttestationResponse;
  }

  function createAssertionResponse(publicKey: NonNullable<ExtensionResponse["publicKey"]>) {
    const response: Record<string, unknown> = {
      authenticatorData: base64ToArrayBuffer(
        publicKey.response?.["authenticatorData"] as string | undefined,
      ),
      clientDataJSON: base64ToArrayBuffer(
        publicKey.response?.["clientDataJSON"] as string | undefined,
      ),
      signature: base64ToArrayBuffer(
        publicKey.response?.["signature"] as string | undefined,
      ),
      userHandle: publicKey.response?.["userHandle"]
        ? base64ToArrayBuffer(publicKey.response["userHandle"] as string)
        : null,
    };
    const extensionResults = publicKey.response?.["clientExtensionResults"];
    if (extensionResults) {
      response["clientExtensionResults"] = extensionResults;
    }
    return Object.setPrototypeOf(
      response,
      AuthenticatorAssertionResponse.prototype,
    ) as AuthenticatorAssertionResponse;
  }

  function createPublicKeyCredential(
    publicKey: NonNullable<ExtensionResponse["publicKey"]>,
  ): PublicKeyCredential {
    const authenticatorResponse = publicKey.response?.["attestationObject"]
      ? createAttestationResponse(publicKey)
      : createAssertionResponse(publicKey);
    const extensionResults =
      (authenticatorResponse as unknown as { clientExtensionResults?: Record<string, unknown> })
        .clientExtensionResults ??
      publicKey.clientExtensionResults ??
      {};
    const credential = {
      authenticatorAttachment: publicKey.authenticatorAttachment,
      id: publicKey.id,
      rawId: base64ToArrayBuffer(publicKey.id),
      response: authenticatorResponse,
      type: publicKey.type,
      getClientExtensionResults: () => extensionResults,
      toJSON: () =>
        publicKeyCredentialJson(
          credential as unknown as PublicKeyCredential,
          publicKey,
        ),
    };
    return Object.setPrototypeOf(
      credential,
      PublicKeyCredential.prototype,
    ) as PublicKeyCredential;
  }

  function abortPending(reason: unknown): void {
    for (const request of pending.values()) {
      request.reject(reason);
    }
    pending.clear();
  }

  document.addEventListener(RESPONSE_EVENT, (event) => {
    const response = (event as CustomEvent).detail as ExtensionResponse;
    if (!response) {
      return;
    }
    if (response.errorCode === "abort") {
      abortPending(new DOMException("AbortError", "AbortError"));
      return;
    }
    const id = typeof response.id === "number" ? response.id : 0;
    const request = pending.get(id);
    if (!request) {
      return;
    }
    pending.delete(id);
    request.resolve(response);
  });

  function postMessageToExtension(
    request: Record<string, unknown>,
    signal: AbortSignal | undefined,
  ): Promise<ExtensionResponse> {
    return new Promise((resolve, reject) => {
      const id = nextRequestId++;
      pending.set(id, { resolve, reject });

      const abort = () => {
        if (pending.delete(id)) {
          document.dispatchEvent(
            new CustomEvent(REQUEST_EVENT, {
              detail: { action: "abort", id },
            }),
          );
          reject(new DOMException("AbortError", "AbortError"));
        }
      };

      if (signal) {
        if (signal.aborted) {
          pending.delete(id);
          reject(new DOMException("AbortError", "AbortError"));
          return;
        }
        signal.addEventListener("abort", abort, { once: true });
      }

      document.dispatchEvent(
        new CustomEvent(REQUEST_EVENT, {
          detail: { ...request, id },
        }),
      );
    });
  }

  function waitForFocus(): Promise<void> {
    return new Promise((resolve) => {
      if (document.hasFocus()) {
        resolve();
        return;
      }
      document.addEventListener("focus", () => resolve(), {
        capture: true,
        passive: true,
        once: true,
      });
    });
  }

  function throwError(errorCode: number | undefined, errorMessage: string | undefined): never {
    if (
      errorCode === PASSKEYS_DOMAIN_RPID_MISMATCH ||
      errorCode === PASSKEYS_DOMAIN_IS_NOT_VALID
    ) {
      throw new DOMException(errorMessage, "SecurityError");
    }
    if (
      errorCode === PASSKEYS_NO_SUPPORTED_ALGORITHMS ||
      errorCode === PASSKEYS_EVAL_BY_CREDENTIAL_NOT_SUPPORTED ||
      errorCode === PASSKEYS_EVAL_BY_CREDENTIAL_NOT_EMPTY
    ) {
      throw new DOMException(errorMessage, "NotSupportedError");
    }
    if (errorCode === PASSKEYS_EVAL_BY_CREDENTIAL_NOT_FOUND) {
      throw new DOMException(errorMessage, "SyntaxError");
    }
    if (
      errorCode === PASSKEYS_INVALID_CHALLENGE ||
      errorCode === PASSKEYS_INVALID_USER_ID
    ) {
      throw new TypeError(errorMessage);
    }
    if (
      errorCode === PASSKEYS_NO_LOGINS_FOUND ||
      errorCode === PASSKEYS_CREDENTIAL_IS_EXCLUDED ||
      errorCode === PASSKEYS_REQUEST_CANCELED ||
      errorCode === PASSKEYS_WAIT_FOR_LIFETIMER ||
      errorCode === PASSKEYS_ATTESTATION_NOT_SUPPORTED ||
      errorCode === PASSKEYS_INVALID_URL_PROVIDED ||
      errorCode === PASSKEYS_INVALID_USER_VERIFICATION ||
      errorCode === PASSKEYS_EMPTY_PUBLIC_KEY ||
      errorCode === PASSKEYS_UNKNOWN_ERROR ||
      errorCode === PASSKEYS_ORIGIN_NOT_ALLOWED
    ) {
      throw new DOMException(errorMessage, "NotAllowedError");
    }
    throw new DOMException(errorMessage, "UnknownError");
  }

  const originalCredentials = navigator.credentials;

  const passkeysCredentials = {
    async create(options?: CredentialCreationOptions): Promise<Credential | null> {
      if (!options?.publicKey) {
        return null;
      }
      const response = await postMessageToExtension(
        { action: "passkeys_create", publicKey: options.publicKey },
        options.signal ?? undefined,
      );
      if (!response.publicKey) {
        if (!response.fallback) {
          throwError(response.errorCode as number | undefined, response.errorMessage);
        }
        await waitForFocus();
        return originalCredentials.create(options);
      }
      return createPublicKeyCredential(response.publicKey);
    },

    async get(options?: CredentialRequestOptions): Promise<Credential | null> {
      if (!options?.publicKey || options.mediation === "silent") {
        return null;
      }
      if (options.mediation === "conditional") {
        return originalCredentials.get(options);
      }
      const response = await postMessageToExtension(
        { action: "passkeys_get", publicKey: options.publicKey },
        options.signal ?? undefined,
      );
      if (!response.publicKey) {
        if (!response.fallback) {
          throwError(response.errorCode as number | undefined, response.errorMessage);
        }
        await waitForFocus();
        return originalCredentials.get(options);
      }
      return createPublicKeyCredential(response.publicKey);
    },

    async store(credential: Credential): Promise<void> {
      const store = (originalCredentials as unknown as {
        store?: (credential: Credential) => Promise<void>;
      }).store;
      if (store) {
        return store.call(originalCredentials, credential);
      }
    },
  };

  const isConditionalMediationAvailable = async () => false;
  const isUserVerifyingPlatformAuthenticatorAvailable = async () => true;

  try {
    Object.defineProperty(navigator, "credentials", {
      value: passkeysCredentials,
      configurable: true,
    });
    if (window.PublicKeyCredential) {
      Object.defineProperty(
        window.PublicKeyCredential,
        "isConditionalMediationAvailable",
        { value: isConditionalMediationAvailable },
      );
      Object.defineProperty(
        window.PublicKeyCredential,
        "isUserVerifyingPlatformAuthenticatorAvailable",
        { value: isUserVerifyingPlatformAuthenticatorAvailable },
      );
    }
    // Explicit signal for the e2e harness (never read by production code).
    (window as unknown as Record<string, unknown>)["__friendlypassPasskeys"] = true;
  } catch {
    // The page's own policy may forbid redefining navigator.credentials; the
    // native API then keeps working, which is the safe outcome.
  }
})();
