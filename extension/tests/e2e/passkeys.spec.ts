/**
 * End-to-end passkey registration and sign-in (ACTIONS.md §4.12).
 *
 * Real Chromium + the built extension + the real native host + the real Rust
 * protocol server (`examples/test_server.rs`) backed by a real KDBX. A local
 * page calls `navigator.credentials.create/get`; the test verifies the
 * attestation and assertion server-side with `node:crypto`, so a credential
 * that only "looks right" cannot pass.
 *
 * `http://localhost` is a secure context; the headless server opts into
 * KeePassXC's "Allow localhost with passkeys" setting.
 */

import { expect, test } from "@playwright/test";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { Harness } from "../harness/harness";

function b64url(value: Buffer): string {
  return value.toString("base64url");
}

function fromB64(value: string): Buffer {
  return Buffer.from(value, "base64");
}

function sha256(value: Buffer): Buffer {
  return createHash("sha256").update(value).digest();
}

const PAGE = `<!doctype html>
<html><head><meta charset="utf-8"><title>Passkey test</title></head>
<body><p>passkey test page</p></body></html>`;

async function startPageServer(): Promise<{ origin: string; close(): Promise<void> }> {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(PAGE);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://localhost:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

test("registers a passkey and signs in with it", async () => {
  test.setTimeout(120_000);
  const pageServer = await startPageServer();
  const harness = await Harness.start({
    appMode: "rust",
    hostMode: "real",
    createRustDatabase: true,
  });
  try {
    const page = await harness.context.newPage();
    const settings = await harness.internalRequest("settings.set", {
      passkeys: true,
      passkeysFallback: true,
    });
    expect(settings).toBeTruthy();

    await page.goto(pageServer.origin);
    await page.waitForFunction(
      () =>
        (window as unknown as Record<string, unknown>)["__friendlypassPasskeys"] === true,
      undefined,
      { timeout: 10_000 },
    );

    const challenge = Buffer.from(
      "0123456789abcdef0123456789abcdef0123456789abcdef",
      "hex",
    );
    const userId = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);

    const registration = await page.evaluate(
      async ({ challengeBytes, userIdBytes }) => {
        const toBase64 = (buffer: ArrayBuffer): string => {
          const bytes = new Uint8Array(buffer);
          let binary = "";
          for (const byte of bytes) binary += String.fromCharCode(byte);
          return window.btoa(binary);
        };
        const challenge = Uint8Array.from(challengeBytes).buffer;
        const credential = (await navigator.credentials.create({
          publicKey: {
            challenge,
            rp: { id: "localhost", name: "friendlypass test" },
            user: {
              id: Uint8Array.from(userIdBytes).buffer,
              name: "alice@example.test",
              displayName: "Alice",
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: {
              residentKey: "required",
              userVerification: "required",
            },
            attestation: "none",
            timeout: 60_000,
          },
        })) as PublicKeyCredential;
        const response = credential.response as AuthenticatorAttestationResponse;
        return {
          id: credential.id,
          type: credential.type,
          clientDataJSON: toBase64(response.clientDataJSON),
          attestationObject: toBase64(response.attestationObject),
          authenticatorData: toBase64(response.getAuthenticatorData()),
          publicKey: response.getPublicKey()
            ? toBase64(response.getPublicKey() as ArrayBuffer)
            : null,
          publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
        };
      },
      { challengeBytes: [...challenge], userIdBytes: [...userId] },
    );

    // --- verify the registration server-side -----------------------------
    expect(registration.type).toBe("public-key");
    expect(registration.publicKeyAlgorithm).toBe(-7);
    expect(registration.publicKey).not.toBeNull();

    const createClientData = JSON.parse(
      fromB64(registration.clientDataJSON).toString("utf8"),
    );
    expect(createClientData.type).toBe("webauthn.create");
    expect(createClientData.challenge).toBe(b64url(challenge));
    expect(createClientData.origin).toBe(pageServer.origin);
    expect(createClientData.crossOrigin).toBe(false);

    const registrationAuthData = fromB64(registration.authenticatorData);
    expect(registrationAuthData.subarray(0, 32)).toEqual(sha256(Buffer.from("localhost")));
    const registrationFlags = registrationAuthData[32];
    expect(registrationFlags & 0x01).toBe(0x01); // UP
    expect(registrationFlags & 0x04).toBe(0x04); // UV
    expect(registrationFlags & 0x40).toBe(0x40); // AT
    const credentialIdLength = registrationAuthData.readUInt16BE(53);
    const credentialId = registrationAuthData.subarray(55, 55 + credentialIdLength);
    expect(b64url(credentialId)).toBe(registration.id);

    // The attestation object is CBOR {"fmt":"none", ...}.
    const attestation = fromB64(registration.attestationObject);
    expect(attestation.subarray(0, 10)).toEqual(
      Buffer.from([0xa3, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65]),
    );

    // The headless bridge saves the entry, then refreshes the served snapshot.
    await harness.rustApp().waitForEvent("database-saved");

    const challenge2 = Buffer.from(
      "fedcba9876543210fedcba9876543210fedcba9876543210",
      "hex",
    );
    const assertion = await page.evaluate(
      async ({ challengeBytes, credentialIdB64Url }) => {
        const toBase64 = (buffer: ArrayBuffer): string => {
          const bytes = new Uint8Array(buffer);
          let binary = "";
          for (const byte of bytes) binary += String.fromCharCode(byte);
          return window.btoa(binary);
        };
        const challenge = Uint8Array.from(challengeBytes).buffer;
        const id = credentialIdB64Url.replaceAll("-", "+").replaceAll("_", "/");
        const raw = window.atob(id);
        const credentialId = Uint8Array.from(raw, (char) =>
          char.charCodeAt(0),
        ).buffer;
        const credential = (await navigator.credentials.get({
          publicKey: {
            challenge,
            rpId: "localhost",
            allowCredentials: [
              { type: "public-key", id: credentialId, transports: ["internal"] },
            ],
            userVerification: "required",
            timeout: 60_000,
          },
        })) as PublicKeyCredential;
        const response = credential.response as AuthenticatorAssertionResponse;
        return {
          id: credential.id,
          clientDataJSON: toBase64(response.clientDataJSON),
          authenticatorData: toBase64(response.authenticatorData),
          signature: toBase64(response.signature),
          userHandle: response.userHandle
            ? toBase64(response.userHandle)
            : null,
        };
      },
      { challengeBytes: [...challenge2], credentialIdB64Url: registration.id },
    );

    expect(assertion.id).toBe(registration.id);
    const getClientData = JSON.parse(
      fromB64(assertion.clientDataJSON).toString("utf8"),
    );
    expect(getClientData.type).toBe("webauthn.get");
    expect(getClientData.challenge).toBe(b64url(challenge2));
    expect(getClientData.origin).toBe(pageServer.origin);
    expect(assertion.userHandle).not.toBeNull();
    expect(b64url(fromB64(assertion.userHandle!))).toBe(b64url(userId));

    const assertionAuthData = fromB64(assertion.authenticatorData);
    expect(assertionAuthData.subarray(0, 32)).toEqual(sha256(Buffer.from("localhost")));
    const key = createPublicKey({
      key: fromB64(registration.publicKey!),
      format: "der",
      type: "spki",
    });
    const signed = Buffer.concat([
      assertionAuthData,
      sha256(fromB64(assertion.clientDataJSON)),
    ]);
    expect(
      verifySignature(
        "sha256",
        signed,
        { key, dsaEncoding: "der" },
        fromB64(assertion.signature),
      ),
    ).toBe(true);

    // --- discoverable sign-in (no allowCredentials) ----------------------
    const discoverable = await page.evaluate(
      async ({ challengeBytes }) => {
        const toBase64 = (buffer: ArrayBuffer): string => {
          const bytes = new Uint8Array(buffer);
          let binary = "";
          for (const byte of bytes) binary += String.fromCharCode(byte);
          return window.btoa(binary);
        };
        const challenge = Uint8Array.from(challengeBytes).buffer;
        const credential = (await navigator.credentials.get({
          publicKey: {
            challenge,
            rpId: "localhost",
            userVerification: "required",
            timeout: 60_000,
          },
        })) as PublicKeyCredential;
        const response = credential.response as AuthenticatorAssertionResponse;
        return {
          id: credential.id,
          clientDataJSON: toBase64(response.clientDataJSON),
          authenticatorData: toBase64(response.authenticatorData),
          signature: toBase64(response.signature),
          userHandle: response.userHandle
            ? toBase64(response.userHandle)
            : null,
        };
      },
      { challengeBytes: [...challenge2] },
    );
    expect(discoverable.id).toBe(registration.id);
    expect(discoverable.userHandle).not.toBeNull();
    const discoverableAuth = fromB64(discoverable.authenticatorData);
    const discoverableSigned = Buffer.concat([
      discoverableAuth,
      sha256(fromB64(discoverable.clientDataJSON)),
    ]);
    expect(
      verifySignature(
        "sha256",
        discoverableSigned,
        { key, dsaEncoding: "der" },
        fromB64(discoverable.signature),
      ),
    ).toBe(true);

    await page.close();
  } finally {
    await harness.close();
    await pageServer.close();
  }
});
