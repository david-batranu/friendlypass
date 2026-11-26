/**
 * Passkey serialisation tests (ACTIONS.md §4.12).
 *
 * The page/isolated-world split is exercised end to end by Playwright; these
 * tests lock the binary→base64url conversion and the option shapes the app
 * parses.
 */

import { describe, expect, it } from "vitest";
import {
  arrayBufferToBase64Url,
  buildCredentialCreationOptions,
  buildCredentialRequestOptions,
  PasskeyOptionError,
} from "../../src/content/passkeys";

function buffer(...bytes: number[]): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

const CHALLENGE = buffer(...new Array<number>(32).fill(7));
const USER_ID = buffer(1, 2, 3, 4, 5);

describe("arrayBufferToBase64Url", () => {
  it("uses the URL-safe alphabet without padding", () => {
    expect(arrayBufferToBase64Url(buffer(0xfb, 0xff))).toBe("-_8");
    expect(arrayBufferToBase64Url(buffer(1, 2, 3))).toBe("AQID");
    expect(arrayBufferToBase64Url(new Uint8Array([0, 1, 2]))).toBe("AAEC");
  });
});

describe("credential creation options", () => {
  it("serialises binary values and keeps the page's parameters", () => {
    const credentialId = buffer(...new Array<number>(32).fill(9));
    const publicKey = buildCredentialCreationOptions(
      {
        challenge: CHALLENGE,
        rp: { id: "example.com", name: "Example" },
        user: { id: USER_ID, name: "alice", displayName: "Alice" },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        excludeCredentials: [
          { type: "public-key", id: credentialId, transports: ["internal"] },
        ],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
        },
        timeout: 60_000,
      },
      true,
    );

    expect(publicKey["challenge"]).toBe(arrayBufferToBase64Url(CHALLENGE));
    expect(publicKey["rp"]).toEqual({ id: "example.com", name: "Example" });
    expect(publicKey["user"]).toEqual({
      id: arrayBufferToBase64Url(USER_ID),
      name: "alice",
      displayName: "Alice",
    });
    expect(publicKey["pubKeyCredParams"]).toEqual([
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ]);
    expect(publicKey["excludeCredentials"]).toEqual([
      {
        type: "public-key",
        id: arrayBufferToBase64Url(credentialId),
        transports: ["internal"],
      },
    ]);
    expect(publicKey["timeout"]).toBe(60_000);
  });

  it("clamps the timeout the way upstream does", () => {
    const base = {
      challenge: CHALLENGE,
      rp: { id: "example.com" },
      user: { id: USER_ID, name: "alice" },
      pubKeyCredParams: [],
    };
    expect(
      buildCredentialCreationOptions(
        { ...base, authenticatorSelection: { userVerification: "discouraged" } },
        true,
      )["timeout"],
    ).toBe(120_000);
    expect(
      buildCredentialCreationOptions({ ...base, timeout: 1 }, true)["timeout"],
    ).toBe(30_000);
  });

  it("rejects short challenges and cross-origin requests", () => {
    expect(() =>
      buildCredentialCreationOptions(
        { challenge: buffer(1, 2, 3), user: { id: USER_ID } },
        true,
      ),
    ).toThrowError(PasskeyOptionError);

    try {
      buildCredentialCreationOptions({ challenge: CHALLENGE }, false);
      throw new Error("expected a rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(PasskeyOptionError);
      expect((error as PasskeyOptionError).code).toBe(31);
    }
  });
});

describe("credential request options", () => {
  it("adds the internal transport and keeps allowed ids", () => {
    const id = buffer(...new Array<number>(32).fill(3));
    const publicKey = buildCredentialRequestOptions(
      {
        challenge: CHALLENGE,
        rpId: "example.com",
        allowCredentials: [{ type: "public-key", id }],
        userVerification: "required",
        timeout: 45_000,
      },
      true,
    );
    expect(publicKey["rpId"]).toBe("example.com");
    expect(publicKey["userVerification"]).toBe("required");
    expect(publicKey["timeout"]).toBe(45_000);
    expect(publicKey["allowCredentials"]).toEqual([
      {
        type: "public-key",
        id: arrayBufferToBase64Url(id),
        transports: ["internal"],
      },
    ]);
  });

  it("supports discoverable sign-in without allowCredentials", () => {
    const publicKey = buildCredentialRequestOptions(
      { challenge: CHALLENGE, rpId: "example.com" },
      true,
    );
    expect(publicKey["allowCredentials"]).toEqual([]);
    expect(publicKey["rpId"]).toBe("example.com");
  });
});
