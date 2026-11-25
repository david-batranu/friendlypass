#!/usr/bin/env node
/**
 * Generate the golden protocol fixtures in `protocol/fixtures/`.
 *
 *   node protocol/gen-fixtures.mjs
 *
 * The fixtures are byte-exact: every encrypted outer frame is produced here
 * with `tweetnacl` (the same library the extension uses), fixed TEST keys and
 * fixed TEST nonces. Re-running the script must produce identical files; the
 * Rust test `crates/friendlypass-browser/tests/fixtures_crypto.rs` decrypts
 * every frame and re-encrypts it to prove the vectors are self-consistent.
 *
 * SECURITY: the keys below are deterministic test keys derived from public
 * strings. They are useless outside these fixtures and MUST never be shipped
 * in the extension or the app.
 *
 * Dependency resolution: `tweetnacl` / `tweetnacl-util` are installed by
 * `npm install` in `extension/`. This script resolves them from there so the
 * repository needs no root package.json.
 */

import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const requireFromExtension = createRequire(resolve(here, "../extension/package.json"));
const nacl = requireFromExtension("tweetnacl");
const naclUtil = requireFromExtension("tweetnacl-util");

const PROTOCOL_VERSION = 1;
/** KeePassXC-compatible feature version used inside inner successes. */
const KPXC_VERSION = "2.8.0";
const HOST_VERSION = "0.1.0";
const EXTENSION_VERSION = "0.1.0";
const FIXTURES_DIR = resolve(here, "fixtures");

// ---------------------------------------------------------------------------
// Deterministic TEST key material
// ---------------------------------------------------------------------------

const sha256 = (text) => createHash("sha256").update(text, "utf8").digest();

function keyPairFromSeed(seed) {
  return nacl.box.keyPair.fromSecretKey(new Uint8Array(sha256(seed)));
}

const clientKeys = keyPairFromSeed("friendlypass fixture client session key v1");
const hostKeys = keyPairFromSeed("friendlypass fixture host session key v1");
const identityKeys = keyPairFromSeed("friendlypass fixture identity key v1");

/** Opaque 24-byte client id, Base64 (the upstream regenerates it per handshake). */
const CLIENT_ID = naclUtil.encodeBase64(new Uint8Array(sha256("friendlypass fixture client id v1").slice(0, 24)));

const b64 = (bytes) => naclUtil.encodeBase64(bytes);
const utf8 = (text) => naclUtil.decodeUTF8(text);

/**
 * Fixed nonce for vector `index`. Not random: reproducible and distinct.
 * `nonce[i] = (index * 31 + i * 7 + 1) & 0xff`.
 */
function fixtureNonce(index) {
  const nonce = new Uint8Array(24);
  for (let i = 0; i < nonce.length; i += 1) {
    nonce[i] = (index * 31 + i * 7 + 1) & 0xff;
  }
  return nonce;
}

let nonceCounter = 0;
const nextNonce = () => fixtureNonce((nonceCounter += 1));

/** libsodium `sodium_increment`: little-endian +1 over 24 bytes. */
function incrementNonce(bytes) {
  const out = new Uint8Array(bytes);
  let carry = 1;
  for (let i = 0; i < out.length; i += 1) {
    carry += out[i];
    out[i] = carry & 0xff;
    carry >>= 8;
  }
  return out;
}

// A few stable database values (all derived, all fake).
const hex = (text, bytes) => sha256(text).subarray(0, bytes).toString("hex");
const ROOT_GROUP_UUID = hex("friendlypass fixture root group v1", 16);
const BROWSER_GROUP_UUID = hex("friendlypass fixture browser group v1", 16);
const CHILD_GROUP_UUID = hex("friendlypass fixture child group v1", 16);
const ENTRY_UUID = hex("friendlypass fixture entry v1", 16);
const SECOND_ENTRY_UUID = hex("friendlypass fixture entry v2", 16);
const OLD_DB_HASH = sha256(`legacy:${ROOT_GROUP_UUID}`).toString("hex");
const DB_HASH = sha256(ROOT_GROUP_UUID).toString("hex");

// ---------------------------------------------------------------------------
// Frame builders (the only place ciphertext is produced)
// ---------------------------------------------------------------------------

/**
 * Encrypted request: plaintext sealed with the client secret for the host
 * public key, using the request nonce. Outer frame carries the same nonce.
 */
function encryptedRequest(inner, { nonce, requestID, triggerUnlock } = {}) {
  const nonceBytes = nonce ?? nextNonce();
  const plaintextJson = JSON.stringify(inner);
  const message = b64(
    nacl.box(utf8(plaintextJson), nonceBytes, hostKeys.publicKey, clientKeys.secretKey),
  );

  const frame = {
    action: inner.action,
    message,
    nonce: b64(nonceBytes),
    clientID: CLIENT_ID,
  };
  if (requestID !== undefined) frame.requestID = requestID;
  if (triggerUnlock) frame.triggerUnlock = "true";

  return { nonce: b64(nonceBytes), plaintextJson, plaintext: inner, frame };
}

/** Inner success prefix: version + success + incremented nonce. */
function successInner(requestNonce, params = {}) {
  return {
    version: KPXC_VERSION,
    success: "true",
    nonce: b64(incrementNonce(requestNonce)),
    ...params,
  };
}

/**
 * Encrypted response: plaintext sealed with the host secret for the client
 * public key, using the request nonce incremented by one.
 */
function encryptedResponse(action, inner, requestNonce) {
  const responseNonce = incrementNonce(requestNonce);
  const plaintextJson = JSON.stringify(inner);
  const message = b64(
    nacl.box(utf8(plaintextJson), responseNonce, clientKeys.publicKey, hostKeys.secretKey),
  );
  return {
    nonce: b64(responseNonce),
    plaintextJson,
    plaintext: inner,
    frame: { action, message, nonce: b64(responseNonce) },
  };
}

/** Unencrypted KeePassXC/host error reply: no message, no nonce. */
function errorResponse(action, code, message, extra = {}) {
  return {
    nonce: null,
    plaintextJson: null,
    plaintext: null,
    frame: { action, error: message, errorCode: String(code), ...extra },
  };
}

/** Unencrypted plaintext frame (handshake / host action / push). */
function plainFrame(frame) {
  return {
    nonce: frame.nonce ?? null,
    plaintextJson: null,
    plaintext: null,
    frame,
  };
}

function vector({ name, notes, request, response, nonceRelation = "none", kind }) {
  const action =
    request?.plaintext?.action ?? request?.frame?.action ?? response?.frame?.action ?? "";
  return {
    name,
    action,
    ...(kind ? { kind } : {}),
    nonceRelation,
    notes,
    request: request ?? null,
    response: response ?? null,
  };
}

// ---------------------------------------------------------------------------
// Fixture documents
// ---------------------------------------------------------------------------

const KEY_MATERIAL = {
  note: "FIXED TEST KEYS — deterministic, public, never use outside fixtures.",
  client: {
    publicKey: b64(clientKeys.publicKey),
    secretKey: b64(clientKeys.secretKey),
    role: "extension session keypair (X25519, regenerated per handshake)",
  },
  host: {
    publicKey: b64(hostKeys.publicKey),
    secretKey: b64(hostKeys.secretKey),
    role: "app/host session keypair (X25519, regenerated per handshake)",
  },
  identity: {
    publicKey: b64(identityKeys.publicKey),
    secretKey: b64(identityKeys.secretKey),
    role: "extension PERMANENT identification keypair (public half sent as `idKey`)",
  },
};

const COMMON = {
  schemaVersion: 1,
  protocolVersion: PROTOCOL_VERSION,
  generatedBy: "protocol/gen-fixtures.mjs",
  generatedWith: "tweetnacl (nacl.box = crypto_box_easy, XSalsa20-Poly1305)",
  keys: KEY_MATERIAL,
  clientID: CLIENT_ID,
  database: {
    note: "Fake database values used by the vectors.",
    rootGroupUuid: ROOT_GROUP_UUID,
    databaseHash: DB_HASH,
    legacyDatabaseHash: OLD_DB_HASH,
  },
  nonceRule:
    "Requests use one 24-byte nonce; the response uses the same nonce incremented little-endian by 1 (libsodium sodium_increment). Error replies carry no nonce and are correlated by action.",
  frameRule:
    "Native messaging frame = 4-byte little-endian payload length + UTF-8 JSON payload, max 1 MiB. `plaintextJson` is the exact UTF-8 string sealed into `frame.message`; it is null for unencrypted frames.",
};

function doc(description, vectors) {
  return {
    $comment: "GENERATED FILE — edit protocol/gen-fixtures.mjs and re-run it.",
    ...COMMON,
    description,
    vectors,
  };
}

async function emit(filename, description, vectors) {
  const document = doc(description, vectors);
  await writeFile(resolve(FIXTURES_DIR, filename), `${JSON.stringify(document, null, 2)}\n`, "utf8");
  console.log(`wrote fixtures/${filename} (${vectors.length} vector(s))`);
}

function* build() {
  // -------------------------------------------------------------------------
  // change-public-keys
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const request = plainFrame({
      action: "change-public-keys",
      publicKey: b64(clientKeys.publicKey),
      nonce: b64(nonce),
      clientID: CLIENT_ID,
    });
    const response = plainFrame({
      action: "change-public-keys",
      version: KPXC_VERSION,
      success: "true",
      nonce: b64(incrementNonce(nonce)),
      publicKey: b64(hostKeys.publicKey),
    });

    yield emit(
      "change-public-keys.json",
      "Unencrypted X25519 key exchange. No inner message exists; the response nonce is the request nonce incremented once.",
      [
        vector({
          name: "change-public-keys/new-session",
          notes:
            "First frame of every session. The client generates a fresh keypair and clientID; the host must reply with its public key and success \"true\".",
          request,
          response,
          nonceRelation: "increment",
          kind: "handshake",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // get-databasehash
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const inner = { action: "get-databasehash", connectedKeys: [] };
    const request = encryptedRequest(inner, { nonce, triggerUnlock: true });
    const response = encryptedResponse(
      "get-databasehash",
      successInner(nonce, { hash: DB_HASH }),
      nonce,
    );

    const nonce2 = nextNonce();
    const inner2 = { action: "get-databasehash", connectedKeys: [OLD_DB_HASH] };
    const request2 = encryptedRequest(inner2, { nonce: nonce2 });
    const response2 = encryptedResponse(
      "get-databasehash",
      successInner(nonce2, { hash: DB_HASH, oldHash: OLD_DB_HASH }),
      nonce2,
    );

    yield emit(
      "get-databasehash.json",
      "The app injects its OWN database hash into the decoded request and echoes it. Clients never send `hash`; a response hash MUST be non-empty or clients treat the database as closed.",
      [
        vector({
          name: "get-databasehash/open-database",
          notes:
            "`triggerUnlock` is an outer-frame hint (string \"true\") that the app may raise its unlock UI. `connectedKeys` is deprecated and ignored.",
          request,
          response,
          nonceRelation: "increment",
        }),
        vector({
          name: "get-databasehash/legacy-hash-migration",
          notes:
            "Optional legacy field: when a client presents a keyring entry under the old (root+recycle-bin) hash, the app may return `oldHash` so the client can migrate the keyring. Current KeePassXC 2.8.0 does not emit it; clients must tolerate its absence.",
          request: request2,
          response: response2,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // associate
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const inner = {
      action: "associate",
      key: b64(clientKeys.publicKey),
      idKey: b64(identityKeys.publicKey),
    };
    const request = encryptedRequest(inner, { nonce, triggerUnlock: true });
    const response = encryptedResponse(
      "associate",
      successInner(nonce, { hash: DB_HASH, id: "chrome-work-laptop" }),
      nonce,
    );

    const nonce2 = nextNonce();
    const legacyInner = {
      action: "associate",
      key: b64(clientKeys.publicKey),
    };
    const legacyRequest = encryptedRequest(legacyInner, { nonce: nonce2, triggerUnlock: true });
    const legacyResponse = encryptedResponse(
      "associate",
      successInner(nonce2, { hash: DB_HASH, id: "legacy-client" }),
      nonce2,
    );

    yield emit(
      "associate.json",
      "Association approval. `key` MUST equal the session public key used for the connection; `idKey` is the permanent identification public key. The app asks the user to name the connection; `id` is that user-visible name.",
      [
        vector({
          name: "associate/new-association",
          notes:
            "Success stores the identification key in database metadata. A denial is error 6 (see errors.json).",
          request,
          response,
          nonceRelation: "increment",
        }),
        vector({
          name: "associate/legacy-without-idKey",
          notes:
            "Backwards compatibility: when `idKey` is absent the app stores the session public key as the identification key.",
          request: legacyRequest,
          response: legacyResponse,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // test-associate
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const inner = {
      action: "test-associate",
      id: "chrome-work-laptop",
      key: b64(identityKeys.publicKey),
    };
    const request = encryptedRequest(inner, { nonce });
    const response = encryptedResponse(
      "test-associate",
      successInner(nonce, { hash: DB_HASH, id: "chrome-work-laptop" }),
      nonce,
    );

    yield emit(
      "test-associate.json",
      "Cheap re-validation of a stored association. Called before every credential action; a failure means the keyring entry is stale and the user must re-associate.",
      [
        vector({
          name: "test-associate/known-key",
          notes:
            "The app looks the key up by `id` in database metadata. Missing id/key is error 1; a key mismatch is error 8.",
          request,
          response,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // get-logins
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const inner = {
      action: "get-logins",
      id: "chrome-work-laptop",
      url: "https://accounts.example.com/login",
      keys: [{ id: "chrome-work-laptop", key: b64(identityKeys.publicKey) }],
    };
    const request = encryptedRequest(inner, { nonce });
    const response = encryptedResponse(
      "get-logins",
      successInner(nonce, {
        count: 1,
        entries: [
          {
            login: "alice@example.com",
            password: "correct horse battery staple",
            name: "Example account",
            uuid: ENTRY_UUID,
            group: "KeePassXC-Browser Passwords",
            totp: "123456",
            skipAutoSubmit: "false",
            stringFields: [{ "KPH: pin": "4921" }],
          },
        ],
        hash: DB_HASH,
        id: "chrome-work-laptop",
      }),
      nonce,
    );

    const nonce2 = nextNonce();
    const inner2 = {
      action: "get-logins",
      id: "chrome-work-laptop",
      url: "https://accounts.example.com/login",
      submitUrl: "https://login.example.com/session",
      keys: [{ id: "chrome-work-laptop", key: b64(identityKeys.publicKey) }],
    };
    const request2 = encryptedRequest(inner2, { nonce: nonce2 });
    const response2 = encryptedResponse(
      "get-logins",
      successInner(nonce2, {
        count: 2,
        entries: [
          {
            login: "alice@example.com",
            password: "correct horse battery staple",
            name: "Example account",
            uuid: ENTRY_UUID,
            group: "KeePassXC-Browser Passwords",
          },
          {
            login: "old-alice@example.com",
            password: "expired-password",
            name: "Example account (old)",
            uuid: SECOND_ENTRY_UUID,
            group: "KeePassXC-Browser Passwords",
            expired: "true",
          },
        ],
        hash: DB_HASH,
        id: "chrome-work-laptop",
      }),
      nonce2,
    );

    const nonce3 = nextNonce();
    const inner3 = {
      action: "get-logins",
      id: "chrome-work-laptop",
      url: "https://intranet.example.com/",
      httpAuth: "true",
      keys: [{ id: "chrome-work-laptop", key: b64(identityKeys.publicKey) }],
    };
    const request3 = encryptedRequest(inner3, { nonce: nonce3 });
    const response3 = encryptedResponse(
      "get-logins",
      successInner(nonce3, {
        count: 1,
        entries: [
          {
            login: "bob",
            password: "s3cr3t",
            name: "Intranet",
            uuid: SECOND_ENTRY_UUID,
            group: "Work",
          },
        ],
        hash: DB_HASH,
        id: "chrome-work-laptop",
      }),
      nonce3,
    );

    yield emit(
      "get-logins.json",
      "Credential lookup. Credentials are PLAINTEXT inside the encrypted message — never Base64. `httpAuth` is the HTTP Basic/Digest lookup path (friendlypass get-http-auth reuses it).",
      [
        vector({
          name: "get-logins/plain-single-match",
          notes:
            "Full entry shape: login, password, name, uuid, group, optional totp/expired/skipAutoSubmit/stringFields. The official extension types `login`/`password` verbatim.",
          request,
          response,
          nonceRelation: "increment",
        }),
        vector({
          name: "get-logins/multiple-with-expired",
          notes:
            "Multiple matches in priority order (best URL match first). Expired entries carry `expired: \"true\"`; the app filters them unless the user allowed expired credentials. `count` is a JSON number.",
          request: request2,
          response: response2,
          nonceRelation: "increment",
        }),
        vector({
          name: "get-logins/httpAuth",
          notes:
            "`httpAuth: \"true\"` asks for HTTP Basic/Digest credentials. The app excludes entries marked BrowserNotHttpAuth, may require confirmation, and ranks exact host/realm matches. There is no `realm` field on the wire in 2.8.0.",
          request: request3,
          response: response3,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // set-login
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const inner = {
      action: "set-login",
      id: "chrome-work-laptop",
      login: "alice@example.com",
      password: "correct horse battery staple",
      url: "https://accounts.example.com/login",
      submitUrl: "https://accounts.example.com/login",
      group: "KeePassXC-Browser Passwords",
      groupUuid: BROWSER_GROUP_UUID,
      downloadFavicon: "true",
    };
    const request = encryptedRequest(inner, { nonce });
    const response = encryptedResponse(
      "set-login",
      successInner(nonce, {
        count: null,
        entries: null,
        error: "success",
        hash: DB_HASH,
      }),
      nonce,
    );

    const nonce2 = nextNonce();
    const updateInner = {
      action: "set-login",
      id: "chrome-work-laptop",
      login: "alice@example.com",
      password: "new password",
      url: "https://accounts.example.com/login",
      submitUrl: "https://accounts.example.com/login",
      uuid: ENTRY_UUID,
    };
    const updateRequest = encryptedRequest(updateInner, { nonce: nonce2 });
    const updateResponse = encryptedResponse(
      "set-login",
      successInner(nonce2, {
        count: null,
        entries: null,
        error: "success",
        hash: DB_HASH,
      }),
      nonce2,
    );

    yield emit(
      "set-login.json",
      "Create or update a credential. Without `uuid` a new entry is created (optionally in `group`/`groupUuid`, optionally downloading a favicon); with `uuid` that entry is updated. The result is in the inner `error` field (\"success\"/\"error\"), not in `success` (which is always \"true\" on a protocol success).",
      [
        vector({
          name: "set-login/create",
          notes:
            "Credentials are plaintext inside the encrypted message. References are rejected (error 34).",
          request,
          response,
          nonceRelation: "increment",
        }),
        vector({
          name: "set-login/update-existing",
          notes:
            "`uuid` must be a valid dashless RFC 4122 UUID (error 18 otherwise). `downloadFavicon` is ignored on updates.",
          request: updateRequest,
          response: updateResponse,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // get-totp
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const inner = { action: "get-totp", uuid: ENTRY_UUID };
    const request = encryptedRequest(inner, { nonce });
    const response = encryptedResponse(
      "get-totp",
      successInner(nonce, { totp: "492183" }),
      nonce,
    );

    yield emit(
      "get-totp.json",
      "Current TOTP code. Feature-gated on the inner `version` (>= 2.6.1). An invalid/missing UUID is error 18; an entry without a TOTP secret returns an empty `totp` string.",
      [
        vector({
          name: "get-totp/valid-entry",
          request,
          response,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // get-database-groups
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const inner = { action: "get-database-groups" };
    const request = encryptedRequest(inner, { nonce });
    const response = encryptedResponse(
      "get-database-groups",
      successInner(nonce, {
        groups: {
          groups: [
            {
              name: "Root",
              uuid: ROOT_GROUP_UUID,
              children: [
                {
                  name: "KeePassXC-Browser Passwords",
                  uuid: BROWSER_GROUP_UUID,
                  children: [],
                },
                {
                  name: "Work",
                  uuid: CHILD_GROUP_UUID,
                  children: [],
                },
              ],
            },
          ],
        },
      }),
      nonce,
    );

    yield emit(
      "get-database-groups.json",
      "Group tree for the save dialog. KeePassXC 2.8.0 passes a `{groups:[...]}` object as the `groups` parameter, so the wire value is NESTED: response.groups.groups is the array of root groups. The official extension relies on this; do not flatten it. The recycle bin is excluded. `defaultGroup`/`defaultGroupAlwaysAsk` are extension-side settings, not wire fields.",
      [
        vector({
          name: "get-database-groups/tree",
          request,
          response,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // lock-database
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const inner = { action: "lock-database" };
    const request = encryptedRequest(inner, { nonce });
    const response = encryptedResponse("lock-database", successInner(nonce), nonce);

    yield emit(
      "lock-database.json",
      "Actually locks the database. Success returns only the common prefix (version/success/nonce); the app then broadcasts `database-locked` to every connection. If the database is closed the app replies error 1 or 2 instead (see errors.json).",
      [
        vector({
          name: "lock-database/open-database",
          request,
          response,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // generate-password
  // -------------------------------------------------------------------------
  {
    const nonce = nextNonce();
    const requestID = "a1b2c3d4";
    const inner = {
      action: "generate-password",
      nonce: b64(nonce),
      clientID: CLIENT_ID,
      requestID,
    };
    const request = encryptedRequest(inner, { nonce, requestID });
    const response = encryptedResponse(
      "generate-password",
      successInner(nonce, { password: "oX9#vK2!mQ7@wZ4$" }),
      nonce,
    );

    yield emit(
      "generate-password.json",
      "Asynchronous in KeePassXC: the app shows its password generator and replies later, possibly after seconds. The outer and inner messages both carry `requestID`; cancellation is an unencrypted error 6 that echoes it. Do not apply the 500 ms legacy timeout to this action.",
      [
        vector({
          name: "generate-password/accepted",
          request,
          response,
          nonceRelation: "increment",
        }),
      ],
    );
  }

  // -------------------------------------------------------------------------
  // errors
  // -------------------------------------------------------------------------
  {
    const mk = (name, action, code, message, requestInner, notes, extra = {}) => {
      const nonce = nextNonce();
      const request =
        requestInner === null
          ? null
          : encryptedRequest(requestInner, { nonce });
      const response = errorResponse(action, code, message, extra);
      return vector({
        name,
        notes,
        request,
        response,
        nonceRelation: "none",
        kind: "error",
      });
    };

    const specs = [
      [
        "error/database-not-opened",
        "get-logins",
        1,
        "Database not opened",
        { action: "get-logins", url: "https://example.com" },
        'The app has no unlocked database. `triggerUnlock: "true"` on the outer frame may raise the unlock UI.',
      ],
      [
        "error/database-hash-not-received",
        "get-databasehash",
        2,
        "Database hash not available",
        { action: "get-databasehash" },
        "No database hash could be produced (database closed or no root group). Clients MUST treat this as closed, not as a successful empty hash.",
      ],
      [
        "error/client-public-key-not-received",
        "test-associate",
        3,
        "Client public key not received",
        { action: "test-associate", id: "chrome-work-laptop", key: b64(identityKeys.publicKey) },
        "An encrypted action arrived before `change-public-keys` established the session key.",
      ],
      [
        "error/cannot-decrypt-message",
        "get-logins",
        4,
        "Cannot decrypt message",
        { action: "get-logins", url: "https://example.com" },
        "Wrong key/nonce, corrupt Base64, truncated ciphertext or invalid inner JSON.",
      ],
      [
        "error/association-failed",
        "test-associate",
        8,
        "KeePassXC association failed, try again",
        { action: "test-associate", id: "stale-id", key: b64(identityKeys.publicKey) },
        "Unknown association id or a key that does not match the stored identification key. Also returned for a mismatched `associate` key.",
      ],
      [
        "error/no-url-provided",
        "get-logins",
        14,
        "No URL provided",
        { action: "get-logins", id: "chrome-work-laptop" },
        "`url` was empty or missing.",
      ],
      [
        "error/no-logins-found",
        "get-logins",
        15,
        "No logins found",
        { action: "get-logins", id: "chrome-work-laptop", url: "https://unknown.example/" },
        "No entry matched the site (or all matches were denied). Not an error the user needs to see.",
      ],
      [
        "error/no-valid-uuid",
        "get-totp",
        18,
        "No valid UUID provided",
        { action: "get-totp", uuid: "not-a-uuid" },
        "UUIDs are dashless 32-hex RFC 4122 strings.",
      ],
      [
        "error/cannot-use-references",
        "set-login",
        34,
        "Username or password cannot contain references",
        {
          action: "set-login",
          id: "chrome-work-laptop",
          login: "{REF:u@I:1234}",
          password: "x",
          url: "https://example.com",
        },
        "KeePassXC placeholders such as {REF:...} are rejected on save.",
      ],
    ];

    const errors = specs.map(([name, action, code, message, requestInner, notes]) =>
      mk(name, action, code, message, requestInner, notes),
    );

    errors.push(
      vector({
        name: "error/host-frame-too-large",
        notes:
          "friendlypass extension: the native host discards a frame whose 4-byte length exceeds 1 MiB and answers with this typed error, keeping the process alive. `action` is empty because the body was not decoded.",
        request: null,
        response: errorResponse("", 1001, "Message exceeds the 1 MiB frame limit", { hostError: true }),
        nonceRelation: "none",
        kind: "error",
      }),
      vector({
        name: "error/host-app-unavailable",
        notes:
          "friendlypass extension: the app socket stayed down past the forwarding grace period. The host synthesises a KeePassXC-compatible code 5 so clients can retry.",
        request: null,
        response: errorResponse("get-logins", 5, "friendlypass is not running", { hostError: true }),
        nonceRelation: "none",
        kind: "error",
      }),
    );

    yield emit(
      "errors.json",
      "Unencrypted error replies. `errorCode` is a STRING and there is no nonce: correlate by `action`. Codes 0-37 are KeePassXC-compatible; 1000+ are friendlypass host errors.",
      errors,
    );
  }

  // -------------------------------------------------------------------------
  // host actions and pushes (friendlypass extensions)
  // -------------------------------------------------------------------------
  {
    const pingNonce = nextNonce();
    const pingRequest = plainFrame({ action: "ping", nonce: b64(pingNonce) });
    const pingDown = plainFrame({
      action: "ping",
      success: "true",
      protocolVersion: PROTOCOL_VERSION,
      hostVersion: HOST_VERSION,
      appRunning: false,
      appVersion: null,
      locked: null,
      databaseHash: null,
      nonce: b64(pingNonce),
    });

    const pingNonce2 = nextNonce();
    const pingUpRequest = plainFrame({ action: "ping", nonce: b64(pingNonce2) });
    const pingUp = plainFrame({
      action: "ping",
      success: "true",
      protocolVersion: PROTOCOL_VERSION,
      hostVersion: HOST_VERSION,
      appRunning: true,
      appVersion: "0.1.0",
      locked: false,
      databaseHash: DB_HASH,
      nonce: b64(pingNonce2),
    });

    const helloRequest = plainFrame({
      action: "hello",
      clientID: CLIENT_ID,
      extensionVersion: EXTENSION_VERSION,
    });
    const helloResponse = plainFrame({
      action: "hello",
      success: "true",
      protocolVersion: PROTOCOL_VERSION,
      hostVersion: HOST_VERSION,
      appRunning: true,
      appVersion: "0.1.0",
      locked: true,
      databaseHash: null,
      sessionId: "7b1d0c5e-4a2f-4f6e-9c3b-2d1a0e8f6b4c",
      hostPid: 4242,
    });

    yield emit(
      "host-actions.json",
      "friendlypass host-level extensions. These are answered by friendlypass-browser-host itself, without cryptography, even when the app is down. They are NOT part of the KeePassXC protocol and the official extension never sends them.",
      [
        vector({
          name: "host/ping-app-down",
          notes:
            "Heartbeat while the app socket is down. The host stays alive; `appRunning: false` and null status fields are the signal to keep the extension in READY(app-down). The nonce is echoed verbatim (no increment).",
          request: pingRequest,
          response: pingDown,
          nonceRelation: "echo",
          kind: "host",
        }),
        vector({
          name: "host/ping-app-up",
          notes:
            "Heartbeat with a live app socket. `locked`/`databaseHash` may lag by one heartbeat; do not use them as the sole source of truth.",
          request: pingUpRequest,
          response: pingUp,
          nonceRelation: "echo",
          kind: "host",
        }),
        vector({
          name: "host/hello-startup",
          notes:
            "Connection negotiation at service-worker start. `sessionId` identifies this stdio connection in diagnostics. No nonce is used.",
          request: helloRequest,
          response: helloResponse,
          nonceRelation: "none",
          kind: "host",
        }),
        vector({
          name: "push/database-locked",
          notes:
            "App -> extension broadcast, unencrypted, no nonce, no correlation. The official extension reacts by re-running test-associate (which then fails while locked).",
          request: null,
          response: plainFrame({ action: "database-locked" }),
          nonceRelation: "none",
          kind: "push",
        }),
        vector({
          name: "push/database-unlocked",
          notes:
            "App -> extension broadcast after unlock. Clients should re-run get-databasehash and test-associate because the hash may have changed.",
          request: null,
          response: plainFrame({ action: "database-unlocked" }),
          nonceRelation: "none",
          kind: "push",
        }),
        vector({
          name: "push/database-changed",
          notes:
            "friendlypass extension: the database contents/hash changed (edit, save, DB switch). Unencrypted, optional new hash. Not emitted by KeePassXC.",
          request: null,
          response: plainFrame({ action: "database-changed", hash: DB_HASH }),
          nonceRelation: "none",
          kind: "push",
        }),
      ],
    );
  }
}

// Generators are used only to keep each block's locals scoped; consume them.
async function main() {
  await mkdir(FIXTURES_DIR, { recursive: true });
  for (const job of build()) {
    await job;
  }
  await writeFile(resolve(here, "version"), `${PROTOCOL_VERSION}\n`, "utf8");
  console.log(`wrote version (${PROTOCOL_VERSION})`);
}

await main();
