/**
 * Native-messaging framing shared by the e2e harness (WP8).
 *
 * Wire contract: `protocol/ACTIONS.md` §1.1 — a 4-byte little-endian payload
 * length followed by exactly that many UTF-8 bytes containing one JSON object.
 * Maximum payload is 1 MiB in both directions.
 *
 * This module is plain ESM so it can be imported both by the standalone Node
 * stub host (`.mjs`) and by the Playwright tests (`.ts`, `frames.d.ts`).
 *
 * It deliberately has no dependency on the extension sources: the harness must
 * be able to test a broken or unfinished extension.
 */

/** Maximum accepted frame payload, matching `protocol/ACTIONS.md` §1.1. */
export const MAX_FRAME_BYTES = 1024 * 1024;

/** Host-level error codes used by the harness (`protocol/ACTIONS.md` §5.6). */
export const HOST_ERROR = Object.freeze({
  FRAME_TOO_LARGE: "1001",
  MALFORMED_FRAME: "1002",
  UNKNOWN_HOST_ACTION: "1003",
  HOST_INTERNAL_ERROR: "1004",
  APP_UNAVAILABLE: "1005",
  ENCRYPTION_REQUIRED: "1006",
});

const utf8 = new TextDecoder("utf-8", { fatal: true });

/**
 * Encode one JSON value as a native-messaging frame.
 * @param {unknown} value
 * @returns {Buffer}
 */
export function encodeFrame(value) {
  return encodePayload(Buffer.from(JSON.stringify(value), "utf8"));
}

/**
 * Encode raw bytes as a framed payload without parsing them. Used by fault
 * injection to emit deliberately invalid JSON/UTF-8.
 * @param {Buffer|Uint8Array} payload
 * @returns {Buffer}
 */
export function encodePayload(payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  if (body.length > MAX_FRAME_BYTES) {
    throw new RangeError(
      `frame payload ${body.length} exceeds ${MAX_FRAME_BYTES} bytes`,
    );
  }
  const out = Buffer.allocUnsafe(4 + body.length);
  out.writeUInt32LE(body.length, 0);
  body.copy(out, 4);
  return out;
}

/**
 * Increment a Base64 24-byte nonce exactly once (libsodium
 * `sodium_increment`): little-endian add with carry, as frozen in
 * `protocol/ACTIONS.md` §2.3.
 * @param {string} nonceB64
 * @returns {string}
 */
export function incrementNonce(nonceB64) {
  const bytes = Buffer.from(nonceB64, "base64");
  let carry = 1;
  for (let i = 0; i < bytes.length; i += 1) {
    carry += bytes[i];
    bytes[i] = carry & 0xff;
    carry >>= 8;
  }
  return bytes.toString("base64");
}

/**
 * @typedef {{ type: "frame", value: Record<string, unknown> }
 *   | { type: "error", errorCode: string, error: string }} DecodedFrame
 */

/**
 * Incremental frame decoder.
 *
 * Handles partial reads, multiple coalesced frames, invalid UTF-8/JSON and
 * oversize lengths. An oversize frame is skipped exactly as the contract
 * requires (the declared payload is discarded without parsing) while the
 * decoder stays usable.
 */
export class FrameDecoder {
  /** @param {{ maxBytes?: number }} [options] */
  constructor(options = {}) {
    /** @type {Buffer} */
    this.buffer = Buffer.alloc(0);
    this.maxBytes = options.maxBytes ?? MAX_FRAME_BYTES;
    this.skipRemaining = 0;
  }

  /**
   * Feed a chunk and return every complete frame or framing error it produced.
   * @param {Buffer|Uint8Array} chunk
   * @returns {DecodedFrame[]}
   */
  push(chunk) {
    /** @type {DecodedFrame[]} */
    const out = [];
    let buf = Buffer.concat([this.buffer, Buffer.from(chunk)]);

    for (;;) {
      if (this.skipRemaining > 0) {
        const take = Math.min(this.skipRemaining, buf.length);
        buf = buf.subarray(take);
        this.skipRemaining -= take;
        if (this.skipRemaining > 0) break;
      }

      if (buf.length < 4) break;
      const length = buf.readUInt32LE(0);

      if (length > this.maxBytes) {
        out.push({
          type: "error",
          errorCode: HOST_ERROR.FRAME_TOO_LARGE,
          error: `Message exceeds the 1 MiB frame limit (${length} bytes)`,
        });
        buf = buf.subarray(4);
        this.skipRemaining = length;
        continue;
      }

      if (buf.length < 4 + length) break;

      const payload = buf.subarray(4, 4 + length);
      buf = buf.subarray(4 + length);

      let text;
      try {
        text = utf8.decode(payload);
      } catch {
        out.push({
          type: "error",
          errorCode: HOST_ERROR.MALFORMED_FRAME,
          error: "Frame is not valid UTF-8",
        });
        continue;
      }

      let value;
      try {
        value = JSON.parse(text);
      } catch {
        out.push({
          type: "error",
          errorCode: HOST_ERROR.MALFORMED_FRAME,
          error: "Frame is not valid JSON",
        });
        continue;
      }

      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        out.push({
          type: "error",
          errorCode: HOST_ERROR.MALFORMED_FRAME,
          error: "Frame payload must be a single JSON object",
        });
        continue;
      }

      out.push({ type: "frame", value });
    }

    this.buffer = buf;
    return out;
  }
}

/**
 * @param {number} ms
 * @returns {Promise<void>}
 */
export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
