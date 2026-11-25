/**
 * Minimal client for the harness app-mock unix socket. Used by Node-only specs
 * to replay the golden fixtures through the mock without a browser.
 */

import net from "node:net";
import nacl from "tweetnacl";
import { ObjectStreamDecoder, encodeObject, incrementNonce } from "./frames.mjs";

interface Waiter {
  resolve: (frame: Record<string, unknown>) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

export class AppSocketClient {
  readonly socket: net.Socket;
  private readonly decoder = new ObjectStreamDecoder();
  private readonly frames: Array<Record<string, unknown>> = [];
  private readonly waiters: Waiter[] = [];
  private closed = false;

  private constructor(socket: net.Socket) {
    this.socket = socket;
    socket.on("data", (chunk: Buffer) => {
      for (const decoded of this.decoder.push(chunk)) {
        if (decoded.type === "error") continue;
        const waiter = this.waiters.shift();
        if (waiter) {
          clearTimeout(waiter.timer);
          waiter.resolve(decoded.value);
        } else {
          this.frames.push(decoded.value);
        }
      }
    });
    socket.on("close", () => {
      this.closed = true;
      for (const waiter of this.waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(new Error("app mock connection closed"));
      }
    });
    socket.on("error", () => {
      /* surfaced through close/nextFrame */
    });
  }

  static async connect(socketPath: string, timeoutMs = 5000): Promise<AppSocketClient> {
    const socket = net.connect(socketPath);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`timed out connecting to app mock at ${socketPath}`));
      }, timeoutMs);
      socket.once("connect", () => {
        clearTimeout(timer);
        resolve();
      });
      socket.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
    return new AppSocketClient(socket);
  }

  send(frame: Record<string, unknown>): void {
    this.socket.write(encodeObject(frame));
  }

  nextFrame(timeoutMs = 5000): Promise<Record<string, unknown>> {
    const queued = this.frames.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closed) {
      return Promise.reject(new Error("app mock connection is closed"));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.waiters.findIndex((w) => w.timer === timer);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error(`timed out after ${timeoutMs} ms waiting for app frame`));
      }, timeoutMs);
      this.waiters.push({ resolve, reject, timer });
    });
  }

  async request(
    frame: Record<string, unknown>,
    timeoutMs = 5000,
  ): Promise<Record<string, unknown>> {
    this.send(frame);
    return this.nextFrame(timeoutMs);
  }

  close(): void {
    this.socket.destroy();
  }
}

/**
 * Open the `message` ciphertext of an outer response using the fixture client
 * secret key and the incremented request nonce. Returns the parsed inner JSON.
 */
export function openInnerResponse(
  response: Record<string, unknown>,
  requestNonce: string,
  clientSecretKeyB64: string,
  hostPublicKeyB64: string,
): Record<string, unknown> {
  if (typeof response.message !== "string") {
    throw new Error("response has no encrypted message");
  }
  const opened = nacl.box.open(
    new Uint8Array(Buffer.from(response.message, "base64")),
    new Uint8Array(Buffer.from(incrementNonce(requestNonce), "base64")),
    new Uint8Array(Buffer.from(hostPublicKeyB64, "base64")),
    new Uint8Array(Buffer.from(clientSecretKeyB64, "base64")),
  );
  if (!opened) throw new Error("could not open response ciphertext");
  const value = JSON.parse(Buffer.from(opened).toString("utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("response inner payload is not an object");
  }
  return value;
}
