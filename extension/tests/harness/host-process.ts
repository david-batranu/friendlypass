/**
 * Direct stdio handle on the Node stub host, used to prove the harness's
 * framing and fault behaviour without a browser.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { FrameDecoder, encodeFrame, sleep } from "./frames.mjs";
import { STUB_HOST_PATH } from "./app-mock";

export interface HostProcessOptions {
  appSocket?: string | null;
  logPath?: string | null;
  pidFile?: string | null;
  hostVersion?: string;
}

export class HostProcess {
  readonly child: ChildProcess;
  private readonly decoder = new FrameDecoder();
  private readonly frames: Array<Record<string, unknown>> = [];
  private readonly waiters: Array<{
    resolve: (frame: Record<string, unknown>) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];
  private stderr = "";
  private exited = false;

  private constructor(child: ChildProcess) {
    this.child = child;
    child.stdout?.on("data", (chunk: Buffer) => {
      for (const decoded of this.decoder.push(chunk)) {
        if (decoded.type === "error") {
          // The host should never write malformed frames; surface it loudly.
          this.stderr += `\n[decoder] ${decoded.error}`;
          continue;
        }
        const waiter = this.waiters.shift();
        if (waiter) {
          clearTimeout(waiter.timer);
          waiter.resolve(decoded.value);
        } else {
          this.frames.push(decoded.value);
        }
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      this.stderr = `${this.stderr}${chunk.toString("utf8")}`.slice(-16_384);
    });
    child.on("exit", () => {
      this.exited = true;
      for (const waiter of this.waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(new Error(`stub host exited: ${this.stderr}`));
      }
    });
  }

  static spawn(options: HostProcessOptions = {}): HostProcess {
    const args = [STUB_HOST_PATH];
    if (options.appSocket) args.push("--app-socket", options.appSocket);
    if (options.logPath) args.push("--log", options.logPath);
    if (options.pidFile) args.push("--pid", options.pidFile);
    args.push("--host-version", options.hostVersion ?? "0.1.0");
    const child = spawn(process.execPath, args, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    return new HostProcess(child);
  }

  get stderrText(): string {
    return this.stderr;
  }

  get hasExited(): boolean {
    return this.exited;
  }

  sendFrame(frame: Record<string, unknown>): void {
    this.child.stdin?.write(encodeFrame(frame));
  }

  sendRaw(buffer: Buffer): void {
    this.child.stdin?.write(buffer);
  }

  /**
   * Wait for the next frame from the host. If frames arrived earlier they are
   * returned in order.
   */
  nextFrame(timeoutMs = 5000): Promise<Record<string, unknown>> {
    const queued = this.frames.shift();
    if (queued) return Promise.resolve(queued);
    if (this.exited) {
      return Promise.reject(
        new Error(`stub host already exited: ${this.stderr}`),
      );
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.waiters.findIndex((w) => w.timer === timer);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error(`timed out after ${timeoutMs} ms: ${this.stderr}`));
      }, timeoutMs);
      this.waiters.push({ resolve, reject, timer });
    });
  }

  async close(): Promise<void> {
    if (this.exited) return;
    this.child.kill("SIGTERM");
    const deadline = Date.now() + 2000;
    while (!this.exited && Date.now() < deadline) await sleep(20);
    if (!this.exited) this.child.kill("SIGKILL");
  }
}
