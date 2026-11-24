/**
 * Real friendlypass protocol server as the harness "app" (Phase-1 exit test).
 *
 * Spawns `crates/friendlypass-browser/examples/test_server.rs`, which opens a
 * database from `fixtures/`, auto-approves associations and serves the frozen
 * KeePassXC-Browser protocol on `FP_APP_SOCKET`. Killing and restarting it
 * therefore exercises the real app lifecycle (socket gone → EOF → reconnect),
 * not a mock.
 *
 * The wrapper only starts/stops the process and reads its JSONL lifecycle log;
 * it never speaks the protocol itself.
 */

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { readJsonl } from "./setup";
import { sleep } from "./frames.mjs";

export interface RustAppOptions {
  socketPath: string;
  /** Path to the built `test_server` example binary. */
  binaryPath: string;
  /** Fixture database copied into the temp root before the first start. */
  fixtureDatabase: string;
  /** Working root for the copied DB and the associations sidecar. */
  root: string;
  /** JSONL lifecycle log (listening/client-count). */
  logPath: string;
}

export class RustApp {
  readonly socketPath: string;
  readonly binaryPath: string;
  readonly logPath: string;
  readonly databasePath: string;
  readonly associationsPath: string;

  private child: ChildProcess | null = null;
  private starts = 0;
  private startsReady = 0;

  constructor(options: RustAppOptions) {
    this.socketPath = options.socketPath;
    this.binaryPath = options.binaryPath;
    this.logPath = options.logPath;
    this.databasePath = path.join(options.root, "app-db.kdbx");
    this.associationsPath = path.join(options.root, "app-associations.json");
    if (!fs.existsSync(this.databasePath)) {
      fs.copyFileSync(options.fixtureDatabase, this.databasePath);
    }
  }

  get listening(): boolean {
    return this.child !== null && this.startsReady >= this.starts && this.starts > 0;
  }

  /**
   * Highest number of concurrently connected hosts the server reported. The
   * harness only needs "did the real host connect while probing".
   */
  get connectionCount(): number {
    let max = 0;
    for (const event of this.lifecycle()) {
      if (event.event === "client-count" && typeof event.count === "number") {
        max = Math.max(max, event.count);
      }
    }
    return max;
  }

  get currentConnections(): number {
    const counts = this.lifecycle().filter((event) => event.event === "client-count");
    const last = counts.at(-1);
    return typeof last?.count === "number" ? last.count : 0;
  }

  async start(): Promise<void> {
    if (this.child) return;
    fs.mkdirSync(path.dirname(this.logPath), { recursive: true });
    this.starts += 1;
    const expected = this.starts;

    const child = spawn(
      this.binaryPath,
      [
        "--db",
        this.databasePath,
        "--associations",
        this.associationsPath,
        "--log",
        this.logPath,
      ],
      {
        stdio: ["ignore", "ignore", "pipe"],
        env: { ...process.env, FP_APP_SOCKET: this.socketPath },
      },
    );
    this.child = child;
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = (stderr + chunk.toString("utf8")).slice(-4000);
    });
    child.once("exit", (code, signal) => {
      if (this.child === child) {
        this.child = null;
      }
      if (code !== 0 && code !== null && signal === null) {
        process.stderr.write(`[rust-app] test_server exited ${code}: ${stderr}\n`);
      }
    });

    const deadline = Date.now() + 10_000;
    for (;;) {
      if (this.listeningEvents() >= expected) {
        this.startsReady = expected;
        return;
      }
      if (this.child === null) {
        throw new Error(`test_server exited before listening:\n${stderr}`);
      }
      if (Date.now() > deadline) {
        throw new Error(`test_server did not listen within 10 s:\n${stderr}`);
      }
      await sleep(25);
    }
  }

  /** Simulate the app being killed: the host must observe EOF immediately. */
  async stop(): Promise<void> {
    const child = this.child;
    this.child = null;
    if (child) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* already gone */
          }
        }, 3000);
        child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
        try {
          child.kill("SIGTERM");
        } catch {
          clearTimeout(timer);
          resolve();
        }
      });
    }
    fs.rmSync(this.socketPath, { force: true });
  }

  /**
   * Wait until the server has flushed at least one association to its sidecar.
   * A real app saves this in KDBX metadata before the user can kill it; the
   * spec uses this to avoid racing the sidecar flush itself (not to skip any
   * reconnect/re-association behaviour).
   */
  async waitForPersistedAssociation(timeoutMs = 5000): Promise<number> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const data = JSON.parse(
          fs.readFileSync(this.associationsPath, "utf8"),
        ) as Record<string, string>;
        const count = Object.keys(data).length;
        if (count > 0) return count;
      } catch {
        /* not written yet */
      }
      if (Date.now() > deadline) {
        throw new Error(
          `test_server did not persist an association within ${timeoutMs} ms`,
        );
      }
      await sleep(25);
    }
  }

  async restart(): Promise<void> {
    await this.stop();
    await this.start();
  }

  async close(): Promise<void> {
    await this.stop();
  }

  private lifecycle(): Array<Record<string, unknown>> {
    return readJsonl(this.logPath);
  }

  private listeningEvents(): number {
    return this.lifecycle().filter((event) => event.event === "listening").length;
  }
}
