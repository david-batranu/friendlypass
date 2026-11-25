/**
 * Real `friendlypass-browser` protocol server as the app under test (WP9).
 *
 * Spawns the same `examples/test_server.rs` binary the Chromium Phase-1 exit
 * test uses: it opens a real KDBX (copied into the scenario's temp root),
 * auto-approves associations, writes `set-login` changes back to disk and
 * serves the frozen protocol on `FP_APP_SOCKET`.
 *
 * Killing and restarting it is a real process death/start, so the app-restart
 * scenario exercises the extension's reconnect path rather than a mock.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { readJsonl } from "./environment.mjs";
import { TEST_SERVER_BINARY, sleep } from "./config.mjs";

export class RustApp {
  /**
   * @param {{ socketPath: string, root: string, logPath: string, fixtureDatabase: string }} options
   */
  constructor(options) {
    this.socketPath = options.socketPath;
    this.logPath = options.logPath;
    this.databasePath = path.join(options.root, "app-db.kdbx");
    this.associationsPath = path.join(options.root, "app-associations.json");
    /** @type {import("node:child_process").ChildProcess | null} */
    this.child = null;
    this.starts = 0;
    this.startsReady = 0;
    if (!fs.existsSync(this.databasePath)) {
      fs.copyFileSync(options.fixtureDatabase, this.databasePath);
    }
  }

  get listening() {
    return this.child !== null && this.startsReady >= this.starts && this.starts > 0;
  }

  get currentConnections() {
    const counts = this.lifecycle().filter((event) => event.event === "client-count");
    const last = counts.at(-1);
    return typeof last?.count === "number" ? last.count : 0;
  }

  async start() {
    if (this.child) return;
    fs.mkdirSync(path.dirname(this.logPath), { recursive: true });
    this.starts += 1;
    const expected = this.starts;

    const child = spawn(
      TEST_SERVER_BINARY,
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
    child.stderr?.on("data", (chunk) => {
      stderr = (stderr + chunk.toString("utf8")).slice(-4000);
    });
    child.once("exit", (code, signal) => {
      if (this.child === child) this.child = null;
      if (code !== 0 && code !== null && signal === null) {
        process.stderr.write(`[firefox-harness] test_server exited ${code}: ${stderr}\n`);
      }
    });

    const deadline = Date.now() + 15_000;
    for (;;) {
      if (this.listeningEvents() >= expected) {
        this.startsReady = expected;
        return;
      }
      if (this.child === null) {
        throw new Error(`test_server exited before listening:\n${stderr}`);
      }
      if (Date.now() > deadline) {
        throw new Error(`test_server did not listen within 15 s:\n${stderr}`);
      }
      await sleep(25);
    }
  }

  /** Real process death: SIGTERM, then SIGKILL after 3 s. */
  async stop() {
    const child = this.child;
    this.child = null;
    if (child) {
      await new Promise((resolve) => {
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

  async restart() {
    await this.stop();
    await this.start();
  }

  async close() {
    await this.stop();
  }

  lifecycle() {
    return readJsonl(this.logPath);
  }

  listeningEvents() {
    return this.lifecycle().filter((event) => event.event === "listening").length;
  }

  /** Wait until at least one association was persisted to the sidecar. */
  async waitForPersistedAssociation(timeoutMs = 5000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const data = JSON.parse(fs.readFileSync(this.associationsPath, "utf8"));
        if (Object.keys(data).length > 0) return Object.keys(data).length;
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
}
