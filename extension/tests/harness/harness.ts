/**
 * Playwright harness for the friendlypass browser extension (WP8).
 *
 * One call to `Harness.start()` gives a spec:
 *   - a fresh temp `$HOME` + Chromium profile (never the user's real ones);
 *   - a native-messaging manifest pointing at the Node stub host or the real
 *     WP1 host (`FP_HOST=stub|real|auto`);
 *   - a running app mock on a unix socket;
 *   - a Chromium window with `extension/dist` loaded;
 *   - a fault-injection API (`killHost`, `killApp`, `restartApp`,
 *     `stallApp`, `sendCorruptFrame`, `reloadExtension`).
 *
 * The service worker is reachable via `harness.swEvaluate` / `nativeRoundTrip`,
 * so specs can exercise the actual Chrome↔manifest↔host path even while the
 * extension's own transport is still a stub.
 */

import { chromium, test as base } from "@playwright/test";
import type { BrowserContext, Worker } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import {
  AppMock,
  EXTENSION_DIST,
  REPO_ROOT,
  waitForAppConnection,
} from "./app-mock";
import { probeHostBinary } from "./host-probe";
import {
  NATIVE_HOST_NAME,
  createHarnessEnvironment,
  defaultHostBinary,
  extensionIdCandidates,
  installNativeManifests,
  readHostPid,
  readJsonl,
  removeHarnessEnvironment,
  type HarnessPaths,
  type HostMode,
  writeHostWrapper,
} from "./setup";
import { RustApp } from "./rust-app";
import { sleep } from "./frames.mjs";

export interface HarnessOptions {
  /** `auto` uses the real host only if it answers `ping`; otherwise stub. */
  hostMode?: HostMode | "auto";
  extensionPath?: string;
  hostBinary?: string | null;
  headless?: boolean;
  channel?: string;
  /**
   * `mock` (default) uses the Node app mock. `rust` runs the real
   * `friendlypass-browser` protocol server from `fixtures/` (Phase-1 exit
   * test); it always pairs with `hostMode: "real"`.
   */
  appMode?: "mock" | "rust";
  /** Built `test_server` example; defaults to target/debug/examples/test_server. */
  testServerBinary?: string;
  /** Create a fresh writable KDBX4 instead of copying `fixtures/sample4.kdbx`. */
  createRustDatabase?: boolean;
  /**
   * Start the Node app mock with `associate` denied (error 6). Only meaningful
   * with `appMode: "mock"`; the real Rust test server auto-approves.
   */
  denyAssociations?: boolean;
  /**
   * Have the mock accept but never answer passkey actions, so the extension's
   * approval hint can be observed while a prompt is pending.
   */
  holdPasskeys?: boolean;
}

/** The lifecycle surface the harness needs from either app backend. */
export interface HarnessApp {
  readonly socketPath: string;
  readonly logPath: string;
  readonly listening: boolean;
  readonly connectionCount: number;
  readonly currentConnections: number;
  start(): Promise<void>;
  stop(): Promise<void>;
  restart(): Promise<void>;
  close(): Promise<void>;
}

export type NativeRoundTrip =
  | { ok: true; frame: Record<string, unknown> }
  | { ok: false; error: string };

export interface HostEvent extends Record<string, unknown> {
  ts?: number;
  event?: string;
  action?: string;
  direction?: string;
}

export class Harness {
  context: BrowserContext;
  readonly paths: HarnessPaths;
  readonly app: HarnessApp;
  /** The built extension directory passed to `--load-extension`. */
  readonly extensionPath: string;
  readonly requestedHostMode: HostMode | "auto";
  readonly computedExtensionIds: string[];
  readonly headless: boolean;
  readonly channel: string;
  extensionId: string;
  sw: Worker;

  private constructor(args: {
    context: BrowserContext;
    paths: HarnessPaths;
    app: HarnessApp;
    extensionPath: string;
    extensionId: string;
    sw: Worker;
    requestedHostMode: HostMode | "auto";
    computedExtensionIds: string[];
    headless: boolean;
    channel: string;
  }) {
    this.context = args.context;
    this.paths = args.paths;
    this.app = args.app;
    this.extensionPath = args.extensionPath;
    this.extensionId = args.extensionId;
    this.sw = args.sw;
    this.requestedHostMode = args.requestedHostMode;
    this.computedExtensionIds = args.computedExtensionIds;
    this.headless = args.headless;
    this.channel = args.channel;
  }

  static async start(options: HarnessOptions = {}): Promise<Harness> {
    const extensionPath = path.resolve(options.extensionPath ?? EXTENSION_DIST);
    assertExtensionBuilt(extensionPath);

    const requestedHostMode =
      options.hostMode ??
      (normalizeHostMode(process.env.FP_HOST) as HostMode | "auto");
    const hostBinary =
      options.hostBinary ??
      process.env.FP_HOST_BINARY ??
      defaultHostBinary(REPO_ROOT);

    let paths: HarnessPaths | null = null;
    let app: HarnessApp | null = null;
    let context: BrowserContext | null = null;
    try {
      paths = createHarnessEnvironment({
        // Created as stub-first: the wrapper is rewritten below if the real host
        // passes a probe against the harness app socket.
        mode: "stub",
        hostBinary,
        extensionPath,
      });

      if (options.appMode === "rust") {
        app = new RustApp({
          socketPath: paths.appSocket,
          binaryPath:
            options.testServerBinary ??
            process.env.FP_TEST_SERVER_BINARY ??
            path.join(REPO_ROOT, "target/debug/examples/test_server"),
          fixtureDatabase: path.join(REPO_ROOT, "fixtures/sample4.kdbx"),
          createDatabase: options.createRustDatabase === true,
          root: paths.root,
          logPath: path.join(paths.root, "app-server.jsonl"),
        });
      } else {
        app = new AppMock({
          socketPath: paths.appSocket,
          logPath: paths.appLog,
          denyAssociations: options.denyAssociations === true,
          holdPasskeys: options.holdPasskeys === true,
        });
      }
      await app.start();

      const probeEnv: Record<string, string> = {
        HOME: paths.home,
        XDG_CONFIG_HOME: path.join(paths.home, ".config"),
        TMPDIR: paths.root,
      };
      if (process.platform === "darwin") {
        probeEnv.CFFIXED_USER_HOME = paths.home;
      }
      const mode = await resolveHostMode(
        requestedHostMode,
        hostBinary,
        app,
        probeEnv,
      );
      paths.mode = mode;
      if (mode === "real") writeHostWrapper(paths, "0.1.0");
      try {
        const infoFile = path.join(paths.root, "harness-env.json");
        const info = JSON.parse(fs.readFileSync(infoFile, "utf8")) as Record<
          string,
          unknown
        >;
        info.mode = mode;
        fs.writeFileSync(infoFile, `${JSON.stringify(info, null, 2)}\n`);
      } catch {
        /* diagnostics only */
      }

      installNativeManifests(paths, extensionIdCandidates(extensionPath));

      const headless = options.headless ?? process.env.FP_HEADED !== "1";
      const channel = options.channel ?? process.env.FP_CHANNEL ?? "chromium";
      const computedExtensionIds = extensionIdCandidates(extensionPath);

      let sw: Worker;
      let extensionId: string;
      let attempts = 0;
      for (;;) {
        context = await launchBrowser({
          paths,
          extensionPath,
          headless,
          channel,
        });
        sw = await waitForServiceWorker(context, 20_000);
        extensionId = extensionIdFromWorker(sw);

        if (computedExtensionIds.includes(extensionId)) break;

        // The unpacked-extension ID is path-derived. If Chromium disagrees
        // with our computation (for example a symlink is resolved differently),
        // rewrite the manifest with the authoritative ID and relaunch once.
        installNativeManifests(paths, [extensionId, ...computedExtensionIds]);
        await context.close();
        context = null;
        attempts += 1;
        if (attempts > 1) {
          throw new Error(
            `Chromium extension ID ${extensionId} never matched ${computedExtensionIds.join(", ")}`,
          );
        }
      }

      return new Harness({
        context: context!,
        paths: paths!,
        app: app!,
        extensionPath,
        extensionId,
        sw,
        requestedHostMode,
        computedExtensionIds,
        headless,
        channel,
      });
    } catch (error) {
      if (context) await context.close().catch(() => undefined);
      if (app) await app.close().catch(() => undefined);
      if (paths) removeHarnessEnvironment(paths);
      throw error;
    }
  }

  /** The currently reachable extension service worker, if it is awake. */
  async currentServiceWorker(): Promise<Worker> {
    try {
      await this.sw.evaluate(() => 1);
      return this.sw;
    } catch {
      this.sw = await waitForServiceWorker(this.context, 1500);
      return this.sw;
    }
  }

  /** Evaluate a function inside the extension service worker. */
  async swEvaluate<T>(fn: () => T | Promise<T>): Promise<T> {
    const worker = await this.currentServiceWorker();
    return worker.evaluate(fn);
  }

  /**
   * Send one frame over a real `chrome.runtime.connectNative` port and return
   * the first host reply. This proves the manifest/host path independently of
   * the extension's own transport implementation.
   */
  async nativeRoundTrip(
    frame: Record<string, unknown>,
    timeoutMs = 5000,
  ): Promise<NativeRoundTrip> {
    const worker = await this.currentServiceWorker();
    return worker.evaluate(extensionNativeRoundTrip, {
      hostName: NATIVE_HOST_NAME,
      frame,
      timeoutMs,
    });
  }

  /** Host-level `ping` through Chrome. Returns the response frame. */
  async ping(nonce?: string): Promise<Record<string, unknown>> {
    const request: Record<string, unknown> = { action: "ping" };
    if (nonce) request.nonce = nonce;
    const result = await this.nativeRoundTrip(request);
    if (!result.ok) throw new Error(`native ping failed: ${result.error}`);
    return result.frame;
  }

  /**
   * Keep one native port open and ping until the host reports
   * `appRunning: true`.
   *
   * A brand-new host process answers `ping` before its background probe has
   * heard from the app, so a single ping on a fresh port legitimately reports
   * false for about a second. Reusing the port makes readiness observable.
   */
  async waitForAppRunning(timeoutMs = 5000): Promise<Record<string, unknown>> {
    const worker = await this.currentServiceWorker();
    const result = await worker.evaluate(extensionWaitForAppRunning, {
      hostName: NATIVE_HOST_NAME,
      timeoutMs,
    });
    if (!result.ok) throw new Error(`app never reported running: ${result.error}`);
    return result.frame;
  }

  /** Host-level `hello` through Chrome. */
  async hello(): Promise<Record<string, unknown>> {
    const result = await this.nativeRoundTrip({
      action: "hello",
      extensionVersion: "0.1.0",
    });
    if (!result.ok) throw new Error(`native hello failed: ${result.error}`);
    return result.frame;
  }

  /**
   * Open a native port kept in the service-worker global scope. Use together
   * with `nativeProbeFrames()` to observe unsolicited host frames (for example
   * the 1002 error produced by `sendCorruptFrame`).
   */
  async openNativeProbePort(): Promise<void> {
    const worker = await this.currentServiceWorker();
    await worker.evaluate(({ hostName }) => {
      const globalObject = globalThis as unknown as {
        __fpProbe?: {
          frames: unknown[];
          port: chrome.runtime.Port;
          disconnected: boolean;
          error: string | null;
        };
      };
      try {
        globalObject.__fpProbe?.port.disconnect();
      } catch {
        /* ignore */
      }
      const port = chrome.runtime.connectNative(hostName);
      const state = {
        frames: [] as unknown[],
        port,
        disconnected: false,
        error: null as string | null,
      };
      port.onMessage.addListener((message) => state.frames.push(message));
      port.onDisconnect.addListener(() => {
        state.disconnected = true;
        state.error = chrome.runtime.lastError?.message ?? null;
      });
      globalObject.__fpProbe = state;
    }, { hostName: NATIVE_HOST_NAME });
  }

  async nativeProbeFrames(): Promise<Array<Record<string, unknown>>> {
    const worker = await this.currentServiceWorker();
    return worker.evaluate(() => {
      const globalObject = globalThis as unknown as {
        __fpProbe?: { frames: Array<Record<string, unknown>> };
      };
      return globalObject.__fpProbe?.frames ?? [];
    });
  }

  async closeNativeProbePort(): Promise<void> {
    const worker = await this.currentServiceWorker();
    await worker
      .evaluate(() => {
        const globalObject = globalThis as unknown as {
          __fpProbe?: { port: chrome.runtime.Port };
        };
        try {
          globalObject.__fpProbe?.port.disconnect();
        } catch {
          /* ignore */
        }
        delete globalObject.__fpProbe;
      })
      .catch(() => undefined);
  }

  /**
   * Restart the browser context with the same temp profile and extension.
   *
   * Why not `chrome.runtime.reload()`: Chrome for Testing marks an unpacked
   * extension loaded via `--load-extension` as DISABLED
   * (`disableReasons.unsupportedDeveloperExtension`) when an extension API
   * reloads it, which would make every later assertion meaningless. Closing and
   * relaunching the persistent context is the strongest still-valid form of
   * "the browser slept / the service worker restarted": the SW goes away, the
   * native host is killed and re-spawned, and the extension must recover with
   * no manual step.
   */
  async reloadExtension(): Promise<Worker> {
    await this.context.close().catch(() => undefined);
    this.context = await launchBrowser({
      paths: this.paths,
      extensionPath: this.extensionPath,
      headless: this.headless,
      channel: this.channel,
    });
    const worker = await waitForServiceWorker(this.context, 20_000);
    this.sw = worker;
    this.extensionId = extensionIdFromWorker(worker);
    return worker;
  }

  /** Alias matching the WP8 brief's fault-injection vocabulary. */
  async simulateSleep(): Promise<Worker> {
    return this.reloadExtension();
  }

  /** Kill the native host with SIGKILL. Chrome spawns a new one on reconnect. */
  async killHost(): Promise<number> {
    const pid = readHostPid(this.paths);
    if (!pid) throw new Error("no host PID recorded; start the host first");
    try {
      process.kill(pid, "SIGKILL");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline && isProcessAlive(pid)) await sleep(25);
    return pid;
  }

  async killApp(): Promise<void> {
    await this.app.stop();
  }

  async restartApp(): Promise<void> {
    await this.app.restart();
  }

  stallApp(ms: number): number {
    if (this.app instanceof AppMock) {
      return this.app.stall(ms);
    }
    throw new Error("stallApp() requires the Node app mock");
  }

  /** Simulate the app user approving or denying association prompts. */
  setAssociationDenied(denied: boolean): void {
    if (this.app instanceof AppMock) {
      this.app.setAssociationDenied(denied);
      return;
    }
    throw new Error("setAssociationDenied() requires the Node app mock");
  }

  sendCorruptFrame(): boolean {
    if (this.app instanceof AppMock) {
      return this.app.sendCorruptFrame();
    }
    throw new Error("sendCorruptFrame() requires the Node app mock");
  }

  /**
   * Call an internal background request through the service worker's debug
   * bridge. This is the same handler map the popup uses, so specs exercise the
   * real transport/session/action path without a test-only shortcut.
   */
  async internalRequest<A extends string>(
    action: A,
    args?: unknown,
  ): Promise<unknown> {
    const worker = await this.currentServiceWorker();
    return worker.evaluate(
      async ({ action: innerAction, args: innerArgs }) => {
        const debug = (
          globalThis as unknown as {
            __friendlypassDebug?: {
              request(a: string, v?: unknown): Promise<unknown>;
            };
          }
        ).__friendlypassDebug;
        if (!debug) throw new Error("friendlypass debug bridge is not installed");
        return await debug.request(innerAction, innerArgs);
      },
      { action, args },
    );
  }

  /** Unhandled rejections observed by the current service worker. */
  async swRejections(): Promise<string[]> {
    const worker = await this.currentServiceWorker();
    return worker.evaluate(() => {
      const debug = (
        globalThis as unknown as {
          __friendlypassDebug?: { rejections(): string[] };
        }
      ).__friendlypassDebug;
      return debug?.rejections() ?? [];
    });
  }

  /** The Rust app backend, when `appMode: "rust"` selected it. */
  rustApp(): RustApp {
    if (this.app instanceof RustApp) {
      return this.app;
    }
    throw new Error("rustApp() requires appMode: \"rust\"");
  }

  /** PID written by the generated host wrapper, if a host is running. */
  hostProcessId(): number | null {
    return readHostPid(this.paths);
  }

  hostEvents(): HostEvent[] {
    return readJsonl(this.paths.hostLog) as HostEvent[];
  }

  hostStarts(): HostEvent[] {
    return this.hostEvents().filter((event) => event.event === "start");
  }

  hostActions(direction: "ext->host" | "ext->app" | "app->ext" = "ext->host") {
    return this.hostEvents().filter(
      (event) =>
        event.event === "frame" &&
        event.direction === direction &&
        typeof event.action === "string" &&
        event.action.length > 0,
    );
  }

  async waitForHostAction(
    action: string,
    timeoutMs = 10_000,
  ): Promise<HostEvent> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const match = this.hostActions().find((event) => event.action === action);
      if (match) return match;
      await sleep(50);
    }
    throw new Error(
      `host never saw action ${action}; events: ${JSON.stringify(
        this.hostEvents().slice(-10),
      )}`,
    );
  }

  async waitForHostStart(count = 1, timeoutMs = 5000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.hostStarts().length >= count) return;
      await sleep(25);
    }
    throw new Error(
      `host did not start ${count} time(s); events: ${JSON.stringify(
        this.hostEvents().slice(-10),
      )}`,
    );
  }

  /** Wait until the host has an app-socket connection (for corrupt frames). */
  async waitForAppConnected(timeoutMs = 5000): Promise<void> {
    await waitForAppConnection(this.app, timeoutMs);
  }

  /**
   * Wait for the app to have at least `minimum` live host connections. Each
   * native port is a separate host process, so fault injection must target the
   * port under test (not merely "some" host connection).
   */
  async waitForAppConnections(minimum: number, timeoutMs = 5000): Promise<void> {
    await waitForAppConnection(this.app, timeoutMs, minimum);
  }

  /**
   * Whether the extension bundle appears to have a real native transport.
   * WP2's placeholder throws a TODO and contains no `connectNative` call.
   */
  transportImplemented(): boolean {
    const bundle = fs.readFileSync(
      path.join(this.extensionPath, "background/sw.js"),
      "utf8",
    );
    return /connectNative\s*\(/.test(bundle);
  }

  async close(): Promise<void> {
    const pid = readHostPid(this.paths);
    await this.context.close().catch(() => undefined);
    if (pid && isProcessAlive(pid)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        /* already gone */
      }
    }
    await this.app.close().catch(() => undefined);
    removeHarnessEnvironment(this.paths);
  }
}

function assertExtensionBuilt(extensionPath: string): void {
  const manifest = path.join(extensionPath, "manifest.json");
  const bundle = path.join(extensionPath, "background/sw.js");
  if (!fs.existsSync(manifest) || !fs.existsSync(bundle)) {
    throw new Error(
      `extension build not found at ${extensionPath}; run \`cd extension && npm run build\` (or scripts/e2e.sh)`,
    );
  }
}

function normalizeHostMode(value: string | undefined): HostMode | "auto" {
  const mode = (value ?? "auto").toLowerCase();
  if (mode === "real" || mode === "stub" || mode === "auto") return mode;
  throw new Error(`invalid FP_HOST=${value}; expected real|stub|auto`);
}

async function resolveHostMode(
  requested: HostMode | "auto",
  hostBinary: string,
  app?: { socketPath: string; connectionCount: number },
  env?: Record<string, string>,
): Promise<HostMode> {
  if (requested === "stub") return "stub";
  if (!fs.existsSync(hostBinary)) {
    if (requested === "real") {
      throw new Error(
        `FP_HOST=real but no host binary at ${hostBinary}; run \`cargo build -p friendlypass-browser-host\``,
      );
    }
    return "stub";
  }

  const connectionsBefore = app?.connectionCount ?? 0;
  const probe = await probeHostBinary(hostBinary, {
    appConnected: app
      ? () => app.connectionCount > connectionsBefore
      : undefined,
    env: {
      ...env,
      ...(app
        ? {
            FP_APP_SOCKET: app.socketPath,
            FRIENDLYPASS_BROWSER_SOCKET: app.socketPath,
            FRIENDLYPASS_APP_SOCKET: app.socketPath,
            FRIENDLYPASS_SOCKET: app.socketPath,
          }
        : {}),
    },
  });

  let ok = probe.ok;
  // A real host that answers ping but ignores the harness's app socket would
  // make every credential test meaningless. Require one app-socket connection
  // during the probe before choosing it in `auto` mode.
  if (ok && app) {
    const deadline = Date.now() + 1500;
    while (Date.now() < deadline && app.connectionCount <= connectionsBefore) {
      await sleep(25);
    }
    if (app.connectionCount <= connectionsBefore) {
      ok = false;
      probe.error =
        "host answered ping but did not connect to the harness app socket";
    }
  }

  if (ok) return "real";
  if (requested === "real") {
    throw new Error(
      `FP_HOST=real but ${hostBinary} is not usable: ${probe.error ?? "unknown"}`,
    );
  }
  return "stub";
}

async function launchBrowser(args: {
  paths: HarnessPaths;
  extensionPath: string;
  headless: boolean;
  channel: string;
}): Promise<BrowserContext> {
  const { paths, extensionPath } = args;
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    HOME: paths.home,
    XDG_CONFIG_HOME: path.join(paths.home, ".config"),
    TMPDIR: paths.root,
  };
  // macOS Foundation ignores $HOME for Application Support paths (and therefore
  // for user-level native-messaging manifests). CFFIXED_USER_HOME is the
  // supported override; without it the harness would have to write into the
  // user's real ~/Library/Application Support.
  if (process.platform === "darwin") env.CFFIXED_USER_HOME = paths.home;

  return chromium.launchPersistentContext(paths.profile, {
    channel: args.channel,
    headless: args.headless,
    env,
    ignoreDefaultArgs: ["--disable-extensions"],
    timeout: 45_000,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-component-update",
      "--disable-background-networking",
      "--disable-sync",
      "--disable-dev-shm-usage",
      "--metrics-recording-only",
      "--password-store=basic",
      "--use-mock-keychain",
    ],
  });
}

/**
 * Runs inside an extension context (service worker or probe page). Kept as a
 * top-level function so the exact same native-messaging logic is used in both.
 */
async function extensionNativeRoundTrip(args: {
  hostName: string;
  frame: Record<string, unknown>;
  timeoutMs: number;
}): Promise<
  { ok: true; frame: Record<string, unknown> } | { ok: false; error: string }
> {
  const { hostName, frame, timeoutMs } = args;
  return await new Promise((resolve) => {
    let settled = false;
    let port: chrome.runtime.Port | null = null;
    const finish = (
      value:
        | { ok: true; frame: Record<string, unknown> }
        | { ok: false; error: string },
    ) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        port?.disconnect();
      } catch {
        /* already gone */
      }
      resolve(value);
    };
    const timer = setTimeout(
      () => finish({ ok: false, error: "timeout" }),
      timeoutMs,
    );
    try {
      port = chrome.runtime.connectNative(hostName);
    } catch (error) {
      finish({ ok: false, error: String(error) });
      return;
    }
    port.onMessage.addListener((message) => {
      finish({ ok: true, frame: message as Record<string, unknown> });
    });
    port.onDisconnect.addListener(() => {
      const lastError = chrome.runtime.lastError;
      finish({
        ok: false,
        error: lastError?.message ?? "native port disconnected",
      });
    });
    try {
      port.postMessage(frame);
    } catch (error) {
      finish({ ok: false, error: String(error) });
    }
  });
}

/**
 * Runs inside the service worker: open one native port and ping on it until
 * `appRunning: true` or the deadline. Chrome gives each port its own host
 * process, so reusing the port keeps the same status cache.
 */
async function extensionWaitForAppRunning(args: {
  hostName: string;
  timeoutMs: number;
}): Promise<
  { ok: true; frame: Record<string, unknown> } | { ok: false; error: string }
> {
  const { hostName, timeoutMs } = args;
  return await new Promise((resolve) => {
    let settled = false;
    let port: chrome.runtime.Port | null = null;
    let last: Record<string, unknown> | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let nextPing: ReturnType<typeof setTimeout> | null = null;

    const finish = (
      value:
        | { ok: true; frame: Record<string, unknown> }
        | { ok: false; error: string },
    ) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      if (nextPing !== null) clearTimeout(nextPing);
      try {
        port?.disconnect();
      } catch {
        /* already gone */
      }
      resolve(value);
    };

    timer = setTimeout(() => {
      finish({
        ok: false,
        error: `appRunning stayed false for ${timeoutMs} ms (last: ${JSON.stringify(last)})`,
      });
    }, timeoutMs);

    try {
      port = chrome.runtime.connectNative(hostName);
    } catch (error) {
      finish({ ok: false, error: String(error) });
      return;
    }
    port.onMessage.addListener((message) => {
      const frame = message as Record<string, unknown>;
      if (frame.action !== "ping") return;
      last = frame;
      if (frame.appRunning === true) {
        finish({ ok: true, frame });
        return;
      }
      if (nextPing === null) {
        nextPing = setTimeout(() => {
          nextPing = null;
          try {
            port?.postMessage({ action: "ping" });
          } catch {
            finish({ ok: false, error: "native port closed" });
          }
        }, 150);
      }
    });
    port.onDisconnect.addListener(() => {
      finish({
        ok: false,
        error: chrome.runtime.lastError?.message ?? "native port disconnected",
      });
    });
    try {
      port.postMessage({ action: "ping" });
    } catch (error) {
      finish({ ok: false, error: String(error) });
    }
  });
}

async function waitForServiceWorker(
  context: BrowserContext,
  timeoutMs: number,
): Promise<Worker> {
  const match = (worker: Worker) => worker.url().includes("/background/sw.js");
  const existing = context.serviceWorkers().filter(match);
  if (existing.length > 0) return existing[existing.length - 1];

  return context.waitForEvent("serviceworker", {
    timeout: timeoutMs,
    predicate: match,
  });
}

function extensionIdFromWorker(worker: Worker): string {
  const match = /^chrome-extension:\/\/([a-p]{32})\//.exec(worker.url());
  if (!match) {
    throw new Error(`unexpected service-worker URL: ${worker.url()}`);
  }
  return match[1];
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Playwright fixture. Every test gets its own temp HOME, profile, app mock,
 * host and browser, so fault injection in one spec cannot leak into another.
 */
export const test = base.extend<{ harness: Harness }>({
  harness: async ({}, use) => {
    const harness = await Harness.start();
    try {
      await use(harness);
    } finally {
      await harness.close();
    }
  },
});

export { expect } from "@playwright/test";
