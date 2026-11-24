/**
 * Firefox e2e harness (WP9).
 *
 * One `startHarness()` gives a scenario:
 *   - a pinned Firefox (WebDriver BiDi via Puppeteer) with the real
 *     `dist-firefox` add-on installed;
 *   - a fresh temp HOME/profile and a Firefox native-messaging manifest that
 *     points at the REAL `friendlypass-browser-host`;
 *   - the REAL `friendlypass-browser` protocol server on a temp unix socket,
 *     backed by a scenario KDBX created with the `friendlypass` CLI.
 *
 * Nothing outside the temp directory is touched.
 */

import fs from "node:fs";
import path from "node:path";

import { launchFirefox, ensureFirefox } from "./browser.mjs";
import { createEnvironment, isProcessAlive, readHostPid, removeEnvironment } from "./environment.mjs";
import { RustApp } from "./rust-app.mjs";
import { SAMPLE_DATABASE, sleep } from "./config.mjs";

export class FirefoxHarness {
  /**
   * @param {{
   *   paths: ReturnType<typeof createEnvironment>,
   *   app: RustApp,
   *   browser: import("puppeteer-core").Browser,
   *   extensionId: string,
   * }} options
   */
  constructor(options) {
    this.paths = options.paths;
    this.app = options.app;
    this.browser = options.browser;
    this.extensionId = options.extensionId;
    /** @type {import("puppeteer-core").Page | null} */
    this.extensionPage = null;
  }

  /**
   * @param {{
   *   prepareDatabase?: (context: { paths: ReturnType<typeof createEnvironment>, databasePath: string }) => void | Promise<void>,
   * }} [options]
   */
  static async start(options = {}) {
    const executablePath = await ensureFirefox();
    const paths = createEnvironment();
    /** @type {RustApp | null} */
    let app = null;
    /** @type {import("puppeteer-core").Browser | null} */
    let browser = null;
    try {
      await options.prepareDatabase?.({
        paths,
        databasePath: path.join(paths.root, "app-db.kdbx"),
      });

      app = new RustApp({
        socketPath: paths.appSocket,
        root: paths.root,
        logPath: paths.appLog,
        fixtureDatabase: SAMPLE_DATABASE,
      });
      await app.start();

      const launched = await launchFirefox({ executablePath, paths });
      browser = launched.browser;
      const harness = new FirefoxHarness({
        paths,
        app,
        browser,
        extensionId: launched.extensionId,
      });
      await harness.waitForHost();
      return harness;
    } catch (error) {
      await browser?.close().catch(() => undefined);
      await app?.close().catch(() => undefined);
      removeEnvironment(paths);
      throw error;
    }
  }

  /** Wait until Firefox has spawned the native host through the manifest. */
  async waitForHost(timeoutMs = 30_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const pid = readHostPid(this.paths);
      if (pid && isProcessAlive(pid)) return pid;
      await sleep(50);
    }
    throw new Error(
      `native host never started; manifests: ${this.paths.manifests.join(", ")}`,
    );
  }

  /** Wait until the host has a live connection to the Rust protocol server. */
  async waitForAppConnection(timeoutMs = 20_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.app.currentConnections > 0) return;
      await sleep(25);
    }
    throw new Error("native host never connected to the Rust app socket");
  }

  async newPage() {
    const page = await this.browser.newPage();
    page.setDefaultTimeout(30_000);
    return page;
  }

  /**
   * Firefox reports the module UUID (not the add-on id) as the moz-extension
   * resource id. It is written to `prefs.js` when the temporary add-on starts.
   */
  async extensionUuid(timeoutMs = 10_000) {
    const prefsFile = path.join(this.paths.profile, "prefs.js");
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const text = fs.readFileSync(prefsFile, "utf8");
        const line = text
          .split("\n")
          .find((entry) => entry.includes("extensions.webextensions.uuids"));
        const match = /friendlypass@friendlypass\.org\\":\\"([0-9a-f-]+)\\"/.exec(
          line ?? "",
        );
        if (match) return match[1];
      } catch {
        /* prefs not written yet */
      }
      await sleep(50);
    }
    throw new Error("the friendlypass UUID never appeared in prefs.js");
  }

  /**
   * Open one of the extension's own pages.
   *
   * Firefox's WebDriver BiDi navigation to `moz-extension://` commits the
   * document but never fires a load event that Puppeteer recognises, so
   * `page.goto` always reports a timeout even though `location.href` is the
   * extension page and `chrome.runtime` is live. Navigate best-effort and then
   * wait for the document itself.
   */
  async openExtensionPage(pageName = "popup/popup.html", timeoutMs = 15_000) {
    const uuid = await this.extensionUuid();
    const url = `moz-extension://${uuid}/${pageName}`;
    const page = await this.newPage();
    await page
      .goto(url, { waitUntil: "domcontentloaded", timeout: 4_000 })
      .catch(() => undefined);
    await waitFor(
      async () => {
        try {
          return await page.evaluate((expected) => location.href === expected, url);
        } catch {
          return false;
        }
      },
      timeoutMs,
      `extension page ${pageName}`,
    );
    return page;
  }

  /**
   * Dispatch one internal request from an extension page. This is the same
   * `chrome.runtime.sendMessage` path the popup uses (not a hidden backdoor):
   * the Firefox harness has no direct service-worker handle, so association and
   * read-only diagnostics go through the extension's public message API.
   */
  async extensionRequest(action, args) {
    if (!this.extensionPage) {
      this.extensionPage = await this.openExtensionPage();
    }
    const result = await this.extensionPage.evaluate(
      ({ action: innerAction, args: innerArgs }) =>
        new Promise((resolve) => {
          chrome.runtime.sendMessage(
            {
              channel: "friendlypass",
              action: innerAction,
              args: innerArgs,
              requestId: `firefox-harness-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2)}`,
            },
            (response) => {
              const lastError = chrome.runtime.lastError;
              resolve(
                lastError
                  ? { ok: false, error: { message: lastError.message } }
                  : response,
              );
            },
          );
        }),
      { action, args },
    );
    if (!result || result.ok !== true) {
      throw new Error(
        `extension request "${action}" failed: ${JSON.stringify(
          result?.error ?? result ?? null,
        )}`,
      );
    }
    return result.value;
  }

  /** Associate this browser with the test database (the popup's Connect). */
  async connect() {
    return await this.extensionRequest("association.create");
  }

  /** Current background status; read-only. */
  async status() {
    return await this.extensionRequest("status.get");
  }


  /** Navigate and return the response (may be null for about: pages). */
  async open(page, url) {
    return await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: 30_000,
    });
  }

  /** Open a fresh page on `url` and wait for a friendlypass selector. */
  async openAndWait(url, selector, timeoutMs = 30_000) {
    const page = await this.newPage();
    await this.open(page, url);
    await waitForSelector(page, selector, timeoutMs);
    return page;
  }

  /** Kill the host; Firefox respawns it on the next reconnect. */
  async killHost() {
    const pid = readHostPid(this.paths);
    if (!pid) throw new Error("no host PID recorded");
    try {
      process.kill(pid, "SIGKILL");
    } catch (error) {
      if (error.code !== "ESRCH") throw error;
    }
  }

  async close() {
    const pid = readHostPid(this.paths);
    await this.browser.close().catch(() => undefined);    if (pid && isProcessAlive(pid)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        /* already gone */
      }
    }
    await this.app.close().catch(() => undefined);
    removeEnvironment(this.paths);
  }

  /** Diagnostic tail for a failed scenario. */
  diagnostics() {
    const read = (file) => {
      try {
        return fs.readFileSync(file, "utf8").slice(-4000);
      } catch {
        return "(missing)";
      }
    };
    return {
      root: this.paths.root,
      hostPid: readHostPid(this.paths),
      hostStderr: read(this.paths.hostStderr),
      appLog: read(this.paths.appLog),
    };
  }
}

export async function waitForSelector(page, selector, timeoutMs = 30_000) {
  await page.waitForSelector(selector, { timeout: timeoutMs });
  return page;
}

/** Poll `predicate` until it is truthy or the deadline expires. */
export async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await sleep(50);
  }
  throw new Error(`timed out waiting for ${label}`);
}

export const LOGIN_ICON = '[data-friendlypass="icon"][data-friendlypass-kind="login"]';
export const LOGIN_ICON_MATCHES =
  '[data-friendlypass="icon"][data-friendlypass-kind="login"][data-friendlypass-state="matches"]';
export const BANNER = '[data-friendlypass="banner"]';
