/**
 * WP6b end-to-end inline-UI tests.
 *
 * Real extension bundle + real native host + a mutable in-spec protocol app.
 * The app adds what the WP6b flows need over the WP8 mock: `generate-password`,
 * a lock/unlock push, and group persistence on `set-login`.
 *
 * Every visual state is captured as a PNG (light and dark) under
 * `extension/test-results/shots/wp6b-inline/` (or `$FP_SHOTS_DIR`).
 */

import { expect, test as base } from "@playwright/test";
import type { Page, Worker } from "@playwright/test";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import nacl from "tweetnacl";
import { Harness } from "../harness/harness";
import { shotsDir } from "../harness/shots";
import {
  ObjectStreamDecoder,
  encodeObject,
  incrementNonce,
  sleep,
} from "../harness/frames.mjs";

// ---------------------------------------------------------------------------
// Mutable protocol app
// ---------------------------------------------------------------------------

interface DbEntry {
  login: string;
  password: string;
  name: string;
  uuid: string;
  group: string;
  url: string;
  totp?: string;
}

interface AppSession {
  clientKey: Uint8Array | null;
  keyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
  associated: boolean;
}

const DB_HASH =
  "4265c37dbe9ad073ac19837734d54fdd7d7c30bd87322ba886da62b147d66fbb";
const ROOT_GROUP_UUID = "bb710c2f876761bb90748cc271ff8fae";
const ASSOCIATION_ID = "chrome-wp6b";

function fromB64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

function toB64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64");
}

function stringField(
  record: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function newUuid(): string {
  return randomBytes(16).toString("hex");
}

function normaliseUrl(raw: string): string | null {
  try {
    const url = new URL(raw);
    return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
  } catch {
    return null;
  }
}

function dirnameOf(file: string): string {
  const index = file.lastIndexOf("/");
  return index > 0 ? file.slice(0, index) : ".";
}

class FixtureApp {
  readonly socketPath: string;
  readonly entries: DbEntry[];
  connectionCount = 0;
  generatedCount = 0;

  private server: net.Server | null = null;
  private locked = false;
  private readonly sockets = new Set<net.Socket>();
  private readonly sessions = new WeakMap<net.Socket, AppSession>();

  constructor(socketPath: string, entries: DbEntry[]) {
    this.socketPath = socketPath;
    this.entries = entries.map((entry) => ({ ...entry }));
  }

  get currentConnections(): number {
    return this.sockets.size;
  }

  get isLocked(): boolean {
    return this.locked;
  }

  addEntry(entry: DbEntry): void {
    this.entries.push({ ...entry });
  }

  /** Toggle the app-side lock and push `database-locked`/`-unlocked`. */
  setLocked(locked: boolean): void {
    this.locked = locked;
    this.push(locked ? "database-locked" : "database-unlocked");
  }

  entryFor(path: string): DbEntry | undefined {
    return this.entries.find((entry) => entry.url.endsWith(path));
  }

  async start(): Promise<void> {
    fs.mkdirSync(dirnameOf(this.socketPath), { recursive: true });
    fs.rmSync(this.socketPath, { force: true });

    const server = net.createServer((socket) => this.accept(socket));
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.socketPath, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    try {
      fs.chmodSync(this.socketPath, 0o600);
    } catch {
      /* best effort outside POSIX */
    }
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) {
      socket.destroy();
    }
    this.sockets.clear();
    const server = this.server;
    this.server = null;
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    fs.rmSync(this.socketPath, { force: true });
  }

  private push(action: string): void {
    for (const socket of this.sockets) {
      this.write(socket, { action });
    }
  }

  private accept(socket: net.Socket): void {
    socket.setNoDelay(true);
    this.sockets.add(socket);
    this.connectionCount += 1;

    const session: AppSession = {
      clientKey: null,
      keyPair: nacl.box.keyPair(),
      associated: false,
    };
    this.sessions.set(socket, session);

    const decoder = new ObjectStreamDecoder();
    socket.on("data", (chunk: Buffer) => {
      for (const decoded of decoder.push(chunk)) {
        if (decoded.type === "frame") {
          this.handle(socket, session, decoded.value);
        }
      }
    });
    socket.on("error", () => undefined);
    socket.on("close", () => {
      this.sockets.delete(socket);
    });
  }

  private handle(
    socket: net.Socket,
    session: AppSession,
    frame: Record<string, unknown>,
  ): void {
    const action = stringField(frame, "action") ?? "";
    const nonce = stringField(frame, "nonce");

    if (action === "change-public-keys") {
      const publicKey = stringField(frame, "publicKey");
      if (!publicKey || !nonce) {
        this.error(socket, action, 3, "Client public key or nonce missing");
        return;
      }
      session.clientKey = fromB64(publicKey);
      session.keyPair = nacl.box.keyPair();
      session.associated = false;
      this.write(socket, {
        action,
        version: "2.8.0",
        success: "true",
        nonce: incrementNonce(nonce),
        publicKey: toB64(session.keyPair.publicKey),
      });
      return;
    }

    this.handleEncrypted(socket, session, frame, action);
  }

  private handleEncrypted(
    socket: net.Socket,
    session: AppSession,
    frame: Record<string, unknown>,
    action: string,
  ): void {
    const requestNonce = stringField(frame, "nonce");
    const message = stringField(frame, "message");
    if (!session.clientKey || !requestNonce || !message) {
      this.error(socket, action, 3, "Client public key not received");
      return;
    }

    let inner: Record<string, unknown>;
    try {
      const opened = nacl.box.open(
        fromB64(message),
        fromB64(requestNonce),
        session.clientKey,
        session.keyPair.secretKey,
      );
      if (!opened) {
        throw new Error("decrypt failed");
      }
      const parsed: unknown = JSON.parse(Buffer.from(opened).toString("utf8"));
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("inner is not an object");
      }
      inner = parsed as Record<string, unknown>;
    } catch {
      this.error(socket, action, 4, "Cannot decrypt message");
      return;
    }

    if (stringField(inner, "action") !== action) {
      this.error(socket, action, 12, "Incorrect action");
      return;
    }

    switch (action) {
      case "get-databasehash":
        this.reply(socket, action, requestNonce, { hash: DB_HASH });
        return;

      case "associate":
        session.associated = true;
        this.reply(socket, action, requestNonce, {
          hash: DB_HASH,
          id: ASSOCIATION_ID,
        });
        return;

      case "test-associate":
        session.associated = true;
        this.reply(socket, action, requestNonce, {
          hash: DB_HASH,
          id: ASSOCIATION_ID,
        });
        return;

      case "get-logins": {
        if (!session.associated) {
          this.error(socket, action, 8, "Association failed");
          return;
        }
        if (this.locked) {
          this.error(socket, action, 1, "Database not opened");
          return;
        }
        const url = stringField(inner, "url") ?? "";
        const submitUrl = stringField(inner, "submitUrl");
        if (!url) {
          this.error(socket, action, 14, "No URL provided");
          return;
        }
        const matches = this.match(url, submitUrl);
        if (matches.length === 0) {
          this.error(socket, action, 15, "No logins found");
          return;
        }
        this.reply(socket, action, requestNonce, {
          count: matches.length,
          entries: matches.map((entry) => this.wireEntry(entry)),
          hash: DB_HASH,
          id: ASSOCIATION_ID,
        });
        return;
      }

      case "set-login": {
        if (!session.associated) {
          this.error(socket, action, 8, "Association failed");
          return;
        }
        if (this.locked) {
          this.error(socket, action, 1, "Database not opened");
          return;
        }
        const url = stringField(inner, "url") ?? "";
        if (!url) {
          this.error(socket, action, 14, "No URL provided");
          return;
        }
        const login = stringField(inner, "login") ?? "";
        const password = stringField(inner, "password") ?? "";
        const group = stringField(inner, "group");
        const uuid = stringField(inner, "uuid");
        const existing = uuid
          ? this.entries.find((entry) => entry.uuid === uuid)
          : this.entries.find(
              (entry) => entry.login === login && entry.url === url,
            );
        if (existing) {
          existing.login = login;
          existing.password = password;
          existing.url = url;
          if (group) {
            existing.group = group;
          }
        } else {
          this.entries.push({
            login,
            password,
            name: login || "Saved login",
            uuid: newUuid(),
            group: group || "KeePassXC-Browser Passwords",
            url,
          });
        }
        this.reply(socket, action, requestNonce, {
          count: null,
          entries: null,
          error: "success",
          hash: DB_HASH,
        });
        return;
      }

      case "get-totp": {
        if (this.locked) {
          this.error(socket, action, 1, "Database not opened");
          return;
        }
        const uuid = stringField(inner, "uuid") ?? "";
        const entry = this.entries.find((candidate) => candidate.uuid === uuid);
        this.reply(socket, action, requestNonce, { totp: entry?.totp ?? "" });
        return;
      }

      case "generate-password": {
        this.generatedCount += 1;
        const password = `G3n-${this.generatedCount}-${randomBytes(6).toString("hex")}!`;
        this.reply(socket, action, requestNonce, { password, entries: password });
        return;
      }

      case "get-database-groups":
        this.reply(socket, action, requestNonce, {
          groups: {
            groups: [
              {
                name: "Root",
                uuid: ROOT_GROUP_UUID,
                children: [
                  {
                    name: "Work",
                    uuid: "d5ec68c35705b72fde380bd469aa149f",
                    children: [
                      {
                        name: "Production",
                        uuid: "31f7cbd1c9d44f6ea0a74be2f0aa1f2c",
                        children: [],
                      },
                    ],
                  },
                  {
                    name: "Personal",
                    uuid: "d5ec68c35705b72fde380bd469aa1490",
                    children: [],
                  },
                ],
              },
            ],
          },
        });
        return;

      case "lock-database":
        this.setLocked(true);
        this.reply(socket, action, requestNonce, {});
        return;

      default:
        this.error(socket, action, 12, "Incorrect action");
    }
  }

  private match(url: string, submitUrl: string | undefined): DbEntry[] {
    const page = normaliseUrl(url);
    const submit = submitUrl ? normaliseUrl(submitUrl) : null;
    return this.entries.filter((entry) => {
      const entryUrl = normaliseUrl(entry.url);
      return (
        entryUrl !== null &&
        ((page !== null && entryUrl === page) ||
          (submit !== null && entryUrl === submit))
      );
    });
  }

  private wireEntry(entry: DbEntry): Record<string, string> {
    return {
      login: entry.login,
      password: entry.password,
      name: entry.name,
      uuid: entry.uuid,
      group: entry.group,
      ...(entry.totp ? { totp: entry.totp } : {}),
    };
  }

  private reply(
    socket: net.Socket,
    action: string,
    requestNonce: string,
    fields: Record<string, unknown>,
  ): void {
    const responseNonce = incrementNonce(requestNonce);
    this.write(socket, {
      action,
      message: toB64(
        nacl.box(
          Buffer.from(
            JSON.stringify({
              version: "2.8.0",
              success: "true",
              nonce: responseNonce,
              ...fields,
            }),
            "utf8",
          ),
          fromB64(responseNonce),
          this.clientKeyOf(socket),
          this.secretKeyOf(socket),
        ),
      ),
      nonce: responseNonce,
    });
  }

  private clientKeyOf(socket: net.Socket): Uint8Array {
    const session = this.sessions.get(socket);
    if (!session?.clientKey) {
      throw new Error("reply without client key");
    }
    return session.clientKey;
  }

  private secretKeyOf(socket: net.Socket): Uint8Array {
    const session = this.sessions.get(socket);
    if (!session) {
      throw new Error("reply without session");
    }
    return session.keyPair.secretKey;
  }

  private error(
    socket: net.Socket,
    action: string,
    code: number,
    message: string,
  ): void {
    this.write(socket, { action, errorCode: String(code), error: message });
  }

  private write(socket: net.Socket, frame: Record<string, unknown>): void {
    if (!this.sockets.has(socket)) {
      return;
    }
    socket.write(encodeObject(frame));
  }
}

// ---------------------------------------------------------------------------
// Test pages
// ---------------------------------------------------------------------------

function loginPage(action: string, title: string, extra = ""): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>
<body>
<h1>${title}</h1>
<form id="login-form" action="${action}" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  ${extra}
  <button id="submit" type="submit">Log in</button>
</form>
</body></html>`;
}

function savePage(): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Create account</title></head>
<body>
<h1>Create account</h1>
<form id="signup-form" action="/save" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="new-password">
  <button id="submit" type="submit">Save</button>
</form>
<script>
  document.getElementById('signup-form').addEventListener('submit', (event) => {
    event.preventDefault();
  });
</script>
</body></html>`;
}

const PAGES: Record<string, string> = {
  "/login": loginPage("/login", "Sign in"),
  "/login-two": loginPage("/login-two", "Two logins"),
  "/no-match": loginPage("/no-match", "No saved login"),
  "/totp-two": `<!doctype html><html><head><meta charset="utf-8"><title>TOTP</title></head>
<body>
<h1>Two-factor</h1>
<form id="totp-form" action="/totp-two" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password">
  <input id="totp" name="totp" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="6-digit code">
  <button type="submit">Verify</button>
</form>
</body></html>`,
  "/scroll": `<!doctype html><html><head><meta charset="utf-8"><title>Scrollable</title></head>
<body>
<h1>Scrollable login</h1>
<form id="login-form" action="/scroll" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password">
  <button type="submit">Log in</button>
</form>
<div style="height:2000px"></div>
</body></html>`,
  "/save": savePage(),
  "/signup": `<!doctype html><html><head><meta charset="utf-8"><title>Sign up</title></head>
<body>
<h1>Sign up</h1>
<form id="signup-form" action="/signup" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="new-password" name="new-password" type="password" autocomplete="new-password">
  <input id="confirm-password" name="confirm-password" type="password" autocomplete="new-password">
  <button id="submit" type="submit">Create account</button>
</form>
</body></html>`,
  "/bottom": `<!doctype html><html><head><meta charset="utf-8"><title>Bottom form</title>
<style>body{margin:0;padding-top:calc(100vh - 150px)}</style></head>
<body>
<form id="login-form" action="/bottom" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password">
  <button type="submit">Log in</button>
</form>
</body></html>`,
  "/hostile": `<!doctype html><html><head><meta charset="utf-8"><title>Hostile CSS</title>
<style>
  * { all: unset; }
  [data-friendlypass] { all: unset !important; }
  body, form { display: block; }
  h1 { display: block; font-size: 20px; margin: 16px; }
  form { margin: 24px; }
  input { display: inline-block; width: 240px; height: 32px; margin: 6px 0; border: 1px solid #888; }
</style></head>
<body>
<h1>Hostile page CSS</h1>
<form id="login-form" action="/hostile" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Log in</button>
</form>
</body></html>`,
  "/search-mixed": `<!doctype html><html><head><meta charset="utf-8"><title>Search and login</title></head>
<body>
<h1>Search and login</h1>
<form action="/search" role="search">
  <input id="search" type="search" name="q" placeholder="Search">
  <button type="submit">Search</button>
</form>
<form id="login-form" action="/login" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password">
  <button type="submit">Log in</button>
</form>
</body></html>`,
  "/eye": `<!doctype html><html><head><meta charset="utf-8"><title>Password eye</title>
<style>
  .wrap{position:relative;display:inline-block;margin:24px}
  .wrap input{width:320px;height:36px;padding-right:40px}
  .eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:28px;height:28px;border:0;background:transparent}
</style></head>
<body>
<h1>Password with eye toggle</h1>
<form id="login-form" action="/login" method="post">
  <div class="wrap">
    <input id="username" name="username" type="text" autocomplete="username">
    <input id="password" name="password" type="password">
    <button class="eye" id="eye" type="button" aria-label="Show password">👁</button>
  </div>
  <button id="submit" type="submit">Log in</button>
</form>
</body></html>`,
};

interface PagesServer {
  baseUrl: string;
  close(): Promise<void>;
}

async function startPages(): Promise<PagesServer> {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const html = PAGES[url.pathname];
    if (!html) {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("not found");
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(html);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: async () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

// ---------------------------------------------------------------------------
// Stack fixture
// ---------------------------------------------------------------------------

interface Stack {
  harness: Harness;
  app: FixtureApp;
  pages: PagesServer;
}

function entry(
  baseUrl: string,
  path: string,
  login: string,
  password: string,
  extra: Partial<DbEntry> = {},
): DbEntry {
  return {
    login,
    password,
    name: `WP6b ${path} ${login}`,
    uuid: newUuid(),
    group: "Work",
    url: `${baseUrl}${path}`,
    ...extra,
  };
}

function baseEntries(baseUrl: string): DbEntry[] {
  return [
    entry(baseUrl, "/login", "alice@example.com", "correct horse battery staple"),
    entry(baseUrl, "/login-two", "alice@example.com", "alice-password"),
    entry(baseUrl, "/login-two", "bob@example.com", "bob-password", {
      name: "Bob work account",
      group: "Personal",
    }),
    entry(baseUrl, "/no-match", "unused@example.com", "unused", {
      url: `${baseUrl}/somewhere-else`,
    }),
    entry(baseUrl, "/bottom", "bottom-a@example.com", "bottom-a"),
    entry(baseUrl, "/bottom", "bottom-b@example.com", "bottom-b", {
      group: "Personal",
    }),
    entry(baseUrl, "/scroll", "scroll-a@example.com", "scroll-a"),
    entry(baseUrl, "/scroll", "scroll-b@example.com", "scroll-b", {
      group: "Personal",
    }),
    entry(baseUrl, "/totp-two", "totp-a@example.com", "totp-a", {
      totp: "777777",
    }),
    entry(baseUrl, "/totp-two", "totp-b@example.com", "totp-b", {
      totp: "888888",
    }),
    entry(baseUrl, "/hostile", "hostile@example.com", "hostile-password"),
    entry(baseUrl, "/hostile", "hostile2@example.com", "hostile-password-2", {
      name: "Second hostile login",
      group: "Personal",
    }),
    entry(baseUrl, "/login", "eye@example.com", "eye-password", {
      name: "Eye button login",
    }),
  ];
}

async function waitFor(
  condition: () => boolean,
  timeoutMs: number,
  label: string,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (condition()) {
      return;
    }
    await sleep(25);
  }
  throw new Error(`timed out waiting for ${label}`);
}

async function startStack(): Promise<Stack> {
  const pages = await startPages();
  const harness = await Harness.start();
  let app: FixtureApp | null = null;
  try {
    await harness.killApp();
    app = new FixtureApp(harness.paths.appSocket, baseEntries(pages.baseUrl));
    await app.start();
    await waitFor(
      () => app!.currentConnections > 0,
      10_000,
      "native host to reconnect to the test app",
    );
    await harness.internalRequest("connection.reconnect");
    await harness.internalRequest("association.create");
    return { harness, app, pages };
  } catch (error) {
    await app?.stop().catch(() => undefined);
    await harness.close().catch(() => undefined);
    await pages.close().catch(() => undefined);
    throw error;
  }
}

const stackTest = base.extend<{ stack: Stack }>({
  stack: async ({}, use) => {
    const stack = await startStack();
    try {
      await use(stack);
    } finally {
      await stack.app.stop().catch(() => undefined);
      await stack.harness.close().catch(() => undefined);
      await stack.pages.close().catch(() => undefined);
    }
  },
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SHOTS_DIR = shotsDir("wp6b-inline");

base.beforeAll(() => {
  fs.mkdirSync(SHOTS_DIR, { recursive: true });
});
async function openPage(stack: Stack, path: string): Promise<Page> {
  const page = await stack.harness.context.newPage();
  await page.goto(`${stack.pages.baseUrl}${path}`, { waitUntil: "load" });
  return page;
}

function loginIcon(page: Page) {
  return page.locator('[data-friendlypass="icon"][data-friendlypass-kind="login"]');
}

function totpIcon(page: Page) {
  return page.locator('[data-friendlypass="icon"][data-friendlypass-kind="totp"]');
}

function menuItems(page: Page) {
  return page.locator('[data-friendlypass="menu-item"]');
}

function menuAction(page: Page, id: string) {
  return page.locator(
    `[data-friendlypass="menu-action"][data-action="${id}"]`,
  );
}

async function shot(page: Page, name: string): Promise<void> {
  await page.screenshot({
    path: `${SHOTS_DIR}/${name}-light.png`,
    animations: "disabled",
  });
  await page.emulateMedia({ colorScheme: "dark" });
  await sleep(80);
  await page.screenshot({
    path: `${SHOTS_DIR}/${name}-dark.png`,
    animations: "disabled",
  });
  await page.emulateMedia({ colorScheme: "light" });
}

/** Full settings payload (content normalises defaults anyway). */
function settingsPayload(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    autoFillSingleEntry: false,
    showFieldIcons: true,
    httpAuthAutoFill: true,
    autoFillAndSubmit: false,
    launchAppOnConnect: false,
    defaultGroup: "",
    defaultGroupAlwaysAsk: false,
    debugLogging: false,
    siteExceptions: [],
    ...overrides,
  };
}

/** Emulate the background `settings.changed` broadcast. */
async function broadcastSettings(
  harness: Harness,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  const worker: Worker = await harness.currentServiceWorker();
  await worker.evaluate(async (payload) => {
    const envelope = {
      channel: "friendlypass",
      action: "settings.changed",
      args: payload,
      requestId: crypto.randomUUID(),
    };
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (typeof tab.id !== "number") {
        continue;
      }
      try {
        chrome.tabs.sendMessage(tab.id, envelope, () => {
          void chrome.runtime.lastError;
        });
      } catch {
        // Tab without a content script.
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 120));
  }, settingsPayload(overrides));
}

/** Send the raw command the background emits for a manifest shortcut. */
async function invokeShortcut(
  harness: Harness,
  action: "content.openInlineMenu" | "content.generatePassword",
): Promise<void> {
  const worker: Worker = await harness.currentServiceWorker();
  await worker.evaluate(async ({ name }) => {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (typeof tab.id !== "number") {
        continue;
      }
      try {
        chrome.tabs.sendMessage(
          tab.id,
          {
            channel: "friendlypass",
            action: name,
            args: undefined,
            requestId: crypto.randomUUID(),
          },
          () => {
            void chrome.runtime.lastError;
          },
        );
      } catch {
        // Tab without a content script.
      }
    }
  }, { name: action });
}

async function focusedBannerAction(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    const host = document.querySelector<HTMLElement>('[data-friendlypass="banner"]');
    return host?.shadowRoot?.activeElement?.getAttribute("data-action") ?? null;
  });
}

// ---------------------------------------------------------------------------
// Icon states
// ---------------------------------------------------------------------------

stackTest("icon states: matches, no matches, locked, app down", async ({ stack }) => {
  const matches = await openPage(stack, "/login-two");
  await expect(loginIcon(matches)).toHaveAttribute(
    "data-friendlypass-state",
    "matches",
    { timeout: 20_000 },
  );
  await shot(matches, "icon-matches");

  const empty = await openPage(stack, "/no-match");
  await expect(loginIcon(empty)).toHaveAttribute(
    "data-friendlypass-state",
    "empty",
    { timeout: 20_000 },
  );
  await expect(loginIcon(empty)).toHaveAttribute(
    "aria-label",
    /No saved login/,
  );
  await shot(empty, "icon-empty");

  await stack.harness.internalRequest("database.lock");
  await expect(matches.locator('[data-friendlypass="icon"]').first()).toHaveAttribute(
    "data-friendlypass-state",
    "locked",
    { timeout: 20_000 },
  );
  await shot(matches, "icon-locked");

  await stack.app.stop();
  await expect(matches.locator('[data-friendlypass="icon"]').first()).toHaveAttribute(
    "data-friendlypass-state",
    "hidden",
    { timeout: 20_000 },
  );
  await shot(matches, "icon-hidden");

  await expect(matches.locator('[data-friendlypass="icon"]').first()).toBeHidden();
});

stackTest("icon avoids the page's own password eye button", async ({ stack }) => {
  const page = await openPage(stack, "/eye");
  const icon = loginIcon(page);
  await expect(icon).toHaveAttribute("data-friendlypass-state", "matches", {
    timeout: 20_000,
  });
  const boxes = await page.evaluate(() => {
    const iconHost = document.querySelector<HTMLElement>(
      '[data-friendlypass="icon"]',
    );
    const eye = document.querySelector<HTMLElement>("#eye")?.getBoundingClientRect();
    const field = document
      .querySelector<HTMLElement>("#password")
      ?.getBoundingClientRect();
    const iconRect = iconHost?.getBoundingClientRect();
    return {
      iconRight: iconRect?.right ?? 0,
      eyeLeft: eye?.left ?? 0,
      fieldRight: field?.right ?? 0,
    };
  });
  expect(boxes.iconRight).toBeLessThan(boxes.eyeLeft);
  expect(boxes.iconRight).toBeGreaterThan(0);
  await shot(page, "icon-eye-offset");
});

// ---------------------------------------------------------------------------
// Inline menu
// ---------------------------------------------------------------------------

stackTest("menu lists logins and keyboard navigation fills", async ({ stack }) => {
  const page = await openPage(stack, "/login-two");
  await expect(loginIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "matches",
    { timeout: 20_000 },
  );
  await page.focus("#username");
  await invokeShortcut(stack.harness, "content.openInlineMenu");
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(1, {
    timeout: 10_000,
  });
  await expect(menuItems(page)).toHaveCount(2);
  await shot(page, "menu-list");

  // ↑/↓/Enter, no mouse.
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(page.locator("#username")).toHaveValue("bob@example.com");
  await expect(page.locator("#password")).toHaveValue("bob-password");
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(0);
});

stackTest("type-to-search filters the menu and Enter fills the match", async ({
  stack,
}) => {
  const page = await openPage(stack, "/login-two");
  const icon = loginIcon(page);
  await expect(icon).toHaveAttribute("data-friendlypass-state", "matches", {
    timeout: 20_000,
  });
  await icon.click();
  await expect(menuItems(page)).toHaveCount(2);
  const search = page.locator('[data-friendlypass="menu-search"]');
  await expect(search).toBeFocused();

  await page.keyboard.type("bob");
  await expect(menuItems(page)).toHaveCount(1);
  await expect(menuItems(page).first()).toContainText("bob@example.com");
  await shot(page, "menu-search");

  await page.keyboard.press("Enter");
  await expect(page.locator("#username")).toHaveValue("bob@example.com");
  await expect(page.locator("#password")).toHaveValue("bob-password");
});

stackTest("menu closes on Escape and on an outside click", async ({ stack }) => {
  const page = await openPage(stack, "/login-two");
  await expect(loginIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "matches",
    { timeout: 20_000 },
  );
  await loginIcon(page).click();
  await expect(menuItems(page)).toHaveCount(2);
  await page.keyboard.press("Escape");
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(0);

  await loginIcon(page).click();
  await expect(menuItems(page)).toHaveCount(2);
  await page.locator("h1").click();
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(0);
});

stackTest("menu flips above a field near the viewport bottom", async ({ stack }) => {
  const page = await openPage(stack, "/bottom");
  await expect(loginIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "matches",
    { timeout: 20_000 },
  );
  await loginIcon(page).click();
  await expect(menuItems(page)).toHaveCount(2);
  const menu = page.locator('[data-friendlypass="menu"]');
  await expect(menu).toHaveAttribute("data-friendlypass-placement", "above");
  const geometry = await page.evaluate(() => {
    const host = document.querySelector<HTMLElement>('[data-friendlypass="menu"]');
    const field = document.querySelector<HTMLElement>("#username");
    const menuRect = host?.getBoundingClientRect();
    const fieldRect = field?.getBoundingClientRect();
    return {
      menuBottom: menuRect?.bottom ?? 0,
      fieldTop: fieldRect?.top ?? 0,
      placement: host?.getAttribute("data-friendlypass-placement"),
    };
  });
  expect(geometry.placement).toBe("above");
  expect(geometry.menuBottom).toBeLessThanOrEqual(geometry.fieldTop + 1);
  await shot(page, "menu-flip-above");
});

stackTest("menu opens on empty field focus without stealing focus, and follows scroll", async ({
  stack,
}) => {
  const page = await openPage(stack, "/scroll");
  await expect(loginIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "matches",
    { timeout: 20_000 },
  );
  const before = await page.evaluate(() => {
    const icon = document
      .querySelector<HTMLElement>('[data-friendlypass="icon"]')
      ?.getBoundingClientRect();
    return { top: icon?.top ?? 0 };
  });

  // Focus an empty login field: the menu opens but focus stays in the field.
  await page.focus("#username");
  await expect(menuItems(page)).toHaveCount(2, { timeout: 10_000 });
  const focus = await page.evaluate(() => ({
    page: document.activeElement?.id ?? "",
    menu: document
      .querySelector('[data-friendlypass="menu"]')
      ?.shadowRoot?.activeElement?.tagName ?? "",
  }));
  expect(focus.page).toBe("username");
  expect(focus.menu).not.toBe("INPUT");
  await shot(page, "menu-focus-open");

  // Escape closes from the field without moving focus.
  await page.keyboard.press("Escape");
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(0);
  await expect(page.locator("#username")).toBeFocused();

  // Reposition on scroll: the icon follows the field.
  await page.evaluate(() => window.scrollTo(0, 40));
  await sleep(120);
  const after = await page.evaluate(() => {
    const icon = document
      .querySelector<HTMLElement>('[data-friendlypass="icon"]')
      ?.getBoundingClientRect();
    const field = document
      .querySelector<HTMLElement>("#username")
      ?.getBoundingClientRect();
    return { top: icon?.top ?? 0, fieldTop: field?.top ?? 0 };
  });
  expect(after.top).toBeLessThan(before.top);
  expect(Math.abs(after.top - (before.top - 40))).toBeLessThanOrEqual(2);
  expect(Math.abs(after.top - after.fieldTop)).toBeLessThanOrEqual(14);

  // Open the menu, then scroll the field out of view: it closes.
  await loginIcon(page).click();
  await expect(menuItems(page)).toHaveCount(2);
  await shot(page, "menu-scrolled");
  await page.evaluate(() => window.scrollTo(0, 1200));
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(0, {
    timeout: 5_000,
  });
});

stackTest("no menu matches offers Open friendlypass and opens the popup", async ({
  stack,
}) => {
  const page = await openPage(stack, "/no-match");
  await expect(loginIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "empty",
    { timeout: 20_000 },
  );
  await loginIcon(page).click();
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(1);
  await expect(page.locator('[data-friendlypass="menu"]')).toContainText(
    "No saved login for this page",
  );
  await expect(menuAction(page, "open-friendlypass")).toHaveCount(1);
  await shot(page, "menu-empty");
  await menuAction(page, "open-friendlypass").click();
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(0);

  // The content script asks the service worker; either the action popup opens
  // or the fallback window is created. Both are observable.
  await expect
    .poll(
      async () => {
        const current = await stack.harness.swEvaluate(async () => {
          const debug = (
            globalThis as unknown as {
              __friendlypassDebug?: {
                popupStats(): {
                  attempts: number;
                  action: number;
                  fallback: number;
                };
              };
            }
          ).__friendlypassDebug;
          return debug?.popupStats() ?? null;
        });
        return (current?.action ?? 0) + (current?.fallback ?? 0);
      },
      { timeout: 10_000 },
    )
    .toBeGreaterThan(0);

  const stats = await stack.harness.swEvaluate(async () => {
    const debug = (
      globalThis as unknown as {
        __friendlypassDebug?: {
          popupStats(): { attempts: number; action: number; fallback: number };
        };
      }
    ).__friendlypassDebug;
    return debug?.popupStats() ?? null;
  });
  expect(stats).not.toBeNull();
  expect(stats?.attempts ?? 0).toBeGreaterThan(0);

  if ((stats?.fallback ?? 0) > 0) {
    await expect
      .poll(
        () =>
          stack.harness.context
            .pages()
            .some((candidate) => candidate.url().includes("popup/popup.html")),
        { timeout: 10_000 },
      )
      .toBe(true);
  }
});

stackTest("locked icon opens the unlock menu", async ({ stack }) => {
  const page = await openPage(stack, "/login-two");
  await expect(loginIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "matches",
    { timeout: 20_000 },
  );
  await stack.harness.internalRequest("database.lock");
  await expect(loginIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "locked",
    { timeout: 20_000 },
  );
  await loginIcon(page).click();
  await expect(menuAction(page, "unlock")).toHaveCount(1);
  await expect(menuAction(page, "unlock")).toContainText(
    "Locked — unlock friendlypass",
  );
  await shot(page, "menu-locked");
});

stackTest("TOTP fields expose Fill TOTP in the menu", async ({ stack }) => {
  const page = await openPage(stack, "/totp-two");
  await expect(totpIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "matches",
    { timeout: 20_000 },
  );
  await totpIcon(page).click();
  await expect(menuAction(page, "fill-totp")).toHaveCount(1);
  await shot(page, "menu-totp");
  await menuAction(page, "fill-totp").click();
  await expect(page.locator("#totp")).toHaveValue("777777");
});

// ---------------------------------------------------------------------------
// Generate password
// ---------------------------------------------------------------------------

stackTest("generate password shortcut fills both fields and offers save", async ({
  stack,
}) => {
  const page = await openPage(stack, "/signup");
  await page.focus("#new-password");
  await invokeShortcut(stack.harness, "content.generatePassword");

  await expect(page.locator("#new-password")).not.toHaveValue("", {
    timeout: 10_000,
  });
  const generated = await page.locator("#new-password").inputValue();
  await expect(page.locator("#confirm-password")).toHaveValue(generated);
  expect(generated.length).toBeGreaterThan(8);

  const banner = page.locator('[data-friendlypass="banner"]');
  await expect(banner).toHaveCount(1, { timeout: 10_000 });
  await expect(banner).toHaveAttribute("data-friendlypass-kind", "create");
  await shot(page, "banner-create");

  await banner.locator('[data-action="save"]').click();
  await expect(banner).toHaveCount(0);
  await expect
    .poll(() => stack.app.entryFor("/signup")?.password, { timeout: 10_000 })
    .toBe(generated);
});

stackTest("menu offers Generate password on a signup field", async ({ stack }) => {
  const page = await openPage(stack, "/signup");
  await expect(loginIcon(page)).toHaveAttribute(
    "data-friendlypass-state",
    "empty",
    { timeout: 20_000 },
  );
  await loginIcon(page).click();
  await expect(menuAction(page, "generate-password")).toHaveCount(1);
  await shot(page, "menu-generate");
  await menuAction(page, "generate-password").click();
  await expect(page.locator("#new-password")).not.toHaveValue("");
  await expect(page.locator("#confirm-password")).toHaveValue(
    await page.locator("#new-password").inputValue(),
  );
});

// ---------------------------------------------------------------------------
// Save card
// ---------------------------------------------------------------------------

stackTest("save card is keyboard accessible and saves with Enter", async ({
  stack,
}) => {
  const page = await openPage(stack, "/save");
  await page.fill("#username", "keyboard@example.com");
  await page.fill("#password", "keyboard-password");
  await page.click("#submit");

  const banner = page.locator('[data-friendlypass="banner"]');
  await expect(banner).toHaveCount(1, { timeout: 10_000 });
  await expect
    .poll(() => focusedBannerAction(page), {
      timeout: 5_000,
    })
    .toBe("save");
  await shot(page, "banner-create-keyboard");

  await page.keyboard.press("Enter");
  await expect(banner).toHaveCount(0);
  await expect
    .poll(() => stack.app.entryFor("/save")?.login, { timeout: 10_000 })
    .toBe("keyboard@example.com");
});

stackTest("save card Escape dismisses without saving", async ({ stack }) => {
  const page = await openPage(stack, "/save");
  await page.fill("#username", "dismiss@example.com");
  await page.fill("#password", "dismiss-password");
  await page.click("#submit");

  const banner = page.locator('[data-friendlypass="banner"]');
  await expect(banner).toHaveCount(1, { timeout: 10_000 });
  await expect
    .poll(() => focusedBannerAction(page))
    .toBe("save");
  await page.keyboard.press("Escape");
  await expect(banner).toHaveCount(0);
  await sleep(600);
  expect(stack.app.entryFor("/save")).toBeUndefined();
});

stackTest("group picker appears when defaultGroupAlwaysAsk is on", async ({
  stack,
}) => {
  const page = await openPage(stack, "/save");
  await broadcastSettings(stack.harness, {
    defaultGroupAlwaysAsk: true,
    defaultGroup: "Work",
  });
  await sleep(150);
  await page.fill("#username", "group@example.com");
  await page.fill("#password", "group-password");
  await page.click("#submit");

  const banner = page.locator('[data-friendlypass="banner"]');
  await expect(banner).toHaveCount(1, { timeout: 10_000 });
  const group = banner.locator('[data-friendlypass="banner-group"]');
  await expect(group).toBeVisible();
  await expect(group.locator("option")).toHaveCount(4, { timeout: 10_000 });
  await group.selectOption({ label: "— Personal" });
  await shot(page, "banner-group");

  await banner.locator('[data-action="save"]').click();
  await expect(banner).toHaveCount(0);
  await expect
    .poll(() => stack.app.entryFor("/save")?.group, { timeout: 10_000 })
    .toBe("Personal");
});

stackTest("update card says Update for an existing username", async ({ stack }) => {
  // Re-use the login entry: submit a new password with its username.
  const page = await openPage(stack, "/login");
  await page.fill("#username", "alice@example.com");
  await page.fill("#password", "new-alice-password");
  await page.click("#submit");

  const banner = page.locator('[data-friendlypass="banner"]');
  await expect(banner).toHaveCount(1, { timeout: 10_000 });
  await expect(banner).toHaveAttribute("data-friendlypass-kind", "update");
  await expect(banner).toContainText("Update saved login?");
  await shot(page, "banner-update");
  await banner.locator('[data-action="save"]').click();
  await expect(banner).toHaveCount(0);
  await expect
    .poll(() => stack.app.entryFor("/login")?.password, { timeout: 10_000 })
    .toBe("new-alice-password");
});

// ---------------------------------------------------------------------------
// Settings, site exceptions and hostile CSS
// ---------------------------------------------------------------------------

stackTest("settings.changed hides and restores icons live", async ({ stack }) => {
  const page = await openPage(stack, "/login-two");
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

  await broadcastSettings(stack.harness, { showFieldIcons: false });
  await expect(loginIcon(page)).toHaveCount(0, { timeout: 10_000 });

  await broadcastSettings(stack.harness, { showFieldIcons: true });
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 10_000 });
});

stackTest("site exceptions disable icons, fill and save per origin", async ({
  stack,
}) => {
  const page = await openPage(stack, "/login-two");
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });
  const origin = new URL(page.url()).origin;

  await broadcastSettings(stack.harness, {
    siteExceptions: [{ origin, disableIcons: true }],
  });
  await expect(loginIcon(page)).toHaveCount(0, { timeout: 10_000 });

  await broadcastSettings(stack.harness, {
    siteExceptions: [{ origin, disableFill: true }],
  });
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 10_000 });
  await loginIcon(page).click();
  await expect(page.locator("#username")).toHaveValue("");
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(0);
  await expect(page.locator('[data-friendlypass="notification"]')).toContainText(
    "Filling is disabled for this site",
  );

  await broadcastSettings(stack.harness, {
    siteExceptions: [{ origin, disableSave: true }],
  });
  await page.fill("#username", "blocked@example.com");
  await page.fill("#password", "blocked-password");
  await page.click("#submit");
  await sleep(800);
  await expect(page.locator('[data-friendlypass="banner"]')).toHaveCount(0);
});

stackTest("hostile page CSS cannot break the icon or menu", async ({ stack }) => {
  const page = await openPage(stack, "/hostile");
  const icon = loginIcon(page);
  await expect(icon).toHaveAttribute("data-friendlypass-state", "matches", {
    timeout: 20_000,
  });
  const position = await page.evaluate(() => {
    const host = document.querySelector<HTMLElement>('[data-friendlypass="icon"]');
    const field = document.querySelector<HTMLElement>("#username");
    const hostRect = host?.getBoundingClientRect();
    const fieldRect = field?.getBoundingClientRect();
    return {
      display: host ? getComputedStyle(host).display : "none",
      position: host ? getComputedStyle(host).position : "none",
      inside:
        !!hostRect &&
        !!fieldRect &&
        hostRect.top >= fieldRect.top - 1 &&
        hostRect.bottom <= fieldRect.bottom + 1,
    };
  });
  expect(position.display).not.toBe("none");
  expect(position.position).toBe("fixed");
  expect(position.inside).toBe(true);

  await icon.click();
  await expect(menuItems(page)).toHaveCount(2);
  const menuVisible = await page.evaluate(() => {
    const host = document.querySelector<HTMLElement>('[data-friendlypass="menu"]');
    const rect = host?.getBoundingClientRect();
    return {
      display: host ? getComputedStyle(host).display : "none",
      position: host ? getComputedStyle(host).position : "none",
      width: rect?.width ?? 0,
      height: rect?.height ?? 0,
    };
  });
  expect(menuVisible.display).not.toBe("none");
  expect(menuVisible.position).toBe("fixed");
  expect(menuVisible.width).toBeGreaterThan(100);
  expect(menuVisible.height).toBeGreaterThan(40);
  await shot(page, "menu-hostile");
});

stackTest("search boxes never get an icon on a mixed page", async ({ stack }) => {
  const page = await openPage(stack, "/search-mixed");
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });
  const attachedToSearch = await page.evaluate(() => {
    const icons = Array.from(
      document.querySelectorAll<HTMLElement>('[data-friendlypass="icon"]'),
    );
    const search = document.querySelector<HTMLElement>("#search");
    if (!search) return false;
    const rect = search.getBoundingClientRect();
    return icons.some((icon) => {
      const other = icon.getBoundingClientRect();
      return (
        Math.abs(other.top - rect.top) < 6 &&
        Math.abs(other.right - rect.right) < 8
      );
    });
  });
  expect(attachedToSearch).toBe(false);
});

stackTest("all four WP6b shortcuts are registered", async ({ stack }) => {
  const commands = await stack.harness.swEvaluate(async () =>
    chrome.commands.getAll(),
  );
  const names = commands.map((command) => command.name);
  expect(names).toEqual(
    expect.arrayContaining([
      "fill-login",
      "open-inline-menu",
      "generate-password",
      "_execute_action",
    ]),
  );

  // Headless Chromium leaves suggested keys unresolved in `getAll()`, so
  // assert the shipped manifest carries a default/mac key for each command.
  const manifestCommands = await stack.harness.swEvaluate(async () => {
    const manifest = chrome.runtime.getManifest() as unknown as {
      commands?: Record<
        string,
        { suggested_key?: { default?: string; mac?: string } }
      >;
    };
    return manifest.commands ?? {};
  });
  for (const name of [
    "fill-login",
    "open-inline-menu",
    "generate-password",
    "_execute_action",
  ]) {
    expect(manifestCommands[name]?.suggested_key?.default, name).toBeTruthy();
    expect(manifestCommands[name]?.suggested_key?.mac, name).toBeTruthy();
  }

  // WP6c: Ctrl/Cmd+Shift+O belongs to Chrome's bookmark manager, so the popup
  // uses Alt/Option+Shift+F instead.
  expect(manifestCommands["_execute_action"]?.suggested_key).toEqual({
    default: "Alt+Shift+F",
    mac: "Alt+Shift+F",
  });
});
