/**
 * WP4 end-to-end fill tests.
 *
 * Real extension bundle + real native host. Two app backends are used:
 *
 *  - a small in-spec protocol app for pure fill/detection scenarios (fast and
 *    mutable, so a test can add a second login without rebuilding a database);
 *  - the REAL Rust protocol server (`examples/test_server.rs`) with a
 *    throwaway KDBX created by the `friendlypass` CLI for the save/update
 *    scenarios. Those tests reopen the file with the CLI and assert the
 *    persisted entry, so `set-login` is proven to reach disk.
 *
 * Chrome, the manifest, the content script, the service worker, the transport,
 * the native-messaging host and the protocol envelopes are the production
 * stack in both cases. Test pages are served from Node HTTP servers bound to
 * 127.0.0.1 on ephemeral ports, so database entries match the real page URLs.
 * No fixtures in `fixtures/` are modified and credentials never appear in
 * logs written by production code.
 */

import { expect, test as base } from "@playwright/test";
import type { Locator, Page } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import nacl from "tweetnacl";
import { Harness } from "../harness/harness";
import { shotsDir } from "../harness/shots";
import { REPO_ROOT } from "../harness/app-mock";
import type { RustApp } from "../harness/rust-app";
import {
  ObjectStreamDecoder,
  encodeObject,
  incrementNonce,
  sleep,
} from "../harness/frames.mjs";

// ---------------------------------------------------------------------------
// Test database app
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
const ASSOCIATION_ID = "chrome-work-laptop";

function fromB64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

function toB64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64");
}

function stringField(record: Record<string, unknown>, key: string): string | undefined {
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

class FixtureApp {
  readonly socketPath: string;
  readonly entries: DbEntry[];
  connectionCount = 0;

  private server: net.Server | null = null;
  private readonly sockets = new Set<net.Socket>();
  private readonly sessions = new WeakMap<net.Socket, AppSession>();

  constructor(socketPath: string, entries: DbEntry[]) {
    this.socketPath = socketPath;
    this.entries = entries.map((entry) => ({ ...entry }));
  }

  get currentConnections(): number {
    return this.sockets.size;
  }

  addEntry(entry: DbEntry): void {
    this.entries.push({ ...entry });
  }

  async start(): Promise<void> {
    fs.mkdirSync(requireDirname(this.socketPath), { recursive: true });
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

    if (action === "ping" || action === "hello") {
      this.write(socket, {
        action,
        success: "true",
        protocolVersion: 1,
        hostVersion: "0.0.0-wp4-test",
        appRunning: true,
        appVersion: "0.0.0-wp4-test",
        locked: false,
        databaseHash: DB_HASH,
        ...(action === "ping" && nonce ? { nonce } : {}),
        ...(action === "hello" ? { sessionId: "wp4-test", hostPid: process.pid } : {}),
      });
      return;
    }

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
        // Test double: the extension's identity key is dynamic, so accept the
        // stored association rather than replaying the fixture key.
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
        const url = stringField(inner, "url") ?? "";
        if (!url) {
          this.error(socket, action, 14, "No URL provided");
          return;
        }
        const login = stringField(inner, "login") ?? "";
        const password = stringField(inner, "password") ?? "";
        const uuid = stringField(inner, "uuid");
        const existing = uuid
          ? this.entries.find((entry) => entry.uuid === uuid)
          : this.entries.find((entry) => entry.login === login && entry.url === url);
        if (existing) {
          existing.login = login;
          existing.password = password;
          existing.url = url;
        } else {
          this.entries.push({
            login,
            password,
            name: login || "Saved login",
            uuid: newUuid(),
            group: "KeePassXC-Browser Passwords",
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
        const uuid = stringField(inner, "uuid") ?? "";
        const entry = this.entries.find((candidate) => candidate.uuid === uuid);
        this.reply(socket, action, requestNonce, { totp: entry?.totp ?? "" });
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
                    name: "KeePassXC-Browser Passwords",
                    uuid: "d5ec68c35705b72fde380bd469aa149f",
                    children: [],
                  },
                ],
              },
            ],
          },
        });
        return;

      case "lock-database":
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

function requireDirname(file: string): string {
  const index = file.lastIndexOf("/");
  return index > 0 ? file.slice(0, index) : ".";
}

// ---------------------------------------------------------------------------
// Local test pages
// ---------------------------------------------------------------------------

const LOGIN_FORM = `<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>
<body>
<h1>Sign in</h1>
<form id="login-form" action="/login" method="post">
  <label>Username <input id="username" name="username" type="text" autocomplete="username"></label>
  <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
  <button id="submit" type="submit">Log in</button>
</form>
</body></html>`;

function plainPage(title: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>
<body><h1>${title}</h1></body></html>`;
}

function rustLoginPage(action: string, title: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>
<body>
<h1>${title}</h1>
<form id="login-form" action="${action}" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button id="submit" type="submit">Log in</button>
</form>
</body></html>`;
}

const PAGES: Record<string, string> = {
  "/login": LOGIN_FORM,
  "/two-step": `<!doctype html><html><head><meta charset="utf-8"><title>Two step</title></head>
<body>
<h1>Sign in</h1>
<form id="login-form" action="/two-step" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <button id="next" type="button">Next</button>
</form>
<script>
  document.getElementById('next').addEventListener('click', () => {
    const form = document.getElementById('login-form');
    form.innerHTML =
      '<input id="password" name="password" type="password" autocomplete="current-password">' +
      '<button type="submit">Sign in</button>';
  });
</script>
</body></html>`,
  "/spa": `<!doctype html><html><head><meta charset="utf-8"><title>SPA</title></head>
<body>
<h1>Single page app</h1>
<div id="root">Loading…</div>
<script>
  setTimeout(() => {
    document.getElementById('root').innerHTML =
      '<form id="login-form" action="/spa" method="post">' +
      '<input id="username" name="username" type="text" autocomplete="username">' +
      '<input id="password" name="password" type="password">' +
      '<button type="submit">Log in</button></form>';
  }, 400);
</script>
</body></html>`,
  "/iframe": `<!doctype html><html><head><meta charset="utf-8"><title>Iframe</title></head>
<body>
<h1>Outer page</h1>
<iframe id="login-frame" src="/iframe-inner" style="width:480px;height:220px;border:1px solid #ccc"></iframe>
</body></html>`,
  "/iframe-inner": `<!doctype html><html><head><meta charset="utf-8"><title>Login frame</title></head>
<body>
<form id="login-form" action="/iframe-inner" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button id="submit" type="submit">Log in</button>
</form>
</body></html>`,
  "/shadow": `<!doctype html><html><head><meta charset="utf-8"><title>Shadow DOM</title></head>
<body>
<h1>Shadow DOM form</h1>
<div id="host"></div>
<script>
  const root = document.getElementById('host').attachShadow({ mode: 'open' });
  root.innerHTML =
    '<form id="login-form" action="/shadow" method="post">' +
    '<input id="username" name="username" type="text" autocomplete="username">' +
    '<input id="password" name="password" type="password">' +
    '<button type="submit">Log in</button></form>';
</script>
</body></html>`,
  "/search": `<!doctype html><html><head><meta charset="utf-8"><title>Search</title></head>
<body>
<h1>Search only</h1>
<form action="/search" role="search">
  <input type="search" name="q" placeholder="Search">
  <button type="submit">Search</button>
</form>
<input id="maybe-username" type="text" name="maybeUsername" placeholder="search" autocomplete="username">
</body></html>`,
  "/save": `<!doctype html><html><head><meta charset="utf-8"><title>Create account</title></head>
<body>
<h1>Create account</h1>
<form id="signup-form" action="/save" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="new-password">
  <button id="submit" type="submit">Create account</button>
</form>
<div id="result"></div>
<script>
  document.getElementById('signup-form').addEventListener('submit', (event) => {
    event.preventDefault();
    document.getElementById('result').textContent = 'Submitted';
  });
</script>
</body></html>`,
  "/save-update": `<!doctype html><html><head><meta charset="utf-8"><title>Change password</title></head>
<body>
<h1>Change password</h1>
<form id="change-form" action="/save-update" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="new-password">
  <button id="submit" type="submit">Change password</button>
</form>
<div id="result"></div>
<script>
  document.getElementById('change-form').addEventListener('submit', (event) => {
    event.preventDefault();
    document.getElementById('result').textContent = 'Changed';
  });
</script>
</body></html>`,
  "/totp": `<!doctype html><html><head><meta charset="utf-8"><title>TOTP</title></head>
<body>
<h1>Two-factor</h1>
<form id="totp-form" action="/totp" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password">
  <input id="totp" name="totp" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="6-digit code">
  <button type="submit">Verify</button>
</form>
</body></html>`,
  // -- real-server save/update pages (WP4b) ---------------------------------
  "/rust-save": rustLoginPage("/rust-save", "Save login"),
  "/rust-save-home": plainPage("Signed in"),
  "/rust-update": rustLoginPage("/rust-update", "Change password"),
  "/rust-update-home": plainPage("Password changed"),
  "/rust-signup": `<!doctype html><html><head><meta charset="utf-8"><title>Create account</title></head>
<body>
<h1>Create account</h1>
<form id="signup-form" action="/rust-signup" method="post">
  <input id="email" name="email" type="email" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="new-password">
  <button id="submit" type="submit">Create account</button>
</form>
</body></html>`,
  "/rust-signup-home": plainPage("Account created"),
  "/rust-match": rustLoginPage("/rust-match", "Already saved"),
  "/rust-match-home": plainPage("Welcome back"),
  "/rust-expiry": rustLoginPage("/rust-expiry", "Slow redirect"),
  "/rust-expiry-home": plainPage("Expired offer"),
  "/rust-different": rustLoginPage("/rust-different", "Cross-site redirect"),
  "/rust-other": plainPage("Other site"),
  // A JS "login" that never fires a submit event: XHR, then location.href.
  "/rust-js": `<!doctype html><html><head><meta charset="utf-8"><title>JS login</title></head>
<body>
<h1>JS login</h1>
<form id="login-form">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button id="submit" type="button">Log in</button>
</form>
<script>
  document.getElementById('submit').addEventListener('click', async () => {
    await fetch('/rust-js-step', { method: 'POST' });
    location.href = '/rust-js-home';
  });
</script>
</body></html>`,
  "/rust-js-home": plainPage("JS signed in"),
};

interface PagesServer {
  baseUrl: string;
  close(): Promise<void>;
}

/**
 * Destination of the throwaway Rust-server DB: a second pages server on a
 * different loopback port, i.e. a genuinely different site for the
 * cross-site suppression check.
 */
let crossSiteBaseUrl = "";

/** Long enough for a shortened pending TTL to expire before the redirect. */
const EXPIRY_REDIRECT_DELAY_MS = 1_400;

async function startPages(): Promise<PagesServer> {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");

    if (request.method === "POST") {
      request.resume();
      if (url.pathname === "/rust-js-step") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"ok":true}');
        return;
      }
      const destinations: Record<string, string> = {
        "/rust-save": "/rust-save-home",
        "/rust-update": "/rust-update-home",
        "/rust-signup": "/rust-signup-home",
        "/rust-match": "/rust-match-home",
        "/rust-expiry": "/rust-expiry-home",
        "/rust-different": crossSiteBaseUrl
          ? `${crossSiteBaseUrl}/rust-other`
          : "/rust-other",
      };
      const destination = destinations[url.pathname];
      if (!destination) {
        response.writeHead(404, { "content-type": "text/plain" });
        response.end("not found");
        return;
      }
      const redirect = (): void => {
        response.writeHead(302, { location: destination });
        response.end();
      };
      if (url.pathname === "/rust-expiry") {
        setTimeout(redirect, EXPIRY_REDIRECT_DELAY_MS);
      } else {
        redirect();
      }
      return;
    }

    const html = PAGES[url.pathname];
    if (!html) {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("not found");
      return;
    }
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(html);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const address = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
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

function baseEntries(baseUrl: string): DbEntry[] {
  const entry = (
    path: string,
    login: string,
    password: string,
    extra: Partial<DbEntry> = {},
  ): DbEntry => ({
    login,
    password,
    name: `WP4 ${path}`,
    uuid: newUuid(),
    group: "KeePassXC-Browser Passwords",
    url: `${baseUrl}${path}`,
    ...extra,
  });

  return [
    entry("/login", "alice@example.com", "correct horse battery staple"),
    entry("/two-step", "two-step@example.com", "two-step-password"),
    entry("/spa", "spa@example.com", "spa-password"),
    entry("/iframe-inner", "frame@example.com", "frame-password"),
    entry("/shadow", "shadow@example.com", "shadow-password"),
    entry("/totp", "totp@example.com", "totp-password", { totp: "777777" }),
  ];
}

async function waitFor(condition: () => boolean, timeoutMs: number, label: string): Promise<void> {
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
    // Replace the Phase-1 app mock with the mutable test database. The real
    // host keeps running and reconnects to the same socket path.
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

// ---------------------------------------------------------------------------
// Real Rust protocol server with a throwaway KDBX (WP4b save tests)
// ---------------------------------------------------------------------------

interface RustStack {
  harness: Harness;
  rust: RustApp;
  baseUrl: string;
}

interface StatusLike {
  appRunning: boolean;
  state: string;
  associated: boolean;
  databaseHash: string | null;
}

interface AssociationLike {
  id: string;
  hash: string;
}

/** Matches `test_server`'s default (`FP_TEST_DB_PASSWORD` unset). */
const TEST_DB_PASSWORD = "testpassword";

const WP6C_SHOTS = shotsDir("wp6c-polish");

async function captureViewport(page: Page, name: string): Promise<void> {
  await page.emulateMedia({ colorScheme: "light" });
  await sleep(80);
  await page.screenshot({
    path: path.join(WP6C_SHOTS, `${name}-light.png`),
    animations: "disabled",
  });
  await page.emulateMedia({ colorScheme: "dark" });
  await sleep(80);
  await page.screenshot({
    path: path.join(WP6C_SHOTS, `${name}-dark.png`),
    animations: "disabled",
  });
  await page.emulateMedia({ colorScheme: "light" });
}

async function captureLocator(
  page: Page,
  locator: Locator,
  name: string,
): Promise<void> {
  await page.emulateMedia({ colorScheme: "light" });
  await sleep(80);
  await locator.screenshot({
    path: path.join(WP6C_SHOTS, `${name}-light.png`),
    animations: "disabled",
  });
  await page.emulateMedia({ colorScheme: "dark" });
  await sleep(80);
  await locator.screenshot({
    path: path.join(WP6C_SHOTS, `${name}-dark.png`),
    animations: "disabled",
  });
  await page.emulateMedia({ colorScheme: "light" });
}

let rustPages: PagesServer;
let otherPages: PagesServer;
let rustTempRoot = "";
let pristineRustDb = "";

function binaryPath(name: string): string {
  return path.join(REPO_ROOT, "target/debug", name);
}

function ensureBinary(target: string, args: string[]): void {
  if (fs.existsSync(target)) return;
  const result = spawnSync("cargo", args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    timeout: 300_000,
  });
  if (result.status !== 0) {
    throw new Error(
      `failed to build ${target}:\n${result.stderr ?? result.stdout ?? ""}`,
    );
  }
}

function runCli(args: string[], input: string): void {
  const result = spawnSync(binaryPath("friendlypass"), args, {
    encoding: "utf8",
    input,
    timeout: 120_000,
  });
  if (result.status !== 0) {
    throw new Error(
      `friendlypass ${args.join(" ")} failed:\n${result.stderr ?? ""}`,
    );
  }
}

/**
 * Pristine KDBX for the save tests. The two seeded entries are what the
 * update/no-banner scenarios match; the save pages have no entry.
 */
function createRustDatabase(dbPath: string, baseUrl: string): void {
  fs.rmSync(dbPath, { force: true });
  runCli(
    ["db-create", "-p", dbPath],
    `${TEST_DB_PASSWORD}\n${TEST_DB_PASSWORD}\n`,
  );
  const entries = [
    {
      title: "Existing update",
      username: "update@example.com",
      password: "old-password",
      url: `${baseUrl}/rust-update`,
    },
    {
      title: "Existing match",
      username: "match@example.com",
      password: "match-password",
      url: `${baseUrl}/rust-match`,
    },
  ];
  for (const entry of entries) {
    runCli(
      [
        "add",
        "-p",
        dbPath,
        entry.title,
        "-u",
        entry.username,
        "-U",
        entry.url,
      ],
      `${TEST_DB_PASSWORD}\n${entry.password}\n`,
    );
  }
}

/**
 * Reopen the KDBX with the friendlypass CLI, exactly as another process would.
 * Returns `null` while the entry is not there yet (used with `expect.poll`).
 */
function readEntryViaCli(
  dbPath: string,
  title: string,
): Record<string, string> | null {
  const result = spawnSync(binaryPath("friendlypass"), ["show", dbPath, title], {
    encoding: "utf8",
    input: `${TEST_DB_PASSWORD}\n`,
    timeout: 30_000,
  });
  if (result.status !== 0) {
    return null;
  }
  const entry: Record<string, string> = {};
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = /^(Title|UserName|Password|URL):\s*(.*)$/.exec(line);
    if (match) {
      entry[match[1]] = match[2];
    }
  }
  return Object.keys(entry).length > 0 ? entry : null;
}

/** Shorten the pending store TTL for the expiry test (test-only setting). */
async function setPendingTtl(harness: Harness, ttlMs: number): Promise<void> {
  const worker = await harness.currentServiceWorker();
  await worker.evaluate(async (value) => {
    await chrome.storage.local.set({
      "friendlypass.pending.settings.v1": { ttlMs: value },
    });
  }, ttlMs);
}

async function status(harness: Harness): Promise<StatusLike> {
  return (await harness.internalRequest("status.get")) as StatusLike;
}

async function prepareRust(harness: Harness): Promise<void> {
  const rust = harness.rustApp();
  await rust.stop();
  fs.copyFileSync(pristineRustDb, rust.databasePath);
  fs.rmSync(rust.associationsPath, { force: true });
  await rust.start();

  // The database hash changed; rebuild the session and associate explicitly.
  await harness.internalRequest("connection.reconnect").catch(() => undefined);
  await expect
    .poll(async () => (await status(harness)).appRunning, { timeout: 15_000 })
    .toBe(true);

  let lastError: unknown = null;
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const association = (await harness.internalRequest(
        "association.create",
      )) as AssociationLike;
      if (association.id.length > 0 && /^[0-9a-f]{64}$/.test(association.hash)) {
        return;
      }
    } catch (cause) {
      lastError = cause;
    }
    await sleep(150);
  }
  throw new Error(`could not associate the test database: ${String(lastError)}`);
}

const test = base.extend<{ stack: Stack; rust: RustStack }>({
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

  rust: async ({}, use) => {
    const harness = await Harness.start({ hostMode: "real", appMode: "rust" });
    try {
      await prepareRust(harness);
      await use({ harness, rust: harness.rustApp(), baseUrl: rustPages.baseUrl });
    } finally {
      await harness.close().catch(() => undefined);
    }
  },
});

test.beforeAll(async () => {
  test.setTimeout(300_000);
  fs.mkdirSync(WP6C_SHOTS, { recursive: true });
  ensureBinary(binaryPath("friendlypass"), ["build", "-q", "-p", "friendlypass"]);
  ensureBinary(binaryPath("friendlypass-browser-host"), [
    "build",
    "-q",
    "-p",
    "friendlypass-browser-host",
  ]);
  ensureBinary(path.join(REPO_ROOT, "target/debug/examples/test_server"), [
    "build",
    "-q",
    "-p",
    "friendlypass-browser",
    "--example",
    "test_server",
  ]);

  rustPages = await startPages();
  otherPages = await startPages();
  crossSiteBaseUrl = otherPages.baseUrl;
  rustTempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fp-wp4b-save-"));
  pristineRustDb = path.join(rustTempRoot, "save.kdbx");
  createRustDatabase(pristineRustDb, rustPages.baseUrl);
});

test.afterAll(async () => {
  await rustPages?.close().catch(() => undefined);
  await otherPages?.close().catch(() => undefined);
  if (rustTempRoot) {
    fs.rmSync(rustTempRoot, { recursive: true, force: true });
  }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("classic login form: icon fills username and password once", async ({ stack }) => {
  // The manifest shortcut is registered even though browser-level key presses
  // cannot be simulated reliably in headless Chromium.
  const commands = await stack.harness.swEvaluate(async () =>
    chrome.commands.getAll(),
  );
  expect(commands.some((command) => command.name === "fill-login")).toBe(true);

  const page = await openPage(stack, "/login");
  const icon = loginIcon(page);
  await expect(icon).toHaveCount(1, { timeout: 20_000 });

  await icon.click();
  await expect(page.locator("#username")).toHaveValue("alice@example.com");
  await expect(page.locator("#password")).toHaveValue("correct horse battery staple");

  // A DOM mutation must not duplicate the icon.
  await page.evaluate(() => {
    const extra = document.createElement("div");
    extra.id = "late-banner";
    extra.textContent = "late";
    document.body.append(extra);
  });
  await sleep(400);
  await expect(icon).toHaveCount(1);
});

test("auto-fill single entry is off by default and can be enabled", async ({ stack }) => {
  const first = await openPage(stack, "/login");
  await expect(loginIcon(first)).toHaveCount(1, { timeout: 20_000 });
  await sleep(500);
  // Default off: nothing is written before the user clicks the icon.
  await expect(first.locator("#username")).toHaveValue("");

  await stack.harness.swEvaluate(async () => {
    await chrome.storage.local.set({
      "friendlypass.content.settings.v1": {
        autoFillSingleEntry: true,
        showIcons: true,
      },
    });
  });

  const second = await openPage(stack, "/login");
  await expect(second.locator("#username")).toHaveValue("alice@example.com", {
    timeout: 20_000,
  });
  await expect(second.locator("#password")).toHaveValue(
    "correct horse battery staple",
  );
});

test("dropdown lists every matching login and fills the picked one", async ({ stack }) => {
  stack.app.addEntry({
    login: "bob@example.com",
    password: "bob-password",
    name: "WP4 second login",
    uuid: newUuid(),
    group: "KeePassXC-Browser Passwords",
    url: `${stack.pages.baseUrl}/login`,
  });

  const page = await openPage(stack, "/login");
  const icon = loginIcon(page);
  await expect(icon).toHaveCount(1, { timeout: 20_000 });
  await icon.click();

  const items = page.locator('[data-friendlypass="menu-item"]');
  await expect(items).toHaveCount(2, { timeout: 10_000 });
  await items.nth(1).click();

  await expect(page.locator("#username")).toHaveValue("bob@example.com");
  await expect(page.locator("#password")).toHaveValue("bob-password");
});

test("two-step username then password", async ({ stack }) => {
  const page = await openPage(stack, "/two-step");

  await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });
  await loginIcon(page).click();
  await expect(page.locator("#username")).toHaveValue("two-step@example.com");

  await page.click("#next");
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 10_000 });
  await loginIcon(page).click();
  await expect(page.locator("#password")).toHaveValue("two-step-password");
});

test("SPA renders the form after load", async ({ stack }) => {
  const page = await openPage(stack, "/spa");
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });
  await loginIcon(page).click();

  await expect(page.locator("#username")).toHaveValue("spa@example.com");
  await expect(page.locator("#password")).toHaveValue("spa-password");
});

test("form inside an iframe is filled from its own frame", async ({ stack }) => {
  const page = await openPage(stack, "/iframe");
  const frame = page.frameLocator("#login-frame");

  await expect(frame.locator('[data-friendlypass="icon"]')).toHaveCount(1, {
    timeout: 20_000,
  });
  await frame.locator('[data-friendlypass="icon"]').click();

  await expect(frame.locator("#username")).toHaveValue("frame@example.com");
  await expect(frame.locator("#password")).toHaveValue("frame-password");
});

test("form inside an open shadow root is filled", async ({ stack }) => {
  const page = await openPage(stack, "/shadow");
  const icon = loginIcon(page);
  await expect(icon).toHaveCount(1, { timeout: 20_000 });
  await icon.click();

  await expect(page.locator('#host input[name="username"]')).toHaveValue(
    "shadow@example.com",
  );
  await expect(page.locator('#host input[name="password"]')).toHaveValue(
    "shadow-password",
  );
});

test("search boxes never get an icon", async ({ stack }) => {
  const page = await openPage(stack, "/search");
  await sleep(2_000);
  await expect(page.locator('[data-friendlypass="icon"]')).toHaveCount(0);
  await expect(page.locator('[data-friendlypass="menu"]')).toHaveCount(0);
});

test("save banner survives a form-submit navigation and stores the login on disk", async ({
  rust,
}) => {
  const page = await rust.harness.context.newPage();
  try {
    await page.goto(`${rust.baseUrl}/rust-save`, { waitUntil: "load" });
    await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

    await page.fill("#username", "nav-save@example.com");
    await page.fill("#password", "nav-save-password");
    await page.click("#submit");
    await page.waitForURL("**/rust-save-home");
    expect(page.url()).toContain("/rust-save-home");

    const banner = page.locator('[data-friendlypass="banner"]');
    await expect(banner).toHaveCount(1, { timeout: 10_000 });
    await expect(banner).toHaveAttribute("data-friendlypass-kind", "create");
    await banner.locator('[data-action="save"]').click();
    await expect(banner).toHaveCount(0);

    // Reopen the KDBX with the CLI: the save must be on disk, not just in the
    // server process.
    const title = new URL(`${rust.baseUrl}/rust-save`).host;
    await expect
      .poll(() => readEntryViaCli(rust.rust.databasePath, title), {
        timeout: 10_000,
      })
      .not.toBeNull();
    const entry = readEntryViaCli(rust.rust.databasePath, title);
    expect(entry?.UserName).toBe("nav-save@example.com");
    expect(entry?.Password).toBe("nav-save-password");
    expect(entry?.URL).toBe(`${rust.baseUrl}/rust-save`);

    await expect
      .poll(
        async () => {
          try {
            const saved = (await rust.harness.internalRequest("logins.get", {
              url: `${rust.baseUrl}/rust-save`,
            })) as Array<{ login: string }>;
            return saved.some((item) => item.login === "nav-save@example.com");
          } catch {
            return false;
          }
        },
        { timeout: 10_000 },
      )
      .toBe(true);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("save banner survives JS navigation after an XHR (no submit event)", async ({
  rust,
}) => {
  const page = await rust.harness.context.newPage();
  try {
    await page.goto(`${rust.baseUrl}/rust-js`, { waitUntil: "load" });
    await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

    await page.fill("#username", "xhr-save@example.com");
    await page.fill("#password", "xhr-save-password");
    await page.click("#submit");
    await page.waitForURL("**/rust-js-home");

    const banner = page.locator('[data-friendlypass="banner"]');
    await expect(banner).toHaveCount(1, { timeout: 10_000 });
    await banner.locator('[data-action="save"]').click();
    await expect(banner).toHaveCount(0);

    const title = new URL(`${rust.baseUrl}/rust-js`).host;
    await expect
      .poll(() => readEntryViaCli(rust.rust.databasePath, title), {
        timeout: 10_000,
      })
      .not.toBeNull();
    const entry = readEntryViaCli(rust.rust.databasePath, title);
    expect(entry?.UserName).toBe("xhr-save@example.com");
    expect(entry?.Password).toBe("xhr-save-password");
    expect(entry?.URL).toBe(`${rust.baseUrl}/rust-js`);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("update banner changes the existing entry's password in the KDBX", async ({
  rust,
}) => {
  const page = await rust.harness.context.newPage();
  try {
    await page.goto(`${rust.baseUrl}/rust-update`, { waitUntil: "load" });
    await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

    await page.fill("#username", "update@example.com");
    await page.fill("#password", "new-password");
    await page.click("#submit");
    await page.waitForURL("**/rust-update-home");

    const banner = page.locator('[data-friendlypass="banner"]');
    await expect(banner).toHaveCount(1, { timeout: 10_000 });
    await expect(banner).toHaveAttribute("data-friendlypass-kind", "update");
    await banner.locator('[data-action="save"]').click();
    await expect(banner).toHaveCount(0);

    await expect
      .poll(() => readEntryViaCli(rust.rust.databasePath, "Existing update"), {
        timeout: 10_000,
      })
      .not.toBeNull();
    const entry = readEntryViaCli(rust.rust.databasePath, "Existing update");
    expect(entry?.UserName).toBe("update@example.com");
    expect(entry?.Password).toBe("new-password");
    expect(entry?.URL).toBe(`${rust.baseUrl}/rust-update`);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("generated signup password saves the username typed in the banner", async ({
  rust,
}) => {
  const page = await rust.harness.context.newPage();
  try {
    await page.goto(`${rust.baseUrl}/rust-signup`, { waitUntil: "load" });
    await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

    // Generate through the real inline menu; the username field is left empty.
    await loginIcon(page).click();
    const generate = page.locator(
      '[data-friendlypass="menu-action"][data-action="generate-password"]',
    );
    await expect(generate).toHaveCount(1, { timeout: 10_000 });
    await generate.click();

    await expect(page.locator("#password")).not.toHaveValue("", {
      timeout: 10_000,
    });
    const password = await page.locator("#password").inputValue();
    expect(password.length).toBeGreaterThan(8);

    const banner = page.locator('[data-friendlypass="banner"]');
    await expect(banner).toHaveCount(1, { timeout: 10_000 });
    await expect(banner).toHaveAttribute("data-friendlypass-kind", "create");

    const title = banner.locator('[data-friendlypass="banner-title"]');
    const username = banner.locator('[data-friendlypass="banner-username"]');
    await expect(title).toHaveValue(new URL(rust.baseUrl).host);
    await expect(username).toHaveValue("");
    await expect(username).toHaveAttribute("placeholder", "Username (optional)");

    await title.fill("My generated signup");
    await username.fill("typed-in-banner@example.com");
    await captureViewport(page, "banner-editable");
    await banner.locator('[data-action="save"]').click();
    await expect(banner).toHaveCount(0);

    const entryTitle = "My generated signup";
    await expect
      .poll(() => readEntryViaCli(rust.rust.databasePath, entryTitle), {
        timeout: 10_000,
      })
      .not.toBeNull();
    const entry = readEntryViaCli(rust.rust.databasePath, entryTitle);
    expect(entry?.Title).toBe(entryTitle);
    expect(entry?.UserName).toBe("typed-in-banner@example.com");
    expect(entry?.Password).toBe(password);
    expect(entry?.URL).toBe(`${rust.baseUrl}/rust-signup`);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("Never for this site persists, hides the banner and is removable in options", async ({
  stack,
}) => {
  const { harness } = stack;
  const origin = new URL(stack.pages.baseUrl).origin;
  const submit = async (page: Page, username: string): Promise<void> => {
    await page.fill("#username", username);
    await page.fill("#password", "never-password");
    await page.click("#submit");
  };

  const page = await openPage(stack, "/save");
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

  await submit(page, "never-one@example.com");
  const banner = page.locator('[data-friendlypass="banner"]');
  await expect(banner).toHaveCount(1, { timeout: 10_000 });
  await banner.locator('[data-action="never"]').click();
  await expect(banner).toHaveCount(0);

  // Persisted through settings.set, merged as a disableSave exception.
  await expect
    .poll(
      async () =>
        (
          (await harness.internalRequest("settings.get")) as {
            siteExceptions: Array<{
              origin: string;
              disableSave?: boolean;
            }>;
          }
        ).siteExceptions,
      { timeout: 10_000 },
    )
    .toEqual([{ origin, disableSave: true }]);

  // Same page: the live settings broadcast stops the next offer.
  await submit(page, "never-two@example.com");
  await sleep(700);
  await expect(banner).toHaveCount(0);

  // After navigation the content script reads the persisted exception.
  await page.reload({ waitUntil: "load" });
  await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });
  await submit(page, "never-three@example.com");
  await sleep(700);
  await expect(page.locator('[data-friendlypass="banner"]')).toHaveCount(0);

  // And after a full extension restart, because it lives in chrome.storage.
  await harness.reloadExtension();
  const afterRestart = await openPage(stack, "/save");
  await expect(loginIcon(afterRestart)).toHaveCount(1, { timeout: 20_000 });
  await submit(afterRestart, "never-four@example.com");
  await sleep(700);
  await expect(afterRestart.locator('[data-friendlypass="banner"]')).toHaveCount(0);

  // The entry is visible in options, can be screenshotted and removed there.
  const options = await harness.context.newPage();
  await options.setViewportSize({ width: 900, height: 1_240 });
  await options.goto(
    `chrome-extension://${harness.extensionId}/options/options.html`,
    { waitUntil: "load" },
  );
  const row = options.locator(`tr[data-origin="${origin}"]`);
  await expect(row).toHaveCount(1, { timeout: 15_000 });
  await expect(row.locator('[data-exception-toggle="disableSave"]')).toBeChecked();
  await captureLocator(
    options,
    options.locator("#exceptions-section"),
    "options-site-exceptions-never",
  );

  await row.locator('[data-action="remove-exception"]').click();
  await expect
    .poll(
      async () =>
        (
          (await harness.internalRequest("settings.get")) as {
            siteExceptions: unknown[];
          }
        ).siteExceptions,
      { timeout: 10_000 },
    )
    .toEqual([]);

  // Removing it brings the save offer back.
  const restored = await openPage(stack, "/save");
  await expect(loginIcon(restored)).toHaveCount(1, { timeout: 20_000 });
  await submit(restored, "never-five@example.com");
  await expect(restored.locator('[data-friendlypass="banner"]')).toHaveCount(1, {
    timeout: 10_000,
  });

  await options.close();
  await restored.close();
  await page.close();
  await afterRestart.close();
});

test("no save banner after navigating to a different site", async ({ rust }) => {
  const page = await rust.harness.context.newPage();
  try {
    await page.goto(`${rust.baseUrl}/rust-different`, { waitUntil: "load" });
    await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

    await page.fill("#username", "cross-site@example.com");
    await page.fill("#password", "cross-site-password");
    await page.click("#submit");
    await page.waitForURL("**/rust-other");
    expect(new URL(page.url()).port).not.toBe(new URL(rust.baseUrl).port);

    await sleep(1_000);
    await expect(page.locator('[data-friendlypass="banner"]')).toHaveCount(0);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("no save banner when the submitted credentials already match", async ({
  rust,
}) => {
  const page = await rust.harness.context.newPage();
  try {
    await page.goto(`${rust.baseUrl}/rust-match`, { waitUntil: "load" });
    await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

    await page.fill("#username", "match@example.com");
    await page.fill("#password", "match-password");
    await page.click("#submit");
    await page.waitForURL("**/rust-match-home");

    await sleep(1_000);
    await expect(page.locator('[data-friendlypass="banner"]')).toHaveCount(0);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("pending save banner expires before the next page loads", async ({ rust }) => {
  await setPendingTtl(rust.harness, 700);
  const page = await rust.harness.context.newPage();
  try {
    await page.goto(`${rust.baseUrl}/rust-expiry`, { waitUntil: "load" });
    await expect(loginIcon(page)).toHaveCount(1, { timeout: 20_000 });

    await page.fill("#username", "expired@example.com");
    await page.fill("#password", "expired-password");
    await page.click("#submit");
    // The server holds the redirect for 1.4 s, longer than the 700 ms TTL.
    await page.waitForURL("**/rust-expiry-home");

    await sleep(500);
    await expect(page.locator('[data-friendlypass="banner"]')).toHaveCount(0);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("TOTP field is filled from get-totp", async ({ stack }) => {
  const page = await openPage(stack, "/totp");
  await expect(totpIcon(page)).toHaveCount(1, { timeout: 20_000 });

  await totpIcon(page).click();
  await expect(page.locator("#totp")).toHaveValue("777777");
});
