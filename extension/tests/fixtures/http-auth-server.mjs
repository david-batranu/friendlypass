/**
 * Dependency-free HTTP Basic / Digest test server for the WP5 e2e spec.
 *
 * One instance listens on one loopback address and protects every path except
 * the diagnostics endpoints:
 *
 *   GET /__stats   JSON counters (never credentials)
 *   GET /__reset   reset counters
 *   GET /public    unprotected body
 *   GET /parallel  unprotected HTML with 20 protected images
 *   *              protected by Basic or Digest
 *
 * Digest is implemented directly with MD5/qop=auth so the tests do not depend
 * on an external package. Counters let specs prove "exactly one retry, then no
 * more Authorization headers" and "20 parallel challenges all succeeded".
 *
 * This module is data-plane only: it never starts the browser or the native
 * host, and it never writes credentials to its log.
 */

import http from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

function md5(value) {
  return createHash("md5").update(value, "utf8").digest("hex");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a), "utf8");
  const right = Buffer.from(String(b), "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function parseAuthorization(header) {
  if (typeof header !== "string") return null;
  const space = header.indexOf(" ");
  if (space <= 0) return null;
  const scheme = header.slice(0, space).toLowerCase();
  const rest = header.slice(space + 1).trim();
  if (scheme === "basic") {
    try {
      const decoded = Buffer.from(rest, "base64").toString("utf8");
      const colon = decoded.indexOf(":");
      if (colon < 0) return { scheme, username: decoded, password: "" };
      return {
        scheme,
        username: decoded.slice(0, colon),
        password: decoded.slice(colon + 1),
      };
    } catch {
      return null;
    }
  }
  if (scheme === "digest") {
    const params = {};
    const pattern = /([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^\s,]+))/g;
    let match;
    while ((match = pattern.exec(rest)) !== null) {
      params[match[1].toLowerCase()] = match[2] ?? match[3] ?? "";
    }
    return { scheme, params };
  }
  return { scheme, raw: rest };
}

function statsFor() {
  return {
    challenges: 0,
    attempts: 0,
    successes: 0,
    failures: 0,
    requests: 0,
    byPath: {},
  };
}

export class HttpAuthServer {
  /**
   * @param {object} options
   * @param {string} [options.host]
   * @param {number} [options.port]
   * @param {"basic"|"digest"} [options.mode]
   * @param {string} [options.realm]
   * @param {Record<string,string>} [options.users] username -> password
   * @param {string} [options.name]
   */
  constructor(options = {}) {
    // `host` is the *URL* host. Every name under `.localhost` resolves to the
    // loopback interface in Chrome, so each scenario can have a distinct host
    // (and therefore a distinct credential match) without editing /etc/hosts.
    this.host = options.host ?? "127.0.0.1";
    this.requestedPort = options.port ?? 0;
    this.mode = options.mode ?? "basic";
    this.realm = options.realm ?? `friendlypass-${this.mode}`;
    this.users = { ...(options.users ?? {}) };
    this.name = options.name ?? `${this.mode}@${this.host}`;
    this.servers = [];
    this.port = 0;
    this.counters = statsFor();
    this.nonces = new Set();
    this.opaque = randomBytes(8).toString("hex");
  }

  get origin() {
    return `http://${this.host}:${this.port}`;
  }

  async start() {
    if (this.servers.length > 0) return this;
    const handler = (req, res) => this.handle(req, res);
    const listen = (server, port, host) =>
      new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.removeListener("error", reject);
          resolve();
        });
      });

    const primary = http.createServer(handler);
    await listen(primary, this.requestedPort, "127.0.0.1");
    this.port = primary.address().port;
    this.servers.push(primary);

    // Also accept IPv6 loopback: macOS resolves *.localhost to ::1 first.
    // Failure here is non-fatal (IPv4 fallback still works).
    try {
      const secondary = http.createServer(handler);
      await listen(secondary, this.port, "::1");
      this.servers.push(secondary);
    } catch {
      /* IPv6 loopback unavailable */
    }
    return this;
  }

  async stop() {
    const servers = this.servers;
    this.servers = [];
    await Promise.all(
      servers.map(
        (server) =>
          new Promise((resolve) => {
            server.close(() => resolve());
            server.closeAllConnections?.();
          }),
      ),
    );
  }

  url(path = "/") {
    return `${this.origin}${path.startsWith("/") ? path : `/${path}`}`;
  }

  stats() {
    const byPath = {};
    for (const [path, value] of Object.entries(this.counters.byPath)) {
      byPath[path] = { ...value };
    }
    return {
      name: this.name,
      host: this.host,
      port: this.port,
      mode: this.mode,
      realm: this.realm,
      ...this.counters,
      byPath,
    };
  }

  resetStats() {
    this.counters = statsFor();
    this.nonces.clear();
  }

  pathStats(path) {
    return (
      this.counters.byPath[path] ?? {
        challenges: 0,
        attempts: 0,
        successes: 0,
        failures: 0,
      }
    );
  }

  // -- request handling -----------------------------------------------------

  handle(req, res) {
    this.counters.requests += 1;
    const url = new URL(req.url ?? "/", this.origin);
    const path = url.pathname;

    if (path === "/__stats") {
      this.writeJson(res, 200, this.stats());
      return;
    }
    if (path === "/__reset") {
      this.resetStats();
      this.writeJson(res, 200, { ok: true });
      return;
    }
    if (path === "/public") {
      this.writeBody(res, 200, "public-body");
      return;
    }
    if (path === "/parallel") {
      this.writeHtml(res, 200, this.parallelPage());
      return;
    }

    const pathCounters = this.pathCounters(path);
    pathCounters.requests += 1;

    const header = req.headers.authorization;
    if (header) {
      this.counters.attempts += 1;
      pathCounters.attempts += 1;
    }

    const realm = this.realmFor(path);
    const result =
      this.mode === "digest"
        ? this.verifyDigest(req, header, realm)
        : this.verifyBasic(header);

    if (result.ok) {
      this.counters.successes += 1;
      pathCounters.successes += 1;
      if (path.startsWith("/img/")) {
        this.writeImage(res);
        return;
      }
      this.writeBody(res, 200, `ok ${this.mode}:${result.username} path=${path}`);
      return;
    }

    this.counters.failures += 1;
    pathCounters.failures += 1;
    this.counters.challenges += 1;
    pathCounters.challenges += 1;
    const challenge =
      this.mode === "digest"
        ? this.digestChallenge(realm)
        : `Basic realm="${realm.replace(/"/g, '\\"')}", charset="UTF-8"`;
    res.statusCode = 401;
    res.setHeader("WWW-Authenticate", challenge);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end("authentication required");
  }

  pathCounters(path) {
    let value = this.counters.byPath[path];
    if (!value) {
      value = { requests: 0, challenges: 0, attempts: 0, successes: 0, failures: 0 };
      this.counters.byPath[path] = value;
    }
    return value;
  }

  realmFor(path) {
    if (path.startsWith("/img/")) {
      return `${this.realm}-${path.slice("/img/".length)}`;
    }
    if (path.startsWith("/parallel/")) {
      return `${this.realm}-${path.slice("/parallel/".length)}`;
    }
    return this.realm;
  }

  verifyBasic(header) {
    const parsed = parseAuthorization(header);
    if (!parsed || parsed.scheme !== "basic") {
      return { ok: false };
    }
    const expected = this.users[parsed.username];
    if (expected === undefined) {
      return { ok: false };
    }
    if (!safeEqual(parsed.password, expected)) {
      return { ok: false };
    }
    return { ok: true, username: parsed.username };
  }

  digestChallenge(realm) {
    const nonce = randomBytes(16).toString("hex");
    this.nonces.add(nonce);
    // Bound the nonce table for a long-lived test process.
    if (this.nonces.size > 512) {
      const first = this.nonces.values().next().value;
      if (first !== undefined) this.nonces.delete(first);
    }
    return (
      `Digest realm="${realm.replace(/"/g, '\\"')}", ` +
      `qop="auth", algorithm=MD5, nonce="${nonce}", opaque="${this.opaque}"`
    );
  }

  verifyDigest(req, header, realm) {
    const parsed = parseAuthorization(header);
    if (!parsed || parsed.scheme !== "digest") {
      return { ok: false };
    }
    const p = parsed.params;
    if (!p || p.realm !== realm || !p.username || !p.nonce || !p.uri) {
      return { ok: false };
    }
    if (!this.nonces.has(p.nonce)) {
      return { ok: false };
    }
    if (p.qop !== "auth") {
      return { ok: false };
    }
    const password = this.users[p.username];
    if (password === undefined) {
      return { ok: false };
    }
    const method = (req.method ?? "GET").toUpperCase();
    const ha1 = md5(`${p.username}:${realm}:${password}`);
    const ha2 = md5(`${method}:${p.uri}`);
    const expected = md5(
      `${ha1}:${p.nonce}:${p.nc ?? ""}:${p.cnonce ?? ""}:${p.qop}:${ha2}`,
    );
    if (!safeEqual(p.response ?? "", expected)) {
      return { ok: false };
    }
    return { ok: true, username: p.username };
  }

  parallelPage() {
    // Every image has its own Digest realm, so Chrome cannot replay cached
    // credentials: each request produces a genuine 401.
    const images = Array.from(
      { length: 20 },
      (_, index) =>
        `<img alt="auth ${index}" src="/img/${index}" width="8" height="8">`,
    ).join("");
    return (
      "<!doctype html><meta charset=\"utf-8\">" +
      "<title>parallel auth</title>" +
      "<p id=\"done\">parallel</p>" +
      images
    );
  }

  writeImage(res) {
    // 1x1 transparent GIF.
    const gif = Buffer.from(
      "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==",
      "base64",
    );
    res.statusCode = 200;
    res.setHeader("Content-Type", "image/gif");
    res.setHeader("Cache-Control", "no-store");
    res.end(gif);
  }

  writeBody(res, status, body) {
    res.statusCode = status;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(body);
  }

  writeHtml(res, status, body) {
    res.statusCode = status;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(body);
  }

  writeJson(res, status, value) {
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(JSON.stringify(value));
  }
}

/**
 * Start the set of loopback servers the WP5 e2e spec needs. Each scenario uses
 * a distinct host so the app's URL matching cannot mix the databases.
 */
export async function startHttpAuthServers() {
  const servers = {
    single: new HttpAuthServer({
      host: "alice.localhost",
      mode: "basic",
      realm: "friendlypass-basic",
      users: { alice: "alice-secret" },
      name: "single-basic",
    }),
    digest: new HttpAuthServer({
      host: "digest.localhost",
      mode: "digest",
      realm: "friendlypass-digest",
      users: { dave: "dave-secret" },
      name: "digest",
    }),
    wrong: new HttpAuthServer({
      host: "wrong.localhost",
      mode: "basic",
      realm: "friendlypass-wrong",
      users: {},
      name: "wrong-password",
    }),
    parallel: new HttpAuthServer({
      host: "parallel0.localhost",
      // Digest cannot be replayed preemptively into a different realm, so each
      // of the 20 parallel requests gets a real 401 instead of reusing the
      // Basic auth cache.
      mode: "digest",
      realm: "friendlypass-parallel",
      users: { par: "par-secret" },
      name: "parallel",
    }),
    noMatch: new HttpAuthServer({
      host: "nomatch.localhost",
      mode: "basic",
      realm: "friendlypass-nomatch",
      users: { nobody: "nobody-secret" },
      name: "no-match",
    }),
  };
  await Promise.all(Object.values(servers).map((server) => server.start()));
  return servers;
}

// Standalone `/__stats` scrape helper used by the spec and by manual runs.
export async function fetchStats(server) {
  const response = await fetch(`${server.origin}/__stats`);
  if (!response.ok) throw new Error(`__stats returned ${response.status}`);
  return await response.json();
}
