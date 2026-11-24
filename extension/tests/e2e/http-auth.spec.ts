/**
 * WP5 end-to-end — HTTP Basic/Digest with the real stack.
 *
 * Real extension (`extension/dist`), real `friendlypass-browser-host`, real
 * Rust protocol server (`examples/test_server.rs`) and a Node Basic/Digest
 * server. The database is a throwaway KDBX created with the `friendlypass` CLI
 * at test time, so the fixture database in `fixtures/` is never touched.
 *
 * Scenarios (REPORT §4, §8.1):
 *   1. Basic single match auto-fills; the page shows the 200 body.
 *   2. Digest (MD5, qop=auth) works.
 *   3. Wrong stored password → exactly one retry, then Chrome's prompt.
 *   4. No match → no Authorization header is ever sent.
 *   5. App killed → the callback settles well inside the 10 s budget.
 *   6. 20 parallel 401s all settle and the page loads.
 *
 * Nothing here prints a credential.
 */

import { expect, test as base } from "@playwright/test";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Harness } from "../harness/harness";
import { REPO_ROOT } from "../harness/app-mock";
import {
  fetchStats,
  startHttpAuthServers,
  type HttpAuthServer,
} from "../fixtures/http-auth-server.mjs";

interface AuthServers {
  single: HttpAuthServer;
  digest: HttpAuthServer;
  wrong: HttpAuthServer;
  parallel: HttpAuthServer;
  noMatch: HttpAuthServer;
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

interface DiagnosticsLike {
  active: number;
  challenges: number;
  settled: number;
  autoFilled: number;
  pickers: number;
  fallbacks: number;
  lastReason: string | null;
  lastOrigin: string | null;
  lastSettledAt: number | null;
  lastLookupError: string | null;
}

let servers: AuthServers;
let tempRoot: string;
let fixtureDbPath: string;

// ---------------------------------------------------------------------------
// Throwaway database construction
// ---------------------------------------------------------------------------

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
  const cli = binaryPath("friendlypass");
  const result = spawnSync(cli, args, {
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

function createAuthDatabase(dbPath: string, authServers: AuthServers): void {
  fs.rmSync(dbPath, { force: true });
  // Database password must match test_server's default ("testpassword").
  runCli(["db-create", "-p", dbPath], "testpassword\ntestpassword\n");

  const entries = [
    {
      title: "Basic single",
      username: "alice",
      password: "alice-secret",
      url: authServers.single.url("/"),
    },
    {
      title: "Digest",
      username: "dave",
      password: "dave-secret",
      url: authServers.digest.url("/"),
    },
    // Two candidates for the same origin. Neither password is accepted by the
    // server, which is how the loop guard is exercised.
    {
      title: "Wrong A",
      username: "u1",
      password: "wrong-one",
      url: authServers.wrong.url("/"),
    },
    {
      title: "Wrong B",
      username: "u2",
      password: "wrong-two",
      url: authServers.wrong.url("/"),
    },
    {
      title: "Parallel",
      username: "par",
      password: "par-secret",
      url: authServers.parallel.url("/"),
    },
    // Deliberately no entry for authServers.noMatch.
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
      `testpassword\n${entry.password}\n`,
    );
  }
}

// ---------------------------------------------------------------------------
// Per-test harness: real host + real Rust server, then swap in our database
// ---------------------------------------------------------------------------

const test = base.extend<{ harness: Harness }>({
  harness: async ({}, use) => {
    const harness = await Harness.start({ hostMode: "real", appMode: "rust" });
    try {
      await use(harness);
    } finally {
      await harness.close().catch(() => undefined);
    }
  },
});

async function status(harness: Harness): Promise<StatusLike> {
  return (await harness.internalRequest("status.get")) as StatusLike;
}

async function diagnostics(harness: Harness): Promise<DiagnosticsLike> {
  return (await harness.swEvaluate(() => {
    const bridge = (
      globalThis as unknown as {
        __friendlypassHttpAuth?: { diagnostics(): DiagnosticsLike };
      }
    ).__friendlypassHttpAuth;
    return (
      bridge?.diagnostics() ?? {
        active: 0,
        challenges: 0,
        settled: 0,
        autoFilled: 0,
        pickers: 0,
        fallbacks: 0,
        lastReason: null,
        lastOrigin: null,
        lastSettledAt: null,
        lastLookupError: null,
      }
    );
  })) as DiagnosticsLike;
}

function pathStats(
  stats: Awaited<ReturnType<typeof fetchStats>>,
  path: string,
): { challenges: number; attempts: number; successes: number; failures: number } {
  return (
    stats.byPath[path] ?? {
      challenges: 0,
      attempts: 0,
      successes: 0,
      failures: 0,
    }
  );
}

async function setHttpAuthSettings(
  harness: Harness,
  settings: Record<string, unknown>,
): Promise<void> {
  const worker = await harness.currentServiceWorker();
  await worker.evaluate(async (value) => {
    await chrome.storage.local.set({ "friendlypass.httpAuth.v1": value });
  }, settings);
}

async function prepare(harness: Harness): Promise<void> {
  const rust = harness.rustApp();
  await rust.stop();
  fs.copyFileSync(fixtureDbPath, rust.databasePath);
  fs.rmSync(rust.associationsPath, { force: true });
  await rust.start();

  // The database hash changed; rebuild the session and associate explicitly.
  // A reconnect can legitimately race the host noticing the new app process;
  // the retry loop below handles that, so a transport rejection here is not
  // fatal.
  await harness
    .internalRequest("connection.reconnect")
    .catch(() => undefined);
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
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`could not associate the test database: ${String(lastError)}`);
}

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

test.beforeAll(async () => {
  test.setTimeout(300_000);
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

  servers = (await startHttpAuthServers()) as AuthServers;
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fp-wp5-auth-"));
  fixtureDbPath = path.join(tempRoot, "http-auth.kdbx");
  createAuthDatabase(fixtureDbPath, servers);
});

test.afterAll(async () => {
  if (servers) {
    await Promise.all(
      Object.values(servers).map((server) => server.stop().catch(() => undefined)),
    );
  }
  if (tempRoot) {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

test("Basic: a single match is filled automatically", async ({ harness }) => {
  test.setTimeout(90_000);
  await prepare(harness);
  servers.single.resetStats();

  const page = await harness.context.newPage();
  try {
    const response = await page.goto(servers.single.url("/private"), {
      waitUntil: "domcontentloaded",
      timeout: 15_000,
    });
    expect(response?.status()).toBe(200);
    await expect(page.locator("body")).toContainText("ok basic:alice");

    // The browser may also fetch /favicon.ico after the page; assert the
    // protected document itself, not aggregate counters.
    const stats = pathStats(await fetchStats(servers.single), "/private");
    expect(stats.challenges).toBe(1);
    expect(stats.attempts).toBe(1);
    expect(stats.successes).toBe(1);

    const diag = await diagnostics(harness);
    expect(diag.autoFilled).toBeGreaterThanOrEqual(1);
    expect(diag.active).toBe(0);
    expect(await harness.swRejections()).toEqual([]);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("Digest: MD5/qop=auth challenge is answered", async ({ harness }) => {
  test.setTimeout(90_000);
  await prepare(harness);
  servers.digest.resetStats();

  const page = await harness.context.newPage();
  try {
    const response = await page.goto(servers.digest.url("/private"), {
      waitUntil: "domcontentloaded",
      timeout: 15_000,
    });
    expect(response?.status()).toBe(200);
    await expect(page.locator("body")).toContainText("ok digest:dave");

    const stats = pathStats(await fetchStats(servers.digest), "/private");
    expect(stats.challenges).toBe(1);
    expect(stats.attempts).toBeGreaterThanOrEqual(1);
    expect(stats.successes).toBe(1);

    const diag = await diagnostics(harness);
    expect(diag.active).toBe(0);
    expect(await harness.swRejections()).toEqual([]);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("wrong stored password: one retry, then Chrome's prompt (no loop)", async ({
  harness,
}) => {
  test.setTimeout(90_000);
  await prepare(harness);
  servers.wrong.resetStats();

  // Two entries match this origin. Remembering u1 makes the first challenge a
  // deterministic auto-fill; the second challenge may try u2 exactly once.
  await setHttpAuthSettings(harness, {
    httpAuthAutoFill: true,
    lastUsed: { [servers.wrong.url("/")]: "u1" },
    realms: {},
  });

  const page = await harness.context.newPage();
  try {
    const navigation = page
      .goto(servers.wrong.url("/private"), {
        waitUntil: "domcontentloaded",
        timeout: 15_000,
      })
      .then((response) => ({ status: response?.status() ?? 0 }))
      .catch((cause: unknown) => ({ error: String(cause) }));

    await expect
      .poll(
        async () =>
          pathStats(await fetchStats(servers.wrong), "/private").attempts,
        {
          timeout: 10_000,
          intervals: [50, 100, 200],
        },
      )
      .toBe(2);

    // No loop: after the retry Chrome shows its prompt and nothing else is
    // sent, even after a generous wait.
    await delay(1_500);
    const stats = pathStats(await fetchStats(servers.wrong), "/private");
    expect(stats.attempts).toBe(2);
    expect(stats.successes).toBe(0);

    const diag = await diagnostics(harness);
    expect(diag.lastReason).toBe("retry-exhausted");
    expect(diag.active).toBe(0);

    // The navigation is either still blocked by Chrome's prompt or failed
    // with an auth error; it must never have loaded the protected body.
    const outcome = await Promise.race([
      navigation.then((value) => value),
      delay(500).then(() => ({ blocked: true })),
    ]);
    if ("status" in outcome) {
      expect(outcome.status).not.toBe(200);
    }
    expect(await harness.swRejections()).toEqual([]);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("no match: Chrome's prompt appears and no credentials are sent", async ({
  harness,
}) => {
  test.setTimeout(90_000);
  await prepare(harness);
  servers.noMatch.resetStats();

  const page = await harness.context.newPage();
  try {
    const navigation = page
      .goto(servers.noMatch.url("/private"), {
        waitUntil: "domcontentloaded",
        timeout: 15_000,
      })
      .then((response) => ({ status: response?.status() ?? 0 }))
      .catch((cause: unknown) => ({ error: String(cause) }));

    await expect
      .poll(
        async () =>
          pathStats(await fetchStats(servers.noMatch), "/private").challenges,
        {
          timeout: 10_000,
          intervals: [50, 100, 200],
        },
      )
      .toBe(1);

    await delay(1_000);
    const stats = pathStats(await fetchStats(servers.noMatch), "/private");
    expect(stats.attempts).toBe(0);
    expect(stats.successes).toBe(0);

    const diag = await diagnostics(harness);
    expect(diag.lastReason).toBe("no-match");
    expect(diag.fallbacks).toBeGreaterThanOrEqual(1);

    const outcome = await Promise.race([
      navigation.then((value) => value),
      delay(500).then(() => ({ blocked: true })),
    ]);
    if ("status" in outcome) {
      expect(outcome.status).not.toBe(200);
    }
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("app killed: the page never hangs (settles within 10 s)", async ({
  harness,
}) => {
  test.setTimeout(90_000);
  await prepare(harness);
  servers.single.resetStats();
  const before = await diagnostics(harness);

  await harness.rustApp().stop();

  const started = Date.now();
  const page = await harness.context.newPage();
  try {
    void page
      .goto(servers.single.url("/private"), {
        waitUntil: "domcontentloaded",
        timeout: 20_000,
      })
      .catch(() => undefined);

    await expect
      .poll(async () => (await diagnostics(harness)).settled, {
        timeout: 12_000,
        intervals: [100, 200, 400],
      })
      .toBeGreaterThan(before.settled);

    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(10_000);

    const diag = await diagnostics(harness);
    expect(diag.active).toBe(0);
    // The app is gone, so no credential can be produced; Chrome's prompt is
    // the only acceptable outcome.
    expect(diag.fallbacks).toBeGreaterThanOrEqual(before.fallbacks + 1);
    const stats = pathStats(await fetchStats(servers.single), "/private");
    expect(stats.attempts).toBe(0);
    expect(await harness.swRejections()).toEqual([]);
  } finally {
    await page.close().catch(() => undefined);
  }
});

test("20 parallel 401s all settle and the page loads", async ({ harness }) => {
  test.setTimeout(90_000);
  await prepare(harness);
  servers.parallel.resetStats();

  const page = await harness.context.newPage();
  try {
    // The page itself is unprotected; every image has its own Digest realm,
    // so Chrome cannot replay cached credentials and all 20 get a real 401.
    await page.goto(servers.parallel.url("/parallel"), {
      waitUntil: "domcontentloaded",
      timeout: 15_000,
    });
    await expect(page.locator("body")).toContainText("parallel");
    await expect
      .poll(
        () =>
          page.evaluate(() =>
            Array.from(document.images).every(
              (image) => image.complete && image.naturalWidth > 0,
            ),
          ),
        { timeout: 15_000, intervals: [100, 250, 500] },
      )
      .toBe(true);

    const stats = await fetchStats(servers.parallel);
    const imagePaths = Object.keys(stats.byPath)
      .filter((path) => path.startsWith("/img/"))
      .sort();
    expect(imagePaths).toHaveLength(20);
    for (const imagePath of imagePaths) {
      const image = pathStats(stats, imagePath);
      // Chrome may repeat a fetch; every completed attempt authenticated.
      expect(image.challenges).toBeGreaterThanOrEqual(1);
      expect(image.attempts).toBeGreaterThanOrEqual(1);
      expect(image.successes).toBeGreaterThanOrEqual(1);
    }
    expect(stats.challenges).toBeGreaterThanOrEqual(20);
    expect(stats.failures).toBeGreaterThanOrEqual(20);

    const diag = await diagnostics(harness);
    expect(diag.active).toBe(0);
    expect(diag.settled).toBeGreaterThanOrEqual(20);
    expect(await harness.swRejections()).toEqual([]);
  } finally {
    await page.close().catch(() => undefined);
  }
});
