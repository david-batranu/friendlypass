/**
 * Phase 1 EXIT TEST — "never disconnect".
 *
 * Runs the **real** extension bundle, the **real** `friendlypass-browser-host`
 * and the **real** Rust protocol server (`examples/test_server.rs`, which opens
 * `fixtures/sample4.kdbx` and auto-approves the association). No Node mock is
 * involved.
 *
 * Scenario:
 *   1. associate, then `get-logins` succeeds;
 *   2. 20 × { kill the app → status reports app down within 5 s → restart the
 *      app → `get-logins` succeeds again within 5 s } with **no** manual
 *      reconnect and **no** re-association;
 *   3. interleaved with 5 × SIGKILL of the native host and 3 × service-worker
 *      restarts;
 *   4. every request settles in under 15 s and the service worker records no
 *      unhandled rejection.
 *
 * Nothing here prints credentials; only action outcomes, counts and timings.
 */

import { expect, test } from "@playwright/test";
import { Harness } from "../harness/harness";

const APP_DOWN_BUDGET_MS = 5_000;
const APP_UP_BUDGET_MS = 5_000;
const REQUEST_BUDGET_MS = 15_000;
const TEST_URL = "https://example.com";

interface StatusLike {
  appRunning: boolean;
  state: string;
  associated: boolean;
  databaseHash: string | null;
  hostVersion: string | null;
}

interface LoginsLike {
  length: number;
  [index: number]: { login?: string; password?: string; uuid?: string };
}

async function status(harness: Harness): Promise<StatusLike> {
  return (await harness.internalRequest("status.get")) as StatusLike;
}

async function logins(harness: Harness): Promise<LoginsLike> {
  return (await harness.internalRequest("logins.get", {
    url: TEST_URL,
  })) as LoginsLike;
}

/** Run one request with a hard deadline; every call must settle, never hang. */
async function timed<T>(
  harness: Harness,
  action: string,
  args: unknown,
  budgetMs = REQUEST_BUDGET_MS,
): Promise<{ value: T; elapsedMs: number }> {
  const started = Date.now();
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    const value = await Promise.race([
      harness.internalRequest(action, args) as Promise<T>,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${action} did not settle within ${budgetMs} ms`)),
          budgetMs,
        );
      }),
    ]);
    return { value, elapsedMs: Date.now() - started };
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

/**
 * Retry `get-logins` until it succeeds, asserting success within `budgetMs`.
 * Failures are expected while the host reconnects; the point is that recovery
 * is automatic, so no explicit connect/re-associate call is made.
 */
async function waitForLogins(
  harness: Harness,
  budgetMs: number,
  actionBudgetMs = REQUEST_BUDGET_MS,
): Promise<{ elapsedMs: number; attempts: number }> {
  const started = Date.now();
  let attempts = 0;
  let lastError: unknown = null;
  while (Date.now() - started < budgetMs) {
    attempts += 1;
    try {
      const { value } = await timed<LoginsLike>(
        harness,
        "logins.get",
        { url: TEST_URL },
        actionBudgetMs,
      );
      if (!Array.isArray(value) || value.length === 0) {
        throw new Error("get-logins returned no entries");
      }
      const elapsedMs = Date.now() - started;
      expect(elapsedMs).toBeLessThanOrEqual(budgetMs);
      return { elapsedMs, attempts };
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  const message = lastError instanceof Error ? lastError.message : String(lastError);
  throw new Error(
    `get-logins did not recover within ${budgetMs} ms after ${attempts} attempt(s): ${message}`,
  );
}

test("never disconnect: 20 app restarts, 5 host kills, 3 service-worker restarts", async () => {
  test.setTimeout(300_000);

  const harness = await Harness.start({ hostMode: "real", appMode: "rust" });
  const appDownMs: number[] = [];
  const appUpMs: number[] = [];
  const hostRecoveryMs: number[] = [];
  const swRecoveryMs: number[] = [];

  try {
    // ---- real stack, real protocol -------------------------------------
    expect(harness.paths.mode).toBe("real");
    expect(harness.paths.hostBinary).toBeTruthy();

    // The initial handshake needs the app; wait for liveness without ever
    // calling connection.reconnect.
    await expect
      .poll(async () => (await status(harness)).appRunning, { timeout: 15_000 })
      .toBe(true);

    const association = (await timed<{ id: string; hash: string }>(
      harness,
      "association.create",
      undefined,
    )).value;
    expect(association.id.length).toBeGreaterThan(0);
    expect(association.hash).toMatch(/^[0-9a-f]{64}$/);
    // The headless server mirrors the real app's immediate metadata save.
    expect(await harness.rustApp().waitForPersistedAssociation()).toBe(1);

    const first = await waitForLogins(harness, 15_000);
    expect(first.elapsedMs).toBeLessThan(15_000);
    const initial = await logins(harness);
    expect(initial.length).toBeGreaterThan(0);
    // Credentials are present but never printed.
    expect(typeof initial[0].password).toBe("string");
    expect((initial[0].password ?? "").length).toBeGreaterThan(0);

    let hostKills = 0;
    let swRestarts = 0;

    for (let cycle = 0; cycle < 20; cycle += 1) {
      // ---- kill the app ------------------------------------------------
      await harness.killApp();
      const downStarted = Date.now();
      await expect
        .poll(async () => (await status(harness)).appRunning, {
          timeout: APP_DOWN_BUDGET_MS,
          intervals: [50, 100, 200],
        })
        .toBe(false);
      const downMs = Date.now() - downStarted;
      appDownMs.push(downMs);
      expect(downMs).toBeLessThanOrEqual(APP_DOWN_BUDGET_MS);

      // ---- restart the app ---------------------------------------------
      await harness.restartApp();
      const upStarted = Date.now();
      const recovered = await waitForLogins(
        harness,
        APP_UP_BUDGET_MS,
        APP_UP_BUDGET_MS,
      );
      const upMs = Date.now() - upStarted;
      appUpMs.push(upMs);
      expect(upMs).toBeLessThanOrEqual(APP_UP_BUDGET_MS);

      // No re-association: the persisted keyring must still authenticate.
      const healthy = await status(harness);
      expect(healthy.appRunning).toBe(true);
      expect(healthy.associated).toBe(true);
      expect(healthy.databaseHash).toBe(association.hash);
      expect(recovered.attempts).toBeGreaterThanOrEqual(1);

      // ---- interleaved fault: SIGKILL the native host ------------------
      if (cycle % 4 === 0) {
        const hostStarted = Date.now();
        await expect
          .poll(() => harness.hostProcessId(), { timeout: 8_000 })
          .toBeGreaterThan(0);
        await harness.killHost();
        await waitForLogins(harness, REQUEST_BUDGET_MS);
        hostRecoveryMs.push(Date.now() - hostStarted);
        hostKills += 1;
      }

      // ---- interleaved fault: service-worker restart -------------------
      if (cycle % 7 === 0) {
        const swStarted = Date.now();
        const extensionId = harness.extensionId;
        await harness.reloadExtension();
        expect(harness.extensionId).toBe(extensionId);
        await waitForLogins(harness, REQUEST_BUDGET_MS);
        swRecoveryMs.push(Date.now() - swStarted);
        swRestarts += 1;

        // The stable id and persisted keyring survived the restart.
        expect(harness.extensionId).toBe(extensionId);
      }
    }

    // ---- final assertions ----------------------------------------------
    expect(hostKills).toBe(5);
    expect(swRestarts).toBe(3);
    expect(appDownMs).toHaveLength(20);
    expect(appUpMs).toHaveLength(20);

    const finalStatus = await status(harness);
    expect(finalStatus.appRunning).toBe(true);
    expect(finalStatus.associated).toBe(true);
    expect(finalStatus.state).not.toBe("DISCONNECTED");
    expect(finalStatus.hostVersion).toBeTruthy();

    const finalEntries = await logins(harness);
    expect(finalEntries.length).toBeGreaterThan(0);

    // Every request settled; the transport/session produced no unhandled
    // rejection during any of the fault cycles.
    expect(await harness.swRejections()).toEqual([]);

    // Hard budgets for the whole scenario.
    for (const value of appDownMs) expect(value).toBeLessThanOrEqual(APP_DOWN_BUDGET_MS);
    for (const value of appUpMs) expect(value).toBeLessThanOrEqual(APP_UP_BUDGET_MS);
    for (const value of hostRecoveryMs) expect(value).toBeLessThan(REQUEST_BUDGET_MS);
    for (const value of swRecoveryMs) expect(value).toBeLessThan(REQUEST_BUDGET_MS);

    const average = (values: number[]): number =>
      Math.round(values.reduce((sum, value) => sum + value, 0) / values.length);
    console.log(
      `[never-disconnect] app-down max ${Math.max(...appDownMs)} ms (avg ${average(appDownMs)}), ` +
        `app-up max ${Math.max(...appUpMs)} ms (avg ${average(appUpMs)}), ` +
        `host-kill recovery max ${Math.max(...hostRecoveryMs)} ms (avg ${average(hostRecoveryMs)}), ` +
        `SW-restart recovery max ${Math.max(...swRecoveryMs)} ms (avg ${average(swRecoveryMs)})`,
    );
  } finally {
    await harness.close().catch(() => undefined);
  }
});
