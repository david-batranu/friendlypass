/**
 * Harness smoke tests (WP8).
 *
 * They prove, in order:
 *   1. the extension loads from `dist/` into an isolated temp profile;
 *   2. Chrome can launch the native host through the generated manifest and a
 *      `ping` round-trips (this is the harness-level proof and works even while
 *      WP2's transport is still a stub);
 *   3. the Node stub host is a faithful framing/liveness stand-in;
 *   4. the app mock speaks the frozen crypto/handshake/get-logins vectors;
 *   5. the extension's own transport connects and pings (skipped while it is a
 *      TODO stub);
 *   6. every fault-injection primitive behaves (app down/up, corrupt frame,
 *      host SIGKILL, extension reload).
 *
 * No credentials or keys are written to logs or failure messages.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test as playwrightTest } from "./harness";
import { AppMock, PROTOCOL_FIXTURES } from "./app-mock";
import { AppSocketClient, openInnerResponse } from "./app-client";
import { HostProcess } from "./host-process";
import { encodeFrame, encodePayload, incrementNonce, sleep } from "./frames.mjs";
import { readJsonl } from "./setup";

const test = playwrightTest;

function fixture(name: string): any {
  return JSON.parse(
    fs.readFileSync(path.join(PROTOCOL_FIXTURES, `${name}.json`), "utf8"),
  );
}

test("harness installs an isolated native-messaging manifest and loads the extension", async ({
  harness,
}) => {
  expect(harness.paths.home).not.toBe(os.homedir());
  expect(harness.paths.home.startsWith(harness.paths.root)).toBe(true);

  expect(harness.paths.manifests.length).toBeGreaterThan(0);
  const manifestFile = harness.paths.manifests[0];
  const manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
  expect(manifest.name).toBe("org.friendlypass.browser");
  expect(manifest.type).toBe("stdio");
  expect(manifest.path).toBe(harness.paths.wrapper);
  expect(manifest.allowed_origins).toContain(
    `chrome-extension://${harness.extensionId}/`,
  );
  expect(fs.statSync(harness.paths.wrapper).mode & 0o111).not.toBe(0);

  // The path-derived ID algorithm must agree with Chromium, otherwise the
  // manifest would need the post-launch rewrite path every run.
  expect(harness.computedExtensionIds).toContain(harness.extensionId);

  const runtimeId = await harness.swEvaluate(() => chrome.runtime.id);
  expect(runtimeId).toBe(harness.extensionId);
  const extensionManifest = await harness.swEvaluate(() =>
    chrome.runtime.getManifest(),
  );
  expect(extensionManifest.name).toBe("friendlypass");
  expect(extensionManifest.manifest_version).toBe(3);
  expect(
    (extensionManifest.background as { service_worker?: string } | undefined)
      ?.service_worker,
  ).toBe("background/sw.js");

  expect(harness.app.listening).toBe(true);
  expect(harness.paths.mode).toMatch(/^(stub|real)$/);
});

test("native-messaging manifest launches the host and ping round-trips through Chromium", async ({
  harness,
}) => {
  const nonce = Buffer.alloc(24, 7).toString("base64");

  const pong = await harness.waitForAppRunning();
  expect(pong.action).toBe("ping");
  expect(pong.success).toBe("true");
  expect(pong.protocolVersion).toBe(1);
  expect(pong.appRunning).toBe(true);
  expect(typeof pong.hostVersion).toBe("string");

  // The nonce is echoed verbatim (never incremented).
  const echo = await harness.ping(nonce);
  expect(echo.action).toBe("ping");
  expect(echo.nonce).toBe(nonce);

  const hello = await harness.hello();
  expect(hello.action).toBe("hello");
  expect(hello.success).toBe("true");
  expect(hello.protocolVersion).toBe(1);
  expect(hello.hostPid).toBeGreaterThan(0);

  // The host really was launched through the generated manifest, not a fake.
  if (harness.paths.mode === "stub") {
    await harness.waitForHostAction("ping");
    expect(harness.hostStarts().length).toBeGreaterThan(0);
  } else {
    expect(harness.hostProcessId()).toBeGreaterThan(0);
  }
});

test("stub host handles split, coalesced and malformed frames and stays alive", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fp8-host-"));
  const app = new AppMock({
    socketPath: path.join(root, "app.sock"),
    logPath: path.join(root, "app.jsonl"),
  });
  await app.start();

  const host = HostProcess.spawn({
    appSocket: app.socketPath,
    logPath: path.join(root, "host.jsonl"),
    pidFile: path.join(root, "host.pid"),
  });

  try {
    const nonce = Buffer.alloc(24, 3).toString("base64");
    const pingFrame = encodeFrame({ action: "ping", nonce });

    // Partial read: the host must buffer until the 4-byte prefix arrives.
    host.sendRaw(pingFrame.subarray(0, 2));
    await sleep(30);
    host.sendRaw(pingFrame.subarray(2));
    const pong = await host.nextFrame();
    expect(pong.action).toBe("ping");
    expect(pong.nonce).toBe(nonce);
    expect(pong.appRunning).toBe(true);

    // Coalesced frames in one write must both be processed.
    host.sendRaw(
      Buffer.concat([
        encodeFrame({ action: "ping", nonce: "a" }),
        encodeFrame({ action: "ping", nonce: "b" }),
      ]),
    );
    expect((await host.nextFrame()).nonce).toBe("a");
    expect((await host.nextFrame()).nonce).toBe("b");

    // Invalid JSON → host error 1002, then still alive.
    host.sendRaw(encodePayload(Buffer.from('{"action":', "utf8")));
    const malformed = await host.nextFrame();
    expect(malformed.hostError).toBe(true);
    expect(malformed.errorCode).toBe("1002");

    host.sendFrame({ action: "hello" });
    const hello = await host.nextFrame();
    expect(hello.action).toBe("hello");
    expect(hello.success).toBe("true");

    // stallApp(): app-side delay is observable through the host.
    app.stall(350);
    const startedAt = Date.now();
    host.sendFrame(fixture("change-public-keys").vectors[0].request.frame);
    const stalledResponse = await host.nextFrame();
    expect(stalledResponse.action).toBe("change-public-keys");
    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(300);

    // App loss: forwarded frames settle with host error 5 after the grace
    // period, and ping still answers with appRunning:false.
    await app.stop();
    host.sendFrame(fixture("change-public-keys").vectors[0].request.frame);
    const unavailable = await host.nextFrame(4000);
    expect(unavailable.hostError).toBe(true);
    expect(unavailable.errorCode).toBe("5");
    host.sendFrame({ action: "ping" });
    const downPing = await host.nextFrame();
    expect(downPing.action).toBe("ping");
    expect(downPing.appRunning).toBe(false);

    expect(host.hasExited).toBe(false);
    expect(app.connectionCount).toBeGreaterThan(0);
  } finally {
    await host.close();
    await app.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("app mock replays the golden change-public-keys → test-associate → get-logins path", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fp8-app-"));
  const app = new AppMock({
    socketPath: path.join(root, "app.sock"),
    logPath: path.join(root, "app.jsonl"),
  });
  await app.start();
  const client = await AppSocketClient.connect(app.socketPath);

  try {
    const handshake = fixture("change-public-keys").vectors[0];
    const associate = fixture("test-associate").vectors[0];
    const logins = fixture("get-logins").vectors[0];

    const handshakeResponse = await client.request(handshake.request.frame);
    expect(handshakeResponse.action).toBe("change-public-keys");
    expect(handshakeResponse.success).toBe("true");
    expect(handshakeResponse.publicKey).toBe(handshake.response.frame.publicKey);
    expect(handshakeResponse.nonce).toBe(
      incrementNonce(handshake.request.nonce),
    );

    const associateResponse = await client.request(associate.request.frame);
    const associateInner = openInnerResponse(
      associateResponse,
      associate.request.nonce,
      fixture("get-logins").keys.client.secretKey,
      fixture("get-logins").keys.host.publicKey,
    );
    expect(associateInner.success).toBe("true");
    expect(associateInner.hash).toBe(fixture("get-logins").database.databaseHash);

    const loginsResponse = await client.request(logins.request.frame);
    const loginsInner = openInnerResponse(
      loginsResponse,
      logins.request.nonce,
      fixture("get-logins").keys.client.secretKey,
      fixture("get-logins").keys.host.publicKey,
    );
    const expectedEntries = logins.response.plaintext.entries;
    expect(loginsInner.success).toBe("true");
    expect(loginsInner.count).toBe(expectedEntries.length);
    expect(Array.isArray(loginsInner.entries)).toBe(true);
    const entries = loginsInner.entries as Array<Record<string, unknown>>;
    expect(entries.length).toBe(expectedEntries.length);
    expect(entries[0].login === expectedEntries[0].login).toBe(true);
    expect(entries[0].password === expectedEntries[0].password).toBe(true);

    expect(app.counters.requests["get-logins"]).toBe(1);
    expect(app.counters.handshakes).toBe(1);

    // The app mock's log must never contain plaintext credentials.
    const log = fs.readFileSync(app.logPath, "utf8");
    expect(log.includes(expectedEntries[0].password)).toBe(false);
    expect(log.includes(expectedEntries[0].login)).toBe(false);
  } finally {
    client.close();
    await app.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("extension transport connects to the host and pings", async ({
  harness,
}) => {
  test.setTimeout(60_000);
  test.skip(
    !harness.transportImplemented(),
    "WP2 native transport is still the TODO stub; the Chrome↔manifest↔host ping test above exercises the same path",
  );

  // Wait for the extension's own status surface, which proves the real
  // transport → host → session path. The host's JSONL action log only exists
  // for the Node stub host.
  await expect
    .poll(
      async () => {
        const status = (await harness.internalRequest("status.get")) as {
          hostVersion?: string | null;
          state?: string;
        };
        return typeof status.hostVersion === "string" && status.state !== "DISCONNECTED";
      },
      { timeout: 15_000 },
    )
    .toBe(true);
});

test("fault injection: app down/up, corrupt frame, host kill, extension reload", async ({
  harness,
}) => {
  test.setTimeout(90_000);

  // App down: the host must keep answering ping and report appRunning:false.
  await harness.waitForAppRunning();
  await harness.killApp();
  await expect
    .poll(async () => (await harness.ping()).appRunning, { timeout: 8_000 })
    .toBe(false);

  // App back: the host reconnects without user action.
  await harness.restartApp();
  await harness.waitForAppRunning(10_000);

  // A malformed app→host frame becomes a host error 1002; the host survives.
  // Each native port is a separate host process, so wait for the probe's own
  // app connection before injecting.
  const connectionsBeforeProbe = harness.app.currentConnections;
  await harness.openNativeProbePort();
  await harness.waitForAppConnections(connectionsBeforeProbe + 1, 8_000);
  expect(harness.sendCorruptFrame()).toBe(true);
  await expect
    .poll(
      async () =>
        (await harness.nativeProbeFrames()).some(
          (frame) =>
            frame.hostError === true && String(frame.errorCode) === "1002",
        ),
      { timeout: 8_000 },
    )
    .toBe(true);
  await harness.closeNativeProbePort();

  // SIGKILL the host while a port is open, then reconnect: Chrome spawns a new
  // host and ping works again. The PID must change.
  // The extension's own native port is open by now (it opened one for the
  // transport), so a SIGKILL of the recorded host exercises the same path
  // without requiring a second probe process.
  await expect
    .poll(() => harness.hostProcessId(), { timeout: 8_000 })
    .toBeGreaterThan(0);
  const startsBefore = harness.hostStarts().length;
  const oldPid = await harness.killHost();

  const afterKill = await harness.waitForAppRunning(10_000);
  expect(afterKill.action).toBe("ping");
  expect(afterKill.appRunning).toBe(true);

  if (harness.paths.mode === "stub") {
    expect(harness.hostStarts().length).toBeGreaterThan(startsBefore);
    const newPid = harness.hostStarts().at(-1)?.pid;
    expect(newPid).not.toBe(oldPid);
  } else {
    await expect
      .poll(() => harness.hostProcessId(), { timeout: 8_000 })
      .not.toBe(oldPid);
  }

  // Simulated browser sleep: reload the extension, same ID, ping still works.
  const oldExtensionId = harness.extensionId;
  await harness.reloadExtension();
  expect(harness.extensionId).toBe(oldExtensionId);
  expect((await harness.ping()).action).toBe("ping");

  // Every request settled: the service worker has no unhandled rejection.
  expect(await harness.swRejections()).toEqual([]);

  if (harness.paths.mode === "stub") {
    // The Node stub host records an event log; the real Rust host writes
    // diagnostics to stderr only.
    const events = readJsonl(harness.paths.hostLog);
    expect(events.some((event) => event.event === "start")).toBe(true);
    expect(events.some((event) => event.event === "uncaught")).toBe(false);
    expect(events.some((event) => event.event === "unhandled-rejection")).toBe(
      false,
    );
  }
});
