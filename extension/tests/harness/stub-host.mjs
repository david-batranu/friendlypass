#!/usr/bin/env node
/**
 * Stand-in for `friendlypass-browser-host` (WP1) for the e2e harness (WP8).
 *
 * It speaks exactly the stdio side of `protocol/ACTIONS.md`:
 *   - 4-byte LE length + UTF-8 JSON, 1 MiB cap, partial/coalesced frames;
 *   - `ping` and `hello` answered locally, even with the app down;
 *   - every other frame forwarded unchanged to the app's unix socket;
 *   - host error frames (1001/1002, code 5 for an unavailable app) and it
 *     never dies because of a bad frame or a missing app.
 *
 * Run through the generated wrapper in the temp HOME so Chrome can launch it as
 * the native-messaging host. See `README.md` in this directory.
 *
 * Diagnostics go to stderr and to the JSONL event log. The log records action
 * names and error codes only — never frame bodies, which may carry (encrypted)
 * credentials.
 */

import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import {
  FrameDecoder,
  HOST_ERROR,
  encodeFrame,
  sleep,
} from "./frames.mjs";

/** @param {string} name @param {string|null} fallback */
function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

const HOST_VERSION = arg("host-version", "0.1.0");
const APP_SOCKET = arg("app-socket", process.env.FP_APP_SOCKET ?? null);
const LOG_PATH = arg("log", null);
const PID_FILE = arg("pid", null);
const FORWARD_GRACE_MS = Number(arg("forward-grace-ms", "1000"));

const sessionId = randomUUID();
const startedAt = Date.now();

if (PID_FILE) {
  try {
    fs.mkdirSync(path.dirname(PID_FILE), { recursive: true });
    fs.writeFileSync(PID_FILE, `${process.pid}\n`);
  } catch (error) {
    process.stderr.write(`stub-host: cannot write pid file: ${error}\n`);
  }
}

/** @param {Record<string, unknown>} event */
function log(event) {
  if (!LOG_PATH) return;
  try {
    fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
    fs.appendFileSync(
      LOG_PATH,
      `${JSON.stringify({ ts: Date.now(), pid: process.pid, ...event })}\n`,
    );
  } catch {
    /* logging must never take the host down */
  }
}

log({ event: "start", appSocket: APP_SOCKET, hostVersion: HOST_VERSION });

/** @type {import("node:net").Socket|null} */
let appSocket = null;
let appConnected = false;
let shuttingDown = false;

/** @type {Array<{ frame: Record<string, unknown>, timer: NodeJS.Timeout }>} */
const pending = [];
const MAX_PENDING = 64;

/** @param {Record<string, unknown>} frame */
function writeFrame(frame) {
  if (shuttingDown) return;
  try {
    process.stdout.write(encodeFrame(frame));
  } catch (error) {
    process.stderr.write(`stub-host: stdout write failed: ${error}\n`);
    shutdown(0);
  }
}

/** @param {unknown} action */
function actionOf(action) {
  return typeof action === "string" ? action : "";
}

/** @param {Record<string, unknown>} frame */
function logFrame(direction, frame, extra = {}) {
  log({
    event: "frame",
    direction,
    action: actionOf(frame.action),
    bytes: Buffer.byteLength(JSON.stringify(frame)),
    ...extra,
  });
}

/**
 * Host error frame, `protocol/ACTIONS.md` §3.6.
 * @param {string} action
 * @param {string} code
 * @param {string} message
 */
function hostError(action, code, message) {
  writeFrame({
    action,
    error: message,
    errorCode: String(code),
    hostError: true,
  });
  log({ event: "host-error", action, errorCode: String(code) });
}

/** @returns {Record<string, unknown>} */
function statusFields() {
  return {
    protocolVersion: 1,
    hostVersion: HOST_VERSION,
    appRunning: appConnected,
    appVersion: appConnected ? "0.1.0" : null,
    locked: appConnected ? false : null,
    databaseHash: null,
  };
}

/** @param {Record<string, unknown>} frame */
function handleHostAction(frame) {
  const action = frame.action;
  if (action === "ping") {
    /** @type {Record<string, unknown>} */
    const response = { action: "ping", success: "true", ...statusFields() };
    if (typeof frame.nonce === "string") response.nonce = frame.nonce;
    writeFrame(response);
    logFrame("out", response);
    return true;
  }
  if (action === "hello") {
    const response = {
      action: "hello",
      success: "true",
      ...statusFields(),
      sessionId,
      hostPid: process.pid,
    };
    writeFrame(response);
    logFrame("out", response);
    return true;
  }
  return false;
}

/**
 * Queue a forwarded frame while the app socket is connecting, bounded by a
 * short grace period. This mirrors the host's "stays alive while the app is
 * down" contract without allowing unbounded memory growth.
 * @param {Record<string, unknown>} frame
 */
function forwardToApp(frame) {
  if (appConnected && appSocket) {
    appSocket.write(encodeFrame(frame));
    logFrame("ext->app", frame);
    return;
  }

  if (pending.length >= MAX_PENDING) {
    hostError(
      actionOf(frame.action),
      "5",
      "friendlypass app is not running (forward queue full)",
    );
    return;
  }

  const timer = setTimeout(() => {
    const index = pending.findIndex((item) => item.timer === timer);
    if (index >= 0) pending.splice(index, 1);
    if (!appConnected) {
      hostError(
        actionOf(frame.action),
        "5",
        "friendlypass app is not running",
      );
    }
  }, FORWARD_GRACE_MS);

  pending.push({ frame, timer });
  log({ event: "queued", action: actionOf(frame.action) });
}

function flushPending() {
  while (pending.length > 0) {
    const item = pending.shift();
    if (!item) break;
    clearTimeout(item.timer);
    if (appSocket) {
      appSocket.write(encodeFrame(item.frame));
      logFrame("ext->app", item.frame);
    }
  }
}

const stdinDecoder = new FrameDecoder();

process.stdin.on("data", (chunk) => {
  for (const decoded of stdinDecoder.push(chunk)) {
    if (decoded.type === "error") {
      hostError("", decoded.errorCode, decoded.error);
      continue;
    }
    const frame = decoded.value;
    logFrame("ext->host", frame);
    if (!handleHostAction(frame)) forwardToApp(frame);
  }
});

process.stdin.on("end", () => shutdown(0));
process.stdin.on("error", () => shutdown(0));

const appDecoder = new FrameDecoder();
let reconnectDelay = 250;
/** @type {NodeJS.Timeout|null} */
let reconnectTimer = null;

function scheduleReconnect() {
  if (shuttingDown || !APP_SOCKET || reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectToApp();
  }, reconnectDelay);
  log({ event: "reconnect-scheduled", delayMs: reconnectDelay });
  reconnectDelay = Math.min(reconnectDelay * 2, 5000);
}

function connectToApp() {
  if (shuttingDown || !APP_SOCKET) return;

  const socket = net.connect(APP_SOCKET);
  socket.setNoDelay(true);

  socket.on("connect", () => {
    appSocket = socket;
    appConnected = true;
    reconnectDelay = 250;
    log({ event: "app-connected" });
    flushPending();
  });

  socket.on("data", (chunk) => {
    for (const decoded of appDecoder.push(chunk)) {
      if (decoded.type === "error") {
        hostError("", decoded.errorCode, `app sent ${decoded.error}`);
        continue;
      }
      writeFrame(decoded.value);
      logFrame("app->ext", decoded.value);
    }
  });

  socket.on("error", (error) => {
    log({ event: "app-error", code: error.code ?? String(error) });
  });

  socket.on("close", () => {
    if (appSocket === socket) {
      appSocket = null;
      appConnected = false;
      log({ event: "app-disconnected" });
      scheduleReconnect();
    }
  });
}

if (APP_SOCKET) connectToApp();
else log({ event: "no-app-socket" });

/** @param {number} code */
function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  log({ event: "shutdown", code, uptimeMs: Date.now() - startedAt });
  for (const item of pending) clearTimeout(item.timer);
  pending.length = 0;
  if (reconnectTimer) clearTimeout(reconnectTimer);
  try {
    appSocket?.destroy();
  } catch {
    /* ignore */
  }
  // Give the final frame/log a tick to flush, then exit.
  void sleep(10).then(() => process.exit(code));
}

process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));
process.on("uncaughtException", (error) => {
  log({ event: "uncaught", message: String(error) });
  hostError("", HOST_ERROR.HOST_INTERNAL_ERROR, "host internal error");
});
process.on("unhandledRejection", (error) => {
  log({ event: "unhandled-rejection", message: String(error) });
});
