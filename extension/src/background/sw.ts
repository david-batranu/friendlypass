/**
 * friendlypass extension service worker (WP2).
 *
 * Entry point of the MV3 background. It must:
 *   1. register every listener synchronously (no top-level `await`), so a
 *      message that wakes the worker can never race the initialiser;
 *   2. start the idempotent native connection at top level;
 *   3. install the HTTP-auth listener before the first navigation.
 *
 * Build: `npm run build` bundles this file to `dist/background/sw.js`.
 */

import {
  KpxcErrorCode,
  NATIVE_HOST_NAME,
  PushAction,
  SUPPORTED_PROTOCOL_VERSION,
} from "../common/types";
import type {
  ConnectionSnapshot,
  DbHash,
  HostPingResponse,
  HostToExtensionFrame,
  NativeRequestFrame,
  ProtocolError,
  StatusSummary,
} from "../common/types";
import {
  isRecord,
  makeProtocolError,
  onBackgroundMessage,
} from "../common/messages";
import { createNativeTransport } from "./transport";
import type {
  NativeTransport,
  TransportHandlers,
  TransportStateEvent,
} from "./transport";
import { ensureWatchdogAlarm, registerLifecycleListeners } from "./lifecycle";
import { createSession } from "./session";
import type { ProtocolSession } from "./session";
import { createStateStore } from "./state";
import type { StateStore } from "./state";
import {
  createNewGroup,
  generatePassword,
  getDatabaseGroups,
  getLogins,
  getTotp,
  lockDatabase,
  setLogin,
} from "./actions";
import type { ActionContext } from "./actions";
import { installHttpAuthListener } from "./http-auth";

const EXTENSION_VERSION = "0.1.0";

let transport: NativeTransport | null = null;
let stateStore: StateStore | null = null;
let protocolSession: ProtocolSession | null = null;
let bootstrapped = false;

// ---------------------------------------------------------------------------
// Lazy WP3 wiring
//
// WP3 lands in parallel. Constructing its modules lazily keeps a partially
// merged tree from killing the service worker before the transport exists, and
// still uses only the exported signatures declared in the scaffold.
// ---------------------------------------------------------------------------

function getTransport(): NativeTransport {
  if (transport === null) {
    throw new Error("Native transport has not been initialised");
  }
  return transport;
}

function getStateStore(): StateStore {
  if (stateStore === null) {
    stateStore = createStateStore();
  }
  return stateStore;
}

function getSession(): ProtocolSession {
  if (protocolSession === null) {
    const store = getStateStore();
    protocolSession = createSession({
      send: (frame: unknown, timeoutMs?: number) =>
        getTransport().request(frame as NativeRequestFrame, timeoutMs),
      loadKeyRing: async () => {
        const ring = await store.keyRing();
        const result: Record<DbHash, { id: string; key: string }> = {};
        for (const [hash, record] of Object.entries(ring)) {
          result[hash] = { id: record.id, key: record.key };
        }
        return result;
      },
      saveAssociation: async (hash: DbHash, id: string, key: string) => {
        const now = Date.now();
        await store.putAssociation(hash, {
          id,
          key,
          hash,
          created: now,
          lastUsed: now,
        });
      },
      onSnapshot: (snapshot: ConnectionSnapshot) => {
        try {
          store.setSnapshot(snapshot);
        } catch (cause) {
          debug("state", `cannot persist snapshot: ${messageOf(cause)}`);
        }
      },
    });
  }
  return protocolSession;
}

function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

function debug(action: string, message: string): void {
  // Never pass frames, inner messages or credentials to this helper.
  console.debug(`[friendlypass] ${action}: ${message}`);
}

function fail(protocol: ProtocolError): never {
  throw protocolError(protocol);
}

function protocolError(protocol: ProtocolError): Error {
  const error = new Error(protocol.message) as Error & {
    code?: number;
    retryable?: boolean;
  };
  error.name = protocol.name;
  error.code = protocol.code;
  error.retryable = protocol.retryable;
  return error;
}

async function usableSnapshot(triggerUnlock = false): Promise<ConnectionSnapshot> {
  const snapshot = await getSession().ensureSession({ triggerUnlock });
  if (snapshot.lastError) {
    fail(snapshot.lastError);
  }
  if (!snapshot.appRunning) {
    fail(makeProtocolError(KpxcErrorCode.TIMEOUT_OR_NOT_CONNECTED, "friendlypass is not running"));
  }
  if (snapshot.locked) {
    fail(makeProtocolError(KpxcErrorCode.DATABASE_NOT_OPENED));
  }
  return snapshot;
}

async function actionContext(snapshot?: ConnectionSnapshot): Promise<ActionContext> {
  const store = getStateStore();
  const current = snapshot ?? store.snapshot();
  const persisted = await store.load();
  const ring = await store.keyRing();
  const hash = current.databaseHash;
  const association = hash ? ring[hash] : undefined;

  return {
    clientID: persisted.clientId ?? "",
    dbHash: hash ?? "",
    association: association
      ? { id: association.id, key: association.key }
      : null,
  };
}

function currentStatus(): StatusSummary {
  try {
    return getStateStore().status();
  } catch {
    // WP3 not merged yet: keep the connection status visible.
    const status = getTransport().status;
    return {
      connected: status.connected,
      appRunning: status.appRunning,
      databaseOpen: false,
      locked: !status.appRunning,
      associated: false,
      databaseHash: null,
      state: status.state,
      hostVersion: status.hostVersion,
      appVersion: status.appVersion,
      protocolVersion: status.protocolVersion,
      error: status.lastError,
    };
  }
}

// ---------------------------------------------------------------------------
// Transport callbacks
// ---------------------------------------------------------------------------

function handleFrame(frame: HostToExtensionFrame): void {
  if (!isRecord(frame) || typeof frame.action !== "string") {
    return;
  }
  const action = frame.action;
  if (
    action !== PushAction.DATABASE_LOCKED &&
    action !== PushAction.DATABASE_UNLOCKED &&
    action !== PushAction.DATABASE_CHANGED
  ) {
    // Responses are correlated by `transport.request()`; pushes are the only
    // frames the service worker itself needs to act on.
    return;
  }

  try {
    const session = getSession();
    session.reset(`push:${action}`);
    if (action !== PushAction.DATABASE_LOCKED) {
      // `database-unlocked` and `database-changed` may have changed the hash;
      // revalidating in the background needs no user action.
      void session.ensureSession().catch((cause: unknown) => {
        debug("session", `revalidation after ${action} failed: ${messageOf(cause)}`);
      });
    }
  } catch (cause) {
    debug("session", `cannot handle ${action}: ${messageOf(cause)}`);
  }
  ensureWatchdogAlarm();
}

function handleConnect(): void {
  debug("transport", "native port opened");
}

function handleDisconnect(reason: string, detail?: string): void {
  debug("transport", `native port lost (${reason})${detail ? `: ${detail}` : ""}`);
  if (protocolSession !== null) {
    try {
      protocolSession.reset(`transport:${reason}`);
    } catch (cause) {
      debug("session", `reset after disconnect failed: ${messageOf(cause)}`);
    }
  }
}

function handleTransportState(event: TransportStateEvent): void {
  try {
    const store = getStateStore();
    const snapshot = store.snapshot();
    const patch: Partial<ConnectionSnapshot> = {};

    switch (event.type) {
      case "connecting":
        patch.state = "CONNECTING";
        break;
      case "connected":
        patch.appRunning = event.hello.appRunning;
        patch.hostVersion = event.hello.hostVersion;
        patch.appVersion = event.hello.appVersion;
        patch.protocolVersion = event.hello.protocolVersion;
        if (snapshot.state === "DISCONNECTED") {
          patch.state = "READY";
        }
        break;
      case "appDown":
        patch.appRunning = false;
        break;
      case "appUp":
        patch.appRunning = true;
        patch.lastError = null;
        break;
      case "disconnected":
        patch.state = "DISCONNECTED";
        patch.appRunning = false;
        patch.associated = false;
        patch.lastError = event.error;
        break;
    }

    store.setSnapshot({ ...snapshot, ...patch });
  } catch {
    // WP3 state store not available yet; status falls back to transport.
  }

  if (event.type === "appUp") {
    // Recovery must not wait for the user: rebuild the session in the
    // background as soon as the app starts answering.
    try {
      void getSession().ensureSession().catch((cause: unknown) => {
        debug("session", `recovery handshake failed: ${messageOf(cause)}`);
      });
    } catch (cause) {
      debug("session", `cannot start recovery handshake: ${messageOf(cause)}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Internal message API (the surface WP4/WP5/WP6 call)
// ---------------------------------------------------------------------------

type BackgroundHandlers = Parameters<typeof onBackgroundMessage>[0];

function registerBackgroundMessageHandlers(): void {
  const handlers: BackgroundHandlers = {
    "status.get": async () => currentStatus(),

    "status.refresh": async (args) => {
      const triggerUnlock =
        typeof args === "object" && args !== null && args.triggerUnlock === true;
      await getSession().ensureSession({ triggerUnlock });
      return currentStatus();
    },

    "connection.connect": async () => {
      await getTransport().connect();
      await getSession().ensureSession();
      return currentStatus();
    },

    "connection.reconnect": async () => {
      getTransport().disconnect();
      protocolSession?.reset("manual-reconnect");
      await getTransport().connect();
      await getSession().ensureSession();
      return currentStatus();
    },

    "connection.ping": async (): Promise<HostPingResponse> => getTransport().ping(),

    "logins.get": async (args) => {
      const snapshot = await usableSnapshot(args.triggerUnlock === true);
      const context = await actionContext(snapshot);
      const ring = await getStateStore().keyRing();
      const keys = Object.values(ring).map((record) => ({
        id: record.id,
        key: record.key,
      }));
      return getLogins(context, {
        url: args.url,
        ...(args.submitUrl ? { submitUrl: args.submitUrl } : {}),
        ...(args.httpAuth ? { httpAuth: true } : {}),
        keys,
      });
    },

    "logins.save": async (args) => {
      const snapshot = await usableSnapshot(true);
      return setLogin(await actionContext(snapshot), args);
    },

    "totp.get": async (args) => {
      const snapshot = await usableSnapshot();
      try {
        return await getTotp(await actionContext(snapshot), args.uuid);
      } catch (cause) {
        if (args.fallback !== undefined && args.fallback !== "") {
          return args.fallback;
        }
        throw cause;
      }
    },

    "password.generate": async () => {
      const snapshot = await usableSnapshot();
      return generatePassword(await actionContext(snapshot));
    },

    "groups.list": async () => {
      const snapshot = await usableSnapshot();
      return getDatabaseGroups(await actionContext(snapshot));
    },

    "group.create": async (args) => {
      const snapshot = await usableSnapshot(true);
      return createNewGroup(await actionContext(snapshot), args.name);
    },

    "database.lock": async () => {
      const snapshot = await usableSnapshot();
      await lockDatabase(await actionContext(snapshot));
      return currentStatus();
    },

    "database.unlock": async () => {
      await getSession().ensureSession({ triggerUnlock: true });
      return currentStatus();
    },

    // WP5 owns the HTTP-auth picker; the background surface exists so the
    // listener can land without another WP2 change.
    "httpAuth.lookup": async () => null,
    "httpAuth.choose": async () => null,

    "settings.get": async () => getStateStore().getSettings(),
    "settings.set": async (args) => getStateStore().setSettings(args),
    "diagnostics.get": async () => getStateStore().diagnostics(),
  };

  onBackgroundMessage(handlers);
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

export function bootstrap(): void {
  if (bootstrapped) {
    return;
  }
  bootstrapped = true;

  const transportHandlers: TransportHandlers = {
    onFrame: handleFrame,
    onConnect: handleConnect,
    onDisconnect: handleDisconnect,
    onStateChange: handleTransportState,
  };

  transport = createNativeTransport(transportHandlers, {
    extensionVersion: EXTENSION_VERSION,
    clientId: () => {
      // WP3 persists the stable clientID; tolerate its absence during startup.
      return null;
    },
  });

  // All of the following registration is synchronous: a message that wakes
  // the worker can never arrive before the listeners exist.
  registerLifecycleListeners({
    connect: () => getTransport().connect().then(() => undefined),
    shutdown: () => {
      protocolSession?.reset("shutdown");
      getTransport().disconnect();
    },
  });

  registerBackgroundMessageHandlers();

  try {
    installHttpAuthListener();
  } catch (cause) {
    // WP5 lands in parallel; this is expected until then.
    debug("http-auth", `listener not installed yet: ${messageOf(cause)}`);
  }

  ensureWatchdogAlarm();

  console.info(
    `[friendlypass] service worker loaded (protocol v${SUPPORTED_PROTOCOL_VERSION}, host ${NATIVE_HOST_NAME})`,
  );

  void getTransport()
    .connect()
    .catch((cause: unknown) => {
      debug("transport", `initial connect failed: ${messageOf(cause)}`);
    });
}

bootstrap();
