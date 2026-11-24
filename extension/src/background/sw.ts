/**
 * friendlypass extension service worker (WP2 + WP3 integration).
 *
 * Entry point of the MV3 background. It must:
 *   1. register every listener synchronously (no top-level `await`), so a
 *      message that wakes the worker can never race the initialiser;
 *   2. create the state store, the protocol session and the native transport
 *      in WP3's order (`createStateStore` → `createSession` →
 *      `createNativeTransport(session.transportHandlers)`) and start the
 *      idempotent connection;
 *   3. install the HTTP-auth listener before the first navigation.
 *
 * Build: `npm run build` bundles this file to `dist/background/sw.js`.
 */

import {
  KpxcErrorCode,
  INTERNAL_CHANNEL,
  NATIVE_HOST_NAME,
  SUPPORTED_PROTOCOL_VERSION,
} from "../common/types";
import type {
  BackgroundRequestAction,
  BackgroundRequestArgs,
  BackgroundRequestResult,
  ConnectionSnapshot,
  HostPingResponse,
  ProtocolError,
  StatusSummary,
} from "../common/types";
import {
  makeProtocolError,
  newRequestId,
  onBackgroundMessage,
  sendContentCommand,
} from "../common/messages";
import { createNativeTransport } from "./transport";
import type { NativeTransport, TransportStateEvent } from "./transport";
import { ensureWatchdogAlarm, registerLifecycleListeners } from "./lifecycle";
import { createSession } from "./session";
import type { ProtocolSession } from "./session";
import { broadcastEvent } from "./broadcast";
import { createStateStore, normaliseOrigin, upsertSiteException } from "./state";
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
import {
  installHttpAuthListener,
  migrateHttpAuthAutoFill,
  setHttpAuthSettingsBridge,
} from "./http-auth";
import { createPendingStore, readPendingTtlMs } from "./pending";
import type { PendingStore } from "./pending";

const EXTENSION_VERSION = "0.1.0";

let transport: NativeTransport | null = null;
let stateStore: StateStore | null = null;
let protocolSession: ProtocolSession | null = null;
let cachedClientId: string | null = null;
let bootstrapped = false;
let started = false;
let pendingStore: PendingStore | null = null;

/**
 * Unhandled rejections observed in this service worker. The e2e suite reads
 * this through the debug bridge below; it keeps working across an SW wake-up
 * for the lifetime of the worker.
 */
const rejectionLog: string[] = [];

// ---------------------------------------------------------------------------
// Lazy accessors
// ---------------------------------------------------------------------------

function getStateStore(): StateStore {
  if (stateStore === null) {
    stateStore = createStateStore({
      // WP6c: the one `settings.changed` path. It reaches extension pages and
      // every content-script frame; the old storage.onChanged fan-out is gone.
      broadcastSettings: (settings) =>
        broadcastEvent("settings.changed", settings),
    });
  }
  return stateStore;
}

/**
 * A transport facade that lets the session be constructed before the native
 * port exists. `session.transportHandlers` needs the session, and the session
 * needs a `NativeTransport`; the facade breaks the cycle without weakening
 * either half (every call is forwarded to the real implementation).
 */
function createTransportFacade(): NativeTransport {
  const impl = (): NativeTransport => {
    if (transport === null) {
      throw new Error("Native transport has not been initialised");
    }
    return transport;
  };
  return {
    get connected() {
      return transport?.connected ?? false;
    },
    get state() {
      return transport?.state ?? "DISCONNECTED";
    },
    get appRunning() {
      return transport?.appRunning ?? false;
    },
    get hello() {
      return transport?.hello ?? null;
    },
    get status() {
      return impl().status;
    },
    connect: () => impl().connect(),
    disconnect: () => impl().disconnect(),
    ping: () => impl().ping(),
    send: (frame) => impl().send(frame),
    request: (frame, timeoutMs) => impl().request(frame, timeoutMs),
  };
}

function getTransport(): NativeTransport {
  if (transport === null) {
    throw new Error("Native transport has not been initialised");
  }
  return transport;
}

function getSession(): ProtocolSession {
  if (protocolSession === null) {
    protocolSession = createSession({
      transport: createTransportFacade(),
      store: getStateStore(),
    });
  }
  return protocolSession;
}

/**
 * Pending submitted-credential store (WP4b). Lazily created so this module can
 * be imported without `chrome` (unit tests build the store themselves).
 */
function getPendingStore(): PendingStore {
  if (pendingStore === null) {
    pendingStore = createPendingStore({
      storage: chrome.storage.session,
      neverStorage: chrome.storage.local,
      ttlMs: () => readPendingTtlMs(chrome.storage.local),
    });
  }
  return pendingStore;
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
  const session = getSession();
  const store = getStateStore();
  const current = snapshot ?? store.snapshot();
  const ring = await store.keyRing();
  const hash = current.databaseHash;
  const association = hash ? ring[hash] : undefined;
  const clientID = cachedClientId ?? (await session.getClientId());

  return {
    session,
    clientID,
    dbHash: hash ?? "",
    association: association
      ? { id: association.id, key: association.key }
      : null,
  };
}

function currentStatus(): StatusSummary {
  return getStateStore().status();
}

// ---------------------------------------------------------------------------
// Transport callbacks
// ---------------------------------------------------------------------------

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
  } catch (cause) {
    debug("state", `cannot update connection snapshot: ${messageOf(cause)}`);
  }

  if (event.type === "appUp") {
    // Recovery must not wait for the user: rebuild the session in the
    // background as soon as the app starts answering again.
    void getSession()
      .ensureSession()
      .catch((cause: unknown) => {
        debug("session", `recovery handshake failed: ${messageOf(cause)}`);
      });
  }
}

// ---------------------------------------------------------------------------
// Internal message API (the surface WP4/WP5/WP6 call)
// ---------------------------------------------------------------------------

type BackgroundHandlers = Parameters<typeof onBackgroundMessage>[0];

function buildBackgroundHandlers(): BackgroundHandlers {
  return {
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

    "association.create": async () => getSession().associate(),

    "logins.get": async (args) => {
      const snapshot = await usableSnapshot(args.triggerUnlock === true);
      return getLogins(await actionContext(snapshot), {
        url: args.url,
        ...(args.submitUrl ? { submitUrl: args.submitUrl } : {}),
        ...(args.httpAuth ? { httpAuth: true } : {}),
        ...(args.triggerUnlock ? { triggerUnlock: true } : {}),
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

    // WP4b: the content script's submitted-credential hand-off. The tab id
    // comes from the browser-provided sender, never from the page.
    "submit.store": async (args, sender) => {
      const tabId = sender.tab?.id;
      if (typeof tabId !== "number") {
        return { stored: false };
      }
      const stored = await getPendingStore().store({
        tabId,
        ...(typeof sender.frameId === "number" ? { frameId: sender.frameId } : {}),
        url: typeof args.url === "string" ? args.url : "",
        username: typeof args.username === "string" ? args.username : "",
        password: typeof args.password === "string" ? args.password : "",
        ...(typeof args.submitUrl === "string" && args.submitUrl
          ? { submitUrl: args.submitUrl }
          : {}),
      });
      return { stored };
    },

    "submit.pending": async (args, sender) => {
      const tabId = sender.tab?.id;
      if (typeof tabId !== "number") {
        return null;
      }
      return getPendingStore().take({
        tabId,
        ...(typeof sender.frameId === "number" ? { frameId: sender.frameId } : {}),
        url: typeof args.url === "string" ? args.url : "",
      });
    },

    "submit.clear": async (_args, sender) => {
      const tabId = sender.tab?.id;
      if (typeof tabId === "number") {
        await getPendingStore().clear(tabId);
      }
    },

    "submit.never": async (args, sender) => {
      const requested =
        typeof args.origin === "string" && args.origin
          ? args.origin
          : (sender.url ?? "");
      const origin = normaliseOrigin(requested);
      if (origin !== null) {
        await getPendingStore().never(origin);
        // WP6c: persist the opt-out in the unified settings too, merging with
        // any existing flags for this origin. The options page lists and can
        // remove it; the content scripts apply it on the next page load.
        const store = getStateStore();
        const current = await store.getSettings();
        await store.setSettings({
          siteExceptions: upsertSiteException(current.siteExceptions, origin, {
            disableSave: true,
          }),
        });
      }
      const tabId = sender.tab?.id;
      if (typeof tabId === "number") {
        await getPendingStore().clear(tabId);
      }
    },

    "tab.fillLogin": async (args, sender) => {
      if (!isPopupSender(sender)) {
        throw new Error("tab.fillLogin is only available from extension pages");
      }
      return fillTabFromPopup(args);
    },

    "popup.open": async (_args, sender) => openPopupForTab(sender.tab?.id),
  };
}

/**
 * Test/diagnostics bridge.
 *
 * Reachable only from the extension's own service-worker context (Playwright
 * `worker.evaluate`, the DevTools console). It dispatches through exactly the
 * same handlers the popup uses, so the e2e suite exercises the real code path
 * without a hidden production backdoor: content scripts and web pages cannot
 * reach a service-worker global.
 */
interface DebugBridge {
  request<A extends BackgroundRequestAction>(
    action: A,
    args?: BackgroundRequestArgs<A>,
  ): Promise<BackgroundRequestResult<A>>;
  rejections(): string[];
  popupStats(): PopupOpenStats;
}

function installDebugBridge(handlers: BackgroundHandlers): void {
  const debugBridge: DebugBridge = {
    async request(action, args) {
      const handler = (handlers as unknown as Record<
        string,
        (value: unknown) => unknown
      >)[action];
      if (typeof handler !== "function") {
        throw new Error(`No internal handler for "${action}"`);
      }
      return (await handler(args)) as BackgroundRequestResult<typeof action>;
    },
    rejections() {
      return [...rejectionLog];
    },
    popupStats() {
      return { ...popupOpenStats };
    },
  };
  (globalThis as unknown as { __friendlypassDebug?: DebugBridge }).__friendlypassDebug =
    debugBridge;
}

// ---------------------------------------------------------------------------
// WP4 content-script integration (owned by WP4; keep this block self-contained)
// ---------------------------------------------------------------------------

/**
 * `Ctrl/Cmd+Shift+L` (manifest `commands.fill-login`): resolve the active tab's
 * URL through the normal `get-logins` path and ask every frame's content
 * script to fill the best combination. Errors are logged as text only; the
 * entry (which contains a password) is never logged.
 */
function fillActiveTabFromCommand(): void {
  void (async () => {
    try {
      const [tab] = await chrome.tabs.query({
        active: true,
        lastFocusedWindow: true,
      });
      const tabId = tab?.id;
      const url = tab?.url;
      if (typeof tabId !== "number" || typeof url !== "string" || !/^https?:/i.test(url)) {
        return;
      }

      const snapshot = await usableSnapshot();
      const entries = await getLogins(await actionContext(snapshot), { url });
      const entry = entries[0];
      if (!entry) {
        return;
      }
      await sendContentCommand(tabId, "content.fillLogin", { entry });
    } catch (cause) {
      debug("command.fill-login", messageOf(cause));
    }
  })();
}

// ---------------------------------------------------------------------------
// WP6b — in-page UI commands (settings fan-out lives in broadcast.ts)
// ---------------------------------------------------------------------------
//
// These are deliberately self-contained: WP6a owns the settings types and the
// popup/options, so this block speaks the shared raw internal envelope instead
// of extending `ContentCommandMap`/`BackgroundEventMap`.

/** Fire-and-forget raw internal command to every frame of a tab. */
function sendWp6bContentCommand(tabId: number, action: string): void {
  const envelope = {
    channel: INTERNAL_CHANNEL,
    action,
    args: undefined,
    requestId: newRequestId(),
  };
  try {
    chrome.tabs.sendMessage(tabId, envelope, () => {
      // No content script in this tab (or it navigated): expected.
      void chrome.runtime.lastError;
    });
  } catch {
    // A missing tab/frame is not worth surfacing.
  }
}

async function activeHttpTab(): Promise<{ tabId: number } | null> {
  const [tab] = await chrome.tabs.query({
    active: true,
    lastFocusedWindow: true,
  });
  if (
    typeof tab?.id !== "number" ||
    typeof tab.url !== "string" ||
    !/^https?:/i.test(tab.url)
  ) {
    return null;
  }
  return { tabId: tab.id };
}

/** `Ctrl/Cmd+Shift+K`: open the inline menu for the focused field. */
function openInlineMenuFromCommand(): void {
  void (async () => {
    const target = await activeHttpTab();
    if (target) {
      sendWp6bContentCommand(target.tabId, "content.openInlineMenu");
    }
  })().catch((cause: unknown) => {
    debug("command.open-inline-menu", messageOf(cause));
  });
}

/** `Ctrl/Cmd+Shift+G`: generate a password into the focused field. */
function generatePasswordFromCommand(): void {
  void (async () => {
    const target = await activeHttpTab();
    if (target) {
      sendWp6bContentCommand(target.tabId, "content.generatePassword");
    }
  })().catch((cause: unknown) => {
    debug("command.generate-password", messageOf(cause));
  });
}

/**
 * Content scripts must see lock/unlock/app-down transitions without a reload.
 * Extension pages are covered by the state store's own `sendBackgroundEvent`;
 * this adds the per-tab delivery. `settings.changed` does not use this path:
 * it is emitted once by the state store's `broadcastSettings` (WP6c).
 */
function installStatusTabBroadcast(): void {
  try {
    getStateStore().subscribe((next) => {
      broadcastEvent("status.changed", next);
    });
  } catch (cause) {
    debug("status", `tab broadcast not installed: ${messageOf(cause)}`);
  }
}

/** Registered synchronously by `bootstrap()`; a command may wake the worker. */
function installContentCommandListener(): void {
  try {
    chrome.commands.onCommand.addListener((command) => {
      if (command === "fill-login") {
        fillActiveTabFromCommand();
        return;
      }
      // --- WP6b commands -------------------------------------------------
      if (command === "open-inline-menu") {
        openInlineMenuFromCommand();
        return;
      }
      if (command === "generate-password") {
        generatePasswordFromCommand();
      }
    });
  } catch (cause) {
    debug("command", `listener not installed: ${messageOf(cause)}`);
  }

  // --- WP6b: status tab fan-out (settings use the state store path) --------
  installStatusTabBroadcast();
}

// ---------------------------------------------------------------------------
// WP6a — popup/options support (owner: WP6a; keep edits inside this block)
// ---------------------------------------------------------------------------

interface PopupOpenStats {
  attempts: number;
  action: number;
  fallback: number;
  failed: number;
  lastError: string | null;
}

const popupOpenStats: PopupOpenStats = {
  attempts: 0,
  action: 0,
  fallback: 0,
  failed: 0,
  lastError: null,
};

/** How long `action.openPopup()` may hang before the fallback window is used. */
const POPUP_OPEN_TIMEOUT_MS = 750;

/**
 * Open the action popup for the tab that asked (WP6c). Recent Chrome exposes
 * `chrome.action.openPopup()`; where it is unavailable, rejects because the
 * user-gesture token did not survive the content-script message, or never
 * settles in headless mode, open the same page in a small popup window
 * instead, scoped to that tab.
 */
async function openPopupForTab(
  tabId?: number,
): Promise<{ opened: boolean; via: "action" | "fallback" }> {
  popupOpenStats.attempts += 1;
  const actionApi = chrome.action as unknown as {
    openPopup?: () => Promise<void>;
  };
  if (typeof actionApi.openPopup === "function") {
    const pending = actionApi.openPopup();
    let timer: number | null = null;
    const timedOut = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), POPUP_OPEN_TIMEOUT_MS);
    });
    try {
      const outcome = await Promise.race([
        pending.then(() => "opened" as const),
        timedOut,
      ]);
      if (outcome === "opened") {
        popupOpenStats.action += 1;
        return { opened: true, via: "action" };
      }
      popupOpenStats.lastError = "action.openPopup did not settle";
      pending.catch(() => undefined);
    } catch (cause) {
      popupOpenStats.lastError = messageOf(cause);
      debug("popup", `action.openPopup unavailable: ${popupOpenStats.lastError}`);
    } finally {
      if (timer !== null) {
        clearTimeout(timer);
      }
    }
  }
  try {
    const base = chrome.runtime.getURL("popup/popup.html");
    const url =
      typeof tabId === "number" ? `${base}?tab=${encodeURIComponent(tabId)}` : base;
    await chrome.windows.create({
      url,
      type: "popup",
      width: 380,
      height: 620,
      focused: true,
    });
    popupOpenStats.fallback += 1;
    return { opened: true, via: "fallback" };
  } catch (cause) {
    popupOpenStats.failed += 1;
    popupOpenStats.lastError = messageOf(cause);
    debug("popup", `fallback window failed: ${popupOpenStats.lastError}`);
    return { opened: false, via: "fallback" };
  }
}

/** True when a message came from our own popup page (not a content script). */
function isPopupSender(sender: chrome.runtime.MessageSender): boolean {
  const base =
    typeof chrome.runtime.getURL === "function" ? chrome.runtime.getURL("") : "";
  const url = sender.url ?? "";
  return base.length > 0 && url.startsWith(`${base}popup/`);
}

/**
 * Fill one tab on the popup's behalf. The entry comes from this service
 * worker's own `logins.get` result; nothing is logged here.
 */
async function fillTabFromPopup(
  args: BackgroundRequestArgs<"tab.fillLogin">,
): Promise<BackgroundRequestResult<"tab.fillLogin">> {
  const tabId = Number(args?.tabId);
  if (!Number.isInteger(tabId) || tabId < 0) {
    throw new Error("Invalid tab id");
  }
  const entry = args?.entry;
  if (
    !entry ||
    typeof entry !== "object" ||
    typeof entry.uuid !== "string" ||
    typeof entry.login !== "string" ||
    typeof entry.password !== "string"
  ) {
    throw new Error("Invalid login entry");
  }
  const result = await sendContentCommand(tabId, "content.fillLogin", { entry });
  return { delivered: result.ok };
}

// `httpAuthAutoFill` is part of the unified settings (WP6a). Register the
// bridge here so it is in place before `bootstrap()` installs the HTTP-auth
// listener, and migrate the pre-WP6a value exactly once.
const wp6aSettingsStore = getStateStore();
const wp6aSettingsBridge = {
  getAutoFill: async () =>
    (await wp6aSettingsStore.getSettings()).httpAuthAutoFill,
  setAutoFill: async (value: boolean) => {
    await wp6aSettingsStore.setSettings({ httpAuthAutoFill: value });
  },
};
setHttpAuthSettingsBridge(wp6aSettingsBridge);
void migrateHttpAuthAutoFill({
  bridge: wp6aSettingsBridge,
  log: (event, detail) => debug(event, detail ?? ""),
}).catch((cause: unknown) => {
  debug("settings", `http-auth migration failed: ${messageOf(cause)}`);
});

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

export function bootstrap(): void {
  if (bootstrapped) {
    return;
  }
  bootstrapped = true;

  const session = getSession();
  const store = getStateStore();

  transport = createNativeTransport(
    {
      ...session.transportHandlers,
      onStateChange: handleTransportState,
    },
    {
      extensionVersion: EXTENSION_VERSION,
      clientId: () => cachedClientId,
    },
  );

  // Resolve the stable clientID before any connect so every `hello` carries
  // it; listeners registered below wait for this promise.
  const ready = start(session, store);

  // All of the following registration is synchronous: a message that wakes
  // the worker can never arrive before the listeners exist.
  registerLifecycleListeners({
    connect: () =>
      ready.then(() => getTransport().connect()).then(() => undefined),
    shutdown: () => {
      protocolSession?.reset("shutdown");
      getTransport().disconnect();
    },
  });

  const handlers = buildBackgroundHandlers();
  onBackgroundMessage(handlers);
  installDebugBridge(handlers);
  installContentCommandListener();

  try {
    installHttpAuthListener({ logins: getLogins, snapshot: usableSnapshot, context: actionContext });
  } catch (cause) {
    // WP5 lands in parallel; this is expected until then.
    debug("http-auth", `listener not installed yet: ${messageOf(cause)}`);
  }

  ensureWatchdogAlarm();

  console.info(
    `[friendlypass] service worker loaded (protocol v${SUPPORTED_PROTOCOL_VERSION}, host ${NATIVE_HOST_NAME})`,
  );

  // `start()` is already running (see above) and logs its own failures; this
  // keeps the rejection from becoming an unhandled promise.
  void ready.catch((cause: unknown) => {
    debug("transport", `startup failed: ${messageOf(cause)}`);
  });
}

async function start(session: ProtocolSession, store: StateStore): Promise<void> {
  if (started) {
    return;
  }
  started = true;
  try {
    cachedClientId = await session.getClientId();
  } catch (cause) {
    debug("state", `cannot read the stable clientID: ${messageOf(cause)}`);
  }
  try {
    // `chrome.storage.local` may still be loading the persisted keyring; the
    // session fetches it again per handshake, so a connect here is safe.
    void store.load().catch(() => undefined);
    await getTransport().connect();
  } catch (cause) {
    debug("transport", `initial connect failed: ${messageOf(cause)}`);
  }
}

if (typeof self !== "undefined" && typeof self.addEventListener === "function") {
  self.addEventListener("unhandledrejection", (event) => {
    const reason = (event as PromiseRejectionEvent).reason;
    rejectionLog.push(messageOf(reason));
    if (rejectionLog.length > 50) {
      rejectionLog.shift();
    }
  });
}

bootstrap();
