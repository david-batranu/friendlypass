/**
 * friendlypass toolbar popup (WP6a).
 *
 * Shows the live connection status, the logins that match the current tab,
 * a password generator, and a compact diagnostics disclosure.
 *
 * Rules:
 *  - status comes from `status.get` once and then from `status.changed`
 *    events; there is no polling;
 *  - every action goes through the typed internal message API — this page
 *    never touches the native port, the protocol or `chrome.storage` directly;
 *  - this page holds plaintext credentials in memory (it must, to copy them);
 *    they are never written to storage, the console or the DOM as HTML.
 */

import { onBackgroundEvent, sendBackgroundMessage } from "../common/messages";
import { getTab, queryTabs, type TabLike } from "../common/platform";
import type {
  CredentialEntry,
  DiagnosticsSnapshot,
  ExtensionSettings,
  SiteException,
  StatusSummary,
} from "../common/types";

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`popup: missing #${id}`);
  }
  return element as T;
}

interface ElementOptions {
  className?: string;
  text?: string;
  title?: string;
  attrs?: Record<string, string>;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  options: ElementOptions = {},
  children: Array<Node | string> = [],
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (options.className) element.className = options.className;
  if (options.text !== undefined) element.textContent = options.text;
  if (options.title) element.title = options.title;
  for (const [name, value] of Object.entries(options.attrs ?? {})) {
    element.setAttribute(name, value);
  }
  for (const child of children) {
    element.append(child);
  }
  return element;
}

function button(
  label: string,
  action: string,
  onClick: () => void,
  extra: { className?: string; title?: string; disabled?: boolean } = {},
): HTMLButtonElement {
  const element = el("button", {
    className: `fp-button fp-button--small ${extra.className ?? ""}`.trim(),
    text: label,
    attrs: {
      type: "button",
      "data-action": action,
      ...(extra.title ? { title: extra.title, "aria-label": extra.title } : {}),
    },
  });
  element.disabled = extra.disabled === true;
  element.addEventListener("click", onClick);
  return element;
}

// ---------------------------------------------------------------------------
// Message helpers
// ---------------------------------------------------------------------------

function failureText(error: { message?: unknown; code?: unknown } | undefined): string {
  const message =
    typeof error?.message === "string" && error.message.length > 0
      ? error.message
      : "friendlypass did not answer";
  return message;
}

// ---------------------------------------------------------------------------
// Clipboard (write + best-effort clear after 30 s)
// ---------------------------------------------------------------------------

/** Default clipboard lifetime for copied credentials. */
const CLIPBOARD_CLEAR_MS = 30_000;

/**
 * Optional `?clipboardClearMs=` override (clamped). Used by the e2e suite so
 * the 30 s clear can be observed without a 30 s test.
 */
function clipboardClearDelay(): number {
  const raw = new URLSearchParams(location.search).get("clipboardClearMs");
  if (raw === null) return CLIPBOARD_CLEAR_MS;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) return CLIPBOARD_CLEAR_MS;
  return Math.min(60_000, Math.max(250, value));
}

let copyTimer: number | null = null;
let lastCopy: { text: string; label: string; at: number } | null = null;
let clipboardCleared = false;
let clipboardClearedAt: number | null = null;

async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for contexts without the async clipboard API.
    try {
      const area = el("textarea", { attrs: { readonly: "readonly" } });
      area.value = text;
      area.style.position = "fixed";
      area.style.top = "-1000px";
      area.style.opacity = "0";
      document.body.append(area);
      area.select();
      const ok = document.execCommand("copy");
      area.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

async function clearClipboardIfUnchanged(text: string): Promise<void> {
  if (lastCopy === null || lastCopy.text !== text) {
    return;
  }
  let current: string | null = null;
  try {
    current = await navigator.clipboard.readText();
  } catch {
    current = null;
  }
  if (current !== null) {
    if (current !== text) {
      // The user copied something else in the meantime; leave it alone.
      return;
    }
  } else if (document.visibilityState !== "visible" && !document.hasFocus()) {
    // Without read permission we cannot verify the clipboard, so only clear
    // while this page is still in front of the user.
    return;
  }
  if (await writeClipboard("")) {
    clipboardCleared = true;
    clipboardClearedAt = Date.now();
  }
}

async function copyValue(text: string, label: string): Promise<boolean> {
  const ok = await writeClipboard(text);
  lastCopy = { text, label, at: Date.now() };
  clipboardCleared = false;
  clipboardClearedAt = null;
  if (copyTimer !== null) {
    window.clearTimeout(copyTimer);
  }
  copyTimer = window.setTimeout(() => {
    copyTimer = null;
    void clearClipboardIfUnchanged(text);
  }, clipboardClearDelay());
  return ok;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

interface LoginListState {
  loading: boolean;
  entries: CredentialEntry[];
  error: string | null;
}

const state: {
  tabId: number | null;
  url: string | null;
  pageTitle: string | null;
  status: StatusSummary | null;
  diagnostics: DiagnosticsSnapshot | null;
  settings: ExtensionSettings | null;
  logins: LoginListState;
} = {
  tabId: null,
  url: null,
  pageTitle: null,
  status: null,
  diagnostics: null,
  settings: null,
  logins: { loading: false, entries: [], error: null },
};

const statusHeader = byId("status");
const statusTitle = byId("status-title");
const statusDetail = byId("status-detail");
const statusAction = byId<HTMLButtonElement>("status-action");
const statusIndicator = byId("status-indicator");
const searchWrap = byId("search-wrap");
const searchInput = byId<HTMLInputElement>("search");
const loginsContainer = byId("logins");
const announcer = byId("announcer");
const generateRow = byId("generate-row");
const generateValue = byId<HTMLOutputElement>("generate-value");
const generateToggle = byId<HTMLButtonElement>("generate-toggle");
const generateCopy = byId<HTMLButtonElement>("generate-copy");
const generateRegenerate = byId<HTMLButtonElement>("generate-regenerate");
const generateError = byId("generate-error");
const lockButton = byId<HTMLButtonElement>("lock-database");
const diagnostics = byId<HTMLDetailsElement>("diagnostics");
const diagHost = byId("diag-host");
const diagApp = byId("diag-app");
const diagProtocol = byId("diag-protocol");
const diagReconnects = byId("diag-reconnects");
const diagError = byId("diag-error");
const diagHelp = byId("diag-help");

function announce(message: string): void {
  announcer.textContent = "";
  // A microtask keeps repeated identical announcements audible.
  window.setTimeout(() => {
    announcer.textContent = message;
  }, 0);
}

// ---------------------------------------------------------------------------
// Target tab
// ---------------------------------------------------------------------------

function isPopupUrl(url: string | undefined): boolean {
  const base =
    typeof chrome.runtime.getURL === "function" ? chrome.runtime.getURL("") : "";
  return base.length > 0 && typeof url === "string" && url.startsWith(`${base}popup/`);
}

async function resolveTargetTab(): Promise<void> {
  const param = new URLSearchParams(location.search).get("tab");
  let tab: TabLike | null = null;

  if (param !== null && /^\d+$/.test(param)) {
    tab = await getTab(Number(param));
  }

  if (tab === null) {
    try {
      const [active] = await queryTabs({ active: true, currentWindow: true });
      if (active && !isPopupUrl(active.url)) {
        tab = active;
      }
    } catch {
      // No tabs API (unit harness); the popup simply shows no logins.
    }
  }

  if (!tab) {
    return;
  }
  state.tabId = typeof tab.id === "number" ? tab.id : null;
  state.url = typeof tab.url === "string" ? tab.url : null;
  state.pageTitle = typeof tab.title === "string" ? tab.title : null;
}

function hostOf(url: string | null): string {
  if (url === null) return "this page";
  try {
    return new URL(url).hostname;
  } catch {
    return "this page";
  }
}

function isWebUrl(url: string | null): url is string {
  return url !== null && /^https?:/i.test(url);
}

// ---------------------------------------------------------------------------
// Status header
// ---------------------------------------------------------------------------

type Tone = "ok" | "warn" | "error" | "muted";

interface StatusView {
  title: string;
  detail: string;
  tone: Tone;
  spinner: boolean;
  action?: { label: string; run: () => Promise<void> };
}

function shortHash(hash: string | null): string {
  if (hash === null || hash.length < 8) return hash ?? "";
  return `${hash.slice(0, 8)}…`;
}

function statusView(status: StatusSummary): StatusView {
  if (status.state === "CONNECTING" || status.state === "HANDSHAKING") {
    return {
      title: "Connecting",
      detail: "Talking to friendlypass…",
      tone: "warn",
      spinner: true,
    };
  }
  if (!status.appRunning) {
    return {
      title: "App not running",
      detail: "Start friendlypass, then retry.",
      tone: "error",
      spinner: false,
      action: {
        label: "Retry",
        run: async () => {
          await sendBackgroundMessage("status.refresh", undefined);
          await refreshStatus();
        },
      },
    };
  }
  if (status.locked) {
    return {
      title: "Locked",
      detail: "Locked — unlock friendlypass to continue",
      tone: "warn",
      spinner: false,
      action: {
        label: "Unlock friendlypass",
        run: async () => {
          await sendBackgroundMessage("status.refresh", { triggerUnlock: true });
          await refreshStatus();
        },
      },
    };
  }
  if (!status.associated) {
    return {
      title: "Not connected to this database",
      detail: "Allow this browser to use friendlypass.",
      tone: "warn",
      spinner: false,
      action: {
        label: "Connect",
        run: async () => {
          const result = await sendBackgroundMessage("association.create");
          if (!result.ok) {
            announce("Could not connect to the database");
          }
          await refreshStatus();
          await refreshLogins(true);
        },
      },
    };
  }
  if (status.connected && status.databaseOpen) {
    return {
      title: "Connected",
      detail: `Database ${shortHash(status.databaseHash)}`,
      tone: "ok",
      spinner: false,
    };
  }
  return {
    title: "Not connected",
    detail: status.error?.message ?? "friendlypass is not answering.",
    tone: "error",
    spinner: false,
    action: {
      label: "Reconnect",
      run: async () => {
        await sendBackgroundMessage("connection.reconnect");
        await refreshStatus();
        await refreshLogins(true);
      },
    },
  };
}

let currentAction: (() => Promise<void>) | null = null;

function renderStatus(): void {
  const status = state.status;
  if (status === null) {
    statusTitle.textContent = "Connecting";
    statusDetail.hidden = true;
    return;
  }
  const view = statusView(status);
  statusTitle.textContent = view.title;
  statusDetail.textContent = view.detail;
  statusDetail.hidden = view.detail.length === 0;
  statusHeader.dataset["tone"] = view.tone;
  statusHeader.dataset["state"] = status.state;

  statusIndicator.className = view.spinner
    ? "status-indicator fp-spinner"
    : `status-indicator fp-dot fp-dot--${view.tone}`;

  if (view.action) {
    currentAction = view.action.run;
    statusAction.hidden = false;
    statusAction.textContent = view.action.label;
  } else {
    currentAction = null;
    statusAction.hidden = true;
  }

  lockButton.disabled = !status.appRunning || status.locked;
}

statusAction.addEventListener("click", () => {
  const action = currentAction;
  if (action === null) return;
  statusAction.disabled = true;
  void action()
    .catch(() => undefined)
    .finally(() => {
      statusAction.disabled = false;
    });
});

// ---------------------------------------------------------------------------
// Login list
// ---------------------------------------------------------------------------

function siteExceptionFor(url: string | null): SiteException | null {
  const settings = state.settings;
  if (settings === null || url === null) return null;
  let origin: string;
  try {
    origin = new URL(url).origin;
  } catch {
    return null;
  }
  return settings.siteExceptions.find((entry) => entry.origin === origin) ?? null;
}

function loginMatches(entry: CredentialEntry, query: string): boolean {
  if (query.length === 0) return true;
  const haystack = [entry.name, entry.login, entry.group]
    .filter((value): value is string => typeof value === "string")
    .join("\n")
    .toLowerCase();
  return haystack.includes(query);
}

function monogram(entry: CredentialEntry): string {
  const source = (entry.name || entry.login || "?").trim();
  const letter = source.charAt(0);
  return letter.length > 0 ? letter : "?";
}

function loginStatus(entry: CredentialEntry, message: string): void {
  const node = loginsContainer.querySelector<HTMLElement>(
    `[data-login-uuid="${CSS.escape(entry.uuid)}"] .login-status`,
  );
  if (node === null) return;
  node.textContent = message;
  node.hidden = false;
  window.setTimeout(() => {
    node.hidden = true;
  }, 2_500);
}

async function fillEntry(entry: CredentialEntry): Promise<void> {
  if (state.tabId === null) {
    announce("No page to fill");
    return;
  }
  const result = await sendBackgroundMessage("tab.fillLogin", {
    tabId: state.tabId,
    entry,
  });
  if (!result.ok) {
    loginStatus(entry, "Could not fill this page.");
    announce("Could not fill this page");
    return;
  }
  if (!result.value.delivered) {
    loginStatus(entry, "Reload the page, then try again.");
    announce("Could not reach the page");
    return;
  }
  loginStatus(entry, "Filled");
  announce(`Filled ${entry.name || entry.login}`);
}

async function copyLoginField(
  entry: CredentialEntry,
  kind: "username" | "password",
): Promise<void> {
  const value = kind === "username" ? entry.login : entry.password;
  const label = kind === "username" ? "Username" : "Password";
  if (value.length === 0) {
    announce(`No ${label.toLowerCase()} stored`);
    return;
  }
  const ok = await copyValue(value, label);
  loginStatus(entry, ok ? `${label} copied` : `Could not copy ${label.toLowerCase()}`);
  announce(ok ? `${label} copied` : `Could not copy ${label.toLowerCase()}`);
}

async function copyTotp(entry: CredentialEntry): Promise<void> {
  let code = typeof entry.totp === "string" ? entry.totp : "";
  const result = await sendBackgroundMessage("totp.get", {
    uuid: entry.uuid,
    fallback: code,
  });
  if (result.ok && result.value.length > 0) {
    code = result.value;
  }
  if (code.length === 0) {
    announce("No TOTP code available");
    return;
  }
  const ok = await copyValue(code, "TOTP code");
  loginStatus(entry, ok ? "TOTP code copied" : "Could not copy the TOTP code");
  announce(ok ? "TOTP code copied" : "Could not copy the TOTP code");
}

function renderLoginCard(entry: CredentialEntry, fillDisabled: boolean): HTMLElement {
  const card = el("article", {
    className: "login",
    attrs: {
      "data-testid": "login",
      "data-login-uuid": entry.uuid,
    },
  });

  const monogramNode = el("span", {
    className: "login-monogram",
    text: monogram(entry),
    attrs: { "aria-hidden": "true" },
  });
  const titleNode = el("p", {
    className: "login-title",
    text: entry.name || entry.login || "Login",
  });
  const usernameNode = el("p", {
    className: "login-username",
    text: entry.login || "No username",
  });

  const actions = el("div", { className: "login-actions" });
  actions.append(
    button(
      "Fill",
      "fill",
      () => void fillEntry(entry),
      fillDisabled
        ? { className: "fp-button--primary", disabled: true, title: "Filling is disabled for this site" }
        : { className: "fp-button--primary", title: `Fill ${entry.name || entry.login}` },
    ),
    button("Copy username", "copy-username", () => void copyLoginField(entry, "username")),
    button("Copy password", "copy-password", () => void copyLoginField(entry, "password")),
  );
  if (typeof entry.totp === "string" && entry.totp.length > 0) {
    actions.append(button("Copy TOTP", "copy-totp", () => void copyTotp(entry)));
  }

  const status = el("p", { className: "login-status", attrs: { role: "status" } });
  status.hidden = true;
  status.textContent = "";

  card.append(monogramNode, titleNode, usernameNode, actions, status);
  return card;
}

function emptyMessage(): string {
  const status = state.status;
  const host = hostOf(state.url);
  if (status === null) return "Connecting…";
  if (status.state === "CONNECTING" || status.state === "HANDSHAKING") {
    return "Waiting for friendlypass…";
  }
  if (!status.appRunning) return "Start friendlypass to see logins.";
  if (status.locked) return "Unlock friendlypass to see logins.";
  if (!status.associated) return "Connect this browser to see logins.";
  if (!isWebUrl(state.url)) return "This page cannot be filled.";
  return `No logins for ${host}`;
}

function renderLogins(): void {
  const query = searchInput.value.trim().toLowerCase();
  const { entries, loading, error } = state.logins;
  const visible = entries.filter((entry) => loginMatches(entry, query));
  const showSearch = entries.length > 0 && state.status?.associated === true;
  searchWrap.hidden = !showSearch;

  loginsContainer.replaceChildren();

  if (loading && entries.length === 0) {
    loginsContainer.append(el("p", { className: "empty-state", text: "Loading logins…" }));
    return;
  }

  if (visible.length === 0) {
    const message =
      entries.length > 0
        ? `No logins match “${searchInput.value.trim()}”`
        : error !== null
          ? "Could not load logins."
          : emptyMessage();
    const stateNode = el("p", { className: "empty-state", text: message });
    loginsContainer.append(stateNode);
    if (error !== null && entries.length === 0) {
      loginsContainer.append(
        el("p", { className: "empty-state fp-muted", text: error }),
      );
    }
    return;
  }

  const exception = siteExceptionFor(state.url);
  const fillDisabled = exception?.disableFill === true;
  for (const entry of visible) {
    loginsContainer.append(renderLoginCard(entry, fillDisabled));
  }
  if (fillDisabled) {
    loginsContainer.append(
      el("p", {
        className: "empty-state fp-muted",
        text: "Filling is disabled for this site.",
      }),
    );
  }
}

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

let loginRequestToken = 0;

async function refreshLogins(force = false): Promise<void> {
  const status = state.status;
  if (
    !force &&
    (status === null ||
      !status.appRunning ||
      status.locked ||
      !status.associated ||
      !isWebUrl(state.url))
  ) {
    state.logins = { loading: false, entries: [], error: null };
    renderLogins();
    return;
  }
  const token = ++loginRequestToken;
  state.logins = { loading: true, entries: state.logins.entries, error: null };
  renderLogins();
  const result = await sendBackgroundMessage("logins.get", { url: state.url as string });
  if (token !== loginRequestToken) {
    return;
  }
  if (result.ok) {
    state.logins = { loading: false, entries: result.value, error: null };
  } else if (result.error.code === 15) {
    // NO_LOGINS_FOUND is the normal empty case, not an error.
    state.logins = { loading: false, entries: [], error: null };
  } else {
    state.logins = {
      loading: false,
      entries: [],
      error: failureText(result.error),
    };
  }
  renderLogins();
}

async function refreshStatus(): Promise<void> {
  const result = await sendBackgroundMessage("status.get");
  if (!result.ok) {
    return;
  }
  state.status = result.value;
  renderStatus();
}

async function refreshSettings(): Promise<void> {
  const result = await sendBackgroundMessage("settings.get");
  if (result.ok) {
    state.settings = result.value;
    renderLogins();
  }
}

async function refreshDiagnostics(): Promise<void> {
  // One host-level ping keeps the host/app versions in the snapshot current
  // (the heartbeat only refreshes them every 20 s). Never a poll: this runs on
  // load and when the disclosure is opened.
  if (state.diagnostics === null || state.diagnostics.connection.appVersion === null) {
    await sendBackgroundMessage("connection.ping");
  }
  const result = await sendBackgroundMessage("diagnostics.get");
  if (!result.ok) {
    return;
  }
  state.diagnostics = result.value;
  const connection = result.value.connection;
  diagHost.textContent = connection.hostVersion ?? "—";
  diagApp.textContent = connection.appVersion ?? "—";
  diagProtocol.textContent = `v${connection.protocolVersion}`;
  diagReconnects.textContent = String(result.value.reconnects);
  diagError.textContent =
    connection.lastError === null
      ? "None"
      : `${connection.lastError.message} (${connection.lastError.code})`;
  const help = result.value.host === null ? "friendlypass is not answering." : "";
  diagHelp.textContent = help;
  diagHelp.hidden = help.length === 0;
}

// ---------------------------------------------------------------------------
// Generate password
// ---------------------------------------------------------------------------

async function generatePassword(): Promise<void> {
  generateToggle.disabled = true;
  generateError.hidden = true;
  generateValue.textContent = "Generating…";
  generateRow.hidden = false;
  const result = await sendBackgroundMessage("password.generate");
  generateToggle.disabled = false;
  if (!result.ok || result.value.length === 0) {
    generateValue.textContent = "";
    generateError.textContent = result.ok
      ? "No password was generated."
      : "Could not generate a password.";
    generateError.hidden = false;
    return;
  }
  generateValue.textContent = result.value;
  generateCopy.disabled = false;
  generateRegenerate.disabled = false;
}

generateToggle.addEventListener("click", () => {
  void generatePassword();
});

generateRegenerate.addEventListener("click", () => {
  void generatePassword();
});

generateCopy.addEventListener("click", () => {
  const value = generateValue.textContent ?? "";
  if (value.length === 0) return;
  void copyValue(value, "Generated password").then((ok) => {
    announce(ok ? "Password copied" : "Could not copy the password");
  });
});

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

byId("open-settings").addEventListener("click", () => {
  void chrome.runtime.openOptionsPage();
});

lockButton.addEventListener("click", () => {
  lockButton.disabled = true;
  void sendBackgroundMessage("database.lock")
    .then(async (result) => {
      if (result.ok) {
        state.status = result.value;
        renderStatus();
        announce("Database locked");
      } else {
        announce("Could not lock the database");
      }
      await refreshLogins(true);
    })
    .finally(() => {
      lockButton.disabled = state.status?.locked === true;
    });
});

diagnostics.addEventListener("toggle", () => {
  if (diagnostics.open) {
    void refreshDiagnostics();
  }
});

// ---------------------------------------------------------------------------
// Search + keyboard
// ---------------------------------------------------------------------------

searchInput.addEventListener("input", () => {
  renderLogins();
});

document.addEventListener("keydown", (event) => {
  const target = event.target as HTMLElement | null;
  const typing =
    target !== null &&
    (target.tagName === "INPUT" ||
      target.tagName === "TEXTAREA" ||
      target.isContentEditable);

  if (event.key === "Escape" && target === searchInput) {
    searchInput.value = "";
    renderLogins();
    return;
  }
  if (event.key === "/" && !typing && !searchWrap.hidden) {
    event.preventDefault();
    searchInput.focus();
  }
});

// ---------------------------------------------------------------------------
// Live updates
// ---------------------------------------------------------------------------

let loginContext = "";

function contextKey(status: StatusSummary): string {
  return [status.state, status.appRunning, status.locked, status.associated].join("|");
}

let refreshTimer: number | null = null;
function scheduleLoginRefresh(): void {
  if (refreshTimer !== null) {
    window.clearTimeout(refreshTimer);
  }
  refreshTimer = window.setTimeout(() => {
    refreshTimer = null;
    void refreshLogins();
  }, 150);
}

function subscribeToBackground(): void {
  onBackgroundEvent((action, payload) => {
    if (action === "status.changed") {
      const status = payload as StatusSummary;
      state.status = status;
      renderStatus();
      const next = contextKey(status);
      if (next !== loginContext) {
        loginContext = next;
        scheduleLoginRefresh();
      }
      if (diagnostics.open) {
        void refreshDiagnostics();
      }
      return;
    }
    if (action === "settings.changed") {
      state.settings = payload as ExtensionSettings;
      renderLogins();
    }
  });
}

// ---------------------------------------------------------------------------
// Test/diagnostics hook (extension page only; never reachable from a page)
// ---------------------------------------------------------------------------

interface PopupDebug {
  lastCopy(): { text: string; label: string; at: number } | null;
  clipboardCleared(): boolean;
  clipboardClearedAt(): number | null;
  entries(): Array<{ uuid: string; login: string; name: string }>;
}

(window as unknown as { __fpPopupDebug?: PopupDebug }).__fpPopupDebug = {
  lastCopy: () => (lastCopy === null ? null : { ...lastCopy }),
  clipboardCleared: () => clipboardCleared,
  clipboardClearedAt: () => clipboardClearedAt,
  entries: () =>
    state.logins.entries.map((entry) => ({
      uuid: entry.uuid,
      login: entry.login,
      name: entry.name,
    })),
};

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function boot(): Promise<void> {
  subscribeToBackground();
  await resolveTargetTab();
  await Promise.all([refreshStatus(), refreshSettings()]);
  loginContext = state.status === null ? "" : contextKey(state.status);
  await refreshLogins();
  await refreshDiagnostics();
  renderStatus();
}

void boot().catch(() => {
  statusTitle.textContent = "Not connected";
  statusDetail.textContent = "friendlypass could not be reached.";
  statusDetail.hidden = false;
});
