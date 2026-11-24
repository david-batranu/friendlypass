/**
 * friendlypass options page (WP6a).
 *
 * Every control writes through `settings.set` immediately; the background
 * persists the unified {@link ExtensionSettings} and broadcasts
 * `settings.changed` to every extension context. No control is ever left in a
 * "pending" state, so a closed tab cannot lose a change.
 */

import { onBackgroundEvent, sendBackgroundMessage } from "../common/messages";
import type {
  DiagnosticsSnapshot,
  ExtensionSettings,
  SiteException,
  StatusSummary,
} from "../common/types";

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`options: missing #${id}`);
  }
  return element as T;
}

interface ElementOptions {
  className?: string;
  text?: string;
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
  for (const [name, value] of Object.entries(options.attrs ?? {})) {
    element.setAttribute(name, value);
  }
  for (const child of children) {
    element.append(child);
  }
  return element;
}

type BooleanSettingKey =
  | "autoFillSingleEntry"
  | "showFieldIcons"
  | "autoFillAndSubmit"
  | "defaultGroupAlwaysAsk"
  | "httpAuthAutoFill"
  | "launchAppOnConnect"
  | "debugLogging";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state: {
  settings: ExtensionSettings | null;
  status: StatusSummary | null;
  diagnostics: DiagnosticsSnapshot | null;
} = {
  settings: null,
  status: null,
  diagnostics: null,
};

const saveState = byId("save-state");
const exceptionForm = byId<HTMLFormElement>("exception-form");
const exceptionOrigin = byId<HTMLInputElement>("exception-origin");
const exceptionError = byId("exception-error");
const exceptionList = byId("exception-list");
const exceptionEmpty = byId("exception-empty");

let saveStateTimer: number | null = null;

function showSaveState(message: string, failed = false): void {
  saveState.textContent = message;
  saveState.dataset["state"] = failed ? "error" : "ok";
  if (saveStateTimer !== null) {
    window.clearTimeout(saveStateTimer);
  }
  if (!failed) {
    saveStateTimer = window.setTimeout(() => {
      saveStateTimer = null;
      saveState.textContent = "";
    }, 2_500);
  }
}

async function saveSettings(patch: Partial<ExtensionSettings>): Promise<boolean> {
  showSaveState("Saving…");
  const result = await sendBackgroundMessage("settings.set", patch);
  if (!result.ok) {
    showSaveState("Could not save", true);
    return false;
  }
  state.settings = result.value;
  renderExceptions();
  showSaveState("Saved");
  return true;
}

// ---------------------------------------------------------------------------
// Simple controls
// ---------------------------------------------------------------------------

function bindCheckbox(id: string, key: BooleanSettingKey): void {
  const input = byId<HTMLInputElement>(id);
  input.addEventListener("change", () => {
    void saveSettings({ [key]: input.checked } as Partial<ExtensionSettings>);
  });
}

bindCheckbox("opt-autoFillSingleEntry", "autoFillSingleEntry");
bindCheckbox("opt-showFieldIcons", "showFieldIcons");
bindCheckbox("opt-autoFillAndSubmit", "autoFillAndSubmit");
bindCheckbox("opt-defaultGroupAlwaysAsk", "defaultGroupAlwaysAsk");
bindCheckbox("opt-httpAuthAutoFill", "httpAuthAutoFill");
bindCheckbox("opt-launchAppOnConnect", "launchAppOnConnect");
bindCheckbox("opt-debugLogging", "debugLogging");

const defaultGroupInput = byId<HTMLInputElement>("opt-defaultGroup");
let defaultGroupTimer: number | null = null;

function scheduleDefaultGroupSave(): void {
  if (defaultGroupTimer !== null) {
    window.clearTimeout(defaultGroupTimer);
  }
  defaultGroupTimer = window.setTimeout(() => {
    defaultGroupTimer = null;
    void saveSettings({ defaultGroup: defaultGroupInput.value });
  }, 350);
}

defaultGroupInput.addEventListener("input", scheduleDefaultGroupSave);
defaultGroupInput.addEventListener("change", () => {
  if (defaultGroupTimer !== null) {
    window.clearTimeout(defaultGroupTimer);
    defaultGroupTimer = null;
  }
  void saveSettings({ defaultGroup: defaultGroupInput.value });
});

// ---------------------------------------------------------------------------
// Site exceptions
// ---------------------------------------------------------------------------

/** Same normalisation the background applies; the background re-validates. */
function normaliseOrigin(value: string): string | null {
  const text = value.trim();
  if (text.length === 0 || /\s/.test(text)) return null;
  try {
    const url = new URL(text.includes("://") ? text : `https://${text}`);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.hostname.length === 0 || /\s/.test(url.hostname)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function currentExceptions(): SiteException[] {
  return state.settings?.siteExceptions ?? [];
}

function renderExceptions(): void {
  const exceptions = currentExceptions();
  exceptionList.replaceChildren();

  for (const entry of exceptions) {
    const row = el("tr", { attrs: { "data-origin": entry.origin } });
    row.append(el("td", { className: "origin-cell", text: entry.origin }));

    const toggles: Array<[
      "disableFill" | "disableSave" | "disableIcons",
      string,
    ]> = [
      ["disableFill", "No fill"],
      ["disableSave", "No save"],
      ["disableIcons", "No icons"],
    ];
    for (const [key, label] of toggles) {
      const cell = el("td", { className: "toggle-cell" });
      const input = el("input", {
        attrs: {
          type: "checkbox",
          "aria-label": `${label} for ${entry.origin}`,
          "data-exception-toggle": key,
        },
      });
      input.checked = entry[key] === true;
      input.addEventListener("change", () => {
        void toggleException(entry.origin, key, input.checked);
      });
      cell.append(input);
      row.append(cell);
    }

    const actionCell = el("td", { className: "action-cell" });
    const remove = el("button", {
      className: "fp-button fp-button--small fp-button--quiet fp-button--danger",
      text: "Remove",
      attrs: {
        type: "button",
        "aria-label": `Remove ${entry.origin}`,
        "data-action": "remove-exception",
      },
    });
    remove.addEventListener("click", () => {
      void saveSettings({
        siteExceptions: currentExceptions().filter((candidate) => candidate.origin !== entry.origin),
      });
    });
    actionCell.append(remove);
    row.append(actionCell);

    exceptionList.append(row);
  }

  exceptionEmpty.hidden = exceptions.length > 0;
}

async function toggleException(
  origin: string,
  key: "disableFill" | "disableSave" | "disableIcons",
  enabled: boolean,
): Promise<void> {
  const next = currentExceptions().map((entry) => {
    if (entry.origin !== origin) return entry;
    const updated: SiteException = { ...entry };
    if (enabled) {
      updated[key] = true;
    } else {
      delete updated[key];
    }
    return updated;
  });
  await saveSettings({ siteExceptions: next });
}

function showExceptionError(message: string): void {
  exceptionError.textContent = message;
  exceptionError.hidden = false;
}

exceptionForm.addEventListener("submit", (event) => {
  event.preventDefault();
  exceptionError.hidden = true;
  const origin = normaliseOrigin(exceptionOrigin.value);
  if (origin === null) {
    showExceptionError("Enter a site such as https://example.com");
    exceptionOrigin.focus();
    return;
  }
  if (currentExceptions().some((entry) => entry.origin === origin)) {
    showExceptionError(`${origin} is already listed`);
    return;
  }
  void saveSettings({
    siteExceptions: [...currentExceptions(), { origin }],
  }).then((ok) => {
    if (ok) {
      exceptionOrigin.value = "";
      exceptionOrigin.focus();
    }
  });
});

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

const connDot = byId("conn-dot");
const connState = byId("conn-state");
const connHost = byId("conn-host");
const connApp = byId("conn-app");
const connProtocol = byId("conn-protocol");
const connDatabase = byId("conn-database");
const reconnectStatus = byId("reconnect-status");

function describeConnection(status: StatusSummary): { label: string; tone: string } {
  if (status.state === "CONNECTING" || status.state === "HANDSHAKING") {
    return { label: "Connecting…", tone: "warn" };
  }
  if (!status.appRunning) {
    return { label: "friendlypass is not running", tone: "error" };
  }
  if (status.locked) {
    return { label: "Database locked", tone: "warn" };
  }
  if (!status.associated) {
    return { label: "Not connected to this database", tone: "warn" };
  }
  if (status.connected && status.databaseOpen) {
    return { label: "Connected", tone: "ok" };
  }
  return { label: "Not connected", tone: "error" };
}

function renderConnection(): void {
  const status = state.status;
  if (status === null) {
    connState.textContent = "Checking…";
    connDot.className = "fp-dot";
    return;
  }
  const view = describeConnection(status);
  connState.textContent = view.label;
  connDot.className = `fp-dot fp-dot--${view.tone}`;

  const diagnostics = state.diagnostics;
  connHost.textContent = diagnostics?.connection.hostVersion ?? "—";
  connApp.textContent = diagnostics?.connection.appVersion ?? "—";
  connProtocol.textContent = `v${status.protocolVersion}`;
  connDatabase.textContent =
    status.databaseHash === null ? "—" : `${status.databaseHash.slice(0, 16)}…`;
}

byId("reconnect").addEventListener("click", () => {
  reconnectStatus.textContent = "Reconnecting…";
  void sendBackgroundMessage("connection.reconnect")
    .then(async (result) => {
      if (result.ok) {
        state.status = result.value;
        reconnectStatus.textContent = "Reconnected";
      } else {
        reconnectStatus.textContent = "Could not reconnect";
      }
      await refreshDiagnostics();
      renderConnection();
    })
    .catch(() => {
      reconnectStatus.textContent = "Could not reconnect";
    });
});

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

function applySettings(settings: ExtensionSettings): void {
  state.settings = settings;
  byId<HTMLInputElement>("opt-autoFillSingleEntry").checked = settings.autoFillSingleEntry;
  byId<HTMLInputElement>("opt-showFieldIcons").checked = settings.showFieldIcons;
  byId<HTMLInputElement>("opt-autoFillAndSubmit").checked = settings.autoFillAndSubmit;
  byId<HTMLInputElement>("opt-defaultGroupAlwaysAsk").checked = settings.defaultGroupAlwaysAsk;
  byId<HTMLInputElement>("opt-httpAuthAutoFill").checked = settings.httpAuthAutoFill;
  byId<HTMLInputElement>("opt-launchAppOnConnect").checked = settings.launchAppOnConnect;
  byId<HTMLInputElement>("opt-debugLogging").checked = settings.debugLogging;
  defaultGroupInput.value = settings.defaultGroup;
  renderExceptions();
}

async function refreshSettings(): Promise<void> {
  const result = await sendBackgroundMessage("settings.get");
  if (result.ok) {
    applySettings(result.value);
  }
}

async function refreshStatus(): Promise<void> {
  const result = await sendBackgroundMessage("status.get");
  if (result.ok) {
    state.status = result.value;
    renderConnection();
  }
}

async function refreshDiagnostics(): Promise<void> {
  // One host-level ping refreshes host/app versions in the snapshot; the
  // heartbeat only does this every 20 s. Skipped once a version is known.
  if (state.diagnostics === null || state.diagnostics.connection.appVersion === null) {
    await sendBackgroundMessage("connection.ping");
  }
  const result = await sendBackgroundMessage("diagnostics.get");
  if (result.ok) {
    state.diagnostics = result.value;
    renderConnection();
  }
}

async function boot(): Promise<void> {
  onBackgroundEvent((action, payload) => {
    if (action === "status.changed") {
      state.status = payload as StatusSummary;
      renderConnection();
      // Host/app versions change with the connection; refresh the details too.
      void refreshDiagnostics();
      return;
    }
    if (action === "settings.changed") {
      // Another page changed the settings (e.g. the popup): reflect it, but do
      // not fight the control the user is currently editing.
      const settings = payload as ExtensionSettings;
      state.settings = settings;
      renderExceptions();
    }
  });

  await refreshSettings();
  await Promise.all([refreshStatus(), refreshDiagnostics()]);
}

void boot().catch(() => {
  showSaveState("Could not load settings", true);
});
