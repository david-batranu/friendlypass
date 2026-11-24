/**
 * friendlypass content script entry point (WP4).
 *
 * Runs in every frame (`all_frames: true`) and:
 *   1. detects login/TOTP fields, including late-rendered SPA forms, open
 *      shadow roots and cross-origin frames;
 *   2. renders one inline icon per fillable field;
 *   3. fetches matching logins through the internal message API only;
 *   4. fills from the icon/dropdown or from a background shortcut command;
 *   5. offers to save a newly submitted login with `set-login`;
 *   6. fills TOTP fields through `get-totp`.
 *
 * Nothing here talks to the native host, and credentials never leave the
 * isolated content-script world except through the typed internal API.
 */

import {
  onBackgroundEvent,
  onContentCommand,
  sendBackgroundMessage,
} from "../common/messages";
import type {
  CredentialEntry,
  ExtensionSettings,
  PendingCredential,
  StatusSummary,
} from "../common/types";
import { dismissSaveBanner, showSaveBanner } from "./banner";
import { CredentialAutocomplete } from "./credential-autocomplete";
import { fillCombination, fillTotp } from "./fill";
import type { FieldCombination } from "./fields";
import {
  buildCombinations,
  findCombination,
  getInputs,
  isLoginCombination,
} from "./fields";
import {
  findExistingEntry,
  isAlreadySaved,
  readSubmittedCredentials,
} from "./form";
import type { SubmittedCredentials } from "./form";
import { cleanupIcons, ensureIcon, hasIcon, setIconState } from "./icon";
import { startDomObserver, startNavigationObserver } from "./observer";
import type { DomObserver } from "./observer";
import { TOTPAutocomplete } from "./totp-autocomplete";
import { entryHasTotp, entryStringTotp } from "./totp-field";
import { formActionUrl, showNotification } from "./ui";
import { ensureLoginIcon } from "./username-field";

/** Content-only preferences. Kept separate from the background settings. */
interface ContentSettings {
  /** Fill automatically when exactly one matching login exists. Default off. */
  autoFillSingleEntry: boolean;
  /** Render field icons. Default on. */
  showIcons: boolean;
}

const CONTENT_SETTINGS_KEY = "friendlypass.content.settings.v1";
const CONTENT_SINGLETON_KEY = "__friendlypassContentInstalled";
const FETCH_THROTTLE_MS = 1000;

const DEFAULT_CONTENT_SETTINGS: ContentSettings = {
  autoFillSingleEntry: false,
  showIcons: true,
};

let extensionSettings: ExtensionSettings | null = null;
let contentSettings: ContentSettings = { ...DEFAULT_CONTENT_SETTINGS };
let status: StatusSummary | null = null;
let combinations: FieldCombination[] = [];
let credentials: CredentialEntry[] = [];
let fetching: Promise<void> | null = null;
let lastFetchAt = 0;
let lastFetchUrl = "";
let lastPageUrl = "";
let autoFilled = false;
let detectTimer: number | null = null;

const boundForms = new WeakSet<HTMLFormElement>();
const credentialMenu = new CredentialAutocomplete();
const totpMenu = new TOTPAutocomplete();

let domObserver: DomObserver | null = null;
let navigationObserver: DomObserver | null = null;

function logDebug(message: string): void {
  if (extensionSettings?.debugLogging) {
    // Never pass values from credential entries to this helper.
    console.debug(`[friendlypass content] ${message}`);
  }
}

/**
 * Run a fire-and-forget UI task and settle it: no icon/menu click may surface
 * an unhandled rejection, and diagnostics never include the thrown value's
 * contents beyond its string form (which is DOM errors only).
 */
function settle(task: Promise<void>, label: string): void {
  void task.catch((cause: unknown) => {
    logDebug(`${label} failed: ${String(cause)}`);
  });
}

function isStatusSummary(value: unknown): value is StatusSummary {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as StatusSummary).appRunning === "boolean" &&
    typeof (value as StatusSummary).locked === "boolean" &&
    typeof (value as StatusSummary).state === "string"
  );
}

function applyStatus(next: StatusSummary): void {
  status = next;
  if (!next.appRunning) {
    setIconState("disconnected");
  } else if (next.locked || !next.databaseOpen) {
    setIconState("locked");
  } else if (!next.associated) {
    // App reachable but this browser is not associated: the icon can still
    // trigger a fetch, which may raise the association UI.
    setIconState("locked");
  } else {
    setIconState("unlocked");
  }
}

function updateIconStateFromState(): void {
  if (status) {
    applyStatus(status);
    return;
  }
  setIconState("disconnected");
}

async function readContentSettings(): Promise<ContentSettings> {
  const settings: ContentSettings = { ...DEFAULT_CONTENT_SETTINGS };
  try {
    const stored = await chrome.storage.local.get(CONTENT_SETTINGS_KEY);
    const raw = stored[CONTENT_SETTINGS_KEY];
    if (typeof raw === "object" && raw !== null) {
      const record = raw as Record<string, unknown>;
      if (typeof record["autoFillSingleEntry"] === "boolean") {
        settings.autoFillSingleEntry = record["autoFillSingleEntry"];
      }
      if (typeof record["showIcons"] === "boolean") {
        settings.showIcons = record["showIcons"];
      }
    }
  } catch {
    // Storage may be unavailable while the extension starts; defaults are safe.
  }
  return settings;
}

/** Rebuild the field map synchronously from the current DOM. */
function refreshCombinations(): void {
  combinations = buildCombinations(getInputs(document));
}

function comboSubmitUrl(combination: FieldCombination | undefined): string | undefined {
  return formActionUrl(combination?.form ?? null);
}

async function fetchCredentials(triggerUnlock = false, force = false): Promise<void> {
  if (fetching) {
    return fetching;
  }

  const url = document.location.href;
  const now = Date.now();
  if (
    !force &&
    url === lastFetchUrl &&
    credentials.length === 0 &&
    now - lastFetchAt < FETCH_THROTTLE_MS
  ) {
    return;
  }

  const combination = combinations.find(
    (candidate) => candidate.username !== null || candidate.password !== null,
  );
  const submitUrl = comboSubmitUrl(combination);

  fetching = (async () => {
    try {
      const result = await sendBackgroundMessage("logins.get", {
        url,
        ...(submitUrl ? { submitUrl } : {}),
        ...(triggerUnlock ? { triggerUnlock: true } : {}),
      });
      if (result.ok) {
        credentials = result.value;
      } else {
        // Code 15 ("no logins") is normal; the internal wrapper reports every
        // failure the same way, so an empty list covers app-down and no-match.
        credentials = [];
      }
      lastFetchAt = Date.now();
      lastFetchUrl = url;
      logDebug(`logins.get ${result.ok ? "ok" : "failed"}; entries=${credentials.length}`);
      updateIconStateFromState();
      maybeAutoFill();
    } catch {
      credentials = [];
    } finally {
      fetching = null;
    }
  })();

  return fetching;
}

async function ensureCredentials(triggerUnlock = false): Promise<void> {
  if (credentials.length > 0) {
    return;
  }
  await fetchCredentials(triggerUnlock, true);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

/**
 * Ask the service worker for a pair submitted just before the previous page
 * unloaded. The store itself enforces tab/frame/site/expiry isolation; this
 * loop only tolerates the store message still being in flight when the new
 * document starts.
 */
async function pendingSubmissionForPage(): Promise<PendingCredential | null> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = await sendBackgroundMessage("submit.pending", {
      url: document.location.href,
    });
    if (result.ok && result.value) {
      return result.value;
    }
    if (attempt < 2) {
      await sleep(120);
    }
  }
  return null;
}

/**
 * Show the save/update banner for a login submitted on the previous page.
 * The entry lookup uses the *submitted* URL (the login page), not the current
 * one (often a dashboard), so "already saved"/"update existing" still work.
 */
async function checkPendingSubmission(): Promise<void> {
  const pending = await pendingSubmissionForPage();
  if (!pending) {
    return;
  }
  const result = await sendBackgroundMessage("logins.get", {
    url: pending.url,
    ...(pending.submitUrl ? { submitUrl: pending.submitUrl } : {}),
  });
  const entries = result.ok ? result.value : [];
  showBannerForSubmission(
    {
      username: pending.username,
      password: pending.password,
      passwordChange: false,
      ...(pending.submitUrl ? { submitUrl: pending.submitUrl } : {}),
    },
    entries,
    pending.url,
  );
}

function largestCombination(): FieldCombination | undefined {
  for (let index = combinations.length - 1; index >= 0; index -= 1) {
    const combination = combinations[index];
    if (combination && isLoginCombination(combination)) {
      return combination;
    }
  }
  return undefined;
}

function maybeAutoFill(): void {
  if (!contentSettings.autoFillSingleEntry || autoFilled) {
    return;
  }
  if (credentials.length !== 1) {
    return;
  }
  const combination = largestCombination();
  const entry = credentials[0];
  if (!combination || !entry) {
    return;
  }
  autoFilled = true;
  fillCombination(combination, entry);
}

function fillWithEntry(combination: FieldCombination | undefined, entry: CredentialEntry): void {
  if (!combination) {
    showNotification("warning", "No fillable login field was found on this page.");
    return;
  }
  logDebug(
    `fill; usernameField=${combination.username !== null} passwordField=${
      combination.password !== null
    }`,
  );
  fillCombination(combination, entry, {
    passOnly: combination.username === null && combination.password !== null,
  });
  credentialMenu.close();
  totpMenu.close();
}

async function onLoginIconClick(field: HTMLInputElement): Promise<void> {
  if (credentialMenu.isOpenFor(field)) {
    credentialMenu.close();
    return;
  }

  logDebug(`login icon click; entries=${credentials.length}`);
  refreshCombinations();
  const combination = findCombination(combinations, field) ?? largestCombination();

  if (credentials.length === 0) {
    await ensureCredentials();
  }
  refreshCombinations();
  const fresh = findCombination(combinations, field) ?? combination;

  if (credentials.length === 0) {
    showNotification("info", "No saved login matches this page.");
    return;
  }

  if (credentials.length === 1) {
    const entry = credentials[0];
    if (entry) {
      fillWithEntry(fresh, entry);
    }
    return;
  }

  credentialMenu.show(field, credentials, (entry) => {
    refreshCombinations();
    fillWithEntry(findCombination(combinations, field) ?? fresh, entry);
  });
}

async function onTotpIconClick(field: HTMLInputElement): Promise<void> {
  if (totpMenu.isOpenFor(field)) {
    totpMenu.close();
    return;
  }

  if (credentials.length === 0) {
    await ensureCredentials();
  }

  const withTotp = credentials.filter((entry) => entryHasTotp(entry));
  if (withTotp.length === 0) {
    showNotification("warning", "No one-time password is saved for this page.");
    return;
  }

  if (withTotp.length === 1) {
    const entry = withTotp[0];
    if (entry) {
      await fillTotpForEntry(field, entry);
    }
    return;
  }

  totpMenu.show(field, withTotp, (entry) => {
    settle(fillTotpForEntry(field, entry), "fill-totp");
  });
}

async function fillTotpForEntry(field: HTMLInputElement, entry: CredentialEntry): Promise<void> {
  const fallback = entry.totp ?? entryStringTotp(entry) ?? "";
  const result = await sendBackgroundMessage("totp.get", {
    uuid: entry.uuid,
    ...(fallback ? { fallback } : {}),
  });
  const code = result.ok && typeof result.value === "string" && result.value
    ? result.value
    : fallback;
  if (!code) {
    showNotification("warning", "friendlypass could not generate a one-time password.");
    return;
  }
  fillTotp(field, code);
  totpMenu.close();
}

function renderIcons(): void {
  for (const combination of combinations) {
    if (combination.totp) {
      if (!hasIcon(combination.totp)) {
        const field = combination.totp;
        ensureIcon(field, "totp", () => {
          settle(onTotpIconClick(field), "totp-icon");
        });
      }
      continue;
    }

    if (!isLoginCombination(combination)) {
      continue;
    }

    ensureLoginIcon(combination, (field) => {
      settle(onLoginIconClick(field), "login-icon");
    });
  }
}

function handlerForForm(form: HTMLFormElement): FieldCombination | undefined {
  return combinations.find((combination) => combination.form === form);
}

/**
 * Tell the service worker about a submission before the page can unload.
 * Fire-and-forget: the banner does not wait for the round-trip, and the SW
 * call is dispatched from the capture-phase listener ahead of navigation.
 */
function storeSubmission(submitted: SubmittedCredentials): void {
  void sendBackgroundMessage("submit.store", {
    url: document.location.href,
    username: submitted.username,
    password: submitted.password,
    ...(submitted.submitUrl ? { submitUrl: submitted.submitUrl } : {}),
  });
}

/** Show the create/update card, unless the exact pair is already stored. */
function showBannerForSubmission(
  submitted: SubmittedCredentials,
  entries: CredentialEntry[],
  url: string,
): void {
  if (isAlreadySaved(entries, submitted.username, submitted.password)) {
    return;
  }
  const existing = findExistingEntry(entries, submitted.username);
  showSaveBanner(
    {
      kind: existing ? "update" : "create",
      username: submitted.username,
      password: submitted.password,
      url,
      ...(submitted.submitUrl ? { submitUrl: submitted.submitUrl } : {}),
      ...(existing ? { uuid: existing.uuid } : {}),
    },
    {
      onSaved: () => {
        void fetchCredentials(false, true);
      },
    },
  );
}

/**
 * Same-document save path (a form that calls `preventDefault`, or a JS submit
 * that stays on the page). Credentials are loaded first so an existing entry
 * produces "update" and an exact match produces no banner at all.
 */
function offerSave(submitted: SubmittedCredentials): void {
  // Capture the page URL before any await: if the document navigates, the
  // banner must still be attributed to the page that submitted the form.
  const url = document.location.href;
  void (async () => {
    let entries = credentials;
    if (entries.length === 0) {
      await fetchCredentials(false, true);
      entries = credentials;
    }
    showBannerForSubmission(submitted, entries, url);
  })();
}

function onSubmit(event: Event): void {
  if (!event.isTrusted) {
    return;
  }
  const form = event.currentTarget;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  const submitted = readSubmittedCredentials(form, handlerForForm(form));
  if (!submitted) {
    return;
  }
  storeSubmission(submitted);
  offerSave(submitted);
}

/**
 * Submit-control click. Many sites submit through `type=button` + JS (often
 * after an XHR), so there may be no `submit` event at all; this capture-phase
 * listener still reports the pair before the page navigates.
 */
function onSubmitControlClick(event: Event): void {
  if (!event.isTrusted || !(event.target instanceof Element)) {
    return;
  }
  const control = event.target.closest(
    "button, input[type=submit], input[type=button], input[type=image]",
  );
  if (!(control instanceof HTMLElement)) {
    return;
  }
  const form =
    (control as HTMLButtonElement | HTMLInputElement).form ??
    (control.closest("form") as HTMLFormElement | null);
  if (!form) {
    return;
  }
  refreshCombinations();
  const submitted = readSubmittedCredentials(form, handlerForForm(form));
  if (!submitted) {
    return;
  }
  storeSubmission(submitted);
  offerSave(submitted);
}

/** Enter in a password field, for sites without a real submit button. */
function onPasswordKeydown(event: Event): void {
  if (
    !(event instanceof KeyboardEvent) ||
    !event.isTrusted ||
    event.key !== "Enter" ||
    !(event.target instanceof HTMLInputElement) ||
    event.target.type !== "password"
  ) {
    return;
  }
  const field = event.target;
  const form = field.form;
  refreshCombinations();
  const combination =
    findCombination(combinations, field) ?? (form ? handlerForForm(form) : undefined);
  const submitted = readSubmittedCredentials(form, combination);
  if (!submitted) {
    return;
  }
  storeSubmission(submitted);
  offerSave(submitted);
}

function bindForms(): void {
  for (const combination of combinations) {
    const form = combination.form;
    if (!form || boundForms.has(form)) {
      continue;
    }
    boundForms.add(form);
    form.addEventListener("submit", onSubmit, true);
  }
}

function detectAndRender(): void {
  try {
    if (document.location.href !== lastPageUrl) {
      lastPageUrl = document.location.href;
      autoFilled = false;
    }

    refreshCombinations();
    bindForms();
    if (contentSettings.showIcons) {
      renderIcons();
    }
    cleanupIcons();
    updateIconStateFromState();

    if (combinations.length > 0) {
      if (credentials.length > 0) {
        maybeAutoFill();
      } else {
        void fetchCredentials();
      }
    }
  } catch (cause) {
    logDebug(`detection failed: ${String(cause)}`);
  }
}

function scheduleDetect(): void {
  if (detectTimer !== null) {
    window.clearTimeout(detectTimer);
  }
  detectTimer = window.setTimeout(() => {
    detectTimer = null;
    detectAndRender();
  }, 60);
}

async function init(): Promise<void> {
  try {
    if (
      document.contentType !== "text/html" &&
      document.contentType !== "application/xhtml+xml"
    ) {
      return;
    }

    const settingsResult = await sendBackgroundMessage("settings.get");
    if (settingsResult.ok) {
      extensionSettings = settingsResult.value;
    }
    contentSettings = await readContentSettings();

    const statusResult = await sendBackgroundMessage("status.get");
    if (statusResult.ok) {
      applyStatus(statusResult.value);
    }

    detectAndRender();
    void checkPendingSubmission();
    domObserver = startDomObserver(() => scheduleDetect());
    navigationObserver = startNavigationObserver(() => scheduleDetect());
  } catch (cause) {
    logDebug(`initialisation failed: ${String(cause)}`);
  }
}

function registerHandlers(): void {
  onContentCommand({
    "content.fillLogin": ({ entry }) => {
      refreshCombinations();
      const combination = largestCombination();
      if (!combination) {
        showNotification("warning", "No fillable login field was found on this page.");
        return;
      }
      credentials = [entry];
      fillWithEntry(combination, entry);
    },

    "content.fillTotp": ({ totp }) => {
      refreshCombinations();
      const combination = combinations.find((candidate) => candidate.totp !== null);
      if (combination?.totp) {
        fillTotp(combination.totp, totp);
      }
    },

    "content.clearCredentials": () => {
      credentials = [];
      credentialMenu.close();
      totpMenu.close();
      dismissSaveBanner();
      updateIconStateFromState();
    },

    "content.redetectFields": () => {
      autoFilled = false;
      detectAndRender();
    },

    "content.showSaveBanner": ({ kind, entry }) => {
      if (entry) {
        showSaveBanner({
          kind,
          username: entry.login,
          password: entry.password,
          url: document.location.href,
          ...(kind === "update" ? { uuid: entry.uuid } : {}),
        });
        return;
      }

      refreshCombinations();
      const combination = largestCombination();
      const username = combination?.username?.value.trim() ?? "";
      const password = combination?.password?.value ?? "";
      if (password) {
        const submitUrl = formActionUrl(combination?.form ?? null);
        showSaveBanner({
          kind,
          username,
          password,
          url: document.location.href,
          ...(submitUrl ? { submitUrl } : {}),
        });
      }
    },

    "content.showConnectedStatus": ({ status: nextStatus }) => {
      applyStatus(nextStatus);
    },
  });

  onBackgroundEvent((action, payload) => {
    if (action === "status.changed" && isStatusSummary(payload)) {
      applyStatus(payload);
    }
  });

  window.addEventListener("pagehide", () => {
    domObserver?.stop();
    navigationObserver?.stop();
    credentialMenu.close();
    totpMenu.close();
  });

  // Capture phase so the submission is reported before the page's own click
  // handler starts an XHR/navigation. Never prevented or stopped.
  document.addEventListener("click", onSubmitControlClick, true);
  document.addEventListener("keydown", onPasswordKeydown, true);
}

function main(): void {
  const globalScope = globalThis as unknown as Record<string, unknown>;
  if (globalScope[CONTENT_SINGLETON_KEY] === true) {
    return;
  }
  globalScope[CONTENT_SINGLETON_KEY] = true;

  // Listener registration is synchronous so a fill command that wakes the
  // service worker can never race the first detection pass.
  registerHandlers();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      void init();
    }, { once: true });
  } else {
    void init();
  }
}

main();
