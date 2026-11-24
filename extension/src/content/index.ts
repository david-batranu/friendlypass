/**
 * friendlypass content script entry point (WP4 engine, WP6b in-page UX).
 *
 * Runs in every frame (`all_frames: true`) and:
 *   1. detects login/TOTP fields, including late-rendered SPA forms, open
 *      shadow roots and cross-origin frames;
 *   2. renders one inline icon per fillable field, with 1Password-style states
 *      (matches / no matches / locked / hidden);
 *   3. fetches matching logins through the internal message API only;
 *   4. fills from the icon, the inline menu (search + keyboard) or a background
 *      shortcut command, and generates passwords into signup forms;
 *   5. offers to save a newly submitted login with `set-login`;
 *   6. fills TOTP fields through `get-totp`;
 *   7. reacts live to `settings.changed` and enforces per-origin exceptions.
 *
 * Nothing here talks to the native host, and credentials never leave the
 * isolated content-script world except through the typed internal API.
 */

import {
  onBackgroundEvent,
  onContentCommand,
  sendBackgroundMessage,
} from "../common/messages";
import { INTERNAL_CHANNEL } from "../common/types";
import type {
  CredentialEntry,
  PendingCredential,
  StatusSummary,
} from "../common/types";
import { InlineMenu } from "./autocomplete";
import type { MenuAction } from "./autocomplete";
import { dismissSaveBanner, showSaveBanner } from "./banner";
import { loginMenuEntries } from "./credential-autocomplete";
import { fillCombination, fillTotp, setValue } from "./fill";
import type { FieldCombination } from "./fields";
import {
  buildCombinations,
  findCombination,
  findForm,
  getInputs,
  isLoginCombination,
  isNewPasswordField,
  isSearchField,
  passwordInputsForForm,
} from "./fields";
import {
  findExistingEntry,
  isAlreadySaved,
  readSubmittedCredentials,
} from "./form";
import type { SubmittedCredentials } from "./form";
import {
  cleanupIcons,
  ensureIcon,
  hasIcon,
  removeAllIcons,
  setIconState,
} from "./icon";
import { iconStateFor } from "./icon-state";
import { startDomObserver, startNavigationObserver } from "./observer";
import type { DomObserver } from "./observer";
import {
  CONTENT_SETTINGS_KEY,
  DEFAULT_CONTENT_SETTINGS,
  currentOrigin,
  isSettingsChangedMessage,
  normaliseSettings,
  readContentSettings,
  sitePolicyFor,
} from "./settings";
import type { ContentSettings, SitePolicy } from "./settings";
import { totpMenuEntries } from "./totp-autocomplete";
import { entryHasTotp, entryStringTotp } from "./totp-field";
import { formActionUrl, isOwnElement, showNotification } from "./ui";
import { ensureLoginIcon } from "./username-field";

const CONTENT_SINGLETON_KEY = "__friendlypassContentInstalled";
const FETCH_THROTTLE_MS = 1000;
/** Wait before opening the menu on field focus, so typing never races it. */
const AUTO_OPEN_DELAY_MS = 280;
/** After a user close, don't immediately reopen on the same focus. */
const AUTO_OPEN_SUPPRESS_MS = 900;
/** How long a field focus counts as "the field the user is on" for shortcuts. */
const FOCUS_RECENCY_MS = 15_000;
const GENERATE_ITEM_ID = "generate-password";
const OPEN_APP_ITEM_ID = "open-friendlypass";
const UNLOCK_ITEM_ID = "unlock";
const FILL_TOTP_ITEM_ID = "fill-totp";

let settings: ContentSettings = { ...DEFAULT_CONTENT_SETTINGS };
let policy: SitePolicy = sitePolicyFor(DEFAULT_CONTENT_SETTINGS, "");
let status: StatusSummary | null = null;
let combinations: FieldCombination[] = [];
let credentials: CredentialEntry[] = [];
let fetching: Promise<void> | null = null;
let lastFetchAt = 0;
let lastFetchUrl = "";
let lastPageUrl = "";
let autoFilled = false;
let detectTimer: number | null = null;
let autoOpenTimer: number | null = null;
let suppressAutoOpenUntil = 0;
let lastFocusedField: HTMLInputElement | null = null;
let lastFocusedAt = 0;

const boundForms = new WeakSet<HTMLFormElement>();
const menu = new InlineMenu();

let domObserver: DomObserver | null = null;
let navigationObserver: DomObserver | null = null;

function logDebug(message: string): void {
  if (settings.debugLogging) {
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

function totpCredentials(): CredentialEntry[] {
  return credentials.filter((entry) => entryHasTotp(entry));
}

function canFill(): boolean {
  return Boolean(
    status &&
      status.appRunning &&
      status.databaseOpen &&
      !status.locked &&
      status.associated &&
      !policy.disableFill,
  );
}

function appReachable(): boolean {
  return status?.appRunning === true;
}

// ---------------------------------------------------------------------------
// Settings and icon state
// ---------------------------------------------------------------------------

function applyPolicy(): void {
  policy = sitePolicyFor(settings, currentOrigin());
}

function updateIconStates(): void {
  const visible = settings.showFieldIcons && !policy.disableIcons;
  const base = {
    visible,
    appRunning: status?.appRunning ?? false,
    locked: status?.locked ?? true,
    databaseOpen: status?.databaseOpen ?? false,
    associated: status?.associated ?? false,
  };
  setIconState(
    iconStateFor({ ...base, hasMatches: credentials.length > 0 }),
    "login",
  );
  setIconState(
    iconStateFor({ ...base, hasMatches: totpCredentials().length > 0 }),
    "totp",
  );
}

function applyStatus(next: StatusSummary): void {
  status = next;
  if (!next.appRunning || next.locked) {
    menu.close("programmatic");
  }
  updateIconStates();
}

function applySettings(next: ContentSettings): void {
  settings = next;
  applyPolicy();
  if (!settings.showFieldIcons || policy.disableIcons) {
    removeAllIcons();
  }
  if (policy.disableFill) {
    menu.close("programmatic");
  }
  updateIconStates();
  detectAndRender();
}

/** Re-read `settings.get` (plus the legacy content key). */
async function refreshSettings(): Promise<void> {
  try {
    const next = await readContentSettings();
    applySettings(next);
  } catch (cause) {
    logDebug(`settings refresh failed: ${String(cause)}`);
  }
}

// ---------------------------------------------------------------------------
// Field detection and credential fetch
// ---------------------------------------------------------------------------

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
      updateIconStates();
      maybeAutoFill();
    } catch {
      credentials = [];
      updateIconStates();
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
  if (policy.disableSave) {
    return;
  }
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
  if (!settings.autoFillSingleEntry || autoFilled || !canFill()) {
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
  if (policy.disableFill) {
    showNotification("info", "Filling is disabled for this site.");
    return;
  }
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
  menu.close("programmatic");
}

// ---------------------------------------------------------------------------
// Inline menu
// ---------------------------------------------------------------------------

function closeForUser(): void {
  suppressAutoOpenUntil = Date.now() + AUTO_OPEN_SUPPRESS_MS;
}

async function openFriendlypassApp(): Promise<void> {
  try {
    const result = await sendBackgroundMessage("popup.open");
    if (result.ok && result.value.opened) {
      return;
    }
  } catch {
    // Fall through to the toolbar hint.
  }
  showNotification("info", "Open friendlypass from the toolbar to manage logins.");
}

async function unlockFriendlypass(): Promise<void> {
  try {
    const result = await sendBackgroundMessage("database.unlock");
    if (result.ok) {
      applyStatus(result.value);
      if (result.value.locked) {
        showNotification("info", "Unlock friendlypass to continue.");
      } else {
        showNotification("success", "friendlypass unlocked.");
        void fetchCredentials(false, true);
      }
    } else {
      showNotification("info", "Unlock friendlypass to continue.");
    }
  } catch {
    showNotification("info", "Unlock friendlypass to continue.");
  }
}

function openLockedMenu(field: HTMLInputElement): void {
  const actions: MenuAction[] = [
    {
      id: UNLOCK_ITEM_ID,
      label: "Locked — unlock friendlypass",
      icon: "lock",
      tone: "primary",
    },
    {
      id: OPEN_APP_ITEM_ID,
      label: "Open friendlypass",
      icon: "external",
    },
  ];
  menu.open(field, [], {
    focusSearch: false,
    label: "friendlypass locked",
    emptyMessage: "",
    actions,
    onAction: (action) => {
      if (action.id === UNLOCK_ITEM_ID) {
        settle(unlockFriendlypass(), "unlock");
      } else {
        settle(openFriendlypassApp(), "open-friendlypass");
      }
    },
    onClose: (reason) => {
      if (reason === "user") {
        closeForUser();
      }
    },
  });
}

function openAppMenu(field: HTMLInputElement, emptyMessage: string): void {
  const actions: MenuAction[] = [
    {
      id: OPEN_APP_ITEM_ID,
      label: "Open friendlypass",
      icon: "external",
      tone: "primary",
    },
  ];
  menu.open(field, [], {
    focusSearch: false,
    label: "friendlypass",
    emptyMessage,
    actions,
    onAction: (action) => {
      if (action.id === OPEN_APP_ITEM_ID) {
        settle(openFriendlypassApp(), "open-friendlypass");
      }
    },
    onClose: (reason) => {
      if (reason === "user") {
        closeForUser();
      }
    },
  });
}

function openLoginMenu(
  field: HTMLInputElement,
  combination: FieldCombination | undefined,
  focusSearch: boolean,
): void {
  const actions: MenuAction[] = [];
  if (combination && isNewPasswordField(field, combination)) {
    actions.push({
      id: GENERATE_ITEM_ID,
      label: "Generate password",
      icon: "generate",
    });
  }

  menu.open(field, loginMenuEntries(credentials), {
    focusSearch,
    label: "friendlypass logins",
    searchPlaceholder: "Search logins",
    emptyMessage: "No saved login for this page",
    actions,
    onPick: (picked) => {
      const entry = credentials.find((candidate) => candidate.uuid === picked.uuid);
      if (!entry) {
        return;
      }
      refreshCombinations();
      fillWithEntry(
        findCombination(combinations, field) ?? combination,
        entry,
      );
    },
    onAction: (action) => {
      if (action.id === GENERATE_ITEM_ID) {
        settle(
          generatePasswordInto(combination, field),
          "generate-password",
        );
      }
    },
    onClose: (reason) => {
      if (reason === "user") {
        closeForUser();
      }
    },
  });
}

function openTotpMenu(field: HTMLInputElement, focusSearch: boolean): void {
  const entries = totpCredentials();
  const actions: MenuAction[] = [
    {
      id: FILL_TOTP_ITEM_ID,
      label: "Fill TOTP",
      icon: "totp",
      tone: "primary",
      needsEntry: true,
    },
    {
      id: OPEN_APP_ITEM_ID,
      label: "Open friendlypass",
      icon: "external",
    },
  ];

  const fillFor = (entry: CredentialEntry): void => {
    settle(fillTotpForEntry(field, entry), "fill-totp");
  };

  menu.open(field, totpMenuEntries(credentials), {
    focusSearch,
    label: "friendlypass one-time passwords",
    searchPlaceholder: "Search entries",
    emptyMessage: "No one-time password is saved for this page",
    actions,
    onPick: (picked) => {
      const entry = credentials.find((candidate) => candidate.uuid === picked.uuid);
      if (entry) {
        fillFor(entry);
      }
    },
    onAction: (action, activeEntry) => {
      if (action.id === OPEN_APP_ITEM_ID) {
        settle(openFriendlypassApp(), "open-friendlypass");
        return;
      }
      if (action.id !== FILL_TOTP_ITEM_ID) {
        return;
      }
      const uuid = activeEntry?.uuid ?? entries[0]?.uuid;
      const entry = credentials.find((candidate) => candidate.uuid === uuid);
      if (entry) {
        fillFor(entry);
      }
    },
    onClose: (reason) => {
      if (reason === "user") {
        closeForUser();
      }
    },
  });
}

async function onLoginIconClick(field: HTMLInputElement): Promise<void> {
  if (menu.isOpenFor(field)) {
    menu.close("user");
    return;
  }
  if (policy.disableFill) {
    showNotification("info", "Filling is disabled for this site.");
    return;
  }
  if (!appReachable()) {
    return;
  }

  refreshCombinations();
  // A step transition can leave the icon attached to a field the page just
  // removed; fall back to the page's best login combination.
  const combination =
    findCombination(combinations, field) ?? largestCombination();
  logDebug(`login icon click; entries=${credentials.length}`);

  if (!canFill()) {
    openLockedMenu(field);
    return;
  }

  if (credentials.length === 0) {
    await ensureCredentials();
  }
  refreshCombinations();
  const fresh = findCombination(combinations, field) ?? combination;
  updateIconStates();

  if (credentials.length === 0) {
    if (fresh && isNewPasswordField(field, fresh)) {
      openLoginMenu(field, fresh, true);
    } else {
      openAppMenu(field, "No saved login for this page");
    }
    return;
  }

  if (credentials.length === 1) {
    const entry = credentials[0];
    if (entry) {
      fillWithEntry(fresh, entry);
    }
    return;
  }

  openLoginMenu(field, fresh, true);
}

async function onTotpIconClick(field: HTMLInputElement): Promise<void> {
  if (menu.isOpenFor(field)) {
    menu.close("user");
    return;
  }
  if (policy.disableFill) {
    showNotification("info", "Filling is disabled for this site.");
    return;
  }
  if (!appReachable()) {
    return;
  }
  if (!canFill()) {
    openLockedMenu(field);
    return;
  }

  refreshCombinations();
  // The field may have been replaced by a step transition between the icon
  // render and the click.
  const target =
    findCombination(combinations, field)?.totp ??
    combinations.find((candidate) => candidate.totp)?.totp ??
    field;

  if (credentials.length === 0) {
    await ensureCredentials();
  }
  updateIconStates();

  const withTotp = totpCredentials();
  if (withTotp.length === 0) {
    openAppMenu(target, "No one-time password is saved for this page");
    return;
  }

  if (withTotp.length === 1) {
    const entry = withTotp[0];
    if (entry) {
      await fillTotpForEntry(target, entry);
    }
    return;
  }

  openTotpMenu(target, true);
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
  menu.close("programmatic");
}

// ---------------------------------------------------------------------------
// Password generation
// ---------------------------------------------------------------------------

/**
 * Inputs that should receive a generated password: explicit
 * `autocomplete=new-password` fields, otherwise every password field after the
 * current one in a multi-password form, otherwise the single password field.
 */
function generatedPasswordTargets(
  combination: FieldCombination | undefined,
  field: HTMLInputElement | null,
): HTMLInputElement[] {
  const form = combination?.form ?? (field ? findForm(field) : null);
  const inputs = form ? passwordInputsForForm(form) : [];
  const explicit = inputs.filter(
    (input) =>
      (input.getAttribute("autocomplete") ?? "").toLowerCase() === "new-password",
  );
  let targets: HTMLInputElement[] = explicit;
  if (targets.length === 0) {
    if (inputs.length >= 2) {
      targets = inputs.slice(1);
    } else if (inputs.length === 1) {
      targets = inputs;
    } else if (field && field.type === "password") {
      targets = [field];
    }
  }
  return Array.from(new Set(targets));
}

function generatedUsername(
  combination: FieldCombination | undefined,
  field: HTMLInputElement | null,
): string {
  const direct = combination?.username?.value.trim();
  if (direct) {
    return direct;
  }
  const form = combination?.form ?? (field ? findForm(field) : null);
  const input = form?.querySelector<HTMLInputElement>(
    'input[type="text"], input[type="email"]',
  );
  return input?.value.trim() ?? "";
}

async function generatePasswordInto(
  combination: FieldCombination | undefined,
  field: HTMLInputElement | null,
): Promise<void> {
  if (policy.disableFill) {
    showNotification("info", "Filling is disabled for this site.");
    return;
  }
  if (!canFill()) {
    showNotification("info", "Locked — unlock friendlypass to continue.");
    return;
  }
  refreshCombinations();
  const fresh =
    (field ? findCombination(combinations, field) : undefined) ??
    combination ??
    largestCombination();
  const targets = generatedPasswordTargets(fresh, field);
  if (targets.length === 0) {
    showNotification("warning", "No password field was found on this page.");
    return;
  }

  const result = await sendBackgroundMessage("password.generate");
  const password = result.ok && typeof result.value === "string" ? result.value : "";
  if (!password) {
    showNotification("warning", "friendlypass could not generate a password.");
    return;
  }

  for (const target of targets) {
    setValue(target, password, true);
  }
  logDebug(`generated password into ${targets.length} field(s)`);

  if (!policy.disableSave) {
    showBannerForSubmission(
      {
        username: generatedUsername(fresh, field),
        password,
        passwordChange: targets.length > 1,
      },
      credentials,
      document.location.href,
      true,
    );
  }
}

// ---------------------------------------------------------------------------
// Shortcut entry points (background command -> raw content message)
// ---------------------------------------------------------------------------

function focusedLoginField(): HTMLInputElement | null {
  const active = document.activeElement;
  if (active instanceof HTMLInputElement && !isSearchField(active)) {
    return active;
  }
  if (
    lastFocusedField &&
    lastFocusedField.isConnected &&
    Date.now() - lastFocusedAt < FOCUS_RECENCY_MS &&
    (document.hasFocus() || Date.now() - lastFocusedAt < 1500)
  ) {
    return lastFocusedField;
  }
  return null;
}

function openMenuForFocusedField(): void {
  const field = focusedLoginField();
  if (!field) {
    showNotification("info", "Focus a login field first.");
    return;
  }
  refreshCombinations();
  const combination = findCombination(combinations, field);
  if (!combination) {
    return;
  }
  if (combination.totp === field) {
    settle(onTotpIconClick(field), "shortcut-totp-menu");
    return;
  }
  settle(onLoginIconClick(field), "shortcut-login-menu");
}

function generateForFocusedField(): void {
  const field = focusedLoginField();
  refreshCombinations();
  let combination = field
    ? findCombination(combinations, field)
    : undefined;
  if (!combination) {
    // No focused login field: only a signup/password-change form is a safe
    // target. Never overwrite an unrelated login password.
    combination = combinations.find((candidate) => {
      const form = candidate.form;
      if (!form) {
        return false;
      }
      const inputs = passwordInputsForForm(form);
      return (
        inputs.length >= 2 ||
        inputs.some(
          (input) =>
            (input.getAttribute("autocomplete") ?? "").toLowerCase() ===
            "new-password",
        )
      );
    });
  }
  if (!combination) {
    showNotification("info", "Focus a password field first.");
    return;
  }
  settle(generatePasswordInto(combination, field), "shortcut-generate");
}

// ---------------------------------------------------------------------------
// Icons and save offers
// ---------------------------------------------------------------------------

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
  if (policy.disableSave) {
    return;
  }
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
  skipFocus = false,
): void {
  if (policy.disableSave) {
    return;
  }
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
      ...(existing?.name ? { title: existing.name } : {}),
      ...(existing ? { uuid: existing.uuid } : {}),
    },
    {
      onSaved: () => {
        void fetchCredentials(false, true);
      },
      groupAlwaysAsk: settings.defaultGroupAlwaysAsk,
      defaultGroup: settings.defaultGroup,
      skipFocus,
    },
  );
}

/**
 * Same-document save path (a form that calls `preventDefault`, or a JS submit
 * that stays on the page). Credentials are loaded first so an existing entry
 * produces "update" and an exact match produces no banner at all.
 */
function offerSave(submitted: SubmittedCredentials): void {
  if (policy.disableSave) {
    return;
  }
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
  if (!event.isTrusted || policy.disableSave) {
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
  if (!event.isTrusted || !(event.target instanceof Element) || policy.disableSave) {
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
    policy.disableSave ||
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

    if (!settings.showFieldIcons || policy.disableIcons) {
      removeAllIcons();
      menu.close("programmatic");
    } else {
      renderIcons();
      cleanupIcons();
    }
    updateIconStates();

    if (menu.anchorField) {
      const anchor = menu.anchorField;
      if (!anchor.isConnected || !findCombination(combinations, anchor)) {
        menu.close("programmatic");
      } else {
        menu.reposition();
      }
    }

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

// ---------------------------------------------------------------------------
// Focus-driven menu opening
// ---------------------------------------------------------------------------

function scheduleAutoOpen(field: HTMLInputElement): void {
  if (autoOpenTimer !== null) {
    window.clearTimeout(autoOpenTimer);
    autoOpenTimer = null;
  }
  if (
    Date.now() < suppressAutoOpenUntil ||
    policy.disableFill ||
    !settings.showFieldIcons ||
    policy.disableIcons ||
    field.value !== ""
  ) {
    return;
  }

  autoOpenTimer = window.setTimeout(() => {
    autoOpenTimer = null;
    if (!field.matches(":focus") || field.value !== "" || menu.isOpen()) {
      return;
    }
    if (!canFill()) {
      return;
    }
    refreshCombinations();
    const combination = findCombination(combinations, field);
    if (!combination || combination.totp || !isLoginCombination(combination)) {
      return;
    }
    void (async () => {
      if (credentials.length === 0) {
        await ensureCredentials();
      }
      if (
        !field.matches(":focus") ||
        field.value !== "" ||
        menu.isOpen() ||
        !canFill()
      ) {
        return;
      }
      if (credentials.length === 0) {
        return;
      }
      openLoginMenu(field, findCombination(combinations, field) ?? combination, false);
    })();
  }, AUTO_OPEN_DELAY_MS);
}

function onFocusIn(event: Event): void {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) {
    if (menu.isOpen() && (!(target instanceof Element) || !isOwnElement(target))) {
      menu.close("programmatic");
    }
    return;
  }

  lastFocusedField = target;
  lastFocusedAt = Date.now();

  if (menu.isOpen() && menu.anchorField !== target) {
    menu.close("programmatic");
  }
  scheduleAutoOpen(target);
}

function onDocumentInput(event: Event): void {
  if (!(event.target instanceof HTMLInputElement) || !event.isTrusted) {
    return;
  }
  if (menu.isOpenFor(event.target)) {
    menu.close("user");
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init(): Promise<void> {
  try {
    if (
      document.contentType !== "text/html" &&
      document.contentType !== "application/xhtml+xml"
    ) {
      return;
    }

    settings = await readContentSettings();
    applyPolicy();

    const statusResult = await sendBackgroundMessage("status.get");
    if (statusResult.ok) {
      applyStatus(statusResult.value);
    }

    detectAndRender();
    if (!policy.disableSave) {
      void checkPendingSubmission();
    }
    domObserver = startDomObserver(() => scheduleDetect());
    navigationObserver = startNavigationObserver(() => scheduleDetect());
  } catch (cause) {
    logDebug(`initialisation failed: ${String(cause)}`);
  }
}

function registerHandlers(): void {
  onContentCommand({
    "content.fillLogin": ({ entry }) => {
      if (policy.disableFill) {
        return;
      }
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
      if (policy.disableFill) {
        return;
      }
      refreshCombinations();
      const combination = combinations.find((candidate) => candidate.totp !== null);
      if (combination?.totp) {
        fillTotp(combination.totp, totp);
      }
    },

    "content.clearCredentials": () => {
      credentials = [];
      menu.close("programmatic");
      dismissSaveBanner();
      updateIconStates();
    },

    "content.redetectFields": () => {
      autoFilled = false;
      detectAndRender();
    },

    "content.showSaveBanner": ({ kind, entry }) => {
      if (policy.disableSave) {
        return;
      }
      if (entry) {
        showSaveBanner({
          kind,
          username: entry.login,
          password: entry.password,
          url: document.location.href,
          ...(entry.name ? { title: entry.name } : {}),
          ...(kind === "update" ? { uuid: entry.uuid } : {}),
        }, {
          groupAlwaysAsk: settings.defaultGroupAlwaysAsk,
          defaultGroup: settings.defaultGroup,
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
        }, {
          groupAlwaysAsk: settings.defaultGroupAlwaysAsk,
          defaultGroup: settings.defaultGroup,
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

  // WP6b raw messages: settings broadcast, inline-menu shortcut and the
  // generate-password shortcut. The typed content-command map is owned by WP3
  // and is intentionally not extended here (WP6a owns types.ts); these actions
  // are fire-and-forget and answered by no one.
  chrome.runtime.onMessage.addListener((message: unknown) => {
    if (isSettingsChangedMessage(message)) {
      applySettings(normaliseSettings(message.args));
      return false;
    }
    if (
      typeof message === "object" &&
      message !== null &&
      (message as Record<string, unknown>)["channel"] === INTERNAL_CHANNEL
    ) {
      const action = (message as Record<string, unknown>)["action"];
      if (action === "content.openInlineMenu") {
        openMenuForFocusedField();
      } else if (action === "content.generatePassword") {
        generateForFocusedField();
      }
    }
    return false;
  });

  // Legacy WP4 content key changes still apply live (the unified settings
  // arrive through `settings.changed`).
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local" || !changes[CONTENT_SETTINGS_KEY]) {
        return;
      }
      void refreshSettings();
    });
  } catch {
    // Storage may be unavailable; initial settings are enough.
  }

  window.addEventListener("pagehide", () => {
    domObserver?.stop();
    navigationObserver?.stop();
    menu.close("programmatic");
  });

  // Capture phase so the submission is reported before the page's own click
  // handler starts an XHR/navigation. Never prevented or stopped.
  document.addEventListener("focusin", onFocusIn, true);
  document.addEventListener("input", onDocumentInput, true);
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
