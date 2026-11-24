/**
 * Content-script view of the unified extension settings (WP6b).
 *
 * The only settings API is the internal `settings.get` / `settings.set`
 * message pair. This module normalises whatever the background returns against
 * the WP6 defaults so the content script keeps working while WP6a is still
 * landing the new `ExtensionSettings` fields in `common/types.ts` and
 * `background/state.ts` (the brief explicitly forbids this package from
 * editing those files).
 *
 * The legacy content-only key (`friendlypass.content.settings.v1`, written by
 * WP4's tests and the old popup) is still honoured as a fallback for
 * `autoFillSingleEntry` / `showIcons` so existing installs do not change
 * behaviour. Everything else comes from `settings.get`.
 */

import { sendBackgroundMessage } from "../common/messages";
import type { ExtensionSettings } from "../common/types";

/** One per-origin exception from the unified settings. */
export interface SiteException {
  origin: string;
  disableFill?: boolean;
  disableSave?: boolean;
  disableIcons?: boolean;
}

/** The settings fields the in-page UI needs, with WP6 defaults applied. */
export interface ContentSettings {
  autoFillSingleEntry: boolean;
  showFieldIcons: boolean;
  httpAuthAutoFill: boolean;
  autoFillAndSubmit: boolean;
  launchAppOnConnect: boolean;
  defaultGroup: string;
  defaultGroupAlwaysAsk: boolean;
  debugLogging: boolean;
  siteExceptions: SiteException[];
}

export const DEFAULT_CONTENT_SETTINGS: Readonly<ContentSettings> = Object.freeze({
  autoFillSingleEntry: false,
  showFieldIcons: true,
  httpAuthAutoFill: true,
  autoFillAndSubmit: false,
  launchAppOnConnect: false,
  defaultGroup: "",
  defaultGroupAlwaysAsk: false,
  debugLogging: false,
  siteExceptions: [],
});

/** Legacy WP4 content-only key. Read-only fallback, never written here. */
export const CONTENT_SETTINGS_KEY = "friendlypass.content.settings.v1";

/** `chrome.storage.local` key owned by `background/state.ts`. */
export const BACKGROUND_STATE_KEY = "friendlypass.state.v1";

export interface LegacyContentSettings {
  autoFillSingleEntry?: boolean;
  showIcons?: boolean;
}

export interface SitePolicy {
  disableFill: boolean;
  disableSave: boolean;
  disableIcons: boolean;
}

export const NO_SITE_POLICY: Readonly<SitePolicy> = Object.freeze({
  disableFill: false,
  disableSave: false,
  disableIcons: false,
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function text(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

/** Keep only well-formed exceptions; malformed entries are ignored. */
export function sanitiseSiteExceptions(value: unknown): SiteException[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const out: SiteException[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (!isRecord(raw)) {
      continue;
    }
    const origin = typeof raw["origin"] === "string" ? raw["origin"].trim() : "";
    if (!origin || seen.has(origin)) {
      continue;
    }
    seen.add(origin);
    const exception: SiteException = { origin };
    if (typeof raw["disableFill"] === "boolean") {
      exception.disableFill = raw["disableFill"];
    }
    if (typeof raw["disableSave"] === "boolean") {
      exception.disableSave = raw["disableSave"];
    }
    if (typeof raw["disableIcons"] === "boolean") {
      exception.disableIcons = raw["disableIcons"];
    }
    out.push(exception);
  }
  return out;
}

/**
 * Apply WP6 defaults to any `settings.get` payload.
 *
 * `autoFillHttpAuth` (the pre-WP6 name) is accepted as an alias so an older
 * background still produces the intended `httpAuthAutoFill` value.
 */
export function normaliseSettings(raw: unknown): ContentSettings {
  const source = isRecord(raw) ? raw : {};
  const defaults = DEFAULT_CONTENT_SETTINGS;
  return {
    autoFillSingleEntry: bool(source["autoFillSingleEntry"], defaults.autoFillSingleEntry),
    showFieldIcons: bool(source["showFieldIcons"], defaults.showFieldIcons),
    httpAuthAutoFill: bool(
      source["httpAuthAutoFill"],
      bool(source["autoFillHttpAuth"], defaults.httpAuthAutoFill),
    ),
    autoFillAndSubmit: bool(source["autoFillAndSubmit"], defaults.autoFillAndSubmit),
    launchAppOnConnect: bool(source["launchAppOnConnect"], defaults.launchAppOnConnect),
    defaultGroup: text(source["defaultGroup"], defaults.defaultGroup),
    defaultGroupAlwaysAsk: bool(
      source["defaultGroupAlwaysAsk"],
      defaults.defaultGroupAlwaysAsk,
    ),
    debugLogging: bool(source["debugLogging"], defaults.debugLogging),
    siteExceptions: sanitiseSiteExceptions(source["siteExceptions"]),
  };
}

/** The exact-origin policy for `origin` (`""` never matches). */
export function sitePolicyFor(
  settings: Pick<ContentSettings, "siteExceptions">,
  origin: string,
): SitePolicy {
  if (!origin) {
    return { ...NO_SITE_POLICY };
  }
  for (const exception of settings.siteExceptions) {
    if (exception.origin === origin) {
      return {
        disableFill: exception.disableFill === true,
        disableSave: exception.disableSave === true,
        disableIcons: exception.disableIcons === true,
      };
    }
  }
  return { ...NO_SITE_POLICY };
}

/** `origin` of the current document, or `""` for non-http(s) pages. */
export function currentOrigin(): string {
  try {
    const url = new URL(document.location.href);
    return url.protocol === "http:" || url.protocol === "https:" ? url.origin : "";
  } catch {
    return "";
  }
}

/** Read the legacy key (kept out of the pure normaliser). */
export async function readLegacyContentSettings(): Promise<LegacyContentSettings> {
  try {
    if (typeof chrome === "undefined" || !chrome.storage?.local) {
      return {};
    }
    const stored = await chrome.storage.local.get(CONTENT_SETTINGS_KEY);
    const raw = stored[CONTENT_SETTINGS_KEY];
    if (!isRecord(raw)) {
      return {};
    }
    const legacy: LegacyContentSettings = {};
    if (typeof raw["autoFillSingleEntry"] === "boolean") {
      legacy.autoFillSingleEntry = raw["autoFillSingleEntry"];
    }
    if (typeof raw["showIcons"] === "boolean") {
      legacy.showIcons = raw["showIcons"];
    }
    return legacy;
  } catch {
    return {};
  }
}

/**
 * The effective content settings: unified background settings plus the legacy
 * WP4 overrides. A legacy `autoFillSingleEntry: true` enables the behaviour;
 * a legacy `showIcons: false` still hides icons.
 */
export function mergeLegacySettings(
  unified: ContentSettings,
  legacy: LegacyContentSettings,
): ContentSettings {
  return {
    ...unified,
    autoFillSingleEntry:
      unified.autoFillSingleEntry || legacy.autoFillSingleEntry === true,
    showFieldIcons: legacy.showIcons === false ? false : unified.showFieldIcons,
  };
}

/** Ask the background for settings and apply legacy overrides. */
export async function readContentSettings(): Promise<ContentSettings> {
  let raw: unknown = null;
  try {
    const result = await sendBackgroundMessage("settings.get");
    if (result.ok) {
      raw = result.value;
    }
  } catch {
    // Background asleep/restarting: WP6 defaults are safe.
  }
  const legacy = await readLegacyContentSettings();
  return mergeLegacySettings(normaliseSettings(raw), legacy);
}

/**
 * Remember "Never for this site" in the unified exception list as well as the
 * pending-credential store (which the banner still calls separately).
 *
 * The write is best-effort: an older background that drops unknown settings
 * fields simply keeps the `submit.never` behaviour.
 */
export async function rememberNeverForSite(origin: string): Promise<void> {
  if (!origin) {
    return;
  }
  try {
    const current = await sendBackgroundMessage("settings.get");
    const settings = normaliseSettings(current.ok ? current.value : null);
    if (settings.siteExceptions.some((exception) => exception.origin === origin)) {
      return;
    }
    await sendBackgroundMessage("settings.set", {
      siteExceptions: [
        ...settings.siteExceptions,
        { origin, disableSave: true },
      ],
    } as unknown as Partial<ExtensionSettings>);
  } catch {
    // Never let bookkeeping break the banner's dismiss action.
  }
}

/** Shape of the raw `settings.changed` broadcast from the service worker. */
export interface SettingsChangedMessage {
  channel: "friendlypass";
  action: "settings.changed";
  args: unknown;
  requestId: string;
}

export function isSettingsChangedMessage(
  value: unknown,
): value is SettingsChangedMessage {
  return (
    isRecord(value) &&
    value["channel"] === "friendlypass" &&
    value["action"] === "settings.changed" &&
    typeof value["requestId"] === "string"
  );
}
