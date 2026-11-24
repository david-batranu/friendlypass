/**
 * Inline field icon (WP6b, replaces the WP4 icon renderer).
 *
 * One fixed-position host per detected field, each with an **open** shadow
 * root and its own stylesheet (see `styles.ts`). Page CSS cannot break it and
 * Playwright can still see `[data-friendlypass="icon"]`.
 *
 * States are driven by `icon-state.ts`:
 *   matches  accent glyph
 *   empty    muted glyph (no saved login for this page)
 *   locked   muted glyph with a lock badge
 *   hidden   visual-only (app down / icons disabled)
 *
 * The icon is repositioned on scroll, resize and field resize. It reserves the
 * right-edge space used by the page's own eye/clear controls so it never sits
 * on top of them.
 */

import { isSearchField } from "./fields";
import type { IconState } from "./icon-state";
import { appendShadowMarkup, createShadowHost } from "./styles";
import { FP_ATTR, isElementVisible, isRTL } from "./ui";

export type IconKind = "login" | "totp";
export type { IconState } from "./icon-state";

interface IconRecord {
  host: HTMLDivElement;
  field: HTMLInputElement;
  kind: IconKind;
  handler: () => void;
  state: IconState;
  resizeObserver: ResizeObserver | null;
}

const MIN_ICON_SIZE = 18;
const MAX_ICON_SIZE = 24;
/** Horizontal band at the field's right edge that page controls may occupy. */
const RESERVED_CONTROL_BAND = 52;

const ICON_CSS = `
:host{--fp-icon-size:20px}
.glyph{
  display:flex;align-items:center;justify-content:center;width:100%;height:100%;
  border-radius:50%;background:var(--fp-bg);color:var(--fp-muted);
  box-shadow:0 0 0 1px var(--fp-border),0 1px 3px rgba(0,0,0,.18);
  border:0;cursor:pointer;transition:color .12s ease,box-shadow .12s ease;
}
.glyph:hover{box-shadow:0 0 0 1px var(--fp-accent),0 1px 4px rgba(0,0,0,.22)}
:host([data-friendlypass-state="matches"]) .glyph,
:host([data-friendlypass-state="matches"]) .glyph:hover{color:var(--fp-accent)}
:host([data-friendlypass-state="empty"]) .glyph{color:var(--fp-muted)}
:host([data-friendlypass-state="locked"]) .glyph{color:var(--fp-muted)}
svg.key{width:64%;height:64%;display:block;fill:currentColor}
.badge{
  position:absolute;right:-2px;bottom:-2px;width:10px;height:10px;border-radius:50%;
  background:var(--fp-surface);border:1px solid var(--fp-border);color:var(--fp-muted);
  display:none;align-items:center;justify-content:center;
}
:host([data-friendlypass-state="locked"]) .badge{display:flex}
.badge svg{width:7px;height:7px;fill:currentColor;display:block}
`;

const KEY_PATH =
  "M14 2a6 6 0 0 0-5.66 8L2 16.34V22h5.66l1.6-1.6V19h1.4l1.6-1.6V16h1.4l1.06-1.06A6 6 0 1 0 14 2zm2.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3z";
const LOCK_PATH =
  "M6 8V6a4 4 0 1 1 8 0v2h1a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1h1zm2 0h4V6a2 2 0 1 0-4 0v2z";

const icons = new Map<HTMLInputElement, IconRecord>();
let listenersInstalled = false;
let repositionFrame: number | null = null;

function titleFor(record: IconRecord): string {
  switch (record.state) {
    case "matches":
      return record.kind === "totp"
        ? "Fill one-time password from friendlypass"
        : "Fill login from friendlypass";
    case "empty":
      return record.kind === "totp"
        ? "No one-time password saved for this page"
        : "No saved login for this page";
    case "locked":
      return "Locked — unlock friendlypass to continue";
    case "hidden":
      return "";
  }
}

function labelFor(record: IconRecord): string {
  const title = titleFor(record);
  return title || "friendlypass";
}

function sizeFor(field: HTMLInputElement): number {
  const rect = field.getBoundingClientRect();
  return Math.max(
    MIN_ICON_SIZE,
    Math.min(MAX_ICON_SIZE, Math.round(rect.height - 6)),
  );
}

/**
 * Extra edge inset for a page-provided control (password eye, clear button)
 * that overlaps the field's trailing edge. Returns 0 when there is none.
 */
function reservedEdgeInset(
  field: HTMLInputElement,
  rect: DOMRect,
  rtl: boolean,
): number {
  const container = field.parentElement;
  if (!container || rect.width <= 0) {
    return 0;
  }
  let inset = 0;
  const candidates = container.querySelectorAll(
    "button,[role=button],a[href],input[type=button],input[type=image]," +
      "[class*=eye i],[class*=reveal i],[class*=password-toggle i]," +
      "[aria-label*=password i]",
  );
  for (const candidate of Array.from(candidates)) {
    if (candidate === field || !(candidate instanceof HTMLElement)) {
      continue;
    }
    const control = candidate.getBoundingClientRect();
    if (control.width === 0 || control.height === 0) {
      continue;
    }
    const verticalOverlap =
      control.top < rect.bottom && control.bottom > rect.top;
    if (!verticalOverlap) {
      continue;
    }
    if (rtl) {
      const nearLeft =
        control.right <= rect.left + RESERVED_CONTROL_BAND &&
        control.right > rect.left - 4;
      if (nearLeft) {
        inset = Math.max(inset, Math.round(control.right - rect.left) + 2);
      }
    } else {
      const nearRight =
        control.left >= rect.right - RESERVED_CONTROL_BAND &&
        control.left < rect.right + 4;
      if (nearRight) {
        inset = Math.max(inset, Math.round(rect.right - control.left) + 2);
      }
    }
  }
  return Math.min(inset, Math.round(rect.width / 2));
}

function position(record: IconRecord): void {
  const { field, host } = record;
  if (!field.isConnected || record.state === "hidden") {
    return;
  }
  const rect = field.getBoundingClientRect();
  const size = sizeFor(field);
  const rtl = isRTL(field);
  const inset = reservedEdgeInset(field, rect, rtl);
  const top = rect.top + Math.max(0, (rect.height - size) / 2);
  const left = rtl ? rect.left + 4 + inset : rect.right - size - 4 - inset;

  host.style.setProperty("top", `${Math.max(0, Math.round(top))}px`, "important");
  host.style.setProperty("left", `${Math.max(0, Math.round(left))}px`, "important");
  host.style.setProperty("width", `${size}px`, "important");
  host.style.setProperty("height", `${size}px`, "important");
  host.style.setProperty("position", "fixed", "important");
}

function scheduleReposition(): void {
  if (repositionFrame !== null) {
    return;
  }
  repositionFrame = window.requestAnimationFrame(() => {
    repositionFrame = null;
    for (const record of icons.values()) {
      position(record);
    }
  });
}

function installGlobalListeners(): void {
  if (listenersInstalled) {
    return;
  }
  listenersInstalled = true;
  window.addEventListener("scroll", scheduleReposition, {
    passive: true,
    capture: true,
  });
  window.addEventListener("resize", scheduleReposition, { passive: true });
  window.visualViewport?.addEventListener("resize", scheduleReposition, {
    passive: true,
  });
  window.visualViewport?.addEventListener("scroll", scheduleReposition, {
    passive: true,
  });
}

function buildMarkup(): string {
  return (
    `<style>${ICON_CSS}</style>` +
    '<span class="glyph" aria-hidden="true">' +
    `<svg class="key" viewBox="0 0 24 24"><path d="${KEY_PATH}"/></svg>` +
    `<span class="badge"><svg viewBox="0 0 16 16"><path d="${LOCK_PATH}"/></svg></span>` +
    "</span>"
  );
}

function applyState(record: IconRecord): void {
  const { host, state } = record;
  host.setAttribute(`${FP_ATTR}-state`, state);
  if (state === "hidden") {
    host.style.setProperty("display", "none", "important");
    host.setAttribute("aria-hidden", "true");
    return;
  }
  host.style.setProperty("display", "block", "important");
  host.removeAttribute("aria-hidden");
  host.setAttribute("title", titleFor(record));
  host.setAttribute("aria-label", labelFor(record));
  position(record);
}

/** Ensure exactly one icon is attached to `field`. */
export function ensureIcon(
  field: HTMLInputElement,
  kind: IconKind,
  handler: () => void,
): void {
  if (!field.isConnected || isSearchField(field) || field.type === "search") {
    return;
  }
  installGlobalListeners();

  const existing = icons.get(field);
  if (existing) {
    existing.handler = handler;
    existing.kind = kind;
    existing.host.setAttribute(`${FP_ATTR}-kind`, kind);
    position(existing);
    return;
  }

  const { host, shadow } = createShadowHost({
    [FP_ATTR]: "icon",
    [`${FP_ATTR}-kind`]: kind,
    [`${FP_ATTR}-state`]: "hidden",
    role: "button",
    tabindex: "-1",
    "aria-haspopup": "dialog",
  });
  appendShadowMarkup(shadow, buildMarkup());

  const record: IconRecord = {
    host,
    field,
    kind,
    handler,
    state: "hidden",
    resizeObserver: null,
  };

  host.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    record.handler();
  });
  // Keep the page field focused: the menu fills the field the icon belongs to.
  host.addEventListener("mousedown", (event) => {
    event.preventDefault();
    event.stopPropagation();
  });
  host.addEventListener("contextmenu", (event) => {
    event.stopPropagation();
  });

  if (typeof ResizeObserver === "function") {
    record.resizeObserver = new ResizeObserver(() => position(record));
    record.resizeObserver.observe(field);
  }

  icons.set(field, record);
  applyState(record);
  document.documentElement.append(host);
}

export function hasIcon(field: HTMLInputElement): boolean {
  return icons.has(field);
}

/** Number of icons currently attached (test/diagnostics helper). */
export function iconCount(kind?: IconKind): number {
  if (kind === undefined) {
    return icons.size;
  }
  let count = 0;
  for (const record of icons.values()) {
    if (record.kind === kind) {
      count += 1;
    }
  }
  return count;
}

/** State of one field's icon, or `null` when it has none. */
export function iconStateOf(field: HTMLInputElement): IconState | null {
  return icons.get(field)?.state ?? null;
}

/** Set the state for every icon, or for one kind only. */
export function setIconState(state: IconState, kind?: IconKind): void {
  for (const record of icons.values()) {
    if (kind !== undefined && record.kind !== kind) {
      continue;
    }
    if (record.state === state) {
      continue;
    }
    record.state = state;
    applyState(record);
  }
}

export function repositionIcons(): void {
  scheduleReposition();
}

/** Remove icons whose field disappeared, became invisible, or was disabled. */
export function cleanupIcons(): void {
  for (const [field, record] of icons) {
    if (!field.isConnected || field.disabled || !isElementVisible(field)) {
      record.resizeObserver?.disconnect();
      record.host.remove();
      icons.delete(field);
    }
  }
}

/** Remove every icon (used when icons are disabled). */
export function removeAllIcons(): void {
  for (const record of icons.values()) {
    record.resizeObserver?.disconnect();
    record.host.remove();
  }
  icons.clear();
}

/** Remove one field's icon. */
export function removeIcon(field: HTMLInputElement): void {
  const record = icons.get(field);
  if (!record) {
    return;
  }
  record.resizeObserver?.disconnect();
  record.host.remove();
  icons.delete(field);
}
