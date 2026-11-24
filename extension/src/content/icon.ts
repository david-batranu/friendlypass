/**
 * Inline field icon (WP4, ported from upstream `content/icon.js`,
 * `icon-handler.js`, `username-field.js` and `totp-field.js`).
 *
 * Icons live in an absolutely positioned host element directly in the page's
 * light DOM with an **open** shadow root, so page CSS cannot break them and
 * Playwright/WP6 can still find them (`[data-friendlypass="icon"]`).
 * Upstream's closed roots and per-site offset table are dropped.
 */

import { createElement, FP_ATTR, isElementVisible, isRTL } from "./ui";

export type IconKind = "login" | "totp";
export type IconState = "unlocked" | "locked" | "disconnected";

interface IconRecord {
  host: HTMLDivElement;
  field: HTMLInputElement;
  kind: IconKind;
  handler: () => void;
  state: IconState;
}

const MIN_ICON_SIZE = 14;
const MAX_ICON_SIZE = 24;

const icons = new Map<HTMLInputElement, IconRecord>();
let listenersInstalled = false;

function colorFor(state: IconState): string {
  if (state === "unlocked") {
    return "#2f855a";
  }
  if (state === "locked") {
    return "#b7791f";
  }
  return "#7b8794";
}

function sizeFor(field: HTMLInputElement): number {
  return Math.max(Math.min(MAX_ICON_SIZE, field.offsetHeight - 4), MIN_ICON_SIZE);
}

function installGlobalListeners(): void {
  if (listenersInstalled) {
    return;
  }
  listenersInstalled = true;
  const reposition = (): void => repositionIcons();
  window.addEventListener("scroll", reposition, { passive: true, capture: true });
  window.addEventListener("resize", reposition, { passive: true });
}

function position(record: IconRecord): void {
  const { field, host } = record;
  if (!field.isConnected) {
    return;
  }
  const rect = field.getBoundingClientRect();
  const size = sizeFor(field);
  const rtl = isRTL(field);
  const top = rect.top + Math.max(0, (rect.height - size) / 2);
  const left = rtl ? rect.left + 4 : rect.right - size - 4;
  host.style.top = `${Math.max(0, Math.round(top))}px`;
  host.style.left = `${Math.max(0, Math.round(left))}px`;
  host.style.width = `${size}px`;
  host.style.height = `${size}px`;
}

function render(record: IconRecord): void {
  const { host, kind, state } = record;
  host.setAttribute(`${FP_ATTR}-state`, state);
  host.style.color = colorFor(state);
  host.title =
    kind === "totp"
      ? "Fill one-time password from friendlypass"
      : state === "unlocked"
        ? "Fill login from friendlypass"
        : "friendlypass is not connected";

  if (!host.shadowRoot) {
    const shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML =
      "<style>" +
      ":host{all:initial}" +
      "button{all:unset;display:block;width:100%;height:100%;box-sizing:border-box;" +
      "border-radius:50%;background:rgba(255,255,255,.92);color:inherit;cursor:pointer;" +
      "box-shadow:0 0 0 1px rgba(0,0,0,.18),0 1px 3px rgba(0,0,0,.22);" +
      "display:flex;align-items:center;justify-content:center;padding:2px}" +
      "button:hover{background:#fff}" +
      "svg{width:100%;height:100%;display:block;fill:currentColor}" +
      "</style>" +
      '<button type="button" tabindex="-1" aria-hidden="true">' +
      '<svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path d="M14 2a6 6 0 0 0-5.66 8L2 16.34V22h5.66l1.6-1.6V19h1.4l1.6-1.6V16h1.4l1.06-1.06A6 6 0 1 0 14 2zm2.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3z"/>' +
      "</svg></button>";
  } else {
    const shadow = host.shadowRoot;
    (shadow.querySelector("button") as HTMLButtonElement | null)?.setAttribute(
      "aria-hidden",
      "true",
    );
  }
}

/** Ensure exactly one icon is attached to `field`. */
export function ensureIcon(
  field: HTMLInputElement,
  kind: IconKind,
  handler: () => void,
): void {
  if (!field.isConnected) {
    return;
  }
  installGlobalListeners();

  const existing = icons.get(field);
  if (existing) {
    // Keep the newest handler closure; the field/node is the same element.
    existing.handler = handler;
    existing.kind = kind;
    position(existing);
    return;
  }

  const host = createElement("div", undefined, {
    [FP_ATTR]: "icon",
    [`${FP_ATTR}-kind`]: kind,
    [`${FP_ATTR}-state`]: "disconnected",
    role: "button",
    tabindex: "-1",
  });
  host.style.cssText = [
    "all: initial",
    "display: block",
    "position: fixed",
    "z-index: 2147483647",
    "cursor: pointer",
    "pointer-events: auto",
  ].join(";");

  const record: IconRecord = {
    host,
    field,
    kind,
    handler,
    state: "disconnected",
  };

  host.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    record.handler();
  });
  host.addEventListener("mousedown", (event) => {
    event.stopPropagation();
  });
  host.addEventListener("mouseup", (event) => {
    event.stopPropagation();
  });

  icons.set(field, record);
  render(record);
  position(record);
  document.body.append(host);
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

export function setIconState(state: IconState): void {
  for (const record of icons.values()) {
    record.state = state;
    render(record);
  }
}

export function repositionIcons(): void {
  for (const record of icons.values()) {
    position(record);
  }
}

/** Remove icons whose field disappeared, became invisible, or was disabled. */
export function cleanupIcons(): void {
  for (const [field, record] of icons) {
    if (
      !field.isConnected ||
      field.disabled ||
      !isElementVisible(field)
    ) {
      record.host.remove();
      icons.delete(field);
    }
  }
}

/** Remove every icon (used when the page becomes an ignored/locked state). */
export function removeAllIcons(): void {
  for (const record of icons.values()) {
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
  record.host.remove();
  icons.delete(field);
}
