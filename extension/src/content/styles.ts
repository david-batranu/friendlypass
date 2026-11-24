/**
 * In-page UI stylesheet and shadow-root helpers (WP6b).
 *
 * Every injected surface (icon, inline menu, save card, toast) lives in its own
 * **open shadow root** with this stylesheet, so page CSS cannot reach it and it
 * cannot affect the page. The tokens are the shared WP6 contract; light and
 * dark values follow `prefers-color-scheme`.
 *
 * Critical host properties are inline `!important` so even a hostile
 * `* { all: unset !important }` stylesheet cannot collapse the host and hide
 * the UI from the user.
 */

import { FP_ATTR } from "./ui";

export const SHADOW_BASE_CSS = `
:host{all:initial}
:host{
  --fp-bg:#ffffff;--fp-surface:#f5f6f8;--fp-text:#1b1d21;--fp-muted:#5f6670;
  --fp-border:#d9dce1;--fp-accent:#2f6fed;--fp-accent-text:#ffffff;
  --fp-danger:#c62828;--fp-ok:#1f8a4c;
  --fp-radius:8px;--fp-radius-control:6px;
  --fp-shadow:0 8px 24px rgba(0,0,0,.18);
  --fp-font:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,Cantarell,"Noto Sans",sans-serif;
}
@media (prefers-color-scheme: dark){
  :host{
    --fp-bg:#1e1f22;--fp-surface:#2b2d31;--fp-text:#e8e9ec;--fp-muted:#a2a7b0;
    --fp-border:#3d4047;--fp-accent:#6c9bff;--fp-accent-text:#101215;
    --fp-danger:#ff6b6b;--fp-ok:#4cc38a;
    --fp-shadow:0 8px 24px rgba(0,0,0,.45);
  }
}
*{box-sizing:border-box}
.fp-panel{
  font-family:var(--fp-font);font-size:13px;line-height:1.35;color:var(--fp-text);
  background:var(--fp-bg);border:1px solid var(--fp-border);
  border-radius:var(--fp-radius);box-shadow:var(--fp-shadow);
}
button{font:inherit;color:inherit;background:none;border:0;padding:0;margin:0;cursor:pointer}
input{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--fp-accent);outline-offset:2px}
.fp-btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  min-height:28px;padding:5px 12px;border-radius:var(--fp-radius-control);
  border:1px solid transparent;font-weight:600;white-space:nowrap;
}
.fp-btn.secondary{background:var(--fp-surface);border-color:var(--fp-border);color:var(--fp-text)}
.fp-btn.primary{background:var(--fp-accent);color:var(--fp-accent-text)}
.fp-btn.ghost{color:var(--fp-muted)}
.fp-btn:hover{filter:brightness(.97)}
.fp-btn:disabled{opacity:.55;cursor:default}
.fp-muted{color:var(--fp-muted)}
.fp-monogram{
  display:inline-flex;align-items:center;justify-content:center;flex:none;
  width:26px;height:26px;border-radius:50%;
  background:var(--fp-accent);color:var(--fp-accent-text);
  font-size:11px;font-weight:700;letter-spacing:.02em;text-transform:uppercase;
}
.fp-visually-hidden{
  position:absolute!important;width:1px!important;height:1px!important;
  padding:0!important;margin:-1px!important;overflow:hidden!important;
  clip:rect(0 0 0 0)!important;white-space:nowrap!important;border:0!important;
}
`;

/**
 * Create a fixed-position host with an open shadow root and the shared
 * stylesheet. Returns both so callers can append component markup.
 */
export function createShadowHost(
  attributes: Record<string, string>,
): { host: HTMLDivElement; shadow: ShadowRoot } {
  const host = document.createElement("div");
  for (const [name, value] of Object.entries(attributes)) {
    host.setAttribute(name, value);
  }
  // `all: initial` first, then the properties we need. All important so a
  // page-level `* { ... !important }` cannot hide or move the host. Per-frame
  // geometry is applied later with setProperty(..., "important").
  host.style.cssText = [
    "all: initial !important",
    "display: block !important",
    "position: fixed !important",
    "z-index: 2147483647 !important",
    "pointer-events: auto !important",
    "margin: 0 !important",
    "padding: 0 !important",
    "border: 0 !important",
    "background: transparent !important",
    "overflow: visible !important",
    "color-scheme: light dark",
  ].join(";");

  const shadow = host.attachShadow({ mode: "open" });
  const style = document.createElement("style");
  style.textContent = SHADOW_BASE_CSS;
  shadow.append(style);
  return { host, shadow };
}

/** Attribute helper shared by the injected surfaces. */
export function fpAttributes(
  kind: string,
  extra: Record<string, string> = {},
): Record<string, string> {
  return { [FP_ATTR]: kind, ...extra };
}

/** Append a component stylesheet to a shadow root. */
export function appendShadowStyle(shadow: ShadowRoot, css: string): void {
  const style = document.createElement("style");
  style.textContent = css;
  shadow.append(style);
}

/**
 * Parse a static markup string into nodes and append them to a shadow root.
 * Used for the small inline SVG/glyph fragments that are not built with DOM
 * APIs; never pass user or page content to it.
 */
export function appendShadowMarkup(shadow: ShadowRoot, markup: string): void {
  const wrapper = document.createElement("div");
  wrapper.innerHTML = markup;
  shadow.append(...Array.from(wrapper.childNodes));
}
