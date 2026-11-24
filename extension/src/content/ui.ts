/**
 * Content-script UI primitives (WP4, ported from upstream `content/ui.js`).
 *
 * Only layout-independent helpers live here so the field-detection core can be
 * unit-tested in a plain page (see `testing.ts`). Anything that talks to the
 * service worker stays in `index.ts`.
 *
 * Upstream relies on `Element.prototype` monkey-patching and closed shadow
 * roots; both are dropped deliberately. Icons, menus and banners are ordinary
 * hosts with an **open** shadow root (`icon.ts`) or light-DOM markup, which
 * keeps page CSS out without hiding the elements from tests and WP6.
 */

export const MIN_INPUT_FIELD_WIDTH_PX = 8;
export const MIN_INPUT_FIELD_OFFSET_WIDTH = 60;
export const MIN_OPACITY = 0.7;
export const MAX_OPACITY = 1;

/** Attribute prefix shared by every friendlypass element injected into a page. */
export const FP_ATTR = "data-friendlypass";

/** True for any node injected by this content script. */
export function isOwnElement(node: Node | null): boolean {
  if (!node || node.nodeType !== Node.ELEMENT_NODE) {
    return false;
  }
  const element = node as Element;
  return (
    element.hasAttribute(FP_ATTR) ||
    element.closest(`[${FP_ATTR}]`) !== null
  );
}

/** Lower-cased value of an attribute, or undefined when it is absent. */
export function lowerAttr(element: Element, name: string): string | undefined {
  const value = element.getAttribute(name);
  return value === null ? undefined : value.toLowerCase();
}

/** `true` for the input types the fill engine considers. */
export function acceptedInputType(element: HTMLInputElement): boolean {
  const type = element.type;
  return (
    type === "text" ||
    type === "email" ||
    type === "password" ||
    type === "tel" ||
    type === "number" ||
    type === "username" ||
    type === ""
  );
}

function opacityAllowed(value: string): boolean {
  if (value === "") {
    return true;
  }
  const opacity = Number(value);
  return Number.isFinite(opacity) && opacity >= MIN_OPACITY && opacity <= MAX_OPACITY;
}

/**
 * Visibility check modelled on upstream `kpxcFields.isVisible`.
 *
 * The topmost-element (`elementFromPoint`) probe is intentionally omitted: our
 * own icon sits above the field, and page overlays are handled by the
 * consent/overlay heuristics upstream carries per site. Size, position,
 * `visibility`, `display` and opacity are still enforced, which is what the
 * hidden-field regression cases depend on.
 */
export function isElementVisible(element: HTMLElement): boolean {
  if (!element.isConnected) {
    return false;
  }

  const rect = element.getBoundingClientRect();
  if (
    rect.x < 0 ||
    rect.y < 0 ||
    rect.width < MIN_INPUT_FIELD_WIDTH_PX ||
    rect.height < MIN_INPUT_FIELD_WIDTH_PX
  ) {
    return false;
  }

  const maxWidth = Math.max(
    document.body?.scrollWidth ?? 0,
    document.body?.offsetWidth ?? 0,
    document.documentElement?.clientWidth ?? 0,
  );
  const maxHeight = Math.max(
    document.body?.scrollHeight ?? 0,
    document.body?.offsetHeight ?? 0,
    document.documentElement?.clientHeight ?? 0,
  );
  // A field laid out entirely outside the document is hidden (upstream
  // `hiddenFields1` case). Once scrolled the rect is viewport-relative, so only
  // reject when the page itself is not scrollable in that direction.
  if (maxWidth > 0 && rect.x > maxWidth + window.scrollX) {
    return false;
  }
  if (maxHeight > 0 && rect.y > maxHeight + window.scrollY) {
    return false;
  }

  const style = getComputedStyle(element);
  if (style.visibility === "hidden" || style.visibility === "collapse") {
    return false;
  }
  if (style.display === "none") {
    return false;
  }
  if (!opacityAllowed(style.opacity)) {
    return false;
  }
  const width = Number.parseFloat(style.width);
  const height = Number.parseFloat(style.height);
  if (style.width.endsWith("px") && Number.isFinite(width) && width <= MIN_INPUT_FIELD_WIDTH_PX) {
    return false;
  }
  if (style.height.endsWith("px") && Number.isFinite(height) && height <= MIN_INPUT_FIELD_WIDTH_PX) {
    return false;
  }

  for (let parent = element.parentElement; parent; parent = parent.parentElement) {
    const parentStyle = getComputedStyle(parent);
    if (parentStyle.display === "none") {
      return false;
    }
    if (!opacityAllowed(parentStyle.opacity)) {
      return false;
    }
  }

  // Walk out of an open shadow root too: the host can be hidden.
  const root = element.getRootNode();
  if (root instanceof ShadowRoot) {
    return isElementVisible(root.host as HTMLElement);
  }

  return true;
}

/** `true` when the element's writing direction resolves to RTL. */
export function isRTL(element: HTMLElement | null): boolean {
  if (!element) {
    return false;
  }
  const style = getComputedStyle(element);
  if (style.textAlign.toLowerCase() === "left") {
    return false;
  }
  if (style.textAlign.toLowerCase() === "right") {
    return true;
  }
  for (let parent: HTMLElement | null = element; parent; parent = parent.parentElement) {
    const dir = lowerAttr(parent, "dir");
    if (dir === "ltr") {
      return false;
    }
    if (dir === "rtl") {
      return true;
    }
  }
  return false;
}

/** Create an element with classes, attributes and text in one call. */
export function createElement<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  attributes?: Record<string, string>,
  textContent?: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) {
    for (const name of className.split(" ")) {
      if (name) {
        element.classList.add(name);
      }
    }
  }
  if (attributes) {
    for (const [name, value] of Object.entries(attributes)) {
      element.setAttribute(name, value);
    }
  }
  if (textContent !== undefined) {
    element.textContent = textContent;
  }
  return element;
}

/** A small, self-dismissing toast. Never receives passwords. */
export function showNotification(
  type: "success" | "info" | "warning" | "error",
  message: string,
): void {
  if (!message || typeof document === "undefined" || !document.body) {
    return;
  }

  document.querySelector(`[${FP_ATTR}="notification"]`)?.remove();

  const host = createElement("div", undefined, {
    [FP_ATTR]: "notification",
    "data-friendlypass-type": type,
    role: "status",
  });
  host.style.cssText = [
    "all: initial",
    "display: block",
    "position: fixed",
    "z-index: 2147483647",
    "right: 16px",
    "top: 16px",
    "max-width: 360px",
    "font: 13px/1.4 system-ui, -apple-system, sans-serif",
    "color: #1f2933",
    "background: #ffffff",
    "border: 1px solid rgba(0, 0, 0, 0.18)",
    "border-left: 4px solid " +
      (type === "error" ? "#c0392b" : type === "warning" ? "#b7791f" : "#2f855a"),
    "border-radius: 6px",
    "box-shadow: 0 6px 24px rgba(0, 0, 0, 0.18)",
    "padding: 10px 12px",
  ].join(";");
  host.textContent = message;
  host.addEventListener("click", () => host.remove());
  document.body.append(host);
  window.setTimeout(() => host.remove(), 6000);
}

/**
 * Form action URL, or the page URL when the form has no usable action.
 * Mirrors upstream `kpxc.getFormActionUrl`.
 */
export function formActionUrl(form: HTMLFormElement | null): string | undefined {
  if (!form) {
    return undefined;
  }
  const action = form.getAttribute("action");
  if (action === null || action.trim() === "") {
    return undefined;
  }
  try {
    const resolved = new URL(action, document.baseURI).href;
    // `form.action` is the empty string for `action="#"`-style forms; sending
    // the page URL twice only confuses the app's URL matching.
    return resolved === document.documentURI ? undefined : resolved;
  } catch {
    return undefined;
  }
}
