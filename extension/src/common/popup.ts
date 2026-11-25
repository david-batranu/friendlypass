/**
 * The toolbar popup's fallback window, shared by the background and the unit
 * tests.
 *
 * Chrome can usually open the action popup itself. Firefox cannot when the
 * request comes from a content script (the user-gesture token does not
 * survive the message), so the background opens `popup/popup.html` in a small
 * window instead.
 *
 * Firefox may create a `type: "popup"` window before a privileged
 * `moz-extension:` URL is navigable, which shows an empty window. There, the
 * window is created first and its tab is then navigated to the popup page with
 * `tabs.update`; Chrome keeps the single `windows.create({ url })` call.
 */

import {
  detectBrowserKind,
  tabUpdate,
  windowsCreate,
  windowsRemove,
  type BrowserKind,
} from "./platform";

/** Extension-relative path of the toolbar popup. */
export const POPUP_PAGE = "popup/popup.html";

const POPUP_WIDTH = 380;
const POPUP_HEIGHT = 620;

/** APIs the fallback needs; injectable so the unit tests stay browser-free. */
export interface PopupWindowApi {
  kind: BrowserKind;
  getURL(path: string): string;
  createWindow(options: Record<string, unknown>): Promise<unknown>;
  updateTab?(
    tabId: number,
    options: Record<string, unknown>,
  ): Promise<unknown>;
  removeWindow?(windowId: number): Promise<void>;
}

/** The real `chrome.*` implementation. */
export function popupWindowApi(): PopupWindowApi {
  return {
    kind: detectBrowserKind(),
    getURL: (path) => chrome.runtime.getURL(path),
    createWindow: (options) => windowsCreate(options),
    updateTab: (tabId, options) => tabUpdate(tabId, options),
    removeWindow: (windowId) => windowsRemove(windowId),
  };
}

/**
 * Absolute URL of the popup page. A valid tab id is passed as `?tab=` so the
 * popup resolves the caller's tab even though it now runs in its own window.
 */
export function popupPageUrl(
  tabId: number | undefined,
  getURL: (path: string) => string = (path) => chrome.runtime.getURL(path),
): string {
  const base = getURL(POPUP_PAGE);
  if (
    typeof tabId !== "number" ||
    !Number.isInteger(tabId) ||
    tabId < 0
  ) {
    return base;
  }
  const url = new URL(base);
  url.searchParams.set("tab", String(tabId));
  return url.toString();
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : null;
}

function windowIdOf(value: unknown): number | null {
  const id = asRecord(value)?.id;
  return typeof id === "number" && Number.isInteger(id) && id >= 0 ? id : null;
}

function firstTabId(value: unknown): number | null {
  const tabs = asRecord(value)?.tabs;
  if (!Array.isArray(tabs) || tabs.length === 0) return null;
  const id = asRecord(tabs[0])?.id;
  return typeof id === "number" && Number.isInteger(id) && id >= 0 ? id : null;
}

/** How the fallback window was filled, for diagnostics/tests. */
export type PopupWindowVia = "window" | "window-tab";

/**
 * Open the popup page in a small window, scoped to `tabId` when known.
 *
 * Rejects only when no window could be opened at all; a failed Firefox
 * `tabs.update` closes the empty window and retries with `windows.create`.
 */
export async function openPopupWindow(
  tabId?: number,
  api: PopupWindowApi = popupWindowApi(),
): Promise<{ via: PopupWindowVia }> {
  const url = popupPageUrl(tabId, api.getURL);
  const windowOptions: Record<string, unknown> = {
    type: "popup",
    width: POPUP_WIDTH,
    height: POPUP_HEIGHT,
    focused: true,
  };

  if (api.kind === "firefox" && api.updateTab) {
    const created = await api.createWindow(windowOptions);
    const windowId = windowIdOf(created);
    const targetTabId = firstTabId(created);
    if (targetTabId !== null) {
      try {
        await api.updateTab(targetTabId, { url });
        return { via: "window-tab" };
      } catch {
        if (windowId !== null && api.removeWindow) {
          await api.removeWindow(windowId).catch(() => undefined);
        }
      }
    } else if (windowId !== null && api.removeWindow) {
      await api.removeWindow(windowId).catch(() => undefined);
    }
  }

  await api.createWindow({ ...windowOptions, url });
  return { via: "window" };
}
