/**
 * The popup fallback window (WP5 integration fix).
 *
 * Chrome opens the popup page with `windows.create({ url })`. Firefox creates
 * the window first and navigates its tab, because a `moz-extension:` URL is
 * not necessarily navigable in a brand-new popup window (the visible symptom
 * is an empty window from the inline menu's "Open friendlypass").
 */

import { describe, expect, it, vi } from "vitest";

import {
  POPUP_PAGE,
  openPopupWindow,
  popupPageUrl,
  type PopupWindowApi,
} from "../../src/common/popup";

const EXTENSION_URL = "moz-extension://test-uuid";

function getURL(path: string): string {
  return `${EXTENSION_URL}/${path}`;
}

function fakeApi(overrides: Partial<PopupWindowApi> = {}): PopupWindowApi {
  return {
    kind: "chrome",
    getURL,
    createWindow: vi.fn(async () => ({ id: 7, tabs: [{ id: 11 }] })),
    updateTab: vi.fn(async () => ({ id: 11 })),
    removeWindow: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe("popupPageUrl", () => {
  it("builds the page URL with runtime.getURL", () => {
    expect(popupPageUrl(undefined, getURL)).toBe(
      `${EXTENSION_URL}/${POPUP_PAGE}`,
    );
  });

  it("carries the caller tab as a query parameter", () => {
    expect(popupPageUrl(42, getURL)).toBe(
      `${EXTENSION_URL}/${POPUP_PAGE}?tab=42`,
    );
  });

  it("ignores an invalid tab id", () => {
    for (const value of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(popupPageUrl(value, getURL)).toBe(
        `${EXTENSION_URL}/${POPUP_PAGE}`,
      );
    }
  });
});

describe("openPopupWindow", () => {
  it("uses a single windows.create({ url }) call on Chrome", async () => {
    const api = fakeApi({ kind: "chrome" });
    await expect(openPopupWindow(5, api)).resolves.toEqual({ via: "window" });

    expect(api.createWindow).toHaveBeenCalledTimes(1);
    expect(api.createWindow).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "popup",
        url: `${EXTENSION_URL}/${POPUP_PAGE}?tab=5`,
      }),
    );
    expect(api.updateTab).not.toHaveBeenCalled();
  });

  it("creates the Firefox window first and then navigates its tab", async () => {
    const api = fakeApi({ kind: "firefox" });
    await expect(openPopupWindow(5, api)).resolves.toEqual({
      via: "window-tab",
    });

    expect(api.createWindow).toHaveBeenCalledTimes(1);
    expect(api.createWindow).toHaveBeenCalledWith(
      expect.not.objectContaining({ url: expect.anything() }),
    );
    expect(api.updateTab).toHaveBeenCalledWith(11, {
      url: `${EXTENSION_URL}/${POPUP_PAGE}?tab=5`,
    });
  });

  it("closes the empty Firefox window and retries when tabs.update fails", async () => {
    const api = fakeApi({
      kind: "firefox",
      updateTab: vi.fn(async () => {
        throw new Error("no such tab");
      }),
    });
    await expect(openPopupWindow(5, api)).resolves.toEqual({ via: "window" });

    expect(api.removeWindow).toHaveBeenCalledWith(7);
    expect(api.createWindow).toHaveBeenCalledTimes(2);
    expect(api.createWindow).toHaveBeenLastCalledWith(
      expect.objectContaining({
        url: `${EXTENSION_URL}/${POPUP_PAGE}?tab=5`,
      }),
    );
  });

  it("falls back to windows.create when Firefox returns no tab", async () => {
    const api = fakeApi({
      kind: "firefox",
      createWindow: vi.fn(async () => ({ id: 7 })),
    });
    await expect(openPopupWindow(undefined, api)).resolves.toEqual({
      via: "window",
    });

    expect(api.updateTab).not.toHaveBeenCalled();
    expect(api.createWindow).toHaveBeenLastCalledWith(
      expect.objectContaining({ url: `${EXTENSION_URL}/${POPUP_PAGE}` }),
    );
  });
});
