/**
 * Desktop approval notices (vitest / Node).
 *
 * The browser UI is exercised by Playwright; this locks the timing contract:
 * fast requests never flash a notification, shown ones are cleared exactly
 * once, and dismissal before the delay cancels creation.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import {
  clearStaleApprovalNotices,
  showApprovalNotice,
  withApprovalNotice,
} from "../../src/background/notifications";

interface ChromeLike {
  chrome?: {
    notifications: {
      create: (
        id: string,
        options: unknown,
        callback: (id: string) => void,
      ) => void;
      clear: (id: string, callback: (cleared: boolean) => void) => void;
      getAll(callback: (items: Record<string, true>) => void): void;
    };
    runtime: { lastError?: unknown; getURL(path: string): string };
  };
}

let create: Mock<
  (id: string, options: unknown, callback: (id: string) => void) => void
>;
let clear: Mock<(id: string, callback: (cleared: boolean) => void) => void>;
let existing: Record<string, true>;

beforeEach(() => {
  vi.useFakeTimers();
  create = vi.fn(
    (id: string, _options: unknown, callback: (id: string) => void) => callback(id),
  );
  clear = vi.fn(
    (_id: string, callback: (cleared: boolean) => void) => callback(true),
  );
  existing = {};
  const getAll = vi.fn((callback: (items: Record<string, true>) => void) =>
    callback(existing),
  );
  const scope = globalThis as ChromeLike;
  scope.chrome = {
    notifications: { create, clear, getAll },
    runtime: { lastError: undefined, getURL: (path: string) => path },
  };
});

afterEach(() => {
  vi.useRealTimers();
  const scope = globalThis as ChromeLike;
  delete scope.chrome;
});

describe("passkey approval notices", () => {
  it("never flashes for a request answered inside the delay", () => {
    const notice = showApprovalNotice(
      "friendlypass",
      "Approve saving a passkey for example.com.",
    );
    notice.dismiss();
    vi.advanceTimersByTime(5_000);
    expect(create).not.toHaveBeenCalled();
    expect(clear).not.toHaveBeenCalled();
  });

  it("shows after the delay and clears once when the request settles", () => {
    const notice = showApprovalNotice(
      "friendlypass",
      "Approve saving a passkey for example.com.",
    );
    vi.advanceTimersByTime(499);
    expect(create).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(create).toHaveBeenCalledTimes(1);

    const [id, options] = create.mock.calls[0];
    expect(options).toMatchObject({
      type: "basic",
      iconUrl: "icons/icon-128.png",
      title: "friendlypass",
      message: "Approve saving a passkey for example.com.",
    });

    notice.dismiss();
    notice.dismiss();
    expect(clear).toHaveBeenCalledTimes(1);
    expect(clear.mock.calls[0][0]).toBe(id);
  });

  it("clears the shown notice when the action succeeds", async () => {
    const gate = Promise.withResolvers<void>();
    const result = withApprovalNotice(
      "friendlypass",
      "Approve saving a passkey for example.com.",
      () => gate.promise,
    );
    await vi.advanceTimersByTimeAsync(600);
    expect(create).toHaveBeenCalledTimes(1);

    gate.resolve();
    await result;
    expect(clear).toHaveBeenCalledTimes(1);
  });

  it("clears the notice and rethrows when the action fails", async () => {
    const gate = Promise.withResolvers<void>();
    const result = withApprovalNotice(
      "friendlypass",
      "Approve saving a passkey for example.com.",
      () => gate.promise,
    );
    await vi.advanceTimersByTimeAsync(600);
    expect(create).toHaveBeenCalledTimes(1);

    gate.reject(new Error("denied"));
    await expect(result).rejects.toThrow("denied");
    expect(clear).toHaveBeenCalledTimes(1);
  });

  it("clears only notices left by an earlier service worker", () => {
    existing = { "friendlypass-approval-4": true, "other-notice": true };
    clearStaleApprovalNotices();
    expect(clear).toHaveBeenCalledTimes(1);
    expect(clear.mock.calls[0][0]).toBe("friendlypass-approval-4");
  });
});
