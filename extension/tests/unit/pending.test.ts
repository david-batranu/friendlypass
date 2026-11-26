/**
 * WP4b unit tests for the pending submitted-credential store.
 *
 * The store owns every isolation rule in the feature, so these tests cover the
 * ones that must never regress: one-minute expiry, per-tab isolation,
 * cross-site suppression, frame isolation, "never for this site", and
 * surviving a service-worker restart because state only lives in the injected
 * session storage.
 */

import { describe, expect, it } from "vitest";

import {
  PENDING_STORAGE_KEY,
  createPendingStore,
  originOfUrl,
  readPendingTtlMs,
  siteKeyFromUrl,
  type PendingStorageArea,
} from "../../src/background/pending";

class MemoryArea implements PendingStorageArea {
  private readonly data = new Map<string, unknown>();
  writes = 0;

  async get(key: string): Promise<Record<string, unknown>> {
    if (!this.data.has(key)) return {};
    return { [key]: structuredClone(this.data.get(key)) };
  }

  async set(items: Record<string, unknown>): Promise<void> {
    this.writes += 1;
    for (const [key, value] of Object.entries(items)) {
      this.data.set(key, structuredClone(value));
    }
  }

  async remove(key: string): Promise<void> {
    this.data.delete(key);
  }

  keys(): string[] {
    return [...this.data.keys()];
  }
}

const LOGIN = "https://app.example.com/login";
const PASSWORD = "correct horse battery staple";

function submission(overrides: Record<string, unknown> = {}) {
  return {
    tabId: 7,
    frameId: 0,
    url: LOGIN,
    username: "alice@example.com",
    password: PASSWORD,
    ...overrides,
  };
}

describe("pending submitted credentials", () => {
  it("returns the pair once on the same site and then forgets it", async () => {
    const storage = new MemoryArea();
    const store = createPendingStore({ storage });

    expect(await store.store(submission())).toBe(true);
    const pending = await store.take({
      tabId: 7,
      frameId: 0,
      url: "https://app.example.com/welcome",
    });
    expect(pending?.username).toBe("alice@example.com");
    expect(pending?.password).toBe(PASSWORD);
    expect(pending?.origin).toBe("https://app.example.com");

    // Consumed: a second page load must not show the banner again.
    expect(
      await store.take({ tabId: 7, frameId: 0, url: "https://app.example.com/welcome" }),
    ).toBeNull();
    expect(storage.keys()).not.toContain(PENDING_STORAGE_KEY);
  });

  it("expires after the TTL", async () => {
    const storage = new MemoryArea();
    let now = 1_000;
    const store = createPendingStore({ storage, now: () => now, ttlMs: 1_000 });

    expect(await store.store(submission())).toBe(true);
    now = 1_999;
    expect(
      await store.take({ tabId: 7, frameId: 0, url: LOGIN }),
    ).not.toBeNull();

    now = 2_000;
    expect(await store.store(submission())).toBe(true);
    now = 3_000;
    expect(await store.take({ tabId: 7, frameId: 0, url: LOGIN })).toBeNull();
  });

  it("never hands one tab's submission to another tab", async () => {
    const storage = new MemoryArea();
    const store = createPendingStore({ storage });

    expect(await store.store(submission({ tabId: 1 }))).toBe(true);
    expect(await store.store(submission({ tabId: 2, username: "bob@example.com" }))).toBe(
      true,
    );

    const first = await store.take({ tabId: 1, frameId: 0, url: LOGIN });
    expect(first?.username).toBe("alice@example.com");
    const second = await store.take({ tabId: 2, frameId: 0, url: LOGIN });
    expect(second?.username).toBe("bob@example.com");
    expect(await store.take({ tabId: 3, frameId: 0, url: LOGIN })).toBeNull();
  });

  it("suppresses the banner on a different site but allows a sibling subdomain", async () => {
    const storage = new MemoryArea();
    const store = createPendingStore({ storage });

    expect(await store.store(submission())).toBe(true);
    // Different registrable domain: no banner, and the pending pair is not
    // consumed by the wrong site.
    expect(
      await store.take({ tabId: 7, frameId: 0, url: "https://evil.example.net/" }),
    ).toBeNull();
    // Same registrable domain (a redirect from login. to app.): allowed.
    expect(
      await store.take({ tabId: 7, frameId: 0, url: "https://login.example.com/step" }),
    ).not.toBeNull();
  });

  it("treats different loopback ports as different sites", async () => {
    const storage = new MemoryArea();
    const store = createPendingStore({ storage });

    expect(await store.store(submission({ url: "http://127.0.0.1:4100/login" }))).toBe(
      true,
    );
    expect(
      await store.take({ tabId: 7, frameId: 0, url: "http://127.0.0.1:4200/home" }),
    ).toBeNull();
    expect(
      await store.take({ tabId: 7, frameId: 0, url: "http://127.0.0.1:4100/home" }),
    ).not.toBeNull();
  });

  it("only returns the pair to the frame that submitted it", async () => {
    const storage = new MemoryArea();
    const store = createPendingStore({ storage });

    expect(await store.store(submission({ frameId: 4 }))).toBe(true);
    expect(await store.take({ tabId: 7, frameId: 0, url: LOGIN })).toBeNull();
    expect(await store.take({ tabId: 7, frameId: 4, url: LOGIN })).not.toBeNull();
  });

  it("never hands a submission back to the document that stored it", async () => {
    // The submitting page is still alive until the navigation commits, and its
    // own pending-check can run in that window. It must not consume the pair:
    // the next document has to get the banner, and the old one must not.
    const storage = new MemoryArea();
    const store = createPendingStore({ storage });

    expect(await store.store(submission({ documentId: "login-doc" }))).toBe(true);
    expect(
      await store.take({ tabId: 7, frameId: 0, url: LOGIN, documentId: "login-doc" }),
    ).toBeNull();

    const next = await store.take({
      tabId: 7,
      frameId: 0,
      url: LOGIN,
      documentId: "home-doc",
    });
    expect(next?.username).toBe("alice@example.com");
    expect(next?.password).toBe(PASSWORD);
  });

  it("does not store for an origin the user opted out of", async () => {
    const storage = new MemoryArea();
    const never = new MemoryArea();
    const store = createPendingStore({ storage, neverStorage: never });

    await store.never("https://app.example.com");
    expect(await store.isNever("https://app.example.com")).toBe(true);
    expect(await store.store(submission())).toBe(false);
    expect(await store.take({ tabId: 7, frameId: 0, url: LOGIN })).toBeNull();

    // Another origin is unaffected.
    expect(
      await store.store(submission({ url: "https://other.example.com/login" })),
    ).toBe(true);
  });

  it("survives a service-worker restart because it only uses storage", async () => {
    const session = new MemoryArea();
    const before = createPendingStore({ storage: session });
    expect(await before.store(submission())).toBe(true);
    // A new worker has no in-memory state; it rebuilds from storage.session.
    const after = createPendingStore({ storage: session });
    const pending = await after.take({ tabId: 7, frameId: 0, url: LOGIN });
    expect(pending?.password).toBe(PASSWORD);
    expect(await before.take({ tabId: 7, frameId: 0, url: LOGIN })).toBeNull();
  });

  it("clears a tab explicitly", async () => {
    const storage = new MemoryArea();
    const store = createPendingStore({ storage });
    expect(await store.store(submission())).toBe(true);
    await store.clear(7);
    expect(await store.take({ tabId: 7, frameId: 0, url: LOGIN })).toBeNull();
  });

  it("reads a shortened test TTL and ignores invalid values", async () => {
    const settings = new MemoryArea();
    expect(await readPendingTtlMs(settings)).toBe(60_000);

    await settings.set({ "friendlypass.pending.settings.v1": { ttlMs: 800 } });
    expect(await readPendingTtlMs(settings)).toBe(800);

    await settings.set({ "friendlypass.pending.settings.v1": { ttlMs: 120_000 } });
    expect(await readPendingTtlMs(settings)).toBe(60_000);

    await settings.set({ "friendlypass.pending.settings.v1": { ttlMs: -1 } });
    expect(await readPendingTtlMs(settings)).toBe(60_000);
  });

  it("derives site keys for domains and IP hosts", () => {
    expect(siteKeyFromUrl("https://app.example.com/x")).toBe("example.com");
    expect(siteKeyFromUrl("https://example.com/x")).toBe("example.com");
    expect(siteKeyFromUrl("https://a.b.example.co.uk/x")).toBe("example.co.uk");
    expect(siteKeyFromUrl("http://127.0.0.1:4100/")).toBe("http://127.0.0.1:4100");
    expect(siteKeyFromUrl("not a url")).toBeNull();
    expect(siteKeyFromUrl("file:///etc/passwd")).toBeNull();
    expect(originOfUrl("https://app.example.com/login")).toBe("https://app.example.com");
    expect(originOfUrl("mailto:alice@example.com")).toBeNull();
  });
});
