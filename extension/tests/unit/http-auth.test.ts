/**
 * WP5 unit tests — HTTP Basic/Digest settlement, deadline, loop guard, proxy,
 * host-down and the multi-match picker.
 *
 * The fake adapter is the only platform dependency: the controller under test
 * is the same one the service worker installs. Never assert on credentials in
 * logs; only on the exact callback payloads the browser would receive.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createChromeHttpAuthAdapter,
  createDefaultHttpAuthAdapter,
  createFirefoxHttpAuthAdapter,
  createHttpAuthController,
  createMemoryHttpAuthSettingsStore,
  HTTP_AUTH_DEADLINE_MS,
  type HttpAuthAdapter,
  type HttpAuthCallback,
  type HttpAuthChallengeDetails,
  type HttpAuthDiagnostics,
  type HttpAuthLookup,
  type HttpAuthPicker,
  type HttpAuthPickerRequest,
  type HttpAuthResponse,
} from "../../src/background/http-auth";
import type { CredentialEntry } from "../../src/common/types";

// ---------------------------------------------------------------------------
// Fixtures and fakes
// ---------------------------------------------------------------------------

function entry(
  login: string,
  password: string,
  uuid: string,
  extra: Partial<CredentialEntry> = {},
): CredentialEntry {
  return {
    login,
    password,
    name: `${login} account`,
    uuid,
    group: "Test",
    ...extra,
  };
}

const ALICE = entry("alice", "alice-secret", "11111111111111111111111111111111");
const BOB = entry("bob", "bob-secret", "22222222222222222222222222222222");

const DETAILS: HttpAuthChallengeDetails = {
  requestId: "request-1",
  url: "https://intranet.example.com/private",
  realm: "Intranet",
  scheme: "basic",
  isProxy: false,
  tabId: 7,
  challenger: { host: "intranet.example.com", port: 443 },
};

class FakeAdapter implements HttpAuthAdapter {
  readonly kind = "chrome" as const;
  readonly responses: HttpAuthResponse[] = [];
  listener: ((details: HttpAuthChallengeDetails, callback: HttpAuthCallback) => void) | null =
    null;
  completed: ((details: { requestId: string }) => void) | null = null;
  errored: ((details: { requestId: string }) => void) | null = null;

  install(listener: (details: HttpAuthChallengeDetails, callback: HttpAuthCallback) => void): void {
    this.listener = listener;
  }

  onCompleted(listener: (details: { requestId: string }) => void): void {
    this.completed = listener;
  }

  onErrorOccurred(listener: (details: { requestId: string }) => void): void {
    this.errored = listener;
  }

  fire(details: Partial<HttpAuthChallengeDetails> = {}): Promise<HttpAuthResponse> {
    if (!this.listener) throw new Error("adapter not installed");
    return new Promise<HttpAuthResponse>((resolve) => {
      this.listener?.({ ...DETAILS, ...details }, (response) => {
        this.responses.push(response);
        resolve(response);
      });
    });
  }

  complete(requestId: string): void {
    this.completed?.({ requestId });
  }
}

class FakePicker implements HttpAuthPicker {
  readonly requests: HttpAuthPickerRequest[] = [];
  readonly cancelled: string[] = [];
  next: string | null = null;
  never = false;

  async show(request: HttpAuthPickerRequest): Promise<string | null> {
    this.requests.push(request);
    if (this.never) return await new Promise<string | null>(() => undefined);
    return this.next;
  }

  cancel(token: string): void {
    this.cancelled.push(token);
  }
}

interface Harness {
  controller: ReturnType<typeof createHttpAuthController>;
  adapter: FakeAdapter;
  picker: FakePicker;
  lookupCalls: HttpAuthChallengeDetails[];
  diagnostics(): HttpAuthDiagnostics;
}

function setup(
  entries: CredentialEntry[] | (() => Promise<CredentialEntry[]>) = [ALICE],
  overrides: {
    settings?: ReturnType<typeof createMemoryHttpAuthSettingsStore>;
    picker?: FakePicker;
    deadlineMs?: number;
    pickerTimeoutMs?: number;
  } = {},
): Harness {
  const adapter = new FakeAdapter();
  const picker = overrides.picker ?? new FakePicker();
  const lookupCalls: HttpAuthChallengeDetails[] = [];
  const lookup: HttpAuthLookup =
    typeof entries === "function"
      ? async () => await entries()
      : async () => {
          lookupCalls.push(DETAILS);
          return entries;
        };

  const controller = createHttpAuthController({
    lookup,
    adapter,
    settings:
      overrides.settings ?? createMemoryHttpAuthSettingsStore(),
    picker,
    deadlineMs: overrides.deadlineMs ?? HTTP_AUTH_DEADLINE_MS,
    pickerTimeoutMs: overrides.pickerTimeoutMs ?? 6_000,
  });
  controller.install();
  return {
    controller,
    adapter,
    picker,
    lookupCalls,
    diagnostics: () => controller.diagnostics(),
  };
}

async function flush(): Promise<void> {
  await vi.advanceTimersByTimeAsync(0);
  await Promise.resolve();
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  delete (globalThis as { chrome?: unknown }).chrome;
  delete (globalThis as { browser?: unknown }).browser;
});

// ---------------------------------------------------------------------------
// Platform adapter
// ---------------------------------------------------------------------------

describe("chrome webRequest adapter", () => {
  it("registers asyncBlocking for all URLs and forwards one response", () => {
    const registrations: Array<{
      listener: (details: chrome.webRequest.OnAuthRequiredDetails, callback?: (response: chrome.webRequest.BlockingResponse) => void) => chrome.webRequest.BlockingResponse | undefined;
      filter: chrome.webRequest.RequestFilter;
      extra: string[];
    }> = [];
    const completed = vi.fn();
    const errored = vi.fn();

    (globalThis as { chrome?: unknown }).chrome = {
      webRequest: {
        onAuthRequired: {
          addListener: (
            listener: (typeof registrations)[number]["listener"],
            filter: chrome.webRequest.RequestFilter,
            extra: string[],
          ) => {
            registrations.push({ listener, filter, extra });
          },
        },
        onCompleted: { addListener: completed },
        onErrorOccurred: { addListener: errored },
      },
    };

    const adapter = createChromeHttpAuthAdapter();
    expect(adapter).not.toBeNull();
    expect(adapter?.kind).toBe("chrome");

    const challenges: HttpAuthChallengeDetails[] = [];
    const responses: HttpAuthResponse[] = [];
    adapter?.install((details, callback) => {
      challenges.push(details);
      callback({ cancel: false });
    });
    adapter?.onCompleted(() => undefined);
    adapter?.onErrorOccurred(() => undefined);

    expect(registrations).toHaveLength(1);
    expect(registrations[0].filter).toEqual({ urls: ["<all_urls>"] });
    expect(registrations[0].extra).toEqual(["asyncBlocking"]);
    expect(completed).toHaveBeenCalledWith(expect.any(Function), {
      urls: ["<all_urls>"],
    });
    expect(errored).toHaveBeenCalledWith(expect.any(Function), {
      urls: ["<all_urls>"],
    });

    registrations[0].listener(
      {
        requestId: "adapter-request",
        url: "https://intranet.example.com/private",
        realm: "Intranet",
        scheme: "Basic",
        isProxy: false,
        tabId: -1,
        challenger: { host: "intranet.example.com", port: 443 },
        method: "GET",
        type: "main_frame",
        frameId: 0,
        parentFrameId: -1,
        timeStamp: Date.now(),
        statusCode: 401,
        statusLine: "HTTP/1.1 401 Unauthorized",
        documentLifecycle: "active",
        frameType: "outermost_frame",
      },
      (response) => responses.push(response as HttpAuthResponse),
    );

    expect(challenges).toHaveLength(1);
    expect(challenges[0]).toMatchObject({
      requestId: "adapter-request",
      scheme: "Basic",
      realm: "Intranet",
      isProxy: false,
      challenger: { host: "intranet.example.com", port: 443 },
    });
    expect(responses).toEqual([{ cancel: false }]);
  });
});

// ---------------------------------------------------------------------------
// Firefox platform adapter
// ---------------------------------------------------------------------------

interface FakeFirefoxEvent {
  listener?: (details: Record<string, unknown>) => Promise<HttpAuthResponse>;
  filter?: { urls: string[] };
  extra?: string[];
}

function installFirefoxWebRequest(): {
  auth: FakeFirefoxEvent;
  completed: ReturnType<typeof vi.fn>;
  errored: ReturnType<typeof vi.fn>;
} {
  const auth: FakeFirefoxEvent = {};
  const completed = vi.fn();
  const errored = vi.fn();
  (globalThis as { browser?: unknown }).browser = {
    runtime: { getBrowserInfo: () => Promise.resolve({ name: "Firefox" }) },
    webRequest: {
      onAuthRequired: {
        addListener: (
          listener: FakeFirefoxEvent["listener"],
          filter: { urls: string[] },
          extra: string[],
        ) => {
          auth.listener = listener;
          auth.filter = filter;
          auth.extra = extra;
        },
      },
      onCompleted: { addListener: completed },
      onErrorOccurred: { addListener: errored },
    },
  };
  return { auth, completed, errored };
}

const FIREFOX_DETAILS = {
  requestId: "firefox-request-1",
  url: "https://intranet.example.com/private",
  realm: "Intranet",
  scheme: "basic",
  isProxy: false,
  tabId: 3,
  challenger: { host: "intranet.example.com", port: 443 },
};

describe("firefox webRequest adapter", () => {
  it("registers blocking and resolves a Promise<BlockingResponse>", async () => {
    const fake = installFirefoxWebRequest();
    const adapter = createFirefoxHttpAuthAdapter();
    expect(adapter).not.toBeNull();
    expect(adapter?.kind).toBe("firefox");

    const seen: HttpAuthChallengeDetails[] = [];
    adapter?.install((details, callback) => {
      seen.push(details);
      callback({ authCredentials: { username: "alice", password: "alice-secret" } });
    });
    adapter?.onCompleted(() => undefined);
    adapter?.onErrorOccurred(() => undefined);

    expect(fake.auth.filter).toEqual({ urls: ["<all_urls>"] });
    expect(fake.auth.extra).toEqual(["blocking"]);
    expect(fake.completed).toHaveBeenCalledWith(expect.any(Function), {
      urls: ["<all_urls>"],
    });
    expect(fake.errored).toHaveBeenCalledWith(expect.any(Function), {
      urls: ["<all_urls>"],
    });

    const response = await fake.auth.listener?.(FIREFOX_DETAILS);
    expect(response).toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      requestId: "firefox-request-1",
      url: "https://intranet.example.com/private",
      realm: "Intranet",
      scheme: "basic",
      isProxy: false,
      tabId: 3,
      challenger: { host: "intranet.example.com", port: 443 },
    });
  });

  it("settles exactly once even if the listener answers twice", async () => {
    const fake = installFirefoxWebRequest();
    const adapter = createFirefoxHttpAuthAdapter();
    adapter?.install((_details, callback) => {
      callback({ cancel: false });
      callback({ authCredentials: { username: "late", password: "late" } });
    });

    await expect(fake.auth.listener?.(FIREFOX_DETAILS)).resolves.toEqual({
      cancel: false,
    });
  });

  it("answers cancel:false when the listener throws", async () => {
    const fake = installFirefoxWebRequest();
    const adapter = createFirefoxHttpAuthAdapter();
    adapter?.install(() => {
      throw new Error("listener bug");
    });

    await expect(fake.auth.listener?.(FIREFOX_DETAILS)).resolves.toEqual({
      cancel: false,
    });
  });

  it("never leaves a blocked request hanging (safety deadline)", async () => {
    const fake = installFirefoxWebRequest();
    const adapter = createFirefoxHttpAuthAdapter();
    adapter?.install(() => {
      // Simulates a listener that loses its callback; the adapter must still
      // settle so Firefox can show its own prompt.
    });

    const pending = fake.auth.listener?.(FIREFOX_DETAILS);
    await vi.advanceTimersByTimeAsync(HTTP_AUTH_DEADLINE_MS + 2_000);
    await expect(pending).resolves.toEqual({ cancel: false });
  });

  it("is selected as the default adapter on Firefox", () => {
    installFirefoxWebRequest();
    const adapter = createDefaultHttpAuthAdapter();
    expect(adapter?.kind).toBe("firefox");
  });

  it("returns null when Firefox's webRequest API is absent", () => {
    (globalThis as { browser?: unknown }).browser = {
      runtime: { getBrowserInfo: () => Promise.resolve({}) },
    };
    expect(createFirefoxHttpAuthAdapter()).toBeNull();
  });

  it("ignores Chromium's browser alias", () => {
    (globalThis as { browser?: unknown }).browser = {
      runtime: {},
      webRequest: {
        onAuthRequired: { addListener: () => undefined },
        onCompleted: { addListener: () => undefined },
        onErrorOccurred: { addListener: () => undefined },
      },
    };
    expect(createFirefoxHttpAuthAdapter()).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Settlement and deadline
// ---------------------------------------------------------------------------

describe("http auth settlement", () => {
  it("auto-fills a single match exactly once", async () => {
    const h = setup();
    const pending = h.adapter.fire();

    await flush();
    await expect(pending).resolves.toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });

    // Neither the picker nor a later timer may answer a second time.
    await vi.advanceTimersByTimeAsync(HTTP_AUTH_DEADLINE_MS + 5_000);
    expect(h.adapter.responses).toHaveLength(1);
    expect(h.diagnostics().active).toBe(0);
    expect(h.diagnostics().autoFilled).toBe(1);
  });

  it("honours the 8 s deadline when the lookup never settles", async () => {
    const h = setup(() => new Promise<CredentialEntry[]>(() => undefined));
    const pending = h.adapter.fire();

    await vi.advanceTimersByTimeAsync(HTTP_AUTH_DEADLINE_MS - 1);
    expect(h.adapter.responses).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(h.diagnostics().lastReason).toBe("deadline");

    await vi.advanceTimersByTimeAsync(HTTP_AUTH_DEADLINE_MS);
    expect(h.adapter.responses).toHaveLength(1);
  });

  it("falls back when the lookup rejects (host/app down)", async () => {
    const h = setup(async () => {
      throw new Error("friendlypass is not running");
    });
    const pending = h.adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(h.diagnostics().active).toBe(0);
  });

  it("falls back when no credentials match", async () => {
    const h = setup([]);
    const pending = h.adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(h.diagnostics().lastReason).toBe("no-match");
  });

  it("ignores a lookup that resolves after the deadline", async () => {
    const adapter = new FakeAdapter();
    let resolveLookup!: (entries: CredentialEntry[]) => void;
    const controller = createHttpAuthController({
      lookup: () =>
        new Promise<CredentialEntry[]>((resolve) => {
          resolveLookup = resolve;
        }),
      adapter,
      picker: new FakePicker(),
      settings: createMemoryHttpAuthSettingsStore(),
    });
    controller.install();

    const pending = adapter.fire();
    await vi.advanceTimersByTimeAsync(HTTP_AUTH_DEADLINE_MS);
    await expect(pending).resolves.toEqual({ cancel: false });

    resolveLookup([ALICE]);
    await flush();
    expect(adapter.responses).toHaveLength(1);
    expect(controller.diagnostics().active).toBe(0);
  });

  it("honours a realm stored for an entry", async () => {
    const settings = createMemoryHttpAuthSettingsStore({
      realms: { [ALICE.uuid]: "Some other realm" },
    });
    const h = setup([ALICE], { settings });
    const pending = h.adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(h.diagnostics().lastReason).toBe("no-match");
  });

  it("uses an entry whose stored realm matches the challenge", async () => {
    const settings = createMemoryHttpAuthSettingsStore({
      realms: { [ALICE.uuid]: "Intranet" },
    });
    const h = setup([ALICE], { settings });
    const pending = h.adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });
  });

  it("never auto-answers proxy authentication", async () => {
    const h = setup();
    const pending = h.adapter.fire({ isProxy: true, url: "http://proxy.example:8080/" });
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(h.lookupCalls).toHaveLength(0);
    expect(h.diagnostics().lastReason).toBe("proxy");
  });

  it("never auto-answers NTLM/Negotiate", async () => {
    const h = setup();
    const pending = h.adapter.fire({ scheme: "ntlm" });
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(h.lookupCalls).toHaveLength(0);
    expect(h.diagnostics().lastReason).toBe("unsupported-scheme");
  });

  it("still answers Digest challenges", async () => {
    const h = setup();
    const pending = h.adapter.fire({ scheme: "digest" });
    await flush();
    await expect(pending).resolves.toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });
  });
});

// ---------------------------------------------------------------------------
// Loop guard
// ---------------------------------------------------------------------------

describe("http auth loop guard", () => {
  it("tries the next candidate once, then falls back to Chrome's prompt", async () => {
    const settings = createMemoryHttpAuthSettingsStore({
      lastUsed: { "https://intranet.example.com/": "alice" },
    });
    const h = setup([ALICE, BOB], { settings });

    const first = h.adapter.fire();
    await flush();
    await expect(first).resolves.toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });

    const second = h.adapter.fire();
    await flush();
    await expect(second).resolves.toEqual({
      authCredentials: { username: "bob", password: "bob-secret" },
    });

    const third = h.adapter.fire();
    await flush();
    await expect(third).resolves.toEqual({ cancel: false });
    expect(h.diagnostics().lastReason).toBe("retry-exhausted");

    // A fourth challenge must not restart the sequence.
    const fourth = h.adapter.fire();
    await flush();
    await expect(fourth).resolves.toEqual({ cancel: false });
    expect(h.adapter.responses).toHaveLength(4);
  });

  it("does not retry the same credential when only one match exists", async () => {
    const h = setup([ALICE]);
    const first = h.adapter.fire();
    await flush();
    await expect(first).resolves.toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });

    const second = h.adapter.fire();
    await flush();
    await expect(second).resolves.toEqual({ cancel: false });
    expect(h.diagnostics().lastReason).toBe("no-next-candidate");
  });

  it("cleans up after onCompleted so a reused requestId starts fresh", async () => {
    let calls = 0;
    const h = setup(async () => {
      calls += 1;
      return [ALICE];
    });

    const first = h.adapter.fire();
    await flush();
    await expect(first).resolves.toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });

    h.adapter.complete(DETAILS.requestId);
    expect(h.diagnostics().active).toBe(0);

    const second = h.adapter.fire();
    await flush();
    await expect(second).resolves.toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });
    expect(calls).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Multiple matches and the picker
// ---------------------------------------------------------------------------

describe("http auth picker", () => {
  it("auto-uses the username last used for the origin", async () => {
    const settings = createMemoryHttpAuthSettingsStore({
      lastUsed: { "https://intranet.example.com/": "bob" },
    });
    const h = setup([ALICE, BOB], { settings });

    const pending = h.adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({
      authCredentials: { username: "bob", password: "bob-secret" },
    });
    expect(h.picker.requests).toHaveLength(0);
    expect(h.diagnostics().lastReason).toBe("last-used");
  });

  it("shows the picker for multiple matches and uses the choice", async () => {
    const h = setup([ALICE, BOB]);
    h.picker.next = BOB.uuid;

    const pending = h.adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({
      authCredentials: { username: "bob", password: "bob-secret" },
    });
    expect(h.picker.requests).toHaveLength(1);
    expect(h.picker.requests[0].entries.map((item) => item.login)).toEqual([
      "alice",
      "bob",
    ]);
    // The picker never receives passwords.
    expect(
      (h.picker.requests[0].entries[0] as unknown as Record<string, unknown>)[
        "password"
      ],
    ).toBe("");
    expect(h.diagnostics().lastReason).toBe("picker");
  });

  it("falls back when the picker is cancelled or times out", async () => {
    const h = setup([ALICE, BOB]);
    h.picker.next = null;

    const pending = h.adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(h.diagnostics().lastReason).toBe("picker-cancelled");
  });

  it("closes the picker and settles at the hard deadline", async () => {
    const picker = new FakePicker();
    picker.never = true;
    const h = setup([ALICE, BOB], { picker, deadlineMs: 1_000, pickerTimeoutMs: 5_000 });

    const pending = h.adapter.fire();
    await flush();
    expect(picker.requests).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(1_000);
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(picker.cancelled).toHaveLength(1);
    expect(h.diagnostics().lastReason).toBe("deadline");
  });

  it("shows the picker for a single match when auto-fill is off", async () => {
    const settings = createMemoryHttpAuthSettingsStore({
      httpAuthAutoFill: false,
    });
    const h = setup([ALICE], { settings });
    h.picker.next = ALICE.uuid;

    const pending = h.adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({
      authCredentials: { username: "alice", password: "alice-secret" },
    });
    expect(h.picker.requests).toHaveLength(1);
  });

  it("falls back when auto-fill is off and the picker is unavailable", async () => {
    const settings = createMemoryHttpAuthSettingsStore({
      httpAuthAutoFill: false,
    });
    const adapter = new FakeAdapter();
    const controller = createHttpAuthController({
      lookup: async () => [ALICE],
      adapter,
      settings,
      picker: null,
    });
    controller.install();

    const pending = adapter.fire();
    await flush();
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(controller.diagnostics().lastReason).toBe("picker-unavailable");
  });
});

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

describe("http auth concurrency", () => {
  it("settles 20 parallel challenges exactly once each", async () => {
    const h = setup([ALICE]);
    const pending = Array.from({ length: 20 }, (_, index) =>
      h.adapter.fire({ requestId: `parallel-${index}` }),
    );

    await flush();
    const responses = await Promise.all(pending);
    expect(responses).toHaveLength(20);
    for (const response of responses) {
      expect(response).toEqual({
        authCredentials: { username: "alice", password: "alice-secret" },
      });
    }
    expect(h.adapter.responses).toHaveLength(20);
    expect(h.diagnostics().active).toBe(0);
    expect(h.diagnostics().settled).toBe(20);

    await vi.advanceTimersByTimeAsync(HTTP_AUTH_DEADLINE_MS + 5_000);
    expect(h.adapter.responses).toHaveLength(20);
  });

  it("settles every active callback on shutdown", async () => {
    const h = setup(() => new Promise<CredentialEntry[]>(() => undefined));
    const pending = h.adapter.fire();

    h.controller.shutdown();
    await expect(pending).resolves.toEqual({ cancel: false });
    expect(h.diagnostics().active).toBe(0);
  });
});
