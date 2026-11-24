/**
 * WP6c — exactly one `settings.changed` path.
 *
 * The state store emits settings once (`broadcastSettings`); the production
 * fan-out delivers that single event to extension pages and to every tab's
 * content scripts. The old storage.onChanged fan-out and the duplicate
 * runtime.sendMessage in sw.ts are gone, so a page and a tab must each see one
 * event per `settings.set`.
 */

import { describe, expect, it } from "vitest";

import { broadcastEvent, type BroadcastScope } from "../../src/background/broadcast";
import {
  MemoryStorageArea,
  createStateStore,
  upsertSiteException,
} from "../../src/background/state";
import type { InternalEnvelope } from "../../src/common/types";

function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

interface Recorded {
  pages: InternalEnvelope<string, unknown>[];
  tabs: Map<number, InternalEnvelope<string, unknown>[]>;
}

function recordingScope(): { scope: BroadcastScope; recorded: Recorded } {
  const recorded: Recorded = { pages: [], tabs: new Map() };
  const scope: BroadcastScope = {
    sendToExtensionPages(message) {
      recorded.pages.push(message as InternalEnvelope<string, unknown>);
    },
    async queryTabs() {
      return [{ id: 11 }, { id: 22 }, {}];
    },
    sendToTab(tabId, message) {
      const list = recorded.tabs.get(tabId) ?? [];
      list.push(message as InternalEnvelope<string, unknown>);
      recorded.tabs.set(tabId, list);
    },
  };
  return { scope, recorded };
}

describe("settings.changed fan-out", () => {
  it("delivers one event to one page and each tab per settings.set", async () => {
    const { scope, recorded } = recordingScope();
    const store = createStateStore({
      storage: new MemoryStorageArea(),
      broadcast: () => undefined,
      broadcastSettings: (settings) =>
        broadcastEvent("settings.changed", settings, scope),
    });

    const updated = await store.setSettings({ debugLogging: true });
    await flush();

    expect(recorded.pages).toHaveLength(1);
    expect(recorded.pages[0].channel).toBe("friendlypass");
    expect(recorded.pages[0].action).toBe("settings.changed");
    expect(recorded.pages[0].args).toEqual(updated);

    expect(recorded.tabs.get(11)).toHaveLength(1);
    expect(recorded.tabs.get(22)).toHaveLength(1);
    expect(recorded.tabs.get(11)?.[0].args).toEqual(updated);

    // A tab without an id is skipped, not sent to `undefined`.
    expect(recorded.tabs.size).toBe(2);

    await store.setSettings({ debugLogging: false });
    await flush();
    expect(recorded.pages).toHaveLength(2);
    expect(recorded.tabs.get(11)).toHaveLength(2);
  });

  it("does not emit anything when the store has no settings listener", async () => {
    const { recorded } = recordingScope();
    const store = createStateStore({
      storage: new MemoryStorageArea(),
      broadcast: () => undefined,
      broadcastSettings: () => undefined,
    });
    await store.setSettings({ showFieldIcons: false });
    await flush();
    // This store deliberately has no fan-out: the production store wires one.
    expect(recorded.pages).toHaveLength(0);
    expect(recorded.tabs.size).toBe(0);
  });
});

describe("upsertSiteException", () => {
  it("merges Never-for-this-site into an existing origin instead of duplicating", () => {
    expect(
      upsertSiteException(
        [{ origin: "https://example.com", disableFill: true }],
        "https://example.com/login",
        { disableSave: true },
      ),
    ).toEqual([
      {
        origin: "https://example.com",
        disableFill: true,
        disableSave: true,
      },
    ]);
  });

  it("adds a new normalised origin and ignores an invalid one", () => {
    expect(
      upsertSiteException([], "example.org", { disableSave: true }),
    ).toEqual([{ origin: "https://example.org", disableSave: true }]);
    expect(
      upsertSiteException(
        [{ origin: "https://example.com", disableSave: true }],
        "ftp://example.net",
        { disableSave: true },
      ),
    ).toEqual([{ origin: "https://example.com", disableSave: true }]);
  });
});
