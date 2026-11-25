/**
 * One fan-out path for background events (WP6c).
 *
 * Chrome reaches extension pages (popup, options) with
 * `chrome.runtime.sendMessage`, but content scripts only with
 * `chrome.tabs.sendMessage`. Every broadcast therefore has to use both, and it
 * must do so exactly once per state change: the old code had three independent
 * `settings.changed` paths and a single `settings.set` reached a page three
 * times.
 *
 * `BroadcastScope` is injected so unit tests can model one extension page and
 * several tabs without a browser.
 */

import { INTERNAL_CHANNEL } from "../common/types";
import { newRequestId } from "../common/messages";
import { queryTabs as queryBrowserTabs } from "../common/platform";

export interface BroadcastTab {
  id?: number;
}

export interface BroadcastScope {
  /** Deliver to every extension page (`chrome.runtime.sendMessage`). */
  sendToExtensionPages(message: unknown): void;
  /** Enumerate tabs (`chrome.tabs.query({})`). */
  queryTabs(): Promise<BroadcastTab[]>;
  /** Deliver to every frame of one tab (`chrome.tabs.sendMessage`). */
  sendToTab(tabId: number, message: unknown): void;
}

/** The production scope, backed by the WebExtension APIs (Chrome + Firefox). */
export function chromeBroadcastScope(): BroadcastScope {
  return {
    sendToExtensionPages(message) {
      try {
        // Callback form works in Firefox's `chrome` namespace; Chrome accepts it
        // too and the callback doubles as the lastError consumer.
        chrome.runtime.sendMessage(message, () => {
          void chrome.runtime.lastError;
        });
      } catch {
        // No listener alive: events are best-effort by design.
      }
    },
    async queryTabs() {
      const tabs = await queryBrowserTabs({});
      return tabs.map((tab) => ({ ...(typeof tab.id === "number" ? { id: tab.id } : {}) }));
    },
    sendToTab(tabId, message) {
      try {
        chrome.tabs.sendMessage(tabId, message, () => {
          void chrome.runtime.lastError;
        });
      } catch {
        // Tab closed or not scriptable.
      }
    },
  };
}

/** Build the raw internal envelope both delivery paths share. */
export function eventEnvelope(action: string, args: unknown): {
  channel: typeof INTERNAL_CHANNEL;
  action: string;
  args: unknown;
  requestId: string;
} {
  return {
    channel: INTERNAL_CHANNEL,
    action,
    args,
    requestId: newRequestId(),
  };
}

/**
 * Deliver one event to extension pages and to every content-script frame in
 * every tab. Never throws and never rejects.
 */
export function broadcastEvent(
  action: string,
  args: unknown,
  scope: BroadcastScope = chromeBroadcastScope(),
): void {
  const envelope = eventEnvelope(action, args);
  scope.sendToExtensionPages(envelope);
  void scope
    .queryTabs()
    .then((tabs) => {
      for (const tab of tabs) {
        if (typeof tab.id !== "number") {
          continue;
        }
        scope.sendToTab(tab.id, envelope);
      }
    })
    .catch(() => undefined);
}
