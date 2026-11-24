/**
 * Service-worker lifecycle (WP2).
 *
 * Owns: synchronous listener registration at worker startup, `onStartup` /
 * `onInstalled` reconnects, the 30 s `chrome.alarms` watchdog, and keeping the
 * worker alive while a native port is open.
 *
 * Listeners MUST be registered synchronously in `sw.ts`; nothing here may be
 * called after an `await`. The watchdog is the safety net for an MV3 worker
 * that was suspended and then restarted while the native port was gone.
 */

import { WATCHDOG_ALARM_PERIOD_MINUTES } from "../common/types";

export const WATCHDOG_ALARM_NAME = "friendlypass-native-watchdog";

export interface LifecycleHooks {
  /** Open (or re-open) the native connection. Must be idempotent. */
  connect(): void | Promise<void>;
  /** Close the port and cancel timers during reload/shutdown. */
  shutdown(): void;
}

let registered = false;
let hooks: LifecycleHooks | null = null;

function log(message: string): void {
  console.warn(`[friendlypass] ${message}`);
}

function safeConnect(): void {
  const current = hooks;
  if (current === null) {
    return;
  }
  try {
    const result = current.connect();
    if (result instanceof Promise) {
      result.catch((cause: unknown) => {
        log(`reconnect failed: ${cause instanceof Error ? cause.message : String(cause)}`);
      });
    }
  } catch (cause) {
    log(`connect threw: ${cause instanceof Error ? cause.message : String(cause)}`);
  }
}

function safeShutdown(): void {
  const current = hooks;
  if (current === null) {
    return;
  }
  try {
    current.shutdown();
  } catch (cause) {
    log(`shutdown threw: ${cause instanceof Error ? cause.message : String(cause)}`);
  }
}

export function registerLifecycleListeners(nextHooks: LifecycleHooks): void {
  hooks = nextHooks;
  if (registered) {
    return;
  }
  registered = true;

  ensureWatchdogAlarm();

  chrome.runtime.onStartup.addListener(() => {
    ensureWatchdogAlarm();
    safeConnect();
  });

  chrome.runtime.onInstalled.addListener(() => {
    ensureWatchdogAlarm();
    safeConnect();
  });

  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name !== WATCHDOG_ALARM_NAME) {
      return;
    }
    // Re-arm in case the browser dropped the periodic alarm; alarms are
    // one-shot by default and a suspended worker may have missed a period.
    ensureWatchdogAlarm();
    safeConnect();
  });

  // Chrome fires `onSuspend` as the worker is being torn down. Closing the
  // port here keeps the host from lingering, and the next event reconnects.
  if (chrome.runtime.onSuspend) {
    chrome.runtime.onSuspend.addListener(() => safeShutdown());
  }
}

/**
 * Arms the watchdog alarm if it is not already scheduled.
 *
 * `chrome.alarms.create` is idempotent for a name, but reading first avoids
 * resetting the period on every service-worker wake-up.
 */
export function ensureWatchdogAlarm(): void {
  if (typeof chrome === "undefined" || !chrome.alarms) {
    return;
  }
  try {
    chrome.alarms.get(WATCHDOG_ALARM_NAME, (alarm) => {
      // Touch lastError so Chrome does not log an unchecked-runtime-error
      // warning when the alarms API is unavailable (e.g. Firefox shim).
      void chrome.runtime.lastError;
      if (alarm) {
        return;
      }
      try {
        chrome.alarms.create(WATCHDOG_ALARM_NAME, {
          periodInMinutes: WATCHDOG_ALARM_PERIOD_MINUTES,
          // Fire reasonably promptly after a wake-up rather than waiting a
          // full period from the create() call.
          delayInMinutes: WATCHDOG_ALARM_PERIOD_MINUTES,
        });
      } catch (cause) {
        log(`cannot create watchdog alarm: ${cause instanceof Error ? cause.message : String(cause)}`);
      }
    });
  } catch (cause) {
    log(`cannot read watchdog alarm: ${cause instanceof Error ? cause.message : String(cause)}`);
  }
}
