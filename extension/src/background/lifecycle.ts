/**
 * Service-worker lifecycle (WP2).
 *
 * Owns: synchronous listener registration at worker startup, `onStartup` /
 * `onInstalled` reconnects, the 30 s `chrome.alarms` watchdog, and keeping the
 * worker alive while a native port is open.
 *
 * TODO(WP2): implement. Listeners MUST be registered synchronously in `sw.ts`;
 * nothing here may be called after an `await`.
 */

export interface LifecycleHooks {
  /** Open (or re-open) the native connection. Must be idempotent. */
  connect(): void | Promise<void>;
  /** Close the port and cancel timers during reload/shutdown. */
  shutdown(): void;
}

export function registerLifecycleListeners(_hooks: LifecycleHooks): void {
  throw new Error("TODO(WP2): register lifecycle listeners");
}

/** Arms the watchdog alarm if it is not already scheduled. */
export function ensureWatchdogAlarm(): void {
  throw new Error("TODO(WP2): implement watchdog alarm");
}
