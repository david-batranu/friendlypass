/**
 * Desktop notifications for actions that need the user in the friendlypass app.
 *
 * These are shown *in addition* to the in-page hint (`content/ui.ts`) because
 * the user may be looking at another tab or window while the app waits. Best
 * effort: a browser without the `notifications` permission, or a headless test
 * browser, simply shows nothing — the flow itself is unaffected.
 */

/** Do not flash a notification for requests the app answers immediately. */
const APPROVAL_DELAY_MS = 500;

const NOTICE_PREFIX = "friendlypass-approval-";

let nextNoticeId = 1;

export interface ApprovalNotice {
  /** Cancel a pending notification and clear it once it is on screen. */
  dismiss(): void;
}

function postNotice(
  api: typeof chrome.notifications,
  id: string,
  title: string,
  message: string,
): void {
  try {
    api.create(
      id,
      {
        type: "basic",
        // Chrome will not load a bare relative path here.
        iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
        title,
        message,
        priority: 1,
      },
      () => {
        // Reading lastError avoids Chrome's "Unchecked runtime.lastError".
        void chrome.runtime.lastError;
      },
    );
  } catch {
    // Notifications are not available in this browser/build.
  }
}

function clearNotice(api: typeof chrome.notifications, id: string): void {
  try {
    api.clear(id, () => {
      void chrome.runtime.lastError;
    });
  } catch {
    // Already gone.
  }
}

/**
 * Clear approval notices left behind by a previous service-worker instance.
 *
 * Notifications outlive the worker that created them, so an MV3 restart while
 * a prompt was pending would otherwise leave one on screen forever.
 */
export function clearStaleApprovalNotices(): void {
  const scope = globalThis as {
    chrome?: { notifications?: typeof chrome.notifications };
  };
  const api = scope.chrome?.notifications;
  if (!api) {
    return;
  }
  try {
    api.getAll((items) => {
      void chrome.runtime.lastError;
      for (const id of Object.keys(items)) {
        if (id.startsWith(NOTICE_PREFIX)) {
          clearNotice(api, id);
        }
      }
    });
  } catch {
    // Notifications are not available in this browser/build.
  }
}

/**
 * Show a desktop notification if the action is still pending after a short
 * delay. `dismiss()` cancels the timer and clears the notification.
 */
export function showApprovalNotice(
  title: string,
  message: string,
): ApprovalNotice {
  const scope = globalThis as {
    chrome?: { notifications?: typeof chrome.notifications };
  };
  const api = scope.chrome?.notifications;
  if (!api) {
    return { dismiss() {} };
  }
  const id = `${NOTICE_PREFIX}${nextNoticeId++}`;
  let shown = false;
  let cleared = false;
  const timer = setTimeout(() => {
    shown = true;
    postNotice(api, id, title, message);
  }, APPROVAL_DELAY_MS);
  return {
    dismiss() {
      clearTimeout(timer);
      if (shown && !cleared) {
        cleared = true;
        clearNotice(api, id);
      }
    },
  };
}

/** Run `run` while an approval notice is pending, and clear it when it ends. */
export async function withApprovalNotice<T>(
  title: string,
  message: string,
  run: () => Promise<T>,
): Promise<T> {
  const notice = showApprovalNotice(title, message);
  try {
    return await run();
  } finally {
    notice.dismiss();
  }
}
