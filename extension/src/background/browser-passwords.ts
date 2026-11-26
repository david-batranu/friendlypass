/**
 * Keep the browser's own password manager out of the way.
 *
 * With `disableBrowserPasswordManager` on, the extension takes control of
 * `privacy.services.passwordSavingEnabled` and sets it to false, so the
 * browser stops offering to save passwords next to friendlypass. Turning the
 * option off clears our value and hands the setting back to the user. The
 * browser also reverts an extension-controlled setting when the extension is
 * removed, so nothing sticks after an uninstall.
 *
 * Both Chrome and Firefox expose the same `ChromeSetting` object. Firefox's
 * `chrome.*` namespace is callback-only, so every call goes through a callback
 * wrapped in a promise.
 */

/** What happened when the preference was applied (for diagnostics/tests). */
export type BrowserPasswordsResult =
  | "disabled"
  | "released"
  | "unavailable"
  | "controlled_by_other"
  | "error";

/** The subset of `chrome.types.ChromeSetting` used here. */
export interface PasswordSavingSetting {
  get(details: Record<string, never>, callback: (details: { value: unknown; levelOfControl?: string }) => void): void;
  set(details: { value: boolean }, callback?: () => void): void;
  clear(details: Record<string, never>, callback?: () => void): void;
}

/** The browser's `passwordSavingEnabled` setting, or null when not exposed. */
export function passwordSavingSetting(): PasswordSavingSetting | null {
  try {
    const setting = (
      globalThis as unknown as {
        chrome?: { privacy?: { services?: { passwordSavingEnabled?: PasswordSavingSetting } } };
      }
    ).chrome?.privacy?.services?.passwordSavingEnabled;
    return setting ?? null;
  } catch {
    return null;
  }
}

function lastError(): string | null {
  const error = (globalThis as unknown as { chrome?: { runtime?: { lastError?: { message?: string } } } })
    .chrome?.runtime?.lastError;
  return error ? (error.message ?? "unknown error") : null;
}

function call(run: (done: () => void) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    try {
      run(() => {
        const error = lastError();
        if (error) {
          reject(new Error(error));
        } else {
          resolve();
        }
      });
    } catch (cause) {
      reject(cause instanceof Error ? cause : new Error(String(cause)));
    }
  });
}

function levelOfControl(setting: PasswordSavingSetting): Promise<string | undefined> {
  return new Promise((resolve) => {
    try {
      setting.get({}, (details) => {
        void lastError();
        resolve(details?.levelOfControl);
      });
    } catch {
      resolve(undefined);
    }
  });
}

/**
 * Apply the option: `disable` true takes over the browser setting and turns
 * password saving off; false releases it. Never throws.
 */
export async function applyBrowserPasswordManager(
  disable: boolean,
  setting: PasswordSavingSetting | null = passwordSavingSetting(),
): Promise<BrowserPasswordsResult> {
  if (setting === null) {
    return "unavailable";
  }
  try {
    const level = await levelOfControl(setting);
    if (level === "not_controllable" || level === "controlled_by_other_extensions") {
      return "controlled_by_other";
    }
    if (disable) {
      await call((done) => setting.set({ value: false }, done));
      return "disabled";
    }
    if (level === "controlled_by_this_extension") {
      await call((done) => setting.clear({}, done));
    }
    return "released";
  } catch {
    return "error";
  }
}
