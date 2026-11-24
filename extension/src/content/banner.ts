/**
 * Save/update banner (WP4, ported from upstream `content/banner.js`).
 *
 * Behaviour kept from upstream: one banner at a time; "Save" creates an entry,
 * "Update" writes the new password to the existing entry; the password is held
 * in a closure and never written into the DOM, an attribute or a log. The group
 * picker, drag-to-reposition and the sort button are dropped (WP6 restyles this
 * card; `create-new-group` is reserved by protocol v1 anyway).
 */

import { sendBackgroundMessage } from "../common/messages";
import { createElement, FP_ATTR, showNotification } from "./ui";

export interface SaveBannerRequest {
  kind: "create" | "update";
  username: string;
  /** Plaintext password; only ever sent back to the service worker. */
  password: string;
  url: string;
  submitUrl?: string;
  /** Existing entry for `kind: "update"`. */
  uuid?: string;
}

export interface SaveBannerOptions {
  /** Called after `set-login` reports success (refresh the cached list). */
  onSaved?: () => void;
}

let currentBanner: HTMLDivElement | null = null;

export function dismissSaveBanner(): void {
  currentBanner?.remove();
  currentBanner = null;
}

function button(
  label: string,
  action: "save" | "dismiss" | "never",
  primary: boolean,
): HTMLButtonElement {
  const element = createElement(
    "button",
    undefined,
    {
      type: "button",
      [FP_ATTR]: `banner-${action}`,
      "data-action": action,
    },
    label,
  );
  element.style.cssText = [
    "all: unset",
    "display: inline-block",
    "box-sizing: border-box",
    "padding: 6px 14px",
    "border-radius: 4px",
    "cursor: pointer",
    "font: 600 13px/1.2 system-ui, -apple-system, sans-serif",
    primary ? "background: #2f855a;color: #ffffff" : "background: #e4e7eb;color: #1f2933",
  ].join(";");
  return element;
}

/**
 * Show (or replace) the save card for a submitted form.
 * Returns immediately; saving happens when the user clicks the primary button.
 */
export function showSaveBanner(
  request: SaveBannerRequest,
  options: SaveBannerOptions = {},
): void {
  if (typeof document === "undefined" || !document.body) {
    return;
  }
  dismissSaveBanner();

  const host = createElement("div", undefined, {
    [FP_ATTR]: "banner",
    "data-friendlypass-kind": request.kind,
    role: "dialog",
    "aria-label": "friendlypass save login",
  });
  host.style.cssText = [
    "all: initial",
    "display: block",
    "position: fixed",
    "z-index: 2147483647",
    "right: 16px",
    "bottom: 16px",
    "width: 340px",
    "box-sizing: border-box",
    "background: #ffffff",
    "color: #1f2933",
    "border: 1px solid rgba(0, 0, 0, 0.18)",
    "border-radius: 8px",
    "box-shadow: 0 12px 32px rgba(0, 0, 0, 0.24)",
    "font: 13px/1.4 system-ui, -apple-system, sans-serif",
    "padding: 14px",
  ].join(";");

  const title = createElement("div");
  title.style.cssText = "font-weight: 650;font-size:14px;margin-bottom:6px";
  title.textContent =
    request.kind === "update"
      ? "Update saved login?"
      : "Save this login to friendlypass?";

  const detail = createElement("div");
  detail.style.cssText = "color:#52606d;margin-bottom:12px;word-break:break-all";
  detail.textContent = request.username
    ? `Username: ${request.username}`
    : "No username in this form";

  const actions = createElement("div");
  actions.style.cssText = "display:flex;gap:8px;justify-content:flex-end";

  const dismiss = button("Not now", "dismiss", false);
  const never = button("Never for this site", "never", false);
  never.style.background = "transparent";
  never.style.color = "#52606d";
  const save = button(request.kind === "update" ? "Update" : "Save", "save", true);
  actions.append(never, dismiss, save);
  host.append(title, detail, actions);

  const finish = (): void => {
    dismiss.disabled = true;
    save.disabled = true;
    dismissSaveBanner();
  };

  dismiss.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    // The pending pair belongs to this tab; a dismissal ends the offer even if
    // the next page has not asked for it yet.
    void sendBackgroundMessage("submit.clear");
    finish();
  });

  never.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    try {
      const origin = new URL(request.url).origin;
      void sendBackgroundMessage("submit.never", { origin });
    } catch {
      // An unparsable URL cannot be remembered; the banner still closes.
    }
    finish();
  });

  save.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    save.disabled = true;
    dismiss.disabled = true;
    void (async () => {
      try {
        const result = await sendBackgroundMessage("logins.save", {
          url: request.url,
          submitUrl: request.submitUrl,
          login: request.username,
          password: request.password,
          uuid: request.uuid,
        });
        if (result.ok && result.value.success) {
          void sendBackgroundMessage("submit.clear");
          showNotification(
            "success",
            request.kind === "update" ? "Password updated." : "Login saved.",
          );
          try {
            options.onSaved?.();
          } catch {
            // A refresh failure must not turn a successful save into an error.
          }
        } else {
          const message = result.ok ? result.value.message : result.error.message;
          showNotification("error", `Could not save login: ${message}`);
        }
      } catch {
        showNotification("error", "Could not save login.");
      } finally {
        dismissSaveBanner();
      }
    })();
  });

  document.body.append(host);
  currentBanner = host;
}
