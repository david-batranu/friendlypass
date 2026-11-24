/**
 * Save/update card (WP6b, replaces the WP4 banner).
 *
 * A top-right card with the entry title, username, Save/Update, Not now and
 * Never for this site. When `defaultGroupAlwaysAsk` is on, a group picker is
 * shown and the chosen group is passed to `logins.save`. The plaintext
 * password lives only in this module's closure: it is never written into the
 * DOM, an attribute, or a log.
 *
 * Keyboard: role=dialog, native buttons in tab order, Escape dismisses. When
 * the page has no focused control (the common post-navigation case) the
 * primary action receives focus; while the user is typing in the page, focus
 * is left alone. The card auto-dismisses after 60 s.
 */

import { sendBackgroundMessage } from "../common/messages";
import type { DatabaseGroup } from "../common/types";
import { rememberNeverForSite } from "./settings";
import { appendShadowStyle, createShadowHost } from "./styles";
import { FP_ATTR, showNotification } from "./ui";

/** How long the card stays before dismissing itself. */
export const BANNER_TIMEOUT_MS = 60_000;

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
  /** Show the group picker (`settings.defaultGroupAlwaysAsk`). */
  groupAlwaysAsk?: boolean;
  /** Preselected group name (`settings.defaultGroup`). */
  defaultGroup?: string;
  /** Do not move focus into the card (defaults to false). */
  skipFocus?: boolean;
}

interface BannerController {
  timer: number | null;
}

let current: (BannerController & { host: HTMLDivElement }) | null = null;

const BANNER_CSS = `
.card{padding:14px;width:100%}
.head{display:flex;align-items:flex-start;gap:10px;margin-bottom:10px}
.logo{display:flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:8px;background:var(--fp-surface);border:1px solid var(--fp-border);color:var(--fp-accent);flex:none}
.logo svg{width:16px;height:16px;fill:currentColor;display:block}
.head .text{min-width:0;flex:1}
.title{font-size:14px;font-weight:650;line-height:1.3}
.site{color:var(--fp-muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.detail{display:flex;flex-direction:column;gap:2px;padding:8px 10px;background:var(--fp-surface);border:1px solid var(--fp-border);border-radius:var(--fp-radius-control);margin-bottom:10px}
.detail .label{font-size:11px;font-weight:600;color:var(--fp-muted);text-transform:uppercase;letter-spacing:.04em}
.detail .value{font-weight:600;overflow-wrap:anywhere}
.group{display:flex;flex-direction:column;gap:4px;margin-bottom:10px}
.group .label{font-size:11px;font-weight:600;color:var(--fp-muted);text-transform:uppercase;letter-spacing:.04em}
.group select{
  appearance:none;width:100%;min-height:30px;padding:5px 28px 5px 9px;
  border-radius:var(--fp-radius-control);border:1px solid var(--fp-border);
  background:var(--fp-bg) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%235f6670'%3E%3Cpath d='M7 10l5 5 5-5z'/%3E%3C/svg%3E") no-repeat right 6px center;
  background-size:16px 16px;color:var(--fp-text);font:inherit;
}
.group select:focus-visible{outline:2px solid var(--fp-accent);outline-offset:2px}
.actions{display:flex;align-items:center;gap:6px;margin-top:2px}
.actions .spacer{flex:1}
@media (max-width:420px){.actions{flex-wrap:wrap}.actions .spacer{display:none}}
`;

const LOGO =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2a6 6 0 0 0-5.66 8L2 16.34V22h5.66l1.6-1.6V19h1.4l1.6-1.6V16h1.4l1.06-1.06A6 6 0 1 0 14 2zm2.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3z"/></svg>';

export function dismissSaveBanner(): void {
  if (!current) {
    return;
  }
  if (current.timer !== null) {
    window.clearTimeout(current.timer);
  }
  current.host.remove();
  current = null;
}

function originLabel(url: string): string {
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

function button(
  label: string,
  action: "save" | "dismiss" | "never",
  className: string,
): HTMLButtonElement {
  const element = document.createElement("button");
  element.type = "button";
  element.className = `fp-btn ${className}`.trim();
  element.setAttribute("data-action", action);
  element.textContent = label;
  return element;
}

/** Depth-first group list (root first) for the picker. */
export function flattenGroups(
  groups: DatabaseGroup[],
  depth = 0,
  out: Array<{ group: DatabaseGroup; depth: number }> = [],
): Array<{ group: DatabaseGroup; depth: number }> {
  for (const group of groups) {
    out.push({ group, depth });
    flattenGroups(group.children ?? [], depth + 1, out);
  }
  return out;
}

/**
 * Show (or replace) the save card for a submitted form.
 * Returns immediately; saving happens when the user activates the primary
 * button (or presses Enter while it is focused).
 */
export function showSaveBanner(
  request: SaveBannerRequest,
  options: SaveBannerOptions = {},
): void {
  if (typeof document === "undefined" || !document.body) {
    return;
  }
  dismissSaveBanner();

  const { host, shadow } = createShadowHost({
    [FP_ATTR]: "banner",
    "data-friendlypass-kind": request.kind,
    role: "dialog",
    "aria-label": "friendlypass save login",
  });
  host.style.setProperty("right", "16px", "important");
  host.style.setProperty("top", "16px", "important");
  host.style.setProperty("width", "360px", "important");
  host.style.setProperty("max-width", "calc(100vw - 32px)", "important");
  appendShadowStyle(shadow, BANNER_CSS);

  const card = document.createElement("div");
  card.className = "fp-panel card";

  const head = document.createElement("div");
  head.className = "head";
  const logo = document.createElement("span");
  logo.className = "logo";
  logo.insertAdjacentHTML("beforeend", LOGO);
  const headText = document.createElement("div");
  headText.className = "text";
  const title = document.createElement("div");
  title.className = "title";
  title.id = "fp-banner-title";
  title.textContent =
    request.kind === "update" ? "Update saved login?" : "Save this login?";
  const site = document.createElement("div");
  site.className = "site";
  site.textContent = originLabel(request.url);
  headText.append(title, site);
  head.append(logo, headText);

  const detail = document.createElement("div");
  detail.className = "detail";
  const detailLabel = document.createElement("span");
  detailLabel.className = "label";
  detailLabel.textContent = "Username";
  const detailValue = document.createElement("span");
  detailValue.className = "value";
  detailValue.textContent = request.username || "No username";
  detail.append(detailLabel, detailValue);

  const groupWrap = document.createElement("label");
  groupWrap.className = "group";
  groupWrap.style.display = "none";
  const groupLabel = document.createElement("span");
  groupLabel.className = "label";
  groupLabel.textContent = "Save in group";
  const select = document.createElement("select");
  select.setAttribute(FP_ATTR, "banner-group");
  select.disabled = true;
  groupWrap.append(groupLabel, select);

  const actions = document.createElement("div");
  actions.className = "actions";
  const never = button("Never for this site", "never", "ghost");
  const dismiss = button("Not now", "dismiss", "secondary");
  const save = button(request.kind === "update" ? "Update" : "Save", "save", "primary");
  const spacer = document.createElement("span");
  spacer.className = "spacer";
  actions.append(never, spacer, dismiss, save);

  card.append(head, detail, groupWrap, actions);
  shadow.append(card);
  host.setAttribute("aria-labelledby", title.id);
  host.setAttribute("aria-label", title.textContent ?? "friendlypass save login");

  const controller: BannerController & { host: HTMLDivElement } = {
    host,
    timer: null,
  };
  current = controller;

  const finish = (clearPending: boolean): void => {
    if (clearPending) {
      void sendBackgroundMessage("submit.clear");
    }
    dismissSaveBanner();
  };

  controller.timer = window.setTimeout(() => {
    finish(true);
  }, BANNER_TIMEOUT_MS);

  dismiss.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    finish(true);
  });

  never.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    try {
      const origin = new URL(request.url).origin;
      void sendBackgroundMessage("submit.never", { origin });
      void rememberNeverForSite(origin);
    } catch {
      // An unparsable URL cannot be remembered; the card still closes.
    }
    finish(false);
  });

  const saveNow = (): void => {
    if (save.disabled) {
      return;
    }
    save.disabled = true;
    dismiss.disabled = true;
    never.disabled = true;
    void (async () => {
      try {
        const group = select.value || undefined;
        const result = await sendBackgroundMessage("logins.save", {
          url: request.url,
          submitUrl: request.submitUrl,
          login: request.username,
          password: request.password,
          uuid: request.uuid,
          ...(group ? { group } : {}),
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
  };

  save.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    saveNow();
  });

  shadow.addEventListener("keydown", (event) => {
    if ((event as KeyboardEvent).key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      finish(true);
    }
  });

  document.documentElement.append(host);

  if (options.groupAlwaysAsk === true) {
    groupWrap.style.display = "flex";
    void (async () => {
      try {
        const result = await sendBackgroundMessage("groups.list");
        if (!result.ok || current !== controller) {
          select.disabled = false;
          return;
        }
        const flat = flattenGroups(result.value);
        const preferred =
          flat.find((entry) => entry.group.name === options.defaultGroup) ??
          flat.find((entry) => entry.depth > 0) ??
          flat[0];
        select.textContent = "";
        for (const entry of flat) {
          const option = document.createElement("option");
          option.value = entry.group.name;
          option.textContent = `${"— ".repeat(entry.depth)}${entry.group.name}`;
          if (preferred && entry.group.name === preferred.group.name) {
            option.selected = true;
          }
          select.append(option);
        }
        select.disabled = flat.length === 0;
      } catch {
        // The group picker is optional; saving still works without a group.
        select.disabled = false;
      }
    })();
  }

  // Focus only when the page has no active control (usually after a
  // navigation) or the user just activated a submit/button. Never take focus
  // away from a text field the user is typing in.
  const active = document.activeElement;
  const activeIsControl =
    active instanceof HTMLButtonElement ||
    (active instanceof HTMLInputElement &&
      (active.type === "submit" ||
        active.type === "button" ||
        active.type === "image"));
  if (
    options.skipFocus !== true &&
    (active === null ||
      active === document.body ||
      active === document.documentElement ||
      activeIsControl)
  ) {
    save.focus({ preventScroll: true });
  }
}
