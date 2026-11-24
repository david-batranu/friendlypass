/**
 * DOM observer for single-page apps (WP4, adapted from upstream
 * `content/observer-helper.js`).
 *
 * Upstream reacts to every individual mutation with a full detection pass. That
 * is expensive on React/Ember pages, so this port debounces bursts into one
 * pass and ignores mutations inside our own injected UI. The semantics the
 * acceptance tests need are unchanged: a form rendered after page load is
 * detected, and a step that swaps username for password is picked up.
 */

import { isOwnElement } from "./ui";

export interface DomObserver {
  stop(): void;
}

const DEBOUNCE_MS = 80;
const MAX_MUTATIONS = 200;

/**
 * Watch the document for added/removed nodes and visibility changes.
 * `onChange` is called at most once per burst with the first relevant target.
 */
export function startDomObserver(onChange: (target: Node) => void): DomObserver {
  let timer: number | null = null;
  let pendingTarget: Node | null = null;
  let stopped = false;

  const flush = (): void => {
    timer = null;
    if (stopped) {
      return;
    }
    const target = pendingTarget;
    pendingTarget = null;
    onChange(target ?? document.body ?? document.documentElement);
  };

  const observer = new MutationObserver((records) => {
    if (stopped || document.visibilityState === "hidden") {
      return;
    }

    let relevant = false;
    const limit = Math.min(records.length, MAX_MUTATIONS);
    for (let index = 0; index < limit; index += 1) {
      const record = records[index];
      if (!record) {
        continue;
      }
      if (isOwnElement(record.target)) {
        continue;
      }
      if (record.type === "childList") {
        if (record.addedNodes.length > 0 || record.removedNodes.length > 0) {
          relevant = true;
        }
      } else if (record.type === "attributes") {
        // `style`/`class` changes reveal or hide a form; `type` can turn a
        // text field into a password field during a step transition.
        relevant = true;
      }
      if (relevant) {
        pendingTarget = record.target;
        break;
      }
    }

    if (!relevant) {
      return;
    }

    if (timer !== null) {
      window.clearTimeout(timer);
    }
    timer = window.setTimeout(flush, DEBOUNCE_MS);
  });

  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["style", "class", "type", "hidden", "disabled"],
  });

  return {
    stop(): void {
      stopped = true;
      if (timer !== null) {
        window.clearTimeout(timer);
        timer = null;
      }
      observer.disconnect();
    },
  };
}

/** Re-run detection when the visible route changes without a reload. */
export function startNavigationObserver(onChange: () => void): DomObserver {
  const handler = (): void => onChange();
  window.addEventListener("popstate", handler);
  window.addEventListener("hashchange", handler);
  return {
    stop(): void {
      window.removeEventListener("popstate", handler);
      window.removeEventListener("hashchange", handler);
    },
  };
}
