/**
 * Dropdown menu for login/TOTP selection (WP4, ported from upstream
 * `content/autocomplete.js`).
 *
 * Upstream renders the menu in a closed shadow root and adds a search box,
 * sorting, colours and compact modes. This port keeps the interaction the fill
 * engine needs: a fixed-position list anchored to the field, mouse selection,
 * and Escape/Arrow/Enter handling. WP6 owns the visual redesign.
 *
 * The menu never receives passwords: it only shows entry titles, groups and
 * usernames supplied by the background.
 */

import { createElement, FP_ATTR } from "./ui";

export interface MenuItem {
  /** Entry UUID; opaque to the menu. */
  uuid: string;
  /** Primary line, e.g. the entry title. */
  title: string;
  /** Secondary line, e.g. the username. */
  value: string;
  group?: string;
}

export interface MenuPick {
  item: MenuItem;
  index: number;
}

let globalListenersInstalled = false;

export class AutocompleteMenu {
  private host: HTMLDivElement | null = null;
  private field: HTMLInputElement | null = null;
  private items: MenuItem[] = [];
  private onPick: ((pick: MenuPick) => void) | null = null;
  private index = -1;
  private readonly ownListener = (event: MouseEvent): void => {
    if (!this.host || !this.field) {
      return;
    }
    const path = event.composedPath();
    if (path.includes(this.host) || path.includes(this.field)) {
      return;
    }
    this.close();
  };
  private readonly ownKeyListener = (event: KeyboardEvent): void => {
    if (!this.host || event.target !== this.field) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      this.close();
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (this.items.length === 0) {
        return;
      }
      const delta = event.key === "ArrowDown" ? 1 : -1;
      this.index = (this.index + delta + this.items.length) % this.items.length;
      this.highlight();
      return;
    }
    if (event.key === "Enter" && this.index >= 0) {
      const item = this.items[this.index];
      if (item) {
        event.preventDefault();
        this.pick(item, this.index);
      }
    }
  };

  isOpen(): boolean {
    return this.host !== null;
  }

  isOpenFor(field: HTMLInputElement): boolean {
    return this.field === field && this.host !== null;
  }

  open(
    field: HTMLInputElement,
    items: MenuItem[],
    onPick: (pick: MenuPick) => void,
  ): void {
    if (items.length === 0) {
      this.close();
      return;
    }
    this.close();

    this.field = field;
    this.items = items;
    this.onPick = onPick;
    this.index = -1;

    const host = createElement("div", undefined, {
      [FP_ATTR]: "menu",
      role: "menu",
    });
    host.style.cssText = [
      "all: initial",
      "display: block",
      "position: fixed",
      "z-index: 2147483647",
      "box-sizing: border-box",
      "min-width: 220px",
      "max-width: 460px",
      "max-height: 280px",
      "overflow: auto",
      "background: #ffffff",
      "color: #1f2933",
      "border: 1px solid rgba(0, 0, 0, 0.18)",
      "border-radius: 6px",
      "box-shadow: 0 8px 28px rgba(0, 0, 0, 0.22)",
      "font: 13px/1.35 system-ui, -apple-system, sans-serif",
      "padding: 4px",
    ].join(";");

    items.forEach((item, index) => {
      const button = createElement("button", undefined, {
        type: "button",
        [FP_ATTR]: "menu-item",
        "data-friendlypass-uuid": item.uuid,
        role: "menuitem",
      });
      button.style.cssText = [
        "all: unset",
        "display: block",
        "box-sizing: border-box",
        "width: 100%",
        "padding: 6px 8px",
        "border-radius: 4px",
        "cursor: pointer",
        "white-space: nowrap",
        "overflow: hidden",
        "text-overflow: ellipsis",
      ].join(";");

      const title = createElement("div");
      title.textContent = item.title;
      title.style.fontWeight = "600";
      const value = createElement("div");
      value.textContent = item.value;
      value.style.color = "#52606d";
      button.append(title, value);
      if (item.group) {
        value.title = item.group;
      }

      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        this.pick(item, index);
      });
      button.addEventListener("mousedown", (event) => {
        // Keep focus in the input; some pages close their own popover on blur.
        event.preventDefault();
        event.stopPropagation();
      });

      host.append(button);
    });

    this.host = host;
    document.body.append(host);
    this.position();
    this.installGlobalListeners();
    document.addEventListener("click", this.ownListener);
    field.addEventListener("keydown", this.ownKeyListener);
  }

  close(): void {
    if (this.host) {
      this.host.remove();
      this.host = null;
    }
    if (this.field) {
      this.field.removeEventListener("keydown", this.ownKeyListener);
    }
    this.field = null;
    this.items = [];
    this.onPick = null;
    this.index = -1;
    document.removeEventListener("click", this.ownListener);
  }

  private installGlobalListeners(): void {
    if (globalListenersInstalled) {
      return;
    }
    globalListenersInstalled = true;
    const reposition = (): void => this.position();
    window.addEventListener("scroll", reposition, { passive: true, capture: true });
    window.addEventListener("resize", reposition, { passive: true });
  }

  private position(): void {
    if (!this.host || !this.field) {
      return;
    }
    const rect = this.field.getBoundingClientRect();
    const height = this.host.offsetHeight || 0;
    const below = rect.bottom + 2;
    const above = rect.top - height - 2;
    const top = below + Math.min(height, 280) > window.innerHeight && above > 0 ? above : below;
    this.host.style.top = `${Math.max(0, Math.round(top))}px`;
    this.host.style.left = `${Math.max(0, Math.round(rect.left))}px`;
    this.host.style.minWidth = `${Math.max(220, Math.round(rect.width))}px`;
  }

  private highlight(): void {
    if (!this.host) {
      return;
    }
    const buttons = Array.from(
      this.host.querySelectorAll<HTMLButtonElement>(`[${FP_ATTR}="menu-item"]`),
    );
    buttons.forEach((button, index) => {
      button.style.background = index === this.index ? "rgba(47, 133, 90, 0.12)" : "";
    });
    buttons[this.index]?.scrollIntoView({ block: "nearest" });
  }

  private pick(item: MenuItem, index: number): void {
    const handler = this.onPick;
    this.close();
    handler?.({ item, index });
  }
}
