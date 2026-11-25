/**
 * Inline menu (WP6b, replaces the WP4 dropdown).
 *
 * A 1Password-style card anchored to a field: title/username monogram list,
 * type-to-search, keyboard navigation (↑/↓/Enter/Esc), footer actions ("Fill
 * TOTP", "Generate password", "Locked — unlock friendlypass", "Open
 * friendlypass") and viewport-aware placement (flips above near the bottom).
 *
 * Everything lives in an open shadow root with the shared tokens. The menu
 * never contains passwords and never writes one into the DOM.
 */

import { computeMenuPosition } from "./position";
import { appendShadowStyle, createShadowHost } from "./styles";
import { FP_ATTR } from "./ui";

export interface MenuEntry {
  /** Entry UUID; opaque to the menu. */
  uuid: string;
  /** Primary line, e.g. the entry title. */
  title: string;
  /** Secondary line, e.g. the username. */
  username: string;
  group?: string;
  /** Marks entries that can supply a one-time code. */
  totp?: boolean;
}

export type MenuActionTone = "default" | "primary" | "danger";
export type MenuActionIcon = "key" | "lock" | "generate" | "external" | "totp";

export interface MenuAction {
  id: string;
  label: string;
  tone?: MenuActionTone;
  icon?: MenuActionIcon;
  disabled?: boolean;
  /** Entry that was active when the action was activated. */
  needsEntry?: boolean;
}

export interface MenuOpenOptions {
  /** Focus the search box (icon click / keyboard shortcut). */
  focusSearch?: boolean;
  searchPlaceholder?: string;
  /** Message when the (filtered) list is empty. */
  emptyMessage?: string;
  actions?: MenuAction[];
  /** `menu` role label, e.g. "friendlypass logins". */
  label?: string;
  onPick?: (entry: MenuEntry, index: number) => void;
  onAction?: (action: MenuAction, entry: MenuEntry | null) => void;
  onClose?: (reason: MenuCloseReason) => void;
}

export type MenuCloseReason = "user" | "pick" | "programmatic" | "replace";

const MENU_CSS = `
.panel{display:flex;flex-direction:column;overflow:hidden;max-height:inherit}
.search{display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--fp-surface);border-bottom:1px solid var(--fp-border)}
.search svg{width:14px;height:14px;flex:none;color:var(--fp-muted);fill:currentColor}
.search input{border:0;outline:none;background:transparent;width:100%;font-size:13px;color:var(--fp-text);padding:2px 0}
.search input::placeholder{color:var(--fp-muted)}
.list{padding:4px;overflow-y:auto;overscroll-behavior:contain;flex:1 1 auto;min-height:0}
.item{display:flex;align-items:center;gap:8px;width:100%;padding:6px;border-radius:var(--fp-radius-control);text-align:left}
.item:hover,.item[aria-selected="true"]{background:color-mix(in srgb,var(--fp-accent) 12%,transparent)}
.item:focus-visible{outline:2px solid var(--fp-accent);outline-offset:-2px}
.item .text{min-width:0;flex:1}
.item .title{display:block;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.item .value{display:block;color:var(--fp-muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.totp-mark{margin-left:auto;color:var(--fp-muted);font-size:11px;font-weight:600;letter-spacing:.02em;flex:none}
.empty-msg{padding:10px 12px;color:var(--fp-muted)}
.actions{border-top:1px solid var(--fp-border);padding:4px;flex:none}
.action{display:flex;align-items:center;gap:8px;width:100%;padding:7px 8px;border-radius:var(--fp-radius-control);text-align:left;font-weight:500}
.action:hover,.action:focus-visible{background:var(--fp-surface)}
.action svg{width:14px;height:14px;flex:none;fill:currentColor;color:var(--fp-muted)}
.action[data-tone="primary"]{color:var(--fp-accent);font-weight:600}
.action[data-tone="primary"] svg{color:var(--fp-accent)}
.action[data-tone="danger"]{color:var(--fp-danger)}
.action[data-tone="danger"] svg{color:var(--fp-danger)}
.action:disabled{opacity:.55;cursor:default}
`;

const ICONS: Record<MenuActionIcon, string> = {
  key: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2a6 6 0 0 0-5.66 8L2 16.34V22h5.66l1.6-1.6V19h1.4l1.6-1.6V16h1.4l1.06-1.06A6 6 0 1 0 14 2zm2.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3z"/></svg>',
  lock: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a5 5 0 0 0-5 5v3H6a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-9a1 1 0 0 0-1-1h-1V7a5 5 0 0 0-5-5zm3 8H9V7a3 3 0 1 1 6 0v3z"/></svg>',
  generate:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15 2a7 7 0 0 0-6.6 9.3L2 17.7V22h4.3l.9-.9V19h1.8l1.2-1.2V16h1.8l1.2-1.2A7 7 0 1 0 15 2zm2.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3z"/></svg>',
  external:
    '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 3h7v7h-2V6.4l-8.3 8.3-1.4-1.4L17.6 5H14V3zM5 5h6v2H7v10h10v-4h2v6H5V5z"/></svg>',
  totp: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a10 10 0 1 0 10 10h-2a8 8 0 1 1-8-8V2zm1 5h-2v6l4 2 1-1.7-3-1.5V7z"/></svg>',
};

let nextMenuId = 0;

function searchIcon(): string {
  return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 2a8 8 0 1 0 4.9 14.3l5.4 5.4 1.4-1.4-5.4-5.4A8 8 0 0 0 10 2zm0 2a6 6 0 1 1 0 12 6 6 0 0 1 0-12z"/></svg>';
}

/** First visible character of a login/title, uppercased. */
export function monogramFor(entry: Pick<MenuEntry, "title" | "username">): string {
  const source = entry.title.trim() || entry.username.trim() || "friendlypass";
  const first = Array.from(source)[0] ?? "f";
  return first.toUpperCase();
}

/**
 * Filter entries for the type-to-search box. The query is matched
 * case-insensitively against title, username and group.
 */
export function filterMenuEntries(
  entries: MenuEntry[],
  query: string,
): MenuEntry[] {
  const needle = query.trim().toLowerCase();
  if (!needle) {
    return entries;
  }
  return entries.filter((entry) => {
    const haystack = [entry.title, entry.username, entry.group ?? ""]
      .join("\n")
      .toLowerCase();
    return haystack.includes(needle);
  });
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

export class InlineMenu {
  private host: HTMLDivElement | null = null;
  private panel: HTMLDivElement | null = null;
  private list: HTMLDivElement | null = null;
  private search: HTMLInputElement | null = null;
  private emptyMessage: HTMLDivElement | null = null;
  private field: HTMLInputElement | null = null;
  private entries: MenuEntry[] = [];
  private visible: MenuEntry[] = [];
  private actions: MenuAction[] = [];
  private options: MenuOpenOptions = {};
  private index = -1;
  private readonly menuId = `fp-menu-${(nextMenuId += 1)}`;

  private readonly onDocumentPointerDown = (event: Event): void => {
    if (!this.host || !this.field) {
      return;
    }
    const path = event.composedPath();
    if (path.includes(this.host) || path.includes(this.field)) {
      return;
    }
    if (
      path.some(
        (node) =>
          node instanceof Element && node.hasAttribute(FP_ATTR),
      )
    ) {
      // An icon click toggles its own menu.
      return;
    }
    this.close("user");
  };

  private readonly onScroll = (): void => {
    if (!this.host || !this.field) {
      return;
    }
    const rect = this.field.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const scrolledAway =
      rect.bottom <= 0 ||
      rect.top >= viewportHeight ||
      rect.right <= 0 ||
      rect.left >= viewportWidth;
    if (scrolledAway) {
      this.close("user");
      return;
    }
    this.position();
  };

  private readonly onResize = (): void => {
    if (this.host) {
      this.position();
    }
  };

  private readonly onFieldKeyDown = (event: KeyboardEvent): void => {
    if (!this.host || event.target !== this.field) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      this.close("user");
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      event.stopPropagation();
      this.move(event.key === "ArrowDown" ? 1 : -1);
      return;
    }
    if (event.key === "Enter" && this.index >= 0) {
      const entry = this.visible[this.index];
      if (entry) {
        event.preventDefault();
        event.stopPropagation();
        this.pick(entry, this.index);
      }
    }
  };

  isOpen(): boolean {
    return this.host !== null;
  }

  isOpenFor(field: HTMLInputElement): boolean {
    return this.field === field && this.host !== null;
  }

  /** The field this menu is anchored to. */
  get anchorField(): HTMLInputElement | null {
    return this.field;
  }

  containsNode(node: Node | null): boolean {
    if (!this.host || !node) {
      return false;
    }
    return node === this.host || this.host.contains(node);
  }

  /** The entry currently highlighted by keyboard navigation. */
  activeEntry(): MenuEntry | null {
    return this.index >= 0 ? this.visible[this.index] ?? null : null;
  }

  open(
    field: HTMLInputElement,
    entries: MenuEntry[],
    options: MenuOpenOptions = {},
  ): void {
    if (this.host) {
      this.close("replace");
    }
    this.field = field;
    this.entries = entries;
    this.options = options;
    this.actions = options.actions ?? [];
    this.index = entries.length > 0 ? 0 : -1;

    const { host, shadow } = createShadowHost({
      [FP_ATTR]: "menu",
      [`${FP_ATTR}-role`]: "inline-menu",
      role: "dialog",
      "aria-label": options.label ?? "friendlypass",
    });
    host.style.setProperty("top", "0px", "important");
    host.style.setProperty("left", "0px", "important");

    appendShadowStyle(shadow, MENU_CSS);
    const panel = element("div", "fp-panel panel");
    panel.style.maxHeight = "inherit";

    if (entries.length > 0) {
      const search = element("div", "search");
      search.insertAdjacentHTML("beforeend", searchIcon());
      const input = element("input");
      input.type = "search";
      input.placeholder = options.searchPlaceholder ?? "Search logins";
      input.setAttribute(FP_ATTR, "menu-search");
      input.setAttribute("aria-label", options.searchPlaceholder ?? "Search logins");
      input.setAttribute("role", "combobox");
      input.setAttribute("aria-expanded", "true");
      input.setAttribute("aria-autocomplete", "list");
      input.setAttribute("aria-controls", `${this.menuId}-list`);
      input.autocomplete = "off";
      input.spellcheck = false;
      search.append(input);
      panel.append(search);
      this.search = input;
    }

    const list = element("div", "list");
    list.id = `${this.menuId}-list`;
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-label", "Matching logins");
    panel.append(list);
    this.list = list;

    const empty = element("div", "empty-msg");
    empty.style.display = "none";
    panel.append(empty);
    this.emptyMessage = empty;

    const actions = element("div", "actions");
    actions.setAttribute("role", "group");
    actions.setAttribute("aria-label", "Actions");
    for (const action of this.actions) {
      const button = element("button", "action");
      button.type = "button";
      button.setAttribute(FP_ATTR, "menu-action");
      button.setAttribute("data-action", action.id);
      button.setAttribute("data-tone", action.tone ?? "default");
      if (action.icon) {
        button.insertAdjacentHTML("beforeend", ICONS[action.icon]);
      }
      const label = element("span");
      label.textContent = action.label;
      button.append(label);
      button.disabled = action.disabled === true;
      button.addEventListener("mousedown", (event) => event.preventDefault());
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const entry = this.activeEntry();
        const handler = this.options.onAction;
        this.close("programmatic");
        handler?.(action, entry);
      });
      actions.append(button);
    }
    if (this.actions.length > 0) {
      panel.append(actions);
    }

    shadow.append(panel);
    this.host = host;
    this.panel = panel;

    this.renderList();
    this.installListeners();

    document.documentElement.append(host);
    this.position();
    // A second pass measures the fully laid-out card (flips above correctly).
    this.position();

    if (options.focusSearch === true && this.search) {
      this.search.focus({ preventScroll: true });
      this.search.select();
    } else if (entries.length === 0 && this.actions.length > 0) {
      // Locked/empty menus have nothing to search: focus the primary action so
      // keyboard users can press Enter immediately.
      shadow
        .querySelector<HTMLButtonElement>('[data-friendlypass="menu-action"]')
        ?.focus({ preventScroll: true });
    }
  }

  close(reason: MenuCloseReason = "programmatic"): void {
    const handler = this.options.onClose;
    const hadHost = this.host !== null;
    if (this.host) {
      this.host.remove();
    }
    if (this.field) {
      this.field.removeEventListener("keydown", this.onFieldKeyDown);
    }
    document.removeEventListener("pointerdown", this.onDocumentPointerDown, true);
    window.removeEventListener("scroll", this.onScroll, { capture: true });
    window.removeEventListener("resize", this.onResize);

    this.host = null;
    this.panel = null;
    this.list = null;
    this.search = null;
    this.emptyMessage = null;
    this.field = null;
    this.entries = [];
    this.visible = [];
    this.actions = [];
    this.options = {};
    this.index = -1;

    if (hadHost && handler) {
      try {
        handler(reason);
      } catch {
        // A listener bug must not break the next menu.
      }
    }
  }

  /** Reposition after the page moved the field without a scroll event. */
  reposition(): void {
    this.position();
  }

  private installListeners(): void {
    document.addEventListener("pointerdown", this.onDocumentPointerDown, true);
    window.addEventListener("scroll", this.onScroll, { passive: true, capture: true });
    window.addEventListener("resize", this.onResize, { passive: true });
    this.field?.addEventListener("keydown", this.onFieldKeyDown);
    this.host?.addEventListener("keydown", this.onKeyDown);
    this.search?.addEventListener("input", this.onSearchInput);
  }

  private readonly onSearchInput = (): void => {
    this.visible = filterMenuEntries(this.entries, this.search?.value ?? "");
    this.index = this.visible.length > 0 ? 0 : -1;
    this.renderList();
    this.position();
  };

  private readonly onKeyDown = (event: KeyboardEvent): void => {
    if (!this.host) {
      return;
    }
    // Never let page hotkeys see keys typed into the card.
    event.stopPropagation();

    if (event.key === "Escape") {
      event.preventDefault();
      this.close("user");
      this.field?.focus({ preventScroll: true });
      return;
    }

    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      if (this.visible.length === 0) {
        return;
      }
      event.preventDefault();
      this.move(event.key === "ArrowDown" ? 1 : -1);
      return;
    }

    if (event.key === "Enter") {
      const target = event.target;
      if (target instanceof HTMLButtonElement) {
        // Native Enter activation for the focused action.
        return;
      }
      const entry = this.visible[this.index];
      if (entry) {
        event.preventDefault();
        this.pick(entry, this.index);
      }
    }
  };

  private move(delta: number): void {
    if (this.visible.length === 0) {
      return;
    }
    this.index =
      this.index < 0
        ? 0
        : (this.index + delta + this.visible.length) % this.visible.length;
    this.highlight();
  }

  private renderList(): void {
    const list = this.list;
    if (!list) {
      return;
    }
    list.textContent = "";
    this.visible = filterMenuEntries(this.entries, this.search?.value ?? "");
    if (this.index >= this.visible.length) {
      this.index = this.visible.length > 0 ? 0 : -1;
    }
    for (const [index, entry] of this.visible.entries()) {
      const button = element("button", "item");
      button.type = "button";
      button.setAttribute(FP_ATTR, "menu-item");
      button.setAttribute("data-friendlypass-uuid", entry.uuid);
      button.setAttribute("role", "option");
      button.id = `${this.menuId}-item-${index}`;
      button.setAttribute("aria-selected", index === this.index ? "true" : "false");

      const monogram = element("span", "fp-monogram");
      monogram.textContent = monogramFor(entry);
      const text = element("span", "text");
      const title = element("span", "title");
      title.textContent = entry.title || entry.username || "friendlypass entry";
      const value = element("span", "value");
      value.textContent = entry.username || "(no username)";
      if (entry.group) {
        value.title = entry.group;
      }
      text.append(title, value);
      button.append(monogram, text);
      if (entry.totp) {
        const mark = element("span", "totp-mark", "TOTP");
        button.append(mark);
      }

      button.addEventListener("mousedown", (event) => event.preventDefault());
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        this.pick(entry, index);
      });
      list.append(button);
    }

    if (this.emptyMessage) {
      const query = this.search?.value.trim() ?? "";
      if (this.visible.length === 0 && (!query && this.options.emptyMessage === "")) {
        this.emptyMessage.style.display = "none";
      } else if (this.visible.length === 0) {
        this.emptyMessage.textContent = query
          ? `No logins match “${query}”.`
          : this.options.emptyMessage ?? "No saved logins for this page.";
        this.emptyMessage.style.display = "block";
      } else {
        this.emptyMessage.style.display = "none";
      }
    }

    this.search?.setAttribute(
      "aria-activedescendant",
      this.index >= 0 ? `${this.menuId}-item-${this.index}` : "",
    );
    this.highlight();
  }

  private highlight(): void {
    if (!this.list) {
      return;
    }
    const items = this.list.querySelectorAll<HTMLButtonElement>(
      `[${FP_ATTR}="menu-item"]`,
    );
    items.forEach((item, index) => {
      item.setAttribute("aria-selected", index === this.index ? "true" : "false");
    });
    this.search?.setAttribute(
      "aria-activedescendant",
      this.index >= 0 ? `${this.menuId}-item-${this.index}` : "",
    );
    items[this.index]?.scrollIntoView({ block: "nearest" });
  }

  private pick(entry: MenuEntry, index: number): void {
    const handler = this.options.onPick;
    this.close("pick");
    handler?.(entry, index);
  }

  private position(): void {
    if (!this.host || !this.field) {
      return;
    }
    const anchor = this.field.getBoundingClientRect();
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    const first = computeMenuPosition(
      anchor,
      { width: 0, height: this.host.offsetHeight },
      viewport,
    );
    this.host.style.setProperty("width", `${first.width}px`, "important");
    this.host.style.setProperty("max-height", `${first.maxHeight}px`, "important");
    if (this.panel) {
      this.panel.style.maxHeight = `${first.maxHeight}px`;
    }
    const chrome = this.list
      ? Math.max(0, this.host.offsetHeight - this.list.offsetHeight)
      : 0;
    if (this.list) {
      this.list.style.maxHeight = `${Math.max(72, first.maxHeight - chrome - 2)}px`;
    }
    const measured = {
      width: this.host.offsetWidth || first.width,
      height: this.host.offsetHeight || first.maxHeight,
    };
    const placement = computeMenuPosition(anchor, measured, viewport);
    this.host.style.setProperty("top", `${placement.top}px`, "important");
    this.host.style.setProperty("left", `${placement.left}px`, "important");
    this.host.style.setProperty("width", `${placement.width}px`, "important");
    this.host.style.setProperty(
      "max-height",
      `${placement.maxHeight}px`,
      "important",
    );
    this.host.setAttribute(`${FP_ATTR}-placement`, placement.placement);
  }
}
