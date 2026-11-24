# Content fill engine and in-page UI (WP4 + WP6b)

Runs in every frame (`all_frames: true`) and talks to the background **only**
through the typed internal API in `src/common/messages.ts`.

| Module | Ported from | Responsibility |
|---|---|---|
| `index.ts` | `content/keepassxc-browser.js` | controller: init, detection passes, icon/menu wiring, fills, generate, save banner, shortcut commands, settings/site policies |
| `fields.ts` | `content/fields.js` | input collection (incl. open shadow roots), search exclusion, combinations, new-password helper |
| `totp-field.ts` | `content/totp-field.js` | TOTP predicate + entry TOTP helpers |
| `observer.ts` | `content/observer-helper.js` | debounced `MutationObserver` for SPA/late forms |
| `form.ts` | `content/form.js` | submitted username/password extraction |
| `fill.ts` | `content/fill.js` | value write + framework-friendly event sequence |
| `icon.ts` | `content/icon.js`, `icon-handler.js` | field icon in an open shadow root; states/repositioning/eye-control offset |
| `icon-state.ts` | — | pure matches/empty/locked/hidden decision table |
| `username-field.ts` | `content/username-field.js` | which field gets the login icon |
| `autocomplete.ts` | `content/autocomplete.js` | inline menu: search, keyboard navigation, actions, viewport-aware placement |
| `position.ts` | — | pure below/flip-above/clamp geometry |
| `credential-autocomplete.ts` | `content/credential-autocomplete.js` | credential → menu entry mapping |
| `totp-autocomplete.ts` | `content/totp-autocomplete.js` | TOTP-only menu entry mapping |
| `banner.ts` | `content/banner.js` | top-right save/update card → `logins.save`, group picker |
| `ui.ts` | `content/ui.js` | visibility, shadow-root toast, small DOM helpers |
| `settings.ts` | — | WP6 settings defaults/aliases, per-origin policy, settings.changed guard |
| `styles.ts` | — | design tokens (light/dark) and open-shadow-root host helper |
| `testing.ts` | — | test-only bundle exposing the pure detection and UI API |

## In-page UI (WP6b)

Everything injected lives in an **open shadow root** with its own stylesheet and
the WP6 tokens (`--fp-bg`, `--fp-surface`, `--fp-text`, `--fp-muted`,
`--fp-border`, `--fp-accent`, `--fp-danger`, `--fp-ok`; 8 px grid, 8/6 px radii,
2 px focus ring, system fonts). No external fonts, no network requests, no
remote code. Host properties are inline `!important`, so a hostile page
stylesheet cannot hide or move the icon, menu, card or toast.

- **Icon** — accent when matches exist, muted when none, lock badge when
  locked, visually hidden when the app is down or icons are disabled. One icon
  per field, never on search fields, repositioned on scroll/resize/field resize,
  and offset away from a page-provided eye/clear control.
- **Inline menu** — opens on icon click, on focus of an empty login field with
  matches (focus is *not* moved), or through `Ctrl/Cmd+Shift+K`. Search box,
  ↑/↓/Enter/Esc, monograms, "Fill TOTP", "Generate password", "Locked — unlock
  friendlypass", "Open friendlypass", flips above near the viewport bottom and
  closes on outside click/Esc/scroll-away.
- **Save/update card** — top-right, Save/Update, Not now, Never for this site,
  optional group picker (`defaultGroupAlwaysAsk`), keyboard accessible, auto-
  dismisses after 60 s.
- **Shortcuts** (`manifest.commands`, four suggested keys — Chrome's maximum):
  fill login `Ctrl/Cmd+Shift+L`, inline menu `Ctrl/Cmd+Shift+K`, generate
  password `Ctrl/Cmd+Shift+G`, open popup `Alt+Shift+F` (`Option+Shift+F` on
  macOS). Chrome reserves `Ctrl/Cmd+Shift+O` for the bookmark manager, so it
  cannot be used as an extension shortcut. The options page lists the effective
  keys from `chrome.commands.getAll()`.

## Settings

The only settings API is `settings.get` / `settings.set`. `settings.ts` applies
the WP6 defaults and aliases (`autoFillHttpAuth` → `httpAuthAutoFill`) while
WP6a finishes the unified `ExtensionSettings` type:

```ts
autoFillSingleEntry: false, showFieldIcons: true, httpAuthAutoFill: true,
autoFillAndSubmit: false, launchAppOnConnect: false, defaultGroup: "",
defaultGroupAlwaysAsk: false, debugLogging: false, siteExceptions: []
```

`settings.changed` is broadcast exactly once per `settings.set`: the state
store's single `broadcastSettings` fans out to extension pages
(`chrome.runtime.sendMessage`) and to every content-script frame in every tab
(`chrome.tabs.sendMessage`). The content script applies the payload live
(icons appear/disappear, fill/save are disabled). Per-origin `siteExceptions`
(`disableFill`, `disableSave`, `disableIcons`) match the exact origin.
"Never for this site" merges `disableSave: true` into the existing entry (or
adds one) through `settings.set`, so it survives page and extension reloads and
is listed on the options page. The legacy WP4 key
`chrome.storage.local["friendlypass.content.settings.v1"]`
(`{ autoFillSingleEntry, showIcons }`) is still read as a fallback so existing
installs keep their behaviour.

## Internal messages used

- `logins.get` — matching entries for `location.href` / form action
- `logins.save` — create/update from the save card (group included)
- `submit.store` — remember a just-submitted pair before the page can unload
- `submit.pending` — consume the pair on the next page in the same tab/site
- `submit.clear`, `submit.never` — dismiss/opt out of the save offer
- `popup.open` — open the action popup (or its fallback window) from the menu
- `totp.get` — current code, with the `get-logins` value as fallback
- `password.generate` — generator for signup/password-change forms
- `groups.list` — save-card group picker
- `database.unlock` — the locked menu item
- `settings.get`, `settings.set`, `status.get` — background settings/status
- content commands: `content.fillLogin`, `content.fillTotp`,
  `content.clearCredentials`, `content.redetectFields`,
  `content.showSaveBanner`, `content.showConnectedStatus`
- raw shortcut/broadcast events (WP6b): `content.openInlineMenu`,
  `content.generatePassword`, `settings.changed`, `status.changed`

The pending store lives in `chrome.storage.session` (never on disk), keyed by
tab, and is only returned to the frame that submitted the form, on the same
registrable site, within 60 s. Two loopback ports are different sites, and
"Never for this site" marks the origin in the pending store and merges
`disableSave: true` into `siteExceptions` (visible and removable in options).

## Known gaps

- No passkeys, custom login fields, StringField filling, segmented TOTP boxes,
  auto-submit or context-menu fill.
- The action popup is opened through a `popup.open` background request:
  `chrome.action.openPopup()` when Chrome accepts it, otherwise a small popup
  window. Chrome may decline the API without a user gesture; the fallback is
  then used.
- The save card's editable title is sent as the optional `[friendlypass]`
  `title` field of `set-login`; new entries use it and updates rewrite the title
  only when the user changed it. Without it, the entry title remains derived
  from the URL host.
- The 60 s auto-dismiss is covered by a unit assertion on the constant, not by
  a 60 s browser test.
- A pending submission is offered only once (it is consumed when the card is
  shown); there is no "review missed logins" list.
- Closed shadow roots are not traversed (open roots are).
