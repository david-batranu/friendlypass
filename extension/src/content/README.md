# Content fill engine (WP4)

Runs in every frame (`all_frames: true`) and talks to the background **only**
through the typed internal API in `src/common/messages.ts`.

| Module | Ported from | Responsibility |
|---|---|---|
| `index.ts` | `content/keepassxc-browser.js` | controller: init, detection passes, icon wiring, fills, save banner, content commands |
| `fields.ts` | `content/fields.js` | input collection (incl. open shadow roots), search exclusion, combinations, new-password helper |
| `totp-field.ts` | `content/totp-field.js` | TOTP predicate + entry TOTP helpers |
| `observer.ts` | `content/observer-helper.js` | debounced `MutationObserver` for SPA/late forms |
| `form.ts` | `content/form.js` | submitted username/password extraction |
| `fill.ts` | `content/fill.js` | value write + framework-friendly event sequence |
| `icon.ts` | `content/icon.js`, `icon-handler.js` | one fixed-position icon per field, open shadow root |
| `username-field.ts` | `content/username-field.js` | which field gets the login icon |
| `autocomplete.ts` | `content/autocomplete.js` | anchored dropdown, keyboard handling |
| `credential-autocomplete.ts` | `content/credential-autocomplete.js` | login dropdown |
| `totp-autocomplete.ts` | `content/totp-autocomplete.js` | TOTP dropdown |
| `banner.ts` | `content/banner.js` | save/update card → `logins.save` |
| `ui.ts` | `content/ui.js` | visibility, notifications, small DOM helpers |
| `testing.ts` | — | test-only bundle exposing the pure detection API |

## Internal messages used

- `logins.get` — matching entries for `location.href` / form action
- `logins.save` — create/update from the save banner
- `submit.store` — remember a just-submitted pair before the page can unload
- `submit.pending` — consume the pair on the next page in the same tab/site
- `submit.clear`, `submit.never` — dismiss/opt out of the save offer
- `totp.get` — current code, with the `get-logins` value as fallback
- `settings.get`, `status.get` — background settings/status
- content commands: `content.fillLogin`, `content.fillTotp`,
  `content.clearCredentials`, `content.redetectFields`,
  `content.showSaveBanner`, `content.showConnectedStatus`

The pending store lives in `chrome.storage.session` (never on disk), keyed by
tab, and is only returned to the frame that submitted the form, on the same
registrable site, within 60 s. Two loopback ports are different sites, and
"Never for this site" is remembered per origin in `chrome.storage.local`.

## Content-only settings

`chrome.storage.local["friendlypass.content.settings.v1"]`:

```json
{ "autoFillSingleEntry": false, "showIcons": true }
```

Both default to upstream behaviour. The popup/options UI (WP6) should write this
key; the background's `ExtensionSettings` does not own it.

## Known gaps

- No passkeys, password generator, custom login fields, StringField filling,
  segmented TOTP boxes, site-specific exception list, site ignore list,
  auto-submit or context-menu fill.
- A pending submission is offered only once (it is consumed when the banner is
  shown); there is no "review missed logins" list.
- Closed shadow roots are not traversed (open roots are).
- Settings are read once per document load; changes apply on the next page.
