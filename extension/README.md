# friendlypass browser extension

This is a **hard fork** of [keepassxc-browser](https://github.com/keepassxreboot/keepassxc-browser)
(upstream snapshot: `9d27471`, v1.10.4.1, 2026-11-19), rebranded and rebuilt as
the friendlypass browser extension.

## Licence

GPL-3.0-or-later. The fork keeps the upstream copyright notices and licence
headers; the full GPL-3.0 text is in the friendlypass repository. Any binary
distribution must be accompanied by the corresponding source.

## What is here

| Path | Owner | Purpose |
|---|---|---|
| `src/common/{types,messages}.ts` | WP3 | Frozen wire types and internal message API |
| `src/background/{transport,sw,lifecycle}.ts` | WP2 | Native port, framing, heartbeat, reconnect |
| `src/background/{session,actions,state}.ts` | WP3 | Handshake, actions, persistence |
| `src/background/http-auth.ts` | WP5 | `webRequest.onAuthRequired` |
| `src/content/**` | WP4 | Forked field/fill engine (not yet vendored) |
| `src/popup/**`, `src/options/**` | WP6 | UI |
| `tests/**`, `playwright.config.ts`, `scripts/e2e.sh` | WP8 | Harness and CI |

The upstream background layer (`client.js`, `keepass.js`, `init.js`,
`httpauth.js`) is **not** carried over: it is replaced by the typed modules
above. The upstream content/fill engine is intended to be vendored into
`src/content/` by WP4, with licence headers intact.

## Native host

The extension talks to the native host `org.friendlypass.browser` (not
`org.keepassxc.keepassxc_browser`). See `../protocol/ACTIONS.md` for the wire
contract and `../protocol/OWNERSHIP.md` for file ownership.

## Commands

```sh
npm install          # first time
npm run build        # esbuild bundle -> dist/ (+ manifest.json), Chrome MV3
npm run build:firefox# esbuild bundle -> dist-firefox/ (+ Firefox MV3 manifest)
npm run package      # both builds -> artifacts/friendlypass-{chrome,firefox}-<ver>.zip
npm run typecheck    # tsc: src/ (tsconfig.json) + tests/ (tsconfig.tests.json)
npm test             # vitest (tests/unit only)
npm run e2e          # playwright Chromium e2e (config in playwright.config.ts)
npm run e2e:firefox  # Puppeteer/WebDriver BiDi Firefox e2e (tests/firefox)
```

`dist/`, `dist-firefox/`, `artifacts/`, `.cache/` and `node_modules/` are
git-ignored. The built manifests are generated from `src/manifest.json`; edit
the source, never the build output.

## Firefox

One source tree, two manifests. `npm run build:firefox` reuses the same bundles
and produces `dist-firefox/` with:

- `background.scripts` (a classic IIFE) instead of Chrome's `service_worker`;
- `browser_specific_settings.gecko.id = friendlypass@friendlypass.org` and
  `strict_min_version = 128.0` (MV3 event pages, `storage.session`, blocking
  `webRequest`);
- `webRequestBlocking` instead of `webRequestAuthProvider` (Firefox supports
  blocking auth in MV3, Chrome does not);
- no Chrome `key` and no `minimum_chrome_version`.

`src/common/platform.ts` holds the only browser branches: callback/promise
storage, the 1-minute Firefox `alarms` minimum, `port.error` vs
`runtime.lastError`, tabs/commands/windows wrappers and the options shortcut
link. `HttpAuthAdapter` has a Firefox `["blocking"]` + `Promise` implementation
next to Chrome's `asyncBlocking` callback one; both feed the same controller.

`npm run package` runs `web-ext lint` over `dist-firefox` and fails if the
Firefox build has manifest errors.

## Stable extension id

`src/manifest.json` pins an RSA public `key`; Chrome therefore derives the same
32-character id for every load path: `pfdmagadklmhbghfipamhfbphcljdkbi`. The
installer defaults to that id, so `installer/install.sh` needs no
`--extension-id`. The private key lives outside the repository at
`../secrets/extension-key.pem` and must never be committed or shipped.
`browser_specific_settings.gecko.id` (`friendlypass@friendlypass.org`) is the
Firefox equivalent; Chrome warns about the unknown key but loads the extension
(the e2e harness proves it).
