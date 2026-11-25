# friendlypass browser extension — file ownership

**Frozen in WP0.** This table exists so parallel work packages never edit the
same file. If a change is needed in a file you do not own, message the owner (or
the architect for frozen files); do not edit it "just this once" — that is how
merge conflicts and diverging contracts happen.

Derived from REPORT §8.1 and adjusted to the scaffold paths actually created in
WP0.

## 1. Rule of first claim

1. **One owner per file.** Directories are owned recursively unless a sub-path
   is listed separately.
2. **Frozen files** (§2) may only be changed by the architect (WP0). They are
   contract or build plumbing.
3. **New files** belong to the owner of their directory. New *tests* go under
   the owning test directory with a WP-specific name, e.g.
   `extension/tests/unit/transport.test.ts`.
4. **Generated files** are never edited: `extension/dist/**`,
   `extension/node_modules/**`, `target/**`, `protocol/fixtures/*.json`
   (regenerate them instead).
5. If two packages truly need a shared helper, the helper goes in the owner's
   file with an exported, documented signature; the other package imports it.
   No copy-paste forks of contract code.

## 2. Frozen by WP0 (architect) — do not edit

| Path | Why frozen |
|---|---|
| `protocol/ACTIONS.md` | The wire contract everyone codes against |
| `protocol/version` | Protocol version (`1`) |
| `protocol/fixtures/*.json` | Golden vectors; regenerate, never hand-edit |
| `protocol/gen-fixtures.mjs` | Fixture generator; changes require regenerated vectors |
| `protocol/OWNERSHIP.md` | This file |
| `extension/package.json` | Dependency + script manifest; request changes from WP0 |
| `extension/package-lock.json` | Lockfile for the above |
| `extension/tsconfig.json` | Shared compiler settings |
| `extension/src/manifest.json` | MV3 manifest (permissions, host name, SW entry) |
| `extension/scripts/build.mjs` | Single build definition (entry points may be extended only by the build owner) |
| `extension/.gitignore` | Build outputs |
| `extension/README.md` | Fork/licence/commands documentation |
| `Cargo.toml` (workspace `members`) | Adding crates is an architect decision |
| `Cargo.lock` | Updated by cargo; do not hand-edit |
| `crates/friendlypass-browser/tests/fixtures_crypto.rs` | WP0 conformance test |

Notes:

- **Dependencies:** WP agents that need a new npm package ask the architect to
  add it to `extension/package.json` (and to run `npm install`), so the lockfile
  has one author.
- **Build entries:** WP2/WP4/WP5/WP6 will need additional esbuild entry points
  (content scripts, popup, options). Add them to `scripts/build.mjs` through a
  coordinated change with the architect; do not create a second build script.
- **Protocol changes:** only the architect bumps `protocol/version`, updates
  `ACTIONS.md`, regenerates fixtures, and mirrors changes into
  `extension/src/common/types.ts`.

## 3. Phase 1 owners

| WP | Owned paths (create/edit only these) | Deliverable |
|---|---|---|
| **WP1 — native host + installer** | `crates/friendlypass-browser-host/**` (Cargo.toml, `src/**`, `tests/**`) · `installer/**` · `packaging/**` | stdio host with framing/UTF-8/1 MiB guard, retry/backoff, host-level `ping`/`hello`, forward to app socket; per-browser native-messaging manifests |
| **WP2 — extension transport & lifecycle** | `extension/src/background/transport.ts` · `extension/src/background/sw.ts` · `extension/src/background/lifecycle.ts` · `extension/tests/unit/transport.test.ts` · `extension/tests/e2e/connection.spec.ts` | `NativePort`, heartbeat, backoff, alarms watchdog, idempotent connect, typed pending-request rejection; synchronous listener registration |
| **WP3 — protocol client, session, state** | `extension/src/background/session.ts` · `extension/src/background/actions.ts` · `extension/src/background/state.ts` · `extension/src/common/types.ts` · `extension/src/common/messages.ts` · `extension/src/common/urls.ts` · `extension/tests/unit/protocol.test.ts` | handshake/nonce/crypto, serialized `ensureSession()`, association cache, typed actions, persisted `clientID`, state events |
| **WP7a — Rust server basics** | `crates/friendlypass-browser/src/**` · `crates/friendlypass-browser/tests/e2e_proxy.rs` · `crates/friendlypass-gui/src/browser_bridge.rs` (new) · browser section of `crates/friendlypass-gui/src/dialogs.rs` · wiring only in `crates/friendlypass-gui/src/app.rs` | `get-databasehash` fix, plaintext entries, `ping`/`hello` server side, persistent/approved associations, auto-start, lock/unlock pushes, no fake hash |
| **WP8 — harness, CI, packaging tests** | `extension/tests/harness/**` · `extension/playwright.config.ts` · `.github/workflows/**` · `scripts/e2e.sh` | one-command app-mock + host + extension harness, fault injection, CI matrix |

### WP1 details

Owns the whole new crate, including its `Cargo.toml` dependencies and its own
`tests/**`. It must not edit `crates/friendlypass-browser/**` or any GUI file.
It may add fixtures/integration scripts under `installer/**` and
`packaging/**`; if a mock app server is needed for tests, it goes in
`crates/friendlypass-browser-host/tests/` (WP1), not in WP8's TS harness.

### WP2 details

Owns the transport boundary `createNativeTransport()` declared in
`transport.ts` and the service-worker entry `sw.ts`. WP3 imports the interface
but must not edit those files. Any change to `TransportHandlers` /
`NativeTransport` is a WP2 change that must be announced to WP3 and WP5.

`sw.ts` is the only place listeners are registered synchronously. WP5's
`installHttpAuthListener()` is called from `sw.ts`; WP2 adds that call, WP5 owns
the implementation file.

### WP3 details

Owns the contract-adjacent TypeScript files (`common/types.ts`,
`common/messages.ts`). They are frozen in shape: WP3 may add helpers and
internal-API actions, but wire types change only with the architect. WP3 must
keep the golden fixtures passing and must not alter the Rust crypto module.

### WP7a details

Owns `crates/friendlypass-browser/src/**` and may fix the seven P0 protocol bugs
listed in REPORT §5.1. It must keep `tests/fixtures_crypto.rs` green (read-only
for WP7a) and must not weaken the crypto module's public API without telling
WP3/WP1. GUI edits are limited to the browser bridge, the browser section of
`dialogs.rs`, and wiring in `app.rs`.

Do **not** edit `crates/friendlypass-browser/tests/fixtures_crypto.rs`; it is
WP0's acceptance test. Add new tests under a new file name.

### WP8 details

Owns the test harness, Playwright config and CI. It may add test fixtures under
`extension/tests/harness/**` and may create `extension/tests/fixtures/**`. It
must not edit `playwright` specs owned by WP2 (`tests/e2e/connection.spec.ts`) or
WP5 (`tests/e2e/http-auth.spec.ts`); it runs them.

## 4. Later-phase placeholders (already scaffolded, not owned yet)

These files exist so the project builds, but their real owners arrive in later
phases. Until then, only the listed owner may replace the TODO stub.

| Path | Future owner |
|---|---|
| `extension/src/background/http-auth.ts` | WP5 (HTTP Basic/Digest) |
| `extension/src/auth/**` | WP5 |
| `extension/tests/e2e/http-auth.spec.ts` | WP5 |
| `extension/tests/fixtures/http-auth-server.mjs` | WP5 |
| `extension/src/content/**` | WP4 (forked fill engine) |
| `extension/tests/content/**` | WP4 |
| `extension/src/popup/**` | WP6 |
| `extension/src/options/**` | WP6 |

WP2 must add the `installHttpAuthListener()` call in `sw.ts` when WP5 lands; it
does not take ownership of `http-auth.ts`.

## 5. Shared files that require coordination

| File | Owner | Coordination rule |
|---|---|---|
| `extension/scripts/build.mjs` | WP0 | Entry points added by request; keep one build |
| `extension/package.json` / lock | WP0 | New dependency = request to WP0 |
| `crates/friendlypass-browser/src/protocol.rs` | WP7a | Shared action/error constants; announce signature changes |
| `crates/friendlypass-browser/src/crypto.rs` | WP7a | Used by WP0 test; do not change semantics |
| `crates/friendlypass-gui/src/app.rs` | WP7a (wiring only) | Keep changes minimal; coordinate with GUI work |
| `.github/workflows/**` | WP8 | Other WPs may request jobs, not edit |

## 6. Conflict checklist for every PR/agent

- [ ] Every changed file is in a path you own (§3) or you have explicit
      permission from its owner.
- [ ] Frozen files (§2) untouched.
- [ ] No hand-edited fixtures; `node protocol/gen-fixtures.mjs` was run if
      protocol code changed.
- [ ] `cargo test -p friendlypass-browser --test fixtures_crypto` still passes.
- [ ] `cd extension && npm run build && npm run typecheck` still passes.
- [ ] No secrets, plaintext credentials or decrypted payloads in logs, tests or
      committed files.
