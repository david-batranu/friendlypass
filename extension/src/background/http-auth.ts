/**
 * HTTP Basic/Digest authentication (WP5).
 *
 * Register `webRequest.onAuthRequired` synchronously at service-worker top
 * level. Every browser callback must be settled exactly once; on doubt answer
 * `{cancel: false}` so the page never hangs. See `protocol/ACTIONS.md` §5.5.
 *
 * TODO(WP5): implement with an 8 s deadline, a per-requestId loop guard, proxy
 * handling, and the single/multi-match picker.
 */

export function installHttpAuthListener(): void {
  throw new Error("TODO(WP5): register webRequest.onAuthRequired");
}
