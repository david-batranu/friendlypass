/**
 * URL helpers (WP3).
 *
 * These decide which origin/subdomain an entry matches. KeePassXC's rules
 * (BrowserService::handleURL / sortPriority) are the reference; the extension
 * must send the page URL unchanged and let the app rank matches.
 *
 * TODO(WP3): implement. Keep all host parsing here; content scripts must not
 * reinvent it.
 */

/** Lower-cased hostname without a trailing dot; empty for invalid URLs. */
export function getHost(_url: string): string {
  throw new Error("TODO(WP3): implement getHost");
}

/** `https://host[:port]/` with no path, query or credentials. */
export function getOrigin(_url: string): string {
  throw new Error("TODO(WP3): implement getOrigin");
}

/** True when both URLs resolve to the same registrable site. */
export function isSameSite(_a: string, _b: string): boolean {
  throw new Error("TODO(WP3): implement isSameSite");
}

/**
 * The base domain (eTLD+1) used by `request-autotype`'s `search` field.
 * A full public-suffix list is not required for phase 1.
 */
export function getBaseDomain(_url: string): string {
  throw new Error("TODO(WP3): implement getBaseDomain");
}
