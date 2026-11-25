/**
 * URL helpers (WP3).
 *
 * These decide which origin/subdomain an entry matches. KeePassXC's rules
 * (`BrowserService::handleURL` / `sortPriority`) are the reference; the
 * extension sends the page URL unchanged and lets the app rank matches, but it
 * still needs local helpers for HTTP-auth matching, the inline menu and
 * diagnostics.
 *
 * Design rules:
 *  - never throw on untrusted input (a page can navigate to `javascript:` or a
 *    malformed URL); invalid input yields `""` / `null` / `false`;
 *  - normalise exactly once, through the WHATWG `URL` parser, so IDNs become
 *    punycode and default ports disappear;
 *  - paths are case-sensitive; hosts and schemes are not;
 *  - fragments are never significant for matching, query strings are only
 *    significant for an "exact" match.
 */

/** Kind of match between a saved-entry URL and the current page URL. */
export type UrlMatchKind = "exact" | "origin" | "path" | "subdomain";

export interface UrlMatch {
  kind: UrlMatchKind;
  /**
   * Higher is better. The ranking mirrors KeePassXC's priority order: exact
   * URL, same path on the origin, same origin, then a parent-domain match.
   */
  score: number;
}

/**
 * Frequent multi-label public suffixes. Phase 1 deliberately does not vendor a
 * full Public Suffix List (that is a data-update problem of its own); this list
 * covers the common cases where a naive "last two labels" rule is wrong.
 */
const MULTI_LABEL_SUFFIXES: ReadonlySet<string> = new Set([
  "ac.uk",
  "co.in",
  "co.jp",
  "co.nz",
  "co.uk",
  "co.za",
  "com.au",
  "com.br",
  "com.cn",
  "com.hk",
  "com.mx",
  "com.sg",
  "com.tr",
  "edu.au",
  "gov.uk",
  "ne.jp",
  "net.au",
  "org.au",
  "org.uk",
  "or.jp",
]);

function parse(url: string): URL | null {
  if (typeof url !== "string" || url.length === 0) {
    return null;
  }
  try {
    const parsed = new URL(url);
    // `javascript:`, `data:` and `about:` have no host and must never be
    // matched against a saved login.
    if (!parsed.hostname) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/** Lower-cased hostname without a trailing dot; empty for invalid URLs. */
export function getHost(url: string): string {
  const parsed = parse(url);
  if (!parsed) {
    return "";
  }
  return parsed.hostname.replace(/\.$/, "").toLowerCase();
}

/** Lower-cased scheme including the colon (`https:`), or `""`. */
export function getProtocol(url: string): string {
  return parse(url)?.protocol.toLowerCase() ?? "";
}

/** True for `http:` and `https:` URLs; the only schemes a login matches. */
export function isHttpUrl(url: string): boolean {
  const protocol = getProtocol(url);
  return protocol === "http:" || protocol === "https:";
}

/**
 * Explicit port, or `null` when absent or default for the scheme. The WHATWG
 * parser already drops `:443` for https and `:80` for http.
 */
export function getPort(url: string): number | null {
  const parsed = parse(url);
  if (!parsed || parsed.port === "") {
    return null;
  }
  const port = Number.parseInt(parsed.port, 10);
  return Number.isFinite(port) ? port : null;
}

/**
 * `https://host[:port]/` with no path, query, fragment or credentials.
 * Non-web schemes return `scheme://host` without a trailing slash. Invalid
 * URLs return `""`.
 */
export function getOrigin(url: string): string {
  const parsed = parse(url);
  if (!parsed) {
    return "";
  }
  const base = `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}`;
  return parsed.protocol === "http:" || parsed.protocol === "https:"
    ? `${base}/`
    : base;
}

/**
 * Canonical form used for comparisons: scheme and host lower-cased, default
 * port removed, fragment dropped, empty path replaced with `/`. Query strings
 * are preserved because they can distinguish a login form (`?next=`).
 * Returns `null` for invalid/unsupported URLs.
 */
export function normalizeUrl(url: string): string | null {
  const parsed = parse(url);
  if (!parsed) {
    return null;
  }
  const path = parsed.pathname === "" ? "/" : parsed.pathname;
  return `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}${path}${parsed.search}`;
}

/** Path with an empty value normalised to `/`; `null` for invalid URLs. */
export function getPath(url: string): string | null {
  const parsed = parse(url);
  if (!parsed) {
    return null;
  }
  return parsed.pathname === "" ? "/" : parsed.pathname;
}

/** Strip a single trailing slash (except for the root path). */
export function normalizePath(path: string): string {
  if (!path.startsWith("/")) {
    return normalizePath(`/${path}`);
  }
  if (path.length > 1 && path.endsWith("/")) {
    return path.slice(0, -1);
  }
  return path;
}

/**
 * True when `pagePath` is the same as, or below, `entryPath`, at a path-segment
 * boundary. `/login` matches `/login` and `/login/step2`, but not `/loginx`.
 * An entry path of `/` matches everything on the origin.
 */
export function pathMatches(entryPath: string, pagePath: string): boolean {
  const entry = normalizePath(entryPath || "/");
  const page = normalizePath(pagePath || "/");
  if (entry === "/" || entry === page) {
    return true;
  }
  return page.startsWith(`${entry}/`);
}

function normaliseHostInput(value: string): string {
  if (!value) {
    return "";
  }
  const asUrl = parse(value);
  if (asUrl) {
    return getHost(value);
  }
  return value.trim().replace(/^\.+|\.+$/g, "").toLowerCase();
}

/** True when `host` equals `domain` or ends with `.<domain>` at label boundary. */
export function isSubdomainOf(host: string, domain: string): boolean {
  const child = normaliseHostInput(host);
  const parent = normaliseHostInput(domain);
  if (!child || !parent) {
    return false;
  }
  if (child === parent) {
    return true;
  }
  // IPv6 literals keep their brackets; a suffix match there is meaningless.
  if (parent.startsWith("[") || child.startsWith("[")) {
    return false;
  }
  return child.endsWith(`.${parent}`);
}

function isIpv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const value = Number.parseInt(part, 10);
    return value >= 0 && value <= 255;
  });
}

/**
 * The base domain (eTLD+1) used by `request-autotype`'s `search` field and by
 * same-site checks. IP addresses and single-label hosts (`localhost`) are
 * returned unchanged. A full public-suffix list is not required for phase 1;
 * the common multi-label suffixes are handled explicitly.
 */
export function getBaseDomain(url: string): string {
  const host = getHost(url);
  if (!host) {
    return "";
  }
  if (host.startsWith("[") || isIpv4(host)) {
    return host;
  }
  const labels = host.split(".").filter((label) => label.length > 0);
  if (labels.length <= 2) {
    return labels.join(".");
  }
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

/** True when both URLs use the same scheme and registrable domain (eTLD+1). */
export function isSameSite(a: string, b: string): boolean {
  const protocolA = getProtocol(a);
  const protocolB = getProtocol(b);
  if (!protocolA || protocolA !== protocolB) {
    return false;
  }
  if (!isHttpUrl(a) || !isHttpUrl(b)) {
    return getHost(a) !== "" && getHost(a) === getHost(b);
  }
  const baseA = getBaseDomain(a);
  const baseB = getBaseDomain(b);
  return baseA !== "" && baseA === baseB;
}

/** True when scheme, host and port all match. */
export function isSameOrigin(a: string, b: string): boolean {
  const originA = getOrigin(a);
  return originA !== "" && originA === getOrigin(b);
}

/** True when both URLs have the same host, ignoring scheme, port and path. */
export function isSameHost(a: string, b: string): boolean {
  const host = getHost(a);
  return host !== "" && host === getHost(b);
}

/**
 * Match a saved-entry URL against the current page URL.
 *
 * This is only a local pre-filter/ranking hint; the authoritative match order
 * comes from the app (`get-logins` returns entries already ordered). It is used
 * by HTTP auth (which may only match the exact origin) and by UI previews.
 *
 * Ranking, best first:
 *   exact    — normalised URLs equal (including query)
 *   path     — same origin and entry path is a prefix at a segment boundary
 *   origin   — same scheme/host/port, any path
 *   subdomain— page host is a subdomain of the entry host (same scheme)
 */
export function matchUrl(entryUrl: string, pageUrl: string): UrlMatch | null {
  if (!isHttpUrl(entryUrl) || !isHttpUrl(pageUrl)) {
    return null;
  }
  if (getProtocol(entryUrl) !== getProtocol(pageUrl)) {
    return null;
  }

  const normalEntry = normalizeUrl(entryUrl);
  const normalPage = normalizeUrl(pageUrl);
  if (normalEntry !== null && normalEntry === normalPage) {
    return { kind: "exact", score: 100 };
  }

  if (isSameOrigin(entryUrl, pageUrl)) {
    const entryPath = getPath(entryUrl);
    const pagePath = getPath(pageUrl);
    if (entryPath !== null && pagePath !== null && pathMatches(entryPath, pagePath)) {
      return { kind: "path", score: 80 };
    }
    return { kind: "origin", score: 60 };
  }

  const entryHost = getHost(entryUrl);
  const pageHost = getHost(pageUrl);
  if (entryHost && pageHost && isSubdomainOf(pageHost, entryHost)) {
    const entryPort = getPort(entryUrl);
    const pagePort = getPort(pageUrl);
    if (entryPort === pagePort) {
      return { kind: "subdomain", score: 40 };
    }
  }

  return null;
}

/** Convenience boolean form of {@link matchUrl}. */
export function urlMatches(entryUrl: string, pageUrl: string): boolean {
  return matchUrl(entryUrl, pageUrl) !== null;
}

/**
 * URL suitable for `get-logins`: the page URL without the fragment, preserving
 * scheme/host/path/query. Returns `""` for invalid or non-http(s) URLs.
 */
export function sanitizeForLookup(url: string): string {
  if (!isHttpUrl(url)) {
    return "";
  }
  const parsed = parse(url);
  if (!parsed) {
    return "";
  }
  return `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}${parsed.pathname === "" ? "/" : parsed.pathname}${parsed.search}`;
}
