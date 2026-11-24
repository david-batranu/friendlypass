/**
 * TOTP field detection (WP4, ported from upstream `content/totp-field.js`).
 *
 * Only the detection predicate lives here; the icon and the fill path live in
 * `icon.ts` / `index.ts`. Segmented one-time-code inputs (six single-character
 * boxes) are a known gap: the current engine fills a single TOTP input.
 */

/** Words that make an input look like a one-time-code entry. */
export const ACCEPTED_OTP_FIELDS = [
  "2fa",
  "2fpin",
  "auth",
  "challenge",
  "code",
  "idvpin",
  "mfa",
  "one_time_password",
  "one-time password",
  "otc-confirmation-input",
  "otp",
  "otppw",
  "token",
  "twofa",
  "two-factor",
  "twofactor",
  "verification_pin",
  "mfacode",
] as const;

/** False positives: coupon/postcode/encoding fields that contain "code". */
const IGNORE_REGEX =
  /(bank|bar|coupon|post(al)?|user|zip|promo).*code|(en|de)code(d|r)*|comment|author|error/i;

const IGNORED_TYPES = ["email", "username"] as const;
const ALLOWED_INPUT_TYPES = ["number", "password", "tel", "text"] as const;
const ACCEPTED_PARENTS = [".mfa-verify"] as const;

export const MIN_TOTP_INPUT_LENGTH = 6;
export const MAX_TOTP_INPUT_LENGTH = 10;

function attributeIncludes(element: Element, word: string): boolean {
  const id = (element.getAttribute("id") ?? "").toLowerCase();
  const name = (element.getAttribute("name") ?? "").toLowerCase();
  const placeholder = (element.getAttribute("placeholder") ?? "").toLowerCase();
  return id.includes(word) || name.includes(word) || placeholder.includes(word);
}

/**
 * Quick check for a plausible TOTP input: one of the accepted words appears in
 * the id/name/placeholder and none of the ignored words does, or the input is
 * inside a known MFA container.
 */
export function isAcceptedTOTPField(field: HTMLInputElement): boolean {
  const type = (field.getAttribute("type") ?? "").toLowerCase();
  if (!ALLOWED_INPUT_TYPES.some((allowed) => allowed === type)) {
    return false;
  }

  const accepted =
    ACCEPTED_OTP_FIELDS.some((word) => attributeIncludes(field, word)) ||
    ACCEPTED_PARENTS.some((selector) => field.closest(selector) !== null);
  if (!accepted) {
    return false;
  }

  return !IGNORED_TYPES.some((word) => attributeIncludes(field, word));
}

/**
 * Full TOTP validity check. `forced` skips the heuristics (used for a
 * user-defined TOTP field in Custom Login Fields, not implemented yet).
 *
 * `maxlength` is read from the attribute rather than the IDL property: the IDL
 * defaults to 524288 in Chromium, which would otherwise reject every field
 * without an explicit `maxLength` attribute.
 */
export function isTOTPField(field: HTMLInputElement | null, forced = false): boolean {
  if (!field) {
    return false;
  }

  if ((field.getAttribute("autocomplete") ?? "").toLowerCase() === "one-time-code") {
    return true;
  }

  if (!isAcceptedTOTPField(field)) {
    return false;
  }

  if (forced) {
    return true;
  }

  const type = (field.getAttribute("type") ?? "").toLowerCase();
  if (IGNORED_TYPES.some((ignored) => ignored === type)) {
    return false;
  }
  if (field.offsetWidth < 60) {
    return false;
  }
  if (field.size < 2) {
    return false;
  }

  const maxLengthAttr = field.getAttribute("maxlength");
  if (maxLengthAttr !== null) {
    const maxLength = Number.parseInt(maxLengthAttr, 10);
    if (
      Number.isFinite(maxLength) &&
      (maxLength < MIN_TOTP_INPUT_LENGTH || maxLength > MAX_TOTP_INPUT_LENGTH)
    ) {
      return false;
    }
  }

  if (IGNORED_TYPES.some((ignored) => ignored === (field.autocomplete ?? "").toLowerCase())) {
    return false;
  }
  if (IGNORE_REGEX.test(field.id)) {
    return false;
  }
  if (IGNORE_REGEX.test(field.name)) {
    return false;
  }
  if (IGNORE_REGEX.test(field.placeholder)) {
    return false;
  }
  if (field.readOnly) {
    return false;
  }
  if (field.inputMode === "email") {
    return false;
  }

  return true;
}

/** `true` when the entry has a TOTP secret (wire `totp` or a `KPH: {TOTP}` field). */
export function entryHasTotp(entry: {
  totp?: string;
  stringFields?: Array<Record<string, string>>;
}): boolean {
  if (typeof entry.totp === "string" && entry.totp.length > 0) {
    return true;
  }
  return (entry.stringFields ?? []).some((field) => Boolean(field["KPH: {TOTP}"]));
}

/** TOTP value embedded in the entry's KeePassXC string fields, if any. */
export function entryStringTotp(entry: {
  stringFields?: Array<Record<string, string>>;
}): string | undefined {
  for (const field of entry.stringFields ?? []) {
    const value = field["KPH: {TOTP}"];
    if (value) {
      return value;
    }
  }
  return undefined;
}
