/**
 * Username-field icon (WP4, ported from upstream
 * `content/username-field.js` and the username half of `icon-handler.js`).
 *
 * Upstream attaches a username icon to the username field, or to the password
 * field when the form is a password-only step. The icon itself, its shadow root
 * and its state live in `icon.ts`; this module owns the "which field gets the
 * login icon" decision so it matches upstream's two-step behaviour.
 */

import type { FieldCombination } from "./fields";
import { ensureIcon, hasIcon } from "./icon";
import { MIN_INPUT_FIELD_OFFSET_WIDTH } from "./ui";

function isUsableField(field: HTMLInputElement | null): field is HTMLInputElement {
  return Boolean(
    field &&
      field.isConnected &&
      field.offsetWidth >= MIN_INPUT_FIELD_OFFSET_WIDTH &&
      !field.readOnly,
  );
}

/**
 * Attach the login icon to a combination when it has a fillable field.
 * Invokes `onActivate` with the field the icon belongs to.
 */
export function ensureLoginIcon(
  combination: FieldCombination,
  onActivate: (field: HTMLInputElement) => void,
): void {
  const field =
    combination.username && isUsableField(combination.username)
      ? combination.username
      : isUsableField(combination.password)
        ? combination.password
        : null;

  if (!field || hasIcon(field)) {
    return;
  }

  ensureIcon(field, "login", () => onActivate(field));
}
