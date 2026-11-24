/**
 * Credential filling (WP4, ported from upstream `content/fill.js`).
 *
 * The fill path is the part every site depends on, so it keeps upstream's event
 * order: focus/focusin, keydown, beforeinput, keypress, the value write, input,
 * keyup, change, then legacy `input`/`change` events on the document. Frameworks
 * that listen for only one of those still see the change.
 *
 * Auto-submit and StringField filling are deliberately not ported yet; both are
 * listed as known gaps in the WP4 report.
 */

import type { CredentialEntry } from "../common/types";
import type { FieldCombination } from "./fields";

function legacyEvent(field: HTMLInputElement, type: string): void {
  const event = field.ownerDocument.createEvent("Event");
  event.initEvent(type, true, false);
  field.dispatchEvent(event);
}

/** Set an input/select/checkbox value and notify the page exactly once. */
export function setValue(
  field: HTMLInputElement,
  value: string,
  forced = false,
): void {
  if (!field || (field.readOnly && !forced)) {
    return;
  }

  try {
    field.focus();
  } catch {
    // Some pages throw from a focus handler; the write must still happen.
  }

  field.dispatchEvent(new FocusEvent("focus", { bubbles: false, cancelable: false }));
  field.dispatchEvent(new FocusEvent("focusin", { bubbles: true, cancelable: false }));
  field.dispatchEvent(
    new KeyboardEvent("keydown", { bubbles: true, cancelable: false, key: value }),
  );
  field.dispatchEvent(
    new InputEvent("beforeinput", {
      bubbles: true,
      cancelable: false,
      inputType: "insertText",
      data: value,
    }),
  );
  field.dispatchEvent(
    new KeyboardEvent("keypress", { bubbles: true, cancelable: false, key: value }),
  );

  // React stores its own value tracker; the prototype setter is the reliable
  // way to make it observe a programmatic change.
  const descriptor = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  );
  if (descriptor?.set) {
    descriptor.set.call(field, value);
  } else {
    field.value = value;
  }

  field.dispatchEvent(new Event("input", { bubbles: true, cancelable: false }));
  field.dispatchEvent(
    new KeyboardEvent("keyup", { bubbles: true, cancelable: false, key: value }),
  );
  field.dispatchEvent(new Event("change", { bubbles: true, cancelable: false }));
  legacyEvent(field, "input");
  legacyEvent(field, "change");
}

export interface FillOptions {
  /** Fill only the password (a password-only step). */
  passOnly?: boolean;
}

/**
 * Fill one username/password combination from an entry.
 *
 * Returns `true` when at least one value was written.
 */
export function fillCombination(
  combination: FieldCombination,
  entry: CredentialEntry,
  options: FillOptions = {},
): boolean {
  const passOnly = options.passOnly === true;
  let filled = false;

  if (combination.password) {
    setValue(combination.password, entry.password);
    filled = true;
  }

  if (
    !passOnly &&
    combination.username &&
    combination.username !== combination.password
  ) {
    setValue(combination.username, entry.login);
    filled = true;
  }

  return filled;
}

/** Fill a one-time code into a TOTP input. */
export function fillTotp(field: HTMLInputElement, code: string): boolean {
  if (!code) {
    return false;
  }
  setValue(field, code);
  return true;
}
