/**
 * Form submission handling (WP4, ported from `content/form.js`).
 *
 * Reads the submitted username/password pair (including "current/new/repeat"
 * password-change forms) and decides whether it is worth offering to save it.
 * The actual banner and `set-login` call live in `banner.ts`.
 */

import type { CredentialEntry } from "../common/types";
import type { FieldCombination } from "./fields";
import { getNewPassword, passwordInputsForForm } from "./fields";
import { formActionUrl } from "./ui";

export interface SubmittedCredentials {
  username: string;
  password: string;
  submitUrl?: string;
  /** True when the new password was taken from a multi-password form. */
  passwordChange: boolean;
}

function firstTextValue(form: HTMLFormElement | null): string {
  if (!form) {
    return "";
  }
  const field = Array.from(form.querySelectorAll("input")).find((input) => {
    if (input.type === "text" || input.type === "email") {
      return true;
    }
    return false;
  });
  return field?.value ?? "";
}

/** Extract the credentials a submit event is about to send. */
export function readSubmittedCredentials(
  form: HTMLFormElement | null,
  combination: FieldCombination | undefined,
): SubmittedCredentials | null {
  const passwordInputs = form
    ? passwordInputsForForm(form)
    : (combination?.passwordInputs ?? []);

  let password = "";
  let passwordChange = false;
  if (passwordInputs.length >= 2) {
    passwordChange = true;
    password = getNewPassword(passwordInputs);
  } else if (combination?.password) {
    password = combination.password.value;
  } else {
    password = passwordInputs[0]?.value ?? "";
  }

  if (!password) {
    return null;
  }

  const username =
    (combination?.username?.value ??
      (form?.querySelector('input[type="text"], input[type="email"]') as HTMLInputElement | null)
        ?.value) ||
    firstTextValue(form);

  const result: SubmittedCredentials = {
    username: username.trim(),
    password,
    passwordChange,
  };
  const submitUrl = formActionUrl(form);
  if (submitUrl) {
    result.submitUrl = submitUrl;
  }
  return result;
}

/** `true` when the exact pair is already known for this page. */
export function isAlreadySaved(
  entries: CredentialEntry[],
  username: string,
  password: string,
): boolean {
  return entries.some(
    (entry) => entry.login === username && entry.password === password,
  );
}

/** Existing entry with the same username, if the new password should update it. */
export function findExistingEntry(
  entries: CredentialEntry[],
  username: string,
): CredentialEntry | undefined {
  return entries.find((entry) => entry.login === username);
}
