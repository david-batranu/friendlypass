/**
 * Login field detection (WP4, ported from upstream `content/fields.js`).
 *
 * The upstream engine carries years of per-site exceptions (`sites.js`). This
 * port keeps the structural behaviour that the acceptance tests bind to and
 * deliberately drops the site list:
 *
 *   - inputs are collected in document order, including **open shadow roots**;
 *   - invisible fields, `type=hidden` fields and **search fields** are excluded;
 *   - a password input pairs with the closest preceding username candidate;
 *   - TOTP inputs become their own combination;
 *   - a lone username input is a username-only step when it opts in with
 *     `autocomplete=username|email` (or is the only field of a form);
 *   - a lone password input is a password-only step.
 *
 * Everything here is DOM-only so `testing.ts` can expose it to unit tests.
 */

import { acceptedInputType, isElementVisible, lowerAttr } from "./ui";
import { isTOTPField } from "./totp-field";

export interface FieldCombination {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
  passwordInputs: HTMLInputElement[];
  /** TOTP field when this combination represents a one-time-code step. */
  totp: HTMLInputElement | null;
  form: HTMLFormElement | null;
}

function isFormElement(element: Element | null): element is HTMLFormElement {
  return element !== null && element.tagName === "FORM";
}

/** The form that owns an input, walking out of open shadow roots. */
export function findForm(element: HTMLInputElement): HTMLFormElement | null {
  if (isFormElement(element.form)) {
    return element.form;
  }
  let current: Node | null = element.parentNode;
  while (current) {
    if (isFormElement(current as Element)) {
      return current as HTMLFormElement;
    }
    if (current instanceof ShadowRoot) {
      current = current.host;
      continue;
    }
    current = current.parentNode;
  }
  return null;
}

/**
 * Every input under `root`, including inputs inside open shadow roots.
 * Deduplicated while preserving traversal order.
 */
export function collectInputs(root: ParentNode): HTMLInputElement[] {
  const out: HTMLInputElement[] = [];
  const seenElements = new Set<Element>();
  const seenRoots = new Set<ParentNode>();

  const pushInput = (element: Element): void => {
    if (element instanceof HTMLInputElement && !seenElements.has(element)) {
      seenElements.add(element);
      out.push(element);
    }
  };

  const walk = (node: ParentNode): void => {
    if (seenRoots.has(node)) {
      return;
    }
    seenRoots.add(node);

    if (node instanceof HTMLInputElement) {
      pushInput(node);
    }

    for (const element of Array.from(node.querySelectorAll("*"))) {
      pushInput(element);
      if (element.shadowRoot) {
        walk(element.shadowRoot);
      }
    }

    if (node instanceof Element && node.shadowRoot) {
      walk(node.shadowRoot);
    }
  };

  walk(root);
  return out;
}

/** `true` when the form is a search form (action/id/class say "search"). */
export function isSearchForm(form: HTMLFormElement): boolean {
  const action = lowerAttr(form, "action");
  if (action?.includes("search") && !action.includes("research")) {
    return true;
  }
  const id = lowerAttr(form, "id");
  if (form.className && String(form.className).toLowerCase().includes("search")) {
    return true;
  }
  return Boolean(id?.includes("search") && !id.includes("research"));
}

/**
 * `true` when the input is a search box: an attribute mentions search/`q`, the
 * owning form is a search form, or an ancestor has `role="search"`.
 */
export function isSearchField(element: HTMLInputElement): boolean {
  for (const attribute of Array.from(element.attributes)) {
    const value = attribute.value.toLowerCase();
    if (value.includes("search") || value === "q") {
      return true;
    }
  }

  const form = findForm(element);
  if (form && isSearchForm(form)) {
    return true;
  }

  return element.closest('[role~="search"]') !== null;
}

export interface GetInputsOptions {
  /** Include invisible fields (upstream's password-change helper does). */
  ignoreVisibility?: boolean;
}

/** Visible, non-search candidate login inputs under `root`. */
export function getInputs(
  root: ParentNode,
  options: GetInputsOptions = {},
): HTMLInputElement[] {
  const inputs: HTMLInputElement[] = [];
  for (const element of collectInputs(root)) {
    if (element.disabled || !acceptedInputType(element)) {
      continue;
    }
    if (!options.ignoreVisibility && !isElementVisible(element)) {
      continue;
    }
    if (isSearchField(element)) {
      continue;
    }
    inputs.push(element);
  }
  return inputs;
}

function combinationFor(
  username: HTMLInputElement | null,
  password: HTMLInputElement,
): FieldCombination {
  return {
    username,
    password,
    passwordInputs: [password],
    totp: null,
    form: findForm(password),
  };
}

/**
 * Group inputs into username/password and TOTP combinations.
 *
 * A password input consumes the last username candidate seen before it. When
 * several passwords belong to one form (password change), each becomes its own
 * combination; the UI must not render login icons for those (see
 * `isLoginCombination`).
 */
export function buildCombinations(inputs: HTMLInputElement[]): FieldCombination[] {
  const combinations: FieldCombination[] = [];
  let usernameField: HTMLInputElement | null = null;

  for (const input of inputs) {
    if (input.type === "password") {
      combinations.push(combinationFor(usernameField, input));
      usernameField = null;
      continue;
    }

    if (isTOTPField(input)) {
      combinations.push({
        username: null,
        password: null,
        passwordInputs: [],
        totp: input,
        form: findForm(input),
      });
      continue;
    }

    usernameField = input;
  }

  if (combinations.length === 0 && usernameField) {
    const autocomplete = lowerAttr(usernameField, "autocomplete") ?? "";
    const singleFieldOfForm = inputs.length === 1 && findForm(usernameField) !== null;
    if (
      singleFieldOfForm ||
      autocomplete.includes("username") ||
      autocomplete.includes("email")
    ) {
      combinations.push({
        username: usernameField,
        password: null,
        passwordInputs: [],
        totp: null,
        form: findForm(usernameField),
      });
    }
  }

  return combinations;
}

/** Combination that owns `field` for any of the given roles. */
export function findCombination(
  combinations: FieldCombination[],
  field: HTMLInputElement,
  role?: "username" | "password" | "totp",
): FieldCombination | undefined {
  for (const combination of combinations) {
    if (role === "username" && combination.username === field) {
      return combination;
    }
    if (role === "password" && (combination.password === field || combination.passwordInputs.includes(field))) {
      return combination;
    }
    if (role === "totp" && combination.totp === field) {
      return combination;
    }
    if (
      role === undefined &&
      (combination.username === field ||
        combination.password === field ||
        combination.passwordInputs.includes(field) ||
        combination.totp === field)
    ) {
      return combination;
    }
  }
  return undefined;
}

/** `true` for a combination that should render a login icon and be fillable. */
export function isLoginCombination(combination: FieldCombination): boolean {
  if (combination.totp) {
    return false;
  }
  if (!combination.username && combination.password) {
    const form = combination.form;
    if (form && form.querySelectorAll('input[type="password"]').length > 1) {
      // Password-change form: current/new/repeat fields are not a login.
      return false;
    }
  }
  return combination.username !== null || combination.password !== null;
}

/**
 * New password from a multi-password form (current, new, repeat).
 * Ported verbatim from upstream `kpxcForm.getNewPassword`.
 */
export function getNewPassword(passwordInputs: Array<HTMLInputElement> = []): string {
  if (passwordInputs.length < 2) {
    return "";
  }
  if (passwordInputs.length === 2 && passwordInputs[0] !== passwordInputs[1]) {
    return passwordInputs[1].value;
  }

  const current = passwordInputs[passwordInputs.length - 3]?.value;
  const newPassword = passwordInputs[passwordInputs.length - 2]?.value;
  const repeatNew = passwordInputs[passwordInputs.length - 1]?.value;

  if (
    (newPassword === repeatNew && current !== newPassword && current !== repeatNew) ||
    (current === newPassword && repeatNew !== newPassword && repeatNew !== current)
  ) {
    return newPassword;
  }

  return "";
}

/** Password inputs belonging to one form, in DOM order. */
export function passwordInputsForForm(form: HTMLFormElement): HTMLInputElement[] {
  return Array.from(form.querySelectorAll('input[type="password"]'));
}

/**
 * True for a field that accepts a *new* password: it opts in with
 * `autocomplete=new-password`, its form has more than one password input
 * (current/new/repeat), or a sibling password input marks the new-password
 * role. Used for the inline "Generate password" action.
 */
export function isNewPasswordField(
  field: HTMLInputElement,
  combination?: FieldCombination,
): boolean {
  const autocomplete = (
    field.getAttribute("autocomplete") ?? ""
  ).toLowerCase();
  if (autocomplete === "new-password") {
    return true;
  }
  const form = combination?.form ?? findForm(field);
  if (!form) {
    return false;
  }
  const passwords = passwordInputsForForm(form);
  if (passwords.length >= 2) {
    return true;
  }
  return passwords.some(
    (input) =>
      (input.getAttribute("autocomplete") ?? "").toLowerCase() === "new-password",
  );
}
