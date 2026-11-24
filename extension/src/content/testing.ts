/**
 * Test-only API for the field-detection core (WP4).
 *
 * `scripts/build.mjs` bundles this into `dist/content/testing.js`. Playwright
 * content tests load it into a plain page with `page.addScriptTag()`; it never
 * runs as a content script and never touches `chrome.*`.
 *
 * The production content script imports the same modules, so these tests cover
 * the real detection logic rather than a copy.
 */

import {
  buildCombinations,
  collectInputs,
  findCombination,
  getInputs,
  getNewPassword,
  isLoginCombination,
  isSearchField,
  isSearchForm,
} from "./fields";
import { isTOTPField } from "./totp-field";
import { isElementVisible } from "./ui";

const api = {
  buildCombinations,
  collectInputs,
  findCombination,
  getInputs,
  getNewPassword,
  isLoginCombination,
  isSearchField,
  isSearchForm,
  isTOTPField,
  isVisible: isElementVisible,
};

(globalThis as unknown as Record<string, unknown>).__friendlypassContentTest = api;
