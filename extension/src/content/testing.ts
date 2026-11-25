/**
 * Test-only API for the field-detection core and WP6b UI helpers.
 *
 * `scripts/build.mjs` bundles this into `dist/content/testing.js`. Playwright
 * content tests load it into a plain page with `page.addScriptTag()`; it never
 * runs as a content script and never touches `chrome.*`.
 *
 * The production content script imports the same modules, so these tests cover
 * the real logic rather than a copy.
 */

import { filterMenuEntries, monogramFor } from "./autocomplete";
import { BANNER_TIMEOUT_MS } from "./banner";
import {
  buildCombinations,
  collectInputs,
  findCombination,
  getInputs,
  getNewPassword,
  isLoginCombination,
  isNewPasswordField,
  isSearchField,
  isSearchForm,
} from "./fields";
import { iconStateFor } from "./icon-state";
import { computeMenuPosition } from "./position";
import {
  DEFAULT_CONTENT_SETTINGS,
  normaliseSettings,
  sitePolicyFor,
} from "./settings";
import { isTOTPField } from "./totp-field";
import { isElementVisible } from "./ui";

const api = {
  buildCombinations,
  collectInputs,
  findCombination,
  getInputs,
  getNewPassword,
  isLoginCombination,
  isNewPasswordField,
  isSearchField,
  isSearchForm,
  isTOTPField,
  isVisible: isElementVisible,
  // WP6b
  bannerTimeoutMs: BANNER_TIMEOUT_MS,
  defaultSettings: DEFAULT_CONTENT_SETTINGS,
  filterMenuEntries,
  iconStateFor,
  monogramFor,
  normaliseSettings,
  sitePolicyFor,
  computeMenuPosition,
};

(globalThis as unknown as Record<string, unknown>).__friendlypassContentTest = api;
