/**
 * Pinned Firefox binary management and launch (WP9).
 *
 * Why Puppeteer + WebDriver BiDi instead of selenium-webdriver/geckodriver:
 * Puppeteer 23+ ships production WebDriver BiDi support for Firefox, including
 * `browser.installExtension()` for temporary add-ons. That removes a separate
 * geckodriver download/version matrix, and the harness needs no CDP-only
 * features: navigation, DOM interaction and screenshots all work over BiDi.
 * Firefox has no `--load-extension` flag, so an extension must be installed at
 * runtime; `installExtension()` is the supported way to do that.
 */

import fs from "node:fs";
import path from "node:path";

import {
  Browser,
  getInstalledBrowsers,
  install,
  detectBrowserPlatform,
} from "@puppeteer/browsers";
import { launch } from "puppeteer-core";

import {
  FIREFOX_CACHE,
  FIREFOX_DIST,
  FIREFOX_VERSION,
} from "./config.mjs";

/** Download the pinned Firefox on first use; reuse the cached build after. */
export async function ensureFirefox() {
  const platform = detectBrowserPlatform();
  if (!platform) {
    throw new Error(`unsupported platform for a Firefox download: ${process.platform}`);
  }
  const cached = await getInstalledBrowsers({ cacheDir: FIREFOX_CACHE });
  const match = cached.find(
    (browser) =>
      browser.browser === Browser.FIREFOX && browser.buildId === FIREFOX_VERSION,
  );
  if (match) {
    return match.executablePath;
  }
  process.stderr.write(
    `[firefox-harness] downloading Firefox ${FIREFOX_VERSION} (${platform}) into ${path.relative(process.cwd(), FIREFOX_CACHE)}...\n`,
  );
  const installed = await install({
    browser: Browser.FIREFOX,
    buildId: FIREFOX_VERSION,
    cacheDir: FIREFOX_CACHE,
    platform,
  });
  return installed.executablePath;
}

/**
 * Firefox preferences for unattended runs: no first-run onboarding, no
 * telemetry, no password-manager prompts, no update checks.
 */
const PREFS = {
  "browser.shell.checkDefaultBrowser": false,
  "browser.startup.page": 0,
  "browser.startup.homepage_override.mstone": "ignore",
  "browser.aboutwelcome.enabled": false,
  "browser.tabs.warnOnClose": false,
  "browser.tabs.warnOnCloseOtherTabs": false,
  "browser.sessionstore.resume_from_crash": false,
  "browser.formfill.enable": false,
  "datareporting.policy.dataSubmissionEnabled": false,
  "datareporting.healthreport.uploadEnabled": false,
  "toolkit.telemetry.enabled": false,
  "toolkit.telemetry.reportingpolicy.firstRun": false,
  "app.update.enabled": false,
  "app.update.auto": false,
  "extensions.update.enabled": false,
  "extensions.autoDisableScopes": 0,
  "network.captive-portal-service.enabled": false,
  "network.connectivity-service.enabled": false,
  // Route extension/content console output to stdout when FP_FIREFOX_DUMPIO=1
  // is used; background diagnostics contain no credentials by design.
  "devtools.console.stdout.chrome": true,
  "devtools.console.stdout.content": true,
  // Friendlypass owns credentials; Firefox's own manager must stay quiet.
  "signon.rememberSignons": false,
  "signon.autofillForms": false,
  "signon.generation.enabled": false,
  "signon.management.page.breach-alerts.enabled": false,
};

/**
 * @param {{ executablePath: string, paths: { home: string, profile: string, root: string } }} options
 */
export async function launchFirefox({ executablePath, paths }) {
  if (!fs.existsSync(FIREFOX_DIST)) {
    throw new Error(
      `Firefox build not found at ${FIREFOX_DIST}; run \`npm run build:firefox\``,
    );
  }

  /** @type {Record<string, string>} */
  const env = {
    ...process.env,
    HOME: paths.home,
    XDG_CONFIG_HOME: path.join(paths.home, ".config"),
    TMPDIR: paths.root,
    // WebDriver BiDi needs this to evaluate scripts in moz-extension pages
    // (the popup window assertion). Test-only; never set for users.
    MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: "1",
  };
  // Foundation ignores $HOME for ~/Library/Application Support (and therefore
  // for the native-messaging manifest); CFFIXED_USER_HOME is the override.
  if (process.platform === "darwin") {
    env.CFFIXED_USER_HOME = paths.home;
  }

  const browser = await launch({
    browser: "firefox",
    executablePath,
    headless: process.env.FP_FIREFOX_HEADED !== "1",
    userDataDir: paths.profile,
    env,
    dumpio: process.env.FP_FIREFOX_DUMPIO === "1",
    timeout: 60_000,
    extraPrefsFirefox: PREFS,
  });

  let extensionId;
  try {
    extensionId = await browser.installExtension(FIREFOX_DIST);
  } catch (error) {
    await browser.close().catch(() => undefined);
    throw error;
  }
  return { browser, extensionId };
}
