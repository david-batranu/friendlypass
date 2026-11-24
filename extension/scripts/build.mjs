/**
 * Build the unpacked MV3 extension.
 *
 *   node scripts/build.mjs            # Chrome/Chromium → dist/
 *   node scripts/build.mjs firefox    # Firefox MV3      → dist-firefox/
 *   node scripts/build.mjs all        # both
 *
 * One source tree, one bundling definition. The Firefox target differs only in
 * the output directory, the manifest variant (`background.scripts` instead of
 * `service_worker`, `webRequestBlocking` instead of `webRequestAuthProvider`,
 * a Gecko id + `strict_min_version`, no Chrome `key`) and the fact that the
 * background is bundled as a classic IIFE: Firefox MV3 event pages load
 * `background.scripts`, and a classic script removes any dependency on
 * `background.type: "module"` support.
 */
import { build } from "esbuild";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** @typedef {"chrome" | "firefox"} Target */

/** @type {Record<Target, {dist: string, target: string, backgroundFormat: "esm" | "iife"}>} */
const TARGETS = {
  chrome: {
    dist: resolve(root, "dist"),
    target: "chrome124",
    backgroundFormat: "esm",
  },
  firefox: {
    dist: resolve(root, "dist-firefox"),
    target: "firefox128",
    backgroundFormat: "iife",
  },
};

/** Firefox's MV3 manifest, derived from the shipping Chrome manifest. */
export function firefoxManifest(base) {
  const manifest = JSON.parse(JSON.stringify(base));
  // Chrome-specific fields that web-ext lint rejects or that Firefox ignores.
  delete manifest.key;
  delete manifest.minimum_chrome_version;

  // Firefox MV3 uses a non-persistent event page, loaded from
  // `background.scripts`. The bundle is a classic IIFE (see build() below).
  manifest.background = { scripts: ["background/sw.js"] };

  // Chrome needs `webRequestAuthProvider` for asyncBlocking; Firefox uses
  // blocking `webRequest` and explicitly supports `webRequestBlocking` in MV3.
  manifest.permissions = manifest.permissions.map((permission) =>
    permission === "webRequestAuthProvider" ? "webRequestBlocking" : permission,
  );
  manifest.permissions = [...new Set(manifest.permissions)];

  manifest.browser_specific_settings = {
    ...(manifest.browser_specific_settings ?? {}),
    gecko: {
      ...(manifest.browser_specific_settings?.gecko ?? {}),
      id: "friendlypass@friendlypass.org",
      strict_min_version: "128.0",
    },
  };
  return manifest;
}

/** @param {Target} target */
async function buildTarget(target) {
  const config = TARGETS[target];
  const dist = config.dist;
  const chrome = target === "chrome";

  await rm(dist, { recursive: true, force: true });

  await build({
    absWorkingDir: root,
    entryPoints: ["src/background/sw.ts"],
    outfile: chrome ? "dist/background/sw.js" : "dist-firefox/background/sw.js",
    bundle: true,
    format: config.backgroundFormat,
    platform: "browser",
    target: config.target,
    sourcemap: true,
    logLevel: "info",
  });

  // -------------------------------------------------------------------------
  // WP4: content script (IIFE — MV3 content scripts are classic scripts)
  // WP6b's icon/menu/card/toast live in the same bundle (open shadow roots).
  // -------------------------------------------------------------------------
  await build({
    absWorkingDir: root,
    entryPoints: ["src/content/index.ts"],
    outfile: chrome ? "dist/content/content.js" : "dist-firefox/content/content.js",
    bundle: true,
    format: "iife",
    platform: "browser",
    target: config.target,
    sourcemap: true,
    logLevel: "info",
  });

  // Field-detection API for Playwright tests. Pure DOM code, no chrome.* access.
  // WP6b adds the settings/icon/position/menu helper API to the same bundle.
  await build({
    absWorkingDir: root,
    entryPoints: ["src/content/testing.ts"],
    outfile: chrome ? "dist/content/testing.js" : "dist-firefox/content/testing.js",
    bundle: true,
    format: "iife",
    platform: "browser",
    target: config.target,
    sourcemap: false,
    logLevel: "info",
  });

  await mkdir(resolve(dist, "background"), { recursive: true });
  const sourceManifest = JSON.parse(
    await readFile(resolve(root, "src/manifest.json"), "utf8"),
  );
  const manifest = chrome ? sourceManifest : firefoxManifest(sourceManifest);
  await writeFile(
    resolve(dist, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );

  // --- WP6a popup + options (owned by WP6a) --------------------------------
  await build({
    absWorkingDir: root,
    entryPoints: ["src/popup/popup.ts"],
    outfile: chrome ? "dist/popup/popup.js" : "dist-firefox/popup/popup.js",
    bundle: true,
    format: "esm",
    platform: "browser",
    target: config.target,
    sourcemap: true,
    logLevel: "info",
  });
  await build({
    absWorkingDir: root,
    entryPoints: ["src/options/options.ts"],
    outfile: chrome ? "dist/options/options.js" : "dist-firefox/options/options.js",
    bundle: true,
    format: "esm",
    platform: "browser",
    target: config.target,
    sourcemap: true,
    logLevel: "info",
  });
  await mkdir(resolve(dist, "popup"), { recursive: true });
  await mkdir(resolve(dist, "options"), { recursive: true });
  await mkdir(resolve(dist, "common"), { recursive: true });
  await cp(resolve(root, "src/popup/popup.html"), resolve(dist, "popup/popup.html"));
  await cp(resolve(root, "src/popup/popup.css"), resolve(dist, "popup/popup.css"));
  await cp(resolve(root, "src/options/options.html"), resolve(dist, "options/options.html"));
  await cp(resolve(root, "src/options/options.css"), resolve(dist, "options/options.css"));
  await cp(resolve(root, "src/common/theme.css"), resolve(dist, "common/theme.css"));
  // --- end WP6a block ------------------------------------------------------

  // --- WP5 HTTP-auth picker (appended entry point; WP5 owns src/auth/**) ----
  await build({
    absWorkingDir: root,
    entryPoints: ["src/auth/picker.ts"],
    outfile: chrome ? "dist/auth/picker.js" : "dist-firefox/auth/picker.js",
    bundle: true,
    format: "esm",
    platform: "browser",
    target: config.target,
    sourcemap: true,
    logLevel: "info",
  });
  await mkdir(resolve(dist, "auth"), { recursive: true });
  await cp(resolve(root, "src/auth/picker.html"), resolve(dist, "auth/picker.html"));
  await cp(resolve(root, "src/auth/picker.css"), resolve(dist, "auth/picker.css"));
  // --- end WP5 block -------------------------------------------------------
}

const requested = process.argv[2] ?? "chrome";
const targets = requested === "all" ? ["chrome", "firefox"] : [requested];
for (const target of targets) {
  if (!(target in TARGETS)) {
    console.error(`unknown build target "${target}" (expected chrome|firefox|all)`);
    process.exit(2);
  }
  await buildTarget(/** @type {Target} */ (target));
}
