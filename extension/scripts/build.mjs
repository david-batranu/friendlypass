/**
 * Build the unpacked MV3 extension into `dist/`.
 *
 * WP2/WP4/WP5/WP6 may add entry points and asset copies here. Keep this file
 * the single build definition so `npm run build` stays the one command CI uses.
 */
import { build } from "esbuild";
import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dist = resolve(root, "dist");

await rm(dist, { recursive: true, force: true });

await build({
  absWorkingDir: root,
  entryPoints: ["src/background/sw.ts"],
  outfile: "dist/background/sw.js",
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome124",
  sourcemap: true,
  logLevel: "info",
});

// ---------------------------------------------------------------------------
// WP4: content script (IIFE — MV3 content scripts are classic scripts)
// WP6b's icon/menu/card/toast live in the same bundle (open shadow roots).
// ---------------------------------------------------------------------------
await build({
  absWorkingDir: root,
  entryPoints: ["src/content/index.ts"],
  outfile: "dist/content/content.js",
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "chrome124",
  sourcemap: true,
  logLevel: "info",
});

// Field-detection API for Playwright tests. Pure DOM code, no chrome.* access.
// WP6b adds the settings/icon/position/menu helper API to the same bundle.
await build({
  absWorkingDir: root,
  entryPoints: ["src/content/testing.ts"],
  outfile: "dist/content/testing.js",
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "chrome124",
  sourcemap: false,
  logLevel: "info",
});

await mkdir(resolve(dist, "background"), { recursive: true });
await cp(resolve(root, "src/manifest.json"), resolve(dist, "manifest.json"));

// --- WP6a popup + options (owned by WP6a) ----------------------------------
await build({
  absWorkingDir: root,
  entryPoints: ["src/popup/popup.ts"],
  outfile: "dist/popup/popup.js",
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome124",
  sourcemap: true,
  logLevel: "info",
});
await build({
  absWorkingDir: root,
  entryPoints: ["src/options/options.ts"],
  outfile: "dist/options/options.js",
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome124",
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
// --- end WP6a block --------------------------------------------------------

// --- WP5 HTTP-auth picker (appended entry point; WP5 owns src/auth/**) -----
await build({
  absWorkingDir: root,
  entryPoints: ["src/auth/picker.ts"],
  outfile: "dist/auth/picker.js",
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome124",
  sourcemap: true,
  logLevel: "info",
});
await mkdir(resolve(dist, "auth"), { recursive: true });
await cp(resolve(root, "src/auth/picker.html"), resolve(dist, "auth/picker.html"));
await cp(resolve(root, "src/auth/picker.css"), resolve(dist, "auth/picker.css"));
// --- end WP5 block ---------------------------------------------------------
