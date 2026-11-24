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

// TODO(WP6): copy popup/ and options/ HTML, CSS and assets into dist/.
