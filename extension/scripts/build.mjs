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

await mkdir(resolve(dist, "background"), { recursive: true });
await cp(resolve(root, "src/manifest.json"), resolve(dist, "manifest.json"));

// TODO(WP4): copy content scripts, CSS and icons into dist/.
// TODO(WP6): copy popup/ and options/ HTML, CSS and assets into dist/.
