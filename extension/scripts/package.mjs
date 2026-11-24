/**
 * Package both browser builds (WP9).
 *
 *   npm run package
 *
 * Produces:
 *   artifacts/friendlypass-chrome-<version>.zip
 *   artifacts/friendlypass-firefox-<version>.zip
 *
 * The Firefox build must pass `web-ext lint`; packaging fails otherwise. The
 * zips contain exactly the unpacked build (manifest at the archive root), which
 * is what Chrome's "Load unpacked"/enterprise tooling and Firefox's
 * about:debugging / AMO self-distribution expect.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const artifacts = path.join(root, "artifacts");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: "inherit",
    ...options,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited ${result.status}`);
  }
}

function version() {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(root, "src/manifest.json"), "utf8"),
  );
  if (typeof manifest.version !== "string" || manifest.version.length === 0) {
    throw new Error("src/manifest.json has no version");
  }
  return manifest.version;
}

function zip(distName, fileName) {
  const dist = path.join(root, distName);
  const archive = path.join(artifacts, fileName);
  fs.rmSync(archive, { force: true });
  // -X strips extra file attributes so repeated runs are reproducible enough to
  // diff; the archive root must be the manifest, so run from inside dist.
  run("zip", ["-X", "-r", "-q", archive, "."], { cwd: dist });
  return archive;
}

const packageVersion = version();

run(process.execPath, ["scripts/build.mjs", "chrome"]);
run(process.execPath, ["scripts/build.mjs", "firefox"]);

const webExt = path.join(root, "node_modules", ".bin", "web-ext");
if (!fs.existsSync(webExt)) {
  throw new Error("web-ext is missing; run `npm install` in extension/");
}
run(webExt, [
  "lint",
  "--source-dir",
  path.join(root, "dist-firefox"),
  "--ignore-files",
  "**/*.map",
  "--output",
  "text",
]);

fs.mkdirSync(artifacts, { recursive: true });
const chromeZip = zip("dist", `friendlypass-chrome-${packageVersion}.zip`);
const firefoxZip = zip("dist-firefox", `friendlypass-firefox-${packageVersion}.zip`);

for (const archive of [chromeZip, firefoxZip]) {
  const { size } = fs.statSync(archive);
  process.stderr.write(`[package] ${path.relative(root, archive)} (${size} bytes)\n`);
}
