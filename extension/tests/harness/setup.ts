/**
 * Temp-profile / native-messaging plumbing for the e2e harness (WP8).
 *
 * Security: the harness NEVER touches the user's real browser profile or
 * `$HOME`. Every run gets a fresh temp root containing its own `HOME`,
 * Chromium profile, app socket, logs and native-messaging manifests. Chromium
 * is launched with `HOME` (and on Linux `XDG_CONFIG_HOME`) pointed at that temp
 * root, so a mistake can at worst pollute a directory removed at teardown.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { STUB_HOST_PATH } from "./app-mock";

export const NATIVE_HOST_NAME = "org.friendlypass.browser";

export type HostMode = "real" | "stub";

export interface HarnessPaths {
  root: string;
  home: string;
  profile: string;
  appSocket: string;
  appLog: string;
  hostLog: string;
  hostPid: string;
  wrapper: string;
  manifests: string[];
  stubHostPath: string;
  hostBinary: string | null;
  mode: HostMode;
}

/** Path to the WP1 host binary, if the workspace has built it. */
export function defaultHostBinary(repoRoot: string): string {
  return path.join(repoRoot, "target/debug/friendlypass-browser-host");
}

/**
 * Chromium derives an unpacked extension's ID from the absolute path: SHA-256
 * of the path, first 16 bytes, each hex nibble mapped 0→a … f→p.
 */
export function extensionIdForPath(extensionPath: string): string {
  const digest = createHash("sha256")
    .update(path.resolve(extensionPath), "utf8")
    .digest("hex")
    .slice(0, 32);
  return [...digest]
    .map((nibble) => String.fromCharCode(97 + Number.parseInt(nibble, 16)))
    .join("");
}

/** IDs to allow in the manifest: the literal path and its realpath. */
export function extensionIdCandidates(extensionPath: string): string[] {
  const candidates = new Set<string>();
  // A pinned manifest `key` fixes the id regardless of the load path.
  const keyed = extensionIdFromManifestKey(extensionPath);
  if (keyed) candidates.add(keyed);
  candidates.add(extensionIdForPath(extensionPath));
  try {
    candidates.add(extensionIdForPath(fs.realpathSync(extensionPath)));
  } catch {
    /* path may not exist yet; only the literal candidate is used */
  }
  return [...candidates];
}

/**
 * Chrome derives the id from a manifest `key` as SHA-256 of the Base64-decoded
 * DER SubjectPublicKeyInfo, first 16 bytes, each nibble mapped 0→a … f→p.
 * Returns null when the manifest has no key (path-derived id applies).
 */
export function extensionIdFromManifestKey(
  extensionPath: string,
): string | null {
  try {
    const manifest = JSON.parse(
      fs.readFileSync(path.join(extensionPath, "manifest.json"), "utf8"),
    ) as { key?: unknown };
    if (typeof manifest.key !== "string") return null;
    const digest = createHash("sha256")
      .update(Buffer.from(manifest.key, "base64"))
      .digest("hex")
      .slice(0, 32);
    return [...digest]
      .map((nibble) => String.fromCharCode(97 + Number.parseInt(nibble, 16)))
      .join("");
  } catch {
    return null;
  }
}

/**
 * Directories Chromium checks for native-messaging host manifests. We write to
 * every plausible product name because Playwright's bundled Chromium reports
 * itself as either "Chromium" or "Chrome for Testing" depending on version.
 */
export function nativeHostManifestDirs(
  home: string,
  platform: NodeJS.Platform = process.platform,
  xdgConfigHome = process.env.XDG_CONFIG_HOME,
  profile?: string,
): string[] {
  const dirs: string[] = [];
  // Chrome (including Chrome for Testing) also looks in the user-data-dir when
  // it is overridden with --user-data-dir; Playwright always overrides it.
  if (profile) dirs.push(path.join(profile, "NativeMessagingHosts"));
  if (platform === "darwin") {
    dirs.push(
      path.join(home, "Library/Application Support/Chromium/NativeMessagingHosts"),
      path.join(home, "Library/Application Support/Google/Chrome/NativeMessagingHosts"),
      path.join(
        home,
        "Library/Application Support/Google/Chrome for Testing/NativeMessagingHosts",
      ),
    );
  } else if (platform === "linux") {
    const config = xdgConfigHome ?? path.join(home, ".config");
    dirs.push(
      path.join(config, "chromium/NativeMessagingHosts"),
      path.join(config, "google-chrome/NativeMessagingHosts"),
      path.join(config, "google-chrome-for-testing/NativeMessagingHosts"),
    );
  }
  return [...new Set(dirs)];
}

/** @returns temp root, preferring the OS temp dir but keeping socket paths short */
function createTempRoot(): string {
  const base = process.env.FP_E2E_TMPDIR || os.tmpdir();
  let root = fs.mkdtempSync(path.join(base, "friendlypass-e2e-"));
  // AF_UNIX paths are limited to ~104 bytes on macOS. The socket lives at
  // `<root>/app.sock`, so fall back to a short /tmp name if the OS temp dir is
  // unusually deep.
  if (path.join(root, "app.sock").length > 100) {
    fs.rmSync(root, { recursive: true, force: true });
    root = fs.mkdtempSync("/tmp/fp8-");
  }
  return root;
}

export interface CreateEnvironmentOptions {
  mode: HostMode;
  hostBinary?: string | null;
  hostVersion?: string;
  extensionPath: string;
}

export function createHarnessEnvironment(
  options: CreateEnvironmentOptions,
): HarnessPaths {
  const root = createTempRoot();
  const home = path.join(root, "home");
  const profile = path.join(root, "profile");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(profile, { recursive: true });

  const paths: HarnessPaths = {
    root,
    home,
    profile,
    appSocket: path.join(root, "app.sock"),
    appLog: path.join(root, "app-actions.jsonl"),
    hostLog: path.join(root, "host-events.jsonl"),
    hostPid: path.join(root, "host.pid"),
    wrapper: path.join(root, "friendlypass-host.sh"),
    manifests: [],
    stubHostPath: STUB_HOST_PATH,
    hostBinary: options.hostBinary ?? null,
    mode: options.mode,
  };

  writeHostWrapper(paths, options.hostVersion ?? "0.1.0");
  installNativeManifests(
    paths,
    extensionIdCandidates(options.extensionPath),
  );

  fs.writeFileSync(
    path.join(root, "harness-env.json"),
    `${JSON.stringify(
      {
        mode: paths.mode,
        home,
        profile,
        appSocket: paths.appSocket,
        hostBinary: paths.hostBinary,
        node: process.execPath,
        platform: process.platform,
      },
      null,
      2,
    )}\n`,
  );

  return paths;
}

/** @param {string} value */
function shellQuote(value: string): string {
  return `"${value.replace(/(["\\$`])/g, "\\$1")}"`;
}

export function writeHostWrapper(
  paths: HarnessPaths,
  hostVersion: string,
): void {
  const lines = [
    "#!/bin/sh",
    "# Generated by the WP8 e2e harness. Never installed outside the temp HOME.",
    "set -u",
    `echo $$ > ${shellQuote(paths.hostPid)}`,
  ];

  if (paths.mode === "stub") {
    lines.push(
      `exec ${shellQuote(process.execPath)} ${shellQuote(paths.stubHostPath)} \\`,
      `  --app-socket ${shellQuote(paths.appSocket)} \\`,
      `  --log ${shellQuote(paths.hostLog)} \\`,
      `  --pid ${shellQuote(paths.hostPid)} \\`,
      `  --host-version ${shellQuote(hostVersion)}`,
    );
  } else if (paths.hostBinary) {
    lines.push(
      `export FP_APP_SOCKET=${shellQuote(paths.appSocket)}`,
      `export FRIENDLYPASS_BROWSER_SOCKET=${shellQuote(paths.appSocket)}`,
      `export FRIENDLYPASS_APP_SOCKET=${shellQuote(paths.appSocket)}`,
      `export FRIENDLYPASS_SOCKET=${shellQuote(paths.appSocket)}`,
      // Keep the real host's stderr diagnostics in the temp root; Chrome
      // otherwise discards them. Never contains credentials.
      `exec ${shellQuote(paths.hostBinary)} 2>> ${shellQuote(path.join(paths.root, "host-stderr.log"))}`,
    );
  } else {
    throw new Error("real host mode selected but no host binary was provided");
  }

  fs.writeFileSync(paths.wrapper, `${lines.join("\n")}\n`, { mode: 0o755 });
  fs.chmodSync(paths.wrapper, 0o755);
}

/**
 * Write `<name>.json` manifests for every candidate extension ID into every
 * native-messaging directory under the temp HOME.
 */
export function installNativeManifests(
  paths: HarnessPaths,
  extensionIds: string[],
): string[] {
  const manifest = {
    name: NATIVE_HOST_NAME,
    description: "friendlypass e2e harness native messaging host",
    path: paths.wrapper,
    type: "stdio",
    allowed_origins: extensionIds.map((id) => `chrome-extension://${id}/`),
  };

  const written: string[] = [];
  for (const dir of nativeHostManifestDirs(
    paths.home,
    process.platform,
    path.join(paths.home, ".config"),
    paths.profile,
  )) {
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `${NATIVE_HOST_NAME}.json`);
    fs.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, {
      mode: 0o644,
    });
    written.push(file);
  }
  paths.manifests = written;
  return written;
}

export function removeHarnessEnvironment(paths: HarnessPaths): void {
  if (process.env.FP_KEEP_TEMP === "1") {
    process.stderr.write(`[harness] keeping temp dir ${paths.root}\n`);
    return;
  }
  fs.rmSync(paths.root, { recursive: true, force: true });
}

/** Read the PID written by the generated host wrapper, if any. */
export function readHostPid(paths: HarnessPaths): number | null {
  try {
    const value = Number.parseInt(
      fs.readFileSync(paths.hostPid, "utf8").trim(),
      10,
    );
    return Number.isFinite(value) && value > 0 ? value : null;
  } catch {
    return null;
  }
}

/** Parse the harness JSONL logs, tolerating a partially-written final line. */
export function readJsonl(file: string): Array<Record<string, unknown>> {
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return [];
  }
  const entries: Array<Record<string, unknown>> = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      entries.push(JSON.parse(line));
    } catch {
      /* partial last line while the writer is active */
    }
  }
  return entries;
}
