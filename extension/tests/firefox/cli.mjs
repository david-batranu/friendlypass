/**
 * `friendlypass` CLI helpers for the Firefox suite (WP9).
 *
 * Databases are created and verified through the real CLI, exactly as the
 * Chromium save tests do: `set-login` is only proven when another process can
 * reopen the KDBX and read the saved entry.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";

import {
  FRIENDLYPASS_CLI,
  NATIVE_HOST_BINARY,
  REPO_ROOT,
  TEST_DB_PASSWORD,
  TEST_SERVER_BINARY,
} from "./config.mjs";

function build(target, args) {
  if (fs.existsSync(target)) return;
  const result = spawnSync("cargo", ["build", ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    timeout: 600_000,
  });
  if (result.status !== 0) {
    throw new Error(
      `failed to build ${args.join(" ")}:\n${result.stderr ?? result.stdout ?? ""}`,
    );
  }
}

/** Build the CLI, host and protocol server once per run when missing. */
export function ensureBinaries() {
  build(FRIENDLYPASS_CLI, ["-q", "-p", "friendlypass"]);
  build(NATIVE_HOST_BINARY, ["-q", "-p", "friendlypass-browser-host"]);
  build(TEST_SERVER_BINARY, ["-q", "-p", "friendlypass-browser", "--example", "test_server"]);
}

function runCli(args, input) {
  const result = spawnSync(FRIENDLYPASS_CLI, args, {
    encoding: "utf8",
    input,
    timeout: 120_000,
  });
  if (result.status !== 0) {
    throw new Error(`friendlypass ${args.join(" ")} failed:\n${result.stderr ?? ""}`);
  }
}

/**
 * @param {string} dbPath
 * @param {Array<{title: string, username: string, password: string, url: string}>} entries
 */
export function createDatabase(dbPath, entries) {
  runCli(
    ["db-create", "-p", dbPath],
    `${TEST_DB_PASSWORD}\n${TEST_DB_PASSWORD}\n`,
  );
  for (const entry of entries) {
    runCli(
      [
        "add",
        "-p",
        dbPath,
        entry.title,
        "-u",
        entry.username,
        "-U",
        entry.url,
      ],
      `${TEST_DB_PASSWORD}\n${entry.password}\n`,
    );
  }
}

/** Reopen the KDBX as another process would; null while the entry is absent. */
export function readEntryViaCli(dbPath, title) {
  const result = spawnSync(FRIENDLYPASS_CLI, ["show", dbPath, title], {
    encoding: "utf8",
    input: `${TEST_DB_PASSWORD}\n`,
    timeout: 30_000,
  });
  if (result.status !== 0) {
    return null;
  }
  /** @type {Record<string, string>} */
  const entry = {};
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = /^(Title|UserName|Password|URL):\s*(.*)$/.exec(line);
    if (match) entry[match[1]] = match[2];
  }
  return Object.keys(entry).length > 0 ? entry : null;
}
