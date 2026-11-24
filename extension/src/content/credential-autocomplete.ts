/**
 * Credential → inline-menu entries (WP6b).
 *
 * The menu itself lives in `autocomplete.ts`; this module holds the mapping so
 * login and TOTP views cannot drift apart. It never exposes passwords.
 */

import type { CredentialEntry } from "../common/types";
import type { MenuEntry } from "./autocomplete";
import { entryHasTotp } from "./totp-field";

export function loginMenuEntries(entries: CredentialEntry[]): MenuEntry[] {
  return entries.map((entry) => ({
    uuid: entry.uuid,
    title: entry.name || entry.login || "friendlypass entry",
    username: entry.login || "",
    ...(entry.group ? { group: entry.group } : {}),
    ...(entryHasTotp(entry) ? { totp: true } : {}),
  }));
}
