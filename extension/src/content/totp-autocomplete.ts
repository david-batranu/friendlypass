/**
 * TOTP-view menu entries (WP6b).
 *
 * Only entries that actually carry a one-time secret are listed, matching the
 * WP4 TOTP dropdown behaviour.
 */

import type { CredentialEntry } from "../common/types";
import type { MenuEntry } from "./autocomplete";
import { entryHasTotp } from "./totp-field";

export function totpMenuEntries(entries: CredentialEntry[]): MenuEntry[] {
  return entries.filter((entry) => entryHasTotp(entry)).map((entry) => ({
    uuid: entry.uuid,
    title: entry.name || entry.login || "friendlypass entry",
    username: entry.login || "",
    ...(entry.group ? { group: entry.group } : {}),
    totp: true,
  }));
}
