/** TOTP dropdown (WP4, ported from `content/totp-autocomplete.js`). */

import type { CredentialEntry } from "../common/types";
import { AutocompleteMenu } from "./autocomplete";
import { entryHasTotp } from "./totp-field";

export class TOTPAutocomplete {
  private readonly menu = new AutocompleteMenu();

  isOpenFor(field: HTMLInputElement): boolean {
    return this.menu.isOpenFor(field);
  }

  close(): void {
    this.menu.close();
  }

  /** Show only entries that actually carry a TOTP secret. */
  show(
    field: HTMLInputElement,
    entries: CredentialEntry[],
    onPick: (entry: CredentialEntry) => void,
  ): void {
    const withTotp = entries.filter((entry) => entryHasTotp(entry));
    this.menu.open(
      field,
      withTotp.map((entry) => ({
        uuid: entry.uuid,
        title: entry.name || entry.login || "friendlypass entry",
        value: entry.login || "(no username)",
        group: entry.group,
      })),
      ({ item }) => {
        const entry = withTotp.find((candidate) => candidate.uuid === item.uuid);
        if (entry) {
          onPick(entry);
        }
      },
    );
  }
}
