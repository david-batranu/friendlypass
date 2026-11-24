/** Credential dropdown (WP4, ported from `content/credential-autocomplete.js`). */

import type { CredentialEntry } from "../common/types";
import { AutocompleteMenu } from "./autocomplete";

export class CredentialAutocomplete {
  private readonly menu = new AutocompleteMenu();

  isOpenFor(field: HTMLInputElement): boolean {
    return this.menu.isOpenFor(field);
  }

  close(): void {
    this.menu.close();
  }

  show(
    field: HTMLInputElement,
    entries: CredentialEntry[],
    onPick: (entry: CredentialEntry) => void,
  ): void {
    this.menu.open(
      field,
      entries.map((entry) => ({
        uuid: entry.uuid,
        title: entry.name || entry.login || "friendlypass entry",
        value: entry.login || "(no username)",
        group: entry.group,
      })),
      ({ item }) => {
        const entry = entries.find((candidate) => candidate.uuid === item.uuid);
        if (entry) {
          onPick(entry);
        }
      },
    );
  }
}
