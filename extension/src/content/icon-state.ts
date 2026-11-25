/**
 * Field-icon state resolution (WP6b).
 *
 * Kept pure so the state matrix is unit-testable without a page: the icon
 * module only renders whatever this returns, and `index.ts` feeds it the
 * connection status and whether matching entries exist.
 *
 *   app down / icons hidden  -> "hidden"
 *   locked / not associated  -> "locked"   (lock badge)
 *   unlocked + matches       -> "matches"  (accent glyph)
 *   unlocked + no matches    -> "empty"    (muted glyph)
 */

export type IconState = "matches" | "empty" | "locked" | "hidden";

export interface IconStateInput {
  /** False when the user disabled icons or the site exception hides them. */
  visible: boolean;
  /** Host-level `appRunning`. */
  appRunning: boolean;
  /** Database locked (or the app is down, which the snapshot also reports). */
  locked: boolean;
  databaseOpen: boolean;
  associated: boolean;
  /** True when at least one matching login (or TOTP) entry is known. */
  hasMatches: boolean;
}

export function iconStateFor(input: IconStateInput): IconState {
  if (!input.visible || !input.appRunning) {
    return "hidden";
  }
  if (input.locked || !input.databaseOpen || !input.associated) {
    return "locked";
  }
  return input.hasMatches ? "matches" : "empty";
}
