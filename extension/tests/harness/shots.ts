/**
 * Screenshot output directories for the browser e2e specs.
 *
 * Defaults to `extension/test-results/shots` (git-ignored) so screenshots are
 * written inside the checkout and CI can create them. Set `FP_SHOTS_DIR` to
 * redirect every screenshot to another root.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
/** extension/tests/harness -> extension/tests -> extension */
const DEFAULT_ROOT = path.resolve(here, "../../test-results/shots");

/** Directory for one screenshot group, e.g. `shotsDir("wp6a-popup")`. */
export function shotsDir(sub: string): string {
  const root = process.env.FP_SHOTS_DIR ?? DEFAULT_ROOT;
  return path.join(root, sub);
}
