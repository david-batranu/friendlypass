/**
 * friendlypass extension service worker (WP2).
 *
 * Entry point of the MV3 background. It must:
 *   1. register every listener synchronously (no top-level `await`), so a
 *      message that wakes the worker can never race the initialiser;
 *   2. start the idempotent native connection at top level;
 *   3. install the HTTP-auth listener before the first navigation.
 *
 * Build: `npm run build` bundles this file to `dist/background/sw.js`.
 */

import { NATIVE_HOST_NAME, SUPPORTED_PROTOCOL_VERSION } from "../common/types";

export function bootstrap(): void {
  // TODO(WP2): start the native transport, register runtime/alarms/tabs
  // listeners synchronously, and install the lifecycle hooks.
  // TODO(WP5): call installHttpAuthListener() here, unconditionally.
  console.info(
    `[friendlypass] service worker loaded (protocol v${SUPPORTED_PROTOCOL_VERSION}, host ${NATIVE_HOST_NAME})`,
  );
}

bootstrap();
