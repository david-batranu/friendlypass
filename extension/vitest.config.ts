import { defineConfig } from "vitest/config";

/**
 * Vitest owns the unit suite only.
 *
 * Playwright specs (including `tests/harness/smoke.spec.ts` and
 * `tests/e2e/*.spec.ts`) import `@playwright/test` fixtures and must never be
 * collected by Vitest; `npx playwright test` is the single runner for them.
 */
export default defineConfig({
  test: {
    include: ["tests/unit/**/*.test.ts"],
    environment: "node",
    reporters: ["default"],
  },
});
