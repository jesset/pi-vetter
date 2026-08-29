import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "unit",
          include: ["test/*.test.ts"],
        },
      },
      {
        test: {
          name: "e2e",
          include: ["test/e2e/**/*.test.ts"],
          testTimeout: 30_000,
          // env overrides are process-global: serialize e2e in a single fork
          pool: "forks",
          singleFork: true,
        },
      },
      {
        test: {
          // real network; skipped unless LIVE_E2E=1 (nightly CI / opt-in)
          name: "live",
          include: ["test/live/**/*.test.ts"],
          testTimeout: 120_000,
        },
      },
    ],
  },
});
