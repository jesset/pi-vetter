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
    ],
  },
});
