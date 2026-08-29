import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { runVetInstall } from "../../src/commands/vet-install.ts";
import type { FixturePackage } from "./helpers/fixtures.ts";
import { withHarness } from "./helpers/harness.ts";

const quietPkg: FixturePackage = {
  name: "quiet-pkg",
  versions: [
    { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = () => 1;\n" }] },
    { version: "1.1.0", files: [{ path: "index.js", content: "module.exports = () => 2;\n" }] },
  ],
};

/** Non-TUI context: the selection flow goes through group confirm dialogs. */
const fakeCtx = (confirm: () => boolean | Promise<boolean>): ExtensionCommandContext =>
  ({
    mode: "cli",
    ui: {
      custom: async () => ({ selected: [], cancelled: true }),
      confirm: async () => confirm(),
      notify: () => undefined,
    },
  }) as unknown as ExtensionCommandContext;

describe("e2e: /vet-install gated install flow", () => {
  it("installs the exact vetted version via a pinned spec, then restores the unpinned entry", async () => {
    await withHarness(
      {
        fixtures: [quietPkg],
        installed: [
          {
            source: "npm:quiet-pkg",
            name: "quiet-pkg",
            version: "1.0.0",
            pinned: false,
            scope: "user",
          },
        ],
      },
      async ({ deps, registry }) => {
        void registry;
        const exec = vi.fn(async () => ({ stdout: "", stderr: "", code: 0 }));
        const unpin = vi.fn();
        const result = await runVetInstall(
          { ...deps, exec, pinOnInstall: false, unpin },
          "npm:quiet-pkg",
          fakeCtx(async () => true),
        );
        expect(exec).toHaveBeenCalledExactlyOnceWith("pi", ["install", "npm:quiet-pkg@1.1.0"]);
        expect(unpin).toHaveBeenCalledWith("quiet-pkg", "1.1.0");
        expect(result.content).toContain("✓ quiet-pkg@1.1.0 installed");
        expect(result.content).toContain("to pin: pi install npm:quiet-pkg@1.1.0");
      },
    );
  });

  it("refuses to install when registry integrity rotated after vetting (TOCTOU)", async () => {
    await withHarness(
      {
        fixtures: [quietPkg],
        installed: [
          {
            source: "npm:quiet-pkg",
            name: "quiet-pkg",
            version: "1.0.0",
            pinned: false,
            scope: "user",
          },
        ],
      },
      async ({ deps, registry }) => {
        const exec = vi.fn(async () => ({ stdout: "", stderr: "", code: 0 }));
        const unpin = vi.fn();
        const result = await runVetInstall(
          { ...deps, exec, pinOnInstall: false, unpin },
          "npm:quiet-pkg",
          // vetting happened against the original integrity; by the time the
          // user reads the report and approves, the registry serves a rotated
          // value — the install re-check must catch it
          fakeCtx(() => {
            registry.setIntegrity("quiet-pkg", "1.1.0", "sha512-rotated-after-vetting");
            return true;
          }),
        );

        expect(exec).not.toHaveBeenCalled();
        expect(unpin).not.toHaveBeenCalled();
        expect(result.content).toContain("⚠ quiet-pkg@1.1.0 skipped");
        expect(result.content).toContain("registry integrity changed after vetting");
        expect(result.content).toContain("re-run /vet");
      },
    );
  });

  it("installs nothing when the user cancels the selection", async () => {
    await withHarness(
      {
        fixtures: [quietPkg],
        installed: [
          {
            source: "npm:quiet-pkg",
            name: "quiet-pkg",
            version: "1.0.0",
            pinned: false,
            scope: "user",
          },
        ],
      },
      async ({ deps }) => {
        const exec = vi.fn(async () => ({ stdout: "", stderr: "", code: 0 }));
        const result = await runVetInstall(
          { ...deps, exec, pinOnInstall: false, unpin: () => undefined },
          "npm:quiet-pkg",
          fakeCtx(async () => false),
        );

        expect(exec).not.toHaveBeenCalled();
        expect(result.content).toContain("Nothing selected for installation.");
      },
    );
  });
});
