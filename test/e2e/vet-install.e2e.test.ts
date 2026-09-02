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

/** TUI context: the selection flow goes through the modal checkbox component. */
const fakeTuiCtx = (onCustom: () => void): ExtensionCommandContext =>
  ({
    mode: "tui",
    ui: {
      custom: async () => {
        onCustom();
        return { selected: [], cancelled: true };
      },
      confirm: async () => false,
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
        const exec = vi.fn(async (cmd: string, _args?: string[]) => ({
          stdout:
            cmd === "npm"
              ? `${process.env.PI_VETTER_NPM_REGISTRY ?? "https://registry.npmjs.org/"}\n`
              : "",
          stderr: "",
          code: 0,
        }));
        const unpin = vi.fn();
        const result = await runVetInstall(
          { ...deps, exec, pinOnInstall: false, unpin },
          "npm:quiet-pkg",
          fakeCtx(async () => true),
        );
        expect(exec.mock.calls.filter((c) => c[0] === "pi").map((c) => [c[0], c[1]])).toEqual([
          ["pi", ["install", "npm:quiet-pkg@1.1.0"]],
        ]);
        expect(unpin).toHaveBeenCalledWith("quiet-pkg", "1.1.0");
        expect(result.content).toContain("✓ quiet-pkg@1.1.0 installed");
        expect(result.content).toContain("to pin: pi install npm:quiet-pkg@1.1.0");
      },
    );
  });

  it("verifies installed bytes against the vetted artifact after install (#48)", async () => {
    await withHarness(
      {
        fixtures: [quietPkg],
        installed: [
          {
            source: "npm:quiet-pkg",
            name: "quiet-pkg",
            version: "1.0.0",
            pinned: false,
            scope: "user" as const,
          },
        ],
      },
      async ({ deps }) => {
        const exec = vi.fn(async (cmd: string, _args?: string[]) => ({
          stdout:
            cmd === "npm"
              ? `${process.env.PI_VETTER_NPM_REGISTRY ?? "https://registry.npmjs.org/"}\n`
              : "",
          stderr: "",
          code: 0,
        }));
        const manifest =
          JSON.stringify({ name: "quiet-pkg", version: "1.1.0", main: "index.js" }, null, 2) + "\n";
        const onDisk = new Map([
          ["package.json", new TextEncoder().encode(manifest)],
          ["index.js", new TextEncoder().encode("module.exports = () => 2;\n")],
        ]);
        const result = await runVetInstall(
          {
            ...deps,
            exec,
            pinOnInstall: false,
            unpin: () => undefined,
            readInstalledFiles: () => Promise.resolve(onDisk),
          },
          "npm:quiet-pkg",
          fakeCtx(async () => true),
        );
        expect(result.content).toContain("✓ quiet-pkg@1.1.0 installed");
        expect(result.content).toContain("on-disk files match the vetted artifact");
      },
    );
  });

  it("warns with a removal recommendation when installed bytes diverge (#48)", async () => {
    await withHarness(
      {
        fixtures: [quietPkg],
        installed: [
          {
            source: "npm:quiet-pkg",
            name: "quiet-pkg",
            version: "1.0.0",
            pinned: false,
            scope: "user" as const,
          },
        ],
      },
      async ({ deps }) => {
        const exec = vi.fn(async (cmd: string, _args?: string[]) => ({
          stdout:
            cmd === "npm"
              ? `${process.env.PI_VETTER_NPM_REGISTRY ?? "https://registry.npmjs.org/"}\n`
              : "",
          stderr: "",
          code: 0,
        }));
        const manifest =
          JSON.stringify({ name: "quiet-pkg", version: "1.1.0", main: "index.js" }, null, 2) + "\n";
        const tamperedDisk = new Map([
          ["package.json", new TextEncoder().encode(manifest)],
          ["index.js", new TextEncoder().encode("module.exports = () => 666;\n")],
        ]);
        const result = await runVetInstall(
          {
            ...deps,
            exec,
            pinOnInstall: false,
            unpin: () => undefined,
            readInstalledFiles: () => Promise.resolve(tamperedDisk),
          },
          "npm:quiet-pkg",
          fakeCtx(async () => true),
        );
        expect(result.content).toContain("⚠ quiet-pkg@1.1.0 installed but");
        expect(result.content).toContain("changed index.js");
        expect(result.content).toContain("pi remove npm:quiet-pkg@1.1.0");
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
        const exec = vi.fn(async (cmd: string, _args?: string[]) => ({
          stdout:
            cmd === "npm"
              ? `${process.env.PI_VETTER_NPM_REGISTRY ?? "https://registry.npmjs.org/"}\n`
              : "",
          stderr: "",
          code: 0,
        }));
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

        expect(exec.mock.calls.filter((c) => c[0] === "pi").map((c) => [c[0], c[1]])).toEqual([]);
        expect(unpin).not.toHaveBeenCalled();
        expect(result.content).toContain(
          "⚠ quiet-pkg@1.1.0 registry integrity changed after vetting",
        );
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

  it("publishes the report before the selection prompt and excludes it from the returned content (#50)", async () => {
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
        const order: string[] = [];
        const publishReport = vi.fn((content: string) => {
          order.push("publish");
          expect(content).toContain("quiet-pkg");
          expect(content).toContain("**Evidence**");
        });
        const result = await runVetInstall(
          { ...deps, exec, pinOnInstall: false, unpin: () => undefined, publishReport },
          "npm:quiet-pkg",
          fakeCtx(async () => {
            order.push("confirm");
            return false;
          }),
        );

        expect(publishReport).toHaveBeenCalledOnce();
        expect(order).toEqual(["publish", "confirm"]);
        expect(result.content).toContain("Nothing selected for installation.");
        expect(result.content).not.toContain("**Evidence**");
      },
    );
  });

  it("publishes the report before the TUI checkbox dialog opens (#50)", async () => {
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
        const order: string[] = [];
        const publishReport = vi.fn(() => {
          order.push("publish");
        });
        const result = await runVetInstall(
          { ...deps, exec, pinOnInstall: false, unpin: () => undefined, publishReport },
          "npm:quiet-pkg",
          fakeTuiCtx(() => {
            order.push("custom");
          }),
        );

        expect(publishReport).toHaveBeenCalledOnce();
        expect(order).toEqual(["publish", "custom"]);
        expect(result.content).not.toContain("**Evidence**");
      },
    );
  });

  it("keeps the published report out of the install-results content (#50)", async () => {
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
        const exec = vi.fn(async (cmd: string, _args?: string[]) => ({
          stdout:
            cmd === "npm"
              ? `${process.env.PI_VETTER_NPM_REGISTRY ?? "https://registry.npmjs.org/"}\n`
              : "",
          stderr: "",
          code: 0,
        }));
        const publishReport = vi.fn();
        const result = await runVetInstall(
          { ...deps, exec, pinOnInstall: false, unpin: () => undefined, publishReport },
          "npm:quiet-pkg",
          fakeCtx(async () => true),
        );

        expect(publishReport).toHaveBeenCalledOnce();
        expect(result.content).toContain("**Install results**");
        expect(result.content).toContain("✓ quiet-pkg@1.1.0 installed");
        expect(result.content).not.toContain("**Evidence**");
      },
    );
  });

  it("finishes progress before the selection prompt opens (#50)", async () => {
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
        const order: string[] = [];
        const progress = {
          startResolve: () => undefined,
          start: () => undefined,
          item: () => undefined,
          tick: () => undefined,
          finish: () => {
            order.push("finish");
          },
        };
        await runVetInstall(
          { ...deps, exec, pinOnInstall: false, unpin: () => undefined },
          "npm:quiet-pkg",
          fakeCtx(async () => {
            order.push("confirm");
            return false;
          }),
          progress,
        );

        expect(order).toEqual(["finish", "confirm"]);
      },
    );
  });
});
