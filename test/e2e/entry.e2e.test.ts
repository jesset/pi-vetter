import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import extension from "../../src/index.ts";
import { NO_PACKAGES_MESSAGE } from "../../src/ui/report.ts";
import type { FixturePackage } from "./helpers/fixtures.ts";
import { withHarness } from "./helpers/harness.ts";

const quietPkg: FixturePackage = {
  name: "quiet-pkg",
  versions: [
    { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = () => 1;\n" }] },
    { version: "1.1.0", files: [{ path: "index.js", content: "module.exports = () => 2;\n" }] },
  ],
};

interface RecordedEntry {
  type: string;
  entry: { markdown: string };
}

/** Records every surface the extension touches: registrations, exec, entries. */
function fakePi() {
  const entries: RecordedEntry[] = [];
  const exec = vi.fn(async (command: string, _args?: string[], _opts?: unknown) => ({
    stdout:
      command === "npm"
        ? `${process.env.PI_VETTER_NPM_REGISTRY ?? "https://registry.npmjs.org/"}\n`
        : "",
    stderr: "",
    code: 0,
  }));
  const renderers = new Map<string, unknown>();
  const commands = new Map<
    string,
    { description: string; handler: (args: string, ctx: ExtensionCommandContext) => Promise<void> }
  >();
  const pi = {
    registerEntryRenderer: (type: string, renderer: unknown) => {
      renderers.set(type, renderer);
    },
    registerCommand: (
      name: string,
      def: {
        description: string;
        handler: (args: string, ctx: ExtensionCommandContext) => Promise<void>;
      },
    ) => {
      commands.set(name, def);
    },
    appendEntry: (type: string, entry: { markdown: string }) => {
      entries.push({ type, entry });
    },
    exec: (cmd: string, args: string[], opts?: unknown) => exec(cmd, args, opts),
  };
  return { pi: pi as unknown as ExtensionAPI, entries, exec, renderers, commands };
}

interface FakeCtx {
  mode: "tui" | "cli";
  ui: {
    notify: ReturnType<typeof vi.fn>;
    setWidget: ReturnType<typeof vi.fn>;
  };
}

function fakeCtx(
  mode: "tui" | "cli",
  confirm: () => boolean | Promise<boolean> = () => true,
): FakeCtx & ExtensionCommandContext {
  const ctx = {
    mode,
    ui: {
      notify: vi.fn(),
      setWidget: vi.fn(),
      custom: async () => ({ selected: [], cancelled: true }),
      confirm: async () => confirm(),
    },
  };
  return ctx as unknown as FakeCtx & ExtensionCommandContext;
}

/**
 * Throwaway ~/.pi/agent stand-in: settings.json with the given package sources,
 * plus fake installs under npm/node_modules so the package manager reports a
 * real installed version for them.
 */
function mkAgentDir(
  sources: string[],
  installed: { name: string; version: string }[] = [],
): string {
  const dir = mkdtempSync(join(tmpdir(), "pi-vetter-agent-"));
  writeFileSync(join(dir, "settings.json"), `${JSON.stringify({ packages: sources }, null, 2)}\n`);
  for (const pkg of installed) {
    const pkgDir = join(dir, "npm", "node_modules", pkg.name);
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(
      join(pkgDir, "package.json"),
      `${JSON.stringify({ name: pkg.name, version: pkg.version }, null, 2)}\n`,
    );
  }
  return dir;
}

describe("e2e: extension entrypoint", () => {
  it("registers both commands and the report entry renderer", async () => {
    await withHarness({ fixtures: [quietPkg] }, async () => {
      const { pi, renderers, commands } = fakePi();
      extension(pi);
      expect([...commands.keys()].sort()).toEqual(["vet", "vet-install"]);
      expect(commands.get("vet")?.description).toMatch(/read-only/i);
      expect(renderers.has("pi-vetter-report")).toBe(true);
    });
  });

  it("drives /vet in TUI mode: notify, live progress widget, transcript report", async () => {
    await withHarness(
      { fixtures: [quietPkg], agentDir: mkAgentDir(["npm:quiet-pkg"]) },
      async () => {
        const { pi, entries, commands } = fakePi();
        extension(pi);
        const ctx = fakeCtx("tui");
        await commands.get("vet")?.handler("npm:quiet-pkg", ctx);

        const notified = ctx.ui.notify.mock.calls.map((c) => c[0]);
        expect(notified[0]).toBe("pi-vetter: /vet started");
        expect(notified.at(-1)).toBe("pi-vetter: /vet done — 1 vetted: 1 ALLOW, 0 ASK, 0 DENY");

        const widgets = ctx.ui.setWidget.mock.calls.map((c) => c[1]);
        expect(widgets.some((w) => w !== undefined)).toBe(true); // progress shown
        expect(widgets.at(-1)).toBeUndefined(); // and cleared on completion

        expect(entries).toHaveLength(1);
        expect(entries[0]?.type).toBe("pi-vetter-report");
        expect(entries[0]?.entry.markdown).toContain("### install quiet-pkg@1.1.0");
        expect(entries[0]?.entry.markdown).toContain("**Verdict: ALLOW**");
      },
    );
  });

  it("sends the empty-state message when nothing is configured", async () => {
    await withHarness({ fixtures: [quietPkg], agentDir: mkAgentDir([]) }, async () => {
      const { pi, entries, commands } = fakePi();
      extension(pi);
      const ctx = fakeCtx("tui");
      await commands.get("vet")?.handler("", ctx);
      expect(entries).toHaveLength(1);
      expect(entries[0]?.entry.markdown).toBe(NO_PACKAGES_MESSAGE);
    });
  });

  it("drives /vet-install in cli mode: exec, settings unpin, transcript report", async () => {
    // the user previously pinned 1.1.0 by hand: exactly the state `pi install`
    // leaves behind, which the unpin closure is expected to revert
    const agentDir = mkAgentDir(["npm:quiet-pkg@1.1.0"]);
    await withHarness({ fixtures: [quietPkg], agentDir }, async () => {
      const { pi, entries, exec, commands } = fakePi();
      extension(pi);
      const ctx = fakeCtx("cli", () => true);
      await commands.get("vet-install")?.handler("npm:quiet-pkg", ctx);

      expect(exec.mock.calls.filter((c) => c[0] === "pi").map((c) => [c[0], c[1]])).toEqual([
        ["pi", ["install", "npm:quiet-pkg@1.1.0"]],
      ]);
      expect(entries.at(-1)?.entry.markdown).toContain("✓ quiet-pkg@1.1.0 installed");
      expect(entries.at(-1)?.entry.markdown).toContain("to pin: pi install npm:quiet-pkg@1.1.0");
      const notified = ctx.ui.notify.mock.calls.map((c) => c[0]);
      expect(notified.at(-1)).toContain("/vet-install done");

      // the entrypoint's unpin closure wrote through the real package manager
      const settings = JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8")) as {
        packages: string[];
      };
      expect(settings.packages).toEqual(["npm:quiet-pkg"]);
    });
  });

  it("aborts loudly on bad args: error notify, no entry, widget cleared", async () => {
    await withHarness({ fixtures: [quietPkg] }, async () => {
      const { pi, entries, commands } = fakePi();
      extension(pi);
      const ctx = fakeCtx("tui");
      await commands.get("vet")?.handler("bogus", ctx);

      const calls = ctx.ui.notify.mock.calls;
      expect(calls.at(-1)?.[0]).toContain("/vet aborted");
      expect(calls.at(-1)?.[0]).toContain('unsupported spec "bogus"');
      expect(calls.at(-1)?.[1]).toBe("error");
      expect(entries).toEqual([]);
      expect(ctx.ui.setWidget.mock.calls.at(-1)?.[1]).toBeUndefined();
    });
  });

  it("writes the config skeleton under the redirected data dir on first run", async () => {
    const agentDir = mkAgentDir(["npm:quiet-pkg"]);
    await withHarness({ fixtures: [quietPkg], agentDir }, async ({ dataDir }) => {
      const { pi, commands } = fakePi();
      extension(pi);
      await commands.get("vet")?.handler("npm:quiet-pkg", fakeCtx("cli"));
      // first run must never touch the real ~/.pi/agent
      const config = JSON.parse(readFileSync(join(dataDir, "config.json"), "utf8")) as Record<
        string,
        unknown
      >;
      expect(config.scanners).toBeDefined();
    });
  });

  it("leaves settings untouched when the user cancels the selection", async () => {
    const agentDir = mkAgentDir(["npm:quiet-pkg"]);
    await withHarness({ fixtures: [quietPkg], agentDir }, async () => {
      const { pi, exec, commands } = fakePi();
      extension(pi);
      const ctx = fakeCtx("cli", () => false);
      await commands.get("vet-install")?.handler("npm:quiet-pkg", ctx);

      expect(exec.mock.calls.filter((c) => c[0] === "pi").map((c) => [c[0], c[1]])).toEqual([]);
      const settings = JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8")) as {
        packages: string[];
      };
      expect(settings.packages).toEqual(["npm:quiet-pkg"]);
    });
  });

  it("runs /vet with no args against the redirected agent settings", async () => {
    // pinned baseline + a fake install on disk: the installed inventory comes
    // from the entrypoint's real listInstalledPackages wiring (no fixture)
    const agentDir = mkAgentDir(["npm:quiet-pkg@1.0.0"], [{ name: "quiet-pkg", version: "1.0.0" }]);
    await withHarness({ fixtures: [quietPkg], agentDir }, async () => {
      const { pi, entries, commands } = fakePi();
      extension(pi);
      const ctx = fakeCtx("cli");
      await commands.get("vet")?.handler("", ctx);
      // pinned @1.0.0 resolves latest 1.1.0 → evaluated (ADR-0003: always vet pinned)
      expect(entries.at(-1)?.entry.markdown).toContain("### quiet-pkg 1.0.0 → 1.1.0");
      expect(entries.at(-1)?.entry.markdown).toContain("(baseline is pinned)");
      expect(ctx.ui.notify.mock.calls.at(-1)?.[0]).toContain("1 vetted: 1 ALLOW");
    });
  });
});
