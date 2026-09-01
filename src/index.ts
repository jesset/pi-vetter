import { join } from "node:path";
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { createFileCache } from "./cache.ts";
import { runVet } from "./commands/vet.ts";
import { runVetInstall } from "./commands/vet-install.ts";
import { createMaintainerSnapshotStore, dataDir, loadConfig, scannerConfigGaps } from "./config.ts";
import type { SecurityScanner, VetterConfig } from "./core/types.ts";
import { installSpec } from "./install/gated-installer.ts";
import { fetchPackument } from "./npm/registry.ts";
import { diffScanner } from "./scanners/diff.ts";
import { createMetadataScanner } from "./scanners/metadata.ts";
import { createOsvScanner } from "./scanners/osv.ts";
import { createProvenanceScanner } from "./scanners/provenance.ts";
import { createSocketScanner } from "./scanners/socket.ts";
import { staticScanner } from "./scanners/static-analysis.ts";
import { createVirustotalScanner } from "./scanners/virustotal.ts";
import { createPackageManager, listInstalledPackages } from "./settings.ts";
import { reportEntryRenderer } from "./ui/entry.ts";
import { ProgressTracker } from "./ui/progress.ts";
import { NO_PACKAGES_MESSAGE, renderNotes, renderReports, summaryLine } from "./ui/report.ts";

function assembleScanners(config: VetterConfig): SecurityScanner[] {
  const scanners: SecurityScanner[] = [
    createMetadataScanner(createMaintainerSnapshotStore()),
    createOsvScanner({ timeoutMs: config.scanners.osv?.timeoutMs ?? 10_000 }),
    createProvenanceScanner({
      ...(config.scanners.provenance?.timeoutMs !== undefined
        ? { timeoutMs: config.scanners.provenance.timeoutMs }
        : {}),
      required: config.provenance?.required === true,
    }),
    staticScanner,
    diffScanner,
  ].filter((s) => config.scanners[s.name]?.enabled !== false);

  const vt = config.scanners.virustotal;
  if (vt?.enabled && vt.apiKey) {
    scanners.push(
      createVirustotalScanner({
        apiKey: vt.apiKey,
        ...(vt.timeoutMs !== undefined ? { timeoutMs: vt.timeoutMs } : {}),
        ...(vt.pollDeadlineMs !== undefined ? { pollDeadlineMs: vt.pollDeadlineMs } : {}),
      }),
    );
  }

  const socket = config.scanners.socket;
  if (socket?.enabled && socket.apiKey && socket.orgSlug) {
    scanners.push(
      createSocketScanner({
        apiKey: socket.apiKey,
        orgSlug: socket.orgSlug,
        ...(socket.timeoutMs !== undefined ? { timeoutMs: socket.timeoutMs } : {}),
      }),
    );
  }
  return scanners;
}

export default function (pi: ExtensionAPI): void {
  const config = loadConfig();
  const cache = createFileCache(join(dataDir(), "cache"), config.cache);
  const pm = createPackageManager(process.cwd());
  const scanners = assembleScanners(config);

  const vetDeps = {
    config,
    cache,
    scanners,
    listInstalled: () => listInstalledPackages(pm),
    fetchPackument,
  };

  pi.registerEntryRenderer("pi-vetter-report", reportEntryRenderer);

  // Transcript output only: custom entries do NOT participate in LLM context
  // (sendMessage does — and queues through the agent pipeline, so it is
  // neither instant nor free of token pollution).
  const send = (content: string) => {
    pi.appendEntry("pi-vetter-report", { markdown: content });
  };

  const makeProgress = (ctx: ExtensionCommandContext) => {
    const tracker = new ProgressTracker("pi-vetter");
    const isTui = ctx.mode === "tui";
    const render = () => {
      if (isTui) ctx.ui.setWidget("pi-vetter-progress", tracker.lines());
    };
    return {
      startResolve: (names: string[]) => {
        tracker.startResolve(names);
        render();
      },
      start: (names: string[]) => {
        tracker.start(names);
        render();
      },
      item: (name: string) => {
        tracker.item(name);
        render();
      },
      tick: (name: string) => {
        tracker.tick(name);
        render();
      },
      finish: () => {
        if (isTui) ctx.ui.setWidget("pi-vetter-progress", undefined);
      },
    };
  };

  const notifyAborted = (ctx: ExtensionCommandContext, command: string, err: unknown) => {
    ctx.ui.notify(
      `pi-vetter: ${command} aborted — ${err instanceof Error ? err.message : String(err)}`,
      "error",
    );
  };

  // #33: a scanner declared enabled without credentials is silently unusable —
  // warn up front so the user learns it before the report lands in Notes.
  const warnScannerGaps = (ctx: ExtensionCommandContext) => {
    for (const gap of scannerConfigGaps(config)) {
      ctx.ui.notify(
        `pi-vetter: ${gap.name} is enabled but missing ${gap.missing.join(", ")} — scanner will not run (see Notes for the free-key hint)`,
        "warning",
      );
    }
  };

  pi.registerCommand("vet", {
    description: "Evaluate pending extension updates or a specific package (read-only)",
    handler: async (args: string, ctx) => {
      ctx.ui.notify("pi-vetter: /vet started", "info");
      warnScannerGaps(ctx);
      const progress = makeProgress(ctx);
      try {
        const { reports, notes } = await runVet(vetDeps, args, progress);
        progress.finish();
        ctx.ui.notify(summaryLine("/vet", reports), "info");
        const content = [renderReports(reports), renderNotes(notes)].filter(Boolean).join("\n\n");
        send(content || NO_PACKAGES_MESSAGE);
      } catch (err) {
        progress.finish();
        notifyAborted(ctx, "/vet", err);
      }
    },
  });

  // #16: by default, restore the unpinned spec after installing so the
  // evaluator never decides a package's long-term update policy silently.
  // Best-effort: if the re-add step fails after removal, the settings entry
  // is missing (pi update then ignores the package) — the installed version
  // itself is unaffected either way.
  const unpin = (name: string, version: string) => {
    try {
      pm.removeSourceFromSettings(installSpec(name, version));
      pm.addSourceToSettings(`npm:${name}`);
    } catch {
      // see note above
    }
  };

  pi.registerCommand("vet-install", {
    description: "Evaluate, then interactively install approved packages",
    handler: async (args: string, ctx) => {
      ctx.ui.notify("pi-vetter: /vet-install started", "info");
      warnScannerGaps(ctx);
      const progress = makeProgress(ctx);
      try {
        const result = await runVetInstall(
          {
            ...vetDeps,
            exec: (cmd, argv, opts) => pi.exec(cmd, argv, opts),
            pinOnInstall: config.install.pinOnInstall,
            unpin,
          },
          args,
          ctx,
          progress,
        );
        progress.finish();
        ctx.ui.notify(summaryLine("/vet-install", result.reports), "info");
        if (result.content) send(result.content);
      } catch (err) {
        progress.finish();
        notifyAborted(ctx, "/vet-install", err);
      }
    },
  });
}
