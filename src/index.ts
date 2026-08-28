import { join } from "node:path";
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { createFileCache } from "./cache.ts";
import { runVet } from "./commands/vet.ts";
import { runVetInstall } from "./commands/vet-install.ts";
import { createMaintainerSnapshotStore, dataDir, loadConfig } from "./config.ts";
import type { SecurityScanner, VetterConfig } from "./core/types.ts";
import { fetchPackument } from "./npm/registry.ts";
import { diffScanner } from "./scanners/diff.ts";
import { createMetadataScanner } from "./scanners/metadata.ts";
import { createOsvScanner } from "./scanners/osv.ts";
import { createProvenanceScanner } from "./scanners/provenance.ts";
import { createSocketScanner } from "./scanners/socket.ts";
import { staticScanner } from "./scanners/static-analysis.ts";
import { createVirustotalScanner } from "./scanners/virustotal.ts";
import { createPackageManager, listInstalledPackages } from "./settings.ts";
import { ProgressTracker } from "./ui/progress.ts";
import { renderReport } from "./ui/report.ts";

function assembleScanners(config: VetterConfig): SecurityScanner[] {
  const scanners: SecurityScanner[] = [
    createMetadataScanner(createMaintainerSnapshotStore()),
    createOsvScanner(config.scanners.osv?.timeoutMs ?? 10_000),
    createProvenanceScanner({
      ...(config.scanners.provenance?.timeoutMs !== undefined
        ? { timeoutMs: config.scanners.provenance.timeoutMs }
        : {}),
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

  const send = (content: string) =>
    pi.sendMessage({ customType: "pi-vetter", content, display: true });

  const makeProgress = (ctx: ExtensionCommandContext) => {
    const tracker = new ProgressTracker("pi-vetter: vetting");
    const isTui = ctx.mode === "tui";
    const render = () => {
      if (isTui) ctx.ui.setWidget("pi-vetter-progress", tracker.lines());
    };
    return {
      start: (total: number) => {
        tracker.start(total);
        render();
      },
      item: (name: string) => {
        tracker.item(name);
        render();
      },
      tick: () => {
        tracker.tick();
        render();
      },
      finish: () => {
        if (isTui) ctx.ui.setWidget("pi-vetter-progress", undefined);
      },
    };
  };

  pi.registerCommand("vet", {
    description: "Evaluate pending extension updates or a specific package (read-only)",
    handler: async (args: string, ctx) => {
      send("pi-vetter: /vet started…");
      const progress = makeProgress(ctx);
      const { reports, notes } = await runVet(
        vetDeps,
        args,
        (report) => send(renderReport(report)),
        progress,
      );
      progress.finish();
      if (reports.length === 0 && notes.length === 0) send("No packages to evaluate.");
      else if (notes.length > 0) send(`**Notes**\n${notes.join("\n")}`);
    },
  });

  pi.registerCommand("vet-install", {
    description: "Evaluate, then interactively install approved packages",
    handler: async (args: string, ctx) => {
      send("pi-vetter: /vet-install started…");
      const progress = makeProgress(ctx);
      const content = await runVetInstall(
        { ...vetDeps, exec: (cmd, argv, opts) => pi.exec(cmd, argv, opts) },
        args,
        ctx,
        (report) => send(renderReport(report)),
        progress,
      );
      progress.finish();
      if (content) send(content);
    },
  });
}
