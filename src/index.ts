import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createFileCache } from "./cache.ts";
import { runVet } from "./commands/vet.ts";
import { runVetInstall } from "./commands/vet-install.ts";
import { createMaintainerSnapshotStore, dataDir, loadConfig } from "./config.ts";
import type { SecurityScanner } from "./core/types.ts";
import { fetchPackument } from "./npm/registry.ts";
import { diffScanner } from "./scanners/diff.ts";
import { createMetadataScanner } from "./scanners/metadata.ts";
import { createOsvScanner } from "./scanners/osv.ts";
import { createProvenanceScanner } from "./scanners/provenance.ts";
import { staticScanner } from "./scanners/static-analysis.ts";
import { createPackageManager, listInstalledPackages } from "./settings.ts";
import { renderReport } from "./ui/report.ts";

function assembleScanners(): SecurityScanner[] {
  const snapshots = createMaintainerSnapshotStore();
  const osv = createOsvScanner(loadConfig().scanners.osv?.timeoutMs ?? 10_000);
  const provenance = createProvenanceScanner(loadConfig().scanners.provenance?.timeoutMs ?? 10_000);
  return [createMetadataScanner(snapshots), osv, provenance, staticScanner, diffScanner];
}

function enabledScanners(config: ReturnType<typeof loadConfig>): SecurityScanner[] {
  return assembleScanners().filter((s) => config.scanners[s.name]?.enabled !== false);
}

export default function (pi: ExtensionAPI): void {
  const config = loadConfig();
  const cache = createFileCache(join(dataDir(), "cache"), config.cache);
  const pm = createPackageManager(process.cwd());
  const scanners = enabledScanners(config);

  const vetDeps = {
    config,
    cache,
    scanners,
    listInstalled: () => listInstalledPackages(pm),
    fetchPackument,
  };

  const send = (content: string) =>
    pi.sendMessage({ customType: "pi-vetter", content, display: true });

  pi.registerCommand("vet", {
    description: "Evaluate pending extension updates or a specific package (read-only)",
    handler: async (args: string) => {
      const { reports, notes } = await runVet(vetDeps, args, (report) =>
        send(renderReport(report)),
      );
      if (reports.length === 0 && notes.length === 0) send("No packages to evaluate.");
      else if (notes.length > 0) send(`**Notes**\n${notes.join("\n")}`);
    },
  });

  pi.registerCommand("vet-install", {
    description: "Evaluate, then interactively install approved packages",
    handler: async (args: string, ctx) => {
      const content = await runVetInstall(
        { ...vetDeps, exec: (cmd, argv, opts) => pi.exec(cmd, argv, opts) },
        args,
        ctx,
        (report) => send(renderReport(report)),
      );
      if (content) send(content);
    },
  });
}
