import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runVet } from "../src/commands/vet.ts";
import { createFileCache } from "../src/cache.ts";
import { createMaintainerSnapshotStore, defaultConfig } from "../src/config.ts";
import { fetchPackument } from "../src/npm/registry.ts";
import { createMetadataScanner } from "../src/scanners/metadata.ts";
import { createOsvScanner } from "../src/scanners/osv.ts";
import { createProvenanceScanner } from "../src/scanners/provenance.ts";
import { staticScanner } from "../src/scanners/static-analysis.ts";
import { diffScanner } from "../src/scanners/diff.ts";
import { createPackageManager, listInstalledPackages } from "../src/settings.ts";
import { renderReports } from "../src/ui/report.ts";

const dir = mkdtempSync(join(tmpdir(), "pi-vetter-smoke-"));
const config = defaultConfig();
const cache = createFileCache(join(dir, "cache"), config.cache);
const pm = createPackageManager(process.cwd());

const deps = {
  config,
  cache,
  scanners: [
    createMetadataScanner(createMaintainerSnapshotStore(dir)),
    createOsvScanner(10_000),
    createProvenanceScanner(10_000),
    staticScanner,
    diffScanner,
  ],
  listInstalled: () => listInstalledPackages(pm),
  fetchPackument,
};

const args = process.argv[2] ?? "";
console.error(`[smoke] args=${JSON.stringify(args)} dataDir=${dir}`);
const { reports, notes } = await runVet(deps, args);
console.log(renderReports(reports));
if (notes.length > 0) console.log(`\n**Notes**\n${notes.join("\n")}`);
console.error(`[smoke] done: ${reports.length} report(s)`);
