import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createFileCache } from "../../src/cache.ts";
import { runVet } from "../../src/commands/vet.ts";
import { createMaintainerSnapshotStore, loadConfig } from "../../src/config.ts";
import { fetchPackument } from "../../src/npm/registry.ts";
import { diffScanner } from "../../src/scanners/diff.ts";
import { createMetadataScanner } from "../../src/scanners/metadata.ts";
import { createOsvScanner } from "../../src/scanners/osv.ts";
import { createProvenanceScanner } from "../../src/scanners/provenance.ts";
import { staticScanner } from "../../src/scanners/static-analysis.ts";

/**
 * Real network. Only runs with LIVE_E2E=1 (nightly CI or opt-in locally);
 * `npm test` skips these entirely. Asserts invariants, not specific verdicts:
 * upstream data can legitimately change (a new advisory, a new maintainer)
 * without this suite breaking — only a broken chain should.
 */
describe.skipIf(!process.env.LIVE_E2E)("live e2e: /vet against the real npm registry", () => {
  // long-lived, dependency-free, low-churn packages pinned to exact versions
  const specs = ["npm:left-pad@1.3.0", "npm:ms@2.1.3"] as const;

  it.each(specs)("%s vets end to end without crashing", async (spec) => {
    const dataDir = mkdtempSync(join(tmpdir(), "pi-vetter-live-"));
    const config = loadConfig(dataDir);
    const { reports, notes } = await runVet(
      {
        config,
        cache: createFileCache(join(dataDir, "cache"), config.cache),
        scanners: [
          createMetadataScanner(createMaintainerSnapshotStore(dataDir)),
          createOsvScanner(10_000),
          createProvenanceScanner({ timeoutMs: 10_000 }),
          staticScanner,
          diffScanner,
        ],
        listInstalled: () => ({ packages: [], skippedSources: [] }),
        fetchPackument,
      },
      spec,
    );

    expect(notes).toEqual([]); // no per-package degradation against the real registry
    expect(reports).toHaveLength(1);
    const report = reports[0];
    if (!report) throw new Error(`no report for ${spec}`);
    expect(["ALLOW", "ASK", "DENY"]).toContain(report.verdict);
    expect(report.capped).toBe(false); // every scanner completed against the real endpoints
    expect(report.candidateIntegrity).toMatch(/^sha512-/);
    // the full scanner chain ran — a missing family means a silent drop
    expect(new Set(report.evidences.map((e) => e.scanner))).toEqual(
      new Set(["metadata", "osv", "provenance", "static", "diff"]),
    );
  });
});
