import type { Evidence, ScannerContext, ScanResult, SecurityScanner } from "../core/types.ts";
import { scanPatterns } from "./patterns.ts";

/**
 * L2 static analysis. A pattern hit that also exists in the baseline is
 * pre-existing behavior (info); only new hits fail (behavior-change-first).
 */
export const staticScanner: SecurityScanner = {
  name: "static",
  layer: 2,
  async scan(ctx: ScannerContext): Promise<ScanResult> {
    const candidate = scanPatterns(ctx.artifacts.candidateFiles);
    const baseline = ctx.artifacts.baselineFiles ? scanPatterns(ctx.artifacts.baselineFiles) : null;

    const evidences: Evidence[] = [
      {
        scanner: "static",
        key: "static:scanned",
        status: "info",
        detail: `Scanned ${candidate.scannedFileCount} code files for dangerous patterns`,
      },
    ];

    const categories = [
      ["static:credential-access", candidate.credentials, baseline?.credentials],
      ["static:obfuscation", candidate.obfuscation, baseline?.obfuscation],
      ["static:prompt-injection", candidate.promptInjection, baseline?.promptInjection],
    ] as const;

    for (const [key, hits, baselineHits] of categories) {
      if (hits.length === 0) continue;
      const isNew = !baseline || baselineHits === undefined || baselineHits.length === 0;
      // Install scenario (no baseline): credential/obfuscation hits are almost
      // always the package's legitimate nature (e.g. API-key readers), so they
      // stay informational; prompt-injection remains a hard signal either way.
      const installDowngraded = baseline === null && key !== "static:prompt-injection";
      const sample = hits.slice(0, 3).join("; ");
      const fail = isNew && !installDowngraded;
      evidences.push({
        scanner: "static",
        key,
        status: fail ? "fail" : "info",
        detail: fail
          ? `${key.replace("static:", "")} markers found (${hits.length}): ${sample}`
          : installDowngraded && isNew
            ? `${key.replace("static:", "")} markers present (${hits.length}); informational without a baseline to compare against`
            : `pre-existing ${key.replace("static:", "")} markers (${hits.length}), unchanged signal`,
        data: hits,
      });
    }

    if (candidate.evalFamily.length > 0) {
      evidences.push({
        scanner: "static",
        key: "static:eval",
        status: "info",
        detail: `eval-family markers present (${candidate.evalFamily.length}); informational, no verdict rule mapped`,
        data: candidate.evalFamily,
      });
    }

    if (candidate.childProcess.length > 0) {
      evidences.push({
        scanner: "static",
        key: "static:child-process",
        status: "info",
        detail: `child_process usage present (${candidate.childProcess.length}); diff scanner judges whether it is new`,
        data: candidate.childProcess,
      });
    }

    return { scanner: "static", status: "ok", evidences };
  },
};
