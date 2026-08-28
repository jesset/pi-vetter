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
      ["static:eval", candidate.evalFamily, baseline?.evalFamily],
    ] as const;

    for (const [key, hits, baselineHits] of categories) {
      if (hits.length === 0) continue;
      const isNew = !baseline || baselineHits === undefined || baselineHits.length === 0;
      const sample = hits.slice(0, 3).join("; ");
      evidences.push({
        scanner: "static",
        key,
        status: isNew ? "fail" : "info",
        detail: isNew
          ? `${key.replace("static:", "")} markers found (${hits.length}): ${sample}`
          : `pre-existing ${key.replace("static:", "")} markers (${hits.length}), unchanged signal`,
        data: hits,
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
