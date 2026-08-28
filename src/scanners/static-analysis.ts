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
          : installDowngraded
            ? `${key.replace("static:", "")} markers present (${hits.length}); informational without a baseline to compare against`
            : `pre-existing ${key.replace("static:", "")} markers (${hits.length}), unchanged signal`,
        data: hits,
      });
    }

    if (ctx.artifacts.dependencyFiles && ctx.artifacts.dependencyFiles.size > 0) {
      const hits: string[] = [];
      for (const [key, depFiles] of ctx.artifacts.dependencyFiles) {
        const dep = scanPatterns(depFiles);
        const categories: Array<[string, string[]]> = [
          ["credential", dep.credentials],
          ["obfuscation", dep.obfuscation],
          ["prompt-injection", dep.promptInjection],
          ["child-process", dep.childProcess],
          ["eval", dep.evalFamily],
        ];
        for (const [label, list] of categories) {
          if (list.length > 0) hits.push(`${key}: ${label} x${list.length}`);
        }
      }
      if (hits.length > 0) {
        evidences.push({
          scanner: "static",
          key: "static:dependency-hits",
          status: "info",
          detail: `pattern hits inside dependency tarballs (informational in MVP): ${hits.slice(0, 6).join("; ")}${hits.length > 6 ? ` (+${hits.length - 6} more)` : ""}`,
          data: hits,
        });
      } else {
        evidences.push({
          scanner: "static",
          key: "static:dependencies-clean",
          status: "pass",
          detail: `no pattern hits across ${ctx.artifacts.dependencyFiles.size} scanned dependency tarball(s)`,
        });
      }
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
