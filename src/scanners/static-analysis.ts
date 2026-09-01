import type { Evidence, ScannerContext, ScanResult, SecurityScanner } from "../core/types.ts";
import { scanPatterns } from "./patterns.ts";

/**
 * L2 static analysis. A pattern hit that also exists in the baseline is
 * pre-existing behavior (info); only new hits fail (behavior-change-first).
 * Dynamic code execution (#40) is the install-scenario exception: with no
 * baseline to vouch for pre-existing behaviour, eval/dynamic-module hits ask.
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

    if (
      ctx.artifacts.dependencyFiles &&
      (ctx.artifacts.dependencyFiles.size > 0 || ctx.artifacts.dependencySkipped > 0)
    ) {
      const skipped =
        ctx.artifacts.dependencySkipped > 0
          ? ` (+${ctx.artifacts.dependencySkipped} skipped: fetch/verify failed)`
          : "";
      // #41 severity ladder: trusted-extension → trusted-dependency → malicious
      // transitive is the canonical npm attack path, so risky labels inside
      // dependency tarballs escalate; ordinary Node.js API usage stays info.
      const riskHits: string[] = [];
      const infoHits: string[] = [];
      for (const [key, depFiles] of ctx.artifacts.dependencyFiles) {
        const dep = scanPatterns(depFiles);
        const summary: Array<{ label: string; hits: string[]; risky: boolean }> = [
          { label: "credential", hits: dep.credentials, risky: true },
          { label: "obfuscation", hits: dep.obfuscation, risky: true },
          { label: "prompt-injection", hits: dep.promptInjection, risky: true },
          { label: "eval", hits: dep.evalFamily, risky: true },
          { label: "dynamic-module", hits: dep.dynamicModule, risky: true },
          { label: "child-process", hits: dep.childProcess, risky: false },
        ];
        for (const { label, hits, risky } of summary) {
          if (hits.length === 0) continue;
          (risky ? riskHits : infoHits).push(`${key}: ${label} x${hits.length}`);
        }
      }
      if (riskHits.length > 0) {
        evidences.push({
          scanner: "static",
          key: "static:dependency-risk",
          status: "fail",
          detail: `risky pattern hits inside dependency tarballs: ${riskHits.slice(0, 6).join("; ")}${riskHits.length > 6 ? ` (+${riskHits.length - 6} more)` : ""}${skipped}`,
          data: riskHits,
        });
      }
      if (infoHits.length > 0) {
        evidences.push({
          scanner: "static",
          key: "static:dependency-hits",
          status: "info",
          detail: `informational pattern hits inside dependency tarballs: ${infoHits.slice(0, 6).join("; ")}${infoHits.length > 6 ? ` (+${infoHits.length - 6} more)` : ""}${skipped}`,
          data: infoHits,
        });
      }
      if (riskHits.length === 0 && infoHits.length === 0) {
        evidences.push({
          scanner: "static",
          key: "static:dependencies-clean",
          status: "info",
          detail: `no pattern hits across ${ctx.artifacts.dependencyFiles.size} scanned dependency tarball(s)${skipped}`,
        });
      }
    }

    // #40: dynamic code execution asks by default in the install scenario
    // (no baseline to vouch for pre-existing behaviour); in the update
    // scenario the behavior-change-first gate applies — pre-existing hits
    // are info, new hits fail.
    const dynamicCode = [
      ["static:eval", candidate.evalFamily, baseline?.evalFamily],
      ["static:dynamic-module", candidate.dynamicModule, baseline?.dynamicModule],
    ] as const;
    for (const [key, hits, baselineHits] of dynamicCode) {
      if (hits.length === 0) continue;
      const isNew = !baseline || baselineHits === undefined || baselineHits.length === 0;
      const label = key.replace("static:", "");
      evidences.push({
        scanner: "static",
        key,
        status: isNew ? "fail" : "info",
        detail: isNew
          ? `${label} found (${hits.length}): ${hits.slice(0, 3).join("; ")}`
          : `pre-existing ${label} markers (${hits.length}), unchanged signal`,
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
