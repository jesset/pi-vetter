import type { Evidence, ScannerContext, ScanResult, SecurityScanner } from "../core/types.ts";
import { scanPatterns } from "./patterns.ts";

const LIFECYCLE_SCRIPTS = ["install", "preinstall", "postinstall"] as const;

function scriptsOf(
  packument: ScannerContext["artifacts"]["candidatePackument"],
  version: string,
): Record<string, string> {
  return packument.versions[version]?.scripts ?? {};
}

function diffRecords(
  base: Record<string, string>,
  candidate: Record<string, string>,
): { added: string[]; changed: string[] } {
  const added: string[] = [];
  const changed: string[] = [];
  for (const key of Object.keys(candidate)) {
    if (!(key in base)) added.push(key);
    else if (base[key] !== candidate[key]) changed.push(key);
  }
  return { added, changed };
}

function depsOf(
  packument: ScannerContext["artifacts"]["candidatePackument"],
  version: string,
): Record<string, string> {
  return packument.versions[version]?.dependencies ?? {};
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function fileChanges(base: Map<string, Uint8Array>, cand: Map<string, Uint8Array>) {
  const added: string[] = [];
  const removed: string[] = [];
  const modified: string[] = [];
  for (const name of cand.keys()) {
    if (!base.has(name)) added.push(name);
    else if (!bytesEqual(base.get(name) ?? new Uint8Array(), cand.get(name) ?? new Uint8Array()))
      modified.push(name);
  }
  for (const name of base.keys()) if (!cand.has(name)) removed.push(name);
  return { added, removed, modified };
}

export const diffScanner: SecurityScanner = {
  name: "diff",
  layer: 2,
  async scan(ctx: ScannerContext): Promise<ScanResult> {
    const { artifacts, baseline, candidate } = ctx;
    const evidences: Evidence[] = [];

    if (!baseline || !artifacts.baselineFiles) {
      return {
        scanner: "diff",
        status: "ok",
        evidences: [
          {
            scanner: "diff",
            key: "diff:skipped",
            status: "info",
            detail: "No baseline version (install scenario); behavior-diff not applicable",
          },
        ],
      };
    }

    const baseScripts = scriptsOf(artifacts.candidatePackument, baseline.version);
    const candScripts = scriptsOf(artifacts.candidatePackument, candidate.version);
    const lifecycleAdded = [
      ...diffRecords(baseScripts, candScripts).added,
      ...diffRecords(baseScripts, candScripts).changed,
    ].filter((s) => (LIFECYCLE_SCRIPTS as readonly string[]).includes(s));
    if (lifecycleAdded.length > 0) {
      evidences.push({
        scanner: "diff",
        key: "diff:new-script",
        status: "fail",
        detail: `lifecycle script(s) added or changed: ${lifecycleAdded.join(", ")}`,
        data: lifecycleAdded,
      });
    } else {
      evidences.push({
        scanner: "diff",
        key: "diff:scripts-stable",
        status: "pass",
        detail: "No new or changed lifecycle scripts",
      });
    }

    const baseDeps = depsOf(artifacts.candidatePackument, baseline.version);
    const candDeps = depsOf(artifacts.candidatePackument, candidate.version);
    const newDeps = Object.keys(candDeps).filter((d) => !(d in baseDeps));
    if (newDeps.length > 0) {
      evidences.push({
        scanner: "diff",
        key: "diff:new-dependencies",
        status: "info",
        detail: `new runtime dependencies: ${newDeps.join(", ")} (checked against OSV by the osv scanner)`,
        data: newDeps,
      });
    }

    const basePat = scanPatterns(artifacts.baselineFiles);
    const candPat = scanPatterns(artifacts.candidateFiles);
    if (basePat.childProcess.length === 0 && candPat.childProcess.length > 0) {
      evidences.push({
        scanner: "diff",
        key: "diff:new-child-process",
        status: "fail",
        detail: `child_process usage appeared in this update: ${candPat.childProcess[0]}`,
        data: candPat.childProcess,
      });
    }
    const newHosts = [...candPat.endpointHosts].filter((h) => !basePat.endpointHosts.has(h));
    if (newHosts.length > 0) {
      evidences.push({
        scanner: "diff",
        key: "diff:new-endpoint",
        status: "fail",
        detail: `new outbound endpoint(s): ${newHosts.join(", ")}`,
        data: newHosts,
      });
    }

    const changes = fileChanges(artifacts.baselineFiles, artifacts.candidateFiles);
    evidences.push({
      scanner: "diff",
      key: "diff:file-changes",
      status: "info",
      detail: `files: +${changes.added.length} ~${changes.modified.length} -${changes.removed.length}`,
      data: changes,
    });

    return { scanner: "diff", status: "ok", evidences };
  },
};
