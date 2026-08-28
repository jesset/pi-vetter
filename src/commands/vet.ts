import {
  type CacheStore,
  type EngineDeps,
  type EvaluationTarget,
  evaluate,
} from "../core/engine.ts";
import type {
  Artifacts,
  EvaluationReport,
  Packument,
  SecurityScanner,
  VetterConfig,
} from "../core/types.ts";
import { fetchDownloads, fetchPackument, latestVersion } from "../npm/registry.ts";
import { downloadTarball, parseTarball, verifyIntegrity } from "../npm/tarball.ts";
import { type InstalledPackage, listInstalledPackages } from "../settings.ts";

export type ParsedArgs = { specs: string[] } | { error: string };

export function parseArgs(raw: string): ParsedArgs {
  const tokens = raw.trim().split(/\s+/).filter(Boolean);
  if (tokens.some((t) => t === "installed" || t === "--installed")) {
    return {
      error:
        "plain `/vet` or `/vet-install` already implies installed packages; pass explicit specs or nothing",
    };
  }
  for (const token of tokens) {
    if (!token.startsWith("npm:")) {
      return { error: `unsupported spec "${token}" — expected npm:<pkg>[@<version>]` };
    }
  }
  return { specs: tokens };
}

export interface VetDeps {
  config: VetterConfig;
  cache: CacheStore;
  scanners: SecurityScanner[];
  listInstalled: () => InstalledPackage[];
  fetchPackument: (name: string, signal?: AbortSignal) => Promise<Packument>;
}

export interface VetResult {
  reports: EvaluationReport[];
  notes: string[];
}

export async function buildArtifacts(
  target: EvaluationTarget,
  fetcher: VetDeps["fetchPackument"],
  signal?: AbortSignal,
): Promise<Artifacts> {
  const { candidate, baseline } = target;
  const packument = await fetcher(candidate.name, signal);
  const candidateMeta = packument.versions[candidate.version];
  if (!candidateMeta) {
    throw new Error(`version ${candidate.version} not found for ${candidate.name}`);
  }
  const integrity = candidateMeta.dist.integrity;
  if (!integrity) throw new Error(`no dist.integrity for ${candidate.name}@${candidate.version}`);

  const candidateBytes = await downloadTarball(candidateMeta.dist.tarball, signal);
  if (!verifyIntegrity(candidateBytes, integrity)) {
    throw new Error(`integrity mismatch downloading ${candidate.name}@${candidate.version}`);
  }
  const candidateFiles = await parseTarball(candidateBytes);

  let baselineFiles: Artifacts["baselineFiles"] = null;
  if (baseline) {
    const baselineMeta = packument.versions[baseline.version];
    if (baselineMeta) {
      const bytes = await downloadTarball(baselineMeta.dist.tarball, signal);
      baselineFiles = await parseTarball(bytes);
    }
  }

  const downloads = await fetchDownloads(candidate.name, signal);
  return {
    candidateFiles,
    baselineFiles,
    candidatePackument: packument,
    candidateIntegrity: integrity,
    downloads,
  };
}

export async function resolveTargets(
  deps: VetDeps,
  specs: string[],
): Promise<{
  targets: EvaluationTarget[];
  notes: string[];
}> {
  const notes: string[] = [];
  const targets: EvaluationTarget[] = [];
  const installed = deps.listInstalled();

  if (specs.length === 0) {
    for (const pkg of installed) {
      if (pkg.pinned) {
        notes.push(`- ${pkg.name}: pinned (${pkg.source}); skipped by design`);
        continue;
      }
      let packument: Awaited<ReturnType<VetDeps["fetchPackument"]>>;
      try {
        packument = await deps.fetchPackument(pkg.name);
      } catch (err) {
        notes.push(
          `- ${pkg.name}: registry lookup failed: ${err instanceof Error ? err.message : String(err)}`,
        );
        continue;
      }
      const latest = latestVersion(packument);
      if (!latest || !pkg.version) {
        notes.push(`- ${pkg.name}: could not determine latest/installed version`);
        continue;
      }
      if (latest === pkg.version) continue;
      targets.push({
        candidate: { name: pkg.name, version: latest, scenario: "update" },
        baseline: { name: pkg.name, version: pkg.version },
      });
    }
    return { targets, notes };
  }

  for (const spec of specs) {
    const body = spec.slice("npm:".length);
    const at = body.lastIndexOf("@");
    const name = at > 0 ? body.slice(0, at) : body;
    const explicitVersion = at > 0 ? body.slice(at + 1) : undefined;
    if (!name) {
      notes.push(`- ${spec}: could not parse package name`);
      continue;
    }
    let packument: Awaited<ReturnType<VetDeps["fetchPackument"]>>;
    try {
      packument = await deps.fetchPackument(name);
    } catch (err) {
      notes.push(
        `- ${name}: registry lookup failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      continue;
    }
    const version = explicitVersion ?? latestVersion(packument);
    if (!version || !packument.versions[version]) {
      notes.push(`- ${name}: version ${version ?? "(latest)"} not found on registry`);
      continue;
    }
    const already = installed.find((i) => i.name === name && i.version && i.version !== version);
    targets.push({
      candidate: { name, version, scenario: already ? "update" : "install" },
      baseline: already ? { name, version: already.version as string } : null,
    });
  }
  return { targets, notes };
}

export async function runVet(deps: VetDeps, rawArgs: string): Promise<VetResult> {
  const parsed = parseArgs(rawArgs);
  if ("error" in parsed) throw new Error(parsed.error);
  const { targets, notes } = await resolveTargets(deps, parsed.specs);

  const engineDeps: EngineDeps = {
    scanners: deps.scanners,
    config: deps.config,
    cache: deps.cache,
    buildArtifacts: (target) => buildArtifacts(target, deps.fetchPackument),
  };

  const reports: EvaluationReport[] = [];
  for (const target of targets) {
    try {
      reports.push(await evaluate(engineDeps, target));
    } catch (err) {
      notes.push(
        `- ${target.candidate.name}@${target.candidate.version}: evaluation failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  return { reports, notes };
}
