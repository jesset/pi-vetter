import { createHash } from "node:crypto";
import {
  type CacheStore,
  type EngineDeps,
  type EvaluationTarget,
  evaluate,
} from "../core/engine.ts";
import { runPool } from "../core/pool.ts";
import type {
  Artifacts,
  EvaluationReport,
  Packument,
  SecurityScanner,
  TarFiles,
  VetterConfig,
} from "../core/types.ts";
import { collectDependencies, depKey } from "../npm/dependencies.ts";
import { fetchDownloads, latestVersion } from "../npm/registry.ts";
import { downloadTarball, parseTarball, verifyIntegrity } from "../npm/tarball.ts";
import type { InstalledPackage } from "../settings.ts";

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
  timeoutMs = 30_000,
  deepScan?: VetterConfig["dependencies"],
): Promise<Artifacts> {
  const { candidate, baseline } = target;
  const signal = () => AbortSignal.timeout(timeoutMs);
  const packument = await fetcher(candidate.name, signal());
  const candidateMeta = packument.versions[candidate.version];
  if (!candidateMeta) {
    throw new Error(`version ${candidate.version} not found for ${candidate.name}`);
  }
  const integrity = candidateMeta.dist.integrity;
  if (!integrity) throw new Error(`no dist.integrity for ${candidate.name}@${candidate.version}`);

  const candidateBytes = await downloadTarball(candidateMeta.dist.tarball, signal());
  if (!verifyIntegrity(candidateBytes, integrity)) {
    throw new Error(`integrity mismatch downloading ${candidate.name}@${candidate.version}`);
  }
  const candidateFiles = await parseTarball(candidateBytes);

  let baselineFiles: Artifacts["baselineFiles"] = null;
  if (baseline) {
    const baselineMeta = packument.versions[baseline.version];
    if (baselineMeta) {
      const bytes = await downloadTarball(baselineMeta.dist.tarball, signal());
      baselineFiles = await parseTarball(bytes);
    }
  }

  const dependencyFiles = new Map<string, TarFiles>();
  if (deepScan?.enabled) {
    const deps = await collectDependencies(packument, candidate.version, fetcher, {
      maxDepth: deepScan.maxDepth,
      maxPackages: deepScan.maxPackages,
      signal: signal(),
    });
    await runPool(
      deps,
      async (dep) => {
        try {
          const depPackument = await fetcher(dep.name, signal());
          const meta = depPackument.versions[dep.version];
          if (!meta) return;
          const bytes = await downloadTarball(meta.dist.tarball, signal());
          dependencyFiles.set(depKey(dep), await parseTarball(bytes));
        } catch {
          // a single dependency failure must not abort the evaluation
        }
      },
      { concurrency: CONCURRENCY },
    );
  }

  const downloads = await fetchDownloads(candidate.name, signal());
  return {
    candidateFiles,
    baselineFiles,
    candidatePackument: packument,
    candidateIntegrity: integrity,
    candidateSha256: createHash("sha256").update(candidateBytes).digest("hex"),
    candidateTarball: candidateBytes,
    dependencyFiles,
    downloads,
  };
}

function lookupFailedNote(name: string, err: unknown): string {
  return `- ${name}: registry lookup failed: ${err instanceof Error ? err.message : String(err)}`;
}

export async function resolveTargets(
  deps: VetDeps,
  specs: string[],
  progress?: ProgressPort,
): Promise<{
  targets: EvaluationTarget[];
  notes: string[];
}> {
  const notes: string[] = [];
  const targets: EvaluationTarget[] = [];
  const installed = deps.listInstalled();

  if (specs.length === 0) {
    progress?.startResolve(installed.length);
    await runPool(
      installed,
      async (pkg) => {
        progress?.item(pkg.name);
        try {
          const packument = await deps.fetchPackument(pkg.name);
          const latest = latestVersion(packument);
          if (!latest || !pkg.version) {
            notes.push(`- ${pkg.name}: could not determine latest/installed version`);
          } else if (latest !== pkg.version) {
            targets.push({
              candidate: { name: pkg.name, version: latest, scenario: "update" },
              baseline: { name: pkg.name, version: pkg.version, pinned: pkg.pinned },
            });
          }
        } catch (err) {
          notes.push(lookupFailedNote(pkg.name, err));
        }
        progress?.tick();
      },
      { concurrency: CONCURRENCY },
    );
    return { targets, notes };
  }

  progress?.startResolve(specs.length);
  await runPool(
    specs,
    async (spec) => {
      const body = spec.slice("npm:".length);
      const at = body.lastIndexOf("@");
      const name = at > 0 ? body.slice(0, at) : body;
      const explicitVersion = at > 0 ? body.slice(at + 1) : undefined;
      if (!name) {
        notes.push(`- ${spec}: could not parse package name`);
        progress?.tick();
        return;
      }
      progress?.item(name);
      try {
        const packument = await deps.fetchPackument(name);
        const version = explicitVersion ?? latestVersion(packument);
        if (!version || !packument.versions[version]) {
          notes.push(`- ${name}: version ${version ?? "(latest)"} not found on registry`);
        } else {
          const already = installed.find(
            (i) => i.name === name && i.version && i.version !== version,
          );
          targets.push({
            candidate: { name, version, scenario: already ? "update" : "install" },
            baseline: already
              ? { name, version: already.version as string, pinned: already.pinned }
              : null,
          });
        }
      } catch (err) {
        notes.push(lookupFailedNote(name, err));
      }
      progress?.tick();
    },
    { concurrency: CONCURRENCY },
  );
  return { targets, notes };
}

const CONCURRENCY = 3;

/** Duck-typed surface of ProgressTracker; injected so the command layer stays UI-free. */
export interface ProgressPort {
  startResolve(total: number): void;
  start(total: number): void;
  item(name: string): void;
  tick(): void;
}

export async function runVet(
  deps: VetDeps,
  rawArgs: string,
  progress?: ProgressPort,
): Promise<VetResult> {
  const parsed = parseArgs(rawArgs);
  if ("error" in parsed) throw new Error(parsed.error);
  const { targets, notes } = await resolveTargets(deps, parsed.specs, progress);
  progress?.start(targets.length);

  const engineDeps: EngineDeps = {
    scanners: deps.scanners,
    config: deps.config,
    cache: deps.cache,
    buildArtifacts: (target) =>
      buildArtifacts(
        target,
        deps.fetchPackument,
        deps.config.network?.timeoutMs ?? 30_000,
        deps.config.dependencies,
      ),
  };

  const reports: EvaluationReport[] = [];
  await runPool(
    targets,
    async (target) => {
      const report = await evaluate(engineDeps, target);
      reports.push(report);
      progress?.tick();
    },
    {
      concurrency: CONCURRENCY,
      onItemStart: (target) => progress?.item(target.candidate.name),
      onItemError: (target, err) => {
        notes.push(
          `- ${target.candidate.name}@${target.candidate.version}: evaluation failed: ${err instanceof Error ? err.message : String(err)}`,
        );
        progress?.tick();
      },
    },
  );
  return { reports, notes };
}
