import { createHash } from "node:crypto";
import { type ScannerConfigGap, scannerConfigGaps } from "../config.ts";
import {
  type CacheStore,
  type EngineDeps,
  type EvaluationTarget,
  evaluate,
} from "../core/engine.ts";
import { runPool } from "../core/pool.ts";
import { disabledRules, RULES } from "../core/rules.ts";
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
import type { InstalledInventory } from "../settings.ts";

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
  listInstalled: () => InstalledInventory;
  fetchPackument: (name: string, signal?: AbortSignal) => Promise<Packument>;
}

export interface VetResult {
  reports: EvaluationReport[];
  notes: string[];
}

/**
 * Downloads a tarball and verifies it against the version's registry
 * dist.integrity (candidate and baseline share this trust path; dependency
 * tarballs deliberately use a silent-skip policy instead).
 */
async function downloadVerified(
  name: string,
  version: string,
  meta: { dist: { tarball: string; integrity?: string } },
  signal: AbortSignal,
  role = "",
): Promise<Uint8Array> {
  const integrity = meta.dist.integrity;
  const label = role ? `${role} ${name}@${version}` : `${name}@${version}`;
  if (!integrity) throw new Error(`no dist.integrity for ${label}`);
  const bytes = await downloadTarball(meta.dist.tarball, signal);
  if (!verifyIntegrity(bytes, integrity)) {
    throw new Error(`integrity mismatch downloading ${label}`);
  }
  return bytes;
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

  const candidateBytes = await downloadVerified(
    candidate.name,
    candidate.version,
    candidateMeta,
    signal(),
  );
  const candidateFiles = await parseTarball(candidateBytes);

  let baselineFiles: Artifacts["baselineFiles"] = null;
  let baselineIntegrity: Artifacts["baselineIntegrity"] = null;
  if (baseline) {
    const baselineMeta = packument.versions[baseline.version];
    if (baselineMeta) {
      const bytes = await downloadVerified(
        baseline.name,
        baseline.version,
        baselineMeta,
        signal(),
        "baseline",
      );
      baselineIntegrity = baselineMeta.dist.integrity ?? null;
      baselineFiles = await parseTarball(bytes);
    }
  }

  const dependencyFiles = new Map<string, TarFiles>();
  let dependencySkipped = 0;
  if (deepScan?.enabled) {
    const deps = await collectDependencies(packument, candidate.version, fetcher, {
      maxDepth: deepScan.maxDepth,
      maxPackages: deepScan.maxPackages,
      signal: signal(),
    });
    await runPool(
      deps,
      async (entry) => {
        try {
          const meta = entry.packument.versions[entry.node.version];
          if (!meta) {
            dependencySkipped += 1;
            return;
          }
          const bytes = await downloadTarball(meta.dist.tarball, signal());
          if (meta.dist.integrity && !verifyIntegrity(bytes, meta.dist.integrity)) {
            dependencySkipped += 1;
            return;
          }
          dependencyFiles.set(depKey(entry.node), await parseTarball(bytes));
        } catch {
          dependencySkipped += 1;
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
    baselineIntegrity,
    candidateSha256: createHash("sha256").update(candidateBytes).digest("hex"),
    candidateTarball: candidateBytes,
    dependencyFiles,
    dependencySkipped,
    downloads,
  };
}

function lookupFailedNote(name: string, err: unknown): string {
  return `- ${name}: registry lookup failed: ${err instanceof Error ? err.message : String(err)}`;
}

const FREE_KEY_HINT: Record<ScannerConfigGap["name"], string> = {
  virustotal: "free public key: register at virustotal.com",
  socket: "free tier key: register at socket.dev",
};

/** #33: a scanner declared enabled without credentials must be disclosed, not silently skipped. */
export function scannerGapNotes(config: VetterConfig): string[] {
  return scannerConfigGaps(config).map(
    (gap) =>
      `- ${gap.name}: enabled but not configured (${gap.missing.join(", ")} missing) — scanner skipped (${FREE_KEY_HINT[gap.name]})`,
  );
}

/** #42: rules the user disabled shape the verdict; the report must say so. */
export function policyNotes(config: VetterConfig): string[] {
  return disabledRules(config).map(
    (ruleId) =>
      `- rule "${ruleId}" disabled by config (default: ${RULES[ruleId].kind}) — its findings are suppressed`,
  );
}

/** Parse an `npm:<pkg>[@<version>]` spec into its name and optional version. */
function parseSpec(spec: string): { name: string; version?: string } {
  const body = spec.slice("npm:".length);
  const at = body.lastIndexOf("@");
  return at > 0 ? { name: body.slice(0, at), version: body.slice(at + 1) } : { name: body };
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
  const { packages: installed, skippedSources } = deps.listInstalled();

  if (specs.length === 0) {
    progress?.startResolve(installed.map((p) => p.name));
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
        progress?.tick(pkg.name);
      },
      { concurrency: CONCURRENCY },
    );
    for (const source of skippedSources) {
      notes.push(`- ${source}: not an npm source, out of scope`);
    }
    return { targets, notes };
  }

  progress?.startResolve(specs.map((s) => parseSpec(s).name || s));
  await runPool(
    specs,
    async (spec) => {
      const { name, version: explicitVersion } = parseSpec(spec);
      if (!name) {
        notes.push(`- ${spec}: could not parse package name`);
        progress?.tick(spec);
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
      progress?.tick(name);
    },
    { concurrency: CONCURRENCY },
  );
  return { targets, notes };
}

const CONCURRENCY = 3;

/** Duck-typed surface of ProgressTracker; injected so the command layer stays UI-free. */
export interface ProgressPort {
  startResolve(names: string[]): void;
  start(names: string[]): void;
  item(name: string): void;
  tick(name: string): void;
  /** Tears the progress display down early (e.g. before a blocking dialog). */
  finish?(): void;
}

export async function runVet(
  deps: VetDeps,
  rawArgs: string,
  progress?: ProgressPort,
): Promise<VetResult> {
  const parsed = parseArgs(rawArgs);
  if ("error" in parsed) throw new Error(parsed.error);
  const { targets, notes: resolvedNotes } = await resolveTargets(deps, parsed.specs, progress);
  const notes = [...scannerGapNotes(deps.config), ...policyNotes(deps.config), ...resolvedNotes];
  progress?.start(targets.map((t) => t.candidate.name));

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
      progress?.tick(target.candidate.name);
    },
    {
      concurrency: CONCURRENCY,
      onItemStart: (target) => progress?.item(target.candidate.name),
      onItemError: (target, err) => {
        notes.push(
          `- ${target.candidate.name}@${target.candidate.version}: evaluation failed: ${err instanceof Error ? err.message : String(err)}`,
        );
        progress?.tick(target.candidate.name);
      },
    },
  );
  return { reports, notes };
}
