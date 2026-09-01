import { createHash } from "node:crypto";
import { aggregate, deriveFindings, filterEnabled, hasIncomplete } from "./rules.ts";
import { riskScore } from "./score.ts";
import type {
  Artifacts,
  Baseline,
  Candidate,
  EvaluationReport,
  Evidence,
  ScannerContext,
  ScanResult,
  SecurityScanner,
  VetterConfig,
} from "./types.ts";

export interface EvaluationTarget {
  candidate: Candidate;
  baseline: Baseline | null;
}

export interface CacheStore {
  get(scanner: string, pkgKey: string): Promise<ScanResult | null>;
  set(scanner: string, pkgKey: string, result: ScanResult): Promise<void>;
}

export interface EngineDeps {
  scanners: SecurityScanner[];
  config: VetterConfig;
  cache: CacheStore | null;
  buildArtifacts(target: EvaluationTarget): Promise<Artifacts>;
}

function incompleteEvidence(scanner: Evidence["scanner"], result: ScanResult): Evidence {
  const reason =
    result.status === "timeout"
      ? "timed out"
      : result.status === "quota-exhausted"
        ? "API quota exhausted"
        : `errored${result.error ? `: ${result.error}` : ""}`;
  return {
    scanner,
    key: `${scanner}:incomplete`,
    status: "incomplete",
    detail: `Scanner ${scanner} did not complete (${reason}); verdict capped at ASK (fail-closed)`,
  };
}

/**
 * Cache identity = candidate + baseline artifact digests (#37): baseline-aware
 * scanners (diff/static/osv) produce scenario-dependent results, so name@version
 * alone would cross-contaminate install vs update runs; the digests also keep a
 * mirror serving different bytes for the same version from hitting a stale
 * entry. Applied to every scanner uniformly — conservative for
 * baseline-independent ones, which only lose hits when the artifact changes.
 */
function cacheKey(ctx: ScannerContext): string {
  const { candidate, baseline, artifacts } = ctx;
  const digest = createHash("sha256")
    .update(`${artifacts.candidateIntegrity}|${artifacts.baselineIntegrity ?? ""}`)
    .digest("hex")
    .slice(0, 12);
  const base = baseline
    ? `${candidate.name}@${candidate.version}←${baseline.version}`
    : `${candidate.name}@${candidate.version}:install`;
  return `${base}#${digest}`;
}

function ageDays(packument: Artifacts["candidatePackument"], now = Date.now()): number | null {
  const created = packument.time?.created;
  if (!created) return null;
  const ms = now - Date.parse(created);
  return Number.isFinite(ms) && ms >= 0 ? Math.floor(ms / 86_400_000) : null;
}

function hasLifecycleScripts(artifacts: Artifacts, candidate: Candidate): boolean {
  const version = artifacts.candidatePackument.versions[candidate.version];
  if (!version?.scripts) return false;
  const keys = Object.keys(version.scripts);
  return keys.some((k) => k === "install" || k === "preinstall" || k === "postinstall");
}

export async function runScanner(
  deps: EngineDeps,
  scanner: SecurityScanner,
  ctx: ScannerContext,
): Promise<ScanResult> {
  const key = cacheKey(ctx);
  if (deps.cache) {
    const cached = await deps.cache.get(scanner.name, key);
    if (cached) return cached;
  }
  let result: ScanResult;
  try {
    result = await scanner.scan(ctx);
  } catch (err) {
    result = {
      scanner: scanner.name,
      status: "error",
      evidences: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
  if (deps.cache && result.status === "ok") {
    await deps.cache.set(scanner.name, key, result);
  }
  return result;
}

export async function evaluate(
  deps: EngineDeps,
  target: EvaluationTarget,
): Promise<EvaluationReport> {
  const artifacts = await deps.buildArtifacts(target);
  const ctx: ScannerContext = {
    candidate: target.candidate,
    baseline: target.baseline,
    artifacts,
  };

  const results = await Promise.all(deps.scanners.map((s) => runScanner(deps, s, ctx)));

  const evidences: Evidence[] = [];
  for (const r of results) {
    evidences.push(...r.evidences);
    if (r.status !== "ok") evidences.push(incompleteEvidence(r.scanner, r));
  }

  const findings = filterEnabled(deriveFindings(evidences), deps.config);

  const { verdict, capped } = aggregate(findings, hasIncomplete(evidences));
  const provenanceVerified = evidences.some(
    (e) => e.key === "provenance:verified" && e.status === "pass",
  );

  return {
    candidate: target.candidate,
    baseline: target.baseline,
    verdict,
    capped,
    findings,
    evidences,
    riskScore: riskScore(
      findings,
      {
        provenanceVerified,
        packageAgeDays: ageDays(artifacts.candidatePackument),
      },
      deps.config,
    ),
    hasLifecycleScripts: hasLifecycleScripts(artifacts, target.candidate),
    candidateIntegrity: artifacts.candidateIntegrity,
  };
}
