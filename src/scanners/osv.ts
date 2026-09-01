import type {
  Evidence,
  Packument,
  ScannerContext,
  ScanResult,
  SecurityScanner,
} from "../core/types.ts";
import { resolveVersion } from "../npm/dependencies.ts";
import { fetchPackument } from "../npm/registry.ts";

const MAX_DEPS = 50;

/** Overridable OSV API base (private mirrors); read lazily per call. */
export function osvApiBase(): string {
  return process.env.PI_VETTER_OSV_API ?? "https://api.osv.dev";
}

interface OsvVulnRef {
  id: string;
  modified?: string;
}

type Fetcher = (name: string, signal?: AbortSignal) => Promise<Packument>;

/** Rough lower bound of an npm range for version-scoped OSV queries. */
export function lowerBound(range: string): string | null {
  if (!range || range === "*" || range === "latest" || range.startsWith("workspace:")) return null;
  const m = /^(?:\^|~|>=?|v)?(\d+)\.(\d+)(?:\.(\d+))?/.exec(range.trim());
  if (!m) return null;
  return m[3] === undefined ? `${m[1]}.${m[2]}.0` : `${m[1]}.${m[2]}.${m[3]}`;
}

/**
 * The version npm would actually install for a declared range (highest
 * published in-range version), falling back to the range's lower bound when
 * resolution fails; undefined keeps the query version-less (unparseable
 * ranges: git/workspace specs).
 */
async function resolveDepVersion(
  name: string,
  range: string,
  fetcher: Fetcher,
  timeoutMs: number,
): Promise<string | undefined> {
  const lower = lowerBound(range);
  if (lower === null) return undefined;
  try {
    const packument = await fetcher(name, AbortSignal.timeout(timeoutMs));
    return resolveVersion(range, packument) ?? lower;
  } catch {
    return lower;
  }
}

function depsOf(ctx: ScannerContext): Record<string, string> {
  const { artifacts, candidate, baseline } = ctx;
  const current = artifacts.candidatePackument.versions[candidate.version]?.dependencies ?? {};
  if (!baseline) return current;
  const previous = artifacts.candidatePackument.versions[baseline.version]?.dependencies ?? {};
  return Object.fromEntries(Object.entries(current).filter(([d]) => !(d in previous)));
}

async function queryBatch(
  queries: Array<{ name: string; version: string | undefined }>,
  timeoutMs: number,
): Promise<OsvVulnRef[][]> {
  const res = await fetch(`${osvApiBase()}/v1/querybatch`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      queries: queries.map((q) => ({
        package: { name: q.name, ecosystem: "npm" },
        ...(q.version ? { version: q.version } : {}),
      })),
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`OSV querybatch failed: HTTP ${res.status}`);
  const body = (await res.json()) as { results?: Array<{ vulns?: OsvVulnRef[] }> };
  return (body.results ?? []).map((r) => r.vulns ?? []);
}

export function createOsvScanner(options?: {
  timeoutMs?: number;
  fetcher?: Fetcher;
}): SecurityScanner {
  const timeoutMs = options?.timeoutMs ?? 10_000;
  const fetcher = options?.fetcher ?? fetchPackument;
  return {
    name: "osv",
    layer: 1,
    async scan(ctx: ScannerContext): Promise<ScanResult> {
      try {
        const deps = depsOf(ctx);
        const depList = Object.entries(deps).slice(0, MAX_DEPS);
        const versions = await Promise.all(
          depList.map(([name, range]) => resolveDepVersion(name, range, fetcher, timeoutMs)),
        );
        const depEntries = depList.map(([name], i) => ({ name, version: versions[i] }));

        const queries = [
          { name: ctx.candidate.name, version: ctx.candidate.version as string | undefined },
          ...depEntries.map((d) => ({ name: d.name, version: d.version as string | undefined })),
        ];
        const results = await queryBatch(queries, timeoutMs);
        const evidences: Evidence[] = [];

        const [candidateVulns, ...depVulns] = results;
        const malicious = (candidateVulns ?? []).filter((v) => v.id.startsWith("MAL-"));
        const advisories = (candidateVulns ?? []).filter((v) => !v.id.startsWith("MAL-"));

        if (malicious.length > 0) {
          evidences.push({
            scanner: "osv",
            key: "osv:malicious",
            status: "fail",
            detail: `package listed as malicious: ${malicious.map((v) => v.id).join(", ")}`,
            data: malicious,
          });
        }
        if (advisories.length > 0) {
          evidences.push({
            scanner: "osv",
            key: "osv:vulnerability",
            status: "fail",
            detail: `known vulnerability advisories: ${advisories.map((v) => v.id).join(", ")}`,
            data: advisories,
          });
        }

        for (const [i, vulns] of depVulns.entries()) {
          if (vulns.length === 0) continue;
          const dep = depEntries[i];
          if (!dep) continue;
          const depMal = vulns.filter((v) => v.id.startsWith("MAL-"));
          const key = depMal.length > 0 ? "osv:malicious" : "osv:new-dependency-advisory";
          evidences.push({
            scanner: "osv",
            key,
            status: "fail",
            detail:
              depMal.length > 0
                ? `new dependency ${dep.name}@${dep.version ?? "*"} is listed as malicious: ${depMal.map((v) => v.id).join(", ")}`
                : `new dependency ${dep.name}@${dep.version ?? "*"} has advisories: ${vulns.map((v) => v.id).join(", ")}`,
            data: { dependency: dep, vulns },
          });
        }

        if (evidences.length === 0) {
          evidences.push({
            scanner: "osv",
            key: "osv:clean",
            status: "pass",
            detail: `no OSV advisories for ${ctx.candidate.name}@${ctx.candidate.version}${depEntries.length > 0 ? ` or its ${depEntries.length} new/first-party dependencies` : ""}`,
          });
        }

        return { scanner: "osv", status: "ok", evidences };
      } catch (err) {
        if (err instanceof Error && err.name === "TimeoutError") {
          return { scanner: "osv", status: "timeout", evidences: [] };
        }
        throw err;
      }
    },
  };
}
