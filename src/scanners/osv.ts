import type { Evidence, ScannerContext, ScanResult, SecurityScanner } from "../core/types.ts";

const MAX_DEPS = 50;

/** Overridable OSV API base (private mirrors); read lazily per call. */
export function osvApiBase(): string {
  return process.env.PI_VETTER_OSV_API ?? "https://api.osv.dev";
}

interface OsvVulnRef {
  id: string;
  modified?: string;
}

/** Rough lower bound of an npm range for version-scoped OSV queries. */
export function lowerBound(range: string): string | null {
  if (!range || range === "*" || range === "latest" || range.startsWith("workspace:")) return null;
  const m = /^(?:\^|~|>=?|v)?(\d+)\.(\d+)(?:\.(\d+))?/.exec(range.trim());
  if (!m) return null;
  return m[3] === undefined ? `${m[1]}.${m[2]}.0` : `${m[1]}.${m[2]}.${m[3]}`;
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

export function createOsvScanner(timeoutMs = 10_000): SecurityScanner {
  return {
    name: "osv",
    layer: 1,
    async scan(ctx: ScannerContext): Promise<ScanResult> {
      try {
        const deps = depsOf(ctx);
        const depEntries = Object.entries(deps)
          .slice(0, MAX_DEPS)
          .map(([name, range]) => ({ name, version: lowerBound(range) ?? undefined }));

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
                : `new dependency ${dep.name} has advisories: ${vulns.map((v) => v.id).join(", ")}`,
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
