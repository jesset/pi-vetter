import type { DepNode, Packument } from "../core/types.ts";

export type Fetcher = (name: string, signal?: AbortSignal) => Promise<Packument>;

export interface DependencyEntry {
  node: DepNode;
  packument: Packument;
}

function parseVersion(v: string): number[] {
  return v.split(".").map((part) => Number.parseInt(part, 10) || 0);
}

export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export interface SimpleRange {
  /** Inclusive lower bound implied by the range. */
  lower: string;
  /** Exclusive upper bound, or null for exact/>= ranges. */
  upper: string | null;
}

/**
 * Parses the single-term semver shapes we resolve locally (`^1.2.0`, `~1.2`,
 * `1.2.3`, `>=1.2.0`); composite/hyphen/wildcard/or ranges return null.
 */
export function parseSimpleRange(range: string): SimpleRange | null {
  const m = /^(\^|~|>=|=|v)?(\d+)\.(\d+)(?:\.(\d+))?$/.exec(range.trim());
  if (!m) return null;
  const [, op, maj, min, patch] = m;
  return {
    lower: `${maj}.${min}.${patch ?? 0}`,
    upper:
      op === "~" ? `${maj}.${Number(min) + 1}.0` : op === "^" ? `${Number(maj) + 1}.0.0` : null,
  };
}

/**
 * Resolves a dependency range to the highest published version satisfying it
 * (single-term semver shapes only; prerelease tags ignored). Falls back to
 * dist-tags.latest for shapes we do not parse (`*`, git/workspace specs) or
 * when no in-range version exists.
 */
export function resolveVersion(range: string, packument: Packument): string | undefined {
  const latest = packument["dist-tags"]?.latest;
  const parsed = parseSimpleRange(range);
  if (!parsed) return latest;

  const candidates = Object.keys(packument.versions)
    .filter((v) => !v.includes("-"))
    .filter(
      (v) =>
        compareVersions(v, parsed.lower) >= 0 &&
        (parsed.upper === null || compareVersions(v, parsed.upper) < 0),
    )
    .sort(compareVersions);
  return candidates.length > 0 ? candidates[candidates.length - 1] : latest;
}

/**
 * Collects the transitive dependency closure of a package version from
 * registry metadata (BFS, breadth before depth), resolving each dependency to
 * the highest version inside its declared range. Bounded by maxDepth (1 =
 * direct dependencies) and maxPackages; registry failures skip the node
 * instead of aborting. Packuments are returned alongside so callers do not
 * need to re-fetch them.
 */
export async function collectDependencies(
  root: Packument,
  rootVersion: string,
  fetchPackument: Fetcher,
  options: { maxDepth: number; maxPackages: number; signal?: AbortSignal },
): Promise<DependencyEntry[]> {
  const collected: DependencyEntry[] = [];
  const seen = new Set<string>();

  let frontier: Array<{ name: string; range: string }> = Object.entries(
    root.versions[rootVersion]?.dependencies ?? {},
  ).map(([name, range]) => ({ name, range }));

  for (let depth = 0; depth < options.maxDepth && frontier.length > 0; depth++) {
    const next: Array<{ name: string; range: string }> = [];
    for (const dep of frontier) {
      if (collected.length >= options.maxPackages) break;
      if (seen.has(dep.name)) continue;
      seen.add(dep.name);
      let packument: Packument;
      try {
        packument = await fetchPackument(dep.name, options.signal);
      } catch {
        continue;
      }
      const version = resolveVersion(dep.range, packument);
      if (!version || !packument.versions[version]) continue;
      collected.push({ node: { name: dep.name, version }, packument });
      if (collected.length < options.maxPackages) {
        for (const [name, range] of Object.entries(
          packument.versions[version]?.dependencies ?? {},
        )) {
          if (!seen.has(name)) next.push({ name, range });
        }
      }
    }
    frontier = next;
  }
  return collected;
}

export function depKey(node: DepNode): string {
  return `${node.name}@${node.version}`;
}
