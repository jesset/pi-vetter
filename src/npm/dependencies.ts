import type { DepNode, Packument } from "../core/types.ts";

type Fetcher = (name: string, signal?: AbortSignal) => Promise<Packument>;

/**
 * Collects the transitive dependency closure of a package version from
 * registry metadata (BFS, breadth before depth), resolving each dependency to
 * its dist-tags.latest. Bounded by maxDepth (1 = direct dependencies) and
 * maxPackages; registry failures skip the node instead of aborting.
 */
export async function collectDependencies(
  root: Packument,
  rootVersion: string,
  fetchPackument: Fetcher,
  options: { maxDepth: number; maxPackages: number; signal?: AbortSignal },
): Promise<DepNode[]> {
  const collected: DepNode[] = [];
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
      const version = packument["dist-tags"]?.["latest"];
      if (!version || !packument.versions[version]) continue;
      collected.push({ name: dep.name, version });
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
