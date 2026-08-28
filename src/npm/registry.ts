import type { Packument } from "../core/types.ts";

const REGISTRY = "https://registry.npmjs.org";
const DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-month";

function packumentUrl(name: string): string {
  return `${REGISTRY}/${encodeURIComponent(name).replace("%40", "@")}`;
}

export async function fetchPackument(name: string, signal?: AbortSignal): Promise<Packument> {
  const res = await fetch(packumentUrl(name), {
    signal: signal ?? null,
    headers: { accept: "application/json" },
  });
  if (res.status === 404) throw new Error(`package not found on registry: ${name}`);
  if (!res.ok) throw new Error(`packument fetch failed for ${name}: HTTP ${res.status}`);
  return (await res.json()) as Packument;
}

export async function fetchDownloads(name: string, signal?: AbortSignal): Promise<number> {
  try {
    const res = await fetch(`${DOWNLOADS_API}/${encodeURIComponent(name)}`, {
      signal: signal ?? null,
    });
    if (!res.ok) return 0;
    const body = (await res.json()) as { downloads?: number };
    return body.downloads ?? 0;
  } catch {
    return 0;
  }
}

export function latestVersion(packument: Packument): string | undefined {
  return packument["dist-tags"]?.latest;
}
