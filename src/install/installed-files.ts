import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { DefaultPackageManager } from "@earendil-works/pi-coding-agent";
import { npmSpecFromSource } from "../settings.ts";

/** Regular files under dir, as package-internal relative path → bytes. */
export function readTreeFiles(dir: string): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  const walk = (current: string, prefix: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(full, rel);
      } else if (entry.isFile()) {
        out.set(rel, new Uint8Array(readFileSync(full)));
      }
    }
  };
  walk(dir, "");
  return out;
}

/**
 * #48: reads the installed package directory pi tracks for a configured npm
 * source (pinned or unpinned); null when it cannot be located.
 */
export function createInstalledFilesReader(
  pm: DefaultPackageManager,
): (name: string) => Promise<Map<string, Uint8Array> | null> {
  return (name: string) => {
    try {
      const configured = pm.listConfiguredPackages().find((c) => {
        const spec = npmSpecFromSource(c.source);
        return spec?.name === name;
      });
      if (!configured?.installedPath) return Promise.resolve(null);
      return Promise.resolve(readTreeFiles(configured.installedPath));
    } catch {
      return Promise.resolve(null);
    }
  };
}
