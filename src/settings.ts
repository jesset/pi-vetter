import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DefaultPackageManager, SettingsManager } from "@earendil-works/pi-coding-agent";

export const DEFAULT_AGENT_DIR = join(homedir(), ".pi", "agent");

export function agentDir(explicit?: string): string {
  return explicit ?? process.env.PI_VETTER_AGENT_DIR ?? DEFAULT_AGENT_DIR;
}

export interface InstalledPackage {
  source: string; // e.g. npm:foo@1.2.3
  name: string;
  version: string | null;
  pinned: boolean;
  scope: "user" | "project";
}

export function npmSpecFromSource(source: string): { name: string; pinned: boolean } | null {
  if (!source.startsWith("npm:")) return null;
  const spec = source.slice("npm:".length);
  const at = spec.lastIndexOf("@");
  if (at <= 0) return { name: spec, pinned: false };
  return { name: spec.slice(0, at), pinned: true };
}

export function createPackageManager(cwd = process.cwd(), dir?: string): DefaultPackageManager {
  const root = agentDir(dir);
  const settingsManager = SettingsManager.create(cwd, root);
  return new DefaultPackageManager({ cwd, agentDir: root, settingsManager });
}

export interface InstalledInventory {
  packages: InstalledPackage[];
  skippedSources: string[]; // non-npm sources, disclosed instead of silently dropped (#23)
}

export function listInstalledPackages(pm: DefaultPackageManager): InstalledInventory {
  const out: InstalledPackage[] = [];
  const skipped: string[] = [];
  for (const configured of pm.listConfiguredPackages()) {
    const spec = npmSpecFromSource(configured.source);
    if (!spec) {
      skipped.push(configured.source);
      continue;
    }
    let version: string | null = null;
    if (configured.installedPath) {
      try {
        const pkg = JSON.parse(
          readFileSync(join(configured.installedPath, "package.json"), "utf8"),
        ) as { version?: string };
        version = pkg.version ?? null;
      } catch {
        version = null;
      }
    }
    out.push({
      source: configured.source,
      name: spec.name,
      version,
      pinned: spec.pinned,
      scope: configured.scope,
    });
  }
  return { packages: out, skippedSources: skipped };
}
