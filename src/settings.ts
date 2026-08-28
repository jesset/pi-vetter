import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DefaultPackageManager, SettingsManager } from "@earendil-works/pi-coding-agent";

export const DEFAULT_AGENT_DIR = join(homedir(), ".pi", "agent");

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

export function createPackageManager(
  cwd = process.cwd(),
  agentDir = DEFAULT_AGENT_DIR,
): DefaultPackageManager {
  const settingsManager = SettingsManager.create(cwd, agentDir);
  return new DefaultPackageManager({ cwd, agentDir, settingsManager });
}

export function listInstalledPackages(pm: DefaultPackageManager): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  for (const configured of pm.listConfiguredPackages()) {
    const spec = npmSpecFromSource(configured.source);
    if (!spec) continue; // git/local sources are out of scope for MVP
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
  return out;
}
