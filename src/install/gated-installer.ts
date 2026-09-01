import type { EvaluationReport } from "../core/types.ts";
import { fetchPackument, npmRegistryBase } from "../npm/registry.ts";

export type ExecFn = (
  command: string,
  args: string[],
  options?: { cwd?: string; timeout?: number },
) => Promise<{
  stdout: string;
  stderr: string;
  code: number;
}>;

export type InstallOutcome =
  | { name: string; version: string; status: "installed"; message?: string }
  | {
      name: string;
      version: string;
      status: "integrity-mismatch";
      message: string;
    }
  | { name: string; version: string; status: "registry-mismatch"; message: string }
  | { name: string; version: string; status: "failed"; message: string };

const trimSlashes = (url: string): string => url.replace(/\/+$/, "");

/**
 * #43: the integrity re-check queries the vetting registry, but `pi install`
 * resolves through the user's npm config — when those endpoints differ the
 * re-check cannot vouch for what npm fetches, so we fail closed.
 */
async function probeInstallRegistry(exec: ExecFn): Promise<{ url: string } | { error: string }> {
  try {
    const result = await exec("npm", ["config", "get", "registry"], { timeout: 10_000 });
    if (result.code !== 0) {
      return { error: `npm config get registry exited ${result.code}` };
    }
    const url = result.stdout.trim();
    if (!url) return { error: "npm config get registry returned empty output" };
    return { url };
  } catch (err) {
    return {
      error: `npm config get registry failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export function installSpec(name: string, version: string): string {
  return `npm:${name}@${version}`;
}

export interface InstallOptions {
  /**
   * Restores the settings entry to an unpinned spec after install, so future
   * updates flow through normal channels (issue #16: pinning is the user's
   * explicit decision, not an evaluator side effect). Default behaviour.
   */
  unpin?: (name: string, version: string) => void;
  /** Keep the pinned spec written by `pi install` (legacy behaviour). */
  pinOnInstall?: boolean;
}

/**
 * Install the exact vetted version via `pi install npm:<pkg>@<version>`
 * (single-install precision, TOCTOU-guarded by the integrity re-check).
 * By default the resulting pinned spec is then reverted (#16): evaluation
 * must not silently decide the package's long-term update policy.
 */
export async function installApproved(
  exec: ExecFn,
  reports: EvaluationReport[],
  options: InstallOptions = {},
  signal?: AbortSignal,
): Promise<InstallOutcome[]> {
  const outcomes: InstallOutcome[] = [];
  const vettingBase = trimSlashes(npmRegistryBase());
  const probe = await probeInstallRegistry(exec);
  if ("error" in probe) {
    return reports.map(({ candidate }) => ({
      name: candidate.name,
      version: candidate.version,
      status: "failed" as const,
      message: `could not confirm the install registry matches the vetting registry (${probe.error}); set PI_VETTER_NPM_REGISTRY to your install registry and re-run /vet-install`,
    }));
  }
  if (trimSlashes(probe.url) !== vettingBase) {
    return reports.map(({ candidate }) => ({
      name: candidate.name,
      version: candidate.version,
      status: "registry-mismatch" as const,
      message: `vetting registry ${vettingBase} differs from install registry ${trimSlashes(probe.url)}; set PI_VETTER_NPM_REGISTRY to your install registry and re-run /vet-install`,
    }));
  }

  for (const report of reports) {
    const { name, version } = report.candidate;
    try {
      const packument = await fetchPackument(name, signal ?? undefined);
      const fresh = packument.versions[version]?.dist?.integrity;
      if (!fresh || fresh !== report.candidateIntegrity) {
        outcomes.push({
          name,
          version,
          status: "integrity-mismatch",
          message: "registry integrity changed after vetting; re-run /vet before installing",
        });
        continue;
      }
    } catch (err) {
      outcomes.push({
        name,
        version,
        status: "failed",
        message: `could not re-check integrity: ${err instanceof Error ? err.message : String(err)}`,
      });
      continue;
    }

    try {
      const result = await exec("pi", ["install", installSpec(name, version)]);
      if (result.code === 0) {
        if (options.pinOnInstall !== true && options.unpin) {
          options.unpin(name, version);
          outcomes.push({
            name,
            version,
            status: "installed",
            message: `to pin: pi install ${installSpec(name, version)}`,
          });
        } else {
          outcomes.push({ name, version, status: "installed" });
        }
      } else {
        outcomes.push({
          name,
          version,
          status: "failed",
          message: `pi install exited ${result.code}: ${result.stderr.trim().slice(0, 200)}`,
        });
      }
    } catch (err) {
      outcomes.push({
        name,
        version,
        status: "failed",
        message: `pi install could not run: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }
  return outcomes;
}

export function renderOutcomes(outcomes: InstallOutcome[]): string {
  const lines: string[] = [];
  for (const o of outcomes) {
    if (o.status === "installed") {
      lines.push(`- ✓ ${o.name}@${o.version} installed${o.message ? ` — ${o.message}` : ""}`);
    } else if (o.status === "integrity-mismatch" || o.status === "registry-mismatch") {
      lines.push(`- ⚠ ${o.name}@${o.version} skipped: ${o.message}`);
    } else {
      lines.push(`- ✗ ${o.name}@${o.version} failed: ${o.message}`);
    }
  }
  return lines.length > 0 ? lines.join("\n") : "Nothing installed.";
}
