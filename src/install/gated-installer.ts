import type { EvaluationReport } from "../core/types.ts";
import { fetchPackument } from "../npm/registry.ts";

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
  | { name: string; version: string; status: "failed"; message: string };

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
    } else if (o.status === "integrity-mismatch") {
      lines.push(`- ⚠ ${o.name}@${o.version} skipped: ${o.message}`);
    } else {
      lines.push(`- ✗ ${o.name}@${o.version} failed: ${o.message}`);
    }
  }
  return lines.length > 0 ? lines.join("\n") : "Nothing installed.";
}
