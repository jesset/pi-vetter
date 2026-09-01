import { createHash } from "node:crypto";
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
  | { name: string; version: string; status: "installed-mismatch"; message: string }
  | { name: string; version: string; status: "failed"; message: string };

/** npm writes its own lockfile inside each installed package directory. */
const NPM_MANAGED_FILES = new Set([".package-lock.json"]);

export interface InstalledFileDiff {
  missing: string[];
  extra: string[];
  changed: string[];
}

/**
 * Compares the installed package directory against the digests recorded at
 * scan time (#48). Returns null when the bytes match; lists drift otherwise.
 */
export function diffInstalledFiles(
  scanned: Record<string, string>,
  installed: Map<string, Uint8Array>,
): InstalledFileDiff | null {
  const diff: InstalledFileDiff = { missing: [], extra: [], changed: [] };
  const installedPaths = new Set(
    [...installed.keys()].filter((p) => !NPM_MANAGED_FILES.has(p.split("/").pop() ?? "")),
  );
  for (const [path, digest] of Object.entries(scanned)) {
    const bytes = installed.get(path);
    if (bytes === undefined) {
      diff.missing.push(path);
    } else {
      installedPaths.delete(path);
      if (createHash("sha256").update(bytes).digest("hex") !== digest) diff.changed.push(path);
    }
  }
  diff.extra = [...installedPaths];
  return diff.missing.length + diff.extra.length + diff.changed.length > 0 ? diff : null;
}

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
  /**
   * Reads the installed package directory as path → bytes; null when the
   * install path cannot be located (#48 post-install verification). Absent
   * skips verification entirely.
   */
  readInstalledFiles?: (name: string) => Promise<Map<string, Uint8Array> | null>;
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
        }
        outcomes.push(await postInstallOutcome(report, options, installSpec(name, version)));
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
    } else if (
      o.status === "integrity-mismatch" ||
      o.status === "registry-mismatch" ||
      o.status === "installed-mismatch"
    ) {
      lines.push(
        `- ⚠ ${o.name}@${o.version} ${o.status === "installed-mismatch" ? "installed but" : "skipped:"} ${o.message}`,
      );
    } else {
      lines.push(`- ✗ ${o.name}@${o.version} failed: ${o.message}`);
    }
  }
  return lines.length > 0 ? lines.join("\n") : "Nothing installed.";
}

/**
 * #48: detection, not prevention — lifecycle scripts have already run by the
 * time we can compare bytes; the goal is that a substitution is never silent.
 */
async function postInstallOutcome(
  report: EvaluationReport,
  options: InstallOptions,
  pinCommand: string,
): Promise<InstallOutcome> {
  const { name, version } = report.candidate;
  let suffix = "";
  if (options.readInstalledFiles) {
    const installed = await options.readInstalledFiles(name).catch(() => null);
    if (!installed) {
      suffix = "; post-install verification unavailable (installed files not found)";
    } else {
      const diff = diffInstalledFiles(report.candidateFileDigests, installed);
      if (diff) {
        const drift = [
          ...diff.missing.map((p) => `missing ${p}`),
          ...diff.changed.map((p) => `changed ${p}`),
          ...diff.extra.map((p) => `unexpected ${p}`),
        ]
          .slice(0, 5)
          .join(", ");
        return {
          name,
          version,
          status: "installed-mismatch",
          message: `installed bytes differ from the vetted artifact (${drift}) — remove with: pi remove ${installSpec(name, version)} and re-vet`,
        };
      }
      suffix = "; on-disk files match the vetted artifact";
    }
  }
  const base = options.pinOnInstall !== true ? `to pin: pi install ${pinCommand}` : undefined;
  const message = [base, suffix].filter(Boolean).join("");
  return message
    ? { name, version, status: "installed", message }
    : { name, version, status: "installed" };
}
