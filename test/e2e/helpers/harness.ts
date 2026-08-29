import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileCache } from "../../../src/cache.ts";
import type { VetDeps } from "../../../src/commands/vet.ts";
import { createMaintainerSnapshotStore, loadConfig } from "../../../src/config.ts";
import { fetchPackument } from "../../../src/npm/registry.ts";
import { diffScanner } from "../../../src/scanners/diff.ts";
import { createMetadataScanner } from "../../../src/scanners/metadata.ts";
import { createOsvScanner } from "../../../src/scanners/osv.ts";
import { createProvenanceScanner } from "../../../src/scanners/provenance.ts";
import { staticScanner } from "../../../src/scanners/static-analysis.ts";
import type { InstalledPackage } from "../../../src/settings.ts";
import type { FakeRegistry } from "./fake-registry.ts";
import { startFakeRegistry } from "./fake-registry.ts";
import type { FixturePackage } from "./fixtures.ts";
import { buildRegistryState } from "./fixtures.ts";

export interface HarnessOptions {
  fixtures: FixturePackage[];
  /** Installed inventory served to the command layer. Default: nothing installed. */
  installed?: InstalledPackage[];
  /** Non-npm sources disclosed via notes (#23). */
  skippedSources?: string[];
  /** Initial OSV advisory ids per package name (mutable via registry.osvVulns). */
  osvHits?: Record<string, string[]>;
  /** OSV scanner timeout (default 10s); shrink for timeout-fault scenarios. */
  osvTimeoutMs?: number;
  /** Disable the scan-result cache (cross-run state scenarios; cache hits would mask the second run's scanners). */
  cacheEnabled?: boolean;
}

export interface VetHarness {
  /** Real command-layer deps; pass to runVet / runVetInstall. */
  deps: VetDeps;
  registry: FakeRegistry;
  /** Temp data dir (config, cache, maintainer snapshots) — never ~/.pi. */
  dataDir: string;
}

const ENV_KEYS = [
  "PI_VETTER_NPM_REGISTRY",
  "PI_VETTER_DOWNLOADS_API",
  "PI_VETTER_OSV_API",
  "PI_VETTER_DATA_DIR",
] as const;

/**
 * Boots the full stack against a local fake registry: real scanners, real
 * file cache, real config loading — everything except the real network.
 * Restores env and shuts the server down when fn settles.
 */
export async function withHarness<T>(
  opts: HarnessOptions,
  fn: (harness: VetHarness) => Promise<T>,
): Promise<T> {
  const dataDir = mkdtempSync(join(tmpdir(), "pi-vetter-e2e-"));
  const registry = await startFakeRegistry((base) => buildRegistryState(opts.fixtures, base));
  for (const [name, ids] of Object.entries(opts.osvHits ?? {})) {
    registry.osvVulns.set(name, ids);
  }

  const saved = ENV_KEYS.map((key) => [key, process.env[key]] as const);
  process.env.PI_VETTER_NPM_REGISTRY = registry.url;
  process.env.PI_VETTER_DOWNLOADS_API = registry.downloadsUrl;
  process.env.PI_VETTER_OSV_API = registry.osvUrl;
  process.env.PI_VETTER_DATA_DIR = dataDir;

  try {
    const config = loadConfig(dataDir);
    if (opts.cacheEnabled === false) config.cache.enabled = false;
    const deps: VetDeps = {
      config,
      cache: createFileCache(join(dataDir, "cache"), config.cache),
      scanners: [
        createMetadataScanner(createMaintainerSnapshotStore(dataDir)),
        createOsvScanner(opts.osvTimeoutMs ?? config.scanners.osv?.timeoutMs ?? 10_000),
        createProvenanceScanner({ timeoutMs: config.scanners.provenance?.timeoutMs ?? 10_000 }),
        staticScanner,
        diffScanner,
      ],
      listInstalled: () => ({
        packages: opts.installed ?? [],
        skippedSources: opts.skippedSources ?? [],
      }),
      fetchPackument,
    };
    return await fn({ deps, registry, dataDir });
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    // never mask a test failure with a shutdown error
    await registry.close().catch(() => undefined);
  }
}
