import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { VetterConfig } from "./core/types.ts";
import type { MaintainerSnapshotStore } from "./scanners/metadata.ts";

export const DATA_DIR = join(homedir(), ".pi", "agent", "pi-vetter");

export function dataDir(explicit?: string): string {
  return explicit ?? DATA_DIR;
}

export function defaultConfig(): VetterConfig {
  return {
    scanners: {
      metadata: { enabled: true },
      osv: { enabled: true, timeoutMs: 10_000 },
      provenance: { enabled: true, timeoutMs: 10_000 },
      static: { enabled: true },
      diff: { enabled: true },
      virustotal: { enabled: false, timeoutMs: 60_000 },
      socket: { enabled: false },
    },
    rules: { deny: {}, ask: {} },
    cache: { enabled: true, ttlHours: 24 },
    score: { weights: {} },
    network: { timeoutMs: 30_000 },
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function merge<T>(base: T, override: unknown): T {
  if (!isPlainObject(base) || !isPlainObject(override)) {
    return override === undefined ? base : (override as T);
  }
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(override)) {
    out[k] = merge((base as Record<string, unknown>)[k], v);
  }
  return out as T;
}

export function loadConfig(dir?: string): VetterConfig {
  const root = dataDir(dir);
  const file = join(root, "config.json");
  if (!existsSync(file)) {
    mkdirSync(root, { recursive: true });
    writeFileSync(file, `${JSON.stringify(defaultConfig(), null, 2)}\n`);
    return defaultConfig();
  }
  try {
    const user = JSON.parse(readFileSync(file, "utf8")) as unknown;
    return merge(defaultConfig(), user);
  } catch {
    return defaultConfig();
  }
}

/** Local state used by the metadata scanner to detect maintainer changes. */
export function createMaintainerSnapshotStore(dir?: string): MaintainerSnapshotStore {
  const file = join(dataDir(dir), "maintainers.json");
  const readAll = (): Record<string, string[]> => {
    try {
      return JSON.parse(readFileSync(file, "utf8")) as Record<string, string[]>;
    } catch {
      return {};
    }
  };
  return {
    read(name) {
      const ids = readAll()[name];
      return Promise.resolve(ids ?? null);
    },
    write(name, ids) {
      const all = readAll();
      all[name] = ids;
      mkdirSync(dataDir(dir), { recursive: true });
      writeFileSync(file, `${JSON.stringify(all, null, 2)}\n`);
      return Promise.resolve();
    },
  };
}
