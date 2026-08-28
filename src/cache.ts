import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CacheStore } from "./core/engine.ts";
import type { ScannerName, ScanResult } from "./core/types.ts";

interface CacheEntry {
  savedAt: number;
  result: ScanResult;
}

/** VirusTotal hash lookups are immutable: cache them forever. */
const FOREVER_SCANNERS = new Set<ScannerName>(["virustotal"]);

export function createFileCache(
  dir: string,
  opts: { enabled: boolean; ttlHours: number },
): CacheStore {
  const noop: CacheStore = {
    get: () => Promise.resolve(null),
    set: () => Promise.resolve(),
  };
  if (!opts.enabled) return noop;

  const fileFor = (scanner: string, pkgKey: string): string =>
    join(dir, scanner, `${encodeURIComponent(pkgKey)}.json`);

  return {
    get(scanner, pkgKey) {
      try {
        const entry = JSON.parse(readFileSync(fileFor(scanner, pkgKey), "utf8")) as CacheEntry;
        const ttlMs = FOREVER_SCANNERS.has(scanner as ScannerName)
          ? Infinity
          : opts.ttlHours * 3_600_000;
        if (Date.now() - entry.savedAt > ttlMs) {
          rmSync(fileFor(scanner, pkgKey), { force: true });
          return Promise.resolve(null);
        }
        return Promise.resolve(entry.result);
      } catch {
        return Promise.resolve(null);
      }
    },
    set(scanner, pkgKey, result) {
      try {
        mkdirSync(join(dir, scanner), { recursive: true });
        const entry: CacheEntry = { savedAt: Date.now(), result };
        writeFileSync(fileFor(scanner, pkgKey), JSON.stringify(entry));
      } catch {
        // cache failures must never break evaluation
      }
      return Promise.resolve();
    },
  };
}
