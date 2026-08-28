import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createFileCache } from "../src/cache.ts";
import { createMaintainerSnapshotStore, defaultConfig, loadConfig } from "../src/config.ts";
import type { ScanResult } from "../src/core/types.ts";
import { npmSpecFromSource } from "../src/settings.ts";

const dirs: string[] = [];
function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), "pi-vetter-test-"));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function result(): ScanResult {
  return { scanner: "osv", status: "ok", evidences: [] };
}

describe("config", () => {
  it("creates the default config file on first load", () => {
    const dir = tempDir();
    const cfg = loadConfig(dir);
    expect(cfg.scanners.osv?.enabled).toBe(true);
    expect(cfg.scanners.virustotal?.enabled).toBe(false);
    expect(JSON.parse(readFileSync(join(dir, "config.json"), "utf8"))).toEqual(defaultConfig());
  });

  it("merges user overrides over defaults", () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "config.json"),
      JSON.stringify({
        scanners: { osv: { timeoutMs: 5000 } },
        rules: { ask: { "young-package": false } },
      }),
    );
    const cfg = loadConfig(dir);
    expect(cfg.scanners.osv?.timeoutMs).toBe(5000);
    expect(cfg.scanners.osv?.enabled).toBe(true);
    expect(cfg.rules.ask?.["young-package"]).toBe(false);
  });

  it("falls back to defaults on corrupt json", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "config.json"), "{not json");
    expect(loadConfig(dir)).toEqual(defaultConfig());
  });
});

describe("maintainer snapshot store", () => {
  it("round-trips maintainer ids", async () => {
    const dir = tempDir();
    const store = createMaintainerSnapshotStore(dir);
    expect(await store.read("pkg")).toBeNull();
    await store.write("pkg", ["alice"]);
    expect(await store.read("pkg")).toEqual(["alice"]);
  });
});

describe("file cache", () => {
  it("round-trips and expires entries by ttl", async () => {
    const dir = tempDir();
    const cache = createFileCache(dir, { enabled: true, ttlHours: 24 });
    await cache.set("osv", "pkg@1.0.0", result());
    expect(await cache.get("osv", "pkg@1.0.0")).toEqual(result());

    const stale = join(dir, "osv", `${encodeURIComponent("pkg@1.0.0")}.json`);
    const entry = JSON.parse(readFileSync(stale, "utf8")) as { savedAt: number };
    entry.savedAt = Date.now() - 25 * 3_600_000;
    writeFileSync(stale, JSON.stringify(entry));
    expect(await cache.get("osv", "pkg@1.0.0")).toBeNull();
  });

  it("never expires virustotal entries", async () => {
    const dir = tempDir();
    const cache = createFileCache(dir, { enabled: true, ttlHours: 24 });
    const stale = join(dir, "virustotal", `${encodeURIComponent("pkg@1.0.0")}.json`);
    await cache.set("virustotal", "pkg@1.0.0", result());
    const entry = JSON.parse(readFileSync(stale, "utf8")) as { savedAt: number };
    entry.savedAt = Date.now() - 365 * 24 * 3_600_000;
    writeFileSync(stale, JSON.stringify(entry));
    expect((await cache.get("virustotal", "pkg@1.0.0"))?.scanner).toBe("osv");
  });

  it("is a no-op when disabled", async () => {
    const cache = createFileCache(tempDir(), { enabled: false, ttlHours: 24 });
    await cache.set("osv", "pkg@1.0.0", result());
    expect(await cache.get("osv", "pkg@1.0.0")).toBeNull();
  });
});

describe("npmSpecFromSource", () => {
  it("parses npm sources and detects pinned specs", () => {
    expect(npmSpecFromSource("npm:foo")).toEqual({ name: "foo", pinned: false });
    expect(npmSpecFromSource("npm:foo@1.2.3")).toEqual({ name: "foo", pinned: true });
    expect(npmSpecFromSource("npm:@scope/foo@1.2.3")).toEqual({
      name: "@scope/foo",
      pinned: true,
    });
    expect(npmSpecFromSource("git:github.com/a/b")).toBeNull();
  });
});
