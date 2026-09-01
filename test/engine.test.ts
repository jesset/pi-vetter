import { describe, expect, it, vi } from "vitest";
import { defaultConfig } from "../src/config.ts";
import { type CacheStore, type EngineDeps, evaluate } from "../src/core/engine.ts";
import type {
  Artifacts,
  Candidate,
  Evidence,
  ScanResult,
  SecurityScanner,
  VetterConfig,
} from "../src/core/types.ts";

function makePackument(opts?: { createdDaysAgo?: number; scripts?: Record<string, string> }) {
  const created = new Date(Date.now() - (opts?.createdDaysAgo ?? 400) * 86_400_000).toISOString();
  return {
    name: "pkg",
    "dist-tags": { latest: "2.0.0" },
    versions: {
      "2.0.0": {
        version: "2.0.0",
        dist: {
          integrity: "sha512-abc",
          tarball: "https://registry.npmjs.org/pkg/-/pkg-2.0.0.tgz",
        },
        ...(opts?.scripts ? { scripts: opts.scripts } : {}),
      },
    },
    time: { created, "2.0.0": created },
    maintainers: [{ name: "a" }],
  };
}

function makeArtifacts(opts?: {
  createdDaysAgo?: number;
  scripts?: Record<string, string>;
}): Artifacts {
  return {
    candidateFiles: new Map(),
    baselineFiles: null,
    candidatePackument: makePackument(opts),
    candidateIntegrity: "sha512-abc",
    baselineIntegrity: null,
    candidateTarball: new Uint8Array(0),
    dependencyFiles: new Map(),
    dependencySkipped: 0,
    candidateSha256: "abc123",
    downloads: 1000,
  };
}

function makeScanner(
  name: SecurityScanner["name"],
  result: ScanResult | Error,
): SecurityScanner & { scan: ReturnType<typeof vi.fn> } {
  return {
    name,
    layer: 1,
    scan:
      result instanceof Error
        ? vi.fn(() => Promise.reject(result))
        : vi.fn(() => Promise.resolve(result)),
  };
}

function ev(key: string, status: Evidence["status"], detail = key): Evidence {
  return { scanner: "osv", key, status, detail };
}

const config: VetterConfig = { ...defaultConfig() };

const candidate: Candidate = { name: "pkg", version: "2.0.0", scenario: "update" };

function makeDeps(overrides?: Partial<EngineDeps>): EngineDeps {
  return {
    scanners: [],
    config,
    cache: null,
    buildArtifacts: () => Promise.resolve(makeArtifacts()),
    ...overrides,
  };
}

describe("evaluate", () => {
  it("produces ALLOW when scanners report clean evidence", async () => {
    const osv = makeScanner("osv", {
      scanner: "osv",
      status: "ok",
      evidences: [ev("osv:clean", "pass")],
    });
    const report = await evaluate(makeDeps({ scanners: [osv] }), { candidate, baseline: null });
    expect(report.verdict).toBe("ALLOW");
    expect(report.capped).toBe(false);
    expect(report.riskScore).toBe(0);
  });

  it("derives an ASK verdict from a failing rule evidence", async () => {
    const diff = makeScanner("diff", {
      scanner: "diff",
      status: "ok",
      evidences: [ev("diff:new-script", "fail", "new postinstall script")],
    });
    const report = await evaluate(makeDeps({ scanners: [diff] }), { candidate, baseline: null });
    expect(report.verdict).toBe("ASK");
    expect(report.findings.map((f) => f.ruleId)).toEqual(["new-lifecycle-script"]);
  });

  it("caps at ASK and marks capped when a scanner errors (fail-closed)", async () => {
    const broken = makeScanner("osv", new Error("network down"));
    const report = await evaluate(makeDeps({ scanners: [broken] }), { candidate, baseline: null });
    expect(report.verdict).toBe("ASK");
    expect(report.capped).toBe(true);
    expect(report.evidences.some((e) => e.key === "osv:incomplete")).toBe(true);
  });

  it("keeps DENY when another scanner is incomplete", async () => {
    const osv = makeScanner("osv", {
      scanner: "osv",
      status: "ok",
      evidences: [ev("osv:malicious", "fail", "MAL-2026-1")],
    });
    const broken = makeScanner("diff", new Error("boom"));
    const report = await evaluate(makeDeps({ scanners: [osv, broken] }), {
      candidate,
      baseline: null,
    });
    expect(report.verdict).toBe("DENY");
    expect(report.capped).toBe(false);
  });

  it("reports lifecycle scripts presence from packument", async () => {
    const deps = makeDeps({
      buildArtifacts: () =>
        Promise.resolve(makeArtifacts({ scripts: { postinstall: "node x.js" } })),
    });
    const report = await evaluate(deps, { candidate, baseline: null });
    expect(report.hasLifecycleScripts).toBe(true);
  });

  it("carries the candidate artifact sha256 into the report (#47)", async () => {
    const report = await evaluate(makeDeps({ scanners: [] }), { candidate, baseline: null });
    expect(report.candidateSha256).toBe("abc123");
  });

  it("carries per-file digests of the candidate tarball (#48)", async () => {
    const files = new Map([["index.js", new TextEncoder().encode("x = 1;")]]);
    const deps = makeDeps({
      buildArtifacts: () => Promise.resolve({ ...makeArtifacts(), candidateFiles: files }),
    });
    const report = await evaluate(deps, { candidate, baseline: null });
    expect(Object.keys(report.candidateFileDigests)).toEqual(["index.js"]);
    expect(report.candidateFileDigests["index.js"]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("uses cache and skips the scanner on hit", async () => {
    const osv = makeScanner("osv", {
      scanner: "osv",
      status: "ok",
      evidences: [ev("osv:clean", "pass")],
    });
    const cache: CacheStore = {
      get: vi.fn(() =>
        Promise.resolve({
          scanner: "osv",
          status: "ok",
          evidences: [ev("osv:clean", "pass")],
        } as ScanResult),
      ),
      set: vi.fn(() => Promise.resolve()),
    };
    await evaluate(makeDeps({ scanners: [osv], cache }), { candidate, baseline: null });
    expect(osv.scan).not.toHaveBeenCalled();
    expect(cache.get).toHaveBeenCalledWith(
      "osv",
      expect.stringMatching(/^pkg@2\.0\.0:install#[0-9a-f]{12}$/),
    );
  });

  describe("cache identity binds artifact + baseline (#37)", () => {
    const ok = (): ScanResult => ({ scanner: "osv", status: "ok", evidences: [] });

    function run() {
      const cache: CacheStore = {
        get: vi.fn(() => Promise.resolve(null)),
        set: vi.fn(() => Promise.resolve()),
      };
      const osv = makeScanner("osv", ok());
      return { cache, osv };
    }

    const keysOf = (cache: CacheStore): string[] =>
      vi.mocked(cache.get).mock.calls.map((c) => c[1]);

    it("separates install-scenario results from update-scenario results", async () => {
      const { cache, osv } = run();
      const deps = makeDeps({ scanners: [osv], cache });
      await evaluate(deps, { candidate, baseline: null });
      await evaluate(deps, { candidate, baseline: { name: "pkg", version: "1.0.0" } });
      const keys = keysOf(cache);
      expect(keys).toHaveLength(2);
      expect(keys[0]).toMatch(/^pkg@2\.0\.0:install#/);
      expect(keys[1]).toMatch(/^pkg@2\.0\.0←1\.0\.0#/);
    });

    it("separates results across different baselines", async () => {
      const { cache, osv } = run();
      const deps = makeDeps({ scanners: [osv], cache });
      await evaluate(deps, { candidate, baseline: { name: "pkg", version: "1.0.0" } });
      await evaluate(deps, { candidate, baseline: { name: "pkg", version: "1.5.0" } });
      const keys = keysOf(cache);
      expect(keys[0]).not.toBe(keys[1]);
      expect(keys[1]).toMatch(/^pkg@2\.0\.0←1\.5\.0#/);
    });

    it("separates results when the candidate artifact integrity differs", async () => {
      const { cache, osv } = run();
      const good = makeArtifacts();
      const other: Artifacts = { ...makeArtifacts(), candidateIntegrity: "sha512-zzz" };
      const artifacts = [good, other];
      let next = 0;
      const deps = makeDeps({
        scanners: [osv],
        cache,
        buildArtifacts: () => Promise.resolve(artifacts[next++] as Artifacts),
      });
      await evaluate(deps, { candidate, baseline: null });
      await evaluate(deps, { candidate, baseline: null });
      const keys = keysOf(cache);
      expect(keys[0]).not.toBe(keys[1]);
    });

    it("separates results when the baseline artifact integrity differs", async () => {
      const { cache, osv } = run();
      const first = makeArtifacts();
      const second: Artifacts = {
        ...makeArtifacts(),
        baselineFiles: new Map(),
        baselineIntegrity: "sha512-b2",
      };
      first.baselineIntegrity = "sha512-b1";
      const artifacts = [first, second];
      let next = 0;
      const deps = makeDeps({
        scanners: [osv],
        cache,
        buildArtifacts: () => Promise.resolve(artifacts[next++] as Artifacts),
      });
      const baseline = { name: "pkg", version: "1.0.0" };
      await evaluate(deps, { candidate, baseline });
      await evaluate(deps, { candidate, baseline });
      const keys = keysOf(cache);
      expect(keys[0]).not.toBe(keys[1]);
    });

    it("misses old-format cache entries (bare name@version)", async () => {
      const stale: ScanResult = {
        scanner: "osv",
        status: "ok",
        evidences: [ev("osv:clean", "pass")],
      };
      const cache: CacheStore = {
        get: vi.fn((_scanner: string, key: string) =>
          Promise.resolve(key === "pkg@2.0.0" ? stale : null),
        ),
        set: vi.fn(() => Promise.resolve()),
      };
      const osv = makeScanner("osv", { scanner: "osv", status: "ok", evidences: [] });
      await evaluate(makeDeps({ scanners: [osv], cache }), { candidate, baseline: null });
      expect(osv.scan).toHaveBeenCalled();
    });

    it("reuses the same key for an identical target", async () => {
      const { cache, osv } = run();
      const deps = makeDeps({ scanners: [osv], cache });
      await evaluate(deps, { candidate, baseline: { name: "pkg", version: "1.0.0" } });
      await evaluate(deps, { candidate, baseline: { name: "pkg", version: "1.0.0" } });
      const keys = keysOf(cache);
      expect(keys[0]).toBe(keys[1]);
    });
  });

  it("does not cache failed scanner results", async () => {
    const broken = makeScanner("osv", { scanner: "osv", status: "timeout", evidences: [] });
    const cache: CacheStore = {
      get: vi.fn(() => Promise.resolve(null)),
      set: vi.fn(() => Promise.resolve()),
    };
    await evaluate(makeDeps({ scanners: [broken], cache }), { candidate, baseline: null });
    expect(cache.set).not.toHaveBeenCalled();
  });

  it("applies provenance and age modifiers to the risk score", async () => {
    const prov = makeScanner("provenance", {
      scanner: "provenance",
      status: "ok",
      evidences: [ev("provenance:verified", "pass")],
    });
    const report = await evaluate(makeDeps({ scanners: [prov] }), { candidate, baseline: null });
    expect(report.riskScore).toBe(0);
  });
});
