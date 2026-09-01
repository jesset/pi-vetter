import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { buildArtifacts, parseArgs, resolveTargets } from "../src/commands/vet.ts";
import { defaultConfig } from "../src/config.ts";
import type { Packument } from "../src/core/types.ts";
import { installApproved, installSpec } from "../src/install/gated-installer.ts";
import type { InstalledPackage } from "../src/settings.ts";
import { makeTarball } from "./e2e/helpers/fixtures.ts";

describe("parseArgs", () => {
  it("accepts empty args (installed-by-default)", () => {
    expect(parseArgs("")).toEqual({ specs: [] });
    expect(parseArgs("   ")).toEqual({ specs: [] });
  });

  it("accepts multiple npm specs", () => {
    expect(parseArgs("npm:foo npm:bar@1.2.3")).toEqual({
      specs: ["npm:foo", "npm:bar@1.2.3"],
    });
  });

  it("rejects the installed keyword and non-npm specs", () => {
    expect(parseArgs("installed")).toHaveProperty("error");
    expect(parseArgs("git:github.com/a/b")).toHaveProperty("error");
  });
});

describe("resolveTargets", () => {
  const packument = (name: string, versions: string[]): Packument => ({
    name,
    "dist-tags": { latest: versions[versions.length - 1] ?? "" },
    versions: Object.fromEntries(
      versions.map((v) => [
        v,
        {
          version: v,
          dist: {
            integrity: "sha512-x",
            tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz`,
          },
        },
      ]),
    ),
    time: { created: "2020-01-01T00:00:00.000Z" },
    maintainers: [],
  });

  function deps(installed: InstalledPackage[]) {
    return {
      config: { ...defaultConfig() },
      cache: { get: () => Promise.resolve(null), set: () => Promise.resolve() },
      scanners: [],
      listInstalled: () => ({ packages: installed, skippedSources: [] as string[] }),
      fetchPackument: vi.fn((name: string) =>
        Promise.resolve(packument(name, name === "pinned-pkg" ? ["1.0.0"] : ["1.0.0", "2.0.0"])),
      ),
    };
  }

  it("builds update targets for outdated, non-pinned packages", async () => {
    const d = deps([
      { source: "npm:pkg", name: "pkg", version: "1.0.0", pinned: false, scope: "user" },
      {
        source: "npm:pinned-pkg@1.0.0",
        name: "pinned-pkg",
        version: "1.0.0",
        pinned: true,
        scope: "user",
      },
    ]);
    const { targets, notes } = await resolveTargets(d, []);
    expect(targets).toEqual([
      {
        candidate: { name: "pkg", version: "2.0.0", scenario: "update" },
        baseline: { name: "pkg", version: "1.0.0", pinned: false },
      },
    ]);
    expect(notes).toEqual([]);
  });

  it("keeps evaluating pinned packages with available updates (blind-spot fix)", async () => {
    const d = deps([
      {
        source: "npm:pkg@1.0.0",
        name: "pkg",
        version: "1.0.0",
        pinned: true,
        scope: "user",
      },
    ]);
    const { targets } = await resolveTargets(d, []);
    expect(targets).toEqual([
      {
        candidate: { name: "pkg", version: "2.0.0", scenario: "update" },
        baseline: { name: "pkg", version: "1.0.0", pinned: true },
      },
    ]);
  });

  it("resolves explicit specs to install or update scenario", async () => {
    const base = deps([
      { source: "npm:old", name: "old", version: "1.0.0", pinned: false, scope: "user" },
    ]);
    base.fetchPackument = vi.fn((name: string) =>
      Promise.resolve(packument(name, name === "old" ? ["1.0.0", "2.0.0"] : ["1.5.0"])),
    );
    const { targets } = await resolveTargets(base, ["npm:old", "npm:brand-new@1.5.0"]);
    expect(targets).toHaveLength(2);
    expect(targets[0]).toMatchObject({
      candidate: { name: "old", version: "2.0.0", scenario: "update" },
      baseline: { version: "1.0.0" },
    });
    expect(targets[1]).toMatchObject({
      candidate: { name: "brand-new", version: "1.5.0", scenario: "install" },
      baseline: null,
    });
  });

  it("reports resolving progress over all installed packages", async () => {
    const d = deps([
      { source: "npm:pkg", name: "pkg", version: "1.0.0", pinned: false, scope: "user" },
      {
        source: "npm:pinned-pkg@1.0.0",
        name: "pinned-pkg",
        version: "1.0.0",
        pinned: true,
        scope: "user",
      },
    ]);
    const progress = {
      startResolve: vi.fn(),
      start: vi.fn(),
      item: vi.fn(),
      tick: vi.fn(),
    };
    const { targets } = await resolveTargets(d, [], progress);
    expect(targets).toHaveLength(1);
    expect(progress.startResolve).toHaveBeenCalledWith(["pkg", "pinned-pkg"]);
    expect(progress.tick).toHaveBeenCalledTimes(2);
  });

  it("discloses skipped non-npm sources in notes when scanning installed packages", async () => {
    const d = deps([]);
    d.listInstalled = () => ({
      packages: [],
      skippedSources: ["git:git@github.com:foo/bar", "/local/path"],
    });
    const { targets, notes } = await resolveTargets(d, []);
    expect(targets).toHaveLength(0);
    expect(notes).toEqual([
      "- git:git@github.com:foo/bar: not an npm source, out of scope",
      "- /local/path: not an npm source, out of scope",
    ]);
  });
});

describe("installApproved", () => {
  const report = (name: string, version: string, integrity: string) => ({
    candidate: { name, version, scenario: "update" as const },
    baseline: { name, version: "0.0.1" },
    verdict: "ALLOW" as const,
    capped: false,
    findings: [],
    evidences: [],
    riskScore: 0,
    hasLifecycleScripts: false,
    candidateIntegrity: integrity,
  });

  function mockRegistry(integrityByPkg: Record<string, string>) {
    return vi.fn((name: string) =>
      Promise.resolve({
        name,
        "dist-tags": {},
        versions: {
          "2.0.0": {
            version: "2.0.0",
            dist: { integrity: integrityByPkg[name], tarball: "x" },
          },
        },
        time: {},
        maintainers: [],
      }),
    );
  }

  it("installs when integrity matches (ADR-0003: pi install with pinned spec)", async () => {
    const fetchPackument = mockRegistry({ pkg: "sha512-good" });
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string, init?: RequestInit) =>
        fetchPackument("pkg").then((p) => new Response(JSON.stringify(p), init)),
      ),
    );
    const exec = vi.fn(() => Promise.resolve({ stdout: "", stderr: "", code: 0 }));
    const unpin = vi.fn();
    const outcomes = await installApproved(exec as never, [report("pkg", "2.0.0", "sha512-good")], {
      unpin,
    });
    vi.unstubAllGlobals();
    expect(outcomes).toEqual([
      {
        name: "pkg",
        version: "2.0.0",
        status: "installed",
        message: "to pin: pi install npm:pkg@2.0.0",
      },
    ]);
    expect(exec).toHaveBeenCalledWith("pi", ["install", "npm:pkg@2.0.0"]);
    expect(unpin).toHaveBeenCalledWith("pkg", "2.0.0");
  });

  it("keeps the pinned spec when pinOnInstall is enabled", async () => {
    const fetchPackument = mockRegistry({ pkg: "sha512-good" });
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string, init?: RequestInit) =>
        fetchPackument("pkg").then((p) => new Response(JSON.stringify(p), init)),
      ),
    );
    const exec = vi.fn(() => Promise.resolve({ stdout: "", stderr: "", code: 0 }));
    const unpin = vi.fn();
    const outcomes = await installApproved(exec as never, [report("pkg", "2.0.0", "sha512-good")], {
      unpin,
      pinOnInstall: true,
    });
    vi.unstubAllGlobals();
    expect(outcomes).toEqual([{ name: "pkg", version: "2.0.0", status: "installed" }]);
    expect(unpin).not.toHaveBeenCalled();
  });

  it("skips on integrity mismatch (TOCTOU guard)", async () => {
    const fetchPackument = mockRegistry({ pkg: "sha512-rotated" });
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string, init?: RequestInit) =>
        fetchPackument("pkg").then((p) => new Response(JSON.stringify(p), init)),
      ),
    );
    const exec = vi.fn(() => Promise.resolve({ stdout: "", stderr: "", code: 0 }));
    const outcomes = await installApproved(exec as never, [
      report("pkg", "2.0.0", "sha512-original"),
    ]);
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "integrity-mismatch" });
    expect(exec).not.toHaveBeenCalled();
  });

  it("reports failed installs", async () => {
    const fetchPackument = mockRegistry({ pkg: "sha512-good" });
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string, init?: RequestInit) =>
        fetchPackument("pkg").then((p) => new Response(JSON.stringify(p), init)),
      ),
    );
    const exec = vi.fn(() => Promise.resolve({ stdout: "", stderr: "boom", code: 1 }));
    const outcomes = await installApproved(exec as never, [report("pkg", "2.0.0", "sha512-good")]);
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "failed" });
  });
});

describe("installSpec", () => {
  it("formats scoped and plain names", () => {
    expect(installSpec("@scope/pkg", "1.0.0")).toBe("npm:@scope/pkg@1.0.0");
  });
});

describe("buildArtifacts", () => {
  const integ = (b: Uint8Array) => `sha512-${createHash("sha512").update(b).digest("base64")}`;

  async function fixture(tamperBaseline: boolean) {
    const candidate = await makeTarball([["index.js", "module.exports = () => 2;\n"]]);
    const intendedBase = await makeTarball([["index.js", "module.exports = () => 1;\n"]]);
    const servedBase = tamperBaseline
      ? await makeTarball([["evil.js", "// tampered\n"]])
      : intendedBase;
    const pk: Packument = {
      name: "pkg",
      "dist-tags": { latest: "2.0.0" },
      versions: {
        "2.0.0": {
          version: "2.0.0",
          dist: { integrity: integ(candidate), tarball: "https://r/pkg-2.0.0.tgz" },
        },
        "1.0.0": {
          version: "1.0.0",
          dist: { integrity: integ(intendedBase), tarball: "https://r/pkg-1.0.0.tgz" },
        },
      },
      time: { created: "2020-01-01T00:00:00.000Z" },
      maintainers: [],
    };
    const served = new Map<string, Uint8Array>([
      ["https://r/pkg-2.0.0.tgz", candidate],
      ["https://r/pkg-1.0.0.tgz", servedBase],
    ]);
    const fetcher = vi.fn(() => Promise.resolve(pk));
    vi.stubGlobal(
      "fetch",
      vi.fn((input: string | URL | Request) =>
        Promise.resolve(
          new Response(served.get(String(input instanceof Request ? input.url : input)) ?? "{}"),
        ),
      ),
    );
    return fetcher;
  }

  it("rejects a baseline tarball that does not match dist.integrity", async () => {
    const fetcher = await fixture(true);
    await expect(
      buildArtifacts(
        {
          candidate: { name: "pkg", version: "2.0.0", scenario: "update" },
          baseline: { name: "pkg", version: "1.0.0" },
        },
        fetcher as never,
      ),
    ).rejects.toThrow(/integrity mismatch downloading baseline pkg@1.0.0/);
    vi.unstubAllGlobals();
  });

  it("parses a baseline whose bytes match dist.integrity", async () => {
    const fetcher = await fixture(false);
    const artifacts = await buildArtifacts(
      {
        candidate: { name: "pkg", version: "2.0.0", scenario: "update" },
        baseline: { name: "pkg", version: "1.0.0" },
      },
      fetcher as never,
    );
    vi.unstubAllGlobals();
    expect(artifacts.baselineFiles).not.toBeNull();
    expect([...(artifacts.baselineFiles?.keys() ?? [])]).toContain("index.js");
  });
});
