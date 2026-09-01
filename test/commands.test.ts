import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { buildArtifacts, parseArgs, policyNotes, resolveTargets } from "../src/commands/vet.ts";
import { defaultConfig } from "../src/config.ts";
import type { Packument } from "../src/core/types.ts";
import {
  diffInstalledFiles,
  installApproved,
  installSpec,
} from "../src/install/gated-installer.ts";
import { createInstalledFilesReader } from "../src/install/installed-files.ts";
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

describe("policyNotes (#42)", () => {
  it("discloses rules disabled via config", () => {
    const config = { ...defaultConfig() };
    config.rules.ask = { "young-package": false };
    expect(policyNotes(config)).toEqual([
      '- rule "young-package" disabled by config (default: ask) — its findings are suppressed',
    ]);
  });

  it("stays silent under the default policy", () => {
    expect(policyNotes({ ...defaultConfig() })).toEqual([]);
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
    candidateSha256: "0".repeat(64),
    candidateFileDigests: {},
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
    const exec = vi.fn((cmd: string) =>
      Promise.resolve(
        cmd === "npm"
          ? { stdout: "https://registry.npmjs.org/\n", stderr: "", code: 0 }
          : { stdout: "", stderr: "", code: 0 },
      ),
    );
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
    const exec = vi.fn((cmd: string) =>
      Promise.resolve(
        cmd === "npm"
          ? { stdout: "https://registry.npmjs.org/\n", stderr: "", code: 0 }
          : { stdout: "", stderr: "", code: 0 },
      ),
    );
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
    const exec = vi.fn((cmd: string) =>
      Promise.resolve(
        cmd === "npm"
          ? { stdout: "https://registry.npmjs.org/\n", stderr: "", code: 0 }
          : { stdout: "", stderr: "", code: 0 },
      ),
    );
    const outcomes = await installApproved(exec as never, [
      report("pkg", "2.0.0", "sha512-original"),
    ]);
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "integrity-mismatch" });
    expect(exec).not.toHaveBeenCalledWith("pi", ["install", "npm:pkg@2.0.0"]);
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

describe("installApproved registry guard (#43)", () => {
  const report = (name = "pkg") => ({
    candidate: { name, version: "2.0.0", scenario: "update" as const },
    baseline: { name, version: "0.0.1" },
    verdict: "ALLOW" as const,
    capped: false,
    findings: [],
    evidences: [],
    riskScore: 0,
    hasLifecycleScripts: false,
    candidateIntegrity: "sha512-good",
    candidateSha256: "0".repeat(64),
    candidateFileDigests: {},
  });
  const registryPackument = vi.fn(() =>
    Promise.resolve({
      name: "pkg",
      "dist-tags": {},
      versions: { "2.0.0": { version: "2.0.0", dist: { integrity: "sha512-good", tarball: "x" } } },
      time: {},
      maintainers: [],
    }),
  );

  it("skips every package when the install registry diverges from the vetting registry", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({})))),
    );
    const exec = vi.fn(() =>
      Promise.resolve({ stdout: "https://mirror.corp/\n", stderr: "", code: 0 }),
    );
    const outcomes = await installApproved(exec as never, [report()]);
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "registry-mismatch" });
    expect(outcomes[0]?.message).toContain("https://registry.npmjs.org");
    expect(outcomes[0]?.message).toContain("https://mirror.corp");
    expect(exec).not.toHaveBeenCalledWith("pi", ["install", "npm:pkg@2.0.0"]);
  });

  it("skips conservatively when the registry probe fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({})))),
    );
    const exec = vi.fn(() => Promise.reject(new Error("npm not found")));
    const outcomes = await installApproved(exec as never, [report()]);
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "failed" });
    expect(outcomes[0]?.message).toContain("could not confirm the install registry");
    expect(exec).not.toHaveBeenCalledWith("pi", ["install", "npm:pkg@2.0.0"]);
  });

  it("skips conservatively when the probe exits non-zero", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({})))),
    );
    const exec = vi.fn(() => Promise.resolve({ stdout: "", stderr: "boom", code: 1 }));
    const outcomes = await installApproved(exec as never, [report()]);
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "failed" });
    expect(outcomes[0]?.message).toContain("exited 1");
    expect(exec).not.toHaveBeenCalledWith("pi", ["install", "npm:pkg@2.0.0"]);
  });

  it("skips conservatively when the probe returns empty output", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({})))),
    );
    const exec = vi.fn(() => Promise.resolve({ stdout: "  \n", stderr: "", code: 0 }));
    const outcomes = await installApproved(exec as never, [report()]);
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "failed" });
    expect(outcomes[0]?.message).toContain("empty output");
    expect(exec).not.toHaveBeenCalledWith("pi", ["install", "npm:pkg@2.0.0"]);
  });

  it("installs normally when both registries agree", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => registryPackument().then((p) => new Response(JSON.stringify(p)))),
    );
    const exec = vi.fn((cmd: string) =>
      Promise.resolve(
        cmd === "npm"
          ? { stdout: "https://registry.npmjs.org", stderr: "", code: 0 }
          : { stdout: "", stderr: "", code: 0 },
      ),
    );
    const outcomes = await installApproved(exec as never, [report()]);
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "installed" });
    expect(exec).toHaveBeenCalledWith("pi", ["install", "npm:pkg@2.0.0"]);
  });
});

describe("diffInstalledFiles (#48)", () => {
  const sha = (b: string) => createHash("sha256").update(b).digest("hex");
  const files = (entries: Array<[string, string]>) =>
    new Map(entries.map(([p, c]) => [p, new TextEncoder().encode(c)]));

  it("returns null on a byte-for-byte match", () => {
    expect(diffInstalledFiles({ "a.js": sha("1") }, files([["a.js", "1"]]))).toBeNull();
  });

  it("ignores npm's root lockfile but flags deeper same-name files", () => {
    expect(
      diffInstalledFiles(
        { "a.js": sha("1") },
        files([
          ["a.js", "1"],
          [".package-lock.json", "{}"],
        ]),
      ),
    ).toBeNull();
    const diff = diffInstalledFiles(
      { "a.js": sha("1") },
      files([
        ["a.js", "1"],
        ["sub/.package-lock.json", "{}"],
      ]),
    );
    expect(diff?.extra).toEqual(["sub/.package-lock.json"]);
  });

  it("reports missing, changed and unexpected files", () => {
    const diff = diffInstalledFiles(
      { "a.js": sha("1"), "gone.js": sha("2") },
      files([
        ["a.js", "tampered"],
        ["extra.js", "x"],
      ]),
    );
    expect(diff).toMatchObject({
      missing: ["gone.js"],
      changed: ["a.js"],
      extra: ["extra.js"],
    });
  });
});

describe("installApproved post-install verification (#48)", () => {
  const reportWith = (digests: Record<string, string>) => ({
    candidate: { name: "pkg", version: "2.0.0", scenario: "update" as const },
    baseline: { name: "pkg", version: "0.0.1" },
    verdict: "ALLOW" as const,
    capped: false,
    findings: [],
    evidences: [],
    riskScore: 0,
    hasLifecycleScripts: false,
    candidateIntegrity: "sha512-good",
    candidateSha256: "0".repeat(64),
    candidateFileDigests: digests,
  });
  const execOk = vi.fn((cmd: string, _args?: string[]) =>
    Promise.resolve(
      cmd === "npm"
        ? { stdout: "https://registry.npmjs.org/\n", stderr: "", code: 0 }
        : { stdout: "", stderr: "", code: 0 },
    ),
  );
  const registry = () => {
    const fetchPackument = vi.fn((_name: string) =>
      Promise.resolve({
        name: "pkg",
        "dist-tags": {},
        versions: {
          "2.0.0": { version: "2.0.0", dist: { integrity: "sha512-good", tarball: "x" } },
        },
        time: {},
        maintainers: [],
      }),
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(() => fetchPackument("pkg").then((p) => new Response(JSON.stringify(p)))),
    );
  };

  it("marks the outcome verified when on-disk bytes match", async () => {
    registry();
    const content = "module.exports = () => 42;\n";
    const read = vi.fn(() =>
      Promise.resolve(new Map([["index.js", new TextEncoder().encode(content)]])),
    );
    const outcomes = await installApproved(
      execOk as never,
      [reportWith({ "index.js": createHash("sha256").update(content).digest("hex") })],
      {
        readInstalledFiles: read as never,
      },
    );
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "installed" });
    expect(outcomes[0]?.message).toContain("verified: on-disk files match the vetted artifact");
  });

  it("warns with a removal recommendation on byte divergence", async () => {
    registry();
    const read = vi.fn(() =>
      Promise.resolve(new Map([["index.js", new TextEncoder().encode("tampered")]])),
    );
    const outcomes = await installApproved(
      execOk as never,
      [reportWith({ "index.js": createHash("sha256").update("clean").digest("hex") })],
      { readInstalledFiles: read as never },
    );
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "installed-mismatch" });
    expect(outcomes[0]?.message).toContain("changed index.js");
    expect(outcomes[0]?.message).toContain("pi remove npm:pkg@2.0.0");
  });

  it("notes unavailable verification without failing the install", async () => {
    registry();
    const read = vi.fn(() => Promise.resolve(null));
    const outcomes = await installApproved(execOk as never, [reportWith({})], {
      readInstalledFiles: read as never,
    });
    vi.unstubAllGlobals();
    expect(outcomes[0]).toMatchObject({ status: "installed" });
    expect(outcomes[0]?.message).toContain("post-install verification unavailable");
  });
});

describe("createInstalledFilesReader (#48)", () => {
  it("matches pinned and unpinned source forms and reads the tree", async () => {
    const root = mkdtempSync(join(tmpdir(), "pi-vetter-inst-"));
    const pkgDir = join(root, "pkg");
    mkdirSync(join(pkgDir, "lib"), { recursive: true });
    writeFileSync(join(pkgDir, "index.js"), "exports = 1;");
    writeFileSync(join(pkgDir, "lib", "a.js"), "exports = 2;");
    const pm = {
      listConfiguredPackages: () => [
        { source: "npm:other-pkg@1.0.0", installedPath: join(root, "other") },
        { source: "npm:pkg@2.0.0", installedPath: pkgDir },
      ],
    };
    const read = createInstalledFilesReader(pm as never);
    const files = await read("pkg");
    expect(files).not.toBeNull();
    expect([...(files?.keys() ?? [])].sort()).toEqual(["index.js", "lib/a.js"]);
    expect(new TextDecoder().decode(files?.get("index.js") ?? new Uint8Array())).toBe(
      "exports = 1;",
    );
  });

  it("returns null when no configured source matches or the path is missing", async () => {
    const pm = {
      listConfiguredPackages: () => [{ source: "npm:pkg", installedPath: undefined }],
    };
    expect(await createInstalledFilesReader(pm as never)("pkg")).toBeNull();
    expect(await createInstalledFilesReader(pm as never)("ghost")).toBeNull();
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
    return { fetcher, intendedIntegrity: integ(intendedBase) };
  }

  it("rejects a baseline tarball that does not match dist.integrity", async () => {
    const { fetcher } = await fixture(true);
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
    const { fetcher, intendedIntegrity } = await fixture(false);
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
    expect(artifacts.baselineIntegrity).toBe(intendedIntegrity);
  });
});
