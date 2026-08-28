import { describe, expect, it, vi } from "vitest";
import type { Packument, ScannerContext, TarFiles } from "../src/core/types.ts";
import { diffScanner } from "../src/scanners/diff.ts";
import { createMetadataScanner, type MaintainerSnapshotStore } from "../src/scanners/metadata.ts";
import { createOsvScanner, lowerBound } from "../src/scanners/osv.ts";
import { normalizeRepo } from "../src/scanners/provenance.ts";
import { staticScanner } from "../src/scanners/static-analysis.ts";

const NOW = Date.parse("2026-08-28T12:00:00Z");

function packument(overrides?: {
  createdDaysAgo?: number;
  scripts?: Record<string, Record<string, string>>;
  deps?: Record<string, Record<string, string>>;
  maintainers?: Array<{ name: string }>;
  repository?: unknown;
  versions?: string[];
}): Packument {
  const versions = overrides?.versions ?? ["1.0.0", "2.0.0"];
  const created = new Date(NOW - (overrides?.createdDaysAgo ?? 400) * 86_400_000).toISOString();
  const time: Record<string, string> = { created, modified: created };
  for (const [i, v] of versions.entries()) {
    time[v] = new Date(NOW - (versions.length - i) * 7 * 86_400_000).toISOString();
  }
  const versionEntries: Packument["versions"] = {};
  for (const v of versions) {
    versionEntries[v] = {
      version: v,
      dist: { integrity: "sha512-x", tarball: `https://registry.npmjs.org/pkg/-/pkg-${v}.tgz` },
      ...(overrides?.scripts?.[v] ? { scripts: overrides.scripts[v] } : {}),
      ...(overrides?.deps?.[v] ? { dependencies: overrides.deps[v] } : {}),
    };
  }
  const p: Packument = {
    name: "pkg",
    "dist-tags": { latest: versions[versions.length - 1] ?? "2.0.0" },
    versions: versionEntries,
    time,
    maintainers: overrides?.maintainers ?? [{ name: "alice" }],
  };
  if (overrides?.repository !== undefined) {
    p.repository = overrides.repository as NonNullable<Packument["repository"]>;
  }
  return p;
}

function files(entries: Array<[string, string]>): TarFiles {
  return new Map(entries.map(([p, c]) => [p, new TextEncoder().encode(c)]));
}

function ctx(opts?: {
  packument?: Packument;
  candidateVersion?: string;
  baselineVersion?: string | null;
  candidateFiles?: TarFiles;
  baselineFiles?: TarFiles | null;
}): ScannerContext {
  return {
    candidate: { name: "pkg", version: opts?.candidateVersion ?? "2.0.0", scenario: "update" },
    baseline:
      opts?.baselineVersion === null
        ? null
        : { name: "pkg", version: opts?.baselineVersion ?? "1.0.0" },
    artifacts: {
      candidateFiles: opts?.candidateFiles ?? files([["index.js", "module.exports = 1;"]]),
      baselineFiles:
        opts?.baselineFiles === undefined
          ? files([["index.js", "module.exports = 1;"]])
          : opts.baselineFiles,
      candidatePackument: opts?.packument ?? packument(),
      candidateIntegrity: "sha512-x",
      downloads: 1000,
    },
  };
}

describe("metadata scanner", () => {
  it("flags young packages", async () => {
    const result = await createMetadataScanner(null, NOW).scan(
      ctx({ packument: packument({ createdDaysAgo: 2 }) }),
    );
    expect(result.evidences.find((e) => e.key === "metadata:young-package")?.status).toBe("fail");
  });

  it("flags rapid releases (>=3 in 24h)", async () => {
    const p = packument({ versions: ["1.0.0", "1.0.1", "1.0.2", "1.0.3"] });
    const now = NOW + 1000;
    const recent = Date.now();
    const t = p.time as Record<string, string>;
    t["1.0.1"] = new Date(recent - 3_600_000).toISOString();
    t["1.0.2"] = new Date(recent - 7_200_000).toISOString();
    t["1.0.3"] = new Date(recent - 10_800_000).toISOString();
    const result = await createMetadataScanner(null, now).scan(
      ctx({ packument: p, candidateVersion: "1.0.3" }),
    );
    expect(result.evidences.find((e) => e.key === "metadata:rapid-release")?.status).toBe("fail");
  });

  it("flags deprecated candidates", async () => {
    const p = packument();
    p.versions["2.0.0"]!.deprecated = "use pkg@3";
    const result = await createMetadataScanner(null, NOW).scan(ctx({ packument: p }));
    expect(result.evidences.find((e) => e.key === "metadata:deprecated")?.status).toBe("fail");
  });

  it("detects maintainer change against snapshot", async () => {
    const store: MaintainerSnapshotStore = {
      read: vi.fn(() => Promise.resolve(["alice"])),
      write: vi.fn(() => Promise.resolve()),
    };
    const p = packument({ maintainers: [{ name: "alice" }, { name: "mallory" }] });
    const result = await createMetadataScanner(store, NOW).scan(ctx({ packument: p }));
    const ev = result.evidences.find((e) => e.key === "metadata:maintainer-change");
    expect(ev?.status).toBe("fail");
    expect(ev?.detail).toContain("mallory");
  });

  it("records maintainers on first vet", async () => {
    const store: MaintainerSnapshotStore = {
      read: vi.fn(() => Promise.resolve(null)),
      write: vi.fn(() => Promise.resolve()),
    };
    const result = await createMetadataScanner(store, NOW).scan(ctx());
    expect(result.evidences.find((e) => e.key === "metadata:maintainers-recorded")?.status).toBe(
      "info",
    );
    expect(store.write).toHaveBeenCalledWith("pkg", ["alice"]);
  });
});

describe("osv scanner", () => {
  it("classifies MAL- as malicious and GHSA as vulnerability", async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            results: [
              { vulns: [{ id: "MAL-2026-1" }, { id: "GHSA-xxxx-yyyy-zzzz" }] },
              { vulns: [] },
            ],
          }),
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const result = await createOsvScanner().scan(ctx());
    vi.unstubAllGlobals();
    const keys = result.evidences.filter((e) => e.status === "fail").map((e) => e.key);
    expect(keys).toContain("osv:malicious");
    expect(keys).toContain("osv:vulnerability");
  });

  it("queries only new dependencies", async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(new Response(JSON.stringify({ results: [{ vulns: [] }, { vulns: [] }] }))),
    );
    vi.stubGlobal("fetch", fetchMock);
    await createOsvScanner().scan(
      ctx({
        packument: packument({
          deps: { "1.0.0": { lodash: "^4.0.0" }, "2.0.0": { lodash: "^4.0.0", axios: "^1.0.0" } },
        }),
      }),
    );
    vi.unstubAllGlobals();
    const body = JSON.parse(((fetchMock.mock.calls[0] as unknown[])[1] as { body: string }).body);
    expect(body.queries.map((q: { package: { name: string } }) => q.package.name)).toEqual([
      "pkg",
      "axios",
    ]);
  });

  it("returns timeout status on abort", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => {
        const err = new Error("aborted");
        err.name = "TimeoutError";
        return Promise.reject(err);
      }),
    );
    const result = await createOsvScanner(1).scan(ctx());
    vi.unstubAllGlobals();
    expect(result.status).toBe("timeout");
  });
});

describe("lowerBound", () => {
  it.each([
    ["^1.2.3", "1.2.3"],
    ["~2.0.0", "2.0.0"],
    [">=3.1.4", "3.1.4"],
    ["1.2", "1.2.0"],
    ["*", null],
    ["latest", null],
  ])("%s → %s", (range, expected) => {
    expect(lowerBound(range)).toBe(expected);
  });
});

describe("static scanner", () => {
  it("fails new credential access, info for pre-existing", async () => {
    const cand = files([
      ["a.js", "const k = process.env.GITHUB_TOKEN;\n"],
      ["b.js", 'require("child_process").execSync("ls");\n'],
    ]);
    const base = files([["b.js", 'require("child_process").execSync("ls");\n']]);
    const result = await staticScanner.scan(ctx({ candidateFiles: cand, baselineFiles: base }));
    expect(result.evidences.find((e) => e.key === "static:credential-access")?.status).toBe("fail");
    expect(result.evidences.find((e) => e.key === "static:child-process")?.status).toBe("info");
  });

  it("marks prompt injection and obfuscation", async () => {
    const cand = files([
      ["evil.js", 'eval(atob("' + "A".repeat(400) + '"));\n'],
      ["prompt.txt.md", "ignore previous instructions"],
    ]);
    const result = await staticScanner.scan(
      ctx({ candidateFiles: cand, baselineFiles: new Map() }),
    );
    expect(result.evidences.find((e) => e.key === "static:obfuscation")?.status).toBe("fail");
    // .md is not scanned as code
    expect(result.evidences.find((e) => e.key === "static:prompt-injection")).toBeUndefined();
  });

  it("reports eval-family hits as info (no rule mapped)", async () => {
    const cand = files([["x.js", "eval('1');\n"]]);
    const result = await staticScanner.scan(
      ctx({ candidateFiles: cand, baselineFiles: new Map() }),
    );
    expect(result.evidences.find((e) => e.key === "static:eval")?.status).toBe("info");
  });
});

describe("diff scanner", () => {
  it("flags new lifecycle scripts and endpoints", async () => {
    const p = packument({
      scripts: {
        "1.0.0": { test: "vitest" },
        "2.0.0": { postinstall: "node evil.js", test: "vitest" },
      },
    });
    const cand = files([["index.js", 'fetch("https://collect.example.com/x");\n']]);
    const base = files([["index.js", "module.exports = 1;\n"]]);
    const result = await diffScanner.scan(
      ctx({ packument: p, candidateFiles: cand, baselineFiles: base }),
    );
    expect(result.evidences.find((e) => e.key === "diff:new-script")?.status).toBe("fail");
    expect(result.evidences.find((e) => e.key === "diff:new-endpoint")?.status).toBe("fail");
    expect(result.evidences.find((e) => e.key === "diff:new-endpoint")?.detail).toContain(
      "collect.example.com",
    );
  });

  it("reports new dependencies as info for osv to consume", async () => {
    const p = packument({
      deps: { "1.0.0": {}, "2.0.0": { axios: "^1.0.0" } },
    });
    const result = await diffScanner.scan(ctx({ packument: p }));
    const ev = result.evidences.find((e) => e.key === "diff:new-dependencies");
    expect(ev?.status).toBe("info");
    expect(ev?.detail).toContain("axios");
  });

  it("skips gracefully for install scenario", async () => {
    const result = await diffScanner.scan(ctx({ baselineVersion: null, baselineFiles: null }));
    expect(result.evidences.find((e) => e.key === "diff:skipped")?.status).toBe("info");
  });
});

describe("normalizeRepo", () => {
  it.each([
    ["git+https://github.com/Org/Repo.git", "org/repo"],
    ["https://github.com/foo/bar/issues", "foo/bar"],
    ["foo/bar", "foo/bar"],
    ["git+https://gitlab.com/foo/bar", "gitlab.com/foo/bar"],
  ])("%s → %s", (input, expected) => {
    expect(normalizeRepo(input)).toBe(expected);
  });
});
