import { describe, expect, it } from "vitest";
import { runVet } from "../../src/commands/vet.ts";
import type { EvaluationReport } from "../../src/core/types.ts";
import { renderReports } from "../../src/ui/report.ts";
import type { FixturePackage } from "./helpers/fixtures.ts";
import { withHarness } from "./helpers/harness.ts";

const installed = (name: string, version = "1.0.0", pinned = false) => ({
  source: pinned ? `npm:${name}@${version}` : `npm:${name}`,
  name,
  version,
  pinned,
  scope: "user" as const,
});

const byName = (reports: EvaluationReport[], name: string): EvaluationReport | undefined =>
  reports.find((r) => r.candidate.name === name);

describe("e2e: verdict derivation & presentation", () => {
  it("asks when the candidate adds a lifecycle script the baseline never had", async () => {
    const pkg: FixturePackage = {
      name: "scripty-pkg",
      versions: [
        { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
        {
          version: "1.1.0",
          files: [{ path: "index.js", content: "module.exports = 2;\n" }],
          scripts: { postinstall: "node setup.js" },
        },
      ],
    };
    await withHarness(
      { fixtures: [pkg], installed: [installed("scripty-pkg")] },
      async ({ deps }) => {
        const { reports, notes } = await runVet(deps, "npm:scripty-pkg");
        expect(notes).toEqual([]);
        const report = byName(reports, "scripty-pkg");
        expect(report?.verdict).toBe("ASK");
        expect(report?.findings.map((f) => f.ruleId)).toEqual(["new-lifecycle-script"]);
        expect(report?.hasLifecycleScripts).toBe(true);
        expect(
          report?.evidences.some((e) => e.key === "diff:new-script" && e.status === "fail"),
        ).toBe(true);
        // the fixed lifecycle-script warning must surface in the report
        expect(renderReports(reports)).toContain("**Lifecycle scripts**");
      },
    );
  });

  it("asks on eval-family code in the candidate (#40)", async () => {
    const pkg: FixturePackage = {
      name: "eval-pkg",
      versions: [
        {
          version: "1.1.0",
          files: [{ path: "index.js", content: "module.exports = eval(process.argv[2]);\n" }],
        },
      ],
    };
    await withHarness({ fixtures: [pkg] }, async ({ deps }) => {
      const { reports } = await runVet(deps, "npm:eval-pkg");
      const report = byName(reports, "eval-pkg");
      expect(report?.verdict).toBe("ASK");
      expect(report?.findings.map((f) => f.ruleId)).toContain("dynamic-code-execution");
      expect(renderReports(reports)).toContain("**Verdict: ASK**");
    });
  });

  it("denies when OSV lists the candidate as malicious", async () => {
    const pkg: FixturePackage = {
      name: "evil-pkg",
      versions: [
        { version: "1.1.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
      ],
    };
    await withHarness(
      { fixtures: [pkg], osvHits: { "evil-pkg": ["MAL-2026-9999"] } },
      async ({ deps }) => {
        const { reports } = await runVet(deps, "npm:evil-pkg");
        const report = byName(reports, "evil-pkg");
        expect(report?.verdict).toBe("DENY");
        expect(report?.capped).toBe(false);
        expect(report?.findings.map((f) => f.ruleId)).toEqual(["malicious-package"]);
        expect(report?.evidences.some((e) => e.key === "osv:malicious")).toBe(true);
        expect(renderReports(reports)).toContain("**Verdict: DENY**");
      },
    );
  });

  it("still targets a pinned baseline with a newer version available", async () => {
    const pkg: FixturePackage = {
      name: "pinned-pkg",
      versions: [
        { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
        { version: "1.1.0", files: [{ path: "index.js", content: "module.exports = 2;\n" }] },
      ],
    };
    await withHarness(
      { fixtures: [pkg], installed: [installed("pinned-pkg", "1.0.0", true)] },
      async ({ deps }) => {
        // no explicit specs: the installed inventory is the whole universe
        const { reports, notes } = await runVet(deps, "");
        expect(notes).toEqual([]);
        const report = byName(reports, "pinned-pkg");
        expect(report?.candidate.version).toBe("1.1.0");
        expect(report?.baseline?.pinned).toBe(true);
        expect(renderReports(reports)).toContain("(baseline is pinned)");
      },
    );
  });

  it("discloses scanners enabled but missing credentials instead of running silently (#33)", async () => {
    const pkg: FixturePackage = {
      name: "gap-pkg",
      versions: [
        { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
      ],
    };
    await withHarness({ fixtures: [pkg] }, async ({ deps }) => {
      deps.config.scanners.virustotal = { enabled: true, timeoutMs: 1000 };
      deps.config.scanners.socket = { enabled: true };
      const { notes } = await runVet(deps, "npm:gap-pkg");
      expect(notes).toContain(
        "- virustotal: enabled but not configured (apiKey missing) — scanner skipped (free public key: register at virustotal.com)",
      );
      expect(notes).toContain(
        "- socket: enabled but not configured (apiKey, orgSlug missing) — scanner skipped (free tier key: register at socket.dev)",
      );
    });
  });

  it("escalates risky deep-scan hits to an ASK verdict attributed per dependency (#41)", async () => {
    const host: FixturePackage = {
      name: "host-pkg",
      versions: [
        { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
        {
          version: "1.1.0",
          files: [{ path: "index.js", content: "module.exports = 2;\n" }],
          dependencies: { "sketchy-dep": "^1.0.0" },
        },
      ],
    };
    const sketchyDep: FixturePackage = {
      name: "sketchy-dep",
      versions: [
        {
          version: "1.0.4",
          files: [
            // credential-access pattern (process.env SECRET token read)
            { path: "index.js", content: "module.exports = process.env.CI_SECRET_TOKEN;\n" },
          ],
        },
      ],
    };
    await withHarness(
      { fixtures: [host, sketchyDep], installed: [installed("host-pkg")] },
      async ({ deps }) => {
        const { reports, notes } = await runVet(deps, "npm:host-pkg");
        expect(notes).toEqual([]);
        const report = byName(reports, "host-pkg");
        // risky transitive hits fail and drive the verdict, still attributed per dependency
        const hit = report?.evidences.find((e) => e.key === "static:dependency-risk");
        expect(hit?.status).toBe("fail");
        expect(hit?.detail).toContain("sketchy-dep@1.0.4: credential");
        expect(report?.verdict).toBe("ASK");
        expect(report?.findings.map((f) => f.ruleId)).toContain("transitive-risk");
      },
    );
  });

  it("renders a mixed batch ordered DENY → ASK → ALLOW", async () => {
    const mk = (name: string, script?: Record<string, string>): FixturePackage => ({
      name,
      versions: [
        { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
        {
          version: "1.1.0",
          files: [{ path: "index.js", content: "module.exports = 2;\n" }],
          ...(script ? { scripts: script } : {}),
        },
      ],
    });
    await withHarness(
      {
        fixtures: [mk("allow-pkg"), mk("ask-pkg", { postinstall: "node x.js" }), mk("deny-pkg")],
        installed: [installed("allow-pkg"), installed("ask-pkg"), installed("deny-pkg")],
        osvHits: { "deny-pkg": ["MAL-2026-1"] },
      },
      async ({ deps }) => {
        const { reports } = await runVet(deps, "");
        expect(reports.map((r) => r.verdict).sort()).toEqual(["ALLOW", "ASK", "DENY"]);
        const rendered = renderReports(reports);
        const pos = (name: string): number => rendered.indexOf(`### ${name}`);
        expect(pos("deny-pkg")).toBeLessThan(pos("ask-pkg"));
        expect(pos("ask-pkg")).toBeLessThan(pos("allow-pkg"));
      },
    );
  });

  it("asks on the second run when the maintainer set changed in between", async () => {
    const pkg: FixturePackage = {
      name: "flip-pkg",
      versions: [
        { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
        { version: "1.1.0", files: [{ path: "index.js", content: "module.exports = 2;\n" }] },
      ],
    };
    await withHarness(
      {
        fixtures: [pkg],
        installed: [installed("flip-pkg")],
        // cross-run state needs the second run's scanners to actually run
        cacheEnabled: false,
      },
      async ({ deps, registry }) => {
        const first = await runVet(deps, "npm:flip-pkg");
        expect(byName(first.reports, "flip-pkg")?.verdict).toBe("ALLOW");
        expect(
          byName(first.reports, "flip-pkg")?.evidences.some(
            (e) => e.key === "metadata:maintainers-recorded",
          ),
        ).toBe(true);

        // the registry hands over maintainership between the two runs
        registry.packumentOf("flip-pkg")?.maintainers.push({ username: "newcomer" });

        const second = await runVet(deps, "npm:flip-pkg");
        const report = byName(second.reports, "flip-pkg");
        expect(report?.verdict).toBe("ASK");
        expect(report?.findings.map((f) => f.ruleId)).toEqual(["maintainer-change"]);
        expect(
          report?.evidences.some(
            (e) => e.key === "metadata:maintainer-change" && e.status === "fail",
          ),
        ).toBe(true);
      },
    );
  });
});
