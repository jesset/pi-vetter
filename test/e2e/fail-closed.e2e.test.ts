import { describe, expect, it } from "vitest";
import { runVet } from "../../src/commands/vet.ts";
import type { EvaluationReport } from "../../src/core/types.ts";
import { renderReports } from "../../src/ui/report.ts";
import type { FixturePackage } from "./helpers/fixtures.ts";
import { withHarness } from "./helpers/harness.ts";

/** Clean in every dimension — faults below are the only thing that can bite. */
const quietPkg: FixturePackage = {
  name: "quiet-pkg",
  versions: [
    { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = () => 1;\n" }] },
    { version: "1.1.0", files: [{ path: "index.js", content: "module.exports = () => 2;\n" }] },
  ],
};

const installedQuiet = [
  {
    source: "npm:quiet-pkg",
    name: "quiet-pkg",
    version: "1.0.0",
    pinned: false,
    scope: "user" as const,
  },
];

const osvQuerybatch = (method: string, url: URL): boolean =>
  method === "POST" && url.pathname === "/osv/v1/querybatch";

function osvIncomplete(report: EvaluationReport | undefined) {
  return report?.evidences.find((e) => e.key === "osv:incomplete");
}

describe("e2e: fail-closed under fault injection", () => {
  it("caps the verdict at ASK when the OSV endpoint returns 500", async () => {
    await withHarness(
      { fixtures: [quietPkg], installed: installedQuiet },
      async ({ deps, registry }) => {
        registry.setFault({ match: osvQuerybatch, status: 500 });

        const { reports, notes } = await runVet(deps, "npm:quiet-pkg");
        expect(notes).toEqual([]);

        const [report] = reports;
        expect(report?.verdict).toBe("ASK");
        expect(report?.capped).toBe(true);
        expect(osvIncomplete(report)?.status).toBe("incomplete");
        // #35: the underlying failure reason must be diagnosable from the report
        expect(osvIncomplete(report)?.detail).toContain("errored: OSV querybatch failed: HTTP 500");

        // the fault is contained: osv is the ONLY incomplete evidence
        expect(
          report?.evidences.filter((e) => e.status === "incomplete").map((e) => e.scanner),
        ).toEqual(["osv"]);
        expect(report?.evidences.some((e) => e.key === "diff:scripts-stable")).toBe(true);
        expect(renderReports(reports)).toContain("**Verdict: ASK (capped: incomplete evidence)**");
      },
    );
  });

  it("caps the verdict at ASK when the OSV endpoint stalls past its timeout", async () => {
    await withHarness(
      { fixtures: [quietPkg], installed: installedQuiet, osvTimeoutMs: 200 },
      async ({ deps, registry }) => {
        registry.setFault({ match: osvQuerybatch, delayMs: 5_000 });

        const { reports } = await runVet(deps, "npm:quiet-pkg");
        const [report] = reports;
        expect(report?.verdict).toBe("ASK");
        expect(report?.capped).toBe(true);
        expect(osvIncomplete(report)?.detail).toContain("timed out");
      },
    );
  });

  it("fails loudly when served tarball bytes do not match dist.integrity", async () => {
    const tampered: FixturePackage = {
      name: "tampered-pkg",
      versions: [
        // corrupt: the registry serves different bytes than it attests to
        {
          version: "1.1.0",
          corrupt: true,
          files: [{ path: "index.js", content: "module.exports = () => 3;\n" }],
        },
      ],
    };
    await withHarness({ fixtures: [tampered] }, async ({ deps }) => {
      const { reports, notes } = await runVet(deps, "npm:tampered-pkg");
      // no report at all — a tampered candidate never reaches a verdict,
      // let alone ALLOW
      expect(reports).toEqual([]);
      expect(notes).toHaveLength(1);
      expect(notes[0]).toContain("tampered-pkg@1.1.0");
      expect(notes[0]).toContain("integrity mismatch");
    });
  });

  it("discloses a packument 404 in notes without crashing", async () => {
    await withHarness({ fixtures: [quietPkg] }, async ({ deps }) => {
      const { reports, notes } = await runVet(deps, "npm:ghost-pkg");
      expect(reports).toEqual([]);
      expect(notes).toEqual([expect.stringContaining("registry lookup failed")]);
      expect(notes[0]).toContain("ghost-pkg");
    });
  });

  it("discloses an unknown version in notes without crashing", async () => {
    await withHarness({ fixtures: [quietPkg] }, async ({ deps }) => {
      const { reports, notes } = await runVet(deps, "npm:quiet-pkg@9.9.9");
      expect(reports).toEqual([]);
      expect(notes).toEqual([expect.stringContaining("version 9.9.9 not found on registry")]);
    });
  });
});
