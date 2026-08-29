import { describe, expect, it } from "vitest";
import { runVet } from "../../src/commands/vet.ts";
import { renderReports } from "../../src/ui/report.ts";
import type { FixturePackage } from "./helpers/fixtures.ts";
import { withHarness } from "./helpers/harness.ts";

/** A package whose 1.0.0 → 1.1.0 update touches no risk signal at all. */
const cleanPkg: FixturePackage = {
  name: "clean-pkg",
  versions: [
    { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = () => 42;\n" }] },
    { version: "1.1.0", files: [{ path: "index.js", content: "module.exports = () => 43;\n" }] },
  ],
};

describe("e2e: /vet full chain against the fake registry", () => {
  it("yields ALLOW for a clean update, end to end", async () => {
    await withHarness(
      {
        fixtures: [cleanPkg],
        installed: [
          {
            source: "npm:clean-pkg",
            name: "clean-pkg",
            version: "1.0.0",
            pinned: false,
            scope: "user",
          },
        ],
      },
      async ({ deps }) => {
        // Full chain: parseArgs → resolveTargets → buildArtifacts (download,
        // integrity check, tarball parse) → evaluate (all scanners) → render.
        const { reports, notes } = await runVet(deps, "npm:clean-pkg");
        expect(notes).toEqual([]);
        expect(reports).toHaveLength(1);

        const [report] = reports;
        if (!report) throw new Error("expected exactly one report");
        expect(report.candidate).toMatchObject({
          name: "clean-pkg",
          version: "1.1.0",
          scenario: "update",
        });
        expect(report.verdict).toBe("ALLOW");
        expect(report.capped).toBe(false);
        expect(report.findings).toEqual([]);
        expect(report.hasLifecycleScripts).toBe(false);

        // every enabled scanner completed and reported
        const keys = report.evidences.map((e) => e.key);
        expect(keys).toContain("osv:clean");
        expect(keys).toContain("diff:scripts-stable");
        expect(keys).toContain("provenance:none");
        expect(keys).toContain("static:scanned");
        expect(keys).toContain("metadata:downloads");
        expect(report.evidences.every((e) => e.status !== "incomplete")).toBe(true);

        // rendering carries the verdict and the update headline
        const rendered = renderReports(reports);
        expect(rendered).toContain("clean-pkg 1.0.0 → 1.1.0");
        expect(rendered).toContain("**Verdict: ALLOW**");
        expect(rendered).toContain("`osv:clean`");
      },
    );
  });
});
