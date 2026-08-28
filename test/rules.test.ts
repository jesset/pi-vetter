import { describe, expect, it } from "vitest";
import { aggregate, deriveFindings, filterEnabled, RULES } from "../src/core/rules.ts";
import type { Evidence, Finding, VetterConfig } from "../src/core/types.ts";

function askFinding(ruleId: keyof typeof RULES = "young-package"): Finding {
  return { ruleId, severity: RULES[ruleId].severity, message: "x", evidenceKeys: ["k"] };
}

function denyFinding(): Finding {
  return { ruleId: "malicious-package", severity: "critical", message: "x", evidenceKeys: ["k"] };
}

function ev(key: string, status: Evidence["status"]): Evidence {
  return { scanner: "osv", key, status, detail: key };
}

describe("aggregate", () => {
  it("no findings and complete evidence → ALLOW", () => {
    expect(aggregate([], false)).toEqual({ verdict: "ALLOW", capped: false });
  });

  it("ask finding → ASK", () => {
    expect(aggregate([askFinding()], false)).toEqual({ verdict: "ASK", capped: false });
  });

  it("deny finding → DENY", () => {
    expect(aggregate([askFinding(), denyFinding()], false)).toEqual({
      verdict: "DENY",
      capped: false,
    });
  });

  it("incomplete evidence with no findings → ASK capped", () => {
    expect(aggregate([], true)).toEqual({ verdict: "ASK", capped: true });
  });

  it("incomplete evidence with ask finding → ASK capped", () => {
    expect(aggregate([askFinding()], true)).toEqual({ verdict: "ASK", capped: true });
  });

  it("incomplete evidence never downgrades DENY (ADR-0002)", () => {
    expect(aggregate([denyFinding()], true)).toEqual({ verdict: "DENY", capped: false });
  });
});

describe("deriveFindings", () => {
  it("maps evidence hits to rule findings", () => {
    const findings = deriveFindings([
      ev("diff:new-script", "fail"),
      ev("provenance:verified", "pass"),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("new-lifecycle-script");
  });

  it("ignores non-rule evidence keys", () => {
    expect(deriveFindings([ev("osv:clean", "pass"), ev("unknown:key", "fail")])).toEqual([]);
  });
});

describe("filterEnabled", () => {
  const config: VetterConfig = {
    scanners: {},
    rules: { deny: {}, ask: { "young-package": false } },
    cache: { enabled: true, ttlHours: 24 },
    score: { weights: {} },
  };

  it("drops findings whose rule is disabled", () => {
    const kept = filterEnabled([askFinding("young-package"), askFinding("rapid-release")], config);
    expect(kept.map((f) => f.ruleId)).toEqual(["rapid-release"]);
  });

  it("keeps rules not mentioned in config (default on)", () => {
    const kept = filterEnabled([askFinding("obfuscation")], config);
    expect(kept).toHaveLength(1);
  });
});
