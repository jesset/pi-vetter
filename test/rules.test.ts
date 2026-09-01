import { describe, expect, it } from "vitest";
import {
  aggregate,
  deriveFindings,
  disabledRules,
  filterEnabled,
  RULES,
} from "../src/core/rules.ts";
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

  it("maps socket alerts to the socket-flagged rule", () => {
    const findings = deriveFindings([
      { scanner: "socket", key: "socket:alerts", status: "fail", detail: "gptMalware" },
    ]);
    expect(findings[0]?.ruleId).toBe("socket-flagged");
  });

  it("maps eval and dynamic-module hits to dynamic-code-execution (#40)", () => {
    const findings = deriveFindings([
      { scanner: "static", key: "static:eval", status: "fail", detail: "eval" },
      { scanner: "static", key: "static:dynamic-module", status: "fail", detail: "join" },
    ]);
    expect(findings.map((f) => f.ruleId)).toEqual([
      "dynamic-code-execution",
      "dynamic-code-execution",
    ]);
  });

  it("maps transitive dependency risk to the transitive-risk rule (#41)", () => {
    const findings = deriveFindings([
      { scanner: "static", key: "static:dependency-risk", status: "fail", detail: "x" },
    ]);
    expect(findings[0]?.ruleId).toBe("transitive-risk");
  });
  it("maps provenance:missing to the provenance-missing rule (#44)", () => {
    const findings = deriveFindings([
      { scanner: "provenance", key: "provenance:missing", status: "fail", detail: "x" },
    ]);
    expect(findings[0]?.ruleId).toBe("provenance-missing");
  });
});

describe("disabledRules (#42)", () => {
  it("lists rules disabled via config with their default kind", () => {
    const config = {
      ...{ rules: { deny: {}, ask: { "young-package": false, obfuscation: false } } },
    } as unknown as VetterConfig;
    const disabled = disabledRules(config);
    expect(disabled).toContain("young-package");
    expect(disabled).toContain("obfuscation");
  });

  it("is empty with the default policy", () => {
    expect(disabledRules({ rules: { deny: {}, ask: {} } } as unknown as VetterConfig)).toEqual([]);
  });
});

describe("filterEnabled", () => {
  const config: VetterConfig = {
    scanners: {},
    rules: { deny: {}, ask: { "young-package": false } },
    provenance: { required: false },
    cache: { enabled: true, ttlHours: 24 },
    score: { weights: {} },
    network: { timeoutMs: 30_000 },
    install: { pinOnInstall: false },
    dependencies: { enabled: false, maxDepth: 2, maxPackages: 20 },
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
