import type {
  Evidence,
  Finding,
  RuleId,
  RuleKind,
  Severity,
  Verdict,
  VetterConfig,
} from "./types.ts";

interface RuleDef {
  kind: RuleKind;
  severity: Severity;
  description: string;
}

export const RULES: Record<RuleId, RuleDef> = {
  "malicious-package": {
    kind: "deny",
    severity: "critical",
    description: "Listed as malicious (OpenSSF MAL- advisory via OSV)",
  },
  "provenance-conflict": {
    kind: "deny",
    severity: "critical",
    description: "Provenance/attestation missing or contradicting the declared repository",
  },
  "provenance-missing": {
    kind: "ask",
    severity: "medium",
    description: "No npm attestations published for the version (provenance.required policy)",
  },
  "vt-detections": {
    kind: "deny",
    severity: "critical",
    description: "Multiple antivirus engines flag the tarball on VirusTotal",
  },
  "known-vulnerability": {
    kind: "ask",
    severity: "high",
    description: "Candidate version has a known vulnerability advisory (GHSA/CVE via OSV)",
  },
  "socket-flagged": {
    kind: "ask",
    severity: "high",
    description:
      "High-risk Socket.dev alert (gptMalware, installScripts, obfuscatedFile, typosquatting, ...)",
  },
  "new-lifecycle-script": {
    kind: "ask",
    severity: "high",
    description: "New install/preinstall/postinstall script since baseline",
  },
  "maintainer-change": {
    kind: "ask",
    severity: "medium",
    description: "Maintainer set changed (new maintainer added)",
  },
  "new-dependency-flagged": {
    kind: "ask",
    severity: "high",
    description: "New dependency has an OSV advisory",
  },
  "new-network-endpoint": {
    kind: "ask",
    severity: "medium",
    description: "New outbound URL/host since baseline",
  },
  "new-child-process": {
    kind: "ask",
    severity: "medium",
    description: "child_process usage appeared since baseline",
  },
  "credential-access": {
    kind: "ask",
    severity: "high",
    description: "Reads credential paths or secret environment variables",
  },
  "dynamic-code-execution": {
    kind: "ask",
    severity: "medium",
    description:
      "eval/new Function/vm family, or dynamic module resolution (concatenated, decoded or variable require/import)",
  },
  "transitive-risk": {
    kind: "ask",
    severity: "high",
    description:
      "Risky pattern hits (credentials, obfuscation, prompt injection, dynamic code) inside a scanned dependency tarball",
  },
  obfuscation: {
    kind: "ask",
    severity: "high",
    description: "Obfuscation markers (long base64/hex blobs, dynamic require, eval family)",
  },
  "prompt-injection-marker": {
    kind: "ask",
    severity: "medium",
    description: "Prompt-injection marker strings detected",
  },
  "young-package": {
    kind: "ask",
    severity: "medium",
    description: "Package younger than 7 days",
  },
  "rapid-release": {
    kind: "ask",
    severity: "low",
    description: "3 or more releases within 24h",
  },
  "deprecated-candidate": {
    kind: "ask",
    severity: "medium",
    description: "Candidate version is marked deprecated",
  },
};

export function isRuleEnabled(config: VetterConfig, ruleId: RuleId): boolean {
  const def = RULES[ruleId];
  const section = config.rules[def.kind];
  const entry = section?.[ruleId];
  return entry !== false;
}

export function filterEnabled(findings: Finding[], config: VetterConfig): Finding[] {
  return findings.filter((f) => isRuleEnabled(config, f.ruleId));
}

/** Rules the user switched off (#42): the report must disclose this policy. */
export function disabledRules(config: VetterConfig): RuleId[] {
  return (Object.keys(RULES) as RuleId[]).filter((id) => !isRuleEnabled(config, id));
}

export interface AggregateResult {
  verdict: Verdict;
  capped: boolean;
}

/**
 * ADR-0001: verdicts are rule-driven. ADR-0002: incomplete evidence caps the
 * verdict at ASK, but never downgrades an earned DENY.
 */
export function aggregate(findings: Finding[], hasIncompleteEvidence: boolean): AggregateResult {
  if (findings.some((f) => RULES[f.ruleId]?.kind === "deny")) {
    return { verdict: "DENY", capped: false };
  }
  if (findings.some((f) => RULES[f.ruleId]?.kind === "ask")) {
    return { verdict: "ASK", capped: hasIncompleteEvidence };
  }
  if (hasIncompleteEvidence) {
    return { verdict: "ASK", capped: true };
  }
  return { verdict: "ALLOW", capped: false };
}

export function hasIncomplete(evidences: Evidence[]): boolean {
  return evidences.some((e) => e.status === "incomplete");
}

/** Evidence key → rule triggered when the evidence reports a hit (status "fail"). */
const RULE_EVIDENCE_KEYS: Record<string, RuleId> = {
  "osv:malicious": "malicious-package",
  "provenance:conflict": "provenance-conflict",
  "provenance:missing": "provenance-missing",
  "virustotal:detections": "vt-detections",
  "osv:vulnerability": "known-vulnerability",
  "socket:alerts": "socket-flagged",
  "diff:new-script": "new-lifecycle-script",
  "metadata:maintainer-change": "maintainer-change",
  "osv:new-dependency-advisory": "new-dependency-flagged",
  "diff:new-endpoint": "new-network-endpoint",
  "diff:new-child-process": "new-child-process",
  "static:credential-access": "credential-access",
  "static:eval": "dynamic-code-execution",
  "static:dynamic-module": "dynamic-code-execution",
  "static:dependency-risk": "transitive-risk",
  "static:obfuscation": "obfuscation",
  "static:prompt-injection": "prompt-injection-marker",
  "metadata:young-package": "young-package",
  "metadata:rapid-release": "rapid-release",
  "metadata:deprecated": "deprecated-candidate",
};

export function deriveFindings(evidences: Evidence[]): Finding[] {
  const findings: Finding[] = [];
  for (const e of evidences) {
    const ruleId = RULE_EVIDENCE_KEYS[e.key];
    if (!ruleId || e.status !== "fail") continue;
    findings.push({
      ruleId,
      severity: RULES[ruleId].severity,
      message: e.detail,
      evidenceKeys: [e.key],
    });
  }
  return findings;
}
