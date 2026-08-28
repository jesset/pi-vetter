import { RULES } from "./rules.ts";
import type { Finding, VetterConfig } from "./types.ts";

const DEFAULT_WEIGHTS: Record<string, number> = {
  "malicious-package": 100,
  "provenance-conflict": 95,
  "vt-detections": 90,
  "known-vulnerability": 45,
  "new-lifecycle-script": 40,
  "new-dependency-flagged": 35,
  "credential-access": 50,
  obfuscation: 40,
  "prompt-injection-marker": 30,
  "maintainer-change": 20,
  "new-network-endpoint": 30,
  "new-child-process": 30,
  "young-package": 20,
  "rapid-release": 10,
  "deprecated-candidate": 15,
};

export interface ScoreModifiers {
  provenanceVerified: boolean;
  packageAgeDays: number | null;
}

/**
 * Display-only aggregation (ADR-0001): the score never influences the verdict.
 */
export function riskScore(
  findings: Finding[],
  modifiers: ScoreModifiers,
  config: VetterConfig,
): number {
  let score = 0;
  for (const f of findings) {
    const configured = config.score.weights[f.ruleId];
    score += configured ?? DEFAULT_WEIGHTS[f.ruleId] ?? 0;
  }
  if (modifiers.provenanceVerified) score -= 10;
  if (modifiers.packageAgeDays !== null && modifiers.packageAgeDays > 365) score -= 10;
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function severityOf(ruleId: keyof typeof RULES): string {
  return RULES[ruleId].severity;
}
