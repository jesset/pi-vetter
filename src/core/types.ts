export type Verdict = "ALLOW" | "ASK" | "DENY";
export type Layer = 0 | 1 | 2 | 3;
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type RuleKind = "deny" | "ask";

export type ScannerName =
  | "metadata"
  | "osv"
  | "provenance"
  | "static"
  | "diff"
  | "virustotal"
  | "socket";

export type RuleId =
  | "malicious-package"
  | "provenance-conflict"
  | "vt-detections"
  | "known-vulnerability"
  | "new-lifecycle-script"
  | "maintainer-change"
  | "new-dependency-flagged"
  | "new-network-endpoint"
  | "new-child-process"
  | "credential-access"
  | "obfuscation"
  | "prompt-injection-marker"
  | "young-package"
  | "rapid-release"
  | "deprecated-candidate";

export interface Candidate {
  name: string;
  version: string;
  scenario: "update" | "install";
}

export interface Baseline {
  name: string;
  version: string;
}

export interface Evidence {
  scanner: ScannerName;
  key: string;
  status: "pass" | "fail" | "info" | "skipped" | "incomplete";
  detail: string;
  data?: unknown;
}

export interface ScanResult {
  scanner: ScannerName;
  status: "ok" | "error" | "timeout" | "quota-exhausted";
  evidences: Evidence[];
}

export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  message: string;
  evidenceKeys: string[];
}

/** npm registry 完整 packument 中单个 version 的形状（仅声明用到的字段） */
export interface PackumentVersion {
  version: string;
  deprecated?: string;
  dist: {
    integrity?: string;
    tarball: string;
    attestations?: { url: string };
  };
  dependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

export interface Packument {
  name: string;
  "dist-tags": Record<string, string>;
  versions: Record<string, PackumentVersion>;
  time: Record<string, string>;
  maintainers: { name?: string; email?: string; username?: string }[];
  repository?: { type?: string; url?: string } | string;
}

/** In-memory file map of a parsed tarball: package-internal path → raw bytes. */
export type TarFiles = Map<string, Uint8Array>;

export interface Artifacts {
  candidateFiles: TarFiles;
  baselineFiles: TarFiles | null;
  candidatePackument: Packument;
  candidateIntegrity: string;
  downloads: number;
}

export interface ScannerContext {
  candidate: Candidate;
  baseline: Baseline | null;
  artifacts: Artifacts;
}

export interface SecurityScanner {
  readonly name: ScannerName;
  readonly layer: Layer;
  scan(ctx: ScannerContext): Promise<ScanResult>;
}

export interface EvaluationReport {
  candidate: Candidate;
  baseline: Baseline | null;
  verdict: Verdict;
  capped: boolean;
  findings: Finding[];
  evidences: Evidence[];
  riskScore: number;
  hasLifecycleScripts: boolean;
}

export interface ScannerConfig {
  enabled: boolean;
  apiKey?: string;
  timeoutMs?: number;
}

export interface VetterConfig {
  scanners: Partial<Record<ScannerName, ScannerConfig>>;
  rules: { deny: Partial<Record<string, boolean>>; ask: Partial<Record<string, boolean>> };
  cache: { enabled: boolean; ttlHours: number };
  score: { weights: Partial<Record<string, number>> };
}
