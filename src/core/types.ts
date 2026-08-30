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
  | "socket-flagged"
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
  /** True when the installed baseline is a pinned spec (still evaluated, never auto-skipped). */
  pinned?: boolean;
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
  /** Failure message for status "error", so the incomplete evidence is diagnosable (#35). */
  error?: string;
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

export interface DepNode {
  name: string;
  version: string;
}

export interface Artifacts {
  candidateFiles: TarFiles;
  baselineFiles: TarFiles | null;
  candidatePackument: Packument;
  candidateIntegrity: string;
  /** Raw candidate tarball bytes (integrity-verified; used for engine uploads). */
  candidateTarball: Uint8Array;
  /** sha256 of the raw candidate tarball (VirusTotal lookup key). */
  candidateSha256: string;
  /** Deep-scan dependency tarballs keyed by `name@version` (empty when disabled). */
  dependencyFiles: Map<string, TarFiles>;
  /** Dependencies the deep scan tried but failed to fetch/verify (ADR-0002 transparency). */
  dependencySkipped: number;
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
  /** Registry dist.integrity recorded at scan time; re-checked before install (TOCTOU). */
  candidateIntegrity: string;
}

export interface ScannerConfig {
  enabled: boolean;
  apiKey?: string;
  orgSlug?: string;
  timeoutMs?: number;
  /** VirusTotal only: total budget for upload + polling (default: timeoutMs). */
  pollDeadlineMs?: number;
}

export interface VetterConfig {
  scanners: Partial<Record<ScannerName, ScannerConfig>>;
  rules: { deny: Partial<Record<string, boolean>>; ask: Partial<Record<string, boolean>> };
  cache: { enabled: boolean; ttlHours: number };
  score: { weights: Partial<Record<string, number>> };
  network: { timeoutMs: number };
  install: { pinOnInstall: boolean };
  dependencies: { enabled: boolean; maxDepth: number; maxPackages: number };
}
