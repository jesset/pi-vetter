import { RULES } from "../core/rules.ts";
import type { EvaluationReport } from "../core/types.ts";

const STATUS_GLYPH: Record<string, string> = {
  pass: "✓",
  fail: "✗",
  info: "·",
  skipped: "-",
  incomplete: "!",
};

function headline(report: EvaluationReport): string {
  if (report.candidate.scenario === "install" || !report.baseline) {
    return `install ${report.candidate.name}@${report.candidate.version}`;
  }
  return `${report.candidate.name} ${report.baseline.version} → ${report.candidate.version}`;
}

export function renderReport(report: EvaluationReport): string {
  const lines: string[] = [];
  const verdictLabel = report.capped
    ? `${report.verdict} (capped: incomplete evidence)`
    : report.verdict;
  lines.push(`### ${headline(report)}`);
  lines.push(`**Verdict: ${verdictLabel}** · Risk score ${report.riskScore}/100 (display only)`);

  if (report.findings.length > 0) {
    lines.push("");
    lines.push("**Findings**");
    for (const f of report.findings) {
      lines.push(`- **${f.ruleId}** (${RULES[f.ruleId]?.kind}/${f.severity}): ${f.message}`);
    }
  }

  lines.push("");
  lines.push("**Evidence**");
  for (const e of report.evidences) {
    lines.push(`- ${STATUS_GLYPH[e.status] ?? "?"} \`${e.key}\` — ${e.detail}`);
  }

  if (report.hasLifecycleScripts) {
    lines.push("");
    lines.push(
      "> ⚠ **Lifecycle scripts**: approving install will run this package's install scripts. Pi does not install with `--ignore-scripts`, so this happens with your user permissions.",
    );
  }
  return lines.join("\n");
}

const VERDICT_ORDER = { DENY: 0, ASK: 1, ALLOW: 2 } as const;

export function renderReports(reports: EvaluationReport[]): string {
  if (reports.length === 0) return "No packages to evaluate.";
  return [...reports]
    .sort((a, b) => VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict])
    .map(renderReport)
    .join("\n\n---\n\n");
}
