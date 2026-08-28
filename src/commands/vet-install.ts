import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import type { EvaluationReport } from "../core/types.ts";
import { type ExecFn, installApproved, renderOutcomes } from "../install/gated-installer.ts";
import { renderReports } from "../ui/report.ts";
import { selectForInstall, type UiPort } from "../ui/select.ts";
import { type ProgressPort, runVet, type VetDeps } from "./vet.ts";

export interface InstallCommandDeps extends VetDeps {
  exec: ExecFn;
}

export interface VetInstallResult {
  content: string;
  reports: EvaluationReport[];
}

function toUiPort(ctx: ExtensionCommandContext): UiPort {
  return {
    mode: ctx.mode,
    custom: (factory) => ctx.ui.custom(factory),
    confirm: (title, message) => ctx.ui.confirm(title, message),
  };
}

export async function runVetInstall(
  deps: InstallCommandDeps,
  rawArgs: string,
  ctx: ExtensionCommandContext,
  progress?: ProgressPort,
): Promise<VetInstallResult> {
  const { reports, notes } = await runVet(deps, rawArgs, undefined, progress);
  const header = [renderReports(reports), notes.length > 0 ? `**Notes**\n${notes.join("\n")}` : ""]
    .filter(Boolean)
    .join("\n\n");

  if (reports.length === 0) {
    return { content: header || "No packages to evaluate.", reports };
  }

  const selection = await selectForInstall(toUiPort(ctx), reports);
  if (selection.cancelled || selection.selected.length === 0) {
    return {
      content: [header, "Nothing selected for installation."].filter(Boolean).join("\n\n"),
      reports,
    };
  }

  const chosen = reports.filter((r) => selection.selected.includes(r.candidate.name));
  const outcomes = await installApproved(deps.exec, chosen);
  return {
    content: [header, `**Install results**\n${renderOutcomes(outcomes)}`]
      .filter(Boolean)
      .join("\n\n"),
    reports,
  };
}
