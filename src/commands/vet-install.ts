import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import type { EvaluationReport } from "../core/types.ts";
import { type ExecFn, installApproved, renderOutcomes } from "../install/gated-installer.ts";
import { selectForInstall, type UiPort } from "../ui/select.ts";
import { type ProgressPort, runVet, type VetDeps } from "./vet.ts";

export interface InstallCommandDeps extends VetDeps {
  exec: ExecFn;
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
  onReport?: (report: EvaluationReport) => void,
  progress?: ProgressPort,
): Promise<string> {
  const { reports, notes } = await runVet(deps, rawArgs, onReport, progress);
  const header = notes.length > 0 ? `**Notes**\n${notes.join("\n")}` : "";

  if (reports.length === 0) {
    return header || "No packages to evaluate.";
  }

  const selection = await selectForInstall(toUiPort(ctx), reports);
  if (selection.cancelled || selection.selected.length === 0) {
    return [header, "Nothing selected for installation."].filter(Boolean).join("\n\n");
  }

  const chosen = reports.filter((r) => selection.selected.includes(r.candidate.name));
  const outcomes = await installApproved(deps.exec, chosen);
  return [header, `**Install results**\n${renderOutcomes(outcomes)}`].filter(Boolean).join("\n\n");
}
