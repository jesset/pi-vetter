import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { type ExecFn, installApproved, renderOutcomes } from "../install/gated-installer.ts";
import { renderReports } from "../ui/report.ts";
import { selectForInstall, type UiPort } from "../ui/select.ts";
import { runVet, type VetDeps } from "./vet.ts";

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
): Promise<string> {
  const { reports, notes } = await runVet(deps, rawArgs);
  const header = [renderReports(reports), notes.join("\n")].filter(Boolean).join("\n\n");

  if (reports.length === 0) {
    return header || "No packages to evaluate.";
  }

  const selection = await selectForInstall(toUiPort(ctx), reports);
  if (selection.cancelled || selection.selected.length === 0) {
    return `${header}\n\nNothing selected for installation.`;
  }

  const chosen = reports.filter((r) => selection.selected.includes(r.candidate.name));
  const outcomes = await installApproved(deps.exec, chosen);
  return `${header}\n\n**Install results**\n${renderOutcomes(outcomes)}`;
}
