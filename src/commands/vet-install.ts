import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import type { EvaluationReport } from "../core/types.ts";
import {
  type ExecFn,
  type InstalledFilesReader,
  installApproved,
  renderOutcomes,
} from "../install/gated-installer.ts";
import { NO_PACKAGES_MESSAGE, renderNotes, renderReports } from "../ui/report.ts";
import { selectForInstall, type UiPort } from "../ui/select.ts";
import { type ProgressPort, runVet, type VetDeps } from "./vet.ts";

export interface InstallCommandDeps extends VetDeps {
  exec: ExecFn;
  pinOnInstall: boolean;
  unpin: (name: string, version: string) => void;
  /** Reads the installed package directory for post-install verification (#48). */
  readInstalledFiles?: InstalledFilesReader;
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
  const { reports, notes } = await runVet(deps, rawArgs, progress);
  const header = [renderReports(reports), renderNotes(notes)].filter(Boolean).join("\n\n");

  if (reports.length === 0) {
    return { content: header || NO_PACKAGES_MESSAGE, reports };
  }

  const selection = await selectForInstall(toUiPort(ctx), reports);
  if (selection.cancelled || selection.selected.length === 0) {
    return {
      content: [header, "Nothing selected for installation."].filter(Boolean).join("\n\n"),
      reports,
    };
  }

  const chosen = reports.filter((r) => selection.selected.includes(r.candidate.name));
  const outcomes = await installApproved(deps.exec, chosen, {
    unpin: deps.unpin,
    pinOnInstall: deps.pinOnInstall,
    ...(deps.readInstalledFiles ? { readInstalledFiles: deps.readInstalledFiles } : {}),
  });
  return {
    content: [header, `**Install results**\n${renderOutcomes(outcomes)}`]
      .filter(Boolean)
      .join("\n\n"),
    reports,
  };
}
