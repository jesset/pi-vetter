import type { Component } from "@earendil-works/pi-tui";
import type { EvaluationReport } from "../core/types.ts";

export interface CheckboxItem {
  key: string;
  label: string;
  verdict: EvaluationReport["verdict"];
}

export interface SelectionResult {
  selected: string[];
  cancelled: boolean;
}

/** Terminal-agnostic checkbox list; rendered and driven by raw key data. */
export class CheckboxComponent implements Component {
  private cursor = 0;
  private checked: Set<string>;

  constructor(
    private readonly items: CheckboxItem[],
    private readonly done: (result: SelectionResult) => void,
    private readonly title = "Select packages to install",
  ) {
    this.checked = new Set(items.filter((i) => i.verdict === "ALLOW").map((i) => i.key));
  }

  private get selectable(): number[] {
    return this.items.map((item, i) => (item.verdict === "DENY" ? -1 : i)).filter((i) => i >= 0);
  }

  invalidate(): void {
    // no cached render state to invalidate
  }

  render(width: number): string[] {
    const lines: string[] = [this.title, ""];
    for (const [i, item] of this.items.entries()) {
      const pointer = i === this.cursor ? "❯" : " ";
      const box = item.verdict === "DENY" ? "✗" : this.checked.has(item.key) ? "[x]" : "[ ]";
      const label = `${item.label}  (${item.verdict})`.slice(0, Math.max(1, width - 8));
      lines.push(`${pointer} ${box} ${label}`);
    }
    lines.push("");
    lines.push("space=toggle  j/k=move  a=all  enter=confirm  q=cancel");
    return lines;
  }

  handleInput(data: string): void {
    if (data === "\r" || data === "\n") {
      this.done({ selected: [...this.checked], cancelled: false });
      return;
    }
    if (data === "q" || data === "\x1b" || data === "\x03") {
      this.done({ selected: [], cancelled: true });
      return;
    }
    if (data === "\x1b[A" || data === "k") {
      this.cursor = (this.cursor - 1 + this.items.length) % this.items.length;
      return;
    }
    if (data === "\x1b[B" || data === "j") {
      this.cursor = (this.cursor + 1) % this.items.length;
      return;
    }
    if (data === " ") {
      const item = this.items[this.cursor];
      if (item && item.verdict !== "DENY") {
        if (this.checked.has(item.key)) this.checked.delete(item.key);
        else this.checked.add(item.key);
      }
      return;
    }
    if (data === "a") {
      const everySelected = this.selectable.every((i) =>
        this.checked.has(this.items[i]?.key ?? ""),
      );
      for (const i of this.selectable) {
        const key = this.items[i]?.key;
        if (key && !everySelected) this.checked.add(key);
        else if (key) this.checked.delete(key);
      }
    }
  }
}

/** Minimal UI port so the flow is testable without a real pi context. */
export interface UiPort {
  mode: string;
  custom<T>(
    factory: (
      tui: unknown,
      theme: unknown,
      keybindings: unknown,
      done: (result: T) => void,
    ) => Component,
  ): Promise<T>;
  confirm(title: string, message: string): Promise<boolean>;
}

export function itemsFromReports(reports: EvaluationReport[]): CheckboxItem[] {
  return reports.map((r) => ({
    key: r.candidate.name,
    label: `${r.candidate.name}@${r.candidate.version}${r.baseline ? ` (from ${r.baseline.version})` : ""}`,
    verdict: r.verdict,
  }));
}

export async function selectForInstall(
  ui: UiPort,
  reports: EvaluationReport[],
): Promise<SelectionResult> {
  const items = itemsFromReports(reports);
  const allowed = items.filter((i) => i.verdict !== "DENY");

  if (ui.mode === "tui" && allowed.length > 0) {
    return ui.custom<SelectionResult>((tui, theme, keybindings, done) => {
      void tui;
      void theme;
      void keybindings;
      return new CheckboxComponent(items, done);
    });
  }

  // Non-TUI fallback: group confirm for ALLOW, one-by-one for ASK.
  const selected: string[] = [];
  const allowGroup = items.filter((i) => i.verdict === "ALLOW");
  const askGroup = items.filter((i) => i.verdict === "ASK");

  if (allowGroup.length > 0) {
    const ok = await ui.confirm(
      "pi-vetter",
      `Install ${allowGroup.length} ALLOW verdict(s): ${allowGroup.map((i) => i.label).join(", ")}?`,
    );
    if (ok) selected.push(...allowGroup.map((i) => i.key));
  }
  for (const item of askGroup) {
    const ok = await ui.confirm("pi-vetter", `Install ${item.label} (verdict ASK)?`);
    if (ok) selected.push(item.key);
  }
  return { selected, cancelled: false };
}
