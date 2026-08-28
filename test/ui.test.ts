import type { Component } from "@earendil-works/pi-tui";
import { describe, expect, it, vi } from "vitest";
import type { EvaluationReport } from "../src/core/types.ts";
import { renderReport } from "../src/ui/report.ts";
import {
  CheckboxComponent,
  type SelectionResult,
  selectForInstall,
  type UiPort,
} from "../src/ui/select.ts";

function report(verdict: EvaluationReport["verdict"], name = "pkg"): EvaluationReport {
  return {
    candidate: { name, version: "2.0.0", scenario: "update" },
    baseline: { name, version: "1.0.0" },
    verdict,
    capped: false,
    findings: [],
    evidences: [{ scanner: "osv", key: "osv:clean", status: "pass", detail: "clean" }],
    riskScore: 0,
    hasLifecycleScripts: false,
  };
}

describe("renderReport", () => {
  it("renders headline, verdict and evidence", () => {
    const text = renderReport(report("ASK"));
    expect(text).toContain("### pkg 1.0.0 → 2.0.0");
    expect(text).toContain("**Verdict: ASK**");
    expect(text).toContain("✓ `osv:clean` — clean");
  });

  it("notes capped verdicts and lifecycle warnings", () => {
    const r = report("ASK");
    r.capped = true;
    r.hasLifecycleScripts = true;
    const text = renderReport(r);
    expect(text).toContain("capped: incomplete evidence");
    expect(text).toContain("Lifecycle scripts");
  });
});

describe("CheckboxComponent", () => {
  function make(items: Array<[string, "ALLOW" | "ASK" | "DENY"]>) {
    const done = vi.fn();
    const comp = new CheckboxComponent(
      items.map(([key, verdict]) => ({ key, label: key, verdict })),
      done,
    );
    return { comp, done };
  }

  it("defaults ALLOW to checked, never DENY", () => {
    const { comp, done } = make([
      ["a", "ALLOW"],
      ["b", "ASK"],
      ["c", "DENY"],
    ]);
    comp.handleInput("\r");
    expect(done).toHaveBeenCalledWith({ selected: ["a"], cancelled: false });
  });

  it("toggles with space and moves with j", () => {
    const { comp, done } = make([
      ["a", "ALLOW"],
      ["b", "ASK"],
    ]);
    comp.handleInput("j");
    comp.handleInput(" ");
    comp.handleInput("\r");
    expect(done).toHaveBeenCalledWith({ selected: ["a", "b"], cancelled: false });
  });

  it("DENY items cannot be toggled", () => {
    const { comp, done } = make([["deny-me", "DENY"]]);
    comp.handleInput(" ");
    comp.handleInput("\r");
    expect(done).toHaveBeenCalledWith({ selected: [], cancelled: false });
  });

  it("cancel with q", () => {
    const { comp, done } = make([["a", "ALLOW"]]);
    comp.handleInput("q");
    expect(done).toHaveBeenCalledWith({ selected: [], cancelled: true });
  });

  it("a toggles all selectable items", () => {
    const { comp, done } = make([
      ["a", "ALLOW"],
      ["b", "ASK"],
      ["c", "DENY"],
    ]);
    comp.handleInput("a"); // uncheck all (a was checked)
    comp.handleInput("a"); // check all
    comp.handleInput("\r");
    expect(done).toHaveBeenCalledWith({ selected: ["a", "b"], cancelled: false });
  });
});

describe("selectForInstall", () => {
  it("uses grouped confirms in non-TUI mode", async () => {
    const confirm = vi
      .fn()
      .mockResolvedValueOnce(true) // ALLOW group → yes
      .mockResolvedValueOnce(false); // ASK item → no
    const ui: UiPort = {
      mode: "headless",
      custom: vi.fn(),
      confirm: (t, m) => confirm(t, m),
    };
    const result = await selectForInstall(ui, [report("ALLOW", "a"), report("ASK", "b")]);
    expect(result).toEqual({ selected: ["a"], cancelled: false });
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it("uses the checkbox component in TUI mode", async () => {
    const ui: UiPort = {
      mode: "tui",
      confirm: vi.fn(),
      custom: async <T>(
        factory: (
          tui: unknown,
          theme: unknown,
          keybindings: unknown,
          done: (r: T) => void,
        ) => Component,
      ) => {
        let captured: T | undefined;
        const comp = factory({}, {}, {}, (r: T) => {
          captured = r;
        });
        comp.handleInput?.("q");
        return captured as T;
      },
    };
    const result = await selectForInstall(ui, [report("ALLOW", "a")]);
    expect(result.cancelled).toBe(true);
  });
});
