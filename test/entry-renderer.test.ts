import { describe, expect, it } from "vitest";
import { reportEntryRenderer } from "../src/ui/entry.ts";

function entry(markdown: string): { data: { markdown: string } } {
  return { data: { markdown } };
}

describe("reportEntryRenderer", () => {
  it("renders the report markdown as transcript lines", () => {
    const component = reportEntryRenderer(
      entry("### pkg 1.0.0 → 2.0.0\n**Verdict: ASK**"),
      {},
      null,
    );
    const lines = component.render(80);
    expect(lines.join("\n")).toContain("pkg 1.0.0 → 2.0.0");
    expect(lines.join("\n")).toContain("Verdict: ASK");
  });
});
