import { describe, expect, it } from "vitest";
import { runPool } from "../src/core/pool.ts";
import { ProgressTracker } from "../src/ui/progress.ts";

describe("ProgressTracker", () => {
  it("renders an idle line before any target is resolved", () => {
    const tracker = new ProgressTracker("pi-vetter");
    expect(tracker.lines()).toEqual(["pi-vetter…"]);
  });

  it("lists every package as pending when resolving starts", () => {
    const tracker = new ProgressTracker("pi-vetter");
    tracker.startResolve(["pkg-a", "pkg-b"]);
    expect(tracker.lines()).toEqual(["pi-vetter: resolving packages (0/2)", "· pkg-a", "· pkg-b"]);
  });

  it("marks rows in-flight on item and done on tick, with out-of-order completion", () => {
    const tracker = new ProgressTracker("pi-vetter");
    tracker.startResolve(["pkg-a", "pkg-b", "pkg-c"]);
    tracker.item("pkg-a");
    tracker.item("pkg-b");
    expect(tracker.lines()).toEqual([
      "pi-vetter: resolving packages (0/3)",
      "… pkg-a",
      "… pkg-b",
      "· pkg-c",
    ]);

    tracker.tick("pkg-b");
    expect(tracker.lines()).toEqual([
      "pi-vetter: resolving packages (1/3)",
      "… pkg-a",
      "✓ pkg-b",
      "· pkg-c",
    ]);
  });

  it("resets to a fresh vetting checklist when vetting starts", () => {
    const tracker = new ProgressTracker("pi-vetter");
    tracker.startResolve(["pkg-a", "pkg-b"]);
    tracker.tick("pkg-a");
    tracker.start(["pkg-b"]);
    expect(tracker.lines()).toEqual(["pi-vetter: vetting (0/1)", "· pkg-b"]);
  });

  it("marks every row done and appends done when all packages finished", () => {
    const tracker = new ProgressTracker("pi-vetter");
    tracker.start(["a", "b"]);
    tracker.item("a");
    tracker.tick("a");
    tracker.item("b");
    tracker.tick("b");
    expect(tracker.lines()).toEqual(["pi-vetter: vetting (2/2) done", "✓ a", "✓ b"]);
  });

  it("tracks duplicate row names independently", () => {
    const tracker = new ProgressTracker("pi-vetter");
    tracker.start(["a", "a"]);
    tracker.item("a");
    tracker.item("a");
    tracker.tick("a");
    tracker.tick("a");
    expect(tracker.lines()).toEqual(["pi-vetter: vetting (2/2) done", "✓ a", "✓ a"]);
  });
});

describe("runPool", () => {
  const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it("runs every item with concurrency bounded and emits start/end per item", async () => {
    const events: string[] = [];
    let active = 0;
    let peak = 0;
    await runPool(
      ["a", "b", "c", "d", "e"],
      async (item) => {
        active += 1;
        peak = Math.max(peak, active);
        await delay(5);
        active -= 1;
        events.push(`end:${item}`);
      },
      {
        concurrency: 2,
        onItemStart: (item) => events.push(`start:${item}`),
      },
    );
    expect(events.filter((e) => e.startsWith("start:"))).toHaveLength(5);
    expect(events.filter((e) => e.startsWith("end:"))).toHaveLength(5);
    for (const item of ["a", "b", "c", "d", "e"]) {
      expect(events.indexOf(`start:${item}`)).toBeLessThan(events.indexOf(`end:${item}`));
    }
    expect(peak).toBeLessThanOrEqual(2);
  });

  it("one failing item does not stop the others and reports the error", async () => {
    const finished: string[] = [];
    const errors: string[] = [];
    await runPool(
      ["a", "b", "c"],
      async (item) => {
        if (item === "b") throw new Error("boom");
        await delay(2);
        finished.push(item);
      },
      {
        concurrency: 3,
        onItemError: (item, err) => errors.push(`${item}:${(err as Error).message}`),
      },
    );
    expect(finished.sort()).toEqual(["a", "c"]);
    expect(errors).toEqual(["b:boom"]);
  });
});
