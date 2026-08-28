import { describe, expect, it } from "vitest";
import { runPool } from "../src/core/pool.ts";
import { ProgressTracker } from "../src/ui/progress.ts";

describe("ProgressTracker", () => {
  it("renders an idle line before any target is resolved", () => {
    const tracker = new ProgressTracker("pi-vetter");
    expect(tracker.lines()).toEqual(["pi-vetter…"]);
  });

  it("shows the resolving phase before vetting starts", () => {
    const tracker = new ProgressTracker("pi-vetter");
    tracker.startResolve(3);
    expect(tracker.lines()).toEqual(["pi-vetter: resolving packages (0/3)"]);

    tracker.item("pkg-a");
    expect(tracker.lines()).toEqual(["pi-vetter: resolving packages (0/3)", "→ pkg-a"]);

    tracker.tick();
    expect(tracker.lines()).toEqual(["pi-vetter: resolving packages (1/3)"]);

    tracker.start(2);
    expect(tracker.lines()).toEqual(["pi-vetter: vetting (0/2)"]);
  });

  it("counts completed packages and shows the current one", () => {
    const tracker = new ProgressTracker("pi-vetter");
    tracker.start(4);
    expect(tracker.lines()).toEqual(["pi-vetter: vetting (0/4)"]);

    tracker.item("pi-web-access");
    expect(tracker.lines()).toEqual(["pi-vetter: vetting (0/4)", "→ pi-web-access"]);

    tracker.tick();
    tracker.item("pi-mcp-adapter");
    expect(tracker.lines()).toEqual(["pi-vetter: vetting (1/4)", "→ pi-mcp-adapter"]);
  });

  it("shows completion when all packages finished", () => {
    const tracker = new ProgressTracker("pi-vetter");
    tracker.start(2);
    tracker.item("a");
    tracker.tick();
    tracker.item("b");
    tracker.tick();
    expect(tracker.lines()).toEqual(["pi-vetter: vetting (2/2) done"]);
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
