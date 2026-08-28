import { describe, expect, it, vi } from "vitest";
import type { Packument } from "../src/core/types.ts";
import { collectDependencies, resolveVersion } from "../src/npm/dependencies.ts";

function packumentWith(name: string, version: string, deps: Record<string, string>): Packument {
  return {
    name,
    "dist-tags": { latest: version },
    versions: {
      [version]: {
        version,
        dependencies: deps,
        dist: { integrity: "sha512-x", tarball: "x" },
      },
    },
    time: { created: "2020-01-01T00:00:00.000Z" },
    maintainers: [],
  };
}

function fixture(): Map<string, Packument> {
  const registry = new Map<string, Packument>();
  registry.set("root", packumentWith("root", "1.0.0", { a: "^1.0.0", b: "^2.0.0" }));
  registry.set("a", packumentWith("a", "1.5.0", { c: "^3.0.0" }));
  registry.set("b", packumentWith("b", "2.1.0", { c: "^3.0.0" }));
  registry.set("c", packumentWith("c", "3.2.0", { a: "^1.0.0" }));
  return registry;
}

const fetcher = (registry: Map<string, Packument>) =>
  vi.fn((name: string) =>
    registry.has(name)
      ? Promise.resolve(registry.get(name) as Packument)
      : Promise.reject(new Error(`not found: ${name}`)),
  );

describe("collectDependencies", () => {
  it("walks direct and transitive dependencies, deduped, cycle-safe", async () => {
    const deps = await collectDependencies(
      fixture().get("root") as Packument,
      "1.0.0",
      fetcher(fixture()),
      { maxDepth: 3, maxPackages: 20 },
    );
    const names = deps.map((d) => `${d.node.name}@${d.node.version}`);
    expect(names).toEqual(["a@1.5.0", "b@2.1.0", "c@3.2.0"]);
  });

  it("respects maxDepth (1 = direct only)", async () => {
    const deps = await collectDependencies(
      fixture().get("root") as Packument,
      "1.0.0",
      fetcher(fixture()),
      { maxDepth: 1, maxPackages: 20 },
    );
    expect(deps.map((d) => d.node.name).sort()).toEqual(["a", "b"]);
  });

  it("respects maxPackages", async () => {
    const deps = await collectDependencies(
      fixture().get("root") as Packument,
      "1.0.0",
      fetcher(fixture()),
      { maxDepth: 3, maxPackages: 1 },
    );
    expect(deps).toHaveLength(1);
  });

  it("skips registry failures without aborting", async () => {
    const registry = fixture();
    const f = vi.fn((name: string) =>
      name === "b"
        ? Promise.reject(new Error("gone"))
        : Promise.resolve(registry.get(name) as Packument),
    );
    const deps = await collectDependencies(registry.get("root") as Packument, "1.0.0", f, {
      maxDepth: 2,
      maxPackages: 20,
    });
    expect(deps.map((d) => d.node.name)).toEqual(["a", "c"]);
  });
});

describe("resolveVersion", () => {
  const multi: Packument = {
    name: "m",
    "dist-tags": { latest: "3.0.0" },
    versions: Object.fromEntries(
      ["1.0.0", "1.2.0", "1.9.9", "2.0.0", "3.0.0"].map((v) => [
        v,
        { version: v, dist: { integrity: "x", tarball: "x" } },
      ]),
    ),
    time: {},
    maintainers: [],
  };

  it("picks the highest version satisfying a caret range (not latest)", () => {
    expect(resolveVersion("^1.1.0", multi)).toBe("1.9.9");
  });

  it("picks the highest version satisfying a tilde range", () => {
    expect(resolveVersion("~1.2.0", multi)).toBe("1.2.0");
  });

  it("falls back to latest when the range has no plain-semver shape", () => {
    expect(resolveVersion("*", multi)).toBe("3.0.0");
    expect(resolveVersion("workspace:^1.0.0", multi)).toBe("3.0.0");
  });

  it("falls back to latest when no in-range version exists", () => {
    expect(resolveVersion("^4.0.0", multi)).toBe("3.0.0");
  });
});
