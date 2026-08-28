import { describe, expect, it, vi } from "vitest";
import type { Packument } from "../src/core/types.ts";
import { collectDependencies } from "../src/npm/dependencies.ts";

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
    const names = deps.map((d) => `${d.name}@${d.version}`);
    expect(names).toEqual(["a@1.5.0", "b@2.1.0", "c@3.2.0"]);
  });

  it("respects maxDepth (1 = direct only)", async () => {
    const deps = await collectDependencies(
      fixture().get("root") as Packument,
      "1.0.0",
      fetcher(fixture()),
      { maxDepth: 1, maxPackages: 20 },
    );
    expect(deps.map((d) => d.name).sort()).toEqual(["a", "b"]);
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
    expect(deps.map((d) => d.name)).toEqual(["a", "c"]);
  });
});
