import type { DefaultPackageManager } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import { listInstalledPackages, npmSpecFromSource } from "../src/settings.ts";

const pmWith = (sources: string[]): DefaultPackageManager =>
  ({
    listConfiguredPackages: () =>
      sources.map((source) => ({ source, installedPath: undefined, scope: "user" })),
  }) as unknown as DefaultPackageManager;

describe("npmSpecFromSource", () => {
  it("parses pinned and floating npm specs, rejects non-npm sources", () => {
    expect(npmSpecFromSource("npm:foo")).toEqual({ name: "foo", pinned: false });
    expect(npmSpecFromSource("npm:foo@1.2.3")).toEqual({ name: "foo", pinned: true });
    expect(npmSpecFromSource("git:github.com/a/b")).toBeNull();
    expect(npmSpecFromSource("/local/path")).toBeNull();
  });
});

describe("listInstalledPackages", () => {
  it("returns npm packages and discloses skipped non-npm sources separately", () => {
    const { packages, skippedSources } = listInstalledPackages(
      pmWith(["npm:foo@1.0.0", "git:git@github.com:foo/bar", "/local/path"]),
    );
    expect(packages).toHaveLength(1);
    expect(packages[0]).toMatchObject({
      source: "npm:foo@1.0.0",
      name: "foo",
      version: null,
      pinned: true,
      scope: "user",
    });
    expect(skippedSources).toEqual(["git:git@github.com:foo/bar", "/local/path"]);
  });
});
