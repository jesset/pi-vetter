import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { pack } from "tar-stream";
import type { Packument, PackumentVersion } from "../../../src/core/types.ts";

export interface FixtureFile {
  path: string;
  content: string;
}

export interface FixtureVersion {
  version: string;
  files: FixtureFile[];
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  deprecated?: string;
  /**
   * Serve bytes that do NOT match the claimed dist.integrity (tamper /
   * fail-closed scenarios). Integrity still describes the intended bytes.
   */
  corrupt?: boolean;
}

export interface FixturePackage {
  name: string;
  versions: FixtureVersion[];
  /** Days since time.created. Default 400 (clears the young-package rule). */
  createdDaysAgo?: number;
  /** Maintainer usernames. Default ["maintainer-a"]. */
  maintainers?: string[];
  /** Last-month downloads served by the downloads endpoint. Default 1000. */
  downloads?: number;
}

/** The tarball a healthy registry would serve for this version. */
export interface PublishedVersion {
  version: string;
  /** Bytes actually served (corrupted bytes when `corrupt` is set). */
  tarball: Uint8Array;
  /** Claimed dist.integrity, always computed over the intended bytes. */
  integrity: string;
}

export interface RegistryState {
  packages: Map<
    string,
    {
      packument: Packument;
      published: Map<string, PublishedVersion>;
      downloads: number;
    }
  >;
}

/** Packs entries as a real npm tarball: `package/<path>` entries, gzipped. */
export async function makeTarball(entries: Array<[string, string]>): Promise<Uint8Array> {
  const p = pack();
  for (const [name, content] of entries) {
    p.entry({ name: `package/${name}`, type: "file" }, content);
  }
  p.finalize();
  const chunks: Buffer[] = [];
  const reader = p as unknown as AsyncIterable<Buffer>;
  for await (const chunk of reader) chunks.push(chunk);
  return gzipSync(Buffer.concat(chunks));
}

async function buildVersion(name: string, version: FixtureVersion): Promise<PublishedVersion> {
  const manifest =
    version.files.find((f) => f.path === "package.json")?.content ??
    `${JSON.stringify({ name, version: version.version, main: "index.js" }, null, 2)}\n`;
  const entries: Array<[string, string]> = [
    ["package.json", manifest],
    ...version.files
      .filter((f) => f.path !== "package.json")
      .map((f): [string, string] => [f.path, f.content]),
  ];
  const intended = await makeTarball(entries);
  const integrity = `sha512-${createHash("sha512").update(intended).digest("base64")}`;
  const tarball = version.corrupt ? await makeTarball([["index.js", "// tampered"]]) : intended;
  return { version: version.version, tarball, integrity };
}

/** Builds the in-memory registry state: packuments + tarball bytes + integrity. */
export async function buildRegistryState(
  fixtures: FixturePackage[],
  registryBase: string,
  now = Date.now(),
): Promise<RegistryState> {
  const state: RegistryState = { packages: new Map() };
  for (const fixture of fixtures) {
    const createdDaysAgo = fixture.createdDaysAgo ?? 400;
    const maintainers = fixture.maintainers ?? ["maintainer-a"];
    const versions = fixture.versions;
    const created = now - createdDaysAgo * 86_400_000;

    const packumentVersions: Record<string, PackumentVersion> = {};
    const published = new Map<string, PublishedVersion>();
    for (const v of versions) {
      const pub = await buildVersion(fixture.name, v);
      published.set(v.version, pub);
      const base = `${registryBase}/${fixture.name}/-/${fixture.name.replace(/^@[^/]+\//, "")}-${v.version}.tgz`;
      packumentVersions[v.version] = {
        version: v.version,
        dist: { integrity: pub.integrity, tarball: base },
        ...(v.scripts ? { scripts: v.scripts } : {}),
        ...(v.dependencies ? { dependencies: v.dependencies } : {}),
        ...(v.deprecated ? { deprecated: v.deprecated } : {}),
      };
    }

    // Release times spread evenly from created to (now - 1 day): never trips
    // rapid-release, and age comes from time.created.
    const time: Record<string, string> = {
      created: new Date(created).toISOString(),
    };
    for (const [i, v] of versions.entries()) {
      const t = created + ((now - 86_400_000 - created) * i) / Math.max(1, versions.length - 1);
      time[v.version] = new Date(t).toISOString();
    }

    state.packages.set(fixture.name, {
      packument: {
        name: fixture.name,
        "dist-tags": { latest: versions[versions.length - 1]?.version ?? "" },
        versions: packumentVersions,
        time,
        maintainers: maintainers.map((username) => ({ username })),
      },
      published,
      downloads: fixture.downloads ?? 1000,
    });
  }
  return state;
}
