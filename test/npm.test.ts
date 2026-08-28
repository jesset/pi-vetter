import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { pack } from "tar-stream";
import { describe, expect, it } from "vitest";
import { downloadTarball, parseTarball, textFiles, verifyIntegrity } from "../src/npm/tarball.ts";

async function makeTarball(entries: Array<[string, string]>): Promise<Uint8Array> {
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

describe("parseTarball", () => {
  it("parses files and strips the package/ prefix", async () => {
    const tgz = await makeTarball([
      ["package.json", '{"name":"demo"}'],
      ["src/index.ts", "console.log(1)"],
    ]);
    const files = await parseTarball(tgz);
    expect([...files.keys()].sort()).toEqual(["package.json", "src/index.ts"]);
    expect(Buffer.from(files.get("package.json") ?? []).toString()).toBe('{"name":"demo"}');
  });

  it("drops directories, symlinks and path-traversal entries", async () => {
    const p = pack();
    p.entry({ name: "package/dir/", type: "directory" });
    p.entry({ name: "package/link", type: "symlink", linkname: "../../etc/passwd" });
    p.entry({ name: "package/../escape.txt", type: "file" }, "x");
    p.entry({ name: "package/ok.txt", type: "file" }, "ok");
    p.finalize();
    const chunks: Buffer[] = [];
    for await (const chunk of p as unknown as AsyncIterable<Buffer>) chunks.push(chunk);
    const files = await parseTarball(gzipSync(Buffer.concat(chunks)));
    expect([...files.keys()]).toEqual(["ok.txt"]);
  });

  it("rejects oversized payloads", async () => {
    const tgz = await makeTarball([["big.txt", "a".repeat(1000)]]);
    await expect(parseTarball(tgz, 100)).rejects.toThrow(/too large/);
  });
});

describe("verifyIntegrity", () => {
  it("matches the npm dist.integrity format", () => {
    const bytes = new TextEncoder().encode("hello");
    const digest = createHash("sha512").update(bytes).digest("base64");
    expect(verifyIntegrity(bytes, `sha512-${digest}`)).toBe(true);
    expect(verifyIntegrity(new TextEncoder().encode("evil"), `sha512-${digest}`)).toBe(false);
  });
});

describe("textFiles", () => {
  it("keeps text-like files only", async () => {
    const tgz = await makeTarball([
      ["a.js", "1"],
      ["b.node", "\x00\x01"],
      ["c.md", "doc"],
    ]);
    const files = await parseTarball(tgz);
    expect([...textFiles(files).keys()].sort()).toEqual(["a.js", "c.md"]);
  });
});

describe("downloadTarball", () => {
  it("throws on non-2xx", async () => {
    await expect(
      downloadTarball("https://registry.npmjs.org/-/nonexistent-404.tgz"),
    ).rejects.toThrow(/HTTP \d+/);
  });
});
