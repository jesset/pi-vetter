import { describe, expect, it, vi } from "vitest";
import type { ScannerContext } from "../src/core/types.ts";
import { createSocketScanner } from "../src/scanners/socket.ts";

function ctx(name = "pkg", version = "2.0.0"): ScannerContext {
  return {
    candidate: { name, version, scenario: "update" },
    baseline: null,
    artifacts: {
      candidateFiles: new Map(),
      baselineFiles: null,
      candidatePackument: {
        name,
        "dist-tags": { latest: version },
        versions: {
          [version]: { version, dist: { integrity: "sha512-x", tarball: "x" } },
        },
        time: { created: "2020-01-01T00:00:00.000Z" },
        maintainers: [],
      },
      candidateIntegrity: "sha512-x",
      baselineIntegrity: null,
      candidateTarball: new Uint8Array(0),
      dependencyFiles: new Map(),
      dependencySkipped: 0,
      candidateSha256: "abc",
      downloads: 1,
    },
  };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe("socket scanner", () => {
  it("reports a clean score as pass evidence", async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(json([{ score: { supplyChainAttack: 0 }, alerts: [] }])),
    );
    const scanner = createSocketScanner({ apiKey: "k", orgSlug: "my-org", fetchImpl });
    const result = await scanner.scan(ctx());
    expect(result.status).toBe("ok");
    expect(result.evidences[0]).toMatchObject({
      key: "socket:clean",
      status: "pass",
    });
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://api.socket.dev/v0/orgs/my-org/purl",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ authorization: "Bearer k" }),
      }),
    );
  });

  it("fails on high-severity Socket alerts and keeps low alerts informational", async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        json({
          score: { supplyChainAttack: 9 },
          alerts: [
            { key: "gptMalware", severity: "high" },
            { key: "hiddenSourceCode", severity: "medium" },
          ],
        }),
      ),
    );
    const scanner = createSocketScanner({ apiKey: "k", orgSlug: "my-org", fetchImpl });
    const result = await scanner.scan(ctx());
    const keys = result.evidences.map((e) => `${e.key}:${e.status}`);
    expect(keys).toContain("socket:alerts:fail");
    expect(keys.find((k) => k.startsWith("socket:"))).toBeDefined();
    const failEvidence = result.evidences.find((e) => e.key === "socket:alerts");
    expect(failEvidence?.detail).toContain("gptMalware");
    expect(failEvidence?.detail).not.toContain("hiddenSourceCode");
    const infoEvidence = result.evidences.find((e) => e.key === "socket:minor-alerts");
    expect(infoEvidence?.detail).toContain("hiddenSourceCode");
  });

  it("encodes scoped package names into purls correctly", async () => {
    const fetchImpl = vi.fn(() => Promise.resolve(json({ alerts: [] })));
    const scanner = createSocketScanner({ apiKey: "k", orgSlug: "o", fetchImpl });
    await scanner.scan(ctx("@scope/foo", "1.2.3"));
    const body = JSON.parse(((fetchImpl.mock.calls[0] as unknown[])[1] as { body: string }).body);
    expect(body.purl).toBe("pkg:npm/%40scope/foo@1.2.3");
  });

  it("maps quota rejections to quota-exhausted (fail-closed capping upstream)", async () => {
    const fetchImpl = vi.fn(() => Promise.resolve(json({ error: {} }, 429)));
    const scanner = createSocketScanner({ apiKey: "k", orgSlug: "o", fetchImpl });
    const result = await scanner.scan(ctx());
    expect(result.status).toBe("quota-exhausted");
    expect(result.evidences).toEqual([]);
  });
});
