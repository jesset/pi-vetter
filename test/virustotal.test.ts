import { describe, expect, it, vi } from "vitest";
import type { ScannerContext, ScanResult } from "../src/core/types.ts";
import { createVirustotalScanner } from "../src/scanners/virustotal.ts";

function ctx(): ScannerContext {
  return {
    candidate: { name: "pkg", version: "2.0.0", scenario: "update" },
    baseline: null,
    artifacts: {
      candidateFiles: new Map(),
      baselineFiles: null,
      candidatePackument: {
        name: "pkg",
        "dist-tags": { latest: "2.0.0" },
        versions: {
          "2.0.0": {
            version: "2.0.0",
            dist: {
              integrity: "sha512-x",
              tarball: "https://registry.npmjs.org/pkg/-/pkg-2.0.0.tgz",
            },
          },
        },
        time: { created: "2020-01-01T00:00:00.000Z" },
        maintainers: [],
      },
      candidateIntegrity: "sha512-x",
      candidateTarball: new TextEncoder().encode("fake-tarball"),
      candidateSha256: "a".repeat(64),
      downloads: 1,
    },
  };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe("virustotal scanner", () => {
  it("uses an existing sample report (hash hit) and classifies detections", async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        json({
          data: {
            attributes: { last_analysis_stats: { malicious: 3, suspicious: 1, undetected: 60 } },
          },
        }),
      ),
    );
    const scanner = createVirustotalScanner({ apiKey: "k", fetchImpl, pollIntervalMs: 1 });
    const result = await scanner.scan(ctx());
    expect(result.status).toBe("ok");
    expect(result.evidences[0]).toMatchObject({
      key: "virustotal:detections",
      status: "fail",
    });
    expect(fetchImpl).toHaveBeenCalledWith(
      `https://www.virustotal.com/api/v3/files/${"a".repeat(64)}`,
      expect.objectContaining({ headers: expect.objectContaining({ "x-apikey": "k" }) }),
    );
  });

  it("uploads unknown samples and polls the analysis", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json({}, 404))
      .mockResolvedValueOnce(json({ data: { id: "analysis-1" } }))
      .mockResolvedValueOnce(json({ data: { attributes: { status: "queued" } } }))
      .mockResolvedValueOnce(
        json({
          data: {
            attributes: {
              status: "completed",
              stats: { malicious: 0, suspicious: 0, undetected: 65 },
            },
          },
        }),
      );
    const scanner = createVirustotalScanner({ apiKey: "k", fetchImpl, pollIntervalMs: 1 });
    const result: ScanResult = await scanner.scan(ctx());
    expect(result.status).toBe("ok");
    expect(result.evidences[0]).toMatchObject({ key: "virustotal:clean", status: "pass" });
    expect(fetchImpl).toHaveBeenCalledTimes(4);
    const uploadCall = fetchImpl.mock.calls[1] as unknown[];
    expect(uploadCall?.[0]).toBe("https://www.virustotal.com/api/v3/files");
    expect((uploadCall[1] as { method: string }).method).toBe("POST");
  });

  it("bounds the upload+poll total duration to a deadline", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json({}, 404))
      .mockResolvedValueOnce(json({ data: { id: "analysis-1" } }))
      .mockImplementation(() =>
        Promise.resolve(json({ data: { attributes: { status: "queued" } } })),
      );
    const scanner = createVirustotalScanner({
      apiKey: "k",
      fetchImpl,
      pollIntervalMs: 5,
      pollDeadlineMs: 60,
    });
    const result = await scanner.scan(ctx());
    expect(result.status).toBe("timeout");
    // hash lookup + upload + deadline-bounded polls (well under the
    // unbounded 30-poll ceiling)
    expect(fetchImpl.mock.calls.length).toBeLessThan(20);
  });

  it("maps quota rejections to quota-exhausted status", async () => {
    const fetchImpl = vi.fn(() => Promise.resolve(json({ error: {} }, 429)));
    const scanner = createVirustotalScanner({ apiKey: "k", fetchImpl, pollIntervalMs: 1 });
    const result = await scanner.scan(ctx());
    expect(result.status).toBe("quota-exhausted");
  });

  it("a single suspicious engine is info, not a detection", async () => {
    const fetchImpl = vi.fn(() =>
      Promise.resolve(
        json({
          data: {
            attributes: { last_analysis_stats: { malicious: 0, suspicious: 1, undetected: 64 } },
          },
        }),
      ),
    );
    const scanner = createVirustotalScanner({ apiKey: "k", fetchImpl, pollIntervalMs: 1 });
    const result = await scanner.scan(ctx());
    expect(result.evidences[0]).toMatchObject({ key: "virustotal:weak-detection", status: "info" });
  });
});
