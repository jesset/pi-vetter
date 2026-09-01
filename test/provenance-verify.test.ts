import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { Packument, ScannerContext } from "../src/core/types.ts";
import { createProvenanceScanner } from "../src/scanners/provenance.ts";

function ctx(repo = "git+https://github.com/sigstore/sigstore-js.git"): ScannerContext {
  const packument: Packument = {
    name: "@sigstore/verify",
    "dist-tags": { latest: "4.1.2" },
    versions: {
      "4.1.2": {
        version: "4.1.2",
        dist: {
          integrity: "sha512-x",
          tarball: "x",
          attestations: { url: "https://registry.npmjs.org/-/attestations/sample" },
        },
      },
    },
    time: { created: "2020-01-01T00:00:00.000Z" },
    maintainers: [],
    ...(repo ? { repository: repo } : {}),
  };
  return {
    candidate: { name: "@sigstore/verify", version: "4.1.2", scenario: "install" },
    baseline: null,
    artifacts: {
      candidateFiles: new Map(),
      baselineFiles: null,
      candidatePackument: packument,
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

function sampleAttestations(): unknown {
  return JSON.parse(readFileSync("test/fixtures/attestations-sample.json", "utf8"));
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe("provenance-required policy (#44)", () => {
  // strip the attestations url so the scanner sees a version without any
  function ctxNoAttestations(): ScannerContext {
    const base = ctx();
    const version = base.artifacts.candidatePackument.versions["4.1.2"];
    if (!version) throw new Error("fixture missing version");
    version.dist = { integrity: "sha512-x", tarball: "x" };
    return base;
  }

  it("keeps missing attestations informational by default", async () => {
    const scanner = createProvenanceScanner();
    const result = await scanner.scan(ctxNoAttestations());
    expect(result.evidences.find((e) => e.key === "provenance:none")?.status).toBe("info");
    expect(result.evidences.find((e) => e.key === "provenance:missing")).toBeUndefined();
  });

  it("escalates missing attestations to fail when required", async () => {
    const scanner = createProvenanceScanner({ required: true });
    const result = await scanner.scan(ctxNoAttestations());
    const ev = result.evidences.find((e) => e.key === "provenance:missing");
    expect(ev?.status).toBe("fail");
    expect(ev?.detail).toContain("required");
    expect(result.evidences.find((e) => e.key === "provenance:none")).toBeUndefined();
  });

  it("verified attestation behaviour is unchanged when required", async () => {
    const scanner = createProvenanceScanner({
      fetchImpl: vi.fn(() => Promise.resolve(json(sampleAttestations()))),
      required: true,
    });
    const result = await scanner.scan(ctx());
    expect(result.evidences.find((e) => e.key === "provenance:verified")?.status).toBe("pass");
  });
});

describe("provenance verification", () => {
  it("fails with provenance:conflict when a verifiable bundle fails signature verification", async () => {
    const tampered = sampleAttestations() as {
      attestations: Array<{
        bundle: {
          dsseEnvelope?: { payload?: string; payloadType?: string; signatures?: unknown[] };
        };
      }>;
    };
    // Tamper with the payload of the publicly-verifiable bundle (index 1):
    // the bytes no longer match the DSSE signature.
    const target = tampered.attestations[1];
    if (!target) throw new Error("fixture missing bundle");
    target.bundle.dsseEnvelope = {
      ...target.bundle.dsseEnvelope,
      payload: Buffer.from("tampered").toString("base64"),
    };
    const scanner = createProvenanceScanner({
      fetchImpl: vi.fn(() => Promise.resolve(json(tampered))),
    });
    const result = await scanner.scan(ctx());
    expect(result.evidences.find((e) => e.key === "provenance:conflict")?.status).toBe("fail");
    expect(result.evidences.find((e) => e.key === "provenance:verified")).toBeUndefined();
  });

  it("verifies a real untampered attestation against the vendored trusted root", async () => {
    const scanner = createProvenanceScanner({
      fetchImpl: vi.fn(() => Promise.resolve(json(sampleAttestations()))),
    });
    const result = await scanner.scan(ctx());
    const verified = result.evidences.find((e) => e.key === "provenance:verified");
    expect(verified?.status).toBe("pass");
    expect(verified?.detail).toContain("sigstore/sigstore-js");
    expect(verified?.detail).toContain("signature chain verified");
  });
});
