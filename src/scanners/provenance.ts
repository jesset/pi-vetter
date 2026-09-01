import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { bundleFromJSON } from "@sigstore/bundle";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import type {
  Evidence,
  Packument,
  ScannerContext,
  ScanResult,
  SecurityScanner,
} from "../core/types.ts";

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

interface BundleJson {
  mediaType?: string;
  verificationMaterial?: {
    /** bundle v0.2: single certificate */
    certificate?: { rawBytes?: string };
    content?: {
      x509CertificateChain?: {
        certificates?: Array<{ rawBytes?: string }>;
      };
    };
  };
  dsseEnvelope?: {
    payload?: string;
  };
  content?: {
    dsseEnvelope?: {
      payload?: string;
    };
  };
}

let cachedVerifier: Verifier | null = null;

/** Vendored from sigstore's TUF repo (scripts/fetch-trusted-root.ts); bump manually. */
function loadVerifier(): Verifier {
  if (cachedVerifier) return cachedVerifier;
  const rootJson = JSON.parse(
    readFileSync(new URL("./trusted-root.json", import.meta.url), "utf8"),
  ) as unknown;
  const trustMaterial = toTrustMaterial(TrustedRoot.fromJSON(rootJson));
  cachedVerifier = new Verifier(trustMaterial);
  return cachedVerifier;
}

/** owner/repo for GitHub URLs and shorthand, lowercased host/path otherwise. */
export function normalizeRepo(input: string | undefined): string | null {
  if (!input) return null;
  const s = input.trim();
  const gh = /github\.com[/:]([^/\s]+)\/([^/\s#?]+)/.exec(s);
  if (gh) {
    const repo = gh[2]?.replace(/\.git$/, "") ?? "";
    return `${gh[1]?.toLowerCase()}/${repo.toLowerCase()}`;
  }
  if (!s.includes("://") && /^[\w.-]+\/[\w.-]+$/.test(s)) return s.toLowerCase();
  const m = /^(?:git\+)?(https?:\/\/[^/]+\/[^?#]+?)(?:\.git)?(?:@[\w./-]+)?$/i.exec(s);
  if (m) return m[1]?.replace(/^https?:\/\//i, "").toLowerCase() ?? null;
  return s.includes("/") ? s.toLowerCase() : null;
}

function reposFromBundles(bundles: BundleJson[]): {
  fromCert: Set<string>;
  fromPayload: Set<string>;
} {
  const fromCert = new Set<string>();
  const fromPayload = new Set<string>();

  for (const bundle of bundles) {
    const certRaw =
      bundle.verificationMaterial?.certificate?.rawBytes ??
      bundle.verificationMaterial?.content?.x509CertificateChain?.certificates?.[0]?.rawBytes;
    if (certRaw) {
      try {
        const x509 = new X509Certificate(Buffer.from(certRaw, "base64"));
        const san = x509.subjectAltName ?? "";
        for (const m of san.matchAll(/github\.com\/([^/\s]+)\/([^/\s]+)/g)) {
          fromCert.add(`${m[1]?.toLowerCase()}/${m[2]?.replace(/\.git$/, "")?.toLowerCase()}`);
        }
      } catch {
        // unparseable cert: ignore, decision relies on other signals
      }
    }
    const payload = bundle.dsseEnvelope?.payload ?? bundle.content?.dsseEnvelope?.payload;
    if (payload) {
      try {
        const json = JSON.parse(Buffer.from(payload, "base64").toString("utf8")) as Record<
          string,
          unknown
        >;
        const collect = (node: unknown, depth: number): void => {
          if (depth > 6 || node === null || typeof node !== "object") return;
          if (Array.isArray(node)) {
            for (const item of node) collect(item, depth + 1);
            return;
          }
          for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
            if (typeof v === "string" && /repo(sitory)?|uri/i.test(k)) {
              const repo = normalizeRepo(v);
              if (repo) fromPayload.add(repo);
            } else {
              collect(v, depth + 1);
            }
          }
        };
        collect(json, 0);
      } catch {
        // ignore unparseable payload
      }
    }
  }
  return { fromCert, fromPayload };
}

function packumentRepo(packument: Packument): string | null {
  const repo = packument.repository;
  if (!repo) return null;
  if (typeof repo === "string") return normalizeRepo(repo);
  return normalizeRepo(repo.url);
}

interface VerificationOutcome {
  verified: number;
  /** Failures that indicate tampering or an invalid chain. */
  hardFailures: string[];
  /** Failures because the public trust root lacks the key (e.g. npm's own publish-attestation key). */
  unverifiable: string[];
}

function verifyBundles(bundles: BundleJson[]): VerificationOutcome {
  const outcome: VerificationOutcome = { verified: 0, hardFailures: [], unverifiable: [] };
  let verifier: Verifier;
  try {
    verifier = loadVerifier();
  } catch (err) {
    outcome.hardFailures.push(
      `trusted root unavailable: ${err instanceof Error ? err.message : String(err)}`,
    );
    return outcome;
  }
  for (const [i, bundleJson] of bundles.entries()) {
    try {
      const entity = toSignedEntity(bundleFromJSON(bundleJson));
      verifier.verify(entity);
      outcome.verified += 1;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const reason = `bundle #${i}: ${message}`;
      if (/key not found/i.test(message)) outcome.unverifiable.push(reason);
      else outcome.hardFailures.push(reason);
    }
  }
  return outcome;
}

export function createProvenanceScanner(options?: {
  timeoutMs?: number;
  fetchImpl?: FetchLike;
  /** #44: fail (ASK-level rule) when a version publishes no attestations. */
  required?: boolean;
}): SecurityScanner {
  const timeoutMs = options?.timeoutMs ?? 10_000;
  const doFetch = options?.fetchImpl ?? ((url: string, init?: RequestInit) => fetch(url, init));

  return {
    name: "provenance",
    layer: 1,
    async scan(ctx: ScannerContext): Promise<ScanResult> {
      const versionMeta = ctx.artifacts.candidatePackument.versions[ctx.candidate.version];
      const attestations = versionMeta?.dist?.attestations;
      if (!attestations?.url) {
        return {
          scanner: "provenance",
          status: "ok",
          evidences: [
            options?.required
              ? {
                  scanner: "provenance",
                  key: "provenance:missing",
                  status: "fail",
                  detail:
                    "no npm attestations published for this version (provenance.required is enabled)",
                }
              : {
                  scanner: "provenance",
                  key: "provenance:none",
                  status: "info",
                  detail: "no npm attestations published for this version (common)",
                },
          ],
        };
      }

      const res = await doFetch(attestations.url, {
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`attestations fetch failed: HTTP ${res.status}`);
      const json = (await res.json()) as unknown;
      const bundles: BundleJson[] = Array.isArray((json as { attestations?: unknown }).attestations)
        ? ((json as { attestations: Array<{ bundle?: BundleJson }> }).attestations
            .map((a) => a.bundle)
            .filter((b): b is BundleJson => Boolean(b)) ?? [])
        : Array.isArray(json)
          ? (json as BundleJson[])
          : [];

      const { fromCert, fromPayload } = reposFromBundles(bundles);
      const declared = packumentRepo(ctx.artifacts.candidatePackument);
      const observed = [...fromCert, ...fromPayload];
      const verification = verifyBundles(bundles);
      const evidences: Evidence[] = [];
      if (verification.unverifiable.length > 0) {
        evidences.push({
          scanner: "provenance",
          key: "provenance:unverifiable-bundles",
          status: "info",
          detail: `not covered by the public trust root (typically npm's publish-attestation key): ${verification.unverifiable.join("; ")}`,
        });
      }

      if (verification.hardFailures.length > 0) {
        evidences.push({
          scanner: "provenance",
          key: "provenance:conflict",
          status: "fail",
          detail: `signature verification failed: ${verification.hardFailures.join("; ")}`,
          data: verification,
        });
        return { scanner: "provenance", status: "ok", evidences };
      }

      if (verification.verified === 0) {
        evidences.push({
          scanner: "provenance",
          key: "provenance:present",
          status: "info",
          detail: "no bundle could be verified against the public trust root",
        });
        return { scanner: "provenance", status: "ok", evidences };
      }

      if (observed.length === 0) {
        evidences.push({
          scanner: "provenance",
          key: "provenance:present",
          status: "info",
          detail: `signatures verified (${verification.verified} bundle(s)) but no source repository could be extracted`,
        });
        return { scanner: "provenance", status: "ok", evidences };
      }

      if (declared && !observed.includes(declared)) {
        return {
          scanner: "provenance",
          status: "ok",
          evidences: [
            {
              scanner: "provenance",
              key: "provenance:conflict",
              status: "fail",
              detail: `attestations point to ${[...new Set(observed)].join(", ")} but package.json declares ${declared}`,
              data: { observed, declared },
            },
          ],
        };
      }

      const unique = [...new Set(observed)].join(", ");
      evidences.push({
        scanner: "provenance",
        key: "provenance:verified",
        status: "pass",
        detail: `signature chain verified (${verification.verified} bundle(s)); declared source ${declared ?? "(none)"} matches attested source(s) ${unique}`,
        data: { observed },
      });
      return { scanner: "provenance", status: "ok", evidences };
    },
  };
}
