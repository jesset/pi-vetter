import { X509Certificate } from "node:crypto";
import type {
  Evidence,
  Packument,
  ScannerContext,
  ScanResult,
  SecurityScanner,
} from "../core/types.ts";

interface Bundle {
  verificationMaterial?: {
    content?: {
      x509CertificateChain?: {
        certificates?: Array<{ rawBytes?: string }>;
      };
    };
  };
  content?: {
    dsseEnvelope?: {
      payload?: string;
    };
  };
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
  const m = /^(?:git\+)?(https?:\/\/[^/]+\/.+?)(?:\.git)?$/i.exec(s);
  if (m) return m[1]?.replace(/^https?:\/\//i, "").toLowerCase() ?? null;
  return s.toLowerCase() || null;
}

function reposFromBundles(bundles: Bundle[]): { fromCert: Set<string>; fromPayload: Set<string> } {
  const fromCert = new Set<string>();
  const fromPayload = new Set<string>();

  for (const bundle of bundles) {
    for (const cert of bundle.verificationMaterial?.content?.x509CertificateChain?.certificates ??
      []) {
      if (!cert.rawBytes) continue;
      try {
        const x509 = new X509Certificate(Buffer.from(cert.rawBytes, "base64"));
        const san = x509.subjectAltName ?? "";
        for (const m of san.matchAll(/github\.com\/([^/\s]+)\/([^/\s]+)/g)) {
          fromCert.add(`${m[1]?.toLowerCase()}/${m[2]?.replace(/\.git$/, "")?.toLowerCase()}`);
        }
      } catch {
        // unparseable cert: ignore, decision relies on other signals
      }
    }
    const payload = bundle.content?.dsseEnvelope?.payload;
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

export function createProvenanceScanner(timeoutMs = 10_000): SecurityScanner {
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
            {
              scanner: "provenance",
              key: "provenance:none",
              status: "info",
              detail: "no npm attestations published for this version (common)",
            },
          ],
        };
      }

      const res = await fetch(attestations.url, { signal: AbortSignal.timeout(timeoutMs) });
      if (!res.ok) throw new Error(`attestations fetch failed: HTTP ${res.status}`);
      const json = (await res.json()) as unknown;
      const bundles: Bundle[] = Array.isArray((json as { attestations?: unknown }).attestations)
        ? ((json as { attestations: Array<{ bundle?: Bundle }> }).attestations
            .map((a) => a.bundle)
            .filter((b): b is Bundle => Boolean(b)) ?? [])
        : Array.isArray(json)
          ? (json as Bundle[])
          : [];

      const { fromCert, fromPayload } = reposFromBundles(bundles);
      const declared = packumentRepo(ctx.artifacts.candidatePackument);
      const observed = [...fromCert, ...fromPayload];

      if (observed.length === 0) {
        return {
          scanner: "provenance",
          status: "ok",
          evidences: [
            {
              scanner: "provenance",
              key: "provenance:present",
              status: "info",
              detail: "attestations exist but no source repository could be extracted from them",
            },
          ],
        };
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
      return {
        scanner: "provenance",
        status: "ok",
        evidences: [
          {
            scanner: "provenance",
            key: "provenance:declared",
            status: "info",
            detail: `declared source ${declared ?? "(none)"} matches attested source(s) ${unique}; signature chain not cryptographically verified in MVP`,
            data: { observed },
          },
        ],
      };
    },
  };
}
