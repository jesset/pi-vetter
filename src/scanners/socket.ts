import type { Evidence, ScannerContext, ScanResult, SecurityScanner } from "../core/types.ts";

const SOCKET_API = "https://api.socket.dev/v0/orgs";

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** purl encoding: scoped names escape the leading @ as %40 in the namespace. */
export function toPurl(name: string, version: string): string {
  return `pkg:npm/${name.startsWith("@") ? `%40${name.slice(1)}` : name}@${version}`;
}

/** Socket alert keys that indicate serious supply-chain risk (Socket docs: Alert Types). */
const HIGH_ALERT_KEYS = new Set([
  "gptMalware",
  "gptSuspicious",
  "installScripts",
  "obfuscatedFile",
  "typosquatting",
]);

interface SocketAlert {
  key?: string;
  severity?: string;
}

function alertsEvidences(alerts: SocketAlert[], label: string): Evidence[] {
  const high = alerts.filter((a) => a.key && HIGH_ALERT_KEYS.has(a.key));
  const minor = alerts.filter((a) => !a.key || !HIGH_ALERT_KEYS.has(a.key));
  const evidences: Evidence[] = [];
  if (high.length > 0) {
    evidences.push({
      scanner: "socket",
      key: "socket:alerts",
      status: "fail",
      detail: `${label}: high-risk Socket alerts: ${high.map((a) => a.key).join(", ")}`,
      data: high,
    });
  }
  if (minor.length > 0) {
    evidences.push({
      scanner: "socket",
      key: "socket:minor-alerts",
      status: "info",
      detail: `${label}: informational Socket alerts: ${minor.map((a) => a.key).join(", ")}`,
      data: minor,
    });
  }
  if (evidences.length === 0) {
    evidences.push({
      scanner: "socket",
      key: "socket:clean",
      status: "pass",
      detail: `${label}: no Socket alerts`,
    });
  }
  return evidences;
}

export function createSocketScanner(options: {
  apiKey: string;
  orgSlug: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}): SecurityScanner {
  const { apiKey, orgSlug, timeoutMs = 10_000 } = options;
  const doFetch = options.fetchImpl ?? ((url: string, init?: RequestInit) => fetch(url, init));

  return {
    name: "socket",
    layer: 3,
    async scan(ctx: ScannerContext): Promise<ScanResult> {
      const { candidate } = ctx;
      const label = `${candidate.name}@${candidate.version}`;
      try {
        const res = await doFetch(`${SOCKET_API}/${orgSlug}/purl`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${apiKey}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ purl: toPurl(candidate.name, candidate.version) }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (res.status === 429 || res.status === 402 || res.status === 403) {
          return { scanner: "socket", status: "quota-exhausted", evidences: [] };
        }
        if (!res.ok) throw new Error(`Socket purl scan failed: HTTP ${res.status}`);
        const body = (await res.json()) as unknown;
        const report = (Array.isArray(body) ? body[0] : body) as
          | { alerts?: SocketAlert[] }
          | undefined;
        return {
          scanner: "socket",
          status: "ok",
          evidences: alertsEvidences(report?.alerts ?? [], label),
        };
      } catch (err) {
        if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
          return { scanner: "socket", status: "timeout", evidences: [] };
        }
        throw err;
      }
    },
  };
}
