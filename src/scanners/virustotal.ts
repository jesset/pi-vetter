import type { Evidence, ScannerContext, ScanResult, SecurityScanner } from "../core/types.ts";

const VT_API = "https://www.virustotal.com/api/v3";
const DETECTION_THRESHOLD = 2;
const MAX_POLLS = 30;
const POLL_INTERVAL_MS = 2_000;

interface AnalysisStats {
  malicious?: number;
  suspicious?: number;
  undetected?: number;
  harmless?: number;
  timeout?: number;
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export class QuotaExhaustedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QuotaExhaustedError";
  }
}

async function vtFetch(
  url: string,
  init: RequestInit,
  apiKey: string,
  timeoutMs: number,
  fetchImpl: FetchLike,
): Promise<Response> {
  const res = await fetchImpl(url, {
    ...init,
    headers: { "x-apikey": apiKey, ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 429 || res.status === 402 || res.status === 403) {
    throw new QuotaExhaustedError(`VirusTotal API rejected the request (HTTP ${res.status})`);
  }
  return res;
}

export function createVirustotalScanner(options: {
  apiKey: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
  pollIntervalMs?: number;
}): SecurityScanner {
  const { apiKey, timeoutMs = 60_000, pollIntervalMs = POLL_INTERVAL_MS } = options;
  const doFetch = options.fetchImpl ?? ((url: string, init?: RequestInit) => fetch(url, init));

  return {
    name: "virustotal",
    layer: 3,
    async scan(ctx: ScannerContext): Promise<ScanResult> {
      const { candidate, artifacts } = ctx;
      const label = `${candidate.name}@${candidate.version}`;
      try {
        // Hash-first: existing sample reports cost one request and are often cached.
        const report = await vtFetch(
          `${VT_API}/files/${artifacts.candidateSha256}`,
          {},
          apiKey,
          timeoutMs,
          doFetch,
        );
        if (report.ok) {
          const body = (await report.json()) as {
            data?: { attributes?: { last_analysis_stats?: AnalysisStats } };
          };
          const stats = body.data?.attributes?.last_analysis_stats ?? {};
          return { scanner: "virustotal", status: "ok", evidences: statsEvidence(stats, label) };
        }
        if (report.status !== 404) {
          throw new Error(`VirusTotal file lookup failed: HTTP ${report.status}`);
        }

        // Unknown sample: upload the exact verified bytes we vetted
        // (uploads of new files do not consume the daily quota).
        const form = new FormData();
        form.append(
          "file",
          new Blob([artifacts.candidateTarball], { type: "application/gzip" }),
          `${candidate.name}.tgz`,
        );
        const upload = await vtFetch(
          `${VT_API}/files`,
          { method: "POST", body: form },
          apiKey,
          timeoutMs,
          doFetch,
        );
        if (!upload.ok) throw new Error(`VirusTotal upload failed: HTTP ${upload.status}`);
        const uploaded = (await upload.json()) as { data?: { id?: string } };
        const analysisId = uploaded.data?.id;
        if (!analysisId) throw new Error("VirusTotal upload returned no analysis id");

        // Async analysis: poll until completed, then read the stats.
        for (let i = 0; i < MAX_POLLS; i++) {
          await new Promise((r) => setTimeout(r, pollIntervalMs));
          const analysis = await vtFetch(
            `${VT_API}/analyses/${analysisId}`,
            {},
            apiKey,
            timeoutMs,
            doFetch,
          );
          if (!analysis.ok) continue;
          const attr = (
            (await analysis.json()) as {
              data?: { attributes?: { status?: string; stats?: AnalysisStats } };
            }
          ).data?.attributes;
          if (attr?.status === "completed") {
            const stats = attr.stats ?? {};
            return { scanner: "virustotal", status: "ok", evidences: statsEvidence(stats, label) };
          }
        }
        return {
          scanner: "virustotal",
          status: "timeout",
          evidences: [],
        };
      } catch (err) {
        if (err instanceof QuotaExhaustedError) {
          return { scanner: "virustotal", status: "quota-exhausted", evidences: [] };
        }
        if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
          return { scanner: "virustotal", status: "timeout", evidences: [] };
        }
        throw err;
      }
    },
  };
}

function statsEvidence(stats: AnalysisStats, label: string): Evidence[] {
  const flagged = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
  const detail = `engines: ${flagged} malicious/suspicious, ${stats.undetected ?? 0} undetected`;
  if (flagged >= DETECTION_THRESHOLD) {
    return [
      {
        scanner: "virustotal",
        key: "virustotal:detections",
        status: "fail",
        detail: `${label}: ${detail}`,
        data: stats,
      },
    ];
  }
  if (flagged === 1) {
    return [
      {
        scanner: "virustotal",
        key: "virustotal:weak-detection",
        status: "info",
        detail: `${label}: ${detail}`,
        data: stats,
      },
    ];
  }
  return [
    {
      scanner: "virustotal",
      key: "virustotal:clean",
      status: "pass",
      detail: `${label}: ${detail}`,
      data: stats,
    },
  ];
}
