import { createServer, type Server, type ServerResponse } from "node:http";
import type { Packument } from "../../../src/core/types.ts";
import type { RegistryState } from "./fixtures.ts";

export interface FaultRule {
  match: (method: string, url: URL) => boolean;
  /** Respond with this status instead of serving (default 500). */
  status?: number;
  /** Delay before responding (timeout scenarios). */
  delayMs?: number;
}

export interface FakeRegistry {
  /** Base URL to point PI_VETTER_NPM_REGISTRY at. */
  url: string;
  /** Base URL to point PI_VETTER_DOWNLOADS_API at. */
  downloadsUrl: string;
  /** Base URL to point PI_VETTER_OSV_API at (same server, /osv prefix). */
  osvUrl: string;
  state: RegistryState;
  /** package name → OSV advisory ids returned by querybatch (mutable). */
  osvVulns: Map<string, string[]>;
  setFault(rule: FaultRule): void;
  clearFaults(): void;
  /** Live packument reference — mutate for cross-run scenarios (#28). */
  packumentOf(name: string): Packument | undefined;
  /** Rotate dist.integrity for a version (TOCTOU scenarios, #29). */
  setIntegrity(name: string, version: string, integrity: string): void;
  close(): Promise<void>;
}

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
};

/**
 * Minimal in-memory npm registry + downloads API + OSV querybatch, served
 * over real HTTP on 127.0.0.1. Supports programmable faults and live
 * mutation of the served state. The factory receives the bound base URL so
 * fixture tarball URLs can point back at this server.
 */
export async function startFakeRegistry(
  stateOrFactory: RegistryState | ((baseUrl: string) => Promise<RegistryState>),
): Promise<FakeRegistry> {
  const faults: FaultRule[] = [];
  const osvVulns = new Map<string, string[]>();
  let state: RegistryState =
    typeof stateOrFactory === "function" ? { packages: new Map() } : stateOrFactory;

  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const method = req.method ?? "GET";

      for (const fault of faults) {
        if (fault.match(method, url)) {
          if (fault.delayMs) await new Promise((r) => setTimeout(r, fault.delayMs));
          res.statusCode = fault.status ?? 500;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ error: "injected fault" }));
          return;
        }
      }

      if (method === "POST" && url.pathname === "/osv/v1/querybatch") {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
          queries?: Array<{ package?: { name?: string } }>;
        };
        const results = (body.queries ?? []).map((q) => ({
          vulns: (osvVulns.get(q.package?.name ?? "") ?? []).map((id) => ({ id })),
        }));
        json(res, 200, { results });
        return;
      }

      const dl = /^\/downloads\/point\/last-month\/(.+)$/.exec(url.pathname);
      if (method === "GET" && dl) {
        const name = decodeURIComponent(dl[1] ?? "");
        const pkg = state.packages.get(name);
        json(res, 200, { downloads: pkg?.downloads ?? 0 });
        return;
      }

      const tarball = /^(.+)\/-\/[^/]+\.tgz$/.exec(url.pathname);
      if (method === "GET" && tarball) {
        // Exact pathname match against the packuments' own dist.tarball URLs —
        // no name/version string parsing to drift out of sync with fixtures.
        let pub: Uint8Array | undefined;
        for (const pkg of state.packages.values()) {
          for (const meta of Object.values(pkg.packument.versions)) {
            if (new URL(meta.dist.tarball).pathname === url.pathname) {
              pub = pkg.published.get(meta.version)?.tarball;
            }
          }
        }
        if (!pub) {
          res.statusCode = 404;
          res.end("not found");
          return;
        }
        res.setHeader("content-type", "application/octet-stream");
        res.end(Buffer.from(pub));
        return;
      }

      if (method === "GET") {
        const name = decodeURIComponent(url.pathname.replace(/^\//, ""));
        const pkg = state.packages.get(name);
        if (!pkg) {
          res.statusCode = 404;
          res.end(JSON.stringify({ error: "Not found" }));
          return;
        }
        json(res, 200, pkg.packument);
        return;
      }

      res.statusCode = 405;
      res.end();
    })().catch(() => {
      res.statusCode = 500;
      res.end();
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (typeof address !== "object" || address === null) throw new Error("no listen address");
  const base = `http://127.0.0.1:${address.port}`;
  if (typeof stateOrFactory === "function") {
    state = await stateOrFactory(base);
  }

  return {
    url: base,
    downloadsUrl: `${base}/downloads/point/last-month`,
    osvUrl: `${base}/osv`,
    state,
    osvVulns,
    setFault: (rule) => faults.push(rule),
    clearFaults: () => faults.splice(0),
    packumentOf: (name) => state.packages.get(name)?.packument,
    setIntegrity: (name, version, integrity) => {
      const meta = state.packages.get(name)?.packument.versions[version];
      if (meta) meta.dist.integrity = integrity;
    },
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
