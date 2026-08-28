import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { gunzipSync } from "node:zlib";
import { extract } from "tar-stream";

export type TarFiles = Map<string, Uint8Array>;

export interface TarballIntegrity {
  algorithm: string;
  base64: string;
}

export function parseIntegrity(integrity: string): TarballIntegrity {
  const idx = integrity.indexOf("-");
  if (idx <= 0) throw new Error(`malformed integrity string: ${integrity}`);
  return { algorithm: integrity.slice(0, idx), base64: integrity.slice(idx + 1) };
}

export function verifyIntegrity(bytes: Uint8Array, integrity: string): boolean {
  const { algorithm, base64 } = parseIntegrity(integrity);
  const digest = createHash(algorithm).update(bytes).digest("base64");
  return digest === base64;
}

export async function downloadTarball(url: string, signal?: AbortSignal): Promise<Uint8Array> {
  const res = await fetch(url, { signal: signal ?? null });
  if (!res.ok) throw new Error(`tarball download failed: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

function normalizeEntryName(name: string): string | null {
  let p = name;
  if (p.startsWith("package/")) p = p.slice("package/".length);
  if (p === "" || p === "." || p === "./") return null;
  if (p.startsWith("/")) return null;
  const parts = p.split("/");
  if (parts.some((seg) => seg === "..")) return null;
  return parts.join("/");
}

/**
 * Parses a gzipped npm tarball fully in memory. No extraction to disk: the
 * bytes come from an untrusted package, so we never touch the filesystem with
 * them, and only regular files are kept (symlinks/dirs dropped).
 */
export async function parseTarball(
  gzipped: Uint8Array,
  maxBytes = 64 * 1024 * 1024,
): Promise<TarFiles> {
  const unzipped = gunzipSync(gzipped);
  if (unzipped.byteLength > maxBytes) {
    throw new Error(`tarball too large to analyze (${unzipped.byteLength} bytes)`);
  }

  const files: TarFiles = new Map();
  let total = 0;

  await new Promise<void>((resolve, reject) => {
    const ex = extract();
    ex.on("entry", (header, stream, next) => {
      const name = header.type === "file" ? normalizeEntryName(header.name) : null;
      if (name === null) {
        stream.resume();
        next();
        return;
      }
      const chunks: Buffer[] = [];
      stream.on("data", (c: unknown) => chunks.push(c as Buffer));
      stream.on("end", () => {
        const buf = Buffer.concat(chunks);
        total += buf.byteLength;
        if (total > maxBytes) {
          next(new Error("tarball content exceeds analysis size limit"));
          return;
        }
        files.set(name, new Uint8Array(buf));
        next();
      });
      stream.on("error", next);
    });
    ex.on("finish", () => resolve());
    ex.on("error", reject);
    Readable.from(unzipped).pipe(ex);
  });

  return files;
}

export function fileText(files: TarFiles, path: string): string | null {
  const bytes = files.get(path);
  if (!bytes) return null;
  return Buffer.from(bytes).toString("utf8");
}

export function textFiles(files: TarFiles): Map<string, string> {
  const out = new Map<string, string>();
  const textExt = /\.(js|mjs|cjs|ts|mts|cts|json|jsonc|ya?ml|toml|sh|env|md|txt)$/i;
  for (const [path, bytes] of files) {
    if (textExt.test(path) || path === "LICENSE" || path.startsWith("scripts/")) {
      out.set(path, Buffer.from(bytes).toString("utf8"));
    }
  }
  return out;
}
