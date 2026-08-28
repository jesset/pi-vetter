import type { TarFiles } from "../core/types.ts";
import { textFiles } from "../npm/tarball.ts";

export interface PatternSummary {
  evalFamily: string[];
  childProcess: string[];
  credentials: string[];
  obfuscation: string[];
  promptInjection: string[];
  endpointHosts: Set<string>;
  scannedFileCount: number;
}

const CODE_EXT = /\.(js|mjs|cjs|ts|mts|cts)$/;

const PATTERNS: Array<[keyof Omit<PatternSummary, "endpointHosts" | "scannedFileCount">, RegExp]> =
  [
    ["evalFamily", /\beval\s*\(|\bnew\s+Function\s*\(|vm\.runIn(?:Context|NewContext)\s*\(/],
    [
      "childProcess",
      /require\(\s*["']child_process["']\s*\)|from\s+["']child_process["']|\b(?:execSync|spawnSync|execFile|child_process)\b/,
    ],
    [
      "credentials",
      /~?\/?\.ssh\/|id_rsa|id_ed25519|\.aws\/|\.npmrc|\.gitconfig|process\.env\.[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*|process\.env\.(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY)/,
    ],
    [
      "obfuscation",
      /[A-Za-z0-9+/]{300,}={0,2}|[0-9a-fA-F]{200,}|eval\s*\(\s*(?:atob|unescape)|String\.fromCharCode\([^)]{60,}\)/,
    ],
    [
      "promptInjection",
      /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior|the\s+above)|(?:reveal|print|dump|show)\s+(?:your\s+|the\s+)?system\s+prompt|(?:override|bypass)\s+(?:your\s+)?(?:safety|security)\s+(?:rules|guidelines)|you\s+are\s+now\s+(?:a|an)\s+(?:different|new)/i,
    ],
  ];

const URL_RE = /https?:\/\/([a-zA-Z0-9.-]+(?::\d+)?)/g;

export function scanPatterns(files: TarFiles): PatternSummary {
  const summary: PatternSummary = {
    evalFamily: [],
    childProcess: [],
    credentials: [],
    obfuscation: [],
    promptInjection: [],
    endpointHosts: new Set(),
    scannedFileCount: 0,
  };
  for (const [path, text] of textFiles(files)) {
    if (!CODE_EXT.test(path) && path !== "package.json") continue;
    summary.scannedFileCount++;
    for (const [category, re] of PATTERNS) {
      const m = re.exec(text);
      if (m) summary[category].push(`${path}: ${m[0].slice(0, 60)}`);
    }
    for (const m of text.matchAll(URL_RE)) {
      summary.endpointHosts.add(m[1] ?? "");
    }
  }
  return summary;
}
