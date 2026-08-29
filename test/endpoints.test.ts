import { afterEach, describe, expect, it, vi } from "vitest";
import { DATA_DIR, dataDir } from "../src/config.ts";
import { downloadsApiBase, npmRegistryBase } from "../src/npm/registry.ts";
import { osvApiBase } from "../src/scanners/osv.ts";
import { agentDir, DEFAULT_AGENT_DIR } from "../src/settings.ts";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("endpoint env overrides", () => {
  it("defaults to the public endpoints when unset", () => {
    expect(npmRegistryBase()).toBe("https://registry.npmjs.org");
    expect(downloadsApiBase()).toBe("https://api.npmjs.org/downloads/point/last-month");
    expect(osvApiBase()).toBe("https://api.osv.dev");
    expect(dataDir()).toBe(DATA_DIR);
    expect(agentDir()).toBe(DEFAULT_AGENT_DIR);
  });

  it("reads overrides lazily at call time (private registries/mirrors, E2E)", () => {
    vi.stubEnv("PI_VETTER_NPM_REGISTRY", "https://mirror.example.com");
    vi.stubEnv("PI_VETTER_DOWNLOADS_API", "https://mirror.example.com/downloads/point/last-month");
    vi.stubEnv("PI_VETTER_OSV_API", "http://127.0.0.1:9/v1");
    vi.stubEnv("PI_VETTER_DATA_DIR", "/tmp/pi-vetter-test");
    vi.stubEnv("PI_VETTER_AGENT_DIR", "/tmp/pi-vetter-agent");
    expect(npmRegistryBase()).toBe("https://mirror.example.com");
    expect(downloadsApiBase()).toBe("https://mirror.example.com/downloads/point/last-month");
    expect(osvApiBase()).toBe("http://127.0.0.1:9/v1");
    expect(dataDir()).toBe("/tmp/pi-vetter-test");
    expect(agentDir()).toBe("/tmp/pi-vetter-agent");
    // precedence: explicit argument still wins over the environment
    expect(dataDir("/explicit/dir")).toBe("/explicit/dir");
    expect(agentDir("/explicit/agent")).toBe("/explicit/agent");
  });
});
